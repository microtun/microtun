#!/usr/bin/env bash
set -Eeuo pipefail

# Reproducibly build a firmware payload in its target-specific Dockerfile, then
# create and verify an externally signed MCUboot image using microtun-signer.
#
# imgtool defines the exact bytes covered by the MCUboot signature. This script
# asks imgtool for the SHA-256 digest, sends only that digest to microtun-signer,
# injects the returned Ed25519 signature, and verifies the final image with the
# public key. The private signing key never enters the build runner.
#
# Required environment:
#   MICROTUN_SIGNER_URL
#   MICROTUN_SIGNER_KEY_ID
# Optional environment:
#   MICROTUN_FIRMWARE_PUBLIC_KEY_PEM_PATH (optional pre-fetched public key)
#   MICROTUN_SIGNER_TOKEN (bearer token used by microtun-signer sign)
#   MICROTUN_SIGNER (default: microtun-signer)
#   IMGTOOL (default: imgtool)
#   DOCKER (default: docker)
#
# Usage:
#   scripts/make-mcuboot-image.sh <target> [output.bin]
#
# Supported targets:
#   esp32-c6-plc-v
#   nucleo-h753zi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CALLER_DIR="$PWD"
DOCKER="${DOCKER:-docker}"
IMGTOOL="${IMGTOOL:-imgtool}"
MICROTUN_SIGNER="${MICROTUN_SIGNER:-microtun-signer}"
VID="firmware.microtun.dev"

fail() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

sign_mcuboot_image() (
    local input="$1"
    local output="$2"
    local public_key="$3"

    [[ -f "$input" ]] || fail "firmware input not found: $input"
    [[ -f "$public_key" ]] || fail "firmware public key not found: $public_key"

    local output_dir
    output_dir="$(dirname "$output")"
    mkdir -p "$output_dir"
    output_dir="$(cd "$output_dir" && pwd -P)"
    output="$output_dir/$(basename "$output")"
    input="$(realpath "$input")"
    public_key="$(realpath "$public_key")"

    # Keep the final image temporary file on the same filesystem as the output,
    # so replacing OUTPUT below is an atomic rename under normal filesystems.
    local temp_dir
    temp_dir="$(mktemp -d "$output_dir/.microtun-mcuboot.XXXXXX")"

    local digest_path="$temp_dir/digest.bin"
    local signature_b64_path="$temp_dir/signature.b64"
    local signature_bin_path="$temp_dir/signature.bin"
    local image_path="$temp_dir/image.bin"

    trap 'rm -rf "$temp_dir"' EXIT

    # These options define the bytes covered by the signature. Keep both
    # imgtool invocations identical apart from the external-signing options.
    local common_args=(
        --sha 256
        --align 1
        --version "$VERSION"
        --header-size 32
        --pad-header
        --slot-size "$SLOT_SIZE"
        --vid "$VID"
        --cid "$CID"
    )

    "$IMGTOOL" sign \
        --key "$public_key" \
        --vector-to-sign digest \
        "${common_args[@]}" \
        "$input" "$digest_path"

    local digest_size
    digest_size="$(wc -c < "$digest_path" | tr -d '[:space:]')"
    [[ "$digest_size" == "32" ]] || fail "imgtool returned a ${digest_size}-byte digest; expected SHA-256"

    # Command substitution strips trailing newlines. Removing embedded line
    # wraps keeps this portable across common base64 implementations.
    local digest_b64
    digest_b64="$(base64 < "$digest_path" | tr -d '\r\n')"
    [[ -n "$digest_b64" ]] || fail "failed to base64-encode MCUboot digest"

    local signature_b64
    signature_b64="$({
        "$MICROTUN_SIGNER" \
            --url "$MICROTUN_SIGNER_URL" \
            sign \
            --key-id "$MICROTUN_SIGNER_KEY_ID" \
            --digest "$digest_b64"
    } | tr -d '\r\n')"

    [[ -n "$signature_b64" ]] || fail "microtun-signer returned an empty signature"
    [[ "$signature_b64" =~ ^[A-Za-z0-9+/]*={0,2}$ ]] || fail "microtun-signer returned a non-base64 signature"
    (( ${#signature_b64} % 4 == 0 )) || fail "microtun-signer returned malformed base64"
    printf '%s\n' "$signature_b64" > "$signature_b64_path"

    if ! printf '%s' "$signature_b64" | base64 --decode > "$signature_bin_path" 2>/dev/null; then
        fail "microtun-signer returned a non-base64 signature"
    fi

    local signature_size
    signature_size="$(wc -c < "$signature_bin_path" | tr -d '[:space:]')"
    [[ "$signature_size" == "64" ]] || fail "microtun-signer returned a ${signature_size}-byte signature; expected Ed25519 (64 bytes)"

    "$IMGTOOL" sign \
        --fix-sig "$signature_b64_path" \
        --fix-sig-pubkey "$public_key" \
        "${common_args[@]}" \
        "$input" "$image_path"

    "$IMGTOOL" verify --key "$public_key" "$image_path"
    [[ -s "$image_path" ]] || fail "imgtool produced an empty firmware image"

    mv -f "$image_path" "$output"
)

if [[ $# -lt 1 || $# -gt 2 ]]; then
    echo "usage: $0 <target> [output.bin]" >&2
    exit 2
fi

TARGET="$1"
case "$TARGET" in
    esp32-c6-plc-v)
        CID="esp32-c6-plc-v"
        SLOT_SIZE="0x1f0000"
        BUILD_LABEL="ESP32-C6"
        ;;
    nucleo-h753zi)
        CID="nucleo-h753zi"
        SLOT_SIZE="0x0c0000"
        BUILD_LABEL="NUCLEO-H753ZI"
        ;;
    *)
        echo "unsupported firmware target: $TARGET" >&2
        exit 2
        ;;
esac

FIRMWARE_DIR="$REPO_ROOT/firmware/$TARGET"
DOCKERFILE="$FIRMWARE_DIR/app/Dockerfile.firmware"
if [[ ! -f "$DOCKERFILE" ]]; then
    echo "firmware Dockerfile not found for target $TARGET: $DOCKERFILE" >&2
    exit 2
fi

for tool in "$DOCKER" sha256sum "$IMGTOOL" "$MICROTUN_SIGNER" base64 wc realpath; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "required tool not found: $tool" >&2
        exit 127
    fi
done

WORKSPACE_MANIFEST="$REPO_ROOT/firmware/Cargo.toml"
WORKSPACE_VERSION="$(sed -nE 's/^version[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' "$WORKSPACE_MANIFEST" | head -n1)"
if [[ -z "$WORKSPACE_VERSION" ]]; then
    echo "could not determine firmware version from $WORKSPACE_MANIFEST" >&2
    exit 2
fi

VERSION="${VERSION:-$WORKSPACE_VERSION}"
if [[ "$VERSION" != "$WORKSPACE_VERSION" ]]; then
    echo "firmware version $VERSION does not match firmware workspace version $WORKSPACE_VERSION" >&2
    exit 2
fi
if [[ ! "$VERSION" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
    echo "firmware version must be release SemVer x.y.z: $VERSION" >&2
    exit 2
fi

if [[ $# -eq 2 ]]; then
    OUTPUT="$2"
    if [[ "$OUTPUT" != /* ]]; then
        OUTPUT="$CALLER_DIR/$OUTPUT"
    fi
else
    OUTPUT="$CALLER_DIR/microtun-$TARGET-$VERSION.mcuboot.bin"
fi
mkdir -p "$(dirname "$OUTPUT")"

: "${MICROTUN_SIGNER_URL:?MICROTUN_SIGNER_URL is required}"
: "${MICROTUN_SIGNER_KEY_ID:?MICROTUN_SIGNER_KEY_ID is required}"

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/microtun-$TARGET-docker.XXXXXX")"
trap 'rm -rf "$WORK_DIR"' EXIT

PUBLIC_KEY="${MICROTUN_FIRMWARE_PUBLIC_KEY_PEM_PATH:-}"
if [[ -n "$PUBLIC_KEY" ]]; then
    if [[ ! -f "$PUBLIC_KEY" ]]; then
        echo "firmware public key not found: $PUBLIC_KEY" >&2
        exit 2
    fi
    PUBLIC_KEY="$(realpath "$PUBLIC_KEY")"
else
    PUBLIC_KEY="$WORK_DIR/firmware-signing-public.pem"
    "$MICROTUN_SIGNER" \
        --url "$MICROTUN_SIGNER_URL" \
        public-key \
        --key-id "$MICROTUN_SIGNER_KEY_ID" \
        > "$PUBLIC_KEY"
    test -s "$PUBLIC_KEY"
fi

# BuildKit deliberately excludes secret contents from cache keys. Feed a hash
# of the fetched public-key file through a non-secret build arg as a cache key
# so a future key transition cannot reuse firmware built with a different key.
read -r PUBLIC_KEY_CACHE_KEY _ < <(sha256sum "$PUBLIC_KEY")

printf 'Building %s firmware payload in Docker...\n' "$BUILD_LABEL"
DOCKER_BUILDKIT=1 "$DOCKER" build \
    --file "$DOCKERFILE" \
    --target artifact \
    --build-arg "FIRMWARE_PUBLIC_KEY_CACHE_KEY=$PUBLIC_KEY_CACHE_KEY" \
    --secret "id=firmware_public_key,src=$PUBLIC_KEY" \
    --output "type=local,dest=$WORK_DIR" \
    "$REPO_ROOT"

test -s "$WORK_DIR/firmware.bin"

sign_mcuboot_image "$WORK_DIR/firmware.bin" "$OUTPUT" "$PUBLIC_KEY"
