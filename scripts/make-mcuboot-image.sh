#!/usr/bin/env bash
set -euo pipefail

# Reproducibly build a firmware payload in its target-specific Dockerfile, then
# create an MCUboot image using the public key retrieved from the network signer.
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

EXAMPLE_DIR="$REPO_ROOT/examples/$TARGET"
DOCKERFILE="$EXAMPLE_DIR/app/Dockerfile.firmware"
if [[ ! -f "$DOCKERFILE" ]]; then
    echo "firmware Dockerfile not found for target $TARGET: $DOCKERFILE" >&2
    exit 2
fi

for tool in "$DOCKER" sha256sum "$IMGTOOL" "$MICROTUN_SIGNER"; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "required tool not found: $tool" >&2
        exit 127
    fi
done

WORKSPACE_MANIFEST="$REPO_ROOT/examples/Cargo.toml"
WORKSPACE_VERSION="$(sed -nE 's/^version[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' "$WORKSPACE_MANIFEST" | head -n1)"
if [[ -z "$WORKSPACE_VERSION" ]]; then
    echo "could not determine firmware version from $WORKSPACE_MANIFEST" >&2
    exit 2
fi

VERSION="${VERSION:-$WORKSPACE_VERSION}"
if [[ "$VERSION" != "$WORKSPACE_VERSION" ]]; then
    echo "firmware version $VERSION does not match examples workspace version $WORKSPACE_VERSION" >&2
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

"$REPO_ROOT/scripts/sign-mcuboot.sh" \
    --input "$WORK_DIR/firmware.bin" \
    --output "$OUTPUT" \
    --public-key "$PUBLIC_KEY" \
    --version "$VERSION" \
    --vid firmware.microtun.dev \
    --cid "$CID" \
    --slot-size "$SLOT_SIZE" \
    --signer "$MICROTUN_SIGNER" \
    --signer-url "$MICROTUN_SIGNER_URL" \
    --key-id "$MICROTUN_SIGNER_KEY_ID" \
    --imgtool "$IMGTOOL"
