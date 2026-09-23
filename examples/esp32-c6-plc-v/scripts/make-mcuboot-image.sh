#!/usr/bin/env bash
set -euo pipefail

# Reproducibly build the ESP32-C6 payload in Docker, then create an MCUboot
# image using the public key retrieved from the network signer.
#
# Required environment:
#   MICROTUN_SIGNING_SERVICE_URL
#   MICROTUN_SIGNING_KEY_ID
# Optional environment:
#   MICROTUN_FIRMWARE_PUBLIC_KEY_PEM_PATH (optional pre-fetched public key)
#   MICROTUN_SIGNING_OIDC_AUDIENCE (default: microtun-firmware-signer)
#   MICROTUN_SIGNING_SERVICE_TOKEN (fallback when GitHub OIDC is not used)
#   IMGTOOL (default: imgtool)
#   DOCKER (default: docker)
#
# Usage:
#   ./make-mcuboot-image.sh [output.bin]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXAMPLE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$EXAMPLE_DIR/../.." && pwd)"
CALLER_DIR="$PWD"
DOCKER="${DOCKER:-docker}"
IMGTOOL="${IMGTOOL:-imgtool}"

if [[ $# -gt 1 ]]; then
    echo "usage: $0 [output.bin]" >&2
    exit 2
fi

for tool in "$DOCKER" python3 "$IMGTOOL"; do
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

if [[ $# -eq 1 ]]; then
    OUTPUT="$1"
    if [[ "$OUTPUT" != /* ]]; then
        OUTPUT="$CALLER_DIR/$OUTPUT"
    fi
else
    OUTPUT="$CALLER_DIR/microtun-esp32-c6-plc-v-$VERSION.mcuboot.bin"
fi
mkdir -p "$(dirname "$OUTPUT")"

: "${MICROTUN_SIGNING_SERVICE_URL:?MICROTUN_SIGNING_SERVICE_URL is required}"
: "${MICROTUN_SIGNING_KEY_ID:?MICROTUN_SIGNING_KEY_ID is required}"

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/microtun-esp32-c6-plc-v-docker.XXXXXX")"
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
    python3 "$REPO_ROOT/.github/scripts/firmware-signing-client.py" get-public-key \
        --service-url "$MICROTUN_SIGNING_SERVICE_URL" \
        --key-id "$MICROTUN_SIGNING_KEY_ID" \
        --audience "${MICROTUN_SIGNING_OIDC_AUDIENCE:-microtun-firmware-signer}" \
        --output "$PUBLIC_KEY"
fi

# BuildKit deliberately excludes secret contents from cache keys. Feed a hash
# of the fetched public-key file through a non-secret build arg as a cache key
# so a future key transition cannot reuse firmware built with a different key.
PUBLIC_KEY_CACHE_KEY="$(python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())' "$PUBLIC_KEY")"

printf 'Building ESP32-C6 firmware payload in Docker...\n'
DOCKER_BUILDKIT=1 "$DOCKER" build \
    --file "$SCRIPT_DIR/Dockerfile.mcuboot" \
    --target artifact \
    --build-arg "FIRMWARE_PUBLIC_KEY_CACHE_KEY=$PUBLIC_KEY_CACHE_KEY" \
    --secret "id=firmware_public_key,src=$PUBLIC_KEY" \
    --output "type=local,dest=$WORK_DIR" \
    "$REPO_ROOT"

test -s "$WORK_DIR/firmware.bin"

python3 "$REPO_ROOT/.github/scripts/firmware-signing-client.py" sign-mcuboot \
    --input "$WORK_DIR/firmware.bin" \
    --output "$OUTPUT" \
    --public-key "$PUBLIC_KEY" \
    --version "$VERSION" \
    --board esp32-c6-plc-v \
    --cid esp32-c6-plc-v \
    --slot-size 0x1f0000 \
    --service-url "$MICROTUN_SIGNING_SERVICE_URL" \
    --key-id "$MICROTUN_SIGNING_KEY_ID" \
    --audience "${MICROTUN_SIGNING_OIDC_AUDIENCE:-microtun-firmware-signer}" \
    --imgtool "$IMGTOOL"
