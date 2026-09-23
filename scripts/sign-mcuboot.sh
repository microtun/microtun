#!/usr/bin/env bash
set -Eeuo pipefail

# Create and verify an externally signed MCUboot image using microtun-signer.
#
# imgtool defines the exact bytes covered by the MCUboot signature. This helper
# asks imgtool for the SHA-256 digest, sends only that digest to microtun-signer,
# injects the returned Ed25519 signature, and verifies the final image with the
# public key. The private signing key never enters the build runner.

usage() {
    cat >&2 <<'USAGE'
usage: sign-mcuboot.sh \
  --input FILE \
  --output FILE \
  --public-key FILE \
  --version VERSION \
  --vid VID \
  --cid CID \
  --slot-size SIZE \
  [--imgtool COMMAND] \
  [--signer COMMAND] \
  [--signer-url URL] \
  [--key-id KEY_ID]

Defaults:
  --imgtool     $IMGTOOL or imgtool
  --signer      $MICROTUN_SIGNER or microtun-signer
  --signer-url  $MICROTUN_SIGNER_URL
  --key-id      $MICROTUN_SIGNER_KEY_ID
USAGE
}

fail() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

require_value() {
    local option="$1"
    local value="${2-}"
    [[ -n "$value" ]] || fail "$option requires a value"
}

INPUT=""
OUTPUT=""
PUBLIC_KEY=""
VERSION=""
VID=""
CID=""
SLOT_SIZE=""
IMGTOOL="${IMGTOOL:-imgtool}"
MICROTUN_SIGNER="${MICROTUN_SIGNER:-microtun-signer}"
SIGNER_URL="${MICROTUN_SIGNER_URL:-}"
KEY_ID="${MICROTUN_SIGNER_KEY_ID:-}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --input)
            require_value "$1" "${2-}"; INPUT="$2"; shift 2 ;;
        --output)
            require_value "$1" "${2-}"; OUTPUT="$2"; shift 2 ;;
        --public-key)
            require_value "$1" "${2-}"; PUBLIC_KEY="$2"; shift 2 ;;
        --version)
            require_value "$1" "${2-}"; VERSION="$2"; shift 2 ;;
        --vid)
            require_value "$1" "${2-}"; VID="$2"; shift 2 ;;
        --cid)
            require_value "$1" "${2-}"; CID="$2"; shift 2 ;;
        --slot-size)
            require_value "$1" "${2-}"; SLOT_SIZE="$2"; shift 2 ;;
        --imgtool)
            require_value "$1" "${2-}"; IMGTOOL="$2"; shift 2 ;;
        --signer)
            require_value "$1" "${2-}"; MICROTUN_SIGNER="$2"; shift 2 ;;
        --signer-url)
            require_value "$1" "${2-}"; SIGNER_URL="$2"; shift 2 ;;
        --key-id)
            require_value "$1" "${2-}"; KEY_ID="$2"; shift 2 ;;
        -h|--help)
            usage
            exit 0 ;;
        *)
            usage
            fail "unknown argument: $1" ;;
    esac
done

[[ -n "$INPUT" ]] || fail "--input is required"
[[ -n "$OUTPUT" ]] || fail "--output is required"
[[ -n "$PUBLIC_KEY" ]] || fail "--public-key is required"
[[ -n "$VERSION" ]] || fail "--version is required"
[[ -n "$VID" ]] || fail "--vid is required"
[[ -n "$CID" ]] || fail "--cid is required"
[[ -n "$SLOT_SIZE" ]] || fail "--slot-size is required"
[[ -n "$SIGNER_URL" ]] || fail "--signer-url or MICROTUN_SIGNER_URL is required"
[[ -n "$KEY_ID" ]] || fail "--key-id or MICROTUN_SIGNER_KEY_ID is required"

[[ -f "$INPUT" ]] || fail "firmware input not found: $INPUT"
[[ -f "$PUBLIC_KEY" ]] || fail "firmware public key not found: $PUBLIC_KEY"
command -v "$IMGTOOL" >/dev/null 2>&1 || fail "imgtool executable not found: $IMGTOOL"
command -v "$MICROTUN_SIGNER" >/dev/null 2>&1 || fail "microtun-signer executable not found: $MICROTUN_SIGNER"
command -v base64 >/dev/null 2>&1 || fail "base64 executable not found"
command -v wc >/dev/null 2>&1 || fail "wc executable not found"
command -v realpath >/dev/null 2>&1 || fail "realpath executable not found"

OUTPUT_DIR="$(dirname "$OUTPUT")"
mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd -P)"
OUTPUT="$OUTPUT_DIR/$(basename "$OUTPUT")"
INPUT="$(realpath "$INPUT")"
PUBLIC_KEY="$(realpath "$PUBLIC_KEY")"

TEMP_DIR="$(mktemp -d "$OUTPUT_DIR/.microtun-mcuboot.XXXXXX")"
cleanup() {
    rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

DIGEST_PATH="$TEMP_DIR/digest.bin"
SIGNATURE_B64_PATH="$TEMP_DIR/signature.b64"
SIGNATURE_BIN_PATH="$TEMP_DIR/signature.bin"
IMAGE_PATH="$TEMP_DIR/image.bin"

# These options define the bytes covered by the signature. Keep both imgtool
# invocations identical apart from the external-signing options.
COMMON_ARGS=(
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
    --key "$PUBLIC_KEY" \
    --vector-to-sign digest \
    "${COMMON_ARGS[@]}" \
    "$INPUT" "$DIGEST_PATH"

DIGEST_SIZE="$(wc -c < "$DIGEST_PATH" | tr -d '[:space:]')"
[[ "$DIGEST_SIZE" == "32" ]] || fail "imgtool returned a ${DIGEST_SIZE}-byte digest; expected SHA-256"

# Command substitution strips trailing newlines. Removing embedded line wraps
# keeps this portable across common base64 implementations.
DIGEST_B64="$(base64 < "$DIGEST_PATH" | tr -d '\r\n')"
[[ -n "$DIGEST_B64" ]] || fail "failed to base64-encode MCUboot digest"

SIGNATURE_B64="$({
    "$MICROTUN_SIGNER" \
        --url "$SIGNER_URL" \
        sign \
        --key-id "$KEY_ID" \
        --digest "$DIGEST_B64"
} | tr -d '\r\n')"

[[ -n "$SIGNATURE_B64" ]] || fail "microtun-signer returned an empty signature"
[[ "$SIGNATURE_B64" =~ ^[A-Za-z0-9+/]*={0,2}$ ]] || fail "microtun-signer returned a non-base64 signature"
(( ${#SIGNATURE_B64} % 4 == 0 )) || fail "microtun-signer returned malformed base64"
printf '%s\n' "$SIGNATURE_B64" > "$SIGNATURE_B64_PATH"

if ! printf '%s' "$SIGNATURE_B64" | base64 --decode > "$SIGNATURE_BIN_PATH" 2>/dev/null; then
    fail "microtun-signer returned a non-base64 signature"
fi
SIGNATURE_SIZE="$(wc -c < "$SIGNATURE_BIN_PATH" | tr -d '[:space:]')"
[[ "$SIGNATURE_SIZE" == "64" ]] || fail "microtun-signer returned a ${SIGNATURE_SIZE}-byte signature; expected Ed25519 (64 bytes)"

"$IMGTOOL" sign \
    --fix-sig "$SIGNATURE_B64_PATH" \
    --fix-sig-pubkey "$PUBLIC_KEY" \
    "${COMMON_ARGS[@]}" \
    "$INPUT" "$IMAGE_PATH"

"$IMGTOOL" verify --key "$PUBLIC_KEY" "$IMAGE_PATH"
[[ -s "$IMAGE_PATH" ]] || fail "imgtool produced an empty firmware image"

# TEMP_DIR is created beneath OUTPUT_DIR, so mv is an atomic rename on the same
# filesystem when OUTPUT does not already involve an unusual mount boundary.
mv -f "$IMAGE_PATH" "$OUTPUT"
