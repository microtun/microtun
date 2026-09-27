#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
    cat <<'USAGE'
Usage: scripts/bump-version.sh [--dry-run] <version>

Set the Microtun release version everywhere it is owned by the repository:
  - Cargo.toml [workspace.package].version
  - firmware/Cargo.toml [workspace.package].version
  - debian/changelog (release old stanza, then open new UNRELEASED stanza via dch)
  - Cargo.lock and firmware/Cargo.lock (workspace package versions only, via
    cargo update --workspace; third-party dependencies are left as locked)

<version> must be canonical release SemVer X.Y.Z. A leading "v" is accepted
and stripped.

Options:
  -n, --dry-run   Validate and show what would change without modifying files.
  -h, --help      Show this help.
USAGE
}

fail() {
    echo "error: $*" >&2
    exit 1
}

dry_run=0
args=()
while (($#)); do
    case "$1" in
        -n|--dry-run)
            dry_run=1
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        --)
            shift
            args+=("$@")
            break
            ;;
        -*)
            echo "error: unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
        *)
            args+=("$1")
            ;;
    esac
    shift
done

if ((${#args[@]} != 1)); then
    usage >&2
    exit 2
fi

new_version="${args[0]#v}"
semver_re='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'
if [[ ! "$new_version" =~ $semver_re ]]; then
    echo "error: version must be canonical release SemVer X.Y.Z: ${args[0]}" >&2
    exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

ROOT_MANIFEST="$REPO_ROOT/Cargo.toml"
FIRMWARE_MANIFEST="$REPO_ROOT/firmware/Cargo.toml"
CHANGELOG="$REPO_ROOT/debian/changelog"
CHECK_SCRIPT="$REPO_ROOT/scripts/check-release-tag.sh"

for path in "$ROOT_MANIFEST" "$FIRMWARE_MANIFEST" "$CHANGELOG" "$CHECK_SCRIPT"; do
    [[ -f "$path" ]] || fail "required file not found: $path"
done

command -v awk >/dev/null 2>&1 || fail "awk is required"
command -v dpkg-parsechangelog >/dev/null 2>&1 || fail "dpkg-parsechangelog is required"
command -v dpkg >/dev/null 2>&1 || fail "dpkg is required"

workspace_version() {
    local manifest="$1"
    local version

    version="$({
        awk '
            /^\[workspace\.package\][[:space:]]*$/ { in_workspace_package = 1; next }
            /^\[/ && in_workspace_package { exit }
            in_workspace_package && /^[[:space:]]*version[[:space:]]*=/ {
                line = $0
                sub(/^[^=]*=[[:space:]]*/, "", line)
                sub(/[[:space:]]*#.*/, "", line)
                gsub(/^[[:space:]]*"|"[[:space:]]*$/, "", line)
                print line
                exit
            }
        ' "$manifest"
    } || true)"

    [[ -n "$version" ]] || fail "could not read [workspace.package].version from $manifest"
    printf '%s\n' "$version"
}

set_workspace_version() {
    local manifest="$1"
    local version="$2"
    local tmp

    tmp="$(mktemp "${manifest}.tmp.XXXXXX")"

    if ! awk -v version="$version" '
        BEGIN {
            in_workspace_package = 0
            updated = 0
        }

        /^\[workspace\.package\][[:space:]]*$/ {
            in_workspace_package = 1
            print
            next
        }

        /^\[/ && in_workspace_package {
            in_workspace_package = 0
        }

        in_workspace_package && /^[[:space:]]*version[[:space:]]*=/ {
            if (!sub(/"[^"]+"/, "\"" version "\"")) {
                exit 2
            }
            updated++
        }

        { print }

        END {
            if (updated != 1) {
                exit 3
            }
        }
    ' "$manifest" >"$tmp"; then
        rm -f "$tmp"
        fail "could not update [workspace.package].version in $manifest"
    fi

    # Write through the existing file so its ownership and mode are preserved.
    cat "$tmp" >"$manifest"
    rm -f "$tmp"
}

old_version="$(workspace_version "$ROOT_MANIFEST")"
firmware_version="$(workspace_version "$FIRMWARE_MANIFEST")"

if [[ "$firmware_version" != "$old_version" ]]; then
    fail "workspace versions differ: root='$old_version', firmware='$firmware_version'"
fi

debian_version="$(dpkg-parsechangelog -l"$CHANGELOG" -SVersion)"
debian_distribution="$(dpkg-parsechangelog -l"$CHANGELOG" -SDistribution)"

if [[ "$debian_version" != "$old_version" ]]; then
    fail "debian/changelog version '$debian_version' differs from workspace version '$old_version'"
fi

if [[ "$debian_distribution" != "UNRELEASED" ]]; then
    fail "top debian/changelog stanza is '$debian_distribution', not UNRELEASED"
fi

if [[ "$new_version" == "$old_version" ]]; then
    echo "version is already $new_version"
    "$CHECK_SCRIPT"
    exit 0
fi

if ! dpkg --compare-versions "$new_version" gt "$old_version"; then
    fail "new version '$new_version' must be greater than '$old_version'"
fi

printf 'Version bump: %s -> %s\n' "$old_version" "$new_version"
printf '  debian/changelog: release %s, then open %s UNRELEASED\n' "$old_version" "$new_version"
printf '  %s\n' \
    "Cargo.toml" \
    "firmware/Cargo.toml" \
    "Cargo.lock" \
    "firmware/Cargo.lock"

if ((dry_run)); then
    echo "dry run: no files changed"
    exit 0
fi

command -v cargo >/dev/null 2>&1 || fail "cargo is required to refresh Cargo.lock files"
command -v dch >/dev/null 2>&1 || fail "dch is required (install the devscripts package)"

# Back up every file this script can modify. If anything fails after editing,
# restore the exact pre-bump contents rather than leaving a partial bump.
backup_dir="$(mktemp -d)"
committed=0
backup_files=(
    "Cargo.toml"
    "firmware/Cargo.toml"
    "debian/changelog"
)
[[ -f "$REPO_ROOT/Cargo.lock" ]] && backup_files+=("Cargo.lock")
[[ -f "$REPO_ROOT/firmware/Cargo.lock" ]] && backup_files+=("firmware/Cargo.lock")

for rel in "${backup_files[@]}"; do
    mkdir -p "$backup_dir/$(dirname "$rel")"
    cp -p "$REPO_ROOT/$rel" "$backup_dir/$rel"
done

restore_on_error() {
    local status=$?

    if ((status != 0 && committed == 0)); then
        echo "error: version bump failed; restoring modified files" >&2
        for rel in "${backup_files[@]}"; do
            cp -p "$backup_dir/$rel" "$REPO_ROOT/$rel"
        done
    fi

    rm -rf "$backup_dir"
}
trap restore_on_error EXIT

# Finalize the current UNRELEASED stanza first. With the changelog release
# heuristic, dch --release changes UNRELEASED to the distribution from the
# previous stanza (or Debian's default for the first release) and refreshes
# the trailer timestamp. Passing an empty change suppresses the editor.
(
    cd "$REPO_ROOT"
    dch --no-conf \
        --release-heuristic changelog \
        --release \
        --maintmaint \
        --no-auto-nmu \
        ""

    # Now that the previous version is released, --newversion creates a fresh
    # stanza instead of rewriting it. Keep that new development stanza
    # explicitly UNRELEASED and empty, ready for subsequent changelog entries.
    dch --no-conf \
        --release-heuristic changelog \
        --newversion "$new_version" \
        --distribution UNRELEASED \
        --maintmaint \
        --no-auto-nmu \
        --preserve \
        ""
)

set_workspace_version "$ROOT_MANIFEST" "$new_version"
set_workspace_version "$FIRMWARE_MANIFEST" "$new_version"

# Refresh only the workspace's own packages in each lockfile, so they record the
# new version. Every third-party dependency stays pinned exactly as locked:
# dependency upgrades belong in their own reviewed change, not in a version
# bump. The firmware workspace pulls the host crates in as path dependencies,
# which Cargo re-reads from their manifests and updates here too.
cargo update --workspace --manifest-path "$ROOT_MANIFEST"
cargo update --workspace --manifest-path "$FIRMWARE_MANIFEST"

# Verify both updated lockfiles are accepted without further resolution, then
# run the repository's existing consistency check.
for manifest in "$ROOT_MANIFEST" "$FIRMWARE_MANIFEST"; do
    cargo metadata \
        --manifest-path "$manifest" \
        --format-version 1 \
        --no-deps \
        --locked \
        >/dev/null
done

"$CHECK_SCRIPT"

committed=1
echo "bumped version to $new_version"
