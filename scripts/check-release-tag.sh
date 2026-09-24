#!/usr/bin/env bash
set -euo pipefail

if (( $# > 1 )); then
    echo "usage: $0 [tag]" >&2
    exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

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

    if [[ -z "$version" ]]; then
        echo "error: could not read [workspace.package].version from $manifest" >&2
        exit 1
    fi

    printf '%s\n' "$version"
}

root_version="$(workspace_version "$REPO_ROOT/Cargo.toml")"
examples_version="$(workspace_version "$REPO_ROOT/examples/Cargo.toml")"

if [[ "$root_version" != "$examples_version" ]]; then
    echo "error: workspace versions differ: root='$root_version', examples='$examples_version'" >&2
    exit 1
fi

debian_version="$(sed -nE '1s/^[^[:space:]]+[[:space:]]+\(([^)]+)\)[[:space:]]+.*/\1/p' "$REPO_ROOT/debian/changelog")"
if [[ -z "$debian_version" ]]; then
    echo "error: could not read package version from debian/changelog" >&2
    exit 1
fi

if [[ "$root_version" != "$debian_version" ]]; then
    echo "error: workspace version '$root_version' differs from debian/changelog version '$debian_version'" >&2
    exit 1
fi

echo "workspace version: $root_version"
echo "debian package version: $debian_version"

# With no tag, this is the CI workspace/package-version consistency check.
tag="${1:-}"
if [[ -z "$tag" ]]; then
    exit 0
fi

# Canonical vMAJOR.MINOR.PATCH only, with no leading zeroes, 
# pre-release, or build metadata.
semver_tag_re='^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'
if [[ ! "$tag" =~ $semver_tag_re ]]; then
    echo "error: release tag '$tag' must use canonical vX.Y.Z SemVer format" >&2
    exit 1
fi

version="${tag#v}"
if [[ "$version" != "$root_version" ]]; then
    echo "error: release tag '$tag' does not match workspace version '$root_version' (expected 'v$root_version')" >&2
    exit 1
fi

if [[ "$version" != "$debian_version" ]]; then
    echo "error: release tag '$tag' does not match debian/changelog version '$debian_version' (expected 'v$debian_version')" >&2
    exit 1
fi

echo "release tag: $tag"
