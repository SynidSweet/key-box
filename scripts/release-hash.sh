#!/usr/bin/env bash
# The content hash H of release commit C, as the bootstrap computes it: downloads codeload's tarball of C, takes the H line out of
# deploy/cloud-init.yaml AT C (found by its text, so it cannot drift), runs it over the extracted tree, cross-checks the result with
# src/pure/release-hash.ts, prints H, and fails on any difference.   bash scripts/release-hash.sh <40-hex commit>
set -euo pipefail
C=${1:-}
[[ $C =~ ^[0-9a-f]{40}$ ]] || { echo "usage: release-hash.sh <40-hex commit>" >&2; exit 2; }
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
mkdir -p "$HOME/.cache"
T=$(mktemp -d "$HOME/.cache/key-box-release-hash.XXXXXX")
trap 'rm -rf "$T"' EXIT
curl --proto '=https' -fsSLo "$T/src.tar.gz" "https://codeload.github.com/SynidSweet/key-box/tar.gz/$C"
mkdir "$T/src" && tar xzf "$T/src.tar.gz" -C "$T/src" --strip-components=1 --no-same-owner
# The bootstrap's own lines, found by text: the tree check and the H line.
LINES=$(grep -E '^ +(\[ -z "\$\(cd src && find|H=\$\(cd src && find)' "$T/src/deploy/cloud-init.yaml" | sed 's/^ *//')
[ "$(printf '%s\n' "$LINES" | wc -l)" -eq 2 ] || { echo "release-hash: the bootstrap's tree check and H line were not found exactly once each" >&2; exit 1; }
SCRIPT=$T/h.sh
printf 'set -eu\ncd "$1"\n%s\necho "$H"\n' "$LINES" > "$SCRIPT"
H=$(sh "$SCRIPT" "$T")
[[ $H =~ ^[0-9a-f]{64}$ ]] || { echo "release-hash: the bootstrap's line gave no hash" >&2; exit 1; }
read -r H2 N < <(node "$HERE/release-hash-tree.ts" "$T/src")
if [ "$H" != "$H2" ]; then echo "release-hash: MISMATCH bootstrap line $H, release-hash.ts $H2" >&2; exit 1; fi
echo "$H"
echo "files: $N" >&2
