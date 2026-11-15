#!/usr/bin/env bash
# Build the release bundle that threatfalcon-server-deploy installs.
#
#   deploy/server/package-bundle.sh <commit-sha> [<cargo-release-dir>] [<out-dir>]
#
# The bundle contains exactly REVISION, bin/threatfalcon-server and
# bin/threatfalcon (the investigation CLI, for use on the server).
set -euo pipefail

rev=${1:?usage: package-bundle.sh <commit-sha> [<cargo-release-dir>] [<out-dir>]}
release_dir=${2:-target/release}
out_dir=${3:-dist}
readonly BUNDLE_NAME="threatfalcon-server-linux-x86_64.tar.gz"

[[ $rev =~ ^[0-9a-f]{40}$ ]] || { echo "revision must be a full 40-character commit SHA" >&2; exit 1; }

stage=$(mktemp -d)
trap 'rm -rf -- "$stage"' EXIT
install -d "$stage/bin"
install -m 0755 "$release_dir/threatfalcon-server" "$stage/bin/threatfalcon-server"
install -m 0755 "$release_dir/threatfalcon" "$stage/bin/threatfalcon"
printf '%s\n' "$rev" >"$stage/REVISION"

mkdir -p "$out_dir"
tar --owner=0 --group=0 --numeric-owner -C "$stage" -czf "$out_dir/$BUNDLE_NAME" \
    REVISION bin/threatfalcon-server bin/threatfalcon
(cd "$out_dir" && sha256sum "$BUNDLE_NAME" >"$BUNDLE_NAME.sha256")
cat "$out_dir/$BUNDLE_NAME.sha256"
