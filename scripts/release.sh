#!/usr/bin/env bash
# Build the release binary reproducibly: no VCS stamping, no workspace paths in
# the binary, no build id, CGO disabled. The script builds twice and refuses to
# publish a hash if the two builds differ, because a hash of a non-reproducible
# artifact is only a random number.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"

version=$(sed -n 's/^const ToolVersion = "xammu-\([^"]*\)"$/\1/p' internal/integrity/manifest.go)
if [ -z "$version" ]; then
	echo "release: cannot read ToolVersion from internal/integrity/manifest.go" >&2
	exit 1
fi

goos="${GOOS:-$(go env GOOS)}"
goarch="${GOARCH:-$(go env GOARCH)}"
ext=""
if [ "$goos" = "windows" ]; then
	ext=".exe"
fi

mkdir -p dist
out="dist/xammu-${version}-${goos}-${goarch}${ext}"

export CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch"
flags=(-trimpath -buildvcs=false -ldflags "-s -w -buildid=" -o)
go build "${flags[@]}" "$out" ./cmd/xammu
go build "${flags[@]}" "$out.repro" ./cmd/xammu

if ! cmp -s "$out" "$out.repro"; then
	echo "release: two builds of the same source differ; refusing to publish a hash" >&2
	rm -f "$out.repro"
	exit 1
fi
rm -f "$out.repro"

hash=$(sha256sum "$out" | cut -d' ' -f1)
printf '%s  %s\n' "$hash" "$out" | tee "$out.sha256"

"$out" version 2>/dev/null | head -1 || true
