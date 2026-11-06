#!/usr/bin/env bash
# Native Go fuzzing with a bounded budget. Each target runs its versioned seed
# corpus first (that is what `go test` does without -fuzz), then explores for the
# requested time. A crash writes a reproducer under testdata/fuzz/<Name>/; letting
# that file exist is the point, so this script never deletes it.
#
# Usage: scripts/fuzz.sh [duration]   (default 30s per target)
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"

duration="${1:-30s}"
if ! [[ "$duration" =~ ^[0-9]+(s|m)$ ]]; then
	echo "fuzz: duration must look like 10s or 2m, got '$duration'" >&2
	exit 2
fi

# package|target, one per line. Keep this list equal to the fuzz functions in the
# tree: a target that is added there and not here silently stops being exercised.
targets=(
	"internal/corpus|FuzzParseItem"
	"internal/integrity|FuzzParseManifest"
	"internal/httpclient|FuzzCheckRequest"
	"cmd/xammu|FuzzDecodeHexKey"
)

status=0
for entry in "${targets[@]}"; do
	pkg="${entry%%|*}"
	name="${entry##*|}"
	printf '\n== %s (%s) ==\n' "$name" "$duration"
	if ! go test "./${pkg}" -run '^$' -fuzz "^${name}\$" -fuzztime "$duration"; then
		echo "fuzz: ${name} failed; the reproducer is under ${pkg}/testdata/fuzz/${name}" >&2
		status=1
	fi
done
exit "$status"
