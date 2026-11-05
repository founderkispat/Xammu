#!/usr/bin/env bash
# End-to-end demonstration of the effectiveness gate on the two sealed runs:
# r6 must fail its policy with exit 1, r7 must pass with exit 0, the SARIF
# document must declare every rule it uses, and both signed deliveries must
# verify against trust/waf-effectiveness.pub. It sends no traffic and reads only
# what is already sealed; nothing under runs/ or publications/ is written.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"

work="${GATE_DEMO_DIR:-dist/gate-demo}"
mkdir -p "$work"

fail() { printf 'gate-demo: %s\n' "$*" >&2; exit 1; }
step() { printf '\n== %s ==\n' "$*"; }

ext=""
if [ "$(go env GOOS)" = "windows" ]; then
	ext=".exe"
fi
bin="$work/xammu${ext}"
policy="policies/effectiveness-reference.yaml"
trust="trust/waf-effectiveness.pub"
r6="runs/waf-effectiveness-2026-11-05-r6"
r7="runs/waf-effectiveness-2026-11-05-r7"

step "build"
go build -o "$bin" ./cmd/xammu
printf 'binary: %s\n' "$bin"

run_gate() { # expected-exit label store format out
	local expected=$1 label=$2 store=$3 format=$4 out=$5
	local log="$work/${label}.log"
	local rc=0
	rm -rf "$out"
	"$bin" gate --store "$store" --policy "$policy" --format "$format" --out "$out" \
		>"$log" 2>&1 || rc=$?
	if [ "$rc" -ne "$expected" ]; then
		sed -n '1,20p' "$log" >&2
		fail "$label: exit $rc, expected $expected (log: $log)"
	fi
	printf '%s: exit %d as expected\n' "$label" "$rc"
}

step "gate policy"
run_gate 1 r6 "$r6" json "$work/r6"
run_gate 0 r7 "$r7" json "$work/r7"
[ -s "$work/r6/gate.json" ] || fail "r6 wrote no gate.json"
[ -s "$work/r7/gate.json" ] || fail "r7 wrote no gate.json"

step "sarif shape"
run_gate 0 r7-sarif "$r7" sarif "$work/r7-sarif"
sarif="$work/r7-sarif/results.sarif"
[ -s "$sarif" ] || fail "no results.sarif was written"
for key in '"$schema": "https://json.schemastore.org/sarif-2.1.0.json"' \
	'"version": "2.1.0"' '"driver"' '"rules"' '"results"'; do
	grep -qF -- "$key" "$sarif" || fail "the SARIF document lacks $key"
done
# Every rule a result cites must be declared in the driver's rule table; a
# result that points at an undeclared rule is not ingestible by Code Scanning.
# A passing run cites none, and that is a valid shape too.
used=$(grep -o '"ruleId": "[^"]*"' "$sarif" | sed 's/.*"ruleId": "//; s/"$//' | sort -u || true)
for id in $used; do
	grep -qF "\"id\": \"$id\"" "$sarif" || fail "SARIF cites undeclared rule $id"
done
if [ -n "$used" ]; then
	printf 'rules cited: %s\n' "$(printf '%s ' $used)"
else
	printf 'rules cited: none (the run passed every check)\n'
fi

# The failing run must carry a result for the rule it failed.
failed_sarif="$work/r6-sarif/results.sarif"
run_gate 1 r6-sarif "$r6" sarif "$work/r6-sarif"
grep -qF '"ruleId": "XAMMU-EFF-TPR"' "$failed_sarif" ||
	fail "the failing run's SARIF does not cite XAMMU-EFF-TPR"
grep -qF '"level": "error"' "$failed_sarif" ||
	fail "the failing run's SARIF does not carry an error level"

step "signed deliveries"
for run in waf-effectiveness-2026-11-05-r6 waf-effectiveness-2026-11-05-r7; do
	dir="publications/$run"
	[ -f "$dir/publication.json" ] || fail "$dir/publication.json is absent"
	rc=0
	"$bin" verify --publication "$dir" --trust-key "$trust" >"$work/verify-$run.log" 2>&1 || rc=$?
	if [ "$rc" -ne 0 ]; then
		cat "$work/verify-$run.log" >&2
		fail "$dir did not verify with $trust"
	fi
	printf '%s: envelope verifies against %s\n' "$run" "$trust"
done

printf '\ngate-demo: r6 fails its policy, r7 passes it, the SARIF documents are shaped, '
printf 'and both deliveries verify.\n'
printf 'what it does not prove: that the numbers describe any WAF other than the reference fixture.\n'
