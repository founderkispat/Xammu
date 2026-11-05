#!/usr/bin/env bash
# Internal acceptance run. It executes every check the certification dossier
# cites and writes one evidence file under dist/. It does not certify anything
# externally: the last lines of the file say what the run does not prove.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"

stamp=$(date -u +%Y%m%dT%H%M%SZ)
mkdir -p dist
evidence="dist/certification-${stamp}.txt"
: > "$evidence"

log() { printf '%s\n' "$*" | tee -a "$evidence"; }
run() {
	printf '\n$ %s\n' "$*" >>"$evidence"
	if "$@" >>"$evidence" 2>&1; then
		printf '  -> ok\n' | tee -a "$evidence"
	else
		printf '  -> FAILED: %s\n' "$*" | tee -a "$evidence" >&2
		log ""
		log "RESULT: FAILED"
		log "evidence: $evidence"
		exit 1
	fi
}

log "XAMMU internal certification evidence"
log "generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
log "host: $(uname -srm)"
log "go: $(go version)"
log "tool: $(go run ./cmd/xammu version | head -1)"

log ""
log "== 1. source hygiene and full suite =="
unformatted=$(gofmt -l cmd internal)
if [ -n "$unformatted" ]; then
	log "gofmt lists files that need formatting:"
	log "$unformatted"
	log "RESULT: FAILED"
	exit 1
fi
log "gofmt: no file under cmd/ or internal/ needs formatting"
run go vet ./...
run go build ./...
run go test ./... -count=1
run go run ./cmd/xammu corpus check --corpus corpus
run go run ./cmd/xammu effectiveness check --corpus corpus/effectiveness

log ""
log "== 2. sealed demonstrations verify against their own manifests =="
run go run ./cmd/xammu verify --run demo-lab \
	--authorization AUTH-SMOKE-LOCAL-001 --authorizations authorizations \
	--issuer-keyring trust/issuers \
	--corpus corpus --class sqli --vector query,body_json,cookie \
	--trust-key trust/demo-lab.pub
run go run ./cmd/xammu verify --run demo-origin \
	--authorization AUTH-SMOKE-ORIGIN-001 --authorizations authorizations \
	--issuer-keyring trust/issuers \
	--corpus corpus --trust-key trust/demo-origin.pub
run go run ./cmd/xammu verify --store runs/waf-effectiveness-2026-11-05-r3 --rederive \
	--authorization authorizations/effectiveness-local.json \
	--issuer-keyring trust/issuers \
	--trust-key trust/waf-effectiveness.pub

log ""
log "== 3. client annex renders in both languages and formats =="
annexdir=$(mktemp -d)
trap 'rm -rf "$annexdir"' EXIT
run go run ./cmd/xammu report --run demo-lab \
	--authorization AUTH-SMOKE-LOCAL-001 --authorizations authorizations \
	--issuer-keyring trust/issuers \
	--corpus corpus --format annex --lang es \
	--client "Cliente de certificación" --engagement "Aceptación interna" \
	--prepared-by "Izkuna" --out "$annexdir"
run go run ./cmd/xammu report --run demo-origin \
	--authorization AUTH-SMOKE-ORIGIN-001 --authorizations authorizations \
	--issuer-keyring trust/issuers \
	--corpus corpus --format annex-html --lang en \
	--client "Certification client" --engagement "Internal acceptance" \
	--prepared-by "Izkuna" --out "$annexdir"
for f in annex-es.md annex-en.html; do
	if [ ! -s "$annexdir/$f" ]; then
		log "the annex renderer did not produce $f"
		log "RESULT: FAILED"
		exit 1
	fi
done
{
	printf '\nannex digests:\n'
	sha256sum "$annexdir"/annex-es.md "$annexdir"/annex-en.html
} >>"$evidence" 2>&1
log "annexes: annex-es.md and annex-en.html rendered and hashed"

log ""
log "== 4. reproducible release build =="
if ! ./scripts/release.sh >>"$evidence" 2>&1; then
	log "release build failed or was not reproducible"
	log "RESULT: FAILED"
	exit 1
fi
log "release: two builds compared byte for byte; hash written under dist/"

log ""
log "== 5. source anchor =="
source_hash=$(
	find cmd internal corpus lab docs scripts tools authorizations trust go.mod \
		README.md LICENSE runs/demo-lab runs/demo-origin runs/waf-effectiveness-2026-11-05-r3 \
		-type f -print0 | sort -z | xargs -0 sha256sum | sha256sum | cut -d' ' -f1
)
log "source tree sha256: ${source_hash}"
log "anchor: this hash covers every source, document, script, authorization and"
log "        demonstration bundle in the delivery; a byte changed without a new"
log "        run makes two certifications incomparable, not equivalent."

log ""
log "RESULT: PASSED"
log ""
log "what this run does not prove:"
log "- that the readings are correct: verify proves the evidence commits to itself"
log "- who signed the bundles: trust/ was pinned from the manifests themselves (TOFU), not"
log "  obtained through an independent channel"
log "- that the tool is externally certified: this is Izkuna's internal acceptance"
log "- that every environment reproduces the build: only this host was exercised"
log ""
log "evidence: $evidence"
