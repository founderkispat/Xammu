#!/usr/bin/env bash
# Local mirror of .github/workflows/ci.yml. It runs every check that does not
# need a GitHub runner and writes one evidence file under dist/. A check whose
# tool is absent prints SKIP and is counted in the final result; it is never
# reported as a pass.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"

stamp=$(date -u +%Y%m%dT%H%M%SZ)
mkdir -p dist
evidence="dist/ci-local-${stamp}.txt"
: > "$evidence"
skips=0

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
skip() {
	skips=$((skips + 1))
	log "SKIP: $*"
}

log "XAMMU local CI evidence"
log "generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
log "host: $(uname -srm)"
log "go: $(go version) (the workflow pins 1.27.3)"
log "gitleaks: $(gitleaks version 2>/dev/null || echo 'not installed')"

log ""
log "== 1. formatting and vet =="
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

log ""
log "== 2. full suite =="
run go test ./... -count=1
if [ "$(go env CGO_ENABLED)" = "1" ] && command -v gcc >/dev/null 2>&1; then
	run go test -race ./... -count=1
else
	skip "go test -race: cgo or a C compiler is unavailable on this host; the workflow runs it on ubuntu-latest"
fi

log ""
log "== 2b. fuzzing (bounded) =="
run ./scripts/fuzz.sh 10s

log ""
log "== 3. govulncheck =="
if command -v govulncheck >/dev/null 2>&1; then
	run govulncheck ./...
else
	skip "govulncheck: not on PATH; install with 'go install golang.org/x/vuln/cmd/govulncheck@v1.9.0'"
fi

log ""
log "== 4. gitleaks (tree and history) =="
if command -v gitleaks >/dev/null 2>&1; then
	run gitleaks dir --no-banner --redact .
	run gitleaks git --no-banner --redact --log-opts="--all" .
else
	skip "gitleaks: not on PATH; the workflow downloads 8.30.1 and checks its sha256"
fi

log ""
log "== 5. reproducible release build =="
run ./scripts/release.sh

log ""
log "== 6. gate demonstration =="
run ./scripts/gate-demo.sh

log ""
log "== 7. SBOM =="
if command -v syft >/dev/null 2>&1; then
	version=$(sed -n 's/^const ToolVersion = "xammu-\([^"]*\)"$/\1/p' internal/integrity/manifest.go)
	goos=$(go env GOOS)
	goarch=$(go env GOARCH)
	ext=""
	if [ "$goos" = "windows" ]; then
		ext=".exe"
	fi
	binary="dist/xammu-${version}-${goos}-${goarch}${ext}"
	sbom="dist/xammu-${version}-${goos}-${goarch}-sbom.cdx.json"
	run syft scan "$binary" --output "cyclonedx-json=$sbom"
	sha256sum "$sbom" | tee -a "$evidence"
else
	skip "SBOM: syft is not on PATH; the workflow generates CycloneDX JSON with anchore/sbom-action"
fi
if command -v cosign >/dev/null 2>&1; then
	skip "keyless signing: cosign needs the GitHub OIDC token; it runs only in the release job on a v* tag"
else
	skip "keyless signing: cosign is not installed; it runs only in the release job on a v* tag"
fi

log ""
if [ "$skips" -eq 0 ]; then
	log "RESULT: PASSED"
else
	log "RESULT: PASSED WITH ${skips} SKIPS (listed above)"
fi
log ""
log "what this run does not prove:"
log "- that .github/workflows/ci.yml runs green on GitHub: without a push, the evidence is this file"
log "- that the release artifacts were signed: keyless signing needs the workflow's OIDC token"
log "- that another OS reproduces the build: the two builds run on this host only"
log ""
log "evidence: $evidence"
