#!/usr/bin/env bash
# Shared checks for the evidence scripts. This file is sourced, never executed.

# go_pin prints the Go version the CI workflow pins. There is one source of truth:
# the workflow, so the local scripts cannot drift from the runner.
go_pin() {
	sed -n 's/^  GO_VERSION: "\([0-9][0-9.]*\)"$/\1/p' .github/workflows/ci.yml
}

# require_go_pin refuses to produce acceptance evidence with a toolchain other
# than the one the workflow pins. A different compiler can change the binary,
# the stdlib vulnerabilities it carries and the reproducibility claim, so a
# mismatch is a failure, not a warning to read later.
require_go_pin() {
	local pin actual
	pin=$(go_pin)
	if [ -z "$pin" ]; then
		printf 'cannot read GO_VERSION from .github/workflows/ci.yml\n' >&2
		return 1
	fi
	if ! command -v go >/dev/null 2>&1; then
		printf 'go is not on PATH; the workflow pins go%s\n' "$pin" >&2
		return 1
	fi
	actual=$(go env GOVERSION)
	if [ "$actual" != "go${pin}" ]; then
		printf 'toolchain mismatch: this host runs %s, the workflow pins go%s.\n' \
			"$actual" "$pin" >&2
		printf 'Install the pinned toolchain and put it first on PATH; acceptance evidence ' >&2
		printf 'must name the toolchain that produced it.\n' >&2
		return 1
	fi
	return 0
}
