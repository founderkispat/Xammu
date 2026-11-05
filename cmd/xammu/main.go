// Command xammu is the only surface of this tool that may put a probe on a wire,
// and it may do so only through an authorization someone signed.
//
// The commands are not interchangeable, and the difference is the point:
//
//   - playbook builds and validates a plan and sends nothing, so an operator can see
//     what would be asked before anything is asked.
//   - run executes that plan through the single egress the authorization covers,
//     journals every exchange, derives the findings and publishes the C-15 report.
//     It refuses to send unless the operator names the authorization they are holding.
//   - report, verify and validate read a sealed bundle. They cannot write to it, they
//     re-derive from it, and they say so when the re-derivation disagrees.
//
// Nothing here takes a target, a scope or a budget from the command line that the
// authorization does not already permit: flags narrow, they never widen.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"xammu/internal/gate"
)

const usageText = `xammu -- defensive-behaviour discovery through one authorized egress

usage:
  xammu version
  xammu authorization sign --authorization FILE --signing-key FILE
  xammu corpus  check    --corpus DIR [--partition NAME]
  xammu playbook         --authorization FILE --issuer-keyring DIR --corpus DIR [plan flags]
  xammu run              --authorization FILE --authorize REF --issuer-keyring DIR --run ID [plan flags]
  xammu effectiveness check  --corpus DIR
  xammu effectiveness tampers
  xammu effectiveness run    --authorization FILE --authorize REF --issuer-keyring DIR --run ID [--corpus DIR]
  xammu effectiveness report --run ID | --store DIR [--format F] [--rederive]
  xammu gate             (--store DIR | --run ID) --policy FILE --format json|yaml|sarif|markdown|annex|all [--out DIR]
  xammu report           --run ID | --store DIR --authorization FILE --issuer-keyring DIR --corpus DIR [--format F]
  xammu verify           --run ID | --store DIR [--trust-key FILE] [--authorization FILE --issuer-keyring DIR] [--rederive]
  xammu verify           --publication DIR [--trust-key FILE] [--store DIR | --run ID]
  xammu validate         --finding REF --run ID --authorization FILE --issuer-keyring DIR --corpus DIR
  xammu lab              scenarios | test --scenario NAME [--apply]

trust flags (an authorization is refused until one of these verifies it):
  --issuer-keyring DIR  directory of *.pub files, each one hex ed25519 public key;
                        required by every command that loads a C-09 or C-10, and never
                        discovered from the authorization or from a bundle

plan flags (they narrow the authorization, never widen it):
  --corpus DIR       corpus tree to load through the inertness gate (default "corpus")
  --partition NAME   where probes come from (default "development")
  --controls NAME    where calibration traffic comes from (default "calibration")
  --target ORIGIN    one of the authorized origins; the default is the first listed
  --budget N         requests this run may spend, at most the authorized maximum
  --class LIST       comma-separated attack classes to plan (default: all authorized)
  --vector LIST      comma-separated transports to plan (default: all authorized)
  --encoding LIST    comma-separated encodings to plan (default: all authorized)
  --path P           endpoint probes are placed against (default "/api/search")
  --query-param, --body-field, --header-name, --cookie-name, --media-type
                     the slot names a probe is placed into
  --sensitive-header NAME
                     withhold this response header's value from the evidence; repeatable,
                     and it only adds to the base cookie/credential list

where the evidence lives, and who signs it:
  --run ID           the run a command writes or reads
  --runs-dir DIR     where bundles are looked up by --run (default "runs"; the directory a
                     published reproduction command assumes, so name it when it differs)
  --store DIR        one bundle directory directly, instead of a --runs-dir lookup
  --authorizations DIR
                     searched when --authorization names a reference rather than a file
  --signing-key FILE ed25519 seed file kept outside the bundle, created 0600 if absent
  --generated-by NAME operator named in the evidence block
  --round LABEL      round name (default "round-1"); a second round needs its own C-09

run only (nothing is sent until all of these are satisfied):
  --authorize REF    repeat the reference of the permission you are holding
  --validation FILE  C-10 authorization for a hypothesis-testing round
  --parent-run ID    the run this round continues
  --circuit-threshold N  consecutive transport failures that pause the run

read flags:
  --format F         human (markdown), json, both, annex (Markdown) or annex-html
  --out DIR          write the document instead of printing it; an annex is named annex-LANG.md|.html
  --lang es|en       annex language (default en); evidence fields stay verbatim from C-16
  --client NAME      annex only: client named in the engagement block
  --engagement NAME  annex only: engagement label
  --prepared-by NAME annex only: who prepared the annex
  --cell REF         print one measured cell instead of the document
  --finding REF      finding to re-derive; repeatable
  --trust-key FILE   hex ed25519 public key this operator trusts
  --rederive         re-issue the report from the sealed evidence and compare it

gate flags:
  --policy FILE      xammu.policy/v1 thresholds; required, and never discovered from the bundle
  --format F         json, yaml, sarif, markdown (report.md), annex (annex-LANG.md) or all
  --out DIR          write the document instead of printing it; --format all requires it and writes
                     gate.json, gate.yaml, results.sarif, report.md, both annexes and the envelope
  --signing-key FILE ed25519 seed that signs publication.json; --format all only, never copied out
  --lang es|en       --format annex only; --format all writes both languages
  --prepared-by NAME preparer named in the report and the annexes; the bundle stays anonymous
  --trust-key FILE   anchor the bundle signature to this hex ed25519 public key
  gate exit codes:   0 every applicable check passed, 1 a check failed, 2 the gate could not evaluate.

verify --publication flags:
  --publication DIR  verify a signed delivery: envelope signature, every listed file, gate.json
                     against its embedded policy, and the source bundle's manifest digest
  --store DIR        the source bundle, when it does not sit where the envelope says
  --trust-key FILE   anchor both the envelope and the source manifest to this key

laboratory flags:
  --lab-dir DIR      where the laboratory lives (default "lab")
  --scenario NAME    the scenario to preview or run
  --apply            bring the laboratory up; without it lab test only previews
  --teardown         take the laboratory down again after the checks

exit codes: 0 succeeded, 1 refused or failed, 2 the command line was not usable.
`

// errUsage marks a command line that could not be understood. It exits 2 rather
// than 1 so a script can tell "the operator typed the wrong thing" apart from
// "the tool refused", which is the difference between a bug in the invocation and
// a finding about the target.
var errUsage = errors.New("the command line is not usable")

// cli is where a command writes. The split between out and err is not cosmetic:
// a refusal that belongs to the tool goes to stderr, and the evidence an operator
// asked for goes to stdout, so `xammu report --run ID > report.txt` cannot capture
// an error message as if it were the document.
type cli struct {
	out io.Writer
	err io.Writer
}

func main() {
	os.Exit(dispatch(os.Args[1:], os.Stdout, os.Stderr))
}

// dispatch is the whole command table. It returns the process exit code so the
// behaviour is testable without spawning anything.
func dispatch(argv []string, stdout, stderr io.Writer) int {
	c := &cli{out: stdout, err: stderr}
	if len(argv) == 0 {
		fmt.Fprint(stderr, usageText)
		return 2
	}
	cmd := argv[0]
	rest := argv[1:]
	var err error
	switch cmd {
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usageText)
		return 0
	case "version":
		err = cmdVersion(c, rest)
	case "authorization":
		err = cmdAuthorization(c, rest)
	case "corpus":
		err = cmdCorpus(c, rest)
	case "playbook":
		err = cmdPlaybook(c, rest)
	case "run":
		ctx, stop := contextWithStop()
		defer stop()
		err = cmdRun(ctx, c, rest)
	case "effectiveness":
		ctx, stop := contextWithStop()
		defer stop()
		err = cmdEffectiveness(ctx, c, rest)
	case "gate":
		err = cmdGate(c, rest)
	case "report":
		err = cmdReport(c, rest)
	case "verify":
		err = cmdVerify(c, rest)
	case "validate":
		err = cmdValidate(c, rest)
	case "lab":
		err = cmdLab(c, rest)
	default:
		fmt.Fprintf(stderr, "xammu: unknown command %q\n\n%s", cmd, usageText)
		return 2
	}
	if err != nil {
		if errors.Is(err, gate.ErrFailed) {
			// cmdGate already published the failing check summary. Exit 1 is a
			// result about the target, not a tool error.
			return 1
		}
		if errors.Is(err, errUsage) || errors.Is(err, flag.ErrHelp) {
			fmt.Fprintf(stderr, "xammu: %v\n", err)
			return 2
		}
		if errors.Is(err, gate.ErrUnusable) {
			fmt.Fprintf(stderr, "xammu: %v\n", err)
			return 2
		}
		fmt.Fprintf(stderr, "xammu: %v\n", err)
		return 1
	}
	return 0
}

// contextWithStop gives an operator a way to stop a run that is asking someone's
// system for traffic. The executor turns the cancellation into an operator halt, so
// the run records that it was stopped rather than pretending it finished.
func contextWithStop() (context.Context, func()) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	return ctx, stop
}
