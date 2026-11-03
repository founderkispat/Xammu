package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"xammu/internal/contracts"
)

// newFlagSet builds a command's flags with its own usage text. Nothing is parsed
// until the command has registered its flags and parseFlags is called, so a flag
// declared after the set exists is still a flag the parser knows.
func newFlagSet(name string, out io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(out)
	fs.Usage = func() {
		fmt.Fprintf(out, "usage: xammu %s [flags]\n\n", name)
		fs.PrintDefaults()
		fmt.Fprint(out, "\nplan flags and the exit codes are in `xammu help`.\n")
	}
	return fs
}

// parseFlags runs the parser and turns its refusals into this tool's. Every kind of
// parse failure - an unknown flag, a value the parser cannot read, a -h - is a
// command line that could not be understood, so all of them carry errUsage and exit 2
// rather than 1: a script has to be able to tell "the operator typed the wrong thing"
// apart from "the tool refused on the evidence".
func parseFlags(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return fmt.Errorf("%w: %s", errUsage, fs.Name())
		}
		return fmt.Errorf("%w: %v", errUsage, err)
	}
	return nil
}

// requireNoStrayArgs refuses a positional argument. Every command here takes flags
// only, so an extra word means the operator typed something the tool will silently
// ignore, and a silently ignored flag is how a run happens with the wrong scope.
func requireNoStrayArgs(fs *flag.FlagSet) error {
	if fs.NArg() > 0 {
		return fmt.Errorf("%w: %q is not an argument this command takes", errUsage, fs.Arg(0))
	}
	return nil
}

// readContractFile loads one JSON document and validates it as the contract it
// claims to be, before any code above this point gets to act on it. A file that does
// not satisfy its contract is not an authorization, whatever it is called.
func readContractFile(path string, dst any, id contracts.ID, what string) error {
	if path == "" {
		return fmt.Errorf("no %s file supplied", what)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("cannot read the %s %s: %w", what, path, err)
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		return fmt.Errorf("the %s %s is not JSON: %w", what, path, err)
	}
	if err := contracts.Validate(id, dst); err != nil {
		return fmt.Errorf("the %s %s does not satisfy %s: %w", what, path, id, err)
	}
	return nil
}

func loadProfiling(path string) (*contracts.ProfilingAuthorization, error) {
	var a contracts.ProfilingAuthorization
	if err := readContractFile(path, &a, contracts.IDProfilingAuthorization, "authorization"); err != nil {
		return nil, err
	}
	return &a, nil
}

func loadValidation(path string) (*contracts.ValidationAuthorization, error) {
	if path == "" {
		return nil, nil
	}
	var v contracts.ValidationAuthorization
	if err := readContractFile(path, &v, contracts.IDValidationAuthorization, "validation authorization"); err != nil {
		return nil, err
	}
	return &v, nil
}

// loadAuthorization resolves the --authorization value and reports the directory a
// reader has to search to resolve the same reference. A path is read directly; a
// reference is looked up in the authorizations directory, where each file must itself
// satisfy C-09.
//
// The lookup is deliberately narrow: exactly one file must carry the reference. Two
// files with the same ref would mean the operator is holding one of two permissions
// and the tool cannot tell which, so it asks instead of guessing.
//
// The directory comes back with the permission because a report publishes the
// reference, not the path the operator happened to type, and a published reference is
// only paste-able together with the place it was found. Returning it here keeps that
// statement about what this process actually read rather than about what a later
// renderer guesses from the shape of the value.
func loadAuthorization(value, dir string) (*contracts.ProfilingAuthorization, string, error) {
	if value == "" {
		return nil, "", fmt.Errorf("%w: no authorization supplied. Every command that touches a target "+
			"names the C-09 permission it is running under", errUsage)
	}
	if strings.HasSuffix(value, ".json") {
		if _, err := os.Stat(value); err == nil {
			a, err := loadProfiling(value)
			if err != nil {
				return nil, "", err
			}
			return a, filepath.Dir(value), nil
		}
	}
	if dir == "" {
		return nil, "", fmt.Errorf("authorization %q is not a file and no --authorizations dir was given", value)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, "", fmt.Errorf("cannot look for authorization %q in %s: %w", value, dir, err)
	}
	var matches []*contracts.ProfilingAuthorization
	var checked, rejected int
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		a, err := loadProfiling(filepath.Join(dir, e.Name()))
		if err != nil {
			// A file that is not a valid C-09 cannot be a candidate, but it is counted:
			// the refusal below has to say how many files were unreadable, or an
			// operator chasing a reference would not know that the permission next to
			// the one they meant is corrupt.
			rejected++
			continue
		}
		checked++
		if a.Ref == value {
			matches = append(matches, a)
		}
	}
	switch len(matches) {
	case 1:
		return matches[0], dir, nil
	case 0:
		return nil, "", fmt.Errorf("authorization %q was not found in %s (%d valid C-09 file(s) checked, "+
			"%d file(s) in that directory are not valid C-09 documents); pass the file path instead",
			value, dir, checked, rejected)
	default:
		return nil, "", fmt.Errorf("authorization %q appears in %d files under %s: one reference must "+
			"resolve to exactly one permission", value, len(matches), dir)
	}
}

// readProfile reads a run's checkpoint from its bundle. It is validated as C-11
// before it is returned: a report built on a checkpoint that does not match its own
// contract would state arithmetic no record supports.
func readProfile(dir string) (contracts.RunProfile, error) {
	var p contracts.RunProfile
	path := filepath.Join(dir, runCheckpointFile)
	raw, err := os.ReadFile(path)
	if err != nil {
		return p, fmt.Errorf("cannot read the run checkpoint %s: %w", path, err)
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return p, fmt.Errorf("the run checkpoint %s is not JSON: %w", path, err)
	}
	if err := contracts.Validate(contracts.IDRunProfile, &p); err != nil {
		return p, fmt.Errorf("the run checkpoint %s does not satisfy C-11: %w", path, err)
	}
	return p, nil
}

// splitList reads a comma-separated flag value. Empty members are dropped rather
// than passed on: "--class sqli,,xss" is what a shell typo looks like, and a plan that
// carries an unnamed class would fail validation with a message about classes.
func splitList(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func asClasses(in []string) ([]contracts.AttackClass, error) {
	out := make([]contracts.AttackClass, 0, len(in))
	for _, s := range in {
		if !containsString(classesToStrings(contracts.AllAttackClasses()), s) {
			return nil, fmt.Errorf("attack class %q is not in the vocabulary: %s",
				s, strings.Join(classesToStrings(contracts.AllAttackClasses()), "|"))
		}
		out = append(out, contracts.AttackClass(s))
	}
	return out, nil
}

func asVectors(in []string) ([]contracts.Vector, error) {
	out := make([]contracts.Vector, 0, len(in))
	for _, s := range in {
		if !containsString(vectorsToStrings(contracts.AllVectors()), s) {
			return nil, fmt.Errorf("transport %q is not in the vocabulary: %s",
				s, strings.Join(vectorsToStrings(contracts.AllVectors()), "|"))
		}
		out = append(out, contracts.Vector(s))
	}
	return out, nil
}

func asEncodings(in []string) ([]contracts.Encoding, error) {
	out := make([]contracts.Encoding, 0, len(in))
	for _, s := range in {
		if !containsString(encodingsToStrings(contracts.AllEncodings()), s) {
			return nil, fmt.Errorf("encoding %q is not in the vocabulary: %s",
				s, strings.Join(encodingsToStrings(contracts.AllEncodings()), "|"))
		}
		out = append(out, contracts.Encoding(s))
	}
	return out, nil
}

func asPartition(s string) (contracts.PartitionName, error) {
	for _, p := range contracts.AllPartitionNames() {
		if string(p) == s {
			return p, nil
		}
	}
	return "", fmt.Errorf("partition %q is not one of %s", s,
		strings.Join(partitionToStrings(contracts.AllPartitionNames()), "|"))
}

func classesToStrings(in []contracts.AttackClass) []string {
	out := make([]string, len(in))
	for i, v := range in {
		out[i] = string(v)
	}
	return out
}

func vectorsToStrings(in []contracts.Vector) []string {
	out := make([]string, len(in))
	for i, v := range in {
		out[i] = string(v)
	}
	return out
}

func encodingsToStrings(in []contracts.Encoding) []string {
	out := make([]string, len(in))
	for i, v := range in {
		out[i] = string(v)
	}
	return out
}

func partitionToStrings(in []contracts.PartitionName) []string {
	out := make([]string, len(in))
	for i, v := range in {
		out[i] = string(v)
	}
	return out
}

func containsString(in []string, needle string) bool {
	for _, v := range in {
		if v == needle {
			return true
		}
	}
	return false
}

// originURL renders one authorized origin as the base a probe URL is built on, in
// the same canonical form the orchestrator binds a run to: scheme, host and port,
// always with the port stated. An origin with no port is refused rather than
// defaulted, because "which port did we send to" is a question a report cannot answer
// from a zero, and a silently defaulted 443 is a destination nobody wrote down.
func originURL(o contracts.Origin) (string, error) {
	if o.Port <= 0 {
		return "", fmt.Errorf("origin %s://%s declares no port: an authorization names the destination "+
			"exactly, and a run may not complete it", o.Scheme, o.Host)
	}
	return o.Scheme + "://" + o.Host + ":" + strconv.Itoa(o.Port), nil
}

// pickOrigin resolves --target against the authorization. A target that is not
// listed is refused here rather than at the socket, so the operator sees the answer
// before a request is planned against a destination nobody approved.
func pickOrigin(auth *contracts.ProfilingAuthorization, wanted string) (string, error) {
	if len(auth.Origins) == 0 {
		return "", fmt.Errorf("authorization %s lists no origin", auth.Ref)
	}
	var allowed []string
	for _, o := range auth.Origins {
		u, err := originURL(o)
		if err != nil {
			return "", err
		}
		allowed = append(allowed, u)
		if wanted == "" || u == wanted || o.Host == wanted {
			return u, nil
		}
	}
	if wanted == "" {
		return "", fmt.Errorf("authorization %s lists no usable origin", auth.Ref)
	}
	return "", fmt.Errorf("target %q is not an origin of authorization %s; authorized: %s",
		wanted, auth.Ref, strings.Join(allowed, ", "))
}

// headerValue reads one header out of a journaled or placed header list, case
// insensitively, because HTTP names are case-insensitive and a probe that ignored that
// would report a missing Server header on a response that has one.
func headerValue(in []contracts.HeaderEntry, name string) string {
	for _, h := range in {
		if strings.EqualFold(h.Name, name) {
			return h.Value
		}
	}
	return ""
}

// unplannedReason maps the selection's prose onto the reason code C-15 requires for an
// unevaluated zone. The selection states the cause in a sentence; the report has to
// type it, and the type has to come from the sentence rather than from a guess.
func unplannedReason(detail string) contracts.ReasonCode {
	lower := strings.ToLower(detail)
	switch {
	case strings.Contains(lower, "budget"):
		return contracts.ReasonBudgetExhausted
	case strings.Contains(lower, "authorization"):
		// Both wordings the selection uses: an item whose class is not authorized, and
		// a control that lives outside the authorized grid. Either way the zone is
		// unevaluated because of the permission, not because the corpus is short.
		return contracts.ReasonAuthorizationGap
	default:
		return contracts.ReasonCorpusGap
	}
}

// generatedBy names the operator who asked for the document. It is taken from the
// environment when there is one to take, and stated as unknown when there is not: an
// evidence block that quietly claimed a name the process never had is worse than one
// that says it does not know.
func generatedBy(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	for _, k := range []string{"XAMMU_OPERATOR", "USERNAME", "USER"} {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return "unknown"
}
