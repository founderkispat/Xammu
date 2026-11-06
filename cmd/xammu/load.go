package main

import (
	"bytes"
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
	"xammu/internal/integrity"
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
//
// An authorization is decoded strictly: a field this tool does not understand is a
// field the signature would not cover, so accepting the document would verify less
// than it appears to.
func readContractFile(path string, dst any, id contracts.ID, what string, strict bool) error {
	if path == "" {
		return fmt.Errorf("no %s file supplied", what)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("cannot read the %s %s: %w", what, path, err)
	}
	if strict {
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(dst); err != nil {
			return fmt.Errorf("the %s %s is not the JSON of a %s: %w", what, path, id, err)
		}
		if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
			return fmt.Errorf("the %s %s carries more than one JSON value", what, path)
		}
	} else if err := json.Unmarshal(raw, dst); err != nil {
		return fmt.Errorf("the %s %s is not JSON: %w", what, path, err)
	}
	if err := contracts.Validate(id, dst); err != nil {
		return fmt.Errorf("the %s %s does not satisfy %s: %w", what, path, id, err)
	}
	return nil
}

// decodeProfiling reads a C-09 and validates it, without deciding whether it is
// signed. Reference lookup needs that split: an unsigned file may sit beside the
// signed one and must not break the search, but the file the reference resolves to
// is verified before it is returned.
func decodeProfiling(path string) (*contracts.ProfilingAuthorization, error) {
	var a contracts.ProfilingAuthorization
	if err := readContractFile(path, &a, contracts.IDProfilingAuthorization, "authorization", true); err != nil {
		return nil, err
	}
	return &a, nil
}

func loadProfiling(path string, ring integrity.Keyring) (*contracts.ProfilingAuthorization, error) {
	a, err := decodeProfiling(path)
	if err != nil {
		return nil, err
	}
	if err := verifyProfilingSignature(a, path, ring); err != nil {
		return nil, err
	}
	return a, nil
}

// verifyAuthorizationSignature checks the detached sidecar against the issuer
// keyring. The key is looked up by the identifier the sidecar names; a keyring
// that does not carry it is a refusal, not a fallback to the document's own claim.
// It returns the key that verified, because the C-09 fingerprint has to be derived
// from that key rather than from a second lookup.
func verifyAuthorizationSignature(kind contracts.ID, canonical []byte, path string,
	ring integrity.Keyring) (integrity.IssuerKey, error) {
	sig, err := integrity.ReadAuthSignature(path)
	if err != nil {
		return integrity.IssuerKey{}, err
	}
	key, ok := ring.Find(sig.KeyID)
	if !ok {
		return integrity.IssuerKey{}, fmt.Errorf("%s %s is signed by issuer key %s, which is not in the "+
			"keyring %s (it holds %s): a signature is only evidence when the key was obtained "+
			"independently of the document", kind.Label(), path, sig.KeyID, ring.Dir,
			strings.Join(ring.IDs(), ", "))
	}
	if err := integrity.VerifyAuthorization(kind, canonical, sig, key.Public); err != nil {
		return integrity.IssuerKey{}, fmt.Errorf("%s %s: %w", kind.Label(), path, err)
	}
	return key, nil
}

func verifyProfilingSignature(a *contracts.ProfilingAuthorization, path string,
	ring integrity.Keyring) error {
	canonical, err := contracts.Canonical(a)
	if err != nil {
		return fmt.Errorf("cannot canonicalize authorization %s: %w", path, err)
	}
	key, err := verifyAuthorizationSignature(contracts.IDProfilingAuthorization, canonical, path, ring)
	if err != nil {
		return err
	}
	want := integrity.KeyFingerprint(key.Public)
	if a.IssuerKeyFingerprint != want {
		return fmt.Errorf("authorization %s states issuer_key_fingerprint %q but the key that signed it "+
			"derives %q: the fingerprint is derived from the key, not text written beside it", path,
			a.IssuerKeyFingerprint, want)
	}
	return nil
}

func loadValidation(path, keyring string) (*contracts.ValidationAuthorization, error) {
	if path == "" {
		return nil, nil
	}
	var v contracts.ValidationAuthorization
	if err := readContractFile(path, &v, contracts.IDValidationAuthorization, "validation authorization", true); err != nil {
		return nil, err
	}
	ring, err := integrity.LoadIssuerKeyring(keyring)
	if err != nil {
		return nil, err
	}
	want, err := v.RecomputeImmutabilityDigest()
	if err != nil {
		return nil, fmt.Errorf("cannot recompute the immutability digest of %s: %w", path, err)
	}
	if v.ImmutabilityDigest != want {
		return nil, fmt.Errorf("validation authorization %s states immutability_digest %s but its fields "+
			"derive %s: the declaration changed after the digest was written", path,
			v.ImmutabilityDigest, want)
	}
	canonical, err := contracts.Canonical(v)
	if err != nil {
		return nil, fmt.Errorf("cannot canonicalize validation authorization %s: %w", path, err)
	}
	if _, err := verifyAuthorizationSignature(contracts.IDValidationAuthorization, canonical, path, ring); err != nil {
		return nil, err
	}
	return &v, nil
}

// loadAuthorization resolves the --authorization value and reports the directory a
// reader has to search to resolve the same reference. A path is read directly; a
// reference is looked up in the authorizations directory, where each file must itself
// satisfy C-09.
//
// The resolved file is then verified against the issuer keyring: a detached
// signature, the key it names, and the fingerprint the key derives. An unsigned
// permission is refused before any of these commands reaches a plan, and nothing
// above this point ever sees the authorization as if it were approved.
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
func loadAuthorization(value, dir, keyring string) (*contracts.ProfilingAuthorization, string, error) {
	if value == "" {
		return nil, "", fmt.Errorf("%w: no authorization supplied. Every command that touches a target "+
			"names the C-09 permission it is running under", errUsage)
	}
	if strings.HasSuffix(value, ".json") {
		if _, err := os.Stat(value); err == nil {
			ring, err := integrity.LoadIssuerKeyring(keyring)
			if err != nil {
				return nil, "", err
			}
			a, err := loadProfiling(value, ring)
			if err != nil {
				return nil, "", err
			}
			return a, filepath.Dir(value), nil
		}
	}
	if dir == "" {
		return nil, "", fmt.Errorf("authorization %q is not a file and no --authorizations dir was given", value)
	}
	ring, err := integrity.LoadIssuerKeyring(keyring)
	if err != nil {
		return nil, "", err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, "", fmt.Errorf("cannot look for authorization %q in %s: %w", value, dir, err)
	}
	type candidate struct {
		auth *contracts.ProfilingAuthorization
		path string
	}
	var matches []candidate
	var checked, rejected int
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		a, err := decodeProfiling(path)
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
			matches = append(matches, candidate{auth: a, path: path})
		}
	}
	switch len(matches) {
	case 1:
		// Verification happens only for the file the reference resolves to: an
		// unsigned neighbour is not this permission, and failing the whole search
		// on it would hide the one the operator asked for.
		if err := verifyProfilingSignature(matches[0].auth, matches[0].path, ring); err != nil {
			return nil, "", err
		}
		return matches[0].auth, dir, nil
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

// generatedBy names the operator who asked for the document. Only an explicit
// flag names a person: falling back to XAMMU_OPERATOR, USERNAME or USER would
// copy the workstation account into a client deliverable without the operator
// choosing it, and an evidence block that claims a name the process never had
// is worse than one that says it does not know.
func generatedBy(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	return "unknown"
}
