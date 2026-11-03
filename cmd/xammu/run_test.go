package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"xammu/internal/contracts"
	"xammu/internal/inference"
	"xammu/internal/integrity"
)

// blockToken is the literal the laboratory's WAF embeds in its interstitial. The fake
// perimeter below reuses it so this test measures the same observable shape a real run
// against the fixture measures.
const blockToken = "XAMMU-LAB-WAF-BLOCK"

// fakePerimeter answers the way a front end does: a refusal page for a request whose
// decoded value still reads as a signature, and a plain origin response for everything
// else. It decodes exactly one layer, on purpose - that is what a normalizing WAF does,
// and it is why a double-encoded probe reaches the origin while its canonical twin is
// blocked. A test fixture that blocked everything would prove nothing about asymmetry.
func fakePerimeter(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var parts []string
		for key, values := range r.URL.Query() {
			parts = append(parts, key, strings.Join(values, " "))
		}
		parts = append(parts, r.URL.Path)
		for _, name := range []string{"X-Test", "Cookie"} {
			if v := r.Header.Get(name); v != "" {
				parts = append(parts, v)
			}
		}
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
		parts = append(parts, string(body), r.RequestURI)
		hay := strings.ToLower(strings.Join(parts, " "))

		if strings.Contains(hay, "or 1=1") {
			h := w.Header()
			h.Set("Server", "xammu-lab-waf/1.0")
			h.Set("X-Lab-Waf-Action", "reject")
			h.Set("Content-Type", "text/html; charset=utf-8")
			h.Set("X-Lab-Request-Decision", "blocked")
			h.Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintf(w, "<!doctype html>\n<html lang=\"en\">\n<head>\n"+
				"<meta charset=\"utf-8\">\n<title>%s | request blocked</title>\n</head>\n"+
				"<body>\n<h1>%s</h1>\n"+
				"<p>The laboratory WAF refused this request before it reached the origin.</p>\n"+
				"</body>\n</html>\n", blockToken, blockToken)
			return
		}
		h := w.Header()
		h.Set("Content-Type", "application/json")
		h.Set("X-Lab-Request-Decision", "forwarded")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"result":"ok","echo":%q}`, r.RequestURI)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// perimeterPort is the port the fake front end listens on, which is the only origin the
// test authorization may name.
func perimeterPort(t *testing.T, srv *httptest.Server) int {
	t.Helper()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("the test server gave an unusable URL %q: %v", srv.URL, err)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatalf("the test server URL %q carries no port: %v", srv.URL, err)
	}
	return port
}

// splitCommandLine tokenizes a command a report published, so the test can execute the
// very string a reviewer pastes. shellArg quotes a value containing a space or a quote,
// and this is the reader's side of that contract: if the two ever disagree, a published
// command silently re-plans something else.
//
// It scans character by character instead of splitting on whitespace, because a quoted
// value may itself hold a tab. Splitting first would cut one argument in two, which is
// precisely the failure the quoting exists to prevent.
func splitCommandLine(cmd string) ([]string, error) {
	if !strings.HasPrefix(cmd, "xammu ") {
		return nil, fmt.Errorf("the report published a command this tool does not implement: %q", cmd)
	}
	var (
		out     []string
		cur     strings.Builder
		quoted  rune
		started bool
	)
	flush := func() {
		if started {
			out = append(out, cur.String())
			cur.Reset()
			started = false
		}
	}
	runes := []rune(cmd)
	for i := len("xammu "); i < len(runes); i++ {
		ch := runes[i]
		switch {
		case ch == '"' && quoted != '\'':
			if quoted == '"' {
				quoted = 0
			} else {
				quoted = '"'
				started = true
			}
		case ch == '\'':
			// A single-quoted value is literal all the way to the closing quote, which is
			// how a cell reference holding pipes survives the reader's shell.
			if quoted == '\'' {
				quoted = 0
			} else if quoted == 0 {
				quoted = '\''
				started = true
			} else {
				cur.WriteRune(ch)
			}
		case (ch == ' ' || ch == '\t') && quoted == 0:
			flush()
		case ch == '\\' && quoted == '"' && i+1 < len(runes) && runes[i+1] == '"':
			// The only escape shellArg writes. Anything after a backslash stays literal,
			// so a Windows path in a published command survives intact.
			i++
			cur.WriteRune(runes[i])
			started = true
		default:
			cur.WriteRune(ch)
			started = true
		}
	}
	if quoted != 0 {
		return nil, fmt.Errorf("an unbalanced quote in a published command: %q", cmd)
	}
	flush()
	if len(out) == 0 {
		return nil, fmt.Errorf("no arguments in %q", cmd)
	}
	return out, nil
}

// mustExecute runs a published command in-process and fails the test if it does not
// behave. `want` is a substring the successful output must contain, which is how the
// test checks the command said the right thing rather than only that it exited cleanly.
func mustExecute(t *testing.T, cmd, want string) {
	t.Helper()
	argv, err := splitCommandLine(cmd)
	if err != nil {
		t.Fatalf("cannot reuse a published command: %v", err)
	}
	var out, errs bytes.Buffer
	if code := dispatch(argv, &out, &errs); code != 0 {
		t.Fatalf("the report published %q, which exited %d\nstdout: %s\nstderr: %s",
			strings.Join(argv, " "), code, out.String(), errs.String())
	}
	if want != "" && !strings.Contains(out.String(), want) {
		t.Fatalf("%q ran but did not state %q:\n%s", argv[0], want, out.String())
	}
}

// TestEndToEndRunSealsSignsAndPublishesCommandsThatWork drives the whole live loop
// against a fake perimeter: run sends inside one C-09, seals and signs the evidence,
// publishes the C-15 report - and then every command that report cites is executed as
// written. A reproduction step that does not work is not a reproduction step, and this
// is the test that says whether the tool's central promise holds.
func TestEndToEndRunSealsSignsAndPublishesCommandsThatWork(t *testing.T) {
	srv := fakePerimeter(t)
	dir := t.TempDir()
	auth := testAuth(t, perimeterPort(t, srv))
	auth.Limits.MaxRequests = 24
	authPath := writeAuthFile(t, dir, auth, "auth.json")
	runsDir := filepath.Join(dir, "runs")
	keyPath := filepath.Join(dir, "outside-the-bundle.ed25519")

	code, out, errs := run(t, "run", "--authorization", authPath, "--authorize", auth.Ref,
		"--run", "cli-e2e", "--corpus", testCorpusRoot, "--runs-dir", runsDir,
		"--class", "sqli", "--vector", "query", "--budget", "24", "--signing-key", keyPath)
	if code != 0 {
		t.Fatalf("the run must complete: exit %d\nstdout: %s\nstderr: %s", code, out, errs)
	}
	bundle := filepath.Join(runsDir, "cli-e2e")
	for _, want := range []string{"executed", "sealed and signed", "signer public key (hex",
		"report ", "next: xammu verify --run cli-e2e"} {
		if !strings.Contains(out, want) {
			t.Errorf("the run must report %q:\n%s", want, out)
		}
	}

	// The signing key is the one artifact that must stay outside the directory it signs:
	// a bundle that carries its own private key can be re-signed by whoever copies it,
	// which is not the property a manifest is supposed to have.
	assertNoPrivateKeys(t, bundle, keyPath)

	// The published document has to be a real C-15, read back from disk.
	rep, err := readPublishedReport(bundle)
	if err != nil {
		t.Fatalf("the run published no readable report: %v", err)
	}
	if rep.RunID != "cli-e2e" || rep.AuthorizationRef != auth.Ref {
		t.Fatalf("the report describes a different run or permission: %+v", rep)
	}
	if rep.RequestsUsed == 0 || rep.RequestsUsed > rep.RequestBudget {
		t.Fatalf("the report must state the requests actually spent: %d of %d",
			rep.RequestsUsed, rep.RequestBudget)
	}
	if len(rep.Findings) == 0 {
		t.Fatal("a run that exchanged with a perimeter must publish at least one finding")
	}
	if len(rep.Dimensions) != 5 {
		t.Fatalf("the report is a five-dimension document, got %d", len(rep.Dimensions))
	}
	if len(rep.OutOfScope) == 0 {
		t.Fatal("every report has to disclaim application vulnerabilities")
	}

	// The command the report cites for its own integrity check, executed as written.
	mustExecute(t, rep.Evidence.VerifyCommand, "every journal recomputes to its own head")
	assertNamesOnePermission(t, rep.Evidence.VerifyCommand, auth.Ref)

	// Every published finding, re-derived by the command the finding itself prints.
	for _, f := range rep.Findings {
		mustExecute(t, f.ReproductionCommand, "agrees")
		assertNamesOnePermission(t, f.ReproductionCommand, auth.Ref)
	}

	// The cell-level commands the journal publishes. A hypothesis cites the exact
	// `xammu report --run ID --cell REF` that reproduces its own reading, and that
	// command carries the cell reference with pipes in it, so it is also the test of
	// the quoting a reader has to paste.
	for _, cmd := range publishedCellCommands(t, bundle) {
		mustExecute(t, cmd, "cell ")
		assertNamesOnePermission(t, cmd, auth.Ref)
	}

	// The regression steps are how a finding says "close me". Two shapes are honest: a
	// laboratory scenario that reproduces the behaviour, or a playbook that plans the
	// scope this run left unmeasured. Any other shape points at a check that does not
	// exist, and the finding cannot be closed.
	for _, f := range rep.Findings {
		step := f.RegressionTest
		if step == "" {
			continue
		}
		switch {
		case strings.HasPrefix(step, "xammu lab test --scenario "):
			name := strings.TrimPrefix(step, "xammu lab test --scenario ")
			if !scenarioFamily.MatchString(name) {
				t.Errorf("finding %s names scenario %q, outside the families the laboratory provides",
					f.Ref, name)
			}
		case strings.HasPrefix(step, "xammu playbook "):
			// A playbook sends nothing, so the step is safe to run here. It has to be a
			// command line this tool understands; a refusal is allowed to follow, but it
			// has to be a refusal on the corpus or the permission and say what is missing.
			// An unparseable step would be the report sending the reader to a command that
			// does not exist.
			mustBeARunCommandLine(t, step, "plan")
			assertStepStaysInScope(t, step, auth.Ref)
		default:
			t.Errorf("finding %s publishes a regression step this command cannot run: %q", f.Ref, step)
		}
	}
}

// assertStepStaysInScope checks the two ways a published widening step can be false.
// It can name the permission twice - or by a value the run never used - and the reader
// has to guess which scope the requests are authorized under. Or it can inherit this
// run's class, transport or budget, in which case the step spends someone's permission
// to re-plan the probes that were already planned and learn nothing new.
//
// The checks count whole arguments rather than substrings, because the directory flag
// begins with the same characters as the permission flag.
func assertStepStaysInScope(t *testing.T, step, ref string) {
	t.Helper()
	argv, err := splitCommandLine(step)
	if err != nil {
		t.Fatalf("a published step cannot be tokenized: %v", err)
	}
	assertNamesOnePermissionArgs(t, step, argv, ref)
	for _, inherited := range []struct{ flag, value string }{
		{"--class", "sqli"}, {"--vector", "query"}, {"--budget", "24"},
	} {
		if v := flagValue(argv, inherited.flag); v == inherited.value {
			t.Errorf("the widening step %q re-asks this run's %s %q, so the reader spends requests "+
				"on a scope that is already measured", step, inherited.flag, inherited.value)
		}
	}
}

// assertNamesOnePermission checks the published string itself; the argv form is shared
// with the step check, which has already tokenized it.
func assertNamesOnePermission(t *testing.T, cmd, ref string) {
	t.Helper()
	argv, err := splitCommandLine(cmd)
	if err != nil {
		t.Fatalf("a published command cannot be tokenized: %v", err)
	}
	assertNamesOnePermissionArgs(t, cmd, argv, ref)
}

// assertNamesOnePermissionArgs holds the naming rule every command a report publishes
// has to satisfy: exactly one --authorization, and the reference this run was executed
// under. A command that names two leaves the reader to guess which permission the
// requests were authorized under, and one that names a different reference reproduces
// nothing. The rule is stated against the reference rather than a file path because a
// report is read by someone who was given the permission, not the operator's directory.
func assertNamesOnePermissionArgs(t *testing.T, cmd string, argv []string, ref string) {
	t.Helper()
	if n := countFlag(argv, "--authorization"); n != 1 {
		t.Errorf("%q names the permission %d time(s): a reader cannot tell which authorization "+
			"the requests are made under", cmd, n)
		return
	}
	if v := flagValue(argv, "--authorization"); v != ref {
		t.Errorf("%q names permission %q, but this run was executed under %q", cmd, v, ref)
	}
	if n := countFlag(argv, "--authorizations"); n > 1 {
		t.Errorf("%q names the search directory %d time(s)", cmd, n)
	}
}

// countFlag counts whole arguments equal to name.
func countFlag(argv []string, name string) int {
	var n int
	for _, a := range argv {
		if a == name {
			n++
		}
	}
	return n
}

// flagValue returns the first value given to a flag, or "" when the flag is absent.
func flagValue(argv []string, name string) string {
	for i, a := range argv {
		if a == name && i+1 < len(argv) {
			return argv[i+1]
		}
	}
	return ""
}

var scenarioFamily = regexp.MustCompile(`^(coverage-gap|over-blocking|vector-asymmetry|encoding-bypass|configuration-concern|undetermined)-[a-z0-9_-]+$`)

// mustBeARunCommandLine executes a published command and accepts either success or a
// refusal on the evidence. A usage failure is the failure it looks for: it means the
// report printed a command line this tool does not accept, so the step a reader was
// sent to cannot be taken at all.
func mustBeARunCommandLine(t *testing.T, cmd, want string) {
	t.Helper()
	argv, err := splitCommandLine(cmd)
	if err != nil {
		t.Fatalf("cannot reuse a published command: %v", err)
	}
	var out, errs bytes.Buffer
	code := dispatch(argv, &out, &errs)
	if code == 2 {
		t.Fatalf("the report published a command line this tool refuses to parse: %q\nstderr: %s",
			cmd, errs.String())
	}
	if code == 0 {
		if want != "" && !strings.Contains(out.String(), want) {
			t.Fatalf("%q ran but did not state %q:\n%s", argv[0], want, out.String())
		}
		return
	}
	if strings.TrimSpace(errs.String()) == "" {
		t.Fatalf("%q exited %d without saying why:\n%s", cmd, code, out.String())
	}
	t.Logf("%q refused, as the corpus and permission allow: %s", cmd, strings.TrimSpace(errs.String()))
}

// publishedCellCommands reads the hypotheses back out of the sealed bundle and returns
// the reproduction command each one carries. The test executes those strings rather
// than building equivalents, because the promise under test is the one the tool made,
// not one the test invented for it.
func publishedCellCommands(t *testing.T, bundle string) []string {
	t.Helper()
	store, err := integrity.Open(bundle)
	if err != nil {
		t.Fatalf("the sealed bundle cannot be reopened: %v", err)
	}
	j, err := inference.Read(store)
	if err != nil {
		t.Fatalf("the sealed bundle cannot be read back: %v", err)
	}
	if len(j.Hypotheses) == 0 {
		t.Fatal("the run journalled no hypothesis, so nothing was claimed about the perimeter")
	}
	var out []string
	for _, h := range j.Hypotheses {
		if h.ReproductionCommand == "" {
			t.Errorf("hypothesis %s was published without a reproduction command", h.Ref)
			continue
		}
		out = append(out, h.ReproductionCommand)
	}
	return out
}

// TestEndToEndAReaderWithoutThePlanFlagsReDerivesTheSameDocument is the regression test
// for a report that failed its own `validate`. The plan is signed evidence, so a reader
// who types only --run, --authorization and --corpus has to recover the scope the run
// measured and reproduce the same findings - including the reproduction commands, which
// used to be rendered from whoever was typing. A document that only re-derives for the
// operator who remembers their flags is a document that does not re-derive.
func TestEndToEndAReaderWithoutThePlanFlagsReDerivesTheSameDocument(t *testing.T) {
	srv := fakePerimeter(t)
	dir := t.TempDir()
	auth := testAuth(t, perimeterPort(t, srv))
	authPath := writeAuthFile(t, dir, auth, "auth.json")
	runsDir := filepath.Join(dir, "runs")
	bundle := filepath.Join(runsDir, "cli-replan")

	code, out, errs := run(t, "run", "--authorization", authPath, "--authorize", auth.Ref,
		"--run", "cli-replan", "--corpus", testCorpusRoot, "--runs-dir", runsDir,
		"--class", "sqli", "--vector", "query", "--budget", "24",
		"--signing-key", filepath.Join(dir, "signing.ed25519"))
	if code != 0 {
		t.Fatalf("the run must complete: exit %d\nstdout: %s\nstderr: %s", code, out, errs)
	}
	rep, err := readPublishedReport(bundle)
	if err != nil {
		t.Fatalf("the run published no readable report: %v", err)
	}
	if len(rep.Findings) == 0 {
		t.Fatal("the run published no finding, so the re-read below checks nothing")
	}

	// The reader types no --class, --vector, --budget or --encoding. The bundle holds
	// them, so the claim has to come back unchanged.
	for _, f := range rep.Findings {
		code, out, errs := run(t, "validate", "--finding", f.Ref, "--run", "cli-replan",
			"--authorization", auth.Ref, "--authorizations", dir,
			"--corpus", testCorpusRoot, "--runs-dir", runsDir)
		if code != 0 {
			t.Fatalf("finding %s did not re-derive from the bundle that published it: exit %d\n"+
				"stdout: %s\nstderr: %s", f.Ref, code, out, errs)
		}
		if !strings.Contains(out, "agrees") {
			t.Fatalf("finding %s re-derived without saying so:\n%s", f.Ref, out)
		}
	}

	code, out, errs = run(t, "verify", "--run", "cli-replan", "--authorization", auth.Ref,
		"--authorizations", dir, "--corpus", testCorpusRoot, "--runs-dir", runsDir, "--rederive")
	if code != 0 {
		t.Fatalf("the whole document must re-derive without the plan flags: exit %d\n"+
			"stdout: %s\nstderr: %s", code, out, errs)
	}
	if !strings.Contains(out, "re-derive with the same claim") {
		t.Fatalf("the re-derivation did not confirm the published findings:\n%s", out)
	}

	// A reader who asks for a different scope is refused rather than handed a report
	// about a plan they did not name: a flag is not evidence.
	code, out, errs = run(t, "validate", "--finding", rep.Findings[0].Ref,
		"--run", "cli-replan", "--authorization", auth.Ref, "--authorizations", dir,
		"--corpus", testCorpusRoot, "--runs-dir", runsDir, "--class", "xss")
	if code == 0 {
		t.Fatalf("a re-read that names another class must be refused, not answered:\n%s", out)
	}
	if !strings.Contains(errs, "does not match the plan") {
		t.Fatalf("the refusal must say the class is not the run's plan:\n%s", errs)
	}
}

// TestEndToEndRederiveCatchesAEditedReport is the tamper test on the published document.
// The signed inventory covers the journals, not the report, so re-derivation is the only
// thing that can tell a reviewer the document in front of them still comes out of the
// evidence beside it.
func TestEndToEndRederiveCatchesAEditedReport(t *testing.T) {
	srv := fakePerimeter(t)
	dir := t.TempDir()
	auth := testAuth(t, perimeterPort(t, srv))
	authPath := writeAuthFile(t, dir, auth, "auth.json")
	runsDir := filepath.Join(dir, "runs")
	bundle := filepath.Join(runsDir, "cli-rederive")

	code, out, errs := run(t, "run", "--authorization", authPath, "--authorize", auth.Ref,
		"--run", "cli-rederive", "--corpus", testCorpusRoot, "--runs-dir", runsDir,
		"--class", "sqli", "--vector", "query", "--budget", "24",
		"--signing-key", filepath.Join(dir, "signing.ed25519"))
	if code != 0 {
		t.Fatalf("the run must complete: exit %d\n%s\n%s", code, out, errs)
	}
	readArgs := []string{"--authorization", authPath, "--corpus", testCorpusRoot,
		"--runs-dir", runsDir, "--class", "sqli", "--vector", "query", "--budget", "24"}

	// First, as published: the document re-derives from its own evidence.
	clean := append([]string{"verify", "--store", bundle, "--rederive"}, readArgs...)
	code, out, errs = run(t, clean...)
	if code != 0 {
		t.Fatalf("an untouched report must re-derive: exit %d\n%s\n%s", code, out, errs)
	}
	if !strings.Contains(out, "published finding(s) re-derive") ||
		strings.Contains(out, "divergence:") {
		t.Fatalf("the re-derivation must be stated as a full agreement:\n%s", out)
	}

	// Then edit one claim, using a value still inside the C-16 vocabulary: the document
	// stays valid JSON and still satisfies its contract, so only re-derivation can catch
	// it. This is exactly the edit that makes a tool look more useful than it is.
	path := filepath.Join(bundle, reportJSONFile)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the published report: %v", err)
	}
	var rep contracts.Report
	if err := json.Unmarshal(raw, &rep); err != nil {
		t.Fatalf("the published report does not parse: %v", err)
	}
	if len(rep.Findings) == 0 {
		t.Fatal("no finding to edit")
	}
	original := rep.Findings[0].FindingType
	rep.Findings[0].FindingType = contracts.FindingConfigurationConcern
	edited, err := json.MarshalIndent(&rep, "", "  ")
	if err != nil {
		t.Fatalf("re-encoding the edited report: %v", err)
	}
	if err := os.WriteFile(path, edited, 0o640); err != nil {
		t.Fatalf("writing the edited report: %v", err)
	}

	code, out, errs = run(t, clean...)
	if code != 1 {
		t.Fatalf("an edited report must fail re-derivation, got exit %d\n%s\n%s", code, out, errs)
	}
	if !strings.Contains(errs, "does not re-derive from its own evidence") {
		t.Fatalf("the refusal must say what was lost: %s", errs)
	}
	for _, want := range []string{rep.Findings[0].Ref, "finding_type",
		string(original), string(contracts.FindingConfigurationConcern)} {
		if !strings.Contains(out, want) {
			t.Errorf("the divergence must name %q so a reviewer sees which claim moved:\n%s", want, out)
		}
	}

	// validate, the per-claim command, has to catch the same edit.
	if code, out, errs = run(t, append([]string{"validate", "--finding", rep.Findings[0].Ref,
		"--store", bundle}, readArgs...)...); code != 1 ||
		!strings.Contains(out, "disagrees") || !strings.Contains(out, "finding_type") {
		t.Fatalf("validate must refuse the edited claim: exit %d\n%s\n%s", code, out, errs)
	}
	// and must still agree about a claim nobody touched.
	if len(rep.Findings) > 1 {
		untouched := rep.Findings[1].Ref
		if code, out, errs = run(t, append([]string{"validate", "--finding", untouched,
			"--store", bundle}, readArgs...)...); code != 0 || !strings.Contains(out, "agrees") {
			t.Fatalf("validate must still agree about %q: exit %d\n%s\n%s", untouched, code, out, errs)
		}
	}
}

// assertNoPrivateKeys walks a sealed bundle and refuses any file holding key material,
// including the seed as it is stored on disk (hex) and as bytes.
func assertNoPrivateKeys(t *testing.T, bundle, keyPath string) {
	t.Helper()
	rawKey, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("the signing key should exist outside the bundle at %s: %v", keyPath, err)
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(rawKey)))
	if err != nil || len(seed) != ed25519.SeedSize {
		t.Fatalf("the test key is not a hex ed25519 seed: %v", err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	needles := []struct {
		what   string
		needle []byte
	}{
		{"the seed as bytes", seed},
		{"the seed as stored (hex)", bytes.TrimSpace(rawKey)},
		{"the expanded private key", priv},
	}
	err = filepath.WalkDir(bundle, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("reading %s: %w", path, err)
		}
		for _, n := range needles {
			if bytes.Contains(data, n.needle) {
				t.Errorf("%s contains %s: private key material must never enter a bundle",
					filepath.Base(path), n.what)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the bundle: %v", err)
	}
}
