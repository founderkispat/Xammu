package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"xammu/internal/contracts"
	"xammu/internal/corpus"
	"xammu/internal/integrity"
	"xammu/internal/labctl"
)

// testCorpusRoot points at the repository's corpus tree from the directory these tests
// run in. The read-path tests need a real selection to plan against: a synthetic corpus
// would either fail the inertness gate or measure arithmetic no run uses, and either way
// the test would prove nothing about the command a reviewer types.
var testCorpusRoot = filepath.Join("..", "..", "corpus")

// run issues one command line through the same dispatch the binary uses, so the exit
// code under test is the exit code an operator gets.
func run(t *testing.T, argv ...string) (int, string, string) {
	t.Helper()
	var out, errs bytes.Buffer
	code := dispatch(argv, &out, &errs)
	return code, out.String(), errs.String()
}

// canary is a listening socket that only counts. It exists because "nothing was sent" is
// the strongest claim this CLI makes, and a claim about an absence needs a witness rather
// than a comment.
type canary struct {
	mu    sync.Mutex
	conns int
	ln    net.Listener
	p     int
}

func newCanary(t *testing.T) *canary {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("cannot open the canary socket: %v", err)
	}
	tcpAddr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("the canary is not a TCP listener: %s", ln.Addr())
	}
	k := &canary{ln: ln, p: tcpAddr.Port}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			k.mu.Lock()
			k.conns++
			k.mu.Unlock()
			_ = c.Close()
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return k
}

func (k *canary) port() int { return k.p }

// idle fails the test if anything reached the socket.
func (k *canary) idle(t *testing.T, command string) {
	t.Helper()
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.conns != 0 {
		t.Fatalf("%s accepted %d connection(s) on %s: this command must not touch a target",
			command, k.conns, k.ln.Addr())
	}
}

// testAuth builds the C-09 the refusals are tested against. Its only origin is the
// loopback canary, so a probe that escaped the refusal logic lands somewhere the test can
// see instead of somewhere real.
func testAuth(t *testing.T, port int) *contracts.ProfilingAuthorization {
	t.Helper()
	a := contracts.ValidProfilingAuthorization()
	a.Origins = []contracts.Origin{{
		Scheme: "http", Host: "127.0.0.1", Port: port,
		PathPrefixes: []string{"/api/", "/search"},
		AllowedCIDRs: []string{"127.0.0.0/8"},
	}}
	a.Limits.MaxRequests = 24
	a.Limits.RatePerSecond = 20
	a.CorpusPartitions = []string{"development", "calibration"}
	a.ExpiresAt = time.Now().UTC().Add(24 * time.Hour)
	if err := contracts.Validate(contracts.IDProfilingAuthorization, a); err != nil {
		t.Fatalf("the test authorization is not a valid C-09: %v", err)
	}
	return a
}

// testIssuer creates (once per directory) the issuer identity the test
// authorizations are signed with, and publishes its public key in a keyring
// beside them. Reusing the seed inside one directory is what lets two copies of
// one permission verify against one key.
func testIssuer(t *testing.T, dir string) (*integrity.Key, string) {
	t.Helper()
	key, err := integrity.LoadOrCreateKey(filepath.Join(dir, "issuer.ed25519"))
	if err != nil {
		t.Fatalf("cannot create the test issuer key: %v", err)
	}
	ring := testKeyring(dir)
	if err := os.MkdirAll(ring, 0o700); err != nil {
		t.Fatalf("cannot create the test issuer keyring: %v", err)
	}
	pub := []byte(hex.EncodeToString(key.Public) + "\n")
	if err := os.WriteFile(filepath.Join(ring, "test-issuer.pub"), pub, 0o600); err != nil {
		t.Fatalf("cannot publish the test issuer key: %v", err)
	}
	return key, ring
}

func testKeyring(dir string) string { return filepath.Join(dir, "issuers") }

// writeAuthFile puts a signed authorization on disk and returns its path, which is
// also the form a finding publishes in a reproduction command. The fingerprint is
// derived from the key rather than typed, exactly as the loader demands.
func writeAuthFile(t *testing.T, dir string, a *contracts.ProfilingAuthorization, name string) string {
	t.Helper()
	key, _ := testIssuer(t, dir)
	a.IssuerKeyFingerprint = integrity.KeyFingerprint(key.Public)
	raw, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		t.Fatalf("cannot encode the test authorization: %v", err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("cannot write %s: %v", path, err)
	}
	canonical, err := contracts.Canonical(*a)
	if err != nil {
		t.Fatalf("cannot canonicalize the test authorization: %v", err)
	}
	sig, err := integrity.SignAuthorization(contracts.IDProfilingAuthorization, canonical, key)
	if err != nil {
		t.Fatalf("cannot sign the test authorization: %v", err)
	}
	if err := integrity.WriteAuthSignature(path, sig); err != nil {
		t.Fatalf("cannot write the signature of %s: %v", path, err)
	}
	return path
}

// TestDispatchExitCodes locks the contract printed in the usage text: 0 succeeded, 1
// refused on the merits, 2 the command line was not usable. A script that cannot tell a
// typo from a refusal cannot tell whether the tool declined to send or was never asked
// correctly.
func TestDispatchExitCodes(t *testing.T) {
	cases := []struct {
		name string
		argv []string
		want int
	}{
		{"no arguments prints usage", nil, 2},
		{"help is a success", []string{"help"}, 0},
		{"unknown command is usage", []string{"scan", "--target", "x"}, 2},
		{"version succeeds", []string{"version"}, 0},
		{"version with a stray word is usage", []string{"version", "extra"}, 2},
		{"corpus needs a subcommand", []string{"corpus"}, 2},
		{"unknown flag is usage", []string{"verify", "--nope"}, 2},
		{"unreadable flag value is usage", []string{"verify", "--budget", "many"}, 2},
		{"verify with no bundle named is usage", []string{"verify"}, 2},
		{"missing bundle is a failure", []string{"verify", "--store", "no-such-bundle"}, 1},
		{"report with no bundle named is usage", []string{"report"}, 2},
		{"validate with no finding is a failure", []string{"validate", "--store", "x"}, 1},
		{"lab needs a subcommand", []string{"lab"}, 2},
		{"lab subcommand unknown is usage", []string{"lab", "up"}, 2},
		{"playbook with no authorization is usage", []string{"playbook"}, 2},
		{"run with no authorization is usage", []string{"run"}, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, out, errs := run(t, tc.argv...)
			if code != tc.want {
				t.Fatalf("exit %d, want %d\nstdout: %s\nstderr: %s", code, tc.want, out, errs)
			}
			if tc.want == 0 && out == "" {
				t.Fatal("exit 0 with no output at all")
			}
			if tc.want != 0 && errs == "" {
				t.Fatal("a refusal must be reported on stderr, got nothing")
			}
			if tc.want == 2 && !bytes.Contains([]byte(errs), []byte("command line")) {
				t.Fatalf("a usage failure must name the command line, so it is separable from a "+
					"refusal on the evidence: %s", errs)
			}
			if bytes.Contains([]byte(out), []byte("xammu: ")) {
				t.Fatalf("an error was printed on stdout, the stream a report is captured from: %s", out)
			}
		})
	}
}

// TestRunTakesEveryFlagTheUsageAdvertises keeps the help screen honest: usage that names
// a flag the parser rejects is worse than no usage, because the operator follows it.
func TestRunTakesEveryFlagTheUsageAdvertises(t *testing.T) {
	for _, flagName := range []string{"--authorization", "--authorizations", "--issuer-keyring",
		"--authorize",
		"--corpus", "--partition", "--controls", "--target", "--budget", "--class", "--vector",
		"--encoding", "--path", "--query-param", "--body-field", "--header-name", "--cookie-name",
		"--media-type", "--run", "--round", "--runs-dir", "--store", "--signing-key",
		"--generated-by", "--validation", "--parent-run", "--circuit-threshold", "--format",
		"--out", "--cell", "--finding", "--trust-key", "--rederive", "--lab-dir", "--scenario",
		"--apply", "--teardown"} {
		if !bytes.Contains([]byte(usageText), []byte(flagName)) {
			t.Errorf("usage text never mentions %s, which a command here takes", flagName)
		}
	}
	fs := newFlagSet("probe", &bytes.Buffer{})
	var f planFlags
	f.register(fs)
	for _, flagName := range []string{"authorization", "corpus", "partition", "target", "budget",
		"class", "vector", "encoding", "path", "query-param", "body-field", "header-name",
		"cookie-name", "media-type", "run", "runs-dir", "store", "issuer-keyring"} {
		if fs.Lookup(flagName) == nil {
			t.Errorf("planFlags does not declare --%s, which the usage text advertises", flagName)
		}
	}
}

// TestCorpusCheckIsTheGateSurface checks the inertness gate's public command against the
// real tree and that it sends nothing.
func TestCorpusCheckIsTheGateSurface(t *testing.T) {
	k := newCanary(t)
	code, out, errs := run(t, "corpus", "check", "--corpus", testCorpusRoot)
	if code != 0 {
		t.Fatalf("the repository corpus must be usable: exit %d\n%s\n%s", code, out, errs)
	}
	for _, want := range []string{"Nothing was sent", "partition discipline"} {
		if !bytes.Contains([]byte(out), []byte(want)) {
			t.Errorf("corpus check must report %q:\n%s", want, out)
		}
	}
	k.idle(t, "corpus check")

	code, _, errs = run(t, "corpus", "check", "--corpus", filepath.Join(t.TempDir(), "empty"))
	if code != 1 {
		t.Fatalf("an absent corpus tree must fail (exit 1), got %d: %s", code, errs)
	}
	if !bytes.Contains([]byte(errs), []byte("corpus")) {
		t.Fatalf("the refusal must name the corpus: %s", errs)
	}
	k.idle(t, "corpus check on an absent tree")
}

// TestLoadAuthorizationResolvesExactlyOnePermission covers the reference lookup a
// published reproduction command depends on.
func TestLoadAuthorizationResolvesExactlyOnePermission(t *testing.T) {
	auth := testAuth(t, 8099)

	single := t.TempDir()
	path := writeAuthFile(t, single, auth, "one.json")

	got, foundIn, err := loadAuthorization(path, "", testKeyring(single))
	if err != nil {
		t.Fatalf("loading by file path: %v", err)
	}
	if got.Ref != auth.Ref {
		t.Fatalf("loaded %q, want %q", got.Ref, auth.Ref)
	}
	// The directory a file path was read from is what a published command has to name:
	// the reference alone would send a reader looking in the default directory for a
	// permission that is not there.
	if foundIn != filepath.Dir(path) {
		t.Fatalf("found in %q, want %q", foundIn, filepath.Dir(path))
	}

	got, foundIn, err = loadAuthorization(auth.Ref, single, testKeyring(single))
	if err != nil {
		t.Fatalf("loading by reference from %s: %v", single, err)
	}
	if got.Ref != auth.Ref {
		t.Fatalf("reference resolved to %q, want %q", got.Ref, auth.Ref)
	}
	if foundIn != single {
		t.Fatalf("a reference must report the directory it resolved in, got %q", foundIn)
	}

	// A value that is not a file is looked up as a reference; two files carrying the same
	// reference cannot answer which permission is being used.
	dual := t.TempDir()
	writeAuthFile(t, dual, auth, "copy-a.json")
	second := *auth
	second.AuthorizationID = contracts.NewUUID()
	writeAuthFile(t, dual, &second, "copy-b.json")
	if _, _, err := loadAuthorization(auth.Ref, dual, testKeyring(dual)); err == nil {
		t.Fatal("a reference that appears in two files must be refused")
	} else if !bytes.Contains([]byte(err.Error()), []byte("appears in 2 files")) {
		t.Fatalf("unexpected refusal: %v", err)
	}

	// A corrupt neighbour has to be counted out loud: silence here means an operator
	// chasing a reference cannot tell absence from damage.
	mixed := t.TempDir()
	writeAuthFile(t, mixed, auth, "good.json")
	if err := os.WriteFile(filepath.Join(mixed, "broken.json"), []byte("{ not json"), 0o600); err != nil {
		t.Fatalf("seeding the corrupt file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(mixed, "notes.txt"), []byte("ignored"), 0o600); err != nil {
		t.Fatalf("seeding the non-json file: %v", err)
	}
	if _, _, err := loadAuthorization("auth-not-here", mixed, testKeyring(mixed)); err == nil {
		t.Fatal("an unknown reference must be refused")
	} else {
		msg := err.Error()
		for _, want := range []string{"1 valid C-09 file(s) checked",
			"1 file(s) in that directory are not valid"} {
			if !bytes.Contains([]byte(msg), []byte(want)) {
				t.Errorf("refusal must state %q, got: %v", want, err)
			}
		}
	}

	// A .json path that does not exist falls through to the reference lookup, and a bare
	// reference with no directory to search has to say so rather than claim absence.
	if _, _, err := loadAuthorization(filepath.Join(t.TempDir(), "gone.json"), "", ""); err == nil {
		t.Fatal("a path that does not exist must be refused")
	}
	if _, _, err := loadAuthorization("any-ref", "", ""); err == nil ||
		!bytes.Contains([]byte(err.Error()), []byte("no --authorizations dir")) {
		t.Fatalf("a bare reference with no directory must name it, got: %v", err)
	}

	if _, _, err := loadAuthorization("", single, testKeyring(single)); !errors.Is(err, errUsage) {
		t.Fatalf("an empty authorization must be a usage failure, got: %v", err)
	}
}

// TestRunRefusesBeforeTouchingAnything is the security property of the whole CLI: the
// refusals that keep requests off a target happen before a socket exists, and the tool
// never opens the bundle it declined to write.
func TestRunRefusesBeforeTouchingAnything(t *testing.T) {
	k := newCanary(t)
	dir := t.TempDir()
	a := testAuth(t, k.port())
	authPath := writeAuthFile(t, dir, a, "auth.json")
	runsDir := filepath.Join(dir, "runs")
	base := []string{"run", "--authorization", authPath,
		"--issuer-keyring", testKeyring(dir),
		"--corpus", testCorpusRoot, "--runs-dir", runsDir,
		"--class", "sqli", "--vector", "query", "--budget", "8"}

	cases := []struct {
		name   string
		extra  []string
		code   int
		wanted string
	}{
		{
			name:   "no --authorize",
			code:   2,
			wanted: "run needs --authorize",
		},
		{
			name:   "mismatched --authorize",
			extra:  []string{"--authorize", "some-other-permission", "--run", "cli-test"},
			code:   1,
			wanted: "run refuses to send traffic under a permission the operator did not name",
		},
		{
			name:   "missing --run",
			extra:  []string{"--authorize", a.Ref},
			code:   2,
			wanted: "run needs --run",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			argv := append(append([]string{}, base...), tc.extra...)
			code, out, errs := run(t, argv...)
			if code != tc.code {
				t.Fatalf("exit %d, want %d\nstdout: %s\nstderr: %s", code, tc.code, out, errs)
			}
			if !bytes.Contains([]byte(errs), []byte(tc.wanted)) {
				t.Fatalf("refusal must state %q, got: %s", tc.wanted, errs)
			}
			if _, err := os.Stat(runsDir); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("a refused run must not create its bundle directory (%v)", err)
			}
			if bytes.Contains([]byte(out), []byte("executed")) ||
				bytes.Contains([]byte(out), []byte("written")) {
				t.Fatalf("a refused run produced output it should not have reached: %s", out)
			}
			k.idle(t, "run "+tc.name)
		})
	}
}

// TestRunRefusesAnExpiredAuthorization covers the expiry pre-check: a spent permission is
// still a file on disk, and that is not a reason to use it.
func TestRunRefusesAnExpiredAuthorization(t *testing.T) {
	k := newCanary(t)
	dir := t.TempDir()
	expired := testAuth(t, k.port())
	expired.ExpiresAt = time.Now().UTC().Add(-time.Hour)
	authPath := writeAuthFile(t, dir, expired, "expired.json")

	code, out, errs := run(t, "run", "--authorization", authPath,
		"--issuer-keyring", testKeyring(dir),
		"--authorize", expired.Ref, "--run", "cli-test-expired",
		"--corpus", testCorpusRoot, "--runs-dir", filepath.Join(dir, "runs"))
	if code != 1 {
		t.Fatalf("an expired authorization must fail (exit 1), got %d\n%s\n%s", code, out, errs)
	}
	for _, want := range []string{"expired at", "nothing was sent"} {
		if !bytes.Contains([]byte(errs), []byte(want)) {
			t.Errorf("the refusal must state %q: %s", want, errs)
		}
	}
	if bytes.Contains([]byte(out), []byte("executed")) {
		t.Fatalf("an expired authorization must not reach execution: %s", out)
	}
	k.idle(t, "run with an expired authorization")
}

// TestRefuseOverwrite covers the rule that a run never extends an existing bundle.
func TestRefuseOverwrite(t *testing.T) {
	dir := t.TempDir()
	if err := refuseOverwrite(filepath.Join(dir, "absent")); err != nil {
		t.Fatalf("a directory that does not exist is not an overwrite: %v", err)
	}
	if err := refuseOverwrite(dir); err != nil {
		t.Fatalf("an empty directory is not an overwrite: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, runCheckpointFile), []byte("{}"), 0o600); err != nil {
		t.Fatalf("seeding the bundle: %v", err)
	}
	err := refuseOverwrite(dir)
	if err == nil {
		t.Fatal("a bundle that already holds files must be refused")
	}
	for _, want := range []string{"already holds 1 file(s)", "Choose another --run"} {
		if !bytes.Contains([]byte(err.Error()), []byte(want)) {
			t.Errorf("refusal must state %q, got: %v", want, err)
		}
	}
}

// TestPlaybookPlansAndSendsNothing checks that the preview keeps its promise: the same
// arithmetic a run pays for, at no cost.
func TestPlaybookPlansAndSendsNothing(t *testing.T) {
	k := newCanary(t)
	dir := t.TempDir()
	a := testAuth(t, k.port())
	authPath := writeAuthFile(t, dir, a, "auth.json")

	code, out, errs := run(t, "playbook", "--authorization", authPath,
		"--issuer-keyring", testKeyring(dir),
		"--corpus", testCorpusRoot, "--class", "sqli", "--vector", "query", "--budget", "24")
	if code != 0 {
		t.Fatalf("playbook must plan the repository corpus: exit %d\n%s\n%s", code, out, errs)
	}
	for _, want := range []string{"exchange(s) planned", "nothing was sent", a.Ref} {
		if !bytes.Contains([]byte(out), []byte(want)) {
			t.Errorf("the preview must state %q:\n%s", want, out)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "runs")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("playbook must not write a bundle: %v", err)
	}
	k.idle(t, "playbook")

	// A budget that fits the calibration traffic and no probe buys a run with nothing to
	// compare, so it is refused while it still costs nothing. Requests are somebody
	// else's resource; discovering this after spending them is the worst time to learn it.
	code, out, errs = run(t, "playbook", "--authorization", authPath,
		"--issuer-keyring", testKeyring(dir),
		"--corpus", testCorpusRoot, "--class", "sqli", "--vector", "query", "--budget", "8")
	if code != 1 || !bytes.Contains([]byte(errs), []byte("the plan holds none")) ||
		!bytes.Contains([]byte(errs), []byte("raise --budget")) {
		t.Fatalf("a budget that leaves no probe must be refused with its arithmetic:\n%s\n%s", out, errs)
	}
	k.idle(t, "playbook with a probe-less budget")

	// A class the permission does not name is refused rather than quietly dropped, or the
	// operator would believe they asked for it.
	code, out, errs = run(t, "playbook", "--authorization", authPath,
		"--issuer-keyring", testKeyring(dir),
		"--corpus", testCorpusRoot, "--class", "sqli,xxe", "--budget", "8")
	if code != 1 {
		t.Fatalf("an unauthorized class must fail (exit 1), got %d\n%s\n%s", code, out, errs)
	}
	if !bytes.Contains([]byte(errs), []byte("not authorized")) {
		t.Fatalf("refusal must name the authorization: %s", errs)
	}
	k.idle(t, "playbook with an unauthorized class")
}

// TestBundleLookup covers where a bundle lives: --store is taken as written, --run is
// looked up under --runs-dir, and naming neither is a usage failure.
func TestBundleLookup(t *testing.T) {
	f := planFlags{storeDir: filepath.Join("somewhere", "else")}
	dir, err := f.bundle()
	if err != nil || dir != f.storeDir {
		t.Fatalf("--store must win: %q %v", dir, err)
	}
	f = planFlags{runID: "run-1", runsDir: "runs"}
	if dir, err = f.bundle(); err != nil {
		t.Fatalf("--run lookup: %v", err)
	}
	if want := filepath.Join("runs", "run-1"); dir != want {
		t.Fatalf("bundle() = %q, want %q", dir, want)
	}
	neither := planFlags{}
	if _, err := neither.bundle(); !errors.Is(err, errUsage) {
		t.Fatalf("naming neither must be a usage failure, got %v", err)
	}
	noHome := planFlags{runID: "run-1"}
	if _, err := noHome.bundle(); !errors.Is(err, errUsage) {
		t.Fatalf("an empty --runs-dir must be a usage failure, got %v", err)
	}
}

// TestReproFlagsNamesEveryNonDefaultChoice keeps the published reproduction commands
// complete: a reader who pastes one has to re-plan the same exchanges, and a placement
// name silently omitted re-plans a different set.
func TestReproFlagsNamesEveryNonDefaultChoice(t *testing.T) {
	full := planFlags{
		corpusRoot: testCorpusRoot, partition: "development", controls: "calibration",
		path: defaultPlacementPath, runsDir: defaultRunsDir,
	}
	if got := full.reproFlags(); got != "--corpus "+filepath.ToSlash(testCorpusRoot) {
		t.Fatalf("defaults must not be quoted back at the reader, got %q", got)
	}

	corpusDir := filepath.Join(t.TempDir(), "my corpus")
	runsDir := filepath.Join(t.TempDir(), "evidence")
	narrow := planFlags{
		corpusRoot: corpusDir, partition: "development", controls: "independent_validation",
		path: "/api/v1/search", queryParam: "q", bodyField: "s", headerName: "X-Test",
		cookieName: "sid", mediaType: "application/json", classes: "sqli,xss",
		vectors: "query", encodings: "canonical", runsDir: runsDir,
	}
	got := narrow.reproFlags()
	for _, want := range []string{"--corpus ", "--path /api/v1/search", "--query-param q",
		"--body-field s", "--header-name X-Test", "--cookie-name sid",
		"--media-type application/json", "--runs-dir "} {
		if !bytes.Contains([]byte(got), []byte(want)) {
			t.Errorf("reproduction flags omit %q, so the pasted command re-plans a different "+
				"set:\n%s", want, got)
		}
	}
	// The scope of this run is not rendered here: it comes from the scope that was
	// resolved, through scopeFlagsOf, so a run and a re-read of its bundle publish one
	// command instead of two spellings of the same plan.
	for _, forbidden := range []string{"--budget", "--class", "--vector", "--encoding", "--controls"} {
		if bytes.Contains([]byte(got), []byte(forbidden)) {
			t.Errorf("reproduction flags must not render the scope %q, which scopeFlagsOf "+
				"derives from the resolved plan:\n%s", forbidden, got)
		}
	}
	if bytes.Contains([]byte(got), []byte("--partition")) {
		t.Errorf("the partition comes from the checkpoint, not from the reader: %s", got)
	}
	if !bytes.Contains([]byte(got), []byte(`"`+filepath.ToSlash(corpusDir)+`"`)) {
		t.Errorf("a corpus path with a space must be quoted as one argument:\n%s", got)
	}

	// The permission is part of what made the plan. A published command without it
	// either resolves no scope at all or re-plans under another one, and in both cases
	// the reader believes they re-ran the measurement.
	//
	// A bound permission publishes its reference, not the path the operator typed: the
	// report cites the reference in its evidence block, and a reader was given a
	// permission, not the operator's directory layout. The directory it resolved in
	// travels with it, because a reference without a place to look is unresolvable.
	scoped := narrow
	scoped.authorization = filepath.Join(t.TempDir(), "my auth.json")
	scoped.authorizationRef = "auth-2026-1028"
	scoped.authorizationDir = filepath.Join(t.TempDir(), "permissions")
	scoped.budget = 17
	scoped.authDir = "/should/not/appear"
	scoped.runID = "run-7"
	scopedOut := scoped.reproFlags()
	for _, want := range []string{"--authorization auth-2026-1028", "--authorizations ",
		filepath.ToSlash(scoped.authorizationDir)} {
		if !bytes.Contains([]byte(scopedOut), []byte(want)) {
			t.Errorf("reproduction flags omit %q, so the command does not repeat what the run "+
				"was planned under:\n%s", want, scopedOut)
		}
	}
	for _, forbidden := range []string{"my auth.json", "/should/not/appear"} {
		if bytes.Contains([]byte(scopedOut), []byte(forbidden)) {
			t.Errorf("reproduction flags publish %q, which is a fact about this operator's disk "+
				"and not the permission the report cites:\n%s", forbidden, scopedOut)
		}
	}
	if bytes.Contains([]byte(scopedOut), []byte(`\`)) {
		t.Errorf("a Windows separator in a pasted command is an escape character; the path must "+
			"be slash-separated:\n%s", scopedOut)
	}

	// An unbound set of flags - what a unit test or a plan-only caller holds - still
	// names the permission as written, because a command that cites no authorization is
	// a command that resolves no scope.
	typed := narrow
	typed.authorization = filepath.Join(t.TempDir(), "my auth.json")
	typedOut := typed.reproFlags()
	if !bytes.Contains([]byte(typedOut), []byte(`--authorization "`)) ||
		!bytes.Contains([]byte(typedOut), []byte("my auth.json")) {
		t.Errorf("without a resolved reference the flags must publish the value as written:\n%s", typedOut)
	}

	// The engagement set is the same material with the scope taken out, because the
	// steps that ask for a class this run never planned must not inherit --class.
	eng := scoped.engagementFlags()
	for _, forbidden := range []string{"--class", "--vector", "--encoding", "--budget", "--partition"} {
		if bytes.Contains([]byte(eng), []byte(forbidden)) {
			t.Errorf("engagement flags must not carry the scope %q, or a step written to widen "+
				"the plan re-asks this run's question:\n%s", forbidden, eng)
		}
	}
	for _, want := range []string{"--authorization", "--corpus", "--path /api/v1/search",
		"--header-name X-Test"} {
		if !bytes.Contains([]byte(eng), []byte(want)) {
			t.Errorf("engagement flags omit %q, so the reader cannot locate the permission or "+
				"place the probe:\n%s", want, eng)
		}
	}

	// A value with a space or a quote has to survive the shell, or the command splits and
	// the failure gets blamed on the tool.
	cases := []struct{ in, want string }{
		{"a b", `"a b"`},
		{`say "hi"`, `"say \"hi\""`},
		{"/api/v1/search", "/api/v1/search"},
		{"", `""`},
		{"tab\there", "\"tab\there\""},
		{"it's", `"it's"`},
	}
	for _, tc := range cases {
		if got := shellArg(tc.in); got != tc.want {
			t.Errorf("shellArg(%q) = %s, want %s", tc.in, got, tc.want)
		}
	}

	// The verify command a run prints and a report publishes has to find the bundle it
	// names, wherever the operator kept it, and has to carry the scope of the plan it
	// re-derives.
	cmd := verifyCommandOf("run-9", "xammu-placeholder")
	if !strings.HasPrefix(cmd, "xammu verify --run run-9 ") {
		t.Errorf("verify command %q must name the run it re-reads", cmd)
	}
	flags := planFlags{corpusRoot: "corpus", runsDir: "/evidence/2026"}.reproFlags()
	cmd = verifyCommandOf("run-9", flags)
	for _, want := range []string{"xammu verify --run run-9", "--corpus corpus",
		"--runs-dir /evidence/2026"} {
		if !bytes.Contains([]byte(cmd), []byte(want)) {
			t.Errorf("verify command %q must contain %q", cmd, want)
		}
	}

	// A reader who opened the bundle by directory typed no run id. The command the
	// re-issued report publishes still has to name one, or it cites evidence nobody can
	// locate - so the id comes from the bundle, not from the flags.
	fromProfile := verifyCommandOf("run-from-checkpoint", planFlags{corpusRoot: "corpus"}.reproFlags())
	if !strings.HasPrefix(fromProfile, "xammu verify --run run-from-checkpoint ") {
		t.Errorf("the published verify command must name the run it re-read: %q", fromProfile)
	}
	if !bytes.Contains([]byte(fromProfile), []byte("--corpus corpus")) {
		t.Errorf("verify command %q lost the corpus the reader had to supply", fromProfile)
	}
	if got := verifyCommandOf("run-9", planFlags{corpusRoot: "corpus",
		runsDir: defaultRunsDir}.reproFlags()); bytes.Contains([]byte(got), []byte("--runs-dir")) {
		t.Fatalf("the default runs directory must not clutter the published command: %q", got)
	}
}

// TestScopeFlagsAreTheScopeNotTheKeystrokes locks the rule that lets a run and a
// re-read of its bundle publish one command: the scope half of a reproduction command
// is rendered from the resolved scope, not from what the operator typed. Two spellings
// of one plan render one string, a plan that narrows nothing renders none, and the
// string resolves back to the scope it describes.
func TestScopeFlagsAreTheScopeNotTheKeystrokes(t *testing.T) {
	auth := testAuth(t, 8443)
	full := scope{classes: auth.AllowedClasses, vectors: auth.AllowedVectors,
		encodings: auth.AllowedEncodings, controls: contracts.PartitionCalibration,
		budget: auth.Limits.MaxRequests}
	if got := scopeFlagsOf(full, auth); got != "" {
		t.Fatalf("a plan that narrows nothing must publish no scope flags, got %q", got)
	}

	narrow := scope{
		classes:   []contracts.AttackClass{contracts.ClassSQLi, contracts.ClassXSS},
		vectors:   []contracts.Vector{contracts.VectorQuery},
		encodings: []contracts.Encoding{contracts.EncodingCanonical},
		controls:  contracts.PartitionIndependent,
		budget:    17,
	}
	got := scopeFlagsOf(narrow, auth)
	for _, want := range []string{"--budget 17", "--class sqli,xss", "--vector query",
		"--encoding canonical", "--controls independent_validation"} {
		if !strings.Contains(got, want) {
			t.Errorf("scope flags omit %q, so the pasted command re-plans a different set:\n%s",
				want, got)
		}
	}
	if strings.Contains(got, "--partition") {
		t.Errorf("the partition comes from the checkpoint, not from the command: %s", got)
	}

	reordered := narrow
	reordered.classes = []contracts.AttackClass{contracts.ClassXSS, contracts.ClassSQLi}
	if a, b := scopeFlagsOf(narrow, auth), scopeFlagsOf(reordered, auth); a != b {
		t.Fatalf("two orderings of one scope must render one command:\n%s\n%s", a, b)
	}

	f := planFlags{}
	fs := newFlagSet("scope-flags", &bytes.Buffer{})
	f.register(fs)
	if err := parseFlags(fs, strings.Fields(got)); err != nil {
		t.Fatalf("a published scope must parse back: %v", err)
	}
	back, err := resolveScope(auth, f)
	if err != nil {
		t.Fatalf("a published scope must resolve under its permission: %v", err)
	}
	if !sameSet(back.classes, narrow.classes) || !sameSet(back.vectors, narrow.vectors) ||
		!sameSet(back.encodings, narrow.encodings) || back.budget != narrow.budget ||
		back.controls != narrow.controls {
		t.Fatalf("the published flags re-plan a different scope: %+v, want %+v", back, narrow)
	}
}

// unplannedFrom and unplannedReason decide what an unevaluated zone blames. Getting them
// wrong makes the report claim a gap that is actually the design.

func TestUnplannedFromLeavesCalibrationOut(t *testing.T) {
	// These are the exact sentences corpus.Select writes; the filter and the mapping are
	// only correct against the strings a real selection produces.
	sel := &corpus.Selection{Excluded: []corpus.Exclusion{
		{Ref: "CAL-POS-Q-01",
			Reason: "calibration traffic: it validates the detectors, so it stays out of the " +
				"denominator it measures"},
		{Ref: "CAL-NEG-Q-01",
			Reason: "control lives in a class, vector or encoding the authorization does not cover"},
		{Ref: "DEV-SQLI-Q-07", Reason: "the authorized budget ended before this cell's next pass"},
		{Ref: "DEV-XXE-Q-01", Reason: "attack class xxe is not in the authorization"},
	}}
	out := unplannedFrom(sel)
	if len(out) != 2 {
		t.Fatalf("calibration exclusions are the design, not a gap: %+v", out)
	}
	if out[0].Ref != "DEV-SQLI-Q-07" || out[0].Reason != contracts.ReasonBudgetExhausted {
		t.Fatalf("budget exclusion mapped to %+v", out[0])
	}
	if out[1].Ref != "DEV-XXE-Q-01" || out[1].Reason != contracts.ReasonAuthorizationGap {
		t.Fatalf("scope exclusion mapped to %+v", out[1])
	}
	if unplannedFrom(&corpus.Selection{}) != nil {
		t.Fatal("a selection with no exclusions must yield no unplanned items")
	}
}

func TestUnplannedReasonMapping(t *testing.T) {
	cases := []struct {
		detail string
		want   contracts.ReasonCode
	}{
		{"the authorized budget ended before this cell's next pass", contracts.ReasonBudgetExhausted},
		{"attack class xxe is not in the authorization", contracts.ReasonAuthorizationGap},
		{"control lives in a class, vector or encoding the authorization does not cover",
			contracts.ReasonAuthorizationGap},
		{"no probe covers this cell", contracts.ReasonCorpusGap},
		{"", contracts.ReasonCorpusGap},
	}
	for _, tc := range cases {
		if got := unplannedReason(tc.detail); got != tc.want {
			t.Errorf("unplannedReason(%q) = %q, want %q", tc.detail, got, tc.want)
		}
	}
}

// TestCompareFindingIsReaderRelevant: validate and --rederive decide "does this claim
// still come out of this evidence" from this function, so it has to name the fields a
// reader acts on and ignore the ones a re-derivation legitimately rewrites.
func TestCompareFindingIsReaderRelevant(t *testing.T) {
	published := contracts.ValidFinding()
	rewritten := *published
	rewritten.FindingID = contracts.NewUUID()
	rewritten.DetectedAt = published.DetectedAt.Add(3 * time.Hour)
	rewritten.EvidenceProfileRef = published.EvidenceProfileRef + "-again"
	if diffs := compareFinding(*published, rewritten); len(diffs) != 0 {
		t.Fatalf("identifiers and timestamps are the writing of the record, not claims: %v", diffs)
	}

	tampered := *published
	tampered.FindingType = contracts.FindingOverBlocking
	diffs := compareFinding(*published, tampered)
	if len(diffs) != 1 {
		t.Fatalf("one changed field must be one difference, got %v", diffs)
	}
	for _, want := range []string{"finding_type", string(published.FindingType),
		string(contracts.FindingOverBlocking)} {
		if !bytes.Contains([]byte(diffs[0]), []byte(want)) {
			t.Fatalf("the difference must state both values of %q: %s", want, diffs[0])
		}
	}

	claimChanged := *published
	claimChanged.ClaimType = contracts.ClaimAttribution
	if diffs := compareFinding(*published, claimChanged); len(diffs) != 1 ||
		!bytes.Contains([]byte(diffs[0]), []byte("claim_type")) {
		t.Fatalf("a stronger claim must be reported as such: %v", diffs)
	}

	refsDropped := *published
	refsDropped.ObservationRefs = refsDropped.ObservationRefs[:len(refsDropped.ObservationRefs)-1]
	if diffs := compareFinding(*published, refsDropped); len(diffs) == 0 ||
		!bytes.Contains([]byte(diffs[0]), []byte("observation_refs")) {
		t.Fatalf("a finding that cites less evidence must diverge: %v", diffs)
	}

	reproMoved := *published
	reproMoved.ReproductionCommand = reproMoved.ReproductionCommand + " --class xss"
	if diffs := compareFinding(*published, reproMoved); len(diffs) == 0 ||
		!bytes.Contains([]byte(diffs[0]), []byte("reproduction_command")) {
		t.Fatalf("a reproduction command that re-plans something else must diverge: %v", diffs)
	}

	evidenceMoved := *published
	evidenceMoved.EvidenceLevel = contracts.EvidenceReplicated
	if diffs := compareFinding(*published, evidenceMoved); len(diffs) == 0 ||
		!bytes.Contains([]byte(diffs[0]), []byte("evidence_level")) {
		t.Fatalf("a raised grade must diverge: %v", diffs)
	}

	impactMoved := *published
	impactMoved.MeasuredImpact.Numerator++
	if diffs := compareFinding(*published, impactMoved); len(diffs) == 0 ||
		!bytes.Contains([]byte(diffs[0]), []byte("measured_impact")) {
		t.Fatalf("a changed ratio must diverge: %v", diffs)
	}
}

// TestDecodeHexKey covers the format a trusted key file has to be in. A key silently
// misread would make every bundle look untrusted.
func TestDecodeHexKey(t *testing.T) {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i)
	}
	hexKey := hex.EncodeToString(raw)
	got, err := decodeHexKey(hexKey + "\n")
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("a hex key with a trailing newline must load: %x %v", got, err)
	}
	if _, err := decodeHexKey(hexKey[:62]); err == nil ||
		!bytes.Contains([]byte(err.Error()), []byte("32")) {
		t.Fatalf("a short key must be refused with its length: %v", err)
	}
	if _, err := decodeHexKey(hexKey + " " + hexKey); err == nil ||
		!bytes.Contains([]byte(err.Error()), []byte("exactly one")) {
		t.Fatalf("two keys in one file must be refused: %v", err)
	}
	if _, err := decodeHexKey("zzzz"); err == nil ||
		!bytes.Contains([]byte(err.Error()), []byte("hex")) {
		t.Fatalf("non-hex must be refused as such: %v", err)
	}
}

// sealedBundle writes a minimal but genuinely signed bundle: journals hashed into the
// chain, a C-11 checkpoint and a manifest signed by a key kept outside the directory.
// Nothing here needs a target, which is the point a reviewer cares about.
func sealedBundle(t *testing.T) (string, *integrity.Key, contracts.RunProfile) {
	t.Helper()
	return sealedBundleDamaged(t, nil)
}

// sealedBundleDamaged builds a bundle, damages it after the journals are written, then
// signs the inventory of what is on disk - which is exactly how a forgery gets made.
func sealedBundleDamaged(t *testing.T, damage func(dir string)) (string, *integrity.Key, contracts.RunProfile) {
	t.Helper()
	dir := t.TempDir()
	store, err := integrity.Open(dir)
	if err != nil {
		t.Fatalf("opening the store: %v", err)
	}
	obs := contracts.ValidRawObservation()
	if _, err := store.Append(integrity.StreamObservations, obs); err != nil {
		t.Fatalf("journaling the observation: %v", err)
	}
	if _, err := store.AppendNote("cli test: one exchange, journaled before the seal"); err != nil {
		t.Fatalf("journaling the note: %v", err)
	}
	profile := *contracts.ValidCompletedRun()
	profile.RunID = obs.RunID
	raw, err := json.MarshalIndent(&profile, "", "  ")
	if err != nil {
		t.Fatalf("encoding the checkpoint: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, runCheckpointFile), raw, 0o640); err != nil {
		t.Fatalf("writing the checkpoint: %v", err)
	}
	if damage != nil {
		damage(dir)
	}
	manifest, err := integrity.BuildManifest(dir, profile.RunID, profile.AuthorizationRef,
		profile.ValidationRef, store.Count(integrity.StreamObservations),
		store.Head(integrity.StreamObservations))
	if err != nil {
		t.Fatalf("building the manifest: %v", err)
	}
	key, err := integrity.LoadOrCreateKey(filepath.Join(t.TempDir(), integrity.KeyFileName))
	if err != nil {
		t.Fatalf("loading the signing key: %v", err)
	}
	if err := integrity.Sign(&manifest, key); err != nil {
		t.Fatalf("signing: %v", err)
	}
	if err := integrity.WriteManifest(dir, manifest); err != nil {
		t.Fatalf("writing the manifest: %v", err)
	}
	store.Seal()
	return dir, key, profile
}

func writeHexKey(t *testing.T, pub []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "trust.hex")
	if err := os.WriteFile(path, []byte(hex.EncodeToString(pub)+"\n"), 0o600); err != nil {
		t.Fatalf("writing the trusted key: %v", err)
	}
	return path
}

// TestVerifyAnchorednessIsNotFailure draws the line the published reproduction command
// depends on: `xammu verify --run ID` must succeed for a sound bundle whose signer the
// reader has not anchored, and must fail for one that does not add up.
func TestVerifyAnchorednessIsNotFailure(t *testing.T) {
	k := newCanary(t)
	dir, key, profile := sealedBundle(t)

	code, out, errs := run(t, "verify", "--store", dir)
	if code != 0 {
		t.Fatalf("a signed bundle must verify without a trust anchor: exit %d\n%s\n%s", code, out, errs)
	}
	for _, want := range []string{profile.RunID, "note", integrity.CheckSignerTrusted,
		"no trusted key was supplied", "--trust-key"} {
		if !bytes.Contains([]byte(out), []byte(want)) {
			t.Errorf("verify must say %q, so an unanchored identity is never mistaken for "+
				"soundness:\n%s", want, out)
		}
	}
	if bytes.Contains([]byte(out), []byte("FAIL")) {
		t.Fatalf("an unanchored signer must not be printed as a failure:\n%s", out)
	}
	k.idle(t, "verify")

	trusted := writeHexKey(t, []byte(key.Public))
	code, out, errs = run(t, "verify", "--store", dir, "--trust-key", trusted)
	if code != 0 {
		t.Fatalf("the signing key itself must be accepted: exit %d\n%s\n%s", code, out, errs)
	}
	if bytes.Contains([]byte(out), []byte("no trusted key was supplied")) {
		t.Fatalf("with an anchor the identity is a real check and must not be footnoted:\n%s", out)
	}
	k.idle(t, "verify --trust-key")

	// Someone else's key is a statement about who signed this evidence.
	other, err := integrity.LoadOrCreateKey(filepath.Join(t.TempDir(), integrity.KeyFileName))
	if err != nil {
		t.Fatalf("generating the other key: %v", err)
	}
	code, out, errs = run(t, "verify", "--store", dir, "--trust-key", writeHexKey(t, []byte(other.Public)))
	if code != 1 {
		t.Fatalf("a mismatched trusted key must fail (exit 1), got %d\n%s\n%s", code, out, errs)
	}
	if !bytes.Contains([]byte(out), []byte("FAIL")) ||
		!bytes.Contains([]byte(out), []byte(integrity.CheckSignerTrusted)) {
		t.Fatalf("the failure must name the signer check:\n%s", out)
	}
	if !bytes.Contains([]byte(errs), []byte("does not verify")) {
		t.Fatalf("the stderr summary must be explicit: %s", errs)
	}
	k.idle(t, "verify with a wrong trusted key")

	if code, _, errs = run(t, "verify", "--store", dir, "--trust-key",
		filepath.Join(dir, "absent.hex")); code != 1 ||
		!bytes.Contains([]byte(errs), []byte("cannot read the trusted key")) {
		t.Fatalf("an unreadable trust file must be refused by name: exit %d %s", code, errs)
	}
}

// TestVerifyCatchesEvidenceDamage: a bundle whose trail no longer commits to itself, or
// to the files beside it, has to fail rather than verify with a note.
func TestVerifyCatchesEvidenceDamage(t *testing.T) {
	dir, _, _ := sealedBundle(t)

	// A record inserted after the seal is chain-valid but not in the signed inventory:
	// the signature is what catches it.
	extra, err := integrity.Open(dir)
	if err != nil {
		t.Fatalf("reopening the store: %v", err)
	}
	forged := contracts.ValidRawObservation()
	forged.ObservationID = contracts.NewUUID()
	forged.Sequence = 2
	if _, err := extra.Append(integrity.StreamObservations, forged); err != nil {
		t.Fatalf("inserting the forged record: %v", err)
	}
	code, out, errs := run(t, "verify", "--store", dir)
	if code != 1 {
		t.Fatalf("a record added after the seal must fail, got exit %d\n%s\n%s", code, out, errs)
	}
	if !bytes.Contains([]byte(out), []byte("FAIL")) {
		t.Fatalf("the forged record must be reported as a failure:\n%s", out)
	}

	// Rewriting a journaled line breaks the chain itself.
	rewritten, _, _ := sealedBundleDamaged(t, func(dir string) {
		path := filepath.Join(dir, "observations.jsonl")
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		patched := bytes.Replace(raw, []byte("403"), []byte("200"), 1)
		if bytes.Equal(patched, raw) {
			t.Fatal("the seeded observation holds no status to rewrite")
		}
		if err := os.WriteFile(path, patched, 0o640); err != nil {
			t.Fatalf("rewriting %s: %v", path, err)
		}
	})
	code, out, errs = run(t, "verify", "--store", rewritten)
	if code != 1 {
		t.Fatalf("a rewritten journal line must fail, got exit %d\n%s\n%s", code, out, errs)
	}
	if !bytes.Contains([]byte(out+errs), []byte("digest mismatch")) &&
		!bytes.Contains([]byte(out+errs), []byte("hash_chain")) {
		t.Fatalf("the refusal must point at the broken chain:\n%s\n%s", out, errs)
	}

	// A checkpoint that is not a C-11 is not a run, and no report may be built on it.
	bogus, _, _ := sealedBundleDamaged(t, func(dir string) {
		if err := os.WriteFile(filepath.Join(dir, runCheckpointFile), []byte(`{"run_id":"x"}`),
			0o640); err != nil {
			t.Fatalf("writing a bogus checkpoint: %v", err)
		}
	})
	if code, out, errs = run(t, "verify", "--store", bogus); code != 1 ||
		!bytes.Contains([]byte(errs), []byte("C-11")) {
		t.Fatalf("an invalid checkpoint must be refused as a C-11 failure: exit %d\n%s\n%s",
			code, out, errs)
	}

	// The manifest is the entry point: without one there is nothing to check against.
	noManifest := filepath.Join(t.TempDir(), "unsigned")
	store, err := integrity.Open(noManifest)
	if err != nil {
		t.Fatalf("opening the unsigned store: %v", err)
	}
	if _, err := store.AppendNote("sealed but never signed"); err != nil {
		t.Fatalf("journaling the note: %v", err)
	}
	profile := contracts.ValidCompletedRun()
	raw, err := json.Marshal(profile)
	if err != nil {
		t.Fatalf("encoding the checkpoint: %v", err)
	}
	if err := os.WriteFile(filepath.Join(noManifest, runCheckpointFile), raw, 0o640); err != nil {
		t.Fatalf("writing the checkpoint: %v", err)
	}
	if code, _, errs = run(t, "verify", "--store", noManifest); code != 1 ||
		!bytes.Contains([]byte(errs), []byte("manifest")) {
		t.Fatalf("a bundle with no manifest must be refused: exit %d %s", code, errs)
	}
}

// TestVerifyStatesWhatTheSignatureDoesNotCover: the report is written after the seal, so a
// signature cannot authenticate it. The boundary has to be said out loud, and
// re-derivation named as the thing that checks it.
func TestVerifyStatesWhatTheSignatureDoesNotCover(t *testing.T) {
	dir, _, _ := sealedBundle(t)
	if _, err := os.Stat(filepath.Join(dir, reportJSONFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("this bundle must hold no published report yet: %v", err)
	}
	code, out, errs := run(t, "verify", "--store", dir)
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errs)
	}
	if bytes.Contains([]byte(out), []byte("outside the signed inventory")) {
		t.Fatalf("a bundle of journals only must not claim derived documents:\n%s", out)
	}

	// Publish the two documents the way report --out does, then re-verify: they must be
	// named as outside what the signature commits to.
	raw, err := json.MarshalIndent(contracts.ValidReport(), "", "  ")
	if err != nil {
		t.Fatalf("encoding the report fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, reportJSONFile), raw, 0o640); err != nil {
		t.Fatalf("publishing the document: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, reportMarkdown), []byte("# report\n"), 0o640); err != nil {
		t.Fatalf("publishing the markdown: %v", err)
	}
	code, out, errs = run(t, "verify", "--store", dir)
	if code != 0 {
		t.Fatalf("a derived document does not invalidate the evidence: exit %d\n%s\n%s",
			code, out, errs)
	}
	for _, want := range []string{"outside the signed inventory", reportJSONFile, reportMarkdown,
		"--rederive"} {
		if !bytes.Contains([]byte(out), []byte(want)) {
			t.Errorf("verify must name %q as derived after the seal:\n%s", want, out)
		}
	}
	listed := outsideInventory(dir, contracts.IntegrityManifest{Files: []contracts.ManifestFileEntry{
		{Path: "observations.jsonl"}, {Path: "notes.jsonl"}, {Path: "run.json"},
	}})
	for _, want := range []string{reportJSONFile, reportMarkdown} {
		if !containsString(listed, want) {
			t.Errorf("outsideInventory must list %q, got %v", want, listed)
		}
	}
	for _, got := range listed {
		if got == "run.json" || got == "manifest.json" || got == "observations.jsonl" {
			t.Errorf("outsideInventory must not list signed or covered files: %v", listed)
		}
	}
	if listed := outsideInventory(filepath.Join(t.TempDir(), "absent"),
		contracts.IntegrityManifest{}); listed != nil {
		t.Fatalf("an unreadable directory must yield nothing rather than a guess: %v", listed)
	}
}

// TestRederiveNeedsThePermissionThatPaidForIt: a re-derivation re-issues the report, and
// the evidence ladder starts at the authorization. The refusal has to come before the
// evidence is printed, or the operator reads forty checks and then a complaint.
func TestRederiveNeedsThePermissionThatPaidForIt(t *testing.T) {
	dir, _, _ := sealedBundle(t)
	code, out, errs := run(t, "verify", "--store", dir, "--rederive")
	if code != 1 {
		t.Fatalf("--rederive without --authorization must fail, got %d\n%s\n%s", code, out, errs)
	}
	if !bytes.Contains([]byte(errs), []byte("--authorization")) {
		t.Fatalf("the refusal must name the missing flag: %s", errs)
	}
	if bytes.Contains([]byte(out), []byte("re-derivation over")) {
		t.Fatalf("the refusal must come before the evidence dump:\n%s", out)
	}
}

// TestReadCommandsNeverConnect is the general form of the promise the header makes: the
// only command that may put a probe on a wire is run. Whether each command here succeeds
// depends on what the bundle holds; what must never change is that none of them opens a
// socket.
func TestReadCommandsNeverConnect(t *testing.T) {
	k := newCanary(t)
	dir := t.TempDir()
	authPath := writeAuthFile(t, dir, testAuth(t, k.port()), "auth.json")
	bundle, _, _ := sealedBundle(t)

	commands := [][]string{
		{"version"},
		{"corpus", "check", "--corpus", testCorpusRoot},
		{"playbook", "--authorization", authPath, "--issuer-keyring", testKeyring(dir),
			"--corpus", testCorpusRoot, "--class", "sqli", "--vector", "query", "--budget", "8"},
		{"verify", "--store", bundle},
		{"report", "--store", bundle, "--authorization", authPath,
			"--issuer-keyring", testKeyring(dir), "--corpus", testCorpusRoot},
		{"validate", "--finding", "GAP-001", "--store", bundle, "--authorization", authPath,
			"--issuer-keyring", testKeyring(dir), "--corpus", testCorpusRoot},
		{"lab", "scenarios", "--lab-dir", dir},
		{"report", "--store", filepath.Join(dir, "absent-bundle")},
		{"validate", "--finding", "GAP-001", "--store", filepath.Join(dir, "absent-bundle")},
	}
	for _, argv := range commands {
		code, out, errs := run(t, argv...)
		k.idle(t, strings.Join(argv, " "))
		joined := out + errs
		for _, transport := range []string{"connection refused", "dial tcp", "no such host",
			"context deadline", "timeout awaiting response"} {
			if bytes.Contains([]byte(joined), []byte(transport)) {
				t.Fatalf("%s reached for the network (%s):\n%s", argv[0], transport, joined)
			}
		}
		if code != 0 && !bytes.Contains([]byte(errs), []byte("xammu:")) {
			t.Fatalf("a failing read command must explain itself on stderr: exit %d\n%s", code, errs)
		}
	}
	k.idle(t, "the whole read surface")
}

// TestLabCommandsPreviewInsteadOfActing covers the laboratory's front door. A scenario
// list is a reading; bringing a perimeter up is an action, and only --apply takes it.
func TestLabCommandsPreviewInsteadOfActing(t *testing.T) {
	lab := t.TempDir()
	m := labctl.Manifest{Version: "1.0.0", Compose: "compose.yaml", RunMode: labctl.RunModeHost,
		Scenarios: []labctl.Scenario{
			{Name: "coverage-gap-sqli-query-canonical-probe", Summary: "a cell with no probe",
				FindingType: string(contracts.FindingCoverageGap),
				ProbeRefs:   []string{"DEV-SQLI-Q-01"}, Expectation: "the plan refuses",
				Checks: []string{"grep -q coverage_gap report.json"}, Service: "netrunner"},
			{Name: "undetermined-sqli-query-canonical", Summary: "one reading only",
				FindingType: string(contracts.FindingUndeterminedArea),
				ProbeRefs:   []string{"DEV-SQLI-Q-02"}, Expectation: "no hypothesis is offered",
				Checks:  []string{"test \"$(curl -s -o /dev/null -w '%{http_code}' http://origin:8081/)\" = 200"},
				Service: "netrunner"},
		}}
	raw, err := json.MarshalIndent(&m, "", "  ")
	if err != nil {
		t.Fatalf("encoding the manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(lab, labctl.ManifestFile), raw, 0o640); err != nil {
		t.Fatalf("writing the manifest: %v", err)
	}

	code, out, errs := run(t, "lab", "scenarios", "--lab-dir", lab)
	if code != 0 {
		t.Fatalf("a valid manifest must list: exit %d\n%s\n%s", code, out, errs)
	}
	if !bytes.Contains([]byte(out), []byte("coverage-gap-sqli-query-canonical-probe")) ||
		!bytes.Contains([]byte(out), []byte("no scenario reproduces")) {
		t.Fatalf("the listing must name both the scenarios and the uncovered types:\n%s", out)
	}

	code, out, errs = run(t, "lab", "test", "--lab-dir", lab,
		"--scenario", "coverage-gap-sqli-query-canonical-probe")
	if code != 0 {
		t.Fatalf("previewing a scenario must succeed: exit %d\n%s\n%s", code, out, errs)
	}
	for _, want := range []string{"docker compose", "nothing ran", "--apply", "grep -q coverage_gap"} {
		if !bytes.Contains([]byte(out), []byte(want)) {
			t.Errorf("the preview must state %q:\n%s", want, out)
		}
	}
	if bytes.Contains([]byte(out), []byte("the laboratory is up")) {
		t.Fatalf("without --apply the laboratory cannot be up:\n%s", out)
	}

	// A check runs inside the service the scenario names, and the preview must be the
	// same list --apply executes, or a preview drifts into fiction.
	if steps := stepArgs(&m, m.Scenarios[1]); len(steps) != 3 {
		t.Fatalf("a scenario with one check is build, up and that check: %v", steps)
	} else if got := steps[1][len(steps[1])-1]; got != "-d" {
		t.Fatalf("the start step must be detached, got %q", got)
	}
	steps := stepArgs(&m, m.Scenarios[0])
	if len(steps) != 3 || steps[2][len(steps[2])-1] != "grep -q coverage_gap report.json" {
		t.Fatalf("the declared check must appear as an exec step: %v", steps)
	}
	if got := steps[2][len(steps[2])-4]; got != "netrunner" {
		t.Fatalf("the check must run in the service the manifest names, got %q", got)
	}
	if text := labSteps(&m, m.Scenarios[0]); len(text) != 3 ||
		!bytes.Contains([]byte(text[0]), []byte("docker compose -f compose.yaml build")) {
		t.Fatalf("the preview text must mirror the executed steps: %v", text)
	}

	// A scenario name a finding published that the manifest does not hold is a broken
	// promise, so the refusal has to offer the real list.
	code, _, errs = run(t, "lab", "test", "--lab-dir", lab, "--scenario", "coverage-gap-different")
	if code != 1 || !bytes.Contains([]byte(errs), []byte("coverage-gap-sqli-query-canonical-probe")) {
		t.Fatalf("an unknown scenario must be refused with the real names: exit %d %s", code, errs)
	}

	if code, _, errs = run(t, "lab", "test", "--lab-dir", lab); code != 1 ||
		!bytes.Contains([]byte(errs), []byte("--scenario")) {
		t.Fatalf("lab test without a scenario must name the missing flag: exit %d %s", code, errs)
	}
	if code, _, errs = run(t, "lab", "scenarios", "--lab-dir", filepath.Join(lab, "absent")); code != 1 ||
		!bytes.Contains([]byte(errs), []byte("scenario manifest")) {
		t.Fatalf("a missing manifest must be described, not guessed at: exit %d %s", code, errs)
	}

	// A manifest is not allowed to invent a category a report could never publish, and
	// the refusal has to reach both subcommands from the same place: the read.
	offVocabulary := t.TempDir()
	bad := labctl.Manifest{Version: "1.0.0", Compose: "compose.yaml", RunMode: labctl.RunModeHost,
		Scenarios: []labctl.Scenario{{Name: "exploit-confirmed", Summary: "a claim this tool cannot make",
			FindingType: "confirmed_exploit", Expectation: "an exploit",
			ProbeRefs: []string{"DEV-SQLI-Q-01"}, Checks: []string{"true"}}}}
	raw, err = json.MarshalIndent(&bad, "", "  ")
	if err != nil {
		t.Fatalf("encoding the bad manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(offVocabulary, labctl.ManifestFile), raw, 0o640); err != nil {
		t.Fatalf("writing the bad manifest: %v", err)
	}
	for _, argv := range [][]string{
		{"lab", "scenarios", "--lab-dir", offVocabulary},
		{"lab", "test", "--lab-dir", offVocabulary, "--scenario", "exploit-confirmed"},
	} {
		if code, out, errs = run(t, argv...); code != 1 ||
			!bytes.Contains([]byte(errs), []byte("not in the C-16 vocabulary")) {
			t.Fatalf("%v must refuse a scenario outside the vocabulary: exit %d\n%s\n%s",
				argv, code, out, errs)
		}
	}
}

// TestLabManifestReaderRejectsWhatItCannotUse keeps the manifest honest about damage:
// unreadable JSON and an empty scenario set are both refused as what they are.
func TestLabManifestReaderRejectsWhatItCannotUse(t *testing.T) {
	dir := t.TempDir()
	if _, err := readLab(dir); err == nil ||
		!bytes.Contains([]byte(err.Error()), []byte("no laboratory scenario manifest")) {
		t.Fatalf("a missing manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, labctl.ManifestFile), []byte("{oops"), 0o640); err != nil {
		t.Fatalf("seeding bad JSON: %v", err)
	}
	if _, err := readLab(dir); err == nil ||
		!bytes.Contains([]byte(err.Error()), []byte("not readable JSON")) {
		t.Fatalf("unreadable JSON: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, labctl.ManifestFile), []byte(`{"version":"1"}`),
		0o640); err != nil {
		t.Fatalf("seeding an empty manifest: %v", err)
	}
	if m, err := readLab(dir); err == nil ||
		!bytes.Contains([]byte(err.Error()), []byte("names no scenario")) {
		t.Fatalf("an empty scenario set must be refused: %+v %v", m, err)
	}
	if err := os.WriteFile(filepath.Join(dir, labctl.ManifestFile),
		[]byte(`{"version":"1","run_mode":"host","scenarios":[{"name":"a","finding_type":"coverage_gap",`+
			`"summary":"one reading","expected_observation":"a status",`+
			`"probe_refs":["DEV-SQLI-Q-01"],"checks":["true"]}]}`),
		0o640); err != nil {
		t.Fatalf("seeding a compose-less manifest: %v", err)
	}
	m, err := readLab(dir)
	if err != nil {
		t.Fatalf("a manifest with no compose file is still readable: %v", err)
	}
	if m.Compose != "compose.yaml" {
		t.Fatalf("the compose default is compose.yaml, got %q", m.Compose)
	}
}

// TestGeneratedByNamesAnOperatorOnlyWhenThereIsOne: the evidence block attaches a document
// to a person. Claiming a name the process never had is worse than saying it does not know.
func TestGeneratedByNamesAnOperatorOnlyWhenThereIsOne(t *testing.T) {
	t.Setenv("XAMMU_OPERATOR", "")
	t.Setenv("USERNAME", "")
	t.Setenv("USER", "")
	if got := generatedBy(""); got != "unknown" {
		t.Fatalf("with no name anywhere, generatedBy must say unknown, got %q", got)
	}
	if got := generatedBy("a.person"); got != "a.person" {
		t.Fatalf("--generated-by wins, got %q", got)
	}
	t.Setenv("XAMMU_OPERATOR", "operator-from-the-environment")
	if got := generatedBy(""); got != "operator-from-the-environment" {
		t.Fatalf("the environment must be used when the flag is empty, got %q", got)
	}
}

// TestHeaderLookupIsCaseInsensitive because HTTP names are: a probe that ignored that
// would report a missing Server header on a response that has one.
func TestHeaderLookupIsCaseInsensitive(t *testing.T) {
	in := []contracts.HeaderEntry{{Name: "Content-Type", Value: "application/json"}}
	if got := headerValue(in, "content-type"); got != "application/json" {
		t.Fatalf("headerValue = %q", got)
	}
	if got := headerValue(in, "X-Nope"); got != "" {
		t.Fatalf("an absent header must read as empty, got %q", got)
	}
}

// TestOriginURLRefusesAnUnstatedPort: "which port did we send to" cannot be answered from
// a zero, so an authorization that leaves it out is refused rather than defaulted.
func TestOriginURLRefusesAnUnstatedPort(t *testing.T) {
	if got, err := originURL(contracts.Origin{Scheme: "https", Host: "lab.local", Port: 8443}); err != nil ||
		got != "https://lab.local:8443" {
		t.Fatalf("originURL = %q, %v", got, err)
	}
	if _, err := originURL(contracts.Origin{Scheme: "https", Host: "lab.local"}); err == nil ||
		!bytes.Contains([]byte(err.Error()), []byte("declares no port")) {
		t.Fatalf("a portless origin must be refused: %v", err)
	}

	a := testAuth(t, 8443)
	want := "http://127.0.0.1:8443"
	if got, err := pickOrigin(a, ""); err != nil || got != want {
		t.Fatalf("the default target must be the first authorized origin: %q %v", got, err)
	}
	if got, err := pickOrigin(a, want); err != nil || got != want {
		t.Fatalf("naming the authorized origin must resolve to it: %q %v", got, err)
	}
	if _, err := pickOrigin(a, "http://somewhere-else:9000"); err == nil ||
		!bytes.Contains([]byte(err.Error()), []byte("not an origin of authorization")) {
		t.Fatalf("an unauthorized target must be refused with the authorized list: %v", err)
	}
	empty := testAuth(t, 8443)
	empty.Origins = nil
	if _, err := pickOrigin(empty, ""); err == nil {
		t.Fatal("an authorization with no origin must be refused")
	}
}

// TestSplitListDropsShellTypos: "--class sqli,,xss" is what a typo looks like, and a plan
// carrying an unnamed class fails with a message about classes.
func TestSplitListDropsShellTypos(t *testing.T) {
	got := splitList(" sqli,,xss ,")
	if len(got) != 2 || got[0] != "sqli" || got[1] != "xss" {
		t.Fatalf("splitList = %q", got)
	}
	if len(splitList("")) != 0 {
		t.Fatal("an empty value must select nothing, not one empty name")
	}
	if _, err := asClasses([]string{"sqli", "not-a-class"}); err == nil ||
		!bytes.Contains([]byte(err.Error()), []byte("not in the vocabulary")) {
		t.Fatalf("an unknown class must be refused with the vocabulary: %v", err)
	}
	if _, err := asVectors([]string{"carrier_pigeon"}); err == nil {
		t.Fatal("an unknown transport must be refused")
	}
	if _, err := asEncodings([]string{"html_entitized"}); err == nil {
		t.Fatal("an unknown encoding must be refused")
	}
	if _, err := asPartition("holdout"); err == nil ||
		!bytes.Contains([]byte(err.Error()), []byte("is not one of")) {
		t.Fatalf("an unknown partition must name the set: %v", err)
	}
}

// TestResolveScopeNarrowsNeverWidens covers the arithmetic every command shares: the flags
// choose a subset of the permission, and nothing here reaches a socket.
func TestResolveScopeNarrowsNeverWidens(t *testing.T) {
	a := testAuth(t, 8443)

	sc, err := resolveScope(a, planFlags{partition: "development", controls: "calibration",
		classes: "sqli", vectors: "query", encodings: "canonical", budget: 4})
	if err != nil {
		t.Fatalf("a narrowed scope: %v", err)
	}
	if len(sc.classes) != 1 || sc.classes[0] != contracts.ClassSQLi || sc.budget != 4 {
		t.Fatalf("scope did not take the requested subset: %+v", sc)
	}
	if sc.origin != "http://127.0.0.1:8443" {
		t.Fatalf("origin = %q", sc.origin)
	}

	// An empty flag means the whole authorization, not nothing.
	sc, err = resolveScope(a, planFlags{partition: "development", controls: "calibration"})
	if err != nil {
		t.Fatalf("the default scope: %v", err)
	}
	if len(sc.classes) != len(a.AllowedClasses) || len(sc.vectors) != len(a.AllowedVectors) ||
		sc.budget != a.Limits.MaxRequests {
		t.Fatalf("the default scope must be the authorized set: %+v", sc)
	}

	cases := []struct {
		name string
		f    planFlags
		want string
	}{
		{"budget above the authorized maximum",
			planFlags{partition: "development", controls: "calibration", budget: 5000},
			"exceeds the authorized maximum"},
		{"probes and controls from one partition",
			planFlags{partition: "development", controls: "development"},
			"different partitions"},
		{"a class the permission does not name",
			planFlags{partition: "development", controls: "calibration", classes: "xxe"},
			"is not authorized by"},
		{"a transport the permission does not name",
			planFlags{partition: "development", controls: "calibration", vectors: "multipart_form"},
			"is not authorized by"},
		{"an encoding the permission does not name",
			planFlags{partition: "development", controls: "calibration",
				encodings: "html_entity_named"},
			"is not authorized by"},
		{"a target that is not an origin",
			planFlags{partition: "development", controls: "calibration", target: "http://elsewhere:1"},
			"not an origin"},
		{"an unknown partition",
			planFlags{partition: "holdout", controls: "calibration"}, "is not one of"},
		// A name outside the vocabulary at all is refused as that, not as a scope problem:
		// the operator typed a word this tool has never had, and telling them the
		// authorization lacks ssrf would send them to the wrong document.
		{"a class outside the vocabulary",
			planFlags{partition: "development", controls: "calibration", classes: "carrier_pigeon"},
			"not in the vocabulary"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := resolveScope(a, tc.f); err == nil ||
				!bytes.Contains([]byte(err.Error()), []byte(tc.want)) {
				t.Fatalf("want a refusal containing %q, got %v", tc.want, err)
			}
		})
	}

	if _, err := resolveScope(nil, planFlags{}); err == nil ||
		!bytes.Contains([]byte(err.Error()), []byte("needs an authorization")) {
		t.Fatalf("a plan without an authorization must be refused: %v", err)
	}

	// A budget the authorization does not state and the operator does not give means the
	// run cannot be bounded, so it cannot be approved.
	unbounded := testAuth(t, 8443)
	unbounded.Limits.MaxRequests = 0
	if _, err := resolveScope(unbounded, planFlags{partition: "development",
		controls: "calibration"}); err == nil ||
		!bytes.Contains([]byte(err.Error()), []byte("cannot be bounded")) {
		t.Fatalf("a run with no budget must be refused: %v", err)
	}
}

// TestJoinURLKeepsThePlacementReadable checks a planned destination is the bound origin
// plus the placement, with no Windows separator ever published.
func TestJoinURLKeepsThePlacementReadable(t *testing.T) {
	got, err := joinURL("http://127.0.0.1:8099", corpus.Placement{
		Method: "GET", Path: "/api/v1/search", Query: "q=1",
	})
	if err != nil {
		t.Fatalf("joinURL: %v", err)
	}
	if got != "http://127.0.0.1:8099/api/v1/search?q=1" {
		t.Fatalf("joinURL = %q", got)
	}
	if _, err := joinURL("://no-origin", corpus.Placement{Path: "/"}); err == nil {
		t.Fatal("an unparsable origin must be refused")
	}
}

// TestPlaceHeadersDoesNotDuplicateContentType: the placement already reports a content type
// for a body vector, and a request carrying the same header twice is a different request.
func TestPlaceHeadersDoesNotDuplicateContentType(t *testing.T) {
	withCT := corpus.Placement{ContentType: "application/json",
		Headers: []contracts.HeaderEntry{{Name: "content-type", Value: "application/json"}}}
	if got := placeHeaders(withCT); len(got) != 1 {
		t.Fatalf("an existing content type must not be added twice: %v", got)
	}
	plain := corpus.Placement{ContentType: "application/x-www-form-urlencoded"}
	got := placeHeaders(plain)
	if len(got) != 1 || got[0].Name != "Content-Type" {
		t.Fatalf("the placement's content type must join the request: %v", got)
	}
	if orig := plain.Headers; len(orig) != 0 {
		t.Fatalf("placeHeaders must not write into the placement it was given: %v", orig)
	}
}

// TestShortenAndJoinCommas cover the two rendering helpers every table depends on; a
// column that cannot be shortened turns the preview into a wall of text.
func TestShortenAndJoinCommas(t *testing.T) {
	if got := shorten("http://127.0.0.1:8099/api/v1/search?q=1", 20); got != "http://127.0.0.1:..." {
		t.Fatalf("shorten = %q", got)
	}
	if got := shorten("short", 40); got != "short" {
		t.Fatalf("shorten must leave a short value alone, got %q", got)
	}
	if got := joinComma([]string{"a", "b", "c"}); got != "a, b, c" {
		t.Fatalf("joinComma = %q", got)
	}
	if got := joinComma(nil); got != "" {
		t.Fatalf("joinComma of nothing = %q", got)
	}
	if orNoneText("") != "no stop reason was recorded" {
		t.Fatal("an absent stop reason must be stated as absent")
	}
}

// TestReportFormatNamesTheHumanDocument: the handoff names the reviewer-facing
// rendering "human" and the tool calls the same bytes "markdown". Both have to be
// accepted, and neither may quietly become a second format that drifts from the
// other: the JSON payload stays the only authority either one renders.
func TestReportFormatNamesTheHumanDocument(t *testing.T) {
	for _, tc := range []struct{ asked, want string }{
		{"human", "markdown"},
		{"markdown", "markdown"},
		{"json", "json"},
		{"both", "both"},
		{"annex", "annex"},
		{"annex-html", "annex-html"},
	} {
		got, err := asReportFormat(tc.asked)
		if err != nil {
			t.Fatalf("--format %q was refused: %v", tc.asked, err)
		}
		if got != tc.want {
			t.Errorf("--format %q resolved to %q, want %q", tc.asked, got, tc.want)
		}
	}
	for _, bad := range []string{"", "text", "JSON", "Human", "markdown,json", "annex-json", "html"} {
		if _, err := asReportFormat(bad); err == nil {
			t.Errorf("--format %q was accepted; an unrecognised rendering must be refused, not guessed",
				bad)
		}
	}
}
