package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"xammu/internal/contracts"
	"xammu/internal/corpus"
	"xammu/internal/effectiveness"
	"xammu/internal/httpclient"
	"xammu/internal/integrity"
)

// The effectiveness corpus lives beside the profiling corpus, not inside it: the
// two answer different questions and a run of one must never load the other.
const (
	effectivenessCorpusRoot  = "corpus/effectiveness"
	effectivenessMetricsFile = "effectiveness-metrics.json"
	effectivenessReportFile  = "effectiveness-report.md"
)

// cmdEffectiveness hosts the three verbs Phase 1 adds. check and report send
// nothing; run is the only one that asks a target for traffic, and it does so
// under the same C-09, the same single egress and the same inertness gate as
// `xammu run`.
func cmdEffectiveness(ctx context.Context, c *cli, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("%w: effectiveness takes check, run or report", errUsage)
	}
	switch args[0] {
	case "check":
		return cmdEffectivenessCheck(c, args[1:])
	case "run":
		return cmdEffectivenessRun(ctx, c, args[1:])
	case "report":
		return cmdEffectivenessReport(c, args[1:])
	default:
		return fmt.Errorf("%w: effectiveness takes check, run or report, not %q", errUsage, args[0])
	}
}

func cmdEffectivenessCheck(c *cli, args []string) error {
	var root string
	fs := newFlagSet("effectiveness check", c.err)
	fs.StringVar(&root, "corpus", effectivenessCorpusRoot, "effectiveness corpus tree to load through the gate")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := requireNoStrayArgs(fs); err != nil {
		return err
	}
	cases, err := effectiveness.Load(root, corpus.DefaultPolicy())
	if err != nil {
		return err
	}
	counts := effectiveness.Count(cases)
	if err := counts.CheckMinimums(); err != nil {
		return err
	}
	fmt.Fprintf(c.out, "effectiveness corpus %s, gate %s (marker %q)\n",
		filepath.ToSlash(root), corpus.GateVersion, corpus.DefaultPolicy().MarkerToken)
	fmt.Fprintf(c.out, "%d case(s): %d attack, %d benign\n\n",
		counts.Total, counts.Attack, counts.Benign)
	fmt.Fprintf(c.out, "attack classes\n")
	classes := make([]string, 0, len(counts.OWASP))
	for class := range counts.OWASP {
		classes = append(classes, class)
	}
	sort.Strings(classes)
	for _, class := range classes {
		fmt.Fprintf(c.out, "  %-20s %3d  %s\n", class, counts.ByClass[class], counts.OWASP[class])
	}
	fmt.Fprintf(c.out, "\nbenign classes\n")
	benign := effectiveness.AllBenignClasses()
	for _, class := range benign {
		fmt.Fprintf(c.out, "  %-20s %3d\n", class, counts.ByClass[class])
	}
	fmt.Fprintf(c.out, "\nvectors\n")
	vectors := make([]string, 0, len(counts.ByVector))
	for v := range counts.ByVector {
		vectors = append(vectors, string(v))
	}
	sort.Strings(vectors)
	for _, v := range vectors {
		fmt.Fprintf(c.out, "  %-20s %3d\n", v, counts.ByVector[contracts.Vector(v)])
	}
	fmt.Fprintf(c.out, "\nevery payload passed the inertness gate; nothing was sent.\n")
	return nil
}

// effRunFlags are the operator choices a run accepts. They narrow the
// authorization: none of them can add a class, a transport, an encoding or a
// request the C-09 did not name.
type effRunFlags struct {
	authorization string
	authDir       string
	issuerKeyring string
	authorize     string
	corpusRoot    string
	target        string
	budget        int
	path          string
	runsDir       string
	signingKey    string
	generatedBy   string
	runID         string
}

func cmdEffectivenessRun(ctx context.Context, c *cli, args []string) error {
	var f effRunFlags
	fs := newFlagSet("effectiveness run", c.err)
	fs.StringVar(&f.authorization, "authorization", "", "C-09 profiling authorization: a file path or its reference")
	fs.StringVar(&f.authDir, "authorizations", defaultAuthDir,
		"directory searched when --authorization names a reference")
	fs.StringVar(&f.issuerKeyring, "issuer-keyring", "",
		"directory of *.pub hex ed25519 keys that sign authorizations; required")
	fs.StringVar(&f.authorize, "authorize", "",
		"repeat the reference of the authorization you are holding; run refuses without it")
	fs.StringVar(&f.corpusRoot, "corpus", effectivenessCorpusRoot, "effectiveness corpus tree")
	fs.StringVar(&f.target, "target", "", "authorized origin to bind to; default is the first listed")
	fs.IntVar(&f.budget, "budget", 0, "requests this run may spend; default is the authorized maximum")
	fs.StringVar(&f.path, "path", defaultPlacementPath, "endpoint cases are placed against")
	fs.StringVar(&f.runsDir, "runs-dir", defaultRunsDir, "where effectiveness bundles live")
	fs.StringVar(&f.signingKey, "signing-key", ".xammu-signing.ed25519",
		"ed25519 seed file outside the bundle; created with 0600 if absent")
	fs.StringVar(&f.generatedBy, "generated-by", "", "operator named in the evidence block")
	fs.StringVar(&f.runID, "run", "", "run this command writes; the bundle is created under --runs-dir")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := requireNoStrayArgs(fs); err != nil {
		return err
	}
	if f.runID == "" {
		return fmt.Errorf("%w: effectiveness run needs --run: evidence without an owner cannot be cited", errUsage)
	}
	auth, _, err := loadAuthorization(f.authorization, f.authDir, f.issuerKeyring)
	if err != nil {
		return err
	}
	if f.authorize == "" {
		return fmt.Errorf("%w: effectiveness run needs --authorize REF naming authorization %s: nothing "+
			"will be sent until the permission is acknowledged by reference", errUsage, auth.Ref)
	}
	if f.authorize != auth.Ref {
		return fmt.Errorf("--authorize says %q but the loaded authorization is %q: run refuses to send "+
			"traffic under a permission the operator did not name", f.authorize, auth.Ref)
	}
	if now := time.Now().UTC(); now.After(auth.ExpiresAt) {
		return fmt.Errorf("authorization %s expired at %s: nothing was sent", auth.Ref,
			auth.ExpiresAt.UTC().Format(time.RFC3339))
	}
	cases, err := effectiveness.Load(f.corpusRoot, corpus.DefaultPolicy())
	if err != nil {
		return err
	}
	counts := effectiveness.Count(cases)
	if err := counts.CheckMinimums(); err != nil {
		return err
	}
	origin, err := pickOrigin(auth, f.target)
	if err != nil {
		return err
	}
	if err := authorizeCases(auth, cases); err != nil {
		return err
	}
	scope, err := httpclient.ScopeFromProfiling(auth)
	if err != nil {
		return err
	}
	budget := auth.Limits.MaxRequests
	if f.budget > 0 {
		if f.budget > auth.Limits.MaxRequests {
			return fmt.Errorf("--budget %d exceeds the authorized maximum %d: a flag narrows, it never widens",
				f.budget, auth.Limits.MaxRequests)
		}
		budget = f.budget
	}
	if err := preflightPlacement(scope, origin, f.path, cases); err != nil {
		return err
	}

	dir := filepath.Join(f.runsDir, f.runID)
	if err := refuseOverwrite(dir); err != nil {
		return err
	}
	store, err := integrity.Open(dir)
	if err != nil {
		return fmt.Errorf("cannot open evidence directory %s: %w", filepath.ToSlash(dir), err)
	}
	redactor, err := contracts.NewHeaderRedactor(nil)
	if err != nil {
		return err
	}
	client := httpclient.New(scope, budget)
	client.SetHeaderRedactor(redactor)

	fmt.Fprintf(c.out, "authorization %s: origin %s, %d case(s), budget %d\n",
		auth.Ref, origin, len(cases), budget)
	res, runErr := effectiveness.Run(ctx, client, store, auth, f.runID, origin, f.path, cases, time.Now)
	if res == nil {
		if runErr == nil {
			runErr = fmt.Errorf("effectiveness run produced no result")
		}
		return runErr
	}
	metrics := effectiveness.Compute(f.runID, auth.Ref, cases, res.Outcomes, time.Now().UTC())
	if _, err := store.Append(integrity.StreamEffectivenessMetrics, metrics); err != nil {
		return fmt.Errorf("cannot journal the metrics: %w", err)
	}
	fmt.Fprintf(c.out, "executed %d case(s), %d request(s) spent, %d refusal(s), %d failure(s)\n",
		len(res.Outcomes), res.RequestsSent, res.Refusals, len(res.Failures))
	if res.Stopped != "" {
		fmt.Fprintf(c.out, "the loop stopped: %s\n", res.Stopped)
	}
	fmt.Fprintf(c.out, "TP %d FN %d FP %d TN %d excluded %d\n",
		metrics.Counts.TP, metrics.Counts.FN, metrics.Counts.FP, metrics.Counts.TN, metrics.Counts.Excluded)

	if err := checkKeyOutsideBundle(dir, f.signingKey); err != nil {
		return err
	}
	manifest, err := integrity.BuildManifest(dir, f.runID, auth.Ref, "",
		len(res.Outcomes), store.Head(integrity.StreamEffectivenessOutcomes))
	if err != nil {
		return fmt.Errorf("cannot inventory the bundle: %w", err)
	}
	key, err := integrity.LoadOrCreateKey(f.signingKey)
	if err != nil {
		return err
	}
	if err := integrity.Sign(&manifest, key); err != nil {
		return fmt.Errorf("cannot sign the manifest: %w", err)
	}
	if err := integrity.WriteManifest(dir, manifest); err != nil {
		return fmt.Errorf("cannot write the manifest: %w", err)
	}
	if err := publishEffectiveness(dir, metrics); err != nil {
		return err
	}
	fmt.Fprintf(c.out, "sealed and signed: %s\n", filepath.ToSlash(filepath.Join(dir, "manifest.json")))
	fmt.Fprintf(c.out, "signer public key (hex, distribute out of band): %s\n", hex.EncodeToString(key.Public))
	fmt.Fprintf(c.out, "\nnext: xammu verify --store %s --rederive\n", filepath.ToSlash(dir))
	if runErr != nil {
		return runErr
	}
	return nil
}

// authorizeCases refuses before the first socket when the corpus asks for a class,
// transport or encoding the authorization does not name. Skipping those cases
// silently would turn a scope mistake into a smaller denominator.
func authorizeCases(auth *contracts.ProfilingAuthorization, cases []effectiveness.Case) error {
	classes := map[string]bool{}
	for _, c := range auth.AllowedClasses {
		classes[string(c)] = true
	}
	vectors := map[string]bool{}
	for _, v := range auth.AllowedVectors {
		vectors[string(v)] = true
	}
	encodings := map[string]bool{}
	for _, e := range auth.AllowedEncodings {
		encodings[string(e)] = true
	}
	var missing []string
	seen := map[string]bool{}
	note := func(what, value string) {
		key := what + ":" + value
		if seen[key] {
			return
		}
		seen[key] = true
		missing = append(missing, what+" "+value)
	}
	for _, c := range cases {
		// A benign class is a traffic category, not an attack class: the C-09
		// authorizes what may be sent as an attack, and benign traffic is covered
		// by the vector and encoding lists like everything else.
		if c.Kind == effectiveness.KindAttack && !classes[c.Class] {
			note("class", c.Class)
		}
		if !vectors[string(c.Vector)] {
			note("vector", string(c.Vector))
		}
		if !encodings[string(c.Encoding)] {
			note("encoding", string(c.Encoding))
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf("authorization %s does not cover the corpus: %s. A run refuses before the "+
			"first request rather than silently shrinking the measured population", auth.Ref,
			strings.Join(missing, ", "))
	}
	return nil
}

// preflightPlacement proves the authorized path prefixes cover the case paths. It
// renders each case exactly as the runner will, so a typo in --path is answered
// before a budget is opened instead of being recorded 600 times as a refusal.
func preflightPlacement(scope *httpclient.Scope, origin, pathOverride string, cases []effectiveness.Case) error {
	for _, c := range cases {
		req, err := effectiveness.BuildRequest(origin, c, pathOverride)
		if err != nil {
			continue // the runner records this case as excluded; it is not a scope error
		}
		if err := scope.CheckRequest(req.Method, req.URL, req.ProbeRef); err != nil {
			return fmt.Errorf("case %s cannot be placed under authorization %s: %w",
				c.ID, scope.AuthRef, err)
		}
	}
	return nil
}

// publishEffectiveness writes the human and JSON documents after the seal. They
// are not in the manifest on purpose: the signature covers the evidence, and a
// re-derivation is what tells a reader the document still follows from it.
func publishEffectiveness(dir string, m effectiveness.Metrics) error {
	raw, err := effectiveness.JSON(m)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, effectivenessMetricsFile), raw, 0o640); err != nil {
		return fmt.Errorf("cannot write %s: %w", effectivenessMetricsFile, err)
	}
	var b strings.Builder
	if err := effectiveness.Markdown(m, &b); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, effectivenessReportFile), []byte(b.String()), 0o640); err != nil {
		return fmt.Errorf("cannot write %s: %w", effectivenessReportFile, err)
	}
	return nil
}

// ---- report -----------------------------------------------------------------

type effReportFlags struct {
	storeDir      string
	runID         string
	runsDir       string
	format        string
	out           string
	rederive      bool
	authorization string
	authDir       string
	issuerKeyring string
}

func cmdEffectivenessReport(c *cli, args []string) error {
	var f effReportFlags
	fs := newFlagSet("effectiveness report", c.err)
	fs.StringVar(&f.storeDir, "store", "", "bundle directory; instead of --run")
	fs.StringVar(&f.runID, "run", "", "run id looked up under --runs-dir")
	fs.StringVar(&f.runsDir, "runs-dir", defaultRunsDir, "where effectiveness bundles live")
	fs.StringVar(&f.format, "format", "human", "human (markdown), json or both")
	fs.StringVar(&f.out, "out", "", "directory to write the document into instead of printing it")
	fs.BoolVar(&f.rederive, "rederive", false, "recompute E-03 from E-01/E-02 and compare")
	fs.StringVar(&f.authorization, "authorization", "", "optional C-09 to check against the run")
	fs.StringVar(&f.authDir, "authorizations", defaultAuthDir, "directory for a reference-resolved C-09")
	fs.StringVar(&f.issuerKeyring, "issuer-keyring", "", "keyring for the supplied C-09")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := requireNoStrayArgs(fs); err != nil {
		return err
	}
	dir, err := bundleDir(f.storeDir, f.runID, f.runsDir)
	if err != nil {
		return err
	}
	switch f.format {
	case "human", "json", "both":
	default:
		return fmt.Errorf("%w: --format %q is not human, json or both", errUsage, f.format)
	}
	b, err := effectiveness.ReadBundle(dir)
	if err != nil {
		return err
	}
	if f.authorization != "" {
		auth, _, err := loadAuthorization(f.authorization, f.authDir, f.issuerKeyring)
		if err != nil {
			return err
		}
		if auth.Ref != b.Metrics.AuthorizationRef {
			return fmt.Errorf("run %s was executed under authorization %s, not %s: the permission "+
				"supplied does not describe this evidence", b.Metrics.RunID, b.Metrics.AuthorizationRef, auth.Ref)
		}
		fmt.Fprintf(c.err, "authorization %s verified against the issuer keyring\n", auth.Ref)
	}
	if f.rederive {
		if err := rederiveEffectiveness(c.err, c.err, b, dir); err != nil {
			return err
		}
	}
	if f.out != "" {
		if err := publishEffectivenessOut(f.out, dir, f.format, b.Metrics); err != nil {
			return err
		}
		fmt.Fprintf(c.out, "written under %s\n", filepath.ToSlash(f.out))
		return nil
	}
	return printEffectiveness(c.out, f.format, b.Metrics)
}

func printEffectiveness(out io.Writer, format string, m effectiveness.Metrics) error {
	if format == "json" || format == "both" {
		raw, err := effectiveness.JSON(m)
		if err != nil {
			return err
		}
		if format == "both" {
			if err := effectiveness.Markdown(m, out); err != nil {
				return err
			}
			fmt.Fprintln(out)
		}
		fmt.Fprint(out, string(raw))
		return nil
	}
	return effectiveness.Markdown(m, out)
}

// publishEffectivenessOut writes a document outside the bundle. The bundle is
// evidence, and report commands read it: they do not add files to it after it was
// sealed.
func publishEffectivenessOut(outDir, bundleDir, format string, m effectiveness.Metrics) error {
	absOut, err := filepath.Abs(outDir)
	if err != nil {
		return err
	}
	absBundle, err := filepath.Abs(bundleDir)
	if err != nil {
		return err
	}
	if absOut == absBundle {
		return fmt.Errorf("--out names the bundle itself: a read command does not write into evidence")
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("cannot create %s: %w", outDir, err)
	}
	if format == "json" || format == "both" {
		raw, err := effectiveness.JSON(m)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(outDir, effectivenessMetricsFile), raw, 0o640); err != nil {
			return err
		}
	}
	if format == "human" || format == "both" {
		file, err := os.Create(filepath.Join(outDir, effectivenessReportFile))
		if err != nil {
			return err
		}
		defer file.Close()
		if err := effectiveness.Markdown(m, file); err != nil {
			return err
		}
	}
	return nil
}

// rederiveEffectiveness is the 1.4 reproduction check: E-03 must recompute from
// E-01/E-02, and the JSON document published beside the bundle must equal the
// recomputation. A disagreement is an error, not a note. Progress lines go to
// the writer the caller chooses: a report writes them to stderr so its stdout
// stays a document a tool can parse.
func rederiveEffectiveness(out, errOut io.Writer, b *effectiveness.Bundle, dir string) error {
	derived, diffs := b.Rederive()
	if len(diffs) > 0 {
		for _, d := range diffs {
			fmt.Fprintf(errOut, "metrics disagreement: %s\n", d)
		}
		return fmt.Errorf("the journalled metrics do not re-derive from the case and outcome records")
	}
	fmt.Fprintf(out, "ok   metrics_rederive              E-03 recomputes from E-01/E-02\n")
	published, err := os.ReadFile(filepath.Join(dir, effectivenessMetricsFile))
	if err != nil {
		fmt.Fprintf(errOut, "note: %s is absent; only the journalled E-03 was compared\n", effectivenessMetricsFile)
		return nil
	}
	var stored effectiveness.Metrics
	if err := json.Unmarshal(published, &stored); err != nil {
		return fmt.Errorf("cannot read %s: %w", effectivenessMetricsFile, err)
	}
	if diffs := effectiveness.Diff(stored, derived); len(diffs) > 0 {
		for _, d := range diffs {
			fmt.Fprintf(errOut, "published document disagreement: %s\n", d)
		}
		return fmt.Errorf("the published metrics document does not match the evidence")
	}
	fmt.Fprintf(out, "ok   metrics_document            %s matches the re-derived E-03\n", effectivenessMetricsFile)
	return nil
}

// ---- verify -----------------------------------------------------------------

// verifyEffectivenessBundle is the branch `xammu verify` takes for a Phase 1
// bundle. It checks the same signed inventory the profiling path checks, then
// replays E-01/E-02 into E-03 when --rederive is asked for. It sends nothing and
// writes nothing.
func verifyEffectivenessBundle(c *cli, dir, trustKey string, rederive bool, f planFlags) error {
	b, err := effectiveness.ReadBundle(dir)
	if err != nil {
		return err
	}
	if f.authorization == "" && f.issuerKeyring != "" {
		return fmt.Errorf("%w: --issuer-keyring verifies a permission, and no --authorization was named", errUsage)
	}
	if f.authorization != "" {
		auth, _, err := loadAuthorization(f.authorization, f.authDir, f.issuerKeyring)
		if err != nil {
			return err
		}
		if auth.Ref != b.Metrics.AuthorizationRef {
			return fmt.Errorf("run %s was executed under authorization %s, not %s: the permission "+
				"supplied does not describe this evidence", b.Metrics.RunID, b.Metrics.AuthorizationRef, auth.Ref)
		}
		fmt.Fprintf(c.out, "%-4s %-28s %s verified against issuer keyring %s\n", "ok",
			"authorization_signature", auth.Ref, f.issuerKeyring)
	}
	manifest, err := integrity.ReadManifest(dir)
	if err != nil {
		return err
	}
	var trusted []byte
	if trustKey != "" {
		raw, err := os.ReadFile(trustKey)
		if err != nil {
			return fmt.Errorf("cannot read the trusted key %s: %w", trustKey, err)
		}
		trusted, err = decodeHexKey(string(raw))
		if err != nil {
			return err
		}
	}
	statuses := integrity.Verify(dir, manifest, trusted)
	var failed []integrity.VerifyStatus
	unanchored := false
	for _, s := range statuses {
		mark := "ok"
		if !s.OK {
			if s.Check == integrity.CheckSignerTrusted && trustKey == "" {
				mark = "note"
				unanchored = true
			} else {
				mark = "FAIL"
				failed = append(failed, s)
			}
		}
		fmt.Fprintf(c.out, "%-4s %-28s %s\n", mark, s.Check, s.Detail)
	}
	breaks := integrity.VerifyDir(dir)
	if len(breaks) > 0 {
		fmt.Fprintf(c.out, "FAIL %-28s %d break(s): %s\n", "hash_chain", len(breaks), breaks[0])
		failed = append(failed, integrity.VerifyStatus{Check: "hash_chain", Detail: breaks[0].String()})
	} else {
		fmt.Fprintf(c.out, "%-4s %-28s every journal recomputes to its own head\n", "ok", "hash_chain")
	}
	fmt.Fprintf(c.out, "\nrun %s signed by key %s: %d file(s) in the manifest, %d case(s), "+
		"%d outcome(s)\n", b.Metrics.RunID, manifest.SignerKeyID, len(manifest.Files),
		len(b.Cases), len(b.Outcomes))
	fmt.Fprintf(c.out, "TP %d FN %d FP %d TN %d excluded %d\n",
		b.Metrics.Counts.TP, b.Metrics.Counts.FN, b.Metrics.Counts.FP,
		b.Metrics.Counts.TN, b.Metrics.Counts.Excluded)
	if rederive {
		if err := rederiveEffectiveness(c.out, c.err, b, dir); err != nil {
			return err
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("the bundle does not verify: %d check(s) failed, starting with %q: %s",
			len(failed), failed[0].Check, failed[0].Detail)
	}
	fmt.Fprint(c.out, "\nthe evidence commits to itself; the rates describe agreement with this corpus "+
		"on this target in this window, not absolute efficacy.\n")
	if unanchored {
		fmt.Fprintf(c.out, "no trusted key was supplied, so the signature was checked against the "+
			"public key inside the same manifest. Pass --trust-key FILE to make the identity a real check.\n")
	}
	return nil
}

// ---- shared helpers ---------------------------------------------------------

func bundleDir(storeDir, runID, runsDir string) (string, error) {
	if storeDir != "" {
		return storeDir, nil
	}
	if runID == "" {
		return "", fmt.Errorf("%w: a bundle is named by --run ID or by --store DIR", errUsage)
	}
	if runsDir == "" {
		return "", fmt.Errorf("%w: --runs-dir is empty, so run %q has no home", errUsage, runID)
	}
	return filepath.Join(runsDir, runID), nil
}

// isEffectivenessBundle distinguishes the Phase 1 evidence layout from a
// profiling run without guessing: the outcomes journal is the primary stream and
// a profiling bundle never contains it.
func isEffectivenessBundle(dir string) bool {
	if _, err := os.Stat(filepath.Join(dir, "effectiveness_outcomes.jsonl")); err != nil {
		return false
	}
	if _, err := os.Stat(filepath.Join(dir, "run.json")); err == nil {
		return false
	}
	return true
}
