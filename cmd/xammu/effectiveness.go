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
	"xammu/internal/fingerprint"
	"xammu/internal/httpclient"
	"xammu/internal/integrity"
	"xammu/internal/tamper"
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
		return fmt.Errorf("%w: effectiveness takes check, tampers, run or report", errUsage)
	}
	switch args[0] {
	case "check":
		return cmdEffectivenessCheck(c, args[1:])
	case "tampers":
		return cmdEffectivenessTampers(c, args[1:])
	case "run":
		return cmdEffectivenessRun(ctx, c, args[1:])
	case "report":
		return cmdEffectivenessReport(c, args[1:])
	default:
		return fmt.Errorf("%w: effectiveness takes check, tampers, run or report, not %q", errUsage, args[0])
	}
}

// cmdEffectivenessTampers prints the tamper vocabulary and the candidate stacks
// per vendor. It sends nothing and reads no evidence: it is the reference an
// operator consults before choosing --tampers, and it says out loud which
// primitive changes what the gate sees.
func cmdEffectivenessTampers(c *cli, args []string) error {
	fs := newFlagSet("effectiveness tampers", c.err)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := requireNoStrayArgs(fs); err != nil {
		return err
	}
	fmt.Fprintf(c.out, "tamper stack: at most %d primitives, no repeats, applied left to right\n",
		tamper.MaxStackDepth)
	fmt.Fprintf(c.out, "every stack is a re-encoding of an already-admitted value; the inertness gate\n")
	fmt.Fprintf(c.out, "re-checks the transformed value before it is sent\n\n")
	fmt.Fprintf(c.out, "primitives\n")
	for _, t := range contracts.AllTampers() {
		marker := "keeps the inline marker"
		if !tamper.PreservesMarker(t) {
			marker = "erases the inline marker; needs X-Xammu-Probe and is never auto-selected"
		}
		fmt.Fprintf(c.out, "  %-20s %s\n", t, marker)
	}
	fmt.Fprintf(c.out, "\nchunked is absent on purpose: changing request framing would be smuggling, not evasion.\n")
	fmt.Fprintf(c.out, "base64 is available only when forced, so a measured delta on it carries a recorded confounder.\n\n")
	fmt.Fprintf(c.out, "candidate stacks by vendor (candidates to measure, not asserted bypasses)\n")
	for _, vendor := range fingerprint.Vendors() {
		stacks, basis := fingerprint.CandidateStacks(vendor)
		fmt.Fprintf(c.out, "  %s\n", vendor)
		fmt.Fprintf(c.out, "    basis: %s\n", basis)
		if len(stacks) == 0 {
			fmt.Fprintf(c.out, "    none\n")
		}
		for _, s := range stacks {
			fmt.Fprintf(c.out, "    %s\n", tamperStackText(s.Stack))
			fmt.Fprintf(c.out, "      %s\n", s.Basis)
		}
	}
	fmt.Fprintf(c.out, "\nauto selection tries the vendor candidate that keeps the marker; --tampers STACK forces one,\n")
	fmt.Fprintf(c.out, "and --tampers none runs the baseline only. Nothing here was sent.\n")
	return nil
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
	tampers       string
	tamperBenign  bool
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
	fs.StringVar(&f.tampers, "tampers", "auto",
		"auto, none, or a comma-separated stack such as url_encode_double,sql_comment")
	fs.BoolVar(&f.tamperBenign, "tamper-benign", true,
		"measure benign cases on the tamper arm too, so the false-positive cost is not hidden")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := requireNoStrayArgs(fs); err != nil {
		return err
	}
	if f.runID == "" {
		return fmt.Errorf("%w: effectiveness run needs --run: evidence without an owner cannot be cited", errUsage)
	}
	if _, err := runPath(f.runsDir, f.runID); err != nil {
		return err
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
	// The limiter and ledger are per process. Before the first socket, take the
	// lock that makes this process the only live spender of this authorization
	// against this origin; a second live run is refused instead of doubling the
	// aggregate rate the target sees.
	lock, err := acquireAuthorizationLock(auth.Ref, origin)
	if err != nil {
		return err
	}
	defer lock.Release()
	if err := authorizeCases(auth, cases); err != nil {
		return err
	}
	mode, forced, err := parseTamperSpec(f.tampers)
	if err != nil {
		return err
	}
	if mode == "forced" {
		if err := authorizeStack(auth, forced); err != nil {
			return err
		}
	}
	// An automatic arm can only exist when the permission names primitives. The
	// plan is sized for the largest arm it could select, so a budget that cannot
	// pay for it is refused before the baseline starts rather than after.
	planTamper := mode == "forced" || (mode == "auto" && len(auth.AllowedTampers) > 0)
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
	planned := len(cases)
	if planTamper {
		planned += tamperTrialCount(cases, f.tamperBenign)
	}
	if planned > budget {
		return fmt.Errorf("this run plans %d request(s) (baseline plus the largest tamper arm) but the "+
			"budget is %d: nothing was sent, and no arm is published half-measured", planned, budget)
	}

	dir, err := runPath(f.runsDir, f.runID)
	if err != nil {
		return err
	}
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
	if err := effectiveness.JournalCases(store, cases); err != nil {
		return err
	}

	baseRes, runErr := effectiveness.RunArm(ctx, client, store, auth, f.runID, origin, f.path,
		baselineTrials(cases), corpus.DefaultPolicy(), time.Now)
	if baseRes == nil {
		if runErr == nil {
			runErr = fmt.Errorf("effectiveness run produced no result")
		}
		return runErr
	}
	allOutcomes := append([]effectiveness.Outcome(nil), baseRes.Outcomes...)
	printArmResult(c.out, "baseline", baseRes)

	fp := effectiveness.BaselineFingerprint(baseRes.Outcomes)
	if fp != nil {
		printFingerprint(c.out, fp)
	}

	var tamperRes *effectiveness.RunResult
	if runErr == nil && baseRes.Stopped == "" {
		stack, basis, reason := tamper.Stack(nil), "", ""
		if mode == "forced" {
			stack, basis = forced, "forced by the operator"
		} else if mode == "auto" {
			if len(auth.AllowedTampers) == 0 {
				reason = "the authorization names no tamper primitives"
			} else {
				stack, basis = autoStack(fp, auth)
				if stack == nil {
					reason = basis
				}
			}
		}
		if stack == nil {
			if reason != "" {
				fmt.Fprintf(c.out, "tamper arm: not run — %s\n", reason)
			}
		} else {
			trials := tamperTrials(cases, stack, basis, f.tamperBenign)
			if remaining := budget - client.Ledger().Used(); len(trials) > remaining {
				fmt.Fprintf(c.out, "tamper arm: not run — %d trial(s) need %d request(s) and only %d "+
					"remain; a partial arm is not published\n", len(trials), len(trials), remaining)
			} else {
				fmt.Fprintf(c.out, "tamper arm: %s on %d case(s) — %s\n",
					tamperStackText(stack), len(trials), basis)
				var tamperErr error
				tamperRes, tamperErr = effectiveness.RunArm(ctx, client, store, auth, f.runID, origin,
					f.path, trials, corpus.DefaultPolicy(), time.Now)
				if tamperRes == nil {
					if tamperErr == nil {
						tamperErr = fmt.Errorf("effectiveness tamper arm produced no result")
					}
					return tamperErr
				}
				allOutcomes = append(allOutcomes, tamperRes.Outcomes...)
				printArmResult(c.out, "tamper", tamperRes)
				if tamperErr != nil && runErr == nil {
					runErr = tamperErr
				}
			}
		}
	}

	metrics := effectiveness.Compute(f.runID, auth.Ref, cases, allOutcomes, time.Now().UTC())
	if _, err := store.Append(integrity.StreamEffectivenessMetrics, metrics); err != nil {
		return fmt.Errorf("cannot journal the metrics: %w", err)
	}
	fmt.Fprintf(c.out, "baseline TP %d FN %d FP %d TN %d excluded %d\n",
		metrics.Counts.TP, metrics.Counts.FN, metrics.Counts.FP, metrics.Counts.TN, metrics.Counts.Excluded)
	printComparison(c.out, metrics)

	if err := checkKeyOutsideBundle(dir, f.signingKey); err != nil {
		return err
	}
	manifest, err := integrity.BuildManifest(dir, f.runID, auth.Ref, "",
		len(allOutcomes), store.Head(integrity.StreamEffectivenessOutcomes))
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

func baselineTrials(cases []effectiveness.Case) []effectiveness.Trial {
	out := make([]effectiveness.Trial, 0, len(cases))
	for _, c := range cases {
		out = append(out, effectiveness.Trial{Case: c, Arm: effectiveness.ArmBaseline})
	}
	return out
}

func tamperTrials(cases []effectiveness.Case, stack tamper.Stack, basis string,
	includeBenign bool) []effectiveness.Trial {
	out := make([]effectiveness.Trial, 0, len(cases))
	for _, c := range cases {
		if c.Kind == effectiveness.KindBenign && !includeBenign {
			continue
		}
		out = append(out, effectiveness.Trial{
			Case: c, Arm: effectiveness.ArmTamper,
			Stack: append(tamper.Stack(nil), stack...), SelectionBasis: basis,
		})
	}
	return out
}

func tamperTrialCount(cases []effectiveness.Case, includeBenign bool) int {
	n := 0
	for _, c := range cases {
		if c.Kind == effectiveness.KindBenign && !includeBenign {
			continue
		}
		n++
	}
	return n
}

// parseTamperSpec separates the two policies from a forced stack. An empty value
// is auto, which is what a Phase 1 authorization turns into a baseline-only run.
func parseTamperSpec(spec string) (string, tamper.Stack, error) {
	switch strings.TrimSpace(spec) {
	case "", "auto":
		return "auto", nil, nil
	case "none":
		return "none", nil, nil
	}
	stack, err := tamper.Parse(spec)
	if err != nil {
		return "", nil, err
	}
	return "forced", stack, nil
}

func authorizeStack(auth *contracts.ProfilingAuthorization, stack tamper.Stack) error {
	allowed := map[contracts.Tamper]bool{}
	for _, t := range auth.AllowedTampers {
		allowed[t] = true
	}
	var missing []string
	for _, t := range stack {
		if !allowed[t] {
			missing = append(missing, string(t))
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("authorization %s does not name tamper primitive(s) %s: nothing was sent",
			auth.Ref, strings.Join(missing, ", "))
	}
	return nil
}

func stackAuthorized(auth *contracts.ProfilingAuthorization, stack tamper.Stack) bool {
	return authorizeStack(auth, stack) == nil
}

// autoStack picks the first candidate of the first vendor with at least medium
// confidence that the authorization covers. Trying a later candidate is a
// narrowing, never a widening; base64 is absent from every candidate.
func autoStack(fp *fingerprint.Summary, auth *contracts.ProfilingAuthorization) (tamper.Stack, string) {
	if fp == nil {
		return nil, "no fingerprint evidence: automatic selection has nothing to bind to"
	}
	for _, v := range fp.Vendors {
		if v.Support != fingerprint.SupportHigh && v.Support != fingerprint.SupportMedium {
			continue
		}
		candidates, _ := fingerprint.CandidateStacks(v.Vendor)
		for _, r := range candidates {
			if stackAuthorized(auth, r.Stack) {
				return append(tamper.Stack(nil), r.Stack...),
					fmt.Sprintf("auto: vendor=%s confidence=%s; %s", v.Vendor, v.Support, r.Basis)
			}
		}
		return nil, fmt.Sprintf("auto: vendor %s recommends no stack the authorization covers", v.Vendor)
	}
	return nil, "auto: no vendor reached medium confidence, so no stack was selected"
}

func tamperStackText(stack tamper.Stack) string {
	parts := make([]string, 0, len(stack))
	for _, t := range stack {
		parts = append(parts, string(t))
	}
	return strings.Join(parts, " -> ")
}

func printArmResult(w io.Writer, name string, res *effectiveness.RunResult) {
	failures := 0
	for _, o := range res.Outcomes {
		if o.Verdict == effectiveness.VerdictExcluded &&
			o.ExclusionReason != "tamper_gate_refused" && o.ExclusionReason != "policy_refusal" {
			failures++
		}
	}
	fmt.Fprintf(w, "%s: executed %d case(s), %d request(s) spent, %d refusal(s), %d failure(s)\n",
		name, len(res.Outcomes), res.RequestsSent, res.Refusals, failures)
	if res.Stopped != "" {
		fmt.Fprintf(w, "the %s arm stopped: %s\n", name, res.Stopped)
	}
}

func printFingerprint(w io.Writer, fp *fingerprint.Summary) {
	for _, v := range fp.Vendors {
		if len(v.Evidence) == 0 {
			fmt.Fprintf(w, "fingerprint: %s — confidence %s; no vendor signature matched\n",
				v.Vendor, v.Support)
			continue
		}
		details := make([]string, 0, len(v.Evidence))
		for _, e := range v.Evidence {
			details = append(details, e.Detail)
		}
		fmt.Fprintf(w, "fingerprint: %s — confidence %s (%d outcome(s) with evidence): %s\n",
			v.Vendor, v.Support, v.Cases, strings.Join(details, ", "))
	}
}

func printComparison(w io.Writer, m effectiveness.Metrics) {
	if len(m.Comparison) == 0 {
		fmt.Fprintln(w, "comparison: no tamper arm measured")
		return
	}
	for _, r := range m.Comparison {
		if r.Class != "all attack classes" {
			continue
		}
		fmt.Fprintf(w, "comparison: baseline TPR %s (n=%d) vs tamper TPR %s (n=%d), delta %s\n",
			pct(r.BaselineTPR), r.BaselineN, pct(r.TamperTPR), r.TamperN, pctDelta(r.DeltaPP))
	}
}

func pct(v *float64) string {
	if v == nil {
		return "n/a"
	}
	return fmt.Sprintf("%.2f%%", *v*100)
}

func pctDelta(v *float64) string {
	if v == nil {
		return "n/a"
	}
	if *v >= 0 {
		return fmt.Sprintf("+%.2f pp", *v)
	}
	return fmt.Sprintf("%.2f pp", *v)
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
	return runPath(runsDir, runID)
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
