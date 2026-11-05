package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"xammu/internal/contracts"
	"xammu/internal/discover"
	"xammu/internal/inference"
	"xammu/internal/integrity"
	"xammu/internal/observer"
	"xammu/internal/orchestrator"
)

// cmdRun is the only command in this tool that puts a probe on a wire, and it is
// written that way on purpose: the authorization is loaded and named, the plan is
// built and validated against it, the state machine refuses anything outside the
// scope, and the evidence is sealed and signed before a report is issued from it.
//
// Nothing here is offered as a shortcut. There is no flag that widens a scope, no
// flag that skips the inertness gate, and no way to send a probe that is not in the
// accepted plan.
func cmdRun(ctx context.Context, c *cli, args []string) error {
	var (
		f         planFlags
		authorize string
		valPath   string
		parent    string
		circuit   int
	)
	fs := newFlagSet("run", c.err)
	f.register(fs)
	fs.StringVar(&authorize, "authorize", "",
		"repeat the reference of the authorization you are holding; run refuses without it")
	fs.StringVar(&valPath, "validation", "",
		"optional C-10 validation authorization for a hypothesis-testing round")
	fs.StringVar(&parent, "parent-run", "",
		"run id this round continues; a second round still needs its own authorization")
	fs.IntVar(&circuit, "circuit-threshold", 0,
		"consecutive transport failures that pause the run (0 selects the default)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := requireNoStrayArgs(fs); err != nil {
		return err
	}

	auth, err := f.bindAuthorization()
	if err != nil {
		return err
	}
	// The operator has to type the reference back. It is friction, and the friction
	// is the point: a run spends someone's request budget on someone's system, and
	// a flag that named a file path alone would let a stale permission be used by
	// an operator who never read which target it covers.
	if authorize == "" {
		return fmt.Errorf("%w: run needs --authorize REF naming authorization %s: nothing will be sent "+
			"until the permission is acknowledged by reference", errUsage, auth.Ref)
	}
	if authorize != auth.Ref {
		return fmt.Errorf("--authorize says %q but the loaded authorization is %q: run refuses to send "+
			"traffic under a permission the operator did not name", authorize, auth.Ref)
	}
	if now := time.Now().UTC(); now.After(auth.ExpiresAt) {
		return fmt.Errorf("authorization %s expired at %s: a run may not place a request after that "+
			"instant, so nothing was sent", auth.Ref, auth.ExpiresAt.UTC().Format(time.RFC3339))
	}
	// Evidence needs an owner before anything is planned for it: a run id is how a
	// finding cites its own bundle, so the flag is checked here rather than after the
	// corpus has been loaded and the selection arithmetic run.
	if f.runID == "" {
		return fmt.Errorf("%w: run needs --run: evidence without an owner cannot be cited by a finding", errUsage)
	}
	val, err := loadValidation(valPath, f.issuerKeyring)
	if err != nil {
		return err
	}

	summarizeAuth(c.out, auth)
	req, err := buildPlan(auth, f)
	if err != nil {
		return err
	}
	// The placement choices and the scope are published inside the findings, so a reader
	// who copies a reproduction command re-plans the exchanges this run planned instead
	// of discovering, after the fact, that the command points at a different set. The
	// scope half is rendered from the resolved scope rather than from the flags, so a
	// re-read that reconstructs the same scope publishes the same string.
	flags := strings.TrimSpace(f.reproFlags() + " " + scopeFlagsOf(req.sc, auth))
	dir := filepath.Join(f.runsDir, f.runID)
	if err := refuseOverwrite(dir); err != nil {
		return err
	}

	run, err := orchestrator.Begin(auth, val, orchestrator.Config{
		RunID: f.runID, RoundID: f.round, StoreDir: dir,
		Partition: string(req.sc.partition), TargetOrigin: req.sc.origin, Budget: req.sc.budget,
		ParentRunID: parent, CircuitThreshold: circuit,
	})
	if err != nil {
		return fmt.Errorf("run %s could not begin: %w", f.runID, err)
	}
	if err := run.Authorize(); err != nil {
		return fmt.Errorf("authorization check failed before any request: %w", err)
	}
	if err := run.Plan(req.items); err != nil {
		return fmt.Errorf("plan refused before any request: %w", err)
	}
	if err := run.Start(); err != nil {
		return fmt.Errorf("cannot start: %w", err)
	}

	pipe, err := inference.New(observer.DefaultSet())
	if err != nil {
		return err
	}
	ex, execErr := run.Execute(ctx, pipe.Step)
	fmt.Fprintf(c.out, "\nexecuted %d of %d planned exchange(s), %d request(s) spent, %d failure(s)\n",
		len(ex.Executed), len(req.items), ex.RequestsSent, len(ex.Failures))
	if ex.Stopped != "" {
		fmt.Fprintf(c.out, "the loop stopped: %s\n", ex.Stopped)
	}
	for _, fail := range ex.Failures {
		fmt.Fprintf(c.out, "  failed probe %s: %s\n", fail.Ref, fail.Cause)
	}
	if execErr != nil {
		// The executor only returns an error when the evidence itself could not be
		// written. A failed probe is a finding, not an error path.
		return fmt.Errorf("execution stopped by an evidence problem: %w", execErr)
	}
	if err := noteExecution(run, ex, req, auth); err != nil {
		return err
	}

	// The derived records join the journal before the store is sealed: C-04 through
	// C-08 are evidence, and a bundle that holds only raw responses asks a reviewer
	// to take the readings on trust. A pass that refuses does not lose the run: the
	// requests were spent, so the evidence still gets sealed and reported as far as
	// it can be.
	journal, err := inference.Read(run.Store())
	if err != nil {
		return fmt.Errorf("cannot read back the journal just written: %w", err)
	}
	pass, err := pipe.Infer(journal, inference.Options{Sink: run, CommandFlags: flags})
	if err != nil {
		fmt.Fprintf(c.err, "no derived records were journalled: %v\n"+
			"the exchanges that happened are still sealed and readable.\n", err)
	} else {
		fmt.Fprintf(c.out, "%s\n", pass.Summary())
		findings, discErr := discover.Analyze(discover.Input{
			RunID: run.Profile().RunID, RoundID: run.Profile().RoundID,
			Pass: pass, Corpus: req.set, Partition: req.sc.partition,
			AuthorizationRef: auth.Ref, AuthorizedClasses: auth.AllowedClasses,
			AuthorizedVectors: auth.AllowedVectors, Unplanned: unplannedFrom(req.sel),
			GeneratedAt: time.Now().UTC(), CommandFlags: flags,
			EngagementFlags: f.engagementFlags(),
		})
		if discErr != nil {
			fmt.Fprintf(c.err, "no findings were journalled: %v\n", discErr)
		} else if err := journalFindings(run, findings.Findings); err != nil {
			return err
		}
	}

	fin, err := run.Finalize(fmt.Sprintf("the run stopped in state read from the ledger after %d "+
		"request(s): the report is issued from the sealed evidence, not from this process's memory",
		ex.RequestsSent))
	if err != nil {
		return fmt.Errorf("cannot finalize: %w", err)
	}
	fmt.Fprintf(c.out, "run %s is %s: %s\n", fin.RunID, fin.State, orNoneText(fin.TerminalReason))

	manifestPath, signer, err := seal(dir, fin, run.Store(), auth, f.signingKey)
	if err != nil {
		return err
	}
	fmt.Fprintf(c.out, "sealed and signed: %s\n", filepath.ToSlash(manifestPath))
	// The manifest carries its own public key, so checking a bundle against the copy
	// inside it proves only that the two agree. Naming the key here is what lets the
	// operator put that value somewhere a reviewer already trusts.
	fmt.Fprintf(c.out, "signer public key (hex, distribute out of band): %s\n",
		hex.EncodeToString(signer.Public))

	// The published report is built from a second, read-only pass over the sealed
	// bundle, so what an operator reads is what `xammu report --run ID` will produce
	// tomorrow from the same files. Any disagreement between the two passes is in
	// the report's own uncertainty dimension rather than hidden by reusing the
	// in-process result.
	opts := deriveOptions{
		ManifestIn: manifestPath, By: generatedBy(f.generatedBy), Generated: time.Now().UTC(),
		VerifyCmd:       verifyCommandOf(fin.RunID, flags),
		CommandFlags:    flags,
		EngagementFlags: f.engagementFlags(),
	}
	d, err := derive(run.Store(), fin, auth, req.set, req.sc, req.sel, opts)
	if err != nil {
		return fmt.Errorf("the evidence was sealed at %s and no report could be issued from it: %w. "+
			"`xammu verify --store %s` still checks what was spent",
			filepath.ToSlash(dir), err, filepath.ToSlash(dir))
	}
	if len(d.Pass.Divergences) > 0 {
		fmt.Fprintf(c.out, "the sealed bundle re-derives %d reading(s) differently from the run that "+
			"wrote them; the report states this in its uncertainty dimension\n",
			len(d.Pass.Divergences))
	}
	rep, err := buildReport(d, auth, opts)
	if err != nil {
		return err
	}
	if err := publishReport(dir, rep, c.out); err != nil {
		return err
	}
	fmt.Fprintf(c.out, "\nnext: %s\n", opts.VerifyCmd)
	return nil
}

// verifyCommandOf builds the reproducibility command the report publishes from the
// flags the run itself published. A report that cites `xammu verify --run ID` is a
// promise about where the evidence lives and what scope re-derives it, so the command
// is assembled once, in run, and reused rather than recomputed from a later reader's
// flags: two renderings of one plan are two commands a validator would compare.
//
// The run id is the run's own, taken from the finished profile rather than from the
// flag: a reader who opened the bundle with --store typed no id at all, and a verify
// command without one names evidence nobody can locate.
func verifyCommandOf(runID, flags string) string {
	return strings.TrimSpace("xammu verify --run " + runID + " " + flags)
}

// refuseOverwrite keeps two runs out of one directory. Evidence from a second run
// appended to a sealed bundle would either fail the hash chain or, worse, produce a
// trail that commits to two different plans.
func refuseOverwrite(dir string) error {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("cannot check %s: %w", dir, err)
	}
	if len(entries) > 0 {
		return fmt.Errorf("%s already holds %d file(s): a run writes its own evidence and never "+
			"extends a bundle that exists. Choose another --run, or read the existing run with "+
			"`xammu report --store %s`", dir, len(entries), dir)
	}
	return nil
}

// noteExecution writes the executor's own account into the journal before sealing.
// A run that stopped for a reason has to say so in the evidence, not only in the
// terminal profile, because the failures are per-probe facts that no counter holds.
func noteExecution(run *orchestrator.Run, ex *orchestrator.Execution,
	req *planRequest, auth *contracts.ProfilingAuthorization) error {
	note := fmt.Sprintf(
		"execution under authorization %s: %d of %d planned exchange(s) produced evidence, "+
			"%d request(s) spent of a budget of %d; stopped because %s",
		auth.Ref, len(ex.Executed), len(req.items), ex.RequestsSent, req.sc.budget,
		orNoneText(ex.Stopped))
	if len(ex.Failures) > 0 {
		refs := make([]string, 0, len(ex.Failures))
		for _, f := range ex.Failures {
			refs = append(refs, f.Ref)
		}
		note += "; probes with a failed step: " + joinComma(refs)
	}
	return run.Note(note)
}

// journalFindings puts the C-16 records into the evidence trail, so a bundle holds
// the findings it published rather than only the raw exchanges they came from.
func journalFindings(run *orchestrator.Run, in []contracts.DiscoveryFinding) error {
	for _, f := range in {
		if err := run.Journal(integrity.StreamFindings, f); err != nil {
			return fmt.Errorf("cannot journal finding %s: %w", f.Ref, err)
		}
	}
	return nil
}

// seal inventories the finished store, signs the inventory with a key that lives
// outside the bundle and writes the manifest. The private key never enters the
// directory it signs: an artifact set that contains its own key can be re-signed by
// whoever copies it, which is not the property a manifest is supposed to have.
func seal(dir string, fin contracts.RunProfile, store *integrity.Store,
	auth *contracts.ProfilingAuthorization, keyPath string) (string, *integrity.Key, error) {
	if err := checkKeyOutsideBundle(dir, keyPath); err != nil {
		return "", nil, err
	}
	manifest, err := integrity.BuildManifest(dir, fin.RunID, auth.Ref, fin.ValidationRef,
		fin.Counters.Observations, store.Head(integrity.StreamObservations))
	if err != nil {
		return "", nil, fmt.Errorf("cannot inventory the sealed bundle: %w", err)
	}
	key, err := integrity.LoadOrCreateKey(keyPath)
	if err != nil {
		return "", nil, err
	}
	if err := integrity.Sign(&manifest, key); err != nil {
		return "", nil, fmt.Errorf("cannot sign the manifest: %w", err)
	}
	if err := integrity.WriteManifest(dir, manifest); err != nil {
		return "", nil, fmt.Errorf("cannot write the manifest: %w", err)
	}
	return filepath.Join(dir, "manifest.json"), key, nil
}

// checkKeyOutsideBundle keeps the promise seal makes: a copy of the evidence must
// not carry the key that signs it. The comparison is on absolute paths, so a key
// beside the run directory is accepted and one inside it is refused whichever
// spelling of the path reached this process.
func checkKeyOutsideBundle(dir, keyPath string) error {
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("cannot resolve the bundle directory %s: %w", dir, err)
	}
	absKey, err := filepath.Abs(keyPath)
	if err != nil {
		return fmt.Errorf("cannot resolve the signing key %s: %w", keyPath, err)
	}
	rel, err := filepath.Rel(absDir, absKey)
	if err != nil {
		// Different volumes: the key cannot be under this directory.
		return nil
	}
	if rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
		return fmt.Errorf("the signing key %s is inside the bundle %s: a copy of the evidence would "+
			"carry the key that signs it, so pass --signing-key with a path outside the run directory",
			keyPath, dir)
	}
	return nil
}

func joinComma(in []string) string {
	out := ""
	for i, s := range in {
		if i > 0 {
			out += ", "
		}
		out += s
	}
	return out
}

func orNoneText(s string) string {
	if s == "" {
		return "no stop reason was recorded"
	}
	return s
}
