package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"xammu/internal/annex"
	"xammu/internal/contracts"
	"xammu/internal/corpus"
	"xammu/internal/gate"
	"xammu/internal/integrity"
	"xammu/internal/orchestrator"
	"xammu/internal/report"
)

// cmdReport re-derives the C-15 document from a sealed bundle. It sends nothing, it
// loads no target, and it writes nothing unless --out names a directory: the same
// evidence in, the same report out, which is the property a reviewer is actually
// asking about when they say "reproduce it".
func cmdReport(c *cli, args []string) error {
	var (
		f        planFlags
		format   string
		out      string
		cellRef  string
		langName string
		meta     annex.Meta
	)
	fs := newFlagSet("report", c.err)
	f.register(fs)
	fs.StringVar(&format, "format", "markdown",
		"human (markdown), json, both, annex (Markdown annex) or annex-html")
	fs.StringVar(&cellRef, "cell", "",
		"print one cell instead of the whole document: its trials, its reading, what it is "+
			"attributed to and which findings cite it")
	fs.StringVar(&out, "out", "",
		"directory to write the document into: report.json and report.md, or the annex as "+
			"annex-<lang>.md or annex-<lang>.html. Without it the document is printed")
	fs.StringVar(&langName, "lang", "",
		"annex language: es or en (default en)")
	fs.StringVar(&meta.Client, "client", "",
		"annex only: client name printed in the engagement block; the bundle stays anonymous")
	fs.StringVar(&meta.Engagement, "engagement", "",
		"annex only: engagement label printed in the engagement block")
	fs.StringVar(&meta.PreparedBy, "prepared-by", "",
		"annex only: person or team that prepared the annex")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := requireNoStrayArgs(fs); err != nil {
		return err
	}
	resolved, err := asReportFormat(format)
	if err != nil {
		return err
	}
	format = resolved
	isAnnex := isAnnexFormat(format)
	if !isAnnex {
		if used := annexOnlyFlags(fs); len(used) > 0 {
			return fmt.Errorf("%w: %s only apply to --format annex or annex-html",
				errUsage, strings.Join(used, ", "))
		}
	}
	if cellRef != "" && isAnnex {
		return fmt.Errorf("%w: --cell prints one cell and --format %s produces a client "+
			"document; ask for one or the other", errUsage, format)
	}
	lang := annex.English
	if isAnnex {
		lang, err = annex.ParseLang(langName)
		if err != nil {
			return fmt.Errorf("%w: %v", errUsage, err)
		}
	}

	rd, err := openForReading(f)
	if err != nil {
		return err
	}
	opts := deriveOptions{
		ManifestIn: filepath.Join(rd.dir, "manifest.json"),
		By:         generatedBy(f.generatedBy), Generated: time.Now().UTC(),
		CommandFlags: rd.commandFlags, EngagementFlags: rd.engagementFlags,
		VerifyCmd: rd.verifyCommand,
	}
	d, err := derive(rd.store, rd.profile, rd.auth, rd.set, rd.sc, rd.sel, opts)
	if err != nil {
		return err
	}
	rep, err := buildReport(d, rd.auth, opts)
	if err != nil {
		return err
	}
	if cellRef != "" {
		return renderCell(c, rd, d, cellRef)
	}
	fmt.Fprintf(c.err, "run %s in state %s: %d cell(s), %d finding(s), %d divergence(s), %d journal gap(s)\n",
		rep.RunID, rep.RunState, len(d.Pass.Verdicts), len(rep.Findings),
		len(d.Pass.Divergences), len(d.Pass.Missing))
	if len(d.Pass.Divergences) > 0 {
		// Divergences are printed before the document because a reader who sees a
		// rate in the report has to know the trail disagreed somewhere first.
		for _, dv := range d.Pass.Divergences {
			fmt.Fprintf(c.err, "  divergence: %s\n", dv)
		}
	}
	if isAnnex {
		doc := annex.Markdown(rep, lang, meta)
		if format == "annex-html" {
			doc = annex.HTML(rep, lang, meta)
		}
		if out != "" {
			if err := os.MkdirAll(out, 0o755); err != nil {
				return fmt.Errorf("cannot create %s: %w", out, err)
			}
			path := filepath.Join(out, annexFileName(format, lang))
			if err := os.WriteFile(path, []byte(doc), 0o640); err != nil {
				return fmt.Errorf("cannot write %s: %w", path, err)
			}
			fmt.Fprintf(c.out, "annex for run %s written to %s\n", rep.RunID, filepath.ToSlash(path))
			return nil
		}
		fmt.Fprint(c.out, doc)
		return nil
	}
	if out != "" {
		if err := os.MkdirAll(out, 0o755); err != nil {
			return fmt.Errorf("cannot create %s: %w", out, err)
		}
		if err := publishReport(out, rep, c.err); err != nil {
			return err
		}
		fmt.Fprintf(c.out, "written under %s\n", filepath.ToSlash(out))
		return nil
	}
	if format != "json" {
		fmt.Fprint(c.out, report.Markdown(rep))
	}
	if format == "json" || format == "both" {
		raw, err := report.JSON(rep)
		if err != nil {
			return err
		}
		fmt.Fprint(c.out, string(raw))
	}
	return nil
}

// asReportFormat resolves the name a reviewer types to the rendering that name
// means. "human" is the handoff's word for the document read by a person, and it is
// the same bytes as the markdown rendering: accepting both keeps the command in the
// delivery document runnable without giving the report two human formats that could
// drift apart.
func asReportFormat(name string) (string, error) {
	switch name {
	case "markdown", "human":
		return "markdown", nil
	case "json", "both":
		return name, nil
	case "annex", "annex-html":
		return name, nil
	}
	return "", fmt.Errorf("--format %q is not human (markdown), json, both, annex or annex-html", name)
}

func isAnnexFormat(format string) bool {
	return format == "annex" || format == "annex-html"
}

// annexOnlyFlags lists the flags an operator typed that only the annex reads. A
// non-annex rendering that silently ignored them would let someone believe a
// client name or language reached the document.
func annexOnlyFlags(fs *flag.FlagSet) []string {
	only := map[string]bool{"lang": true, "client": true, "engagement": true, "prepared-by": true}
	var used []string
	fs.Visit(func(fl *flag.Flag) {
		if only[fl.Name] {
			used = append(used, "-"+fl.Name)
		}
	})
	sort.Strings(used)
	return used
}

func annexFileName(format string, lang annex.Lang) string {
	ext := ".md"
	if format == "annex-html" {
		ext = ".html"
	}
	return "annex-" + string(lang) + ext
}

// reading is everything a re-derivation reads from disk, gathered once so the three
// read commands cannot disagree about which bundle they opened.
type reading struct {
	dir     string
	store   *integrity.Store
	profile contracts.RunProfile
	auth    *contracts.ProfilingAuthorization
	set     *corpus.Set
	sc      scope
	sel     *corpus.Selection
	// commandFlags are the choices the bundle's own plan says produced it: the
	// engagement flags from what the reader supplied and the scope from the plan
	// journal. A command a re-read prints therefore names the same plan a run printed,
	// not the flag set whoever re-read it happened to type.
	commandFlags string
	// engagementFlags is the same material without this run's scope, for the steps a
	// report publishes that plan a scope the run did not cover.
	engagementFlags string
	// verifyCommand is the command this document cites as its own reproduction step.
	// It is built here because the run id it names belongs to the bundle, not to the
	// flags: a reader who opened it with --store typed no id.
	verifyCommand string
}

// openForReading loads the sealed journals, the checkpoint, the authorization the run
// was executed under, the corpus the probes came from, the plan the run accepted and
// the selection arithmetic that says what was never planned. It opens nothing for
// writing.
func openForReading(f planFlags) (reading, error) {
	none := reading{}
	dir, err := f.bundle()
	if err != nil {
		return none, err
	}
	store, profile, err := readBundle(dir)
	if err != nil {
		return none, err
	}
	auth, err := f.bindAuthorization()
	if err != nil {
		return none, err
	}
	if profile.AuthorizationRef != auth.Ref {
		return none, fmt.Errorf(
			"run %s was executed under authorization %s, not %s: the scope a report states belongs to "+
				"the permission that was in force, and a different file cannot supply it",
			profile.RunID, profile.AuthorizationRef, auth.Ref)
	}
	if f.target != "" && profile.TargetOrigin != "" && f.target != profile.TargetOrigin {
		// --target on a re-read can only name the origin the run was bound to. It
		// cannot redirect the report at a host the run never contacted.
		return none, fmt.Errorf("--target %q does not match the origin run %s was bound to (%s)",
			f.target, profile.RunID, profile.TargetOrigin)
	}
	set, err := corpus.Load(f.corpusRoot, corpus.DefaultPolicy())
	if err != nil {
		return none, fmt.Errorf("corpus %s: %w", f.corpusRoot, err)
	}
	// The plan the run was executed under is signed evidence, so the re-read takes it
	// from there. A reader who types nothing re-derives the run; a reader who types a
	// different scope is refused, because a flag is not evidence and a report about a
	// plan nobody accepted would be a different document with the same run id.
	shape, err := readPlanShape(store, set)
	if err != nil {
		return none, err
	}
	if err := adoptRecordedScope(&f, profile, shape); err != nil {
		return none, err
	}
	f, err = recoverRequest(auth, set, f, shape)
	if err != nil {
		return none, err
	}
	if name, err := asPartition(profile.Partition); err == nil {
		// The partition is read from the checkpoint, not from the flags: the selection
		// arithmetic below has to run over the probes this run planned, and a reader
		// who forgets --partition would otherwise recompute another partition's
		// exclusions and publish them as this run's uncertainty.
		f.partition = string(name)
	}
	sc, sel, err := selectFrom(auth, set, f)
	if err != nil {
		return none, err
	}
	if diff := planDiffers(shape, sel); diff != "" {
		return none, fmt.Errorf("run %s recorded a plan this corpus and permission no longer "+
			"produce: %s. A re-read that planned a different set would publish a document about "+
			"a run that did not happen", profile.RunID, diff)
	} // The report describes the run that happened, so the origin and the budget are
	// the checkpoint's, not the flags' guess.
	sc.origin = profile.TargetOrigin
	sc.budget = profile.RequestBudget
	flags := strings.TrimSpace(f.reproFlags() + " " + scopeFlagsOf(sc, auth))
	return reading{dir: dir, store: store, profile: profile, auth: auth,
		set: set, sc: sc, sel: sel, commandFlags: flags,
		engagementFlags: f.engagementFlags(),
		verifyCommand:   verifyCommandOf(profile.RunID, flags)}, nil
}

// planShape is the plan a bundle's own journal recorded: the scope the selection was
// run over and the exchanges it accepted. It exists so a re-read can ask the evidence
// what the run planned instead of asking the reader what they remember.
type planShape struct {
	classes   []contracts.AttackClass
	vectors   []contracts.Vector
	encodings []contracts.Encoding
	controls  contracts.PartitionName
	refs      []string
}

// readPlanShape decodes the accepted plan the orchestrator journalled before sending
// anything. Every value here is in the signed inventory, which is what makes it
// evidence rather than a note: a plan edited after the seal breaks the hash chain that
// `verify` checks before any of this runs.
func readPlanShape(store *integrity.Store, set *corpus.Set) (planShape, error) {
	var shape planShape
	records, err := store.Records(integrity.StreamPlan)
	if err != nil {
		return shape, fmt.Errorf("cannot read the accepted plan: %w", err)
	}
	if len(records) == 0 {
		return shape, fmt.Errorf("the bundle journals no accepted plan, so there is nothing to say " +
			"which scope the selection ran over")
	}
	classes := map[contracts.AttackClass]bool{}
	vectors := map[contracts.Vector]bool{}
	encodings := map[contracts.Encoding]bool{}
	for _, r := range records {
		var item orchestrator.PlanItem
		if err := json.Unmarshal(r.Payload, &item); err != nil {
			return shape, fmt.Errorf("plan record %d does not decode: %w", r.Seq, err)
		}
		shape.refs = append(shape.refs, item.Ref)
		classes[item.AttackClass] = true
		vectors[item.Vector] = true
		encodings[item.Encoding] = true
		if item.ControlRole == contracts.RoleProbe || item.ControlRole == contracts.RoleEncodingReplica {
			continue
		}
		// Control traffic always comes from the controls partition, and the plan names the
		// corpus item it was placed from. Anything else would be a control the run could
		// not have selected.
		matches, err := set.Find(item.CorpusRef)
		if err != nil || len(matches) != 1 {
			continue
		}
		shape.controls = matches[0].Partition
	}
	shape.classes = orderedClasses(classes)
	shape.vectors = orderedVectors(vectors)
	shape.encodings = orderedEncodings(encodings)
	return shape, nil
}

// adoptRecordedScope replaces the reader's scope flags with the run's own. It refuses
// a flag that contradicts the bundle rather than quietly ignoring it: an operator who
// typed --class xss and got a report about sqli would have no way to tell which of the
// two the tool believed.
func adoptRecordedScope(f *planFlags, profile contracts.RunProfile, shape planShape) error {
	if f.budget != 0 && f.budget != profile.RequestBudget {
		return fmt.Errorf("--budget %d is not what run %s was planned under (%d): a re-read "+
			"re-plans the run's own scope, and a different budget would describe a plan nobody "+
			"accepted", f.budget, profile.RunID, profile.RequestBudget)
	}
	classValue, err := asClasses(splitList(f.classes))
	if err != nil {
		return err
	}
	if len(classValue) > 0 && !sameSet(classValue, shape.classes) {
		return fmt.Errorf("--class %s does not match the plan run %s recorded (%s): a re-read "+
			"describes the run, it does not choose a different one", f.classes, profile.RunID,
			strings.Join(classesToStrings(shape.classes), ","))
	}
	vectorValue, err := asVectors(splitList(f.vectors))
	if err != nil {
		return err
	}
	if len(vectorValue) > 0 && !sameSet(vectorValue, shape.vectors) {
		return fmt.Errorf("--vector %s does not match the plan run %s recorded (%s)",
			f.vectors, profile.RunID, strings.Join(vectorsToStrings(shape.vectors), ","))
	}
	encodingValue, err := asEncodings(splitList(f.encodings))
	if err != nil {
		return err
	}
	if len(encodingValue) > 0 && !sameSet(encodingValue, shape.encodings) {
		return fmt.Errorf("--encoding %s does not match the plan run %s recorded (%s)",
			f.encodings, profile.RunID, strings.Join(encodingsToStrings(shape.encodings), ","))
	}
	f.budget = profile.RequestBudget
	f.classes = strings.Join(classesToStrings(shape.classes), ",")
	f.vectors = strings.Join(vectorsToStrings(shape.vectors), ",")
	f.encodings = strings.Join(encodingsToStrings(shape.encodings), ",")
	if shape.controls != "" {
		if f.controls != "" && f.controls != string(contracts.PartitionCalibration) &&
			f.controls != string(shape.controls) {
			return fmt.Errorf("--controls %s does not match the plan run %s recorded, whose "+
				"control traffic came from %s", f.controls, profile.RunID, shape.controls)
		}
		f.controls = string(shape.controls)
	}
	return nil
}

// recoverRequest asks which request the bundle's plan came from. The plan journal
// records what was planned, not what was asked for: a budget-limited run drops cells
// before they reach the journal, so the realized classes, transports and encodings are
// usually a subset of the request. The request is recovered as the widest authorized
// scope whose selection still plans exactly the exchanges the run accepted, which is
// the operator's default: no flag means "everything this permission allows".
//
// A value the operator narrowed away, whose cells were all cut by the budget, is
// indistinguishable from a value that was requested and cut. Widening is chosen
// because the plan is identical either way: the run planned the same exchanges, and a
// report that says the other cells of the wider scope were never planned is true of
// both readings. The cost is that such a run re-derives a document whose unevaluated
// section is wider than the one it published, and `verify --rederive` says so instead
// of matching silently.
func recoverRequest(auth *contracts.ProfilingAuthorization, set *corpus.Set,
	f planFlags, shape planShape) (planFlags, error) {
	full := []struct {
		set func(*planFlags)
	}{
		{func(t *planFlags) {
			t.classes = strings.Join(classesToStrings(auth.AllowedClasses), ",")
		}},
		{func(t *planFlags) {
			t.vectors = strings.Join(vectorsToStrings(auth.AllowedVectors), ",")
		}},
		{func(t *planFlags) {
			t.encodings = strings.Join(encodingsToStrings(auth.AllowedEncodings), ",")
		}},
	}
	for changed := true; changed; {
		changed = false
		for _, dimension := range full {
			trial := f
			dimension.set(&trial)
			if trial.classes == f.classes && trial.vectors == f.vectors &&
				trial.encodings == f.encodings {
				continue
			}
			_, sel, err := selectFrom(auth, set, trial)
			if err != nil || planDiffers(shape, sel) != "" {
				continue
			}
			f, changed = trial, true
		}
	}
	return f, nil
}

// planDiffers names the way a re-planned selection departs from the journaled plan. It
// is checked because the selection decides which probes were never planned, and a
// selection computed from a different scope would publish an uncertainty section about
// a plan the run never accepted.
func planDiffers(shape planShape, sel *corpus.Selection) string {
	planned := map[string]bool{}
	for _, item := range sel.Items() {
		planned[item.Ref] = true
	}
	recorded := map[string]bool{}
	for _, ref := range shape.refs {
		recorded[ref] = true
	}
	var missing, extra []string
	for _, ref := range shape.refs {
		if !planned[ref] {
			missing = append(missing, ref)
		}
	}
	for _, item := range sel.Items() {
		if !recorded[item.Ref] {
			extra = append(extra, item.Ref)
		}
	}
	var parts []string
	if len(missing) > 0 {
		parts = append(parts, fmt.Sprintf("%d exchange(s) the run accepted are not selected now (%s)",
			len(missing), joinComma(firstN(missing, 3))))
	}
	if len(extra) > 0 {
		parts = append(parts, fmt.Sprintf("%d exchange(s) would be planned that the run never "+
			"accepted (%s)", len(extra), joinComma(firstN(extra, 3))))
	}
	return strings.Join(parts, "; ")
}

func firstN(in []string, n int) []string {
	if len(in) <= n {
		return in
	}
	return in[:n]
}

func orderedClasses(set map[contracts.AttackClass]bool) []contracts.AttackClass {
	var out []contracts.AttackClass
	for _, v := range contracts.AllAttackClasses() {
		if set[v] {
			out = append(out, v)
		}
	}
	return out
}

func orderedVectors(set map[contracts.Vector]bool) []contracts.Vector {
	var out []contracts.Vector
	for _, v := range contracts.AllVectors() {
		if set[v] {
			out = append(out, v)
		}
	}
	return out
}

func orderedEncodings(set map[contracts.Encoding]bool) []contracts.Encoding {
	var out []contracts.Encoding
	for _, v := range contracts.AllEncodings() {
		if set[v] {
			out = append(out, v)
		}
	}
	return out
}

// renderCell answers the question a cell's reproduction command invites: what did this
// bundle measure at this coordinate. It prints the trials, the readings they produced,
// the evidence the profile grants, what those readings are attributed to, and which
// published findings cite the cell. It sends nothing and writes nothing.
func renderCell(c *cli, rd reading, d *derivation, cellRef string) error {
	want := cellRef
	if !strings.HasPrefix(want, "cell:") {
		want = "cell:" + want
	}
	for _, v := range d.Pass.Verdicts {
		if v.Cell.Ref() != want {
			continue
		}
		fmt.Fprintf(c.out, "cell %s on %s\n", v.Cell.Ref(), v.Cell.Origin)
		fmt.Fprintf(c.out, "  %d trial(s): %d valid, %d inconclusive, %d invalid\n",
			len(v.Cell.Trials), v.Cell.Valid, v.Cell.Inconclusive, v.Cell.Invalid)
		if len(v.Cell.Signals) > 0 {
			signals := make([]string, 0, len(v.Cell.Signals))
			for s, n := range v.Cell.Signals {
				signals = append(signals, fmt.Sprintf("%s=%d", s, n))
			}
			sort.Strings(signals)
			fmt.Fprintf(c.out, "  readings: %s\n", joinComma(signals))
		}
		fmt.Fprintf(c.out, "  rounds: %s | runs: %s\n",
			joinComma(v.Cell.RoundIDs), joinComma(v.Cell.RunIDs))
		fmt.Fprintf(c.out, "\nevidence %s, claims up to %s: %s\n",
			v.Profile.Level, v.Profile.ClaimCeiling, v.Profile.CeilingJustification)
		if len(v.Profile.MissingEvidence) > 0 {
			fmt.Fprint(c.out, "  missing before it can rise:\n")
			for _, need := range v.Profile.MissingEvidence {
				fmt.Fprintf(c.out, "    - %s\n", need)
			}
		}
		if v.Attribution != nil {
			fmt.Fprintf(c.out, "\nattribution %s: %s (status %s, basis %s)\n",
				v.Attribution.AttributionID, v.Attribution.Primary,
				v.Attribution.Status, v.Attribution.EvidenceBasis)
			for _, alt := range v.Attribution.Alternatives {
				fmt.Fprintf(c.out, "  %-24s %-12s %s\n", alt.Kind, alt.State, alt.Justification)
			}
			if len(v.Attribution.RequiredMissing) > 0 {
				fmt.Fprint(c.out, "  required but absent:\n")
				for _, need := range v.Attribution.RequiredMissing {
					fmt.Fprintf(c.out, "    - %s\n", need)
				}
			}
		}
		if v.Hypothesis != nil {
			fmt.Fprintf(c.out, "\nhypothesis %s is %s: %s\n",
				v.Hypothesis.Ref, v.Hypothesis.Outcome, v.Hypothesis.OutcomeReason)
			fmt.Fprintf(c.out, "  %s\n", v.Hypothesis.Statement)
			if v.Hypothesis.Falsifier != "" {
				fmt.Fprintf(c.out, "  would refute it: %s\n", v.Hypothesis.Falsifier)
			}
			if v.Hypothesis.ReproductionCommand != "" {
				fmt.Fprintf(c.out, "  reproduce: %s\n", v.Hypothesis.ReproductionCommand)
			}
		} else {
			fmt.Fprintf(c.out, "\nno hypothesis: %s\n", orNoneText(v.Skip))
			for _, ob := range v.Obstacles {
				fmt.Fprintf(c.out, "  obstacle (%s): %s\n", ob.Reason, ob.Detail)
			}
		}
		var cited []string
		for idx := range d.Findings.Findings {
			if d.Findings.Findings[idx].HypothesisRef == "hyp."+want {
				cited = append(cited, d.Findings.Findings[idx].Ref)
			}
		}
		if len(cited) == 0 {
			fmt.Fprint(c.out, "\nno published finding cites this cell, so the report says nothing "+
				"about it beyond the readings above.\n")
			return nil
		}
		fmt.Fprintf(c.out, "\ncited by %d finding(s):\n", len(cited))
		for _, ref := range cited {
			fmt.Fprintf(c.out, "  %s\n", ref)
			fmt.Fprintf(c.out, "    re-check: xammu validate --finding %s --run %s %s\n",
				ref, rd.profile.RunID, rd.commandFlags)
		}
		return nil
	}
	var known []string
	for _, v := range d.Pass.Verdicts {
		if len(known) < 12 {
			known = append(known, v.Cell.Ref())
		}
	}
	return fmt.Errorf("run %s measured no cell %s: this bundle holds %d cell(s), starting with %s",
		rd.profile.RunID, cellRef, len(d.Pass.Verdicts), joinComma(known))
}

// cmdVerify checks a bundle against its own signed manifest. It answers the question
// a report cannot answer about itself: is this evidence what it claims to be.
func cmdVerify(c *cli, args []string) error {
	var (
		f              planFlags
		trustKey       string
		rederive       bool
		publicationDir string
	)
	fs := newFlagSet("verify", c.err)
	f.register(fs)
	fs.StringVar(&trustKey, "trust-key", "",
		"file holding the hex ed25519 public key this operator trusts; without it the signature is "+
			"only checked for self-consistency")
	fs.BoolVar(&rederive, "rederive", false,
		"re-run the inference pass over the sealed journals and report any reading that disagrees")
	fs.StringVar(&publicationDir, "publication", "",
		"verify a signed delivery directory instead of a bundle; checks the envelope, every listed "+
			"file and the source manifest")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := requireNoStrayArgs(fs); err != nil {
		return err
	}
	if publicationDir != "" {
		return verifyPublicationDelivery(c, publicationDir, trustKey, rederive, f, fs)
	}
	dir, err := f.bundle()
	if err != nil {
		return err
	}
	if isEffectivenessBundle(dir) {
		// E-03 is arithmetic over the E-01/E-02 journals, not a re-issued report
		// finding, so the re-derivation does not need the C-09 that paid for the
		// traffic. The bundle names that authorization and --authorization can
		// still be supplied to verify it.
		return verifyEffectivenessBundle(c, dir, trustKey, rederive, f)
	}
	if rederive && f.authorization == "" {
		return fmt.Errorf("--rederive re-issues the report from the evidence, and the evidence ladder " +
			"starts at the permission that allowed the requests: pass --authorization REF or FILE too. " +
			"The C-09 is cited by run.json but not copied into the bundle, so a reviewer needs the copy " +
			"the engagement approved.")
	}
	// The store is opened to prove the journals decode and the checkpoint is a valid
	// C-11; the checks below then work from the files on disk rather than from this
	// process's copies of them.
	_, profile, err := readBundle(dir)
	if err != nil {
		return err
	}
	if f.authorization == "" && f.issuerKeyring != "" {
		return fmt.Errorf("%w: --issuer-keyring verifies a permission, and no --authorization was named", errUsage)
	}
	if f.authorization != "" {
		// A permission named beside a bundle is verified here even without
		// --rederive: if the signature does not hold, the answer is a failed
		// verification, not a note. The bundle itself never holds the C-09, so this
		// is the only place a reader can check the document the run cites.
		auth, err := f.bindAuthorization()
		if err != nil {
			return err
		}
		if auth.Ref != profile.AuthorizationRef {
			return fmt.Errorf("run %s was executed under authorization %s, not %s: the permission "+
				"supplied does not describe this evidence", profile.RunID, profile.AuthorizationRef, auth.Ref)
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
			// A missing trust anchor is a fact about this operator's configuration,
			// not about the bundle. The published reproduction command cannot name a
			// key file, so the bare form must report the evidence as consistent and
			// say plainly that the identity behind the signature was not checked.
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
	fmt.Fprintf(c.out, "\nrun %s (%s) signed by key %s: %d file(s) in the manifest, %d observation(s)\n",
		profile.RunID, profile.State, manifest.SignerKeyID, len(manifest.Files),
		profile.Counters.Observations)
	derived := outsideInventory(dir, manifest)
	if len(derived) > 0 {
		fmt.Fprintf(c.out, "\n%d file(s) sit outside the signed inventory (%s): they are derived after "+
			"the seal, so the signature commits to the evidence and not to the document. `--rederive` "+
			"with the run's authorization re-issues the document from the signed evidence and compares "+
			"them.\n", len(derived), joinComma(derived))
	}
	if rederive {
		if err := rederiveReadings(c, f); err != nil {
			return err
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("the bundle does not verify: %d check(s) failed, starting with %q: %s",
			len(failed), failed[0].Check, failed[0].Detail)
	}
	fmt.Fprint(c.out, "\nthe evidence commits to itself. Verification says nothing about whether the "+
		"readings are correct: that is what the report's findings and the reproduction commands are for.\n")
	if unanchored {
		fmt.Fprintf(c.out, "it says nothing about who signed it either: no trusted key was supplied, so "+
			"the signature was checked against the public key inside the same manifest. Pass "+
			"--trust-key FILE to make the identity a real check.\n")
	}
	return nil
}

// verifyPublicationDelivery verifies a signed delivery: the envelope, every file
// it lists, the internal consistency of gate.json, and the source bundle the
// envelope names. It re-derives no finding: the delivery is a presentation of a
// gate verdict, and the verdict is rechecked by applying the embedded policy to
// the embedded numbers.
func verifyPublicationDelivery(c *cli, dir, trustKey string, rederive bool, f planFlags,
	fs *flag.FlagSet) error {
	if rederive {
		return fmt.Errorf("%w: --rederive re-issues a report from a bundle's journals; a delivery "+
			"is checked against its own gate.json, so verify the bundle instead", errUsage)
	}
	allowed := map[string]bool{"publication": true, "trust-key": true, "store": true,
		"run": true, "runs-dir": true}
	var stray []string
	fs.Visit(func(fl *flag.Flag) {
		if !allowed[fl.Name] {
			stray = append(stray, "--"+fl.Name)
		}
	})
	if len(stray) > 0 {
		sort.Strings(stray)
		return fmt.Errorf("%w: %s do not apply to --publication; a delivery is verified from its "+
			"envelope and the bundle named by --store or --run", errUsage, strings.Join(stray, ", "))
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
	pub, statuses, err := gate.VerifyDelivery(dir, trusted)
	if err != nil {
		return err
	}
	bundleDir, bundleErr := resolvePublicationBundle(pub, dir, f)
	if bundleErr == nil {
		statuses = append(statuses, gate.VerifyPublicationSource(pub, bundleDir, trusted)...)
	} else {
		statuses = append(statuses, integrity.VerifyStatus{Check: "source_bundle_located",
			OK: false, Detail: bundleErr.Error()})
	}
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
		fmt.Fprintf(c.out, "%-4s %-32s %s\n", mark, s.Check, s.Detail)
	}
	digest, err := gate.PublicationDigest(*pub)
	if err != nil {
		return err
	}
	fmt.Fprintf(c.out, "\ndelivery %s: run %s, verdict %s (exit %d), %d document(s)\n",
		filepath.ToSlash(dir), pub.Source.RunID, pub.Verdict, pub.ExitCode, len(pub.Files))
	fmt.Fprintf(c.out, "envelope %s signed by key %s; policy %s\n", digest, pub.SignerKeyID,
		pub.PolicySHA256)
	if bundleErr == nil {
		fmt.Fprintf(c.out, "source bundle %s: manifest %s\n", filepath.ToSlash(bundleDir),
			pub.Source.ManifestSHA256)
	}
	if len(failed) > 0 {
		return fmt.Errorf("the delivery does not verify: %d check(s) failed, starting with %q: %s",
			len(failed), failed[0].Check, failed[0].Detail)
	}
	fmt.Fprint(c.out, "\nthe delivery commits to itself and to the bundle it names. The signature "+
		"proves who signed this envelope, not that the readings are correct: the report's controls "+
		"and reproduction commands are for that.\n")
	if unanchored {
		fmt.Fprintf(c.out, "the identity is not anchored: no trusted key was supplied. Pass "+
			"--trust-key FILE to make it a real check.\n")
	}
	return nil
}

// resolvePublicationBundle finds the evidence a delivery names. An explicit
// --store or --run wins; otherwise the bundle path recorded in the envelope is
// tried as written, then relative to the delivery and its two parent
// directories, which covers the repository's publications/<run-id> layout
// without guessing at an absolute path.
func resolvePublicationBundle(p *gate.Publication, dir string, f planFlags) (string, error) {
	if f.storeDir != "" || f.runID != "" {
		return f.bundle()
	}
	named := strings.TrimSpace(p.Source.Bundle)
	if named == "" {
		return "", fmt.Errorf("the envelope names no source bundle; pass --store DIR or --run ID")
	}
	candidates := []string{named}
	if !filepath.IsAbs(named) {
		rel := filepath.FromSlash(named)
		candidates = append(candidates,
			filepath.Join(dir, rel),
			filepath.Join(dir, "..", rel),
			filepath.Join(dir, "..", "..", rel))
	}
	for _, candidate := range candidates {
		if fi, err := os.Stat(filepath.Join(candidate, "manifest.json")); err == nil && !fi.IsDir() {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("cannot locate the source bundle %q: a delivery names its evidence but "+
		"does not copy it, so pass --store DIR or --run ID to verify where the evidence is", named)
}

// outsideInventory names the files in a bundle that the signed manifest does not
// cover. They are the derived documents, written after the seal: listing them is how
// `verify` keeps from implying that a signature authenticates a report it never saw.
func outsideInventory(dir string, m contracts.IntegrityManifest) []string {
	listed := make(map[string]bool, len(m.Files))
	for _, f := range m.Files {
		listed[f.Path] = true
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := filepath.ToSlash(e.Name())
		if name == "manifest.json" || listed[name] {
			continue
		}
		out = append(out, name)
	}
	return out
}

// rederiveReadings runs the inference pass over the sealed journals with no sink, so
// the comparison cannot rewrite the trail it is checking. It then compares the whole
// published document: the signed manifest covers the journals, and the report is
// derived after the seal, so re-derivation is the only thing that can tell a reviewer
// that the document in front of them still comes out of the evidence beside it.
func rederiveReadings(c *cli, f planFlags) error {
	rd, err := openForReading(f)
	if err != nil {
		return err
	}
	published, err := readPublishedReport(rd.dir)
	if err != nil {
		return err
	}
	opts := deriveOptions{ManifestIn: filepath.Join(rd.dir, "manifest.json"),
		By: generatedBy(f.generatedBy), Generated: time.Now().UTC(),
		CommandFlags: rd.commandFlags, EngagementFlags: rd.engagementFlags,
		VerifyCmd: rd.verifyCommand}
	d, err := derive(rd.store, rd.profile, rd.auth, rd.set, rd.sc, rd.sel, opts)
	if err != nil {
		return err
	}
	fmt.Fprintf(c.out, "\nre-derivation over %s:\n", filepath.ToSlash(rd.dir))
	fmt.Fprintf(c.out, "  %s\n", d.Pass.Summary())
	if len(d.Pass.Divergences) == 0 {
		fmt.Fprint(c.out, "  every re-derived reading agrees with the journaled one\n")
	} else {
		for _, dv := range d.Pass.Divergences {
			fmt.Fprintf(c.out, "  divergence: %s\n", dv)
		}
	}
	for _, ref := range d.Pass.Missing {
		fmt.Fprintf(c.out, "  journal gap: %s was sent but never classified\n", ref)
	}
	problems := 0
	for idx := range published.Findings {
		want := published.Findings[idx]
		got := findFinding(d.Findings.Findings, want.Ref)
		if got == nil {
			fmt.Fprintf(c.out, "  %s is in the published document but this pass over the sealed "+
				"evidence does not produce it\n", want.Ref)
			problems++
			continue
		}
		for _, line := range compareFinding(want, *got) {
			fmt.Fprintf(c.out, "  %s: %s\n", want.Ref, line)
			problems++
		}
	}
	if problems > 0 {
		return fmt.Errorf("the published document does not re-derive from its own evidence: %d "+
			"difference(s) across %d finding(s)", problems, len(published.Findings))
	}
	fmt.Fprintf(c.out, "  all %d published finding(s) re-derive with the same claim, grade and "+
		"missing evidence\n", len(published.Findings))
	return nil
}

// cmdValidate answers the question a finding invites: does this claim still come out
// of this evidence. It re-derives the finding set and compares the reader-relevant
// fields of the one the operator named.
func cmdValidate(c *cli, args []string) error {
	var (
		f        planFlags
		findings refList
	)
	fs := newFlagSet("validate", c.err)
	f.register(fs)
	fs.Var(&findings, "finding", "reference of a published finding to re-derive; repeatable")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := requireNoStrayArgs(fs); err != nil {
		return err
	}
	if len(findings) == 0 {
		return fmt.Errorf("validate needs at least one --finding REF: a run-wide agreement check " +
			"is `xammu verify --rederive`, and this command is about one named claim")
	}
	rd, err := openForReading(f)
	if err != nil {
		return err
	}
	published, err := readPublishedReport(rd.dir)
	if err != nil {
		return err
	}
	opts := deriveOptions{ManifestIn: filepath.Join(rd.dir, "manifest.json"),
		By: generatedBy(f.generatedBy), Generated: time.Now().UTC(),
		CommandFlags: rd.commandFlags, EngagementFlags: rd.engagementFlags,
		VerifyCmd: rd.verifyCommand}
	d, err := derive(rd.store, rd.profile, rd.auth, rd.set, rd.sc, rd.sel, opts)
	if err != nil {
		return err
	}
	fmt.Fprintf(c.out, "run %s, report %s, authorization %s\n", published.RunID,
		published.ReportID, published.AuthorizationRef)
	var problems int
	for _, ref := range findings {
		want := findFinding(published.Findings, ref)
		got := findFinding(d.Findings.Findings, ref)
		switch {
		case want == nil:
			fmt.Fprintf(c.out, "%-28s NOT PUBLISHED: the report for this run carries no finding with "+
				"that reference\n", ref)
			problems++
		case got == nil:
			fmt.Fprintf(c.out, "%-28s NOT RE-DERIVED: the published report claims it, but this pass over "+
				"the sealed evidence does not produce it\n", ref)
			problems++
		default:
			diffs := compareFinding(*want, *got)
			if len(diffs) == 0 {
				fmt.Fprintf(c.out, "%-28s agrees: type %s, %s, evidence %s\n",
					ref, want.FindingType, want.ClaimType, want.EvidenceLevel)
				continue
			}
			fmt.Fprintf(c.out, "%-28s disagrees on %d field(s)\n", ref, len(diffs))
			for _, line := range diffs {
				fmt.Fprintf(c.out, "    %s\n", line)
			}
			problems++
		}
	}
	if problems > 0 {
		return fmt.Errorf("%d of %d finding(s) did not re-derive as published: the report states more "+
			"than the evidence reproduces", problems, len(findings))
	}
	fmt.Fprint(c.out, "\nevery named finding came back from the sealed evidence with the same claim, the "+
		"same grade and the same missing evidence.\n")
	return nil
}

// refList collects repeated --finding values. The flag package needs a setter rather
// than a slice pointer so one reference per occurrence stays explicit.
type refList []string

func (r *refList) String() string { return strings.Join(*r, ",") }

func (r *refList) Set(v string) error {
	trimmed := strings.TrimSpace(v)
	if trimmed == "" {
		return fmt.Errorf("an empty finding reference names nothing to re-derive")
	}
	*r = append(*r, trimmed)
	return nil
}

func findFinding(in []contracts.DiscoveryFinding, ref string) *contracts.DiscoveryFinding {
	for idx := range in {
		if in[idx].Ref == ref {
			return &in[idx]
		}
	}
	return nil
}

// compareFinding lists the fields a reader acts on. Identifiers, timestamps and the
// UUIDs inside the citations are not compared: those are the writing of the record,
// and a re-derivation legitimately writes them again.
func compareFinding(published, derived contracts.DiscoveryFinding) []string {
	var out []string
	add := func(field, a, b string) {
		if a != b {
			out = append(out, fmt.Sprintf("%s: published %q, re-derived %q", field, a, b))
		}
	}
	add("finding_type", string(published.FindingType), string(derived.FindingType))
	add("claim_type", string(published.ClaimType), string(derived.ClaimType))
	add("evidence_level", string(published.EvidenceLevel), string(derived.EvidenceLevel))
	add("attribution_status", string(published.AttributionStatus), string(derived.AttributionStatus))
	add("evidence_basis", string(published.EvidenceBasis), string(derived.EvidenceBasis))
	add("what_was_observed", published.WhatWasObserved, derived.WhatWasObserved)
	add("what_is_inferred", published.WhatIsInferred, derived.WhatIsInferred)
	add("what_evidence_is_missing", published.WhatEvidenceIsMissing, derived.WhatEvidenceIsMissing)
	add("reproduction_command", published.ReproductionCommand, derived.ReproductionCommand)
	add("regression_test", published.RegressionTest, derived.RegressionTest)
	add("priority", string(published.Priority), string(derived.Priority))
	add("attack_class", string(published.AttackClass), string(derived.AttackClass))
	add("vector", string(published.Vector), string(derived.Vector))
	add("encoding", string(published.Encoding), string(derived.Encoding))
	add("affected_scope", published.AffectedScope, derived.AffectedScope)
	add("measured_impact", ratioLine(published.MeasuredImpact), ratioLine(derived.MeasuredImpact))
	if len(published.ObservationRefs) != len(derived.ObservationRefs) {
		out = append(out, fmt.Sprintf("observation_refs: published %d, re-derived %d",
			len(published.ObservationRefs), len(derived.ObservationRefs)))
	}
	if len(published.Limitations) != len(derived.Limitations) {
		out = append(out, fmt.Sprintf("limitations: published %d line(s), re-derived %d",
			len(published.Limitations), len(derived.Limitations)))
	}
	return out
}

func ratioLine(r contracts.Ratio) string {
	return fmt.Sprintf("%d/%d excluding %d inconclusive and %d invalid over %s",
		r.Numerator, r.Denominator, r.ExcludedInconclusive, r.ExcludedInvalid, r.PopulationRef)
}

// decodeHexKey reads a trusted public key file. The format is the hex encoding of the
// 32-byte ed25519 public key; anything else is refused rather than guessed at.
func decodeHexKey(text string) ([]byte, error) {
	fields := strings.Fields(text)
	if len(fields) != 1 {
		return nil, fmt.Errorf("a trusted key file holds exactly one hex ed25519 public key, "+
			"found %d whitespace-separated value(s)", len(fields))
	}
	raw, err := hex.DecodeString(fields[0])
	if err != nil {
		return nil, fmt.Errorf("the trusted key is not a hex ed25519 public key: %w", err)
	}
	if len(raw) != 32 {
		return nil, fmt.Errorf("the trusted key is %d byte(s); an ed25519 public key is 32", len(raw))
	}
	return raw, nil
}
