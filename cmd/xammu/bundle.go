package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"xammu/internal/contracts"
	"xammu/internal/corpus"
	"xammu/internal/discover"
	"xammu/internal/inference"
	"xammu/internal/integrity"
	"xammu/internal/observer"
	"xammu/internal/report"
)

// The two document names a bundle publishes. They are constants rather than
// arguments because a finding's reproduction command has to name the same file the
// run wrote, and a reader who types `xammu verify --run ID` must land on it.
const (
	reportJSONFile = "report.json"
	reportMarkdown = "report.md"

	// defaultRunsDir is the layout a published reproduction command assumes. A
	// run that kept its bundle elsewhere says so in the command it publishes.
	defaultRunsDir = "runs"

	// defaultAuthDir is where a reference-resolved C-09 is looked for. A published
	// command only names the directory when the operator used another one.
	defaultAuthDir = "authorizations"
)

// derivation is one pass over a run's evidence. A live run makes it with a sink, so
// the derived records join the journal before the store is sealed; a re-read passes a
// nil sink, because evidence that is already closed is checked rather than rewritten.
type derivation struct {
	Store     *integrity.Store
	Pipeline  *inference.Pipeline
	Pass      *inference.Result
	Findings  *discover.Report
	Unplanned []discover.Unplanned
	Evidence  report.EvidenceFacts
	Profile   contracts.RunProfile
	Auth      *contracts.ProfilingAuthorization
	Set       *corpus.Set
}

// derive runs the inference pass, the discovery layer and the report assembly over an
// opened store. Nothing in here sends a request: the same code reads the evidence a
// run produced and the evidence a reviewer downloaded, which is what makes "verify it
// yourself" a command rather than a promise.
func derive(store *integrity.Store, profile contracts.RunProfile,
	auth *contracts.ProfilingAuthorization, set *corpus.Set, sc scope,
	sel *corpus.Selection, opts deriveOptions) (*derivation, error) {
	pipe, err := inference.New(observer.DefaultSet())
	if err != nil {
		return nil, fmt.Errorf("detector ensemble: %w", err)
	}
	journal, err := inference.Read(store)
	if err != nil {
		return nil, err
	}
	if journal.RunID != profile.RunID {
		return nil, fmt.Errorf("the journal in %s belongs to run %s but the checkpoint says %s: "+
			"a report cannot mix evidence from two runs", store.Dir(), journal.RunID, profile.RunID)
	}
	pass, err := pipe.Infer(journal, inference.Options{
		Sink: opts.Sink, At: opts.At, CommandFlags: opts.CommandFlags,
	})
	if err != nil {
		return nil, fmt.Errorf("inference pass: %w", err)
	}
	unplanned := unplannedFrom(sel)
	// The authorized grid the discovery layer compares against is the authorization's
	// own scope, not the subset this run's flags narrowed it to: an undetermined zone
	// is about what permission existed, and a flag is not a withdrawal of it.
	findings, err := discover.Analyze(discover.Input{
		RunID: profile.RunID, RoundID: profile.RoundID, Pass: pass, Corpus: set,
		Partition: sc.partition, AuthorizationRef: auth.Ref,
		AuthorizedClasses: auth.AllowedClasses, AuthorizedVectors: auth.AllowedVectors,
		Unplanned: unplanned, GeneratedAt: opts.Generated, CommandFlags: opts.CommandFlags,
		EngagementFlags: opts.EngagementFlags,
	})
	if err != nil {
		return nil, fmt.Errorf("discovery pass: %w", err)
	}
	ev, err := evidenceFacts(opts, store, profile.RunID, set.Root, pipe.Set.Hash())
	if err != nil {
		return nil, err
	}
	return &derivation{Store: store, Pipeline: pipe, Pass: pass, Findings: findings,
		Unplanned: unplanned, Evidence: ev, Profile: profile, Auth: auth, Set: set}, nil
}

// deriveOptions carries the choices that are about the document rather than the
// measurement: where the manifest lives, who asked for the report, when.
type deriveOptions struct {
	// Sink receives the derived records. Only a run in progress may pass one.
	Sink inference.Sink
	// At pins derived timestamps. Zero means "use the journal's own times", which
	// is what a re-read must do to reproduce identical records.
	At         time.Time
	ManifestIn string
	VerifyCmd  string
	// CommandFlags are the choices a published reproduction command has to repeat. A run
	// supplies them from the scope it resolved; a re-read rebuilds them from the sealed
	// plan journal, so the command a report prints is the same string whichever of the
	// two derived it.
	CommandFlags string
	// EngagementFlags is CommandFlags without this run's scope. The report publishes
	// steps that plan a class or a transport the run left unmeasured; carrying the
	// run's own --class onto those would ask the original question again and the
	// reader would spend requests to re-learn nothing.
	EngagementFlags string
	By              string
	Generated       time.Time
}

// evidenceFacts fills the reproducibility block. The manifest digest is read from
// disk after signing, so the report publishes the hash of the file a reviewer will
// open rather than the hash the process remembers computing.
func evidenceFacts(opts deriveOptions, store *integrity.Store,
	runID, corpusRoot, setHash string) (report.EvidenceFacts, error) {
	manifestPath := opts.ManifestIn
	if manifestPath == "" {
		manifestPath = filepath.Join(store.Dir(), "manifest.json")
	}
	digest, err := report.ManifestDigestOf(manifestPath)
	if err != nil {
		return report.EvidenceFacts{}, err
	}
	corpusRef, err := report.CorpusCommitRef(corpusRoot)
	if err != nil {
		return report.EvidenceFacts{}, err
	}
	verify := opts.VerifyCmd
	if verify == "" {
		verify = "xammu verify --run " + runID
	}
	return report.EvidenceFacts{
		ManifestPath: filepath.ToSlash(manifestPath), ManifestDigest: digest,
		VerifyCommand: verify, CorpusCommitRef: corpusRef,
		DetectorSetHash: setHash, ToolVersion: integrity.ToolVersion,
	}, nil
}

// buildReport assembles the C-15 document from a derivation.
func buildReport(d *derivation, auth *contracts.ProfilingAuthorization, opts deriveOptions) (*contracts.Report, error) {
	rep, err := report.Build(report.Input{
		Run: d.Profile, Auth: auth, Pass: d.Pass, Findings: d.Findings,
		Unplanned: d.Unplanned, Evidence: d.Evidence,
		GeneratedBy: opts.By, GeneratedAt: opts.Generated, CommandFlags: opts.CommandFlags,
	})
	if err != nil {
		return nil, fmt.Errorf("report assembly: %w", err)
	}
	return rep, nil
}

// publishReport writes the two renderings into the bundle and validates the JSON
// on the way out: a file that does not parse back into C-15 is not a published
// report, and finding that out after the tool exited would leave the operator with
// an artifact they cannot check.
func publishReport(dir string, rep *contracts.Report, out io.Writer) error {
	raw, err := report.JSON(rep)
	if err != nil {
		return fmt.Errorf("cannot render the report as JSON: %w", err)
	}
	var back contracts.Report
	if err := json.Unmarshal(raw, &back); err != nil {
		return fmt.Errorf("the published JSON does not parse: %w", err)
	}
	if err := contracts.Validate(contracts.IDReport, &back); err != nil {
		return fmt.Errorf("the published JSON does not satisfy C-15: %w", err)
	}
	jsonPath := filepath.Join(dir, reportJSONFile)
	if err := os.WriteFile(jsonPath, raw, 0o640); err != nil {
		return fmt.Errorf("cannot write %s: %w", jsonPath, err)
	}
	mdPath := filepath.Join(dir, reportMarkdown)
	if err := os.WriteFile(mdPath, []byte(report.Markdown(rep)), 0o640); err != nil {
		return fmt.Errorf("cannot write %s: %w", mdPath, err)
	}
	fmt.Fprintf(out, "report %s for run %s: %d finding(s), %d unevaluated zone(s)\n",
		rep.ReportID, rep.RunID, len(rep.Findings), len(rep.Unevaluated))
	fmt.Fprintf(out, "  %s\n  %s\n", filepath.ToSlash(jsonPath), filepath.ToSlash(mdPath))
	return nil
}

// readPublishedReport loads the report a run published. A bundle without one is a
// run that was sealed but never reported, which the tool says instead of inferring.
func readPublishedReport(dir string) (contracts.Report, error) {
	var rep contracts.Report
	path := filepath.Join(dir, reportJSONFile)
	if err := readContractFile(path, &rep, contracts.IDReport, "report"); err != nil {
		return rep, err
	}
	return rep, nil
}

// readBundle opens a run's evidence directory for reading. The store is opened but
// never written to by the commands that call this: report, verify and validate.
func readBundle(dir string) (*integrity.Store, contracts.RunProfile, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, contracts.RunProfile{}, fmt.Errorf("no run bundle at %s: %w", dir, err)
	}
	if !info.IsDir() {
		return nil, contracts.RunProfile{}, fmt.Errorf("%s is not a run bundle directory", dir)
	}
	store, err := integrity.Open(dir)
	if err != nil {
		return nil, contracts.RunProfile{}, fmt.Errorf("cannot open the evidence journals in %s: %w", dir, err)
	}
	profile, err := readProfile(dir)
	if err != nil {
		return nil, contracts.RunProfile{}, err
	}
	return store, profile, nil
}
