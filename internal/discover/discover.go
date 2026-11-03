// Package discover turns a finished inference pass into C-16 findings.
//
// It is the layer that decides whether XAMMU was worth running. Everything below
// it (the report, the CLI output) renders what this package publishes, so the
// rule this package works to is the rule the delivery is judged by: a security
// engineer who reads a finding must be able to take a concrete action from it --
// check a configuration setting, enable inspection on a transport, add a rule to
// a review list -- without having to re-derive the measurement first.
//
// Two constraints shape the whole package:
//
//  1. A finding is a comparison between an expectation the corpus states and a
//     reading the run produced. There is no other source of findings here. A
//     finding that could not look its own expectation up in the corpus is refused
//     rather than written from prose, because "the WAF probably does not inspect
//     the body" is an opinion and "0 of 6 valid trials of group G-DEV-GEN-SENTINEL
//     in body_json were refused, where the same group in query was refused 8 of 8"
//     is a measurement.
//
//  2. Every published finding is validated against C-16 before it is returned.
//     The four honesty fields, the denominator, the reproduction command bound to
//     this authorization, the evaluated alternatives: a finding that fails the
//     contract is an error out of Analyze, not a degraded row in a report. A
//     reader cannot receive an unpublishable finding from this package.
//
// The finding types are exactly the C-16 vocabulary, and the distinction between
// them is stated in each detector rather than left to the reader:
//
//   - coverage_gap: probes the corpus expects to be refused were handled
//     ordinarily, as the majority reading of that cell. A contradiction between
//     the declared rule table and what the engine did.
//   - encoding_bypass_pattern: the canonical form of a probe family was refused
//     while an encoding replica of the same family was not. The engine's decoding
//     depth, measured.
//   - vector_asymmetry: the same group placed in two transports produced
//     different readings. Inspection coverage differs per transport.
//   - over_blocking: traffic the corpus defines as legitimate was refused,
//     measured over the legitimate population.
//   - configuration_concern: a refusal whose corpus grounding is a named policy
//     rather than a signature, i.e. behaviour no rule-table review would predict.
//   - undetermined_area: the run produced no reading. It states where XAMMU did
//     not learn something, and why, with a typed reason code.
package discover

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"xammu/internal/contracts"
	"xammu/internal/corpus"
	"xammu/internal/inference"
)

// Unplanned is a corpus item the run was allowed to send and did not. The CLI
// fills it from the selection's exclusions, because only the selection knows
// whether the cause was the budget, the authorization, or a control that fell
// outside the scope.
type Unplanned struct {
	Ref    string
	Reason contracts.ReasonCode
	Detail string
}

// Input is one finished pass plus the material needed to read it: the corpus the
// probes came from and the scope the authorization covered.
type Input struct {
	RunID             string
	RoundID           string
	Pass              *inference.Result
	Corpus            *corpus.Set
	Partition         contracts.PartitionName
	AuthorizationRef  string
	AuthorizedClasses []contracts.AttackClass
	AuthorizedVectors []contracts.Vector
	Unplanned         []Unplanned
	GeneratedAt       time.Time

	// CommandFlags are the operator's placement choices, carried so every command this
	// layer publishes can be pasted and made to work. A reproduction command that
	// omits where the probes were placed reproduces a different plan, which is worse
	// than no command at all: it looks like a check and is not one. It is never
	// appended to a `xammu lab test` scenario, which takes its own flags.
	CommandFlags string

	// EngagementFlags names the permission and the corpus without naming this run's
	// scope. The steps that ask for a scope the run did NOT cover - a playbook over a
	// class left unmeasured - are built from these, because appending the run's own
	// --class and --budget to them would re-ask the question the step exists to answer.
	EngagementFlags string
}

// Report is the finding set for one pass, in the order a report should render
// them: measured findings first, undetermined areas last.
type Report struct {
	RunID     string
	RoundID   string
	Findings  []contracts.DiscoveryFinding
	Counts    map[contracts.FindingType]int
	Baseline  Baseline
	Generated time.Time
}

// Baseline records what the run's own calibration did. It is not a finding: an
// absent over-block is the healthy result and belongs in the report's health
// section, where its absence would otherwise look like an omission.
type Baseline struct {
	PositiveControls     int
	PositiveRefused      int
	CalibrationTrials    int
	CalibrationRefused   int
	ExcludedInvalid      int
	ExcludedInconclusive int
}

// Summary renders the report as counts, for a log line or a terminal. It states
// no conclusion, because the conclusions are in the findings.
func (r *Report) Summary() string {
	var parts []string
	for _, ty := range contracts.AllFindingTypes() {
		if n := r.Counts[ty]; n > 0 {
			parts = append(parts, string(ty)+"="+fmt.Sprint(n))
		}
	}
	if len(parts) == 0 {
		parts = append(parts, "no finding")
	}
	return fmt.Sprintf("run %s round %s: %d finding(s) (%s); baseline: %d/%d positive control(s) "+
		"refused as declared, %d/%d legitimate exchange(s) refused",
		r.RunID, r.RoundID, len(r.Findings), strings.Join(parts, ", "),
		r.Baseline.PositiveRefused, r.Baseline.PositiveControls,
		r.Baseline.CalibrationRefused, r.Baseline.CalibrationTrials)
}

// reading is one exchange joined to the corpus item that authorised it. The
// join is the whole basis of this package: a trial without its expectation is a
// status code, and a status code cannot be a finding.
type reading struct {
	Trial inference.Trial
	Item  contracts.CorpusItem
	Key   inference.CellKey
	// Verdict is the pass's own conclusion about the cell this trial belongs to,
	// which is where the evidence level and the hypothesis reference come from.
	Verdict inference.Verdict
}

// index holds one pass in the shape the detectors need.
type index struct {
	in       Input
	readings []reading
	byCell   map[inference.CellKey][]reading
	byGroup  map[string][]reading
	verdicts map[inference.CellKey]inference.Verdict

	positive []inference.Trial
	benign   []inference.Trial

	// positiveRefused and anyRateLimited are run-wide facts that the alternatives
	// are judged against. They come from the journaled signals, never from a
	// description of the run.
	positiveRefused bool
	anyRateLimited  bool
	anyRefused      bool
}

// Analyze reads one finished pass and publishes its findings.
func Analyze(in Input) (*Report, error) {
	if err := in.validate(); err != nil {
		return nil, err
	}
	ix, err := buildIndex(in)
	if err != nil {
		return nil, err
	}
	rep := &Report{RunID: in.RunID, RoundID: in.RoundID, Generated: in.GeneratedAt,
		Counts: map[contracts.FindingType]int{}, Baseline: ix.baseline()}

	detectors := []func(*Report) error{
		ix.coverageGaps,
		ix.vectorAsymmetries,
		ix.encodingBypasses,
		ix.overBlocking,
		ix.configurationConcerns,
		ix.undeterminedAreas,
	}
	for _, d := range detectors {
		if err := d(rep); err != nil {
			return nil, err
		}
	}
	sort.Slice(rep.Findings, func(i, k int) bool {
		pi, pk := priorityRank(rep.Findings[i].Priority), priorityRank(rep.Findings[k].Priority)
		if pi != pk {
			return pi < pk
		}
		if rep.Findings[i].FindingType != rep.Findings[k].FindingType {
			return rep.Findings[i].FindingType < rep.Findings[k].FindingType
		}
		return rep.Findings[i].Ref < rep.Findings[k].Ref
	})
	return rep, nil
}

func (in Input) validate() error {
	var gaps []string
	if strings.TrimSpace(in.RunID) == "" {
		gaps = append(gaps, "no run id: a finding that names no run cannot be reproduced")
	}
	if strings.TrimSpace(in.RoundID) == "" {
		gaps = append(gaps, "no round id: the evidence level of a finding is a statement about rounds")
	}
	if in.Pass == nil {
		gaps = append(gaps, "no inference result: findings are derived from a finished pass, not asserted")
	}
	if in.Corpus == nil {
		gaps = append(gaps, "no corpus: an expectation the run did not meet is the only thing this "+
			"package can report")
	}
	if strings.TrimSpace(string(in.Partition)) == "" {
		gaps = append(gaps, "no probe partition named")
	}
	if strings.TrimSpace(in.AuthorizationRef) == "" {
		gaps = append(gaps, "no authorization reference: a reproduction command that is not bound to an "+
			"authorization invites a reader to send traffic outside the authorized scope")
	}
	if in.GeneratedAt.IsZero() {
		gaps = append(gaps, "no generation time: detected_at would be a placeholder")
	}
	if len(gaps) > 0 {
		return fmt.Errorf("discover: refusing to analyse: %s", strings.Join(gaps, "; "))
	}
	return nil
}

func buildIndex(in Input) (*index, error) {
	ix := &index{
		in:       in,
		byCell:   map[inference.CellKey][]reading{},
		byGroup:  map[string][]reading{},
		verdicts: map[inference.CellKey]inference.Verdict{},
		positive: in.Pass.Controls.Positive,
		benign:   in.Pass.Controls.Negative,
	}
	for _, t := range ix.positive {
		ix.anyRateLimited = ix.anyRateLimited || t.Signal == contracts.SignalRateLimited
		if t.Valid && t.Signal == contracts.SignalBlock {
			ix.positiveRefused = true
		}
	}
	for _, t := range ix.benign {
		ix.anyRateLimited = ix.anyRateLimited || t.Signal == contracts.SignalRateLimited
	}
	for _, v := range in.Pass.Verdicts {
		ix.verdicts[v.Cell.CellKey] = v
		for _, tr := range v.Cell.Trials {
			ix.anyRateLimited = ix.anyRateLimited || tr.Signal == contracts.SignalRateLimited
			if tr.Valid && tr.Signal == contracts.SignalBlock {
				ix.anyRefused = true
			}
			item, err := ix.expectationOf(tr)
			if err != nil {
				return nil, err
			}
			r := reading{Trial: tr, Item: item, Key: v.Cell.CellKey, Verdict: v}
			ix.readings = append(ix.readings, r)
			ix.byCell[v.Cell.CellKey] = append(ix.byCell[v.Cell.CellKey], r)
			ix.byGroup[item.GroupID] = append(ix.byGroup[item.GroupID], r)
		}
	}
	sort.Slice(ix.readings, func(i, k int) bool {
		if ix.readings[i].Key.String() != ix.readings[k].Key.String() {
			return ix.readings[i].Key.String() < ix.readings[k].Key.String()
		}
		return ix.readings[i].Trial.ObservationID < ix.readings[k].Trial.ObservationID
	})
	if len(ix.readings) == 0 {
		return nil, fmt.Errorf("discover: run %s round %s produced %d cell verdict(s) and no probe trial: "+
			"there is nothing to compare an expectation against, and a finding set built on an empty run "+
			"would be an assertion that the engine does nothing",
			in.RunID, in.RoundID, len(in.Pass.Verdicts))
	}
	return ix, nil
}

// expectationOf resolves a trial's corpus item. A trial whose reference cannot be
// resolved is refused: the alternative is a finding whose expectation is guessed.
func (ix *index) expectationOf(t inference.Trial) (contracts.CorpusItem, error) {
	if strings.TrimSpace(t.CorpusRef) == "" {
		return contracts.CorpusItem{}, fmt.Errorf(
			"discover: run %s: observation %s (probe %s) carries no corpus reference: nothing states what "+
				"this exchange was supposed to demonstrate, so it cannot enter a measurement",
			ix.in.RunID, t.ObservationID, t.ProbeRef)
	}
	items, err := ix.in.Corpus.Find(t.CorpusRef)
	if err != nil {
		return contracts.CorpusItem{}, fmt.Errorf(
			"discover: run %s: observation %s cites corpus ref %q, which is not in %s: %w. A run that sent "+
				"traffic the shipped corpus does not contain cannot be reported against that corpus",
			ix.in.RunID, t.ObservationID, t.CorpusRef, ix.in.Corpus.Root, err)
	}
	if len(items) > 1 {
		var where []string
		for _, i := range items {
			where = append(where, string(i.Partition))
		}
		return contracts.CorpusItem{}, fmt.Errorf(
			"discover: corpus ref %q resolves in %d partitions (%s): the expectation is ambiguous, "+
				"so no reading of this exchange is", t.CorpusRef, len(items), strings.Join(where, ", "))
	}
	return items[0], nil
}

func (r reading) valid() bool { return r.Trial.Valid }

func (r reading) refused() bool { return r.Trial.Signal == contracts.SignalBlock }

func (r reading) passed() bool { return r.Trial.Signal == contracts.SignalPass }

func (ix *index) baseline() Baseline {
	b := Baseline{PositiveControls: len(ix.positive), CalibrationTrials: len(ix.benign)}
	count := func(trials []inference.Trial, refused *int) {
		for _, tr := range trials {
			if !tr.Valid {
				if tr.Signal == contracts.SignalIndeterminate {
					b.ExcludedInconclusive++
				} else {
					b.ExcludedInvalid++
				}
				continue
			}
			if tr.Signal == contracts.SignalBlock {
				*refused++
			}
		}
	}
	count(ix.positive, &b.PositiveRefused)
	count(ix.benign, &b.CalibrationRefused)
	return b
}

func priorityRank(p contracts.Priority) int {
	switch p {
	case contracts.PriorityHigh:
		return 0
	case contracts.PriorityMedium:
		return 1
	default:
		return 2
	}
}
