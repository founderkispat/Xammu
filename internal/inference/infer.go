package inference

import (
	"errors"
	"fmt"
	"sort"
	"time"

	"xammu/internal/attributor"
	"xammu/internal/classifier"
	"xammu/internal/contracts"
	"xammu/internal/hypothesis"
	"xammu/internal/integrity"
)

// Sink is where a derived record goes. A live run journals it into the evidence
// trail; a re-read of a sealed bundle passes nil and reads the comparison instead,
// because evidence that is already closed is not rewritten by whoever came to check
// it.
type Sink interface {
	Journal(stream integrity.Stream, payload any) error
}

// Options configures one batch pass.
type Options struct {
	Sink Sink

	// Corroboration supplies, per subject ref, a source outside the HTTP response: a
	// filter log entry or a configuration export handed over by an operator who can
	// read it. Nothing here fetches one. Without corroboration an attribution simply
	// cannot rise above the HTTP ceiling.
	Corroboration map[string]*attributor.Corroboration

	// At pins the timestamps of derived records. A re-read of a bundle leaves it
	// zero, which means "use the analysis time already in the journal", so a
	// re-derived record is identical rather than merely equivalent.
	At time.Time

	// CommandFlags carries the operator's placement choices (`--path`, `--corpus` and
	// the rest) so a reproduction command a report prints can be pasted and work. A
	// command that re-runs the measurement is only reproducible if it names where the
	// probes were placed; without this the pipeline can only cite the cell, and the
	// reader has to guess the flags that produced it.
	CommandFlags string
}

// Divergence is one place where this pass and the journal disagree.
type Divergence struct {
	ProbeRef      string `json:"probe_ref"`
	ObservationID string `json:"observation_id"`
	Field         string `json:"field"`
	Journaled     string `json:"journaled"`
	Derived       string `json:"derived"`
}

func (d Divergence) String() string {
	return fmt.Sprintf("%s (%s): %s is %q in the journal, %q as re-derived",
		d.ProbeRef, d.ObservationID, d.Field, d.Journaled, d.Derived)
}

// Verdict is everything the batch pass concluded about one probe cell.
type Verdict struct {
	Cell        Cell                               `json:"cell"`
	Profile     contracts.EvidenceProfile          `json:"profile"`
	Attribution *contracts.Attribution             `json:"attribution,omitempty"`
	Status      *contracts.AttributionStatusRecord `json:"attribution_status,omitempty"`
	Hypothesis  *contracts.Hypothesis              `json:"hypothesis,omitempty"`
	Obstacles   []hypothesis.Obstacle              `json:"obstacles,omitempty"`

	// Skip states in one sentence why there is no hypothesis. A cell with no valid
	// trial is one of the report's undetermined areas; it is not silently absent.
	Skip string `json:"skip_reason,omitempty"`
}

// Result is one batch pass over one run's journal. It is the material the discovery
// layer works from: cells, controls, and the health of the trail itself.
type Result struct {
	RunID    string
	RoundID  string
	Verdicts []Verdict
	Controls Controls

	// Divergences and Missing come first when a report is written, because a run
	// that classified 40 of 44 exchanges is not a run with 40 exchanges.
	Divergences []Divergence `json:"divergences,omitempty"`
	Missing     []string     `json:"missing_evidence,omitempty"`

	// ReferenceCount is the size of the cluster every "ordinary handling" reading
	// was contrasted against. Zero means no pass reading was available anywhere.
	ReferenceCount int `json:"reference_count"`
}

// Summary renders the pass as a block of counts for a note or a log line. It states
// no conclusion, because the conclusions are in the records.
func (r *Result) Summary() string {
	var profiles, attributions, hypotheses, skips int
	outcomes := map[contracts.HypothesisOutcome]int{}
	for _, v := range r.Verdicts {
		if v.Profile.ProfileID != "" {
			profiles++
		}
		if v.Attribution != nil {
			attributions++
		}
		if v.Hypothesis != nil {
			hypotheses++
			outcomes[v.Hypothesis.Outcome]++
		}
		if v.Skip != "" {
			skips++
		}
	}
	return fmt.Sprintf(
		"run %s round %s: %d cell(s), %d evidence profile(s), %d attribution(s), "+
			"%d hypothesis(s) (supported %d, refuted %d, inconclusive %d), %d undetermined, "+
			"%d divergence(s), %d journal gap(s), %d reference exchange(s)",
		r.RunID, r.RoundID, len(r.Verdicts), profiles, attributions, hypotheses,
		outcomes[contracts.HypothesisSupported], outcomes[contracts.HypothesisRefuted],
		outcomes[contracts.HypothesisInconclusive], skips, len(r.Divergences),
		len(r.Missing), r.ReferenceCount)
}

// Infer reads a run's journal and produces what the downstream stages need: a C-04
// for every exchange, then per cell an attribution (C-05, C-06), an evidence profile
// (C-08) and a hypothesis (C-07).
//
// Every record is re-derivable: the classification comes from the journaled C-03
// over the journaled C-01, so a reviewer holding the bundle can check the
// conclusions instead of trusting the process that wrote them.
func (p *Pipeline) Infer(j *Journal, opts Options) (*Result, error) {
	if j == nil {
		return nil, errors.New("inference: no journal supplied")
	}
	if len(j.Observations) == 0 {
		return nil, fmt.Errorf(
			"inference: run %s has no observations: nothing was exchanged, so there is nothing to "+
				"infer and a report written here would be an opinion", j.RunID)
	}
	if want := p.Set.Hash(); j.SetHash != "" && j.SetHash != want {
		return nil, fmt.Errorf(
			"inference: this journal's analyses were produced by detector set %s but the pipeline holds %s: "+
				"classifying would stamp records with a set that did not make them", j.SetHash, want)
	}

	res := &Result{RunID: j.RunID, RoundID: j.RoundID}
	res.ReferenceCount = len(j.referenceShapes(""))

	if err := p.ensureClassified(j, opts, res); err != nil {
		return nil, err
	}
	// After the classifications, not before: on a live pass the journal has no C-04
	// records yet when the pass starts, and reporting every exchange as a gap would
	// tell the engineer the run is missing evidence it produced two lines earlier.
	// What survives this point is a hole the pipeline could not fill.
	res.Missing = j.Missing()

	controls := j.CollectControls(j.RoundID)
	res.Controls = controls
	adapted := controls.ForAttributor()
	posValid := adapted.PositiveValid()
	negValid := adapted.NegativeValid()

	for _, cell := range j.CellsBy(j.RoundID) {
		if err := p.verdict(j, res, cell, controls, adapted, posValid, negValid, opts); err != nil {
			return nil, err
		}
	}
	sort.Slice(res.Divergences, func(i, k int) bool { return res.Divergences[i].String() < res.Divergences[k].String() })
	return res, nil
}

// ensureClassified gives every exchange a C-04. One that already has a journaled
// classification is re-derived and compared, never overwritten: the journal is the
// evidence, and a disagreement between the two is itself a finding.
func (p *Pipeline) ensureClassified(j *Journal, opts Options, res *Result) error {
	for _, o := range j.Observations {
		analysis, ok := j.Analyses[o.ObservationID]
		if !ok {
			continue
		}
		at := opts.At
		if at.IsZero() {
			at = analysis.AnalyzedAt
		}
		derived, err := p.classifier.Classify(classifier.Input{
			Observation: o,
			Analysis:    analysis,
			References:  j.referenceShapes(o.ObservationID),
			Now:         at,
		})
		if err != nil {
			return fmt.Errorf("inference: cannot classify %s: %w", o.Sent.ProbeRef, err)
		}
		stored, had := j.Classified[o.ObservationID]
		if !had {
			j.Classified[o.ObservationID] = derived
			if opts.Sink != nil {
				if err := opts.Sink.Journal(integrity.StreamClassifications, derived); err != nil {
					return fmt.Errorf("inference: cannot journal the classification for %s: %w",
						o.Sent.ProbeRef, err)
				}
			}
			continue
		}
		res.Divergences = append(res.Divergences, compareClassification(o, stored, derived)...)
	}
	return nil
}

// compareClassification reports the fields of C-04 a reader relies on. Identifiers
// and timestamps are ignored: those are the writing, not the reading, and a
// re-derived record legitimately carries new ones.
func compareClassification(o contracts.RawObservation, stored, derived contracts.BehavioralClassification) []Divergence {
	var out []Divergence
	add := func(field, a, b string) {
		if a != b {
			out = append(out, Divergence{o.Sent.ProbeRef, o.ObservationID, field, a, b})
		}
	}
	add("signal", string(stored.Signal), string(derived.Signal))
	add("status_code", fmt.Sprint(stored.StatusCode), fmt.Sprint(derived.StatusCode))
	add("detector_agreement", stored.DetectorAgreement, derived.DetectorAgreement)
	add("status_category", stored.StatusCategory, derived.StatusCategory)
	add("matched_pattern_ids", joinSorted(stored.MatchedPatterns), joinSorted(derived.MatchedPatterns))
	add("non_fired_detector_refs", joinSorted(stored.NonFiredDetectors), joinSorted(derived.NonFiredDetectors))
	add("detector_set_hash", stored.DetectorSetHash, derived.DetectorSetHash)
	return out
}

func joinSorted(in []string) string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	joined := ""
	for i, s := range out {
		if i > 0 {
			joined += ","
		}
		joined += s
	}
	return joined
}

// verdict derives, and journals when a sink is present, the records for one cell.
//
// Two orders are load-bearing. The attribution is derived before anything else
// because the control-validity flags the profile carries are the attributor's own
// derivation, not a restatement of this package's counts. And the profile is
// journalled before the hypothesis, because C-07 cites C-08 and a citation to a
// record that was never written is a dangling reference in the evidence trail.
func (p *Pipeline) verdict(j *Journal, res *Result, cell Cell, controls Controls,
	adapted attributor.Controls, posValid, negValid bool, opts Options) error {
	at := opts.At
	if at.IsZero() {
		at = cellTime(cell)
	}
	v := Verdict{Cell: cell}

	profile, err := p.profileFor(j, res, cell, controls, posValid, negValid, opts, at)
	if err != nil {
		return err
	}
	v.Profile = profile

	if stored, ok := j.Attributions[cell.Ref()]; ok {
		rec := j.Statuses[stored.AttributionID]
		v.Attribution, v.Status = &stored, &rec
	} else {
		rep, err := attributor.Attribute(attributor.Subject{
			RunID: j.RunID, Ref: cell.Ref(),
			AttackClass: cell.AttackClass, Vector: cell.Vector, Encoding: cell.Encoding,
			TargetOrigin: cell.Origin, Path: cell.Path,
			Evidence:      datums(cell),
			Controls:      adapted,
			Corroboration: opts.Corroboration[cell.Ref()],
			Now:           at,
		})
		if err != nil {
			return fmt.Errorf("inference: %w", err)
		}
		v.Attribution, v.Status = &rep.Attribution, &rep.Status
		if opts.Sink != nil {
			if err := opts.Sink.Journal(integrity.StreamAttributions, rep.Attribution); err != nil {
				return fmt.Errorf("inference: cannot journal the attribution for %s: %w", cell.Ref(), err)
			}
			if err := opts.Sink.Journal(integrity.StreamStatuses, rep.Status); err != nil {
				return fmt.Errorf("inference: cannot journal the attribution status for %s: %w", cell.Ref(), err)
			}
		}
	}

	if profile.Level == contracts.EvidenceNone {
		v.Obstacles = []hypothesis.Obstacle{{
			Reason: cellBlocker(cell),
			Detail: fmt.Sprintf("%d of %d trial(s) in this cell produced no valid reading: %s",
				cell.Invalid+cell.Inconclusive, len(cell.Trials), obstacleDetail(cell)),
		}}
		v.Skip = fmt.Sprintf(
			"no valid trial in this cell, so no hypothesis can be formed over it. The zone is "+
				"undetermined for the typed reason in the obstacle (%s), which makes it a C-16 "+
				"finding and not a claim", v.Obstacles[0].Reason)
		res.Verdicts = append(res.Verdicts, v)
		return nil
	}

	claim, obstacles, skip := claimFor(j, cell, controls, negValid, profile, opts.CommandFlags)
	if skip != "" {
		v.Skip = skip
		res.Verdicts = append(res.Verdicts, v)
		return nil
	}
	v.Obstacles = obstacles
	// The obstacles travel with the claim, not only with the verdict: an inconclusive
	// outcome has to name its typed reason inside C-07, and C-07 refuses to exist
	// without one. Dropping them here is what turns "we could not test this" into a
	// silent failure the run cannot explain afterwards.
	claim.Obstacles = obstacles
	h, err := hypothesis.Derive(claim)
	if err != nil {
		return fmt.Errorf("inference: %w", err)
	}
	v.Hypothesis = &h
	stored, had := j.HypothesesByRef[claim.Ref]
	if had {
		// Only a disagreement is a divergence: a re-read that agrees with the journal
		// is the proof the reviewer came for, and reporting it as a difference would
		// make every honest bundle look damaged.
		add := func(field, a, b string) {
			if a != b {
				res.Divergences = append(res.Divergences,
					Divergence{claim.Ref, profile.ProfileID, field, a, b})
			}
		}
		add("hypothesis_outcome", string(stored.Outcome), string(h.Outcome))
		add("claim_type", string(stored.ClaimType), string(h.ClaimType))
		v.Hypothesis = &stored
	}
	// A cell that already contributed a hypothesis keeps the one the run wrote: the
	// journal is the evidence, and a resume that appended a second record for the
	// same subject would leave a reviewer choosing between two of them.
	if opts.Sink != nil && !had {
		if err := opts.Sink.Journal(integrity.StreamHypotheses, h); err != nil {
			return fmt.Errorf("inference: cannot journal the hypothesis for %s: %w", cell.Ref(), err)
		}
	}
	res.Verdicts = append(res.Verdicts, v)
	return nil
}

// profileFor returns the C-08 record for a cell, reusing the journaled one when the
// cell already has it. A re-read of a bundle therefore grades the evidence the run
// actually graded, and any difference in it is reported as a divergence rather than
// quietly rewriting history.
func (p *Pipeline) profileFor(j *Journal, res *Result, cell Cell, controls Controls,
	posValid, negValid bool, opts Options, at time.Time) (contracts.EvidenceProfile, error) {
	derived, err := buildProfile(j, cell, controls, posValid, negValid, opts, at)
	if err != nil {
		return contracts.EvidenceProfile{}, err
	}
	stored, had := j.ProfilesBySubject[cell.Ref()]
	if !had {
		if opts.Sink != nil {
			if err := opts.Sink.Journal(integrity.StreamEvidence, derived); err != nil {
				return contracts.EvidenceProfile{}, fmt.Errorf(
					"inference: cannot journal the evidence profile for %s: %w", cell.Ref(), err)
			}
		}
		j.ProfilesBySubject[cell.Ref()] = derived
		return derived, nil
	}
	add := func(field, a, b string) {
		if a != b {
			res.Divergences = append(res.Divergences,
				Divergence{cell.Ref(), stored.ProfileID, field, a, b})
		}
	}
	add("evidence_level", string(stored.Level), string(derived.Level))
	add("claim_ceiling", string(stored.ClaimCeiling), string(derived.ClaimCeiling))
	add("valid_trials", fmt.Sprint(stored.ValidTrials), fmt.Sprint(derived.ValidTrials))
	add("measured_rate", fmt.Sprintf("%d/%d", stored.Measured.Numerator, stored.Measured.Denominator),
		fmt.Sprintf("%d/%d", derived.Measured.Numerator, derived.Measured.Denominator))
	return stored, nil
}
