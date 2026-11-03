// Package classifier turns one exchange's factual records into C-04: the
// behavioural signal. It reads a C-01 observation, the C-03 analysis made of it
// while its body was still in memory, and the run's reference cluster.
//
// Three rules are structural here rather than stylistic.
//
// A 429 is never readable as a block, whatever the detectors matched (criterion
// 24). The response says the operator is being paced; a tool that reads pacing as
// protection tells the engineer their rules held when only the rate limiter did.
// The patterns are dropped rather than kept-and-ignored, so no later stage can
// re-read them as block evidence.
//
// A 5xx no detector reads as a rejection is never readable as ordinary handling
// either. The destination failed; what the front end would have done with the
// payload was never measured, so the trial is indeterminate rather than a pass.
//
// And a signal is only ever a reading of shape. This package declares no cause,
// because the moment a classification can say "because", it has taken the
// attributor's job and the audit trail from evidence to conclusion is gone.
package classifier

import (
	"fmt"
	"time"

	"xammu/internal/contracts"
	"xammu/internal/observer"
)

// Version is stamped into every classification, so a signal can be re-derived by
// re-running the classifier build that produced it.
const Version = "xammu-classifier/1.0.0"

// redirectCodes are the statuses that mean the exchange ended in a chain rather
// than in a response. A 304 is not one of them: it is a terminal answer about
// freshness, and reading it as a redirect would hide the body it deliberately
// carries.
var redirectCodes = map[int]bool{301: true, 302: true, 303: true, 307: true, 308: true}

// Classifier aggregates the ensemble's readings.
type Classifier struct {
	set *observer.DetectorSet
}

// New builds a classifier over an ensemble. A nil ensemble is refused rather than
// defaulted: a silent default is how a run comes back classified by a set nobody
// approved.
func New(set *observer.DetectorSet) (*Classifier, error) {
	if set == nil {
		return nil, fmt.Errorf("classifier: no detector set supplied")
	}
	return &Classifier{set: set}, nil
}

// Set exposes the ensemble for reporting and for provenance.
func (c *Classifier) Set() *observer.DetectorSet { return c.set }

// Input is one exchange, the analysis made of it, and the reference cluster it may
// be contrasted against.
type Input struct {
	Observation contracts.RawObservation
	Analysis    contracts.SignatureAnalysis
	// References holds the shapes of this run's benign references and negative
	// controls, excluding the probe being classified. A probe that calibrates
	// against itself reports whatever it did as ordinary handling.
	References []observer.Shape
	Now        time.Time
}

// Classify produces the C-04 record for one exchange.
func (c *Classifier) Classify(in Input) (contracts.BehavioralClassification, error) {
	obs := in.Observation
	if in.Now.IsZero() {
		return contracts.BehavioralClassification{}, fmt.Errorf(
			"classifier: no timestamp for the classification of %s", obs.Sent.ProbeRef)
	}
	if obs.ObservationID == "" {
		return contracts.BehavioralClassification{}, fmt.Errorf(
			"classifier: the observation carries no id, so nothing downstream can cite it")
	}
	if err := c.agrees(obs, in.Analysis); err != nil {
		return contracts.BehavioralClassification{}, err
	}

	signal, agreement, matched, nonFired, err := c.derive(obs, in.Analysis, in.References)
	if err != nil {
		return contracts.BehavioralClassification{}, err
	}
	b := contracts.BehavioralClassification{
		ClassificationID:  contracts.NewUUID(),
		ObservationID:     obs.ObservationID,
		AnalysisID:        in.Analysis.AnalysisID,
		RunID:             obs.RunID,
		ClassifiedAt:      in.Now,
		Signal:            signal,
		StatusCode:        obs.ResponseStatus,
		DetectorRefs:      c.set.IDs(),
		MatchedPatterns:   matched,
		NonFiredDetectors: nonFired,
		DetectorAgreement: agreement,
		StatusCategory:    contracts.StatusCategory(obs.ResponseStatus),
		ControlRole:       obs.Sent.ControlRole,
		ProbeRef:          obs.Sent.ProbeRef,
		DetectorSetHash:   c.set.Hash(),
		ClassifierVer:     Version,
	}
	if err := contracts.Validate(contracts.IDBehavioralClassification, &b); err != nil {
		return contracts.BehavioralClassification{}, fmt.Errorf(
			"classifier: classification for %s rejected by C-04: %w", obs.Sent.ProbeRef, err)
	}
	return b, nil
}

// agrees checks that the two records really describe one exchange. A C-03 joined
// to the wrong C-01 would otherwise let a block page found in one response be
// reported as the reading of another.
func (c *Classifier) agrees(obs contracts.RawObservation, an contracts.SignatureAnalysis) error {
	if an.ObservationID != obs.ObservationID {
		return fmt.Errorf("classifier: analysis %s belongs to observation %s, not %s",
			an.AnalysisID, an.ObservationID, obs.ObservationID)
	}
	if an.RunID != obs.RunID {
		return fmt.Errorf("classifier: analysis is from run %s, observation is from run %s",
			an.RunID, obs.RunID)
	}
	if an.StatusCode != obs.ResponseStatus {
		return fmt.Errorf("classifier: analysis reports status %d against an observation of %d for %s",
			an.StatusCode, obs.ResponseStatus, obs.Sent.ProbeRef)
	}
	if an.BodyDigest != obs.ResponseBodyDigest {
		return fmt.Errorf("classifier: analysis digested %s but the observation records %s for %s: "+
			"the body that was matched is not the body that arrived",
			an.BodyDigest, obs.ResponseBodyDigest, obs.Sent.ProbeRef)
	}
	if an.DetectorSetHash != c.set.Hash() {
		return fmt.Errorf("classifier: the analysis came from detector set %s, this classifier runs %s: "+
			"the signals would not be the same measurement", an.DetectorSetHash, c.set.Hash())
	}
	return nil
}

// derive is the whole reading of one exchange. The order matters: the three
// conditions that make a detector reading irrelevant are checked first, because a
// rate limit, a redirect chain and a socket failure each describe an exchange that
// never reached the question the detectors answer.
func (c *Classifier) derive(obs contracts.RawObservation, an contracts.SignatureAnalysis,
	refs []observer.Shape) (contracts.Signal, string, []string, []string, error) {
	consulted := c.set.IDs()

	if obs.Transport.ErrorClass != "" || obs.ResponseStatus == 0 {
		return contracts.SignalTransportError, "no_firing", nil, consulted, nil
	}
	if obs.ResponseStatus == 429 {
		return contracts.SignalRateLimited, "no_firing", nil, consulted, nil
	}
	if redirectCodes[obs.ResponseStatus] {
		return contracts.SignalRedirect, "no_firing", nil, consulted, nil
	}

	probe := observer.ShapeFromJournal(obs)
	readings := c.set.ReadingsFrom(an.Matches)
	// The cluster reading cannot be recovered from the journal, because it is a
	// statement about other exchanges. It is recomputed here over shapes taken from
	// their own C-01 records, so a run authorized for digest-only retention is
	// calibrated by exactly the same data as one that kept prefixes.
	if constraint, ok := c.set.ReferenceDetector(); ok {
		readings[constraint.ID] = constraint.Contrast(probe, refs)
	}

	blocks, passes := 0, 0
	var matched, nonFired []string
	for _, id := range consulted {
		r, known := readings[id]
		if !known {
			return "", "", nil, nil, fmt.Errorf(
				"classifier: detector %s is in the ensemble but produced no reading for %s",
				id, obs.Sent.ProbeRef)
		}
		switch r.Reading {
		case observer.ReadsBlock:
			blocks++
			matched = append(matched, patternIDs(r.Matches)...)
		case observer.ReadsPass:
			passes++
			matched = append(matched, patternIDs(r.Matches)...)
		case observer.ReadsNothing:
			nonFired = append(nonFired, id)
		default:
			return "", "", nil, nil, fmt.Errorf(
				"classifier: detector %s reported the unreadable reading %q", id, r.Reading)
		}
	}

	signal, agreement := combine(blocks, passes)
	// An origin-side failure is not the front end abstaining. A 5xx no detector
	// reads as a rejection ended at a broken destination, and calling that ordinary
	// handling is how an unmeasured zone becomes a clean coverage claim: the
	// exchange never reached the question the detectors answer, so the honest output
	// is no reading at all. A rejection reading still wins, because a WAF
	// interstitial served with a 503 is a decision and not a failure. The pass
	// patterns are dropped rather than carried, exactly as the 429 rule drops them,
	// so no later stage can re-read them as evidence of handling.
	if signal == contracts.SignalPass && obs.ResponseStatus >= 500 {
		return contracts.SignalIndeterminate, "no_firing", nil, consulted, nil
	}
	return signal, agreement, matched, nonFired, nil
}

// combine is the disagreement rule. A rejection reading and an ordinary-handling
// reading over the same exchange is not a tie for arithmetic to break: it is a
// response the ensemble has no name for, and the honest output is indeterminate.
// Awarding the majority would turn one ambiguous page into a claim about a filter.
func combine(blocks, passes int) (contracts.Signal, string) {
	switch {
	case blocks == 0 && passes == 0:
		return contracts.SignalIndeterminate, "no_firing"
	case passes == 0:
		return contracts.SignalBlock, "all_agree"
	case blocks == 0:
		return contracts.SignalPass, "all_agree"
	case blocks-passes >= 2 || passes-blocks >= 2:
		return contracts.SignalIndeterminate, "majority"
	default:
		return contracts.SignalIndeterminate, "split"
	}
}

func patternIDs(matches []contracts.MarkerMatch) []string {
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		out = append(out, m.PatternID)
	}
	return out
}
