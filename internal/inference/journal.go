// Package inference is the reading half of the pipeline: it turns the journals a
// run wrote into the records an engineer can act on.
//
// It has two entry points and they share every rule. The live path (Step) runs
// while a response body is still in this process's memory, because retention
// policy limits what XAMMU keeps, not what a detector may look at once the bytes
// were legitimately received. The batch path (Infer) reads the journals afterwards
// and produces the classification, attribution, evidence profile and hypothesis
// records for the whole run at once, which is where the reference cluster and the
// controls become visible - a single exchange cannot tell whether the thing that
// answered it also answers benign requests.
//
// Both paths can run against a sealed bundle. Infer then compares what it
// re-derives against what was journaled and reports the divergences instead of
// rewriting evidence that is already closed. A reviewer holding a bundle can
// therefore check the conclusions rather than trust the process that wrote them.
package inference

import (
	"encoding/json"
	"fmt"
	"sort"

	"xammu/internal/contracts"
	"xammu/internal/integrity"
	"xammu/internal/observer"
)

// Journal is one run's evidence trail, decoded and keyed for lookup.
//
// The maps are keyed by the identifier a later record cites, so a missing link is
// an explicit absence in this structure rather than a zero value somewhere
// downstream. That distinction is the difference between "this exchange was never
// classified" and "this classification is blank".
type Journal struct {
	RunID        string
	RoundID      string
	TargetOrigin string

	Observations  []contracts.RawObservation
	ByObservation map[string]contracts.RawObservation

	// Captures and Analyses are keyed by observation id: they describe the same
	// exchange, and a capture whose observation is missing is an orphan.
	Captures map[string]contracts.TransientCapture
	Analyses map[string]contracts.SignatureAnalysis

	// Classified is keyed by observation id, the citation C-04 is built on.
	Classified map[string]contracts.BehavioralClassification

	// Attribution and Status are keyed by subject ref, so a cell can find its
	// attribution without rescanning the stream. Profiles and hypotheses are keyed
	// both by id and by subject, because a re-read has to find what the run already
	// graded before it can say whether it agrees.
	Attributions      map[string]contracts.Attribution
	Statuses          map[string]contracts.AttributionStatusRecord
	Profiles          map[string]contracts.EvidenceProfile
	ProfilesBySubject map[string]contracts.EvidenceProfile
	HypothesesByRef   map[string]contracts.Hypothesis
	Hypotheses        []contracts.Hypothesis

	// SetHash records which detector ensemble produced the analyses, so the batch
	// pass can refuse to classify over a journal it was not built for.
	SetHash string
}

// Read decodes the journals of one run. It refuses a broken hash chain: deriving
// conclusions from a trail that no longer commits to itself would launder damage
// into a report, and the chain exists precisely so that this is decidable.
func Read(store *integrity.Store) (*Journal, error) {
	if store == nil {
		return nil, fmt.Errorf("inference: no store to read")
	}
	if breaks := store.Verify(); len(breaks) > 0 {
		return nil, fmt.Errorf("inference: refusing to read a journal whose chain is broken (%d break(s)): %s",
			len(breaks), breaks[0])
	}
	obs, err := stream[contracts.RawObservation](store, integrity.StreamObservations)
	if err != nil {
		return nil, err
	}
	caps, err := stream[contracts.TransientCapture](store, integrity.StreamCaptures)
	if err != nil {
		return nil, err
	}
	ana, err := stream[contracts.SignatureAnalysis](store, integrity.StreamAnalyses)
	if err != nil {
		return nil, err
	}
	cls, err := stream[contracts.BehavioralClassification](store, integrity.StreamClassifications)
	if err != nil {
		return nil, err
	}
	att, err := stream[contracts.Attribution](store, integrity.StreamAttributions)
	if err != nil {
		return nil, err
	}
	st, err := stream[contracts.AttributionStatusRecord](store, integrity.StreamStatuses)
	if err != nil {
		return nil, err
	}
	pro, err := stream[contracts.EvidenceProfile](store, integrity.StreamEvidence)
	if err != nil {
		return nil, err
	}
	hyp, err := stream[contracts.Hypothesis](store, integrity.StreamHypotheses)
	if err != nil {
		return nil, err
	}

	j := &Journal{
		Observations:      obs,
		ByObservation:     make(map[string]contracts.RawObservation, len(obs)),
		Captures:          index(caps, func(c contracts.TransientCapture) string { return c.ObservationID }),
		Analyses:          index(ana, func(a contracts.SignatureAnalysis) string { return a.ObservationID }),
		Classified:        index(cls, func(b contracts.BehavioralClassification) string { return b.ObservationID }),
		Attributions:      index(att, func(a contracts.Attribution) string { return a.SubjectID }),
		Statuses:          index(st, func(s contracts.AttributionStatusRecord) string { return s.AttributionID }),
		Profiles:          index(pro, func(p contracts.EvidenceProfile) string { return p.ProfileID }),
		ProfilesBySubject: index(pro, func(p contracts.EvidenceProfile) string { return p.SubjectRef }),
		HypothesesByRef:   index(hyp, func(h contracts.Hypothesis) string { return h.Ref }),
		Hypotheses:        hyp,
	}
	for _, o := range obs {
		if o.RunID == "" {
			return nil, fmt.Errorf("inference: observation %s names no run", o.ObservationID)
		}
		if j.RunID == "" {
			j.RunID = o.RunID
		} else if o.RunID != j.RunID {
			return nil, fmt.Errorf(
				"inference: observation %s belongs to run %s but this journal is run %s: "+
					"two runs in one bundle cannot be inferred together",
				o.ObservationID, o.RunID, j.RunID)
		}
		j.ByObservation[o.ObservationID] = o
	}
	if len(obs) > 0 {
		j.TargetOrigin = originOf(obs[0])
	}
	if len(ana) > 0 {
		j.SetHash = ana[0].DetectorSetHash
	}
	// The round id and the profile's identity live in the run profile stream, which
	// checkpoints rewrite; the last record is the current one.
	profiles, err := stream[contracts.RunProfile](store, integrity.StreamProfiles)
	if err != nil {
		return nil, err
	}
	if len(profiles) > 0 {
		j.RoundID = profiles[len(profiles)-1].RoundID
		if j.RunID == "" {
			j.RunID = profiles[len(profiles)-1].RunID
		}
	}
	return j, nil
}

// stream decodes one journal. A payload that will not parse is an error rather than
// a skipped record: silently dropping evidence is how a count stops matching the
// trail it came from.
func stream[T any](store *integrity.Store, st integrity.Stream) ([]T, error) {
	recs, err := store.Records(st)
	if err != nil {
		return nil, err
	}
	out := make([]T, 0, len(recs))
	for _, rec := range recs {
		var v T
		if err := json.Unmarshal(rec.Payload, &v); err != nil {
			return nil, fmt.Errorf("inference: %s record %d is unreadable: %w", st, rec.Seq, err)
		}
		out = append(out, v)
	}
	return out, nil
}

func index[T any](in []T, key func(T) string) map[string]T {
	out := make(map[string]T, len(in))
	for _, v := range in {
		k := key(v)
		if k == "" {
			continue
		}
		out[k] = v
	}
	return out
}

// originOf renders the destination of an observation as an origin string, for the
// scope field of the records this package builds.
func originOf(o contracts.RawObservation) string {
	port := o.Target.Port
	if port == 0 {
		if o.Target.Scheme == "https" {
			port = 443
		} else {
			port = 80
		}
	}
	return fmt.Sprintf("%s://%s:%d", o.Target.Scheme, o.Target.Host, port)
}

// Missing reports exchanges that never reached a given stage, sorted and typed.
// Coverage gaps are evidence about the run, and a report that only lists what
// succeeded hides the part the engineer most needs to see.
func (j *Journal) Missing() []string {
	var out []string
	for _, o := range j.Observations {
		ref := o.Sent.ProbeRef
		if _, ok := j.Captures[o.ObservationID]; !ok {
			out = append(out, fmt.Sprintf("%s (%s): no C-02 capture", ref, o.ObservationID))
			continue
		}
		if _, ok := j.Analyses[o.ObservationID]; !ok {
			out = append(out, fmt.Sprintf("%s (%s): no C-03 signature analysis", ref, o.ObservationID))
			continue
		}
		if _, ok := j.Classified[o.ObservationID]; !ok {
			out = append(out, fmt.Sprintf("%s (%s): no C-04 classification", ref, o.ObservationID))
		}
	}
	sort.Strings(out)
	return out
}

// Shapes returns the coarse shapes of every exchange in the journal, keyed by
// observation id. Reconstructed from C-01 fields only, so a sealed bundle needs no
// retained body to re-derive a contrast: the cluster is made of status bands and
// size buckets, both journaled.
func (j *Journal) Shapes() map[string]observer.Shape {
	out := make(map[string]observer.Shape, len(j.Observations))
	for _, o := range j.Observations {
		out[o.ObservationID] = observer.ShapeFromJournal(o)
	}
	return out
}
