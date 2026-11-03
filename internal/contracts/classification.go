package contracts

import (
	"time"
)

// Signal is the behavioural reading of a response. It describes what the
// detector ensemble saw, never what caused it.
type Signal string

const (
	// SignalBlock: the response carries interstitial features the detector set
	// associates with rejection.
	SignalBlock Signal = "signal_block"
	// SignalPass: the response is consistent with ordinary handling.
	SignalPass Signal = "signal_pass"
	// SignalIndeterminate: detectors disagree, or the response shape is not in
	// the detector set. Reported, never forced into block or pass.
	SignalIndeterminate Signal = "signal_indeterminate"
	// SignalRateLimited is emitted for 429. It is not a block signal: a limit
	// says the operator is being paced, not that a payload was rejected.
	SignalRateLimited Signal = "signal_rate_limited"
	// SignalTransportError is emitted when no response was received.
	SignalTransportError Signal = "signal_transport_error"
	// SignalRedirect is emitted when the exchange ended in a redirect chain
	// rather than a terminal response.
	SignalRedirect Signal = "signal_redirect"
)

func AllSignals() []Signal {
	return []Signal{
		SignalBlock, SignalPass, SignalIndeterminate,
		SignalRateLimited, SignalTransportError, SignalRedirect,
	}
}

// causeKeys may not appear on C-04. The classifier correlates detector hits;
// the moment it can say "because", it has taken over the attributor's job and
// the audit trail from evidence to conclusion is gone.
var causeKeys = map[string]bool{
	"cause": true, "caused_by": true, "because": true, "because_of": true,
	"root_cause": true, "attributed_to": true, "blocked_because": true,
	"intent": true, "attacker": true, "meaning": true, "explanation": true,
	"waf_blocked": true, "malicious": true, "score": true, "confidence": true,
}

// BehavioralClassification is C-04. Every classification must name the
// detectors that produced it, so a reviewer can re-run them, and must not name
// a cause.
type BehavioralClassification struct {
	ClassificationID  string    `json:"classification_id"`
	ObservationID     string    `json:"observation_id"`
	AnalysisID        string    `json:"analysis_id"`
	RunID             string    `json:"run_id"`
	ClassifiedAt      time.Time `json:"classified_at"`
	Signal            Signal    `json:"signal"`
	StatusCode        int       `json:"status_code"`
	DetectorRefs      []string  `json:"detector_refs"`
	MatchedPatterns   []string  `json:"matched_pattern_ids"`
	NonFiredDetectors []string  `json:"non_fired_detector_refs"`
	DetectorAgreement string    `json:"detector_agreement"`
	StatusCategory    string    `json:"status_category"`
	ControlRole       string    `json:"control_role"`
	ProbeRef          string    `json:"probe_ref"`
	DetectorSetHash   string    `json:"detector_set_hash"`
	ClassifierVer     string    `json:"classifier_version"`
}

func (BehavioralClassification) Contract() ID { return IDBehavioralClassification }

// ValidTrial reports whether one exchange is countable as a trial in a
// denominator. An indeterminate reading, a transport failure, or a classification
// that does not cite the observation it reads is excluded, so failed and
// undecided work cannot widen a rate (criteria 22 and 23).
//
// This is the single definition. The run's counters and every measured rate in
// the report call it, because two denominators that disagree is the failure mode
// the criterion names.
func ValidTrial(obs RawObservation, cls BehavioralClassification) bool {
	if cls.ObservationID != obs.ObservationID || cls.RunID != obs.RunID {
		return false
	}
	if obs.Transport.ErrorClass != "" {
		return false
	}
	return cls.Signal != SignalIndeterminate && cls.Signal != SignalTransportError
}

func registerClassificationContract() {
	register(IDBehavioralClassification, func(payload any) error {
		b, err := cast[BehavioralClassification](IDBehavioralClassification, payload)
		if err != nil {
			return err
		}
		c := newViolations(IDBehavioralClassification)
		uuidField(c, "classification_id", b.ClassificationID)
		uuidField(c, "observation_id", b.ObservationID)
		uuidField(c, "analysis_id", b.AnalysisID)
		c.required("run_id", b.RunID)
		oneofT(c, "signal", b.Signal, AllSignals()...)
		c.oneof("detector_agreement", b.DetectorAgreement,
			"all_agree", "majority", "split", "no_firing", "conflict")
		c.nonEmpty("detector_refs", len(b.DetectorRefs))
		if b.ClassifiedAt.IsZero() {
			c.add("classified_at", "required")
		}
		c.required("classifier_version", b.ClassifierVer)
		c.required("detector_set_hash", b.DetectorSetHash)
		c.required("probe_ref", b.ProbeRef)
		c.oneof("control_role", b.ControlRole, stringsOf(AllControlRoles())...)

		// Criterion 24: a 429 is never readable as a block, whatever the
		// detectors matched. The limit says the operator is being paced.
		if b.StatusCode == 0 && b.Signal != SignalTransportError {
			c.add("status_code", "required unless the exchange produced no response")
		}
		if b.StatusCode == 429 && b.Signal == SignalBlock {
			c.add("signal",
				"a 429 must classify as signal_rate_limited, never signal_block (criterion 24)")
		}
		if b.StatusCode == 429 && len(b.MatchedPatterns) > 0 {
			c.add("matched_pattern_ids",
				"a rate-limited exchange is not scored by the interstitial detectors")
		}
		if b.Signal == SignalRateLimited && b.StatusCode != 429 {
			c.add("signal", "signal_rate_limited is reserved for a 429")
		}
		// Detector provenance: a classification claiming matches must name the
		// detectors that produced them.
		if len(b.MatchedPatterns) > len(b.DetectorRefs) && len(b.DetectorRefs) == 0 {
			c.add("detector_refs", "matched patterns without detector provenance")
		}
		for _, key := range keysMatching(b, func(k string) bool { return causeKeys[k] }) {
			c.add(key, "behavioral_classification names signals, not causes")
		}
		return c.err()
	})
}

func init() { registerClassificationContract() }
