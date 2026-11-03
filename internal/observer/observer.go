// Package observer produces the three factual records of one exchange: C-01 is
// built by the orchestrator, and this package adds C-02 (what was kept of the
// response body) and C-03 (what the detector set matched in it).
//
// The package runs while the body is still in memory. That is the whole design:
// retention policy limits what XAMMU *keeps*, not what it can *read* once it has
// been handed the bytes, so a run authorized for digest-only retention still gets a
// real signature analysis and still forgets the body immediately afterwards. A
// stage that later wanted to re-run the detectors over a different body would need
// the body, and the journal deliberately does not contain one.
package observer

import (
	"fmt"
	"time"

	"xammu/internal/contracts"
)

// Exchange is everything the observer needs at the moment the response arrived.
type Exchange struct {
	// Observation is the C-01 record of this exchange, already validated. The
	// observer reads it rather than rebuilding it, so the identifiers, the
	// destination and the planning metadata cannot drift apart from what the run
	// actually sent.
	Observation contracts.RawObservation
	// Body is the response body as the client read it. It is never journaled.
	Body []byte
	// BodyTruncated says the client stopped reading at its own size cap, so a
	// marker past that point was not in memory to be matched.
	BodyTruncated bool
	// ReasonPhrase is the textual status the client received or derived.
	ReasonPhrase string
	// ContentType and ServerHeader are recorded as facts for a reviewer. They are
	// not detector inputs: Shape carries no headers, so nothing in the detection
	// path can read them.
	ContentType  string
	ServerHeader string
	// RetryAfterSeconds is the Retry-After value the pipeline parsed, recorded for
	// the operator's pacing and not used to decide anything. Zero means absent.
	RetryAfterSeconds int
	Retention         contracts.RetentionPolicy
	// MaxRetainBytes further caps what may be held, from the authorization.
	MaxRetainBytes int
	Now            time.Time
}

// Records is the observer's output: the capture, the analysis and the per-
// detector readings the analysis was built from.
type Records struct {
	Capture  contracts.TransientCapture
	Analysis contracts.SignatureAnalysis
	Readings map[string]Result
	Set      *DetectorSet
}

// Analyse applies the retention policy to the body and runs the response
// detectors over it. The reference-cluster detector is not run here: a single
// exchange has no cluster to stand beside, and inventing one from one sample is
// how a flaky origin becomes a baseline.
func Analyse(ex Exchange, set *DetectorSet) (Records, error) {
	if set == nil {
		return Records{}, fmt.Errorf("observer: no detector set: an exchange cannot be analysed by an empty ensemble")
	}
	if ex.Now.IsZero() {
		return Records{}, fmt.Errorf("observer: exchange for %s has no timestamp: an undated record cannot be ordered",
			ex.Observation.Sent.ProbeRef)
	}
	if ex.Observation.ObservationID == "" {
		return Records{}, fmt.Errorf("observer: exchange carries no observation id")
	}
	capture, err := captureFor(ex)
	if err != nil {
		return Records{}, err
	}
	shape := Shape{
		Status:    ex.Observation.ResponseStatus,
		Body:      ex.Body,
		BodyBytes: ex.Observation.ResponseBodyBytes,
	}
	var matches []contracts.MarkerMatch
	readings := make(map[string]Result, len(set.detectors))
	for _, d := range set.ResponseDetectors() {
		if d.Evaluate == nil {
			return Records{}, fmt.Errorf("observer: detector %s declares no evaluation", d.ID)
		}
		res := d.Evaluate(shape)
		if res.Reading == ReadsNothing && len(res.Matches) > 0 {
			return Records{}, fmt.Errorf("observer: detector %s abstained but reported matches", d.ID)
		}
		readings[d.ID] = res
		matches = append(matches, res.Matches...)
	}
	analysis, err := buildAnalysis(ex, capture, set, matches)
	if err != nil {
		return Records{}, err
	}
	if err := contracts.Validate(contracts.IDSignatureAnalysis, &analysis); err != nil {
		return Records{}, fmt.Errorf("observer: signature analysis for %s rejected by C-03: %w",
			ex.Observation.Sent.ProbeRef, err)
	}
	if err := contracts.Validate(contracts.IDTransientCapture, &capture); err != nil {
		return Records{}, fmt.Errorf("observer: capture for %s rejected by C-02: %w",
			ex.Observation.Sent.ProbeRef, err)
	}
	return Records{Capture: capture, Analysis: analysis, Readings: readings, Set: set}, nil
}

// captureFor applies the retention policy and returns the C-02 record. The record
// is journaled even when it says nothing was kept, because "we dropped the body"
// is a claim worth having in the evidence trail: the validator refuses a capture
// that reports digest-only retention while still holding bytes.
func captureFor(ex Exchange) (contracts.TransientCapture, error) {
	at := ex.Now
	digest := contracts.NewDigest(ex.Body)
	c := contracts.TransientCapture{
		CaptureID:     contracts.NewUUID(),
		ObservationID: ex.Observation.ObservationID,
		RunID:         ex.Observation.RunID,
		Retention:     string(ex.Retention),
		BodyDigest:    digest,
		CapturedAt:    at,
	}
	switch ex.Retention {
	case contracts.RetainNone, contracts.RetainDigestOnly:
		c.RetainedBytes = 0
		c.DroppedReason = string(ex.Retention) + " was authorized; the body was read for the " +
			"digest and the detector pass and then released"
		return c, nil
	case contracts.RetainTruncated:
		limit := contracts.MaxTruncatedBodyBytes
		if ex.MaxRetainBytes > 0 && ex.MaxRetainBytes < limit {
			limit = ex.MaxRetainBytes
		}
		if limit > len(ex.Body) {
			limit = len(ex.Body)
		}
		c.Body = append([]byte(nil), ex.Body[:limit]...)
		c.RetainedBytes = limit
		c.PrefixDigest = contracts.NewDigest(ex.Body[:limit])
		if ex.BodyTruncated {
			c.DroppedReason = "the response exceeded the client's read cap: the detector pass " +
				"saw the prefix that was in memory, not the whole body"
		}
		return c, nil
	case contracts.RetainFullAllowed:
		limit := len(ex.Body)
		if ex.MaxRetainBytes > 0 && ex.MaxRetainBytes < limit {
			limit = ex.MaxRetainBytes
		}
		c.Body = append([]byte(nil), ex.Body[:limit]...)
		c.RetainedBytes = limit
		c.PrefixDigest = contracts.NewDigest(ex.Body[:limit])
		if limit < len(ex.Body) {
			c.DroppedReason = "the authorization caps retained bytes below the body length; the remainder was released"
		}
		return c, nil
	default:
		return contracts.TransientCapture{}, fmt.Errorf(
			"observer: retention %q is not a policy this build knows", ex.Retention)
	}
}

func buildAnalysis(ex Exchange, capture contracts.TransientCapture,
	set *DetectorSet, matches []contracts.MarkerMatch) (contracts.SignatureAnalysis, error) {
	obs := ex.Observation
	status := obs.ResponseStatus
	if status == 0 && obs.Transport.ErrorClass == "" {
		return contracts.SignatureAnalysis{}, fmt.Errorf(
			"observer: exchange for %s has no status and no transport error", obs.Sent.ProbeRef)
	}
	refs := set.ResponseDetectorIDs()
	if len(refs) == 0 {
		return contracts.SignatureAnalysis{}, fmt.Errorf("observer: the set has no response detectors")
	}
	return contracts.SignatureAnalysis{
		AnalysisID:        contracts.NewUUID(),
		ObservationID:     obs.ObservationID,
		CaptureID:         capture.CaptureID,
		RunID:             obs.RunID,
		AnalyzedAt:        ex.Now,
		StatusCode:        status,
		StatusCategory:    contracts.StatusCategory(status),
		ReasonPhrase:      ex.ReasonPhrase,
		ContentType:       ex.ContentType,
		ServerHeader:      ex.ServerHeader,
		RateLimited:       status == 429,
		RetryAfterSeconds: ex.RetryAfterSeconds,
		HasRetryAfter:     ex.RetryAfterSeconds > 0,
		DetectorRefs:      refs,
		Matches:           matches,
		BodyDigest:        capture.BodyDigest,
		RetentionApplied:  string(ex.Retention),
		DetectorSetHash:   set.Hash(),
	}, nil
}
