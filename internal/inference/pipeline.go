package inference

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"xammu/internal/classifier"
	"xammu/internal/contracts"
	"xammu/internal/integrity"
	"xammu/internal/observer"
	"xammu/internal/orchestrator"
)

// Pipeline is the machinery the two entry points share: one detector ensemble and
// the classifier built on top of it. A run uses a single pipeline, so every record
// in its journal names the same set hash and a reviewer can tell which ensemble a
// reading came from.
type Pipeline struct {
	Set        *observer.DetectorSet
	classifier *classifier.Classifier

	// Clock makes timestamps injectable. It exists for tests and for re-derivation,
	// where "now" would otherwise change a record that is supposed to be identical.
	Clock func() time.Time
}

// New builds a pipeline over an ensemble. A nil set is refused rather than
// defaulted: an empty ensemble reads every response as nothing and reports a clean
// target.
func New(set *observer.DetectorSet) (*Pipeline, error) {
	if set == nil {
		return nil, fmt.Errorf("inference: no detector set supplied")
	}
	cl, err := classifier.New(set)
	if err != nil {
		return nil, err
	}
	return &Pipeline{Set: set, classifier: cl}, nil
}

func (p *Pipeline) now() time.Time {
	if p.Clock != nil {
		return p.Clock().UTC()
	}
	return time.Now().UTC()
}

// Step is the executing-stage step: send the probe, journal C-01, then read the
// body while it is still in this process's memory and journal C-02 and C-03.
//
// It deliberately does not classify. A single exchange has no reference cluster,
// and "this looks like a rejection next to the three benign requests at the same
// path" is a claim about the run; the batch pass makes it once the cluster exists.
//
// The retention policy is read from the run's authorization, not from a parameter,
// so a stage cannot decide to keep more of a response body than the operator
// approved.
func (p *Pipeline) Step(ctx context.Context, r *orchestrator.Run, item orchestrator.PlanItem) error {
	obs, resp, sendErr := orchestrator.Observe(ctx, r, item)
	if resp == nil {
		return sendErr
	}
	// The full body stops being reachable here. What survives is whatever C-02 was
	// allowed to retain, and that is a copy.
	defer func() { resp.Body = nil }()

	retention, maxRetain := r.Retention()
	recs, err := observer.Analyse(observer.Exchange{
		Observation:       obs,
		Body:              resp.Body,
		BodyTruncated:     resp.BodyTruncated,
		ReasonPhrase:      resp.Reason,
		ContentType:       headerOf(obs.ResponseHeaders, "content-type"),
		ServerHeader:      headerOf(obs.ResponseHeaders, "server"),
		RetryAfterSeconds: retryAfterOf(obs.ResponseHeaders),
		Retention:         retention,
		MaxRetainBytes:    maxRetain,
		Now:               p.now(),
	}, p.Set)
	if err != nil {
		return fmt.Errorf("inference: exchange %s produced no analysis: %w", item.Ref, err)
	}
	if err := r.Journal(integrity.StreamCaptures, recs.Capture); err != nil {
		return fmt.Errorf("inference: cannot journal the capture for %s: %w", item.Ref, err)
	}
	if err := r.Journal(integrity.StreamAnalyses, recs.Analysis); err != nil {
		return fmt.Errorf("inference: cannot journal the analysis for %s: %w", item.Ref, err)
	}
	// A transport failure is returned after its evidence is written: the exchange
	// happened, it produced nothing, and that is a fact the run reports.
	return sendErr
}

// headerOf reads one header from the observation's ordered list. The lookup is
// case-insensitive because HTTP names are, and the value is recorded as a fact for
// a reviewer: no detector in XAMMU reads a header, because observer.Shape has no
// field to put one in.
func headerOf(entries []contracts.HeaderEntry, name string) string {
	for _, h := range entries {
		if strings.EqualFold(h.Name, name) {
			return h.Value
		}
	}
	return ""
}

// retryAfterOf parses the delay form of Retry-After. An HTTP-date value is not
// parsed: it would turn a clock difference into a number, and pacing arithmetic is
// the orchestrator's business, not a detector input.
func retryAfterOf(entries []contracts.HeaderEntry) int {
	v := strings.TrimSpace(headerOf(entries, "retry-after"))
	if v == "" {
		return 0
	}
	secs, err := strconv.Atoi(v)
	if err != nil || secs < 0 {
		return 0
	}
	return secs
}
