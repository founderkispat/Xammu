package effectiveness

import (
	"encoding/json"
	"fmt"

	"xammu/internal/integrity"
)

// Bundle is what a sealed effectiveness directory holds.
type Bundle struct {
	Dir      string
	Cases    []Case
	Outcomes []Outcome
	Metrics  Metrics
}

// ReadBundle opens a sealed directory, replays every chain and decodes the
// effectiveness records. Opening through integrity.Open is what makes a damaged
// chain a read error rather than a silently shorter list.
func ReadBundle(dir string) (*Bundle, error) {
	store, err := integrity.Open(dir)
	if err != nil {
		return nil, err
	}
	b := &Bundle{Dir: dir}
	recs, err := store.Records(integrity.StreamEffectivenessCases)
	if err != nil {
		return nil, err
	}
	for _, r := range recs {
		var c Case
		if err := json.Unmarshal(r.Payload, &c); err != nil {
			return nil, fmt.Errorf("effectiveness: case record %d is unreadable: %w", r.Seq, err)
		}
		b.Cases = append(b.Cases, c)
	}
	recs, err = store.Records(integrity.StreamEffectivenessOutcomes)
	if err != nil {
		return nil, err
	}
	for _, r := range recs {
		var o Outcome
		if err := json.Unmarshal(r.Payload, &o); err != nil {
			return nil, fmt.Errorf("effectiveness: outcome record %d is unreadable: %w", r.Seq, err)
		}
		b.Outcomes = append(b.Outcomes, o)
	}
	recs, err = store.Records(integrity.StreamEffectivenessMetrics)
	if err != nil {
		return nil, err
	}
	if len(recs) == 0 {
		return nil, fmt.Errorf("effectiveness: %s holds no metrics record: the run was not finalized", dir)
	}
	if err := json.Unmarshal(recs[len(recs)-1].Payload, &b.Metrics); err != nil {
		return nil, fmt.Errorf("effectiveness: metrics record is unreadable: %w", err)
	}
	if len(b.Cases) == 0 {
		return nil, fmt.Errorf("effectiveness: %s holds no case record", dir)
	}
	return b, nil
}

// Rederive recomputes E-03 from E-01 and E-02 and compares it with the record the
// run journaled. A non-empty diff is a failed reproduction.
func (b *Bundle) Rederive() (Metrics, []string) {
	derived := Compute(b.Metrics.RunID, b.Metrics.AuthorizationRef, b.Cases, b.Outcomes,
		b.Metrics.GeneratedAt)
	return derived, Diff(b.Metrics, derived)
}
