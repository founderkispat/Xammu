package effectiveness

import (
	"testing"
	"time"
)

func metricFixture() ([]Case, []Outcome) {
	cases := []Case{
		{ID: "a1", Kind: KindAttack, Class: "sqli"},
		{ID: "a2", Kind: KindAttack, Class: "sqli"},
		{ID: "b1", Kind: KindBenign, Class: "benign_text"},
		{ID: "b2", Kind: KindBenign, Class: "benign_text"},
	}
	outcomes := []Outcome{
		{CaseID: "a1", Verdict: VerdictBlocked, LatencyMS: 10},
		{CaseID: "a2", Verdict: VerdictAllowed, LatencyMS: 20},
		{CaseID: "b1", Verdict: VerdictBlocked, LatencyMS: 30},
		{CaseID: "b2", Verdict: VerdictAllowed, LatencyMS: 40},
	}
	return cases, outcomes
}

func TestComputeKnownConfusionMatrix(t *testing.T) {
	cases, outcomes := metricFixture()
	m := Compute("run-1", "AUTH-1", cases, outcomes, time.Now())
	if m.Counts != (Counts{TP: 1, FN: 1, FP: 1, TN: 1}) {
		t.Fatalf("counts = %+v", m.Counts)
	}
	for name, pair := range map[string]struct {
		got  *float64
		want float64
	}{
		"TPR": {m.Rates.TPR, 0.5}, "FPR": {m.Rates.FPR, 0.5},
		"Precision": {m.Rates.Precision, 0.5}, "F1": {m.Rates.F1, 0.5},
		"MCC": {m.Rates.MCC, 0},
	} {
		if pair.got == nil || !closeEnough(*pair.got, pair.want) {
			t.Fatalf("%s = %v, want %v", name, pair.got, pair.want)
		}
	}
	if m.Latency.N != 4 || m.Latency.P50 != 20 || m.Latency.P95 != 40 || m.Latency.P99 != 40 {
		t.Fatalf("latency = %+v", m.Latency)
	}
	if m.Latency.SufficientSample || m.Latency.P99Sufficient {
		t.Fatalf("a four-sample tail was published as sufficient: %+v", m.Latency)
	}
}

func TestComputeLeavesZeroDenominatorsNull(t *testing.T) {
	cases := []Case{{ID: "a1", Kind: KindAttack, Class: "sqli"}}
	outcomes := []Outcome{{CaseID: "a1", Verdict: VerdictBlocked, LatencyMS: 5}}
	m := Compute("run-1", "AUTH-1", cases, outcomes, time.Now())
	if m.Rates.TPR == nil || *m.Rates.TPR != 1 {
		t.Fatalf("TPR = %v", m.Rates.TPR)
	}
	if m.Rates.FPR != nil || m.Rates.Precision == nil || m.Rates.F1 == nil || m.Rates.MCC != nil {
		t.Fatalf("rates = %+v", m.Rates)
	}
}

func TestComputeExcludesButDoesNotDrop(t *testing.T) {
	cases := []Case{
		{ID: "a1", Kind: KindAttack, Class: "sqli"},
		{ID: "a2", Kind: KindAttack, Class: "sqli"},
		{ID: "a3", Kind: KindAttack, Class: "sqli"},
	}
	outcomes := []Outcome{
		{CaseID: "a1", Verdict: VerdictBlocked},
		{CaseID: "a2", Verdict: VerdictExcluded, ExclusionReason: "rate_limited"},
	}
	m := Compute("run-1", "AUTH-1", cases, outcomes, time.Now())
	if m.Counts != (Counts{TP: 1, Excluded: 2}) {
		t.Fatalf("counts = %+v", m.Counts)
	}
	if m.ExcludedByReason["rate_limited"] != 1 || m.ExcludedByReason["not_executed"] != 1 {
		t.Fatalf("reasons = %v", m.ExcludedByReason)
	}
	if m.Rates.TPR == nil || *m.Rates.TPR != 1 {
		t.Fatalf("TPR denominator included an excluded case: %v", m.Rates.TPR)
	}
}

func TestComputeUsesTheLastOutcomeForACase(t *testing.T) {
	cases := []Case{{ID: "a1", Kind: KindAttack, Class: "sqli"}}
	outcomes := []Outcome{
		{CaseID: "a1", Verdict: VerdictAllowed},
		{CaseID: "a1", Verdict: VerdictBlocked},
	}
	m := Compute("run-1", "AUTH-1", cases, outcomes, time.Now())
	if m.Counts.TP != 1 || m.Counts.FN != 0 {
		t.Fatalf("counts = %+v", m.Counts)
	}
	if len(m.Notes) == 0 {
		t.Fatal("the duplicate outcome was not noted")
	}
}

func TestPercentileUsesNearestRank(t *testing.T) {
	sorted := make([]int64, 100)
	for i := range sorted {
		sorted[i] = int64(i + 1)
	}
	if got := percentile(sorted, 50); got != 50 {
		t.Fatalf("p50 = %v", got)
	}
	if got := percentile(sorted, 95); got != 95 {
		t.Fatalf("p95 = %v", got)
	}
	if got := percentile(sorted, 99); got != 99 {
		t.Fatalf("p99 = %v", got)
	}
	if got := percentile([]int64{7}, 99); got != 7 {
		t.Fatalf("single sample = %v", got)
	}
}

func TestDiffDetectsAChangedCount(t *testing.T) {
	cases, outcomes := metricFixture()
	a := Compute("run-1", "AUTH-1", cases, outcomes, time.Now())
	b := a
	b.Counts.TP++
	diff := Diff(a, b)
	if len(diff) == 0 {
		t.Fatal("Diff reported no disagreement")
	}
	if diff := Diff(a, a); len(diff) != 0 {
		t.Fatalf("identical metrics differ: %v", diff)
	}
}

func closeEnough(a, b float64) bool {
	const eps = 1e-9
	if a > b {
		return a-b < eps
	}
	return b-a < eps
}
