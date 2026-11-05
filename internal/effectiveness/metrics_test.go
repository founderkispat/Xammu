package effectiveness

import (
	"strings"
	"testing"
	"time"

	"xammu/internal/contracts"
	"xammu/internal/fingerprint"
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

func TestComputeArmsDoNotChangeTheTopLevelMatrix(t *testing.T) {
	cases := []Case{
		{ID: "a1", Kind: KindAttack, Class: "sqli"},
		{ID: "a2", Kind: KindAttack, Class: "sqli"},
		{ID: "b1", Kind: KindBenign, Class: "benign_text"},
	}
	outcomes := []Outcome{
		{CaseID: "a1", Arm: ArmBaseline, Verdict: VerdictBlocked, LatencyMS: 1},
		{CaseID: "a2", Arm: ArmBaseline, Verdict: VerdictAllowed, LatencyMS: 1},
		{CaseID: "b1", Arm: ArmBaseline, Verdict: VerdictAllowed, LatencyMS: 1},
		{CaseID: "a1", Arm: ArmTamper, Verdict: VerdictBlocked, LatencyMS: 2,
			TamperStack: []contracts.Tamper{contracts.TamperURLEncode}, SelectionBasis: "forced"},
		{CaseID: "a2", Arm: ArmTamper, Verdict: VerdictBlocked, LatencyMS: 2,
			TamperStack: []contracts.Tamper{contracts.TamperURLEncode}, SelectionBasis: "forced"},
	}
	m := Compute("run-1", "AUTH-1", cases, outcomes, time.Now())
	if m.Counts != (Counts{TP: 1, FN: 1, TN: 1}) {
		t.Fatalf("top-level counts = %+v, want the baseline matrix", m.Counts)
	}
	if len(m.Arms) != 2 {
		t.Fatalf("arms = %+v", m.Arms)
	}
	base, tamper := m.Arms[0], m.Arms[1]
	if base.Arm != ArmBaseline || base.Counts.TP != 1 || base.Counts.FN != 1 {
		t.Fatalf("baseline arm = %+v", base)
	}
	if tamper.Counts.TP != 2 || tamper.Counts.Excluded != 0 {
		t.Fatalf("tamper arm = %+v", tamper)
	}
	if tamper.Cases != 2 {
		t.Fatalf("a tamper arm that attempted only attacks must count two cases, got %d", tamper.Cases)
	}
	if len(tamper.TamperStack) != 1 || tamper.TamperStack[0] != contracts.TamperURLEncode {
		t.Fatalf("tamper stack = %v", tamper.TamperStack)
	}
	if len(m.Comparison) != len(contracts.AllAttackClasses())+1 {
		t.Fatalf("comparison rows = %d", len(m.Comparison))
	}
	var sqli *ComparisonRow
	for i := range m.Comparison {
		if m.Comparison[i].Class == "sqli" {
			sqli = &m.Comparison[i]
		}
	}
	if sqli == nil || sqli.BaselineTPR == nil || sqli.TamperTPR == nil || sqli.DeltaPP == nil {
		t.Fatalf("sqli comparison = %+v", sqli)
	}
	if !closeEnough(*sqli.BaselineTPR, 0.5) || !closeEnough(*sqli.TamperTPR, 1.0) {
		t.Fatalf("sqli TPRs = %v/%v", *sqli.BaselineTPR, *sqli.TamperTPR)
	}
	if !closeEnough(*sqli.DeltaPP, 50) {
		t.Fatalf("delta = %v pp, want 50", *sqli.DeltaPP)
	}
}

func TestComputeComparisonLeavesAnEmptyArmNull(t *testing.T) {
	cases := []Case{{ID: "a1", Kind: KindAttack, Class: "sqli"}}
	outcomes := []Outcome{
		{CaseID: "a1", Arm: ArmBaseline, Verdict: VerdictBlocked},
		{CaseID: "a1", Arm: ArmTamper, Verdict: VerdictExcluded, ExclusionReason: "rate_limited"},
	}
	m := Compute("run-1", "AUTH-1", cases, outcomes, time.Now())
	row := m.Comparison[0]
	if row.Class != "sqli" || row.TamperN != 0 || row.TamperTPR != nil || row.DeltaPP != nil {
		t.Fatalf("an empty arm must publish null, not zero: %+v", row)
	}
	if row.Note == "" {
		t.Fatal("an empty arm needs a note")
	}
}

func TestComputePhase1OutcomesGainNoPhase2Fields(t *testing.T) {
	cases, outcomes := metricFixture()
	m := Compute("run-1", "AUTH-1", cases, outcomes, time.Now())
	if m.Arms != nil || m.Comparison != nil || m.Fingerprint != nil {
		t.Fatalf("a Phase 1 record grew Phase 2 fields: %+v", m)
	}
	if m.Notes[0] != "TPR and FPR describe agreement with this corpus, on this target, in this window; "+
		"they are not a claim of absolute efficacy." {
		t.Fatalf("the Phase 1 note list changed: %v", m.Notes)
	}
}

func TestComputeFingerprintComesFromBaselineOnly(t *testing.T) {
	cases := []Case{{ID: "a1", Kind: KindAttack, Class: "sqli"}}
	ev := []fingerprint.Evidence{{
		Vendor: "xammu-lab-waf", Signature: "lab-server", Kind: fingerprint.KindHeader,
		Strength: fingerprint.StrengthIdentifying, Detail: "header:server",
	}}
	outcomes := []Outcome{
		{CaseID: "a1", Arm: ArmBaseline, Verdict: VerdictBlocked,
			Fingerprint: ev, FingerprintPolicy: fingerprint.Policy},
		{CaseID: "a1", Arm: ArmTamper, Verdict: VerdictAllowed,
			Fingerprint: []fingerprint.Evidence{{Vendor: "cloudflare", Signature: "cloudflare-ray",
				Kind: fingerprint.KindHeader, Strength: fingerprint.StrengthIdentifying,
				Detail: "header:cf-ray"}},
			FingerprintPolicy: fingerprint.Policy, MarkerHeader: true,
			TamperStack: []contracts.Tamper{contracts.TamperBase64}},
	}
	m := Compute("run-1", "AUTH-1", cases, outcomes, time.Now())
	if m.Fingerprint == nil || len(m.Fingerprint.Vendors) != 1 ||
		m.Fingerprint.Vendors[0].Vendor != "xammu-lab-waf" {
		t.Fatalf("fingerprint = %+v; the tamper arm must not contribute", m.Fingerprint)
	}
	found := false
	for _, n := range m.Notes {
		if strings.Contains(n, "base64") {
			found = true
		}
	}
	if !found {
		t.Fatal("a marker-header trial needs a recorded confounder note")
	}
}

func TestDiffDetectsAChangedComparison(t *testing.T) {
	cases := []Case{{ID: "a1", Kind: KindAttack, Class: "sqli"}}
	outcomes := []Outcome{
		{CaseID: "a1", Arm: ArmBaseline, Verdict: VerdictBlocked},
		{CaseID: "a1", Arm: ArmTamper, Verdict: VerdictBlocked},
	}
	stored := Compute("run-1", "AUTH-1", cases, outcomes, time.Now())
	derived := stored
	derived.Comparison = append([]ComparisonRow(nil), stored.Comparison...)
	five := 5.0
	derived.Comparison[0].DeltaPP = &five
	diffs := Diff(stored, derived)
	if len(diffs) == 0 || !strings.Contains(strings.Join(diffs, " "), "comparison") {
		t.Fatalf("diff did not name the comparison: %v", diffs)
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
