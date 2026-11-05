package effectiveness

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"xammu/internal/contracts"
	"xammu/internal/fingerprint"
)

// Counts is the confusion matrix. Excluded is reported beside it and never in a
// denominator: an inconclusive exchange is not evidence for either verdict.
type Counts struct {
	TP       int `json:"tp"`
	FN       int `json:"fn"`
	FP       int `json:"fp"`
	TN       int `json:"tn"`
	Excluded int `json:"excluded"`
}

// Rates holds the derived statistics. A nil pointer is a metric whose
// denominator is zero; the report prints "n/a" rather than inventing a value.
type Rates struct {
	TPR       *float64 `json:"tpr"`
	FPR       *float64 `json:"fpr"`
	Precision *float64 `json:"precision"`
	F1        *float64 `json:"f1"`
	MCC       *float64 `json:"mcc"`
}

// LatencySummary is a nearest-rank percentile summary over the conclusive
// exchanges of one population. SufficientSample means n>=20; P99Sufficient
// means n>=100. Both are published so a reader can see when a tail figure is a
// description of a handful of requests rather than a stable quantile.
type LatencySummary struct {
	N                int     `json:"n"`
	P50              float64 `json:"p50_ms"`
	P95              float64 `json:"p95_ms"`
	P99              float64 `json:"p99_ms"`
	SufficientSample bool    `json:"sufficient_sample"`
	P99Sufficient    bool    `json:"p99_sufficient"`
	Method           string  `json:"method"`
}

// ClassMetrics is one row of the human table.
type ClassMetrics struct {
	Class   string         `json:"class"`
	Kind    Kind           `json:"kind"`
	Counts  Counts         `json:"counts"`
	Rates   Rates          `json:"rates"`
	Latency LatencySummary `json:"latency"`
	OWASP   string         `json:"owasp,omitempty"`
}

// ArmMetrics is one arm's matrix. The baseline arm carries no stack; the tamper
// arm names the stack that produced it and why it was selected.
type ArmMetrics struct {
	Arm              Arm                `json:"arm"`
	TamperStack      []contracts.Tamper `json:"tamper_stack,omitempty"`
	SelectionBasis   string             `json:"selection_basis,omitempty"`
	Cases            int                `json:"cases"`
	Counts           Counts             `json:"counts"`
	Rates            Rates              `json:"rates"`
	Classes          []ClassMetrics     `json:"classes,omitempty"`
	Latency          LatencySummary     `json:"latency"`
	ExcludedByReason map[string]int     `json:"excluded_by_reason,omitempty"`
}

// ComparisonRow is one row of the Phase 2 table. DeltaPP exists only when both
// arms produced a denominator; a missing rate is null, never zero.
type ComparisonRow struct {
	Class       string   `json:"class"`
	BaselineTPR *float64 `json:"baseline_tpr"`
	TamperTPR   *float64 `json:"tamper_tpr"`
	DeltaPP     *float64 `json:"delta_pp"`
	BaselineN   int      `json:"baseline_n"`
	TamperN     int      `json:"tamper_n"`
	Note        string   `json:"note,omitempty"`
}

// Metrics is E-03: the derived result of one effectiveness run. The top-level
// matrix is the baseline arm, which is exactly what a Phase 1 record holds; a
// Phase 2 run adds arms, comparison and fingerprint.
type Metrics struct {
	RunID            string               `json:"run_id"`
	AuthorizationRef string               `json:"authorization_ref"`
	CorpusDigest     string               `json:"corpus_digest"`
	Cases            int                  `json:"cases"`
	Counts           Counts               `json:"counts"`
	Rates            Rates                `json:"rates"`
	Classes          []ClassMetrics       `json:"classes"`
	Latency          LatencySummary       `json:"latency"`
	ExcludedByReason map[string]int       `json:"excluded_by_reason"`
	Arms             []ArmMetrics         `json:"arms,omitempty"`
	Comparison       []ComparisonRow      `json:"comparison,omitempty"`
	Fingerprint      *fingerprint.Summary `json:"fingerprint,omitempty"`
	Notes            []string             `json:"notes"`
	GeneratedAt      time.Time            `json:"generated_at"`
}

type trialKey struct {
	id  string
	arm Arm
}

type classBucket struct {
	counts Counts
	lat    []int64
}

type armTally struct {
	cases    int
	counts   Counts
	excluded map[string]int
	classes  map[string]*classBucket
	lat      []int64
}

// BaselineFingerprint aggregates the fingerprint evidence captured by the
// baseline arm. It returns nil for a Phase 1 record, which carries no evidence
// at all, so an old bundle rederives to exactly the bytes it was signed with.
func BaselineFingerprint(outcomes []Outcome) *fingerprint.Summary {
	var obs []fingerprint.Observation
	legacy := true
	for _, o := range outcomes {
		if NormalizeArm(o.Arm) != ArmBaseline || o.FingerprintPolicy == "" {
			continue
		}
		legacy = false
		obs = append(obs, fingerprint.Observation{
			Evidence:   o.Fingerprint,
			Conclusive: o.Verdict == VerdictBlocked || o.Verdict == VerdictAllowed,
		})
	}
	if legacy {
		return nil
	}
	s := fingerprint.Aggregate(obs)
	return &s
}

// Compute derives the metrics from the corpus and the outcomes. It is pure: the
// same inputs produce the same numbers, which is what makes --rederive a check
// rather than a second opinion.
func Compute(runID, authRef string, cases []Case, outcomes []Outcome, now time.Time) Metrics {
	m := Metrics{
		RunID: runID, AuthorizationRef: authRef,
		CorpusDigest: CorpusDigest(cases), Cases: len(cases),
		ExcludedByReason: map[string]int{},
		GeneratedAt:      now.UTC(),
	}
	byID := make(map[string]Case, len(cases))
	for _, c := range cases {
		byID[c.ID] = c
	}
	last := make(map[trialKey]Outcome, len(outcomes))
	arms := map[Arm]bool{}
	var baselineOutcomes []Outcome
	for _, o := range outcomes {
		if _, known := byID[o.CaseID]; !known {
			m.Notes = append(m.Notes, fmt.Sprintf("outcome for unknown case %q was ignored", o.CaseID))
			continue
		}
		arm := NormalizeArm(o.Arm)
		arms[arm] = true
		k := trialKey{id: o.CaseID, arm: arm}
		if _, dup := last[k]; dup {
			m.Notes = append(m.Notes, fmt.Sprintf("case %q produced more than one outcome; the last is used",
				o.CaseID))
		}
		last[k] = o
		if arm == ArmBaseline {
			baselineOutcomes = append(baselineOutcomes, o)
		}
	}

	base := tallyArm(cases, last, ArmBaseline, nil)
	m.Counts = base.counts
	m.ExcludedByReason = base.excluded
	m.Classes = classMetrics(cases, base)
	m.Rates = deriveRates(m.Counts)
	m.Latency = summariseLatency(base.lat)

	if arms[ArmTamper] {
		m.Arms = append(m.Arms, armMetrics(cases, last, ArmBaseline, nil))
		covered := coveredKinds(cases, last, ArmTamper)
		m.Arms = append(m.Arms, armMetrics(cases, last, ArmTamper, covered))
		m.Comparison = compareArms(m.Arms[0], m.Arms[1])

		m.Notes = append(m.Notes,
			"The top-level matrix is the baseline arm; arms publishes each arm separately.",
			"Delta in the comparison table is tamper TPR minus baseline TPR in percentage points; "+
				"it is arithmetic over the two matrices, not an estimated effect size.")
	}

	m.Fingerprint = BaselineFingerprint(baselineOutcomes)
	for _, o := range outcomes {
		if o.MarkerHeader {
			m.Notes = append(m.Notes,
				"A base64 stack carries the diagnostic token in X-Xammu-Probe because base64 erases "+
					"the inline marker; the header is a recorded confounder, and auto selection never uses base64.")
			break
		}
	}

	m.Notes = append(m.Notes, []string{
		"TPR and FPR describe agreement with this corpus, on this target, in this window; " +
			"they are not a claim of absolute efficacy.",
		"429 is pacing, never a block (criterion 24): it is excluded and counted with the other " +
			"inconclusive outcomes.",
		"A zero-denominator metric is null; no value is invented.",
		"Percentiles use nearest rank; p99 is marked insufficient below 100 samples and every " +
			"summary below 20 samples.",
	}...)
	return m
}

// tallyArm counts one arm. covered is nil for the baseline (the whole corpus)
// and the kinds the tamper arm actually attempted otherwise; an unattempted kind
// is left out rather than reported as excluded.
func tallyArm(cases []Case, last map[trialKey]Outcome, arm Arm, covered map[Kind]bool) armTally {
	t := armTally{excluded: map[string]int{}, classes: map[string]*classBucket{}}
	bucket := func(class string) *classBucket {
		b, ok := t.classes[class]
		if !ok {
			b = &classBucket{}
			t.classes[class] = b
		}
		return b
	}
	for _, c := range cases {
		if covered != nil && !covered[c.Kind] {
			continue
		}
		t.cases++
		o, seen := last[trialKey{id: c.ID, arm: arm}]
		b := bucket(c.Class)
		if !seen {
			t.counts.Excluded++
			b.counts.Excluded++
			t.excluded["not_executed"]++
			continue
		}
		switch o.Verdict {
		case VerdictBlocked, VerdictAllowed:
			if o.LatencyMS >= 0 {
				b.lat = append(b.lat, o.LatencyMS)
				t.lat = append(t.lat, o.LatencyMS)
			}
			switch {
			case c.Kind == KindAttack && o.Verdict == VerdictBlocked:
				t.counts.TP++
				b.counts.TP++
			case c.Kind == KindAttack && o.Verdict == VerdictAllowed:
				t.counts.FN++
				b.counts.FN++
			case c.Kind == KindBenign && o.Verdict == VerdictBlocked:
				t.counts.FP++
				b.counts.FP++
			case c.Kind == KindBenign && o.Verdict == VerdictAllowed:
				t.counts.TN++
				b.counts.TN++
			}
		default:
			reason := o.ExclusionReason
			if reason == "" {
				reason = "excluded"
			}
			t.counts.Excluded++
			b.counts.Excluded++
			t.excluded[reason]++
		}
	}
	return t
}

func classMetrics(cases []Case, t armTally) []ClassMetrics {
	order := make([]string, 0, len(t.classes))
	for class := range t.classes {
		order = append(order, class)
	}
	sort.Slice(order, func(i, j int) bool {
		ri, rj := classRank(order[i]), classRank(order[j])
		if ri != rj {
			return ri < rj
		}
		return order[i] < order[j]
	})
	out := make([]ClassMetrics, 0, len(order))
	for _, class := range order {
		b := t.classes[class]
		kind := KindAttack
		if benignClassKnown(class) {
			kind = KindBenign
		}
		out = append(out, ClassMetrics{
			Class: class, Kind: kind, Counts: b.counts,
			Rates: deriveRates(b.counts), Latency: summariseLatency(b.lat),
			OWASP: owaspOf(cases, class),
		})
	}
	return out
}

func armMetrics(cases []Case, last map[trialKey]Outcome, arm Arm, covered map[Kind]bool) ArmMetrics {
	t := tallyArm(cases, last, arm, covered)
	a := ArmMetrics{
		Arm: arm, Cases: t.cases, Counts: t.counts, Rates: deriveRates(t.counts),
		Classes: classMetrics(cases, t), Latency: summariseLatency(t.lat),
		ExcludedByReason: t.excluded,
	}
	for _, o := range last {
		if NormalizeArm(o.Arm) == arm && len(o.TamperStack) > 0 {
			a.TamperStack = append([]contracts.Tamper(nil), o.TamperStack...)
			a.SelectionBasis = o.SelectionBasis
			break
		}
	}
	return a
}

// coveredKinds reports which case kinds the arm attempted. A tamper run with
// --tamper-benign=false leaves benign out instead of counting it as excluded.
func coveredKinds(cases []Case, last map[trialKey]Outcome, arm Arm) map[Kind]bool {
	byID := make(map[string]Case, len(cases))
	for _, c := range cases {
		byID[c.ID] = c
	}
	out := map[Kind]bool{}
	for k := range last {
		if k.arm != arm {
			continue
		}
		if c, ok := byID[k.id]; ok {
			out[c.Kind] = true
		}
	}
	return out
}

func compareArms(base, tamper ArmMetrics) []ComparisonRow {
	baseByClass := map[string]ClassMetrics{}
	for _, c := range base.Classes {
		baseByClass[c.Class] = c
	}
	tamperByClass := map[string]ClassMetrics{}
	for _, c := range tamper.Classes {
		tamperByClass[c.Class] = c
	}
	var rows []ComparisonRow
	for _, class := range contracts.AllAttackClasses() {
		name := string(class)
		rows = append(rows, comparisonRow(name, baseByClass[name], tamperByClass[name]))
	}
	all := ClassMetrics{
		Class: "all", Kind: KindAttack,
		Counts: Counts{TP: base.Counts.TP, FN: base.Counts.FN},
		Rates:  base.Rates,
	}
	allTamper := ClassMetrics{
		Class: "all", Kind: KindAttack,
		Counts: Counts{TP: tamper.Counts.TP, FN: tamper.Counts.FN},
		Rates:  tamper.Rates,
	}
	rows = append(rows, comparisonRow("all attack classes", all, allTamper))
	return rows
}

func comparisonRow(class string, base, tamper ClassMetrics) ComparisonRow {
	row := ComparisonRow{Class: class}
	row.BaselineN = base.Counts.TP + base.Counts.FN
	row.TamperN = tamper.Counts.TP + tamper.Counts.FN
	row.BaselineTPR = base.Rates.TPR
	row.TamperTPR = tamper.Rates.TPR
	switch {
	case row.BaselineN == 0 && row.TamperN == 0:
		row.Note = "not measured in either arm"
	case row.BaselineN == 0:
		row.Note = "baseline arm has no conclusive case"
	case row.TamperN == 0:
		row.Note = "tamper arm has no conclusive case"
	default:
		delta := (*row.TamperTPR - *row.BaselineTPR) * 100
		row.DeltaPP = &delta
	}
	return row
}

func classRank(class string) int {
	for i, c := range contracts.AllAttackClasses() {
		if string(c) == class {
			return i
		}
	}
	for i, c := range benignClasses {
		if c == class {
			return len(contracts.AllAttackClasses()) + i
		}
	}
	return len(contracts.AllAttackClasses()) + len(benignClasses)
}

func owaspOf(cases []Case, class string) string {
	for _, c := range cases {
		if c.Class == class && c.OWASP != "" {
			return c.OWASP
		}
	}
	return ""
}

func deriveRates(c Counts) Rates {
	var r Rates
	if c.TP+c.FN > 0 {
		r.TPR = ratio(c.TP, c.TP+c.FN)
	}
	if c.FP+c.TN > 0 {
		r.FPR = ratio(c.FP, c.FP+c.TN)
	}
	if c.TP+c.FP > 0 {
		r.Precision = ratio(c.TP, c.TP+c.FP)
	}
	if r.TPR != nil && r.Precision != nil {
		den := *r.Precision + *r.TPR
		if den > 0 {
			v := 2 * *r.Precision * *r.TPR / den
			r.F1 = &v
		}
	}
	den := float64(c.TP+c.FP) * float64(c.TP+c.FN) * float64(c.TN+c.FP) * float64(c.TN+c.FN)
	if den > 0 {
		v := (float64(c.TP*c.TN) - float64(c.FP*c.FN)) / math.Sqrt(den)
		r.MCC = &v
	}
	return r
}

func ratio(num, den int) *float64 {
	if den == 0 {
		return nil
	}
	v := float64(num) / float64(den)
	return &v
}

func summariseLatency(samples []int64) LatencySummary {
	l := LatencySummary{
		N: len(samples), Method: "nearest_rank",
		SufficientSample: len(samples) >= 20,
		P99Sufficient:    len(samples) >= 100,
	}
	if len(samples) == 0 {
		return l
	}
	sorted := append([]int64(nil), samples...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	l.P50 = percentile(sorted, 50)
	l.P95 = percentile(sorted, 95)
	l.P99 = percentile(sorted, 99)
	return l
}

func percentile(sorted []int64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	rank := int(math.Ceil(p / 100 * float64(len(sorted))))
	if rank < 1 {
		rank = 1
	}
	if rank > len(sorted) {
		rank = len(sorted)
	}
	return float64(sorted[rank-1])
}

// Canonical renders the metrics without the generation timestamp, which is the
// only field a re-derivation is allowed to disagree about.
func (m Metrics) Canonical() ([]byte, error) {
	cp := m
	cp.GeneratedAt = time.Time{}
	return json.Marshal(cp)
}

// Diff reports the fields on which a stored and a re-derived metrics record
// disagree. It is deliberately explicit: "the numbers differ" is not enough for
// an operator to know whether the corpus, the evidence or the arithmetic moved.
func Diff(stored, derived Metrics) []string {
	a, errA := stored.Canonical()
	b, errB := derived.Canonical()
	if errA != nil || errB != nil {
		return []string{"metrics could not be canonicalised for comparison"}
	}
	if string(a) == string(b) {
		return nil
	}
	var out []string
	if stored.CorpusDigest != derived.CorpusDigest {
		out = append(out, fmt.Sprintf("corpus digest %s vs re-derived %s",
			short(stored.CorpusDigest), short(derived.CorpusDigest)))
	}
	if stored.Cases != derived.Cases {
		out = append(out, fmt.Sprintf("case count %d vs re-derived %d", stored.Cases, derived.Cases))
	}
	if stored.Counts != derived.Counts {
		out = append(out, fmt.Sprintf("counts tp/fn/fp/tn/excluded %d/%d/%d/%d/%d vs re-derived %d/%d/%d/%d/%d",
			stored.Counts.TP, stored.Counts.FN, stored.Counts.FP, stored.Counts.TN, stored.Counts.Excluded,
			derived.Counts.TP, derived.Counts.FN, derived.Counts.FP, derived.Counts.TN, derived.Counts.Excluded))
	}
	if len(stored.Classes) != len(derived.Classes) {
		out = append(out, fmt.Sprintf("%d class rows vs re-derived %d",
			len(stored.Classes), len(derived.Classes)))
	} else {
		for i := range stored.Classes {
			if !sameJSON(stored.Classes[i], derived.Classes[i]) {
				out = append(out, fmt.Sprintf("class row %s differs", stored.Classes[i].Class))
			}
		}
	}
	if !sameJSON(stored.Latency, derived.Latency) {
		out = append(out, fmt.Sprintf("latency n=%d vs re-derived n=%d",
			stored.Latency.N, derived.Latency.N))
	}
	if !sameJSON(stored.ExcludedByReason, derived.ExcludedByReason) {
		out = append(out, "exclusion counts differ")
	}
	if !sameJSON(stored.Arms, derived.Arms) {
		out = append(out, fmt.Sprintf("%d arm rows vs re-derived %d",
			len(stored.Arms), len(derived.Arms)))
	}
	if !sameJSON(stored.Comparison, derived.Comparison) {
		out = append(out, "baseline/tamper comparison differs")
	}
	if !sameJSON(stored.Fingerprint, derived.Fingerprint) {
		out = append(out, "fingerprint summary differs")
	}
	if len(out) == 0 {
		out = append(out, "metrics differ outside the compared fields")
	}
	return out
}

func sameJSON(a, b any) bool {
	x, errA := json.Marshal(a)
	y, errB := json.Marshal(b)
	return errA == nil && errB == nil && string(x) == string(y)
}

func short(s string) string {
	s = strings.TrimPrefix(s, "sha256:")
	if len(s) > 12 {
		return s[:12]
	}
	return s
}
