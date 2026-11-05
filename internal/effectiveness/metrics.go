package effectiveness

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"xammu/internal/contracts"
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

// Metrics is E-03: the derived result of one effectiveness run.
type Metrics struct {
	RunID            string         `json:"run_id"`
	AuthorizationRef string         `json:"authorization_ref"`
	CorpusDigest     string         `json:"corpus_digest"`
	Cases            int            `json:"cases"`
	Counts           Counts         `json:"counts"`
	Rates            Rates          `json:"rates"`
	Classes          []ClassMetrics `json:"classes"`
	Latency          LatencySummary `json:"latency"`
	ExcludedByReason map[string]int `json:"excluded_by_reason"`
	Notes            []string       `json:"notes"`
	GeneratedAt      time.Time      `json:"generated_at"`
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
	last := make(map[string]Outcome, len(outcomes))
	for _, o := range outcomes {
		if _, known := byID[o.CaseID]; !known {
			m.Notes = append(m.Notes, fmt.Sprintf("outcome for unknown case %q was ignored", o.CaseID))
			continue
		}
		if _, dup := last[o.CaseID]; dup {
			m.Notes = append(m.Notes, fmt.Sprintf("case %q produced more than one outcome; the last is used",
				o.CaseID))
		}
		last[o.CaseID] = o
	}

	type bucket struct {
		counts Counts
		lat    []int64
	}
	buckets := map[string]*bucket{}
	latencies := func(key string) *bucket {
		b, ok := buckets[key]
		if !ok {
			b = &bucket{}
			buckets[key] = b
		}
		return b
	}
	overall := latencies("")

	for _, c := range cases {
		o, seen := last[c.ID]
		b := latencies(c.Class)
		if !seen {
			m.Counts.Excluded++
			b.counts.Excluded++
			m.ExcludedByReason["not_executed"]++
			continue
		}
		switch o.Verdict {
		case VerdictBlocked, VerdictAllowed:
			if o.LatencyMS >= 0 {
				b.lat = append(b.lat, o.LatencyMS)
				overall.lat = append(overall.lat, o.LatencyMS)
			}
			switch {
			case c.Kind == KindAttack && o.Verdict == VerdictBlocked:
				m.Counts.TP++
				b.counts.TP++
			case c.Kind == KindAttack && o.Verdict == VerdictAllowed:
				m.Counts.FN++
				b.counts.FN++
			case c.Kind == KindBenign && o.Verdict == VerdictBlocked:
				m.Counts.FP++
				b.counts.FP++
			case c.Kind == KindBenign && o.Verdict == VerdictAllowed:
				m.Counts.TN++
				b.counts.TN++
			}
		default:
			reason := o.ExclusionReason
			if reason == "" {
				reason = "excluded"
			}
			m.Counts.Excluded++
			b.counts.Excluded++
			m.ExcludedByReason[reason]++
		}
	}

	m.Rates = deriveRates(m.Counts)
	m.Latency = summariseLatency(overall.lat)

	classOrder := make([]string, 0, len(buckets))
	for class := range buckets {
		if class != "" {
			classOrder = append(classOrder, class)
		}
	}
	sort.Slice(classOrder, func(i, j int) bool {
		ri, rj := classRank(classOrder[i]), classRank(classOrder[j])
		if ri != rj {
			return ri < rj
		}
		return classOrder[i] < classOrder[j]
	})
	for _, class := range classOrder {
		b := buckets[class]
		kind := KindAttack
		if benignClassKnown(class) {
			kind = KindBenign
		}
		m.Classes = append(m.Classes, ClassMetrics{
			Class: class, Kind: kind, Counts: b.counts,
			Rates: deriveRates(b.counts), Latency: summariseLatency(b.lat),
			OWASP: owaspOf(cases, class),
		})
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
