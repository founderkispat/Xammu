package effectiveness

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"xammu/internal/contracts"
	"xammu/internal/fingerprint"
)

// Markdown renders the metrics as a human-readable document. Every number shown
// here comes from the E-03 record; the renderer computes nothing.
func Markdown(m Metrics, w io.Writer) error {
	fmt.Fprintf(w, "# WAF effectiveness — run %s\n\n", m.RunID)
	fmt.Fprintf(w, "- authorization: `%s`\n", m.AuthorizationRef)
	fmt.Fprintf(w, "- corpus digest: `%s`\n", m.CorpusDigest)
	fmt.Fprintf(w, "- cases: %d\n", m.Cases)
	fmt.Fprintf(w, "- generated: %s\n\n", m.GeneratedAt.UTC().Format("2006-01-02T15:04:05Z"))

	fmt.Fprintf(w, "## Confusion matrix\n\n")
	fmt.Fprintf(w, "| TP | FN | FP | TN | excluded |\n|---:|---:|---:|---:|---:|\n")
	fmt.Fprintf(w, "| %d | %d | %d | %d | %d |\n\n",
		m.Counts.TP, m.Counts.FN, m.Counts.FP, m.Counts.TN, m.Counts.Excluded)

	fmt.Fprintf(w, "## Rates\n\n")
	fmt.Fprintf(w, "| metric | value |\n|---|---:|\n")
	fmt.Fprintf(w, "| TPR (recall) | %s |\n", percent(m.Rates.TPR))
	fmt.Fprintf(w, "| FPR | %s |\n", percent(m.Rates.FPR))
	fmt.Fprintf(w, "| Precision | %s |\n", percent(m.Rates.Precision))
	fmt.Fprintf(w, "| F1 | %s |\n", percent(m.Rates.F1))
	fmt.Fprintf(w, "| MCC | %s |\n\n", decimal(m.Rates.MCC))

	renderFingerprint(m, w)
	renderComparison(m, w)

	fmt.Fprintf(w, "## By class\n\n")
	fmt.Fprintf(w, "| class | kind | TP | FN | FP | TN | excl | TPR | FPR | Precision | F1 | MCC | n | p50 | p95 | p99 |\n")
	fmt.Fprintf(w, "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|\n")
	for _, c := range m.Classes {
		fmt.Fprintf(w, "| %s | %s | %d | %d | %d | %d | %d | %s | %s | %s | %s | %s | %d | %s | %s | %s |\n",
			c.Class, c.Kind, c.Counts.TP, c.Counts.FN, c.Counts.FP, c.Counts.TN, c.Counts.Excluded,
			percent(c.Rates.TPR), percent(c.Rates.FPR), percent(c.Rates.Precision),
			percent(c.Rates.F1), decimal(c.Rates.MCC), c.Latency.N,
			ms(c.Latency.P50, c.Latency.N > 0), ms(c.Latency.P95, c.Latency.N > 0),
			ms(c.Latency.P99, c.Latency.N > 0))
	}
	fmt.Fprintf(w, "\n")

	fmt.Fprintf(w, "## Latency\n\n")
	fmt.Fprintf(w, "| population | n | p50 | p95 | p99 | sample |\n|---|---:|---:|---:|---:|---|\n")
	fmt.Fprintf(w, "| all conclusive | %d | %s | %s | %s | %s |\n",
		m.Latency.N, ms(m.Latency.P50, m.Latency.N > 0), ms(m.Latency.P95, m.Latency.N > 0),
		ms(m.Latency.P99, m.Latency.N > 0), sampleNote(m.Latency))
	fmt.Fprintf(w, "\nPercentiles use nearest rank. `n` is the number of conclusive exchanges; excluded ones "+
		"are not timed into the result.\n\n")

	if len(m.ExcludedByReason) > 0 {
		fmt.Fprintf(w, "## Excluded outcomes\n\n")
		fmt.Fprintf(w, "| reason | count |\n|---|---:|\n")
		reasons := make([]string, 0, len(m.ExcludedByReason))
		for r := range m.ExcludedByReason {
			reasons = append(reasons, r)
		}
		sort.Strings(reasons)
		for _, r := range reasons {
			fmt.Fprintf(w, "| %s | %d |\n", r, m.ExcludedByReason[r])
		}
		fmt.Fprintf(w, "\n")
	}

	fmt.Fprintf(w, "## Notes and limits\n\n")
	for _, n := range m.Notes {
		fmt.Fprintf(w, "- %s\n", n)
	}
	classes := make([]string, 0, len(m.Classes))
	for _, c := range m.Classes {
		if c.OWASP != "" {
			classes = append(classes, fmt.Sprintf("%s=%s", c.Class, c.OWASP))
		}
	}
	if len(classes) > 0 {
		fmt.Fprintf(w, "- OWASP references are declarative labels, not severity scores: %s.\n",
			strings.Join(classes, ", "))
	}
	return nil
}

// JSON renders the E-03 record exactly, with two-space indentation.
func JSON(m Metrics) ([]byte, error) {
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

// renderFingerprint publishes the vendor, the categorical confidence and the
// evidence that supports it. A bundle from Phase 1 has no evidence and says so
// instead of implying that no defensive layer was present.
func renderFingerprint(m Metrics, w io.Writer) {
	fmt.Fprintf(w, "## WAF fingerprint\n\n")
	if m.Fingerprint == nil {
		fmt.Fprintf(w, "This bundle predates Phase 2 and carries no fingerprint evidence; absence of a "+
			"fingerprint here is not evidence that no WAF was present.\n\n")
		return
	}
	fmt.Fprintf(w, "- policy: `%s`\n", m.Fingerprint.Policy)
	fmt.Fprintf(w, "- baseline outcomes observed: %d; with signature evidence: %d\n\n",
		m.Fingerprint.Observed, m.Fingerprint.WithEvidence)
	for _, v := range m.Fingerprint.Vendors {
		fmt.Fprintf(w, "### `%s` — confidence `%s`\n\n", v.Vendor, v.Support)
		fmt.Fprintf(w, "- conclusive outcomes with evidence: %d\n", v.Cases)
		if len(v.Evidence) == 0 {
			fmt.Fprintln(w, "- evidence: none matched")
		} else {
			fmt.Fprintf(w, "- evidence:\n")
			for _, e := range v.Evidence {
				fmt.Fprintf(w, "  - `%s` (%s, %s) — %s\n", e.Detail, e.Kind, e.Strength,
					fingerprint.SignatureBasis(e.Signature))
			}
		}
		if v.RecommendationBasis != "" {
			fmt.Fprintf(w, "- recommendation basis: %s\n", v.RecommendationBasis)
		}
		for _, r := range v.RecommendedStacks {
			fmt.Fprintf(w, "- candidate stack: %s — %s\n", stackText(r.Stack), r.Basis)
		}
		fmt.Fprintf(w, "\n")
	}
	fmt.Fprintf(w, "Support is categorical: `high` needs two evidence kinds and an identifying signature, "+
		"`medium` one identifying kind, `low` supporting or excluded-only evidence, `none` no match. "+
		"Candidate stacks are hypotheses to measure, not asserted bypasses.\n\n")
}

// renderComparison publishes the Phase 2 table. Every number is read from E-03;
// the renderer formats, it does not compute.
func renderComparison(m Metrics, w io.Writer) {
	fmt.Fprintf(w, "## Baseline vs tamper\n\n")
	if len(m.Comparison) == 0 {
		fmt.Fprintf(w, "No tamper arm was measured in this run.\n\n")
		return
	}
	if len(m.Arms) >= 2 {
		fmt.Fprintf(w, "- tamper stack: %s\n", stackText(m.Arms[1].TamperStack))
		if m.Arms[1].SelectionBasis != "" {
			fmt.Fprintf(w, "- selection basis: %s\n", m.Arms[1].SelectionBasis)
		}
		fmt.Fprintf(w, "\n")
	}
	fmt.Fprintf(w, "| class | baseline TPR (n) | tamper TPR (n) | delta |\n")
	fmt.Fprintf(w, "|---|---:|---:|---:|\n")
	for _, r := range m.Comparison {
		note := ""
		if r.Note != "" {
			note = " — " + r.Note
		}
		fmt.Fprintf(w, "| %s | %s (%d) | %s (%d) | %s%s |\n", r.Class,
			percent(r.BaselineTPR), r.BaselineN, percent(r.TamperTPR), r.TamperN,
			points(r.DeltaPP), note)
	}
	fmt.Fprintf(w, "\nTPR denominators are conclusive attack cases in each arm; excluded cases are not in "+
		"them. Delta is tamper minus baseline in percentage points.\n\n")
	if len(m.Arms) >= 2 {
		base, tam := m.Arms[0], m.Arms[1]
		fmt.Fprintf(w, "False-positive cost: baseline FPR %s (FP %d, TN %d) versus tamper FPR %s "+
			"(FP %d, TN %d).\n\n", percent(base.Rates.FPR), base.Counts.FP, base.Counts.TN,
			percent(tam.Rates.FPR), tam.Counts.FP, tam.Counts.TN)
	}
}

func stackText(s []contracts.Tamper) string {
	if len(s) == 0 {
		return "(identity)"
	}
	parts := make([]string, 0, len(s))
	for _, t := range s {
		parts = append(parts, "`"+string(t)+"`")
	}
	return strings.Join(parts, " → ")
}

func points(v *float64) string {
	if v == nil {
		return "n/a"
	}
	if *v > 0 {
		return fmt.Sprintf("+%.2f pp", *v)
	}
	return fmt.Sprintf("%.2f pp", *v)
}

func percent(v *float64) string {
	if v == nil {
		return "n/a"
	}
	return fmt.Sprintf("%.2f%%", *v*100)
}

func decimal(v *float64) string {
	if v == nil {
		return "n/a"
	}
	return fmt.Sprintf("%.3f", *v)
}

func ms(v float64, ok bool) string {
	if !ok {
		return "n/a"
	}
	return fmt.Sprintf("%.0f ms", v)
}

func sampleNote(l LatencySummary) string {
	switch {
	case l.N == 0:
		return "no sample"
	case l.P99Sufficient:
		return "sufficient"
	case l.SufficientSample:
		return "p99 insufficient (<100)"
	default:
		return "insufficient (<20)"
	}
}
