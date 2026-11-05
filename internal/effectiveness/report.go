package effectiveness

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
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
