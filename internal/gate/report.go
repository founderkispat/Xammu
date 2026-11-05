package gate

import (
	"fmt"
	"sort"
	"strings"

	"xammu/internal/effectiveness"
	"xammu/internal/fingerprint"
)

// ReportOptions carries the delivery context a report can state without asking
// the evidence for it. PublicationDir is where `--format all` writes the
// envelope, so section 7 can name the command that verifies this delivery; it
// is empty for an ephemeral stdout rendering.
type ReportOptions struct {
	PublicationDir string
}

// ReportMarkdown renders the professional report from the same document the
// machine formats use. It computes nothing: every figure is a field of the
// document, and a missing denominator is printed "n/a", never zero.
func ReportMarkdown(d *Document, opts ReportOptions) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# XAMMU effectiveness gate report - run %s\n\n", d.Source.RunID)
	writeExecutive(&b, d)
	writeScope(&b, d)
	writeMetrics(&b, d)
	writeControls(&b, d)
	writeFindings(&b, d)
	writeLimits(&b, d)
	writeSeal(&b, d, opts)
	return b.String()
}

func writeExecutive(b *strings.Builder, d *Document) {
	b.WriteString("## 1. Executive summary\n\n")
	fmt.Fprintf(b, "- Verdict: **%s**\n", strings.ToUpper(d.Verdict))
	failed := failedIn(d.Checks)
	if len(failed) == 0 {
		b.WriteString("- Failed checks: none\n")
	} else {
		fmt.Fprintf(b, "- Failed checks: %s\n", strings.Join(failed, ", "))
	}
	fmt.Fprintf(b, "- Policy: `%s` (%s)\n", d.Policy.SHA256, d.Policy.SchemaVersion)
	if m := d.Metrics; m != nil {
		fmt.Fprintf(b, "- TPR: %s; FPR: %s; Precision: %s; F1: %s; MCC: %s\n",
			rateText(m.Rates.TPR), rateText(m.Rates.FPR), rateText(m.Rates.Precision),
			rateText(m.Rates.F1), rateText(m.Rates.MCC))
		fmt.Fprintf(b, "- Latency: p50 %s, p95 %s, p99 %s ms over n=%d (%s)\n",
			millis(m.Latency.P50), millis(m.Latency.P95), millis(m.Latency.P99), m.Latency.N,
			sampleText(m.Latency.SufficientSample, m.Latency.P99Sufficient))
		fmt.Fprintf(b, "- Fingerprint: %s\n", fingerprintText(m.Fingerprint))
		if namesReferenceFixture(m.Fingerprint) {
			b.WriteString("- Target: the repository's reference fixture, calibrated against this " +
				"corpus; these figures demonstrate the pipeline, not a real product's efficacy.\n")
		}
	} else {
		counts := map[string]int{}
		for _, f := range d.Findings {
			counts[f.Priority]++
		}
		fmt.Fprintf(b, "- Sealed findings: %d (high %d, medium %d, low %d)\n",
			len(d.Findings), counts["high"], counts["medium"], counts["low"])
	}
	if d.Verdict == VerdictPass {
		fmt.Fprintf(b, "\nThe run meets the thresholds configured for this corpus and this origin. "+
			"That is a policy decision over %d applicable check(s), not a general security assertion.\n\n",
			applicableIn(d.Checks))
	} else {
		fmt.Fprintf(b, "\nThe run does not meet the thresholds configured for this corpus and this "+
			"origin. The verdict is a policy decision over the sealed evidence, not a claim that the "+
			"target is exploitable.\n\n")
	}
}

func writeScope(b *strings.Builder, d *Document) {
	b.WriteString("## 2. Scope and evidence\n\n")
	rows := [][]string{
		{"Source kind", d.Source.Kind},
		{"Run", d.Source.RunID},
		{"Bundle", d.Source.Bundle},
		{"Manifest sha256", d.Source.ManifestSHA256},
		{"Manifest signer key id", d.Source.ManifestSignerKeyID},
	}
	if m := d.Metrics; m != nil {
		rows = append(rows,
			[]string{"Authorization", m.AuthorizationRef},
			[]string{"Corpus digest", m.CorpusDigest},
			[]string{"Cases measured", fmt.Sprint(m.Cases)},
			[]string{"Arms", strings.Join(armNames(m), ", ")},
		)
	}
	writeTable(b, []string{"Field", "Value"}, rows)
	b.WriteString("The artifacts below are the files the signed manifest covers; the gate read " +
		"exactly these digests.\n\n")
	paths := make([]string, 0, len(d.Source.Artifacts))
	for path := range d.Source.Artifacts {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	rows = rows[:0]
	for _, path := range paths {
		rows = append(rows, []string{path, d.Source.Artifacts[path]})
	}
	writeTable(b, []string{"Artifact", "sha256"}, rows)
}

func writeMetrics(b *strings.Builder, d *Document) {
	b.WriteString("## 3. Metrics\n\n")
	m := d.Metrics
	if m == nil {
		b.WriteString("This bundle carries profiling findings and no E-03 effectiveness metrics.\n\n")
		return
	}
	b.WriteString("### Confusion matrix\n\n")
	writeTable(b, []string{"TP", "FN", "FP", "TN", "Excluded", "Cases"}, [][]string{{
		fmt.Sprint(m.Counts.TP), fmt.Sprint(m.Counts.FN), fmt.Sprint(m.Counts.FP),
		fmt.Sprint(m.Counts.TN), fmt.Sprint(m.Counts.Excluded), fmt.Sprint(m.Cases),
	}})
	b.WriteString("Excluded exchanges are reported beside the matrix and never inside a " +
		"denominator. A null rate means the denominator was zero.\n\n")

	b.WriteString("### Rates\n\n")
	writeTable(b, []string{"Metric", "Value", "Denominator"}, [][]string{
		{"TPR", rateText(m.Rates.TPR), tprDenom(m.Counts)},
		{"FPR", rateText(m.Rates.FPR), fprDenom(m.Counts)},
		{"Precision", rateText(m.Rates.Precision), precisionDenom(m.Counts)},
		{"F1", rateText(m.Rates.F1), "harmonic mean of TPR and Precision"},
		{"MCC", rateText(m.Rates.MCC), "all four cells of the matrix"},
	})

	classes := make([]ClassView, 0, len(m.Classes))
	for _, c := range m.Classes {
		classes = append(classes, c)
	}
	sort.Slice(classes, func(i, j int) bool { return classes[i].Class < classes[j].Class })
	b.WriteString("### By class\n\n")
	rows := make([][]string, 0, len(classes))
	for _, c := range classes {
		rows = append(rows, []string{
			c.Class, string(c.Kind), fmt.Sprint(c.Counts.TP), fmt.Sprint(c.Counts.FN),
			fmt.Sprint(c.Counts.FP), fmt.Sprint(c.Counts.TN), fmt.Sprint(c.Counts.Excluded),
			rateText(c.Rates.TPR), rateText(c.Rates.FPR), rateText(c.Rates.Precision),
			c.OWASP,
		})
	}
	writeTable(b, []string{"Class", "Kind", "TP", "FN", "FP", "TN", "Excluded", "TPR", "FPR",
		"Precision", "OWASP"}, rows)

	b.WriteString("### Latency\n\n")
	writeTable(b, []string{"Population", "n", "p50 ms", "p95 ms", "p99 ms", "Sufficiency"},
		[][]string{{"all conclusive exchanges", fmt.Sprint(m.Latency.N), millis(m.Latency.P50),
			millis(m.Latency.P95), millis(m.Latency.P99),
			sampleText(m.Latency.SufficientSample, m.Latency.P99Sufficient)}})

	if len(m.Arms) > 0 {
		b.WriteString("### Arms\n\n")
		var names []string
		for name := range m.Arms {
			names = append(names, name)
		}
		sort.Strings(names)
		rows = rows[:0]
		for _, name := range names {
			a := m.Arms[name]
			stack := "none"
			if len(a.TamperStack) > 0 {
				stack = strings.Join(a.TamperStack, "+")
			}
			rows = append(rows, []string{name, stack, fmt.Sprint(a.Cases), rateText(a.Rates.TPR),
				rateText(a.Rates.FPR), rateText(a.Rates.Precision), fmt.Sprint(a.Latency.N)})
		}
		writeTable(b, []string{"Arm", "Tamper stack", "Cases", "TPR", "FPR", "Precision", "n"},
			rows)
	}
	if len(m.Comparison) > 0 {
		b.WriteString("### Baseline vs tamper\n\n")
		var names []string
		for name := range m.Comparison {
			names = append(names, name)
		}
		sort.Strings(names)
		rows = rows[:0]
		for _, name := range names {
			c := m.Comparison[name]
			rows = append(rows, []string{c.Class, pctText(c.BaselineTPR), fmt.Sprint(c.BaselineN),
				pctText(c.TamperTPR), fmt.Sprint(c.TamperN), deltaText(c.DeltaPP), c.Note})
		}
		writeTable(b, []string{"Class", "Baseline TPR", "Baseline n", "Tamper TPR", "Tamper n",
			"Delta", "Note"}, rows)
	}
}

func writeControls(b *strings.Builder, d *Document) {
	b.WriteString("## 4. Controls with evidence\n\n")
	ids := sortedMapKeys(d.Controls)
	rows := make([][]string, 0, len(ids))
	for _, id := range ids {
		c := d.Controls[id]
		rows = append(rows, []string{id, c.Expectation, c.Observed, c.Evidence, c.Status})
	}
	writeTable(b, []string{"Control", "Expectation", "Observed", "Evidence", "Status"}, rows)
	if len(d.NotApplicable) > 0 {
		b.WriteString("Checks that did not apply are listed so a reader sees they were not silently " +
			"ignored.\n\n")
		rows = rows[:0]
		for _, id := range sortedMapKeys(d.NotApplicable) {
			rows = append(rows, []string{id, d.NotApplicable[id]})
		}
		writeTable(b, []string{"Check", "Reason"}, rows)
	}
}

func writeFindings(b *strings.Builder, d *Document) {
	b.WriteString("## 5. Sealed C-16 findings\n\n")
	if len(d.Findings) == 0 {
		b.WriteString("This bundle publishes no C-16 finding.\n\n")
		return
	}
	ids := sortedMapKeys(d.Findings)
	fmt.Fprintf(b, "%d finding(s) are copied from the sealed findings.jsonl. Observed and inferred "+
		"statements are quoted verbatim; the gate does not turn a priority into a severity score.\n\n",
		len(ids))
	for _, ref := range ids {
		f := d.Findings[ref]
		fmt.Fprintf(b, "### %s - %s (%s)\n\n", f.Ref, f.FindingType, f.Priority)
		rows := [][]string{
			{"Priority basis", f.PriorityBasis},
			{"Claim", fmt.Sprintf("%s; evidence %s; attribution %s", f.ClaimType, f.EvidenceLevel,
				f.AttributionStatus)},
			{"Affected scope", f.AffectedScope},
			{"Measured impact", fmt.Sprintf("%d/%d (basis: %s)", f.MeasuredImpact.Numerator,
				f.MeasuredImpact.Denominator, f.MeasuredImpact.Basis)},
			{"Journal line", fmt.Sprint(f.Line)},
		}
		writeTable(b, []string{"Field", "Value"}, rows)
		fmt.Fprintf(b, "- **Observed:** %s\n", f.WhatWasObserved)
		fmt.Fprintf(b, "- **Inferred:** %s\n", f.WhatIsInferred)
		fmt.Fprintf(b, "- **Evidence missing:** %s\n", f.WhatEvidenceIsMissing)
		for _, limitation := range f.Limitations {
			fmt.Fprintf(b, "- **Limitation:** %s\n", limitation)
		}
		b.WriteString("\n")
		if f.ReproductionCommand != "" {
			fmt.Fprintf(b, "Reproduce:\n\n```\n%s\n```\n\n", strings.TrimSpace(f.ReproductionCommand))
		}
		if f.RegressionTest != "" {
			fmt.Fprintf(b, "Regression test:\n\n```\n%s\n```\n\n", strings.TrimSpace(f.RegressionTest))
		}
	}
}

func writeLimits(b *strings.Builder, d *Document) {
	b.WriteString("## 6. Explicit limits\n\n")
	for _, limit := range d.Limits {
		fmt.Fprintf(b, "- %s\n", limit)
	}
	b.WriteString("\n")
}

func writeSeal(b *strings.Builder, d *Document, opts ReportOptions) {
	b.WriteString("## 7. Reproduction and seal\n\n")
	verify := "xammu verify --store " + d.Source.Bundle
	if d.Source.Bundle == "" {
		verify = "xammu verify --run " + d.Source.RunID
	}
	fmt.Fprintf(b, "Verify the sealed evidence:\n\n```\n%s\n```\n\n", verify)
	dir := opts.PublicationDir
	if dir == "" {
		dir = "DIR"
	}
	fmt.Fprintf(b, "Verify this delivery and its Ed25519 envelope:\n\n```\n"+
		"xammu verify --publication %s --trust-key FILE\n```\n\n", dir)
	fmt.Fprintf(b, "The envelope (`publication.json`, `%s`) is signed by %s over "+
		"sha256(canonical-json(publication minus the signature fields)). It lists every delivered "+
		"file with its sha256, including this document. A document cannot contain the digest of the "+
		"envelope that hashes it, so the envelope digest is not printed here: `verify --publication` "+
		"recomputes it, prints it, and refuses any file that no longer matches.\n\n",
		PublicationSchemaVersion, PublicationSigningRule)
}

// --- helpers ---------------------------------------------------------------

func failedIn(checks map[string]Check) []string {
	var out []string
	for _, id := range checkOrder {
		if c, ok := checks[id]; ok && c.Status == StatusFail {
			out = append(out, id)
		}
	}
	return out
}

func applicableIn(checks map[string]Check) int {
	n := 0
	for _, c := range checks {
		if c.Applies {
			n++
		}
	}
	return n
}

func armNames(m *MetricsView) []string {
	names := make([]string, 0, len(m.Arms))
	for name := range m.Arms {
		names = append(names, name)
	}
	sort.Strings(names)
	if len(names) == 0 {
		return []string{"baseline"}
	}
	return names
}

func rateText(v *float64) string {
	if v == nil {
		return "n/a"
	}
	return formatRatio(*v)
}

func pctText(v *float64) string {
	if v == nil {
		return "n/a"
	}
	return fmt.Sprintf("%.2f%%", *v*100)
}

func deltaText(v *float64) string {
	if v == nil {
		return "n/a"
	}
	return formatDelta(v)
}

func millis(v float64) string {
	return fmt.Sprintf("%.2f", v)
}

func sampleText(sufficient, p99 bool) string {
	switch {
	case sufficient && p99:
		return "n>=100, p99 stable"
	case sufficient:
		return "n>=20, p99 describes fewer than 100 exchanges"
	default:
		return "n<20, tail figures describe a handful of exchanges"
	}
}

func fingerprintText(f *FingerprintView) string {
	if f == nil {
		return "no fingerprint recorded in this bundle"
	}
	if len(f.Vendors) == 0 {
		return "no vendor signature matched"
	}
	names := sortedMapKeys(f.Vendors)
	parts := make([]string, 0, len(names))
	for _, name := range names {
		v := f.Vendors[name]
		parts = append(parts, fmt.Sprintf("%s=%s (n=%d)", v.Vendor, v.Support, v.Cases))
	}
	return strings.Join(parts, ", ")
}

// namesReferenceFixture reports whether the fingerprint attributes the target to
// the repository's own fixture, whose rates measure the pipeline and not a
// product.
func namesReferenceFixture(f *FingerprintView) bool {
	if f == nil {
		return false
	}
	_, ok := f.Vendors[fingerprint.VendorReferenceFixture]
	return ok
}

func tprDenom(c effectiveness.Counts) string {
	return fmt.Sprintf("%d attacks: %d caught (TP), %d missed (FN)", c.TP+c.FN, c.TP, c.FN)
}

func fprDenom(c effectiveness.Counts) string {
	return fmt.Sprintf("%d benign: %d blocked (FP), %d allowed (TN)", c.FP+c.TN, c.FP, c.TN)
}

func precisionDenom(c effectiveness.Counts) string {
	return fmt.Sprintf("%d blocks: %d true (TP), %d false (FP)", c.TP+c.FP, c.TP, c.FP)
}

func sortedMapKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for key := range m {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

func writeTable(b *strings.Builder, header []string, rows [][]string) {
	write := func(cells []string) {
		b.WriteString("| ")
		for i, cell := range cells {
			if i > 0 {
				b.WriteString(" | ")
			}
			b.WriteString(strings.ReplaceAll(strings.Join(strings.Fields(cell), " "), "|", "\\|"))
		}
		b.WriteString(" |\n")
	}
	write(header)
	for range header {
		b.WriteString("| --- ")
	}
	b.WriteString("|\n")
	for _, row := range rows {
		cells := make([]string, len(header))
		copy(cells, row)
		for i := range cells {
			if cells[i] == "" {
				cells[i] = "-"
			}
		}
		write(cells)
	}
	b.WriteString("\n")
}
