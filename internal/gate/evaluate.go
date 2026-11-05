package gate

import (
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"xammu/internal/contracts"
	"xammu/internal/effectiveness"
	"xammu/internal/fingerprint"
)

// Evaluation is the document plus the process result. ExitCode is 0 when every
// applicable check passes and 1 when one fails; the CLI maps ErrUnusable to 2
// before this point.
type Evaluation struct {
	Document *Document
	ExitCode int
	Failed   []string
}

// checkOrder fixes the order a failure summary and the SARIF results use, so two
// runs of the gate over the same evidence list the same checks the same way.
var checkOrder = []string{
	"evidence.manifest", "evidence.rederive",
	"effectiveness.tpr", "effectiveness.fpr", "effectiveness.precision",
	"effectiveness.excluded_ratio", "findings.priority",
}

// Evaluate applies the policy to verified evidence. It computes no metric: every
// observed value comes from the sealed E-03 record or the sealed C-16 findings.
func Evaluate(ev *Evidence, policy *Policy, bundle string, anchored bool) (*Evaluation, error) {
	if ev.Kind == KindEffectiveness && policy.Effectiveness == nil {
		return nil, fmt.Errorf("%w: %s holds an effectiveness measurement, and the policy declares no "+
			"effectiveness thresholds; a findings-only policy cannot gate E-03", ErrUnusable,
			filepathSlash(ev.Dir))
	}
	if ev.Kind == KindProfiling && policy.Findings == nil {
		return nil, fmt.Errorf("%w: %s holds profiling findings, and the policy declares no findings "+
			"section; an effectiveness-only policy cannot gate C-16", ErrUnusable, filepathSlash(ev.Dir))
	}

	checks := map[string]Check{}
	limits := baseLimits()

	switch ev.Kind {
	case KindEffectiveness:
		m := ev.Metrics
		effectivenessEvidence := "effectiveness_metrics.jsonl"
		checks["effectiveness.tpr"] = minimumCheck("effectiveness.tpr", m.Rates.TPR,
			policy.Effectiveness.MinTPR, effectivenessEvidence)
		checks["effectiveness.fpr"] = maximumCheck("effectiveness.fpr", m.Rates.FPR,
			policy.Effectiveness.MaxFPR, effectivenessEvidence)
		if policy.Effectiveness.MinPrecision != nil {
			checks["effectiveness.precision"] = minimumCheck("effectiveness.precision", m.Rates.Precision,
				*policy.Effectiveness.MinPrecision, effectivenessEvidence)
		} else {
			checks["effectiveness.precision"] = notApplicableCheck("effectiveness.precision",
				"min_precision is not declared in the policy", effectivenessEvidence)
		}
		checks["effectiveness.excluded_ratio"] = excludedCheck(m,
			policy.Effectiveness.MaxExcludedRatio, effectivenessEvidence)
		checks["evidence.manifest"] = manifestCheck(anchored)
		checks["evidence.rederive"] = rederiveCheck(ev)
		for _, id := range []string{"effectiveness.tpr", "effectiveness.fpr",
			"effectiveness.precision", "effectiveness.excluded_ratio"} {
			c := checks[id]
			c.Line = ev.MetricsLine
			checks[id] = c
		}
		if policy.Findings != nil {
			checks["findings.priority"] = notApplicableCheck("findings.priority",
				"the bundle carries no sealed C-16 findings", "findings.jsonl")
		}
		limits = append(limits,
			"E-03 is recomputed from the E-01 case list and the E-02 outcome journal before any "+
				"threshold is evaluated; a disagreement is exit 2, not a verdict.",
			"Fingerprint support is a categorical reading of observed signatures, not a probability "+
				"and not a product claim.")
		if m.Fingerprint != nil {
			for _, v := range m.Fingerprint.Vendors {
				if v.Vendor == fingerprint.VendorReferenceFixture {
					limits = append(limits,
						"The target identified as the repository's reference fixture, a WAF calibrated "+
							"against this inert corpus. Its rates show that the pipeline measures; they "+
							"are not the efficacy of any real product.")
					break
				}
			}
		}
	case KindProfiling:
		checks["findings.priority"] = findingsCheck(ev.Findings, policy.Findings.FailOnPriority)
		checks["evidence.manifest"] = manifestCheck(anchored)
		checks["evidence.rederive"] = notApplicableCheck("evidence.rederive",
			"profiling findings are read from the sealed findings.jsonl; the gate does not re-derive them",
			"findings.jsonl")
		if policy.Effectiveness != nil {
			for _, id := range []string{"effectiveness.tpr", "effectiveness.fpr",
				"effectiveness.precision", "effectiveness.excluded_ratio"} {
				checks[id] = notApplicableCheck(id, "the bundle carries no E-03 effectiveness metrics",
					"effectiveness_metrics.jsonl")
			}
		}
		limits = append(limits,
			"Profiling findings are read from the sealed findings.jsonl; the gate does not re-derive "+
				"them and does not turn a priority into a severity score.")
	}

	if !anchored {
		limits = append(limits,
			"No trusted key was supplied: the manifest signature was checked against the public key "+
				"inside the same manifest, so the signer identity is not anchored.")
	}

	controls := map[string]Control{}
	notApplicable := map[string]string{}
	for id, check := range checks {
		controls[id] = controlFromCheck(check)
		if !check.Applies {
			// One place decides what "did not apply" means, so the checks table and
			// the not_applicable index cannot disagree.
			notApplicable[id] = check.Reason
		}
	}
	addInformationalControls(controls, ev)

	failed := failedChecks(checks)
	verdict, exitCode := VerdictPass, 0
	if len(failed) > 0 {
		verdict, exitCode = VerdictFail, 1
	}

	doc := &Document{
		SchemaVersion: SchemaVersion,
		ToolVersion:   toolVersion(),
		Source:        ev.sourceView(bundle),
		Policy:        policyView(policy),
		Verdict:       verdict,
		Checks:        checks,
		Findings:      map[string]FindingView{},
		Controls:      controls,
		Limits:        limits,
		NotApplicable: notApplicable,
	}
	if ev.Metrics != nil {
		doc.Metrics = metricsView(*ev.Metrics)
	}
	for _, sealed := range ev.Findings {
		doc.Findings[uniqueKey(doc.Findings, sealed.Finding.Ref)] =
			findingView(sealed.Finding, sealed.Line)
	}
	return &Evaluation{Document: doc, ExitCode: exitCode, Failed: failed}, nil
}

func minimumCheck(id string, observed *float64, minimum float64, evidence string) Check {
	c := Check{ID: id, Applies: true, Status: StatusPass,
		Threshold: ">= " + formatNumber(minimum), Evidence: evidence}
	if observed == nil {
		c.Status = StatusFail
		c.Observed = "n/a"
		c.Reason = reasonNoDenominator
		return c
	}
	c.Observed = formatRatio(*observed)
	if *observed < minimum {
		c.Status = StatusFail
		c.Reason = "below the configured minimum"
	}
	return c
}

func maximumCheck(id string, observed *float64, maximum float64, evidence string) Check {
	c := Check{ID: id, Applies: true, Status: StatusPass,
		Threshold: "<= " + formatNumber(maximum), Evidence: evidence}
	if observed == nil {
		c.Status = StatusFail
		c.Observed = "n/a"
		c.Reason = reasonNoDenominator
		return c
	}
	c.Observed = formatRatio(*observed)
	if *observed > maximum {
		c.Status = StatusFail
		c.Reason = "above the configured maximum"
	}
	return c
}

func excludedCheck(m *effectiveness.Metrics, maximum float64, evidence string) Check {
	c := Check{ID: "effectiveness.excluded_ratio", Applies: true, Status: StatusPass,
		Threshold: "<= " + formatNumber(maximum), Evidence: evidence}
	if m.Cases == 0 {
		c.Status = StatusFail
		c.Observed = "n/a"
		c.Reason = reasonNoDenominator
		return c
	}
	ratio := float64(m.Counts.Excluded) / float64(m.Cases)
	c.Observed = fmt.Sprintf("%d/%d = %s", m.Counts.Excluded, m.Cases, formatRatio(ratio))
	if ratio > maximum {
		c.Status = StatusFail
		c.Reason = "above the configured maximum"
	}
	return c
}

func findingsCheck(findings []SealedFinding, failOn contracts.Priority) Check {
	c := Check{ID: "findings.priority", Applies: true, Status: StatusPass,
		Threshold: "none at or above " + string(failOn), Evidence: "findings.jsonl"}
	floor := priorityRank(failOn)
	var crossed []string
	for _, f := range findings {
		if priorityRank(f.Finding.Priority) >= floor {
			crossed = append(crossed, f.Finding.Ref)
		}
	}
	sort.Strings(crossed)
	c.Observed = fmt.Sprintf("%d of %d sealed finding(s) at or above %s",
		len(crossed), len(findings), failOn)
	if len(crossed) > 0 {
		c.Status = StatusFail
		c.Reason = "finding(s) at or above the configured priority: " + strings.Join(firstN(crossed, 5), ", ")
		if len(crossed) > 5 {
			c.Reason += fmt.Sprintf(" and %d more", len(crossed)-5)
		}
	}
	return c
}

func manifestCheck(anchored bool) Check {
	reason := "manifest, inventory, merkle root and hash chains verify"
	if anchored {
		reason += "; signer identity anchored by a trusted key"
	} else {
		reason += "; signature is self-consistent, identity unanchored"
	}
	return Check{ID: "evidence.manifest", Applies: true, Status: StatusPass,
		Reason: reason, Evidence: "manifest.json"}
}

func rederiveCheck(ev *Evidence) Check {
	reason := "E-03 recomputes from E-01/E-02 and matches the journaled record"
	if ev.PublishedMetricsOK {
		reason += " and the published metrics document"
	}
	return Check{ID: "evidence.rederive", Applies: true, Status: StatusPass, Reason: reason,
		Evidence: "effectiveness_cases.jsonl, effectiveness_outcomes.jsonl, effectiveness_metrics.jsonl"}
}

func notApplicableCheck(id, reason, evidence string) Check {
	return Check{ID: id, Applies: false, Status: StatusNotApplicable, Reason: reason, Evidence: evidence}
}

func controlFromCheck(c Check) Control {
	expectation := c.Threshold
	if expectation == "" {
		expectation = c.Reason
	}
	observed := c.Observed
	if observed == "" {
		observed = "n/a"
	}
	return Control{Expectation: expectation, Observed: observed, Evidence: c.Evidence, Status: c.Status}
}

func addInformationalControls(controls map[string]Control, ev *Evidence) {
	m := ev.Metrics
	if m != nil {
		if row, ok := comparisonRow(m.Comparison, "all attack classes"); ok {
			controls["comparison.base_vs_tamper"] = Control{
				Expectation: "informational: tamper minus baseline, no threshold",
				Observed: fmt.Sprintf("baseline TPR %s (n=%d); tamper TPR %s (n=%d); delta %s",
					formatPct(row.BaselineTPR), row.BaselineN, formatPct(row.TamperTPR), row.TamperN,
					formatDelta(row.DeltaPP)),
				Evidence: "effectiveness_metrics.jsonl (E-03 comparison)",
				Status:   StatusInfo,
			}
		}
		if m.Fingerprint != nil {
			parts := make([]string, 0, len(m.Fingerprint.Vendors))
			for _, v := range m.Fingerprint.Vendors {
				parts = append(parts, fmt.Sprintf("%s=%s", v.Vendor, v.Support))
			}
			sort.Strings(parts)
			observed := "no vendor signature matched"
			if len(parts) > 0 {
				observed = strings.Join(parts, ", ")
			}
			controls["fingerprint.attribution"] = Control{
				Expectation: "informational: categorical support, not a probability",
				Observed:    observed,
				Evidence:    "effectiveness_metrics.jsonl (E-03 fingerprint)",
				Status:      StatusInfo,
			}
		}
	}
	if ev.Kind == KindProfiling {
		counts := map[contracts.Priority]int{}
		for _, f := range ev.Findings {
			counts[f.Finding.Priority]++
		}
		controls["findings.inventory"] = Control{
			Expectation: "informational: inventory of sealed C-16 findings",
			Observed: fmt.Sprintf("%d sealed finding(s): %d high, %d medium, %d low",
				len(ev.Findings), counts[contracts.PriorityHigh],
				counts[contracts.PriorityMedium], counts[contracts.PriorityLow]),
			Evidence: "findings.jsonl",
			Status:   StatusInfo,
		}
	}
}

func comparisonRow(rows []effectiveness.ComparisonRow, class string) (effectiveness.ComparisonRow, bool) {
	for _, r := range rows {
		if r.Class == class {
			return r, true
		}
	}
	return effectiveness.ComparisonRow{}, false
}

func failedChecks(checks map[string]Check) []string {
	var out []string
	for _, id := range checkOrder {
		if c, ok := checks[id]; ok && c.Status == StatusFail {
			out = append(out, id)
		}
	}
	return out
}

func priorityRank(p contracts.Priority) int {
	switch p {
	case contracts.PriorityHigh:
		return 3
	case contracts.PriorityMedium:
		return 2
	case contracts.PriorityLow:
		return 1
	default:
		return 0
	}
}

func baseLimits() []string {
	return []string{
		"The gate reads sealed evidence; it sends no traffic and does not modify the bundle.",
		"Rates describe agreement with this corpus, on this target, in this window; they are not a " +
			"claim of absolute efficacy.",
		"The verdict is a policy decision over declared thresholds; it does not state that the WAF " +
			"is secure.",
		"A zero-denominator metric is null: the check fails with reason \"no denominator\" and the " +
			"null is never read as zero or one.",
		"C-16 priorities are high, medium and low; XAMMU does not add a critical level the evidence " +
			"does not have.",
		"The SARIF document is validated structurally against 2.1.0, not against the complete OASIS " +
			"JSON Schema.",
	}
}

func formatNumber(v float64) string {
	return strconv.FormatFloat(v, 'g', -1, 64)
}

func formatRatio(v float64) string {
	return fmt.Sprintf("%s (%.2f%%)", formatNumber(v), v*100)
}

func formatPct(v *float64) string {
	if v == nil {
		return "n/a"
	}
	return fmt.Sprintf("%.2f%%", *v*100)
}

func formatDelta(v *float64) string {
	if v == nil {
		return "n/a"
	}
	if *v > 0 {
		return fmt.Sprintf("+%.2f pp", *v)
	}
	return fmt.Sprintf("%.2f pp", *v)
}

func firstN(in []string, n int) []string {
	if len(in) <= n {
		return in
	}
	return in[:n]
}

func filepathSlash(p string) string { return filepath.ToSlash(p) }
