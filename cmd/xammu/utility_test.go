package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"xammu/internal/contracts"
	"xammu/internal/labctl"
)

// The utility gate is the acceptance test the handoff added on top of schema
// validation: a finding can satisfy C-16 and still be useless to the engineer who
// has to act on it. This test drives the real `report` command over the shipped
// demonstration bundle and asks, per finding, the question a reader asks: what do I
// do with this, how do I check it, how strong is it, and what is it not saying?
//
// It runs through dispatch rather than reading report.json directly because the
// promise is about the command an operator types, and because a hand-edited
// document could pass a test that only parses the file.

const demoRun = "demo-lab"

func TestTheDemonstrationBundlePassesTheUtilityGate(t *testing.T) {
	root := filepath.Join("..", "..")
	if _, err := os.Stat(filepath.Join(root, "runs", demoRun, "manifest.json")); err != nil {
		t.Fatalf("the demonstration bundle runs/%s ships with the delivery: %v", demoRun, err)
	}
	rep := readDemoReport(t, root)

	if rep.RunID != demoRun {
		t.Fatalf("the report is about run %q, not %q", rep.RunID, demoRun)
	}
	if rep.RunState != contracts.StateCompleted {
		t.Fatalf("the demonstration run is published as %q; a truncated demonstration cannot stand "+
			"for a completed measurement", rep.RunState)
	}
	if len(rep.Dimensions) != 5 {
		t.Fatalf("the report is a five-dimension document, got %d", len(rep.Dimensions))
	}
	if len(rep.Findings) == 0 {
		t.Fatal("the demonstration published no finding, so this gate would assert nothing")
	}
	if len(rep.OutOfScope) == 0 {
		t.Fatal("every report has to disclaim application vulnerabilities")
	}

	// Criterion 8: the seven questions, each with something actually said about it.
	answered := map[int]bool{}
	for _, d := range rep.Dimensions {
		if len(d.Statements) == 0 {
			t.Errorf("dimension %q answers %v with no statement", d.Kind, d.Questions)
		}
		for _, q := range d.Questions {
			answered[q] = true
		}
	}
	for q := 1; q <= 7; q++ {
		if !answered[q] {
			t.Errorf("the report never answers question %d of the handoff's seven", q)
		}
	}

	// Criterion 12: the class x vector matrix is present, and a measured cell carries
	// its denominator while an unmeasured one is named.
	if len(rep.Matrix.Cells) == 0 || len(rep.Matrix.Classes) == 0 || len(rep.Matrix.Vectors) == 0 {
		t.Fatalf("the report has no class x vector matrix: %+v", rep.Matrix)
	}
	for _, c := range rep.Matrix.Cells {
		if c.Aggregate.Basis == "" || c.Aggregate.Denominator == 0 {
			t.Errorf("cell %s x %s has no measured denominator: %+v", c.Class, c.Vector, c.Aggregate)
		}
	}
	if len(rep.Matrix.NotMeasured) == 0 && rep.UnevaluatedNone {
		t.Error("the demonstration measured every cell and declared no blind spot; a one-budget run " +
			"over a 48-cell grid cannot honestly have neither")
	}

	// Criterion 14: unevaluated zones are always present, even when the answer is none.
	if len(rep.Unevaluated) == 0 && !rep.UnevaluatedNone {
		t.Error("the report neither lists an unevaluated zone nor declares that there is none")
	}
	for _, z := range rep.Unevaluated {
		if z.Reason == "" || z.Remediation == "" || z.ReproductionCommand == "" {
			t.Errorf("unevaluated zone %q is not actionable: %+v", z.Scope, z)
		}
	}

	// Criterion 15: three separate residual-risk statements, not one aggregate.
	risk := rep.ResidualRisk
	if risk.ConditionalRisk.Statement == "" {
		t.Error("the conditional-exposure scenario is absent")
	}
	if risk.ConditionNotDemonstrated.Statement == "" {
		t.Error("the not-demonstrated scenario is absent; merging it into the conditional one is " +
			"how a report implies it tested the application")
	}
	if risk.Undeterminable.Statement == "" {
		t.Error("the undeterminable scenario is absent")
	}

	// Criteria 9-11, 13 and the utility rule, finding by finding.
	scenarios := shippedScenarios(t, root)
	measured := 0
	for _, f := range rep.Findings {
		assertDecisionPacket(t, f, scenarios)
		switch f.FindingType {
		case contracts.FindingCoverageGap, contracts.FindingOverBlocking,
			contracts.FindingVectorAsymmetry, contracts.FindingEncodingBypass:
			measured++
		}
	}
	if measured == 0 {
		t.Error("the demonstration published no measured finding, so the gate exercised only the " +
			"absence path")
	}

	// Criterion 19: this run had no source outside the HTTP response, so a confirmed
	// attribution would be a claim the evidence cannot carry.
	for _, f := range rep.Findings {
		if f.AttributionStatus == contracts.AttributionConfirmed {
			t.Errorf("finding %s claims confirmed_by_correlated_evidence from a run with no correlated "+
				"source outside the response", f.Ref)
		}
	}
}

// assertDecisionPacket is the per-finding half of the gate. Each assertion is one
// thing the engineer needs in order to decide on Monday morning.
func assertDecisionPacket(t *testing.T, f contracts.DiscoveryFinding, scenarios *labctl.Manifest) {
	t.Helper()

	// What was done, what is inferred, what is missing, and what this does not show.
	for field, value := range map[string]string{
		"what_was_observed":        f.WhatWasObserved,
		"what_is_inferred":         f.WhatIsInferred,
		"what_evidence_is_missing": f.WhatEvidenceIsMissing,
	} {
		if strings.TrimSpace(value) == "" {
			t.Errorf("finding %s (%s) has no %s", f.Ref, f.FindingType, field)
		}
	}
	if len(f.Limitations) == 0 {
		t.Errorf("finding %s states no limitation, so a reader cannot tell what it does not demonstrate",
			f.Ref)
	}

	// A stance and an evidence level, not a number that pretends to summarise them.
	if f.ClaimType == "" || f.AttributionStatus == "" || f.EvidenceBasis == "" || f.EvidenceLevel == "" {
		t.Errorf("finding %s has no stance: claim=%q attribution=%q basis=%q level=%q",
			f.Ref, f.ClaimType, f.AttributionStatus, f.EvidenceBasis, f.EvidenceLevel)
	}

	// Priority must say where it came from. Measured findings cite a quantity; an
	// undetermined area says, in words, that there was nothing to rank.
	if strings.TrimSpace(f.PriorityBasis) == "" {
		t.Errorf("finding %s states priority %q with no basis", f.Ref, f.Priority)
	}
	if f.FindingType != contracts.FindingUndeterminedArea &&
		!strings.ContainsAny(f.PriorityBasis, "0123456789") {
		t.Errorf("finding %s ranks %q without a measured quantity: %q", f.Ref, f.Priority,
			f.PriorityBasis)
	}
	if f.Priority != contracts.PriorityLow && f.MeasuredImpact.IsEmpty() {
		t.Errorf("finding %s is %q with no measured impact behind it", f.Ref, f.Priority)
	}

	// Coverage findings carry population and denominator (criterion 13).
	switch f.FindingType {
	case contracts.FindingCoverageGap, contracts.FindingOverBlocking,
		contracts.FindingVectorAsymmetry, contracts.FindingEncodingBypass:
		if f.MeasuredImpact.Denominator <= 0 {
			t.Errorf("finding %s is a coverage statement with no denominator: %+v", f.Ref,
				f.MeasuredImpact)
		}
		if strings.TrimSpace(f.MeasuredImpact.Basis) == "" {
			t.Errorf("finding %s does not say what its denominator counts", f.Ref)
		}
		if f.MeasuredImpact.Numerator > f.MeasuredImpact.Denominator {
			t.Errorf("finding %s counts %d out of %d", f.Ref, f.MeasuredImpact.Numerator,
				f.MeasuredImpact.Denominator)
		}
	}

	// The recommendation is an action, not a restatement of the finding.
	if words := len(strings.Fields(f.Recommendation)); words < 8 {
		t.Errorf("finding %s recommends %q: %d word(s) is a label, not an instruction", f.Ref,
			f.Recommendation, words)
	}
	for _, placeholder := range []string{"N/A", "TODO", "TBD", "FIXME", "<", ">"} {
		if strings.Contains(f.Recommendation, placeholder) {
			t.Errorf("finding %s recommends a placeholder (%q): %q", f.Ref, placeholder,
				f.Recommendation)
		}
	}

	// The note has to be readable without the contract vocabulary.
	if n := len(f.SecurityEngineerNote); n < 40 {
		t.Errorf("finding %s has a %d-character engineer note; it has to say something a reader can "+
			"act on: %q", f.Ref, n, f.SecurityEngineerNote)
	}
	for _, internal := range []string{
		"claim_type", "attribution_status", "evidence_level", "evidence_profile_ref",
		"finding_type", "reproduction_command", "measured_impact",
	} {
		if strings.Contains(f.SecurityEngineerNote, internal) {
			t.Errorf("finding %s explains itself with the internal field name %q: %q", f.Ref,
				internal, f.SecurityEngineerNote)
		}
	}

	// The regression step has to be one a reader can actually take.
	if strings.TrimSpace(f.RegressionTest) == "" {
		t.Errorf("finding %s has no regression step, so nobody can re-check it after a change", f.Ref)
	} else if name, ok := strings.CutPrefix(f.RegressionTest, "xammu lab test --scenario "); ok {
		if _, found := scenarios.Find(name); !found {
			t.Errorf("finding %s names laboratory scenario %q, which this repository does not ship",
				f.Ref, name)
		}
	} else if strings.HasPrefix(f.RegressionTest, "xammu playbook ") {
		if !strings.Contains(f.RegressionTest, "--authorization") {
			t.Errorf("finding %s widens the scope with an unbound playbook step: %q", f.Ref,
				f.RegressionTest)
		}
	} else {
		t.Errorf("finding %s publishes a step this tool cannot run: %q", f.Ref, f.RegressionTest)
	}

	// Criterion 10: reproduction is a command bound to this permission, once.
	if !strings.HasPrefix(f.ReproductionCommand, "xammu ") {
		t.Errorf("finding %s reproduces with %q: not a xammu command", f.Ref, f.ReproductionCommand)
	}
	if n := countFlag(strings.Fields(f.ReproductionCommand), "--authorization"); n != 1 {
		t.Errorf("finding %s names the permission %d time(s) in %q", f.Ref, n, f.ReproductionCommand)
	}
	if strings.TrimSpace(f.AffectedScope) == "" {
		t.Errorf("finding %s does not say what it is about", f.Ref)
	}
}

// readDemoReport runs the command an operator would run and decodes the C-15 it
// prints. The flags of the original run are deliberately absent: the bundle's own
// plan supplies them, which is the property that makes the demonstration re-readable.
func readDemoReport(t *testing.T, root string) contracts.Report {
	t.Helper()
	var out, errs bytes.Buffer
	code := dispatch([]string{
		"report",
		"--run", demoRun,
		"--authorization", "AUTH-SMOKE-LOCAL-001",
		"--authorizations", filepath.Join(root, "authorizations"),
		"--issuer-keyring", filepath.Join(root, "trust", "issuers"),
		"--corpus", filepath.Join(root, "corpus"),
		"--runs-dir", filepath.Join(root, "runs"),
		"--format", "json",
	}, &out, &errs)
	if code != 0 {
		t.Fatalf("the demonstration report does not re-derive: exit %d\nstderr: %s", code, errs.String())
	}
	var rep contracts.Report
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatalf("the published report is not a C-15 document: %v\n%s", err, out.String())
	}
	return rep
}

// shippedScenarios reads the laboratory's own catalogue, so a regression step that
// names a scenario nobody ships fails here rather than at the reader's shell.
func shippedScenarios(t *testing.T, root string) *labctl.Manifest {
	t.Helper()
	m, err := labctl.Read(filepath.Join(root, "lab"))
	if err != nil {
		t.Fatalf("the laboratory manifest does not load: %v", err)
	}
	return m
}
