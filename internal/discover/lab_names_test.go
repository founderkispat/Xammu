package discover

import (
	"path/filepath"
	"testing"

	"xammu/internal/contracts"
	"xammu/internal/inference"
	"xammu/internal/labctl"
)

// The laboratory ships scenarios; a finding cites one by name. Nothing in a build
// forces those two lists to stay the same string, and the failure mode is quiet: the
// detector's naming rule changes by one character, every published report keeps
// looking well-formed, and the reader who types the regression step gets "scenario
// not found". These tests bind the two halves together, and the names below are the
// ones real runs of this laboratory published -- they were collected from reports, not
// written from imagination, which is the only reason the binding means anything.

// publishedCell is one reading the laboratory produces, stated the way the detector
// states it: a finding type, the family word labStep is called with, and the subject
// that function is called with.
type publishedCell struct {
	ty      contracts.FindingType
	family  string
	subject string
}

func cellSubject(class contracts.AttackClass, v contracts.Vector, e contracts.Encoding, path string) string {
	return inference.CellKey{AttackClass: class, Vector: v, Encoding: e, Path: path}.String()
}

// labPublished is the whole set of regression steps the laboratory has actually been
// measured to publish, one entry per finding. The four cell-shaped families take a
// CellKey so the name is rebuilt from the model rather than copied from a string.
var labPublished = []publishedCell{
	{contracts.FindingCoverageGap, "coverage-gap",
		cellSubject(contracts.ClassSQLi, contracts.VectorQuery, contracts.EncodingCanonical, "/api/search")},
	{contracts.FindingCoverageGap, "coverage-gap",
		cellSubject(contracts.ClassSQLi, contracts.VectorQuery, contracts.EncodingCaseVariant, "/api/search")},
	{contracts.FindingCoverageGap, "coverage-gap",
		cellSubject(contracts.ClassSQLi, contracts.VectorQuery, contracts.EncodingURLSingle, "/api/search")},
	{contracts.FindingUndeterminedArea, "undetermined",
		cellSubject(contracts.ClassSQLi, contracts.VectorBodyJSON, contracts.EncodingCanonical, "/api/admin")},
	{contracts.FindingUndeterminedArea, "undetermined",
		cellSubject(contracts.ClassSQLi, contracts.VectorBodyJSON, contracts.EncodingCaseVariant, "/api/admin")},
	{contracts.FindingUndeterminedArea, "undetermined",
		cellSubject(contracts.ClassSQLi, contracts.VectorQuery, contracts.EncodingURLDouble, "/api/admin")},
	{contracts.FindingVectorAsymmetry, "vector-asymmetry", "G-DEV-GEN-sentinel"},
	{contracts.FindingEncodingBypass, "encoding-bypass", "G-DEV-SQLI-q-tauto"},
	{contracts.FindingOverBlocking, "over-blocking", "informative_either"},
	{contracts.FindingConfigurationConcern, "configuration-concern", "X-Lab-Probe-Transfer-Encoding"},
}

func shippedLab(t *testing.T) *labctl.Manifest {
	t.Helper()
	path := filepath.Join("..", "..", "lab")
	m, err := labctl.Read(path)
	if err != nil {
		t.Fatalf("the laboratory manifest under %s must load: %v", filepath.ToSlash(path), err)
	}
	return m
}

// TestEveryPublishedRegressionStepResolves is the promise a reader is owed: the command
// printed under a finding runs against this repository's laboratory.
func TestEveryPublishedRegressionStepResolves(t *testing.T) {
	m := shippedLab(t)
	var commands []string
	for _, p := range labPublished {
		step := labStep(p.family, p.subject)
		commands = append(commands, step)
		name, ok := labctl.ScenarioNameOf(step)
		if !ok {
			t.Fatalf("labStep(%q, %q) does not publish a parsable command: %q",
				p.family, p.subject, step)
		}
		s, found := m.Find(name)
		if !found {
			t.Errorf("%s cites scenario %q, which %s does not hold; this laboratory defines: %v",
				step, name, labctl.ManifestFile, m.Names())
			continue
		}
		if s.FindingType != string(p.ty) {
			t.Errorf("scenario %q reproduces %s but is cited by a %s finding, so the regression "+
				"step would not rebuild this reading", name, s.FindingType, p.ty)
		}
	}
	if missing := m.MissingCommands(commands); len(missing) != 0 {
		t.Errorf("published regression steps with no scenario behind them: %v", missing)
	}
	if unreferenced := m.Unreferenced(commands); len(unreferenced) != 0 {
		t.Errorf("scenarios no measured finding cites: %v -- a laboratory row nobody publishes is "+
			"documentation, not a reproduction step", unreferenced)
	}
}

// TestScenarioNamingRuleIsStableAcrossFamilies: one function builds every cited name,
// so a sanitiser change moves all six families at once and the shipped manifest has to
// move with it. The shape assertions are what catch a rename that still resolves.
func TestScenarioNamingRuleIsStableAcrossFamilies(t *testing.T) {
	for _, p := range labPublished {
		name, ok := labctl.ScenarioNameOf(labStep(p.family, p.subject))
		if !ok {
			t.Fatalf("labStep(%q, %q) is not a citable command", p.family, p.subject)
		}
		if name != scenarioName(p.family, p.subject) {
			t.Fatalf("ScenarioNameOf must invert scenarioName, got %q vs %q",
				name, scenarioName(p.family, p.subject))
		}
		for _, c := range name {
			switch {
			case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-':
			default:
				t.Fatalf("scenario name %q carries %q: a name typed at a shell must be "+
					"lowercase alphanumerics and dashes only", name, string(c))
			}
		}
	}
}

// TestContractFixtureCitesAShippedScenario keeps the hand-written C-16 example honest.
// It is the text a reader copies first, and an example command that fails makes every
// later command in the document suspect.
func TestContractFixtureCitesAShippedScenario(t *testing.T) {
	m := shippedLab(t)
	f := contracts.ValidFinding()
	name, ok := labctl.ScenarioNameOf(f.RegressionTest)
	if !ok {
		t.Fatalf("the C-16 fixture's regression step is not a citable command: %q", f.RegressionTest)
	}
	s, found := m.Find(name)
	if !found {
		t.Fatalf("the C-16 fixture cites %q, which this laboratory does not ship: %v",
			name, m.Names())
	}
	if s.FindingType != string(f.FindingType) {
		t.Errorf("the fixture finding is a %s but cites a %s scenario: %q",
			f.FindingType, s.FindingType, name)
	}
}
