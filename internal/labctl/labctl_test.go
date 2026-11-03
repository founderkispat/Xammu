package labctl

import (
	"bytes"
	"path/filepath"
	"testing"

	"xammu/internal/contracts"
)

// shippedManifest loads the laboratory this repository ships. Every test here that
// needs one reads the real file rather than a fixture copy, because the claim under
// test is that the shipped scenarios are usable, and a test against a copy proves
// nothing about the file a reader actually opens.
func shippedManifest(t *testing.T) *Manifest {
	t.Helper()
	path := filepath.Join("..", "..", "lab")
	m, err := Read(path)
	if err != nil {
		t.Fatalf("the laboratory manifest under %s must load: %v", filepath.ToSlash(path), err)
	}
	return m
}

func TestShippedManifestCoversEveryC16FindingType(t *testing.T) {
	m := shippedManifest(t)
	if m.Version == "" {
		t.Fatal("the shipped manifest declares no laboratory version")
	}
	for _, ty := range contracts.AllFindingTypes() {
		got := m.Covering(ty)
		if len(got) == 0 {
			t.Errorf("no scenario reproduces %s, so a report that publishes it cites a "+
				"regression step nothing can run", ty)
			continue
		}
		for _, s := range got {
			if s.Run == "" {
				t.Errorf("scenario %q proves the fixture's behaviour but names no profiling "+
					"command, so nothing shows the detector noticed it", s.Name)
			}
			if s.Service == "" {
				t.Errorf("scenario %q names no service for its checks", s.Name)
			}
		}
	}
}

// TestBridgeCoversEveryFixtureName holds the vocabulary table to the contract it maps
// into. A bridge value that is not a C-02 vector or a C-03 encoding would let a finding
// carry a transport name no other part of the tool recognises, which is the failure the
// table exists to prevent.
func TestBridgeCoversEveryFixtureName(t *testing.T) {
	vectors := map[contracts.Vector]bool{}
	for _, v := range contracts.AllVectors() {
		vectors[v] = true
	}
	for fixture, v := range fixtureVectors {
		if !vectors[v] {
			t.Errorf("fixture transport %q bridges to %q, which is not a C-02 vector", fixture, v)
		}
	}
	encodings := map[contracts.Encoding]bool{}
	for _, e := range contracts.AllEncodings() {
		encodings[e] = true
	}
	for fixture, e := range fixtureEncodings {
		if !encodings[e] {
			t.Errorf("fixture encoding %q bridges to %q, which is not a C-03 encoding", fixture, e)
		}
	}

	// Every transport a finding can be about must be reachable from a laboratory row,
	// or a measurement taken in this fixture could never be read as that transport.
	for _, v := range contracts.AllVectors() {
		if len(FixtureNamesForVector(v)) == 0 {
			t.Errorf("no fixture name bridges to the C-02 vector %q", v)
		}
	}

	// A laboratory may declare extra pairs. Whatever it declares has to land in the
	// contract's vocabulary, in one of the two sorts, or the read refuses it.
	m := shippedManifest(t)
	for fixture, name := range m.Vocab {
		inVector := vectors[contracts.Vector(name)]
		inEncoding := encodings[contracts.Encoding(name)]
		if inVector == inEncoding {
			t.Errorf("manifest vocabulary entry %q -> %q is neither one C-02 vector nor one "+
				"C-03 encoding (inVector=%v inEncoding=%v)", fixture, name, inVector, inEncoding)
		}
	}

	// And every shipped scenario's own transport and encoding must bridge.
	for _, s := range m.Scenarios {
		if _, err := m.Vector(s.FixtureVector); err != nil {
			t.Errorf("scenario %q: %v", s.Name, err)
		}
		if _, err := m.Encoding(s.FixtureEncoding); err != nil {
			t.Errorf("scenario %q: %v", s.Name, err)
		}
	}

	// An unmapped transport is refused rather than passed through, so a laboratory that
	// renames a row cannot quietly start publishing a transport name nothing recognises.
	var nilManifest *Manifest
	if _, err := nilManifest.Vector("query_string"); err != nil {
		t.Errorf("query_string must bridge to the C-02 query vector: %v", err)
	}
	if _, err := nilManifest.Vector("body_not_parsed"); err != nil {
		t.Errorf("the fixture's accounting name for an unread body must bridge: %v", err)
	}
	if _, err := nilManifest.Vector("grpc_metadata"); err == nil {
		t.Error("a transport this vocabulary has never heard of must be refused, not renamed")
	}
	if _, err := nilManifest.Encoding("double_encoded"); err != nil {
		t.Errorf("double_encoded must bridge to the C-03 url_double encoding: %v", err)
	}
	if _, err := nilManifest.Encoding("base64"); err == nil {
		t.Error("an encoding outside the contract's vocabulary must be refused, not passed through")
	}
}

func TestValidateRefusesWhatCannotBeCited(t *testing.T) {
	good := Scenario{
		Name: "coverage-gap-sqli-query-canonical-api-search", Summary: "a reading",
		FindingType: string(contracts.FindingCoverageGap), Expectation: "a status",
		ProbeRefs: []string{"DEV-SQLI-Q-01"}, Checks: []string{"test 1 = 1"},
	}
	for _, tc := range []struct {
		name   string
		mutate func(*Scenario)
		want   string
	}{
		{"no name", func(s *Scenario) { s.Name = "" }, "has no name"},
		{"outside C-16", func(s *Scenario) { s.FindingType = "confirmed_exploit" },
			"not in the C-16 vocabulary"},
		{"no summary", func(s *Scenario) { s.Summary = "" }, "neither a summary"},
		{"no probes", func(s *Scenario) { s.ProbeRefs = nil }, "names no probe"},
		{"no checks", func(s *Scenario) { s.Checks = nil }, "declares no check"},
		{"blank check", func(s *Scenario) { s.Checks = []string{"  "} }, "blank check"},
		{"unmapped transport", func(s *Scenario) { s.FixtureVector = "grpc_metadata" },
			"has no mapping"},
	} {
		m := &Manifest{Version: "1", RunMode: RunModeHost, Scenarios: []Scenario{good}}
		tc.mutate(&m.Scenarios[0])
		err := m.Validate()
		if err == nil || !bytes.Contains([]byte(err.Error()), []byte(tc.want)) {
			t.Errorf("%s must be refused with %q, got %v", tc.name, tc.want, err)
		}
	}
	dup := &Manifest{Version: "1", RunMode: RunModeHost, Scenarios: []Scenario{good, good}}
	if err := dup.Validate(); err == nil ||
		!bytes.Contains([]byte(err.Error()), []byte("declared twice")) {
		t.Fatalf("one name cannot be two readings: %v", err)
	}
	noVersion := &Manifest{RunMode: RunModeHost, Scenarios: []Scenario{good}}
	if err := noVersion.Validate(); err == nil ||
		!bytes.Contains([]byte(err.Error()), []byte("declares no version")) {
		t.Fatalf("a scenario list without a laboratory version cannot be compared to a report: %v", err)
	}
	// The mode decides where a Run has to be typed, so a third value would publish a
	// command nobody can place.
	for _, mode := range []string{"", "docker", "HOST"} {
		wrong := &Manifest{Version: "1", RunMode: mode, Scenarios: []Scenario{good}}
		if err := wrong.Validate(); err == nil ||
			!bytes.Contains([]byte(err.Error()), []byte("run_mode")) {
			t.Errorf("run_mode %q must be refused, got %v", mode, err)
		}
	}
}

func TestScenarioNameOfReadsOnlyPublishedCommands(t *testing.T) {
	for _, tc := range []struct {
		command string
		want    string
		ok      bool
	}{
		{"xammu lab test --scenario coverage-gap-sqli-query-canonical-api-search",
			"coverage-gap-sqli-query-canonical-api-search", true},
		{"lab test --scenario coverage-gap", "", false},
		{"xammu lab test --coverage-gap", "", false},
		{"xammu lab test --scenario ", "", false},
		{"xammu lab test --scenario a b", "", false},
	} {
		got, ok := ScenarioNameOf(tc.command)
		if ok != tc.ok || got != tc.want {
			t.Errorf("ScenarioNameOf(%q) = %q, %v; want %q, %v",
				tc.command, got, ok, tc.want, tc.ok)
		}
	}
}

// TestManifestCommandsRoundTrip proves both directions of the same promise: a command
// built from a shipped scenario name resolves, and a name the laboratory does not hold
// is reported as missing rather than quietly previewed.
func TestManifestCommandsRoundTrip(t *testing.T) {
	m := shippedManifest(t)
	var published []string
	for _, s := range m.Scenarios {
		published = append(published, "xammu lab test --scenario "+s.Name)
	}
	if missing := m.MissingCommands(published); len(missing) != 0 {
		t.Errorf("a manifest must resolve its own scenario names: %v", missing)
	}
	if unreferenced := m.Unreferenced(published); len(unreferenced) != 0 {
		t.Errorf("no shipped scenario may be unreachable by command: %v", unreferenced)
	}
	missing := m.MissingCommands([]string{"xammu lab test --scenario body-inspection-gap",
		"xammu validate --finding GAP-001"})
	if len(missing) != 1 {
		t.Fatalf("only a cited scenario command can be missing: %v", missing)
	}
	if unreferenced := m.Unreferenced(nil); len(unreferenced) != len(m.Scenarios) {
		t.Fatalf("with nothing published, every scenario is unreferenced: %v", unreferenced)
	}
}
