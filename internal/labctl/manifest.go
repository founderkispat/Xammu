// Package labctl is the machine-readable half of the laboratory.
//
// The lab directory ships a compose file, five documented behaviours and a
// self-test that asserts 134 things about them. What it did not ship, until this
// package, was a statement a program could check: which scenario reproduces which
// C-16 finding type, and with which probes. That gap mattered because a finding
// publishes `xammu lab test --scenario NAME` as its regression step, and a name
// nothing defines is a command that fails for the reader who types it.
//
// Two things live here, and both are about keeping a claim checkable:
//
//  1. The scenario manifest (scenarios.json): the list of readings the fixture
//     reproduces, each bound to one finding type in the C-16 vocabulary and to
//     probe refs that exist in the corpus.
//  2. The vocabulary bridge: the fixture names its transports query_string and
//     json_body, the contract names them query and body_json. The mapping is a
//     table rather than a convention, because an undocumented rename is how a
//     measurement silently stops describing the thing it measured.
package labctl

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"xammu/internal/contracts"
)

// ManifestFile is the name the scenario list is shipped under, inside the lab
// directory. It is a constant because the CLI publishes it in an error message,
// and a reader has to be able to find the file the message names.
const ManifestFile = "scenarios.json"

// Scenario is one reproducible reading of the laboratory.
//
// Expectation and Checks are what make the scenario testable rather than
// descriptive: Checks are commands run inside a service of the compose file, so a
// reviewer can type the same check by hand, and each one states the observation
// the finding is built on. RequiresRun carries the profiling command that turns
// those observations into the finding type named above, because a scenario that
// only proves the fixture's behaviour does not prove the detector noticed it.
type Scenario struct {
	Name        string   `json:"name"`
	Summary     string   `json:"summary"`
	FindingType string   `json:"finding_type"`
	ProbeRefs   []string `json:"probe_refs"`
	Expectation string   `json:"expected_observation"`
	Checks      []string `json:"checks"`
	// Run is the profiling command that publishes this finding type against the
	// running laboratory. Empty is allowed and means what it says: the fixture
	// behaviour is checked here, and the reading is taken by another scenario.
	Run string `json:"run"`
	// FixtureVector and FixtureEncoding name the transport and decoding depth the
	// laboratory calls this reading by, in the fixture's own vocabulary. They are
	// bridged to the contract's by Vector() and Encoding().
	FixtureVector    string `json:"fixture_vector"`
	FixtureEncoding  string `json:"fixture_encoding"`
	Service          string `json:"service"`
	RequiresDocker   bool   `json:"requires_docker"`
	DetectorRef      string `json:"detector_ref"`
	ReadingOfLabSpec int    `json:"lab_spec_behavior"`
}

// Manifest is the whole scenario set of one laboratory build.
type Manifest struct {
	Version string `json:"version"`
	Compose string `json:"compose_file"`
	// RunMode says where the scenarios' Run commands were measured. The laboratory
	// publishes no ports and its network is internal, so a profiler on the host cannot
	// reach the compose services at all: a Run either speaks to the fixture binaries on
	// 127.0.0.1 ("host") or to service names from inside the network ("compose"). The
	// laboratory's own checks always run inside the network, because that is the only
	// place the service names resolve. Naming the mode is not bookkeeping -- an
	// authorization matches a destination by host name, so a command that mixes the two
	// is refused before it sends anything, and a reader would be left holding a
	// reproduction step that cannot run.
	RunMode string `json:"run_mode"`
	// Notes are the things a reader needs that fit nowhere else in the schema.
	Notes     []string          `json:"notes"`
	Scenarios []Scenario        `json:"scenarios"`
	Vocab     map[string]string `json:"vocabulary"`
}

// RunModeHost and RunModeCompose are the only two places a Run command can be
// measured. Anything else is a mode nobody executed.
const (
	RunModeHost    = "host"
	RunModeCompose = "compose"
)

// Read loads and validates the scenario manifest from a lab directory. The
// directory is the operator's argument, so a missing file is reported as the file
// it is missing, with the path the reader can check.
func Read(labDir string) (*Manifest, error) {
	path := filepath.Join(labDir, ManifestFile)
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("no laboratory scenario manifest at %s: %w", filepath.ToSlash(path), err)
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("the scenario manifest %s is not readable JSON: %w",
			filepath.ToSlash(path), err)
	}
	if err := m.Validate(); err != nil {
		return nil, fmt.Errorf("the scenario manifest %s: %w", filepath.ToSlash(path), err)
	}
	return &m, nil
}

// Validate refuses a manifest that cannot carry the weight the findings put on it.
// Each rule below answers a specific way the file could look right and still let a
// published command fail or a claim outrun the fixture.
func (m *Manifest) Validate() error {
	if len(m.Scenarios) == 0 {
		return fmt.Errorf("names no scenario")
	}
	if m.Compose == "" {
		m.Compose = "compose.yaml"
	}
	seen := map[string]bool{}
	for i := range m.Scenarios {
		s := &m.Scenarios[i]
		if s.Name == "" {
			return fmt.Errorf("scenario %d has no name", i)
		}
		if seen[s.Name] {
			return fmt.Errorf("scenario %q is declared twice: one name cannot be two readings", s.Name)
		}
		seen[s.Name] = true
		if !contracts.FindingTypeKnown(contracts.FindingType(s.FindingType)) {
			return fmt.Errorf("scenario %q declares finding type %q, which is not in the C-16 vocabulary",
				s.Name, s.FindingType)
		}
		if s.Summary == "" || s.Expectation == "" {
			return fmt.Errorf("scenario %q states neither a summary nor the observation it expects: "+
				"a scenario a reader cannot state is not a scenario a reviewer can check", s.Name)
		}
		if len(s.ProbeRefs) == 0 {
			return fmt.Errorf("scenario %q names no probe: the reading would have no corpus ref to "+
				"point at, so nothing downstream could look its expectation up", s.Name)
		}
		if len(s.Checks) == 0 {
			return fmt.Errorf("scenario %q declares no check, so nothing in this laboratory proves it",
				s.Name)
		}
		for _, c := range s.Checks {
			if strings.TrimSpace(c) == "" {
				return fmt.Errorf("scenario %q carries a blank check", s.Name)
			}
		}
		if s.FixtureVector != "" {
			if _, err := m.Vector(s.FixtureVector); err != nil {
				return fmt.Errorf("scenario %q: %w", s.Name, err)
			}
		}
		if s.FixtureEncoding != "" {
			if _, err := m.Encoding(s.FixtureEncoding); err != nil {
				return fmt.Errorf("scenario %q: %w", s.Name, err)
			}
		}
	}
	if m.Version == "" {
		return fmt.Errorf("declares no version: a scenario list without the laboratory build it "+
			"describes cannot be compared against a report's digest claims (manifest %s)", ManifestFile)
	}
	if m.RunMode != RunModeHost && m.RunMode != RunModeCompose {
		return fmt.Errorf("declares run_mode %q: a Run command is either measured against the fixture "+
			"listening on the host (%q) or from inside the laboratory network (%q), and a third answer "+
			"would be a mode nobody executed", m.RunMode, RunModeHost, RunModeCompose)
	}
	return nil
}

// Names lists every scenario name, sorted, for error messages.
func (m *Manifest) Names() []string {
	out := make([]string, 0, len(m.Scenarios))
	for _, s := range m.Scenarios {
		out = append(out, s.Name)
	}
	sort.Strings(out)
	return out
}

// Find looks a scenario up by the exact name a finding publishes.
func (m *Manifest) Find(name string) (*Scenario, bool) {
	for i := range m.Scenarios {
		if m.Scenarios[i].Name == name {
			return &m.Scenarios[i], true
		}
	}
	return nil, false
}

// Covering returns the scenarios that reproduce one finding type, in name order, so
// a report can state which readings a reader can rebuild.
func (m *Manifest) Covering(t contracts.FindingType) []Scenario {
	var out []Scenario
	for _, s := range m.Scenarios {
		if s.FindingType == string(t) {
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, k int) bool { return out[i].Name < out[k].Name })
	return out
}

// MissingCommands returns the published regression commands with no scenario behind
// them. It takes whole commands rather than bare names because the command string
// is what a reader types, and a scenario list is only useful if it answers that.
func (m *Manifest) MissingCommands(commands []string) []string {
	var missing []string
	for _, c := range commands {
		name, ok := ScenarioNameOf(c)
		if !ok {
			continue
		}
		if _, found := m.Find(name); !found {
			missing = append(missing, c)
		}
	}
	sort.Strings(missing)
	return dedupe(missing)
}

// Unreferenced returns the scenarios no finding of the declared type can point at,
// which is the other half of the same drift: a manifest entry that no reading
// publishes is documentation nobody maintains.
func (m *Manifest) Unreferenced(published []string) []string {
	want := map[string]bool{}
	for _, c := range published {
		if name, ok := ScenarioNameOf(c); ok {
			want[name] = true
		}
	}
	var out []string
	for _, s := range m.Scenarios {
		if !want[s.Name] {
			out = append(out, s.Name)
		}
	}
	sort.Strings(out)
	return out
}

// ScenarioNameOf pulls the scenario name out of a published regression command.
func ScenarioNameOf(command string) (string, bool) {
	const flag = "--scenario "
	idx := strings.Index(command, flag)
	if idx < 0 || !strings.HasPrefix(command, "xammu lab test ") {
		return "", false
	}
	rest := strings.TrimSpace(command[idx+len(flag):])
	if rest == "" || strings.ContainsAny(rest, " \t\"'") {
		return "", false
	}
	return rest, true
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
