package main

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	"xammu/internal/contracts"
	"xammu/internal/labctl"
)

// labDirDefault is where the reproducible laboratory lives relative to the working
// directory the operator ran xammu from.
const labDirDefault = "lab"

// cmdLab is the laboratory's front door. It distinguishes three things on purpose:
// what scenarios exist, what running one would do, and doing it. Only --apply reaches
// for docker, because bringing up a perimeter on someone's machine is an action
// rather than a reading.
func cmdLab(c *cli, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("%w: lab takes scenarios or test --scenario NAME", errUsage)
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "scenarios":
		return labScenarios(c, rest)
	case "test":
		return labTest(c, rest)
	default:
		return fmt.Errorf("%w: lab scenarios and lab test are the only subcommands, got %q",
			errUsage, sub)
	}
}

// readLab is the one place the CLI touches the laboratory directory. The manifest is
// validated by labctl on the way in, so a scenario that declares a finding type
// outside C-16, or a transport the vocabulary bridge cannot name, never reaches a
// printer that would present it as a reading.
func readLab(dir string) (*labctl.Manifest, error) {
	return labctl.Read(dir)
}

func labScenarios(c *cli, args []string) error {
	fs := newFlagSet("lab scenarios", c.err)
	var dir string
	fs.StringVar(&dir, "lab-dir", labDirDefault, "where the laboratory lives")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := requireNoStrayArgs(fs); err != nil {
		return err
	}
	m, err := readLab(dir)
	if err != nil {
		return err
	}
	fmt.Fprintf(c.out, "laboratory %s, manifest version %s, compose file %s\n",
		filepath.ToSlash(dir), m.Version, m.Compose)
	// The mode is printed because it decides whether a Run command can be typed where
	// the reader is standing: a host measurement is not a compose instruction.
	fmt.Fprintf(c.out, "run commands were measured %s; checks run in %q inside the compose network\n",
		runModeSentence(m.RunMode), labCheckServiceDefault)
	for _, note := range m.Notes {
		fmt.Fprintf(c.out, "\nnote: %s\n", note)
	}
	for _, s := range m.Scenarios {
		fmt.Fprintf(c.out, "\n%s\n  %s\n  finding type: %s\n  probes: %s\n  expected: %s\n",
			s.Name, s.Summary, s.FindingType, strings.Join(s.ProbeRefs, ", "), s.Expectation)
		if cell := describeCell(m, s); cell != "" {
			fmt.Fprintf(c.out, "  cell: %s\n", cell)
		}
		if s.DetectorRef != "" {
			fmt.Fprintf(c.out, "  detector: %s\n", s.DetectorRef)
		}
		if s.Run != "" {
			fmt.Fprintf(c.out, "  run: %s\n", s.Run)
		}
		fmt.Fprintf(c.out, "  checks: %d, run in service %q\n", len(s.Checks), serviceOf(s))
	}
	fmt.Fprintf(c.out, "\ncoverage by finding type:\n")
	var missing []string
	for _, t := range contracts.AllFindingTypes() {
		got := m.Covering(t)
		if len(got) == 0 {
			missing = append(missing, string(t))
			continue
		}
		names := make([]string, 0, len(got))
		for _, s := range got {
			names = append(names, s.Name)
		}
		fmt.Fprintf(c.out, "  %s: %s\n", t, strings.Join(names, ", "))
	}
	if len(missing) > 0 {
		// Printed because a lab that demonstrates four of six is not a lab that
		// demonstrates the six a report can cite, and the report is where a reader
		// would otherwise discover the difference.
		fmt.Fprintf(c.out, "\nno scenario reproduces: %s\n", strings.Join(missing, ", "))
	}
	return nil
}

// describeCell states, in the contract's vocabulary, which measurement cell the
// fixture row behind this scenario sits in. It is printed because a name built from
// the fixture's words and a finding built from the contract's words are only the same
// reading if the bridge says so.
func describeCell(m *labctl.Manifest, s labctl.Scenario) string {
	if s.FixtureVector == "" || s.FixtureEncoding == "" {
		return ""
	}
	v, err := m.Vector(s.FixtureVector)
	if err != nil {
		return ""
	}
	e, err := m.Encoding(s.FixtureEncoding)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%s + %s (fixture %s + %s)", v, e, s.FixtureVector, s.FixtureEncoding)
}

func serviceOf(s labctl.Scenario) string {
	if s.Service == "" {
		return labCheckServiceDefault
	}
	return s.Service
}

// runModeSentence turns the manifest's mode into the phrase a reader needs: where the
// command has to be typed for it to reach the thing it measured.
func runModeSentence(mode string) string {
	switch mode {
	case labctl.RunModeHost:
		return "against the fixture binaries on the host"
	case labctl.RunModeCompose:
		return "from inside the laboratory network"
	default:
		return "in a way this manifest does not name"
	}
}

// labCheckServiceDefault is where a scenario's checks run when the manifest does not
// say. It is the runner rather than a perimeter container because the checks are
// curl invocations, and the only container the compose file guarantees can make a
// request is the one built for it.
const labCheckServiceDefault = "netrunner"

func labTest(c *cli, args []string) error {
	var (
		dir     string
		name    string
		apply   bool
		stopIt  bool
		withRun bool
	)
	fs := newFlagSet("lab test", c.err)
	fs.StringVar(&dir, "lab-dir", labDirDefault, "where the laboratory lives")
	fs.StringVar(&name, "scenario", "", "scenario to run; required")
	fs.BoolVar(&apply, "apply", false,
		"actually build and start the containers; without it this command only states what would happen")
	fs.BoolVar(&stopIt, "teardown", false,
		"take the laboratory down again after the checks, instead of leaving it up for a run to use")
	fs.BoolVar(&withRun, "show-run", false,
		"also print the profiling command that turns these observations into the finding type")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := requireNoStrayArgs(fs); err != nil {
		return err
	}
	if name == "" {
		return fmt.Errorf("lab test needs --scenario NAME: a laboratory is brought up on purpose, " +
			"and `xammu lab scenarios` lists the purposes")
	}
	m, err := readLab(dir)
	if err != nil {
		return err
	}
	scenario, found := m.Find(name)
	if !found {
		return fmt.Errorf("scenario %q is not in %s; this laboratory defines: %s",
			name, filepath.ToSlash(filepath.Join(dir, labctl.ManifestFile)),
			strings.Join(m.Names(), ", "))
	}

	steps := labSteps(m, *scenario)
	fmt.Fprintf(c.out, "scenario %q: %s\n", scenario.Name, scenario.Summary)
	fmt.Fprintf(c.out, "  reproduces finding type %s from probes %s\n",
		scenario.FindingType, strings.Join(scenario.ProbeRefs, ", "))
	if cell := describeCell(m, *scenario); cell != "" {
		fmt.Fprintf(c.out, "  observes the cell %s\n", cell)
	}
	if withRun && scenario.Run != "" {
		fmt.Fprintf(c.out, "  the reading is published by, %s:\n    %s\n",
			runModeSentence(m.RunMode), scenario.Run)
	} else if scenario.Run != "" {
		fmt.Fprintf(c.out, "  the reading is published by the same command, %s; --show-run prints it\n",
			runModeSentence(m.RunMode))
	}
	fmt.Fprint(c.out, "  this would run:\n")
	for _, s := range steps {
		fmt.Fprintf(c.out, "    %s\n", s)
	}
	if !apply {
		fmt.Fprint(c.out, "\nnothing ran. --apply brings the laboratory up on this machine, so it is "+
			"a choice rather than a default.\n")
		return nil
	}
	docker, err := exec.LookPath("docker")
	if err != nil {
		return fmt.Errorf("the laboratory is defined by compose but docker is not on PATH: %w", err)
	}
	for _, cmdArgs := range stepArgs(m, *scenario) {
		fmt.Fprintf(c.out, "\n$ %s %s\n", filepath.Base(docker), strings.Join(cmdArgs, " "))
		run := exec.Command(docker, cmdArgs...)
		run.Dir = dir
		run.Stdout = c.out
		run.Stderr = c.err
		if err := run.Run(); err != nil {
			return fmt.Errorf("the laboratory step %q failed: %w", strings.Join(cmdArgs, " "), err)
		}
	}
	if stopIt {
		fmt.Fprintf(c.out, "\ntearing down because --teardown was given\n")
		args := []string{"compose", "-f", filepath.Base(m.Compose), "down", "-v"}
		run := exec.Command(docker, args...)
		run.Dir = dir
		run.Stdout = c.out
		run.Stderr = c.err
		if err := run.Run(); err != nil {
			return fmt.Errorf("teardown failed; the laboratory may still be up: %w", err)
		}
		return nil
	}
	fmt.Fprintf(c.out, "\nthe laboratory is up. A profiling run against it still needs its own C-09 "+
		"authorization: `xammu run --authorization REF --authorize REF --run ID`.\n")
	fmt.Fprintf(c.out, "for this scenario that is: %s\n", runCommand(scenario))
	return nil
}

// runCommand states the profiling command a scenario was measured with, or the fact
// that this scenario proves fixture behaviour only. A nil manifest is not possible
// here, so no guard is carried for it.
func runCommand(s *labctl.Scenario) string {
	if s.Run == "" {
		return "(this scenario checks the fixture; it publishes no reading of its own)"
	}
	return s.Run
}

// labSteps renders the commands as text. It is the same list stepArgs executes, so a
// preview cannot drift into fiction.
func labSteps(m *labctl.Manifest, s labctl.Scenario) []string {
	var out []string
	for _, args := range stepArgs(m, s) {
		out = append(out, "docker "+strings.Join(args, " "))
	}
	return out
}

// stepArgs builds the compose invocations: build, start, then each check the scenario
// declares run inside the service that owns it, so a check is one command a reviewer
// can type as well.
func stepArgs(m *labctl.Manifest, s labctl.Scenario) [][]string {
	base := []string{"compose", "-f", filepath.Base(m.Compose)}
	out := [][]string{
		append(append([]string{}, base...), "build"),
		append(append([]string{}, base...), "up", "-d"),
	}
	service := serviceOf(s)
	for _, check := range s.Checks {
		out = append(out, append(append([]string{}, base...),
			"exec", "-T", service, "sh", "-c", check))
	}
	return out
}
