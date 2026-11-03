package main

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"xammu/internal/contracts"
	"xammu/internal/corpus"
	"xammu/internal/integrity"
	"xammu/internal/observer"
)

// cmdVersion states what this binary is, in the same fields a report cites. The tool
// version and the schema version are printed together because a bundle records both,
// and a reviewer comparing them needs the pair rather than a slogan.
func cmdVersion(c *cli, args []string) error {
	fs := newFlagSet("version", c.err)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := requireNoStrayArgs(fs); err != nil {
		return err
	}
	set := observer.DefaultSet()
	fmt.Fprintf(c.out, "xammu %s (schema %s)\n", integrity.ToolVersion, contracts.SchemaVersion)
	fmt.Fprintf(c.out, "contracts: %d registered (%s)\n", len(contracts.IDs()),
		strings.Join(idStrings(contracts.IDs()), ", "))
	fmt.Fprintf(c.out, "detectors: %d in the default ensemble, set hash %s\n",
		len(set.IDs()), set.Hash())
	fmt.Fprint(c.out, "egress: one authorized client per run; nothing here sends a request\n")
	return nil
}

func idStrings(in []contracts.ID) []string {
	out := make([]string, len(in))
	for i, id := range in {
		out[i] = string(id)
	}
	sort.Strings(out)
	return out
}

// cmdCorpus is the inertness gate's public surface: it loads the tree the way a run
// would and reports what the gate did, without planning or sending anything. A corpus
// that fails here cannot be used by any command, and this is the command that says
// why before an operator spends requests.
func cmdCorpus(c *cli, args []string) error {
	if len(args) == 0 || args[0] != "check" {
		// A missing subcommand is a usage problem, not a refusal on the merits:
		// nothing was checked and nothing was denied.
		return fmt.Errorf("%w: corpus takes the subcommand check", errUsage)
	}
	fs := newFlagSet("corpus check", c.err)
	var root string
	var only string
	fs.StringVar(&root, "corpus", "corpus", "corpus tree to load through the gate")
	fs.StringVar(&only, "partition", "", "report one partition in detail instead of all three")
	if err := parseFlags(fs, args[1:]); err != nil {
		return err
	}
	if err := requireNoStrayArgs(fs); err != nil {
		return err
	}
	return checkCorpus(c.out, root, only)
}

// checkCorpus loads the tree and prints what the gate and the partition discipline
// say about it. It returns an error when the corpus is not usable, so the exit code
// tells a script what the prose told an operator.
func checkCorpus(out io.Writer, root, only string) error {
	set, err := corpus.Load(root, corpus.DefaultPolicy())
	if err != nil {
		return fmt.Errorf("corpus %s: %w", root, err)
	}
	names := contracts.AllPartitionNames()
	if only != "" {
		name, err := asPartition(only)
		if err != nil {
			return err
		}
		names = []contracts.PartitionName{name}
	}
	policy := corpus.DefaultPolicy()
	fmt.Fprintf(out, "corpus %s, gate %s (marker %q, probe cap %d bytes)\n",
		root, corpus.GateVersion, policy.MarkerToken, policy.MaxProbeBytes)
	for _, name := range names {
		p, err := set.Partition(name)
		if err != nil {
			return err
		}
		var inert, excluded int
		for _, item := range p.Items {
			if item.Inertness.Verdict == contracts.InertVerified {
				inert++
			} else {
				excluded++
			}
		}
		fmt.Fprintf(out, "  %-22s %3d item(s), %d group(s), gate verified %d, excluded %d\n",
			name, len(p.Items), len(p.Groups), inert, excluded)
		if len(p.StaleGate) > 0 {
			fmt.Fprintf(out, "    stale inertness claims: %s\n", strings.Join(p.StaleGate, ", "))
		}
		unobserved := set.Unobserved(name)
		if len(unobserved) > 0 {
			fmt.Fprintf(out, "    %d item(s) whose expectations are declared but never observed by an "+
				"executed run: %s\n", len(unobserved), strings.Join(shortList(unobserved, 8), ", "))
		}
	}
	leaks := set.Overlaps()
	if len(leaks) == 0 {
		fmt.Fprint(out, "  partition discipline: no group or ref is shared across partitions\n")
	} else {
		fmt.Fprintf(out, "  partition discipline: %d leak(s) between partitions\n", len(leaks))
		for _, l := range leaks {
			fmt.Fprintf(out, "    %s\n", l)
		}
	}
	if err := set.EvidenceCheck(); err != nil {
		fmt.Fprintf(out, "  evidence entries: %v\n", err)
	} else {
		fmt.Fprint(out, "  evidence entries: every validation ref is classifiable and names a build\n")
	}
	if err := set.Usable(); err != nil {
		return fmt.Errorf("the corpus is loaded but not usable: %w", err)
	}
	fmt.Fprint(out, "usable: a run may plan against this tree. Nothing was sent to check it.\n")
	return nil
}

// shortList keeps a diagnostic readable; the full list is on disk in the corpus.
func shortList(in []string, max int) []string {
	if len(in) <= max {
		return in
	}
	out := append([]string(nil), in[:max]...)
	return append(out, fmt.Sprintf("... and %d more", len(in)-max))
}

// cmdPlaybook builds and validates a plan, then prints it. A report can cite it for a
// coverage gap because it answers "what would this cost" without asking anyone's
// system for a single request.
func cmdPlaybook(c *cli, args []string) error {
	var f planFlags
	fs := newFlagSet("playbook", c.err)
	f.register(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := requireNoStrayArgs(fs); err != nil {
		return err
	}
	auth, err := f.bindAuthorization()
	if err != nil {
		return err
	}
	summarizeAuth(c.out, auth)
	req, err := buildPlan(auth, f)
	if err != nil {
		return err
	}
	renderPlan(c.out, req)
	return nil
}
