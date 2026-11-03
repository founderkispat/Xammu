package discover

import (
	"fmt"
	"sort"
	"strings"

	"xammu/internal/contracts"
	"xammu/internal/corpus"
	"xammu/internal/inference"
)

func keep(rs []reading, pred func(reading) bool) []reading {
	var out []reading
	for _, r := range rs {
		if pred(r) {
			out = append(out, r)
		}
	}
	return out
}

func sortedCellKeys(byCell map[inference.CellKey][]reading) []inference.CellKey {
	out := make([]inference.CellKey, 0, len(byCell))
	for k := range byCell {
		out = append(out, k)
	}
	sort.Slice(out, func(i, k int) bool { return out[i].String() < out[k].String() })
	return out
}

func (ix *index) sortedGroups() []string {
	out := make([]string, 0, len(ix.byGroup))
	for g := range ix.byGroup {
		out = append(out, g)
	}
	sort.Strings(out)
	return out
}

// majorityOf is the reading most valid trials in the set produced. Ties break by
// signal name so a sentence does not depend on map order.
func majorityOf(rs []reading) contracts.Signal {
	counts := map[contracts.Signal]int{}
	for _, r := range rs {
		if r.valid() {
			counts[r.Trial.Signal]++
		}
	}
	var best contracts.Signal
	n := -1
	for s, k := range counts {
		if k > n || (k == n && s < best) {
			best, n = s, k
		}
	}
	if n <= 0 {
		return contracts.SignalIndeterminate
	}
	return best
}

// anchorsOf names the evidence the corpus declares for these probes. A finding that
// cites the rule ids it contradicts is checkable against the fixture; one that says
// "the WAF" is not.
func anchorsOf(rs []reading) string {
	seen := map[string]bool{}
	var out []string
	for _, r := range rs {
		for _, v := range r.Item.Validation {
			if seen[v.RunRef] {
				continue
			}
			seen[v.RunRef] = true
			out = append(out, v.RunRef)
		}
	}
	sort.Strings(out)
	if len(out) == 0 {
		return "no declared evidence"
	}
	return strings.Join(out, ", ")
}

// declaredID splits one validation entry into the namespace it names and the id
// inside it. The shipped corpus writes all three of its declared artifacts behind the
// one declared prefix -- "lab-rule-table:SQLI-001" is a signature, the same prefix
// with "coverage:" or "policy:" in front of the id is a statement about what the
// engine inspects rather than about what it matches. A finding that quoted the three
// as one list would read as though a policy were a signature, so the split happens
// here once, at the only place that reads them.
func declaredID(v contracts.CorpusValidationEvidence) (namespace, id string, ok bool) {
	if !strings.HasPrefix(v.RunRef, corpus.EvidenceDeclared) {
		return "", "", false
	}
	rest := strings.TrimPrefix(v.RunRef, corpus.EvidenceDeclared)
	for _, ns := range []string{"coverage:", "policy:"} {
		if strings.HasPrefix(rest, ns) {
			return strings.TrimSuffix(ns, ":"), strings.TrimPrefix(rest, ns), true
		}
	}
	return "rule", rest, true
}

// rulesOf keeps the signature ids, for a sentence that has to name what the engine
// matches rather than what it inspects.
func rulesOf(rs []reading) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range rs {
		for _, v := range r.Item.Validation {
			namespace, id, ok := declaredID(v)
			if !ok || namespace != "rule" || id == "" || seen[id] {
				continue
			}
			seen[id] = true
			out = append(out, id)
		}
	}
	sort.Strings(out)
	if len(out) == 0 {
		return []string{"the declared expectation of this family"}
	}
	return out
}

func firstClass(rs []reading) contracts.AttackClass {
	for _, r := range rs {
		if r.Item.AttackClass != "" {
			return r.Item.AttackClass
		}
	}
	return ""
}

func firstVector(rs []reading) contracts.Vector {
	for _, r := range rs {
		if r.Item.Vector != "" {
			return r.Item.Vector
		}
	}
	return ""
}

func firstEncoding(rs []reading) contracts.Encoding {
	for _, r := range rs {
		if r.Item.Encoding != "" {
			return r.Item.Encoding
		}
	}
	return ""
}

func firstPath(rs []reading) string {
	for _, r := range rs {
		if r.Key.Path != "" {
			return r.Key.Path
		}
	}
	return "the authorized path"
}

func verbForReadings(rs []reading) string {
	if methodFor(firstVector(rs)) == "POST" {
		return "POST"
	}
	return "GET"
}

// methodFor restates the transport the corpus placement uses for a vector. The
// trial does not carry the method, and inventing one in prose would be a claim about
// a request the journal does not show.
func methodFor(v contracts.Vector) string {
	switch v {
	case contracts.VectorBodyJSON, contracts.VectorBodyForm, contracts.VectorMultipart:
		return "POST"
	default:
		return "GET"
	}
}

func scopeOf(key inference.CellKey, rs []reading) string {
	return fmt.Sprintf("%s x %s x %s on %s %s", key.AttackClass, key.Vector, key.Encoding,
		verbForReadings(rs), key.Path)
}

// sanitize turns a measured identity into a reference a human can read off a terminal
// and type back into a command. Only letters, digits and single dashes survive: a
// published finding reference is pasted into a shell by someone who is checking the
// tool's work, and a `;` or a `|` left over from a probe would end the command early
// or pipe it somewhere else. A reference that cannot be pasted is not reproducible.
func sanitize(s string) string {
	var b strings.Builder
	prevDash := true
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' {
			b.WriteRune(c)
			prevDash = false
			continue
		}
		if !prevDash {
			b.WriteRune('-')
			prevDash = true
		}
	}
	return strings.Trim(b.String(), "-")
}

// scenarioName builds the laboratory scenario identifier a regression step cites.
//
// It is lowercased and underscore-free on purpose: the string is typed at a shell by a
// reader who is checking the tool's work, a scenario manifest is a list of these names,
// and a name that only exists in one casing (`G-DEV-XSS-Q-MARKUP`) invites a second,
// unresolvable spelling of the same scenario. The rule is one function for all six
// finding families so that a name a report publishes and a name the laboratory ships can
// only ever be the same string.
func scenarioName(family, subject string) string {
	return family + "-" + strings.ToLower(strings.ReplaceAll(sanitize(subject), "_", "-"))
}

// labStep is the whole regression step a finding publishes. The command and the name are
// built together because a step whose prefix drifted by one word is a step that points
// at nothing, and the laboratory's own manifest lists names rather than commands.
func labStep(family, subject string) string {
	return "xammu lab test --scenario " + scenarioName(family, subject)
}

// missingFor states what would raise the claim, in the terms the evidence ladder
// uses. It is generated from the stance so a descriptive finding never claims that
// more rounds are missing when the missing thing is a control.
func missingFor(st stance, profileMissing string) string {
	base := "This run supplies the response side only."
	switch {
	case st.Level == contracts.EvidenceSingleObservation:
		base += " What is missing is repetition: a second authorized round of the same cell, so the " +
			"difference is shown to survive rather than to be one exchange."
	case st.Level == contracts.EvidenceReplicated:
		base += " What is missing is a valid control pair inside the profile, so the reading is anchored " +
			"against ordinary handling rather than against expectation."
	case st.Level == contracts.EvidenceReplicatedWithControls:
		base += " What is missing is an independently authorized round, which would raise the claim from " +
			"association to attribution."
	default:
		base += " What is missing is a source outside the HTTP response: the engine's rule configuration " +
			"or a filter log entry, which is the only thing that separates the surviving alternatives."
	}
	if profileMissing = strings.TrimSpace(profileMissing); profileMissing != "" {
		base += " Recorded by the evidence profile: " + profileMissing + "."
	}
	return base
}

// recommendationFor is the action the engineer takes. Each one is a configuration
// or a review step at the defence, never a change to the application: XAMMU does not
// evaluate the origin, so it cannot recommend anything about it.
func recommendationFor(kind contracts.FindingType, vector contracts.Vector, anchors string) string {
	switch kind {
	case contracts.FindingCoverageGap:
		return fmt.Sprintf("check whether the rule set that produced %s is enabled for the %s transport; "+
			"if it is enabled, the probes reached it and were not matched, so review the match stage for %s",
			anchors, vector, vector)
	case contracts.FindingVectorAsymmetry:
		return fmt.Sprintf("compare inspection coverage for the %s transport against the transport it "+
			"differs from in the engine's configuration; the decision to hand to the operator is whether "+
			"%s traffic is meant to be inspected at all", vector, vector)
	case contracts.FindingOverBlocking:
		return "review the allowlist and the literal matches behind the refused legitimate shapes; each " +
			"one is a legitimate client that will be refused in production"
	case contracts.FindingConfigurationConcern:
		return "confirm the refusal is the named policy rather than a signature, and record it in the " +
			"configuration baseline: signature review will never predict it"
	default:
		return "re-run the planned exchange inside the same authorization so the zone has a reading"
	}
}
