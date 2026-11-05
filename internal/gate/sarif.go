package gate

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"xammu/internal/contracts"
)

// SARIF 2.1.0 output. The shape is validated structurally by the test suite:
// the version, the schema URI, every ruleId used by a result, the level
// vocabulary and the location journals. Full OASIS JSON Schema validation is not
// performed because it would add an external dependency; the limitation is
// published in the document's limits and in docs/gate-output.md.

const sarifSchema = "https://json.schemastore.org/sarif-2.1.0.json"

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool        sarifTool         `json:"tool"`
	Invocations []sarifInvocation `json:"invocations"`
	Results     []sarifResult     `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name            string      `json:"name"`
	SemanticVersion string      `json:"semanticVersion"`
	Rules           []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string         `json:"id"`
	Name                 string         `json:"name,omitempty"`
	ShortDescription     sarifText      `json:"shortDescription"`
	DefaultConfiguration sarifLevelOnly `json:"defaultConfiguration"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifLevelOnly struct {
	Level string `json:"level"`
}

type sarifInvocation struct {
	ExecutionSuccessful bool `json:"executionSuccessful"`
	ExitCode            int  `json:"exitCode"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             sarifText         `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           sarifRegion   `json:"region"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

type ruleSpec struct {
	ID          string
	Name        string
	Description string
	Level       string
}

var checkRuleSpecs = []ruleSpec{
	{"XAMMU-EFF-TPR", "EffectivenessTPR", "Attack detection rate is below the configured minimum.", "error"},
	{"XAMMU-EFF-FPR", "EffectivenessFPR", "False-positive rate is above the configured maximum.", "error"},
	{"XAMMU-EFF-PRECISION", "EffectivenessPrecision", "Precision is below the configured minimum.", "error"},
	{"XAMMU-EFF-EXCLUDED", "EffectivenessExcluded", "Excluded outcomes exceed the configured ratio.", "error"},
}

var checkToRule = func() map[string]ruleSpec {
	out := make(map[string]ruleSpec, len(checkRuleSpecs))
	for _, r := range checkRuleSpecs {
		out[checkIDOfRule(r.ID)] = r
	}
	return out
}()

// checkIDOfRule maps a stable SARIF rule id to the gate check it represents.
func checkIDOfRule(rule string) string {
	switch rule {
	case "XAMMU-EFF-TPR":
		return "effectiveness.tpr"
	case "XAMMU-EFF-FPR":
		return "effectiveness.fpr"
	case "XAMMU-EFF-PRECISION":
		return "effectiveness.precision"
	case "XAMMU-EFF-EXCLUDED":
		return "effectiveness.excluded_ratio"
	}
	return rule
}

// SARIF renders one run. A passing check produces no result: SARIF enumerates
// problems, while the JSON/YAML document enumerates every check.
func SARIF(d *Document, exitCode int) ([]byte, error) {
	var results []sarifResult
	rules := map[string]sarifRule{}

	addRule := func(spec ruleSpec, level string) {
		existing, ok := rules[spec.ID]
		if !ok {
			existing = sarifRule{ID: spec.ID, Name: spec.Name,
				ShortDescription:     sarifText{Text: spec.Description},
				DefaultConfiguration: sarifLevelOnly{Level: level},
			}
		} else if levelRank(level) > levelRank(existing.DefaultConfiguration.Level) {
			existing.DefaultConfiguration.Level = level
		}
		rules[spec.ID] = existing
	}

	for _, id := range checkOrder {
		check, ok := d.Checks[id]
		if !ok || check.Status != StatusFail || id == "findings.priority" {
			// findings.priority fails through one result per finding below, so a
			// generic result here would report the same fact twice.
			continue
		}
		spec, known := checkToRule[id]
		if !known {
			spec = ruleSpec{ID: "XAMMU-" + strings.ToUpper(strings.NewReplacer(".", "-", "_", "-").Replace(id)),
				Name:        strings.ReplaceAll(id, ".", ""),
				Description: "A gate check did not meet the policy.",
				Level:       "error",
			}
		}
		level := spec.Level
		addRule(spec, level)
		uri, line := evidenceLocation(check)
		message := checkMessage(id, check, d.Source.RunID)
		results = append(results, sarifResult{
			RuleID: spec.ID, Level: level,
			Message:             sarifText{Text: message},
			Locations:           []sarifLocation{location(uri, line)},
			PartialFingerprints: fingerprints(spec.ID, uri, line, message),
		})
	}

	if d.Policy.Findings != nil && d.Checks["findings.priority"].Status == StatusFail {
		floor := priorityRank(contracts.Priority(d.Policy.Findings.FailOnPriority))
		refs := make([]string, 0, len(d.Findings))
		for ref := range d.Findings {
			refs = append(refs, ref)
		}
		sort.Strings(refs)
		for _, ref := range refs {
			f := d.Findings[ref]
			if priorityRank(contracts.Priority(f.Priority)) < floor {
				continue
			}
			spec := ruleSpec{
				ID:          "XAMMU-FINDING-" + strings.ToUpper(strings.NewReplacer("-", "_", ".", "_").Replace(f.FindingType)),
				Name:        strings.ReplaceAll(f.FindingType, "_", ""),
				Description: "A sealed C-16 finding meets or exceeds the configured priority.",
			}
			level := sarifLevelForPriority(f.Priority)
			addRule(spec, level)
			uri, line := "findings.jsonl", f.Line
			message := fmt.Sprintf("%s finding %s (%s) meets or exceeds the configured priority %s "+
				"(evidence: findings.jsonl, run %s).", f.Priority, ref, f.FindingType,
				d.Policy.Findings.FailOnPriority, d.Source.RunID)
			results = append(results, sarifResult{
				RuleID: spec.ID, Level: level,
				Message:             sarifText{Text: message},
				Locations:           []sarifLocation{location(uri, line)},
				PartialFingerprints: fingerprints(spec.ID, uri, line, message),
			})
		}
	}

	ruleList := make([]sarifRule, 0, len(rules))
	for _, rule := range rules {
		ruleList = append(ruleList, rule)
	}
	sort.Slice(ruleList, func(i, j int) bool { return ruleList[i].ID < ruleList[j].ID })

	log := sarifLog{
		Schema:  sarifSchema,
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name: "XAMMU", SemanticVersion: semanticVersion(), Rules: ruleList,
			}},
			Invocations: []sarifInvocation{{ExecutionSuccessful: true, ExitCode: exitCode}},
			Results:     results,
		}},
	}
	raw, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

func checkMessage(id string, c Check, runID string) string {
	label := map[string]string{
		"effectiveness.tpr":            "TPR",
		"effectiveness.fpr":            "FPR",
		"effectiveness.precision":      "Precision",
		"effectiveness.excluded_ratio": "Excluded ratio",
	}[id]
	if label == "" {
		label = id
	}
	if c.Reason == reasonNoDenominator {
		return fmt.Sprintf("%s is null (%s) and cannot meet the policy threshold %s "+
			"(evidence: %s, run %s).", label, reasonNoDenominator, c.Threshold, c.Evidence, runID)
	}
	return fmt.Sprintf("%s %s does not meet the policy threshold %s (evidence: %s, run %s).",
		label, c.Observed, c.Threshold, c.Evidence, runID)
}

func evidenceLocation(c Check) (string, int) {
	uri := c.Evidence
	if comma := strings.Index(uri, ","); comma >= 0 {
		uri = uri[:comma]
	}
	uri = strings.TrimSpace(uri)
	if uri == "" {
		uri = "effectiveness_metrics.jsonl"
	}
	return uri, c.Line
}

func location(uri string, line int) sarifLocation {
	if line < 1 {
		line = 1
	}
	return sarifLocation{PhysicalLocation: sarifPhysical{
		ArtifactLocation: sarifArtifact{URI: uri},
		Region:           sarifRegion{StartLine: line},
	}}
}

func fingerprints(ruleID, uri string, line int, message string) map[string]string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%d|%s", ruleID, uri, line, message)))
	return map[string]string{"xammu/v1": fmt.Sprintf("%x", sum)}
}

func sarifLevelForPriority(priority string) string {
	switch priority {
	case "high":
		return "error"
	case "medium":
		return "warning"
	case "low":
		return "note"
	default:
		return "note"
	}
}

func levelRank(level string) int {
	switch level {
	case "error":
		return 3
	case "warning":
		return 2
	case "note":
		return 1
	}
	return 0
}

func semanticVersion() string {
	return strings.TrimPrefix(toolVersion(), "xammu-")
}
