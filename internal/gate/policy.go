package gate

import (
	"fmt"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"

	"xammu/internal/contracts"
	"xammu/internal/yamlish"
)

// PolicySchemaVersion names the policy document. Thresholds live in the file,
// never in the binary: changing the file changes the verdict and the seal.
const PolicySchemaVersion = "xammu.policy/v1"

// Policy is the parsed and normalized xammu.policy/v1 file.
type Policy struct {
	SHA256        string
	Effectiveness *EffectivenessPolicy
	Findings      *FindingsPolicy
}

// EffectivenessPolicy holds the E-03 thresholds. MinPrecision is a pointer
// because its absence means "do not evaluate precision", not "zero".
type EffectivenessPolicy struct {
	MinTPR           float64
	MaxFPR           float64
	MinPrecision     *float64
	MaxExcludedRatio float64
}

// FindingsPolicy holds the C-16 priority ceiling. There is no "critical" level
// in the contract, so a policy that asks for one is refused.
type FindingsPolicy struct {
	FailOnPriority contracts.Priority
}

var (
	policyTopKeys       = []string{"schema_version", "effectiveness", "findings"}
	policyEffectiveness = []string{"min_tpr", "max_fpr", "min_precision", "max_excluded_ratio"}
	policyFindings      = []string{"fail_on_priority"}
)

// LoadPolicy reads one YAML policy through the repository's own subset parser.
// Unknown keys, wrong types and out-of-range thresholds are refused before a
// bundle is read, so a typo cannot turn into a silent pass.
func LoadPolicy(path string) (*Policy, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot read policy %s: %v", ErrUnusable, path, err)
	}
	docs, err := yamlish.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: policy %s: %v", ErrUnusable, path, err)
	}
	if len(docs) != 1 {
		return nil, fmt.Errorf("%w: policy %s holds %d documents; a policy is one document",
			ErrUnusable, path, len(docs))
	}
	root, ok := docs[0].Root.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: policy %s: the root must be a mapping", ErrUnusable, path)
	}
	if err := rejectUnknown(root, policyTopKeys, "top level"); err != nil {
		return nil, fmt.Errorf("%w: policy %s: %v", ErrUnusable, path, err)
	}
	version, _ := root["schema_version"].(string)
	if version != PolicySchemaVersion {
		return nil, fmt.Errorf("%w: policy %s declares schema_version %q; this build reads %q",
			ErrUnusable, path, version, PolicySchemaVersion)
	}
	p := &Policy{SHA256: contracts.NewDigest(raw)}
	if section, ok := root["effectiveness"]; ok {
		parsed, err := parseEffectivenessPolicy(section)
		if err != nil {
			return nil, fmt.Errorf("%w: policy %s: effectiveness: %v", ErrUnusable, path, err)
		}
		p.Effectiveness = parsed
	}
	if section, ok := root["findings"]; ok {
		parsed, err := parseFindingsPolicy(section)
		if err != nil {
			return nil, fmt.Errorf("%w: policy %s: findings: %v", ErrUnusable, path, err)
		}
		p.Findings = parsed
	}
	if p.Effectiveness == nil && p.Findings == nil {
		return nil, fmt.Errorf("%w: policy %s declares neither an effectiveness nor a findings section; "+
			"a gate with no threshold would pass everything silently", ErrUnusable, path)
	}
	return p, nil
}

func parseEffectivenessPolicy(section any) (*EffectivenessPolicy, error) {
	m, ok := section.(map[string]any)
	if !ok || len(m) == 0 {
		return nil, fmt.Errorf("the section must be a non-empty mapping")
	}
	if err := rejectUnknown(m, policyEffectiveness, "effectiveness"); err != nil {
		return nil, err
	}
	out := &EffectivenessPolicy{}
	v, ok := m["min_tpr"]
	if !ok {
		return nil, fmt.Errorf("min_tpr is required")
	}
	var err error
	if out.MinTPR, err = policyRatio("min_tpr", v); err != nil {
		return nil, err
	}
	v, ok = m["max_fpr"]
	if !ok {
		return nil, fmt.Errorf("max_fpr is required")
	}
	if out.MaxFPR, err = policyRatio("max_fpr", v); err != nil {
		return nil, err
	}
	if v, ok := m["min_precision"]; ok {
		value, err := policyRatio("min_precision", v)
		if err != nil {
			return nil, err
		}
		out.MinPrecision = &value
	}
	out.MaxExcludedRatio = 0
	if v, ok := m["max_excluded_ratio"]; ok {
		if out.MaxExcludedRatio, err = policyRatio("max_excluded_ratio", v); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func parseFindingsPolicy(section any) (*FindingsPolicy, error) {
	m, ok := section.(map[string]any)
	if !ok || len(m) == 0 {
		return nil, fmt.Errorf("the section must be a non-empty mapping")
	}
	if err := rejectUnknown(m, policyFindings, "findings"); err != nil {
		return nil, err
	}
	raw, ok := m["fail_on_priority"]
	if !ok {
		return nil, fmt.Errorf("fail_on_priority is required")
	}
	value, ok := raw.(string)
	if !ok {
		return nil, fmt.Errorf("fail_on_priority must be a priority name")
	}
	value = strings.TrimSpace(value)
	if value == "critical" {
		return nil, fmt.Errorf("fail_on_priority %q is not a C-16 priority: XAMMU does not add a level "+
			"the evidence does not have. Use high, medium or low", value)
	}
	priority := contracts.Priority(value)
	for _, allowed := range contracts.AllPriorities() {
		if priority == allowed {
			return &FindingsPolicy{FailOnPriority: priority}, nil
		}
	}
	return nil, fmt.Errorf("fail_on_priority %q is not one of high, medium or low", value)
}

func policyRatio(key string, raw any) (float64, error) {
	text, ok := raw.(string)
	if !ok {
		return 0, fmt.Errorf("%s must be a decimal number", key)
	}
	text = strings.TrimSpace(text)
	if text == "" {
		return 0, fmt.Errorf("%s is empty", key)
	}
	value, err := strconv.ParseFloat(text, 64)
	if err != nil {
		return 0, fmt.Errorf("%s %q is not a decimal number", key, text)
	}
	if math.IsNaN(value) || math.IsInf(value, 0) || value < 0 || value > 1 {
		return 0, fmt.Errorf("%s %q is outside [0,1]", key, text)
	}
	return value, nil
}

// rejectUnknown names every key the policy wrote that this build does not read.
// A silently ignored typo is a threshold that was never applied.
func rejectUnknown(m map[string]any, allowed []string, where string) error {
	set := make(map[string]bool, len(allowed))
	for _, k := range allowed {
		set[k] = true
	}
	var unknown []string
	for k := range m {
		if !set[k] {
			unknown = append(unknown, k)
		}
	}
	if len(unknown) == 0 {
		return nil
	}
	sort.Strings(unknown)
	return fmt.Errorf("%s: unknown key(s) %s; this build reads %s", where,
		strings.Join(unknown, ", "), strings.Join(allowed, ", "))
}
