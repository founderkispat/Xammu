package effectiveness

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"xammu/internal/contracts"
	"xammu/internal/corpus"
	"xammu/internal/yamlish"
)

// MinimumAttackCases and MinimumBenignCases are the corpus floors Phase 1
// requires. Load reports the counts; Check enforces them, so unit fixtures can be
// small while an accepted corpus cannot.
const (
	MinimumAttackCases = 300
	MinimumBenignCases = 300
)

// caseKeys is the exact field set a corpus file may carry. An unknown key is an
// error rather than an ignored field: a typo in "expect" must not silently leave
// a case labelled by its default.
var caseKeys = map[string]bool{
	"id": true, "kind": true, "class": true, "payload": true, "vector": true,
	"encoding": true, "parameter": true, "method": true, "path": true,
	"expect": true, "owasp": true, "provenance": true, "rationale": true,
}

// Load reads every .yaml/.yml file under root in sorted order and gates each
// payload. The directory layout is free: one file per class, one file per
// category or one file for everything all load the same way, which is what lets
// the corpus grow past 2,800 cases without touching the engine.
func Load(root string, gate corpus.Policy) ([]Case, error) {
	if gate.MarkerToken == "" {
		return nil, fmt.Errorf("effectiveness: the inertness gate needs a marker token")
	}
	var files []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		name := strings.ToLower(d.Name())
		if strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("effectiveness: cannot read corpus %s: %w", root, err)
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("effectiveness: corpus %s holds no .yaml file", root)
	}
	sort.Strings(files)

	var out []Case
	seen := map[string]string{}
	for _, file := range files {
		raw, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("effectiveness: cannot read %s: %w", file, err)
		}
		docs, err := yamlish.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("effectiveness: %s: %w", filepath.ToSlash(file), err)
		}
		for _, doc := range docs {
			m, ok := doc.Root.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("effectiveness: %s line %d: a case must be a mapping",
					filepath.ToSlash(file), doc.Line)
			}
			c, err := decodeCase(m)
			if err != nil {
				return nil, fmt.Errorf("effectiveness: %s line %d: %w", filepath.ToSlash(file), doc.Line, err)
			}
			where := fmt.Sprintf("%s:%d", filepath.ToSlash(file), doc.Line)
			if prev, dup := seen[c.ID]; dup {
				return nil, fmt.Errorf("effectiveness: %s: id %q already defined at %s", where, c.ID, prev)
			}
			if err := c.Validate(); err != nil {
				return nil, fmt.Errorf("%s: %w", where, err)
			}
			if err := applyGate(&c, gate); err != nil {
				return nil, fmt.Errorf("%s: %w", where, err)
			}
			seen[c.ID] = where
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("effectiveness: corpus %s holds no case", root)
	}
	return out, nil
}

func decodeCase(m map[string]any) (Case, error) {
	var c Case
	for k := range m {
		if !caseKeys[k] {
			return c, fmt.Errorf("unknown field %q: a corpus file states only %s",
				k, strings.Join(sortedKeys(caseKeys), ", "))
		}
	}
	var err error
	if c.ID, err = stringField(m, "id"); err != nil {
		return c, err
	}
	if c.Kind, err = kindField(m, "kind"); err != nil {
		return c, err
	}
	if c.Class, err = stringField(m, "class"); err != nil {
		return c, err
	}
	if c.Payload, err = stringField(m, "payload"); err != nil {
		return c, err
	}
	var raw string
	if raw, err = stringField(m, "vector"); err != nil {
		return c, err
	}
	c.Vector = contracts.Vector(raw)
	if raw, err = stringField(m, "encoding"); err != nil {
		return c, err
	}
	c.Encoding = contracts.Encoding(raw)
	if c.Parameter, err = stringField(m, "parameter"); err != nil {
		return c, err
	}
	if c.Method, err = stringField(m, "method"); err != nil {
		return c, err
	}
	if c.Path, err = stringField(m, "path"); err != nil {
		return c, err
	}
	if raw, err = stringField(m, "expect"); err != nil {
		return c, err
	}
	c.Expect = Expectation(raw)
	if c.OWASP, err = stringField(m, "owasp"); err != nil {
		return c, err
	}
	if c.Provenance, err = stringField(m, "provenance"); err != nil {
		return c, err
	}
	if c.Rationale, err = stringField(m, "rationale"); err != nil {
		return c, err
	}
	return c, nil
}

func stringField(m map[string]any, key string) (string, error) {
	v, ok := m[key]
	if !ok {
		return "", nil
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("field %q is %T; every case field is a string", key, v)
	}
	return s, nil
}

func kindField(m map[string]any, key string) (Kind, error) {
	s, err := stringField(m, key)
	if err != nil {
		return "", err
	}
	return Kind(strings.ToLower(strings.TrimSpace(s))), nil
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// applyGate runs the inertness gate and records its verdict on the case. Benign
// traffic is ordinary by definition, so the missing marker is forgiven for it
// exactly as the diagnostic corpus already forgives it for a negative control;
// every other rule still applies.
func applyGate(c *Case, gate corpus.Policy) error {
	hits := gate.Check(c.Payload)
	if c.Kind == KindBenign {
		filtered := hits[:0]
		for _, h := range hits {
			if h.Rule == "inert.marker_absent" {
				continue
			}
			filtered = append(filtered, h)
		}
		hits = filtered
	}
	rules := make([]string, 0, len(hits))
	for _, h := range hits {
		rules = append(rules, h.Rule)
	}
	if len(hits) > 0 {
		c.Gate = GateRecord{Version: corpus.GateVersion, Verdict: "failed", RuleHits: rules}
		var why []string
		for _, h := range hits {
			why = append(why, h.Rule+" ("+h.Reason+")")
		}
		return fmt.Errorf("case %s is not inert: %s", c.ID, strings.Join(why, "; "))
	}
	c.Gate = GateRecord{Version: corpus.GateVersion, Verdict: "verified"}
	return nil
}

// Counting summarises a corpus for `effectiveness check`.
type Counting struct {
	Total    int
	Attack   int
	Benign   int
	ByClass  map[string]int
	ByKind   map[Kind]int
	ByVector map[contracts.Vector]int
	OWASP    map[string]string // attack class -> declared reference
}

// Count tallies a loaded corpus.
func Count(cases []Case) Counting {
	out := Counting{Total: len(cases), ByClass: map[string]int{}, ByKind: map[Kind]int{},
		ByVector: map[contracts.Vector]int{}, OWASP: map[string]string{}}
	for _, c := range cases {
		out.ByClass[c.Class]++
		out.ByKind[c.Kind]++
		out.ByVector[c.Vector]++
		if c.Kind == KindAttack {
			out.Attack++
			out.OWASP[c.Class] = c.OWASP
		} else {
			out.Benign++
		}
	}
	return out
}

// CheckMinimums refuses a corpus below the floors Phase 1 requires, naming what
// is short rather than only failing.
func (c Counting) CheckMinimums() error {
	var short []string
	if c.Attack < MinimumAttackCases {
		short = append(short, fmt.Sprintf("%d attack case(s), minimum %d", c.Attack, MinimumAttackCases))
	}
	if c.Benign < MinimumBenignCases {
		short = append(short, fmt.Sprintf("%d benign case(s), minimum %d", c.Benign, MinimumBenignCases))
	}
	if len(short) > 0 {
		return fmt.Errorf("effectiveness: corpus is below the Phase 1 floor: %s", strings.Join(short, "; "))
	}
	return nil
}
