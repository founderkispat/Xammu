package effectiveness

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"xammu/internal/contracts"
	"xammu/internal/corpus"
)

func attackCase() Case {
	return Case{
		ID: "sqli-001", Kind: KindAttack, Class: "sqli",
		Payload: `' OR xammu-probe=1--`,
		Vector:  contracts.VectorQuery, Encoding: contracts.EncodingCanonical,
		Parameter: "q", Method: "GET", Path: "/api/search",
		Expect: ExpectBlocked, OWASP: "A03:2021-Injection",
		Rationale: "canonical SQLi shape in the query string",
	}
}

func benignCase() Case {
	return Case{
		ID: "benign-001", Kind: KindBenign, Class: "benign_text",
		Payload: "Call me Ishmael.",
		Vector:  contracts.VectorQuery, Encoding: contracts.EncodingCanonical,
		Parameter: "q", Method: "GET", Path: "/api/search",
		Expect:     ExpectAllowed,
		Provenance: "Herman Melville, Moby-Dick (1851)",
		Rationale:  "public-domain prose used as a legitimate search query",
	}
}

func TestValidateAcceptsTheTwoPopulations(t *testing.T) {
	a := attackCase()
	if err := a.Validate(); err != nil {
		t.Fatal(err)
	}
	b := benignCase()
	if err := b.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestValidateRefusesAmbiguousCases(t *testing.T) {
	cases := map[string]func(*Case){
		"unknown attack class": func(c *Case) { c.Class = "made_up" },
		"attack expecting allowed": func(c *Case) {
			c.Expect = ExpectAllowed
		},
		"attack without OWASP": func(c *Case) { c.OWASP = "" },
		"unknown vector":       func(c *Case) { c.Vector = contracts.Vector("socket") },
		"unknown encoding":     func(c *Case) { c.Encoding = contracts.Encoding("rot13") },
		"path traversal":       func(c *Case) { c.Path = "/api/../etc" },
		"relative path":        func(c *Case) { c.Path = "api/search" },
		"non-token header":     func(c *Case) { c.Vector = contracts.VectorHeader; c.Parameter = "bad name" },
		"benign text without provenance": func(c *Case) {
			c.Kind = KindBenign
			c.Class = "benign_text"
			c.Expect = ExpectAllowed
		},
		"blank rationale": func(c *Case) { c.Rationale = "" },
		"empty payload":   func(c *Case) { c.Payload = "" },
	}
	for name, mutate := range cases {
		c := attackCase()
		mutate(&c)
		if err := c.Validate(); err == nil {
			t.Fatalf("%s: Validate accepted the case", name)
		}
	}
}

func TestNormalizeFillsTransportDefaults(t *testing.T) {
	c := Case{ID: "x", Kind: KindAttack, Class: "sqli", Payload: "xammu-probe",
		OWASP: "A03:2021-Injection", Rationale: "shape"}
	c.Normalize()
	if c.Vector != contracts.VectorQuery || c.Encoding != contracts.EncodingCanonical {
		t.Fatalf("defaults = %q/%q", c.Vector, c.Encoding)
	}
	if c.Method != "GET" || c.Path != "/api/search" || c.Parameter != "q" || c.Expect != ExpectBlocked {
		t.Fatalf("defaults = %q %q %q %q", c.Method, c.Path, c.Parameter, c.Expect)
	}
	if c.PayloadDigest == "" {
		t.Fatal("payload digest was not derived")
	}
}

func TestLoadGatesAndRejectsNonInertAttackCases(t *testing.T) {
	dir := t.TempDir()
	bad := strings.Join([]string{
		`id: "x-001"`,
		`kind: "attack"`,
		`class: "xss"`,
		`payload: "<script>xammu-probe</script>"`,
		`vector: "query"`,
		`encoding: "canonical"`,
		`parameter: "q"`,
		`method: "GET"`,
		`path: "/api/search"`,
		`expect: "blocked"`,
		`owasp: "A03:2021-Injection"`,
		`rationale: "executable shape the gate must refuse"`,
		"",
	}, "\n")
	if err := os.WriteFile(filepath.Join(dir, "bad.yaml"), []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(dir, corpus.DefaultPolicy())
	if err == nil || !strings.Contains(err.Error(), "not inert") {
		t.Fatalf("Load returned %v; want an inertness refusal", err)
	}
}

func TestLoadAcceptsBenignWithoutTheMarkerButNotAnExecutableShape(t *testing.T) {
	dir := t.TempDir()
	good := benignCase()
	raw := strings.Join([]string{
		`id: "benign-001"`, `kind: "benign"`, `class: "benign_text"`,
		`payload: "Call me Ishmael."`, `vector: "query"`, `encoding: "canonical"`,
		`parameter: "q"`, `method: "GET"`, `path: "/api/search"`, `expect: "allowed"`,
		`provenance: "Herman Melville, Moby-Dick (1851)"`,
		`rationale: "public-domain prose"`, "",
	}, "\n")
	if err := os.WriteFile(filepath.Join(dir, "good.yaml"), []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	cases, err := Load(dir, corpus.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) != 1 || cases[0].Gate.Verdict != "verified" {
		t.Fatalf("cases = %+v", cases)
	}
	if cases[0].ID != good.ID {
		t.Fatalf("id = %q", cases[0].ID)
	}
}

func TestLoadRefusesUnknownFieldsAndDuplicateIDs(t *testing.T) {
	base := strings.Join([]string{
		`id: "dup-001"`, `kind: "attack"`, `class: "sqli"`,
		`payload: "' xammu-probe"`, `vector: "query"`, `encoding: "canonical"`,
		`parameter: "q"`, `method: "GET"`, `path: "/api/search"`, `expect: "blocked"`,
		`owasp: "A03:2021-Injection"`, `rationale: "shape"`,
	}, "\n")
	for name, body := range map[string]string{
		"unknown field": base + "\nseverity: \"high\"\n",
		"duplicate id":  base + "\n---\n" + base + "\n",
	} {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "cases.yaml"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(dir, corpus.DefaultPolicy()); err == nil {
			t.Fatalf("%s: Load accepted the file", name)
		}
	}
}
