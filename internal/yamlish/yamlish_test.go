package yamlish

import (
	"strings"
	"testing"
)

func one(t *testing.T, src string) map[string]any {
	t.Helper()
	docs, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("Parse(%q): %v", src, err)
	}
	if len(docs) != 1 {
		t.Fatalf("Parse(%q) returned %d documents, want 1", src, len(docs))
	}
	m, ok := docs[0].Root.(map[string]any)
	if !ok {
		t.Fatalf("root is %T, want map[string]any", docs[0].Root)
	}
	return m
}

func TestParseScalarsAndNesting(t *testing.T) {
	m := one(t, `id: sqli-001
class: sqli
nested:
  vector: query
  encoding: canonical
list:
  - one
  - two
`)
	if m["id"] != "sqli-001" || m["class"] != "sqli" {
		t.Fatalf("scalars decoded as %#v", m)
	}
	nested, ok := m["nested"].(map[string]any)
	if !ok || nested["vector"] != "query" || nested["encoding"] != "canonical" {
		t.Fatalf("nested mapping decoded as %#v", m["nested"])
	}
	list, ok := m["list"].([]any)
	if !ok || len(list) != 2 || list[0] != "one" || list[1] != "two" {
		t.Fatalf("sequence decoded as %#v", m["list"])
	}
}

func TestParseQuotedScalarsKeepPunctuation(t *testing.T) {
	m := one(t, `single: 'it''s a payload: # not a comment'
double: "a\tb\"c"
plain: a#b
owasp: A03:2021-Injection
`)
	if m["single"] != "it's a payload: # not a comment" {
		t.Fatalf("single-quoted = %q", m["single"])
	}
	if m["double"] != "a\tb\"c" {
		t.Fatalf("double-quoted = %q", m["double"])
	}
	if m["plain"] != "a#b" {
		t.Fatalf("plain with embedded hash = %q", m["plain"])
	}
	if m["owasp"] != "A03:2021-Injection" {
		t.Fatalf("colon inside a value split the key: %q", m["owasp"])
	}
}

func TestParseCommentsAndDocuments(t *testing.T) {
	src := `# leading comment
id: first
# between
---
id: second
---
id: third
`
	docs, err := Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if len(docs) != 3 {
		t.Fatalf("got %d documents, want 3", len(docs))
	}
	for i, want := range []string{"first", "second", "third"} {
		m := docs[i].Root.(map[string]any)
		if m["id"] != want {
			t.Fatalf("document %d id = %v, want %s", i, m["id"], want)
		}
	}
}

func TestParseEmptyValueIsEmptyString(t *testing.T) {
	m := one(t, "id: x\nowasp:\n")
	if m["owasp"] != "" {
		t.Fatalf("empty value = %#v, want empty string", m["owasp"])
	}
}

func TestParseRefusals(t *testing.T) {
	cases := map[string]string{
		"duplicate key":       "id: a\nid: b\n",
		"tab":                 "id:\ta\n",
		"odd indent":          "id: a\n class: x\n",
		"flow sequence":       "classes: [a, b]\n",
		"anchor":              "id: &a x\n",
		"alias":               "id: *a\n",
		"tag":                 "id: !t x\n",
		"block scalar":        "payload: |\n  x\n",
		"sequence of mapping": "list:\n  - id: x\n",
		"unterminated quote":  "id: 'x\n",
		"unterminated double": `id: "x` + "\n",
		"no document":         "# only a comment\n",
		"nested wrong indent": "a:\n    b: c\n",
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(src)); err == nil {
				t.Fatalf("Parse(%q) accepted a construct the subset refuses", src)
			}
		})
	}
}

func TestParseCRLFIsNormalised(t *testing.T) {
	m := one(t, "id: a\r\nclass: sqli\r\n")
	if m["id"] != "a" || m["class"] != "sqli" {
		t.Fatalf("CRLF source decoded as %#v", m)
	}
}

func TestParseReportsTheLine(t *testing.T) {
	_, err := Parse([]byte("id: a\nclass: [x]\n"))
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "line 2") {
		t.Fatalf("error does not locate the offending line: %v", err)
	}
}
