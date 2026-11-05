package tamper

import (
	"encoding/base64"
	"net/url"
	"strings"
	"testing"

	"xammu/internal/contracts"
)

var marker = "xammu-probe"

func TestValidateRefusesStacksThatAreNotExactlyDescribed(t *testing.T) {
	cases := []struct {
		name  string
		stack Stack
		want  string
	}{
		{"empty", nil, "empty stack"},
		{"too deep", Stack{
			contracts.TamperURLEncode, contracts.TamperURLEncodeDouble,
			contracts.TamperCaseSwitch, contracts.TamperSQLComment}, "exceeds the limit"},
		{"duplicate", Stack{contracts.TamperURLEncode, contracts.TamperURLEncode}, "appears twice"},
		{"unknown", Stack{contracts.Tamper("chunked")}, "not in the vocabulary"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.stack.Validate()
			if err == nil {
				t.Fatalf("stack %v was accepted", tc.stack)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

func TestStackDepthBoundary(t *testing.T) {
	ok := Stack{contracts.TamperURLEncode, contracts.TamperSQLComment, contracts.TamperCaseSwitch}
	if err := ok.Validate(); err != nil {
		t.Fatalf("a three-primitive stack must be legal: %v", err)
	}
}

func TestParse(t *testing.T) {
	s, err := Parse(" url_encode_double , sql_comment ")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(s) != 2 || s[0] != contracts.TamperURLEncodeDouble || s[1] != contracts.TamperSQLComment {
		t.Fatalf("unexpected stack %v", s)
	}
	if none, err := Parse("  "); err != nil || none != nil {
		t.Fatalf("an empty list must mean baseline, got %v, %v", none, err)
	}
	if _, err := Parse("url_encode,chunked"); err == nil {
		t.Fatal("chunked must be refused by name")
	}
}

func TestApplyURLEncodings(t *testing.T) {
	value := "' OR xammu-probe=1--"
	once, err := Apply(value, Stack{contracts.TamperURLEncode}, marker)
	if err != nil {
		t.Fatal(err)
	}
	if once != url.QueryEscape(value) {
		t.Fatalf("single encode = %q", once)
	}
	twice, err := Apply(value, Stack{contracts.TamperURLEncodeDouble}, marker)
	if err != nil {
		t.Fatal(err)
	}
	if twice != url.QueryEscape(url.QueryEscape(value)) {
		t.Fatalf("double encode = %q", twice)
	}
	if got, err := url.QueryUnescape(once); err != nil || got != value {
		t.Fatalf("single encode is not reversible: %q, %v", got, err)
	}
}

func TestApplyBase64IsReversibleAndErasesTheInlineMarker(t *testing.T) {
	value := "xammu-probe' OR '1'='1"
	encoded, err := Apply(value, Stack{contracts.TamperBase64}, marker)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || string(raw) != value {
		t.Fatalf("base64 is not reversible: %q, %v", raw, err)
	}
	if CarriesMarker(encoded, marker) {
		t.Fatal("base64 of the whole value must not still carry the marker inline")
	}
	base64Stack := Stack{contracts.TamperBase64}
	if !base64Stack.NeedsMarkerHeader() {
		t.Fatal("a base64 stack must declare that it needs the marker header")
	}
	if (Stack{contracts.TamperURLEncode}).NeedsMarkerHeader() {
		t.Fatal("a marker-preserving stack must not request the header")
	}
}

func TestEveryOtherPrimitiveKeepsTheMarker(t *testing.T) {
	payloads := []string{
		"xammu-probe' OR '1'='1",
		"<script>xammu-probe</script>",
		"../../etc/xammu-probe",
		"; xammu-probe",
		"xammu-probe\r\nX-Lab: 1",
		"{{7*7}}xammu-probe",
	}
	for _, p := range payloads {
		for _, prim := range contracts.AllTampers() {
			if !PreservesMarker(prim) {
				continue
			}
			out, err := Apply(p, Stack{prim}, marker)
			if err != nil {
				t.Fatalf("%s/%q: %v", prim, p, err)
			}
			if !CarriesMarker(out, marker) {
				t.Errorf("%s erased the marker from %q: %q", prim, p, out)
			}
		}
	}
}

func TestCaseSwitchLeavesTheMarkerExact(t *testing.T) {
	out, err := Apply("' OR xammu-probe=1--", Stack{contracts.TamperCaseSwitch}, "XAMMU-PROBE")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "xammu-probe") {
		t.Fatalf("marker was rewritten: %q", out)
	}
}

func TestSQLCommentAndWhitespace(t *testing.T) {
	comment, err := Apply("1' OR xammu-probe=1--", Stack{contracts.TamperSQLComment}, marker)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(comment, "/**/") || strings.Contains(comment, " ") {
		t.Fatalf("sql_comment did not remove spaces: %q", comment)
	}
	commentEncoded, err := Apply("1+OR+xammu-probe=1", Stack{contracts.TamperSQLComment}, marker)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(commentEncoded, "+") {
		t.Fatalf("sql_comment left an encoded space: %q", commentEncoded)
	}
	ws, err := Apply("1 OR xammu-probe=1", Stack{contracts.TamperWhitespace}, marker)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ws, "\t") {
		t.Fatalf("whitespace_variant did not insert a tab: %q", ws)
	}
}

func TestHTMLAndUnicodeEscapes(t *testing.T) {
	html, err := Apply("<xammu-probe>", Stack{contracts.TamperHTMLEntity}, marker)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(html, "&lt;") || !strings.Contains(html, "&gt;") {
		t.Fatalf("html_entity = %q", html)
	}
	uni, err := Apply("<xammu-probe>", Stack{contracts.TamperUnicodeEscape}, marker)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(uni, `\u003c`) || !strings.Contains(uni, `\u003e`) {
		t.Fatalf("unicode_escape = %q", uni)
	}
}

func TestOrderIsPartOfTheStack(t *testing.T) {
	a, err := Apply("a b", Stack{contracts.TamperURLEncode, contracts.TamperSQLComment}, marker)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Apply("a b", Stack{contracts.TamperSQLComment, contracts.TamperURLEncode}, marker)
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatalf("the stack order did not change the result: %q", a)
	}
}

func TestApplyRefusesAnInvalidStack(t *testing.T) {
	if _, err := Apply("x", Stack{contracts.Tamper("chunked")}, marker); err == nil {
		t.Fatal("Apply accepted an unknown primitive")
	}
}
