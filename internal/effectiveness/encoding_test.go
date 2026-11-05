package effectiveness

import (
	"net/url"
	"strings"
	"testing"

	"xammu/internal/contracts"
)

func TestTransformCoversEveryDeclaredEncoding(t *testing.T) {
	const payload = `a b<"'&>`
	cases := []struct {
		enc  contracts.Encoding
		want string
	}{
		{contracts.EncodingCanonical, payload},
		{contracts.EncodingURLSingle, url.QueryEscape(payload)},
		{contracts.EncodingURLDouble, url.QueryEscape(url.QueryEscape(payload))},
		{contracts.EncodingHTMLEntity, "a b&lt;&quot;&apos;&amp;&gt;"},
		{contracts.EncodingHTMLEntityNum, "a b&#60;&#34;&#39;&#38;&#62;"},
		{contracts.EncodingUnicodeEscape, `a b\u003c\u0022\u0027\u0026\u003e`},
		{contracts.EncodingCaseVariant, `a B<"'&>`},
		{contracts.EncodingCommentInsert, `a/**/b<"'&>`},
		{contracts.EncodingWhitespaceVar, "a\tb<\"'&>"},
		{contracts.EncodingMixedNested, url.QueryEscape("a b&#60;&#34;&#39;&#38;&#62;")},
	}
	for _, tc := range cases {
		got, err := Transform(payload, tc.enc)
		if err != nil {
			t.Fatalf("%s: %v", tc.enc, err)
		}
		if got != tc.want {
			t.Fatalf("%s = %q, want %q", tc.enc, got, tc.want)
		}
	}
}

func TestTransformKeepsTheDiagnosticMarkerLiteral(t *testing.T) {
	got, err := Transform(`' OR xammu-probe=1--`, contracts.EncodingCaseVariant)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "xammu-probe") {
		t.Fatalf("case variant %q lost the marker the target's log needs", got)
	}
}

func TestTransformRefusesAnUnknownEncoding(t *testing.T) {
	if _, err := Transform("x", contracts.Encoding("rot13")); err == nil {
		t.Fatal("unknown encoding was accepted")
	}
}
