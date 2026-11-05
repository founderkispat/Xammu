package effectiveness

import (
	"net/url"
	"strings"
	"testing"

	"xammu/internal/contracts"
)

const testOrigin = "http://127.0.0.1:8099"

func caseFor(vector contracts.Vector) Case {
	c := Case{
		ID: "case-001", Kind: KindAttack, Class: "sqli",
		Payload: `a b'`, Vector: vector, Encoding: contracts.EncodingCanonical,
		Parameter: "q", Method: "GET", Path: "/api/search",
		Expect: ExpectBlocked, OWASP: "A03:2021-Injection", Rationale: "shape",
	}
	if vector == contracts.VectorBodyJSON || vector == contracts.VectorBodyForm {
		c.Method = "POST"
	}
	if vector == contracts.VectorHeader {
		c.Parameter = "User-Agent"
	}
	if vector == contracts.VectorCookie {
		c.Parameter = "xammu-probe"
	}
	return c
}

func TestBuildRequestPlacesEachVector(t *testing.T) {
	q, err := BuildRequest(testOrigin, caseFor(contracts.VectorQuery), "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(q.URL, "q=a+b%27") {
		t.Fatalf("query URL = %s", q.URL)
	}
	if q.ProbeRef != "case-001" || q.CorpusRef != "case-001" {
		t.Fatalf("refs = %q/%q", q.ProbeRef, q.CorpusRef)
	}

	j, err := BuildRequest(testOrigin, caseFor(contracts.VectorBodyJSON), "")
	if err != nil {
		t.Fatal(err)
	}
	if string(j.Body) != `{"q":"a b'"}` || headerOf(j.Headers, "Content-Type") != "application/json" {
		t.Fatalf("json = %q %v", j.Body, j.Headers)
	}
	doc := caseFor(contracts.VectorBodyJSON)
	doc.Payload = `{"filters":{"open":true}}`
	jd, err := BuildRequest(testOrigin, doc, "")
	if err != nil {
		t.Fatal(err)
	}
	if string(jd.Body) != doc.Payload {
		t.Fatalf("a complete JSON document was rewrapped: %q", jd.Body)
	}

	f, err := BuildRequest(testOrigin, caseFor(contracts.VectorBodyForm), "")
	if err != nil {
		t.Fatal(err)
	}
	if string(f.Body) != "q=a+b%27" {
		t.Fatalf("form body = %q", f.Body)
	}

	h, err := BuildRequest(testOrigin, caseFor(contracts.VectorHeader), "")
	if err != nil {
		t.Fatal(err)
	}
	if headerOf(h.Headers, "User-Agent") != `a b'` {
		t.Fatalf("header = %v", h.Headers)
	}

	c, err := BuildRequest(testOrigin, caseFor(contracts.VectorCookie), "")
	if err != nil {
		t.Fatal(err)
	}
	want := "xammu-probe=" + url.QueryEscape(`a b'`)
	if headerOf(c.Headers, "Cookie") != want {
		t.Fatalf("cookie = %q, want %q", headerOf(c.Headers, "Cookie"), want)
	}
}

func TestBuildRequestRefusesRawCRLFInAHeaderValue(t *testing.T) {
	c := caseFor(contracts.VectorHeader)
	c.Payload = "value\r\nX-Test: 1"
	if _, err := BuildRequest(testOrigin, c, ""); err == nil {
		t.Fatal("raw CRLF was placed in a header")
	}
}

func TestBuildRequestEncodesTheCookieValue(t *testing.T) {
	c := caseFor(contracts.VectorCookie)
	c.Payload = "%0d%0aX-Test: 1"
	req, err := BuildRequest(testOrigin, c, "")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(headerOf(req.Headers, "Cookie"), "\r") ||
		strings.Contains(headerOf(req.Headers, "Cookie"), "\n") {
		t.Fatalf("cookie header carries a line break: %q", headerOf(req.Headers, "Cookie"))
	}
}

func TestBuildRequestPathVectorNeedsAPlaceholderAndEscapesTheValue(t *testing.T) {
	c := caseFor(contracts.VectorPath)
	c.Path = "/api/{probe}"
	c.Payload = "../../xammu-probe"
	req, err := BuildRequest(testOrigin, c, "")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(req.URL, "../") {
		t.Fatalf("path value was not escaped: %s", req.URL)
	}
	c.Path = "/api/search"
	if _, err := BuildRequest(testOrigin, c, ""); err == nil {
		t.Fatal("a path case without {probe} was accepted")
	}
	c.Path = "/api/{probe}"
	req, err = BuildRequest(testOrigin, c, "/api/search")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(req.URL, "/api/") {
		t.Fatalf("path override erased the placeholder: %s", req.URL)
	}
}

func TestBuildRequestRefusesMultipart(t *testing.T) {
	c := caseFor(contracts.VectorMultipart)
	if _, err := BuildRequest(testOrigin, c, ""); err == nil {
		t.Fatal("multipart was accepted")
	}
}

func TestBuildRequestNeverTakesAnOriginFromTheCase(t *testing.T) {
	c := caseFor(contracts.VectorQuery)
	c.Path = "http://evil.example/api/search"
	if _, err := BuildRequest(testOrigin, c, ""); err == nil {
		t.Fatal("a case supplied its own absolute destination")
	}
}

func TestSecurityHeadersReportsPresenceOnly(t *testing.T) {
	got := SecurityHeaders([]contracts.HeaderEntry{
		{Name: "Content-Security-Policy", Value: "default-src 'self'"},
		{Name: "x-frame-options", Value: "DENY"},
		{Name: "X-Frame-Options", Value: ""},
		{Name: "Server", Value: "xammu-lab-waf"},
	})
	if !got["content-security-policy"] || !got["x-frame-options"] {
		t.Fatalf("presence = %v", got)
	}
	if got["strict-transport-security"] {
		t.Fatalf("absent header reported present: %v", got)
	}
}

func headerOf(in []contracts.HeaderEntry, name string) string {
	for _, e := range in {
		if strings.EqualFold(e.Name, name) {
			return e.Value
		}
	}
	return ""
}
