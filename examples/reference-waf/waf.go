// Package main is the XAMMU reference WAF: a demonstration fixture, not a
// product and not a benchmark. Its only job is to give the Phase 3 gate a
// target that is strong enough for the reference policy and honest about why:
// every rule is written down here, the corpus it is calibrated against is in
// this repository, and nothing it does executes a payload.
//
// It listens in front of the laboratory origin and inspects path, query,
// headers, cookies and both body encodings with up to three percent-decode
// passes. A request is blocked only when the marker token AND a class-shaped
// token appear in the same normalized value: a marker without a shape is a
// probe the fixture cannot classify, and a shape without a marker is ordinary
// traffic that may legitimately contain a quote.
package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const (
	// ServerName is the origin-visible identity of the fixture.
	ServerName = "xammu-reference-waf/1.0"
	// BlockMarker is embedded in the rejection page so a reader can tell a
	// decision from an origin failure without trusting a header.
	BlockMarker = "XAMMU-REFERENCE-WAF-BLOCK"
	// MarkerToken is the inert marker every corpus attack carries.
	MarkerToken = "xammu-probe"
	// MaxBodyBytes bounds what the fixture reads and inspects.
	MaxBodyBytes = 1 << 20
)

// Decision is one request's outcome. A request that produced no decision is
// forwarded; the reason fields are empty in that case.
type Decision struct {
	Blocked  bool
	RuleID   string
	Class    string
	Location string
	Reason   string
}

type classRule struct {
	ID     string
	Class  string
	Shapes []string
	Reason string
}

// classRules is the whole defensive surface. The marker requirement lives in
// matchValue, not in the table, so every row is automatically compound.
var classRules = []classRule{
	{
		ID: "REF-SQLI", Class: "sqli",
		Shapes: []string{"'", `"`, "--", " or ", " and ", "having", "order by", "returning", "like"},
		Reason: "SQL-shaped syntax next to the probe marker",
	},
	{
		ID: "REF-XSS", Class: "xss",
		Shapes: []string{"<", "javascript:"},
		Reason: "markup or script URI next to the probe marker",
	},
	{
		ID: "REF-TRAVERSAL", Class: "path_traversal",
		Shapes: []string{".."},
		Reason: "relative traversal next to the probe marker",
	},
	{
		ID: "REF-CMD", Class: "command_injection",
		Shapes: []string{";", "&&", "|", "${", "\n", "\r", "2>"},
		Reason: "command chaining or substitution next to the probe marker",
	},
	{
		ID: "REF-SSRF", Class: "ssrf",
		Shapes: []string{"//", "http:", "https:", "localhost", "127.", "[::1]"},
		Reason: "an embedded destination next to the probe marker",
	},
	{
		ID: "REF-CRLF", Class: "crlf_injection",
		Shapes: []string{"\r", "\n"},
		Reason: "a line break next to the probe marker",
	},
	{
		ID: "REF-LDAP", Class: "ldap_injection",
		Shapes: []string{"*", "(", ")", `\00`},
		Reason: "LDAP filter syntax next to the probe marker",
	},
	{
		ID: "REF-XXE", Class: "xxe",
		Shapes: []string{"<!doctype", "<!entity", "<?xml", "<", "&"},
		Reason: "an XML declaration or entity next to the probe marker",
	},
	{
		ID: "REF-NOSQL", Class: "nosql_injection",
		Shapes: []string{"$", "||", "'", `"`},
		Reason: "a document operator next to the probe marker",
	},
	{
		ID: "REF-SSTI", Class: "ssti",
		Shapes: []string{"{", "<%"},
		Reason: "a template expression next to the probe marker",
	},
}

type candidate struct {
	location string
	value    string
}

// Inspect decides one request. body is the already-read request body, so the
// caller can forward the same bytes after inspection.
func Inspect(r *http.Request, body []byte) Decision {
	for _, c := range candidates(r, body) {
		if d, ok := matchValue(c); ok {
			return d
		}
	}
	return Decision{}
}

func candidates(r *http.Request, body []byte) []candidate {
	out := []candidate{
		{location: "path", value: r.URL.EscapedPath()},
		{location: "path", value: r.URL.Path},
	}
	if r.URL.RawQuery != "" {
		out = append(out, candidate{location: "query", value: r.URL.RawQuery})
	}
	for _, values := range r.URL.Query() {
		for _, v := range values {
			out = append(out, candidate{location: "query", value: v})
		}
	}
	for name, values := range r.Header {
		for _, v := range values {
			out = append(out, candidate{location: "header:" + strings.ToLower(name), value: v})
		}
	}
	for _, cookie := range r.Cookies() {
		out = append(out, candidate{location: "cookie:" + cookie.Name, value: cookie.Value})
	}
	out = append(out, bodyCandidates(r.Header.Get("Content-Type"), body)...)
	return out
}

// bodyCandidates reads JSON and form bodies structurally so an escaped quote or
// a \u003c does not hide a shape from the matcher. A body that does not parse
// is still inspected as text: refusing to look would be a gap, not a policy.
func bodyCandidates(contentType string, body []byte) []candidate {
	if len(body) == 0 {
		return nil
	}
	mediaType := strings.ToLower(strings.TrimSpace(strings.SplitN(contentType, ";", 2)[0]))
	// The raw body is inspected as well as its decoded fields: a document such
	// as {"$or":[{"xammu-probe":"x"}]} keeps the marker and the operator in
	// different JSON tokens, and splitting them would let it pass.
	raw := candidate{location: "body", value: string(body)}
	switch {
	case strings.Contains(mediaType, "json"):
		var value any
		if err := json.Unmarshal(body, &value); err == nil {
			var out []candidate
			walkJSON(value, func(s string) {
				out = append(out, candidate{location: "body_json", value: s})
			})
			return append(out, raw)
		}
	case mediaType == "application/x-www-form-urlencoded":
		if values, err := url.ParseQuery(string(body)); err == nil {
			var out []candidate
			for _, list := range values {
				for _, v := range list {
					out = append(out, candidate{location: "body_form", value: v})
				}
			}
			return append(out, raw)
		}
	}
	return []candidate{raw}
}

func walkJSON(value any, visit func(string)) {
	switch v := value.(type) {
	case string:
		visit(v)
	case []any:
		for _, item := range v {
			walkJSON(item, visit)
		}
	case map[string]any:
		for key, item := range v {
			visit(key)
			walkJSON(item, visit)
		}
	}
}

// matchValue requires both facts in one normalized value. Splitting them across
// two transports would let an ordinary request that mentions the marker once
// and a quote once look like an attack.
func matchValue(c candidate) (Decision, bool) {
	value := normalize(c.value)
	if !strings.Contains(value, MarkerToken) {
		return Decision{}, false
	}
	for _, rule := range classRules {
		for _, shape := range rule.Shapes {
			if strings.Contains(value, shape) {
				return Decision{
					Blocked: true, RuleID: rule.ID, Class: rule.Class,
					Location: c.location, Reason: rule.Reason,
				}, true
			}
		}
	}
	return Decision{}, false
}

// normalize applies up to three percent-decode passes and lowercases. Three is
// enough for the corpus's deepest encoding and is a bound, not a loop until
// stable: an unbounded decoder is a denial-of-service primitive.
func normalize(s string) string {
	for i := 0; i < 3; i++ {
		decoded, err := url.PathUnescape(s)
		if err != nil || decoded == s {
			break
		}
		s = decoded
	}
	return strings.ToLower(s)
}

func readBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxBodyBytes))
	if err != nil {
		return nil, err
	}
	return body, r.Body.Close()
}
