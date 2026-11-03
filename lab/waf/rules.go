// rules.go holds the laboratory WAF's entire defensive surface: the rule table,
// the header and cookie policies, the legitimate-traffic allowlist and the
// response shapes. Nothing is decided anywhere else, so every rejection the
// proxy issues traces back to exactly one row here.
package main

import (
	"net"
	"regexp"
	"strings"
)

// BlockMarker is the literal token the interstitial embeds inside its <title>
// tag. XAMMU's profiler must be able to recognise a WAF rejection from the
// response body alone, so the strip-marker-headers mode exists precisely to
// prove it is not leaning on a giveaway header.
const BlockMarker = "XAMMU-LAB-WAF-BLOCK"

// Vector names one transport a request value can arrive in.
type Vector string

const (
	VectorPath        Vector = "path"
	VectorQueryString Vector = "query_string"
	VectorJSONBody    Vector = "json_body"
	VectorHeader      Vector = "header"
	VectorCookie      Vector = "cookie"
)

// AllVectors is the complete transport set the origin is able to read. The WAF
// inspects a strict subset of it; the difference is the coverage gap.
var AllVectors = []Vector{VectorPath, VectorQueryString, VectorJSONBody, VectorHeader, VectorCookie}

// MatchMode selects how a rule's pattern is evaluated against a candidate.
type MatchMode string

const (
	ModeKeyword MatchMode = "keyword" // case-insensitive substring
	ModeRegex   MatchMode = "regex"   // case-insensitive regexp
)

// Rule is one documented defensive behaviour.
//
// INVARIANT (the load-bearing design decision, see lab/README.md):
//
//	a candidate is percent-decoded EXACTLY ONCE before Pattern is evaluated.
//
// Every pattern below is written against that single-decode view. That is why
// double-encoded input slips through: after one decode it still carries its own
// percent escapes, so it no longer looks like the signature. No rule mentions
// "double" or "25" anywhere, and there is no special case for encoding depth.
type Rule struct {
	// ID is stable and appears in the rejection reason, so a finding can be
	// attributed to one row of this table.
	ID string
	// Description states the plausible production reason the rule exists.
	Description string
	// Vectors lists where this rule looks. A vector that is absent here is never
	// inspected for this shape -- that absence IS the coverage gap.
	Vectors []Vector
	// Mode selects the matcher.
	Mode MatchMode
	// Pattern is a lexical shape only. It must never be a syntactically
	// complete, executable payload.
	Pattern string
	// Allowlist: if a candidate contains one of these literals the rule does not
	// fire. Used only by SQLI-001 to model configured phrase exceptions.
	Allowlist []string

	matcher *regexp.Regexp
	literal string
}

func keywordRule(id, description string, vectors []Vector, pattern string, allowlist ...string) Rule {
	return Rule{ID: id, Description: description, Vectors: vectors, Mode: ModeKeyword, Pattern: pattern,
		literal: strings.ToLower(pattern), Allowlist: allowlist}
}

func regexRule(id, description string, vectors []Vector, pattern string, allowlist ...string) Rule {
	return Rule{ID: id, Description: description, Vectors: vectors, Mode: ModeRegex, Pattern: pattern,
		matcher: regexp.MustCompile("(?i)" + pattern), Allowlist: allowlist}
}

// Matches reports whether the rule fires on an already once-decoded candidate.
func (r *Rule) Matches(candidate string) bool {
	if candidate == "" {
		return false
	}
	lower := strings.ToLower(candidate)
	for _, benign := range r.Allowlist {
		if benign != "" && strings.Contains(lower, strings.ToLower(benign)) {
			return false
		}
	}
	switch r.Mode {
	case ModeRegex:
		return r.matcher.MatchString(candidate)
	case ModeKeyword:
		return strings.Contains(lower, r.literal)
	default:
		return false
	}
}

// ---------------------------------------------------------------------------
// Legitimate-traffic allowlist (over-blocking control)
//
// The fixture models an admin who added phrase exceptions for the most common
// English contractions, and nothing more. A protected contraction passes; every
// other apostrophe, and every double-quoted search term, still trips the
// signature. That residual gap is the measured false positive and it is
// reproducible because the corpus and the allowlist are both fixed.
// ---------------------------------------------------------------------------
var protectedContractions = []string{
	"don't", "it's", "can't", "won't", "i'm", "let's", "that's", "there's", "what's", "isn't",
}

// ---------------------------------------------------------------------------
// The rule table.
//
// COVERAGE -- which vectors are inspected:
//
//	path         inspected (TRAVERSAL-001, CMD-001, GENERIC-001)
//	query_string inspected (everything except the two header/cookie rules)
//	json_body    NOT inspected by any rule  <- behavior 1 of the lab spec
//	header       only header NAMES are matched against the policy denylist;
//	             header VALUES are never parsed <- behavior 3
//	cookie       only names starting with "lab_probe" or "xammu-" are scanned,
//	             and only for the cookie-vector shapes below <- behavior 3
//
// Stated reason for the json_body gap, in plain production terms: this fixture
// mirrors a deployment whose inspection is configured for the query string and
// whose body parsing is disabled. It is a configuration property of the proxy,
// not a randomised decision, and the same signature applied to the body vector
// would block the same string.
//
// ENCODING -- behavior 2 of the lab spec:
//
//	canonical      q=' or 1=1 xammu-probe          -> decoded once -> blocked
//	single encoded q=%27%20or%201%3d1%20xammu-probe-> decoded once -> blocked
//	double encoded q=%2527%2520or%25201%253d1%2520..-> decoded once -> forwarded
//
// The double-encoded form survives one decode as "%2527..." -> "%27%20or%2520..."
// which contains no quote, no space and no equals sign, so no signature fires.
// ---------------------------------------------------------------------------
var rules = []Rule{
	// --- SQL-shaped rules. Query string only. -------------------------------
	regexRule(
		"SQLI-001",
		"bare single quote in a query parameter; the classic first-order SQL injection marker",
		[]Vector{VectorQueryString},
		`'`,
		protectedContractions...,
	),
	regexRule(
		"SQLI-002",
		"bare double quote in a query parameter",
		[]Vector{VectorQueryString},
		`"`,
	),
	regexRule(
		"SQLI-003",
		"boolean tautology attached to a quote or comment marker",
		[]Vector{VectorQueryString},
		`(?:'|%27|--|#|;)\s*(?:or|and)\s*1\s*=\s*1`,
	),

	// --- XSS-shaped rules. Query string only. -------------------------------
	keywordRule(
		"XSS-001",
		"markup opener token; shape only, no event handler and no closing tag",
		[]Vector{VectorQueryString},
		"<xammu-probe-script",
	),
	keywordRule(
		"XSS-002",
		"script-ish URI scheme prefix; nothing follows the colon, so it cannot execute",
		[]Vector{VectorQueryString},
		"javascript:xammu-probe",
	),

	// --- Path-shaped rules. --------------------------------------------------
	keywordRule(
		"TRAVERSAL-001",
		"relative traversal prefix; the referenced path does not exist anywhere",
		[]Vector{VectorQueryString, VectorPath, VectorCookie},
		"../../xammu-probe",
	),
	keywordRule(
		"CMD-001",
		"command chaining separator around a marker; names no real binary",
		[]Vector{VectorQueryString, VectorPath},
		"; xammu-probe ;",
	),

	// --- Header / cookie shaped rules. --------------------------------------
	regexRule(
		"HEADER-001",
		"CRLF-then-marker shape inside an inspected header value",
		[]Vector{VectorHeader},
		`\r\n\s*xammu-probe`,
	),
	regexRule(
		"COOKIE-001",
		"assignment shape inside the lab cookie jar; models a serialized-payload signature",
		[]Vector{VectorCookie},
		`\bxammu-probe\s*=`,
	),

	// --- Control rule --------------------------------------------------------
	// Present in every inspected vector but NOT in json_body. This is the
	// always-block anchor the profiler uses to tell a WAF decision apart from an
	// origin error: a body-transported sentinel reaching the origin proves the
	// body was forwarded, because the same sentinel is unconditionally blocked
	// in any vector this fixture actually reads.
	keywordRule(
		"GENERIC-001",
		"laboratory sentinel token; unconditional inside every inspected vector",
		[]Vector{VectorPath, VectorQueryString, VectorHeader, VectorCookie},
		"xammu-probe-token",
	),
}

// RulesByID is the trace index used by the /__lab/info endpoint.
func RulesByID() []map[string]any {
	out := make([]map[string]any, 0, len(rules))
	for _, r := range rules {
		vectors := make([]string, 0, len(r.Vectors))
		for _, v := range r.Vectors {
			vectors = append(vectors, string(v))
		}
		out = append(out, map[string]any{
			"id":          r.ID,
			"description": r.Description,
			"mode":        string(r.Mode),
			"pattern":     r.Pattern,
			"vectors":     vectors,
			"allowlist":   r.Allowlist,
		})
	}
	return out
}

// InspectedVectors is the union of every vector appearing in the rule table.
// Anything outside it is, by construction, never inspected.
func InspectedVectors() []string {
	seen := map[string]bool{}
	out := []string{}
	for _, r := range rules {
		for _, v := range r.Vectors {
			if !seen[string(v)] {
				seen[string(v)] = true
				out = append(out, string(v))
			}
		}
	}
	return out
}

// UninspectedVectors is the complement of InspectedVectors over AllVectors.
// With the table above this is exactly ["json_body"] plus the header/cookie
// VALUE positions, which are named separately for documentation purposes.
func UninspectedVectors() []string {
	inspected := map[string]bool{}
	for _, v := range InspectedVectors() {
		inspected[v] = true
	}
	out := []string{}
	for _, v := range AllVectors {
		if !inspected[string(v)] {
			out = append(out, string(v))
		}
	}
	return out
}

// HeaderPolicy is a header-level decision keyed by header NAME. Header values
// are only ever evaluated by the rules whose Vectors include "header", and the
// diagnostic custom headers below are deliberately not in scope for any of
// them, so their values are never inspected.
type HeaderPolicy struct {
	Name     string
	Decision string // always_block
	Reason   string
}

var headerPolicies = []HeaderPolicy{
	{
		Name:     "x-lab-probe-transfer-encoding",
		Decision: "always_block",
		Reason:   "request-smuggling shape: the presence of this diagnostic header name is itself the signal; its value is never parsed",
	},
}

// DiagnosticHeaderPrefixes are the custom header families the profiler is
// expected to use. Their VALUES are never inspected, which is the documented
// reason behavior 3 of the lab spec holds for headers.
var DiagnosticHeaderPrefixes = []string{"x-lab-probe-", "x-xammu-"}

// InspectedCookiePrefixes are the cookie names scanned by the cookie-vector
// rules. Cookies outside this set are never inspected -- the documented second
// half of behavior 3. "lab_probe" covers lab_probe and lab_probe_payload; a name
// like xammu_probe_payload is deliberately outside the set, so the very same
// token is blocked in one cookie name and ignored in the other.
var InspectedCookiePrefixes = []string{"lab_probe", "xammu-"}

// DecomposedHeaders are request headers the engine parses into some other vector
// or treats as pure protocol metadata. Their raw value is NOT additionally
// matched as a header value. Without this, the Cookie header would be scanned
// twice -- once as a header and once as cookies -- and the cookie-side asymmetry
// would be unobservable, because any Cookie header would trip the sentinel rule.
// Note what is NOT in this list: User-Agent, Accept, Referer and any other
// ordinary header keeps its value in scope, which is why the custom-header gap is
// a specific documented gap and not a blanket "headers are never checked".
var DecomposedHeaders = []string{
	"cookie",
	"content-type",
	"content-length",
	"host",
	"connection",
	"accept-encoding",
	"transfer-encoding",
	"upgrade",
	"te",
}

// AllowedHosts restricts which absolute-form request targets the proxy forwards,
// so the fixture can never be used as an open relay.
var allowedHosts = map[string]bool{
	"localhost": true, "127.0.0.1": true, "origin": true, "waf": true, "::1": true, "[::1]": true,
}

func hostIsAllowed(host string) bool {
	h := strings.ToLower(host)
	if stripped, _, err := net.SplitHostPort(h); err == nil {
		h = stripped
	}
	h = strings.Trim(h, "[]")
	return allowedHosts[h]
}
