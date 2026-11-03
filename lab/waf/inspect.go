// inspect.go is the laboratory WAF's decision engine. It collects the candidate
// values the configured vectors expose, applies the rule table from rules.go and
// returns a Decision. It never rewrites the request: the bytes that reach the
// origin are the bytes the client sent, which keeps the coverage report honest
// about normalization depth.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// Action is the proxy's verdict for a request.
type Action string

const (
	ActionForward Action = "forward"
	ActionReject  Action = "reject"
)

// maxInspectedBody bounds how much of a JSON body the WAF will buffer for
// coverage accounting. One fixed value, documented in README.
const maxInspectedBody = 1 << 20 // 1 MiB

// Candidate is one value the engine considered, with its transport and location.
type Candidate struct {
	Vector   Vector `json:"vector"`
	Location string `json:"location"`
	Value    string `json:"value"`
	// RawEncoded records whether Value is the on-the-wire form that still
	// carries percent escapes. It only selects which stdlib unescape is used,
	// never how many passes are performed.
	RawEncoded bool `json:"raw_encoded"`
}

// Decoded performs EXACTLY ONE percent-decoding pass over the candidate. That
// single pass is the whole normalization story of this fixture: matching happens
// on the result, so a value encoded twice is still escaped afterwards and no
// longer resembles any signature.
//
// It returns the decoded value, a note describing the pass, and false when the
// escaping is malformed -- in which case the candidate is left unjudged rather
// than guessed at.
func (c Candidate) Decoded() (decoded string, note string, judged bool) {
	var (
		out string
		err error
	)
	if c.Vector == VectorQueryString {
		// Query components additionally translate '+' to SP. That translation
		// is part of the same single pass, not a second one.
		out, err = url.QueryUnescape(c.Value)
	} else {
		out, err = url.PathUnescape(c.Value)
	}
	if err != nil {
		return c.Value, "malformed_percent_escape:left_candidate_unjudged", false
	}
	if out == c.Value {
		return out, "decoded_once_no_change", true
	}
	return out, "decoded_once", true
}

// WireValue is the value the origin will read for this candidate. The request is
// forwarded byte-for-byte, so a query-string candidate is seen by the origin in
// the single-decoded form net/url produces, and every other vector is seen
// exactly as sent.
func (c Candidate) WireValue() string {
	if c.Vector == VectorQueryString {
		decoded, _, _ := c.Decoded()
		return decoded
	}
	return c.Value
}

// Decision is the engine's output.
type Decision struct {
	Action        Action    `json:"action"`
	RuleID        string    `json:"rule_id,omitempty"`
	Reason        string    `json:"reason"`
	Vector        Vector    `json:"vector,omitempty"`
	Location      string    `json:"location,omitempty"`
	Matched       string    `json:"matched_value,omitempty"`
	Decoded       string    `json:"decoded_value,omitempty"`
	Normalization string    `json:"normalization"`
	Policy        string    `json:"policy"`
	Coverage      *Coverage `json:"-"`
}

func (d Decision) Blocked() bool { return d.Action == ActionReject }

// Coverage records, for one request, what the engine looked at and what it
// deliberately did not. The WAF serves it on /__lab/coverage so the JSON-body
// gap is provable instead of merely asserted.
type Coverage struct {
	Inspected     []map[string]any `json:"inspected"`
	NotInspected  []map[string]any `json:"not_inspected"`
	DecodePasses  int              `json:"decode_passes"`
	SignatureRule string           `json:"signature_identity_rule"`
	BodyConsumed  bool             `json:"body_replayed_to_origin"`
}

func newCoverage() *Coverage {
	return &Coverage{
		Inspected:     []map[string]any{},
		NotInspected:  []map[string]any{},
		DecodePasses:  1,
		SignatureRule: "SignatureOf(value) collapses every percent-encoded layer; two transports with equal signatures carry the same probe",
	}
}

func (c *Coverage) addInspected(candidate Candidate) {
	c.Inspected = append(c.Inspected, map[string]any{
		"vector":      string(candidate.Vector),
		"location":    candidate.Location,
		"value":       candidate.Value,
		"wire_value":  candidate.WireValue(),
		"signature":   SignatureOf(candidate.Value),
		"raw_encoded": candidate.RawEncoded,
	})
}

func (c *Coverage) addNotInspected(candidate Candidate, why string) {
	c.NotInspected = append(c.NotInspected, map[string]any{
		"vector":    string(candidate.Vector),
		"location":  candidate.Location,
		"value":     candidate.Value,
		"signature": SignatureOf(candidate.Value),
		"why":       why,
	})
}

// Inspect evaluates one request against the rule table.
func Inspect(r *http.Request) Decision {
	decision, _, _ := inspectRequest(r)
	return decision
}

// inspectRequest is the internal entry point: it also hands back the candidate
// set and the coverage record, which /__lab/coverage needs in order to report
// one check per transported value.
func inspectRequest(r *http.Request) (Decision, []Candidate, *Coverage) {
	candidates, coverage, parseNote := collectCandidates(r)

	// Step 1 -- header-name policies. Keyed by name, never by value.
	for _, policy := range headerPolicies {
		if _, present := lookupHeader(r, policy.Name); present {
			return Decision{
				Action:        ActionReject,
				RuleID:        "POLICY-HEADER-NAME",
				Reason:        policy.Reason,
				Vector:        VectorHeader,
				Location:      http.CanonicalHeaderKey(policy.Name),
				Policy:        "header_name_policy",
				Normalization: "none",
				Coverage:      coverage,
			}, candidates, coverage
		}
	}

	// Step 2 -- the rule table, over the configured vectors only.
	for _, rule := range rules {
		for _, candidate := range candidates {
			if !vectorIn(rule.Vectors, candidate.Vector) {
				continue
			}
			decoded, note, judged := candidate.Decoded()
			if !judged {
				continue
			}
			if rule.Matches(decoded) {
				return Decision{
					Action:        ActionReject,
					RuleID:        rule.ID,
					Reason:        rule.Description,
					Vector:        candidate.Vector,
					Location:      candidate.Location,
					Matched:       candidate.Value,
					Decoded:       decoded,
					Normalization: note,
					Policy:        "rule_table",
					Coverage:      coverage,
				}, candidates, coverage
			}
		}
	}

	// Step 3 -- default forward.
	reason := "no signature fired in any configured vector"
	if parseNote != "" {
		reason = parseNote
	}
	return Decision{
		Action:        ActionForward,
		Reason:        reason,
		Policy:        "default_forward",
		Normalization: "decoded_once_per_candidate",
		Coverage:      coverage,
	}, candidates, coverage
}

func vectorIn(vectors []Vector, v Vector) bool {
	for _, candidate := range vectors {
		if candidate == v {
			return true
		}
	}
	return false
}

// lookupHeader is a case-insensitive header lookup that reports ABSENCE rather
// than returning an empty string, so an intentionally empty diagnostic header
// cannot be mistaken for a present one.
func lookupHeader(r *http.Request, name string) (string, bool) {
	want := http.CanonicalHeaderKey(name)
	for key, vals := range r.Header {
		if key == want && len(vals) > 0 {
			return strings.Join(vals, ","), true
		}
	}
	return "", false
}

// collectCandidates flattens the vectors this fixture inspects and accounts for
// the ones it does not.
func collectCandidates(r *http.Request) ([]Candidate, *Coverage, string) {
	cov := newCoverage()
	var candidates []Candidate

	// path -- the escaped form, so the engine's single decode is the pass that
	// produces the effective path.
	escapedPath := r.URL.EscapedPath()
	pathCandidate := Candidate{Vector: VectorPath, Location: "request_target", Value: escapedPath}
	candidates = append(candidates, pathCandidate)
	cov.addInspected(pathCandidate)

	// query string
	for _, c := range queryCandidates(r.URL.RawQuery) {
		candidates = append(candidates, c)
		cov.addInspected(c)
	}

	// headers: values of non-diagnostic headers reach the rule table; diagnostic
	// custom header values are carried in the candidate set but stay outside the
	// rule table's vector list, so they are never matched -- and they are
	// accounted for as NOT inspected.
	for _, c := range headerCandidates(r) {
		candidates = append(candidates, c)
		if c.Vector == VectorHeader {
			cov.addInspected(c)
			continue
		}
		cov.addNotInspected(c, "diagnostic custom header values are outside the configured rule scope")
	}

	// cookies: only names in InspectedCookiePrefixes reach the rule table.
	for _, c := range cookieCandidates(r) {
		candidates = append(candidates, c)
		if c.Vector == VectorCookie {
			cov.addInspected(c)
			continue
		}
		cov.addNotInspected(c, "cookie name is outside InspectedCookiePrefixes")
	}

	// JSON body: parsed for accounting, never handed to the rule table. It is
	// still part of the candidate set so the coverage report can show the exact
	// value that travelled uninspected, which is what makes the gap measurable.
	note := ""
	if values, contentType, present := jsonBodyValues(r); present {
		cov.BodyConsumed = true
		for _, c := range values {
			candidates = append(candidates, c)
			cov.addNotInspected(c, "no rule in rules.go lists the json_body vector")
		}
		note = fmt.Sprintf("json body parsed for coverage accounting (%s); not inspected", contentType)
	}

	return candidates, cov, note
}

// queryCandidates splits RawQuery by hand. Doing it by hand matters: net/url's
// ParseQuery silently drops pairs whose escaping is malformed, which would hide
// a candidate instead of reporting it.
func queryCandidates(rawQuery string) []Candidate {
	if rawQuery == "" {
		return nil
	}
	out := []Candidate{}
	for _, pair := range strings.Split(rawQuery, "&") {
		if pair == "" {
			continue
		}
		name, value := pair, ""
		if eq := strings.Index(pair, "="); eq >= 0 {
			name, value = pair[:eq], pair[eq+1:]
		}
		decodedName, err := url.QueryUnescape(name)
		if err != nil {
			decodedName = name
		}
		out = append(out, Candidate{
			Vector: VectorQueryString, Location: decodedName, Value: value, RawEncoded: true,
		})
	}
	return out
}

// headerCandidates returns two kinds of entries: VectorHeader for values that
// reach the rule table, and Vector("header_value_uninspected") for diagnostic
// custom headers, which the caller records as not inspected.
const VectorHeaderUninspected Vector = "header_value_uninspected"

func headerCandidates(r *http.Request) []Candidate {
	out := []Candidate{}
	names := make([]string, 0, len(r.Header))
	for name := range r.Header {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		if isDecomposedHeader(strings.ToLower(name)) {
			continue // consumed by another vector, or protocol metadata
		}
		for i, value := range r.Header[name] {
			location := fmt.Sprintf("%s[%d]", name, i)
			if isDiagnosticHeader(strings.ToLower(name)) {
				out = append(out, Candidate{
					Vector: VectorHeaderUninspected, Location: location, Value: value,
				})
				continue
			}
			out = append(out, Candidate{Vector: VectorHeader, Location: location, Value: value})
		}
	}
	return out
}

// isDiagnosticHeader reports whether a header belongs to the custom diagnostic
// families whose VALUES are never parsed. The policy denylist is evaluated
// separately, before the rule table, so it is unaffected either way.
func isDiagnosticHeader(lowerName string) bool {
	for _, prefix := range DiagnosticHeaderPrefixes {
		if strings.HasPrefix(lowerName, prefix) {
			return true
		}
	}
	return false
}

// isDecomposedHeader reports whether a header is consumed as something other than
// a plain header value (cookies) or is pure protocol metadata. See
// DecomposedHeaders in rules.go for why this matters to behavior 3.
func isDecomposedHeader(lowerName string) bool {
	for _, name := range DecomposedHeaders {
		if lowerName == name {
			return true
		}
	}
	return false
}

const VectorCookieUninspected Vector = "cookie_value_uninspected"

func cookieCandidates(r *http.Request) []Candidate {
	out := []Candidate{}
	for _, cookie := range r.Cookies() {
		if cookieIsInspected(strings.ToLower(cookie.Name)) {
			out = append(out, Candidate{Vector: VectorCookie, Location: cookie.Name, Value: cookie.Value})
			continue
		}
		out = append(out, Candidate{Vector: VectorCookieUninspected, Location: cookie.Name, Value: cookie.Value})
	}
	return out
}

func cookieIsInspected(lowerName string) bool {
	for _, prefix := range InspectedCookiePrefixes {
		if strings.HasPrefix(lowerName, strings.ToLower(prefix)) {
			return true
		}
	}
	return false
}

// jsonBodyValues parses a JSON request body into scalar leaf candidates. It is
// called for accounting only: the returned candidates never reach the rule
// table. The body is buffered and re-served to the origin so the upstream still
// receives the exact bytes.
func jsonBodyValues(r *http.Request) ([]Candidate, string, bool) {
	contentType := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Type")))
	media := strings.TrimSpace(strings.Split(contentType, ";")[0])
	if media != "application/json" && !strings.HasSuffix(media, "+json") {
		return nil, contentType, false
	}
	if r.Body == nil {
		return nil, contentType, false
	}

	raw, err := io.ReadAll(io.LimitReader(r.Body, maxInspectedBody))
	if err != nil {
		return nil, contentType, false
	}
	r.Body = &replayableBody{buffered: raw}

	if len(strings.TrimSpace(string(raw))) == 0 {
		return nil, contentType, false
	}
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, contentType, false
	}
	out := []Candidate{}
	flattenJSON("", doc, &out)
	return out, contentType, true
}

func flattenJSON(path string, node any, out *[]Candidate) {
	switch v := node.(type) {
	case map[string]any:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			flattenJSON(joinJSONPath(path, k), v[k], out)
		}
	case []any:
		for i, item := range v {
			flattenJSON(fmt.Sprintf("%s[%d]", path, i), item, out)
		}
	case string:
		*out = append(*out, Candidate{Vector: VectorJSONBody, Location: pathOrRoot(path), Value: v})
	case float64:
		*out = append(*out, Candidate{Vector: VectorJSONBody, Location: pathOrRoot(path), Value: formatNumber(v)})
	case bool:
		*out = append(*out, Candidate{Vector: VectorJSONBody, Location: pathOrRoot(path), Value: fmt.Sprintf("%t", v)})
	case nil:
		*out = append(*out, Candidate{Vector: VectorJSONBody, Location: pathOrRoot(path), Value: "null"})
	}
}

func joinJSONPath(prefix, key string) string {
	if prefix == "" {
		return key
	}
	return prefix + "." + key
}

func pathOrRoot(path string) string {
	if path == "" {
		return "$"
	}
	return path
}

func formatNumber(f float64) string {
	if f == float64(int64(f)) {
		return fmt.Sprintf("%d", int64(f))
	}
	return fmt.Sprintf("%g", f)
}

// SignatureOf returns the canonical, transport-independent identity of a value:
// what it looks like once every percent-encoded layer has been collapsed. Two
// transports carrying the same signature carry the same probe, which is the
// comparison the vector-asymmetry finding has to make.
//
// Only the accounting path uses it. Matching stays strictly a single pass (see
// Candidate.Decoded), so this depth never changes a verdict.
func SignatureOf(value string) string {
	seen := map[string]bool{value: true}
	current := value
	for i := 0; i < 8; i++ {
		next, err := url.QueryUnescape(current)
		if err != nil || next == current || seen[next] {
			break
		}
		seen[next] = true
		current = next
	}
	return current
}

// replayableBody lets the origin read the exact body bytes after the WAF has
// buffered them for coverage accounting.
type replayableBody struct {
	buffered []byte
}

func (b *replayableBody) Read(p []byte) (int, error) {
	if len(b.buffered) > 0 {
		n := copy(p, b.buffered)
		b.buffered = b.buffered[n:]
		return n, nil
	}
	return 0, io.EOF
}

func (b *replayableBody) Close() error { return nil }
