// coverage.go is the fixture's introspection surface: it answers "what did the
// WAF look at, what did it deliberately skip, and what did the origin make of
// it?" for one probe, and it serves the live rule table.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// handleCoverage builds a single probe request, runs it through the real
// decision engine, then forwards the very same bytes to the origin, so the
// reported decision and the reported origin evidence cannot drift apart.
//
// Query parameters:
//
//	transport     query_string | json_body | header | cookie | path  (required)
//	values        percent-encoded candidate values (optional; when omitted the
//	              values are taken from the request the caller already shaped)
//	locations     parallel list of parameter / header / cookie names
//	raw_query     a literal query string, used instead of building one
//	path          request path, default /api/search
//	method        request method, default GET
//	body          request body, sent verbatim
//	content_type  body content type, defaults to application/json when body is set
//	header_name   header to carry values under (transport=header)
//	cookie_name   cookie to carry values under (transport=cookie)
func (p *Proxy) handleCoverage(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	transport := Vector(strings.TrimSpace(q.Get("transport")))
	if transport == "" {
		transport = VectorJSONBody
	}
	if !knownTransport(transport) {
		p.writePlainJSON(w, http.StatusBadRequest, map[string]any{
			"error":  "unknown_transport",
			"detail": "transport must be one of path, query_string, json_body, header, cookie",
			"given":  string(transport),
		})
		return
	}

	method := strings.ToUpper(strings.TrimSpace(q.Get("method")))
	if method == "" {
		method = http.MethodGet
	}
	targetPath := q.Get("path")
	if targetPath == "" {
		targetPath = "/api/search"
	}
	body := q.Get("body")
	contentType := q.Get("content_type")
	if body != "" && contentType == "" {
		contentType = "application/json"
	}

	values := decodeCSV(q.Get("values"))
	locations := decodeCSV(q.Get("locations"))
	for len(locations) < len(values) {
		locations = append(locations, defaultLocation(transport, len(locations)))
	}

	req, rawQuery, err := p.buildProbe(transport, method, targetPath, q.Get("raw_query"), values, locations, body, contentType, q.Get("header_name"), q.Get("cookie_name"))
	if err != nil {
		p.writePlainJSON(w, http.StatusBadRequest, map[string]any{
			"error": "invalid_probe_request", "detail": err.Error(),
		})
		return
	}

	// One engine pass over the real request object.
	decision, candidates, coverage := inspectRequest(req)

	// Forward the same bytes to the origin. inspectRequest replaced req.Body with
	// a replay of whatever it buffered, so the origin still receives the body.
	originStatus := 0
	originBody := ""
	resp, originErr := coverageClient.Do(req)
	if resp != nil {
		originStatus = resp.StatusCode
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxInspectedBody))
		originBody = string(raw)
		_ = resp.Body.Close()
	} else if originErr != nil {
		originBody = originErr.Error()
	}
	originHasMarker := strings.Contains(originBody, BlockMarker)

	reported := reportCandidates(candidates, transport, values, locations)

	checks := make([]map[string]any, 0, len(reported))
	blocked := 0
	for _, c := range reported {
		decoded, note, judged := c.Decoded()
		hitID, hitVector := firstMatch(c, judged)
		shadow := ""
		if !vectorIsInspected(c.Vector) {
			// What a rule WOULD have said. This turns the gap from an assertion
			// into a measurement.
			shadow = shadowMatch(SignatureOf(c.Value))
		}
		if hitID != "" {
			blocked++
		}
		checks = append(checks, map[string]any{
			"value":             c.Value,
			"signature":         SignatureOf(c.Value),
			"vector":            string(c.Vector),
			"location":          c.Location,
			"decoded_once":      decoded,
			"normalization":     note,
			"judged":            judged,
			"vector_inspected":  vectorIsInspected(c.Vector),
			"blocked_by_rule":   hitID,
			"blocked_in_vector": hitVector,
			"would_match_rule":  shadow,
			"passed_transport":  hitID == "",
		})
	}

	verdict := "mixed"
	switch {
	case len(reported) == 0:
		verdict = "empty"
	case blocked == len(reported):
		verdict = "blocked"
	case blocked == 0:
		verdict = "passed"
	}

	// "ok" is the per-transport answer: did these probes get through this
	// transport? It is deliberately not the health of the endpoint.
	p.writePlainJSON(w, http.StatusOK, map[string]any{
		"ok":        verdict == "passed",
		"source":    "lab-waf",
		"transport": string(transport),
		"method":    method,
		"target":    req.URL.String(),
		"raw_query": rawQuery,
		"decision": map[string]any{
			"action":        string(decision.Action),
			"rule_id":       decision.RuleID,
			"reason":        decision.Reason,
			"vector":        string(decision.Vector),
			"location":      decision.Location,
			"normalization": decision.Normalization,
			"policy":        decision.Policy,
		},
		"coverage":          coverage,
		"checks":            checks,
		"uninspected_probe": !vectorIsInspected(transport),
		"summary": map[string]any{
			"probe_verdict":           verdict,
			"blocked_of":              strconv.Itoa(blocked) + "/" + strconv.Itoa(len(reported)),
			"decode_passes":           1,
			"transport_inspected":     vectorIsInspected(transport),
			"origin_status":           originStatus,
			"origin_has_block_marker": originHasMarker,
			"origin_error":            originErr != nil,
			"block_marker_token":      BlockMarker,
		},
		"details": map[string]any{"origin_response": originBody},
	})
}

// coverageClient is used only for the internal origin hop of /__lab/coverage.
// Proxy: nil matters: the fixture must never relay through an ambient proxy.
var coverageClient = &http.Client{
	Timeout: 10 * time.Second,
	Transport: &http.Transport{
		Proxy:       nil,
		DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
	},
}

func knownTransport(t Vector) bool {
	switch t {
	case VectorPath, VectorQueryString, VectorJSONBody, VectorHeader, VectorCookie:
		return true
	default:
		return false
	}
}

func defaultLocation(t Vector, index int) string {
	switch t {
	case VectorJSONBody, VectorQueryString:
		return "q"
	case VectorHeader:
		return fmt.Sprintf("X-Lab-Probe-%d", index)
	case VectorCookie:
		return fmt.Sprintf("lab_probe_%d", index)
	default:
		return "request_target"
	}
}

func (p *Proxy) buildProbe(transport Vector, method, path, rawQuery string, values, locations []string, body, contentType, headerName, cookieName string) (*http.Request, string, error) {
	effectiveBody := body
	if transport == VectorJSONBody && body == "" && len(values) > 0 {
		// Wrap the supplied values into a JSON document, so the transport really
		// is the body and not a query string in disguise.
		docs := make(map[string]any, len(values))
		for i, v := range values {
			docs[locations[i]] = v
		}
		raw, err := json.Marshal(docs)
		if err != nil {
			return nil, "", err
		}
		effectiveBody = string(raw)
		if contentType == "" {
			contentType = "application/json"
		}
	}

	query := ""
	if transport == VectorQueryString {
		if rawQuery != "" {
			query = rawQuery
		} else {
			parts := make([]string, 0, len(values))
			for i, v := range values {
				parts = append(parts, fmt.Sprintf("%s=%s", url.QueryEscape(locations[i]), v))
			}
			query = strings.Join(parts, "&")
		}
	} else if rawQuery != "" {
		query = rawQuery
	}

	target := path
	if transport == VectorPath && len(values) > 0 {
		target = strings.TrimSuffix(path, "/") + "/" + strings.Join(values, "/")
	}

	u, err := url.ParseRequestURI(target)
	if err != nil {
		return nil, "", err
	}
	u.RawQuery = query

	var reader io.Reader
	if effectiveBody != "" {
		reader = strings.NewReader(effectiveBody)
	}
	req, err := http.NewRequest(method, p.origin.Scheme+"://"+p.origin.Host+u.String(), reader)
	if err != nil {
		return nil, "", err
	}
	if effectiveBody != "" && contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if transport == VectorHeader && len(values) > 0 {
		name := headerName
		if name == "" {
			name = "X-Lab-Probe-Payload"
		}
		req.Header.Set(name, values[0])
		for i, v := range values {
			if i == 0 {
				continue
			}
			req.Header.Add(fmt.Sprintf("%s-%d", name, i), v)
		}
	}
	if transport == VectorCookie && len(values) > 0 {
		name := cookieName
		if name == "" {
			name = "lab_probe_payload"
		}
		for i, v := range values {
			key := name
			if i > 0 {
				key = fmt.Sprintf("%s_%d", name, i)
			}
			req.AddCookie(&http.Cookie{Name: key, Value: v})
		}
	}
	return req, query, nil
}

// reportCandidates reconciles the candidate set the engine saw with the values
// the caller asked about, so a probe carried in an uninspected transport still
// produces a row. That row is the evidence of the gap.
func reportCandidates(candidates []Candidate, transport Vector, values, locations []string) []Candidate {
	matched := make([]Candidate, 0, len(candidates))
	for _, c := range candidates {
		if c.Vector == transport ||
			(transport == VectorHeader && c.Vector == VectorHeaderUninspected) ||
			(transport == VectorCookie && c.Vector == VectorCookieUninspected) {
			matched = append(matched, c)
		}
	}
	if len(matched) > 0 || len(values) == 0 {
		return matched
	}
	out := make([]Candidate, 0, len(values))
	for i, v := range values {
		out = append(out, Candidate{
			Vector: transport, Location: locations[i], Value: v,
			RawEncoded: transport == VectorQueryString,
		})
	}
	return out
}

func vectorIsInspected(t Vector) bool {
	if t == VectorJSONBody || t == VectorHeaderUninspected || t == VectorCookieUninspected {
		return false
	}
	for _, v := range InspectedVectors() {
		if v == string(t) {
			return true
		}
	}
	return false
}

// firstMatch re-derives which rule fired on one candidate. It mirrors the engine
// exactly: same table, same order, same single decode.
func firstMatch(c Candidate, judged bool) (string, string) {
	if !judged {
		return "", ""
	}
	decoded, _, _ := c.Decoded()
	for _, rule := range rules {
		if !vectorIn(rule.Vectors, c.Vector) {
			continue
		}
		if rule.Matches(decoded) {
			return rule.ID, string(c.Vector)
		}
	}
	return "", ""
}

// shadowMatch evaluates the query-string rule set against an already-collapsed
// value, answering "what would have happened had this transport been inspected".
func shadowMatch(signature string) string {
	for _, rule := range rules {
		if !vectorIn(rule.Vectors, VectorQueryString) {
			continue
		}
		if rule.Matches(signature) {
			return rule.ID
		}
	}
	return ""
}

func decodeCSV(csv string) []string {
	if strings.TrimSpace(csv) == "" {
		return nil
	}
	parts := strings.Split(csv, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		decoded, err := url.QueryUnescape(part)
		if err != nil {
			decoded = part
		}
		out = append(out, decoded)
	}
	return out
}

// allVectorNames is the vocabulary the /__lab/info endpoint reports over.
func allVectorNames() []string {
	names := []string{
		string(VectorPath), string(VectorQueryString), string(VectorJSONBody),
		string(VectorHeader), string(VectorCookie),
		string(VectorHeaderUninspected), string(VectorCookieUninspected),
	}
	sort.Strings(names)
	return names
}

func vectorNote(v Vector) string {
	switch v {
	case VectorPath:
		return "inspected for the traversal and command shapes and for the sentinel"
	case VectorQueryString:
		return "fully inspected; this is the vector the fixture was configured to parse"
	case VectorJSONBody:
		return "NOT inspected: no rule lists this vector (behavior 1 of the lab spec)"
	case VectorHeader:
		return "values reach only HEADER-001; header NAMES are matched by the policy denylist"
	case VectorCookie:
		return "values of lab_probe* and xammu-* cookies are scanned by COOKIE-001 and TRAVERSAL-001"
	case VectorHeaderUninspected:
		return "custom diagnostic header VALUES are never parsed (behavior 3 of the lab spec)"
	case VectorCookieUninspected:
		return "cookie names outside InspectedCookiePrefixes are never scanned (behavior 3)"
	default:
		return ""
	}
}
