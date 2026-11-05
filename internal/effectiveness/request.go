package effectiveness

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"xammu/internal/contracts"
	"xammu/internal/httpclient"
)

// ErrInvalidProbe marks a case that cannot be rendered onto its transport. The
// runner records it as excluded rather than sending a request the case did not
// describe.
var ErrInvalidProbe = errors.New("case cannot be rendered onto its transport")

// BuildRequest renders one case onto the transport it declares. It never invents
// a destination: the origin comes from the authorization and the path from the
// case, and a case path must already be absolute.
func BuildRequest(origin string, c Case, pathOverride string) (httpclient.Request, error) {
	req := httpclient.Request{
		Method:      c.Method,
		ProbeRef:    c.ID,
		CorpusRef:   c.ID,
		AttackClass: c.Class,
		Vector:      string(c.Vector),
		Encoding:    string(c.Encoding),
	}
	value, err := Transform(c.Payload, c.Encoding)
	if err != nil {
		return req, fmt.Errorf("%w: %v", ErrInvalidProbe, err)
	}
	// A path-vector case carries its own {probe} placeholder; replacing it with
	// the endpoint override would erase the slot the case exists to test.
	path := c.Path
	if pathOverride != "" && c.Vector != contracts.VectorPath {
		path = pathOverride
	}
	base, err := OriginPath(origin, path)
	if err != nil {
		return req, fmt.Errorf("%w: %v", ErrInvalidProbe, err)
	}
	u, err := url.Parse(base)
	if err != nil {
		return req, fmt.Errorf("%w: %v", ErrInvalidProbe, err)
	}

	switch c.Vector {
	case contracts.VectorQuery:
		q := u.Query()
		q.Set(c.Parameter, value)
		u.RawQuery = q.Encode()
		req.URL = u.String()
	case contracts.VectorBodyJSON:
		req.URL = u.String()
		body := []byte(value)
		if !json.Valid(body) {
			// The case names a value, not a document: place it under the declared
			// field so the body the origin reads is valid JSON. A payload that is
			// already a complete JSON document travels as authored.
			body, err = json.Marshal(map[string]string{c.Parameter: value})
			if err != nil {
				return req, fmt.Errorf("%w: cannot render case %s as JSON: %v", ErrInvalidProbe, c.ID, err)
			}
		}
		req.Body = body
		req.Headers = append(req.Headers, contracts.HeaderEntry{
			Name: "Content-Type", Value: "application/json"})
	case contracts.VectorBodyForm:
		req.URL = u.String()
		req.Body = []byte(url.Values{c.Parameter: {value}}.Encode())
		req.Headers = append(req.Headers, contracts.HeaderEntry{
			Name: "Content-Type", Value: "application/x-www-form-urlencoded"})
	case contracts.VectorHeader:
		if strings.ContainsAny(value, "\r\n") {
			return req, fmt.Errorf("%w: case %s has a header value containing a line break; a raw CRLF "+
				"cannot travel in a header and this tool will not smuggle one", ErrInvalidProbe, c.ID)
		}
		req.URL = u.String()
		req.Headers = append(req.Headers, contracts.HeaderEntry{Name: c.Parameter, Value: value})
	case contracts.VectorCookie:
		// A cookie value travels percent-encoded so no payload can break the
		// Cookie header's framing; the target decodes it once, like a query value.
		req.URL = u.String()
		req.Headers = append(req.Headers, contracts.HeaderEntry{
			Name: "Cookie", Value: c.Parameter + "=" + url.QueryEscape(value)})
	case contracts.VectorPath:
		if !strings.Contains(path, "{probe}") {
			return req, fmt.Errorf("%w: path-vector case %s needs a {probe} placeholder in its path",
				ErrInvalidProbe, c.ID)
		}
		placed := strings.ReplaceAll(path, "{probe}", url.PathEscape(value))
		full, err := OriginPath(origin, placed)
		if err != nil {
			return req, fmt.Errorf("%w: %v", ErrInvalidProbe, err)
		}
		req.URL = full
	case contracts.VectorMultipart:
		return req, fmt.Errorf("%w: the effectiveness corpus does not send multipart bodies",
			ErrInvalidProbe)
	default:
		return req, fmt.Errorf("%w: vector %q has no placement", ErrInvalidProbe, c.Vector)
	}
	if req.Method == "" {
		req.Method = http.MethodGet
	}
	return req, nil
}

// RedactedFingerprint names the response facts that identify the defensive
// layer without retaining a body. It is derived from the outcome, not from a
// guess about the product.
type RedactedFingerprint struct {
	Server      string `json:"server,omitempty"`
	WAFMarker   bool   `json:"waf_marker"`
	BlockHeader bool   `json:"block_header"`
}

// securityHeaderNames are the response headers whose presence the run records.
// Only presence is kept: a value can carry deployment detail the engagement did
// not ask for.
var securityHeaderNames = []string{
	"content-security-policy",
	"x-content-type-options",
	"x-frame-options",
	"strict-transport-security",
	"referrer-policy",
	"permissions-policy",
}

// SecurityHeaders reports which hardening headers were present.
func SecurityHeaders(h []contracts.HeaderEntry) map[string]bool {
	out := map[string]bool{}
	for _, name := range securityHeaderNames {
		out[name] = false
	}
	for _, e := range h {
		key := strings.ToLower(strings.TrimSpace(e.Name))
		if _, tracked := out[key]; tracked && strings.TrimSpace(e.Value) != "" {
			out[key] = true
		}
	}
	return out
}

// serverOf returns the Server header exactly as received, or empty.
func serverOf(h []contracts.HeaderEntry) string {
	for _, e := range h {
		if strings.EqualFold(e.Name, "Server") {
			return e.Value
		}
	}
	return ""
}

func hasHeader(h []contracts.HeaderEntry, name string) bool {
	for _, e := range h {
		if strings.EqualFold(e.Name, name) {
			return true
		}
	}
	return false
}
