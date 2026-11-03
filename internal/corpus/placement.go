package corpus

import (
	"bytes"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"

	"xammu/internal/contracts"
)

// Placement is one corpus item rendered onto one transport, as the request parts
// the transport layer needs. Nothing here contacts a network: this package turns
// a probe into bytes, and only internal/httpclient sends bytes.
type Placement struct {
	Ref         string
	CorpusRef   string
	Group       string
	Method      string
	Path        string
	Query       string
	Body        []byte
	ContentType string
	Headers     []contracts.HeaderEntry
	Role        contracts.ControlRole
	Rationale   string
}

// Options names the slots a probe can be placed into. They are options rather
// than constants because the asymmetry a run is often measuring lives in the
// name: the same token is inspected under one cookie name and ignored under
// another, so the caller has to be able to choose the name deliberately.
type Options struct {
	OriginPath string // endpoint the probes are placed against, e.g. /api/search
	QueryParam string // default q
	BodyField  string // default q
	HeaderName string // default X-Xammu-Probe
	CookieName string // default xammu-probe-0
	MediaType  string // default application/json for the JSON body vector
}

func (o Options) withDefaults() Options {
	if o.OriginPath == "" {
		o.OriginPath = "/api/search"
	}
	if o.QueryParam == "" {
		o.QueryParam = "q"
	}
	if o.BodyField == "" {
		o.BodyField = "q"
	}
	if o.HeaderName == "" {
		o.HeaderName = "X-Xammu-Probe"
	}
	if o.CookieName == "" {
		o.CookieName = "xammu-probe-0"
	}
	if o.MediaType == "" {
		o.MediaType = "application/json"
	}
	return o
}

// RoleOf maps why an item exists to the planning role the pipeline reads.
func RoleOf(p contracts.Purpose) (contracts.ControlRole, error) {
	switch p {
	case contracts.PurposeDiagnosis:
		return contracts.RoleProbe, nil
	case contracts.PurposeEncodingReplica:
		return contracts.RoleEncodingReplica, nil
	case contracts.PurposePositiveControl:
		return contracts.RolePositiveControl, nil
	case contracts.PurposeNegativeControl, contracts.PurposeOverBlockProbe:
		// An over-blocking probe is legitimate traffic that the operator expects to
		// pass. That is exactly what a negative control is, and the alternative --
		// letting it into the probe denominator -- would dilute the measured block
		// rate with requests that were never attack shapes.
		return contracts.RoleNegativeControl, nil
	case contracts.PurposeBenignReference:
		return contracts.RoleBenignReference, nil
	}
	return "", fmt.Errorf("corpus: purpose %q has no planning role", p)
}

// Place renders one item onto its declared vector. The item is refused rather
// than guessed at when its vector is unknown: a probe silently downgraded to the
// query string measures the query string, and the report would say otherwise.
func Place(item contracts.CorpusItem, opts Options) (Placement, error) {
	opts = opts.withDefaults()
	opts = applyTags(opts, item.Tags)
	role, err := RoleOf(item.Purpose)
	if err != nil {
		return Placement{}, fmt.Errorf("corpus: ref %q: %w", item.Ref, err)
	}
	pl := Placement{
		Ref: item.Ref, CorpusRef: item.Ref, Group: item.GroupID, Role: role,
		Method: http.MethodGet, Path: opts.OriginPath,
		Rationale: fmt.Sprintf("probe %s: %s in the %s vector, %s encoding (corpus group %s)",
			item.Ref, item.AttackClass, item.Vector, item.Encoding, item.GroupID),
	}
	if item.AuthoringNote != "" {
		pl.Rationale += ": " + item.AuthoringNote
	}
	// escaped says how the probe text relates to the bytes on the wire. A
	// canonical item holds the semantic value, so the transport's own escaping is
	// applied. Every other encoding is authored as the escaped form, because the
	// encoding *is* the thing under test: re-escaping it would add a layer and turn
	// a single-encoded probe into a double-encoded one.
	escaped := item.Encoding != contracts.EncodingCanonical
	switch item.Vector {
	case contracts.VectorQuery:
		pl.Query = escapeQueryKey(opts.QueryParam) + "=" + wireValue(item.Probe, escaped)
	case contracts.VectorPath:
		pl.Path = strings.TrimSuffix(opts.OriginPath, "/") + "/" + escapePathSegment(item.Probe)
	case contracts.VectorBodyJSON:
		pl.Method = http.MethodPost
		pl.ContentType = opts.MediaType
		body, err := jsonBody(opts.BodyField, item.Probe)
		if err != nil {
			return Placement{}, fmt.Errorf("corpus: ref %q: %w", item.Ref, err)
		}
		pl.Body = body
	case contracts.VectorBodyForm:
		pl.Method = http.MethodPost
		pl.ContentType = "application/x-www-form-urlencoded"
		pl.Body = []byte(escapeQueryKey(opts.BodyField) + "=" + wireValue(item.Probe, escaped))
	case contracts.VectorMultipart:
		pl.Method = http.MethodPost
		body, ct, err := multipartBody(opts.BodyField, item.Probe)
		if err != nil {
			return Placement{}, fmt.Errorf("corpus: ref %q: %w", item.Ref, err)
		}
		pl.Body, pl.ContentType = body, ct
	case contracts.VectorHeader:
		pl.Headers = []contracts.HeaderEntry{{Name: opts.HeaderName, Value: item.Probe}}
	case contracts.VectorCookie:
		// Cookie values are not percent-decoded on the wire, so an authored
		// encoding is placed as authored and a canonical probe is only escaped for
		// the characters that would break the Cookie header. This is what makes the
		// `=` in a serialized-payload signature survive to the rule.
		pl.Headers = []contracts.HeaderEntry{{
			Name: "Cookie", Value: opts.CookieName + "=" + cookieValue(item.Probe),
		}}
	default:
		return Placement{}, fmt.Errorf("corpus: ref %q declares vector %q, which this build cannot place: "+
			"a probe that cannot be rendered cannot be sent, and it must not be moved to another transport "+
			"that the corpus does not claim", item.Ref, item.Vector)
	}
	return pl, nil
}

// jsonBody writes the probe as one JSON string field. A non-canonical probe is
// still JSON-escaped, because percent characters are legal inside a JSON string
// and the escaping that matters for the body vector is the JSON layer, not the
// URL layer.
func jsonBody(field, probe string) ([]byte, error) {
	doc := map[string]string{field: probe}
	raw, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("cannot build the JSON body: %w", err)
	}
	return raw, nil
}

func multipartBody(field, probe string) ([]byte, string, error) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	if err := w.WriteField(field, probe); err != nil {
		return nil, "", fmt.Errorf("cannot write the multipart field: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, "", fmt.Errorf("cannot close the multipart body: %w", err)
	}
	return buf.Bytes(), w.FormDataContentType(), nil
}

// wireValue escapes a canonical probe for a URL component and leaves an
// authored-encoding probe as authored, except for the bytes that would break the
// request line: an unescaped space, ampersand or equals sign in an authored
// variant is corrected without touching its percent sequences.
func wireValue(probe string, escaped bool) string {
	if !escaped {
		return url.QueryEscape(probe)
	}
	return preserveEscaping(probe)
}

// preserveEscaping percent-encodes only what is illegal in a query component.
// A valid %XX triplet is left alone: that triplet is the encoding under test.
func preserveEscaping(probe string) string {
	var b strings.Builder
	for i := 0; i < len(probe); i++ {
		c := probe[i]
		if c == '%' && i+2 < len(probe) && isHex(probe[i+1]) && isHex(probe[i+2]) {
			b.WriteByte('%')
			b.WriteByte(probe[i+1])
			b.WriteByte(probe[i+2])
			i += 2
			continue
		}
		if isQuerySafe(c) {
			b.WriteByte(c)
			continue
		}
		fmt.Fprintf(&b, "%%%02X", c)
	}
	return b.String()
}

// cookieValue escapes only what a Cookie header cannot carry. An `=` inside the
// value stays: the assignment is the serialised-payload signature under test, and
// the header's own separator is the first `=` between name and value.
func cookieValue(probe string) string {
	var b strings.Builder
	for i := 0; i < len(probe); i++ {
		c := probe[i]
		if c == '%' && i+2 < len(probe) && isHex(probe[i+1]) && isHex(probe[i+2]) {
			b.WriteString(probe[i : i+3])
			i += 2
			continue
		}
		if c < 0x21 || c == 0x7f || c == '"' || c == ';' || c == ',' || c == '\\' {
			fmt.Fprintf(&b, "%%%02X", c)
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// isQuerySafe allows the characters that a query component may carry verbatim.
// '=' and '&' stay unsafe: an authored variant that means a separator writes it
// escaped, and one that does not must not gain a parameter boundary on the way
// out.
func isQuerySafe(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	switch c {
	case '-', '_', '.', '~', '!', '*', '(', ')', '\'', '$', '+', ',', ':', '@', '/', '?', '#', '[':
		return true
	}
	return false
}

func escapeQueryKey(k string) string { return url.QueryEscape(k) }

// escapePathSegment percent-encodes every byte that is not unreserved or a
// sub-delim, so a probe authored with traversal dots still arrives as one segment
// rather than silently becoming extra path components the origin would route on.
func escapePathSegment(probe string) string {
	var b strings.Builder
	for i := 0; i < len(probe); i++ {
		c := probe[i]
		if isPathSafe(c) {
			b.WriteByte(c)
			continue
		}
		fmt.Fprintf(&b, "%%%02X", c)
	}
	return b.String()
}

func isPathSafe(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	switch c {
	case '-', '_', '.', '~', '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=', ':', '@':
		return true
	}
	return false
}

// applyTags honours the slot names an item declares. They belong on the item
// because the asymmetry a run measures is often name-keyed: the same token is
// inspected under one cookie name and ignored under another, so the corpus, not
// the operator's mood at planning time, states which name a probe was authored
// for.
func applyTags(o Options, tags []string) Options {
	for _, t := range tags {
		k, v, ok := strings.Cut(t, ":")
		if !ok || v == "" {
			continue
		}
		switch strings.ToLower(k) {
		case "header":
			o.HeaderName = v
		case "cookie":
			o.CookieName = v
		case "param":
			o.QueryParam = v
		case "field":
			o.BodyField = v
		case "path":
			o.OriginPath = v
		case "media":
			o.MediaType = v
		}
	}
	return o
}
