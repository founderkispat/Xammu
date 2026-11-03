// proxy.go wires the decision engine to an httputil.ReverseProxy and defines the
// rejection interstitial. It is the only place in the WAF that produces a
// response of its own.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// wafServerHeader is the origin-visible identity of the defensive layer. Under
// LAB_STRIP_WAF_MARKER_HEADERS=1 it is suppressed, together with
// X-Lab-Waf-Action, so the only remaining rejection signal is the status class
// plus the marker token inside the HTML body.
const wafServerHeader = "xammu-lab-waf/1.0"

const (
	headerWafAction = "X-Lab-Waf-Action"
	headerWafRule   = "X-Lab-Waf-Rule"
	headerWafVector = "X-Lab-Waf-Vector"
)

// Config carries everything tunable from the environment.
type Config struct {
	ListenAddr string
	OriginURL  string
	// StripMarkerHeaders removes the Server and X-Lab-Waf-Action headers from a
	// rejection. This is what lets a test prove the profiler reads the body
	// rather than keying on a giveaway header.
	StripMarkerHeaders bool
	// StripTraceHeaders additionally removes the rule/vector trace headers.
	StripTraceHeaders bool
}

func loadConfig() Config {
	cfg := Config{
		ListenAddr: envOr("WAF_LISTEN_ADDR", ":8080"),
		OriginURL:  envOr("WAF_ORIGIN_URL", "http://origin:8081"),
	}
	cfg.StripMarkerHeaders = isTruthy(os.Getenv("LAB_STRIP_WAF_MARKER_HEADERS"))
	cfg.StripTraceHeaders = isTruthy(os.Getenv("LAB_STRIP_WAF_TRACE_HEADERS"))
	return cfg
}

func jsonEncoder(w io.Writer) *json.Encoder {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc
}

func envOr(key, fallback string) string {
	if v := strings.TrimSpace(getenv(key)); v != "" {
		return v
	}
	return fallback
}

func isTruthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// Proxy is the reverse proxy plus its own control endpoints.
type Proxy struct {
	cfg     Config
	reverse *httputil.ReverseProxy
	origin  *url.URL
	stopLog *log.Logger
	started time.Time
}

func NewProxy(cfg Config) (*Proxy, error) {
	originURL, err := url.Parse(cfg.OriginURL)
	if err != nil {
		return nil, fmt.Errorf("invalid WAF_ORIGIN_URL %q: %w", cfg.OriginURL, err)
	}

	p := &Proxy{
		cfg:     cfg,
		origin:  originURL,
		started: time.Now().UTC(),
	}

	director := func(req *outgoingRequest) {
		req.URL.Scheme = originURL.Scheme
		req.URL.Host = originURL.Host
		// The client's path and raw query are preserved byte-for-byte: the WAF
		// never re-encodes on its way to the origin, so the origin sees exactly
		// the transport the client chose.
		req.Host = ""
	}

	proxy := &httputil.ReverseProxy{
		Director: director,
		Transport: &http.Transport{
			Proxy: nil, // never relay through an ambient HTTP proxy
			DialContext: (&net.Dialer{
				Timeout:   5 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			MaxIdleConns:          16,
			IdleConnTimeout:       60 * time.Second,
			TLSHandshakeTimeout:   0,
			ExpectContinueTimeout: 1 * time.Second,
			ResponseHeaderTimeout: 10 * time.Second,
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			// The origin is unreachable. This is NOT a WAF decision: the body
			// shape and Server value say so explicitly, so a profiler must
			// classify it as an infrastructure error rather than a block.
			log.Printf("waf: origin round-trip failed: %v", err)
			p.writePlainJSON(w, http.StatusServiceUnavailable, map[string]any{
				"ok":      false,
				"source":  "lab-waf",
				"status":  http.StatusServiceUnavailable,
				"error":   "origin_unreachable",
				"detail":  "the WAF could not reach the origin; this is an infrastructure error, not a defensive decision",
				"action":  "not_evaluated",
				"reason":  err.Error(),
				"markers": []string{},
			})
		},
		ModifyResponse: func(resp *http.Response) error {
			resp.Header.Set("X-Lab-Request-Decision", "forwarded")
			return nil
		},
	}

	p.reverse = proxy
	return p, nil
}

// outgoingRequest is an alias that keeps the director signature readable.
type outgoingRequest = http.Request

// Handler returns the mux this service listens on.
func (p *Proxy) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/__lab/info":
			p.handleInfo(w, r)
		case "/__lab/coverage":
			p.handleCoverage(w, r)
		default:
			p.handleProxied(w, r)
		}
	})
}

func (p *Proxy) handleProxied(w http.ResponseWriter, r *http.Request) {
	// Refuse to relay anywhere but the configured origin. Absolute-form targets
	// and unknown hosts are rejected before any inspection work happens.
	if r.URL.Host != "" && !hostIsAllowed(r.URL.Host) {
		p.writePlainJSON(w, http.StatusForbidden, map[string]any{
			"ok": false, "source": "lab-waf", "status": http.StatusForbidden,
			"error": "relay_refused", "detail": "absolute-form targets outside the lab network are refused",
		})
		return
	}

	decision := Inspect(r)

	if decision.Blocked() {
		p.writeInterstitial(w, r, decision)
		return
	}

	w.Header().Set("X-Lab-Request-Decision", "forwarded")
	p.reverse.ServeHTTP(w, r)
}

// writeInterstitial emits the rejection page. Its observable shape is the whole
// point of the fixture and is asserted by lab/verify.sh:
//
//	HTTP 403
//	Content-Type: text/html; charset=utf-8
//	<title> contains the literal BlockMarker token
//	body length is fixed apart from the request-id tail
//	Server: xammu-lab-waf/1.0        (suppressed in strip mode)
//	X-Lab-Waf-Action: reject          (suppressed in strip mode)
//	X-Lab-Waf-Rule / X-Lab-Waf-Vector (trace, suppressed by their own flag)
func (p *Proxy) writeInterstitial(w http.ResponseWriter, r *http.Request, d Decision) {
	h := w.Header()

	if !p.cfg.StripMarkerHeaders {
		h.Set("Server", wafServerHeader)
		h.Set(headerWafAction, "reject")
	}
	if !p.cfg.StripTraceHeaders {
		h.Set(headerWafRule, d.RuleID)
		h.Set(headerWafVector, string(d.Vector))
	}
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("X-Lab-Request-Decision", "blocked")
	h.Set("Cache-Control", "no-store")

	requestID := requestIDFrom(d, r)
	body := renderInterstitial(d, requestID, p.cfg.StripMarkerHeaders)

	w.WriteHeader(http.StatusForbidden)
	if _, err := io.WriteString(w, body); err != nil {
		log.Printf("waf: write interstitial: %v", err)
	}
}

// requestID is derived from the decision and the request line, so it is
// reproducible across runs: the same request always yields the same id. It is
// deliberately short so the body length stays effectively constant, which is
// what lets a profiler key on body length as well as on the token.
func requestIDFrom(d Decision, r *http.Request) string {
	sum := 0
	source := strings.Join([]string{d.RuleID, string(d.Vector), d.Location, r.Method, r.URL.RequestURI()}, "|")
	for _, ch := range []byte(source) {
		sum = (sum*31 + int(ch)) & 0xFFFFFF
	}
	return strconv.FormatInt(int64(sum), 16)
}

func renderInterstitial(d Decision, requestID string, stripped bool) string {
	var b strings.Builder
	b.WriteString("<!doctype html>\n<html lang=\"en\">\n<head>\n")
	b.WriteString("<meta charset=\"utf-8\">\n")
	b.WriteString("<title>" + BlockMarker + " | request blocked</title>\n")
	b.WriteString("</head>\n<body>\n")
	b.WriteString("<h1>" + BlockMarker + "</h1>\n")
	b.WriteString("<p>The laboratory WAF refused this request before it reached the origin.</p>\n")
	b.WriteString("<dl>\n")
	b.WriteString("<dt>rule</dt><dd>" + htmlEscape(d.RuleID) + "</dd>\n")
	b.WriteString("<dt>vector</dt><dd>" + htmlEscape(string(d.Vector)) + "</dd>\n")
	b.WriteString("<dt>location</dt><dd>" + htmlEscape(d.Location) + "</dd>\n")
	b.WriteString("<dt>reason</dt><dd>" + htmlEscape(d.Reason) + "</dd>\n")
	b.WriteString("<dt>normalization</dt><dd>" + htmlEscape(d.Normalization) + "</dd>\n")
	b.WriteString("</dl>\n")
	if !stripped {
		b.WriteString("<p>Request-ID: " + htmlEscape(requestID) + "</p>\n")
	}
	b.WriteString("</body>\n</html>\n")
	return b.String()
}

func htmlEscape(s string) string {
	replacer := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "\"", "&quot;", "'", "&#39;")
	return replacer.Replace(s)
}

// writePlainJSON is the WAF's own non-decision error shape. It never carries the
// marker token, so "no marker" always means "the WAF made no defensive decision"
// rather than "the WAF failed".
func (p *Proxy) writePlainJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Lab-Request-Decision", "not_evaluated")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

// handleInfo documents the live configuration. A third party can read the rule
// table straight out of the running fixture.
func (p *Proxy) handleInfo(w http.ResponseWriter, r *http.Request) {
	vectors := map[string]any{}
	for _, v := range allVectorNames() {
		covered := []string{}
		for _, rule := range rules {
			if vectorIn(rule.Vectors, Vector(v)) {
				covered = append(covered, rule.ID)
			}
		}
		inspected := len(covered) > 0
		if v == "json_body" {
			inspected = false
		}
		if v == "header_value_uninspected" || v == "cookie_value_uninspected" {
			inspected = false
		}
		vectors[v] = map[string]any{
			"inspected": inspected,
			"rules":     covered,
			"note":      vectorNote(Vector(v)),
		}
	}

	p.writePlainJSON(w, http.StatusOK, map[string]any{
		"ok":     true,
		"source": "lab-waf",
		"server": wafServerHeader,
		"config": map[string]any{
			"listen_addr":             p.cfg.ListenAddr,
			"origin_url":              p.cfg.OriginURL,
			"strip_marker_headers":    p.cfg.StripMarkerHeaders,
			"strip_trace_headers":     p.cfg.StripTraceHeaders,
			"decode_passes":           1,
			"block_marker_token":      BlockMarker,
			"block_status":            http.StatusForbidden,
			"block_content_type":      "text/html; charset=utf-8",
			"origin_connect_timeout":  "5s",
			"response_header_timeout": "10s",
			"max_inspected_body":      maxInspectedBody,
		},
		"inspected_vectors":          InspectedVectors(),
		"uninspected_vectors":        UninspectedVectors(),
		"vector_detail":              vectors,
		"rules":                      RulesByID(),
		"header_policies":            headerPolicies,
		"diagnostic_header_prefixes": DiagnosticHeaderPrefixes,
		"inspected_cookie_prefixes":  InspectedCookiePrefixes,
		"protected_contractions":     protectedContractions,
		"uptime_seconds":             int(time.Since(p.started).Seconds()),
	})
}
