// Command origin is the XAMMU laboratory's simulated application backend.
//
// It is a fixture, not a real application: it exists so the WAF in front of it
// has something to talk to, and so the WAF's rejections can be told apart from
// genuine origin failures. Behaviour is deliberately minimal and deterministic.
//
// Build:  go build ./...     (pure standard library, no third-party deps)
// Listen: :8081              (override with ORIGIN_LISTEN_ADDR)
// User:   non-root numeric user inside the container image.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// serverName identifies the origin. It MUST differ from the WAF's Server value
// ("xammu-lab-waf/1.0") so a profiler can attribute a response to the origin
// and never to the defensive layer.
const serverName = "xammu-lab-origin/1.0"

// maxBodyBytes caps the request bodies we read. One fixed value for every route,
// so body size can never become an undocumented variable in an experiment.
const maxBodyBytes = 1 << 20 // 1 MiB

func main() {
	addr := getenv("ORIGIN_LISTEN_ADDR", ":8081")

	srv := &http.Server{
		Addr:              addr,
		Handler:           newOriginHandler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Printf("xammu-lab-origin: listening on %s (uid=%d)", addr, os.Geteuid())
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-errCh:
		log.Fatalf("origin: serve: %v", err)
	case <-stop:
		log.Printf("origin: shutting down")
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// envelope is the origin's own response shape: plain JSON with a "source" field
// always equal to "origin". The WAF's interstitial is HTML with a different
// status class, a different Content-Type, a different Server value and a
// different body length, so the two are never confusable.
type envelope struct {
	OK      bool           `json:"ok"`
	Status  int            `json:"status"`
	Source  string         `json:"source"`
	Error   string         `json:"error,omitempty"`
	Detail  string         `json:"detail,omitempty"`
	Route   string         `json:"route,omitempty"`
	Method  string         `json:"method,omitempty"`
	Params  map[string]any `json:"params,omitempty"`
	Checks  []checkResult  `json:"checks,omitempty"`
	Summary map[string]any `json:"summary,omitempty"`
}

// checkResult mirrors the shape of a XAMMU verification check result so the
// origin's self-attestation reads like a native report.
type checkResult struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Category string `json:"category"`
	Severity string `json:"severity"`
	Result   string `json:"result"`
	Detail   string `json:"detail"`
	Passed   bool   `json:"passed"`
}

// newOriginHandler dispatches on the unmodified request path. http.ServeMux is
// deliberately NOT used: it issues 301 redirects for unclean paths, and a
// redirect in the middle of a measurement would pollute it. Every routing
// decision here is explicit, and the lab never answers with a redirect.
func newOriginHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch path := r.URL.Path; {
		case path == "/healthz":
			handleHealth(w, r)
		case path == "/api/search":
			handleSearch(w, r)
		case path == "/internal/normalize":
			handleNormalize(w, r)
		case path == "/api/admin" || strings.HasPrefix(path, "/api/admin/"):
			handleAdmin(w, r)
		default:
			handleNotFound(w, r)
		}
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	h := w.Header()
	h.Set("Server", serverName)
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("X-Lab-Origin", "1")
	w.WriteHeader(status)

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		log.Printf("origin: write response: %v", err)
	}
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, envelope{
		OK:     true,
		Status: http.StatusOK,
		Source: "origin",
		Route:  r.URL.Path,
		Detail: "ok",
	})
}

func handleAdmin(w http.ResponseWriter, r *http.Request) {
	// No logging, no state, no randomness: a constant, reproducible upstream
	// failure. The WAF passes it through byte-for-byte.
	writeJSON(w, http.StatusBadGateway, envelope{
		OK:     false,
		Status: http.StatusBadGateway,
		Source: "origin",
		Error:  "upstream_unavailable",
		Detail: "the admin upstream is permanently unstable in this laboratory; any observation here is unscoreable",
		Route:  r.URL.Path,
		Method: r.Method,
	})
}

func handleNotFound(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusNotFound, envelope{
		OK:     false,
		Status: http.StatusNotFound,
		Source: "origin",
		Error:  "not_found",
		Detail: "the origin has no route for this path",
		Route:  r.URL.Path,
		Method: r.Method,
	})
}

// handleSearch parses the request in all four vectors and echoes what it found.
// It never rejects anything: over-blocking must be attributable to the WAF, not
// to the origin.
func handleSearch(w http.ResponseWriter, r *http.Request) {
	params := map[string]any{}

	// Vector 1: query string. net/url already percent-decoded these values
	// exactly once; the origin does not decode again.
	for key, vals := range r.URL.Query() {
		params["query_"+key] = vals
	}

	// Vector 2: JSON body.
	if isJSONContentType(r.Header.Get("Content-Type")) {
		body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, envelope{
				OK: false, Status: http.StatusBadRequest, Source: "origin",
				Error: "unreadable_body", Detail: err.Error(), Route: r.URL.Path, Method: r.Method,
			})
			return
		}
		decoded := map[string]any{}
		if len(strings.TrimSpace(string(body))) > 0 {
			if err := json.Unmarshal(body, &decoded); err != nil {
				writeJSON(w, http.StatusBadRequest, envelope{
					OK: false, Status: http.StatusBadRequest, Source: "origin",
					Error: "invalid_json_body", Detail: err.Error(), Route: r.URL.Path, Method: r.Method,
				})
				return
			}
		}
		for key, val := range decoded {
			params["json_"+key] = val
		}
		params["json_body_bytes"] = len(body)
	}

	// Vector 3: cookies.
	for _, cookie := range r.Cookies() {
		params["cookie_"+cookie.Name] = cookie.Value
	}

	// Vector 4: custom headers, restricted to X-Lab-* so we never echo secrets.
	headerDump := map[string]any{}
	for name, vals := range r.Header {
		if strings.HasPrefix(strings.ToLower(name), "x-lab-") {
			headerDump[name] = vals
		}
	}
	params["headers"] = headerDump

	writeJSON(w, http.StatusOK, envelope{
		OK:     true,
		Status: http.StatusOK,
		Source: "origin",
		Route:  r.URL.Path,
		Method: r.Method,
		Params: params,
	})
}

func isJSONContentType(contentType string) bool {
	ct := strings.ToLower(strings.TrimSpace(contentType))
	if ct == "" {
		return false
	}
	media := strings.TrimSpace(strings.Split(ct, ";")[0])
	return media == "application/json" || strings.HasSuffix(media, "+json")
}

// handleNormalize proves the origin's decoding depth empirically. For every
// candidate it reports the value as received and the value after exactly ONE
// percent-decoding pass, so a reader can verify that neither the origin nor the
// WAF collapses %2527 down to a plain quote in a single pass.
//
// Usage: POST /internal/normalize with a JSON object {"id": "candidate", ...}.
func handleNormalize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, envelope{
			OK: false, Status: http.StatusMethodNotAllowed, Source: "origin",
			Error: "method_not_allowed", Detail: "POST a JSON object of candidates",
			Route: r.URL.Path, Method: r.Method,
		})
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, envelope{
			OK: false, Status: http.StatusBadRequest, Source: "origin",
			Error: "unreadable_body", Detail: err.Error(), Route: r.URL.Path, Method: r.Method,
		})
		return
	}

	var candidates map[string]string
	if err := json.Unmarshal(body, &candidates); err != nil {
		writeJSON(w, http.StatusBadRequest, envelope{
			OK: false, Status: http.StatusBadRequest, Source: "origin",
			Error: "invalid_json_body", Detail: err.Error(), Route: r.URL.Path, Method: r.Method,
		})
		return
	}

	transport := r.URL.Query().Get("transport")
	if transport == "" {
		transport = "json_body"
	}

	ids := make([]string, 0, len(candidates))
	for id := range candidates {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	results := make([]checkResult, 0, len(ids))
	for _, id := range ids {
		value := candidates[id]
		once, onceErr := url.QueryUnescape(value)

		res := checkResult{
			ID:       id,
			Name:     "origin_decoding_depth",
			Category: "input_validation",
			Severity: "info",
			Result:   "completed",
			Passed:   true,
		}
		if onceErr != nil {
			res.Result = "malformed_encoding"
			res.Detail = "received=" + strconv.Quote(value) + " error=invalid_percent_escape"
			results = append(results, res)
			continue
		}

		var detail strings.Builder
		detail.WriteString("received=" + strconv.Quote(value))
		detail.WriteString(" after_one_decode=" + strconv.Quote(once))
		if twice, twiceErr := url.QueryUnescape(once); twiceErr == nil && twice != once {
			detail.WriteString(" a_second_decode_would_yield=" + strconv.Quote(twice))
			detail.WriteString(" (origin does NOT perform a second decode)")
		}
		res.Detail = detail.String()
		results = append(results, res)
	}

	writeJSON(w, http.StatusOK, envelope{
		OK:     true,
		Status: http.StatusOK,
		Source: "origin",
		Route:  r.URL.Path,
		Method: r.Method,
		Checks: results,
		Summary: map[string]any{
			"transport":           transport,
			"candidates":          len(ids),
			"decode_passes":       1,
			"semantics":           "one percent-decoding pass; double-encoded input stays double-encoded",
			"server_header_value": serverName,
		},
	})
}
