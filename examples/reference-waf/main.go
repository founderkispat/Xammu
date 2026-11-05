// Command reference-waf is the Phase 3 demonstration fixture. It is a reverse
// proxy with the compound matcher in waf.go in front of the laboratory origin.
//
// It is not the laboratory WAF and it is not a commercial product: its rules
// are calibrated against the inert corpus in this repository, so its measured
// effectiveness demonstrates the gate pipeline rather than any vendor.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func main() {
	showInfo := flag.Bool("info", false, "print the resolved configuration as JSON and exit")
	flag.Parse()

	cfg := Config{
		ListenAddr: envOr("REFERENCE_WAF_LISTEN_ADDR", "127.0.0.1:8099"),
		OriginURL:  envOr("REFERENCE_WAF_ORIGIN_URL", "http://127.0.0.1:8081"),
	}
	if *showInfo {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]any{
			"listen_addr":   cfg.ListenAddr,
			"origin_url":    cfg.OriginURL,
			"server":        ServerName,
			"block_token":   BlockMarker,
			"decode_passes": 3,
			"rules":         rulesForInfo(),
		})
		return
	}

	proxy, err := NewProxy(cfg)
	if err != nil {
		log.Fatalf("reference-waf: %v", err)
	}
	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           proxy.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		log.Printf("xammu-reference-waf: listening on %s -> %s", cfg.ListenAddr, cfg.OriginURL)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	select {
	case err := <-errCh:
		log.Fatalf("reference-waf: serve: %v", err)
	case <-stop:
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}
}

// Config is the fixture's whole configuration surface.
type Config struct {
	ListenAddr string
	OriginURL  string
}

type Proxy struct {
	cfg     Config
	reverse *httputil.ReverseProxy
}

func NewProxy(cfg Config) (*Proxy, error) {
	origin, err := url.Parse(cfg.OriginURL)
	if err != nil {
		return nil, fmt.Errorf("invalid origin %q: %w", cfg.OriginURL, err)
	}
	reverse := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = origin.Scheme
			req.URL.Host = origin.Host
			req.Host = ""
		},
		Transport: &http.Transport{
			Proxy: nil,
			DialContext: (&net.Dialer{
				Timeout:   5 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			MaxIdleConns:          16,
			IdleConnTimeout:       60 * time.Second,
			ResponseHeaderTimeout: 10 * time.Second,
		},
		ModifyResponse: func(resp *http.Response) error {
			resp.Header.Set("Server", ServerName)
			resp.Header.Set("X-Xammu-Reference-Decision", "forwarded")
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("reference-waf: origin round-trip failed: %v", err)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Header().Set("X-Xammu-Reference-Decision", "not_evaluated")
			w.WriteHeader(http.StatusBadGateway)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok": false, "source": "reference-waf", "status": http.StatusBadGateway,
				"error": "origin_unreachable",
				"detail": "the fixture could not reach the origin; this is an infrastructure " +
					"error, not a defensive decision",
			})
		},
	}
	return &Proxy{cfg: cfg, reverse: reverse}, nil
}

func (p *Proxy) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/__reference/info" {
			writeJSON(w, http.StatusOK, map[string]any{
				"ok": true, "source": "reference-waf", "server": ServerName,
				"block_token": BlockMarker, "origin_url": p.cfg.OriginURL,
				"decode_passes": 3, "rules": rulesForInfo(),
			})
			return
		}
		body, err := readBody(r)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"ok": false, "source": "reference-waf", "error": "unreadable_body",
			})
			return
		}
		if d := Inspect(r, body); d.Blocked {
			writeInterstitial(w, d)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		w.Header().Set("X-Xammu-Reference-Decision", "forwarded")
		p.reverse.ServeHTTP(w, r)
	})
}

// writeInterstitial has the same observable contract as the laboratory
// fixture: a 403 HTML page carrying the marker in its title and body, so the
// observer can recognise a decision from the response alone.
func writeInterstitial(w http.ResponseWriter, d Decision) {
	h := w.Header()
	h.Set("Server", ServerName)
	h.Set("X-Xammu-Reference-Action", "reject")
	h.Set("X-Xammu-Reference-Rule", d.RuleID)
	h.Set("X-Xammu-Reference-Class", d.Class)
	h.Set("X-Xammu-Reference-Decision", "blocked")
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")

	body := strings.Join([]string{
		"<!doctype html>",
		`<html lang="en"><head><meta charset="utf-8">`,
		"<title>" + BlockMarker + " | request blocked</title>",
		"</head><body>",
		"<h1>" + BlockMarker + "</h1>",
		"<p>The reference fixture refused this request before it reached the origin.</p>",
		"<dl>",
		"<dt>rule</dt><dd>" + html.EscapeString(d.RuleID) + "</dd>",
		"<dt>class</dt><dd>" + html.EscapeString(d.Class) + "</dd>",
		"<dt>location</dt><dd>" + html.EscapeString(d.Location) + "</dd>",
		"<dt>reason</dt><dd>" + html.EscapeString(d.Reason) + "</dd>",
		"</dl>",
		"</body></html>",
		"",
	}, "\n")
	w.WriteHeader(http.StatusForbidden)
	_, _ = io.WriteString(w, body)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func rulesForInfo() []map[string]string {
	out := make([]map[string]string, 0, len(classRules))
	for _, r := range classRules {
		out = append(out, map[string]string{
			"id": r.ID, "class": r.Class, "reason": r.Reason,
		})
	}
	return out
}

func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}
