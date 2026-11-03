// Command waf is the XAMMU laboratory's simulated WAF: a reverse proxy in front
// of the origin whose inspection coverage is deliberately incomplete in ways we
// control and document.
//
// It is a measurement fixture with known gaps. It is NOT a security control and
// NOT a benchmark of any commercial WAF.
//
// Build:  go build ./...   (pure standard library, no third-party deps)
// Listen: :8080            (override with WAF_LISTEN_ADDR)
// Origin: http://origin:8081 (override with WAF_ORIGIN_URL)
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func getenv(key string) string { return os.Getenv(key) }

func main() {
	printInfo := flag.Bool("info", false, "print the resolved configuration as JSON and exit")
	flag.Parse()

	cfg := loadConfig()

	if *printInfo {
		// Lets lab/verify.sh confirm the container actually picked up
		// LAB_STRIP_WAF_MARKER_HEADERS without depending on a response header.
		enc := jsonEncoder(os.Stdout)
		_ = enc.Encode(map[string]any{
			"listen_addr":          cfg.ListenAddr,
			"origin_url":           cfg.OriginURL,
			"strip_marker_headers": cfg.StripMarkerHeaders,
			"strip_trace_headers":  cfg.StripTraceHeaders,
			"decode_passes":        1,
			"block_marker_token":   BlockMarker,
			"uid":                  os.Geteuid(),
		})
		return
	}

	proxy, err := NewProxy(cfg)
	if err != nil {
		log.Fatalf("waf: %v", err)
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
		log.Printf("xammu-lab-waf: listening on %s -> %s (uid=%d, strip_marker_headers=%t)",
			cfg.ListenAddr, cfg.OriginURL, os.Geteuid(), cfg.StripMarkerHeaders)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-errCh:
		log.Fatalf("waf: serve: %v", err)
	case <-stop:
		log.Printf("waf: shutting down")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}
}
