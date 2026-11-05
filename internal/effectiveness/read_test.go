package effectiveness

import (
	"os"
	"path/filepath"
	"testing"
)

// The Phase 1 acceptance bundle is committed so this regression runs without the
// laboratory. Phase 2 must not change its re-derivation or grow its metrics.
func TestPhase1BundleStillRederives(t *testing.T) {
	dir := filepath.Join("..", "..", "runs", "waf-effectiveness-2026-11-05-r3")
	if _, err := os.Stat(dir); err != nil {
		t.Skipf("Phase 1 bundle is absent: %v", err)
	}
	b, err := ReadBundle(dir)
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	derived, diffs := b.Rederive()
	if len(diffs) > 0 {
		t.Fatalf("Phase 1 metrics no longer re-derive: %v", diffs)
	}
	if derived.Arms != nil || derived.Comparison != nil || derived.Fingerprint != nil {
		t.Fatalf("Phase 1 re-derivation grew Phase 2 fields: %+v", derived)
	}
	if b.Metrics.Cases != 600 || b.Metrics.Counts.TP != 25 || b.Metrics.Counts.TN != 292 {
		t.Fatalf("Phase 1 figures moved: %+v", b.Metrics)
	}
}
