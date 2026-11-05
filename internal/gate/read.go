package gate

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"xammu/internal/contracts"
	"xammu/internal/effectiveness"
	"xammu/internal/integrity"
)

// Evidence is everything the gate reads from one sealed bundle. It is loaded
// once so the manifest, the metrics and the findings cannot come from different
// moments of the directory.
type Evidence struct {
	Dir                string
	Kind               string
	RunID              string
	Manifest           contracts.IntegrityManifest
	ManifestSHA256     string
	Metrics            *effectiveness.Metrics
	MetricsLine        int
	PublishedMetricsOK bool
	Findings           []SealedFinding
}

// SealedFinding is one C-16 record with the journal line that carries it. The
// line is what a SARIF location cites.
type SealedFinding struct {
	Finding contracts.DiscoveryFinding
	Line    int
}

// Load verifies the sealed manifest and decodes the evidence the gate needs.
// Every failure is ErrUnusable: the gate refuses to evaluate a bundle it cannot
// trust rather than publishing a verdict over unverified bytes.
func Load(dir string, trusted []byte) (*Evidence, error) {
	manifest, digest, err := verifyBundle(dir, trusted)
	if err != nil {
		return nil, err
	}
	ev := &Evidence{Dir: dir, Manifest: manifest, ManifestSHA256: digest}
	switch {
	case isEffectiveness(dir):
		if err := ev.loadEffectiveness(); err != nil {
			return nil, err
		}
	case isProfiling(dir):
		if err := ev.loadProfiling(); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("%w: %s is not a sealed XAMMU bundle: it holds neither "+
			"effectiveness_outcomes.jsonl nor run.json", ErrUnusable, filepath.ToSlash(dir))
	}
	return ev, nil
}

func verifyBundle(dir string, trusted []byte) (contracts.IntegrityManifest, string, error) {
	manifest, err := integrity.ReadManifest(dir)
	if err != nil {
		return contracts.IntegrityManifest{}, "", fmt.Errorf("%w: %s has no readable manifest: %v",
			ErrUnusable, filepath.ToSlash(dir), err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return contracts.IntegrityManifest{}, "", fmt.Errorf("%w: cannot read %s/manifest.json: %v",
			ErrUnusable, filepath.ToSlash(dir), err)
	}
	for _, status := range integrity.Verify(dir, manifest, trusted) {
		if status.OK {
			continue
		}
		// Without a trust anchor the signer check is a statement about this
		// operator's configuration, not about the bundle. The document says so in
		// its limits; it is not a reason to refuse the evaluation.
		if status.Check == integrity.CheckSignerTrusted && len(trusted) == 0 {
			continue
		}
		return contracts.IntegrityManifest{}, "", fmt.Errorf("%w: bundle %s failed %s: %s",
			ErrUnusable, filepath.ToSlash(dir), status.Check, status.Detail)
	}
	return manifest, contracts.NewDigest(raw), nil
}

func isEffectiveness(dir string) bool {
	if _, err := os.Stat(filepath.Join(dir, "effectiveness_outcomes.jsonl")); err != nil {
		return false
	}
	if _, err := os.Stat(filepath.Join(dir, "run.json")); err == nil {
		return false
	}
	return true
}

func isProfiling(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, "run.json"))
	return err == nil
}

func (ev *Evidence) loadEffectiveness() error {
	b, err := effectiveness.ReadBundle(ev.Dir)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnusable, err)
	}
	derived, diffs := b.Rederive()
	if len(diffs) > 0 {
		return fmt.Errorf("%w: E-03 does not re-derive from E-01/E-02: %s", ErrUnusable, diffs[0])
	}
	// The journal is sealed and authoritative. The published JSON is derived
	// after the seal, so when present it must agree; when absent the gate still
	// has the signed E-03 record to evaluate.
	published := filepath.Join(ev.Dir, "effectiveness-metrics.json")
	if raw, err := os.ReadFile(published); err == nil {
		var stored effectiveness.Metrics
		if err := json.Unmarshal(raw, &stored); err != nil {
			return fmt.Errorf("%w: %s is not readable: %v", ErrUnusable,
				filepath.ToSlash(published), err)
		}
		if diffs := effectiveness.Diff(stored, derived); len(diffs) > 0 {
			return fmt.Errorf("%w: the published metrics document disagrees with the sealed "+
				"evidence: %s", ErrUnusable, diffs[0])
		}
		ev.PublishedMetricsOK = true
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("%w: cannot read %s: %v", ErrUnusable, filepath.ToSlash(published), err)
	}
	store, err := integrity.Open(ev.Dir)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnusable, err)
	}
	records, err := store.Records(integrity.StreamEffectivenessMetrics)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnusable, err)
	}
	if len(records) > 0 {
		ev.MetricsLine = records[len(records)-1].Seq
	}
	m := derived
	ev.Metrics = &m
	ev.RunID = m.RunID
	ev.Kind = KindEffectiveness
	return nil
}

func (ev *Evidence) loadProfiling() error {
	raw, err := os.ReadFile(filepath.Join(ev.Dir, "run.json"))
	if err != nil {
		return fmt.Errorf("%w: cannot read run.json: %v", ErrUnusable, err)
	}
	var profile contracts.RunProfile
	if err := json.Unmarshal(raw, &profile); err != nil {
		return fmt.Errorf("%w: run.json is not a C-11 profile: %v", ErrUnusable, err)
	}
	store, err := integrity.Open(ev.Dir)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnusable, err)
	}
	records, err := store.Records(integrity.StreamFindings)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnusable, err)
	}
	for _, record := range records {
		var finding contracts.DiscoveryFinding
		if err := json.Unmarshal(record.Payload, &finding); err != nil {
			return fmt.Errorf("%w: findings.jsonl record %d is not C-16: %v",
				ErrUnusable, record.Seq, err)
		}
		ev.Findings = append(ev.Findings, SealedFinding{Finding: finding, Line: record.Seq})
	}
	ev.RunID = profile.RunID
	ev.Kind = KindProfiling
	return nil
}

// sourceView publishes the evidence identity. Artifacts come from the signed
// manifest, not from a directory walk, so the document lists exactly what the
// signature covers.
func (ev *Evidence) sourceView(bundle string) Source {
	artifacts := make(map[string]string, len(ev.Manifest.Files))
	for _, f := range ev.Manifest.Files {
		artifacts[f.Path] = f.Digest
	}
	return Source{
		Kind: ev.Kind, RunID: ev.RunID, Bundle: bundle,
		ManifestSHA256: ev.ManifestSHA256, ManifestSignerKeyID: ev.Manifest.SignerKeyID,
		Artifacts: artifacts,
	}
}
