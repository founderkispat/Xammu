package gate

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"xammu/internal/contracts"
	"xammu/internal/integrity"
)

func testSigningKey(t *testing.T) *integrity.Key {
	t.Helper()
	key, err := integrity.LoadOrCreateKey(filepath.Join(t.TempDir(), "issuer.ed25519"))
	if err != nil {
		t.Fatalf("creating the test signing key: %v", err)
	}
	return key
}

func writeTestDelivery(t *testing.T, e *Evaluation, key *integrity.Key) (string, *Publication) {
	t.Helper()
	dir := t.TempDir()
	gateRaw, err := JSON(e.Document)
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	reportRaw := []byte(ReportMarkdown(e.Document, ReportOptions{PublicationDir: dir}))
	for name, raw := range map[string][]byte{"gate.json": gateRaw, "report.md": reportRaw} {
		if err := os.WriteFile(filepath.Join(dir, name), raw, 0o600); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}
	pub := NewPublication(e, []PublicationFile{
		{Path: "gate.json", SHA256: contracts.NewDigest(gateRaw), Bytes: len(gateRaw)},
		{Path: "report.md", SHA256: contracts.NewDigest(reportRaw), Bytes: len(reportRaw)},
	}, true, time.Now().UTC())
	if err := SignPublication(pub, key); err != nil {
		t.Fatalf("SignPublication: %v", err)
	}
	rawPub, err := RenderPublication(pub)
	if err != nil {
		t.Fatalf("RenderPublication: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, PublicationFileName), rawPub, 0o600); err != nil {
		t.Fatalf("writing the envelope: %v", err)
	}
	return dir, pub
}

func TestPublicationSignsAndVerifies(t *testing.T) {
	key := testSigningKey(t)
	ev := loadEvidence(t, effectivenessBundle, nil)
	e := evaluate(t, ev, effectivenessPolicyFailTPR)
	dir, pub := writeTestDelivery(t, e, key)

	statuses := VerifyPublication(pub, key.Public)
	for _, s := range statuses {
		if !s.OK {
			t.Errorf("the fresh envelope failed %s: %s", s.Check, s.Detail)
		}
	}
	if pub.SignatureB64 == "" {
		t.Fatal("the envelope must carry a signature")
	}
	if pub.Source.RunID != e.Document.Source.RunID || pub.Verdict != e.Document.Verdict ||
		pub.ExitCode != e.ExitCode {
		t.Fatalf("the envelope misstates the evaluation: %+v", pub)
	}
	if _, err := os.Stat(filepath.Join(dir, PublicationFileName)); err != nil {
		t.Fatalf("the envelope was not written: %v", err)
	}

	// Without a trusted key the signature is still self-consistent, and the only
	// failing status is the one that measures the reader's configuration.
	for _, s := range VerifyPublication(pub, nil) {
		if s.Check == integrity.CheckSignerTrusted {
			if s.OK {
				t.Fatal("an unanchored envelope must not report a trusted signer")
			}
			continue
		}
		if !s.OK {
			t.Errorf("self-consistency failed at %s: %s", s.Check, s.Detail)
		}
	}

	// A different key must be a failed identity check, not a note.
	other := testSigningKey(t)
	blocked := false
	for _, s := range VerifyPublication(pub, other.Public) {
		if s.Check == integrity.CheckSignerTrusted && !s.OK {
			blocked = true
		}
	}
	if !blocked {
		t.Fatal("a different trusted key must fail the signer check")
	}
}

func TestPublicationDigestCoversTheFileList(t *testing.T) {
	key := testSigningKey(t)
	ev := loadEvidence(t, effectivenessBundle, nil)
	e := evaluate(t, ev, effectivenessPolicyPass)
	_, pub := writeTestDelivery(t, e, key)
	before, err := PublicationDigest(*pub)
	if err != nil {
		t.Fatalf("PublicationDigest: %v", err)
	}
	changed := *pub
	changed.Files = append(append([]PublicationFile(nil), pub.Files...), PublicationFile{
		Path: "extra.md", SHA256: contracts.NewDigest([]byte("x")), Bytes: 1})
	after, err := PublicationDigest(changed)
	if err != nil {
		t.Fatalf("PublicationDigest: %v", err)
	}
	if before == after {
		t.Fatal("adding a delivered file must change the envelope digest")
	}
}

func TestVerifyDeliveryDetectsATamperedDocument(t *testing.T) {
	key := testSigningKey(t)
	ev := loadEvidence(t, effectivenessBundle, nil)
	e := evaluate(t, ev, effectivenessPolicyFailTPR)
	dir, _ := writeTestDelivery(t, e, key)

	_, statuses, err := VerifyDelivery(dir, key.Public)
	if err != nil {
		t.Fatalf("VerifyDelivery: %v", err)
	}
	for _, s := range statuses {
		if !s.OK {
			t.Errorf("the fresh delivery failed %s: %s", s.Check, s.Detail)
		}
	}

	path := filepath.Join(dir, "report.md")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the report: %v", err)
	}
	if err := os.WriteFile(path, append(raw, []byte("tampered\n")...), 0o600); err != nil {
		t.Fatalf("tampering: %v", err)
	}
	_, statuses, err = VerifyDelivery(dir, key.Public)
	if err != nil {
		t.Fatalf("VerifyDelivery: %v", err)
	}
	if statusOf(statuses, "delivery_files_unchanged") {
		t.Fatal("a byte added to report.md must fail the file check")
	}
}

func TestVerifyDeliveryRejectsAVerdictThatItsChecksDoNotProduce(t *testing.T) {
	key := testSigningKey(t)
	ev := loadEvidence(t, effectivenessBundle, nil)
	e := evaluate(t, ev, effectivenessPolicyFailTPR)
	dir, _ := writeTestDelivery(t, e, key)

	// Rewrite gate.json and the envelope consistently, claiming pass over the same
	// failing checks. The signature is recomputed, so only the recheck can catch it.
	lying := *e.Document
	lying.Verdict = VerdictPass
	raw, err := JSON(&lying)
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "gate.json"), raw, 0o600); err != nil {
		t.Fatalf("writing gate.json: %v", err)
	}
	pub, err := ReadPublication(dir)
	if err != nil {
		t.Fatalf("ReadPublication: %v", err)
	}
	for i := range pub.Files {
		if pub.Files[i].Path == "gate.json" {
			pub.Files[i].SHA256 = contracts.NewDigest(raw)
			pub.Files[i].Bytes = len(raw)
		}
	}
	pub.Verdict = VerdictPass
	pub.ExitCode = 0
	if err := SignPublication(pub, key); err != nil {
		t.Fatalf("re-signing: %v", err)
	}
	rawPub, err := RenderPublication(pub)
	if err != nil {
		t.Fatalf("RenderPublication: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, PublicationFileName), rawPub, 0o600); err != nil {
		t.Fatalf("writing the envelope: %v", err)
	}

	_, statuses, err := VerifyDelivery(dir, key.Public)
	if err != nil {
		t.Fatalf("VerifyDelivery: %v", err)
	}
	if statusOf(statuses, "verdict_reproduces_from_checks") {
		t.Fatal("a verdict that its own checks do not produce must be refused")
	}
}

func TestVerifyPublicationSourceChecksTheNamedBundle(t *testing.T) {
	key := testSigningKey(t)
	ev := loadEvidence(t, effectivenessBundle, nil)
	e := evaluate(t, ev, effectivenessPolicyPass)
	_, pub := writeTestDelivery(t, e, key)

	for _, s := range VerifyPublicationSource(pub, effectivenessBundle, nil) {
		if !s.OK {
			t.Errorf("the source bundle failed %s: %s", s.Check, s.Detail)
		}
	}

	// The envelope key is not the manifest key, so the bundle stays
	// self-consistent and the check says whose signature it could not anchor.
	envelopeOnly := VerifyPublicationSource(pub, effectivenessBundle, key.Public)
	if !statusOf(envelopeOnly, "source_bundle_verifies") {
		t.Fatalf("a self-consistent source must verify: %+v", envelopeOnly)
	}

	// Naming a different bundle is a failed identity check: a delivery cannot
	// point at evidence whose manifest is not the one it sealed.
	if _, err := os.Stat(filepath.Join(profilingBundle, "manifest.json")); err != nil {
		t.Skipf("the profiling bundle is absent: %v", err)
	}
	mismatched := VerifyPublicationSource(pub, profilingBundle, nil)
	if statusOf(mismatched, "source_manifest_sha256") {
		t.Fatal("a bundle with another manifest digest must not pass the source check")
	}
}

func statusOf(statuses []integrity.VerifyStatus, check string) bool {
	for _, s := range statuses {
		if s.Check == check {
			return s.OK
		}
	}
	return false
}
