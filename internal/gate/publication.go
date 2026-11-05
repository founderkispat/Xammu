package gate

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"xammu/internal/contracts"
	"xammu/internal/effectiveness"
	"xammu/internal/integrity"
)

// A publication envelope is the seal of one delivery: the machine documents, the
// report and the annexes, tied to the sealed evidence and to the policy that
// produced the verdict, and signed with an Ed25519 key that lives outside both
// the bundle and the delivery directory.
const (
	// PublicationSchemaVersion names the envelope document.
	PublicationSchemaVersion = "xammu.publication/v1"

	// PublicationSigningRule states what the signature commits to. It travels
	// inside the envelope so a verifier reads the rule from the document rather
	// than from the program that produced it.
	PublicationSigningRule = "ed25519 over sha256(canonical-json(publication minus signature_base64, " +
		"public_key_base64 and signer_key_id))"

	PublicationFileName = "publication.json"
)

// Publication is the xammu.publication/v1 document.
type Publication struct {
	SchemaVersion string            `json:"schema_version"`
	ToolVersion   string            `json:"tool_version"`
	CreatedAt     time.Time         `json:"created_at"`
	Source        PublicationSource `json:"source"`
	PolicySHA256  string            `json:"policy_sha256"`
	Verdict       string            `json:"verdict"`
	ExitCode      int               `json:"exit_code"`
	Files         []PublicationFile `json:"files"`
	Algorithm     string            `json:"algorithm"`
	SignerKeyID   string            `json:"signer_key_id"`
	PublicKeyB64  string            `json:"public_key_base64"`
	SignatureB64  string            `json:"signature_base64"`
	SigningRule   string            `json:"signing_rule"`
}

// PublicationSource names the sealed bundle the delivery was derived from.
// ManifestSignerAnchored records whether the gate ran with a trusted key: a
// publication made without one is still self-consistent, and it says so instead
// of implying an identity it never checked.
type PublicationSource struct {
	Kind                   string `json:"kind"`
	RunID                  string `json:"run_id"`
	Bundle                 string `json:"bundle"`
	ManifestSHA256         string `json:"manifest_sha256"`
	ManifestSignerKeyID    string `json:"manifest_signer_key_id"`
	ManifestSignatureOK    bool   `json:"manifest_signature_valid"`
	ManifestSignerAnchored bool   `json:"manifest_signer_anchored"`
}

// PublicationFile is one delivered artifact.
type PublicationFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int    `json:"bytes"`
}

// NewPublication builds the unsigned envelope from an evaluation and the files
// that will sit beside it. The file list is sorted by path so the document does
// not depend on the order the caller wrote them.
func NewPublication(e *Evaluation, files []PublicationFile, anchored bool, now time.Time) *Publication {
	sorted := append([]PublicationFile(nil), files...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Path < sorted[j].Path })
	d := e.Document
	return &Publication{
		SchemaVersion: PublicationSchemaVersion,
		ToolVersion:   toolVersion(),
		CreatedAt:     now.UTC(),
		Source: PublicationSource{
			Kind: d.Source.Kind, RunID: d.Source.RunID, Bundle: d.Source.Bundle,
			ManifestSHA256: d.Source.ManifestSHA256, ManifestSignerKeyID: d.Source.ManifestSignerKeyID,
			ManifestSignatureOK: true, ManifestSignerAnchored: anchored,
		},
		PolicySHA256: d.Policy.SHA256,
		Verdict:      d.Verdict,
		ExitCode:     e.ExitCode,
		Files:        sorted,
		Algorithm:    "ed25519",
		SigningRule:  PublicationSigningRule,
	}
}

// SignPublication fills the key identity and signature in place. The private key
// is never written into the envelope: only the public half travels with it.
func SignPublication(p *Publication, key *integrity.Key) error {
	if key == nil || len(key.Private) == 0 {
		return errors.New("no publication signing key was supplied")
	}
	p.Algorithm = "ed25519"
	p.SignerKeyID = key.KeyID
	p.PublicKeyB64 = base64.StdEncoding.EncodeToString(key.Public)
	material, err := publicationMaterial(*p)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(material)
	p.SignatureB64 = base64.StdEncoding.EncodeToString(ed25519.Sign(key.Private, sum[:]))
	return nil
}

// PublicationDigest is the digest of the signed material: the value
// `verify --publication` prints as the seal.
func PublicationDigest(p Publication) (string, error) {
	material, err := publicationMaterial(p)
	if err != nil {
		return "", err
	}
	return contracts.NewDigest(material), nil
}

func publicationMaterial(p Publication) ([]byte, error) {
	p.SignatureB64 = ""
	p.PublicKeyB64 = ""
	p.SignerKeyID = ""
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(p); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// RenderPublication returns the bytes a delivery writes.
func RenderPublication(p *Publication) ([]byte, error) {
	raw, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

// ReadPublication loads and fully decodes an envelope. Unknown fields are
// refused: an envelope this build does not understand is not a delivery it can
// verify, and ignoring a field would hide what it failed to check.
func ReadPublication(dir string) (*Publication, error) {
	path := filepath.Join(dir, PublicationFileName)
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot read %s: %v", ErrUnusable, filepath.ToSlash(path), err)
	}
	var p Publication
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("%w: %s is not a %s envelope: %v", ErrUnusable,
			filepath.ToSlash(path), PublicationSchemaVersion, err)
	}
	return &p, nil
}

// VerifyPublication checks the envelope's own consistency and signature. A
// missing trust anchor is reported as a note, not as a failure: the signature is
// self-consistent either way, and only the operator can say whose key it is.
func VerifyPublication(p *Publication, trusted []byte) []integrity.VerifyStatus {
	var out []integrity.VerifyStatus
	add := func(check string, ok bool, detail string) {
		out = append(out, integrity.VerifyStatus{Check: check, OK: ok, Detail: detail})
	}
	if p.SchemaVersion != PublicationSchemaVersion {
		add("publication_schema", false, fmt.Sprintf("schema_version %q, want %q",
			p.SchemaVersion, PublicationSchemaVersion))
	} else {
		add("publication_schema", true, p.SchemaVersion)
	}
	if p.ToolVersion != toolVersion() {
		add("publication_tool_version", false, fmt.Sprintf("tool_version %q, want %q",
			p.ToolVersion, toolVersion()))
	} else {
		add("publication_tool_version", true, p.ToolVersion)
	}
	if p.Algorithm != "ed25519" {
		add("publication_algorithm", false, fmt.Sprintf("algorithm %q, want ed25519", p.Algorithm))
	} else {
		add("publication_algorithm", true, "ed25519")
	}
	pub, err := base64.StdEncoding.DecodeString(p.PublicKeyB64)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		add("publication_public_key", false, "the envelope's public key is not an ed25519 key")
		return out
	}
	if got := integrity.KeyIDOf(pub); got != p.SignerKeyID {
		add("publication_public_key", false,
			fmt.Sprintf("the envelope key id is %q but the public key hashes to %q", p.SignerKeyID, got))
	} else {
		add("publication_public_key", true, "public key decodes and matches the declared signer")
	}
	if len(trusted) > 0 {
		add(integrity.CheckSignerTrusted, bytes.Equal(pub, trusted),
			fmt.Sprintf("envelope key %s, trusted key %s", p.SignerKeyID, integrity.KeyIDOf(trusted)))
	} else {
		add(integrity.CheckSignerTrusted, false,
			"no trusted key supplied: the envelope signature is self-consistent but the identity "+
				"is unverified")
	}
	material, err := publicationMaterial(*p)
	if err != nil {
		add("publication_signature", false, err.Error())
		return out
	}
	sum := sha256.Sum256(material)
	sig, err := base64.StdEncoding.DecodeString(p.SignatureB64)
	if err != nil {
		add("publication_signature", false, "signature is not base64")
		return out
	}
	if len(sig) != ed25519.SignatureSize {
		add("publication_signature", false, fmt.Sprintf("signature is %d byte(s); ed25519 produces %d",
			len(sig), ed25519.SignatureSize))
		return out
	}
	add("publication_signature", ed25519.Verify(pub, sum[:], sig), "ed25519 over the envelope material")
	return out
}

// VerifyDelivery checks everything a reader can check from the delivery alone:
// the envelope, every listed file, and the internal consistency of gate.json
// against the policy embedded in it. The source bundle is verified separately
// because it lives at a path the envelope names but does not copy.
func VerifyDelivery(dir string, trusted []byte) (*Publication, []integrity.VerifyStatus, error) {
	p, err := ReadPublication(dir)
	if err != nil {
		return nil, nil, err
	}
	statuses := VerifyPublication(p, trusted)
	add := func(check string, ok bool, detail string) {
		statuses = append(statuses, integrity.VerifyStatus{Check: check, OK: ok, Detail: detail})
	}
	if len(p.Files) == 0 {
		add("publication_files", false, "the envelope lists no delivered file")
	} else {
		add("publication_files", true, fmt.Sprintf("%d file(s) listed", len(p.Files)))
	}
	listed := map[string]bool{}
	var changed []string
	for _, f := range p.Files {
		listed[f.Path] = true
		raw, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(f.Path)))
		if err != nil {
			changed = append(changed, f.Path+" (missing)")
			continue
		}
		if got := contracts.NewDigest(raw); got != f.SHA256 || len(raw) != f.Bytes {
			changed = append(changed, fmt.Sprintf("%s (%s, %d bytes; envelope says %s, %d bytes)",
				f.Path, got, len(raw), f.SHA256, f.Bytes))
		}
	}
	add("delivery_files_unchanged", len(changed) == 0, strings.Join(changed, "; "))
	extra := unlistedDeliveryFiles(dir, listed)
	add("delivery_files_all_listed", len(extra) == 0, strings.Join(extra, ", "))
	add("publication_manifest_signed", p.Source.ManifestSignatureOK,
		"the envelope records that the source manifest signature verified")

	doc, err := readGateDocument(filepath.Join(dir, "gate.json"))
	if err != nil {
		add("gate_document_readable", false, err.Error())
		return p, statuses, nil
	}
	add("gate_document_readable", true, "gate.json decodes with only declared fields")
	add("gate_document_matches_envelope",
		doc.Source.Kind == p.Source.Kind && doc.Source.RunID == p.Source.RunID &&
			doc.Source.Bundle == p.Source.Bundle &&
			doc.Source.ManifestSHA256 == p.Source.ManifestSHA256 &&
			doc.Source.ManifestSignerKeyID == p.Source.ManifestSignerKeyID &&
			doc.Policy.SHA256 == p.PolicySHA256,
		fmt.Sprintf("run %s, policy %s", doc.Source.RunID, doc.Policy.SHA256))
	verdict, exitCode, diffs := recheckDocument(doc)
	if len(diffs) > 0 {
		add("checks_reproduce_from_gate_json", false, strings.Join(diffs, "; "))
	} else {
		add("checks_reproduce_from_gate_json", true,
			fmt.Sprintf("%d check(s) reproduce from the embedded policy", len(doc.Checks)))
	}
	add("verdict_reproduces_from_checks",
		verdict == doc.Verdict && verdict == p.Verdict && exitCode == p.ExitCode,
		fmt.Sprintf("document says %s, envelope says %s (exit %d), checks say %s (exit %d)",
			doc.Verdict, p.Verdict, p.ExitCode, verdict, exitCode))
	return p, statuses, nil
}

// VerifyPublicationSource re-opens the bundle the envelope names and checks that
// it is the one the delivery was derived from. A delivery that has travelled
// away from its evidence cannot pass this check silently: the caller must supply
// the bundle or accept the refusal.
//
// The trusted key anchors the envelope signer. The source manifest is a different
// document signed before the delivery existed, so it is required to be
// self-consistent and identical to the one the envelope names; its identity is
// anchored only when the operator supplies the key that actually signed it.
func VerifyPublicationSource(p *Publication, dir string, trusted []byte) []integrity.VerifyStatus {
	var out []integrity.VerifyStatus
	add := func(check string, ok bool, detail string) {
		out = append(out, integrity.VerifyStatus{Check: check, OK: ok, Detail: detail})
	}
	add("publication_manifest_signature", p.Source.ManifestSignatureOK,
		"the envelope records whether the source manifest signature verified")
	manifestTrusted := []byte(nil)
	if len(trusted) > 0 && integrity.KeyIDOf(trusted) == p.Source.ManifestSignerKeyID {
		manifestTrusted = trusted
	}
	ev, err := Load(dir, manifestTrusted)
	if err != nil {
		add("source_bundle_verifies", false, err.Error())
		return out
	}
	detail := "manifest, inventory, merkle root and hash chains verify"
	switch {
	case manifestTrusted != nil:
		detail += "; manifest signer anchored by the supplied key"
	case len(trusted) > 0:
		detail += fmt.Sprintf("; the supplied key is the envelope's, so manifest signer %s is "+
			"self-consistent but not anchored", p.Source.ManifestSignerKeyID)
	default:
		detail += "; manifest signer identity unanchored (no trusted key supplied)"
	}
	add("source_bundle_verifies", true, detail)
	add("source_manifest_sha256", ev.ManifestSHA256 == p.Source.ManifestSHA256,
		fmt.Sprintf("bundle %s, envelope %s", ev.ManifestSHA256, p.Source.ManifestSHA256))
	add("source_identity",
		ev.RunID == p.Source.RunID && ev.Kind == p.Source.Kind &&
			ev.Manifest.SignerKeyID == p.Source.ManifestSignerKeyID,
		fmt.Sprintf("bundle run %s (%s) signed by %s", ev.RunID, ev.Kind, ev.Manifest.SignerKeyID))
	return out
}

func unlistedDeliveryFiles(dir string, listed map[string]bool) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() || e.Name() == PublicationFileName {
			continue
		}
		if !listed[e.Name()] {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out
}

func readGateDocument(path string) (*Document, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read %s: %v", filepath.ToSlash(path), err)
	}
	var d Document
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		return nil, fmt.Errorf("%s is not a gate document: %v", filepath.ToSlash(path), err)
	}
	return &d, nil
}

// recheckDocument rebuilds every check from the policy and the observed values
// embedded in gate.json. It is the property that makes the document consumable:
// a reader who does not trust the producer can apply the same thresholds to the
// same numbers and must reach the same verdict.
func recheckDocument(d *Document) (string, int, []string) {
	expected, err := expectedChecks(d)
	if err != nil {
		return d.Verdict, -1, []string{err.Error()}
	}
	var diffs []string
	for id, want := range expected {
		got, ok := d.Checks[id]
		if !ok {
			diffs = append(diffs, "check "+id+" is missing from the document")
			continue
		}
		if got.Applies != want.Applies || got.Status != want.Status ||
			got.Threshold != want.Threshold || got.Observed != want.Observed ||
			got.Reason != want.Reason {
			diffs = append(diffs, fmt.Sprintf(
				"check %s: document says %s/%q/%q, re-evaluation says %s/%q/%q",
				id, got.Status, got.Threshold, got.Observed, want.Status, want.Threshold, want.Observed))
		}
	}
	verdict, exit := VerdictPass, 0
	for _, id := range checkOrder {
		if c, ok := expected[id]; ok && c.Applies && c.Status == StatusFail {
			verdict, exit = VerdictFail, 1
		}
	}
	sort.Strings(diffs)
	return verdict, exit, diffs
}

func expectedChecks(d *Document) (map[string]Check, error) {
	checks := map[string]Check{}
	switch d.Source.Kind {
	case KindEffectiveness:
		if d.Metrics == nil {
			return nil, errors.New("the document declares an effectiveness source but carries no metrics")
		}
		if d.Policy.Effectiveness == nil {
			return nil, errors.New("the document carries no effectiveness thresholds to re-apply")
		}
		p := d.Policy.Effectiveness
		m := effectiveness.Metrics{Cases: d.Metrics.Cases, Counts: d.Metrics.Counts,
			Rates: d.Metrics.Rates}
		checks["effectiveness.tpr"] = minimumCheck("effectiveness.tpr", m.Rates.TPR, p.MinTPR,
			"effectiveness_metrics.jsonl")
		checks["effectiveness.fpr"] = maximumCheck("effectiveness.fpr", m.Rates.FPR, p.MaxFPR,
			"effectiveness_metrics.jsonl")
		if p.MinPrecision != nil {
			checks["effectiveness.precision"] = minimumCheck("effectiveness.precision", m.Rates.Precision,
				*p.MinPrecision, "effectiveness_metrics.jsonl")
		} else {
			checks["effectiveness.precision"] = notApplicableCheck("effectiveness.precision",
				"min_precision is not declared in the policy", "effectiveness_metrics.jsonl")
		}
		checks["effectiveness.excluded_ratio"] = excludedCheck(&m, p.MaxExcludedRatio,
			"effectiveness_metrics.jsonl")
		if d.Policy.Findings != nil {
			checks["findings.priority"] = notApplicableCheck("findings.priority",
				"the bundle carries no sealed C-16 findings", "findings.jsonl")
		}
	case KindProfiling:
		if d.Policy.Findings == nil {
			return nil, errors.New("the document carries no findings threshold to re-apply")
		}
		var sealed []SealedFinding
		for _, f := range d.Findings {
			sealed = append(sealed, SealedFinding{Finding: contracts.DiscoveryFinding{
				Ref: f.Ref, Priority: contracts.Priority(f.Priority)}})
		}
		checks["findings.priority"] = findingsCheck(sealed, contracts.Priority(
			d.Policy.Findings.FailOnPriority))
		checks["evidence.rederive"] = notApplicableCheck("evidence.rederive",
			"profiling findings are read from the sealed findings.jsonl; the gate does not re-derive them",
			"findings.jsonl")
		if d.Policy.Effectiveness != nil {
			for _, id := range []string{"effectiveness.tpr", "effectiveness.fpr",
				"effectiveness.precision", "effectiveness.excluded_ratio"} {
				checks[id] = notApplicableCheck(id, "the bundle carries no E-03 effectiveness metrics",
					"effectiveness_metrics.jsonl")
			}
		}
	default:
		return nil, fmt.Errorf("the document declares source kind %q", d.Source.Kind)
	}
	// The manifest check is a process fact about the bundle, verified when the
	// document was produced and again from the bundle by the caller. It cannot be
	// recomputed from the document alone, so it is required to have passed.
	manifest, ok := d.Checks["evidence.manifest"]
	if !ok || !manifest.Applies || manifest.Status != StatusPass {
		return nil, errors.New("the document does not record a passing manifest check")
	}
	checks["evidence.manifest"] = manifest
	if d.Source.Kind == KindEffectiveness {
		rederive, ok := d.Checks["evidence.rederive"]
		if !ok || !rederive.Applies || rederive.Status != StatusPass {
			return nil, errors.New("the document does not record a passing re-derivation check")
		}
		checks["evidence.rederive"] = rederive
	}
	for id, c := range checks {
		if got, ok := d.Checks[id]; ok {
			c.Line = got.Line
			checks[id] = c
		}
	}
	return checks, nil
}
