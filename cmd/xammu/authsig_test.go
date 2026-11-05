package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"xammu/internal/contracts"
	"xammu/internal/integrity"
)

// writeUnsignedAuth puts a C-09 on disk with no sidecar, so a test can watch a
// command refuse a permission that merely looks approved.
func writeUnsignedAuth(t *testing.T, dir string, a *contracts.ProfilingAuthorization, name string) string {
	t.Helper()
	key, _ := testIssuer(t, dir)
	a.IssuerKeyFingerprint = integrity.KeyFingerprint(key.Public)
	raw, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		t.Fatalf("cannot encode the unsigned authorization: %v", err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("cannot write %s: %v", path, err)
	}
	return path
}

// rewriteAuthorization edits the document on disk without touching its sidecar,
// which is exactly what an operator changing a field after approval produces.
func rewriteAuthorization(t *testing.T, path string, mutate func(*contracts.ProfilingAuthorization)) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cannot read %s: %v", path, err)
	}
	var a contracts.ProfilingAuthorization
	if err := json.Unmarshal(raw, &a); err != nil {
		t.Fatalf("cannot decode %s: %v", path, err)
	}
	mutate(&a)
	out, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		t.Fatalf("cannot re-encode %s: %v", path, err)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatalf("cannot rewrite %s: %v", path, err)
	}
}

func flipAuthorizationSignature(t *testing.T, authPath string) {
	t.Helper()
	sidecar := integrity.AuthSidecarPath(authPath)
	raw, err := os.ReadFile(sidecar)
	if err != nil {
		t.Fatalf("cannot read %s: %v", sidecar, err)
	}
	var sig integrity.AuthSignature
	if err := json.Unmarshal(raw, &sig); err != nil {
		t.Fatalf("cannot decode %s: %v", sidecar, err)
	}
	body, err := base64.StdEncoding.DecodeString(sig.Signature)
	if err != nil {
		t.Fatalf("the signature is not base64: %v", err)
	}
	body[0] ^= 0xff
	sig.Signature = base64.StdEncoding.EncodeToString(body)
	out, err := json.MarshalIndent(sig, "", "  ")
	if err != nil {
		t.Fatalf("cannot re-encode the sidecar: %v", err)
	}
	if err := os.WriteFile(sidecar, out, 0o600); err != nil {
		t.Fatalf("cannot rewrite %s: %v", sidecar, err)
	}
}

// writeValidationFile writes a C-10 with a correctly derived digest, signed by
// the directory's issuer when sign is true.
func writeValidationFile(t *testing.T, dir, name string, sign bool) (string, *integrity.Key) {
	t.Helper()
	key, _ := testIssuer(t, dir)
	v := contracts.ValidValidationAuthorization()
	digest, err := v.RecomputeImmutabilityDigest()
	if err != nil {
		t.Fatalf("cannot derive the immutability digest: %v", err)
	}
	v.ImmutabilityDigest = digest
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatalf("cannot encode the C-10: %v", err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("cannot write %s: %v", path, err)
	}
	if sign {
		canonical, err := contracts.Canonical(*v)
		if err != nil {
			t.Fatalf("cannot canonicalize the C-10: %v", err)
		}
		sig, err := integrity.SignAuthorization(contracts.IDValidationAuthorization, canonical, key)
		if err != nil {
			t.Fatalf("cannot sign the C-10: %v", err)
		}
		if err := integrity.WriteAuthSignature(path, sig); err != nil {
			t.Fatalf("cannot write the C-10 signature: %v", err)
		}
	}
	return path, key
}

func rewriteValidation(t *testing.T, path string, mutate func(*contracts.ValidationAuthorization)) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cannot read %s: %v", path, err)
	}
	var v contracts.ValidationAuthorization
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("cannot decode %s: %v", path, err)
	}
	mutate(&v)
	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatalf("cannot re-encode %s: %v", path, err)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatalf("cannot rewrite %s: %v", path, err)
	}
}

// TestAuthorizationSignCommandSignsWhatTheLoaderAccepts closes the loop between
// the command that produces a signature and the loader that demands one. A
// signer whose output its own reader refuses would be worse than no signer.
func TestAuthorizationSignCommandSignsWhatTheLoaderAccepts(t *testing.T) {
	dir := t.TempDir()
	key, _ := testIssuer(t, dir)
	auth := testAuth(t, 8099)
	path := writeUnsignedAuth(t, dir, auth, "to-sign.json")

	code, out, errs := run(t, "authorization", "sign", "--authorization", path, "--signing-key", key.Path)
	if code != 0 {
		t.Fatalf("signing must succeed: exit %d\n%s\n%s", code, out, errs)
	}
	for _, want := range []string{"signed ", "C-09", "signature:", "issuer fingerprint: " + integrity.KeyFingerprint(key.Public)} {
		if !strings.Contains(out, want) {
			t.Errorf("the signer must report %q, got:\n%s", want, out)
		}
	}
	ring, err := integrity.LoadIssuerKeyring(testKeyring(dir))
	if err != nil {
		t.Fatalf("cannot load the test keyring: %v", err)
	}
	if _, err := loadProfiling(path, ring); err != nil {
		t.Fatalf("the loader must accept what the signer wrote: %v", err)
	}

	// A fingerprint that does not derive from the signing key is an operator
	// mistake the signer refuses to bless: otherwise the inconsistency would
	// carry a signature.
	wrongPath := writeUnsignedAuth(t, dir, auth, "wrong-fingerprint.json")
	rewriteAuthorization(t, wrongPath, func(x *contracts.ProfilingAuthorization) {
		x.IssuerKeyFingerprint = "ed25519:" + strings.Repeat("0", 64)
	})
	code, out, errs = run(t, "authorization", "sign", "--authorization", wrongPath, "--signing-key", key.Path)
	if code == 0 {
		t.Fatalf("a fingerprint that does not derive from the key must not be signed:\n%s", out)
	}
	if !strings.Contains(errs, "issuer_key_fingerprint") {
		t.Fatalf("the refusal must name the field: %s", errs)
	}
	if _, err := os.Stat(integrity.AuthSidecarPath(wrongPath)); !os.IsNotExist(err) {
		t.Fatalf("a refused signature must leave no sidecar (%v)", err)
	}
}

// TestAuthorizationDecodingRefusesFieldsNoOneSigned covers the strict decode
// that makes a signature mean "these exact fields": a field the tool does not
// know is a field the signature would not cover.
func TestAuthorizationDecodingRefusesFieldsNoOneSigned(t *testing.T) {
	dir := t.TempDir()
	path := writeAuthFile(t, dir, testAuth(t, 8099), "auth.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cannot read %s: %v", path, err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("cannot decode %s: %v", path, err)
	}
	doc["scope_note"] = "an extra field nobody signed"
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatalf("cannot re-encode %s: %v", path, err)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatalf("cannot rewrite %s: %v", path, err)
	}
	ring, err := integrity.LoadIssuerKeyring(testKeyring(dir))
	if err != nil {
		t.Fatalf("cannot load the test keyring: %v", err)
	}
	if _, err := loadProfiling(path, ring); err == nil {
		t.Fatal("an unknown field must make the document unreadable")
	} else if !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("the refusal must name the unknown field: %v", err)
	}
}

// TestValidationAuthorizationIsImmutableAndSigned covers C-10's two bindings:
// the digest proves the declared fields did not change after approval, and the
// detached signature proves who approved them.
func TestValidationAuthorizationIsImmutableAndSigned(t *testing.T) {
	t.Run("as approved", func(t *testing.T) {
		dir := t.TempDir()
		path, _ := writeValidationFile(t, dir, "validation.json", true)
		if _, err := loadValidation(path, testKeyring(dir)); err != nil {
			t.Fatalf("a complete C-10 must load: %v", err)
		}
	})

	t.Run("unsigned", func(t *testing.T) {
		dir := t.TempDir()
		path, _ := writeValidationFile(t, dir, "validation.json", false)
		_, err := loadValidation(path, testKeyring(dir))
		if err == nil || !strings.Contains(err.Error(), "no detached signature") {
			t.Fatalf("a C-10 with no sidecar must be refused, got: %v", err)
		}
	})

	t.Run("digest edited", func(t *testing.T) {
		dir := t.TempDir()
		path, _ := writeValidationFile(t, dir, "validation.json", true)
		rewriteValidation(t, path, func(v *contracts.ValidationAuthorization) {
			v.ImmutabilityDigest = contracts.NewDigest([]byte("rewritten after approval"))
		})
		_, err := loadValidation(path, testKeyring(dir))
		if err == nil || !strings.Contains(err.Error(), "immutability_digest") {
			t.Fatalf("a rewritten digest must be refused, got: %v", err)
		}
	})

	t.Run("field edited under an untouched digest", func(t *testing.T) {
		dir := t.TempDir()
		path, _ := writeValidationFile(t, dir, "validation.json", true)
		rewriteValidation(t, path, func(v *contracts.ValidationAuthorization) {
			v.MaxRequests++
		})
		_, err := loadValidation(path, testKeyring(dir))
		if err == nil || !strings.Contains(err.Error(), "derive") {
			t.Fatalf("a C-10 whose fields no longer match its digest must be refused, got: %v", err)
		}
	})

	t.Run("signature edited", func(t *testing.T) {
		dir := t.TempDir()
		path, _ := writeValidationFile(t, dir, "validation.json", true)
		flipAuthorizationSignature(t, path)
		_, err := loadValidation(path, testKeyring(dir))
		if err == nil || !strings.Contains(err.Error(), "does not verify") {
			t.Fatalf("a C-10 whose signature was edited must be refused, got: %v", err)
		}
	})

	t.Run("signed by an issuer outside the ring", func(t *testing.T) {
		dir := t.TempDir()
		path, _ := writeValidationFile(t, dir, "validation.json", true)
		elsewhere := t.TempDir()
		testIssuer(t, elsewhere)
		_, err := loadValidation(path, testKeyring(elsewhere))
		if err == nil || !strings.Contains(err.Error(), "not in the keyring") {
			t.Fatalf("a C-10 signed by an unknown issuer must be refused, got: %v", err)
		}
	})
}

// TestRunRefusesAnAuthorizationBeforeTheSocket is the security property 0.1
// adds: an unsigned, altered or untrusted permission never reaches a plan, and
// the canary proves no connection was attempted.
func TestRunRefusesAnAuthorizationBeforeTheSocket(t *testing.T) {
	k := newCanary(t)
	dir := t.TempDir()
	a := testAuth(t, k.port())
	unsigned := writeUnsignedAuth(t, dir, a, "unsigned.json")
	tampered := writeAuthFile(t, dir, a, "tampered.json")
	rewriteAuthorization(t, tampered, func(x *contracts.ProfilingAuthorization) {
		x.Limits.MaxRequests = a.Limits.MaxRequests + 1
	})

	elsewhere := t.TempDir()
	testIssuer(t, elsewhere)

	cases := []struct {
		name    string
		auth    string
		keyring string
		wanted  string
	}{
		{"unsigned", unsigned, testKeyring(dir), "no detached signature"},
		{"altered after signing", tampered, testKeyring(dir), "does not verify"},
		{"issuer not in the ring", writeAuthFile(t, dir, a, "other-issuer.json"), testKeyring(elsewhere),
			"not in the keyring"},
		{"no keyring", writeAuthFile(t, dir, a, "no-ring.json"), "", "no issuer keyring was supplied"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runsDir := filepath.Join(dir, "runs-"+strings.ReplaceAll(tc.name, " ", "-"))
			argv := []string{"run", "--authorization", tc.auth, "--authorize", a.Ref,
				"--run", "authsig-refusal", "--corpus", testCorpusRoot, "--runs-dir", runsDir,
				"--class", "sqli", "--vector", "query", "--budget", "24"}
			if tc.keyring != "" {
				argv = append(argv, "--issuer-keyring", tc.keyring)
			}
			code, out, errs := run(t, argv...)
			if code != 1 {
				t.Fatalf("the run must fail on the permission (exit 1), got %d\n%s\n%s", code, out, errs)
			}
			if !strings.Contains(errs, tc.wanted) {
				t.Fatalf("the refusal must state %q, got: %s", tc.wanted, errs)
			}
			if strings.Contains(out, "executed") {
				t.Fatalf("a refused run must not reach execution: %s", out)
			}
			if _, err := os.Stat(runsDir); !os.IsNotExist(err) {
				t.Fatalf("a refused run must not create its bundle (%v)", err)
			}
			k.idle(t, "run "+tc.name)
		})
	}
}

// TestVerifyReportsATamperedAuthorizationAsAFailure covers the reader's half:
// naming a permission beside a bundle is a verification, so a signature that no
// longer holds is a failed verification rather than a note.
func TestVerifyReportsATamperedAuthorizationAsAFailure(t *testing.T) {
	srv := fakePerimeter(t)
	dir := t.TempDir()
	auth := testAuth(t, perimeterPort(t, srv))
	authPath := writeAuthFile(t, dir, auth, "auth.json")
	runsDir := filepath.Join(dir, "runs")

	code, out, errs := run(t, "run", "--authorization", authPath, "--authorize", auth.Ref,
		"--issuer-keyring", testKeyring(dir),
		"--run", "verify-authsig", "--corpus", testCorpusRoot, "--runs-dir", runsDir,
		"--class", "sqli", "--vector", "query", "--budget", "24",
		"--signing-key", filepath.Join(dir, "bundle.ed25519"))
	if code != 0 {
		t.Fatalf("the fixture run must complete: exit %d\n%s\n%s", code, out, errs)
	}

	verify := []string{"verify", "--run", "verify-authsig", "--runs-dir", runsDir,
		"--authorization", authPath, "--issuer-keyring", testKeyring(dir)}
	code, out, errs = run(t, verify...)
	if code != 0 || !strings.Contains(out, "authorization_signature") {
		t.Fatalf("an intact permission must verify: exit %d\n%s\n%s", code, out, errs)
	}

	rewriteAuthorization(t, authPath, func(x *contracts.ProfilingAuthorization) {
		x.Limits.MaxRequests++
	})
	code, out, errs = run(t, verify...)
	if code == 0 {
		t.Fatalf("a permission altered after signing must fail verification:\n%s", out)
	}
	if strings.Contains(out, "authorization_signature") {
		t.Fatalf("the failed check must not be reported as ok:\n%s", out)
	}
	if !strings.Contains(errs, "does not verify") {
		t.Fatalf("the refusal must say the signature does not hold: %s", errs)
	}
}
