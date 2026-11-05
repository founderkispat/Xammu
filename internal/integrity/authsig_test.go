package integrity_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"xammu/internal/contracts"
	"xammu/internal/integrity"
)

// issuerKey creates (or reuses) an ed25519 seed file and returns the key it
// loads. The seed stays in the test's temporary directory: the property under
// test is that a signature can only be produced by whoever holds it.
func issuerKey(t *testing.T, dir, name string) *integrity.Key {
	t.Helper()
	key, err := integrity.LoadOrCreateKey(filepath.Join(dir, name+".ed25519"))
	if err != nil {
		t.Fatalf("cannot create the %s issuer key: %v", name, err)
	}
	return key
}

func publishKey(t *testing.T, dir, name string, pub ed25519.PublicKey) string {
	t.Helper()
	path := filepath.Join(dir, name+".pub")
	if err := os.WriteFile(path, []byte(hex.EncodeToString(pub)+"\n"), 0o600); err != nil {
		t.Fatalf("cannot publish %s: %v", path, err)
	}
	return path
}

// TestAuthorizationSignatureBindsDocumentKindAndKey covers the four ways a
// signature can be wrong, at the level where the answer is unconditional: a
// different document, a different key, a different contract, or bytes that were
// edited after signing.
func TestAuthorizationSignatureBindsDocumentKindAndKey(t *testing.T) {
	dir := t.TempDir()
	a := issuerKey(t, dir, "a")
	b := issuerKey(t, dir, "b")

	auth := contracts.ValidProfilingAuthorization()
	auth.IssuerKeyFingerprint = integrity.KeyFingerprint(a.Public)
	canonical, err := contracts.Canonical(auth)
	if err != nil {
		t.Fatalf("cannot canonicalize the C-09: %v", err)
	}
	sig, err := integrity.SignAuthorization(contracts.IDProfilingAuthorization, canonical, a)
	if err != nil {
		t.Fatalf("cannot sign the C-09: %v", err)
	}

	changed := *auth
	changed.Ref = "auth-2026-043"
	changedCanonical, err := contracts.Canonical(changed)
	if err != nil {
		t.Fatalf("cannot canonicalize the altered C-09: %v", err)
	}

	raw, err := base64.StdEncoding.DecodeString(sig.Signature)
	if err != nil {
		t.Fatalf("the signature is not base64: %v", err)
	}
	flipped := append([]byte(nil), raw...)
	flipped[len(flipped)-1] ^= 0xff
	alteredSig := sig
	alteredSig.Signature = base64.StdEncoding.EncodeToString(flipped)

	cases := []struct {
		name      string
		kind      contracts.ID
		canonical []byte
		sig       integrity.AuthSignature
		pub       ed25519.PublicKey
		wanted    string
	}{
		{"as signed", contracts.IDProfilingAuthorization, canonical, sig, a.Public, ""},
		{"another key", contracts.IDProfilingAuthorization, canonical, sig, b.Public,
			"but the key supplied is"},
		{"field edited after signing", contracts.IDProfilingAuthorization, changedCanonical, sig, a.Public,
			"does not verify"},
		{"signature bytes edited", contracts.IDProfilingAuthorization, canonical, alteredSig, a.Public,
			"does not verify"},
		{"C-09 signature presented as C-10", contracts.IDValidationAuthorization, canonical, sig, a.Public,
			"does not verify"},
		{"unknown sidecar version", contracts.IDProfilingAuthorization, canonical,
			integrity.AuthSignature{Version: "xammu-authsig-v0", KeyID: sig.KeyID, Signature: sig.Signature},
			a.Public, "declares version"},
		{"public key is not ed25519", contracts.IDProfilingAuthorization, canonical, sig,
			ed25519.PublicKey{1, 2, 3}, "not an ed25519 key"},
		{"signature is not base64", contracts.IDProfilingAuthorization, canonical,
			integrity.AuthSignature{Version: sig.Version, KeyID: sig.KeyID, Signature: "!!!"},
			a.Public, "not base64"},
		{"signature is the wrong length", contracts.IDProfilingAuthorization, canonical,
			integrity.AuthSignature{Version: sig.Version, KeyID: sig.KeyID,
				Signature: base64.StdEncoding.EncodeToString(make([]byte, 10))},
			a.Public, "10 byte(s)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := integrity.VerifyAuthorization(tc.kind, tc.canonical, tc.sig, tc.pub)
			if tc.wanted == "" {
				if err != nil {
					t.Fatalf("the signature must verify: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("a signature that does not cover this document and key must be refused")
			}
			if !strings.Contains(err.Error(), tc.wanted) {
				t.Fatalf("refusal must state %q, got: %v", tc.wanted, err)
			}
		})
	}

	if _, err := integrity.SignAuthorization(contracts.IDProfilingAuthorization, canonical, nil); err == nil {
		t.Fatal("signing without an issuer key must be refused")
	}
	if _, err := integrity.SignAuthorization(contracts.IDRunProfile, canonical, a); err == nil {
		t.Fatal("a non-authorization contract must not be signed by this route")
	}
}

// TestAuthSidecarIsDetachedAndStrict covers the sidecar contract: it is written
// beside the document, read back byte-for-byte, refused when missing with the
// command that creates one, and refused when it carries fields this tool would
// not verify.
func TestAuthSidecarIsDetachedAndStrict(t *testing.T) {
	dir := t.TempDir()
	key := issuerKey(t, dir, "issuer")
	auth := contracts.ValidProfilingAuthorization()
	auth.IssuerKeyFingerprint = integrity.KeyFingerprint(key.Public)
	canonical, err := contracts.Canonical(auth)
	if err != nil {
		t.Fatalf("cannot canonicalize the C-09: %v", err)
	}
	sig, err := integrity.SignAuthorization(contracts.IDProfilingAuthorization, canonical, key)
	if err != nil {
		t.Fatalf("cannot sign the C-09: %v", err)
	}
	authPath := filepath.Join(dir, "auth.json")
	if err := os.WriteFile(authPath, canonical, 0o600); err != nil {
		t.Fatalf("cannot write the authorization: %v", err)
	}

	if _, err := integrity.ReadAuthSignature(authPath); err == nil {
		t.Fatal("an unsigned authorization must not read as signed")
	} else if !strings.Contains(err.Error(), "xammu authorization sign") {
		t.Fatalf("the refusal must name the command that signs: %v", err)
	}

	if err := integrity.WriteAuthSignature(authPath, sig); err != nil {
		t.Fatalf("cannot write the sidecar: %v", err)
	}
	if integrity.AuthSidecarPath(authPath) != authPath+".sig" {
		t.Fatalf("the sidecar must live beside the document: %s", integrity.AuthSidecarPath(authPath))
	}
	back, err := integrity.ReadAuthSignature(authPath)
	if err != nil {
		t.Fatalf("cannot read back the sidecar: %v", err)
	}
	if back.Version != sig.Version || back.KeyID != sig.KeyID || back.Signature != sig.Signature {
		t.Fatalf("the sidecar did not round-trip: %+v", back)
	}

	// A field the verifier does not understand is a field the operator might
	// believe was covered. Strict decoding refuses it rather than ignoring it.
	unknown := `{"version":"` + integrity.AuthSignatureVersion + `","key_id":"` + sig.KeyID +
		`","signature":"` + sig.Signature + `","signed_at":"2026-10-27T10:00:00Z","scope":"all"}`
	if err := os.WriteFile(integrity.AuthSidecarPath(authPath), []byte(unknown), 0o600); err != nil {
		t.Fatalf("cannot seed the unexpected sidecar: %v", err)
	}
	if _, err := integrity.ReadAuthSignature(authPath); err == nil {
		t.Fatal("a sidecar with an unknown field must be refused")
	} else if !strings.Contains(err.Error(), "not a readable sidecar") {
		t.Fatalf("unexpected refusal: %v", err)
	}
}

// TestIssuerKeyringIsTheOnlyTrustAnchor covers the keyring's shape. There is no
// default and no discovery: a missing or empty ring is a refusal, and a file
// that is not exactly one hex ed25519 key is not silently skipped.
func TestIssuerKeyringIsTheOnlyTrustAnchor(t *testing.T) {
	if _, err := integrity.LoadIssuerKeyring(""); err == nil {
		t.Fatal("an empty keyring path must be refused")
	} else if !strings.Contains(err.Error(), "--issuer-keyring") {
		t.Fatalf("the refusal must name the flag: %v", err)
	}
	if _, err := integrity.LoadIssuerKeyring(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Fatal("a keyring directory that does not exist must be refused")
	}

	empty := t.TempDir()
	if _, err := integrity.LoadIssuerKeyring(empty); err == nil {
		t.Fatal("a keyring with no .pub files must be refused")
	} else if !strings.Contains(err.Error(), "holds no .pub files") {
		t.Fatalf("unexpected refusal: %v", err)
	}

	cases := []struct {
		name    string
		content string
		wanted  string
	}{
		{"two tokens", "aa bb\n", "2 whitespace-separated"},
		{"not hex", strings.Repeat("zz", 32), "not hex"},
		{"too short", strings.Repeat("ab", 16), "16 byte(s)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "bad.pub"), []byte(tc.content), 0o600); err != nil {
				t.Fatalf("cannot seed the key file: %v", err)
			}
			_, err := integrity.LoadIssuerKeyring(dir)
			if err == nil {
				t.Fatal("a malformed issuer key must be refused")
			}
			if !strings.Contains(err.Error(), tc.wanted) {
				t.Fatalf("refusal must state %q, got: %v", tc.wanted, err)
			}
		})
	}

	dir := t.TempDir()
	a := issuerKey(t, dir, "a")
	b := issuerKey(t, dir, "b")
	publishKey(t, dir, "b", b.Public)
	publishKey(t, dir, "a", a.Public)
	ring, err := integrity.LoadIssuerKeyring(dir)
	if err != nil {
		t.Fatalf("cannot load a valid keyring: %v", err)
	}
	if len(ring.Keys) != 2 {
		t.Fatalf("the ring must hold both keys, got %d", len(ring.Keys))
	}
	if !strings.HasSuffix(ring.Keys[0].Path, "a.pub") || !strings.HasSuffix(ring.Keys[1].Path, "b.pub") {
		t.Fatalf("keys must be ordered by path, got %s then %s", ring.Keys[0].Path, ring.Keys[1].Path)
	}
	key, ok := ring.Find(a.KeyID)
	if !ok || !key.Public.Equal(a.Public) {
		t.Fatalf("the ring cannot find the key it holds: %v", ok)
	}
	if _, ok := ring.Find("0000000000000000"); ok {
		t.Fatal("the ring must not invent a key it does not hold")
	}
	if ids := ring.IDs(); len(ids) != 2 || ids[0] != a.KeyID || ids[1] != b.KeyID {
		t.Fatalf("IDs must name the ring's keys in order, got %v", ids)
	}

	fa, fb := integrity.KeyFingerprint(a.Public), integrity.KeyFingerprint(b.Public)
	if !strings.HasPrefix(fa, "ed25519:") || len(fa) != len("ed25519:")+64 {
		t.Fatalf("a fingerprint is ed25519: plus the full sha256, got %q", fa)
	}
	if fa == fb {
		t.Fatal("two distinct keys must not share a fingerprint")
	}
	if fa != integrity.KeyFingerprint(a.Public) {
		t.Fatal("the fingerprint must be stable for the same key")
	}
}
