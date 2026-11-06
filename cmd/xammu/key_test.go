package main

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"xammu/internal/integrity"
)

// TestKeyInspectMatchesManifestSigner answers the question a reviewer asks about a
// delivered bundle: which identity signed it? The key id and fingerprint printed here
// have to be the ones the manifest and the authorizations already carry, and the
// private seed must not appear in the output that names them.
func TestKeyInspectMatchesManifestSigner(t *testing.T) {
	dir, key, _ := sealedBundle(t)
	manifest, err := integrity.ReadManifest(dir)
	if err != nil {
		t.Fatalf("reading the sealed manifest: %v", err)
	}
	if manifest.SignerKeyID != key.KeyID {
		t.Fatalf("the fixture manifest names %s, the key derives %s", manifest.SignerKeyID, key.KeyID)
	}

	code, out, errs := run(t, "key", "inspect", "--key", key.Path)
	if code != 0 {
		t.Fatalf("key inspect on a valid seed must succeed: exit %d\n%s\n%s", code, out, errs)
	}
	for _, want := range []string{
		"algorithm    ed25519",
		"key id       " + key.KeyID,
		"public key   " + hex.EncodeToString(key.Public),
		"fingerprint  " + integrity.KeyFingerprint(key.Public),
		"not printed",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("key inspect must print %q:\n%s", want, out)
		}
	}

	seed, err := os.ReadFile(key.Path)
	if err != nil {
		t.Fatalf("reading the seed to prove it is not echoed: %v", err)
	}
	if seedHex := strings.TrimSpace(string(seed)); seedHex != "" && strings.Contains(out, seedHex) {
		t.Fatalf("key inspect printed the private seed:\n%s", out)
	}
}

// TestKeyInspectRefusesAMissingKey keeps the command read only. A path that does
// not exist is the operator pointing at the wrong file, not a request to mint one.
func TestKeyInspectRefusesAMissingKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent.ed25519")
	code, out, errs := run(t, "key", "inspect", "--key", path)
	if code != 2 {
		t.Fatalf("a missing key must be a usage error (exit 2), got %d\n%s\n%s", code, out, errs)
	}
	if !bytes.Contains([]byte(errs), []byte("cannot read signing key")) {
		t.Fatalf("the refusal must name the file it could not read: %s", errs)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("key inspect created the file it was asked to describe: %v", err)
	}

	if code, _, _ = run(t, "key", "inspect"); code != 2 {
		t.Fatalf("a missing --key flag must be a usage error, got %d", code)
	}
	if code, _, _ = run(t, "key"); code != 2 {
		t.Fatalf("a missing subcommand must be a usage error, got %d", code)
	}
}

// TestRotationKeepsOldBundlesVerifiable is the property custody depends on: a new
// signing identity does not invalidate evidence already sealed under the previous
// one. Rotation changes what future runs sign, not what past runs proved.
func TestRotationKeepsOldBundlesVerifiable(t *testing.T) {
	dir, oldKey, _ := sealedBundle(t)
	newKey, err := integrity.LoadOrCreateKey(filepath.Join(t.TempDir(), integrity.KeyFileName))
	if err != nil {
		t.Fatalf("creating the rotated key: %v", err)
	}
	if newKey.KeyID == oldKey.KeyID {
		t.Fatalf("rotation produced the same key id %s", newKey.KeyID)
	}

	code, out, errs := run(t, "verify", "--store", dir, "--trust-key", writeHexKey(t, []byte(oldKey.Public)))
	if code != 0 {
		t.Fatalf("the old bundle must keep verifying with the key that signed it: exit %d\n%s\n%s",
			code, out, errs)
	}

	code, out, errs = run(t, "key", "inspect", "--key", newKey.Path)
	if code != 0 {
		t.Fatalf("the rotated key must be inspectable: exit %d\n%s\n%s", code, out, errs)
	}
	if strings.Contains(out, oldKey.KeyID) || strings.Contains(out, integrity.KeyFingerprint(oldKey.Public)) {
		t.Fatalf("the rotated key reports the old identity:\n%s", out)
	}
}

// TestUntrustedKeyIsRejected is the other half of rotation: a bundle signed by A
// does not become verifiable under B just because B exists.
func TestUntrustedKeyIsRejected(t *testing.T) {
	dir, _, _ := sealedBundle(t)
	other, err := integrity.LoadOrCreateKey(filepath.Join(t.TempDir(), integrity.KeyFileName))
	if err != nil {
		t.Fatalf("creating the other key: %v", err)
	}
	code, out, errs := run(t, "verify", "--store", dir, "--trust-key", writeHexKey(t, []byte(other.Public)))
	if code != 1 {
		t.Fatalf("a bundle signed by another key must fail (exit 1), got %d\n%s\n%s", code, out, errs)
	}
	if !strings.Contains(out, integrity.CheckSignerTrusted) || !strings.Contains(out, "FAIL") {
		t.Fatalf("the failure must name the signer check:\n%s", out)
	}
}
