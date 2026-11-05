package integrity

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"xammu/internal/contracts"
)

// Authorization signatures are detached and domain-separated. A permission is a
// document an operator holds, and the tool has to answer two questions about it
// before it spends anyone's request budget: did the holder of the issuer key
// sign these exact fields, and is that key the one named by the fingerprint.
//
// The detached sidecar keeps C-09 and C-10 unchanged. An embedded signature
// would have forced a schema version bump and would have made every bundle
// sealed under the old schema diverge on re-derivation.
const (
	// AuthSignatureVersion names the sidecar format, not the tool version.
	AuthSignatureVersion = "xammu-authsig-v1"

	// authDomain separates these signatures from the manifest signature: the
	// same key signing different kinds of document must not produce material that
	// can be moved from one to the other.
	authDomain = "XAMMU-AUTH-v1"

	// AuthSidecarSuffix is appended to an authorization path.
	AuthSidecarSuffix = ".sig"
)

// AuthSignature is the detached signature of one C-09 or C-10.
type AuthSignature struct {
	Version   string    `json:"version"`
	KeyID     string    `json:"key_id"`
	Signature string    `json:"signature"`
	SignedAt  time.Time `json:"signed_at"`
}

// AuthSidecarPath is where the signature of an authorization lives.
func AuthSidecarPath(authPath string) string {
	return authPath + AuthSidecarSuffix
}

// authMaterial is the exact byte string a signature covers: a domain tag, the
// contract label, and the canonical declaration. The label is included so a C-09
// signature cannot be presented as one over a C-10 that happens to share fields.
func authMaterial(kind contracts.ID, canonical []byte) ([]byte, error) {
	switch kind {
	case contracts.IDProfilingAuthorization, contracts.IDValidationAuthorization:
	default:
		return nil, fmt.Errorf("integrity: %q (%s) is not an authorization contract", kind, kind.Label())
	}
	material := make([]byte, 0, len(authDomain)+len(kind.Label())+2+len(canonical))
	material = append(material, authDomain...)
	material = append(material, 0)
	material = append(material, kind.Label()...)
	material = append(material, 0)
	material = append(material, canonical...)
	return material, nil
}

// SignAuthorization produces the detached signature of one authorization. The
// private key is the issuer's; it lives outside every bundle by the same rule
// that keeps the manifest key out.
func SignAuthorization(kind contracts.ID, canonical []byte, key *Key) (AuthSignature, error) {
	if key == nil || len(key.Private) == 0 {
		return AuthSignature{}, errors.New("integrity: no issuer signing key")
	}
	material, err := authMaterial(kind, canonical)
	if err != nil {
		return AuthSignature{}, err
	}
	sum := sha256.Sum256(material)
	return AuthSignature{
		Version:   AuthSignatureVersion,
		KeyID:     key.KeyID,
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key.Private, sum[:])),
		SignedAt:  time.Now().UTC(),
	}, nil
}

// VerifyAuthorization checks a detached signature against one issuer key. It
// refuses an unknown sidecar version rather than guessing at its material.
func VerifyAuthorization(kind contracts.ID, canonical []byte, sig AuthSignature, pub ed25519.PublicKey) error {
	if sig.Version != AuthSignatureVersion {
		return fmt.Errorf("the authorization signature declares version %q, this tool verifies %q",
			sig.Version, AuthSignatureVersion)
	}
	if len(pub) != ed25519.PublicKeySize {
		return errors.New("the issuer public key is not an ed25519 key")
	}
	if got := keyID(pub); got != sig.KeyID {
		return fmt.Errorf("the signature names issuer key %s but the key supplied is %s", sig.KeyID, got)
	}
	material, err := authMaterial(kind, canonical)
	if err != nil {
		return err
	}
	raw, err := base64.StdEncoding.DecodeString(sig.Signature)
	if err != nil {
		return fmt.Errorf("the authorization signature is not base64: %w", err)
	}
	if len(raw) != ed25519.SignatureSize {
		return fmt.Errorf("the authorization signature is %d byte(s); ed25519 produces %d",
			len(raw), ed25519.SignatureSize)
	}
	sum := sha256.Sum256(material)
	if !ed25519.Verify(pub, sum[:], raw) {
		return errors.New("the authorization signature does not verify: the document changed after " +
			"it was signed, or it was signed by a different key")
	}
	return nil
}

// WriteAuthSignature persists a sidecar beside the authorization it covers.
func WriteAuthSignature(authPath string, sig AuthSignature) error {
	raw, err := json.MarshalIndent(sig, "", "  ")
	if err != nil {
		return fmt.Errorf("cannot encode the authorization signature: %w", err)
	}
	path := AuthSidecarPath(authPath)
	if err := os.WriteFile(path, append(raw, '\n'), 0o640); err != nil {
		return fmt.Errorf("cannot write the authorization signature %s: %w", path, err)
	}
	return nil
}

// ReadAuthSignature loads the sidecar. A missing sidecar is refused with the
// command that creates one, because an unsigned permission is not a permission
// this tool will spend requests under.
func ReadAuthSignature(authPath string) (AuthSignature, error) {
	var sig AuthSignature
	path := AuthSidecarPath(authPath)
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return sig, fmt.Errorf("authorization %s has no detached signature %s: an unsigned permission "+
			"cannot be verified, so nothing will be sent under it. Sign it with "+
			"`xammu authorization sign --authorization %s --signing-key FILE`",
			authPath, path, filepath.ToSlash(authPath))
	}
	if err != nil {
		return sig, fmt.Errorf("cannot read the authorization signature %s: %w", path, err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&sig); err != nil {
		return sig, fmt.Errorf("the authorization signature %s is not a readable sidecar: %w", path, err)
	}
	return sig, nil
}

// IssuerKey is one public key an operator has accepted from an independent
// channel. The keyring is that channel's local record.
type IssuerKey struct {
	KeyID  string
	Path   string
	Public ed25519.PublicKey
}

// Keyring is the set of issuer keys a reader trusts. It is never discovered from
// an authorization or from a bundle: the operator names the directory, so the
// trust decision is theirs.
type Keyring struct {
	Dir  string
	Keys []IssuerKey
}

// LoadIssuerKeyring reads every *.pub file in dir. Each file holds exactly one
// hex-encoded ed25519 public key, the same format --trust-key uses, so an
// engagement can publish both anchors through one convention.
func LoadIssuerKeyring(dir string) (Keyring, error) {
	if strings.TrimSpace(dir) == "" {
		return Keyring{}, errors.New("no issuer keyring was supplied: an authorization must be verified " +
			"against a public key the operator holds independently of the document. Pass " +
			"--issuer-keyring DIR (the directory of *.pub hex ed25519 keys)")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return Keyring{}, fmt.Errorf("cannot read the issuer keyring %s: %w", dir, err)
	}
	var keys []IssuerKey
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".pub") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		raw, err := os.ReadFile(path)
		if err != nil {
			return Keyring{}, fmt.Errorf("cannot read the issuer key %s: %w", path, err)
		}
		fields := strings.Fields(string(raw))
		if len(fields) != 1 {
			return Keyring{}, fmt.Errorf("the issuer key %s holds %d whitespace-separated value(s); "+
				"a key file holds exactly one hex ed25519 public key", path, len(fields))
		}
		decoded, err := hex.DecodeString(fields[0])
		if err != nil {
			return Keyring{}, fmt.Errorf("the issuer key %s is not hex: %w", path, err)
		}
		if len(decoded) != ed25519.PublicKeySize {
			return Keyring{}, fmt.Errorf("the issuer key %s is %d byte(s); an ed25519 public key is %d",
				path, len(decoded), ed25519.PublicKeySize)
		}
		pub := ed25519.PublicKey(decoded)
		keys = append(keys, IssuerKey{KeyID: keyID(pub), Path: path, Public: pub})
	}
	if len(keys) == 0 {
		return Keyring{}, fmt.Errorf("the issuer keyring %s holds no .pub files: without a key there is "+
			"nothing to verify an authorization against", dir)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].Path < keys[j].Path })
	return Keyring{Dir: dir, Keys: keys}, nil
}

// Find returns the key a signature names.
func (k Keyring) Find(id string) (IssuerKey, bool) {
	for _, key := range k.Keys {
		if key.KeyID == id {
			return key, true
		}
	}
	return IssuerKey{}, false
}

// IDs lists the key identifiers in the ring, for a refusal that tells the
// operator which identities were actually available.
func (k Keyring) IDs() []string {
	out := make([]string, len(k.Keys))
	for i, key := range k.Keys {
		out[i] = key.KeyID
	}
	return out
}

// KeyFingerprint is the value issuer_key_fingerprint must carry: a stable
// rendering of the public key, derived rather than typed. Adopting the full
// sha256 avoids the truncation that makes a fingerprint easy to forge a match
// for.
func KeyFingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return "ed25519:" + hex.EncodeToString(sum[:])
}
