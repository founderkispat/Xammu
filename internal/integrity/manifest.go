package integrity

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
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

// ToolVersion is stamped into every manifest and report. It is a literal rather
// than a build-time injection so that a released binary states the same version
// the acceptance suite was run against.
const ToolVersion = "xammu-1.0.0"

// SigningRule is the human-readable statement of what the signature commits to.
// It travels inside the manifest so a verifier reads the rule from the evidence
// rather than from the tool that produced it.
const SigningRule = "ed25519 over sha256(canonical-json(manifest minus signature and payload_digest)); " +
	"payload_digest commits to the merkle root of per-file sha256 digests, ordered by path"

// KeyFileName is the default private key location inside a XAMMU home directory.
// The path is a config value, never a flag value or an environment variable, so
// key material does not appear in a process listing.
const KeyFileName = "signing_key.ed25519"

// Key is one Ed25519 signing identity.
type Key struct {
	Path    string
	KeyID   string
	Public  ed25519.PublicKey
	Private ed25519.PrivateKey
}

// LoadOrCreateKey reads a seed from path, creating one with 0600 when absent.
// The file is the only place the private key exists; nothing about it is passed
// through argv or the environment.
func LoadOrCreateKey(path string) (*Key, error) {
	if path == "" {
		return nil, errors.New("integrity: no key path configured")
	}
	raw, err := os.ReadFile(path)
	if err == nil {
		seed, decErr := hex.DecodeString(strings.TrimSpace(string(raw)))
		if decErr != nil || len(seed) != ed25519.SeedSize {
			return nil, fmt.Errorf("integrity: %s is not an ed25519 seed file", path)
		}
		priv := ed25519.NewKeyFromSeed(seed)
		pub := priv.Public().(ed25519.PublicKey)
		return &Key{Path: path, KeyID: keyID(pub), Public: pub, Private: priv}, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("integrity: cannot read signing key: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("integrity: cannot create key directory: %w", err)
	}
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("integrity: key generation failed: %w", err)
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(seed)), 0o600); err != nil {
		return nil, fmt.Errorf("integrity: cannot write signing key: %w", err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	return &Key{Path: path, KeyID: keyID(pub), Public: pub, Private: priv}, nil
}

func keyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

// FileEntry describes one artifact on disk, exactly as the manifest records it.
type FileEntry struct {
	Path     string
	Digest   string
	Bytes    int
	Lines    int
	Contract contracts.ID
}

// Describe hashes one file and counts its journal lines.
func Describe(root, rel string) (FileEntry, error) {
	abs := filepath.Join(root, filepath.FromSlash(rel))
	raw, err := os.ReadFile(abs)
	if err != nil {
		return FileEntry{}, fmt.Errorf("integrity: cannot hash %s: %w", rel, err)
	}
	lines := 0
	if len(raw) > 0 {
		lines = strings.Count(strings.TrimRight(string(raw), "\n"), "\n") + 1
	}
	st := Stream(strings.TrimSuffix(rel, ".jsonl"))
	id := contracts.ID(strings.TrimSuffix(rel, ".json"))
	if rel == "run.json" {
		id = contracts.IDRunProfile
	}
	if c, ok := StreamContract[st]; ok {
		id = c
	} else if strings.HasSuffix(rel, ".jsonl") {
		// A journal whose records are not contract payloads says so explicitly,
		// so the manifest still covers it instead of quietly omitting it.
		id = contracts.JournalContract(string(st))
	}
	return FileEntry{Path: rel, Digest: contracts.NewDigest(raw), Bytes: len(raw),
		Lines: lines, Contract: id}, nil
}

// MerkleRoot folds ordered leaf hashes pairwise. The leaf material includes the
// path, so a file renamed to another authorized name still changes the root.
func MerkleRoot(entries []FileEntry) string {
	sorted := append([]FileEntry(nil), entries...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Path < sorted[j].Path })
	if len(sorted) == 0 {
		return Genesis
	}
	level := make([]string, 0, len(sorted))
	for _, e := range sorted {
		sum := sha256.Sum256([]byte(e.Path + "\x00" + e.Digest))
		level = append(level, hex.EncodeToString(sum[:]))
	}
	for len(level) > 1 {
		var next []string
		for i := 0; i < len(level); i += 2 {
			if i+1 == len(level) {
				// An odd node is promoted, not paired with a fabricated empty
				// digest: inventing a peer would make two different trees hash
				// the same.
				next = append(next, level[i])
				continue
			}
			sum := sha256.Sum256([]byte(level[i] + level[i+1]))
			next = append(next, hex.EncodeToString(sum[:]))
		}
		level = next
	}
	return "sha256:" + level[0]
}

// signingMaterial is the manifest with its own fields removed from the commit:
// the signature and the payload digest cannot be part of what they sign.
func signingMaterial(m contracts.IntegrityManifest) ([]byte, error) {
	m.Signature = ""
	m.PayloadDigest = ""
	var buf strings.Builder
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(m); err != nil {
		return nil, err
	}
	return []byte(strings.TrimSuffix(buf.String(), "\n")), nil
}

// PayloadDigest is the hash the signature covers.
func PayloadDigest(m contracts.IntegrityManifest) (string, error) {
	raw, err := signingMaterial(m)
	if err != nil {
		return "", err
	}
	return contracts.NewDigest(raw), nil
}

// BuildManifest inventories a sealed store directory and produces the unsigned
// C-12 payload for one run. Contract versions are pinned for every registered
// contract, so a manifest states which schema produced each artifact.
func BuildManifest(root string, runID, authRef, validationRef string,
	observationCount int, chainHead string) (contracts.IntegrityManifest, error) {
	rel, err := listJournals(root)
	if err != nil {
		return contracts.IntegrityManifest{}, err
	}
	if len(rel) == 0 {
		return contracts.IntegrityManifest{}, errors.New("integrity: no artifacts to sign")
	}
	var entries []contracts.ManifestFileEntry
	var described []FileEntry
	for _, p := range rel {
		e, err := Describe(root, p)
		if err != nil {
			return contracts.IntegrityManifest{}, err
		}
		described = append(described, e)
		entries = append(entries, contracts.ManifestFileEntry{
			Path: e.Path, Digest: e.Digest, Bytes: e.Bytes, Lines: e.Lines,
			Contract: e.Contract, AppendOnly: strings.HasSuffix(e.Path, ".jsonl"),
		})
	}
	versions := map[string]string{}
	for _, id := range contracts.IDs() {
		versions[string(id)] = contracts.SchemaVersion.String()
	}
	m := contracts.IntegrityManifest{
		ManifestID: contracts.NewUUID(), RunID: runID, GeneratedAt: time.Now().UTC(),
		ToolVersion: ToolVersion, AuthorizationRef: authRef, ValidationRef: validationRef,
		Algorithm: "ed25519", SignerKeyID: "", PublicKey: "", Signature: "",
		ChainHead: chainHead, RootHash: MerkleRoot(described), FileCount: len(entries),
		ObservationCount: observationCount, ContractVersions: versions,
		Files: entries, SigningRule: SigningRule,
	}
	return m, nil
}

// Sign fills the key, payload digest and signature fields in place.
func Sign(m *contracts.IntegrityManifest, key *Key) error {
	if key == nil || len(key.Private) == 0 {
		return errors.New("integrity: no signing key")
	}
	m.SignerKeyID = key.KeyID
	m.PublicKey = base64.StdEncoding.EncodeToString(key.Public)
	digest, err := PayloadDigest(*m)
	if err != nil {
		return err
	}
	m.PayloadDigest = digest
	raw, err := signingMaterial(*m)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(raw)
	m.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key.Private, sum[:]))
	return contracts.Validate(contracts.IDIntegrityManifest, m)
}

// VerifyStatus is one check performed against a signed manifest, reported
// separately so a reviewer sees which property failed rather than only that the
// run did not verify.
// CheckSignerTrusted names the one Verify check that measures the operator's trust
// rather than the bundle's own consistency. It fails when no trusted key is supplied,
// which is a statement about the reader's configuration and not about the evidence, so
// a caller has to be able to tell the two apart.
const CheckSignerTrusted = "signer_is_trusted"

type VerifyStatus struct {
	Check  string `json:"check"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

// Verify re-derives everything the manifest claims. When trustedPublicKey is
// non-nil the embedded key must match it, which is what turns "the signature is
// self-consistent" into "the signature is from the key this operator trusts".
func Verify(root string, m contracts.IntegrityManifest, trustedPublicKey []byte) []VerifyStatus {
	var out []VerifyStatus
	add := func(check string, ok bool, detail string) {
		out = append(out, VerifyStatus{Check: check, OK: ok, Detail: detail})
	}

	if err := contracts.Validate(contracts.IDIntegrityManifest, &m); err != nil {
		add("contract_valid", false, err.Error())
	} else {
		add("contract_valid", true, "manifest satisfies C-12")
	}

	// Signature and payload digest.
	pub, err := base64.StdEncoding.DecodeString(m.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		add("public_key_decodes", false, "manifest public key is not an ed25519 key")
		return out
	}
	if keyID(pub) != m.SignerKeyID {
		add("public_key_decodes", false,
			"manifest key id "+keyID(pub)+" does not match the declared signer "+m.SignerKeyID)
	} else {
		add("public_key_decodes", true, "public key decodes and matches the declared signer")
	}
	if len(trustedPublicKey) > 0 {
		// bytes.Equal, not PublicKey.Equal: Equal takes crypto.PublicKey, so a
		// []byte argument compares unequal without ever reporting why.
		match := bytes.Equal(pub, trustedPublicKey)
		add(CheckSignerTrusted, match, "manifest key "+keyID(pub)+", trusted key "+keyID(trustedPublicKey))
	} else {
		add(CheckSignerTrusted, false,
			"no trusted key supplied: the signature is self-consistent but the identity is unverified")
	}
	digest, err := PayloadDigest(m)
	if err != nil {
		add("payload_digest_recomputed", false, err.Error())
		return out
	}
	add("payload_digest_recomputed", digest == m.PayloadDigest,
		fmt.Sprintf("recomputed %s", short(digest)))
	raw, err := signingMaterial(m)
	if err != nil {
		add("signature_valid", false, err.Error())
		return out
	}
	sum := sha256.Sum256(raw)
	sig, err := base64.StdEncoding.DecodeString(m.Signature)
	if err != nil {
		add("signature_valid", false, "signature is not base64")
		return out
	}
	add("signature_valid", ed25519.Verify(pub, sum[:], sig), "ed25519 over the payload material")

	// Inventory: every listed file, and no file that is not listed.
	onDisk, err := listJournals(root)
	if err != nil {
		add("inventory_readable", false, err.Error())
		return out
	}
	add("inventory_readable", true, fmt.Sprintf("%d artifacts present", len(onDisk)))
	byPath := map[string]contracts.ManifestFileEntry{}
	for _, f := range m.Files {
		byPath[f.Path] = f
	}
	var missing, changed, extra []string
	var described []FileEntry
	for _, p := range onDisk {
		e, err := Describe(root, p)
		if err != nil {
			add("file_hashable", false, err.Error())
			continue
		}
		described = append(described, e)
		f, ok := byPath[p]
		if !ok {
			extra = append(extra, p)
			continue
		}
		if f.Digest != e.Digest || f.Bytes != e.Bytes || f.Lines != e.Lines {
			changed = append(changed, p)
		}
	}
	for _, f := range m.Files {
		if _, ok := statExists(root, f.Path); !ok {
			missing = append(missing, f.Path)
		}
	}
	add("no_unlisted_files", len(extra) == 0, strings.Join(extra, ", "))
	add("no_missing_files", len(missing) == 0, strings.Join(missing, ", "))
	add("no_modified_files", len(changed) == 0, strings.Join(changed, ", "))

	// Merkle root over the files as they exist now.
	root0 := MerkleRoot(described)
	add("merkle_root_matches", root0 == m.RootHash, "recomputed "+short(root0))

	// Chain head and observation count.
	if f, ok := byPath["observations.jsonl"]; ok {
		add("observation_chain_head", f.Digest != "", "observations.jsonl is inventoried")
	} else {
		add("observation_chain_head", false, "observations.jsonl is not covered by the manifest")
	}
	if records, err := readRecords(root, StreamObservations); err == nil && len(records) > 0 {
		last := records[len(records)-1]
		add("chain_head_is_last_record", last.Digest == m.ChainHead,
			"journal head "+short(last.Digest)+", manifest head "+short(m.ChainHead))
		add("observation_count_matches", len(records) == m.ObservationCount,
			fmt.Sprintf("journal holds %d, manifest claims %d", len(records), m.ObservationCount))
	} else {
		add("chain_head_is_last_record", false, "observations journal unreadable or empty")
		add("observation_count_matches", false, "observations journal unreadable or empty")
	}

	// Chain integrity, independent of the manifest.
	breaks := VerifyDir(root)
	add("hash_chain_intact", len(breaks) == 0, joinBreaks(breaks))
	return out
}

func joinBreaks(breaks []Break) string {
	if len(breaks) == 0 {
		return "all chains verify"
	}
	parts := make([]string, 0, len(breaks))
	for _, b := range breaks {
		parts = append(parts, b.String())
	}
	return strings.Join(parts, "; ")
}

func statExists(root, rel string) (os.FileInfo, bool) {
	fi, err := os.Stat(filepath.Join(root, filepath.FromSlash(rel)))
	return fi, err == nil
}

// listJournals returns every artifact file in the store, slash-separated and
// sorted, excluding the manifest itself (a file cannot cover its own signature).
func listJournals(root string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".jsonl") && name != "run.json" {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		out = append(out, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("integrity: cannot inventory %s: %w", root, err)
	}
	sort.Strings(out)
	return out, nil
}

func readRecords(root string, st Stream) ([]Record, error) {
	raw, err := os.ReadFile(filepath.Join(root, string(st)+".jsonl"))
	if err != nil {
		return nil, err
	}
	var out []Record
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var r Record
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

// WriteManifest persists the signed manifest next to the evidence it covers.
func WriteManifest(root string, m contracts.IntegrityManifest) error {
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(root, "manifest.json"), append(raw, '\n'), 0o640)
}

// ReadManifest loads a manifest from an artifact directory.
func ReadManifest(root string) (contracts.IntegrityManifest, error) {
	var m contracts.IntegrityManifest
	raw, err := os.ReadFile(filepath.Join(root, "manifest.json"))
	if err != nil {
		return m, err
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return m, fmt.Errorf("integrity: manifest.json is not readable: %w", err)
	}
	return m, nil
}

// PublicKeyOf returns the decoded signing key of a manifest, for trust checks.
func PublicKeyOf(m contracts.IntegrityManifest) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(m.PublicKey)
	if err != nil {
		return nil, err
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("integrity: public key has the wrong length")
	}
	return ed25519.PublicKey(raw), nil
}
