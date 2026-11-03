package contracts

import (
	"sort"
	"strings"
	"time"
)

// ManifestFileEntry is one file covered by the signature.
type ManifestFileEntry struct {
	Path       string `json:"path"`
	Digest     string `json:"digest"`
	Bytes      int    `json:"bytes"`
	Lines      int    `json:"lines"`
	Contract   ID     `json:"contract_type"`
	AppendOnly bool   `json:"append_only"`
}

// IntegrityManifest is C-12: the signed closure over a run's evidence. The
// payload digest commits to the exact byte sequence that was signed, so
// verification recomputes rather than re-reads (JAVI-019).
type IntegrityManifest struct {
	ManifestID       string              `json:"manifest_id"`
	RunID            string              `json:"run_id"`
	GeneratedAt      time.Time           `json:"generated_at"`
	ToolVersion      string              `json:"tool_version"`
	AuthorizationRef string              `json:"authorization_ref"`
	ValidationRef    string              `json:"validation_ref,omitempty"`
	Algorithm        string              `json:"algorithm"`
	SignerKeyID      string              `json:"signer_key_id"`
	PublicKey        string              `json:"public_key_base64"`
	Signature        string              `json:"signature_base64"`
	PayloadDigest    string              `json:"payload_digest"`
	ChainHead        string              `json:"observation_chain_head"`
	RootHash         string              `json:"merkle_root"`
	FileCount        int                 `json:"file_count"`
	ObservationCount int                 `json:"observation_count"`
	ContractVersions map[string]string   `json:"contract_versions"`
	Files            []ManifestFileEntry `json:"files"`
	SigningRule      string              `json:"signing_rule"`
}

func (IntegrityManifest) Contract() ID { return IDIntegrityManifest }

func registerManifestContract() {
	register(IDIntegrityManifest, func(payload any) error {
		m, err := cast[IntegrityManifest](IDIntegrityManifest, payload)
		if err != nil {
			return err
		}
		c := newViolations(IDIntegrityManifest)
		uuidField(c, "manifest_id", m.ManifestID)
		c.required("run_id", m.RunID)
		c.required("authorization_ref", m.AuthorizationRef)
		c.required("tool_version", m.ToolVersion)
		if m.GeneratedAt.IsZero() {
			c.add("generated_at", "required")
		}
		c.oneof("algorithm", m.Algorithm, "ed25519")
		c.required("signer_key_id", m.SignerKeyID)
		c.required("public_key_base64", m.PublicKey)
		c.required("signature_base64", m.Signature)
		digestField(c, "payload_digest", m.PayloadDigest)
		digestField(c, "observation_chain_head", m.ChainHead)
		digestField(c, "merkle_root", m.RootHash)
		c.required("signing_rule", m.SigningRule)
		c.nonEmpty("contract_versions", len(m.ContractVersions))
		for _, id := range IDs() {
			if m.ContractVersions[string(id)] == "" {
				c.add("contract_versions", "must pin the version of "+string(id))
			}
		}
		if m.FileCount != len(m.Files) {
			c.add("file_count", "does not match the number of listed files")
		}
		c.nonEmpty("files", len(m.Files))
		prev := ""
		for _, f := range m.Files {
			c.required("files[].path", f.Path)
			digestField(c, "files[].digest", f.Digest)
			c.nonNegative("files[].bytes", f.Bytes)
			c.nonNegative("files[].lines", f.Lines)
			if !Registered(f.Contract) {
				// A bundle legitimately contains files that are not contract
				// payloads: operator notes, refusal notices, the state-transition
				// mirror. Leaving them out to satisfy a type check would make the
				// signature cover less evidence than the run produced, so such a
				// file declares itself with a journal marker -- and the marker has
				// to name the file it is attached to, which keeps an unknown type
				// from being laundered as a journal.
				slug, ok := journalSlug(f.Contract)
				switch {
				case !ok:
					c.add("files[].contract_type", "unknown contract "+string(f.Contract))
				case f.Path != slug+".jsonl":
					c.add("files[].contract_type", "journal marker "+string(f.Contract)+
						" does not match the file name "+f.Path)
				}
			}
			if f.Path < prev {
				c.add("files[].path", "entries must be sorted by path so the merkle root is reproducible")
			}
			if f.Path == prev {
				c.add("files[].path", "duplicate entry "+f.Path)
			}
			prev = f.Path
		}
		// A manifest that covers zero observations signs nothing.
		if m.ObservationCount == 0 {
			c.add("observation_count", "a signed manifest with no observations is not evidence")
		}
		if f := findFile(m.Files, "observations.jsonl"); f != nil && f.Lines != m.ObservationCount {
			c.add("observation_count", "does not match the line count of observations.jsonl")
		}
		return c.err()
	})
}

func findFile(files []ManifestFileEntry, path string) *ManifestFileEntry {
	for i := range files {
		if files[i].Path == path {
			return &files[i]
		}
	}
	return nil
}

// JournalContract names the manifest type of a file that holds journal records
// rather than instances of a registered contract.
func JournalContract(stream string) ID { return ID("journal:" + stream) }

// journalSlug splits a "journal:<stream>" marker. The stream must be a bare
// lower-case slug so it can be matched against the file name.
func journalSlug(id ID) (string, bool) {
	s := string(id)
	if !strings.HasPrefix(s, "journal:") {
		return "", false
	}
	slug := s[len("journal:"):]
	if slug == "" {
		return "", false
	}
	for _, r := range slug {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
			return "", false
		}
	}
	return slug, true
}

// SortedFiles returns the manifest entries in canonical order.
func (m IntegrityManifest) SortedFiles() []ManifestFileEntry {
	out := append([]ManifestFileEntry(nil), m.Files...)
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

func init() { registerManifestContract() }
