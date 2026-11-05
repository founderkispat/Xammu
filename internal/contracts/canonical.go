package contracts

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// Canonical renders a contract payload as deterministic JSON. It is what an
// authorization signature covers: the decoded structure, not the bytes on disk,
// so re-indenting a file does not invalidate a permission while changing a field
// does. Every authorization structure here is a plain struct with ordered fields
// and no maps, which is what makes re-marshalling stable.
func Canonical(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, fmt.Errorf("cannot encode the contract payload: %w", err)
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// ImmutabilityPayload is the C-10 material the immutability digest covers: the
// declaration with its own digest field removed, since a digest cannot cover
// itself. The signature then covers the declaration including that digest.
func (v ValidationAuthorization) ImmutabilityPayload() ([]byte, error) {
	v.ImmutabilityDigest = ""
	return Canonical(v)
}

// RecomputeImmutabilityDigest derives the digest C-10 must carry. A loader
// compares it with the declared value before the signature is checked; a digest
// that only has the right shape proves nothing about the fields beside it.
func (v ValidationAuthorization) RecomputeImmutabilityDigest() (string, error) {
	raw, err := v.ImmutabilityPayload()
	if err != nil {
		return "", err
	}
	return NewDigest(raw), nil
}
