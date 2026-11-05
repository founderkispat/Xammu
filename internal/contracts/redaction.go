package contracts

import (
	"crypto/rand"
	"fmt"
	"sort"
	"strings"
)

// RedactedValueMarker is what C-01 carries in place of a sensitive header's
// value. It is a statement that the value was withheld, not a reading of it.
const RedactedValueMarker = "[redacted]"

// sensitiveResponseHeaders is the base redaction list: cookies and credentials a
// response may echo back. Names are lower-case because HTTP header names are
// case-insensitive. The list is fixed here rather than configurable downward:
// an operator may add names, never remove one.
var sensitiveResponseHeaders = []string{
	"set-cookie",
	"cookie",
	"authorization",
	"proxy-authorization",
	"x-api-key",
	"x-auth-token",
}

// SensitiveResponseHeaderNames returns a copy of the base list, ordered, for docs
// and for the evidence block that publishes the policy.
func SensitiveResponseHeaderNames() []string {
	return append([]string(nil), sensitiveResponseHeaders...)
}

// HeaderRedactor replaces the value of a sensitive response header with the
// marker and keeps only a salted digest of the original. The salt is generated
// once per run and has no accessor: a digest that could be recomputed later
// would let a reader test candidate values offline, which is the property the
// redaction exists to prevent.
//
// The salt is never serialised. Only the digests reach C-01, so two runs that
// see the same cookie value publish two unrelated digests.
type HeaderRedactor struct {
	salt  [32]byte
	names map[string]struct{}
}

// NewHeaderRedactor builds a redactor over the base list plus extra names. An
// extra name only increases redaction; there is no way to ask for less.
func NewHeaderRedactor(extra []string) (*HeaderRedactor, error) {
	r := &HeaderRedactor{names: make(map[string]struct{}, len(sensitiveResponseHeaders)+len(extra))}
	for _, name := range sensitiveResponseHeaders {
		r.names[name] = struct{}{}
	}
	for _, name := range extra {
		name = NormalizeHeaderName(name)
		if name == "" {
			return nil, fmt.Errorf("a sensitive header name cannot be empty")
		}
		if !validHeaderName(name) {
			return nil, fmt.Errorf("%q is not an HTTP header name", name)
		}
		r.names[name] = struct{}{}
	}
	if _, err := rand.Read(r.salt[:]); err != nil {
		return nil, fmt.Errorf("cannot generate the redaction salt: %w", err)
	}
	return r, nil
}

// Sensitive reports whether a response header's value must be withheld.
func (r *HeaderRedactor) Sensitive(name string) bool {
	if r == nil {
		return false
	}
	_, ok := r.names[NormalizeHeaderName(name)]
	return ok
}

// Entry builds the C-01 header entry for one name/value pair. A sensitive value
// never enters the entry: only the marker and the salted digest do.
func (r *HeaderRedactor) Entry(name, value string) HeaderEntry {
	if !r.Sensitive(name) {
		return HeaderEntry{Name: name, Value: value, Digest: NewDigest([]byte(value))}
	}
	return HeaderEntry{
		Name: name, Value: RedactedValueMarker, Digest: r.digest(name, value), Redacted: true,
	}
}

// digest is sha256(salt || lower(name) || 0x00 || value). The separator keeps a
// name and a value that happen to concatenate alike from colliding.
func (r *HeaderRedactor) digest(name, value string) string {
	lower := NormalizeHeaderName(name)
	material := make([]byte, 0, len(r.salt)+len(lower)+1+len(value))
	material = append(material, r.salt[:]...)
	material = append(material, lower...)
	material = append(material, 0)
	material = append(material, value...)
	return NewDigest(material)
}

// Names returns the effective policy, ordered, without the salt.
func (r *HeaderRedactor) Names() []string {
	if r == nil {
		return nil
	}
	out := make([]string, 0, len(r.names))
	for name := range r.names {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// NormalizeHeaderName folds a header name to the form the policy compares in.
func NormalizeHeaderName(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

func validHeaderName(name string) bool {
	for _, r := range name {
		if r <= ' ' || r == ':' || r == 0x7f {
			return false
		}
	}
	return true
}
