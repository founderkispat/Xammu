package labctl

import (
	"fmt"
	"sort"
	"strings"

	"xammu/internal/contracts"
)

// The laboratory and the contract do not share a vocabulary, and the difference is
// not cosmetic: the fixture names a transport after where the bytes sit in the
// request it parses (query_string, json_body), while C-02 names it after where the
// probe was placed (query, body_json). A finding that carried the fixture's words
// would be unreadable next to a finding from any other target, and a mapping done
// by eye at report time is a rename waiting to happen. So the table is here, in
// both directions, and it is checked against the contract's own vocabulary by
// TestBridgeCoversEveryFixtureName.

// fixtureVectors maps the laboratory's transport names to C-02's.
//
// The uninspected-vector names are the fixture's own accounting labels -- the
// strings its coverage document writes for a value it buffered but never read. They
// bridge to the transport they describe, because that is the transport a finding
// can then state it did not measure.
var fixtureVectors = map[string]contracts.Vector{
	"query_string":             contracts.VectorQuery,
	"json_body":                contracts.VectorBodyJSON,
	"form_body":                contracts.VectorBodyForm,
	"multipart_body":           contracts.VectorMultipart,
	"path":                     contracts.VectorPath,
	"header":                   contracts.VectorHeader,
	"header_value_uninspected": contracts.VectorHeader,
	"cookie":                   contracts.VectorCookie,
	"cookie_name_unscanned":    contracts.VectorCookie,
	"cookie_value_uninspected": contracts.VectorCookie,
	"body_not_parsed":          contracts.VectorBodyJSON,
}

// fixtureEncodings maps the laboratory's decoding-depth names to C-03's.
//
// The fixture only ever performs one percent-decode pass, so its names describe how
// many passes a value would need to collapse: single_encoded needs one, double needs
// two. The contract's names are the encoding the probe was authored in, which is the
// same thing stated from the probe's side rather than the engine's.
var fixtureEncodings = map[string]contracts.Encoding{
	"canonical":      contracts.EncodingCanonical,
	"plain":          contracts.EncodingCanonical,
	"single_encoded": contracts.EncodingURLSingle,
	"url_single":     contracts.EncodingURLSingle,
	"double_encoded": contracts.EncodingURLDouble,
	"url_double":     contracts.EncodingURLDouble,
	"case_variant":   contracts.EncodingCaseVariant,
	"mixed_case":     contracts.EncodingCaseVariant,
	"html_entity":    contracts.EncodingHTMLEntity,
	"whitespace":     contracts.EncodingWhitespaceVar,
}

// Vocabulary returns the bridge as declared by the manifest, merged over the
// built-in table so a laboratory build can name a transport the shipped table has
// not caught up with without anyone editing code to read its own fixture.
func (m *Manifest) Vocabulary() map[string]string {
	out := make(map[string]string, len(fixtureVectors)+len(fixtureEncodings)+len(m.Vocab))
	for k, v := range fixtureVectors {
		out[k] = string(v)
	}
	for k, v := range fixtureEncodings {
		out[k] = string(v)
	}
	for k, v := range m.Vocab {
		out[k] = v
	}
	return out
}

// Vector translates one of the laboratory's transport names into C-02's. An
// unmapped name is an error rather than a passthrough: a transport that quietly
// keeps the fixture's spelling in a finding would be invisible to whoever compares
// two runs, which is the one thing a vocabulary is supposed to prevent.
func (m *Manifest) Vector(fixture string) (contracts.Vector, error) {
	fixture = strings.ToLower(strings.TrimSpace(fixture))
	if m != nil {
		if v, ok := m.Vocab[fixture]; ok {
			return contracts.Vector(v), nil
		}
	}
	if v, ok := fixtureVectors[fixture]; ok {
		return v, nil
	}
	return "", fmt.Errorf("fixture transport %q has no mapping into the C-02 vocabulary; %s declares "+
		"the pairs this build understands", fixture, ManifestFile)
}

// Encoding translates one of the laboratory's decoding names into C-03's, with the
// same refusal rule as Vector.
func (m *Manifest) Encoding(fixture string) (contracts.Encoding, error) {
	fixture = strings.ToLower(strings.TrimSpace(fixture))
	if m != nil {
		if v, ok := m.Vocab[fixture]; ok {
			return contracts.Encoding(v), nil
		}
	}
	if v, ok := fixtureEncodings[fixture]; ok {
		return v, nil
	}
	return "", fmt.Errorf("fixture encoding %q has no mapping into the C-03 vocabulary", fixture)
}

// FixtureNamesForVector lists the laboratory names that bridge to one contract
// vector, sorted, so a reader of a finding can see which fixture rows it came from.
func FixtureNamesForVector(v contracts.Vector) []string {
	var out []string
	for k, got := range fixtureVectors {
		if got == v {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}
