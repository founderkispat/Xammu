// Package effectiveness measures how a WAF's observed decisions agree with the
// declarative labels of an attack corpus and a benign corpus. It is not an
// exploit engine: every attack case passes the same inertness gate as a
// diagnostic probe before it can be planned, and a benign case is ordinary
// traffic by construction.
//
// The three record kinds are journals rather than registered contracts:
//
//   - Case (E-01)      one corpus case, its label, its OWASP reference and the
//     gate verdict that admitted it;
//   - Outcome (E-02)   what one case produced on the wire: status, verdict,
//     latency, security headers and WAF fingerprint;
//   - Metrics (E-03)   the derived confusion matrix, rates and latency
//     percentiles.
//
// They live in their own streams so C-12 does not acquire a new contract id and
// every bundle written before Phase 1 still verifies.
package effectiveness

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"xammu/internal/contracts"
)

// Kind separates the two populations a confusion matrix needs.
type Kind string

const (
	KindAttack Kind = "attack"
	KindBenign Kind = "benign"
)

// Expectation is the corpus label the observation is compared against.
type Expectation string

const (
	ExpectBlocked Expectation = "blocked"
	ExpectAllowed Expectation = "allowed"
)

// Verdict is what the evidence says happened to one case.
type Verdict string

const (
	VerdictBlocked  Verdict = "blocked"
	VerdictAllowed  Verdict = "allowed"
	VerdictExcluded Verdict = "excluded"
)

// benignClasses is the benign corpus vocabulary. It is deliberately separate
// from contracts.AllAttackClasses: a legitimate request is not an attack class,
// and pretending otherwise would let a benign case be counted as an attack.
var benignClasses = []string{
	"benign_text", "benign_json", "benign_form", "benign_query",
	"benign_header", "benign_cookie", "benign_path",
}

// AllBenignClasses returns the benign class vocabulary in display order.
func AllBenignClasses() []string { return append([]string(nil), benignClasses...) }

func benignClassKnown(s string) bool {
	for _, c := range benignClasses {
		if c == s {
			return true
		}
	}
	return false
}

// GateRecord is the inertness verdict that admitted a case. It is copied into
// E-01 so a reviewer can see which rule set judged the payload.
type GateRecord struct {
	Version  string   `json:"version"`
	Verdict  string   `json:"verdict"`
	RuleHits []string `json:"rule_hits,omitempty"`
}

// Case is E-01: one corpus case exactly as it will be sent. PayloadDigest is
// derived from Payload, never trusted from the file.
type Case struct {
	ID            string             `json:"id"`
	Kind          Kind               `json:"kind"`
	Class         string             `json:"class"`
	Payload       string             `json:"payload"`
	PayloadDigest string             `json:"payload_digest"`
	Vector        contracts.Vector   `json:"vector"`
	Encoding      contracts.Encoding `json:"encoding"`
	Parameter     string             `json:"parameter"`
	Method        string             `json:"method"`
	Path          string             `json:"path"`
	Expect        Expectation        `json:"expect"`
	OWASP         string             `json:"owasp,omitempty"`
	Provenance    string             `json:"provenance,omitempty"`
	Rationale     string             `json:"rationale"`
	Gate          GateRecord         `json:"gate"`
}

// Normalize fills the defaults a corpus file may omit and derives the values
// that are never read from disk.
func (c *Case) Normalize() {
	c.Kind = Kind(strings.ToLower(strings.TrimSpace(string(c.Kind))))
	c.Class = strings.ToLower(strings.TrimSpace(c.Class))
	c.Vector = contracts.Vector(strings.ToLower(strings.TrimSpace(string(c.Vector))))
	c.Encoding = contracts.Encoding(strings.ToLower(strings.TrimSpace(string(c.Encoding))))
	c.Expect = Expectation(strings.ToLower(strings.TrimSpace(string(c.Expect))))
	c.Method = strings.ToUpper(strings.TrimSpace(c.Method))
	if c.Vector == "" {
		c.Vector = contracts.VectorQuery
	}
	if c.Encoding == "" {
		c.Encoding = contracts.EncodingCanonical
	}
	if c.Method == "" {
		switch c.Vector {
		case contracts.VectorBodyJSON, contracts.VectorBodyForm:
			c.Method = "POST"
		default:
			c.Method = "GET"
		}
	}
	if c.Path == "" {
		c.Path = "/api/search"
	}
	if c.Parameter == "" {
		switch c.Vector {
		case contracts.VectorQuery, contracts.VectorBodyJSON, contracts.VectorBodyForm:
			c.Parameter = "q"
		case contracts.VectorHeader:
			c.Parameter = "X-Xammu-Probe"
		case contracts.VectorCookie:
			c.Parameter = "xammu-probe"
		}
	}
	if c.Expect == "" {
		if c.Kind == KindAttack {
			c.Expect = ExpectBlocked
		} else {
			c.Expect = ExpectAllowed
		}
	}
	if c.Payload != "" {
		c.PayloadDigest = contracts.NewDigest([]byte(c.Payload))
	}
}

// Validate rejects a case whose meaning is ambiguous. It runs before the gate so
// a malformed case never reaches the payload checks.
func (c *Case) Validate() error {
	c.Normalize()
	if c.ID == "" {
		return errors.New("effectiveness: a case needs an id")
	}
	switch c.Kind {
	case KindAttack, KindBenign:
	default:
		return fmt.Errorf("effectiveness: case %s has kind %q; want attack or benign", c.ID, c.Kind)
	}
	if c.Payload == "" {
		return fmt.Errorf("effectiveness: case %s has an empty payload", c.ID)
	}
	if c.Kind == KindAttack {
		if !containsClass(contracts.AllAttackClasses(), contracts.AttackClass(c.Class)) {
			return fmt.Errorf("effectiveness: case %s names attack class %q outside the C-09 vocabulary",
				c.ID, c.Class)
		}
		if c.Expect != ExpectBlocked {
			return fmt.Errorf("effectiveness: attack case %s must expect blocked, not %q", c.ID, c.Expect)
		}
		if c.OWASP == "" {
			return fmt.Errorf("effectiveness: attack case %s needs an OWASP reference; a severity score "+
				"would be an invented number and is not accepted", c.ID)
		}
	} else {
		if !benignClassKnown(c.Class) {
			return fmt.Errorf("effectiveness: benign case %s names class %q outside (%s)",
				c.ID, c.Class, strings.Join(benignClasses, ", "))
		}
		if c.Expect != ExpectAllowed {
			return fmt.Errorf("effectiveness: benign case %s must expect allowed, not %q", c.ID, c.Expect)
		}
	}
	if !containsVector(c.Vector) {
		return fmt.Errorf("effectiveness: case %s names vector %q outside the C-09 vocabulary", c.ID, c.Vector)
	}
	if !containsEncoding(c.Encoding) {
		return fmt.Errorf("effectiveness: case %s names encoding %q outside the C-09 vocabulary", c.ID, c.Encoding)
	}
	if c.Method != "GET" && c.Method != "POST" {
		return fmt.Errorf("effectiveness: case %s names method %s; this corpus sends GET or POST", c.ID, c.Method)
	}
	if !strings.HasPrefix(c.Path, "/") || strings.Contains(c.Path, "..") {
		return fmt.Errorf("effectiveness: case %s names path %q; it must be absolute and free of traversal",
			c.ID, c.Path)
	}
	if c.Rationale == "" {
		return fmt.Errorf("effectiveness: case %s needs a rationale stating what shape it tests", c.ID)
	}
	if c.Vector == contracts.VectorHeader && !validToken(c.Parameter) {
		return fmt.Errorf("effectiveness: case %s names header %q, which is not a valid header name",
			c.ID, c.Parameter)
	}
	if c.Vector == contracts.VectorCookie && !validToken(c.Parameter) {
		return fmt.Errorf("effectiveness: case %s names cookie %q, which is not a valid cookie name",
			c.ID, c.Parameter)
	}
	if c.Kind == KindBenign && c.Class == "benign_text" && c.Provenance == "" {
		return fmt.Errorf("effectiveness: benign text case %s needs provenance naming author, work and year",
			c.ID)
	}
	return nil
}

func containsClass(all []contracts.AttackClass, want contracts.AttackClass) bool {
	for _, c := range all {
		if c == want {
			return true
		}
	}
	return false
}

func containsVector(want contracts.Vector) bool {
	for _, v := range contracts.AllVectors() {
		if v == want {
			return true
		}
	}
	return false
}

func containsEncoding(want contracts.Encoding) bool {
	for _, e := range contracts.AllEncodings() {
		if e == want {
			return true
		}
	}
	return false
}

// validToken accepts an RFC 7230 token, the shape both a header name and a
// cookie name have to be before net/http will put it on a wire.
func validToken(s string) bool {
	if s == "" {
		return false
	}
	const separators = "()<>@,;:\\\"/[]?={} \t"
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c <= 0x20 && c != 0x09 || c >= 0x7f || strings.ContainsRune(separators, rune(c)) {
			return false
		}
	}
	return true
}

// CorpusDigest commits to the exact case list, so a re-derivation can say
// whether it is reading the corpus the run used rather than a later revision.
func CorpusDigest(cases []Case) string {
	var b strings.Builder
	for _, c := range cases {
		b.WriteString(c.ID)
		b.WriteString("\x00")
		b.WriteString(c.PayloadDigest)
		b.WriteString("\x00")
		b.WriteString(string(c.Kind))
		b.WriteString("\x00")
		b.WriteString(c.Class)
		b.WriteString("\n")
	}
	return contracts.NewDigest([]byte(b.String()))
}

// OriginPath joins an authorized origin and a case path without allowing the
// case to supply its own origin.
func OriginPath(origin, path string) (string, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("effectiveness: origin %q is not an absolute URL", origin)
	}
	if !strings.HasPrefix(path, "/") {
		return "", fmt.Errorf("effectiveness: path %q is not absolute", path)
	}
	u.Path = path
	u.RawQuery = ""
	u.Fragment = ""
	return u.String(), nil
}
