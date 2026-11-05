// Package tamper applies stackable representation shifts on top of a case's
// declared encoding. A tamper re-writes the same bytes; it is not a new
// capability, so the inertness gate continues to judge the canonical payload.
//
// The stack is ordered, bounded and closed: one to three primitives from
// contracts.AllTampers, no repetitions, applied left to right. Anything else is
// refused before a request is built rather than approximated at send time.
package tamper

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"unicode/utf8"

	"xammu/internal/contracts"
)

// MaxStackDepth bounds how many representations one value may acquire. Beyond
// three layers the comparison stops describing a WAF normalizer and starts
// describing this tool's own nesting.
const MaxStackDepth = 3

// Stack is an ordered tamper list.
type Stack []contracts.Tamper

// Validate refuses a stack the engine cannot apply exactly as declared.
func (s Stack) Validate() error {
	if len(s) == 0 {
		return errors.New("tamper: an empty stack has nothing to apply")
	}
	if len(s) > MaxStackDepth {
		return fmt.Errorf("tamper: a stack of %d primitives exceeds the limit of %d",
			len(s), MaxStackDepth)
	}
	seen := map[contracts.Tamper]bool{}
	for _, t := range s {
		if !contracts.TamperKnown(t) {
			return fmt.Errorf("tamper: %q is not in the vocabulary; chunked framing is deliberately "+
				"absent because it is request framing, not a value transform", t)
		}
		if seen[t] {
			return fmt.Errorf("tamper: %q appears twice; a repeated primitive measures nesting, not evasion", t)
		}
		seen[t] = true
	}
	return nil
}

// Parse turns an operator list ("url_encode_double,sql_comment") into a stack.
// An empty list means the baseline arm and returns a nil stack without error.
func Parse(list string) (Stack, error) {
	var s Stack
	for _, part := range strings.Split(list, ",") {
		p := strings.TrimSpace(part)
		if p == "" {
			continue
		}
		s = append(s, contracts.Tamper(p))
	}
	if len(s) == 0 {
		return nil, nil
	}
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return s, nil
}

// Apply runs the stack in order. The marker is carried through so case folding
// can leave it untouched; see PreservesMarker for the one primitive that cannot
// keep it inline.
func Apply(value string, s Stack, marker string) (string, error) {
	if err := s.Validate(); err != nil {
		return "", err
	}
	out := value
	for _, t := range s {
		var err error
		out, err = applyOne(out, t, marker)
		if err != nil {
			return "", err
		}
	}
	return out, nil
}

func applyOne(value string, t contracts.Tamper, marker string) (string, error) {
	switch t {
	case contracts.TamperURLEncode:
		return url.QueryEscape(value), nil
	case contracts.TamperURLEncodeDouble:
		return url.QueryEscape(url.QueryEscape(value)), nil
	case contracts.TamperBase64:
		return base64.StdEncoding.EncodeToString([]byte(value)), nil
	case contracts.TamperUnicodeEscape:
		return unicodeEscape(value), nil
	case contracts.TamperCaseSwitch:
		return caseVariant(value, marker), nil
	case contracts.TamperSQLComment:
		return strings.NewReplacer(" ", "/**/", "+", "/**/", "%20", "/**/").Replace(value), nil
	case contracts.TamperWhitespace:
		// A decoded space becomes a tab, and a value that is still encoded gets
		// the encoded tab instead. Both describe the same whitespace variant.
		return strings.NewReplacer(" ", "\t", "+", "%09", "%20", "%09").Replace(value), nil
	case contracts.TamperHTMLEntity:
		return htmlEntity(value), nil
	default:
		return "", fmt.Errorf("tamper: %q has no transform", t)
	}
}

// PreservesMarker reports whether a primitive keeps the diagnostic token inside
// the value. base64 does not: it is available only as a forced stack and the
// trial carries the token in a diagnostic header, recorded in E-02.
func PreservesMarker(t contracts.Tamper) bool {
	return t != contracts.TamperBase64
}

// CarriesMarker reports whether the value still contains the token, ignoring
// case as the inertness gate does.
func CarriesMarker(value, marker string) bool {
	if marker == "" {
		return false
	}
	return strings.Contains(strings.ToLower(value), strings.ToLower(marker))
}

// NeedsMarkerHeader reports whether the stack contains a primitive that erases
// the inline token and therefore needs the diagnostic header to stay
// identifiable in the target's log.
func (s Stack) NeedsMarkerHeader() bool {
	for _, t := range s {
		if !PreservesMarker(t) {
			return true
		}
	}
	return false
}

func unicodeEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '<', '>', '"', '\'', '&':
			fmt.Fprintf(&b, "\\u%04x", r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func htmlEntity(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '<':
			b.WriteString("&lt;")
		case '>':
			b.WriteString("&gt;")
		case '"':
			b.WriteString("&quot;")
		case '\'':
			b.WriteString("&apos;")
		case '&':
			b.WriteString("&amp;")
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// caseVariant alternates letter case outside the marker, which stays exactly as
// authored so the traffic remains identifiable in the target's log.
func caseVariant(s, marker string) string {
	var b strings.Builder
	upper := false
	for i := 0; i < len(s); {
		if marker != "" && strings.HasPrefix(strings.ToLower(s[i:]), strings.ToLower(marker)) {
			b.WriteString(s[i : i+len(marker)])
			i += len(marker)
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r >= 'a' && r <= 'z':
			if upper {
				b.WriteRune(r - 32)
			} else {
				b.WriteRune(r)
			}
			upper = !upper
		case r >= 'A' && r <= 'Z':
			if upper {
				b.WriteRune(r + 32)
			} else {
				b.WriteRune(r)
			}
			upper = !upper
		default:
			b.WriteRune(r)
		}
		i += size
	}
	return b.String()
}
