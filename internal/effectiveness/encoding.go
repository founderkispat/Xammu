package effectiveness

import (
	"fmt"
	"net/url"
	"strings"
	"unicode/utf8"

	"xammu/internal/contracts"
)

// Transform applies the case's declared encoding to its canonical payload. The
// transport then applies its own escaping, which is the point: a case declared
// url_single arrives at the target still percent-encoded after the layer that
// decodes a query string once, and that is the documented bypass shape the
// laboratory models.
//
// Nothing here adds capability to a payload. Encoding changes how a string is
// written, not what it can do, which is why the gate judges the canonical form.
func Transform(payload string, enc contracts.Encoding) (string, error) {
	switch enc {
	case contracts.EncodingCanonical:
		return payload, nil
	case contracts.EncodingURLSingle:
		return url.QueryEscape(payload), nil
	case contracts.EncodingURLDouble:
		return url.QueryEscape(url.QueryEscape(payload)), nil
	case contracts.EncodingHTMLEntity:
		return htmlEntity(payload, true), nil
	case contracts.EncodingHTMLEntityNum:
		return htmlEntity(payload, false), nil
	case contracts.EncodingUnicodeEscape:
		return unicodeEscape(payload), nil
	case contracts.EncodingCaseVariant:
		return caseVariant(payload), nil
	case contracts.EncodingCommentInsert:
		return strings.ReplaceAll(payload, " ", "/**/"), nil
	case contracts.EncodingWhitespaceVar:
		return strings.ReplaceAll(payload, " ", "\t"), nil
	case contracts.EncodingMixedNested:
		return url.QueryEscape(htmlEntity(payload, false)), nil
	default:
		return "", fmt.Errorf("effectiveness: encoding %q has no transform", enc)
	}
}

func htmlEntity(s string, named bool) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '<':
			b.WriteString(entity("lt", "60", named))
		case '>':
			b.WriteString(entity("gt", "62", named))
		case '"':
			b.WriteString(entity("quot", "34", named))
		case '\'':
			b.WriteString(entity("apos", "39", named))
		case '&':
			b.WriteString(entity("amp", "38", named))
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func entity(name, number string, named bool) string {
	if named {
		return "&" + name + ";"
	}
	return "&#" + number + ";"
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

// caseVariant alternates the case of letters outside the marker. The marker
// token is left exactly as authored so the traffic stays identifiable as
// diagnostic in the target's log, while a case-sensitive signature elsewhere in
// the payload is what the variant is meant to miss.
func caseVariant(s string) string {
	const marker = "xammu-probe"
	var b strings.Builder
	upper := false
	for i := 0; i < len(s); {
		if strings.HasPrefix(strings.ToLower(s[i:]), marker) {
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
