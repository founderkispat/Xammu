// Package yamlish parses the small YAML subset the effectiveness corpus is
// written in. The standard library has no YAML decoder and XAMMU ships with zero
// external Go dependencies, so the subset is defined here instead of pulling a
// parser into the build.
//
// Supported, on purpose:
//
//   - documents separated by a line containing exactly "---";
//   - mappings ("key: value") nested by two-space indentation;
//   - sequences of scalars ("- value");
//   - plain, single-quoted and double-quoted scalars;
//   - comments introduced by "#" outside quotes.
//
// Refused, because a corpus file that uses them would be parsed by a different
// implementation than the one this package documents:
//
//   - anchors and aliases (&, *), tags (!), flow collections ({}, []), tabs;
//   - block scalars ("|" and ">"), because their blank-line and comment rules
//     would need a second parser to be exact;
//   - duplicate keys;
//   - a sequence item that carries a mapping.
//
// A refusal is a load error. The parser never guesses at a construct it does not
// implement: an effectiveness case that cannot be read exactly must be rewritten,
// not approximated.
package yamlish

import (
	"fmt"
	"strconv"
	"strings"
)

// Document is one parsed YAML document.
type Document struct {
	// Root is a map[string]any, []any or scalar. The corpus decoder requires a
	// mapping at the root.
	Root any
	// Line is the first line of the document in the source file, for diagnostics.
	Line int
}

// Parse returns every document in src.
func Parse(src []byte) ([]Document, error) {
	lines, err := lex(string(src))
	if err != nil {
		return nil, err
	}
	var docs []Document
	start := 0
	for i := 0; i <= len(lines); i++ {
		atEnd := i == len(lines)
		if !atEnd && !lines[i].separator {
			continue
		}
		if i > start {
			root, next, err := parseBlock(lines, start, lines[start].indent)
			if err != nil {
				return nil, err
			}
			if next != i {
				return nil, fmt.Errorf("line %d: unexpected content after the document", lines[next].number)
			}
			docs = append(docs, Document{Root: root, Line: lines[start].number})
			start = i + 1
			continue
		}
		start = i + 1
	}
	if len(docs) == 0 {
		return nil, fmt.Errorf("the stream holds no documents")
	}
	return docs, nil
}

type line struct {
	number    int
	indent    int
	text      string // line content without indentation; comments are stripped when it is consumed
	separator bool
}

func lex(src string) ([]line, error) {
	raw := strings.Split(strings.ReplaceAll(src, "\r\n", "\n"), "\n")
	var out []line
	for i, original := range raw {
		number := i + 1
		if strings.ContainsRune(original, '\t') {
			return nil, fmt.Errorf("line %d: tab characters are not supported; use spaces", number)
		}
		trimmed := strings.TrimLeft(original, " ")
		indent := len(original) - len(trimmed)
		if indent%2 != 0 {
			return nil, fmt.Errorf("line %d: indentation is %d spaces; this subset uses two-space steps",
				number, indent)
		}
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if trimmed == "---" || trimmed == "..." {
			out = append(out, line{number: number, separator: true})
			continue
		}
		stripped, err := stripComment(trimmed, number)
		if err != nil {
			return nil, err
		}
		if strings.HasSuffix(stripped, ": |") || strings.HasSuffix(stripped, ": |-") ||
			strings.HasSuffix(stripped, ": >") || strings.HasSuffix(stripped, ": >-") {
			return nil, fmt.Errorf("line %d: block scalars are not supported; write the value on one line "+
				"or as a quoted scalar", number)
		}
		out = append(out, line{number: number, indent: indent, text: strings.TrimRight(trimmed, " ")})
	}
	return out, nil
}

// stripComment removes a trailing comment. A "#" only starts a comment when it
// is at the start of the value or preceded by whitespace, which is what keeps a
// payload such as "a#b" intact.
func stripComment(s string, number int) (string, error) {
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch quote {
		case '\'':
			if c == '\'' {
				if i+1 < len(s) && s[i+1] == '\'' {
					i++
					continue
				}
				quote = 0
			}
		case '"':
			if c == '\\' {
				i++
				continue
			}
			if c == '"' {
				quote = 0
			}
		default:
			switch c {
			case '\'', '"':
				quote = c
			case '#':
				if i == 0 || s[i-1] == ' ' {
					return strings.TrimRight(s[:i], " "), nil
				}
			}
		}
	}
	if quote != 0 {
		return "", fmt.Errorf("line %d: unterminated %q string", number, quote)
	}
	return strings.TrimRight(s, " "), nil
}

func content(l line) (string, error) {
	return stripComment(l.text, l.number)
}

func parseBlock(lines []line, i, indent int) (any, int, error) {
	if i >= len(lines) {
		return nil, i, fmt.Errorf("unexpected end of document")
	}
	if lines[i].indent != indent {
		return nil, i, fmt.Errorf("line %d: expected %d spaces of indentation, got %d",
			lines[i].number, indent, lines[i].indent)
	}
	text, err := content(lines[i])
	if err != nil {
		return nil, i, err
	}
	if strings.HasPrefix(text, "- ") || text == "-" {
		return parseSequence(lines, i, indent)
	}
	return parseMapping(lines, i, indent)
}

func parseSequence(lines []line, i, indent int) (any, int, error) {
	out := []any{}
	for i < len(lines) && !lines[i].separator && lines[i].indent == indent {
		text, err := content(lines[i])
		if err != nil {
			return nil, i, err
		}
		if !strings.HasPrefix(text, "-") {
			break
		}
		item := strings.TrimSpace(strings.TrimPrefix(text, "-"))
		if item == "" {
			return nil, i, fmt.Errorf("line %d: an empty sequence item is not supported", lines[i].number)
		}
		if strings.Contains(item, ": ") || strings.HasSuffix(item, ":") {
			return nil, i, fmt.Errorf("line %d: sequence items are scalars in this subset; "+
				"a nested mapping must be written as its own document field", lines[i].number)
		}
		v, err := scalar(item, lines[i].number)
		if err != nil {
			return nil, i, err
		}
		out = append(out, v)
		i++
	}
	return out, i, nil
}

func parseMapping(lines []line, i, indent int) (any, int, error) {
	out := map[string]any{}
	for i < len(lines) && !lines[i].separator && lines[i].indent == indent {
		text, err := content(lines[i])
		if err != nil {
			return nil, i, err
		}
		if strings.HasPrefix(text, "- ") || text == "-" {
			return nil, i, fmt.Errorf("line %d: a sequence cannot share an indentation level with a mapping",
				lines[i].number)
		}
		key, raw, ok, err := splitKey(text, lines[i].number)
		if err != nil {
			return nil, i, err
		}
		if !ok {
			return nil, i, fmt.Errorf("line %d: expected \"key: value\"", lines[i].number)
		}
		if _, dup := out[key]; dup {
			return nil, i, fmt.Errorf("line %d: duplicate key %q", lines[i].number, key)
		}
		if raw != "" {
			v, err := scalar(raw, lines[i].number)
			if err != nil {
				return nil, i, err
			}
			out[key] = v
			i++
			continue
		}
		// A key with no value opens a nested block. With no more-indented line it
		// is the empty string, which lets an optional field be written as "key:".
		if i+1 >= len(lines) || lines[i+1].separator || lines[i+1].indent <= indent {
			out[key] = ""
			i++
			continue
		}
		if lines[i+1].indent != indent+2 {
			return nil, i, fmt.Errorf("line %d: nested block under %q must be indented %d spaces, got %d",
				lines[i+1].number, key, indent+2, lines[i+1].indent)
		}
		v, next, err := parseBlock(lines, i+1, indent+2)
		if err != nil {
			return nil, i, err
		}
		out[key] = v
		i = next
	}
	return out, i, nil
}

// splitKey finds the first ":" that is followed by a space or the end of the
// line, outside quotes. A value such as "A03:2021-Injection" therefore stays a
// value rather than turning into a nested key.
func splitKey(s string, number int) (key, value string, ok bool, err error) {
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch quote {
		case '\'':
			if c == '\'' {
				if i+1 < len(s) && s[i+1] == '\'' {
					i++
					continue
				}
				quote = 0
			}
		case '"':
			if c == '\\' {
				i++
				continue
			}
			if c == '"' {
				quote = 0
			}
		default:
			switch c {
			case '\'', '"':
				quote = c
			case ':':
				if i+1 == len(s) || s[i+1] == ' ' {
					k, err := scalar(strings.TrimSpace(s[:i]), number)
					if err != nil {
						return "", "", false, err
					}
					ks, isString := k.(string)
					if !isString || ks == "" {
						return "", "", false, fmt.Errorf("line %d: a mapping key must be a non-empty scalar",
							number)
					}
					return ks, strings.TrimSpace(s[i+1:]), true, nil
				}
			}
		}
	}
	return "", "", false, nil
}

func scalar(raw string, number int) (any, error) {
	if raw == "" {
		return "", nil
	}
	switch raw[0] {
	case '\'':
		if len(raw) < 2 || raw[len(raw)-1] != '\'' {
			return nil, fmt.Errorf("line %d: unterminated single-quoted scalar", number)
		}
		return strings.ReplaceAll(raw[1:len(raw)-1], "''", "'"), nil
	case '"':
		if len(raw) < 2 || raw[len(raw)-1] != '"' {
			return nil, fmt.Errorf("line %d: unterminated double-quoted scalar", number)
		}
		v, err := strconv.Unquote(raw)
		if err != nil {
			return nil, fmt.Errorf("line %d: double-quoted scalar: %w", number, err)
		}
		return v, nil
	case '&', '*', '!', '{', '[', '|', '>', '@', '`':
		return nil, fmt.Errorf("line %d: %q starts a YAML construct this subset refuses", number, raw[0])
	}
	return raw, nil
}
