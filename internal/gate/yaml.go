package gate

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

// YAML renders the same document as the JSON writer. It exists because GitLab,
// Azure Pipelines and Jenkins consume YAML, and because the repository ships no
// external dependency: the writer emits exactly the subset internal/yamlish
// documents, and the test parses the result back with that parser.
//
// The subset has no representation for an empty collection, so a key whose value
// is an empty map or list is omitted. The JSON keeps it: there a reader can tell
// "no findings" from "field absent". That difference is the only structural
// departure, and it is stated rather than hidden.
func YAML(doc *Document) ([]byte, error) {
	raw, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	var tree any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&tree); err != nil {
		return nil, err
	}
	root, ok := tree.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("gate: the document root is not a mapping")
	}
	var b strings.Builder
	if err := emitMap(&b, root, 0); err != nil {
		return nil, err
	}
	return []byte(b.String()), nil
}

func emitMap(b *strings.Builder, m map[string]any, indent int) error {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	pad := strings.Repeat(" ", indent)
	for _, k := range keys {
		v := m[k]
		if isEmptyCollection(v) {
			continue
		}
		switch typed := v.(type) {
		case map[string]any:
			b.WriteString(pad + yamlText(k) + ":\n")
			if err := emitMap(b, typed, indent+2); err != nil {
				return err
			}
		case []any:
			b.WriteString(pad + yamlText(k) + ":\n")
			if err := emitList(b, typed, indent+2); err != nil {
				return err
			}
		default:
			scalar, err := yamlScalar(v)
			if err != nil {
				return fmt.Errorf("gate: key %q: %v", k, err)
			}
			b.WriteString(pad + yamlText(k) + ": " + scalar + "\n")
		}
	}
	return nil
}

func emitList(b *strings.Builder, list []any, indent int) error {
	pad := strings.Repeat(" ", indent)
	for _, item := range list {
		switch item.(type) {
		case map[string]any, []any:
			// yamlish refuses a sequence item that carries a mapping. The gate
			// document indexes objects by id instead of listing them, so this is a
			// programming error, not an evidence condition.
			return fmt.Errorf("gate: the YAML subset cannot carry a sequence of collections")
		}
		scalar, err := yamlScalar(item)
		if err != nil {
			return err
		}
		b.WriteString(pad + "- " + scalar + "\n")
	}
	return nil
}

func yamlScalar(v any) (string, error) {
	switch typed := v.(type) {
	case nil:
		return "null", nil
	case string:
		return yamlText(typed), nil
	case json.Number:
		return typed.String(), nil
	case bool:
		if typed {
			return "true", nil
		}
		return "false", nil
	}
	return "", fmt.Errorf("unsupported scalar %T", v)
}

// isEmptyCollection reports whether a value has no YAML representation in the
// subset. A map whose every child is empty is itself empty, so pruning is
// recursive.
func isEmptyCollection(v any) bool {
	switch typed := v.(type) {
	case map[string]any:
		for _, child := range typed {
			if !isEmptyCollection(child) {
				return false
			}
		}
		return true
	case []any:
		return len(typed) == 0
	}
	return false
}

// yamlText quotes a string only when the plain form would be ambiguous or
// outside the subset's plain-scalar grammar.
func yamlText(s string) string {
	if plainSafe(s) {
		return s
	}
	return strconv.Quote(s)
}

func plainSafe(s string) bool {
	if s == "" {
		return false
	}
	switch strings.ToLower(s) {
	case "null", "~", "true", "false", "yes", "no", "on", "off":
		return false
	}
	for i, r := range s {
		if i == 0 {
			if r != '_' && !unicode.IsLetter(r) {
				return false
			}
			continue
		}
		if r == '_' || r == '.' || r == '-' || r == '/' ||
			unicode.IsLetter(r) || unicode.IsDigit(r) {
			continue
		}
		return false
	}
	return true
}
