package contracts

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
)

// interpretiveKeys is the denylist for C-01. A raw observation describes a wire
// exchange; if it can carry any of these keys then observation and reading have
// collapsed into one artefact and the pipeline can no longer be audited.
// Matching is on the exact JSON key, so "response_status" is fine and
// "classification" is not.
var interpretiveKeys = map[string]string{
	"blocked":            "response reading",
	"is_blocked":         "response reading",
	"block":              "response reading",
	"block_signal":       "response reading",
	"verdict":            "conclusion",
	"classification":     "downstream product",
	"classified_as":      "downstream product",
	"signal":             "downstream product",
	"signals":            "downstream product",
	"severity":           "invented scale",
	"score":              "numeric scale",
	"confidence":         "numeric scale",
	"risk":               "conclusion",
	"threat":             "conclusion",
	"malicious":          "response reading",
	"exploitable":        "out of scope by design",
	"vulnerable":         "out of scope by design",
	"attribution":        "downstream product",
	"attribution_status": "downstream product",
	"attributed_to":      "downstream product",
	"interpreted":        "downstream product",
	"interpretation":     "downstream product",
	"meaning":            "downstream product",
	"passed":             "verdict",
	"failed":             "verdict",
	"success":            "verdict",
}

// InterpretiveKeyNames lists the denied keys, for docs and for the repo-wide
// invariant test.
func InterpretiveKeyNames() []string {
	out := make([]string, 0, len(interpretiveKeys))
	for k := range interpretiveKeys {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// interpretiveKeysIn walks a value's JSON key space and returns any denied key
// it finds, at any depth. Unknown fields survive a marshal/unmarshal round
// trip in map form, so the store also runs InterpretiveKeysInJSON on ingest.
func interpretiveKeysIn(v any) []string {
	return interpretiveKeysInReflect(reflect.ValueOf(v), "")
}

func interpretiveKeysInReflect(rv reflect.Value, path string) []string {
	for rv.Kind() == reflect.Ptr || rv.Kind() == reflect.Interface {
		if rv.IsNil() {
			return nil
		}
		rv = rv.Elem()
	}
	switch rv.Kind() {
	case reflect.Struct:
		t := rv.Type()
		var hits []string
		for i := 0; i < t.NumField(); i++ {
			key := jsonKeyOf(t.Field(i))
			if key == "" {
				continue
			}
			full := key
			if path != "" {
				full = path + "." + key
			}
			if why, bad := interpretiveKeys[key]; bad {
				hits = append(hits, fmt.Sprintf("%s (%s)", full, why))
			}
			hits = append(hits, interpretiveKeysInReflect(rv.Field(i), full)...)
		}
		return hits
	case reflect.Slice, reflect.Array:
		var hits []string
		for i := 0; i < rv.Len(); i++ {
			hits = append(hits, interpretiveKeysInReflect(rv.Index(i), path)...)
		}
		return hits
	case reflect.Map:
		var hits []string
		iter := rv.MapRange()
		for iter.Next() {
			k, ok := iter.Key().Interface().(string)
			if !ok {
				continue
			}
			full := k
			if path != "" {
				full = path + "." + k
			}
			if why, bad := interpretiveKeys[k]; bad {
				hits = append(hits, fmt.Sprintf("%s (%s)", full, why))
			}
			hits = append(hits, interpretiveKeysInReflect(iter.Value(), full)...)
		}
		return hits
	default:
		return nil
	}
}

func jsonKeyOf(f reflect.StructField) string {
	tag, ok := f.Tag.Lookup("json")
	if !ok {
		return ""
	}
	name := strings.Split(tag, ",")[0]
	if name == "-" {
		return ""
	}
	return name
}

// keysMatching walks a value's JSON key space and returns keys satisfying pred.
// Each contract uses it for its own denylist, so the prohibition is enforced by
// code instead of by review.
func keysMatching(v any, pred func(string) bool) []string {
	return keysMatchingReflect(reflect.ValueOf(v), "", pred)
}

func keysMatchingReflect(rv reflect.Value, path string, pred func(string) bool) []string {
	for rv.Kind() == reflect.Ptr || rv.Kind() == reflect.Interface {
		if rv.IsNil() {
			return nil
		}
		rv = rv.Elem()
	}
	switch rv.Kind() {
	case reflect.Struct:
		t := rv.Type()
		var hits []string
		for i := 0; i < t.NumField(); i++ {
			key := jsonKeyOf(t.Field(i))
			if key == "" {
				continue
			}
			full := key
			if path != "" {
				full = path + "." + key
			}
			if pred(key) {
				hits = append(hits, full)
			}
			hits = append(hits, keysMatchingReflect(rv.Field(i), full, pred)...)
		}
		return hits
	case reflect.Slice, reflect.Array:
		var hits []string
		for i := 0; i < rv.Len(); i++ {
			hits = append(hits, keysMatchingReflect(rv.Index(i), path, pred)...)
		}
		return hits
	case reflect.Map:
		var hits []string
		iter := rv.MapRange()
		for iter.Next() {
			k, ok := iter.Key().Interface().(string)
			if !ok {
				continue
			}
			full := k
			if path != "" {
				full = path + "." + k
			}
			if pred(k) {
				hits = append(hits, full)
			}
			hits = append(hits, keysMatchingReflect(iter.Value(), full, pred)...)
		}
		return hits
	default:
		return nil
	}
}

// InterpretiveKeysInJSON scans decoded JSON (map form) for denied keys. The
// append-only store runs it on ingest so that an unknown field added by a
// future producer cannot bypass the struct-level denylist.
func InterpretiveKeysInJSON(node any) []string {
	return keysMatchingJSON(node, "", func(k string) bool {
		if _, bad := interpretiveKeys[k]; bad {
			return true
		}
		for _, bad := range ForbiddenJSONKeys {
			if k == bad {
				return true
			}
		}
		return false
	})
}

func keysMatchingJSON(node any, path string, pred func(string) bool) []string {
	switch v := node.(type) {
	case map[string]any:
		var hits []string
		for k, child := range v {
			full := k
			if path != "" {
				full = path + "." + k
			}
			if pred(k) {
				hits = append(hits, full)
			}
			hits = append(hits, keysMatchingJSON(child, full, pred)...)
		}
		sort.Strings(hits)
		return hits
	case []any:
		var hits []string
		for _, child := range v {
			hits = append(hits, keysMatchingJSON(child, path, pred)...)
		}
		return hits
	default:
		return nil
	}
}

// ForbiddenSymbols are identifiers that must not exist anywhere in v1.0.0,
// because they would reintroduce a numeric confidence scale (JAVI-021, Javi Q6).
var ForbiddenSymbols = []string{
	"attribution_confidence",
	"AttributionConfidence",
	"confidence_score",
	"confidenceScore",
	"severity_score",
	"severityScore",
	"risk_score",
	"riskScore",
	"score",
	"confirmed",
}

// ForbiddenJSONKeys are keys rejected on ingest of any stored contract, in
// addition to the C-01 denylist: they would smuggle a scale into a payload
// whose Go type does not declare one.
var ForbiddenJSONKeys = []string{
	"attribution_confidence",
	"confidence",
	"confidence_score",
	"score",
	"severity",
	"severity_score",
	"risk_score",
	"percent_confidence",
}

// ForbiddenJSONKeyNames returns the repo-wide forbidden key list.
func ForbiddenJSONKeyNames() []string {
	out := make([]string, len(ForbiddenJSONKeys))
	copy(out, ForbiddenJSONKeys)
	sort.Strings(out)
	return out
}

func init() {
	// The denylist and the C-01 type must stay in agreement: a field added to
	// RawObservation that reads the response has to be caught here, at init,
	// rather than in a report nobody reads.
	var probe RawObservation
	typ := reflect.TypeOf(probe)
	seen := map[string]bool{}
	collectKeys(typ, seen)
	for key := range seen {
		if _, bad := interpretiveKeys[key]; bad {
			panic(fmt.Sprintf("contracts: RawObservation declares interpretive field %q", key))
		}
	}
}

func collectKeys(t reflect.Type, into map[string]bool) {
	switch t.Kind() {
	case reflect.Struct:
		for i := 0; i < t.NumField(); i++ {
			key := jsonKeyOf(t.Field(i))
			if key == "" {
				continue
			}
			into[key] = true
			collectKeys(t.Field(i).Type, into)
		}
	case reflect.Ptr, reflect.Slice, reflect.Array:
		collectKeys(t.Elem(), into)
	case reflect.Map:
		collectKeys(t.Elem(), into)
	}
}
