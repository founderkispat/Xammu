package gate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// The schema is a document, not a dependency: nothing in the build validates
// against it. That makes drift easy to miss, so the suite compares the schema to
// the struct that produces the bytes and to the bytes themselves.

type gateSchema struct {
	Schema     string                     `json:"$schema"`
	ID         string                     `json:"$id"`
	Required   []string                   `json:"required"`
	Properties map[string]json.RawMessage `json:"properties"`
	Defs       map[string]json.RawMessage `json:"$defs"`
}

func readGateSchema(t *testing.T) gateSchema {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "schemas", "xammu-gate-v1.schema.json"))
	if err != nil {
		t.Fatalf("reading the published schema: %v", err)
	}
	var schema gateSchema
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("the published schema must be JSON: %v", err)
	}
	return schema
}

func TestSchemaParsesAndNamesTheDocument(t *testing.T) {
	schema := readGateSchema(t)
	if schema.Schema != "https://json-schema.org/draft/2020-12/schema" {
		t.Fatalf("$schema = %q", schema.Schema)
	}
	if schema.ID == "" {
		t.Fatal("the schema has no $id")
	}
	if len(schema.Defs) == 0 {
		t.Fatal("the schema defines no reusable shapes")
	}
	for _, def := range strings.Fields(`source policy check control counts rates latency class arm
		comparison fingerprint metrics ratio finding effectivenessPolicy findingsPolicy`) {
		if _, ok := schema.Defs[def]; !ok {
			t.Errorf("$defs is missing %q", def)
		}
	}
}

func TestSchemaDeclaresExactlyTheDocumentFields(t *testing.T) {
	schema := readGateSchema(t)
	want := documentFieldNames()
	got := sortedKeys(schema.Properties)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("schema properties and Document disagree:\nschema: %v\ndocument: %v", got, want)
	}
	required := append([]string(nil), schema.Required...)
	sort.Strings(required)
	if strings.Join(required, ",") != strings.Join(want, ",") {
		t.Fatalf("every top-level field is required, so a reader never has to guess at\n"+
			"an absent value:\nrequired: %v\ndocument: %v", required, want)
	}
}

func TestPublishedDocumentOnlyCarriesDeclaredFields(t *testing.T) {
	ev := loadEvidence(t, effectivenessBundle, nil)
	e := evaluate(t, ev, effectivenessPolicyFailTPR)
	raw, err := JSON(e.Document)
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	var published map[string]json.RawMessage
	if err := json.Unmarshal(raw, &published); err != nil {
		t.Fatalf("the rendered document must be a JSON object: %v", err)
	}
	schema := readGateSchema(t)
	for key := range published {
		if _, ok := schema.Properties[key]; !ok {
			t.Errorf("the document publishes %q, which the schema does not declare", key)
		}
	}
	for _, key := range schema.Required {
		if _, ok := published[key]; !ok {
			t.Errorf("the document omits the required field %q", key)
		}
	}
}

func TestPolicySchemaParsesAndDeclaresBothSections(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "schemas", "xammu-policy-v1.schema.json"))
	if err != nil {
		t.Fatalf("reading the published policy schema: %v", err)
	}
	var schema struct {
		Schema     string                     `json:"$schema"`
		Properties map[string]json.RawMessage `json:"properties"`
		Defs       map[string]json.RawMessage `json:"$defs"`
		AnyOf      []map[string][]string      `json:"anyOf"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("the policy schema must be JSON: %v", err)
	}
	if schema.Schema != "https://json-schema.org/draft/2020-12/schema" {
		t.Fatalf("$schema = %q", schema.Schema)
	}
	for _, key := range []string{"schema_version", "effectiveness", "findings"} {
		if _, ok := schema.Properties[key]; !ok {
			t.Errorf("the policy schema does not declare %q", key)
		}
	}
	if len(schema.AnyOf) != 2 {
		t.Fatalf("anyOf = %v; at least one section must be required", schema.AnyOf)
	}

	// The normalized views the gate publishes are the shapes this file describes;
	// comparing them here is how a field rename reaches the schema instead of
	// silently diverging from it.
	eff, ok := schema.Defs["effectiveness"]
	if !ok {
		t.Fatal("the effectiveness definition is missing")
	}
	var effDef struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(eff, &effDef); err != nil {
		t.Fatalf("effectiveness definition: %v", err)
	}
	wantEff := structFieldNames(reflect.TypeOf(EffectivenessPolicyView{}))
	if got := sortedKeys(effDef.Properties); strings.Join(got, ",") != strings.Join(wantEff, ",") {
		t.Fatalf("effectiveness schema and view disagree:\nschema: %v\nview: %v", got, wantEff)
	}
}

// TestPublicationSchemaDeclaresExactlyTheEnvelope keeps the published shape and
// the signed struct in step. A field the schema does not declare is a field a
// consumer was never told about; a required field the producer can omit is a
// reader guessing at an absent value.
func TestPublicationSchemaDeclaresExactlyTheEnvelope(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "schemas", "xammu-publication-v1.schema.json"))
	if err != nil {
		t.Fatalf("reading the publication schema: %v", err)
	}
	var schema gateSchema
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("the publication schema must be JSON: %v", err)
	}
	if schema.Schema != "https://json-schema.org/draft/2020-12/schema" {
		t.Fatalf("$schema = %q", schema.Schema)
	}
	want := structFieldNames(reflect.TypeOf(Publication{}))
	if got := sortedKeys(schema.Properties); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("schema properties and Publication disagree:\nschema: %v\nenvelope: %v", got, want)
	}
	required := append([]string(nil), schema.Required...)
	sort.Strings(required)
	if strings.Join(required, ",") != strings.Join(want, ",") {
		t.Fatalf("required and Publication disagree:\nrequired: %v\nenvelope: %v", required, want)
	}
	for def, typ := range map[string]reflect.Type{
		"source": reflect.TypeOf(PublicationSource{}),
		"file":   reflect.TypeOf(PublicationFile{}),
	} {
		body, ok := schema.Defs[def]
		if !ok {
			t.Fatalf("$defs is missing %q", def)
		}
		var defSchema struct {
			Properties map[string]json.RawMessage `json:"properties"`
		}
		if err := json.Unmarshal(body, &defSchema); err != nil {
			t.Fatalf("%s definition: %v", def, err)
		}
		got := sortedKeys(defSchema.Properties)
		wantDef := structFieldNames(typ)
		if strings.Join(got, ",") != strings.Join(wantDef, ",") {
			t.Fatalf("%s schema and struct disagree:\nschema: %v\nstruct: %v", def, got, wantDef)
		}
	}
}

func structFieldNames(typ reflect.Type) []string {
	out := make([]string, 0, typ.NumField())
	for i := 0; i < typ.NumField(); i++ {
		name := strings.Split(typ.Field(i).Tag.Get("json"), ",")[0]
		if name != "" && name != "-" {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

func documentFieldNames() []string { return structFieldNames(reflect.TypeOf(Document{})) }

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for key := range m {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}
