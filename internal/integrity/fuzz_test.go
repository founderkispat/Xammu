package integrity

import (
	"encoding/json"
	"testing"
)

// FuzzParseManifest exercises the decoder a reviewer's bundle goes through. A
// manifest arrives from disk, from a delivery envelope or from someone else's
// machine, so malformed JSON must be an error and an accepted manifest must
// survive a round trip instead of leaving the rest of the pipeline with a value
// it cannot serialize.
func FuzzParseManifest(f *testing.F) {
	f.Add([]byte(`{"manifest_id":"2f1c3d4e-5a6b-4c7d-8e9f-0a1b2c3d4e5f","run_id":"r1",` +
		`"algorithm":"ed25519","files":[],"chain_head":"sha256:00"}`))
	f.Add([]byte(`{"run_id":""}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`{`))
	f.Add([]byte(``))

	f.Fuzz(func(t *testing.T, raw []byte) {
		m, err := ParseManifest(raw)
		if err != nil {
			return
		}
		if _, err := json.Marshal(m); err != nil {
			t.Fatalf("an accepted manifest does not re-serialize: %v", err)
		}
	})
}
