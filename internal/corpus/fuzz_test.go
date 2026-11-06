package corpus

import (
	"encoding/json"
	"testing"

	"xammu/internal/contracts"
)

// FuzzParseItem feeds arbitrary bytes to the C-13 line decoder. Corpus files are
// authored by hand and read from a directory a reviewer can edit, so a malformed
// line must be an error, never a panic, and an accepted line must hold the digest
// its probe derives: the pair cannot disagree without the loader noticing.
func FuzzParseItem(f *testing.F) {
	f.Add([]byte(`{"item_id":"76aa4ee3-d83f-40de-8270-6f9a9ff9de07","ref":"DEV-CMD-P-01",` +
		`"group_id":"G-DEV-CMD-P","attack_class":"command_injection","vector":"path",` +
		`"encoding":"canonical","canonical_form":"; xammu-probe ;","probe":"; xammu-probe ;",` +
		`"purpose":"coverage_diagnosis","expected_behavior":"expect_block"}`))
	f.Add([]byte(`{"probe":"; xammu-probe ;","probe_digest":"sha256:0000"}`))
	f.Add([]byte(`{"probe":"\u0000\u0001"}`))
	f.Add([]byte(`{`))
	f.Add([]byte(``))

	f.Fuzz(func(t *testing.T, raw []byte) {
		item, err := parseItem(raw)
		if err != nil {
			return
		}
		if item == nil {
			t.Fatalf("parseItem returned neither an item nor an error for %q", raw)
		}
		want := contracts.NewDigest([]byte(item.Probe))
		if item.ProbeDigest != want {
			t.Fatalf("accepted probe_digest %q, probe derives %q", item.ProbeDigest, want)
		}
		if _, err := json.Marshal(item); err != nil {
			t.Fatalf("an accepted item does not re-serialize: %v", err)
		}
	})
}
