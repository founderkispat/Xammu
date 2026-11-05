package contracts_test

import (
	"strings"
	"testing"

	"xammu/internal/contracts"
)

// TestHeaderRedactorWithholdsEveryBaseHeader proves the six names the policy
// states are actually withheld, whatever case the server used.
func TestHeaderRedactorWithholdsEveryBaseHeader(t *testing.T) {
	r, err := contracts.NewHeaderRedactor(nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(contracts.SensitiveResponseHeaderNames()); got != 6 {
		t.Fatalf("base policy declares %d names, want 6", got)
	}
	for _, name := range contracts.SensitiveResponseHeaderNames() {
		for _, spelling := range []string{name, strings.ToUpper(name)} {
			entry := r.Entry(spelling, "session=secreto")
			if !entry.Redacted {
				t.Fatalf("%s was not marked redacted: %+v", spelling, entry)
			}
			if entry.Value != contracts.RedactedValueMarker {
				t.Fatalf("%s kept the value %q instead of the marker", spelling, entry.Value)
			}
			if entry.Digest == "" || entry.Digest == contracts.NewDigest([]byte("session=secreto")) {
				t.Fatalf("%s: digest must be salted and present, got %q", spelling, entry.Digest)
			}
		}
	}
}

// TestHeaderRedactorKeepsOrdinaryHeaders proves redaction is targeted: the two
// headers the detectors read stay intact.
func TestHeaderRedactorKeepsOrdinaryHeaders(t *testing.T) {
	r, err := contracts.NewHeaderRedactor(nil)
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]string{
		"Server":       "lab-edge",
		"Content-Type": "application/json",
		"Retry-After":  "2",
	} {
		entry := r.Entry(name, value)
		if entry.Redacted || entry.Value != value {
			t.Fatalf("%s must keep its value, got %+v", name, entry)
		}
		if entry.Digest != contracts.NewDigest([]byte(value)) {
			t.Fatalf("%s: an unredacted digest must be the plain value digest", name)
		}
	}
}

// TestHeaderRedactorExtendsButNeverReduces checks --sensitive-header semantics:
// an extra name is withheld and the base list still applies.
func TestHeaderRedactorExtendsButNeverReduces(t *testing.T) {
	r, err := contracts.NewHeaderRedactor([]string{"X-Custom-Secret"})
	if err != nil {
		t.Fatal(err)
	}
	if !r.Sensitive("x-custom-secret") {
		t.Fatal("an extra name must be sensitive")
	}
	if !r.Sensitive("Set-Cookie") {
		t.Fatal("adding a name must not remove the base list")
	}
	names := r.Names()
	if len(names) != 7 {
		t.Fatalf("effective policy should hold 7 names, got %v", names)
	}
}

// TestHeaderRedactorDigestsCorrelateOnlyWithinARun is the privacy property: the
// same value repeats one digest in one run and cannot be matched across runs.
func TestHeaderRedactorDigestsCorrelateOnlyWithinARun(t *testing.T) {
	first, err := contracts.NewHeaderRedactor(nil)
	if err != nil {
		t.Fatal(err)
	}
	second, err := contracts.NewHeaderRedactor(nil)
	if err != nil {
		t.Fatal(err)
	}
	a := first.Entry("Cookie", "session=secreto")
	b := first.Entry("cookie", "session=secreto")
	if a.Digest != b.Digest {
		t.Fatalf("one run must correlate equal values through case-insensitive names: %q vs %q",
			a.Digest, b.Digest)
	}
	if a.Digest == second.Entry("Cookie", "session=secreto").Digest {
		t.Fatal("two runs must not produce the same digest for one value")
	}
	if a.Digest == first.Entry("Cookie", "session=otro").Digest {
		t.Fatal("different values must produce different digests")
	}
}

func TestHeaderRedactorRejectsUnusableNames(t *testing.T) {
	for _, name := range []string{"", "  ", "bad name", "a:b"} {
		if _, err := contracts.NewHeaderRedactor([]string{name}); err == nil {
			t.Fatalf("%q must be refused as a sensitive header name", name)
		}
	}
}

// TestRawObservationEnforcesTheRedactionClaim makes "redacted" verifiable: the
// marker and a well-formed digest are mandatory, so a withheld value cannot hide
// behind the flag without evidence that it was withheld.
func TestRawObservationEnforcesTheRedactionClaim(t *testing.T) {
	o := contracts.ValidRawObservation()
	o.ResponseHeaders = append(o.ResponseHeaders, contracts.HeaderEntry{
		Name: "Set-Cookie", Value: "session=secreto",
		Digest:   contracts.NewDigest([]byte("session=secreto")),
		Redacted: true,
	})
	expectInvalid(t, contracts.IDRawObservation, o, contracts.RedactedValueMarker)

	o.ResponseHeaders[len(o.ResponseHeaders)-1] = contracts.HeaderEntry{
		Name: "Set-Cookie", Value: contracts.RedactedValueMarker, Redacted: true,
	}
	expectInvalid(t, contracts.IDRawObservation, o, "value_digest")

	// A pre-redaction entry, and a well-formed redacted one, both stay valid.
	o.ResponseHeaders[len(o.ResponseHeaders)-1] = contracts.HeaderEntry{
		Name: "Set-Cookie", Value: "session=secreto",
		Digest: contracts.NewDigest([]byte("session=secreto")),
	}
	mustValid(t, contracts.IDRawObservation, o)

	o.ResponseHeaders[len(o.ResponseHeaders)-1] = contracts.HeaderEntry{
		Name: "Set-Cookie", Value: contracts.RedactedValueMarker,
		Digest: contracts.NewDigest([]byte("salted")), Redacted: true,
	}
	mustValid(t, contracts.IDRawObservation, o)
}
