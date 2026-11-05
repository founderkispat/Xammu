package fingerprint

import (
	"strings"
	"testing"

	"xammu/internal/contracts"
)

func header(name, value string) contracts.HeaderEntry {
	return contracts.HeaderEntry{Name: name, Value: value}
}

func TestAttributeLabFromHeadersAndMarkedPage(t *testing.T) {
	ev := Attribute([]contracts.HeaderEntry{
		header("Server", "xammu-lab-waf/1.0"),
		header("X-Lab-Waf-Action", "reject"),
	}, []byte("<html>XAMMU-LAB-WAF-BLOCK</html>"))
	if len(ev) != 3 {
		t.Fatalf("expected three lab signatures, got %d: %+v", len(ev), ev)
	}
	for _, e := range ev {
		if e.Vendor != "xammu-lab-waf" {
			t.Fatalf("unexpected vendor %q", e.Vendor)
		}
		if strings.Contains(e.Detail, "xammu-lab-waf/1.0") {
			t.Fatal("the header value leaked into the evidence detail")
		}
	}
}

func TestAttributeReferenceFixtureFromHeadersAndMarkedPage(t *testing.T) {
	ev := Attribute([]contracts.HeaderEntry{
		header("Server", "xammu-reference-waf/1.0"),
		header("X-Xammu-Reference-Action", "reject"),
	}, []byte("<html>XAMMU-REFERENCE-WAF-BLOCK</html>"))
	if len(ev) != 3 {
		t.Fatalf("expected three reference signatures, got %d: %+v", len(ev), ev)
	}
	for _, e := range ev {
		if e.Vendor != "xammu-reference-waf" {
			t.Fatalf("unexpected vendor %q", e.Vendor)
		}
	}
	if stacks, basis := CandidateStacks("xammu-reference-waf"); len(stacks) == 0 || basis == "" {
		t.Fatalf("the reference fixture must receive a measured candidate: %+v %q", stacks, basis)
	}
}

func TestAttributeIsCaseInsensitiveOnHeaderValues(t *testing.T) {
	ev := Attribute([]contracts.HeaderEntry{header("SERVER", "XAMMU-LAB-WAF/1.0")}, nil)
	if len(ev) != 1 || ev[0].Signature != "lab-server" {
		t.Fatalf("header matching must ignore case: %+v", ev)
	}
}

func TestAttributeCookieKeepsOnlyTheName(t *testing.T) {
	ev := Attribute([]contracts.HeaderEntry{
		header("Set-Cookie", "incap_ses_1234_5678=secretvalue; Path=/; HttpOnly"),
	}, nil)
	if len(ev) != 1 || ev[0].Vendor != "imperva" || ev[0].Kind != KindCookie {
		t.Fatalf("cookie signature not matched: %+v", ev)
	}
	if strings.Contains(ev[0].Detail, "secretvalue") {
		t.Fatal("cookie value leaked into evidence")
	}
}

func TestAttributeNoEvidence(t *testing.T) {
	ev := Attribute([]contracts.HeaderEntry{header("Server", "nginx")}, []byte("ok"))
	if len(ev) != 0 {
		t.Fatalf("a generic server header must not attribute a vendor: %+v", ev)
	}
}

func TestAggregateHighNeedsTwoKindsAndAnIdentifyingSignature(t *testing.T) {
	lab := Observation{Conclusive: true, Evidence: Attribute([]contracts.HeaderEntry{
		header("Server", "xammu-lab-waf/1.0"),
		header("X-Lab-Waf-Action", "reject"),
	}, []byte("XAMMU-LAB-WAF-BLOCK"))}
	s := Aggregate([]Observation{lab, lab})
	if len(s.Vendors) != 1 {
		t.Fatalf("expected one vendor, got %+v", s.Vendors)
	}
	f := s.Vendors[0]
	if f.Support != SupportHigh {
		t.Fatalf("confidence = %s, want high", f.Support)
	}
	if f.Cases != 2 {
		t.Fatalf("cases = %d, want 2", f.Cases)
	}
	if s.Observed != 2 || s.WithEvidence != 2 {
		t.Fatalf("observed/with evidence = %d/%d", s.Observed, s.WithEvidence)
	}
	if len(f.RecommendedStacks) == 0 || len(f.RecommendedStacks[0].Stack) == 0 {
		t.Fatal("the laboratory finding must carry candidate stacks")
	}
	for _, r := range f.RecommendedStacks {
		if len(r.Stack) > 3 {
			t.Fatalf("a candidate stack exceeds the depth limit: %v", r.Stack)
		}
	}
}

func TestAggregateMediumWithOneKind(t *testing.T) {
	ev := Attribute([]contracts.HeaderEntry{header("cf-ray", "abc123")}, nil)
	s := Aggregate([]Observation{{Conclusive: true, Evidence: ev}})
	if len(s.Vendors) != 1 || s.Vendors[0].Vendor != "cloudflare" {
		t.Fatalf("unexpected vendors %+v", s.Vendors)
	}
	if s.Vendors[0].Support != SupportMedium {
		t.Fatalf("confidence = %s, want medium", s.Vendors[0].Support)
	}
}

func TestAggregateLowWithSupportingOnly(t *testing.T) {
	ev := Attribute([]contracts.HeaderEntry{header("x-sucuri-cache", "HIT")}, nil)
	s := Aggregate([]Observation{{Conclusive: true, Evidence: ev}})
	if s.Vendors[0].Support != SupportLow {
		t.Fatalf("confidence = %s, want low", s.Vendors[0].Support)
	}
}

func TestAggregateLowWhenOnlyExcludedOutcomesCarryEvidence(t *testing.T) {
	ev := Attribute([]contracts.HeaderEntry{header("cf-ray", "abc")}, nil)
	s := Aggregate([]Observation{{Conclusive: false, Evidence: ev}})
	if s.Vendors[0].Support != SupportLow {
		t.Fatalf("evidence only in excluded outcomes must stay low, got %s", s.Vendors[0].Support)
	}
	if s.Vendors[0].Cases != 0 {
		t.Fatalf("cases = %d, want 0 conclusive", s.Vendors[0].Cases)
	}
}

func TestAggregateUnknown(t *testing.T) {
	s := Aggregate([]Observation{{Conclusive: true}})
	if len(s.Vendors) != 1 || s.Vendors[0].Vendor != "unknown" ||
		s.Vendors[0].Support != SupportNone {
		t.Fatalf("unexpected summary %+v", s)
	}
	if len(s.Vendors[0].RecommendedStacks) != 0 {
		t.Fatal("an unknown vendor must not receive a stack")
	}
}

func TestAggregateTwoVendorsAreNotCollapsed(t *testing.T) {
	a := Attribute([]contracts.HeaderEntry{header("cf-ray", "abc")}, nil)
	b := Attribute([]contracts.HeaderEntry{header("x-sucuri-id", "xyz")}, nil)
	s := Aggregate([]Observation{{Conclusive: true, Evidence: append(a, b...)}})
	if len(s.Vendors) != 2 {
		t.Fatalf("expected two vendors, got %+v", s.Vendors)
	}
	if s.WithEvidence != 1 {
		t.Fatalf("one outcome with two vendors must count once, got %d", s.WithEvidence)
	}
}

func TestCandidateStacksAreBounded(t *testing.T) {
	for _, vendor := range []string{"xammu-lab-waf", "cloudflare", "unknown"} {
		recs, basis := CandidateStacks(vendor)
		if basis == "" {
			t.Errorf("%s: recommendation basis is empty", vendor)
		}
		for _, r := range recs {
			if len(r.Stack) == 0 || len(r.Stack) > 3 {
				t.Errorf("%s: stack %v is outside 1..3", vendor, r.Stack)
			}
			for _, prim := range r.Stack {
				if !contracts.TamperKnown(prim) {
					t.Errorf("%s: unknown primitive %q", vendor, prim)
				}
			}
			if !strings.Contains(strings.ToLower(r.Basis), "measured") &&
				!strings.Contains(strings.ToLower(r.Basis), "candidate") {
				t.Errorf("%s: basis does not label the stack as a candidate: %q", vendor, r.Basis)
			}
		}
	}
}
