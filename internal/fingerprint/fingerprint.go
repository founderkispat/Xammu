package fingerprint

import (
	"bytes"
	"sort"
	"strings"

	"xammu/internal/contracts"
)

// Evidence is one signature match, attributed at capture time. Vendor, Kind and
// Strength travel with the record so aggregation does not depend on a later
// revision of the signature table.
type Evidence struct {
	Vendor    string   `json:"vendor"`
	Signature string   `json:"signature"`
	Kind      Kind     `json:"kind"`
	Strength  Strength `json:"strength"`
	Detail    string   `json:"detail"`
}

// Observation is one outcome's evidence, with whether the outcome was
// conclusive. Evidence seen only in excluded outcomes cannot raise a finding
// above low.
type Observation struct {
	Evidence   []Evidence
	Conclusive bool
}

// Support is the categorical strength of an attribution. It is named support
// rather than confidence because the repository forbids the confidence key: it
// is reserved for a numeric scale, and this is a closed vocabulary over evidence
// kinds, not a probability.
type Support string

const (
	SupportHigh   Support = "high"
	SupportMedium Support = "medium"
	SupportLow    Support = "low"
	SupportNone   Support = "none"
)

// Recommendation is a candidate stack to measure, with its basis.
type Recommendation struct {
	Stack []contracts.Tamper `json:"stack"`
	Basis string             `json:"basis"`
}

// Finding is one identified vendor.
type Finding struct {
	Vendor              string           `json:"vendor"`
	Support             Support          `json:"support"`
	Evidence            []Evidence       `json:"evidence"`
	Cases               int              `json:"cases"`
	RecommendedStacks   []Recommendation `json:"recommended_stacks,omitempty"`
	RecommendationBasis string           `json:"recommendation_basis,omitempty"`
}

// Summary is the fingerprint section of E-03.
type Summary struct {
	Policy       string    `json:"policy"`
	Observed     int       `json:"observed_outcomes"`
	WithEvidence int       `json:"outcomes_with_evidence"`
	Vendors      []Finding `json:"vendors"`
}

// Attribute matches the shipped signatures against one response. The body is
// read here and then dropped by the caller; only the redacted Detail is
// returned.
func Attribute(headers []contracts.HeaderEntry, body []byte) []Evidence {
	byName := map[string][]string{}
	for _, h := range headers {
		name := strings.ToLower(strings.TrimSpace(h.Name))
		if name == "" {
			continue
		}
		byName[name] = append(byName[name], h.Value)
	}
	cookies := cookieNames(byName["set-cookie"])
	lowerBody := bytes.ToLower(body)

	seen := map[string]bool{}
	var out []Evidence
	for _, sig := range signatures {
		if !matches(sig, byName, cookies, lowerBody) {
			continue
		}
		if seen[sig.ID] {
			continue
		}
		seen[sig.ID] = true
		out = append(out, Evidence{
			Vendor: sig.Vendor, Signature: sig.ID, Kind: sig.Kind,
			Strength: sig.Strength, Detail: sig.Detail,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Vendor != out[j].Vendor {
			return out[i].Vendor < out[j].Vendor
		}
		return out[i].Signature < out[j].Signature
	})
	return out
}

func matches(sig signature, headers map[string][]string, cookies []string, body []byte) bool {
	switch sig.Kind {
	case KindHeader:
		values, ok := headers[strings.ToLower(sig.Header)]
		if !ok {
			return false
		}
		if sig.ValueContains == "" {
			return true
		}
		for _, v := range values {
			if strings.Contains(strings.ToLower(v), strings.ToLower(sig.ValueContains)) {
				return true
			}
		}
		return false
	case KindCookie:
		for _, name := range cookies {
			if strings.HasPrefix(name, strings.ToLower(sig.CookieNamePrefix)) {
				return true
			}
		}
		return false
	case KindErrorPage:
		return bytes.Contains(body, []byte(strings.ToLower(sig.BodyContains)))
	default:
		return false
	}
}

func cookieNames(setCookies []string) []string {
	var names []string
	for _, raw := range setCookies {
		first := strings.SplitN(raw, ";", 2)[0]
		name := strings.TrimSpace(strings.SplitN(first, "=", 2)[0])
		if name != "" {
			names = append(names, strings.ToLower(name))
		}
	}
	return names
}

// Aggregate counts the evidence of every outcome into a vendor list. The
// confidence rule is arithmetic over the stored fields:
//
//   - high: at least two evidence kinds in conclusive outcomes and at least one
//     identifying signature;
//   - medium: exactly one kind in conclusive outcomes and at least one
//     identifying signature;
//   - low: signatures exist but only supporting ones, or only in excluded
//     outcomes;
//   - none: no signature matched, reported as vendor "unknown".
func Aggregate(observations []Observation) Summary {
	type bucket struct {
		evidence    map[string]Evidence
		kinds       map[Kind]bool
		identifying bool
		conclusive  int
		excluded    int
	}
	buckets := map[string]*bucket{}
	withEvidence := map[int]bool{}
	for i, o := range observations {
		if len(o.Evidence) > 0 {
			withEvidence[i] = true
		}
		perVendor := map[string]*bucket{}
		for _, e := range o.Evidence {
			b, ok := buckets[e.Vendor]
			if !ok {
				b = &bucket{evidence: map[string]Evidence{}, kinds: map[Kind]bool{}}
				buckets[e.Vendor] = b
			}
			perVendor[e.Vendor] = b
			b.evidence[e.Signature] = e
			if o.Conclusive {
				b.kinds[e.Kind] = true
				if e.Strength == StrengthIdentifying {
					b.identifying = true
				}
			}
		}
		for _, b := range perVendor {
			if o.Conclusive {
				b.conclusive++
			} else {
				b.excluded++
			}
		}
	}

	s := Summary{Policy: Policy, Observed: len(observations), WithEvidence: len(withEvidence)}
	names := make([]string, 0, len(buckets))
	for name := range buckets {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		b := buckets[name]
		f := Finding{Vendor: name, Cases: b.conclusive}
		f.Evidence = make([]Evidence, 0, len(b.evidence))
		for _, e := range b.evidence {
			f.Evidence = append(f.Evidence, e)
		}
		sort.Slice(f.Evidence, func(i, j int) bool {
			if f.Evidence[i].Kind != f.Evidence[j].Kind {
				return f.Evidence[i].Kind < f.Evidence[j].Kind
			}
			return f.Evidence[i].Signature < f.Evidence[j].Signature
		})
		switch {
		case b.conclusive > 0 && len(b.kinds) >= 2 && b.identifying:
			f.Support = SupportHigh
		case b.conclusive > 0 && len(b.kinds) == 1 && b.identifying:
			f.Support = SupportMedium
		default:
			f.Support = SupportLow
		}
		f.RecommendedStacks, f.RecommendationBasis = CandidateStacks(name)
		s.Vendors = append(s.Vendors, f)
	}
	if len(s.Vendors) == 0 {
		f := Finding{Vendor: "unknown", Support: SupportNone}
		f.RecommendationBasis = "no vendor signature matched; no automatic stack is offered"
		s.Vendors = []Finding{f}
	}
	sort.Slice(s.Vendors, func(i, j int) bool {
		ri, rj := supportRank(s.Vendors[i].Support), supportRank(s.Vendors[j].Support)
		if ri != rj {
			return ri < rj
		}
		return s.Vendors[i].Vendor < s.Vendors[j].Vendor
	})
	return s
}

func supportRank(c Support) int {
	switch c {
	case SupportHigh:
		return 0
	case SupportMedium:
		return 1
	case SupportLow:
		return 2
	default:
		return 3
	}
}
