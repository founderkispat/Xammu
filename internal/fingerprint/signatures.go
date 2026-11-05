// Package fingerprint attributes an observed defensive layer from response
// evidence. It never guesses a product from a generic status: a vendor is named
// only when a signature that belongs to that vendor matched, and the evidence
// that matched is published with the finding.
//
// The table below is deliberately small. Each entry names an observation that is
// public and stable enough to cite; a signature that would attribute a vendor on
// resemblance is not here. The confidence is categorical because a percentage
// would be an invented number: the rule counts evidence kinds, not likelihoods.
package fingerprint

import "xammu/internal/contracts"

// Policy is the version of the attribution and confidence rule. It is recorded
// in E-03 so a reader can see which rule produced a finding.
const Policy = "xammu-waf-fingerprint/1.0.0"

// VendorReferenceFixture is the vendor the repository's own Phase 3 fixture
// identifies as. It is named here so a reader that reports on its numbers can
// say what they do and do not demonstrate.
const VendorReferenceFixture = "xammu-reference-waf"

// Kind is what produced one piece of evidence.
type Kind string

const (
	KindHeader    Kind = "header"
	KindCookie    Kind = "cookie"
	KindErrorPage Kind = "error_page"
	KindBehavior  Kind = "behavior"
)

// Strength separates a signature that belongs to one vendor from one that only
// narrows the field.
type Strength string

const (
	StrengthIdentifying Strength = "identifying"
	StrengthSupporting  Strength = "supporting"
)

// signature is one observable marker. Header and cookie values are read to
// decide the match and then discarded; only Detail is ever stored.
type signature struct {
	ID               string
	Vendor           string
	Kind             Kind
	Strength         Strength
	Header           string
	ValueContains    string
	CookieNamePrefix string
	BodyContains     string
	Detail           string
}

// signatures is the shipped table. The laboratory entry is exact because the
// laboratory is ours; the vendor entries are public response markers and do not
// claim any bypass capability.
var signatures = []signature{
	{
		ID: "lab-server", Vendor: "xammu-lab-waf", Kind: KindHeader,
		Strength: StrengthIdentifying, Header: "server", ValueContains: "xammu-lab-waf",
		Detail: "header:server",
	},
	{
		ID: "lab-action", Vendor: "xammu-lab-waf", Kind: KindHeader,
		Strength: StrengthIdentifying, Header: "x-lab-waf-action", ValueContains: "reject",
		Detail: "header:x-lab-waf-action",
	},
	{
		ID: "lab-block-marker", Vendor: "xammu-lab-waf", Kind: KindErrorPage,
		Strength: StrengthIdentifying, BodyContains: "XAMMU-LAB-WAF-BLOCK",
		Detail: "error_page:lab-block-marker",
	},
	{
		ID: "reference-server", Vendor: VendorReferenceFixture, Kind: KindHeader,
		Strength: StrengthIdentifying, Header: "server", ValueContains: "xammu-reference-waf",
		Detail: "header:server",
	},
	{
		ID: "reference-action", Vendor: VendorReferenceFixture, Kind: KindHeader,
		Strength: StrengthIdentifying, Header: "x-xammu-reference-action", ValueContains: "reject",
		Detail: "header:x-xammu-reference-action",
	},
	{
		ID: "reference-block-marker", Vendor: VendorReferenceFixture, Kind: KindErrorPage,
		Strength: StrengthIdentifying, BodyContains: "XAMMU-REFERENCE-WAF-BLOCK",
		Detail: "error_page:reference-block-marker",
	},
	{
		ID: "cloudflare-ray", Vendor: "cloudflare", Kind: KindHeader,
		Strength: StrengthIdentifying, Header: "cf-ray",
		Detail: "header:cf-ray",
	},
	{
		ID: "sucuri-id", Vendor: "sucuri", Kind: KindHeader,
		Strength: StrengthIdentifying, Header: "x-sucuri-id",
		Detail: "header:x-sucuri-id",
	},
	{
		ID: "sucuri-cache", Vendor: "sucuri", Kind: KindHeader,
		Strength: StrengthSupporting, Header: "x-sucuri-cache",
		Detail: "header:x-sucuri-cache",
	},
	{
		ID: "imperva-incap", Vendor: "imperva", Kind: KindCookie,
		Strength: StrengthIdentifying, CookieNamePrefix: "incap_ses_",
		Detail: "cookie:incap_ses_*",
	},
	{
		ID: "imperva-iinfo", Vendor: "imperva", Kind: KindHeader,
		Strength: StrengthSupporting, Header: "x-iinfo",
		Detail: "header:x-iinfo",
	},
	{
		ID: "modsecurity-credit", Vendor: "modsecurity", Kind: KindErrorPage,
		Strength: StrengthIdentifying, BodyContains: "ModSecurity",
		Detail: "error_page:modsecurity-credit",
	},
	{
		ID: "akamai-grn", Vendor: "akamai", Kind: KindHeader,
		Strength: StrengthSupporting, Header: "akamai-grn",
		Detail: "header:akamai-grn",
	},
	{
		ID: "akamai-transformed", Vendor: "akamai", Kind: KindHeader,
		Strength: StrengthSupporting, Header: "x-akamai-transformed",
		Detail: "header:x-akamai-transformed",
	},
}

// SignatureBasis returns the published explanation for a signature id. The
// report cites it; it is prose, not a score.
func SignatureBasis(id string) string {
	switch id {
	case "lab-server", "lab-action", "lab-block-marker":
		return "the laboratory WAF sets this marker itself; see lab/waf/proxy.go"
	case "reference-server", "reference-action", "reference-block-marker":
		return "the repository's reference fixture sets this marker itself; see examples/reference-waf"
	case "cloudflare-ray":
		return "cf-ray is Cloudflare's documented request identifier"
	case "sucuri-id", "sucuri-cache":
		return "Sucuri documents these response headers for its proxy"
	case "imperva-incap", "imperva-iinfo":
		return "Imperva sets the incap_ses cookie and x-iinfo header on protected sites"
	case "modsecurity-credit":
		return "ModSecurity error pages credit the engine by name"
	case "akamai-grn", "akamai-transformed":
		return "Akamai edge responses use these diagnostic headers"
	default:
		return "signature basis is not documented"
	}
}

// Vendors returns the vendors the shipped table can name, in table order. It is
// what `effectiveness tampers` lists: a vendor absent here can never be
// attributed, so offering it a stack would be an invented recommendation.
func Vendors() []string {
	seen := map[string]bool{}
	var out []string
	for _, sig := range signatures {
		if seen[sig.Vendor] {
			continue
		}
		seen[sig.Vendor] = true
		out = append(out, sig.Vendor)
	}
	return out
}

// CandidateStacks returns the stacks the report offers for a vendor. Only the
// laboratory has a stack tailored to knowledge we actually hold; every other
// vendor gets the generic representation-shifting candidate. Neither is a claim
// that the stack bypasses anything: a run measures it.
func CandidateStacks(vendor string) ([]Recommendation, string) {
	switch vendor {
	case "xammu-lab-waf":
		return []Recommendation{
			{Stack: []contracts.Tamper{contracts.TamperURLEncodeDouble, contracts.TamperSQLComment},
				Basis: "laboratory rules match literal signatures; measured candidate, not asserted bypass"},
			{Stack: []contracts.Tamper{contracts.TamperCaseSwitch, contracts.TamperWhitespace},
				Basis: "laboratory rules are case-sensitive in places; measured candidate, not asserted bypass"},
		}, "tailored to the laboratory fixture, whose rules are visible in this repository"
	case "unknown", "":
		return nil, "no vendor signature matched; no automatic stack is offered"
	default:
		return []Recommendation{
			{Stack: []contracts.Tamper{contracts.TamperURLEncodeDouble, contracts.TamperCaseSwitch},
				Basis: "generic representation-shifting candidate; no vendor-specific bypass knowledge is asserted"},
		}, "generic candidate only: no cited vendor-specific technique is available"
	}
}
