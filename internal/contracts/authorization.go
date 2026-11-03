package contracts

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// Environment says what kind of system the authorization covers. Production
// profile runs require the stricter fields the validator checks for.
type Environment string

const (
	EnvLab           Environment = "laboratory"
	EnvStaging       Environment = "staging"
	EnvProduction    Environment = "production"
	EnvDocumentation Environment = "documentation_only"
)

func AllEnvironments() []Environment {
	return []Environment{EnvLab, EnvStaging, EnvProduction, EnvDocumentation}
}

// Origin is one authorized endpoint family. The resolved address constraints
// are what make JAVI-020 testable: a host name alone lets a redirect or a
// rebinding walk the run outside the agreement.
type Origin struct {
	Scheme          string   `json:"scheme"`
	Host            string   `json:"host"`
	Port            int      `json:"port"`
	PathPrefixes    []string `json:"path_prefixes"`
	AllowedIPs      []string `json:"allowed_ips,omitempty"`
	AllowedCIDRs    []string `json:"allowed_cidrs,omitempty"`
	AllowRedirectTo []string `json:"allow_redirect_to,omitempty"`
}

// OperationalLimits are the hard stops a run may not exceed. They are part of
// the authorization, not of the tool's defaults, so an operator cannot forget
// them into existence.
type OperationalLimits struct {
	MaxRequests        int `json:"max_requests"`
	RatePerSecond      int `json:"rate_per_second"`
	MaxRedirects       int `json:"max_redirects"`
	TimeoutMS          int `json:"timeout_ms"`
	MaxConcurrent      int `json:"max_concurrent"`
	MaxBodyRetainBytes int `json:"max_body_retain_bytes"`
	RoundCooldownMS    int `json:"round_cooldown_ms"`
}

// ProfilingAuthorization is C-09. It is approved per execution and per target:
// an authorization file that is valid forever, for any host, is not an
// authorization.
type ProfilingAuthorization struct {
	AuthorizationID      string            `json:"authorization_id"`
	Ref                  string            `json:"ref"`
	IssuedAt             time.Time         `json:"issued_at"`
	ExpiresAt            time.Time         `json:"expires_at"`
	Issuer               string            `json:"issuer"`
	ApprovedBy           string            `json:"approved_by"`
	Environment          Environment       `json:"environment"`
	Origins              []Origin          `json:"origins"`
	ExcludedPaths        []string          `json:"excluded_paths,omitempty"`
	Methods              []string          `json:"methods"`
	Limits               OperationalLimits `json:"limits"`
	Retention            RetentionPolicy   `json:"retention_policy"`
	AllowedClasses       []AttackClass     `json:"allowed_attack_classes"`
	AllowedVectors       []Vector          `json:"allowed_vectors"`
	AllowedEncodings     []Encoding        `json:"allowed_encodings"`
	CorpusPartitions     []string          `json:"corpus_partitions"`
	StatementOfScope     string            `json:"statement_of_scope"`
	RulesOfEngagement    []string          `json:"rules_of_engagement"`
	ContactForHalt       string            `json:"contact_for_halt"`
	IssuerKeyFingerprint string            `json:"issuer_key_fingerprint"`
	Notes                []string          `json:"notes,omitempty"`
}

func (ProfilingAuthorization) Contract() ID { return IDProfilingAuthorization }

// ValidationAuthorization is C-10: a narrow, immutable permission for one
// hypothesis against one bound target. The httpclient verifies it before every
// single request, not once per run.
type ValidationAuthorization struct {
	ValidationID       string    `json:"validation_id"`
	ParentAuthRef      string    `json:"parent_authorization_ref"`
	HypothesisRef      string    `json:"hypothesis_ref"`
	RunID              string    `json:"run_id"`
	Origin             Origin    `json:"bound_origin"`
	AllowedProbes      []string  `json:"allowed_probe_refs"`
	MaxRequests        int       `json:"max_requests"`
	RatePerSecond      int       `json:"rate_per_second"`
	NotBefore          time.Time `json:"not_before"`
	ExpiresAt          time.Time `json:"expires_at"`
	ApprovedBy         string    `json:"approved_by"`
	IssuedAt           time.Time `json:"issued_at"`
	ImmutabilityDigest string    `json:"immutability_digest"`
	RoundBudget        int       `json:"round_budget"`
	StopOn             []string  `json:"stop_on"`
}

func (ValidationAuthorization) Contract() ID { return IDValidationAuthorization }

func registerAuthorizationContracts() {
	register(IDProfilingAuthorization, func(payload any) error {
		a, err := cast[ProfilingAuthorization](IDProfilingAuthorization, payload)
		if err != nil {
			return err
		}
		c := newViolations(IDProfilingAuthorization)
		uuidField(c, "authorization_id", a.AuthorizationID)
		c.required("ref", a.Ref)
		c.required("issuer", a.Issuer)
		c.required("approved_by", a.ApprovedBy)
		oneofT(c, "environment", a.Environment, AllEnvironments()...)
		oneofT(c, "retention_policy", a.Retention, AllRetentionPolicies()...)
		c.nonEmpty("origins", len(a.Origins))
		for _, o := range a.Origins {
			c.oneof("origins[].scheme", o.Scheme, "https", "http")
			c.required("origins[].host", o.Host)
			c.nonNegative("origins[].port", o.Port)
			c.nonEmpty("origins[].path_prefixes", len(o.PathPrefixes))
			if len(o.AllowedIPs) == 0 && len(o.AllowedCIDRs) == 0 {
				c.add("origins[].allowed_cidrs",
					"an origin without resolved-address bounds cannot satisfy JAVI-020")
			}
			// An entry that does not parse is a permission this tool cannot honour: the
			// egress check matches the resolved address against networks, so a malformed
			// entry matches nothing and every request to this origin is refused - after
			// the run has been authorised to spend them. Saying so here costs the operator
			// an edit instead of a budget.
			for _, cidr := range o.AllowedCIDRs {
				if _, _, err := net.ParseCIDR(strings.TrimSpace(cidr)); err != nil {
					c.add("origins[].allowed_cidrs", fmt.Sprintf(
						"%q on origin %s is not a network in CIDR notation: a single address belongs in "+
							"allowed_ips, and an entry the egress check cannot parse authorises nothing",
						cidr, o.Host))
				}
			}
			for _, literal := range o.AllowedIPs {
				if net.ParseIP(strings.TrimSpace(literal)) == nil {
					c.add("origins[].allowed_ips", fmt.Sprintf(
						"%q on origin %s is neither an IPv4 nor an IPv6 address", literal, o.Host))
				}
			}
		}
		c.nonEmpty("methods", len(a.Methods))
		c.nonEmpty("allowed_attack_classes", len(a.AllowedClasses))
		for _, cl := range a.AllowedClasses {
			oneofT(c, "allowed_attack_classes[]", cl, AllAttackClasses()...)
		}
		c.nonEmpty("allowed_vectors", len(a.AllowedVectors))
		for _, v := range a.AllowedVectors {
			oneofT(c, "allowed_vectors[]", v, AllVectors()...)
		}
		for _, e := range a.AllowedEncodings {
			oneofT(c, "allowed_encodings[]", e, AllEncodings()...)
		}
		c.nonEmpty("corpus_partitions", len(a.CorpusPartitions))
		c.required("statement_of_scope", a.StatementOfScope)
		c.nonEmpty("rules_of_engagement", len(a.RulesOfEngagement))
		c.required("contact_for_halt", a.ContactForHalt)
		c.required("issuer_key_fingerprint", a.IssuerKeyFingerprint)
		if a.IssuedAt.IsZero() {
			c.add("issued_at", "required")
		}
		if a.ExpiresAt.IsZero() {
			c.add("expires_at", "an authorization must expire")
		} else if !a.ExpiresAt.After(a.IssuedAt) {
			c.add("expires_at", "must be after issued_at")
		}
		if a.Limits.MaxRequests <= 0 {
			c.add("limits.max_requests", "must be positive")
		}
		if a.Limits.RatePerSecond <= 0 {
			c.add("limits.rate_per_second", "must be positive")
		}
		if a.Limits.TimeoutMS <= 0 {
			c.add("limits.timeout_ms", "must be positive")
		}
		if a.Limits.MaxConcurrent <= 0 {
			c.add("limits.max_concurrent", "must be positive")
		}
		if a.Limits.MaxRedirects < 0 {
			c.add("limits.max_redirects", "must be >= 0")
		}
		if a.Environment == EnvProduction && a.Retention != RetainNone && a.Retention != RetainDigestOnly {
			c.add("retention_policy", "production runs may not retain response bodies")
		}
		return c.err()
	})

	register(IDValidationAuthorization, func(payload any) error {
		v, err := cast[ValidationAuthorization](IDValidationAuthorization, payload)
		if err != nil {
			return err
		}
		c := newViolations(IDValidationAuthorization)
		uuidField(c, "validation_id", v.ValidationID)
		c.required("parent_authorization_ref", v.ParentAuthRef)
		c.required("hypothesis_ref", v.HypothesisRef)
		c.required("run_id", v.RunID)
		c.oneof("bound_origin.scheme", v.Origin.Scheme, "https", "http")
		c.required("bound_origin.host", v.Origin.Host)
		if len(v.Origin.AllowedIPs) == 0 && len(v.Origin.AllowedCIDRs) == 0 {
			c.add("bound_origin.allowed_cidrs", "the bound target must constrain resolved addresses")
		}
		c.nonEmpty("allowed_probe_refs", len(v.AllowedProbes))
		if v.MaxRequests <= 0 {
			c.add("max_requests", "must be positive")
		}
		if v.RatePerSecond <= 0 {
			c.add("rate_per_second", "must be positive")
		}
		if v.NotBefore.IsZero() {
			c.add("not_before", "required")
		}
		if v.ExpiresAt.IsZero() || !v.ExpiresAt.After(v.NotBefore) {
			c.add("expires_at", "must be after not_before")
		}
		c.required("approved_by", v.ApprovedBy)
		if v.IssuedAt.IsZero() {
			c.add("issued_at", "required")
		}
		c.nonEmpty("stop_on", len(v.StopOn))
		for _, s := range v.StopOn {
			c.oneof("stop_on[]", s, "rate_limited", "budget_exhausted", "transport_failure",
				"control_invalid", "operator_halt")
		}
		// Immutability: the digest must be present so verification can detect a
		// field edited after approval.
		digestField(c, "immutability_digest", v.ImmutabilityDigest)
		return c.err()
	})
}

func init() { registerAuthorizationContracts() }
