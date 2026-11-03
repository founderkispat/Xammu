package contracts

// The epistemic vocabulary of XAMMU. Every enum here is deliberately symbolic:
// v1.0.0 has no numeric confidence scale, so ordinal strength is expressed by
// an ordered enum whose ceiling rules are enforced in evidence.go.

// ClaimType states how strong a claim is allowed to be. Ordered weakest to
// strongest.
type ClaimType string

const (
	ClaimDescriptive ClaimType = "descriptive"
	ClaimAssociation ClaimType = "association"
	ClaimAttribution ClaimType = "attribution"
	ClaimConfirmed   ClaimType = "confirmed_attribution"
)

func AllClaimTypes() []ClaimType {
	return []ClaimType{ClaimDescriptive, ClaimAssociation, ClaimAttribution, ClaimConfirmed}
}

// EvidenceLevel states how much evidence backs an observation set. Ordered
// weakest to strongest. It is never converted to a number.
type EvidenceLevel string

const (
	EvidenceNone EvidenceLevel = "none"
	// EvidenceSingleObservation is one request/response pair, no control.
	EvidenceSingleObservation EvidenceLevel = "single_observation"
	// EvidenceReplicated is the same shape reproduced inside one run.
	EvidenceReplicated EvidenceLevel = "replicated_within_run"
	// EvidenceReplicatedWithControls adds a valid positive and negative control.
	EvidenceReplicatedWithControls EvidenceLevel = "replicated_with_valid_controls"
	// EvidenceIndependentRounds reproduces across separately authorized rounds.
	EvidenceIndependentRounds EvidenceLevel = "replicated_independent_rounds"
	// EvidenceCorrelatedIndependent adds a source outside the HTTP response
	// (WAF logs, config export) that agrees with the HTTP evidence.
	EvidenceCorrelatedIndependent EvidenceLevel = "correlated_independent_evidence"
)

func AllEvidenceLevels() []EvidenceLevel {
	return []EvidenceLevel{
		EvidenceNone, EvidenceSingleObservation, EvidenceReplicated,
		EvidenceReplicatedWithControls, EvidenceIndependentRounds, EvidenceCorrelatedIndependent,
	}
}

// rank orders evidence levels; used only for ceiling arithmetic, never emitted
// as a score.
func (e EvidenceLevel) rank() int {
	for i, v := range AllEvidenceLevels() {
		if v == e {
			return i
		}
	}
	return -1
}

func (c ClaimType) rank() int {
	for i, v := range AllClaimTypes() {
		if v == c {
			return i
		}
	}
	return -1
}

// MinEvidenceLevel returns the weakest evidence level that may carry a claim of
// the given type. Enforcing this direction is what stops a single observation
// being reported as an attribution.
func MinEvidenceLevel(c ClaimType) EvidenceLevel {
	switch c {
	case ClaimDescriptive:
		return EvidenceSingleObservation
	case ClaimAssociation:
		return EvidenceReplicatedWithControls
	case ClaimAttribution:
		return EvidenceIndependentRounds
	case ClaimConfirmed:
		return EvidenceCorrelatedIndependent
	default:
		return EvidenceNone
	}
}

// MaxClaimType returns the strongest claim an evidence level can support. This
// is the ceiling direction of the same rule.
func MaxClaimType(e EvidenceLevel) ClaimType {
	switch e {
	case EvidenceNone:
		return ""
	case EvidenceSingleObservation:
		return ClaimDescriptive
	case EvidenceReplicated, EvidenceReplicatedWithControls:
		return ClaimAssociation
	case EvidenceIndependentRounds:
		return ClaimAttribution
	case EvidenceCorrelatedIndependent:
		return ClaimConfirmed
	default:
		return ""
	}
}

// AttributionStatus states how far the evidence takes attribution to the WAF.
// Ordered weakest to strongest. There is no attribution_confidence in v1.0.0:
// strength lives in the ordinal status plus the evaluated alternatives.
type AttributionStatus string

const (
	// AttributionUndetermined: nothing in the evidence discriminates.
	AttributionUndetermined AttributionStatus = "undetermined"
	// AttributionCompatible: the observation is compatible with WAF behaviour
	// but alternatives are not excluded. HTTP evidence only.
	AttributionCompatible AttributionStatus = "compatible"
	// AttributionProbable: alternatives substantially excluded by controls and
	// independent rounds, still no non-HTTP corroboration.
	AttributionProbable AttributionStatus = "probable_without_corroboration"
	// AttributionSupportedByLogs: a WAF log source agrees with the inference.
	AttributionSupportedByLogs AttributionStatus = "supported_by_logs"
	// AttributionConfirmed requires all three JAVI-016 conditions.
	AttributionConfirmed AttributionStatus = "confirmed_by_correlated_evidence"
	// AttributionRejected: evidence points away from WAF attribution.
	AttributionRejected AttributionStatus = "not_attributable_to_waf"
)

func AllAttributionStatuses() []AttributionStatus {
	return []AttributionStatus{
		AttributionUndetermined, AttributionCompatible, AttributionProbable,
		AttributionSupportedByLogs, AttributionConfirmed, AttributionRejected,
	}
}

// EvidenceBasis names the sources that produced an attribution. The run summary
// reports the distribution of bases; a `http_only` finding is not evidence of
// the same quality as one with a correlated log source.
type EvidenceBasis string

const (
	BasisNone          EvidenceBasis = "none"
	BasisHTTPOnly      EvidenceBasis = "http_only"
	BasisHTTPControl   EvidenceBasis = "http_plus_valid_control"
	BasisHTTPRound     EvidenceBasis = "http_plus_independent_rounds"
	BasisHTTPLogs      EvidenceBasis = "http_plus_correlated_logs"
	BasisConfigExport  EvidenceBasis = "http_plus_configuration_export"
	BasisNotApplicable EvidenceBasis = "not_applicable"
)

func AllEvidenceBases() []EvidenceBasis {
	return []EvidenceBasis{
		BasisNone, BasisHTTPOnly, BasisHTTPControl, BasisHTTPRound,
		BasisHTTPLogs, BasisConfigExport, BasisNotApplicable,
	}
}

// AlternativeState records whether a competing explanation was excluded.
type AlternativeState string

const (
	AltSupported   AlternativeState = "supported"
	AltNotRuledOut AlternativeState = "not_ruled_out"
	AltRuledOut    AlternativeState = "ruled_out"
	AltUnevaluable AlternativeState = "unevaluable"
	AltNotInScope  AlternativeState = "not_in_authorized_scope"
)

func AllAlternativeStates() []AlternativeState {
	return []AlternativeState{
		AltSupported, AltNotRuledOut, AltRuledOut, AltUnevaluable, AltNotInScope,
	}
}

// AlternativeKind names a competing explanation for an observed signal.
type AlternativeKind string

const (
	AltWAF                AlternativeKind = "waf"
	AltOriginApplication  AlternativeKind = "origin_application"
	AltReverseProxyOrCDN  AlternativeKind = "reverse_proxy_or_cdn"
	AltLoadBalancerInfra  AlternativeKind = "load_balancer_or_infrastructure"
	AltRateLimiting       AlternativeKind = "rate_limiting_or_throttling"
	AltAuthZLayer         AlternativeKind = "application_authorization"
	AltNetworkOrClient    AlternativeKind = "network_or_client_side"
	AltHarnessArtifact    AlternativeKind = "test_harness_artifact"
	AltInputNormalization AlternativeKind = "framework_input_normalization"
	AltRoutingDivergence  AlternativeKind = "routing_divergence"
)

func AllAlternativeKinds() []AlternativeKind {
	return []AlternativeKind{
		AltWAF, AltOriginApplication, AltReverseProxyOrCDN, AltLoadBalancerInfra,
		AltRateLimiting, AltAuthZLayer, AltNetworkOrClient, AltHarnessArtifact,
		AltInputNormalization, AltRoutingDivergence,
	}
}

// HypothesisOutcome is the state of a hypothesis. v1.0.0 has no "confirmed":
// promotion past `supported` is out of the pipeline's reach by design.
type HypothesisOutcome string

const (
	HypothesisSupported    HypothesisOutcome = "supported"
	HypothesisRefuted      HypothesisOutcome = "refuted"
	HypothesisInconclusive HypothesisOutcome = "inconclusive"
)

func AllHypothesisOutcomes() []HypothesisOutcome {
	return []HypothesisOutcome{HypothesisSupported, HypothesisRefuted, HypothesisInconclusive}
}

// AttackClass names a diagnostic payload family.
type AttackClass string

const (
	ClassSQLi             AttackClass = "sqli"
	ClassXSS              AttackClass = "xss"
	ClassPathTraversal    AttackClass = "path_traversal"
	ClassCommandInjection AttackClass = "command_injection"
	ClassSSRF             AttackClass = "ssrf"
	ClassLDAPInjection    AttackClass = "ldap_injection"
	ClassNoSQLInjection   AttackClass = "nosql_injection"
	ClassXXE              AttackClass = "xxe"
	ClassCRLFInjection    AttackClass = "crlf_injection"
)

func AllAttackClasses() []AttackClass {
	return []AttackClass{
		ClassSQLi, ClassXSS, ClassPathTraversal, ClassCommandInjection, ClassSSRF,
		ClassLDAPInjection, ClassNoSQLInjection, ClassXXE, ClassCRLFInjection,
	}
}

// Vector names where in a request the probe was placed.
type Vector string

const (
	VectorQuery     Vector = "query"
	VectorBodyJSON  Vector = "body_json"
	VectorBodyForm  Vector = "body_form"
	VectorPath      Vector = "path"
	VectorHeader    Vector = "header"
	VectorCookie    Vector = "cookie"
	VectorMultipart Vector = "multipart_form"
)

func AllVectors() []Vector {
	return []Vector{
		VectorQuery, VectorBodyJSON, VectorBodyForm, VectorPath,
		VectorHeader, VectorCookie, VectorMultipart,
	}
}

// Encoding names a transformation applied to a probe's canonical form.
type Encoding string

const (
	EncodingCanonical     Encoding = "canonical"
	EncodingURLSingle     Encoding = "url_single"
	EncodingURLDouble     Encoding = "url_double"
	EncodingHTMLEntity    Encoding = "html_entity_named"
	EncodingHTMLEntityNum Encoding = "html_entity_numeric"
	EncodingUnicodeEscape Encoding = "unicode_escape"
	EncodingCaseVariant   Encoding = "case_variant"
	EncodingCommentInsert Encoding = "comment_insertion"
	EncodingWhitespaceVar Encoding = "whitespace_variant"
	EncodingMixedNested   Encoding = "mixed_nested"
)

func AllEncodings() []Encoding {
	return []Encoding{
		EncodingCanonical, EncodingURLSingle, EncodingURLDouble, EncodingHTMLEntity,
		EncodingHTMLEntityNum, EncodingUnicodeEscape, EncodingCaseVariant,
		EncodingCommentInsert, EncodingWhitespaceVar, EncodingMixedNested,
	}
}

// FindingType categorises a discovery finding.
type FindingType string

const (
	FindingCoverageGap          FindingType = "coverage_gap"
	FindingOverBlocking         FindingType = "over_blocking"
	FindingVectorAsymmetry      FindingType = "vector_asymmetry"
	FindingEncodingBypass       FindingType = "encoding_bypass_pattern"
	FindingConfigurationConcern FindingType = "configuration_concern"
	FindingUndeterminedArea     FindingType = "undetermined_area"
)

func AllFindingTypes() []FindingType {
	return []FindingType{
		FindingCoverageGap, FindingOverBlocking, FindingVectorAsymmetry,
		FindingEncodingBypass, FindingConfigurationConcern, FindingUndeterminedArea,
	}
}

// FindingTypeKnown reports whether a string is in the C-16 vocabulary. It lives
// beside the vocabulary rather than in each caller because two packages used to
// keep their own copy of the loop, and a category added here would have quietly
// failed validation in the one that did not update.
func FindingTypeKnown(t FindingType) bool {
	for _, k := range AllFindingTypes() {
		if k == t {
			return true
		}
	}
	return false
}

// Priority orders a finding for the engineer. It is derived from measured
// coverage deltas; PriorityBasis records the derivation and is mandatory.
type Priority string

const (
	PriorityHigh   Priority = "high"
	PriorityMedium Priority = "medium"
	PriorityLow    Priority = "low"
)

func AllPriorities() []Priority {
	return []Priority{PriorityHigh, PriorityMedium, PriorityLow}
}

// ReasonCode typifies why something was not evaluated. An unevaluated zone is
// always typed; "we did not get to it" is not a reason code.
type ReasonCode string

const (
	ReasonControlInvalid     ReasonCode = "control_invalid"
	ReasonOriginUnstable     ReasonCode = "origin_unstable"
	ReasonOutOfScope         ReasonCode = "out_of_authorized_scope"
	ReasonBudgetExhausted    ReasonCode = "request_budget_exhausted"
	ReasonRateLimited        ReasonCode = "rate_limited_halt"
	ReasonTransportFailure   ReasonCode = "transport_failure"
	ReasonCorpusGap          ReasonCode = "corpus_gap"
	ReasonAuthorizationGap   ReasonCode = "authorization_gap"
	ReasonInconclusiveSignal ReasonCode = "inconclusive_signal"
	ReasonNotYetAttempted    ReasonCode = "not_yet_attempted"
	ReasonOperatorHalt       ReasonCode = "operator_halt"
)

func AllReasonCodes() []ReasonCode {
	return []ReasonCode{
		ReasonControlInvalid, ReasonOriginUnstable, ReasonOutOfScope,
		ReasonBudgetExhausted, ReasonRateLimited, ReasonTransportFailure,
		ReasonCorpusGap, ReasonAuthorizationGap, ReasonInconclusiveSignal,
		ReasonNotYetAttempted, ReasonOperatorHalt,
	}
}

// stringsOf adapts a typed enum slice for the violations helper.
func stringsOf[T ~string](in []T) []string {
	out := make([]string, len(in))
	for i, v := range in {
		out[i] = string(v)
	}
	return out
}
