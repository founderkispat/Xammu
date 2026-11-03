package contracts

import (
	"fmt"
	"sort"
	"time"
)

// ControlRole says what the probe was designed to be before it was sent. It is
// planning metadata, not a reading of the response, so it is allowed on a raw
// observation.
type ControlRole string

const (
	RoleProbe           ControlRole = "probe"
	RolePositiveControl ControlRole = "positive_control"
	RoleNegativeControl ControlRole = "negative_control"
	RoleBenignReference ControlRole = "benign_reference"
	RoleEncodingReplica ControlRole = "encoding_replica"
)

func AllControlRoles() []ControlRole {
	return []ControlRole{
		RoleProbe, RolePositiveControl, RoleNegativeControl,
		RoleBenignReference, RoleEncodingReplica,
	}
}

// RetentionPolicy states what may be kept of a response body.
type RetentionPolicy string

const (
	RetainNone        RetentionPolicy = "none"
	RetainDigestOnly  RetentionPolicy = "digest_only"
	RetainTruncated   RetentionPolicy = "truncated_prefix"
	RetainFullAllowed RetentionPolicy = "full_where_authorized"
)

func AllRetentionPolicies() []RetentionPolicy {
	return []RetentionPolicy{RetainNone, RetainDigestOnly, RetainTruncated, RetainFullAllowed}
}

// Target records where the request actually went, including the resolved
// address. JAVI-020 requires the effective destination to be evidenced, not
// assumed from the URL the operator typed.
type Target struct {
	Scheme       string   `json:"scheme"`
	Host         string   `json:"host"`
	Port         int      `json:"port"`
	Path         string   `json:"path"`
	ResolvedAddr string   `json:"resolved_addr"`
	RedirectHops []string `json:"redirect_hops,omitempty"`
}

// Sent describes the request that left the client. Everything in it is known
// before a response exists, which is what keeps it out of interpretation.
type Sent struct {
	Method      string    `json:"method"`
	ProbeRef    string    `json:"probe_ref"`
	CorpusRef   string    `json:"corpus_item_ref"`
	AttackClass string    `json:"attack_class"`
	Vector      string    `json:"vector"`
	Encoding    string    `json:"encoding"`
	ControlRole string    `json:"control_role"`
	HeaderCount int       `json:"header_count"`
	BodyBytes   int       `json:"body_bytes"`
	BodyDigest  string    `json:"body_digest,omitempty"`
	SentAt      time.Time `json:"sent_at"`
}

// Transport states how the connection behaved. A transport error is a fact
// about the socket, not a verdict about the WAF.
type Transport struct {
	Protocol      string `json:"protocol"`
	TLSVerified   bool   `json:"tls_verified"`
	HTTP2Used     bool   `json:"http2_used"`
	ErrorClass    string `json:"error_class,omitempty"`
	ErrorDetail   string `json:"error_detail,omitempty"`
	ConnectMS     int64  `json:"connect_ms"`
	RedirectCount int    `json:"redirect_count"`
}

// RawObservation is C-01: what happened on the wire, with no reading of it.
// Any field that would classify, score, or attribute is rejected by
// validateRawObservation via the interpretive key denylist.
type RawObservation struct {
	ObservationID      string        `json:"observation_id"`
	RunID              string        `json:"run_id"`
	AuthorizationRef   string        `json:"authorization_ref"`
	Sequence           int           `json:"sequence"`
	ObservedAt         time.Time     `json:"observed_at"`
	Target             Target        `json:"target"`
	Sent               Sent          `json:"sent"`
	ResponseStatus     int           `json:"response_status"`
	ResponseHeaders    []HeaderEntry `json:"response_headers"`
	ResponseBodyBytes  int           `json:"response_body_bytes"`
	ResponseBodyDigest string        `json:"response_body_digest"`
	Transport          Transport     `json:"transport"`
	ObserverConfigHash string        `json:"observer_config_hash"`
}

// HeaderEntry is a single response header as received. Names are kept in the
// case they arrived because header casing is itself a signature datum.
type HeaderEntry struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Digest string `json:"value_digest,omitempty"`
}

func (RawObservation) Contract() ID { return IDRawObservation }

// TransientCapture is C-02: the response body held only as long as policy
// allows. When Retention says the body was dropped, Body must be nil, and the
// validator enforces that so the policy is provable rather than promised.
type TransientCapture struct {
	CaptureID     string    `json:"capture_id"`
	ObservationID string    `json:"observation_id"`
	RunID         string    `json:"run_id"`
	Retention     string    `json:"retention"`
	RetainedBytes int       `json:"retained_bytes"`
	BodyDigest    string    `json:"body_digest"`
	PrefixDigest  string    `json:"prefix_digest,omitempty"`
	DroppedReason string    `json:"dropped_reason,omitempty"`
	CapturedAt    time.Time `json:"captured_at"`

	// Body is in-memory only. It is never marshalled: a contract that can be
	// serialized to disk cannot claim to have dropped the body.
	Body []byte `json:"-"`
}

func (TransientCapture) Contract() ID { return IDTransientCapture }

// MarkerMatch is one lexical detector hit. It names the detector and the
// pattern; it does not say what the hit means.
type MarkerMatch struct {
	DetectorID string `json:"detector_id"`
	PatternID  string `json:"pattern_id"`
	Location   string `json:"location"`
	Evidence   string `json:"evidence_digest"`
}

// SignatureAnalysis is C-03: factual matches over the response plus the
// rate-limit flag. A 429 sets RateLimited so the orchestrator can halt; the
// classifier is given no field that would let it read 429 as a block signal.
type SignatureAnalysis struct {
	AnalysisID        string        `json:"analysis_id"`
	ObservationID     string        `json:"observation_id"`
	CaptureID         string        `json:"capture_id"`
	RunID             string        `json:"run_id"`
	AnalyzedAt        time.Time     `json:"analyzed_at"`
	StatusCode        int           `json:"status_code"`
	StatusCategory    string        `json:"status_category"`
	ReasonPhrase      string        `json:"reason_phrase"`
	ContentType       string        `json:"content_type"`
	ServerHeader      string        `json:"server_header"`
	RateLimited       bool          `json:"rate_limited"`
	RetryAfterSeconds int           `json:"retry_after_seconds"`
	HasRetryAfter     bool          `json:"has_retry_after"`
	DetectorRefs      []string      `json:"detector_refs"`
	Matches           []MarkerMatch `json:"matches"`
	BodyDigest        string        `json:"body_digest"`
	RetentionApplied  string        `json:"retention_applied"`
	DetectorSetHash   string        `json:"detector_set_hash"`
}

func (SignatureAnalysis) Contract() ID { return IDSignatureAnalysis }

func registerObservationContracts() {
	register(IDRawObservation, func(payload any) error {
		o, err := cast[RawObservation](IDRawObservation, payload)
		if err != nil {
			return err
		}
		c := newViolations(IDRawObservation)
		uuidField(c, "observation_id", o.ObservationID)
		c.required("run_id", o.RunID)
		c.required("authorization_ref", o.AuthorizationRef)
		c.nonNegative("sequence", o.Sequence)
		if o.ObservedAt.IsZero() {
			c.add("observed_at", "required")
		}
		c.required("target.scheme", o.Target.Scheme)
		c.oneof("target.scheme", o.Target.Scheme, "https", "http")
		c.required("target.host", o.Target.Host)
		c.nonNegative("target.port", o.Target.Port)
		if o.Target.ResolvedAddr == "" {
			c.add("target.resolved_addr", "effective destination must be recorded")
		}
		c.required("sent.method", o.Sent.Method)
		c.required("sent.probe_ref", o.Sent.ProbeRef)
		c.required("sent.control_role", o.Sent.ControlRole)
		c.oneof("sent.control_role", o.Sent.ControlRole, stringsOf(AllControlRoles())...)
		c.nonNegative("sent.header_count", o.Sent.HeaderCount)
		c.nonNegative("sent.body_bytes", o.Sent.BodyBytes)
		if o.ResponseStatus < 100 || o.ResponseStatus > 599 {
			if o.Transport.ErrorClass == "" && o.ResponseStatus != 0 {
				c.add("response_status", "out of range and no transport error recorded")
			} else if o.Transport.ErrorClass == "" {
				c.add("response_status", "required")
			}
		}
		c.nonNegative("response_body_bytes", o.ResponseBodyBytes)
		digestField(c, "response_body_digest", o.ResponseBodyDigest)
		c.nonNegative("transport.redirect_count", o.Transport.RedirectCount)
		if o.ObserverConfigHash == "" {
			c.add("observer_config_hash", "required")
		}
		// The whole point of C-01: no interpretive keys can be smuggled in,
		// including through unknown JSON fields on a round-tripped payload.
		for _, key := range interpretiveKeysIn(o) {
			c.add(key, "raw_observation must not carry interpretive fields")
		}
		return c.err()
	})

	register(IDTransientCapture, func(payload any) error {
		t, err := cast[TransientCapture](IDTransientCapture, payload)
		if err != nil {
			return err
		}
		c := newViolations(IDTransientCapture)
		uuidField(c, "capture_id", t.CaptureID)
		uuidField(c, "observation_id", t.ObservationID)
		c.required("run_id", t.RunID)
		c.oneof("retention", t.Retention, stringsOf(AllRetentionPolicies())...)
		digestField(c, "body_digest", t.BodyDigest)
		if t.CapturedAt.IsZero() {
			c.add("captured_at", "required")
		}
		c.nonNegative("retained_bytes", t.RetainedBytes)
		switch t.Retention {
		case string(RetainNone), string(RetainDigestOnly):
			if len(t.Body) > 0 {
				c.add("body", fmt_body_leak(string(t.Retention)))
			}
			if t.RetainedBytes > 0 {
				c.add("retained_bytes", fmt.Sprintf("must be 0 when retention is %s", t.Retention))
			}
			if t.DroppedReason == "" {
				c.add("dropped_reason", "required when the body is not retained")
			}
		case string(RetainTruncated):
			if len(t.Body) > MaxTruncatedBodyBytes {
				c.add("body", "truncated retention exceeds the authorized prefix cap")
			}
		}
		return c.err()
	})

	register(IDSignatureAnalysis, func(payload any) error {
		s, err := cast[SignatureAnalysis](IDSignatureAnalysis, payload)
		if err != nil {
			return err
		}
		c := newViolations(IDSignatureAnalysis)
		uuidField(c, "analysis_id", s.AnalysisID)
		uuidField(c, "observation_id", s.ObservationID)
		c.required("run_id", s.RunID)
		c.oneof("status_category", s.StatusCategory, "1xx", "2xx", "3xx", "4xx", "5xx", "none")
		if s.AnalyzedAt.IsZero() {
			c.add("analyzed_at", "required")
		}
		c.nonNegative("retry_after_seconds", s.RetryAfterSeconds)
		c.nonEmpty("detector_refs", len(s.DetectorRefs))
		for i, m := range s.Matches {
			c.required("matches[].detector_id", m.DetectorID)
			c.required("matches[].pattern_id", m.PatternID)
			c.required("matches[].location", m.Location)
			if m.Evidence == "" {
				c.add("matches[].evidence_digest", "required")
			}
			_ = i
		}
		digestField(c, "body_digest", s.BodyDigest)
		c.oneof("retention_applied", s.RetentionApplied, stringsOf(AllRetentionPolicies())...)
		c.required("detector_set_hash", s.DetectorSetHash)
		if s.RateLimited && s.StatusCode != 429 {
			c.add("rate_limited",
				"only a 429 may set rate_limited; a limit is pacing, not a block (criterion 24)")
		}
		if s.StatusCode == 429 && !s.RateLimited {
			c.add("rate_limited", "a 429 must set rate_limited so the orchestrator can halt")
		}
		if s.StatusCode > 0 && s.StatusCategory != StatusCategory(s.StatusCode) {
			c.add("status_category", "does not match status_code")
		}
		if s.StatusCode == 0 && s.StatusCategory != "none" {
			c.add("status_code", "required unless the exchange produced no response")
		}
		return c.err()
	})
}

func fmt_body_leak(policy string) string {
	return "body retained although policy is " + policy
}

// StatusCategory groups a status code into its class band.
func StatusCategory(code int) string {
	switch {
	case code >= 500:
		return "5xx"
	case code >= 400:
		return "4xx"
	case code >= 300:
		return "3xx"
	case code >= 200:
		return "2xx"
	case code >= 100:
		return "1xx"
	default:
		return "none"
	}
}

// MaxTruncatedBodyBytes caps a retained response prefix. Bodies larger than
// this are hashed and cut.
const MaxTruncatedBodyBytes = 4096

func init() { registerObservationContracts() }

// SortHeaders orders header entries by name so that a stored observation is
// byte-stable across runs and its digest is reproducible.
func SortHeaders(h []HeaderEntry) {
	sort.SliceStable(h, func(i, j int) bool {
		if h[i].Name != h[j].Name {
			return h[i].Name < h[j].Name
		}
		return h[i].Value < h[j].Value
	})
}
