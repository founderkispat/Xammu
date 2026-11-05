package effectiveness

import (
	"bytes"
	"strings"
	"time"

	"xammu/internal/contracts"
	"xammu/internal/fingerprint"
	"xammu/internal/httpclient"
)

// LabBlockMarker is the literal the laboratory WAF embeds in a rejection
// interstitial. Reading it proves the verdict is not leaning on a header the WAF
// may be configured to strip; a production WAF would need its own marker
// configured before this check can fire.
const LabBlockMarker = "XAMMU-LAB-WAF-BLOCK"

// Outcome is E-02: one case's observed result. It stores no response body and no
// request URL; the body is read for the block marker and then dropped, and the
// payload already lives in E-01.
type Outcome struct {
	CaseID          string          `json:"case_id"`
	RunID           string          `json:"run_id"`
	ObservedAt      time.Time       `json:"observed_at"`
	Verdict         Verdict         `json:"verdict"`
	Basis           string          `json:"basis"`
	StatusCode      int             `json:"status_code"`
	LatencyMS       int64           `json:"latency_ms"`
	TransportError  string          `json:"transport_error,omitempty"`
	ExclusionReason string          `json:"exclusion_reason,omitempty"`
	ServerHeader    string          `json:"server_header,omitempty"`
	SecurityHeaders map[string]bool `json:"security_headers"`
	WAFMarker       bool            `json:"waf_marker"`
	BlockHeader     bool            `json:"block_header"`

	// Phase 2. An empty Arm is a Phase 1 record and reads as the baseline arm.
	Arm               Arm                    `json:"arm,omitempty"`
	TamperStack       []contracts.Tamper     `json:"tamper_stack,omitempty"`
	TamperDigest      string                 `json:"tamper_digest,omitempty"`
	SelectionBasis    string                 `json:"selection_basis,omitempty"`
	MarkerHeader      bool                   `json:"marker_header,omitempty"`
	Fingerprint       []fingerprint.Evidence `json:"fingerprint,omitempty"`
	FingerprintPolicy string                 `json:"fingerprint_policy,omitempty"`
}

// Arm names the measurement a trial belongs to.
type Arm string

const (
	ArmBaseline Arm = "baseline"
	ArmTamper   Arm = "tamper"
)

// NormalizeArm reads a Phase 1 record, which carries no arm, as baseline.
func NormalizeArm(a Arm) Arm {
	if a == "" {
		return ArmBaseline
	}
	return a
}

// Classify turns one client response into a verdict. A response the metrics
// cannot use is excluded with a reason, never folded into blocked or allowed:
// 429 is pacing, 5xx is the origin failing, and a transport error is not
// evidence about the WAF.
func Classify(runID string, c Case, resp *httpclient.Response, now time.Time) Outcome {
	o := Outcome{
		CaseID: c.ID, RunID: runID, ObservedAt: now.UTC(),
		StatusCode: resp.Status, LatencyMS: resp.TotalMS,
		TransportError:    resp.TransportError,
		SecurityHeaders:   SecurityHeaders(resp.Headers),
		ServerHeader:      serverOf(resp.Headers),
		BlockHeader:       blockHeader(resp.Headers),
		Fingerprint:       fingerprint.Attribute(resp.Headers, resp.Body),
		FingerprintPolicy: fingerprint.Policy,
	}
	o.WAFMarker = strings.HasPrefix(strings.ToLower(o.ServerHeader), "xammu-lab-waf") ||
		o.BlockHeader || bytes.Contains(resp.Body, []byte(LabBlockMarker))

	switch {
	case resp.RateLimited || resp.Status == 429:
		o.Verdict = VerdictExcluded
		o.ExclusionReason = "rate_limited"
		o.Basis = "status_429"
	case resp.TransportError != "":
		if connectionClosed(resp) {
			o.Verdict = VerdictBlocked
			o.Basis = "connection_closed"
		} else {
			o.Verdict = VerdictExcluded
			o.ExclusionReason = "transport_error:" + resp.TransportError
			o.Basis = "transport_" + resp.TransportError
		}
	case resp.Status == 403:
		o.Verdict = VerdictBlocked
		o.Basis = "status_403"
	case resp.Status == 406:
		o.Verdict = VerdictBlocked
		o.Basis = "status_406"
	case resp.Status >= 500:
		o.Verdict = VerdictExcluded
		o.ExclusionReason = "server_error"
		o.Basis = "status_5xx"
	case resp.Status >= 400:
		o.Verdict = VerdictExcluded
		o.ExclusionReason = "other_4xx"
		o.Basis = "status_4xx"
	case resp.Status >= 300:
		o.Verdict = VerdictExcluded
		o.ExclusionReason = "redirect_not_followed"
		o.Basis = "status_3xx"
	case bytes.Contains(resp.Body, []byte(LabBlockMarker)):
		o.Verdict = VerdictBlocked
		o.Basis = "body_block_marker"
	case resp.Status >= 200:
		o.Verdict = VerdictAllowed
		o.Basis = "status_2xx"
	default:
		o.Verdict = VerdictExcluded
		o.ExclusionReason = "no_response"
		o.Basis = "no_status"
	}
	return o
}

func blockHeader(h []contracts.HeaderEntry) bool {
	for _, e := range h {
		if strings.EqualFold(e.Name, "X-Lab-Waf-Action") &&
			strings.EqualFold(strings.TrimSpace(e.Value), "block") {
			return true
		}
	}
	return false
}

// connectionClosed recognises the one transport failure that is a defensive
// decision rather than a broken path: the peer accepted the request and closed
// the connection without a response. A refused connect, DNS failure or timeout
// is excluded instead, because none of them shows the WAF deciding anything.
func connectionClosed(resp *httpclient.Response) bool {
	if resp.TransportError != "transport_error" {
		return false
	}
	d := strings.ToLower(resp.TransportDetail)
	return strings.Contains(d, "eof") || strings.Contains(d, "reset by peer") ||
		strings.Contains(d, "broken pipe") || strings.Contains(d, "connection closed")
}
