package effectiveness

import (
	"testing"
	"time"

	"xammu/internal/contracts"
	"xammu/internal/httpclient"
)

func TestClassifyUsesObservedFacts(t *testing.T) {
	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	c := attackCase()
	cases := []struct {
		name    string
		resp    httpclient.Response
		verdict Verdict
		reason  string
	}{
		{"403", httpclient.Response{Status: 403}, VerdictBlocked, ""},
		{"406", httpclient.Response{Status: 406}, VerdictBlocked, ""},
		{"lab marker in a 200", httpclient.Response{Status: 200, Body: []byte(LabBlockMarker)},
			VerdictBlocked, ""},
		{"200", httpclient.Response{Status: 200}, VerdictAllowed, ""},
		{"429 is pacing", httpclient.Response{Status: 429, RateLimited: true},
			VerdictExcluded, "rate_limited"},
		{"500", httpclient.Response{Status: 500}, VerdictExcluded, "server_error"},
		{"404", httpclient.Response{Status: 404}, VerdictExcluded, "other_4xx"},
		{"302", httpclient.Response{Status: 302}, VerdictExcluded, "redirect_not_followed"},
		{"connection closed", httpclient.Response{TransportError: "transport_error",
			TransportDetail: "read tcp: connection reset by peer"}, VerdictBlocked, ""},
		{"timeout", httpclient.Response{TransportError: "timeout"}, VerdictExcluded, "transport_error:timeout"},
	}
	for _, tc := range cases {
		o := Classify("run-1", c, &tc.resp, now)
		if o.Verdict != tc.verdict {
			t.Fatalf("%s: verdict = %q, want %q", tc.name, o.Verdict, tc.verdict)
		}
		if o.ExclusionReason != tc.reason {
			t.Fatalf("%s: reason = %q, want %q", tc.name, o.ExclusionReason, tc.reason)
		}
		if o.CaseID != c.ID || o.RunID != "run-1" || !o.ObservedAt.Equal(now) {
			t.Fatalf("%s: identity = %+v", tc.name, o)
		}
	}
}

func TestClassifyRecordsFingerprintAndLatency(t *testing.T) {
	resp := httpclient.Response{
		Status: 403, TotalMS: 42,
		Headers: []contracts.HeaderEntry{
			{Name: "Server", Value: "xammu-lab-waf/1.0"},
			{Name: "X-Lab-Waf-Action", Value: "block"},
			{Name: "Content-Security-Policy", Value: "default-src 'self'"},
		},
	}
	o := Classify("run-1", attackCase(), &resp, time.Now())
	if !o.WAFMarker || !o.BlockHeader {
		t.Fatalf("fingerprint = %+v", o)
	}
	if o.ServerHeader == "" || !o.SecurityHeaders["content-security-policy"] {
		t.Fatalf("facts = %+v", o)
	}
	if o.LatencyMS != 42 {
		t.Fatalf("latency = %d", o.LatencyMS)
	}
}

func TestClassifyDoesNotTreatAnOrdinary403AsAWFingerprint(t *testing.T) {
	resp := httpclient.Response{Status: 403, Headers: []contracts.HeaderEntry{
		{Name: "Server", Value: "nginx"}}}
	o := Classify("run-1", attackCase(), &resp, time.Now())
	if o.Verdict != VerdictBlocked {
		t.Fatalf("verdict = %q", o.Verdict)
	}
	if o.WAFMarker {
		t.Fatal("an ordinary 403 was labelled a laboratory WAF marker")
	}
}
