package effectiveness

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"xammu/internal/contracts"
	"xammu/internal/corpus"
	"xammu/internal/httpclient"
	"xammu/internal/integrity"
	"xammu/internal/tamper"
)

func testAuthorization(t *testing.T, origin string) *contracts.ProfilingAuthorization {
	t.Helper()
	u, err := url.Parse(origin)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatal(err)
	}
	auth := contracts.ValidProfilingAuthorization()
	auth.Ref = "AUTH-EFFECTIVENESS-TEST"
	auth.Origins = []contracts.Origin{{
		Scheme: "http", Host: u.Hostname(), Port: port,
		PathPrefixes: []string{"/api/"},
		AllowedIPs:   []string{"127.0.0.1"},
	}}
	auth.Methods = []string{"GET", "POST"}
	auth.AllowedClasses = contracts.AllAttackClasses()
	auth.AllowedVectors = contracts.AllVectors()
	auth.AllowedEncodings = contracts.AllEncodings()
	auth.IssuedAt = time.Now().Add(-time.Hour)
	auth.ExpiresAt = time.Now().Add(time.Hour)
	auth.Limits.MaxRequests = 20
	auth.Limits.RatePerSecond = 1000
	return auth
}

func testClient(t *testing.T, auth *contracts.ProfilingAuthorization, budget int) *httpclient.Client {
	t.Helper()
	scope, err := httpclient.ScopeFromProfiling(auth)
	if err != nil {
		t.Fatal(err)
	}
	client := httpclient.New(scope, budget)
	r, err := contracts.NewHeaderRedactor(nil)
	if err != nil {
		t.Fatal(err)
	}
	client.SetHeaderRedactor(r)
	return client
}

func TestRunObservesBlockedAndAllowed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("q") == "block me xammu-probe" {
			w.Header().Set("Server", "xammu-lab-waf/test")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(LabBlockMarker))
			return
		}
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	auth := testAuthorization(t, srv.URL)
	store, err := integrity.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cases := []Case{
		{ID: "attack-1", Kind: KindAttack, Class: "sqli", Payload: "block me xammu-probe",
			Vector: contracts.VectorQuery, Encoding: contracts.EncodingCanonical,
			Parameter: "q", Method: "GET", Path: "/api/search", Expect: ExpectBlocked},
		{ID: "benign-1", Kind: KindBenign, Class: "benign_text", Payload: "hello xammu-probe",
			Vector: contracts.VectorQuery, Encoding: contracts.EncodingCanonical,
			Parameter: "q", Method: "GET", Path: "/api/search", Expect: ExpectAllowed},
	}
	res, err := Run(context.Background(), testClient(t, auth, 10), store, auth,
		"run-test", srv.URL, "", cases, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Outcomes) != 2 || res.RequestsSent != 2 {
		t.Fatalf("result = %+v", res)
	}
	byID := map[string]Outcome{}
	for _, o := range res.Outcomes {
		byID[o.CaseID] = o
	}
	if byID["attack-1"].Verdict != VerdictBlocked || byID["benign-1"].Verdict != VerdictAllowed {
		t.Fatalf("outcomes = %+v", byID)
	}
	if !byID["attack-1"].WAFMarker || byID["attack-1"].SecurityHeaders["content-security-policy"] {
		t.Fatalf("attack facts = %+v", byID["attack-1"])
	}
	if !byID["benign-1"].SecurityHeaders["content-security-policy"] {
		t.Fatalf("benign security headers = %+v", byID["benign-1"])
	}
	m := Compute("run-test", auth.Ref, cases, res.Outcomes, time.Now())
	if m.Counts.TP != 1 || m.Counts.TN != 1 {
		t.Fatalf("counts = %+v", m.Counts)
	}
}

func TestRunArmRecordsTheStackAndTheDiagnosticHeader(t *testing.T) {
	var sawMarkerHeader []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawMarkerHeader = append(sawMarkerHeader, r.Header.Get("X-Xammu-Probe"))
		if strings.Contains(strings.ToLower(r.URL.Query().Get("q")), "block me") {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(LabBlockMarker))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	auth := testAuthorization(t, srv.URL)
	store, err := integrity.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c := Case{ID: "attack-1", Kind: KindAttack, Class: "sqli", Payload: "BLOCK ME xammu-probe",
		Vector: contracts.VectorQuery, Encoding: contracts.EncodingCanonical,
		Parameter: "q", Method: "GET", Path: "/api/search", Expect: ExpectBlocked}
	if err := JournalCases(store, []Case{c}); err != nil {
		t.Fatal(err)
	}
	client := testClient(t, auth, 10)
	base, err := RunArm(context.Background(), client, store, auth, "run-test", srv.URL, "",
		[]Trial{{Case: c, Arm: ArmBaseline}}, corpus.DefaultPolicy(), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	stack := tamper.Stack{contracts.TamperBase64}
	tampered, err := RunArm(context.Background(), client, store, auth, "run-test", srv.URL, "",
		[]Trial{{Case: c, Arm: ArmTamper, Stack: stack, SelectionBasis: "forced"}},
		corpus.DefaultPolicy(), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if len(base.Outcomes) != 1 || base.Outcomes[0].Verdict != VerdictBlocked {
		t.Fatalf("baseline = %+v", base.Outcomes)
	}
	if len(tampered.Outcomes) != 1 {
		t.Fatalf("tamper = %+v", tampered.Outcomes)
	}
	o := tampered.Outcomes[0]
	if o.Arm != ArmTamper || len(o.TamperStack) != 1 || o.TamperDigest == "" ||
		o.SelectionBasis != "forced" || !o.MarkerHeader {
		t.Fatalf("tamper outcome lost its provenance: %+v", o)
	}
	if len(sawMarkerHeader) != 2 || sawMarkerHeader[0] != "" || sawMarkerHeader[1] != c.ID {
		t.Fatalf("marker header sequence = %q", sawMarkerHeader)
	}
	if tampered.RequestsSent != 1 {
		t.Fatalf("tamper arm spent %d requests", tampered.RequestsSent)
	}
}

func TestRunArmRefusesATransformedValueTheGateWouldNotAdmit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("a transformed value that fails the gate reached the origin")
	}))
	defer srv.Close()

	auth := testAuthorization(t, srv.URL)
	store, err := integrity.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c := Case{ID: "long-1", Kind: KindAttack, Class: "sqli",
		Payload: strings.Repeat("<", 400) + " xammu-probe",
		Vector:  contracts.VectorQuery, Encoding: contracts.EncodingCanonical,
		Parameter: "q", Method: "GET", Path: "/api/search", Expect: ExpectBlocked}
	if err := JournalCases(store, []Case{c}); err != nil {
		t.Fatal(err)
	}
	res, err := RunArm(context.Background(), testClient(t, auth, 5), store, auth,
		"run-test", srv.URL, "",
		[]Trial{{Case: c, Arm: ArmTamper, Stack: tamper.Stack{contracts.TamperURLEncode}}},
		corpus.DefaultPolicy(), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if res.RequestsSent != 0 || res.Refusals != 1 || len(res.Outcomes) != 1 {
		t.Fatalf("result = %+v", res)
	}
	if res.Outcomes[0].Verdict != VerdictExcluded ||
		res.Outcomes[0].ExclusionReason != "tamper_gate_refused" {
		t.Fatalf("outcome = %+v", res.Outcomes[0])
	}
}

func TestRunArmTreatsAMarkerlessBenignCaseAsTheGateDoes(t *testing.T) {
	var sent []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sent = append(sent, r.URL.Query().Get("q"))
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	auth := testAuthorization(t, srv.URL)
	store, err := integrity.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	benign := Case{ID: "benign-1", Kind: KindBenign, Class: "benign_text", Payload: "hello there",
		Vector: contracts.VectorQuery, Encoding: contracts.EncodingCanonical,
		Parameter: "q", Method: "GET", Path: "/api/search", Expect: ExpectAllowed}
	attack := Case{ID: "attack-1", Kind: KindAttack, Class: "sqli", Payload: "block me",
		Vector: contracts.VectorQuery, Encoding: contracts.EncodingCanonical,
		Parameter: "q", Method: "GET", Path: "/api/search", Expect: ExpectBlocked}
	if err := JournalCases(store, []Case{benign, attack}); err != nil {
		t.Fatal(err)
	}
	stack := tamper.Stack{contracts.TamperCaseSwitch}
	res, err := RunArm(context.Background(), testClient(t, auth, 5), store, auth,
		"run-test", srv.URL, "", []Trial{
			{Case: benign, Arm: ArmTamper, Stack: stack},
			{Case: attack, Arm: ArmTamper, Stack: stack},
		}, corpus.DefaultPolicy(), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if res.RequestsSent != 1 || len(sent) != 1 {
		t.Fatalf("sent %d request(s), want only the benign trial: %+v", res.RequestsSent, res)
	}
	if res.Outcomes[0].Verdict != VerdictAllowed {
		t.Fatalf("benign outcome = %+v", res.Outcomes[0])
	}
	if res.Outcomes[1].Verdict != VerdictExcluded || res.Outcomes[1].ExclusionReason != "tamper_gate_refused" {
		t.Fatalf("an attack without the marker was admitted: %+v", res.Outcomes[1])
	}
}

func TestRunStopsAtTheBudgetAndLeavesTheRestUncounted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	auth := testAuthorization(t, srv.URL)
	store, err := integrity.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var cases []Case
	for i := 0; i < 3; i++ {
		cases = append(cases, Case{ID: "a-" + strconv.Itoa(i), Kind: KindAttack, Class: "sqli",
			Payload: "xammu-probe", Vector: contracts.VectorQuery, Encoding: contracts.EncodingCanonical,
			Parameter: "q", Method: "GET", Path: "/api/search", Expect: ExpectBlocked})
	}
	res, err := Run(context.Background(), testClient(t, auth, 1), store, auth,
		"run-test", srv.URL, "", cases, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if res.Stopped != "budget_exhausted" || res.RequestsSent != 1 || len(res.Outcomes) != 1 {
		t.Fatalf("result = %+v", res)
	}
	m := Compute("run-test", auth.Ref, cases, res.Outcomes, time.Now())
	if m.Counts.Excluded != 2 || m.ExcludedByReason["not_executed"] != 2 {
		t.Fatalf("metrics = %+v", m)
	}
}

func TestRunRefusesAClosedAuthorizationWindow(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("a request reached the origin after the window closed")
	}))
	defer srv.Close()

	auth := testAuthorization(t, srv.URL)
	auth.ExpiresAt = time.Now().Add(-time.Minute)
	store, err := integrity.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cases := []Case{{ID: "a-1", Kind: KindAttack, Class: "sqli", Payload: "xammu-probe",
		Vector: contracts.VectorQuery, Encoding: contracts.EncodingCanonical,
		Parameter: "q", Method: "GET", Path: "/api/search", Expect: ExpectBlocked}}
	res, err := Run(context.Background(), testClient(t, auth, 5), store, auth,
		"run-test", srv.URL, "", cases, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if res.Stopped != "authorization_window_closed" || len(res.Outcomes) != 0 {
		t.Fatalf("result = %+v", res)
	}
}

func TestRunRecordsAnUnrenderableCaseAsExcluded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	auth := testAuthorization(t, srv.URL)
	store, err := integrity.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cases := []Case{{ID: "bad-header", Kind: KindAttack, Class: "crlf_injection",
		Payload: "a\r\nb", Vector: contracts.VectorHeader, Encoding: contracts.EncodingCanonical,
		Parameter: "User-Agent", Method: "GET", Path: "/api/search", Expect: ExpectBlocked}}
	res, err := Run(context.Background(), testClient(t, auth, 5), store, auth,
		"run-test", srv.URL, "", cases, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Outcomes) != 1 || res.Outcomes[0].Verdict != VerdictExcluded ||
		res.Outcomes[0].ExclusionReason != "invalid_probe" {
		t.Fatalf("result = %+v", res)
	}
	if res.RequestsSent != 0 {
		t.Fatalf("an unrenderable case spent a request: %d", res.RequestsSent)
	}
}
