package orchestrator_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"xammu/internal/contracts"
	"xammu/internal/httpclient"
	"xammu/internal/integrity"
	"xammu/internal/orchestrator"
)

// lab is a target that answers exactly what the authorization covers and nothing
// else. It counts hits per probe so a test can prove that a refused probe produced
// no traffic, instead of trusting the run's own account of itself. Scripts are
// keyed by the q parameter, which is where the probe reference travels: every
// planned URL shares the /api/search path the authorization allows.
type lab struct {
	mu      sync.Mutex
	hits    map[string]int
	scripts map[string]int
	drop    map[string]bool
	srv     *httptest.Server
}

func newLab(t *testing.T) *lab {
	t.Helper()
	l := &lab{hits: map[string]int{}, scripts: map[string]int{}, drop: map[string]bool{}}
	l.srv = httptest.NewServer(l)
	t.Cleanup(l.srv.Close)
	return l
}

func (l *lab) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("q")
	l.mu.Lock()
	l.hits[key]++
	drop := l.drop[key]
	status, scripted := l.scripts[key]
	l.mu.Unlock()
	if drop {
		// Hijacking and closing produces a transport error rather than a status,
		// which is the only way to exercise the circuit honestly.
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "no hijack", http.StatusInternalServerError)
			return
		}
		conn, _, err := hj.Hijack()
		if err == nil {
			_ = conn.Close()
		}
		return
	}
	if !scripted {
		status = http.StatusOK
	}
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(status)
	fmt.Fprintf(w, "<html><body>xammu lab %s status %d</body></html>", key, status)
}

// hitsFor reports how many requests one probe actually received.
func (l *lab) hitsFor(key string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.hits[key]
}

// total counts every request the target actually received.
func (l *lab) total() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, c := range l.hits {
		n += c
	}
	return n
}

func (l *lab) origin() string {
	u, _ := url.Parse(l.srv.URL)
	port, _ := strconv.Atoi(u.Port())
	return fmt.Sprintf("http://%s:%d", u.Hostname(), port)
}

// clock is the run's own notion of time, so expiry and monotonic timestamps are
// tested by moving a pointer rather than by sleeping.
type clock struct {
	mu sync.Mutex
	at time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.at
}

func (c *clock) set(at time.Time) {
	c.mu.Lock()
	c.at = at.UTC()
	c.mu.Unlock()
}

func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.at = c.at.Add(d).UTC()
	c.mu.Unlock()
}

func newClock() *clock { return &clock{at: time.Now().UTC()} }

// testAuthorization is a C-09 covering exactly the lab: one origin, one path
// prefix, and resolved addresses limited to loopback so the destination gate has
// something real to check.
func testAuthorization(l *lab, c *clock) *contracts.ProfilingAuthorization {
	u, err := url.Parse(l.srv.URL)
	if err != nil {
		panic(err)
	}
	port, _ := strconv.Atoi(u.Port())
	now := c.now()
	return &contracts.ProfilingAuthorization{
		AuthorizationID: contracts.NewUUID(),
		Ref:             "auth-orchestrator-test",
		IssuedAt:        now.Add(-time.Hour),
		ExpiresAt:       now.Add(time.Hour),
		Issuer:          "security-owner@example.internal",
		ApprovedBy:      "CISO delegate",
		Environment:     contracts.EnvLab,
		Origins: []contracts.Origin{{
			Scheme: "http", Host: u.Hostname(), Port: port,
			PathPrefixes: []string{"/api/"},
			AllowedCIDRs: []string{"127.0.0.0/8"},
		}},
		Methods: []string{"GET", "POST"},
		Limits: contracts.OperationalLimits{
			MaxRequests: 500, RatePerSecond: 1000, MaxRedirects: 0,
			TimeoutMS: 2000, MaxConcurrent: 1, MaxBodyRetainBytes: 4096,
		},
		Retention:        contracts.RetainDigestOnly,
		AllowedClasses:   []contracts.AttackClass{contracts.ClassSQLi},
		AllowedVectors:   []contracts.Vector{contracts.VectorQuery},
		AllowedEncodings: []contracts.Encoding{contracts.EncodingCanonical},
		CorpusPartitions: []string{"development"},
		StatementOfScope: "Behavioural profiling of the lab WAF only.",
		RulesOfEngagement: []string{
			"no exploitation attempts",
			"stop on any 429 and report",
		},
		ContactForHalt:       "oncall@example.internal",
		IssuerKeyFingerprint: "ed25519:test",
	}
}

func plan(refs ...string) []orchestrator.PlanItem {
	out := make([]orchestrator.PlanItem, 0, len(refs))
	for _, ref := range refs {
		out = append(out, orchestrator.PlanItem{
			Ref: ref, CorpusRef: "item-" + ref, Group: "development",
			Method: "GET", AttackClass: contracts.ClassSQLi,
			Vector: contracts.VectorQuery, Encoding: contracts.EncodingCanonical,
			ControlRole: contracts.RoleProbe,
			Rationale:   "compare the answer for this shape against its control",
		})
	}
	return out
}

func withTargets(l *lab, items []orchestrator.PlanItem) []orchestrator.PlanItem {
	for i := range items {
		items[i].URL = l.origin() + "/api/search?q=" + items[i].Ref
	}
	return items
}

// start moves a fresh run to the executing state with the given plan.
func start(t *testing.T, l *lab, c *clock, budget int, refs ...string) *orchestrator.Run {
	t.Helper()
	r := begin(t, l, c, budget)
	if err := r.Plan(withTargets(l, plan(refs...))); err != nil {
		t.Fatalf("plan: %v", err)
	}
	if err := r.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	return r
}

func begin(t *testing.T, l *lab, c *clock, budget int) *orchestrator.Run {
	t.Helper()
	auth := testAuthorization(l, c)
	dir := t.TempDir()
	r, err := orchestrator.Begin(auth, nil, orchestrator.Config{
		RunID: "run-test", StoreDir: dir, Partition: "development",
		TargetOrigin: l.origin(), Budget: budget, RoundID: "round-1", Now: c.now,
	})
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := r.Authorize(); err != nil {
		t.Fatalf("authorize: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return r
}

func storeDirOf(t *testing.T, r *orchestrator.Run) string {
	t.Helper()
	return r.Store().Dir()
}

func TestBeginRefusesAnUnusableRun(t *testing.T) {
	c := newClock()
	l := newLab(t)

	if _, err := orchestrator.Begin(nil, nil, orchestrator.Config{
		RunID: "x", StoreDir: t.TempDir(), Partition: "development", Budget: 10, Now: c.now,
	}); err == nil {
		t.Fatal("a run started with no authorization")
	}

	auth := testAuthorization(l, c)
	base := orchestrator.Config{
		RunID: "run-test", StoreDir: t.TempDir(), Partition: "development",
		TargetOrigin: l.origin(), Budget: 10, Now: c.now,
	}

	cases := []struct {
		name   string
		mutate func(*orchestrator.Config)
		want   string
	}{
		{"no store", func(cfg *orchestrator.Config) { cfg.StoreDir = "" }, "store directory"},
		{"no run id", func(cfg *orchestrator.Config) { cfg.RunID = "" }, "run id"},
		{"zero budget", func(cfg *orchestrator.Config) { cfg.Budget = 0 }, "positive request budget"},
		{"no partition", func(cfg *orchestrator.Config) { cfg.Partition = "" }, "partition"},
		{"budget beyond authorization", func(cfg *orchestrator.Config) { cfg.Budget = 5000 },
			"exceeds the authorized maximum"},
		{"unauthorized target", func(cfg *orchestrator.Config) { cfg.TargetOrigin = "http://elsewhere:9000" },
			"not an authorized origin"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			cfg.StoreDir = t.TempDir()
			tc.mutate(&cfg)
			_, err := orchestrator.Begin(auth, nil, cfg)
			if err == nil {
				t.Fatalf("begin accepted a run with %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error says %q, want it to name %q", err, tc.want)
			}
			if l.total() != 0 {
				t.Fatalf("setup sent %d requests before authorization", l.total())
			}
		})
	}
}

func TestIllegalTransitionsAreRefused(t *testing.T) {
	c := newClock()
	l := newLab(t)
	r := begin(t, l, c, 20)

	if err := r.Start(); !errors.Is(err, orchestrator.ErrIllegalTransition) {
		t.Fatalf("start from authorized accepted: %v", err)
	}
	if err := r.Pause("no reason"); !errors.Is(err, orchestrator.ErrIllegalTransition) {
		t.Fatalf("pause from authorized accepted: %v", err)
	}
	if err := r.Halt(contracts.TriggerOperator, "halt"); !errors.Is(err, orchestrator.ErrIllegalTransition) {
		t.Fatalf("halt before execution accepted: %v", err)
	}
	if err := r.Plan(withTargets(l, plan("P-1"))); err != nil {
		t.Fatalf("plan: %v", err)
	}
	if err := r.Authorize(); !errors.Is(err, orchestrator.ErrIllegalTransition) {
		t.Fatalf("re-authorize accepted: %v", err)
	}
	if err := r.Plan(withTargets(l, plan("P-2"))); !errors.Is(err, orchestrator.ErrIllegalTransition) {
		t.Fatalf("a second plan accepted: %v", err)
	}

	// A rate-limited run may only be finalized. "Resume as if it were a pause" is
	// what criterion 24 forbids, and the transition table says so.
	if err := r.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := r.Halt(contracts.TriggerRateLimited, "simulated 429"); err != nil {
		t.Fatalf("halt: %v", err)
	}
	if err := r.ResumeExecution("operator changed their mind"); !errors.Is(err, orchestrator.ErrIllegalTransition) {
		t.Fatalf("resuming a rate-limited run accepted: %v", err)
	}
	if _, err := r.Finalize("closing after the halt"); err != nil {
		t.Fatalf("finalize: %v", err)
	}
	if err := r.Halt(contracts.TriggerOperator, "again"); !errors.Is(err, orchestrator.ErrIllegalTransition) {
		t.Fatalf("halt from a terminal state accepted: %v", err)
	}
}

// TestNoRequestLeavesANonExecutingRun is criterion 27 measured at the socket: the
// target's own count, not the run's word for it.
func TestNoRequestLeavesANonExecutingRun(t *testing.T) {
	c := newClock()
	l := newLab(t)
	r := begin(t, l, c, 20)
	items := withTargets(l, plan("P-1", "P-2", "P-3"))
	if err := r.Plan(items); err != nil {
		t.Fatalf("plan: %v", err)
	}
	ctx := context.Background()

	// Planned but never started: the plan is approved, the state machine has not
	// opened the gate.
	if _, err := r.Send(ctx, items[0].ClientRequest()); !errors.Is(err, orchestrator.ErrRequestFromState) {
		t.Fatalf("send from planned accepted: %v", err)
	}
	if got := l.total(); got != 0 {
		t.Fatalf("a run that never started sent %d requests", got)
	}

	if err := r.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	if _, err := r.Send(ctx, items[0].ClientRequest()); err != nil {
		t.Fatalf("first send: %v", err)
	}
	sent := l.total()

	if err := r.Pause("operator parked the run"); err != nil {
		t.Fatalf("pause: %v", err)
	}
	for i := 0; i < 5; i++ {
		if _, err := r.Send(ctx, items[1].ClientRequest()); !errors.Is(err, orchestrator.ErrRequestFromState) {
			t.Fatalf("send from paused accepted: %v", err)
		}
	}
	if got := l.total(); got != sent {
		t.Fatalf("a paused run reached the target: %d requests, was %d", got, sent)
	}

	if err := r.ResumeExecution("target confirmed healthy"); err != nil {
		t.Fatalf("resume: %v", err)
	}
	if err := r.Halt(contracts.TriggerOperator, "operator stopped it"); err != nil {
		t.Fatalf("halt: %v", err)
	}
	for i := 0; i < 5; i++ {
		if _, err := r.Send(ctx, items[2].ClientRequest()); !errors.Is(err, orchestrator.ErrRequestFromState) {
			t.Fatalf("send from a halted run accepted: %v", err)
		}
	}
	if got := l.total(); got != sent {
		t.Fatalf("a halted run reached the target: %d requests, was %d", got, sent)
	}

	prof, err := r.Finalize("closing")
	if err != nil {
		t.Fatalf("finalize: %v", err)
	}
	for i := 0; i < 5; i++ {
		if _, err := r.Send(ctx, items[1].ClientRequest()); !errors.Is(err, orchestrator.ErrRequestFromState) {
			t.Fatalf("send from terminal state %s accepted: %v", prof.State, err)
		}
	}
	if got := l.total(); got != sent {
		t.Fatalf("a terminal run reached the target: %d requests, was %d", got, sent)
	}

	// The refusals are evidence too: a reviewer must be able to see that the run
	// asked for traffic and the state machine said no.
	recs, err := r.Store().Records(integrity.StreamRefusals)
	if err != nil {
		t.Fatal(err)
	}
	// Sixteen denied sends, eleven records: the journal is sealed when the run
	// finalizes, so the five attempts made afterwards are refused with an error and
	// cannot be appended. A frozen evidence trail is the point; a reviewer sees the
	// eleven denials and the sealed profile.
	if len(recs) != 11 {
		t.Fatalf("refusals journaled = %d, want the 11 denials made before the seal", len(recs))
	}
	if !r.Store().Sealed() {
		t.Fatal("a finalized run left its journal writable")
	}
}

func TestExecuteRunsThePlanAndStopsOnARateLimit(t *testing.T) {
	c := newClock()
	l := newLab(t)
	l.scripts["P-3"] = http.StatusTooManyRequests
	r := start(t, l, c, 50, "P-1", "P-2", "P-3", "P-4", "P-5")

	ex, err := r.Execute(context.Background(), orchestrator.SendAndObserve)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if ex.Stopped == "" {
		t.Fatal("the executor reported no stopping reason")
	}
	if got := l.total(); got != 3 {
		t.Fatalf("the target saw %d requests; a 429 must stop the run at the third", got)
	}
	// The two probes after the limit were authorized too, and still never reached
	// the target: the halt is at the socket, not in a report.
	for _, ref := range []string{"P-4", "P-5"} {
		if got := l.hitsFor(ref); got != 0 {
			t.Fatalf("probe %s was sent %d times after the rate limit", ref, got)
		}
	}
	if len(ex.Executed) != 3 {
		t.Fatalf("executed %v, want the three probes with evidence", ex.Executed)
	}
	prof := r.Profile()
	if prof.State != contracts.StateHaltedRateLimit {
		t.Fatalf("state after a 429 is %s, want halted_rate_limit", prof.State)
	}
	if prof.StopTrigger != contracts.TriggerRateLimited {
		t.Fatalf("trigger is %q, want rate_limited", prof.StopTrigger)
	}

	fin, err := r.Finalize("closing after the rate limit")
	if err != nil {
		t.Fatalf("finalize: %v", err)
	}
	if fin.State != contracts.StateTruncated {
		t.Fatalf("a rate-limited run finalized as %s, want truncated", fin.State)
	}
	if fin.TerminalCode != contracts.ReasonRateLimited {
		t.Fatalf("terminal reason code is %q, want rate_limited", fin.TerminalCode)
	}
	if !strings.Contains(fin.TerminalReason, "2 of 5") {
		t.Fatalf("terminal reason hides the gap: %q", fin.TerminalReason)
	}
	// The 429 is recorded as an observation: what happened is evidence even when
	// it is the thing that ended the run.
	if n := r.Store().Count(integrity.StreamObservations); n != 3 {
		t.Fatalf("journal holds %d observations, want 3", n)
	}
}

// TestSpentBudgetIsNeverCompleted is criterion 26: the arithmetic decides, not
// the fact that the plan happened to finish.
func TestSpentBudgetIsNeverCompleted(t *testing.T) {
	c := newClock()

	t.Run("budget exactly spent truncates", func(t *testing.T) {
		l := newLab(t)
		r := start(t, l, c, 3, "P-1", "P-2", "P-3")
		if _, err := r.Execute(context.Background(), orchestrator.SendAndObserve); err != nil {
			t.Fatal(err)
		}
		fin, err := r.Finalize("plan finished")
		if err != nil {
			t.Fatal(err)
		}
		if fin.State != contracts.StateTruncated {
			t.Fatalf("state is %s although the whole authorized budget was spent; want truncated", fin.State)
		}
		if fin.StopTrigger != contracts.TriggerBudgetExhausted ||
			fin.TerminalCode != contracts.ReasonBudgetExhausted {
			t.Fatalf("budget run reports %q/%q", fin.StopTrigger, fin.TerminalCode)
		}
		if !strings.Contains(fin.TerminalReason, "criterion 26") {
			t.Fatalf("terminal reason does not name the rule that applied: %q", fin.TerminalReason)
		}
	})

	t.Run("budget with room completes", func(t *testing.T) {
		l := newLab(t)
		r := start(t, l, c, 10, "P-1", "P-2", "P-3")
		if _, err := r.Execute(context.Background(), orchestrator.SendAndObserve); err != nil {
			t.Fatal(err)
		}
		fin, err := r.Finalize("plan finished")
		if err != nil {
			t.Fatal(err)
		}
		if fin.State != contracts.StateCompleted {
			t.Fatalf("state is %s, want completed", fin.State)
		}
		if fin.StopTrigger != contracts.TriggerNone {
			t.Fatalf("a completed run reports stop trigger %q", fin.StopTrigger)
		}
		if fin.ResumeToken != "" {
			t.Fatal("a terminal run still advertises a resume token")
		}
		if !r.Store().Sealed() {
			t.Fatal("the evidence journal of a completed run is still writable")
		}
	})

	t.Run("plan larger than budget is refused before any request", func(t *testing.T) {
		l := newLab(t)
		r := begin(t, l, c, 2)
		err := r.Plan(withTargets(l, plan("P-1", "P-2", "P-3")))
		if err == nil {
			t.Fatal("a plan of 3 probes accepted with a budget of 2")
		}
		if !strings.Contains(err.Error(), "budget") {
			t.Fatalf("error does not name the budget: %v", err)
		}
		if l.total() != 0 {
			t.Fatalf("%d requests left the process for a plan that cannot finish", l.total())
		}
		if p := r.Profile(); p.State != contracts.StateFailed {
			t.Fatalf("a rejected plan leaves the run in %s, want failed", p.State)
		}
	})
}

func TestExpiredAuthorizationFailsTheRun(t *testing.T) {
	c := newClock()
	l := newLab(t)
	auth := testAuthorization(l, c)
	r, err := orchestrator.Begin(auth, nil, orchestrator.Config{
		RunID: "run-expired", StoreDir: t.TempDir(), Partition: "development",
		TargetOrigin: l.origin(), Budget: 10, Now: c.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	// The window closes while the operator is still holding the plan.
	c.add(2 * time.Hour)

	if err := r.Authorize(); err == nil {
		t.Fatal("an expired authorization was accepted")
	}
	prof := r.Profile()
	if prof.State != contracts.StateFailed {
		t.Fatalf("state is %s, want failed", prof.State)
	}
	if prof.StopTrigger != contracts.TriggerAuthorizationGone {
		t.Fatalf("trigger is %q, want authorization_expired", prof.StopTrigger)
	}
	if l.total() != 0 {
		t.Fatalf("%d requests were sent under an expired authorization", l.total())
	}
	if _, err := r.Send(context.Background(), httpclient.Request{
		URL: l.origin() + "/api/search?q=P-1", ProbeRef: "P-1"}); !errors.Is(err, orchestrator.ErrRequestFromState) {
		t.Fatalf("send from a failed run accepted: %v", err)
	}
}

func TestTransportCircuitPausesTheRun(t *testing.T) {
	c := newClock()
	l := newLab(t)
	l.drop["P-1"] = true
	l.drop["P-2"] = true
	r := start(t, l, c, 50, "P-1", "P-2", "P-3")

	ex, err := r.Execute(context.Background(), orchestrator.SendAndObserve)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if len(ex.Failures) < 2 {
		t.Fatalf("failures %v, want the two probes the target never answered", ex.Failures)
	}
	// The default threshold is five, so three probes cannot open the circuit; the
	// run ends because the plan ran out, and the failures are still reported.
	if p := r.Profile(); p.State != contracts.StateExecuting {
		t.Fatalf("state is %s, want executing after fewer failures than the threshold", p.State)
	}
	if p := r.Profile(); p.Counters.TransportErrors != 2 {
		t.Fatalf("transport errors counted %d, want 2", p.Counters.TransportErrors)
	}

	// Now with a threshold the failures actually cross.
	l2 := newLab(t)
	for _, ref := range []string{"P-1", "P-2", "P-3"} {
		l2.drop[ref] = true
	}
	r2 := beginWith(t, l2, c, orchestrator.Config{
		RunID: "run-circuit", Partition: "development", TargetOrigin: l2.origin(),
		Budget: 50, CircuitThreshold: 2,
	})
	if err := r2.Plan(withTargets(l2, plan("P-1", "P-2", "P-3"))); err != nil {
		t.Fatal(err)
	}
	if err := r2.Start(); err != nil {
		t.Fatal(err)
	}
	if _, err := r2.Execute(context.Background(), orchestrator.SendAndObserve); err != nil {
		t.Fatalf("execute: %v", err)
	}
	p := r2.Profile()
	if p.State != contracts.StatePaused {
		t.Fatalf("state is %s after 2 consecutive failures with a threshold of 2; want paused", p.State)
	}
	if p.StopTrigger != contracts.TriggerTransportCircuit {
		t.Fatalf("trigger is %q, want transport_circuit_open", p.StopTrigger)
	}
	if p.ResumeToken == "" {
		t.Fatal("a paused run carries no resume token, so it cannot be continued")
	}
	// A paused run may not send: the circuit is open until someone closes it.
	if _, err := r2.Send(context.Background(), withTargets(l2, plan("P-3"))[0].ClientRequest()); !errors.Is(err, orchestrator.ErrRequestFromState) {
		t.Fatalf("send from a paused run accepted: %v", err)
	}
	if got := l2.total(); got != 2 {
		t.Fatalf("the target saw %d requests after the circuit opened, want 2", got)
	}
}

func beginWith(t *testing.T, l *lab, c *clock, cfg orchestrator.Config) *orchestrator.Run {
	t.Helper()
	cfg.StoreDir = t.TempDir()
	cfg.Now = c.now
	if cfg.RoundID == "" {
		cfg.RoundID = "round-1"
	}
	r, err := orchestrator.Begin(testAuthorization(l, c), nil, cfg)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := r.Authorize(); err != nil {
		t.Fatalf("authorize: %v", err)
	}
	return r
}

func TestCountersAreDerivedFromTheJournal(t *testing.T) {
	c := newClock()
	l := newLab(t)
	l.scripts["P-2"] = http.StatusForbidden
	r := start(t, l, c, 50, "P-1", "P-2")
	if _, err := r.Execute(context.Background(), orchestrator.SendAndObserve); err != nil {
		t.Fatal(err)
	}

	// Classify two of the exchanges by hand, one of them inconclusive, to show
	// that the tally follows the records rather than the number of requests.
	obs, err := r.Store().Records(integrity.StreamObservations)
	if err != nil {
		t.Fatal(err)
	}
	if len(obs) != 2 {
		t.Fatalf("journal holds %d observations, want 2", len(obs))
	}
	var first, second contracts.RawObservation
	if err := decode(obs[0], &first); err != nil {
		t.Fatal(err)
	}
	if err := decode(obs[1], &second); err != nil {
		t.Fatal(err)
	}
	if err := r.Journal(integrity.StreamClassifications,
		classification(first, contracts.SignalBlock)); err != nil {
		t.Fatal(err)
	}
	if err := r.Journal(integrity.StreamClassifications,
		classification(second, contracts.SignalIndeterminate)); err != nil {
		t.Fatal(err)
	}

	p := r.Profile()
	if p.Counters.Observations != 2 || p.Counters.Classified != 2 {
		t.Fatalf("counters are %d/%d, want 2/2", p.Counters.Observations, p.Counters.Classified)
	}
	if p.Counters.BlockSignals != 1 || p.Counters.Indeterminate != 1 {
		t.Fatalf("signal tallies are block %d indeterminate %d, want 1 and 1",
			p.Counters.BlockSignals, p.Counters.Indeterminate)
	}
	// Criterion 22: an inconclusive classification is not a valid trial, so it
	// cannot quietly widen a denominator.
	if p.Counters.ValidTrials != 1 || p.Counters.InvalidTrials != 1 {
		t.Fatalf("valid/invalid trials are %d/%d, want 1/1", p.Counters.ValidTrials, p.Counters.InvalidTrials)
	}
	if p.Counters.ExecutedProbes != 2 || p.Counters.PlannedProbes != 2 {
		t.Fatalf("executed/planned are %d/%d, want 2/2", p.Counters.ExecutedProbes, p.Counters.PlannedProbes)
	}

	// The checkpoint is a mutable summary; the journals are the evidence. A
	// checkpoint that inflates its own counters fails C-11 on resume, and one that
	// states the truth still gets its counters re-derived from the records rather
	// than trusted from the file.
	dir := storeDirOf(t, r)
	truth := r.Profile()
	forgeCheckpoint(t, dir, func(p *contracts.RunProfile) { p.Counters.Observations = 99 })
	if _, err := orchestrator.Load(orchestrator.ResumeOptions{
		StoreDir: dir, Auth: testAuthorization(l, c),
	}); err == nil || !strings.Contains(err.Error(), "counters.observations") {
		t.Fatalf("a checkpoint claiming 99 observations over 2 records resumed: %v", err)
	}

	writeCheckpoint(t, dir, truth)
	loaded, err := orchestrator.Load(orchestrator.ResumeOptions{
		StoreDir: dir, Auth: testAuthorization(l, c),
	})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	lp := loaded.Profile()
	if lp.Counters.ValidTrials != 1 || lp.Counters.InvalidTrials != 1 || lp.Counters.Observations != 2 {
		t.Fatalf("a reloaded run reports different counters: %+v", lp.Counters)
	}
	if lp.State != contracts.StateExecuting {
		t.Fatalf("reloaded state is %s, want executing", lp.State)
	}
}

func refsOf(items []orchestrator.PlanItem) []string {
	out := make([]string, 0, len(items))
	for _, p := range items {
		out = append(out, p.Ref)
	}
	return out
}

// TestSignedManifestCoversARealRun takes the bundle an actual run wrote, with the
// streams a run really has, and signs it. A manifest that only verifies over
// hand-built fixtures proves nothing about the tool's own output.
func TestSignedManifestCoversARealRun(t *testing.T) {
	c := newClock()
	l := newLab(t)
	r := start(t, l, c, 20, "P-1", "P-2")
	if _, err := r.Execute(context.Background(), orchestrator.SendAndObserve); err != nil {
		t.Fatal(err)
	}
	obs, err := r.Store().Records(integrity.StreamObservations)
	if err != nil {
		t.Fatal(err)
	}
	for _, rec := range obs {
		var o contracts.RawObservation
		if err := decode(rec, &o); err != nil {
			t.Fatal(err)
		}
		if err := r.Journal(integrity.StreamClassifications,
			classification(o, contracts.SignalPass)); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.Note("both probes answered like an ordinary 200"); err != nil {
		t.Fatal(err)
	}
	fin, err := r.Finalize("plan finished")
	if err != nil {
		t.Fatal(err)
	}
	if fin.State != contracts.StateCompleted {
		t.Fatalf("state is %s, want completed", fin.State)
	}

	dir := storeDirOf(t, r)
	key, err := integrity.LoadOrCreateKey(filepath.Join(t.TempDir(), "run-signing.ed25519"))
	if err != nil {
		t.Fatal(err)
	}
	m, err := integrity.BuildManifest(dir, fin.RunID, fin.AuthorizationRef, "",
		fin.Counters.Observations, r.Store().Head(integrity.StreamObservations))
	if err != nil {
		t.Fatalf("the run's own bundle could not be inventoried: %v", err)
	}
	if err := integrity.Sign(&m, key); err != nil {
		t.Fatalf("the run's own bundle is not signable as C-12: %v", err)
	}
	for _, st := range integrity.Verify(dir, m, key.Public) {
		if !st.OK {
			t.Errorf("check %s failed on a clean run: %s", st.Check, st.Detail)
		}
	}

	// Sealing is not a figure of speech: after the signature, the evidence cannot
	// grow, so what was signed is what a reviewer reads.
	if err := r.Note("an attempt to add to a signed bundle"); !errors.Is(err, integrity.ErrSealed) {
		t.Fatalf("a sealed run accepted a new record: %v", err)
	}

	// And one edited byte in the signed bundle is reported, with the stream named.
	forgeLine(t, filepath.Join(dir, "observations.jsonl"), func(line string) string {
		edited := strings.Replace(line, `"response_status":200`, `"response_status":403`, 1)
		if edited == line {
			return line
		}
		return edited
	})
	var broken []string
	for _, st := range integrity.Verify(dir, m, key.Public) {
		if !st.OK {
			broken = append(broken, st.Check)
		}
	}
	if len(broken) == 0 {
		t.Fatal("an edited observation was signed and still verified clean")
	}
}

// TestResumeOfAnUnplannedRunKeepsItPlannable covers the states before a plan
// exists. An empty plan journal there is not missing evidence: the run simply has
// not been told what to ask yet, and refusing the resume would strand it.
func TestResumeOfAnUnplannedRunKeepsItPlannable(t *testing.T) {
	c := newClock()
	l := newLab(t)
	r := begin(t, l, c, 20)
	dir := storeDirOf(t, r)

	loaded, err := orchestrator.Load(orchestrator.ResumeOptions{
		StoreDir: dir, Auth: testAuthorization(l, c),
	})
	if err != nil {
		t.Fatalf("an authorized, unplanned run could not be resumed: %v", err)
	}
	if p := loaded.Profile(); p.State != contracts.StateAuthorized {
		t.Fatalf("reloaded state is %s, want authorized", p.State)
	}
	pending, err := loaded.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Fatalf("an unplanned run reports %v as pending", refsOf(pending))
	}
	// Nothing may be sent until a plan is accepted and started.
	if _, err := loaded.Send(context.Background(), httpclient.Request{
		Method: "GET", URL: l.origin() + "/api/search?q=P-1", ProbeRef: "P-1",
	}); !errors.Is(err, orchestrator.ErrRequestFromState) {
		t.Fatalf("an unplanned run sent traffic: %v", err)
	}
	if err := loaded.Plan(withTargets(l, plan("P-1"))); err != nil {
		t.Fatalf("the resumed run could not be planned: %v", err)
	}
	if err := loaded.Start(); err != nil {
		t.Fatal(err)
	}
	if _, err := loaded.Execute(context.Background(), orchestrator.SendAndObserve); err != nil {
		t.Fatal(err)
	}
	if got := l.total(); got != 1 {
		t.Fatalf("the target saw %d requests, want the one planned probe", got)
	}
	if _, err := loaded.Finalize("plan finished"); err != nil {
		t.Fatal(err)
	}
}

func writeCheckpoint(t *testing.T, dir string, p contracts.RunProfile) {
	t.Helper()
	raw, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, orchestrator.CheckpointFile),
		append(raw, '\n'), 0o640); err != nil {
		t.Fatal(err)
	}
}

// forgeCheckpoint edits the mutable summary the way a reviewer with filesystem
// access would have to be protected against: without touching the journals, whose
// hash chain would give the edit away immediately.
func forgeCheckpoint(t *testing.T, dir string, mutate func(*contracts.RunProfile)) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, orchestrator.CheckpointFile))
	if err != nil {
		t.Fatal(err)
	}
	var p contracts.RunProfile
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	mutate(&p)
	writeCheckpoint(t, dir, p)
}

func classification(o contracts.RawObservation, signal contracts.Signal) contracts.BehavioralClassification {
	return contracts.BehavioralClassification{
		ClassificationID:  contracts.NewUUID(),
		ObservationID:     o.ObservationID,
		AnalysisID:        contracts.NewUUID(),
		RunID:             o.RunID,
		ClassifiedAt:      o.ObservedAt.Add(time.Second),
		Signal:            signal,
		StatusCode:        o.ResponseStatus,
		DetectorRefs:      []string{"det-interstitial-01", "det-status-shape-02"},
		MatchedPatterns:   []string{"pat-forbidden-shape"},
		NonFiredDetectors: []string{"det-js-challenge-03"},
		DetectorAgreement: "majority",
		StatusCategory:    contracts.StatusCategory(o.ResponseStatus),
		ControlRole:       o.Sent.ControlRole,
		ProbeRef:          o.Sent.ProbeRef,
		DetectorSetHash:   contracts.NewDigest([]byte("detector-set-v1")),
		ClassifierVer:     "xammu-classifier-1.0.0",
	}
}

func decode(rec integrity.Record, dst any) error {
	if err := json.Unmarshal(rec.Payload, dst); err != nil {
		return fmt.Errorf("record %d is unreadable: %w", rec.Seq, err)
	}
	return nil
}

func TestResumeContinuesTheSameRunOnTheSameBudget(t *testing.T) {
	c := newClock()
	l := newLab(t)
	r := start(t, l, c, 6, "P-1", "P-2", "P-3", "P-4")

	ex, err := r.Execute(context.Background(), orchestrator.SendAndObserve)
	if err != nil {
		t.Fatal(err)
	}
	if len(ex.Executed) != 4 {
		t.Fatalf("executed %v", ex.Executed)
	}
	if _, err := r.Finalize("closing"); err != nil {
		t.Fatal(err)
	}

	// A terminal run is closed for good: resuming it would re-open evidence that a
	// signed manifest already describes.
	dir := storeDirOf(t, r)
	if _, err := orchestrator.Load(orchestrator.ResumeOptions{
		StoreDir: dir, Auth: testAuthorization(l, c),
	}); !errors.Is(err, orchestrator.ErrRunTerminal) {
		t.Fatalf("a terminal run was resumable: %v", err)
	}

	// The resumed half of the story: park the run mid-plan, hand the directory to a
	// second process, continue.
	l2 := newLab(t)
	r2 := start(t, l2, c, 6, "P-1", "P-2", "P-3", "P-4")
	first := orchestrator.Step(func(ctx context.Context, run *orchestrator.Run, item orchestrator.PlanItem) error {
		if item.Ref == "P-3" {
			return errors.New("stop here: the operator parked the run")
		}
		return orchestrator.SendAndObserve(ctx, run, item)
	})
	if _, err := r2.Execute(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	if err := r2.Pause("shift change"); err != nil {
		t.Fatal(err)
	}
	dir2 := storeDirOf(t, r2)
	before := r2.Profile()
	// A step that fails is a hole in the evidence, not a reason for the executor to
	// stop the run: the other probes were authorized, and abandoning them would
	// report a truncated run as though the target had refused. P-3 never left the
	// process, so three observations exist and one probe is pending.
	if before.Counters.Observations != 3 || before.Counters.ExecutedProbes != 3 {
		t.Fatalf("the first process journaled %d observations for %d executed probes",
			before.Counters.Observations, before.Counters.ExecutedProbes)
	}

	loaded, err := orchestrator.Load(orchestrator.ResumeOptions{
		StoreDir: dir2, Auth: testAuthorization(l2, c),
	})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if lp := loaded.Profile(); lp.RunID != before.RunID || lp.ConfigHash != before.ConfigHash {
		t.Fatalf("the resumed run describes a different run: %s vs %s", lp.RunID, before.RunID)
	}
	// The budget is a total for the run. A resume that forgot it would let two
	// processes spend 6 requests each under one authorization of 6.
	pending, err := loaded.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].Ref != "P-3" {
		t.Fatalf("a resumed run plans %v, want only the probe with no evidence", refsOf(pending))
	}
	if err := loaded.ResumeExecution("second shift took over"); err != nil {
		t.Fatal(err)
	}
	ex2, err := loaded.Execute(context.Background(), orchestrator.SendAndObserve)
	if err != nil {
		t.Fatal(err)
	}
	if len(ex2.Executed) != 1 || ex2.Executed[0] != "P-3" {
		t.Fatalf("the second process executed %v, want P-3", ex2.Executed)
	}
	if got := l2.total(); got != 4 {
		t.Fatalf("the target received %d requests across both processes, want 4", got)
	}
	fin, err := loaded.Finalize("plan finished")
	if err != nil {
		t.Fatalf("finalize: %v", err)
	}
	if fin.State != contracts.StateCompleted {
		t.Fatalf("a continued run finalized as %s, want completed", fin.State)
	}
	if fin.RequestsUsed != 4 {
		t.Fatalf("the finished run reports %d requests used, want 4", fin.RequestsUsed)
	}
	// The history a reviewer replays must show both halves as one machine.
	if err := contracts.Validate(contracts.IDRunProfile, &fin); err != nil {
		t.Fatalf("the resumed history is not a legal C-11: %v", err)
	}
	if n := loaded.Store().Count(integrity.StreamObservations); n != 4 {
		t.Fatalf("journal holds %d observations, want 4", n)
	}
}

func TestResumeRefusesEvidenceItNoLongerRecognises(t *testing.T) {
	c := newClock()

	t.Run("edited observation payload", func(t *testing.T) {
		l := newLab(t)
		r := start(t, l, c, 10, "P-1", "P-2")
		if _, err := r.Execute(context.Background(), orchestrator.SendAndObserve); err != nil {
			t.Fatal(err)
		}
		if err := r.Pause("operator stopped to look at the traffic"); err != nil {
			t.Fatal(err)
		}
		dir := storeDirOf(t, r)
		changed := false
		forgeLine(t, filepath.Join(dir, "observations.jsonl"), func(line string) string {
			edited := strings.Replace(line, `"response_status":200`, `"response_status":403`, 1)
			changed = changed || edited != line
			return edited
		})
		if !changed {
			t.Fatal("the forgery edited nothing, so the test would prove nothing")
		}
		_, err := orchestrator.Load(orchestrator.ResumeOptions{
			StoreDir: dir, Auth: testAuthorization(l, c),
		})
		if err == nil {
			t.Fatal("a run resumed over an edited observation")
		}
		if !errors.Is(err, integrity.ErrTampered) {
			t.Fatalf("the resume did not report a chain break, it said: %v", err)
		}
		if !strings.Contains(err.Error(), "observations") {
			t.Fatalf("the failure does not name the journal that broke: %v", err)
		}
	})

	t.Run("truncated observation journal", func(t *testing.T) {
		l := newLab(t)
		r := start(t, l, c, 10, "P-1", "P-2")
		if _, err := r.Execute(context.Background(), orchestrator.SendAndObserve); err != nil {
			t.Fatal(err)
		}
		if err := r.Pause("operator stopped to look at the traffic"); err != nil {
			t.Fatal(err)
		}
		dir := storeDirOf(t, r)
		path := filepath.Join(dir, "observations.jsonl")
		lines := readLines(t, path)
		if len(lines) < 2 {
			t.Fatalf("expected two observation lines, got %d", len(lines))
		}
		// Dropping the newest line and keeping the checkpoint is the cheapest
		// forgery: the chain still verifies, so the resume token has to be what
		// catches it.
		writeLines(t, path, lines[:1])
		_, err := orchestrator.Load(orchestrator.ResumeOptions{
			StoreDir: dir, Auth: testAuthorization(l, c),
		})
		if err == nil {
			t.Fatal("a run resumed after its newest evidence disappeared")
		}
		if !strings.Contains(err.Error(), "resume token") &&
			!strings.Contains(err.Error(), "does not match") {
			t.Fatalf("error does not explain the mismatch: %v", err)
		}
	})

	t.Run("plan rewritten after approval", func(t *testing.T) {
		l := newLab(t)
		r := start(t, l, c, 10, "P-1", "P-2")
		if err := r.Pause("parked with a plan on disk"); err != nil {
			t.Fatal(err)
		}
		dir := storeDirOf(t, r)
		path := filepath.Join(dir, "plan.jsonl")
		forgeLine(t, path, func(line string) string {
			return strings.Replace(line, "/api/search?q=P-2", "/admin/shell", 1)
		})
		_, err := orchestrator.Load(orchestrator.ResumeOptions{
			StoreDir: dir, Auth: testAuthorization(l, c),
		})
		if err == nil {
			t.Fatal("a run resumed with a plan that no longer matches its journal chain")
		}
	})

	t.Run("authorization swapped for a friendlier one", func(t *testing.T) {
		l := newLab(t)
		r := start(t, l, c, 10, "P-1")
		if err := r.Pause("parked"); err != nil {
			t.Fatal(err)
		}
		auth := testAuthorization(l, c)
		auth.Ref = "auth-someone-else-approved"
		_, err := orchestrator.Load(orchestrator.ResumeOptions{
			StoreDir: storeDirOf(t, r), Auth: auth,
		})
		if err == nil {
			t.Fatal("a run resumed under a different authorization reference")
		}
		if !strings.Contains(err.Error(), "belongs to authorization") {
			t.Fatalf("error does not name the authorization mismatch: %v", err)
		}
	})

	// The checkpoint file is the one part of the bundle that is mutable and outside
	// the hash chain, so nothing it claims about the run's shape is trusted: the
	// configuration hash is re-derived and the authorized ceiling is re-applied.
	t.Run("summary rewritten to widen the budget", func(t *testing.T) {
		l := newLab(t)
		r := start(t, l, c, 10, "P-1")
		if err := r.Pause("parked"); err != nil {
			t.Fatal(err)
		}
		dir := storeDirOf(t, r)
		forgeCheckpoint(t, dir, func(p *contracts.RunProfile) { p.RequestBudget = 400 })
		_, err := orchestrator.Load(orchestrator.ResumeOptions{
			StoreDir: dir, Auth: testAuthorization(l, c),
		})
		if !errors.Is(err, orchestrator.ErrResumeMismatch) {
			t.Fatalf("a checkpoint with an inflated budget resumed: %v", err)
		}
		if !strings.Contains(err.Error(), "configuration") {
			t.Fatalf("the refusal does not say what was forged: %v", err)
		}

		// Past the authorized maximum it is refused even more directly.
		forgeCheckpoint(t, dir, func(p *contracts.RunProfile) { p.RequestBudget = 5000 })
		if _, err := orchestrator.Load(orchestrator.ResumeOptions{
			StoreDir: dir, Auth: testAuthorization(l, c),
		}); err == nil || !strings.Contains(err.Error(), "authorized maximum") {
			t.Fatalf("a budget above the authorization was not named: %v", err)
		}
	})

	t.Run("summary rewritten to move the partition", func(t *testing.T) {
		l := newLab(t)
		r := start(t, l, c, 10, "P-1")
		if err := r.Pause("parked"); err != nil {
			t.Fatal(err)
		}
		dir := storeDirOf(t, r)
		// Which corpus partition the probes came from is part of what the findings
		// mean, so a resume may not quietly re-label it.
		forgeCheckpoint(t, dir, func(p *contracts.RunProfile) { p.Partition = "independent_validation" })
		if _, err := orchestrator.Load(orchestrator.ResumeOptions{
			StoreDir: dir, Auth: testAuthorization(l, c),
		}); !errors.Is(err, orchestrator.ErrResumeMismatch) {
			t.Fatal("a checkpoint that re-labelled the partition resumed")
		}
	})

	t.Run("summary rewritten to rename the run", func(t *testing.T) {
		l := newLab(t)
		r := start(t, l, c, 10, "P-1")
		if err := r.Pause("parked"); err != nil {
			t.Fatal(err)
		}
		dir := storeDirOf(t, r)
		forgeCheckpoint(t, dir, func(p *contracts.RunProfile) { p.RunID = "run-somebody-elses-evidence" })
		if _, err := orchestrator.Load(orchestrator.ResumeOptions{
			StoreDir: dir, Auth: testAuthorization(l, c),
		}); err == nil {
			t.Fatal("a checkpoint re-owned by another run resumed")
		}
	})
}

func TestExecuteIsHonestAboutProbesWithoutEvidence(t *testing.T) {
	c := newClock()
	l := newLab(t)
	r := start(t, l, c, 20, "P-1", "P-2")

	if _, err := r.Execute(context.Background(), nil); err == nil {
		t.Fatal("execute accepted a plan with no step")
	}

	// A step that sends the request but never journals the observation: the probe
	// stays pending, so the run truncates instead of claiming completion. This is
	// the property that keeps "we ran everything" out of reach of a broken stage.
	silent := orchestrator.Step(func(ctx context.Context, run *orchestrator.Run, item orchestrator.PlanItem) error {
		_, err := run.Send(ctx, item.ClientRequest())
		return err
	})
	ex, err := r.Execute(context.Background(), silent)
	if err != nil {
		t.Fatal(err)
	}
	if len(ex.Executed) != 0 {
		t.Fatalf("the executor claimed %v as executed with no evidence", ex.Executed)
	}
	if len(ex.Failures) == 0 {
		t.Fatal("a probe that produced no evidence was reported as a success")
	}
	if got := l.total(); got != 2 {
		t.Fatalf("the target saw %d requests, want 2: the traffic happened even though the stage dropped it", got)
	}
	fin, err := r.Finalize("closing")
	if err != nil {
		t.Fatal(err)
	}
	if fin.State != contracts.StateTruncated {
		t.Fatalf("state is %s although nothing was journaled, want truncated", fin.State)
	}
	if fin.RequestsUsed != 2 {
		t.Fatalf("the profile hides the spent budget: %d used", fin.RequestsUsed)
	}
}

func TestSendRefusesDestinationsTheAuthorizationDoesNotCover(t *testing.T) {
	c := newClock()
	l := newLab(t)
	r := beginWith(t, l, c, orchestrator.Config{
		RunID: "run-scope", Partition: "development", TargetOrigin: l.origin(), Budget: 20,
	})
	// The plan is checked before it is accepted, so an out-of-scope probe cannot
	// even reach the journaled plan.
	err := r.Plan([]orchestrator.PlanItem{{
		Ref: "P-1", Method: "GET", URL: l.origin() + "/admin/console",
		AttackClass: contracts.ClassSQLi, Vector: contracts.VectorQuery,
		Encoding: contracts.EncodingCanonical, ControlRole: contracts.RoleProbe,
		Rationale: "the operator wants to see the admin console",
	}})
	if err == nil {
		t.Fatal("a probe outside the authorized path prefixes was planned")
	}
	if !strings.Contains(err.Error(), "path") {
		t.Fatalf("error does not name the path: %v", err)
	}
	if l.total() != 0 {
		t.Fatalf("%d requests left the process for a refused plan", l.total())
	}

	// A class nobody approved is refused for the same reason, and the message says
	// which field failed rather than blaming the target.
	if err := r.Start(); !errors.Is(err, orchestrator.ErrIllegalTransition) {
		t.Fatalf("start after a rejected plan accepted: %v", err)
	}
}

func TestHaltFromAControlProbeIsResumableButARateLimitIsNot(t *testing.T) {
	c := newClock()
	l := newLab(t)

	t.Run("control invalid", func(t *testing.T) {
		r := start(t, l, c, 20, "P-1")
		if err := r.Halt(contracts.TriggerControlInvalid, "the positive control answered like a pass"); err != nil {
			t.Fatal(err)
		}
		if p := r.Profile(); p.State != contracts.StateHaltedControl {
			t.Fatalf("state is %s, want halted_control_invalid", p.State)
		}
		if err := r.ResumeExecution("control re-baselined and re-approved"); err != nil {
			t.Fatalf("a control halt that cannot be re-approved is a dead run: %v", err)
		}
		if p := r.Profile(); p.State != contracts.StateExecuting {
			t.Fatalf("state is %s after resume, want executing", p.State)
		}
	})

	t.Run("not a halting reason", func(t *testing.T) {
		l2 := newLab(t)
		r := start(t, l2, c, 20, "P-1")
		if err := r.Halt(contracts.TriggerBudgetExhausted, "mislabelled"); err == nil {
			t.Fatal("a budget trigger was accepted as an operator halt")
		}
	})
}

func TestPlanRejectionsNameTheFieldThatFailed(t *testing.T) {
	c := newClock()
	l := newLab(t)

	cases := []struct {
		name   string
		mutate func(*orchestrator.PlanItem)
		want   string
	}{
		{"no rationale", func(p *orchestrator.PlanItem) { p.Rationale = "   " }, "rationale"},
		{"no reference", func(p *orchestrator.PlanItem) { p.Ref = "" }, "reference"},
		{"no destination", func(p *orchestrator.PlanItem) { p.URL = "" }, "destination"},
		{"unauthorized class", func(p *orchestrator.PlanItem) {
			p.AttackClass = contracts.ClassSSRF
		}, "attack class"},
		{"unauthorized vector", func(p *orchestrator.PlanItem) { p.Vector = contracts.VectorHeader }, "vector"},
		{"unauthorized encoding", func(p *orchestrator.PlanItem) {
			p.Encoding = contracts.EncodingURLDouble
		}, "encoding"},
		{"unknown role", func(p *orchestrator.PlanItem) { p.ControlRole = "weaponize" }, "control role"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// A rejected plan fails that run, so the next case cannot reuse it: a
			// second Plan call would be refused for the wrong reason.
			r := beginWith(t, l, c, orchestrator.Config{
				RunID: "run-plan", Partition: "development", TargetOrigin: l.origin(), Budget: 20,
			})
			items := withTargets(l, plan("P-"+strings.ReplaceAll(tc.name, " ", "-")))
			tc.mutate(&items[0])
			err := r.Plan(items)
			if err == nil {
				t.Fatalf("plan accepted a probe with %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error says %q, want it to name %q", err, tc.want)
			}
		})
	}
	if l.total() != 0 {
		t.Fatalf("%d requests left the process while plans were being rejected", l.total())
	}
	// Duplicate references are refused too: two probes answering to one ref make
	// the executed-from-evidence derivation meaningless.
	dup := withTargets(l, plan("P-dup", "P-dup"))
	dupRun := beginWith(t, l, c, orchestrator.Config{
		RunID: "run-dup", Partition: "development", TargetOrigin: l.origin(), Budget: 20,
	})
	if err := dupRun.Plan(dup); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate probe references accepted: %v", err)
	}
	// And an empty plan is a run that proves nothing.
	emptyRun := beginWith(t, l, c, orchestrator.Config{
		RunID: "run-empty", Partition: "development", TargetOrigin: l.origin(), Budget: 20,
	})
	if err := emptyRun.Plan(nil); err == nil {
		t.Fatal("an empty plan was accepted")
	}
}

// TestUnplannedProbeNeverLeaves closes the gap a scope check cannot: the
// destination can be perfectly authorized and still be a request nobody approved,
// because the plan is what the operator signed up for. Send therefore requires the
// probe reference to exist in the accepted plan, whatever a stage claims.
func TestUnplannedProbeNeverLeaves(t *testing.T) {
	c := newClock()
	l := newLab(t)
	r := start(t, l, c, 20, "P-1")
	resp, err := r.Send(context.Background(), httpclient.Request{
		Method: "GET", URL: l.origin() + "/api/search?q=P-rogue", ProbeRef: "P-rogue",
	})
	if err == nil {
		t.Fatalf("a request with no plan entry was delivered: %+v", resp)
	}
	if !errors.Is(err, orchestrator.ErrUnplannedProbe) {
		t.Fatalf("unexpected refusal: %v", err)
	}
	// An unattributed request is the same problem in a different costume.
	if _, err := r.Send(context.Background(), httpclient.Request{
		Method: "GET", URL: l.origin() + "/api/search?q=P-1",
	}); !errors.Is(err, orchestrator.ErrUnplannedProbe) {
		t.Fatalf("a request with no probe reference was accepted: %v", err)
	}
	if got := l.total(); got != 0 {
		t.Fatalf("an unplanned probe reached the target %d times", got)
	}
	// The refusal is journaled, so the reviewer can see the attempt and the denial.
	if n := r.Store().Count(integrity.StreamRefusals); n == 0 {
		t.Fatal("a refused request left no trace in the evidence")
	}
	// The budget was not spent on a request that never left.
	if _, used, _ := r.Client().Ledger().Stats(); used != 0 {
		t.Fatalf("a refused request consumed %d of the budget", used)
	}
}

// readLines / writeLines / forgeLine rewrite a journal for the tampering tests.
// The forgeries are what an attacker with filesystem access would try, and the
// resume path has to refuse them.
func readLines(t *testing.T, path string) []string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	out := []string{}
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.TrimSpace(line) != "" {
			out = append(out, line)
		}
	}
	return out
}

func writeLines(t *testing.T, path string, lines []string) {
	t.Helper()
	body := strings.Join(lines, "\n")
	if body != "" {
		body += "\n"
	}
	if err := os.WriteFile(path, []byte(body), 0o640); err != nil {
		t.Fatal(err)
	}
}

func forgeLine(t *testing.T, path string, edit func(string) string) {
	t.Helper()
	lines := readLines(t, path)
	if len(lines) == 0 {
		t.Fatalf("%s has no records to forge", path)
	}
	out := make([]string, len(lines))
	for i, line := range lines {
		out[i] = edit(line)
	}
	writeLines(t, path, out)
}
