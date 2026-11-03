package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"xammu/internal/contracts"
	"xammu/internal/httpclient"
	"xammu/internal/integrity"
)

// ErrRequestFromState is returned when a probe is attempted while the run is not
// executing. Criterion 27 makes this a hard refusal, not a warning: a paused,
// halted or terminal run must not be able to produce traffic.
var ErrRequestFromState = errors.New("request refused: run is not executing")

// ErrRunTerminal reports that a run has already reached a terminal state.
var ErrRunTerminal = errors.New("run is in a terminal state")

// ErrIllegalTransition guards the state machine against a caller that wants a
// state the transition table does not allow from here.
var ErrIllegalTransition = errors.New("illegal run state transition")

// ErrResumeMismatch reports that the checkpoint and the journal no longer
// describe the same run, which is why a resume refuses instead of guessing.
var ErrResumeMismatch = errors.New("run checkpoint does not match its journal")

// DefaultCircuitThreshold is how many consecutive transport failures pause a run.
// It is a circuit breaker against hammering a target that has gone away, and it
// is an honesty device: a run whose every response is a timeout would otherwise
// report a clean pass.
const DefaultCircuitThreshold = 5

// Config is the operator's intent for one run, kept apart from the authorization
// so that "what was approved" and "what this invocation asked for" stay two
// different documents.
type Config struct {
	RunID        string
	RoundID      string
	StoreDir     string
	Partition    string
	TargetOrigin string
	Budget       int
	ParentRunID  string
	// CircuitThreshold is how many consecutive transport failures pause the run.
	// Zero selects DefaultCircuitThreshold.
	CircuitThreshold int
	// Now supplies the clock. Injectable so that expiry, monotonic timestamps and
	// the whole resume path are testable without waiting.
	Now func() time.Time
}

// Run is one execution in progress.
type Run struct {
	mu      sync.Mutex
	profile contracts.RunProfile
	store   *integrity.Store
	client  *httpclient.Client
	scope   *httpclient.Scope
	auth    *contracts.ProfilingAuthorization
	val     *contracts.ValidationAuthorization
	cfg     Config
	items   []PlanItem
	// executed is derived from the observations journal, never asserted by the
	// caller: a probe counts as executed when evidence of it exists on disk.
	executed map[string]bool

	trigger         contracts.StopTrigger
	triggerNote     string
	refusalSeen     int
	transportStreak int
}

func (r *Run) now() time.Time {
	if r.cfg.Now != nil {
		return r.cfg.Now().UTC()
	}
	return time.Now().UTC()
}

// Begin validates the authorization, creates the C-11 profile at the initialized
// state and opens the evidence journal. Nothing has been sent when Begin returns.
func Begin(auth *contracts.ProfilingAuthorization,
	val *contracts.ValidationAuthorization, cfg Config) (*Run, error) {
	if auth == nil {
		return nil, errors.New("orchestrator: a run requires a C-09 profiling authorization")
	}
	if err := contracts.Validate(contracts.IDProfilingAuthorization, auth); err != nil {
		return nil, fmt.Errorf("orchestrator: authorization is not usable: %w", err)
	}
	if cfg.StoreDir == "" {
		return nil, errors.New("orchestrator: run store directory is required")
	}
	if cfg.RunID == "" {
		return nil, errors.New("orchestrator: run id is required so evidence has an owner")
	}
	if cfg.Budget <= 0 {
		return nil, errors.New("orchestrator: a run must declare a positive request budget")
	}
	if auth.Limits.MaxRequests > 0 && cfg.Budget > auth.Limits.MaxRequests {
		return nil, fmt.Errorf("orchestrator: budget %d exceeds the authorized maximum %d",
			cfg.Budget, auth.Limits.MaxRequests)
	}
	if val != nil {
		if err := contracts.Validate(contracts.IDValidationAuthorization, val); err != nil {
			return nil, fmt.Errorf("orchestrator: validation authorization is not usable: %w", err)
		}
		if val.MaxRequests > 0 && cfg.Budget > val.MaxRequests {
			return nil, fmt.Errorf("orchestrator: budget %d exceeds the validation cap %d",
				cfg.Budget, val.MaxRequests)
		}
	}
	if cfg.Partition == "" {
		return nil, errors.New("orchestrator: corpus partition is required; which items were used " +
			"is part of what the findings mean")
	}
	scope, err := scopeFor(auth, val)
	if err != nil {
		return nil, err
	}
	if cfg.Now != nil {
		scope.Now = cfg.Now
	}
	target, err := bindTarget(cfg.TargetOrigin, auth)
	if err != nil {
		return nil, err
	}
	cfg.TargetOrigin = target
	if cfg.RoundID == "" {
		cfg.RoundID = "round-1"
	}
	if cfg.CircuitThreshold <= 0 {
		cfg.CircuitThreshold = DefaultCircuitThreshold
	}

	store, err := integrity.Open(cfg.StoreDir)
	if err != nil {
		return nil, err
	}
	r := &Run{
		store: store, scope: scope, auth: auth, val: val, cfg: cfg,
		client:   httpclient.New(scope, cfg.Budget),
		executed: map[string]bool{},
		trigger:  contracts.TriggerNone,
	}
	started := r.now()
	r.profile = contracts.RunProfile{
		RunID: cfg.RunID, State: contracts.StateInitialized,
		AuthorizationRef: auth.Ref, TargetOrigin: cfg.TargetOrigin,
		Partition: cfg.Partition, ConfigHash: r.configHash(),
		StartedAt: started, UpdatedAt: started,
		RequestBudget: cfg.Budget, StopTrigger: contracts.TriggerNone,
		RoundID: cfg.RoundID, ParentRunID: cfg.ParentRunID,
		SchemaVersion: contracts.SchemaVersion.String(),
	}
	if val != nil {
		r.profile.ValidationRef = val.HypothesisRef
	}
	if err := r.checkpoint(); err != nil {
		return nil, err
	}
	// initialized -> authorization_pending is the only legal opening move, and the
	// cause states plainly that validity has not been checked yet.
	if err := r.advance(contracts.StateAuthorizationPending,
		"authorization "+auth.Ref+" loaded, validity not yet checked"); err != nil {
		return nil, err
	}
	return r, nil
}

func scopeFor(auth *contracts.ProfilingAuthorization,
	val *contracts.ValidationAuthorization) (*httpclient.Scope, error) {
	if val != nil {
		return httpclient.ScopeFromValidation(val)
	}
	return httpclient.ScopeFromProfiling(auth)
}

// bindTarget resolves the run's target to exactly one authorized origin. A target
// that is not listed is refused here rather than at the socket, so the operator
// sees the mismatch at planning time instead of in a wall of refusals.
func bindTarget(origin string, auth *contracts.ProfilingAuthorization) (string, error) {
	if origin == "" {
		if len(auth.Origins) == 1 {
			return originOf(auth.Origins[0]), nil
		}
		return "", errors.New("orchestrator: several origins are authorized; the run must name one")
	}
	for _, o := range auth.Origins {
		if originOf(o) == origin {
			return origin, nil
		}
	}
	return "", fmt.Errorf("orchestrator: target %q is not an authorized origin (authorized: %s)",
		origin, strings.Join(originList(auth.Origins), ", "))
}

func originOf(o contracts.Origin) string {
	return fmt.Sprintf("%s://%s:%d", o.Scheme, o.Host, o.Port)
}

func originList(in []contracts.Origin) []string {
	out := make([]string, 0, len(in))
	for _, o := range in {
		out = append(out, originOf(o))
	}
	return out
}

// Authorize checks the window and moves the run to authorized, or fails it. An
// expired authorization ends the run as failed: continuing would mean sending
// requests nobody approved, and reporting that as a completed profile would be
// the worst possible outcome of an honest tool.
func (r *Run) Authorize() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.profile.State != contracts.StateAuthorizationPending {
		return fmt.Errorf("%w: cannot authorize from state %s", ErrIllegalTransition, r.profile.State)
	}
	now := r.now()
	if !now.Before(r.auth.ExpiresAt) {
		err := fmt.Errorf("authorization %s expired at %s", r.auth.Ref,
			r.auth.ExpiresAt.UTC().Format(time.RFC3339))
		_ = r.terminal(contracts.StateFailed, contracts.TriggerAuthorizationGone,
			contracts.ReasonAuthorizationGap, err.Error())
		return err
	}
	if now.Before(r.auth.IssuedAt) {
		err := fmt.Errorf("authorization %s is not valid before %s", r.auth.Ref, r.auth.IssuedAt)
		_ = r.terminal(contracts.StateFailed, contracts.TriggerAuthorizationGone,
			contracts.ReasonAuthorizationGap, err.Error())
		return err
	}
	return r.advance(contracts.StateAuthorized,
		"window valid: issued "+r.auth.IssuedAt.UTC().Format(time.RFC3339)+
			", expires "+r.auth.ExpiresAt.UTC().Format(time.RFC3339))
}

// Plan validates the probe list against the authorization, journals it so a
// resumed process can continue the same plan, and moves the run to planned.
func (r *Run) Plan(items []PlanItem) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.profile.State != contracts.StateAuthorized {
		return fmt.Errorf("%w: cannot plan from state %s", ErrIllegalTransition, r.profile.State)
	}
	if err := r.advance(contracts.StatePlanning,
		fmt.Sprintf("validating %d probes against authorization %s", len(items), r.auth.Ref)); err != nil {
		return err
	}
	if err := ValidatePlan(items, r.auth, r.scope, r.cfg.Budget); err != nil {
		_ = r.terminal(contracts.StateFailed, contracts.TriggerNone,
			contracts.ReasonOutOfScope, "plan rejected before any request was sent: "+err.Error())
		return err
	}
	r.items = append([]PlanItem(nil), items...)
	r.profile.Counters.PlannedProbes = len(r.items)
	// The plan digest is part of the config hash, so a resumed run whose plan file
	// was edited fails its resume token instead of quietly sending different probes.
	r.profile.ConfigHash = r.configHash()
	for _, p := range r.items {
		if _, err := r.store.Append(integrity.StreamPlan, p); err != nil {
			return err
		}
	}
	return r.advance(contracts.StatePlanned,
		fmt.Sprintf("%d probes planned within a budget of %d requests", len(r.items), r.cfg.Budget))
}

// Start moves the run into executing, the only state from which traffic may leave.
func (r *Run) Start() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.profile.State != contracts.StatePlanned {
		return fmt.Errorf("%w: cannot start from state %s", ErrIllegalTransition, r.profile.State)
	}
	return r.advance(contracts.StateExecuting, "plan accepted, execution began")
}

// ErrUnplannedProbe reports a request for a probe the accepted plan does not
// contain. The plan is validated before execution, so a stage that sends something
// else is not profiling the target, it is exploring it.
var ErrUnplannedProbe = errors.New("request refused: probe is not in the accepted plan")

// Send is the only egress path a pipeline stage may use. It refuses anything that
// is not executing and anything that is not in the plan, delegates every
// destination check to the single client, and reads the consequences back into the
// state machine: a 429 halts, an exhausted budget stops the run for finalization,
// repeated transport failure trips the circuit, a closed authorization window
// aborts it.
func (r *Run) Send(ctx context.Context, req httpclient.Request) (*httpclient.Response, error) {
	r.mu.Lock()
	state := r.profile.State
	planned := false
	for _, p := range r.items {
		if p.Ref == req.ProbeRef {
			planned = true
			break
		}
	}
	r.mu.Unlock()
	if state != contracts.StateExecuting {
		_ = r.journalRefusal(httpclient.Refusal{
			At: r.now(), URL: req.URL, Probe: req.ProbeRef,
			Reason: fmt.Sprintf("%v: run state is %s", ErrRequestFromState, state),
			Stage:  "run_state",
		})
		return nil, fmt.Errorf("%w (state %s)", ErrRequestFromState, state)
	}
	if !planned {
		_ = r.journalRefusal(httpclient.Refusal{
			At: r.now(), URL: req.URL, Probe: req.ProbeRef,
			Reason: ErrUnplannedProbe.Error(), Stage: "plan",
		})
		return nil, fmt.Errorf("%w: %q (the plan holds %d probes)",
			ErrUnplannedProbe, req.ProbeRef, len(r.items))
	}

	// The exchange happens without the lock held: a slow target must not block an
	// operator's halt request.
	resp, err := r.client.Do(ctx, req)

	r.mu.Lock()
	defer r.mu.Unlock()
	r.syncRefusals()
	switch {
	case errors.Is(err, httpclient.ErrBudgetExhausted):
		r.noteStop(contracts.TriggerBudgetExhausted,
			"request budget of "+strconv.Itoa(r.cfg.Budget)+" is spent")
	case errors.Is(err, httpclient.ErrAuthorizationExpired):
		r.noteStop(contracts.TriggerAuthorizationGone, "authorization window closed mid-run")
	case errors.Is(err, httpclient.ErrHalted):
		// Already halted; nothing to add.
	case err != nil && isTransportFailure(err):
		r.transportStreak++
		if r.transportStreak >= r.cfg.CircuitThreshold {
			r.noteStop(contracts.TriggerTransportCircuit,
				strconv.Itoa(r.transportStreak)+" consecutive transport failures")
		}
	case err == nil:
		r.transportStreak = 0
		if resp != nil && resp.RateLimited {
			r.noteStop(contracts.TriggerRateLimited, "target answered 429 (criterion 24)")
		}
	}
	if trigger := r.trigger; trigger != contracts.TriggerNone {
		if stateErr := r.applyStop(trigger, r.triggerNote); stateErr != nil {
			return resp, stateErr
		}
	}
	return resp, err
}

func isTransportFailure(err error) bool {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return true
	}
	return errors.Is(err, httpclient.ErrResolvedAddrBlocked) ||
		errors.Is(err, httpclient.ErrNoAuthorizedAddress)
}

// syncRefusals journals the policy refusals the client recorded since the last
// look. They are evidence too: they show destinations XAMMU declined to touch.
func (r *Run) syncRefusals() {
	all := r.client.Refusals()
	if len(all) <= r.refusalSeen {
		return
	}
	for _, ref := range all[r.refusalSeen:] {
		_ = r.journalRefusal(ref)
	}
	r.refusalSeen = len(all)
}

func (r *Run) journalRefusal(ref httpclient.Refusal) error {
	if r.store.Sealed() {
		return nil
	}
	_, err := r.store.Append(integrity.StreamRefusals, map[string]any{
		"at": ref.At, "url": ref.URL, "probe": ref.Probe,
		"reason": ref.Reason, "stage": ref.Stage, "ips": ref.IPs,
	})
	return err
}

// applyStop turns a recorded trigger into the state the table assigns it.
func (r *Run) applyStop(trigger contracts.StopTrigger, cause string) error {
	switch trigger {
	case contracts.TriggerRateLimited:
		return r.terminal(contracts.StateHaltedRateLimit, trigger, contracts.ReasonRateLimited, cause)
	case contracts.TriggerControlInvalid:
		return r.terminal(contracts.StateHaltedControl, trigger, contracts.ReasonControlInvalid, cause)
	case contracts.TriggerOperator:
		return r.terminal(contracts.StateHaltedOperator, trigger, contracts.ReasonOperatorHalt, cause)
	case contracts.TriggerTransportCircuit:
		return r.terminal(contracts.StatePaused, trigger, contracts.ReasonTransportFailure,
			cause+"; the run may resume from its journal")
	case contracts.TriggerAuthorizationGone:
		// Without a live authorization the run may not continue at all, and calling
		// that "truncated" would imply the remaining probes were merely not reached.
		return r.terminal(contracts.StateAborted, trigger, contracts.ReasonAuthorizationGap, cause)
	default:
		return nil
	}
}

// noteStop records a trigger without changing state yet; Send applies it once the
// counters are current, so the halt and the request that caused it are journaled
// in the order a reviewer expects.
func (r *Run) noteStop(trigger contracts.StopTrigger, cause string) {
	if r.trigger == contracts.TriggerNone || rankTrigger(trigger) > rankTrigger(r.trigger) {
		r.trigger = trigger
		r.triggerNote = cause
	}
}

// rankTrigger decides which stop wins when two happen in the same exchange. An
// authorization lapse outranks everything because it forbids traffic at all.
func rankTrigger(t contracts.StopTrigger) int {
	switch t {
	case contracts.TriggerAuthorizationGone:
		return 6
	case contracts.TriggerRateLimited:
		return 5
	case contracts.TriggerControlInvalid:
		return 4
	case contracts.TriggerOperator:
		return 3
	case contracts.TriggerBudgetExhausted:
		return 2
	case contracts.TriggerTransportCircuit:
		return 1
	default:
		return 0
	}
}

// Halt stops execution now, from the operator's hand or because a control probe
// answered in a way that invalidates the comparison it was there to anchor.
func (r *Run) Halt(trigger contracts.StopTrigger, cause string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.profile.State != contracts.StateExecuting {
		return fmt.Errorf("%w: cannot halt from state %s", ErrIllegalTransition, r.profile.State)
	}
	switch trigger {
	case contracts.TriggerOperator, contracts.TriggerControlInvalid, contracts.TriggerRateLimited:
	default:
		return fmt.Errorf("orchestrator: %q is not a halting reason", trigger)
	}
	r.noteStop(trigger, cause)
	return r.applyStop(trigger, cause)
}

// Pause suspends the run with a stated reason. It is the only stop that promises
// a continuation.
func (r *Run) Pause(cause string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.profile.State != contracts.StateExecuting {
		return fmt.Errorf("%w: cannot pause from state %s", ErrIllegalTransition, r.profile.State)
	}
	return r.advance(contracts.StatePaused, cause)
}

// ResumeExecution re-enters executing from paused, halted_control or
// halted_operator. A rate-limited run is deliberately excluded: the transition
// table allows only finalizing from it, which is the machine's way of saying that
// being told to slow down is not a pause you may simply ignore.
func (r *Run) ResumeExecution(cause string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	switch r.profile.State {
	case contracts.StatePaused, contracts.StateHaltedControl, contracts.StateHaltedOperator:
	default:
		return fmt.Errorf("%w: cannot resume execution from state %s",
			ErrIllegalTransition, r.profile.State)
	}
	r.trigger = contracts.TriggerNone
	r.triggerNote = ""
	r.transportStreak = 0
	// The trigger that stopped the run belongs to the stop, not to the run: once
	// execution resumes, the profile must say so rather than keep advertising a
	// halt that was dealt with. The transition history still shows both.
	r.profile.StopTrigger = contracts.TriggerNone
	return r.advance(contracts.StateExecuting, cause)
}

// Pending returns the planned probes with no observation in the journal yet.
func (r *Run) Pending() ([]PlanItem, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.recount(); err != nil {
		return nil, err
	}
	out := make([]PlanItem, 0, len(r.items))
	for _, p := range r.items {
		if !r.executed[p.Ref] {
			out = append(out, p)
		}
	}
	return out, nil
}

// Journal hands the store to a pipeline stage. Payloads are validated by the
// stream's own contract before they are written, so a stage cannot persist
// something its schema forbids.
func (r *Run) Journal(stream integrity.Stream, payload any) error {
	if _, err := r.store.Append(stream, payload); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	// The summary follows the evidence: counters and the resume token are
	// re-derived, so a stage writing classifications cannot leave the checkpoint
	// describing a journal that no longer matches its own hash.
	return r.writeSummary(false)
}

// Finalize closes the run. It decides between completed and truncated from the
// ledger's arithmetic rather than from the executor's account of itself, seals the
// evidence, and returns the terminal C-11.
func (r *Run) Finalize(cause string) (contracts.RunProfile, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	switch r.profile.State {
	case contracts.StateExecuting, contracts.StatePaused,
		contracts.StateHaltedRateLimit, contracts.StateHaltedControl, contracts.StateHaltedOperator:
	default:
		return r.profile, fmt.Errorf("%w: cannot finalize from state %s",
			ErrIllegalTransition, r.profile.State)
	}
	if err := r.recount(); err != nil {
		return r.profile, err
	}
	if err := r.advance(contracts.StateFinalizing, cause); err != nil {
		return r.profile, err
	}

	pending := 0
	for _, p := range r.items {
		if !r.executed[p.Ref] {
			pending++
		}
	}
	used := r.client.Ledger().Used()

	switch {
	case r.trigger == contracts.TriggerAuthorizationGone:
		err := r.terminal(contracts.StateAborted, r.trigger, contracts.ReasonAuthorizationGap,
			r.triggerNote)
		return r.profile, err

	case pending > 0:
		trigger, code := r.trigger, codeFor(r.trigger)
		if trigger == contracts.TriggerNone {
			trigger, code = contracts.TriggerBudgetExhausted, contracts.ReasonBudgetExhausted
		}
		reason := fmt.Sprintf("%d of %d planned probes were not executed: %s",
			pending, len(r.items), r.triggerNote)
		if r.triggerNote == "" {
			reason = fmt.Sprintf("%d requests consumed the authorized budget of %d with "+
				"%d probes still planned", used, r.profile.RequestBudget, pending)
		}
		err := r.terminal(contracts.StateTruncated, trigger, code, reason)
		return r.profile, err

	case used >= r.profile.RequestBudget:
		// Criterion 26. The plan finished, but spending the whole authorized budget
		// means the run cannot claim it stopped because it had nothing left to ask.
		err := r.terminal(contracts.StateTruncated, contracts.TriggerBudgetExhausted,
			contracts.ReasonBudgetExhausted,
			fmt.Sprintf("all %d probes executed, but the authorized budget of %d requests was "+
				"fully spent, so completion cannot be claimed under criterion 26",
				len(r.items), r.profile.RequestBudget))
		return r.profile, err

	case r.trigger != contracts.TriggerNone:
		// Nothing was left unexecuted, but something did cut the run short: a
		// completed profile may not report a stop trigger, and a stop the operator
		// ordered is not a run that finished on its own terms.
		err := r.terminal(contracts.StateTruncated, r.trigger, codeFor(r.trigger),
			r.triggerNote)
		return r.profile, err

	default:
		err := r.terminal(contracts.StateCompleted, contracts.TriggerNone,
			contracts.ReasonNotYetAttempted,
			fmt.Sprintf("all %d planned probes executed with %d of %d authorized requests left",
				len(r.items), r.profile.RequestBudget-used, r.profile.RequestBudget))
		return r.profile, err
	}
}

func codeFor(t contracts.StopTrigger) contracts.ReasonCode {
	switch t {
	case contracts.TriggerRateLimited:
		return contracts.ReasonRateLimited
	case contracts.TriggerBudgetExhausted:
		return contracts.ReasonBudgetExhausted
	case contracts.TriggerControlInvalid:
		return contracts.ReasonControlInvalid
	case contracts.TriggerOperator:
		return contracts.ReasonOperatorHalt
	case contracts.TriggerAuthorizationGone:
		return contracts.ReasonAuthorizationGap
	case contracts.TriggerTransportCircuit:
		return contracts.ReasonTransportFailure
	default:
		return contracts.ReasonNotYetAttempted
	}
}

// terminal enters a stop state. The trigger is recorded whatever the state,
// because the reason execution stopped is knowable the moment it stops: a paused
// or halted profile that reports "none" would leave a reviewer to guess, and a
// profile is evidence. For a terminal state the closing fields are written too,
// and the journal is sealed so the report and the manifest are derived from
// evidence that can no longer change.
func (r *Run) terminal(state contracts.RunState, trigger contracts.StopTrigger,
	code contracts.ReasonCode, reason string) error {
	r.profile.StopTrigger = trigger
	if contracts.IsTerminal(state) {
		r.profile.TerminalCode = code
		r.profile.TerminalReason = reason
		r.profile.FinishedAt = r.now()
	}
	if err := r.advance(state, reason); err != nil {
		return err
	}
	if contracts.IsTerminal(state) {
		r.store.Seal()
	}
	return nil
}

// advance performs one legal transition and persists it. It is the only writer of
// run state, so "the state machine was bypassed" is not a failure this tool can
// have.
func (r *Run) advance(to contracts.RunState, cause string) error {
	from := r.profile.State
	if !contracts.LegalTransition(from, to) {
		return fmt.Errorf("%w: %s -> %s (legal outcomes from %s: %s)", ErrIllegalTransition,
			from, to, from, strings.Join(stateNames(contracts.Outcomes(from)), ", "))
	}
	at := r.now()
	if len(r.profile.Transitions) > 0 && !at.After(r.profile.UpdatedAt) {
		// Timestamps must be monotonic for C-11. The clock is the operator's, so a
		// step backwards is corrected to the smallest legal increment and the
		// correction is visible in the recorded time rather than hidden.
		at = r.profile.UpdatedAt.Add(time.Millisecond)
	}
	tr := contracts.StateTransition{
		From: from, To: to, At: at, Cause: cause,
		RequestSeq: r.client.Ledger().Used(),
	}
	r.profile.Transitions = append(r.profile.Transitions, tr)
	r.profile.State = to
	r.profile.UpdatedAt = at
	return r.checkpoint()
}

func stateNames(in []contracts.RunState) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		out = append(out, string(s))
	}
	return out
}

// checkpoint journals the profile, which validates it as C-11, then writes the
// mutable checkpoint file the next process reads.
func (r *Run) checkpoint() error { return r.writeSummary(true) }

// writeSummary refreshes the C-11 and persists it. With record set, the profile is
// also appended to its own journal, which is what makes a state change part of the
// evidence rather than a claim in a mutable file.
//
// Without record it only rewrites the summary, and that is what a stage's journal
// append triggers: the resume token commits to the journal heads, so if the file
// fell behind the records, an honest resume would look like tampering. The profile
// journal stays a history of state changes, not a copy of every record written.
func (r *Run) writeSummary(record bool) error {
	if err := r.recount(); err != nil {
		return err
	}
	if contracts.IsTerminal(r.profile.State) {
		// A terminal run is not resumable, so it must not advertise a token.
		r.profile.ResumeToken = ""
	} else {
		r.profile.ResumeToken = r.computeToken()
	}
	if err := contracts.Validate(contracts.IDRunProfile, &r.profile); err != nil {
		return fmt.Errorf("orchestrator: run profile rejected by C-11: %w", err)
	}
	if record && !r.store.Sealed() {
		if _, err := r.store.Append(integrity.StreamProfiles, r.profile); err != nil {
			return err
		}
	}
	raw, err := json.MarshalIndent(r.profile, "", "  ")
	if err != nil {
		return err
	}
	// Written through a rename, so a crash mid-write cannot leave a half-written
	// profile that a reviewer reads as a state the run never reached.
	tmp := filepath.Join(r.cfg.StoreDir, CheckpointFile+".tmp")
	if err := os.WriteFile(tmp, append(raw, '\n'), 0o640); err != nil {
		return fmt.Errorf("orchestrator: cannot write checkpoint: %w", err)
	}
	return os.Rename(tmp, filepath.Join(r.cfg.StoreDir, CheckpointFile))
}

// recount derives every counter from the journal. Counters are not incremented on
// request, because a tally that drifts from the records it summarises is the most
// expensive kind of lie a report can tell.
func (r *Run) recount() error {
	cnt := &r.profile.Counters
	obs, err := r.store.Records(integrity.StreamObservations)
	if err != nil {
		return err
	}
	cnt.Observations = len(obs)
	cnt.TransportErrors = 0
	refs := map[string]bool{}
	byID := map[string]contracts.RawObservation{}
	for _, rec := range obs {
		var o contracts.RawObservation
		if err := json.Unmarshal(rec.Payload, &o); err != nil {
			return fmt.Errorf("orchestrator: observation record %d is unreadable: %w", rec.Seq, err)
		}
		byID[o.ObservationID] = o
		if o.Sent.ProbeRef != "" {
			refs[o.Sent.ProbeRef] = true
		}
		if o.Transport.ErrorClass != "" {
			cnt.TransportErrors++
		}
	}
	r.executed = refs
	cnt.ExecutedProbes = len(refs)

	cls, err := r.store.Records(integrity.StreamClassifications)
	if err != nil {
		return err
	}
	cnt.Classified = len(cls)
	cnt.BlockSignals, cnt.PassSignals, cnt.Indeterminate, cnt.RateLimited = 0, 0, 0, 0
	valid, invalid := 0, 0
	for _, rec := range cls {
		var b contracts.BehavioralClassification
		if err := json.Unmarshal(rec.Payload, &b); err != nil {
			return fmt.Errorf("orchestrator: classification record %d is unreadable: %w", rec.Seq, err)
		}
		switch b.Signal {
		case contracts.SignalBlock:
			cnt.BlockSignals++
		case contracts.SignalPass:
			cnt.PassSignals++
		case contracts.SignalIndeterminate:
			cnt.Indeterminate++
		case contracts.SignalRateLimited:
			cnt.RateLimited++
		}
		o, known := byID[b.ObservationID]
		// A trial counts as valid when the exchange produced a readable response and
		// the classifier reached a signal. Inconclusive and transport-failed work is
		// tallied apart so it can never widen a denominator (criterion 22). The rule
		// lives in contracts so the report's rates and these counters cannot drift.
		if known && contracts.ValidTrial(o, b) {
			valid++
		} else {
			invalid++
		}
	}
	cnt.ValidTrials, cnt.InvalidTrials = valid, invalid

	hy, err := r.store.Records(integrity.StreamHypotheses)
	if err != nil {
		return err
	}
	cnt.Hypotheses = len(hy)
	cnt.Supported, cnt.Refuted, cnt.Inconclusive = 0, 0, 0
	for _, rec := range hy {
		var h contracts.Hypothesis
		if err := json.Unmarshal(rec.Payload, &h); err != nil {
			return fmt.Errorf("orchestrator: hypothesis record %d is unreadable: %w", rec.Seq, err)
		}
		switch h.Outcome {
		case contracts.HypothesisSupported:
			cnt.Supported++
		case contracts.HypothesisRefuted:
			cnt.Refuted++
		case contracts.HypothesisInconclusive:
			cnt.Inconclusive++
		}
	}
	fi, err := r.store.Records(integrity.StreamFindings)
	if err != nil {
		return err
	}
	cnt.Findings = len(fi)
	_, sent, _ := r.client.Ledger().Stats()
	r.profile.RequestsUsed = sent
	return nil
}

// configHash pins everything that gives the evidence its meaning: authorization,
// target, budget, partition and the accepted plan.
func (r *Run) configHash() string {
	material := fmt.Sprintf("auth=%s|val=%s|target=%s|budget=%d|partition=%s|round=%s|tool=%s|items=%d",
		r.auth.Ref, hypothesisOf(r.val), r.cfg.TargetOrigin, r.cfg.Budget, r.cfg.Partition,
		r.cfg.RoundID, integrity.ToolVersion, len(r.items))
	for _, p := range r.items {
		material += fmt.Sprintf("|%s:%s:%s:%s:%s", p.Ref, p.AttackClass, p.Vector, p.Encoding, p.URL)
	}
	return contracts.NewDigest([]byte(material))
}

func hypothesisOf(v *contracts.ValidationAuthorization) string {
	if v == nil {
		return "-"
	}
	return v.HypothesisRef
}

// computeToken binds the checkpoint to the journal it belongs to. It is not a
// secret and not a capability: it is the check that this profile and these files
// came from the same run, so a resume cannot be pointed at a swapped, edited or
// shorter evidence directory and still claim to continue the work.
func (r *Run) computeToken() string {
	parts := []string{r.profile.RunID, string(r.profile.State)}
	for _, st := range integrity.AllStreams() {
		// The profiles stream is the checkpoint history itself. Including it would
		// make every token commit to a record that is written after the token, so a
		// clean, untouched run could never reproduce its own resume claim.
		if st == integrity.StreamProfiles {
			continue
		}
		parts = append(parts, string(st)+"="+r.store.Head(st))
	}
	parts = append(parts,
		strconv.Itoa(r.profile.RequestBudget),
		strconv.Itoa(r.client.Ledger().Used()))
	return contracts.NewDigest([]byte(strings.Join(parts, "|")))
}

// Profile returns a copy of the current C-11 so a caller cannot mutate the run.
func (r *Run) Profile() contracts.RunProfile {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := r.profile
	out.Transitions = append([]contracts.StateTransition(nil), r.profile.Transitions...)
	return out
}

// Store exposes the evidence journal to the pipeline stages.
func (r *Run) Store() *integrity.Store { return r.store }

// Client exposes the single egress point. Stages must not build their own.
func (r *Run) Client() *httpclient.Client { return r.client }

// Scope exposes the destination policy for reporting.
func (r *Run) Scope() *httpclient.Scope { return r.scope }

// Retention reports the body-retention policy the authorization grants this run.
// It is read from the authorization rather than passed in by the caller, because a
// pipeline stage that could choose its own policy could choose to keep bodies the
// operator did not approve keeping.
func (r *Run) Retention() (contracts.RetentionPolicy, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.auth.Retention, r.auth.Limits.MaxBodyRetainBytes
}

// Items returns the accepted plan.
func (r *Run) Items() []PlanItem {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]PlanItem(nil), r.items...)
}

// Note journals an operator-visible remark about this run.
func (r *Run) Note(text string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.store.Sealed() {
		return integrity.ErrSealed
	}
	_, err := r.store.Append(integrity.StreamNotes, map[string]any{
		"note": text, "at": r.now(), "run_id": r.profile.RunID,
	})
	return err
}

// StopTrigger reports why execution stopped, for callers that need the reason
// before the run is finalized.
func (r *Run) StopTrigger() contracts.StopTrigger {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.trigger
}
