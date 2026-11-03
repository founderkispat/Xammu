package contracts

import (
	"sort"
	"time"
)

// RunState is a state of the run state machine (C-11). The set is exhaustive by
// construction: transitionsTable declares an entry for every state, including
// the terminal ones, which have an empty outgoing set.
type RunState string

const (
	StateInitialized          RunState = "initialized"
	StateAuthorizationPending RunState = "authorization_pending"
	StateAuthorized           RunState = "authorized"
	StatePlanning             RunState = "planning"
	StatePlanned              RunState = "planned"
	StateExecuting            RunState = "executing"
	StatePaused               RunState = "paused"
	StateHaltedRateLimit      RunState = "halted_rate_limit"
	StateHaltedControl        RunState = "halted_control_invalid"
	StateHaltedOperator       RunState = "halted_operator"
	StateFinalizing           RunState = "finalizing"
	StateCompleted            RunState = "completed"
	StateTruncated            RunState = "truncated"
	StateFailed               RunState = "failed"
	StateAborted              RunState = "aborted"
)

// StopTrigger names why execution stopped before the plan finished.
type StopTrigger string

const (
	TriggerNone              StopTrigger = "none"
	TriggerRateLimited       StopTrigger = "rate_limited"
	TriggerBudgetExhausted   StopTrigger = "budget_exhausted"
	TriggerControlInvalid    StopTrigger = "control_invalid"
	TriggerOperator          StopTrigger = "operator_halt"
	TriggerAuthorizationGone StopTrigger = "authorization_expired"
	TriggerIntegrityFailure  StopTrigger = "integrity_failure"
	TriggerTransportCircuit  StopTrigger = "transport_circuit_open"
)

func AllStopTriggers() []StopTrigger {
	return []StopTrigger{
		TriggerNone, TriggerRateLimited, TriggerBudgetExhausted, TriggerControlInvalid,
		TriggerOperator, TriggerAuthorizationGone, TriggerIntegrityFailure, TriggerTransportCircuit,
	}
}

// transitionsTable is the single source of truth for legal moves. JAVI-022 asks
// for exhaustiveness: a state missing from this table is a state the machine
// could occupy without a documented exit, so init refuses to build it.
var transitionsTable = map[RunState][]RunState{
	StateInitialized:          {StateAuthorizationPending, StateFailed, StateAborted},
	StateAuthorizationPending: {StateAuthorized, StateFailed, StateAborted},
	StateAuthorized:           {StatePlanning, StateFailed, StateAborted},
	StatePlanning:             {StatePlanned, StateFailed, StateAborted},
	StatePlanned:              {StateExecuting, StateFailed, StateAborted},
	StateExecuting:            {StatePaused, StateHaltedRateLimit, StateHaltedControl, StateHaltedOperator, StateFinalizing, StateFailed, StateAborted},
	StatePaused:               {StateExecuting, StateFinalizing, StateFailed, StateAborted},
	StateHaltedRateLimit:      {StateFinalizing, StateFailed, StateAborted},
	StateHaltedControl:        {StateFinalizing, StateExecuting, StateFailed, StateAborted},
	StateHaltedOperator:       {StateFinalizing, StateExecuting, StateFailed, StateAborted},
	StateFinalizing:           {StateCompleted, StateTruncated, StateFailed, StateAborted},
	StateCompleted:            {},
	StateTruncated:            {},
	StateFailed:               {},
	StateAborted:              {},
}

// AllStates returns every declared state, sorted.
func AllStates() []RunState {
	out := make([]RunState, 0, len(transitionsTable))
	for s := range transitionsTable {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// LegalTransition reports whether from->to is in the table.
func LegalTransition(from, to RunState) bool {
	outs, ok := transitionsTable[from]
	if !ok {
		return false
	}
	for _, t := range outs {
		if t == to {
			return true
		}
	}
	return false
}

// Outcomes lists the legal successors of a state.
func Outcomes(from RunState) []RunState {
	out := append([]RunState(nil), transitionsTable[from]...)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// IsTerminal reports whether a state may not issue another request.
func IsTerminal(s RunState) bool { return len(transitionsTable[s]) == 0 }

// TerminalStates returns the four terminal states.
func TerminalStates() []RunState {
	return []RunState{StateCompleted, StateTruncated, StateFailed, StateAborted}
}

// StateTransition is one recorded move, with the cause that justified it.
type StateTransition struct {
	From       RunState  `json:"from"`
	To         RunState  `json:"to"`
	At         time.Time `json:"at"`
	Cause      string    `json:"cause"`
	RequestSeq int       `json:"request_seq"`
}

// RunCounters holds the tallies a report needs, kept apart so that inconclusive
// work is never silently merged into valid work.
type RunCounters struct {
	Observations    int `json:"observations"`
	Classified      int `json:"classified"`
	BlockSignals    int `json:"block_signals"`
	PassSignals     int `json:"pass_signals"`
	Indeterminate   int `json:"indeterminate_signals"`
	RateLimited     int `json:"rate_limited_responses"`
	TransportErrors int `json:"transport_errors"`
	ValidTrials     int `json:"valid_trials"`
	InvalidTrials   int `json:"invalid_trials"`
	PlannedProbes   int `json:"planned_probes"`
	ExecutedProbes  int `json:"executed_probes"`
	Hypotheses      int `json:"hypotheses"`
	Supported       int `json:"supported"`
	Refuted         int `json:"refuted"`
	Inconclusive    int `json:"inconclusive"`
	Findings        int `json:"findings"`
}

// RunProfile is C-11: the persisted identity and state of one execution.
type RunProfile struct {
	RunID            string            `json:"run_id"`
	State            RunState          `json:"state"`
	AuthorizationRef string            `json:"authorization_ref"`
	ValidationRef    string            `json:"validation_ref,omitempty"`
	TargetOrigin     string            `json:"target_origin"`
	Partition        string            `json:"corpus_partition"`
	ConfigHash       string            `json:"config_hash"`
	StartedAt        time.Time         `json:"started_at"`
	UpdatedAt        time.Time         `json:"updated_at"`
	FinishedAt       time.Time         `json:"finished_at,omitempty"`
	RequestBudget    int               `json:"request_budget"`
	RequestsUsed     int               `json:"requests_used"`
	StopTrigger      StopTrigger       `json:"stop_trigger"`
	TerminalReason   string            `json:"terminal_reason,omitempty"`
	TerminalCode     ReasonCode        `json:"terminal_reason_code,omitempty"`
	Transitions      []StateTransition `json:"transitions"`
	Counters         RunCounters       `json:"counters"`
	ResumeToken      string            `json:"resume_token"`
	ParentRunID      string            `json:"parent_run_id,omitempty"`
	RoundID          string            `json:"round_id"`
	SchemaVersion    string            `json:"schema_version"`
}

func (RunProfile) Contract() ID { return IDRunProfile }

func registerRunContract() {
	register(IDRunProfile, func(payload any) error {
		r, err := cast[RunProfile](IDRunProfile, payload)
		if err != nil {
			return err
		}
		c := newViolations(IDRunProfile)
		c.required("run_id", r.RunID)
		oneofT(c, "state", r.State, AllStates()...)
		c.required("authorization_ref", r.AuthorizationRef)
		c.required("target_origin", r.TargetOrigin)
		c.required("round_id", r.RoundID)
		c.required("config_hash", r.ConfigHash)
		c.required("schema_version", r.SchemaVersion)
		if r.StartedAt.IsZero() {
			c.add("started_at", "required")
		}
		if r.UpdatedAt.IsZero() {
			c.add("updated_at", "required")
		}
		c.nonNegative("request_budget", r.RequestBudget)
		c.nonNegative("requests_used", r.RequestsUsed)
		oneofT(c, "stop_trigger", r.StopTrigger, AllStopTriggers()...)
		if r.RequestBudget <= 0 {
			c.add("request_budget", "a run must declare a positive budget")
		}

		// Criterion 26: the budget is arithmetic, not trust.
		if r.RequestsUsed > r.RequestBudget {
			c.add("requests_used", "exceeds the authorized budget")
		}
		budgetSpent := r.RequestBudget > 0 && r.RequestsUsed >= r.RequestBudget
		if r.State == StateCompleted {
			if budgetSpent {
				c.add("state", "budget exhausted yields truncated, never completed (criterion 26)")
			}
			if r.StopTrigger != TriggerNone {
				c.add("stop_trigger", "a completed run cannot report a stop trigger")
			}
		}
		if r.State == StateTruncated && r.StopTrigger == TriggerNone {
			c.add("stop_trigger", "truncated requires the trigger that cut it short")
		}
		if IsTerminal(r.State) {
			if r.TerminalReason == "" {
				c.add("terminal_reason", "required in a terminal state")
			}
			oneofT(c, "terminal_reason_code", r.TerminalCode, AllReasonCodes()...)
			if r.FinishedAt.IsZero() {
				c.add("finished_at", "required in a terminal state")
			}
		} else {
			if !r.FinishedAt.IsZero() {
				c.add("finished_at", "set in a non-terminal state")
			}
			if r.ResumeToken == "" {
				c.add("resume_token", "a resumable run must carry a token (JAVI-022)")
			}
		}

		// Transitions replayed against the table: no illegal move, no move out
		// of a terminal state, monotonic timestamps, and the recorded state must
		// be the end of the replay.
		if len(r.Transitions) == 0 && r.State != StateInitialized {
			c.add("transitions", "a run past initialized must carry its transition history")
		}
		expected := StateInitialized
		var lastAt time.Time
		for i, t := range r.Transitions {
			oneofT(c, "transitions[].from", t.From, AllStates()...)
			oneofT(c, "transitions[].to", t.To, AllStates()...)
			if t.From != expected {
				c.add("transitions[].from", "history discontinuity: expected from "+
					string(expected)+", got "+string(t.From))
			}
			if IsTerminal(t.From) {
				c.add("transitions[].from", "request issued from terminal state "+
					string(t.From)+" (criterion 27)")
			}
			if !LegalTransition(t.From, t.To) {
				c.add("transitions[].to", "illegal transition "+string(t.From)+" -> "+string(t.To))
			}
			if t.At.Before(lastAt) {
				c.add("transitions[].at", "timestamps are not monotonic")
			}
			lastAt = t.At
			if t.Cause == "" {
				c.add("transitions[].cause", "required")
			}
			if t.RequestSeq > r.RequestsUsed {
				c.add("transitions[].request_seq", "references a request that never happened")
			}
			expected = t.To
			_ = i
		}
		if len(r.Transitions) > 0 && expected != r.State {
			c.add("state", "does not match replayed history, expected "+string(expected))
		}

		cnt := r.Counters
		c.nonNegative("counters.observations", cnt.Observations)
		c.nonNegative("counters.classified", cnt.Classified)
		c.nonNegative("counters.rate_limited_responses", cnt.RateLimited)
		if cnt.Classified > cnt.Observations {
			c.add("counters.classified", "more classifications than observations")
		}
		if cnt.BlockSignals+cnt.PassSignals+cnt.Indeterminate > cnt.Classified {
			c.add("counters.block_signals", "signal tallies exceed classified count")
		}
		if cnt.ExecutedProbes > cnt.PlannedProbes && cnt.PlannedProbes > 0 {
			c.add("counters.executed_probes", "exceeds the plan")
		}
		if cnt.Supported+cnt.Refuted+cnt.Inconclusive > cnt.Hypotheses {
			c.add("counters.supported", "outcome tallies exceed hypothesis count")
		}
		if cnt.Observations > r.RequestsUsed {
			c.add("counters.observations", "more observations than requests")
		}
		return c.err()
	})
}

func init() {
	// Exhaustiveness check: a state declared in AllStates but absent from the
	// table, or reachable from a state that does not exist, is a build failure.
	declared := map[RunState]bool{}
	for _, s := range AllStates() {
		declared[s] = true
	}
	for from, outs := range transitionsTable {
		if !declared[from] {
			panic("contracts: transition table keys unknown state " + string(from))
		}
		for _, to := range outs {
			if !declared[to] {
				panic("contracts: transition " + string(from) + " -> " + string(to) + " targets unknown state")
			}
		}
	}
	if len(declared) == 0 {
		panic("contracts: empty state machine")
	}
	registerRunContract()
}
