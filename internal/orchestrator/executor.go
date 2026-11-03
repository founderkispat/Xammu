package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"time"

	"xammu/internal/contracts"
)

// Step performs the pipeline work for one planned probe: send it through the
// run's single egress, journal the observation, classify it. The orchestrator
// deliberately does not know what a step does with a response, because the
// executor that owns the state machine must not also own the interpretation of
// evidence. A step that does not journal its own observation leaves the probe
// pending, and a pending probe makes the run truncated rather than completed.
type Step func(ctx context.Context, r *Run, item PlanItem) error

// ProbeFailure is one probe whose step returned an error. It is kept with the
// reference so a report can name exactly which planned exchanges produced no
// evidence, instead of reporting a count the reader has to trust.
type ProbeFailure struct {
	Ref    string
	Cause  string
	At     time.Time
	SentAt time.Time
}

func (f ProbeFailure) Error() string { return f.Ref + ": " + f.Cause }

// Execution is the executor's account of one Execute call.
type Execution struct {
	// Executed lists the probes the journal has evidence for, in plan order. It
	// is read back from the journal rather than accumulated, so it cannot claim
	// more work than the files on disk show.
	Executed []string
	Failures []ProbeFailure
	// Stopped says why the loop finished, in a sentence an operator can act on.
	Stopped string
	// RequestsSent is the ledger's count at the end of the loop.
	RequestsSent int
}

// Execute walks the pending plan in order and runs one step per probe.
//
// It stops on the first condition that forbids traffic, and it never decides the
// run's outcome: budget exhaustion, a 429, a tripped circuit and an operator's
// cancellation each leave the run in the state Send put it in, and Finalize reads
// the terminal state from the ledger's arithmetic. Retrying a probe is not
// offered, because a retry is a second request against someone's system and that
// is an authorization decision, not a loop decision.
func (r *Run) Execute(ctx context.Context, step Step) (*Execution, error) {
	if step == nil {
		return nil, errors.New("orchestrator: execute needs a step; a plan run by no step " +
			"would journal nothing and truncate the run as if the target refused")
	}
	ex := &Execution{Executed: []string{}, Failures: []ProbeFailure{}}
	tried := map[string]bool{}

	for {
		if err := ctx.Err(); err != nil {
			ex.Stopped = "context ended before the next probe: " + err.Error()
			if haltErr := r.Halt(contracts.TriggerOperator, ex.Stopped); haltErr != nil {
				if !errors.Is(haltErr, ErrIllegalTransition) {
					return ex, haltErr
				}
			}
			break
		}

		state := r.Profile().State
		if state != contracts.StateExecuting {
			ex.Stopped = fmt.Sprintf("run is in state %s, so no further request may leave", state)
			break
		}
		if left := r.client.Ledger().Remaining(); left <= 0 {
			r.mu.Lock()
			r.noteStop(contracts.TriggerBudgetExhausted,
				fmt.Sprintf("the authorized budget of %d requests is spent", r.cfg.Budget))
			r.mu.Unlock()
			ex.Stopped = fmt.Sprintf("authorized budget of %d requests is spent", r.cfg.Budget)
			break
		}

		pending, err := r.Pending()
		if err != nil {
			return ex, err
		}
		var item PlanItem
		var found bool
		for _, p := range pending {
			if !tried[p.Ref] {
				item, found = p, true
				break
			}
		}
		if !found {
			if len(pending) > 0 {
				ex.Stopped = fmt.Sprintf("%d planned probes have no evidence in the journal "+
					"and none may be attempted twice in one run", len(pending))
			} else {
				ex.Stopped = "plan exhausted: every probe has evidence in the journal"
			}
			break
		}
		tried[item.Ref] = true

		stepErr := step(ctx, r, item)
		if stepErr != nil {
			ex.Failures = append(ex.Failures, ProbeFailure{
				Ref: item.Ref, Cause: stepErr.Error(), At: r.now(),
			})
		}

		// The evidence, not the step's return value, decides what counts as done.
		after, err := r.Pending()
		if err != nil {
			return ex, err
		}
		if stillPending(after, item.Ref) && stepErr == nil {
			ex.Failures = append(ex.Failures, ProbeFailure{
				Ref: item.Ref, At: r.now(),
				Cause: "step returned without an error but left no observation in the journal",
			})
		}
		if !stillPending(after, item.Ref) {
			ex.Executed = append(ex.Executed, item.Ref)
		}
	}

	// A send that was refused because the run had already stopped is reported, not
	// swallowed: the operator needs to see that the loop asked for traffic the state
	// machine denied.
	_, sent, _ := r.client.Ledger().Stats()
	ex.RequestsSent = sent
	if len(ex.Failures) > 0 && ex.Stopped == "" {
		ex.Stopped = fmt.Sprintf("%d probes failed; see the failure list", len(ex.Failures))
	}
	return ex, nil
}

func stillPending(items []PlanItem, ref string) bool {
	for _, p := range items {
		if p.Ref == ref {
			return true
		}
	}
	return false
}
