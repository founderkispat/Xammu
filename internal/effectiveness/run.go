package effectiveness

import (
	"context"
	"errors"
	"fmt"
	"time"

	"xammu/internal/contracts"
	"xammu/internal/corpus"
	"xammu/internal/httpclient"
	"xammu/internal/integrity"
	"xammu/internal/tamper"
)

// Trial is one planned exchange: a case measured on one arm. The baseline arm
// carries no stack; the tamper arm carries the stack the operator forced or the
// fingerprint selected.
type Trial struct {
	Case           Case
	Arm            Arm
	Stack          tamper.Stack
	SelectionBasis string
}

// RunResult is what the executor observed, for the operator summary. Requests
// Sent counts only this invocation, so two arms can share one budget ledger.
type RunResult struct {
	Outcomes     []Outcome
	RequestsSent int
	Refusals     int
	Stopped      string
	Failures     []string
	CaseCount    int
}

// Run journals the case list and executes the baseline arm. It is the Phase 1
// entry point; Phase 2 composes arms through JournalCases and RunArm.
func Run(ctx context.Context, client *httpclient.Client, store *integrity.Store,
	auth *contracts.ProfilingAuthorization, runID, origin, pathOverride string,
	cases []Case, now func() time.Time) (*RunResult, error) {
	if err := JournalCases(store, cases); err != nil {
		return nil, err
	}
	trials := make([]Trial, 0, len(cases))
	for _, c := range cases {
		trials = append(trials, Trial{Case: c, Arm: ArmBaseline})
	}
	return RunArm(ctx, client, store, auth, runID, origin, pathOverride, trials,
		corpus.DefaultPolicy(), now)
}

// JournalCases writes E-01 once per corpus case. Arms share the case list.
func JournalCases(store *integrity.Store, cases []Case) error {
	for _, c := range cases {
		if _, err := store.Append(integrity.StreamEffectivenessCases, c); err != nil {
			return fmt.Errorf("effectiveness: cannot journal case %s: %w", c.ID, err)
		}
	}
	return nil
}

// RunArm sends one arm and journals each outcome. A trial whose transformed
// value fails the inertness gate is recorded as excluded, never sent. It stops
// on the same conditions the client enforces: an expired window, an exhausted
// budget, a 429 halt or an operator interrupt.
func RunArm(ctx context.Context, client *httpclient.Client, store *integrity.Store,
	auth *contracts.ProfilingAuthorization, runID, origin, pathOverride string,
	trials []Trial, gate corpus.Policy, now func() time.Time) (*RunResult, error) {
	if auth == nil {
		return nil, errors.New("effectiveness: a run needs an authorization")
	}
	if now == nil {
		now = time.Now
	}
	startUsed := client.Ledger().Used()
	res := &RunResult{CaseCount: len(trials)}
	journaled := func(o Outcome) error {
		if _, err := store.Append(integrity.StreamEffectivenessOutcomes, o); err != nil {
			return fmt.Errorf("effectiveness: cannot journal outcome for %s: %w", o.CaseID, err)
		}
		res.Outcomes = append(res.Outcomes, o)
		return nil
	}

	for _, trial := range trials {
		if err := ctx.Err(); err != nil {
			res.Stopped = "operator_halt"
			break
		}
		if t := now().UTC(); t.Before(auth.IssuedAt) || t.After(auth.ExpiresAt) {
			res.Stopped = "authorization_window_closed"
			break
		}

		value, renderErr := RenderValue(trial.Case, trial.Stack, gate.MarkerToken)
		if renderErr != nil {
			o := trialOutcome(trial, runID, now(), VerdictExcluded, "invalid_probe", "invalid_probe")
			if err := journaled(o); err != nil {
				return res, err
			}
			res.Failures = append(res.Failures, trial.Case.ID+": "+renderErr.Error())
			continue
		}
		if refusal := transformedRefusal(trial.Stack, value, gate, trial.Case.Kind == KindBenign); refusal != "" {
			o := trialOutcome(trial, runID, now(), VerdictExcluded,
				"tamper_gate_refused", "tamper_gate_refused")
			o.TamperDigest = contracts.NewDigest([]byte(value))
			if err := journaled(o); err != nil {
				return res, err
			}
			res.Refusals++
			res.Failures = append(res.Failures, trial.Case.ID+": "+refusal)
			continue
		}

		req, err := BuildTrialRequest(origin, trial.Case, pathOverride, trial.Stack, gate.MarkerToken)
		if err != nil {
			o := trialOutcome(trial, runID, now(), VerdictExcluded, "invalid_probe", "invalid_probe")
			if err := journaled(o); err != nil {
				return res, err
			}
			res.Failures = append(res.Failures, trial.Case.ID+": "+err.Error())
			continue
		}
		if err := client.Scope().CheckRequest(req.Method, req.URL, req.ProbeRef); err != nil {
			o := trialOutcome(trial, runID, now(), VerdictExcluded, "policy_refusal", "policy_refusal")
			if err := journaled(o); err != nil {
				return res, err
			}
			res.Refusals++
			res.Failures = append(res.Failures, trial.Case.ID+": "+err.Error())
			continue
		}

		resp, err := client.Do(ctx, req)
		if err != nil {
			switch {
			case errors.Is(err, httpclient.ErrBudgetExhausted):
				res.Stopped = "budget_exhausted"
				res.RequestsSent = client.Ledger().Used() - startUsed
				return res, nil
			case errors.Is(err, httpclient.ErrHalted):
				res.Stopped = "halted"
				res.RequestsSent = client.Ledger().Used() - startUsed
				return res, nil
			case errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded):
				res.Stopped = "operator_halt"
				res.RequestsSent = client.Ledger().Used() - startUsed
				return res, nil
			case resp != nil:
				o := Classify(runID, trial.Case, resp, now())
				applyTrial(&o, trial, value)
				if jerr := journaled(o); jerr != nil {
					return res, jerr
				}
				if o.Verdict == VerdictExcluded {
					res.Failures = append(res.Failures, trial.Case.ID+": "+o.ExclusionReason)
				}
				continue
			default:
				o := trialOutcome(trial, runID, now(), VerdictExcluded, "policy_refusal", "policy_refusal")
				if jerr := journaled(o); jerr != nil {
					return res, jerr
				}
				res.Refusals++
				res.Failures = append(res.Failures, trial.Case.ID+": "+err.Error())
				continue
			}
		}
		o := Classify(runID, trial.Case, resp, now())
		applyTrial(&o, trial, value)
		if err := journaled(o); err != nil {
			return res, err
		}
		if o.Verdict == VerdictExcluded {
			res.Failures = append(res.Failures, trial.Case.ID+": "+o.ExclusionReason)
		}
		if resp.RateLimited {
			res.Stopped = "rate_limited"
			res.RequestsSent = client.Ledger().Used() - startUsed
			return res, nil
		}
	}
	res.RequestsSent = client.Ledger().Used() - startUsed
	return res, nil
}

// transformedRefusal re-checks the value a tamper stack produced. Two rules are
// tolerated: an absent inline marker when the trial carries the diagnostic header
// instead, and the same absence on a benign case, whose traffic never carries the
// probe token by design. Every other hit means the transform produced traffic the
// gate would not have admitted, so it is not sent.
func transformedRefusal(stack tamper.Stack, value string, gate corpus.Policy, benign bool) string {
	if len(stack) == 0 {
		return ""
	}
	for _, f := range gate.Check(value) {
		if f.Rule == "inert.marker_absent" && (benign || stack.NeedsMarkerHeader()) {
			continue
		}
		return f.Rule + ": " + f.Reason
	}
	return ""
}

func trialOutcome(trial Trial, runID string, at time.Time, verdict Verdict,
	basis, reason string) Outcome {
	o := Outcome{
		CaseID: trial.Case.ID, RunID: runID, ObservedAt: at.UTC(),
		Verdict: verdict, Basis: basis, ExclusionReason: reason,
		SecurityHeaders: map[string]bool{},
		Arm:             NormalizeArm(trial.Arm),
		SelectionBasis:  trial.SelectionBasis,
		TamperStack:     append([]contracts.Tamper(nil), trial.Stack...),
	}
	return o
}

func applyTrial(o *Outcome, trial Trial, value string) {
	o.Arm = NormalizeArm(trial.Arm)
	o.SelectionBasis = trial.SelectionBasis
	o.TamperStack = append([]contracts.Tamper(nil), trial.Stack...)
	o.MarkerHeader = trial.Stack.NeedsMarkerHeader()
	if len(trial.Stack) > 0 {
		o.TamperDigest = contracts.NewDigest([]byte(value))
	}
}
