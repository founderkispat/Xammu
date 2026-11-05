package effectiveness

import (
	"context"
	"errors"
	"fmt"
	"time"

	"xammu/internal/contracts"
	"xammu/internal/httpclient"
	"xammu/internal/integrity"
)

// RunResult is what the executor observed, for the operator summary.
type RunResult struct {
	Outcomes     []Outcome
	RequestsSent int
	Refusals     int
	Stopped      string
	Failures     []string
	CaseCount    int
}

// Run journals the case list, sends each case through the client and journals
// each outcome. It stops on the same conditions the client enforces: an expired
// window, an exhausted budget, a 429 halt or an operator interrupt. A case that
// could not be rendered is recorded as excluded; it is never sent approximately.
func Run(ctx context.Context, client *httpclient.Client, store *integrity.Store,
	auth *contracts.ProfilingAuthorization, runID, origin, pathOverride string,
	cases []Case, now func() time.Time) (*RunResult, error) {
	if auth == nil {
		return nil, errors.New("effectiveness: a run needs an authorization")
	}
	if now == nil {
		now = time.Now
	}
	for _, c := range cases {
		if _, err := store.Append(integrity.StreamEffectivenessCases, c); err != nil {
			return nil, fmt.Errorf("effectiveness: cannot journal case %s: %w", c.ID, err)
		}
	}
	res := &RunResult{CaseCount: len(cases)}
	journaled := func(o Outcome) error {
		if _, err := store.Append(integrity.StreamEffectivenessOutcomes, o); err != nil {
			return fmt.Errorf("effectiveness: cannot journal outcome for %s: %w", o.CaseID, err)
		}
		res.Outcomes = append(res.Outcomes, o)
		return nil
	}

	for _, c := range cases {
		if err := ctx.Err(); err != nil {
			res.Stopped = "operator_halt"
			break
		}
		if t := now().UTC(); t.Before(auth.IssuedAt) || t.After(auth.ExpiresAt) {
			res.Stopped = "authorization_window_closed"
			break
		}
		req, err := BuildRequest(origin, c, pathOverride)
		if err != nil {
			o := Outcome{CaseID: c.ID, RunID: runID, ObservedAt: now().UTC(),
				Verdict: VerdictExcluded, Basis: "invalid_probe",
				ExclusionReason: "invalid_probe", SecurityHeaders: map[string]bool{}}
			if err := journaled(o); err != nil {
				return res, err
			}
			res.Failures = append(res.Failures, c.ID+": "+err.Error())
			continue
		}
		if err := client.Scope().CheckRequest(req.Method, req.URL, req.ProbeRef); err != nil {
			o := Outcome{CaseID: c.ID, RunID: runID, ObservedAt: now().UTC(),
				Verdict: VerdictExcluded, Basis: "policy_refusal",
				ExclusionReason: "policy_refusal", SecurityHeaders: map[string]bool{}}
			if err := journaled(o); err != nil {
				return res, err
			}
			res.Refusals++
			res.Failures = append(res.Failures, c.ID+": "+err.Error())
			continue
		}

		resp, err := client.Do(ctx, req)
		if err != nil {
			switch {
			case errors.Is(err, httpclient.ErrBudgetExhausted):
				res.Stopped = "budget_exhausted"
				res.RequestsSent = client.Ledger().Used()
				return res, nil
			case errors.Is(err, httpclient.ErrHalted):
				res.Stopped = "halted"
				res.RequestsSent = client.Ledger().Used()
				return res, nil
			case errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded):
				res.Stopped = "operator_halt"
				res.RequestsSent = client.Ledger().Used()
				return res, nil
			case resp != nil:
				o := Classify(runID, c, resp, now())
				if jerr := journaled(o); jerr != nil {
					return res, jerr
				}
				if o.Verdict == VerdictExcluded {
					res.Failures = append(res.Failures, c.ID+": "+o.ExclusionReason)
				}
				continue
			default:
				o := Outcome{CaseID: c.ID, RunID: runID, ObservedAt: now().UTC(),
					Verdict: VerdictExcluded, Basis: "policy_refusal",
					ExclusionReason: "policy_refusal", SecurityHeaders: map[string]bool{}}
				if jerr := journaled(o); jerr != nil {
					return res, jerr
				}
				res.Refusals++
				res.Failures = append(res.Failures, c.ID+": "+err.Error())
				continue
			}
		}
		o := Classify(runID, c, resp, now())
		if err := journaled(o); err != nil {
			return res, err
		}
		if o.Verdict == VerdictExcluded {
			res.Failures = append(res.Failures, c.ID+": "+o.ExclusionReason)
		}
		if resp.RateLimited {
			res.Stopped = "rate_limited"
			res.RequestsSent = client.Ledger().Used()
			return res, nil
		}
	}
	res.RequestsSent = client.Ledger().Used()
	return res, nil
}
