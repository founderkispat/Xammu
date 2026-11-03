package orchestrator

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"xammu/internal/contracts"
	"xammu/internal/httpclient"
	"xammu/internal/integrity"
)

// CheckpointFile is the mutable summary of a run. The journals remain the
// evidence: the checkpoint says where a process left off, and every claim in it
// is re-derived from the journal before the next request is allowed.
const CheckpointFile = "run.json"

// ResumeOptions carries what a second process must supply. The authorizations are
// not read from the store: an approval is something someone granted, not
// something this tool may re-issue to itself by finding its own old file.
type ResumeOptions struct {
	StoreDir string
	Auth     *contracts.ProfilingAuthorization
	Val      *contracts.ValidationAuthorization
	// CircuitThreshold is the new process's own breaker setting; it is not read
	// from the checkpoint because it governs only the requests about to be sent.
	CircuitThreshold int
	// Now supplies the clock, so the window check on resume is testable.
	Now func() time.Time
}

// Load reopenss a run from its checkpoint and journals, without sending anything.
//
// It refuses, in this order: a store whose hash chain is broken, a checkpoint in
// a terminal state, a plan that no longer matches the number of probes the run
// claims to have planned, and a resume token that no longer matches the evidence.
// Each refusal is a statement that continuing would mix two runs' evidence or
// spend budget the operator never approved.
func Load(opts ResumeOptions) (*Run, error) {
	if opts.StoreDir == "" {
		return nil, errors.New("orchestrator: resume needs a store directory")
	}
	if opts.Auth == nil {
		return nil, errors.New("orchestrator: resume needs the C-09 authorization again; " +
			"a run may not renew its own permission by reading its own files")
	}
	profile, err := readCheckpoint(opts.StoreDir)
	if err != nil {
		return nil, err
	}
	if err := contracts.Validate(contracts.IDRunProfile, &profile); err != nil {
		return nil, fmt.Errorf("orchestrator: checkpoint is not a valid C-11: %w", err)
	}
	if profile.AuthorizationRef != opts.Auth.Ref {
		return nil, fmt.Errorf("orchestrator: checkpoint belongs to authorization %s, got %s",
			profile.AuthorizationRef, opts.Auth.Ref)
	}
	if err := contracts.Validate(contracts.IDProfilingAuthorization, opts.Auth); err != nil {
		return nil, fmt.Errorf("orchestrator: authorization is not usable: %w", err)
	}
	if contracts.IsTerminal(profile.State) {
		return nil, fmt.Errorf("%w: run %s ended in %s (%s); a terminal run is not resumable, "+
			"start a new run with a new identifier",
			ErrRunTerminal, profile.RunID, profile.State, profile.TerminalReason)
	}
	if profile.ResumeToken == "" {
		return nil, fmt.Errorf("orchestrator: run %s is in %s but records no resume token, "+
			"so there is nothing to match the evidence against", profile.RunID, profile.State)
	}

	store, err := integrity.Open(opts.StoreDir)
	if err != nil {
		return nil, err
	}
	if breaks := store.Verify(); len(breaks) > 0 {
		return nil, fmt.Errorf("orchestrator: refusing to resume over tampered evidence: %s",
			joinBreaks(breaks))
	}

	scope, err := scopeFor(opts.Auth, opts.Val)
	if err != nil {
		return nil, err
	}
	cfg := Config{
		RunID: profile.RunID, RoundID: profile.RoundID, StoreDir: opts.StoreDir,
		Partition: profile.Partition, TargetOrigin: profile.TargetOrigin,
		Budget: profile.RequestBudget, ParentRunID: profile.ParentRunID,
		CircuitThreshold: opts.CircuitThreshold, Now: opts.Now,
	}
	if opts.Now != nil {
		scope.Now = opts.Now
	}
	if cfg.Partition == "" || cfg.Budget <= 0 {
		return nil, fmt.Errorf("orchestrator: checkpoint for run %s is missing its partition or budget",
			profile.RunID)
	}
	// The checkpoint file is mutable and sits outside the hash chain, so its budget
	// is not trusted: the ceiling is the authorization, exactly as at Begin. Editing
	// request_budget in run.json must not be a way to buy traffic nobody approved.
	if opts.Auth.Limits.MaxRequests > 0 && cfg.Budget > opts.Auth.Limits.MaxRequests {
		return nil, fmt.Errorf("orchestrator: the checkpoint claims a budget of %d requests, "+
			"above the authorized maximum %d", cfg.Budget, opts.Auth.Limits.MaxRequests)
	}
	if cfg.CircuitThreshold <= 0 {
		cfg.CircuitThreshold = DefaultCircuitThreshold
	}

	items, err := loadPlan(store)
	if err != nil {
		return nil, err
	}
	if len(items) == 0 && isPrePlanning(profile.State) {
		// The run was interrupted before it had a plan, which is a legal state to
		// leave behind: there is nothing to re-send and no plan to guard. The
		// operator plans it again under the same authorization, and until then Send
		// refuses everything because nothing was approved.
	} else {
		if len(items) != profile.Counters.PlannedProbes {
			return nil, fmt.Errorf("%w: the checkpoint planned %d probes but the plan journal holds %d",
				ErrResumeMismatch, profile.Counters.PlannedProbes, len(items))
		}
		if err := ValidatePlan(items, opts.Auth, scope, cfg.Budget); err != nil {
			return nil, fmt.Errorf("orchestrator: the journaled plan no longer satisfies the "+
				"authorization, so it will not be re-sent: %w", err)
		}
	}

	client := httpclient.New(scope, cfg.Budget)
	// The budget is a total for the run, not a per-process allowance. Restoring the
	// spent count is what stops a resume from buying traffic the operator never
	// approved.
	if profile.RequestsUsed > 0 {
		if err := client.RestoreUsage(profile.RequestsUsed); err != nil {
			return nil, fmt.Errorf("orchestrator: cannot restore the spent budget: %w", err)
		}
	}

	r := &Run{
		store: store, scope: scope, auth: opts.Auth, val: opts.Val, cfg: cfg,
		client: client, items: items, executed: map[string]bool{},
		profile:     profile,
		trigger:     contracts.TriggerNone,
		refusalSeen: len(client.Refusals()),
	}
	if err := r.recount(); err != nil {
		return nil, err
	}
	// The configuration hash covers the authorization, the target, the budget, the
	// partition and the accepted plan, so it is re-derived rather than believed: a
	// run.json edited to describe a different run hashes to something else here,
	// before any request is sent under the new reading.
	if want := r.configHash(); want != profile.ConfigHash {
		return nil, fmt.Errorf("%w: the checkpoint records configuration %s, but the run this "+
			"resume would continue hashes to %s; the summary was edited or belongs to another run",
			ErrResumeMismatch, shortHash(profile.ConfigHash), shortHash(want))
	}
	// The token is recomputed from the same material the previous process used:
	// run identity, journal heads and budget arithmetic. Any edit, truncation or
	// substitution of the evidence changes it, and the run refuses to continue
	// rather than appending to a journal it no longer recognises.
	want := r.computeToken()
	if want != profile.ResumeToken {
		return nil, fmt.Errorf("%w: expected %s, the journals now hash to %s; "+
			"the evidence directory does not describe the run the checkpoint recorded",
			ErrResumeMismatch, profile.ResumeToken, want)
	}
	return r, nil
}

// shortHash trims a digest for an error message. The full value is in the files;
// a message that buries the comparison under 64 hex characters helps nobody.
func shortHash(digest string) string {
	if len(digest) > 22 {
		return digest[:22]
	}
	return digest
}

// isPrePlanning reports the states a run can occupy with no plan accepted yet. A
// plan journal empty in any later state is not an empty plan, it is evidence that
// went missing.
func isPrePlanning(s contracts.RunState) bool {
	switch s {
	case contracts.StateInitialized, contracts.StateAuthorizationPending, contracts.StateAuthorized:
		return true
	default:
		return false
	}
}

func readCheckpoint(dir string) (contracts.RunProfile, error) {
	raw, err := os.ReadFile(filepath.Join(dir, CheckpointFile))
	if err != nil {
		return contracts.RunProfile{}, fmt.Errorf("orchestrator: no checkpoint to resume from in %s: %w", dir, err)
	}
	var p contracts.RunProfile
	if err := json.Unmarshal(raw, &p); err != nil {
		return contracts.RunProfile{}, fmt.Errorf("orchestrator: checkpoint is not readable JSON: %w", err)
	}
	return p, nil
}

func loadPlan(store *integrity.Store) ([]PlanItem, error) {
	recs, err := store.Records(integrity.StreamPlan)
	if err != nil {
		return nil, err
	}
	items := make([]PlanItem, 0, len(recs))
	for _, rec := range recs {
		var p PlanItem
		if err := json.Unmarshal(rec.Payload, &p); err != nil {
			return nil, fmt.Errorf("orchestrator: plan record %d is unreadable: %w", rec.Seq, err)
		}
		items = append(items, p)
	}
	return items, nil
}

func joinBreaks(breaks []integrity.Break) string {
	out := make([]string, 0, len(breaks))
	for _, b := range breaks {
		out = append(out, b.String())
	}
	return strings.Join(out, "; ")
}

// Resume loads a run and re-enters the executing state, so a caller that only
// wants to continue does not have to know which paused states the table allows.
func Resume(opts ResumeOptions, cause string) (*Run, error) {
	r, err := Load(opts)
	if err != nil {
		return nil, err
	}
	if r.profile.State != contracts.StateExecuting {
		if err := r.ResumeExecution(cause); err != nil {
			return nil, err
		}
	}
	return r, nil
}
