// Package report assembles the C-15 delivery from the evidence a finished run left
// behind.
//
// The layer above it (discover) decides what may be claimed; this layer decides how
// the claims are read. Two rules govern the whole package:
//
//  1. Every number in a report is re-derived from the pass and the counters, never
//     carried over from a description. A report that says "the run covered 12 of 63
//     authorized cells" computes 12 and 63 from the matrix it is about to publish, so
//     the sentence and the table cannot disagree. That is the only reason a reader
//     can trust a summary they did not recompute themselves.
//
//  2. The assembled report is validated against C-15 before Build returns. A report
//     with a missing dimension, a merged residual-risk block, a distribution whose
//     denominator absorbed the indeterminate bucket, or a matrix that claims to have
//     measured everything is an error out of this package, not a document someone can
//     hand to a client. The seven questions of section 2 are answered because the
//     contract forces the five dimensions to cover them, not because the author
//     remembered.
//
// The five dimensions are the report's shape, and each one is answerable only from
// material the run produced:
//
//   - coverage (questions 1 and 3): the authorized class x transport grid, the cells
//     with a valid reading, and the ones without -- listed, never dropped.
//   - behavior (question 2): what the front end did with the exchanges, as signal
//     counts over a stated population, plus the reference cluster those counts are
//     contrasted against.
//   - attribution (question 5): how far the evidence places the cause on the defence
//     rather than on the origin, the proxy, a rate limiter or the harness.
//   - discovery (questions 4 and 6): the findings themselves, their claim ceilings
//     and the actions a reviewer can take today.
//   - uncertainty (question 7): the undetermined areas, the unrun items, the state of
//     the evidence trail, and the three residual-risk scenarios kept apart.
package report

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"xammu/internal/contracts"
	"xammu/internal/discover"
	"xammu/internal/inference"
)

// EvidenceFacts are the reproducibility fields of the report. They name where the
// evidence lives and which machinery produced it, so a reader holding the bundle can
// check the report instead of trusting the process that wrote it.
type EvidenceFacts struct {
	// ManifestPath is the artifact directory or file the C-12 manifest was written
	// to, and ManifestDigest is the digest of that file as it now stands.
	ManifestPath    string
	ManifestDigest  string
	VerifyCommand   string
	CorpusCommitRef string
	DetectorSetHash string
	ToolVersion     string
}

// Input is everything a report is allowed to state. Nothing here is prose: each
// field is a record set another package already validated.
type Input struct {
	Run  contracts.RunProfile
	Auth *contracts.ProfilingAuthorization
	Pass *inference.Result

	// Findings is the discovery layer's output for this pass. Its findings are
	// copied into the report as they stand: this package renders C-16 records, it
	// does not rewrite them.
	Findings *discover.Report

	// Unplanned lets a zone state how many requests the run never spent.
	Unplanned []discover.Unplanned

	Evidence    EvidenceFacts
	GeneratedBy string
	GeneratedAt time.Time

	// CommandFlags carries the operator's placement choices so a playbook command
	// printed by this report re-plans the same exchanges rather than a different set.
	// The CLI that re-reads the bundle takes the same flags, so what a reviewer pastes
	// is what the run used.
	CommandFlags string
}

// withFlags appends the carried placement flags to a command that shares them.
func (in Input) withFlags(cmd string) string {
	if in.CommandFlags == "" {
		return cmd
	}
	return cmd + " " + in.CommandFlags
}

// Build assembles and validates the C-15 report for one finished run.
func Build(in Input) (*contracts.Report, error) {
	if err := in.check(); err != nil {
		return nil, err
	}
	grid := authorizedGrid(in.Auth)
	matrix, facts := buildMatrix(in, grid)
	dists := buildDistributions(in, facts)
	findings := append([]contracts.DiscoveryFinding(nil), in.Findings.Findings...)
	sortFindings(findings)

	zones := unevaluatedZones(in, matrix)
	rep := &contracts.Report{
		ReportID:                contracts.NewUUID(),
		RunID:                   in.Run.RunID,
		GeneratedAt:             in.GeneratedAt.UTC(),
		SchemaVersion:           contracts.SchemaVersion.String(),
		AuthorizationRef:        in.Auth.Ref,
		AuthorizationValidUntil: in.Auth.ExpiresAt.UTC(),
		RunState:                in.Run.State,
		StateReason:             stateReason(in.Run),
		TargetOrigin:            in.Run.TargetOrigin,
		Partition:               in.Run.Partition,
		DurationSeconds:         durationSeconds(in.Run),
		RequestsUsed:            in.Run.RequestsUsed,
		RequestBudget:           in.Run.RequestBudget,
		LimitsSummary:           limitsSummary(in),
		ExecutiveSummary:        executiveSummary(in, facts, findings),
		Dimensions:              dimensions(in, matrix, facts, dists, findings, zones),
		Findings:                findings,
		Matrix:                  matrix,
		ResidualRisk:            residualRisk(in, matrix, facts, findings),
		Unevaluated:             zones,
		UnevaluatedNone:         len(zones) == 0,
		Distributions:           dists,
		Evidence:                evidenceSection(in),
		ContractVersions:        contractVersions(),
		OutOfScope:              append([]string(nil), contracts.RequiredOutOfScope...),
	}
	if err := contracts.Validate(contracts.IDReport, rep); err != nil {
		return nil, fmt.Errorf("report: the assembled C-15 is not publishable: %w", err)
	}
	return rep, nil
}

// check refuses an input that could not produce an honest report. Each message names
// the missing fact rather than a general "invalid input", because the operator has to
// know which step of the pipeline was skipped.
func (in Input) check() error {
	if in.Auth == nil {
		return fmt.Errorf("report: no C-09 authorization supplied: a report states what was " +
			"authorized as well as what was measured, and it cannot invent the first")
	}
	if in.Pass == nil {
		return fmt.Errorf("report: no inference pass supplied: the counts in a report are " +
			"derived from classified exchanges, so a report without them would be a template")
	}
	if in.Findings == nil {
		return fmt.Errorf("report: no discovery findings supplied: run discover over this pass " +
			"before asking for a report")
	}
	if len(in.Pass.Verdicts) == 0 {
		return fmt.Errorf("report: the pass graded %d cell(s): a report of an empty pass would "+
			"state coverage it never measured", len(in.Pass.Verdicts))
	}
	if in.Run.State == contracts.StateExecuting || in.Run.State == contracts.StatePlanned ||
		in.Run.State == contracts.StatePlanning || in.Run.State == contracts.StateInitialized ||
		in.Run.State == contracts.StateAuthorizationPending || in.Run.State == contracts.StateAuthorized ||
		in.Run.State == contracts.StateFinalizing {
		return fmt.Errorf("report: run %s is in %s: a report is issued from a stopped run, "+
			"because a run still in progress has no coverage to state", in.Run.RunID, in.Run.State)
	}
	for _, f := range []struct{ name, value string }{
		{"manifest path", in.Evidence.ManifestPath},
		{"manifest digest", in.Evidence.ManifestDigest},
		{"verify command", in.Evidence.VerifyCommand},
		{"corpus commit ref", in.Evidence.CorpusCommitRef},
		{"detector set hash", in.Evidence.DetectorSetHash},
		{"tool version", in.Evidence.ToolVersion},
		{"generated by", in.GeneratedBy},
	} {
		if strings.TrimSpace(f.value) == "" {
			return fmt.Errorf("report: %s is required: the evidence section is what makes a "+
				"report checkable, and an empty field is not a fact", f.name)
		}
	}
	if in.GeneratedAt.IsZero() {
		return fmt.Errorf("report: no generation timestamp supplied")
	}
	return nil
}

// stateReason says why the run is not sending any more. The terminal reason is only
// written when a run reaches a terminal state, so a paused or halted profile falls
// back to the cause of the transition that stopped it: "the run stopped" is a fact,
// and the transition journal holds it.
func stateReason(run contracts.RunProfile) string {
	if run.TerminalReason != "" {
		return run.TerminalReason
	}
	if len(run.Transitions) > 0 {
		last := run.Transitions[len(run.Transitions)-1]
		return fmt.Sprintf("state %s entered from %s: %s", last.To, last.From, last.Cause)
	}
	return fmt.Sprintf("state %s recorded no cause", run.State)
}

func durationSeconds(run contracts.RunProfile) int {
	end := run.FinishedAt
	if end.IsZero() {
		end = run.UpdatedAt
	}
	if end.Before(run.StartedAt) {
		return 0
	}
	return int(end.Sub(run.StartedAt).Seconds())
}

func contractVersions() map[string]string {
	out := make(map[string]string, len(contracts.IDs()))
	v := contracts.SchemaVersion.String()
	for _, id := range contracts.IDs() {
		out[string(id)] = v
	}
	return out
}

func evidenceSection(in Input) contracts.EvidenceSection {
	var rounds []string
	seen := map[string]bool{}
	for _, v := range in.Pass.Verdicts {
		for _, r := range v.Cell.RoundIDs {
			if r != "" && !seen[r] {
				seen[r] = true
				rounds = append(rounds, r)
			}
		}
	}
	sort.Strings(rounds)
	if len(rounds) == 0 && in.Run.RoundID != "" {
		rounds = []string{in.Run.RoundID}
	}
	return contracts.EvidenceSection{
		ManifestPath:     in.Evidence.ManifestPath,
		ManifestDigest:   in.Evidence.ManifestDigest,
		VerifyCommand:    in.Evidence.VerifyCommand,
		ObservationCount: observationCount(in),
		RoundIDs:         rounds,
		CorpusCommitRef:  in.Evidence.CorpusCommitRef,
		DetectorSetHash:  in.Evidence.DetectorSetHash,
		ToolVersion:      in.Evidence.ToolVersion,
		GeneratedByUser:  in.GeneratedBy,
	}
}

// observationCount prefers the journal's own tally. The profile's counters are
// re-derived from the store at finalize, so they are the count of records that exist
// rather than of records a stage claimed to write.
func observationCount(in Input) int {
	if in.Run.Counters.Observations > 0 {
		return in.Run.Counters.Observations
	}
	var n int
	for _, v := range in.Pass.Verdicts {
		n += len(v.Cell.Trials)
	}
	return n
}

// limitsSummary states the bounds the run could not exceed. These are the numbers a
// reader needs to judge whether the coverage is wide enough to mean anything.
func limitsSummary(in Input) []string {
	a := in.Auth
	l := a.Limits
	out := []string{
		fmt.Sprintf("request budget: %d of %d authorized requests spent (%d left); the client "+
			"refuses a request beyond the budget rather than overshooting",
			in.Run.RequestsUsed, in.Run.RequestBudget, in.Run.RequestBudget-in.Run.RequestsUsed),
		fmt.Sprintf("pacing: at most %d request(s) per second, at most %d concurrent, %d ms timeout",
			l.RatePerSecond, l.MaxConcurrent, l.TimeoutMS),
		fmt.Sprintf("redirects: at most %d, and only to a location the authorization lists; an "+
			"unlisted redirect target ends the request as a refusal, not a follow", l.MaxRedirects),
		fmt.Sprintf("response retention: policy %q, at most %d byte(s) of a body kept in the journal; "+
			"the full body is out of the process before classification", a.Retention, l.MaxBodyRetainBytes),
		fmt.Sprintf("scope: %d origin(s), %d method(s), %d attack class(es), %d transport(s), %d "+
			"encoding(s); anything outside that list was refused before the socket",
			len(a.Origins), len(a.Methods), len(a.AllowedClasses), len(a.AllowedVectors),
			len(a.AllowedEncodings)),
		fmt.Sprintf("authorization %s is valid until %s; every reproduction command in this report is "+
			"bound to that reference, and a run may not place a request after that instant",
			a.Ref, a.ExpiresAt.UTC().Format(time.RFC3339)),
		"the inertness gate re-runs when the corpus loads: a probe that can execute never reaches " +
			"the transport, so no limit here is what keeps the run non-exploitative",
		fmt.Sprintf("transport: %d exchange(s) produced no response to classify; a run that hits this "+
			"repeatedly in a row pauses rather than reporting a clean pass, because silence from a target "+
			"is not a refusal", in.Run.Counters.TransportErrors),
		fmt.Sprintf("the run stopped as %q (%s), so coverage in this report is bounded by what it reached "+
			"before that, not by the plan it was given", in.Run.State, in.Run.StopTrigger),
	}
	// A report written after its permission lapsed is normal -- analysis happens
	// later than the run -- but the reader has to know that the reproduction commands
	// below it are no longer executable under the authorization they cite.
	if in.GeneratedAt.After(a.ExpiresAt) {
		out = append(out, fmt.Sprintf(
			"this report was generated at %s, after authorization %s expired: the readings were taken inside "+
				"the window, but every command in this document needs a new authorization to actually be run",
			in.GeneratedAt.UTC().Format(time.RFC3339), a.Ref))
	}
	return out
}

// executiveSummary is the block a reader who will not open the matrix still has to be
// able to trust. Every line carries its own numbers and none of them is a conclusion
// the findings section does not support.
func executiveSummary(in Input, facts coverageFacts,
	findings []contracts.DiscoveryFinding) []string {
	types := map[contracts.FindingType]int{}
	for _, f := range findings {
		types[f.FindingType]++
	}
	var typeParts []string
	for _, ty := range contracts.AllFindingTypes() {
		if n := types[ty]; n > 0 {
			typeParts = append(typeParts, fmt.Sprintf("%s %d", ty, n))
		}
	}
	if len(typeParts) == 0 {
		typeParts = append(typeParts, "none")
	}
	ceiling := strongestClaim(findings)
	level := strongestLevel(findings)
	return []string{
		fmt.Sprintf("One run behind one authorized egress: %s sent %d of %d authorized requests to %s "+
			"from corpus partition %s in %d second(s), and stopped in state %q.",
			in.Run.RunID, in.Run.RequestsUsed, in.Run.RequestBudget, in.Run.TargetOrigin,
			in.Run.Partition, durationSeconds(in.Run), in.Run.State),
		fmt.Sprintf("Of %d classified probe exchange(s) in the graded cells, %d valid trial(s) carried the "+
			"interstitial shape of a refusal and %d the shape of ordinary handling; %d indeterminate and %d "+
			"invalid trial(s) are outside every rate in this report rather than inside a denominator.",
			facts.ValidTrials+facts.Inconclusive+facts.Invalid, facts.Refused, facts.HandledOrdinary,
			facts.Inconclusive, facts.Invalid),
		fmt.Sprintf("The pass published %d finding(s): %s.", len(findings), strings.Join(typeParts, ", ")),
		fmt.Sprintf("The strongest claim any finding makes is %q, at evidence level %q. C-08 derives that "+
			"ceiling from the counts; nothing in this report rises above it, and a claim of a specific rule "+
			"firing would need a source outside the HTTP response.",
			ceiling, level),
		fmt.Sprintf("Coverage of the authorized grid: %d of %d class x transport cell(s) hold at least one "+
			"valid reading; %d entry(ies) are listed as unmeasured, each with the reason it has.",
			facts.PairsWithSignal, facts.GridPairs, facts.UnmeasuredCells),
		fmt.Sprintf("Reproduce it: %s re-derives the evidence trail; every finding carries a command bound "+
			"to authorization %s or to run %s.", in.Evidence.VerifyCommand, in.Auth.Ref, in.Run.RunID),
		"This report does not say the defence is secure, does not evaluate application vulnerabilities, " +
			"and does not replace a penetration test. Those limits are declared in code (the out-of-scope " +
			"section is required by C-15), not written by whoever assembled this document.",
	}
}

func strongestClaim(findings []contracts.DiscoveryFinding) contracts.ClaimType {
	best := contracts.ClaimType("")
	for _, f := range findings {
		if claimRank(f.ClaimType) > claimRank(best) {
			best = f.ClaimType
		}
	}
	if best == "" {
		return contracts.ClaimDescriptive
	}
	return best
}

func strongestLevel(findings []contracts.DiscoveryFinding) contracts.EvidenceLevel {
	best := contracts.EvidenceLevel("")
	for _, f := range findings {
		if levelRank(f.EvidenceLevel) > levelRank(best) {
			best = f.EvidenceLevel
		}
	}
	if best == "" {
		return contracts.EvidenceNone
	}
	return best
}

// sortFindings orders the report's finding list by priority, then by ref, so two runs
// of the same bundle produce byte-identical documents.
func sortFindings(in []contracts.DiscoveryFinding) {
	sort.Slice(in, func(i, k int) bool {
		pi, pk := priorityRank(in[i].Priority), priorityRank(in[k].Priority)
		if pi != pk {
			return pi > pk
		}
		if in[i].FindingType != in[k].FindingType {
			return in[i].FindingType < in[k].FindingType
		}
		return in[i].Ref < in[k].Ref
	})
}

func priorityRank(p contracts.Priority) int {
	switch p {
	case contracts.PriorityHigh:
		return 3
	case contracts.PriorityMedium:
		return 2
	case contracts.PriorityLow:
		return 1
	default:
		return 0
	}
}

// authorizedGrid is the coverage question the report is allowed to answer: the
// classes and transports the authorization covers, not the ones the run happened to
// reach. A grid built from what was sent is a grid with no holes in it by definition.
func authorizedGrid(auth *contracts.ProfilingAuthorization) [][2]string {
	out := make([][2]string, 0, len(auth.AllowedClasses)*len(auth.AllowedVectors))
	for _, c := range auth.AllowedClasses {
		for _, v := range auth.AllowedVectors {
			out = append(out, [2]string{string(c), string(v)})
		}
	}
	sort.Slice(out, func(i, k int) bool {
		if out[i][0] != out[k][0] {
			return out[i][0] < out[k][0]
		}
		return out[i][1] < out[k][1]
	})
	return out
}
