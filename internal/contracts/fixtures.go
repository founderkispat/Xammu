package contracts

import "time"

// Fixtures build contract instances that pass validation. Downstream packages
// and the acceptance suite mutate one field at a time to prove that each
// invariant actually rejects what it claims to.

var fixtureTime = time.Date(2026, 10, 27, 9, 30, 0, 0, time.UTC)

// ValidRawObservation returns a C-01 that satisfies the validator.
func ValidRawObservation() *RawObservation {
	return &RawObservation{
		ObservationID:    NewUUID(),
		RunID:            "run-2026-10-27-lab",
		AuthorizationRef: "auth-2026-042",
		Sequence:         1,
		ObservedAt:       fixtureTime,
		Target: Target{
			Scheme: "https", Host: "lab.local", Port: 8443,
			Path: "/api/search", ResolvedAddr: "127.0.0.1:8443",
		},
		Sent: Sent{
			Method: "GET", ProbeRef: "P-SQLI-001", CorpusRef: "ci-sqli-001",
			AttackClass: string(ClassSQLi), Vector: string(VectorQuery),
			Encoding: string(EncodingCanonical), ControlRole: string(RoleProbe),
			HeaderCount: 6, BodyBytes: 0, SentAt: fixtureTime,
		},
		ResponseStatus:     403,
		ResponseHeaders:    []HeaderEntry{{Name: "Server", Value: "cloudfront-waf"}},
		ResponseBodyBytes:  921,
		ResponseBodyDigest: NewDigest([]byte("interstitial-body")),
		Transport: Transport{
			Protocol: "HTTP/1.1", TLSVerified: true, ConnectMS: 12, RedirectCount: 0,
		},
		ObserverConfigHash: NewDigest([]byte("observer-config")),
	}
}

// ValidTransientCapture returns a C-02 with the digest-only retention policy.
func ValidTransientCapture() *TransientCapture {
	return &TransientCapture{
		CaptureID:     NewUUID(),
		ObservationID: NewUUID(),
		RunID:         "run-2026-10-27-lab",
		Retention:     string(RetainDigestOnly),
		RetainedBytes: 0,
		BodyDigest:    NewDigest([]byte("interstitial-body")),
		DroppedReason: "retention_policy=digest_only",
		CapturedAt:    fixtureTime,
	}
}

// ValidSignatureAnalysis returns a C-03.
func ValidSignatureAnalysis() *SignatureAnalysis {
	return &SignatureAnalysis{
		AnalysisID:     NewUUID(),
		ObservationID:  NewUUID(),
		CaptureID:      NewUUID(),
		RunID:          "run-2026-10-27-lab",
		AnalyzedAt:     fixtureTime,
		StatusCode:     403,
		StatusCategory: "4xx",
		ReasonPhrase:   "Forbidden",
		ContentType:    "text/html",
		ServerHeader:   "cloudfront-waf",
		RateLimited:    false,
		DetectorRefs:   []string{"det-interstitial-v1", "det-status-v1"},
		Matches: []MarkerMatch{{
			DetectorID: "det-interstitial-v1", PatternID: "blocked_token",
			Location: "body", Evidence: NewDigest([]byte("blocked")),
		}},
		BodyDigest:       NewDigest([]byte("interstitial-body")),
		RetentionApplied: string(RetainDigestOnly),
		DetectorSetHash:  NewDigest([]byte("detector-set-v1")),
	}
}

// ValidClassification returns a C-04.
func ValidClassification() *BehavioralClassification {
	return &BehavioralClassification{
		ClassificationID:  NewUUID(),
		ObservationID:     NewUUID(),
		AnalysisID:        NewUUID(),
		RunID:             "run-2026-10-27-lab",
		ClassifiedAt:      fixtureTime,
		Signal:            SignalBlock,
		StatusCode:        403,
		DetectorRefs:      []string{"det-interstitial-v1", "det-status-v1"},
		MatchedPatterns:   []string{"blocked_token"},
		NonFiredDetectors: []string{"det-jschallenge-v1"},
		DetectorAgreement: "all_agree",
		StatusCategory:    "4xx",
		ControlRole:       string(RoleProbe),
		ProbeRef:          "P-SQLI-001",
		DetectorSetHash:   NewDigest([]byte("detector-set-v1")),
		ClassifierVer:     "classifier-1.0.0",
	}
}

// ValidAlternatives returns the competing-explanation set a C-05 needs.
func ValidAlternatives() []AlternativeAssessment {
	return []AlternativeAssessment{
		{
			Kind: AltWAF, State: AltSupported,
			Justification:        "response carries an interstitial body absent from the origin's own error shape",
			TestThatWouldResolve: "compare the interstitial with the origin direct response",
			EvidenceRefs:         []string{"obs-1"},
		},
		{
			Kind: AltOriginApplication, State: AltRuledOut,
			Justification:        "negative control on the same route returned the origin error shape, not this one",
			TestThatWouldResolve: "repeat the negative control with the WAF bypassed",
			EvidenceRefs:         []string{"obs-ctrl-neg"},
		},
		{
			Kind: AltReverseProxyOrCDN, State: AltNotRuledOut,
			Justification:        "no direct-to-origin observation exists in this authorization",
			TestThatWouldResolve: "authorized request that reaches the origin without the proxy",
			EvidenceRefs:         []string{},
		},
		{
			Kind: AltRateLimiting, State: AltRuledOut,
			Justification:        "no 429 and no Retry-After header was observed in scope",
			TestThatWouldResolve: "status and header inspection already performed",
			EvidenceRefs:         []string{"obs-1"},
		},
	}
}

// ValidAttribution returns a C-05.
func ValidAttribution() *Attribution {
	return &Attribution{
		AttributionID:   NewUUID(),
		RunID:           "run-2026-10-27-lab",
		SubjectID:       NewUUID(),
		SubjectContract: IDBehavioralClassification,
		AttributedAt:    fixtureTime,
		Primary:         AltWAF,
		Alternatives:    ValidAlternatives(),
		Status:          AttributionCompatible,
		EvidenceBasis:   BasisHTTPControl,
		RequiredMissing: []string{"waf_logs", "origin_direct_comparison"},
	}
}

// ValidAttributionStatus returns a C-06 at the compatible grade.
func ValidAttributionStatus() *AttributionStatusRecord {
	return &AttributionStatusRecord{
		StatusID:      NewUUID(),
		RunID:         "run-2026-10-27-lab",
		AttributionID: NewUUID(),
		Status:        AttributionCompatible,
		EvidenceBasis: BasisHTTPControl,
		Conditions: ConfirmedConditions{
			ReproducibleAcrossRounds: false,
			ValidControlsInScope:     true,
		},
		Justification:   "controls valid within one round; no independent rounds, no log source",
		MissingEvidence: []string{"independent_rounds", "waf_logs"},
		DeterminedAt:    fixtureTime,
	}
}

// ValidEvidenceProfile returns a C-08 at the controls level, which caps claims
// at association.
func ValidEvidenceProfile() *EvidenceProfile {
	return &EvidenceProfile{
		ProfileID:    NewUUID(),
		RunID:        "run-2026-10-27-lab",
		SubjectRef:   "GAP-001",
		SubjectKind:  "finding",
		CompiledAt:   fixtureTime,
		Level:        EvidenceReplicatedWithControls,
		ClaimCeiling: ClaimAssociation,
		CeilingJustification: "replication with valid controls supports association; " +
			"attribution needs independent rounds",
		Population:           18,
		ValidTrials:          16,
		Inconclusive:         2,
		InvalidTrials:        0,
		Replicas:             8,
		Rounds:               []string{"round-1"},
		PositiveControlValid: true,
		NegativeControlValid: true,
		Measured: Ratio{
			Numerator: 8, Denominator: 16,
			Basis:                "valid SQLi probes across query and body_json vectors",
			ExcludedInconclusive: 2,
		},
		MissingEvidence: []string{"independent_rounds"},
		Refs:            []string{"obs-1", "obs-2"},
	}
}

// ValidHypothesis returns a C-07.
func ValidHypothesis() *Hypothesis {
	profile := ValidEvidenceProfile()
	return &Hypothesis{
		HypothesisID: NewUUID(),
		Ref:          "GAP-001",
		RunID:        "run-2026-10-27-lab",
		FormedAt:     fixtureTime,
		Statement:    "probes with SQLi shape in body_json are handled differently from the same probes in query",
		AttackClass:  ClassSQLi,
		Vector:       VectorBodyJSON,
		Encoding:     EncodingCanonical,
		Scope:        "POST /api/search",
		Predictions:  []string{"canonical SQLi in query is blocked", "canonical SQLi in body_json is not blocked"},
		Falsifier:    "a valid control pair where both vectors produce the same signal",
		Checks: []HypothesisCheck{{
			CheckID: NewUUID(), Prediction: "canonical SQLi in query is blocked",
			Result: "met", EvidenceRef: "obs-1",
		}},
		Outcome:             HypothesisSupported,
		OutcomeReason:       "both predictions held over 8 replicas with valid controls",
		EvidenceProfileRef:  profile.ProfileID,
		ClaimType:           ClaimAssociation,
		AttributionRefs:     []string{"att-1"},
		ReproductionCommand: "xammu validate --finding GAP-001 --run 2026-10-27-lab --authorization ./auth/perfilado.json",
		SourceFindingRef:    "GAP-001",
	}
}

// ValidProfilingAuthorization returns a C-09.
func ValidProfilingAuthorization() *ProfilingAuthorization {
	return &ProfilingAuthorization{
		AuthorizationID: NewUUID(),
		Ref:             "auth-2026-042",
		IssuedAt:        fixtureTime.Add(-24 * time.Hour),
		ExpiresAt:       fixtureTime.Add(24 * time.Hour),
		Issuer:          "security-owner@example.internal",
		ApprovedBy:      "CISO delegate",
		Environment:     EnvLab,
		Origins: []Origin{{
			Scheme: "https", Host: "lab.local", Port: 8443,
			PathPrefixes: []string{"/api/", "/search"},
			AllowedCIDRs: []string{"127.0.0.0/8"},
		}},
		Methods:          []string{"GET", "POST", "PUT"},
		Limits:           OperationalLimits{MaxRequests: 500, RatePerSecond: 10, MaxRedirects: 5, TimeoutMS: 5000, MaxConcurrent: 2, MaxBodyRetainBytes: 4096, RoundCooldownMS: 1000},
		Retention:        RetainDigestOnly,
		AllowedClasses:   []AttackClass{ClassSQLi, ClassXSS, ClassPathTraversal, ClassCommandInjection, ClassSSRF},
		AllowedVectors:   []Vector{VectorQuery, VectorBodyJSON, VectorBodyForm, VectorPath, VectorHeader, VectorCookie},
		AllowedEncodings: []Encoding{EncodingCanonical, EncodingURLSingle, EncodingURLDouble, EncodingCaseVariant},
		CorpusPartitions: []string{"development"},
		StatementOfScope: "Behavioural profiling of the WAF in front of lab.local only.",
		RulesOfEngagement: []string{
			"no exploitation attempts",
			"stop on any 429 and report",
			"no requests outside the listed path prefixes",
		},
		ContactForHalt:       "oncall@example.internal",
		IssuerKeyFingerprint: "ed25519:7f3a...c1",
	}
}

// ValidValidationAuthorization returns a C-10.
func ValidValidationAuthorization() *ValidationAuthorization {
	return &ValidationAuthorization{
		ValidationID:  NewUUID(),
		ParentAuthRef: "auth-2026-042",
		HypothesisRef: "GAP-001",
		RunID:         "run-2026-10-27-validate",
		Origin: Origin{
			Scheme: "https", Host: "lab.local", Port: 8443,
			PathPrefixes: []string{"/api/search"},
			AllowedCIDRs: []string{"127.0.0.0/8"},
		},
		AllowedProbes:      []string{"P-SQLI-001", "P-SQLI-002"},
		MaxRequests:        40,
		RatePerSecond:      5,
		NotBefore:          fixtureTime,
		ExpiresAt:          fixtureTime.Add(2 * time.Hour),
		ApprovedBy:         "security-owner@example.internal",
		IssuedAt:           fixtureTime,
		ImmutabilityDigest: NewDigest([]byte("validation-auth-payload")),
		RoundBudget:        2,
		StopOn:             []string{"rate_limited", "budget_exhausted", "control_invalid"},
	}
}

// ValidRunProfile returns a C-11 in executing state with a legal history.
func ValidRunProfile() *RunProfile {
	steps := []RunState{
		StateAuthorizationPending, StateAuthorized, StatePlanning, StatePlanned, StateExecuting,
	}
	from := StateInitialized
	transitions := make([]StateTransition, 0, len(steps))
	for i, to := range steps {
		transitions = append(transitions, StateTransition{
			From: from, To: to, At: fixtureTime.Add(time.Duration(i) * time.Minute),
			Cause: "planned advance", RequestSeq: 0,
		})
		from = to
	}
	return &RunProfile{
		RunID: "run-2026-10-27-lab", State: StateExecuting,
		AuthorizationRef: "auth-2026-042", TargetOrigin: "https://lab.local:8443",
		Partition:  string(PartitionDevelopment),
		ConfigHash: NewDigest([]byte("run-config")),
		StartedAt:  fixtureTime, UpdatedAt: fixtureTime.Add(5 * time.Minute),
		RequestBudget: 500, RequestsUsed: 120,
		StopTrigger: TriggerNone,
		Transitions: transitions,
		Counters: RunCounters{
			Observations: 120, Classified: 118, BlockSignals: 62, PassSignals: 44,
			Indeterminate: 12, RateLimited: 0, TransportErrors: 2,
			ValidTrials: 110, InvalidTrials: 8, PlannedProbes: 500, ExecutedProbes: 120,
		},
		ResumeToken:   NewUUID(),
		RoundID:       "round-1",
		SchemaVersion: SchemaVersion.String(),
	}
}

// ValidCompletedRun returns a C-11 that reached the completed terminal state.
func ValidCompletedRun() *RunProfile {
	r := ValidRunProfile()
	to := StateFinalizing
	r.Transitions = append(r.Transitions, StateTransition{
		From: StateExecuting, To: to, At: fixtureTime.Add(10 * time.Minute),
		Cause: "plan exhausted with budget remaining", RequestSeq: 480,
	})
	r.Transitions = append(r.Transitions, StateTransition{
		From: StateFinalizing, To: StateCompleted, At: fixtureTime.Add(12 * time.Minute),
		Cause: "report compiled", RequestSeq: 480,
	})
	r.State = StateCompleted
	r.FinishedAt = fixtureTime.Add(12 * time.Minute)
	r.UpdatedAt = r.FinishedAt
	r.RequestsUsed = 480
	r.TerminalReason = "all authorized probes executed"
	r.TerminalCode = ReasonNotYetAttempted
	r.StopTrigger = TriggerNone
	r.ResumeToken = ""
	return r
}

// ValidCorpusItem returns a C-13 that passed the inertness gate.
func ValidCorpusItem() *CorpusItem {
	probe := "xammu-probe' or 1=1 xammu-probe"
	return &CorpusItem{
		ItemID:           NewUUID(),
		Ref:              "P-SQLI-001",
		GroupID:          "g-sqli-canonical",
		AttackClass:      ClassSQLi,
		Vector:           VectorQuery,
		Encoding:         EncodingCanonical,
		Canonical:        probe,
		Probe:            probe,
		ProbeDigest:      NewDigest([]byte(probe)),
		Purpose:          PurposeDiagnosis,
		ExpectedBehavior: ExpectBlock,
		Provenance: Provenance{
			Source: "authored-in-project", RetrievedAt: fixtureTime,
			Author: "corpus-team", ReviewRef: "corpus-review-2026-10-21",
		},
		Inertness: InertnessRecord{
			Verdict: InertVerified, GateVersion: "inertness-gate-1.0.0",
			CheckedAt: fixtureTime,
			Notes: "boolean fragment is not attached to a syntactically valid statement; " +
				"the probe cannot alter a query result",
		},
		Validation: []CorpusValidationEvidence{{
			RunRef: "lab-run-2026-10-25", ObservedAt: fixtureTime,
			Result:             "blocked on query vector as declared",
			LabImageDigest:     NewDigest([]byte("lab-waf-image-digest")),
			MatchesExpectation: true,
		}},
		Partition:     PartitionDevelopment,
		AuthoringNote: "canonical SQLi-shaped probe for coverage diagnosis",
	}
}

// ValidCorpusPartition returns a C-14 for the development partition.
func ValidCorpusPartition() *CorpusPartition {
	others := make([]OverlapCheck, 0, 2)
	for _, name := range AllPartitionNames() {
		if name == PartitionDevelopment {
			continue
		}
		others = append(others, OverlapCheck{
			Against: name, SharedGroups: []string{}, SharedRefs: []string{},
			Verdict: "clean", DetectorVer: "overlap-detector-1.0.0", CheckedAt: fixtureTime,
		})
	}
	return &CorpusPartition{
		PartitionID:    NewUUID(),
		Name:           PartitionDevelopment,
		MemberRefs:     []string{"P-SQLI-001", "P-XSS-001"},
		GroupIDs:       []string{"g-sqli-canonical", "g-xss-canonical"},
		OverlapChecks:  others,
		LeakageVerdict: "clean",
		AllowedUses:    []string{"profiling", "detector_development"},
		CreatedAt:      fixtureTime,
		CommitRef:      "corpus-commit-abc123",
	}
}

// ValidFinding returns a C-16 coverage_gap with all four honesty fields.
func ValidFinding() *DiscoveryFinding {
	return &DiscoveryFinding{
		FindingID:   NewUUID(),
		Ref:         "GAP-001",
		RunID:       "run-2026-10-27-lab",
		DetectedAt:  fixtureTime,
		FindingType: FindingCoverageGap,
		ClaimType:   ClaimAssociation,

		WhatWasObserved: "8/8 canonical SQLi probes in query returned the block interstitial; " +
			"0/8 in body_json returned the normal shape, with a valid control pair.",
		WhatIsInferred: "handling differs between the query and body_json vectors, a pattern compatible " +
			"with inspection configured for query only.",
		WhatEvidenceIsMissing: "WAF rule configuration or logs would raise this from compatible to " +
			"supported_by_logs; independent rounds would raise the claim to attribution.",
		Limitations: []string{
			"does not show the origin is vulnerable to SQLi",
			"does not show the body is unexamined by every rule, only that these probes were not rejected",
			"single round: the pattern is not shown to survive configuration changes",
		},
		AttributionStatus:  AttributionCompatible,
		EvidenceBasis:      BasisHTTPControl,
		Alternatives:       ValidAlternatives(),
		EvidenceLevel:      EvidenceReplicatedWithControls,
		EvidenceProfileRef: NewUUID(),
		HypothesisRef:      "GAP-001",
		ObservationRefs:    []string{"obs-1", "obs-2"},

		ReproductionCommand: "xammu validate --finding GAP-001 --run 2026-10-27-lab --authorization ./auth/perfilado.json",
		Recommendation:      "check whether body inspection is enabled for the /api/search rule group; if it is disabled, enable it in detection mode first and measure false positives",
		// The scenario name here is one the laboratory actually ships, because a
		// regression step a reader cannot run is not a regression step. lab/scenarios.json
		// is the authority on the list, and a test fails if a cited name leaves it.
		RegressionTest: "xammu lab test --scenario coverage-gap-sqli-query-canonical-api-search",
		Priority:       PriorityHigh,
		PriorityBasis:  "100 percentage points of blocking difference between vectors, measured over 16 valid trials",
		MeasuredImpact: Ratio{
			Numerator: 8, Denominator: 16,
			Basis:                "valid SQLi probes with a blocked canonical form in query",
			ExcludedInconclusive: 2,
		},
		AffectedScope: "sqli x body_json x canonical on POST /api/search",
		AttackClass:   ClassSQLi,
		Vector:        VectorBodyJSON,
		Encoding:      EncodingCanonical,
		SecurityEngineerNote: "the JSON body of this application is not being inspected for this class; " +
			"take the query/body gap to the WAF configuration review",
	}
}

// ValidReport returns a C-15 that passes the five-dimension and seven-question
// checks.
func ValidReport() *Report {
	dims := make([]Dimension, 0, 5)
	for _, k := range AllDimensionKinds() {
		dims = append(dims, Dimension{
			Kind: k, Title: "dimension " + string(k),
			Questions:  QuestionsAnsweredBy(k),
			Statements: []string{"measured statement for " + string(k)},
			Refs:       []string{"GAP-001"},
		})
	}
	out := make([]string, len(RequiredOutOfScope))
	copy(out, RequiredOutOfScope)

	matrix := CoverageMatrix{
		Classes: []AttackClass{ClassSQLi},
		Vectors: []Vector{VectorQuery, VectorBodyJSON},
		Cells: []CoverageCell{{
			Class: ClassSQLi, Vector: VectorQuery,
			Encodings: []EncodingRow{{
				Encoding: EncodingCanonical, Blocked: 8, Passed: 0, ValidTrials: 8,
				ControlValid: true, Verdict: "blocked", Evidence: EvidenceReplicatedWithControls,
			}},
			Status: "measured",
			Aggregate: Ratio{
				Numerator: 8, Denominator: 8, Basis: "valid sqli probes in query",
			},
			ClaimType: ClaimAssociation, Evidence: EvidenceReplicatedWithControls,
			ObservationRefs: []string{"obs-1"},
		}},
		Basis:       "class x vector blocking over valid trials only",
		NotMeasured: []string{"sqli x header"},
	}

	versions := map[string]string{}
	for _, id := range IDs() {
		versions[string(id)] = SchemaVersion.String()
	}

	return &Report{
		ReportID: NewUUID(), RunID: "run-2026-10-27-lab",
		GeneratedAt: fixtureTime, SchemaVersion: SchemaVersion.String(),
		AuthorizationRef:        "auth-2026-042",
		AuthorizationValidUntil: fixtureTime.Add(24 * time.Hour),
		RunState:                StateCompleted, StateReason: "plan executed with budget remaining",
		TargetOrigin: "https://lab.local:8443", Partition: string(PartitionDevelopment),
		DurationSeconds: 754, RequestsUsed: 487, RequestBudget: 500,
		LimitsSummary:    []string{"500 requests", "10 req/s", "5 redirects", "digest-only retention"},
		ExecutiveSummary: []string{"coverage 94% (32/34 valid tests executed)"},
		Dimensions:       dims,
		Findings:         []DiscoveryFinding{*ValidFinding()},
		Matrix:           matrix,
		ResidualRisk: ResidualRisk{
			ConditionalRisk: Scenario{
				Statement:    "if the application parses SQLi from JSON bodies, this WAF configuration does not filter it",
				Scope:        "POST /api/search body_json",
				EvidenceRefs: []string{"GAP-001"}, Verification: ValidFinding().ReproductionCommand,
				Untested: []string{"origin parsing behaviour"},
			},
			ConditionNotDemonstrated: Scenario{
				Statement:    "whether the application is vulnerable at all was not tested; XAMMU does not evaluate the origin",
				Scope:        "out of authorized scope",
				EvidenceRefs: []string{"authorization auth-2026-042"},
				Verification: "xammu report --run 2026-10-27-lab --format markdown",
				Untested:     []string{"exploitation", "application vulnerabilities"},
			},
			Undeterminable: Scenario{
				Statement:    "/api/admin is unknown: its negative control failed during the round",
				Scope:        "/api/admin",
				EvidenceRefs: []string{"UND-001"},
				Verification: "xammu validate --finding UND-001 --run 2026-10-27-lab --authorization ./auth/perfilado.json",
				Untested:     []string{"all classes on /api/admin"},
			},
		},
		Unevaluated: []UnevaluatedZone{{
			Scope: "/api/admin", Reason: ReasonControlInvalid,
			Detail:              "origin returned 502 during the control, so the round cannot be scored",
			Remediation:         "re-run in a stability window",
			ReproductionCommand: "xammu validate --finding UND-001 --run 2026-10-27-lab --authorization ./auth/perfilado.json",
			PlannedRequests:     12,
		}},
		Distributions: []Distribution{{
			Name: "behavioral_signal",
			Kind: DistBehavioralSignal,
			Buckets: []Bucket{
				{Name: "compatible_block", Count: 62},
				{Name: "compatible_normal", Count: 44},
				{Name: "indeterminate", Count: 12},
			},
			Denominator: 106, Basis: "classified observations",
			InconclusiveBucket: "indeterminate",
			Excluded:           []string{"indeterminate"},
		}},
		Evidence: EvidenceSection{
			ManifestPath:     "runs/2026-10-27-lab/manifest.json",
			ManifestDigest:   NewDigest([]byte("manifest")),
			VerifyCommand:    "xammu verify --store runs/2026-10-27-lab",
			ObservationCount: 487, RoundIDs: []string{"round-1"},
			CorpusCommitRef: "corpus-commit-abc123",
			DetectorSetHash: NewDigest([]byte("detector-set-v1")),
			ToolVersion:     "xammu-1.0.0", GeneratedByUser: "operator",
		},
		ContractVersions: versions,
		OutOfScope:       out,
	}
}

// ValidManifestSkeleton returns a C-12 without the signature fields that only
// the integrity package can fill.
func ValidManifestSkeleton() *IntegrityManifest {
	files := []ManifestFileEntry{{
		Path: "observations.jsonl", Digest: NewDigest([]byte("obs")),
		Bytes: 1024, Lines: 1, Contract: IDRawObservation, AppendOnly: true,
	}}
	versions := map[string]string{}
	for _, id := range IDs() {
		versions[string(id)] = SchemaVersion.String()
	}
	return &IntegrityManifest{
		ManifestID: NewUUID(), RunID: "run-2026-10-27-lab", GeneratedAt: fixtureTime,
		ToolVersion: "xammu-1.0.0", AuthorizationRef: "auth-2026-042",
		Algorithm: "ed25519", SignerKeyID: "key-1",
		PublicKey: "", Signature: "",
		PayloadDigest: NewDigest([]byte("payload")),
		ChainHead:     NewDigest([]byte("chain")),
		RootHash:      NewDigest([]byte("root")),
		FileCount:     len(files), ObservationCount: 1,
		ContractVersions: versions, Files: files,
		SigningRule: "ed25519 over the merkle root of sorted file digests",
	}
}
