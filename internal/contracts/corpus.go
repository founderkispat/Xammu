package contracts

import (
	"time"
)

// PartitionName is one of the three corpus partitions. The split is by group,
// never by item, so an encoding variant cannot sit in development while its
// canonical twin calibrates the detector.
type PartitionName string

const (
	PartitionDevelopment PartitionName = "development"
	PartitionCalibration PartitionName = "calibration"
	PartitionIndependent PartitionName = "independent_validation"
)

func AllPartitionNames() []PartitionName {
	return []PartitionName{PartitionDevelopment, PartitionCalibration, PartitionIndependent}
}

// Purpose states why an item exists in the corpus.
type Purpose string

const (
	PurposeDiagnosis       Purpose = "coverage_diagnosis"
	PurposePositiveControl Purpose = "positive_control"
	PurposeNegativeControl Purpose = "negative_control"
	PurposeBenignReference Purpose = "benign_reference"
	PurposeEncodingReplica Purpose = "encoding_replica"
	PurposeOverBlockProbe  Purpose = "over_blocking_probe"
)

func AllPurposes() []Purpose {
	return []Purpose{
		PurposeDiagnosis, PurposePositiveControl, PurposeNegativeControl,
		PurposeBenignReference, PurposeEncodingReplica, PurposeOverBlockProbe,
	}
}

// ExpectedBehavior is the corpus author's declared expectation, kept as a label
// rather than a verdict so that a mismatch is reported instead of absorbed.
type ExpectedBehavior string

const (
	ExpectBlock ExpectedBehavior = "expect_block"
	ExpectPass  ExpectedBehavior = "expect_pass"
	ExpectMixed ExpectedBehavior = "informative_either"
)

func AllExpectedBehaviors() []ExpectedBehavior {
	return []ExpectedBehavior{ExpectBlock, ExpectPass, ExpectMixed}
}

// InertnessVerdict is the outcome of the corpus inertness gate.
type InertnessVerdict string

const (
	InertVerified  InertnessVerdict = "verified_inert"
	InertFailed    InertnessVerdict = "not_inert_excluded"
	InertUnchecked InertnessVerdict = "unchecked"
)

func AllInertnessVerdicts() []InertnessVerdict {
	return []InertnessVerdict{InertVerified, InertFailed, InertUnchecked}
}

// InertnessRecord is the auditable proof that a probe has diagnostic shape but
// no execution capability. XAMMU discovers defensive behaviour; the gate is what
// keeps the corpus on that side of the line.
type InertnessRecord struct {
	Verdict     InertnessVerdict `json:"verdict"`
	GateVersion string           `json:"gate_version"`
	CheckedAt   time.Time        `json:"checked_at"`
	RuleHits    []string         `json:"rule_hits,omitempty"`
	Notes       string           `json:"notes"`
}

// Provenance records where a probe came from.
type Provenance struct {
	Source      string    `json:"source"`
	RetrievedAt time.Time `json:"retrieved_at"`
	DerivedFrom string    `json:"derived_from,omitempty"`
	Author      string    `json:"author"`
	ReviewRef   string    `json:"review_ref"`
}

// CorpusValidationEvidence ties an item to a run that showed it behaves as
// declared in the laboratory.
type CorpusValidationEvidence struct {
	RunRef             string    `json:"run_ref"`
	ObservedAt         time.Time `json:"observed_at"`
	Result             string    `json:"result"`
	LabImageDigest     string    `json:"lab_image_digest"`
	MatchesExpectation bool      `json:"matches_expectation"`
}

// CorpusItem is C-13.
type CorpusItem struct {
	ItemID           string                     `json:"item_id"`
	Ref              string                     `json:"ref"`
	GroupID          string                     `json:"group_id"`
	AttackClass      AttackClass                `json:"attack_class"`
	Vector           Vector                     `json:"vector"`
	Encoding         Encoding                   `json:"encoding"`
	Canonical        string                     `json:"canonical_form"`
	Probe            string                     `json:"probe"`
	ProbeDigest      string                     `json:"probe_digest"`
	Purpose          Purpose                    `json:"purpose"`
	ExpectedBehavior ExpectedBehavior           `json:"expected_behavior"`
	Provenance       Provenance                 `json:"provenance"`
	Inertness        InertnessRecord            `json:"inertness"`
	Validation       []CorpusValidationEvidence `json:"validation_evidence"`
	Partition        PartitionName              `json:"partition"`
	Tags             []string                   `json:"tags,omitempty"`
	AuthoringNote    string                     `json:"authoring_note"`
}

func (CorpusItem) Contract() ID { return IDCorpusItem }

// OverlapCheck is one comparison of this partition against another, by group.
type OverlapCheck struct {
	Against      PartitionName `json:"against_partition"`
	SharedGroups []string      `json:"shared_groups"`
	SharedRefs   []string      `json:"shared_refs"`
	Verdict      string        `json:"verdict"`
	DetectorVer  string        `json:"detector_version"`
	CheckedAt    time.Time     `json:"checked_at"`
}

// CorpusPartition is C-14. A partition is only usable when its group-level
// disjointness has been checked and reported.
type CorpusPartition struct {
	PartitionID    string         `json:"partition_id"`
	Name           PartitionName  `json:"name"`
	MemberRefs     []string       `json:"member_refs"`
	GroupIDs       []string       `json:"group_ids"`
	OverlapChecks  []OverlapCheck `json:"overlap_checks"`
	LeakageVerdict string         `json:"leakage_verdict"`
	Sealed         bool           `json:"sealed"`
	AllowedUses    []string       `json:"allowed_uses"`
	CreatedAt      time.Time      `json:"created_at"`
	CommitRef      string         `json:"corpus_commit_ref"`
}

func (CorpusPartition) Contract() ID { return IDCorpusPartition }

func registerCorpusContracts() {
	register(IDCorpusItem, func(payload any) error {
		i, err := cast[CorpusItem](IDCorpusItem, payload)
		if err != nil {
			return err
		}
		c := newViolations(IDCorpusItem)
		uuidField(c, "item_id", i.ItemID)
		c.required("ref", i.Ref)
		c.required("group_id", i.GroupID)
		oneofT(c, "attack_class", i.AttackClass, AllAttackClasses()...)
		oneofT(c, "vector", i.Vector, AllVectors()...)
		oneofT(c, "encoding", i.Encoding, AllEncodings()...)
		oneofT(c, "purpose", i.Purpose, AllPurposes()...)
		oneofT(c, "expected_behavior", i.ExpectedBehavior, AllExpectedBehaviors()...)
		oneofT(c, "partition", i.Partition, AllPartitionNames()...)
		c.required("canonical_form", i.Canonical)
		c.required("probe", i.Probe)
		digestField(c, "probe_digest", i.ProbeDigest)
		c.required("authoring_note", i.AuthoringNote)

		// Provenance and validation are what let a reviewer distrust a probe
		// without deleting it.
		c.required("provenance.source", i.Provenance.Source)
		c.required("provenance.author", i.Provenance.Author)
		c.required("provenance.review_ref", i.Provenance.ReviewRef)
		if i.Provenance.RetrievedAt.IsZero() {
			c.add("provenance.retrieved_at", "required")
		}
		c.nonEmpty("validation_evidence", len(i.Validation))
		for _, v := range i.Validation {
			c.required("validation_evidence[].run_ref", v.RunRef)
			c.required("validation_evidence[].lab_image_digest", v.LabImageDigest)
			c.required("validation_evidence[].result", v.Result)
			if v.ObservedAt.IsZero() {
				c.add("validation_evidence[].observed_at", "required")
			}
		}

		// The inertness gate is a precondition of loading, not a recommendation.
		if i.Inertness.Verdict != InertVerified {
			c.add("inertness.verdict",
				"probe is not loadable unless the inertness gate returned verified_inert "+
					"(got "+string(i.Inertness.Verdict)+")")
		}
		c.required("inertness.gate_version", i.Inertness.GateVersion)
		c.required("inertness.notes", i.Inertness.Notes)
		if i.Inertness.CheckedAt.IsZero() {
			c.add("inertness.checked_at", "required")
		}

		// An encoding replica must differ from its canonical form, otherwise it
		// tests nothing and pollutes the matrix.
		if i.Encoding != EncodingCanonical && i.Probe == i.Canonical {
			c.add("probe", "non-canonical encoding identical to canonical form")
		}
		if i.Encoding == EncodingCanonical && i.Probe != i.Canonical {
			c.add("probe", "canonical item must carry the canonical probe verbatim")
		}
		return c.err()
	})

	register(IDCorpusPartition, func(payload any) error {
		p, err := cast[CorpusPartition](IDCorpusPartition, payload)
		if err != nil {
			return err
		}
		c := newViolations(IDCorpusPartition)
		uuidField(c, "partition_id", p.PartitionID)
		oneofT(c, "name", p.Name, AllPartitionNames()...)
		c.nonEmpty("member_refs", len(p.MemberRefs))
		c.nonEmpty("group_ids", len(p.GroupIDs))
		c.required("corpus_commit_ref", p.CommitRef)
		if p.CreatedAt.IsZero() {
			c.add("created_at", "required")
		}
		seen := map[string]bool{}
		for _, ref := range p.MemberRefs {
			if seen[ref] {
				c.add("member_refs", "duplicate member "+ref)
			}
			seen[ref] = true
		}

		// Every other partition must have been explicitly checked.
		checked := map[PartitionName]bool{}
		for _, o := range p.OverlapChecks {
			oneofT(c, "overlap_checks[].against_partition", o.Against, AllPartitionNames()...)
			oneofT(c, "overlap_checks[].verdict", o.Verdict, "clean", "leak_detected")
			c.required("overlap_checks[].detector_version", o.DetectorVer)
			if o.CheckedAt.IsZero() {
				c.add("overlap_checks[].checked_at", "required")
			}
			if o.Against != p.Name {
				checked[o.Against] = o.Verdict == "clean"
			}
		}
		for _, other := range AllPartitionNames() {
			if other == p.Name {
				continue
			}
			if !checked[other] {
				c.add("overlap_checks", "partition overlaps never checked against "+string(other))
			}
		}
		leaked := false
		for _, o := range p.OverlapChecks {
			if o.Verdict == "leak_detected" && o.Against != p.Name {
				leaked = true
			}
		}
		oneofT(c, "leakage_verdict", p.LeakageVerdict, "clean", "leak_detected")
		if leaked && p.LeakageVerdict != "leak_detected" {
			c.add("leakage_verdict", "an overlap was detected but the verdict claims clean")
		}
		if p.LeakageVerdict == "clean" && leaked {
			c.add("leakage_verdict", "contradicts the recorded checks")
		}

		// The independent partition may not be used to tune anything: that is
		// where corpus leakage becomes a fake result.
		if p.Name == PartitionIndependent {
			if !p.Sealed {
				c.add("sealed", "independent validation must be sealed")
			}
			for _, use := range p.AllowedUses {
				switch use {
				case "calibration", "tuning", "detector_development", "threshold_setting":
					c.add("allowed_uses", "independent validation may not be used for "+use)
				}
			}
		}
		c.nonEmpty("allowed_uses", len(p.AllowedUses))
		for _, use := range p.AllowedUses {
			c.oneof("allowed_uses[]", use, "profiling", "calibration", "tuning",
				"detector_development", "threshold_setting", "independent_validation",
				"regression", "documentation")
		}
		return c.err()
	})
}

func init() { registerCorpusContracts() }
