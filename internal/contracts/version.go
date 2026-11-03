// Package contracts defines the C-01..C-16 data contracts exchanged between
// XAMMU modules, their validators, and the epistemic invariants that keep
// observations separate from interpretation.
package contracts

import (
	"fmt"
	"sort"
)

// Version is a semantic schema version for a contract.
type Version struct {
	Major int `json:"major"`
	Minor int `json:"minor"`
	Patch int `json:"patch"`
}

func (v Version) String() string {
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
}

// SchemaVersion is the version stamped into every contract envelope.
// It is pinned to the XAMMU v1.0.0 delivery declared in the handoff.
var SchemaVersion = Version{Major: 1, Minor: 0, Patch: 0}

// ID names a contract. The string is the on-disk contract type and is stable:
// changing it is a breaking schema change.
type ID string

const (
	IDRawObservation           ID = "raw_observation"
	IDTransientCapture         ID = "transient_capture"
	IDSignatureAnalysis        ID = "signature_analysis"
	IDBehavioralClassification ID = "behavioral_classification"
	IDAttribution              ID = "attribution"
	IDAttributionStatus        ID = "attribution_status"
	IDHypothesis               ID = "hypothesis"
	IDEvidenceProfile          ID = "evidence_profile"
	IDProfilingAuthorization   ID = "profiling_authorization"
	IDValidationAuthorization  ID = "validation_authorization"
	IDRunProfile               ID = "run_profile"
	IDIntegrityManifest        ID = "integrity_manifest"
	IDCorpusItem               ID = "corpus_item"
	IDCorpusPartition          ID = "corpus_partition"
	IDReport                   ID = "report"
	IDDiscoveryFinding         ID = "discovery_finding"
)

var contractRegistry = map[ID]string{
	IDRawObservation:           "C-01",
	IDTransientCapture:         "C-02",
	IDSignatureAnalysis:        "C-03",
	IDBehavioralClassification: "C-04",
	IDAttribution:              "C-05",
	IDAttributionStatus:        "C-06",
	IDHypothesis:               "C-07",
	IDEvidenceProfile:          "C-08",
	IDProfilingAuthorization:   "C-09",
	IDValidationAuthorization:  "C-10",
	IDRunProfile:               "C-11",
	IDIntegrityManifest:        "C-12",
	IDCorpusItem:               "C-13",
	IDCorpusPartition:          "C-14",
	IDReport:                   "C-15",
	IDDiscoveryFinding:         "C-16",
}

// Label returns the catalogue label (C-nn) of a contract ID.
func (id ID) Label() string {
	if l, ok := contractRegistry[id]; ok {
		return l
	}
	return "unknown"
}

// IDs returns every registered contract ID, ordered by catalogue label.
func IDs() []ID {
	out := make([]ID, 0, len(contractRegistry))
	for id := range contractRegistry {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Label() < out[j].Label() })
	return out
}

// Registered reports whether id is a known contract.
func Registered(id ID) bool {
	_, ok := contractRegistry[id]
	return ok
}
