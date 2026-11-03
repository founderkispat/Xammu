package observer

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"xammu/internal/contracts"
)

// Reading is what one detector says about one response. It is a statement about
// shape, not about cause: "block_shape" means the response has the features the
// detector set associates with rejection, and the attributor is the stage that
// asks who produced them.
type Reading string

const (
	ReadsBlock   Reading = "block_shape"
	ReadsPass    Reading = "pass_shape"
	ReadsNothing Reading = "abstain"
)

// DetectorVersion is folded into the detector-set hash material. Changing the
// pattern vocabulary is a new version, so a classification can always be
// re-derived by re-running the set that produced it.
const DetectorVersion = "xammu-detectors/1.0.0"

// Pattern is one literal a detector looks for. Matching is case-insensitive
// substring matching over the scanned window -- no regular expressions, because a
// regex tuned to one vendor's page layout is a claim about one product, and a
// typo in it silently disables the detector.
type Pattern struct {
	ID      string
	Literal string
	// Reason states why this string is in the set, in terms of the responses it
	// was seen in. It is provenance for the reviewer, not a finding.
	Reason string
}

// Result is one detector's output for one shape.
type Result struct {
	Reading Reading
	Matches []contracts.MarkerMatch
}

func abstain() Result { return Result{Reading: ReadsNothing} }

// Detector is one member of the set. Evaluate reads a single response; Contrast
// reads a response together with the run's reference cluster, which is the only
// way a reading of ordinary handling can be earned rather than assumed.
//
// Emits declares the assertive readings a detector may produce; every detector
// may also abstain, and abstention is the answer whenever its input does not
// carry the feature it looks for. The classifier reads this declaration instead
// of matching on detector names, so adding a member to the set is a data change
// rather than a change to the classification rule.
type Detector struct {
	ID       string
	Family   string
	Describe string
	Emits    []Reading
	Patterns []Pattern
	Evaluate func(Shape) Result
	Contrast func(probe Shape, references []Shape) Result
}

// CanReport reports whether this detector is allowed to produce the given
// reading.
func (d Detector) CanReport(r Reading) bool {
	for _, e := range d.Emits {
		if e == r {
			return true
		}
	}
	return false
}

// IsReferenceDetector marks the detector that needs more than one response.
func (d Detector) IsReferenceDetector() bool { return d.Contrast != nil }

// DetectorSet is the fixed ensemble a run is classified with.
type DetectorSet struct {
	detectors []Detector
}

// DefaultSet returns the v1.0.0 ensemble.
func DefaultSet() *DetectorSet {
	return &DetectorSet{detectors: []Detector{
		interstitialPhraseDetector(),
		statusShapeDetector(),
		htmlErrorEnvelopeDetector(),
		lengthCollapseDetector(),
		referenceContrastDetector(),
	}}
}

// NewSet assembles a reviewer-supplied ensemble.
//
// The default set is what a normal run uses; this exists because adding a member to
// the set is meant to be a data change rather than a change to the classification
// rule, and the classifier reads each detector's declared readings instead of
// matching on names. A hand-built set is where a malformed ensemble would otherwise
// go unnoticed: a detector that reads nothing still counts toward agreement, and one
// that declares both a per-response and a cluster reading is consulted as only one
// of them. Those are refused here, at the point someone writes the set down.
func NewSet(dets ...Detector) (*DetectorSet, error) {
	if len(dets) == 0 {
		return nil, fmt.Errorf("observer: an ensemble needs at least one detector")
	}
	seen := map[string]bool{}
	for i, d := range dets {
		if d.ID == "" {
			return nil, fmt.Errorf("observer: detector %d has no id to cite", i)
		}
		if seen[d.ID] {
			return nil, fmt.Errorf("observer: detector %s appears twice; its reading would be counted once and cited twice", d.ID)
		}
		seen[d.ID] = true
		if d.Family == "" {
			return nil, fmt.Errorf("observer: detector %s declares no family", d.ID)
		}
		if len(d.Emits) == 0 {
			return nil, fmt.Errorf("observer: detector %s declares no reading it can report, so it can only ever abstain", d.ID)
		}
		switch {
		case d.Evaluate == nil && d.Contrast == nil:
			return nil, fmt.Errorf("observer: detector %s declares no evaluation", d.ID)
		case d.Evaluate != nil && d.Contrast != nil:
			return nil, fmt.Errorf("observer: detector %s declares both a response and a cluster reading; only the cluster one would run", d.ID)
		}
		for _, p := range d.Patterns {
			if p.ID == "" || p.Literal == "" {
				return nil, fmt.Errorf("observer: detector %s carries a pattern with no id or no literal", d.ID)
			}
		}
	}
	return &DetectorSet{detectors: append([]Detector(nil), dets...)}, nil
}

func (s *DetectorSet) Detectors() []Detector {
	return append([]Detector(nil), s.detectors...)
}

// ResponseDetectors lists the detectors that read one exchange, ordered by ID so
// the same ensemble always produces the same journal bytes.
func (s *DetectorSet) ResponseDetectors() []Detector {
	out := make([]Detector, 0, len(s.detectors))
	for _, d := range s.detectors {
		if !d.IsReferenceDetector() {
			out = append(out, d)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// ResponseDetectorIDs names the detectors that read a single exchange. C-03
// records these as its provenance: the ensemble is the five-detector set, and
// this is the subset that can run before the run's reference cluster exists.
func (s *DetectorSet) ResponseDetectorIDs() []string {
	out := make([]string, 0, len(s.detectors))
	for _, d := range s.ResponseDetectors() {
		out = append(out, d.ID)
	}
	return out
}

// ReferenceDetector returns the cluster-reading detector, or nil when the set has
// none. A set without one cannot earn a pass signal, and the classifier reports
// indeterminate rather than guessing one.
func (s *DetectorSet) ReferenceDetector() (Detector, bool) {
	for _, d := range s.detectors {
		if d.IsReferenceDetector() {
			return d, true
		}
	}
	return Detector{}, false
}

// IDs names every detector consulted, which is what C-04 records as
// detector_refs: a reviewer must be able to re-run exactly this ensemble.
// Naming the set rather than only the firing detectors is also what keeps a
// transport-failed exchange classifiable at all, since C-04 requires non-empty
// provenance even when nothing matched.
func (s *DetectorSet) IDs() []string {
	out := make([]string, 0, len(s.detectors))
	for _, d := range s.detectors {
		out = append(out, d.ID)
	}
	sort.Strings(out)
	return out
}

// Hash commits to the ensemble that produced a classification: version, every
// detector with its family, and every pattern identifier together with the literal
// it looks for, canonically ordered. Two runs with different hashes did not perform
// the same measurement, so their signals are not comparable.
//
// The literal is in the material because the identifier is not the measurement. A
// reviewer re-running this set reads the literals from the build the hash names, and
// an edit that changes what a detector looks for without changing its name -- the
// way a typo silently disables one -- has to show up here or a run would certify a
// vocabulary it never used.
func (s *DetectorSet) Hash() string {
	const sep = "\x1f"
	var b strings.Builder
	b.WriteString(DetectorVersion)
	for _, id := range s.IDs() {
		for _, d := range s.detectors {
			if d.ID != id {
				continue
			}
			b.WriteString("|" + d.ID + "/" + d.Family)
			patterns := append([]Pattern(nil), d.Patterns...)
			sort.Slice(patterns, func(i, j int) bool { return patterns[i].ID < patterns[j].ID })
			for _, p := range patterns {
				b.WriteString(":" + p.ID + sep + p.Literal)
			}
		}
	}
	return contracts.NewDigest([]byte(b.String()))
}

// matchLiterals scans the body for the detector's literals and reports every hit.
// A detector that matches more than one pattern journals all of them: how many
// interstitial strings a page carries is itself shape data.
func matchLiterals(d Detector, s Shape) []contracts.MarkerMatch {
	hay := s.lower()
	var out []contracts.MarkerMatch
	for _, p := range d.Patterns {
		i := strings.Index(hay, p.Literal)
		if i < 0 {
			continue
		}
		end := i + len(p.Literal)
		if end > len(s.Body) {
			end = len(s.Body)
		}
		out = append(out, contracts.MarkerMatch{
			DetectorID: d.ID,
			PatternID:  p.ID,
			Location:   "body",
			Evidence:   contracts.NewDigest(s.Body[i:end]),
		})
	}
	return out
}

var interstitialPatterns = []Pattern{
	{ID: "p.int.request_blocked", Literal: "request blocked",
		Reason: "the heading several commercial interstitials lead with"},
	{ID: "p.int.security_policy", Literal: "security policy",
		Reason: "wording for a policy violation notice"},
	{ID: "p.int.access_denied", Literal: "access denied",
		Reason: "rejection heading shared by filter pages and origin error pages"},
	{ID: "p.int.netadmin", Literal: "network administrator",
		Reason: "the page addresses an administrator rather than the user"},
	{ID: "p.int.query_blocked", Literal: "query was blocked",
		Reason: "SQL-inspection block wording"},
	{ID: "p.int.attack_detected", Literal: "attack detected",
		Reason: "signature-action wording"},
	{ID: "p.int.rule_matched", Literal: "matched a security rule",
		Reason: "rule-action wording used by rule-based engines"},
	{ID: "p.int.mod_security", Literal: "mod_security",
		Reason: "the module names itself in the body of its own block page"},
	{ID: "p.int.incident_id", Literal: "incident id",
		Reason: "a managed block page carries a case identifier"},
}

func interstitialPhraseDetector() Detector {
	return Detector{
		ID:     "det.interstitial_phrase",
		Family: "interstitial",
		Emits:  []Reading{ReadsBlock},
		Describe: "Matches the rejection wording interstitial pages are written with, " +
			"anywhere in the body and whatever the status line says.",
		Patterns: interstitialPatterns,
		Evaluate: func(s Shape) Result {
			m := matchLiterals(interstitialPhraseDetector(), s)
			if len(m) == 0 {
				return abstain()
			}
			return Result{Reading: ReadsBlock, Matches: m}
		},
	}
}

// refusalCodes are the status codes whose semantics are "this request will not be
// handled". A 404 is a routing fact, a 401 is an authorization fact and a 500 is
// the origin's problem; reading any of them as a rejection shape is how an
// unauthenticated scan manufactures a filter that was never there.
var refusalCodes = []int{403, 405, 406, 451}

func statusShapeDetector() Detector {
	patterns := make([]Pattern, 0, len(refusalCodes))
	for _, code := range refusalCodes {
		patterns = append(patterns, Pattern{
			ID:      "p.shape." + strconv.Itoa(code),
			Literal: strconv.Itoa(code),
			Reason:  "status " + strconv.Itoa(code) + " states a refusal to handle the request",
		})
	}
	return Detector{
		ID:       "det.status_shape",
		Family:   "status",
		Emits:    []Reading{ReadsBlock},
		Describe: "Reads the status line alone, for the codes that state a refusal to handle the request.",
		Patterns: patterns,
		Evaluate: func(s Shape) Result {
			id := ""
			for _, code := range refusalCodes {
				if s.Status == code {
					id = "p.shape." + strconv.Itoa(code)
				}
			}
			if id == "" {
				return abstain()
			}
			return Result{Reading: ReadsBlock, Matches: []contracts.MarkerMatch{{
				DetectorID: "det.status_shape",
				PatternID:  id,
				Location:   "status_line",
				Evidence:   contracts.NewDigest([]byte(strconv.Itoa(s.Status))),
			}}}
		},
	}
}

// errorHeadingWords are the words an error document's visible text carries. They
// are matched together with an HTML envelope, never on their own: the same words
// appear in ordinary product copy, and a detector that fired on them alone would
// read the whole corpus as blocked.
var errorHeadingWords = []string{
	"blocked", "denied", "forbidden", "not acceptable", "unavailable",
	"attention required", "violation", "error",
}

func htmlErrorEnvelopeDetector() Detector {
	return Detector{
		ID:     "det.html_error_envelope",
		Family: "envelope",
		Emits:  []Reading{ReadsBlock},
		Describe: "Fires when the body is an HTML document announcing a problem. This is what " +
			"catches an interstitial served with a 200, where the status line says nothing.",
		Patterns: []Pattern{
			{ID: "p.env.html_document", Literal: "<html",
				Reason: "the body is a document rather than the resource the client asked for"},
			{ID: "p.env.error_heading", Literal: "<h1",
				Reason: "interstitials present their reason as a heading"},
		},
		Evaluate: func(s Shape) Result {
			hay := s.lower()
			if !strings.Contains(hay, "<html") && !strings.Contains(hay, "<!doctype html") {
				return abstain()
			}
			if !strings.Contains(hay, "<h1") && !strings.Contains(hay, "<h2") {
				return abstain()
			}
			var words []string
			for _, w := range errorHeadingWords {
				if strings.Contains(hay, w) {
					words = append(words, w)
				}
			}
			if len(words) == 0 {
				return abstain()
			}
			sort.Strings(words)
			return Result{Reading: ReadsBlock, Matches: []contracts.MarkerMatch{
				{DetectorID: "det.html_error_envelope", PatternID: "p.env.html_document",
					Location: "body", Evidence: contracts.NewDigest([]byte("html_envelope"))},
				{DetectorID: "det.html_error_envelope", PatternID: "p.env.error_heading",
					Location: "body", Evidence: contracts.NewDigest([]byte(strings.Join(words, ",")))},
			}}
		},
	}
}

func lengthCollapseDetector() Detector {
	return Detector{
		ID:     "det.length_collapse",
		Family: "length",
		Emits:  []Reading{ReadsBlock},
		Describe: "Fires when a success status arrives with no content: the request was " +
			"answered and nothing was returned, which is what a swallowing rule looks like from outside.",
		Patterns: []Pattern{
			{ID: "p.len.empty_2xx", Literal: "empty",
				Reason: "a 2xx with a zero-length body"},
			{ID: "p.len.trivial_2xx", Literal: "tiny",
				Reason: "a 2xx whose body is too short to be the resource"},
		},
		Evaluate: func(s Shape) Result {
			if s.Status < 200 || s.Status > 299 || s.Status == 204 {
				return abstain()
			}
			id := ""
			switch {
			case s.BodyBytes == 0:
				id = "p.len.empty_2xx"
			case s.BodyBytes <= 16:
				id = "p.len.trivial_2xx"
			default:
				return abstain()
			}
			return Result{Reading: ReadsBlock, Matches: []contracts.MarkerMatch{{
				DetectorID: "det.length_collapse",
				PatternID:  id,
				Location:   "body_length",
				Evidence:   contracts.NewDigest([]byte(strconv.Itoa(s.BodyBytes))),
			}}}
		},
	}
}

func referenceContrastDetector() Detector {
	return Detector{
		ID:     "det.reference_contrast",
		Family: "contrast",
		Emits:  []Reading{ReadsPass},
		Describe: "Reads a probe against the run's own benign references. Only a shape that " +
			"matches the reference cluster earns a pass reading: nothing in a response alone proves it was " +
			"the answer the endpoint would have given anyway.",
		Patterns: []Pattern{
			{ID: "p.con.matches_reference", Literal: "shape_key",
				Reason: "the probe and the reference cluster share a coarse shape key"},
		},
		Contrast: func(probe Shape, references []Shape) Result {
			// One reference is a single observation, not a cluster: a lone anomaly
			// from an unstable origin would otherwise calibrate the whole run.
			if len(references) < 2 {
				return abstain()
			}
			modal := modalKey(references)
			if modal == "" || probe.Key() != modal {
				return abstain()
			}
			return Result{Reading: ReadsPass, Matches: []contracts.MarkerMatch{{
				DetectorID: "det.reference_contrast",
				PatternID:  "p.con.matches_reference",
				Location:   "reference_cluster",
				Evidence:   contracts.NewDigest([]byte(modal)),
			}}}
		},
	}
}

// modalKey returns the shape key the reference cluster agrees on, and "" when it
// does not agree. A reference set with two equally supported shapes measures
// nothing, so it cannot calibrate anything either.
func modalKey(references []Shape) string {
	counts := map[string]int{}
	for _, r := range references {
		counts[r.Key()]++
	}
	best, bestN := "", 0
	for _, r := range references {
		if counts[r.Key()] > bestN {
			best, bestN = r.Key(), counts[r.Key()]
		}
	}
	if best == "" {
		return ""
	}
	for k, n := range counts {
		if k != best && n == bestN {
			return ""
		}
	}
	return best
}
