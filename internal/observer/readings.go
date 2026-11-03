package observer

import "xammu/internal/contracts"

// ReadingsFrom reconstructs each response detector's reading from the matches
// journaled in a C-03 record: a detector that reported a pattern produced the
// reading it declares, and one that reported nothing abstained.
//
// The observer computes readings over the live body and the classifier recomputes
// them from the journal, which is the point: re-running the same set over the same
// analysis must give the same readings, and if it does not, the disagreement is
// evidence that one of the two is not the measurement it claims to be.
func (s *DetectorSet) ReadingsFrom(matches []contracts.MarkerMatch) map[string]Result {
	out := make(map[string]Result, len(s.detectors))
	for _, d := range s.ResponseDetectors() {
		out[d.ID] = abstain()
	}
	byID := make(map[string]Detector, len(s.detectors))
	for _, d := range s.detectors {
		byID[d.ID] = d
	}
	for _, m := range matches {
		d, known := byID[m.DetectorID]
		if !known {
			// A match from outside this ensemble means the analysis came from a
			// different set; the caller compares hashes before trusting it.
			continue
		}
		if d.IsReferenceDetector() {
			// A cluster reading is never journaled as a match of one exchange: it
			// is a statement about other exchanges, and the classifier recomputes
			// it. A record that carried one was not produced by this pipeline.
			continue
		}
		reading, ok := out[d.ID]
		if !ok {
			reading = abstain()
		}
		reading.Matches = append(reading.Matches, m)
		// A detector declares at most one assertive reading, so any match it
		// reported carries that reading.
		if len(d.Emits) > 0 {
			reading.Reading = d.Emits[0]
		}
		out[d.ID] = reading
	}
	return out
}
