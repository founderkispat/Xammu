package inference

import (
	"testing"

	"xammu/internal/contracts"
)

func trial(status int, signal contracts.Signal) Trial {
	return Trial{StatusCode: status, Signal: signal}
}

// cellOf builds the signal tally CellsBy would have produced, because cellBlocker
// reads the tally before it looks at the statuses.
func cellOf(trials ...Trial) Cell {
	c := Cell{Trials: trials, Signals: map[contracts.Signal]int{}}
	for _, tr := range trials {
		c.Signals[tr.Signal]++
	}
	return c
}

func TestEveryTrialFromAFailingOrigin(t *testing.T) {
	cases := []struct {
		name   string
		trials []Trial
		want   bool
	}{
		{"no trials is not a failing origin", nil, false},
		{"every trial 5xx", []Trial{
			trial(500, contracts.SignalIndeterminate),
			trial(502, contracts.SignalIndeterminate),
			trial(599, contracts.SignalIndeterminate),
		}, true},
		{"one answer below 500 disproves it", []Trial{
			trial(502, contracts.SignalIndeterminate),
			trial(499, contracts.SignalIndeterminate),
		}, false},
		// Status 0 means the exchange never arrived: that is a transport failure, not a
		// destination that answers with an error, and the two get different reasons.
		{"a transport failure is not a 5xx origin", []Trial{
			trial(0, contracts.SignalTransportError),
		}, false},
	}
	for _, tc := range cases {
		cell := cellOf(tc.trials...)
		if got := everyTrialFromAFailingOrigin(cell); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestStatusTallyNamesWhatTheCellSaw(t *testing.T) {
	cases := []struct {
		name   string
		trials []Trial
		want   string
	}{
		{"no status", []Trial{trial(0, contracts.SignalTransportError)}, ""},
		{"no trials", nil, ""},
		{"unique and sorted", []Trial{
			trial(502, contracts.SignalIndeterminate),
			trial(200, contracts.SignalPass),
			trial(502, contracts.SignalIndeterminate),
			trial(0, contracts.SignalTransportError),
			trial(404, contracts.SignalIndeterminate),
		}, ", statuses: 200,404,502"},
	}
	for _, tc := range cases {
		cell := cellOf(tc.trials...)
		if got := statusTally(cell); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}

// TestAFailingOriginIsTypedAsSuch: an indeterminate reading that arrived as a 5xx is
// blamed on an unstable destination, not on an ambiguous signal. The distinction is
// what tells a reader the zone was unmeasurable rather than merely unclear.
func TestAFailingOriginIsTypedAsSuch(t *testing.T) {
	cell := cellOf(
		trial(502, contracts.SignalIndeterminate),
		trial(502, contracts.SignalIndeterminate),
	)
	if got := cellBlocker(cell); got != contracts.ReasonOriginUnstable {
		t.Errorf("an all-502 cell is blocked for %q, expected %q", got, contracts.ReasonOriginUnstable)
	}
	// One exchange that arrived below 500 means the destination works; the ambiguity
	// is then in the signal and the reason must say so.
	mixed := cellOf(
		trial(502, contracts.SignalIndeterminate),
		trial(200, contracts.SignalIndeterminate),
	)
	if got := cellBlocker(mixed); got != contracts.ReasonInconclusiveSignal {
		t.Errorf("a mixed cell is blocked for %q, expected %q", got, contracts.ReasonInconclusiveSignal)
	}
}
