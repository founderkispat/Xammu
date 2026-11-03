package inference_test

import (
	"net/http"
	"strings"
	"testing"

	"xammu/internal/contracts"
	"xammu/internal/integrity"
)

// TestAFailingOriginLeavesTheZoneUndetermined is the honest shape of a broken
// destination: the target answers 502 to everything, no trial produces a valid
// reading, and the cell is reported as undetermined for the reason that the origin
// is failing rather than for an ambiguous signal. The detail names the status, so a
// reader can see which failure the tool is blaming.
func TestAFailingOriginLeavesTheZoneUndetermined(t *testing.T) {
	scripts := map[string]script{
		"P-Q1": {status: http.StatusBadGateway, body: ordinaryBody},
		"P-Q2": {status: http.StatusBadGateway, body: ordinaryBody},
	}
	specs := []probeSpec{
		{ref: "P-Q1", method: "GET", vector: contracts.VectorQuery, role: contracts.RoleProbe},
		{ref: "P-Q2", method: "GET", vector: contracts.VectorQuery, role: contracts.RoleProbe},
	}
	rd := runPipeline(t, scripts, specs, 10)

	if len(rd.ex.Failures) != 0 {
		t.Fatalf("a 502 is a completed exchange, not a transport failure: %v", rd.ex.Failures[0])
	}
	if len(rd.res.Verdicts) != 1 {
		t.Fatalf("%d verdicts for one probe cell", len(rd.res.Verdicts))
	}
	v := rd.res.Verdicts[0]
	if v.Cell.Valid != 0 || v.Cell.Inconclusive != 2 {
		t.Errorf("valid=%d inconclusive=%d over two 502 responses",
			v.Cell.Valid, v.Cell.Inconclusive)
	}
	if v.Profile.Level != contracts.EvidenceNone {
		t.Errorf("evidence level %s over no valid trial", v.Profile.Level)
	}
	if v.Hypothesis != nil {
		t.Error("a failing origin produced a hypothesis about a filter")
	}
	if len(v.Obstacles) == 0 {
		t.Fatal("the cell vanished without a typed obstacle")
	}
	ob := v.Obstacles[0]
	if ob.Reason != contracts.ReasonOriginUnstable {
		t.Errorf("obstacle reason %q: the destination answered, and it answered 502", ob.Reason)
	}
	for _, want := range []string{"statuses: 502", "signal_indeterminate"} {
		if !strings.Contains(ob.Detail, want) {
			t.Errorf("obstacle detail %q does not name %q", ob.Detail, want)
		}
	}
	if !strings.Contains(v.Skip, "undetermined") {
		t.Errorf("skip reason %q does not call the zone what it is", v.Skip)
	}
	if got := rd.store().Count(integrity.StreamHypotheses); got != 0 {
		t.Errorf("%d hypotheses journalled over a failing origin", got)
	}
}
