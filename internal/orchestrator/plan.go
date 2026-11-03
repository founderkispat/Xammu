// Package orchestrator drives one execution of the epistemic pipeline. It owns
// the C-11 state machine, the request budget, the authorization window and the
// evidence journal, and it is the only place a run may change state.
//
// Two properties are structural here rather than polite conventions: no request
// can leave while the run is in any state other than executing (criterion 27),
// and a run whose authorized budget is fully spent cannot be reported as
// completed (criterion 26) -- the decision is taken from the ledger's arithmetic,
// not from the executor's optimism.
package orchestrator

import (
	"fmt"
	"strings"

	"xammu/internal/contracts"
	"xammu/internal/httpclient"
)

// PlanItem is one planned exchange. It is planning data: what XAMMU intends to
// send and why, fixed before any response exists.
type PlanItem struct {
	Ref         string                  `json:"ref"`
	CorpusRef   string                  `json:"corpus_item_ref"`
	Group       string                  `json:"partition_group"`
	Method      string                  `json:"method"`
	URL         string                  `json:"url"`
	Body        []byte                  `json:"body,omitempty"`
	Headers     []contracts.HeaderEntry `json:"headers,omitempty"`
	AttackClass contracts.AttackClass   `json:"attack_class"`
	Vector      contracts.Vector        `json:"vector"`
	Encoding    contracts.Encoding      `json:"encoding"`
	ControlRole contracts.ControlRole   `json:"control_role"`
	Rationale   string                  `json:"rationale"`
}

// ClientRequest renders the plan item as the transport layer's request type.
func (p PlanItem) ClientRequest() httpclient.Request {
	return httpclient.Request{
		Method: p.Method, URL: p.URL, ProbeRef: p.Ref, CorpusRef: p.CorpusRef,
		AttackClass: string(p.AttackClass), Vector: string(p.Vector),
		Encoding: string(p.Encoding), ControlRole: string(p.ControlRole),
		Headers: p.Headers, Body: p.Body,
	}
}

// ValidatePlan checks a plan against the authorization that will cover it, before
// a single byte is sent. Every rejection here is a statement that the operator's
// approved scope does not include the probe, so the reason must name the field
// that failed rather than the probe's semantics.
func ValidatePlan(items []PlanItem, auth *contracts.ProfilingAuthorization,
	scope *httpclient.Scope, budget int) error {
	if len(items) == 0 {
		return fmt.Errorf("plan is empty: a run with no probes produces no evidence and must not be started")
	}
	if len(items) > budget {
		return fmt.Errorf("plan holds %d probes but the authorized request budget is %d; "+
			"the run would be truncated by arithmetic rather than by findings",
			len(items), budget)
	}
	classes := map[contracts.AttackClass]bool{}
	for _, c := range auth.AllowedClasses {
		classes[c] = true
	}
	vectors := map[contracts.Vector]bool{}
	for _, v := range auth.AllowedVectors {
		vectors[v] = true
	}
	encodings := map[contracts.Encoding]bool{}
	for _, e := range auth.AllowedEncodings {
		encodings[e] = true
	}
	seen := map[string]bool{}
	for i, p := range items {
		where := fmt.Sprintf("plan[%d] %s", i, p.Ref)
		if p.Ref == "" {
			return fmt.Errorf("%s: probe reference is required", where)
		}
		if seen[p.Ref] {
			return fmt.Errorf("%s: duplicate probe reference", where)
		}
		seen[p.Ref] = true
		if p.URL == "" {
			return fmt.Errorf("%s: destination is required", where)
		}
		if !classes[p.AttackClass] {
			return fmt.Errorf("%s: attack class %q is not in the authorization", where, p.AttackClass)
		}
		if !vectors[p.Vector] {
			return fmt.Errorf("%s: vector %q is not in the authorization", where, p.Vector)
		}
		if !encodings[p.Encoding] {
			return fmt.Errorf("%s: encoding %q is not in the authorization", where, p.Encoding)
		}
		if !validRole(p.ControlRole) {
			return fmt.Errorf("%s: control role %q is unknown", where, p.ControlRole)
		}
		if strings.TrimSpace(p.Rationale) == "" {
			return fmt.Errorf("%s: a probe without a stated rationale is an unexplained request "+
				"against someone's system", where)
		}
		if err := scope.CheckRequest(p.Method, p.URL, p.Ref); err != nil {
			return fmt.Errorf("%s: destination refused by the authorization: %w", where, err)
		}
	}
	return nil
}

func validRole(r contracts.ControlRole) bool {
	for _, v := range contracts.AllControlRoles() {
		if v == r {
			return true
		}
	}
	return false
}
