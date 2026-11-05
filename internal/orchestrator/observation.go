package orchestrator

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"xammu/internal/contracts"
	"xammu/internal/httpclient"
	"xammu/internal/integrity"
)

// buildObservation turns one exchange into C-01. It records what was sent and
// what came back, and nothing else: no signal, no score, no attribution. The
// observer is allowed to be boring on purpose, because the moment a raw record
// carries a reading of itself, every later stage inherits that reading as fact.
func (r *Run) buildObservation(item PlanItem, resp *httpclient.Response) (contracts.RawObservation, error) {
	where := resp.RequestURL
	if where == "" {
		where = item.URL
	}
	u, err := url.Parse(where)
	if err != nil {
		return contracts.RawObservation{}, fmt.Errorf("orchestrator: effective destination %q is unparsable: %w", where, err)
	}
	port := u.Port()
	number := 0
	if port != "" {
		if _, err := fmt.Sscanf(port, "%d", &number); err != nil {
			return contracts.RawObservation{}, fmt.Errorf("orchestrator: destination port %q is not a number", port)
		}
	} else if u.Scheme == "https" {
		number = 443
	} else {
		number = 80
	}

	obs := contracts.RawObservation{
		ObservationID:    contracts.NewUUID(),
		RunID:            r.profile.RunID,
		AuthorizationRef: r.auth.Ref,
		Sequence:         resp.Seq,
		ObservedAt:       r.now(),
		Target: contracts.Target{
			Scheme:       u.Scheme,
			Host:         u.Hostname(),
			Port:         number,
			Path:         pathOf(u),
			ResolvedAddr: effectiveAddr(resp),
			RedirectHops: resp.Hops,
		},
		Sent: contracts.Sent{
			Method:      orStr(resp.Method, item.Method),
			ProbeRef:    item.Ref,
			CorpusRef:   item.CorpusRef,
			AttackClass: string(item.AttackClass),
			Vector:      string(item.Vector),
			Encoding:    string(item.Encoding),
			ControlRole: string(item.ControlRole),
			HeaderCount: len(item.Headers),
			BodyBytes:   len(item.Body),
			SentAt:      resp.SentAt,
		},
		ResponseStatus:     resp.Status,
		ResponseHeaders:    resp.Headers,
		ResponseBodyBytes:  resp.BodyBytes,
		ResponseBodyDigest: resp.BodyDigest,
		Transport: contracts.Transport{
			Protocol:      resp.Protocol,
			TLSVerified:   resp.TLSVerified,
			HTTP2Used:     resp.HTTP2,
			ErrorClass:    resp.TransportError,
			ErrorDetail:   resp.TransportDetail,
			ConnectMS:     resp.ConnectMS,
			TotalMS:       resp.TotalMS,
			RedirectCount: resp.RedirectCount,
		},
		ObserverConfigHash: r.profile.ConfigHash,
	}
	if len(item.Body) > 0 {
		obs.Sent.BodyDigest = contracts.NewDigest(item.Body)
	}
	if obs.Sent.SentAt.IsZero() {
		obs.Sent.SentAt = obs.ObservedAt
	}
	// Headers are ordered so the same exchange always produces the same bytes, and
	// therefore the same digest, on a re-read of the journal.
	contracts.SortHeaders(obs.ResponseHeaders)
	if err := contracts.Validate(contracts.IDRawObservation, &obs); err != nil {
		return contracts.RawObservation{}, fmt.Errorf("orchestrator: observation for %s rejected by C-01: %w", item.Ref, err)
	}
	return obs, nil
}

// effectiveAddr records where the bytes actually went. When the exchange failed
// before a socket was established there is no resolved address to report, and
// inventing one would be the same lie as reporting a response that never
// arrived; the prefix says which of the two the field holds.
func effectiveAddr(resp *httpclient.Response) string {
	if resp.ResolvedAddr != "" {
		return resp.ResolvedAddr
	}
	authority := resp.RequestURL
	if i := strings.Index(authority, "://"); i >= 0 {
		authority = authority[i+3:]
	}
	if j := strings.Index(authority, "/"); j >= 0 {
		authority = authority[:j]
	}
	if authority == "" {
		authority = "unknown"
	}
	return "unresolved:" + authority
}

func pathOf(u *url.URL) string {
	if u.Path == "" {
		return "/"
	}
	return u.Path
}

func orStr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// SendAndObserve is the Step the pipeline uses: send the probe through the run's
// single egress, then journal the raw observation. Classification belongs to a
// later stage reading the same journal.
//
// A refusal that stopped the request inside this process produces no observation,
// because nothing happened on the wire to observe; the client already journaled
// the refusal, and the probe stays pending, which is what makes the run truncated
// instead of quietly completed.
func SendAndObserve(ctx context.Context, r *Run, item PlanItem) error {
	_, _, err := Observe(ctx, r, item)
	return err
}

// Observe is SendAndObserve with the exchange handed back.
//
// The response travels out of here for one reason: the observer has to read the
// body while it is still in this process's memory, because what the retention
// policy permits keeping is a decision about the journal, not about what a
// detector may look at once the bytes were legitimately received. The caller that
// takes the response is responsible for journalling the C-02 capture it is
// allowed to write and holding nothing else.
func Observe(ctx context.Context, r *Run, item PlanItem) (contracts.RawObservation, *httpclient.Response, error) {
	resp, err := r.Send(ctx, item.ClientRequest())
	if resp == nil {
		if err == nil {
			return contracts.RawObservation{}, nil, fmt.Errorf(
				"orchestrator: send for %s produced neither a response nor an error", item.Ref)
		}
		return contracts.RawObservation{}, nil, err
	}
	obs, buildErr := r.buildObservation(item, resp)
	if buildErr != nil {
		return contracts.RawObservation{}, resp, buildErr
	}
	if journalErr := r.Journal(integrity.StreamObservations, obs); journalErr != nil {
		return contracts.RawObservation{}, resp, fmt.Errorf(
			"orchestrator: cannot journal observation for %s: %w", item.Ref, journalErr)
	}
	// The transport failure is still returned after the evidence is written: a
	// probe that produced no response is recorded and reported as failed, never
	// silently counted as an exchange that happened.
	return obs, resp, err
}
