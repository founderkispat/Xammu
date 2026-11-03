package attributor

import (
	"fmt"

	"xammu/internal/contracts"
)

// evaluate rates every competing explanation for the subject. All ten are always
// present: C-05 refuses an attribution whose primary candidate is not among the
// evaluated alternatives, and an omission is harder to notice than a rating of
// "not ruled out".
//
// The rule-out arithmetic is the substance of this function. Four explanations can
// be excluded from HTTP evidence plus valid controls: a limit, a client-side or
// network failure, a harness artifact, and anything that answers identically
// whatever the payload carries (an authorization layer, or a route difference, when
// the probes and the references took the same path and method). The rest cannot be
// excluded from one origin at all, and saying so is what tells an engineer which
// authorization to ask for next.
func evaluate(sub Subject, primary contracts.AlternativeKind) []contracts.AlternativeAssessment {
	blockObserved := containsSignal(sub, contracts.SignalBlock)
	has429 := anyStatus(sub, 429)
	transportFailure := containsSignal(sub, contracts.SignalTransportError)
	everyExchangeCompleted := !transportFailure && everyResponded(sub)
	calibrated := sub.Controls.PositiveValid() && sub.Controls.NegativeValid()
	benignRejected := contains(sub.Controls.NegativeSignals, contracts.SignalBlock)
	// Same path and method for the payload probes and the references, with the
	// references answered normally: whatever changed the answer came with the
	// payload, not with the route or the session.
	sameRouteCleanBaseline := calibrated && !benignRejected

	out := []contracts.AlternativeAssessment{
		{
			Kind: contracts.AltWAF,
			Justification: fmt.Sprintf(
				"the subject is a %s probe placed in the %s vector with %s encoding against %s%s",
				orNone(string(sub.AttackClass)), orNone(string(sub.Vector)),
				orNone(string(sub.Encoding)), sub.TargetOrigin, pathPhrase(sub)),
			TestThatWouldResolve: "compare the response with the same probe sent to the origin directly, " +
				"under its own authorization: a filter rule disappears on that path and an application " +
				"reaction does not",
			State: func() contracts.AlternativeState {
				if blockObserved && calibrated && !benignRejected {
					return contracts.AltSupported
				}
				return contracts.AltNotRuledOut
			}(),
		},
		{
			Kind:                 contracts.AltOriginApplication,
			Justification:        "the origin's own validation can reject exactly the bytes a filter rejects",
			TestThatWouldResolve: "send the same probe to the origin bypassing the front layer, under separate authorization",
			State: func() contracts.AlternativeState {
				if benignRejected {
					return contracts.AltSupported
				}
				return contracts.AltNotRuledOut
			}(),
		},
		{
			Kind: contracts.AltReverseProxyOrCDN,
			Justification: "the authorized scope covers one origin host; an intermediate caching or " +
				"edge layer answers through the same name and cannot be separated from it here",
			TestThatWouldResolve: "resolve the origin behind the edge and probe it directly under its own " +
				"authorization, or read the edge platform's own block identifiers in a log export",
			State: notRuledOutOr(primary, contracts.AltReverseProxyOrCDN),
		},
		{
			Kind: contracts.AltLoadBalancerInfra,
			Justification: "a shared infrastructure rule answers for every node behind one address, " +
				"and node-level variation is not observable from a single origin",
			TestThatWouldResolve: "repeat across several rounds and, where the scope allows, against each " +
				"node address: an infrastructure rule is uniform across them, a node-local one is not",
			State: notRuledOutOr(primary, contracts.AltLoadBalancerInfra),
		},
		{
			Kind:                 contracts.AltRateLimiting,
			Justification:        "pacing is visible in the status line: a 429 with or without Retry-After",
			TestThatWouldResolve: "slow the run below the authorized rate and repeat the probe; a limit returns, a rule does not",
			State: func() contracts.AlternativeState {
				if has429 || containsSignal(sub, contracts.SignalRateLimited) {
					return contracts.AltSupported
				}
				if everyExchangeCompleted {
					return contracts.AltRuledOut
				}
				return contracts.AltNotRuledOut
			}(),
		},
		{
			Kind: contracts.AltAuthZLayer,
			Justification: "an authorization rule keys on the session and the route, not on the " +
				"query string, so it answers benign and attack traffic alike",
			TestThatWouldResolve: "carry valid credentials obtained under the same authorization and " +
				"compare; a 401/403 that persists for benign traffic on the same route is the session, not the payload",
			State: func() contracts.AlternativeState {
				switch {
				case benignRejected || allAuthStatus(sub):
					return contracts.AltSupported
				case sameRouteCleanBaseline:
					return contracts.AltRuledOut
				default:
					return contracts.AltNotRuledOut
				}
			}(),
		},
		{
			Kind: contracts.AltNetworkOrClient,
			Justification: "a socket that never completed, or never received a status line, is a " +
				"fact about the path between this process and the target",
			TestThatWouldResolve: "repeat the exchange from a second client inside the same authorized " +
				"scope; a network artifact moves with the client, a rule does not",
			State: func() contracts.AlternativeState {
				if transportFailure {
					return contracts.AltSupported
				}
				if everyExchangeCompleted {
					return contracts.AltRuledOut
				}
				return contracts.AltNotRuledOut
			}(),
		},
		{
			Kind: contracts.AltHarnessArtifact,
			Justification: "the corpus item, its encoding or the placement itself could produce a " +
				"response that has nothing to do with the target",
			TestThatWouldResolve: "run the inertness gate over the corpus item and replay the reference " +
				"probe with the payload removed: identical answers exclude the harness, divergent ones do not",
			State: func() contracts.AlternativeState {
				switch {
				// Checked before calibration: the controls ran on other exchanges, so
				// their clean answers say nothing about why this one never completed.
				// A harness artifact that mangles one probe's request is exactly what a
				// socket failure looks like from here.
				case transportFailure:
					return contracts.AltSupported
				case calibrated:
					return contracts.AltRuledOut
				default:
					return contracts.AltNotRuledOut
				}
			}(),
		},
		{
			Kind: contracts.AltInputNormalization,
			Justification: "a framework that decodes, re-encodes or truncates input before the " +
				"application sees it changes what any downstream inspection reads",
			TestThatWouldResolve: fmt.Sprintf(
				"compare the reading for %s encoding against the canonical form on the same vector: a "+
					"normalization difference changes one and not the other", orNone(string(sub.Encoding))),
			State: notRuledOutOr(primary, contracts.AltInputNormalization),
		},
		{
			Kind: contracts.AltRoutingDivergence,
			Justification: "different handlers answer different paths, and a payload placed in one is " +
				"not the same request as that payload placed in another",
			TestThatWouldResolve: "issue the identical probe against a second authorized path on the same " +
				"origin: a routing difference changes the answer, a filter rule does not",
			State: func() contracts.AlternativeState {
				switch {
				case sameRouteCleanBaseline:
					return contracts.AltRuledOut
				case primary == contracts.AltRoutingDivergence:
					return contracts.AltSupported
				default:
					return contracts.AltNotRuledOut
				}
			}(),
		},
	}
	return out
}

func notRuledOutOr(primary, kind contracts.AlternativeKind) contracts.AlternativeState {
	if primary == kind {
		return contracts.AltSupported
	}
	return contracts.AltNotRuledOut
}

func anyStatus(sub Subject, code int) bool {
	for _, d := range sub.Evidence {
		if d.StatusCode == code {
			return true
		}
	}
	return false
}

// allAuthStatus reports that every exchange in the subject answered 401 or 403,
// which is what a session or authorization wall looks like from outside.
func allAuthStatus(sub Subject) bool {
	for _, d := range sub.Evidence {
		if d.StatusCode != 401 && d.StatusCode != 403 {
			return false
		}
	}
	return len(sub.Evidence) > 0
}

func everyResponded(sub Subject) bool {
	for _, d := range sub.Evidence {
		if d.StatusCode == 0 {
			return false
		}
	}
	return true
}

func pathPhrase(sub Subject) string {
	if sub.Path == "" {
		return ""
	}
	return " on " + sub.Path
}

func orNone(s string) string {
	if s == "" {
		return "unspecified"
	}
	return s
}

// missingFor lists what would raise the grade, from the conditions that failed and
// the explanations that survived. C-05 requires this for any graded attribution and
// C-06 repeats it, because an engineer reading "probable" needs the next test, not
// the consolation prize.
func missingFor(sub Subject, cc contracts.ConfirmedConditions,
	alts []contracts.AlternativeAssessment) []string {
	var out []string
	if !cc.ReproducibleAcrossRounds {
		out = append(out, "a second independently authorized round reproducing this signal; "+
			"this subject rests on "+roundsPhrase(sub))
	}
	if !cc.ValidControlsInScope {
		why := "the run recorded no positive and negative control pair on this subject"
		switch {
		case !sub.Controls.PositiveValid() && !sub.Controls.NegativeValid():
			why = "neither control class produced a usable reading: no positive control was rejected " +
				"and no benign reference was answered as ordinary handling"
		case !sub.Controls.PositiveValid():
			why = "no positive control read as a rejection, so the detector set has nothing to calibrate against"
		case !sub.Controls.NegativeValid():
			why = "a benign reference did not read as ordinary handling, so the run cannot tell a " +
				"payload reaction from a blanket one"
		}
		out = append(out, "valid positive and negative controls on the same path and method: "+why)
	}
	if !cc.CorroboratedByIndependentSrc {
		out = append(out, "a source outside the HTTP exchange -- a filter log entry or a configuration "+
			"export -- that agrees with the reading; without one the grade cannot pass "+
			string(contracts.AttributionProbable))
	}
	for _, alt := range alts {
		if alt.State == contracts.AltRuledOut || alt.State == contracts.AltNotInScope {
			continue
		}
		if alt.Kind == contracts.AltWAF && cc.ValidControlsInScope &&
			containsSignal(sub, contracts.SignalBlock) {
			// The subject is about the filter candidate; listing it as missing
			// evidence would tell the engineer to test the thing they already asked about.
			continue
		}
		out = append(out, fmt.Sprintf("to exclude %s: %s", alt.Kind, alt.TestThatWouldResolve))
	}
	return out
}
