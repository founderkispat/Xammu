package corpus

import (
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
	"time"

	"xammu/internal/contracts"
)

// GateVersion is stamped into every C-13 inertness record this package writes.
// Changing a rule below means changing this string: a corpus gated by an older
// rule set must be re-gated rather than trusted, and the record says which set
// judged it.
const GateVersion = "xammu-inertness-gate/1.0.0"

// Policy is the inertness gate's configuration. The zero value is not usable: a
// gate with no marker token would accept anonymous traffic, so Load refuses it.
type Policy struct {
	// MarkerToken must appear in every probe. It is what makes a request
	// identifiable as diagnostic in the target's access log, and what lets an
	// operator tell XAMMU's traffic from an actual attack after the fact.
	MarkerToken string

	// MaxProbeBytes caps probe length. A very long value is a stack of nested
	// shapes, and a reviewer cannot certify what they cannot read.
	MaxProbeBytes int

	// AllowedHosts are the only hosts a probe may name in a URL. Loopback and the
	// laboratory service names are in the default set; a probe pointing at a
	// routable host is an out-of-band channel and is refused.
	AllowedHosts []string
}

// DefaultPolicy is the shipped gate: marker "xammu-probe", 512 bytes, and only
// loopback or laboratory hostnames reachable from a probe's URL.
func DefaultPolicy() Policy {
	return Policy{
		MarkerToken:   "xammu-probe",
		MaxProbeBytes: 512,
		AllowedHosts: []string{
			"localhost", "127.0.0.1", "::1", "[::1]", "origin", "waf", "waf-stripped",
		},
	}
}

// rule is one inertness check. It fires on a probe that looks able to do
// something other than be observed.
type rule struct {
	id     string
	reason string
	re     *regexp.Regexp
}

// inertRules is the whole rule set. Matching is case-insensitive and runs on the
// probe as authored, before any transport escaping: what the gate cannot see, it
// cannot approve.
var inertRules = []rule{
	{id: "inert.sql.data_exfiltration",
		reason: "reads data out of a database, which is extraction rather than diagnosis",
		re:     regexp.MustCompile(`(?i)\bunion\b[\s\S]{0,80}\bselect\b|\bfrom\s+information_schema\b|\bselect\b[\s\S]{0,60}\binto\b`)},
	{id: "inert.sql.write",
		reason: "mutates or destroys data",
		re:     regexp.MustCompile(`(?i)\b(drop\s+table|delete\s+from|insert\s+into|update\s+\w+\s+set|truncate\s+table|alter\s+table)\b`)},
	{id: "inert.sql.file_access",
		reason: "asks the database to touch the filesystem",
		re:     regexp.MustCompile(`(?i)\b(load_file|into\s+(out|dump)file|loaddump|pg_read_file|utl_inaddr)\b`)},
	{id: "inert.sql.stacked_query",
		reason: "chains a second statement onto the first, which is execution not observation",
		re:     regexp.MustCompile(`(?i);\s*(select|insert|update|delete|drop|create|exec|truncate)\s`)},
	{id: "inert.sql.timed_side_effect",
		reason: "makes the database wait or compute, i.e. a side channel rather than a signature test",
		re:     regexp.MustCompile(`(?i)\b(sleep|benchmark|pg_sleep|waitfor\s+delay|dbms_pipe\.sleep)\s*\(`)},
	{id: "inert.db.exec",
		reason: "calls an operating-system command through the database",
		re:     regexp.MustCompile(`(?i)\b(xp_cmdshell|sp_executesql|sys\.odbc_exec|utl_http|runcommand)\b`)},
	{id: "inert.os.command_substitution",
		reason: "embeds a command substitution or an interpreter call, which the target would run",
		re:     regexp.MustCompile("(?i)`|\\$\\(|\\b(exec|eval|system|popen|shell_exec|passthru|proc_open|os\\.system)\\s*\\(")},
	{id: "inert.os.binary_named",
		reason: "names a real binary, shell or system file to be reached",
		re:     regexp.MustCompile(`(?i)/bin/(sh|bash)|cmd\.exe|\bpowershell\b|/etc/(passwd|shadow|hosts)|\bcurl\b|\bwget\b|\bnc\b|\bnetcat\b|\bsocat\b|bash\s+-i|python\s+-c`)},
	{id: "inert.os.reverse_shell",
		reason: "opens a network socket from the target, i.e. a foothold",
		re:     regexp.MustCompile(`(?i)/dev/(tcp|udp)|\bncat\b|\bbind\s+shell\b`)},
	{id: "inert.script.executable",
		reason: "carries script a browser would run",
		re:     regexp.MustCompile(`(?i)<\s*script|javascript\s*:\s*(?:\w+\s*[\(.]|alert|eval|prompt|confirm|fetch|document|window|location|top\.|parent\.)|data\s*:\s*text/html|\bon(error|load|click|mouseover|focus)\s*=|\b(alert|prompt|confirm|fetch|XMLHttpRequest)\s*\(|document\.cookie|localStorage|sessionStorage`)},
	{id: "inert.template.expression",
		reason: "is a template or expression injection that evaluates",
		re:     regexp.MustCompile(`(?i)\$\{[^}]*\b(jndi|T\(|Runtime|getRuntime|getClass)|@\{[^}]*\b(Runtime|T\()|\{\{[^}]*__`)},
	{id: "inert.xml.external_entity",
		reason: "declares an external entity or an internal subset, which makes the server fetch a resource",
		re:     regexp.MustCompile(`(?i)<!ENTITY\s+[\w%]*\s+(SYSTEM|PUBLIC)\s|<!DOCTYPE\s+[^>\[]*\[`)},
	{id: "inert.file.null_byte",
		reason: "uses a truncation byte to alter how a path is interpreted",
		re:     regexp.MustCompile(`%00|\x00`)},
	{id: "inert.file.absolute_path",
		reason: "references a real filesystem location rather than a marker-shaped one",
		re:     regexp.MustCompile(`(?i)(\.\./){2,}[\w./-]*\b(etc|proc|sys|windows|winnt|system32|home/|var/)\b`)},
	{id: "inert.url.scheme_smuggling",
		reason: "uses a non-HTTP URL scheme that turns the target into a client",
		re:     regexp.MustCompile(`(?i)\b(gopher|dict|file|ftp|ldap|ldaps|jar|netdoc|php|expect|rmi|tftp)://`)},
	{id: "inert.ldap.filter",
		reason: "closes an LDAP filter and appends a second condition",
		re:     regexp.MustCompile(`(?i)\)\s*\(&|\)\s*\(\||\(&\s*\|`)},
	{id: "inert.nosql.operator",
		reason: "injects a query operator that changes what the database returns",
		re:     regexp.MustCompile(`(?i)\$(?:where|gt|gte|lt|lte|ne|nin|in|regex|exists|elemMatch|type)\b`)},
	{id: "inert.control.request_smuggling",
		reason: "manipulates request framing, which is out of scope by design",
		re:     regexp.MustCompile(`(?i)\b(transfer-encoding|content-length)\s*:`)},
	{id: "inert.secret.material",
		reason: "carries credential-shaped material; a diagnostic probe has no reason to",
		re:     regexp.MustCompile(`(?i)\b(api[_-]?key|secret|token|password|passwd|pwd)\s*[:=]\s*[A-Za-z0-9/+=_-]{8,}|AKIA[0-9A-Z]{16}|-----BEGIN`)},
}

// allowedControlBytes is checked character by character rather than by pattern:
// control bytes are how a probe smuggles a request boundary that a JSON file
// cannot show a reviewer. \r\n stays allowed because the CRLF-injection class is
// defined by exactly that sequence, and \t because whitespace-variant encodings
// are a documented vector.
var allowedControlBytes = map[byte]bool{'\r': true, '\n': true, '\t': true}

// Finding is one gate hit.
type Finding struct {
	Rule   string `json:"rule"`
	Reason string `json:"reason"`
}

// Check runs the gate over one probe and returns every hit. An empty result
// means the probe has diagnostic shape without execution capability.
func (p Policy) Check(probe string) []Finding {
	var hits []Finding
	if !strings.Contains(strings.ToLower(probe), strings.ToLower(p.MarkerToken)) {
		hits = append(hits, Finding{
			Rule: "inert.marker_absent",
			Reason: "the probe does not carry the marker token " + p.MarkerToken + ": traffic that cannot be " +
				"identified as diagnostic in the target's log is indistinguishable from an attack",
		})
	}
	if len(probe) > p.MaxProbeBytes {
		hits = append(hits, Finding{
			Rule: "inert.over_length",
			Reason: fmt.Sprintf("the probe is %d bytes, above the %d the gate will certify by reading",
				len(probe), p.MaxProbeBytes),
		})
	}
	for _, r := range inertRules {
		if r.re.MatchString(probe) {
			hits = append(hits, Finding{Rule: r.id, Reason: r.reason})
		}
	}
	for i := 0; i < len(probe); i++ {
		b := probe[i]
		if (b < 0x20 && !allowedControlBytes[b]) || b == 0x7f {
			hits = append(hits, Finding{
				Rule: "inert.control_byte",
				Reason: fmt.Sprintf("byte %d is an unprintable control character (0x%02x): a probe that hides "+
					"framing bytes cannot be reviewed as text", i, b),
			})
			break
		}
	}
	if why := p.checkURLs(probe); why != "" {
		hits = append(hits, Finding{Rule: "inert.url.host_not_allowed", Reason: why})
	}
	sort.Slice(hits, func(i, k int) bool { return hits[i].Rule < hits[k].Rule })
	return hits
}

// checkURLs refuses a probe whose URL names a host outside the allowlist. The
// host is what decides whether a probe stays inside the authorized target, so it
// is checked as a host and not as a substring.
func (p Policy) checkURLs(probe string) string {
	for _, m := range urlCandidateRE.FindAllString(probe, -1) {
		trimmed := strings.TrimPrefix(strings.TrimPrefix(m, "http://"), "https://")
		host, _, cut := strings.Cut(trimmed, "/")
		if !cut {
			host = trimmed
		}
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		host = strings.Trim(host, "[]")
		if host == "" {
			return fmt.Sprintf("the URL %q has no host: a probe with an unparseable destination cannot be "+
				"shown to stay inside the authorized target", m)
		}
		allowed := false
		for _, a := range p.AllowedHosts {
			if strings.EqualFold(a, host) {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Sprintf("the probe names host %q, outside the allowlist (%s): a diagnostic probe may "+
				"not reach a routable address, which would send traffic against a third party from this run",
				host, strings.Join(p.AllowedHosts, ", "))
		}
	}
	return ""
}

var urlCandidateRE = regexp.MustCompile(`(?i)\bhttps?://[^\s'"<>]+`)

// Apply runs the gate over an item and writes the resulting C-13 inertness
// record. It refuses rather than downgrading: the claim in the file is checked,
// and a disagreement is an error the operator has to resolve, not an input.
func (p Policy) Apply(item *contracts.CorpusItem) error {
	hits := p.dropMarkerForBenignTraffic(item.Probe, item.Purpose)
	if item.Canonical != "" {
		// The canonical form is what a reviewer reads as the probe's meaning. If
		// it can execute, the encoded variant is only a disguise over it.
		for _, h := range p.Check(item.Canonical) {
			if h.Rule == "inert.marker_absent" {
				continue
			}
			hits = append(hits, Finding{Rule: h.Rule, Reason: h.Reason + " (in the declared canonical form)"})
		}
	}
	rules := make([]string, 0, len(hits))
	for _, h := range hits {
		rules = append(rules, h.Rule)
	}
	if item.Inertness.CheckedAt.IsZero() {
		return fmt.Errorf("corpus: ref %q has no inertness.checked_at: the gate records when it judged a "+
			"probe so that a later rule change can be traced; a blank date makes that trace impossible", item.Ref)
	}
	item.Inertness.GateVersion = GateVersion
	item.Inertness.RuleHits = rules
	if len(hits) == 0 {
		item.Inertness.Verdict = contracts.InertVerified
		item.Inertness.Notes = "gate " + GateVersion + " found no execution-capable shape: the probe carries " +
			p.MarkerToken + ", names no routable host, and matches none of the " +
			fmt.Sprintf("%d", len(inertRules)) + " refusal rules"
		return nil
	}
	item.Inertness.Verdict = contracts.InertFailed
	var why []string
	for _, h := range hits {
		why = append(why, h.Rule+" ("+h.Reason+")")
	}
	item.Inertness.Notes = "gate " + GateVersion + " refused: " + strings.Join(why, "; ")
	return fmt.Errorf("corpus: ref %q is not inert: %s: XAMMU discovers defensive behaviour rather than "+
		"exploiting it, so a probe with this shape does not enter the corpus",
		item.Ref, strings.Join(why, "; "))
}

// dropMarkerForBenignTraffic runs the gate and then forgives exactly one hit, for
// the items that are ordinary traffic by definition. A negative control carrying
// a diagnostic marker is not a negative control: its whole purpose is to look
// like what a real user sends. Every other rule still applies, because "benign"
// is not the same as "unchecked" -- a reference that closes an LDAP filter or
// names a routable host is refused like any other probe.
func (p Policy) dropMarkerForBenignTraffic(probe string, purpose contracts.Purpose) []Finding {
	hits := p.Check(probe)
	switch purpose {
	case contracts.PurposeBenignReference, contracts.PurposeNegativeControl, contracts.PurposeOverBlockProbe:
	default:
		return hits
	}
	out := make([]Finding, 0, len(hits))
	for _, h := range hits {
		if h.Rule == "inert.marker_absent" {
			continue
		}
		out = append(out, h)
	}
	return out
}

// staleGate reports whether an item's own record was written by a different gate
// version than the one judging it now. The verdict is re-derived either way; the
// mismatch is surfaced because a corpus gated by a weaker rule set has to be
// re-certified deliberately rather than quietly re-blessed on load.
// mismatch is surfaced because a corpus gated by a weaker rule set has to be
// re-certified deliberately rather than quietly re-blessed on load.
func staleGate(item contracts.CorpusItem) bool {
	return item.Inertness.GateVersion != "" && item.Inertness.GateVersion != GateVersion
}

// checkedInThePast guards against a record whose timestamp is a placeholder.
func checkedInThePast(item contracts.CorpusItem, now time.Time) bool {
	return item.Inertness.CheckedAt.After(now.Add(24 * time.Hour))
}
