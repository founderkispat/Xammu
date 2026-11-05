# The XAMMU corpus

The corpus is the set of requests XAMMU is allowed to make. Nothing else in this
repository authorises an exchange with a target: the orchestrator plans a run from
`corpus/` items, and an item that the loader refuses is a request that never leaves
the process.

That is the whole reason the corpus is code rather than a text file of payloads. A
payload list can contain a working exploit and nobody notices until a run executes it.
A corpus is gated before it is read.

**XAMMU discovers defensive behaviour. It does not exploit anything.** If a payload has
the capability to do something to a system, it does not belong here. Every probe in this
tree is shaped like an attack and carries no capability: it names the marker token, it
addresses the laboratory host, and the rule that fires on it is the point of the
exercise, not a step toward damage.

## Layout

| Directory | Partition | Purpose | Sealed uses |
|---|---|---|---|
| `calibration/` | `calibration` | Detector validation. Traffic sent before and after probes so a reading means something. | calibration, profiling, threshold setting |
| `development/` | `development` | Coverage diagnosis. The probes a run plans against to learn where the WAF inspects. | profiling, detector development, tuning, threshold setting, regression |
| `independent_validation/` | `independent_validation` | The set the detectors were *not* written against. The only partition that can say a finding replicated. | independent validation, documentation |

Membership is decided by the directory a line lives in, not by the `partition` field
inside it. A record that claims a partition it is not filed in is refused at load:
"the directory is the authority on membership." Otherwise a copied line could move
traffic into a sealed partition without moving any bytes.

Files are JSONL — one `contracts.CorpusItem` (C-13) per line. Any unknown field is an
error at load (`DisallowUnknownFields`), so a typo in a field name cannot silently drop
a constraint.

## The inertness gate

`internal/corpus/inert.go`. The gate is a **precondition of loading**, not a linter you
can skip: `corpus.Load(root, gate)` runs `gate.Apply(item)` on every line, and a probe
that fails refuses the whole tree with the rule ids it hit.

Two properties are worth stating plainly, because they are the opposite of what most
corpora do:

1. **The gate re-runs at load and overwrites the record.** `inertness.verdict`,
   `gate_version` and `rule_hits` in the file are treated as a *claim*. If the claim and
   a fresh evaluation disagree, the tree is refused. A file cannot certify itself.
2. **`probe_digest` is derived from the probe.** Load recomputes
   `sha256:` over the bytes it read. An empty digest is filled in; a digest that
   disagrees with its own probe is a refusal, not a recompute. A record whose digest
   points somewhere else makes every downstream statement about that digest a lie.

A gate whose version differs from the shipped `GateVersion` (`xammu-inertness-gate/1.0.0`)
is reported as a stale gate, and a partition carrying stale-gated items refuses to load.
Certification against a weaker rule set has to be a deliberate re-certification, not an
accident of the file being older than the code.

### What the gate refuses

Nineteen rules, all named `inert.*`, matched case-insensitively against the probe **as
authored** — before any transport escaping, because what the gate cannot see it cannot
approve:

- **SQL with an effect** — `sql.data_exfiltration` (`union … select`,
  `from information_schema`, `select … into`), `sql.write` (`drop table`, `delete from`,
  `insert into`, `update … set`, `truncate table`, `alter table`), `sql.file_access`
  (`load_file`, `into outfile|dumpfile`, `loaddump`, `pg_read_file`, `utl_inaddr`),
  `sql.stacked_query` (`;` then a statement keyword — a probe that chains a second
  statement is execution, not observation), `sql.timed_side_effect` (`sleep(`,
  `benchmark(`, `pg_sleep`, `waitfor delay`, `dbms_pipe.sleep(`) — a probe that sleeps is
  a probe that occupies a worker.
- **Database-side execution** — `db.exec` (`xp_cmdshell`, `sp_executesql`,
  `sys.odbc_exec`, `utl_http`, `runcommand`).
- **OS-level execution** — `os.command_substitution` (backtick, `$(`, and any of
  `exec|eval|system|popen|shell_exec|passthru|proc_open|os.system(`), `os.binary_named`
  (`/bin/sh`, `/bin/bash`, `cmd.exe`, `powershell`, `/etc/passwd|shadow|hosts`, `curl`,
  `wget`, `nc`, `netcat`, `socat`, `bash -i`, `python -c`), `os.reverse_shell`
  (`/dev/tcp`, `/dev/udp`, `ncat`, `bind shell`) — a socket opened from the target is a
  foothold, not a measurement.
- **Script and template execution** — `script.executable` (`<script`, an event handler
  attribute, `alert(`/`fetch(`/`XMLHttpRequest(`, `document.cookie`,
  `localStorage`/`sessionStorage`, `data:text/html`, and a `javascript:` URL that
  actually references a call or a DOM object), `template.expression` — only an
  expression that reaches for something live (`${…Jndi|Runtime|getClass`, `@{…Runtime`,
  `{{__…`); a bare `${id}` stays allowed because it is syntax, not capability.
- **Parser attacks** — `xml.external_entity` (`<!ENTITY … SYSTEM|PUBLIC `, or a
  `<!DOCTYPE` carrying an internal subset): XXE makes the server fetch a resource, so it
  is a file read dressed as a string match.
- **Request-boundary effects** — `file.null_byte` (`%00` or a raw NUL: truncation
  behaviour is a bug in the origin, not evidence about the defence),
  `file.absolute_path` (`../../` resolving into `etc|proc|sys|windows|winnt|system32|home/|var/`),
  `url.scheme_smuggling` (any of `gopher|dict|file|ftp|ldap|ldaps|jar|netdoc|php|expect|rmi|tftp://`
  — a non-HTTP scheme turns the target into a client), `control.request_smuggling` (a
  `Transfer-Encoding:` or `Content-Length:` inside the probe: it can desynchronise a real
  front end from a real origin, and there is no version of that which is safe to send at
  somebody else's system).
- **Query-semantics surgery** — `ldap.filter` (`)(&`, `)(|`, `(&|` — a filter whose
  boolean structure is being rewritten; a marker inside a *balanced* filter like
  `)(xammu-probe=*` is shape only and passes), `nosql.operator` (`$ne`, `$gt`, `$in`,
  `$where`, `$regex`, `$elemMatch`, …).
- **Secret material** — `secret.material` (`api_key|secret|token|password|pwd` assigned a
  value of 8+ characters, an `AKIA…` access key, a PEM `-----BEGIN` header). A diagnostic
  probe has no reason to carry a credential, so one that does is either not diagnostic or
  not safe to log.

Plus four structural checks: the marker token must be present (see the exception), the
probe must be ≤ 512 bytes (a long value is a stack of nested encodings that a reviewer
cannot read at a glance), no unprintable control bytes except `\r \n \t` — which is what
keeps a CRLF probe reviewable as text while still allowing the class that is defined by
that sequence — and every URL in a probe must name a host in the allowlist (`localhost`,
`127.0.0.1`, `::1`, `[::1]`, `origin`, `waf`, `waf-stripped`). A probe that points at
someone else's host is an attack on them.


### The marker exception

`inert.marker_absent` is required for `coverage_diagnosis` and `encoding_replica` items.
It is forgiven for `benign_reference`, `negative_control` and `over_blocking_probe`:
those items are *supposed* to look like ordinary traffic — a benign reference that is
marked is not a test of anything. Forgiven means only the marker rule. `inert.*`
capability rules still run, so `widget list page 2; /bin/sh` labelled a negative control
is still refused.

### Why `nosql_injection` has no probes

The development partition covers sqli, xss, path traversal, command injection, CRLF,
SSRF, XXE and LDAP. It carries **zero** `nosql_injection` items, and that is deliberate.
A NoSQL operator injection *is* an execution primitive: `{"$ne": null}` changes query
semantics on the database, and anything strong enough to demonstrate that on a real
target is strong enough to read data out of it. The gate refuses the `$ne` / `$where`
shape on principle, so a probe XAMMU would refuse to send cannot be used to report a
finding about it. The honest entry is the one the report makes instead: *this build does
not cover NoSQL injection*, which is a coverage statement rather than a claim about a
defence.

## Item semantics

- **`ref`** — unique across the tree. Two probes with one reference make every
  observation about that reference ambiguous, so the loader refuses duplicates.
- **`group_id`** — a probe family shared across encodings. Planning cells are keyed
  `attack_class | vector | group`, **without encoding**: the point of an encoding
  replica is to be read against the canonical item's reading, so splitting them into
  separate cells would let a truncated budget buy three URL-encodings of one family and
  leave four other families untested.
- **`canonical_form`** — what the probe *means*. A non-canonical item's `probe` must
  differ from it (the encoding is the variant); a canonical item's `probe` must equal it
  verbatim. C-13 enforces both, and the gate runs against the canonical form too — an
  encoded payload over an executable one is not inert.
- **`expected_behavior`** — `expect_block`, `expect_pass`, or `informative_either`. It is
  not a guess. See the evidence below.
- **`tags`** — `header:`, `cookie:`, `param:`, `field:`, `path:`, `media:` place the probe
  at a named location instead of the default. The CRLF name-keyed asymmetry only exists
  because two items differ by `header:` tag and nothing else.

### Placement

`corpus.Placement` renders an item into one exchange (`Place`). The rule that governs it:
a **canonical** probe is URL-escaped by the transport because it holds the semantic
value; every other encoding is placed **as authored**, because the encoding is the thing
under test — re-escaping a `%27` produces `%2527` and silently converts a single-encoded
probe into a double-encoded one. Only bytes that would break the request line (`=`, `&`,
space) are corrected, and existing `%XX` triplets are left alone. Cookie values are
handled by their own escape set so that the `=` inside `xammu-probe=1` survives to the
rule — the signature is the assignment.

## Evidence: declared versus observed

Every item carries non-empty `validation_evidence` (C-13). The `run_ref` prefix says what
kind of claim it is, and `internal/corpus/evidence.go` keeps the kinds apart:

| Kind | `run_ref` prefix | Meaning |
|---|---|---|
| Declared | `lab-rule-table:<RULE-ID>` | The laboratory fixture's rule table says this must fire. Read from `lab/waf/rules.go`, not from a run. |
| Declared | `coverage:<gap>` | The expected outcome comes from something the fixture *does not do* — `json_body_uninspected`, `body_not_parsed`, `header_value_uninspected`, `cookie_name_unscanned`, `no_ldap_rule`, `no_ssrf_rule`, `no_xxe_rule`, `benign_baseline`. |
| Declared | `policy:<name>` | A named non-signature policy, e.g. `x-lab-probe-transfer-encoding` (refused by header *name*, always, whatever the value). |
| Observed | `lab-run:<run-ref>` | An actual exchange happened, and this is what it did. |

Right now the tree holds **65 declared records and 0 observed records**. That is the
accurate state of this build: no laboratory run has been executed yet, so nothing here
pretends to have been seen. `Set.Unobserved("development")` returns every item in the
partition, and `AppendObservation` is how that changes — one entry per run, keyed to the
real run reference and the real image digest, and it refuses a `lab-rule-table:` prefix
on an observation. A `corpus.EvidenceCheck()` report tells a reader which of the two
kinds each expectation rests on.

The two kinds are kept in separate fields of the same record precisely so that a reader
can tell them apart. Declared evidence grounds an *expectation*; it is not a measurement,
and nothing in a report may use it as though it were one. A `expected_block` item whose
only record is `lab-rule-table:XSS-001` says "the fixture's rule table declares this"; the
sentence "the WAF blocked it" requires a `lab-run:` line next to it.


## Leakage

`Set.Overlaps()` reports two kinds of collision:

- **`group_id` shared across any two partitions** — a family used to write the
  detectors cannot also be used to validate them.
- **`probe_digest` shared where one holder is `independent_validation`** — the
  independent set may not contain traffic the other partitions replay.

Probe-text sharing between *calibration and development* is not flagged: the fixture's
anchor token `xammu-probe-token` is what `GENERIC-001` matches, so the calibration anchor
and the development sentinel necessarily use it. A C-14 record has no field that could
record that honestly, so `BuildPartition` refuses rather than mislabel it: if the
independent partition ever shares probe text with another partition, the build fails
closed instead of writing a leak it cannot describe.

`OverlapChecks` stamps the per-partition C-14 record (one row per *other* partition, with
shared groups and refs and a `clean` / `leak_detected` verdict), and `EnsureAllows`
refuses `independent_validation` use while its leakage verdict is not clean.

## Composition of the shipped tree

| | calibration | development | independent_validation |
|---|---|---|---|
| items | 25 | 35 | 8 |
| groups | 17 | 18 | 5 |
| positive control | 6 | — | — |
| negative control | 6 | — | — |
| over-blocking probe | 2 | — | — |
| benign reference | 11 | — | — |
| coverage diagnosis | — | 21 | 6 |
| encoding replica | — | 14 | 2 |
| expect_block | 6 | 21 | 5 |
| expect_pass | 17 | 12 | 3 |
| informative_either | 2 | 2 | — |

Independent-validation probe texts are suffixed `-iv`, so no digest in that partition is
shared with development — which is the point of it.

## Controls: what makes a reading mean something

A probe that comes back 403 proves nothing on its own: the origin may be broken, the
front end may refuse everything, or the signature may be so broad that ordinary traffic
trips it. The calibration partition exists to close those three holes, and
`controlsAreSufficient` (`internal/corpus/select.go`) refuses to plan any run whose
scope cannot reach all of them:

| requirement | what it rules out | what satisfies it |
|---|---|---|
| ≥ 1 positive control | a block-shaped reading that is really an origin error | a marker the fixture's rule table is cited to block |
| ≥ 1 negative control or over-blocking probe | a pass-shaped reading that is really a detector firing on everything | benign traffic the fixture is cited to pass, and traffic it is cited to refuse |
| ≥ 2 benign references | an ordinary reading with nothing ordinary to compare against | distinct benign shapes, so "normal" is a range and not one sample |

The set is filtered by class × vector × encoding, and the requirement is on the
**scope**, not on each cell. That is deliberate — a cell with no control of its own
still reads inside a run that carries controls for its transport — but it has a
consequence worth stating plainly: a scope whose transports have no controls at all is
refused before a single request. It is not a technicality. `--class path_traversal
--vector path` is refused today because `path` has one positive control (`CAL-POS-P-01`)
and no negative control or benign reference; `--class sqli --vector body_json` is refused
because nothing in the fixture blocks there, so an honest positive control cannot exist.

What the groups prove, one line each:

| group | refs | the property it pins |
|---|---|---|
| sqli / query | `CAL-POS-Q-01`, `CAL-NEG-Q-01`, `CAL-NEG-Q-02`, `CAL-BEN-Q-01..03`, `CAL-OVB-Q-01/02` | the canonical tautology is refused, ordinary queries and a parseable-looking apostrophe pass, and two legitimate shapes are refused by a rule that also refuses real text — the over-blocking denominator |
| sqli / header | `CAL-POS-H-01`, `CAL-NEG-H-01`, `CAL-BEN-H-01/02` | the sentinel is refused in an ordinary header name (`X-Trace-Site`) while ordinary strings pass in that same header and in `User-Agent`, so a header verdict separates the marker from the header it rides in |
| sqli / cookie | `CAL-POS-C-01`, `CAL-NEG-C-01`, `CAL-BEN-C-01/02` | the sentinel is refused inside a scanned cookie name (`lab_probe_*`) while ordinary strings pass both there and in an unscanned name (`xammu-probe-0`), so a cookie verdict separates the value from the cookie name |
| xss / query | `CAL-POS-X-01`, `CAL-NEG-X-01`, `CAL-BEN-X-01/02` | the tag-opening shape fires `XSS-001` while ordinary text containing angle brackets does not, so an XSS reading separates markup from prose |
| crlf / header | `CAL-POS-CR-01`, `CAL-NEG-CR-01`, `CAL-BEN-CR-01/02` | a single-encoded header injection is refused while ordinary text in the same header passes, and the probe states its canonical form as the literal CRLF text, so the decoding pass is exercised rather than assumed |

Two limits are declared rather than papered over:

- **No positive control can exist for `body_json` or `body_form`.** The fixture buffers
  and forwards those bodies without applying any rule. A "positive control" there would
  have to be a block the fixture does not perform, so the honest position is that body
  cells cap at `replicated_within_run`. Anywhere a report shows a body cell above that
  level, the report is wrong.
- **`path` has a positive control but no negative or benign partner.** `CAL-POS-P-01`
  names a traversal the fixture's `TRAVERSAL-001` refuses; there is no path-shaped
  benign reference, so a path-only plan is refused. The laboratory's own C-09 could not
  carry that probe either: its `path_prefixes` list `/api/` and `/search`, and the
  traversal resolves outside both, so the destination check refuses it before the run
  starts. Adding a benign path reference is a legitimate future change; inventing one to
  make a run pass, or widening `path_prefixes` to admit a traversal, would not be.

## What the tree is built to find

Each of these is a group in `development/` whose `expected_behavior` traces to a named
rule id or a named gap:

1. **The body vector is not inspected at all.** `GENERIC-001` never matches `json_body`,
   and `json_body` is outside the rule table's vector list. So the same sentinel token
   is placed twice — query (block) and JSON body (pass) — and the *difference* is the
   finding: a defence that reads the query string but not the payload the origin actually
   parses.
2. **Double encoding walks past a single decode pass.** The fixture applies exactly one
   percent-decode. A canonically-encoded tautology fires; `%2527%2520or…` decodes to
   `%27 or…`, which is not the signature, and passes. `G-DEV-SQLI-Q-TAUTO` carries both
   so the bypass is measured, not asserted.
3. **Escaping coverage is by coincidence, not by design.** `<!ENTITY xammu-probe "…">`
   blocks — on `SQLI-002`'s double quote. There is no XXE rule. A finding that says
   "XXE is detected" would be wrong; the finding is that the XML construct is caught by
   an unrelated string match and would vanish with the quote.
4. **Name-keyed asymmetries.** Two `%0D%0Axammu-probe%3A%201` items differing only by
   header name: `X-Xammu-Probe`/`x-lab-probe-*` values are carried in the candidate set
   but kept out of the rule table (expect pass), a normal custom header is inspected
   (expect block). Same shape for cookies: `xammu-probe-0` is scanned by `COOKIE-001`,
   an unscanned cookie name is not. The defence keys on the *name*, so a signature that
   exists for one spelling is absent for another.
5. **A header-name policy that blocks regardless of value** (`policy:x-lab-probe-transfer-encoding`)
   — a refusal that no payload analysis explains, which is only visible because an
   identical value under a different name behaves differently.
6. **Over-blocking, with a denominator.** `the user's cart` and `search "widget sets"`
   trip `SQLI-001` / `SQLI-002`, and four allowlisted contractions (`don't`, `it's`,
   `can't`, `won't`) do not. The allowlist is ten entries long. Both sides are in the
   corpus, so the false-positive rate is a ratio over counted trials rather than an
   impression.
7. **Vector-specific rules.** `CMD-001` and `TRAVERSAL-001` are scoped to
   query/path/cookie, so the same tautology-shaped command probe in a body form is
   `informative_either` — an honest expectation is one the rule table does not already
   answer.

## Planning a run from the corpus

```go
set, err := corpus.Load("corpus", corpus.DefaultPolicy())          // the gate runs here
if err != nil {
    return err                                                     // nothing is planned from a refused tree
}
if err := set.EvidenceCheck(); err != nil {                        // every run_ref names a known kind
    return err
}
partitions, err := set.BuildPartitions(commitRef, time.Now().UTC())
if err != nil {
    return err
}
if err := corpus.EnsureAllows(partitions, contracts.PartitionDevelopment, "detector_development"); err != nil {
    return err
}
if missing := set.Unobserved(contracts.PartitionDevelopment); len(missing) > 0 {
    // Not an error: it is the honest precondition of a report that may say
    // "first observation" instead of "replicated".
    log.Printf("%d refs carry declared-only evidence", len(missing))
}
sel, err := set.Select(corpus.SelectionRequest{
    Partition:          contracts.PartitionDevelopment,
    ControlsPartition:  contracts.PartitionCalibration,
    Classes:            contracts.AllAttackClasses(),
    Vectors:            contracts.AllVectors(),
    Encodings:          contracts.AllEncodings(),
    Budget:             60,
})
if err != nil {
    return err
}
for _, item := range sel.Items() {
    placed, err := corpus.Place(item, corpus.Options{})            // the one exchange this item means
    if err != nil {
        return err
    }
    _ = placed
}
```


`Select` spends the **budget** — the number of authorized exchanges — coverage-first: one
item per cell per round-robin pass, so a run that cannot afford the matrix returns a
truncated *spread* rather than one fully-tested family. Everything that did not fit is
named in `Excluded` with its reason (`budget ended before this cell's next pass`, a class
outside the authorization, calibration traffic in the probe partition).

`controlsAreSufficient` refuses a selection that cannot validate its own readings: no
positive control means nothing proves the detectors can fire, no negative control means
a block cannot be distinguished from the baseline, and fewer than
`MinBenignReferences` (2) benign references means an over-block has no denominator. An
encoding replica is held back until its `provenance.derived_from` twin is planned,
because a replica without its canonical reading is uninterpretable.

`BuildPartitions` seals all three partitions with their allowed uses and writes the C-14
overlap record for each, against the real commit reference. `docker-compose.yml` is not
reproducibility evidence and a sealed partition is not a claim that a run happened.

## The effectiveness corpus (Phase 1)

`corpus/effectiveness/` answers a different question from the profiling tree: not what the WAF
does, but how closely it agrees with a declarative label on every case. It holds 300 attack cases
(10 classes × 30) and 300 benign cases, split into one file per class or traffic category. The
counts and the floor live in `internal/effectiveness/corpus_test.go`; `xammu effectiveness check`
prints the same numbers from the tree.

- **Format:** the YAML subset implemented by `internal/yamlish` — documents separated by `---`,
  two-space maps, scalar lists, quotes and comments. Block scalars, flow collections, anchors,
  aliases, tags, tabs and duplicate keys are refused at load. There is no YAML dependency.
- **Attack labels** name an OWASP category (`A03:2021-Injection`, …). That is a declarative
  reference, never a CVSS score or an invented severity.
- **Inertness:** every attack payload carries `xammu-probe` and passes the same 19-rule gate as a
  diagnostic probe. A benign case may omit the marker, because it must look like real traffic, but
  it is still refused if it has an executable shape.
- **Benign provenance** is mandatory and names the source; the 60 text excerpts come from Project
  Gutenberg public-domain works and the rest are authored for the laboratory.
- **Population shape:** the laboratory origin routes one path, so only one benign path case can be
  conclusive; the rest of the benign population is queries, JSON, forms, headers and cookies. A
  case that could only return 404 would measure the missing route, not the WAF.
- **Regeneration:** `go run ./tools/gencorpus` writes the tree deterministically. The generator is
  part of the repository so a reviewer can see the payload construction; the sealed run still
  records the corpus digest it actually loaded.
- **Scale:** add files, not code. The loader, the gate, the executor and E-03 accept any number of
  cases; 2,800+ is a generation choice, not an engine limit.

The gates here are the same ones `xammu effectiveness run` applies; loading the tree through
`effectiveness check` is the cheapest way to see that nothing executable entered it.

**Phase 2 re-admission.** A tamper stack re-encodes a value the gate already admitted, and the
transformed value is passed through the gate again before it is sent. The only finding tolerated is
`inert.marker_absent`, and only in the two situations where the gate tolerates it at load: a benign
case (which is markerless by design) and a stack that moves the marker to the `X-Xammu-Probe` header
(`base64`). Any other finding excludes the case as `tamper_gate_refused`; it is never counted as a
block. The corpus itself does not change in Phase 2 and its digest stays fixed.

## Adding an item

1. Give it a fresh UUID `item_id`, a unique `ref`, and a `group_id` — join an existing
   family only if this is an encoding replica of it.
2. Leave `probe_digest` empty (it is derived) and `inertness.gate_version` empty (the
   gate stamps it).
3. Write a real `authoring_note`: which behaviour this item distinguishes, and what a
   different reading would mean. A note that restates the payload is not a note.
4. Point `validation_evidence` at the rule id or the named gap that grounds the
   expectation. If neither exists, the expectation does not exist — do not add the item.
5. Run `go test ./internal/corpus/`. `TestShippedCorpusIsCertifiable` re-loads, re-gates
   and re-checks leakage; `TestShippedCorpusCoversTheMatrixItClaims` fails if the tree no
   longer covers what this README says it covers.
