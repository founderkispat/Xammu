# XAMMU defensive-behaviour report

| run | state | target | partition | generated | schema |
| --- | --- | --- | --- | --- | --- |
| demo-lab | completed | http://127.0.0.1:8099 | development | 2026-11-06T17:27:30Z | 1.0.0 |

Authorization `AUTH-SMOKE-LOCAL-001`, valid until 2026-10-29T18:43:14Z. Stopped because: all 23 planned probes executed with 25 of 48 authorized requests left

Budget: 23 of 48 authorized requests spent in 1 second(s).

## Executive summary

- One run behind one authorized egress: demo-lab sent 23 of 48 authorized requests to http://127.0.0.1:8099 from corpus partition development in 1 second(s), and stopped in state "completed".
- Of 11 classified probe exchange(s) in the graded cells, 6 valid trial(s) carried the interstitial shape of a refusal and 5 the shape of ordinary handling; 0 indeterminate and 0 invalid trial(s) are outside every rate in this report rather than inside a denominator.
- The pass published 14 finding(s): over_blocking 1, vector_asymmetry 1, encoding_bypass_pattern 1, undetermined_area 11.
- The strongest claim any finding makes is "descriptive", at evidence level "replicated_with_valid_controls". C-08 derives that ceiling from the counts; nothing in this report rises above it, and a claim of a specific rule firing would need a source outside the HTTP response.
- Coverage of the authorized grid: 3 of 48 class x transport cell(s) hold at least one valid reading; 25 entry(ies) are listed as unmeasured, each with the reason it has.
- Reproduce it: xammu verify --run demo-lab --authorization AUTH-SMOKE-LOCAL-001 --issuer-keyring trust/issuers --corpus corpus --class sqli --vector query,body_json,cookie re-derives the evidence trail; every finding carries a command bound to authorization AUTH-SMOKE-LOCAL-001 or to run demo-lab.
- This report does not say the defence is secure, does not evaluate application vulnerabilities, and does not replace a penetration test. Those limits are declared in code (the out-of-scope section is required by C-15), not written by whoever assembled this document.

### Limits the run could not exceed

- request budget: 23 of 48 authorized requests spent (25 left); the client refuses a request beyond the budget rather than overshooting
- pacing: at most 20 request(s) per second, at most 2 concurrent, 5000 ms timeout
- redirects: at most 5, and only to a location the authorization lists; an unlisted redirect target ends the request as a refusal, not a follow
- response retention: policy "digest_only", at most 4096 byte(s) of a body kept in the journal; the full body is out of the process before classification
- scope: 1 origin(s), 3 method(s), 8 attack class(es), 6 transport(s), 4 encoding(s); anything outside that list was refused before the socket
- authorization AUTH-SMOKE-LOCAL-001 is valid until 2026-10-29T18:43:14Z; every reproduction command in this report is bound to that reference, and a run may not place a request after that instant
- the inertness gate re-runs when the corpus loads: a probe that can execute never reaches the transport, so no limit here is what keeps the run non-exploitative
- transport: 0 exchange(s) produced no response to classify; a run that hits this repeatedly in a row pauses rather than reporting a clean pass, because silence from a target is not a refusal
- the run stopped as "completed" (none), so coverage in this report is bounded by what it reached before that, not by the plan it was given
- this report was generated at 2026-11-06T17:27:30Z, after authorization AUTH-SMOKE-LOCAL-001 expired: the readings were taken inside the window, but every command in this document needs a new authorization to actually be run

## The five dimensions

### Coverage: what this run measured, and the cells it left open

Answers Q1, Q3.

- The authorized grid is 8 attack class(es) x 6 transport(s) = 48 cell(s). This run placed a probe in 3 of them and 3 hold at least one valid reading; 25 cell(s) are listed in the matrix as unmeasured, each with the reason the pass recorded.
- Over the cells that produced readings: 11 valid trial(s) of probe traffic, 6 refused and 5 handled ordinarily by the classifier's agreement. 0 inconclusive and 0 invalid exchange(s) are named in this sentence and are in no denominator anywhere in the report.
- Coverage was measured across 1 path(s) and 4 encoding(s), rendered as 3 class x transport row(s) with 7 encoding row(s) beneath them. A cell that mixed encodings is marked partial rather than averaged, because an average of a refusal and a pass is a number that describes neither.
- At the transport level: no valid reading in transport(s) body_form, header, path.
- At the attack class level: no valid reading of class(es) command_injection, crlf_injection, ldap_injection, path_traversal, ssrf, xss, xxe inside this authorization.

_Data behind this section: coverage_matrix:3 cell(s) rendered, 25 unmeasured entry(ies) listed; grid:sqli|body_json; grid:sqli|cookie; grid:sqli|query_

### Behaviour: what the front end did with the exchanges it received

Answers Q2.

- Of the 11 classified probe exchange(s) in this pass, 6 carried the interstitial shape the detector set associates with rejection, 5 the shape of ordinary handling, 0 were indeterminate, 0 were rate-limited and 0 produced no response at all; 0 valid trial(s) landed on neither side of the agreement (a redirect, typically) and are bucketed as not measured.
- Against the valid trials only, 6 of 11 (54%) were refused. The denominator is the run's own arithmetic; the distribution over behavioral_signal states the same exchanges counted by signal so a reader can see which buckets were empty rather than inferring it.
- The comparison every "handled ordinarily" reading rests on is a reference cluster of 10 ordinary exchange(s) collected by the pass itself. Without it, a 200 response would be a status code rather than a reading, and no behaviour in this report could be stated at all.
- 0 exchange(s) were rate-limited. Pacing is a limit placed on this run, not a protection result: behavioral_signal counts them in their own bucket and they are never part of a refusal rate.

_Data behind this section: run:demo-lab/round:round-1/classifications; distribution:behavioral_signal_

### Attribution: how far the evidence places the cause on the defence

Answers Q5.

- Of 7 graded cell(s), 0 carry an attribution record at all; 7 sit at "undetermined", which is the bucket this distribution keeps out of its denominator. An absent attribution is a statement about the evidence, not about the defence.
- The strongest grade reached anywhere in the run is undetermined. The ladder above it requires a source outside the HTTP response -- filter logs or a configuration export -- and none was supplied to this run. Everything above it in the ladder is therefore out of reach for this evidence, whatever the readings say.
- Evidence basis of the graded cells: http_only 7. "http_only" means a response and nothing else, which is why a finding that rests on it may describe a difference but may not name the component that caused it.
- 0 cell(s) have no evidence basis of any kind (evidence_basis bucket "none"). Those cells appear in the matrix as readings without attribution and in the findings as descriptive claims only.

_Data behind this section: run:demo-lab/attributions; distribution:attribution_status; distribution:evidence_basis_

### Discovery: the differences this run found and what to do about them

Answers Q4, Q6.

- The pass published 14 finding(s): coverage_gap 0, over_blocking 1, vector_asymmetry 1, encoding_bypass_pattern 1, configuration_concern 0, undetermined_area 11. 3 of them rest on a measurement; the rest state where the run produced none, and they carry no risk claim by construction.
- Priority distribution: high 0, medium 2, low 12. Priority is computed from the size of the difference and the number of valid trials behind it, never from how alarming a finding type sounds.
- No finding reached high priority in this pass: every measured difference either rests on too few valid trials or is contradicted by the run's own controls. That is a statement about this run's evidence, not a clean result for the target.
- Every finding cites xammu as its reproduction surface, bound to authorization AUTH-SMOKE-LOCAL-001 or to run demo-lab, so a reader who wants the measurement again cannot wander outside the scope that allowed it.

_Data behind this section: BYP-G-DEV-SQLI-Q-TAUTO; OVB-informative_either; UND-class-command_injection; UND-class-crlf_injection; UND-class-ldap_injection; UND-class-path_traversal; UND-class-ssrf; UND-class-xss; UND-class-xxe; UND-unplanned-authorization_gap; UND-vector-body_form; UND-vector-header; and 2 further finding ref(s)_

### Uncertainty: what was not determined, and why it could not be

Answers Q7.

- The run stopped in state "completed" and 23 of 48 authorized requests were spent, so 25 request(s) and 0 planned probe(s) remain. The report states the arithmetic rather than leaving a reader to divide two numbers: all 23 planned probes executed with 25 of 48 authorized requests left.
- Undetermined areas: 11, typed as authorization_gap 1, not_yet_attempted 10. Every one names what is absent and the command that would produce a reading; 24 planned request(s) were never spent on them.
- Evidence-trail health: 0 re-derivation disagreement(s) with the journal and 0 exchange(s) that were sent but never classified. A divergence is a defect in the trail rather than a reading, so it is reported before any rate is quoted from a cell it touches.
- The residual-risk block states three things separately: a conditional exposure the run measured, a condition the evidence does not yet demonstrate, and a question this kind of measurement cannot answer. They are not merged into one risk figure because merging them would hide which of the three a reader is being told about.

_Data behind this section: runs/demo-lab/manifest.json; distribution:hypothesis_outcome; attack class command_injection: unmeasured in this run; attack class crlf_injection: unmeasured in this run; attack class ldap_injection: unmeasured in this run; attack class path_traversal: unmeasured in this run; attack class ssrf: unmeasured in this run; attack class xss: unmeasured in this run; attack class xxe: unmeasured in this run; probes not run in partition development: 24 item(s); transport body_form: unmeasured in this run; transport header: unmeasured in this run; transport path: unmeasured in this run_

## Coverage matrix

the grid is the authorization's own scope: 8 attack class(es) x 6 transport(s) = 48 cell(s), authorized by AUTH-SMOKE-LOCAL-001. Rows inside a cell are the encodings the run placed there, and a cell aggregates every path. A rate over valid trials only: 0 inconclusive and 0 invalid exchange(s) are named outside the denominator rather than folded into it.

| class | transport | status | refused/valid | encodings | evidence | claim ceiling |
| --- | --- | --- | --- | --- | --- | --- |
| sqli | body_json | measured | 0/3 | canonical passed 0/2; case_variant passed 0/1 | single_observation | descriptive |
| sqli | cookie | measured | 1/2 | canonical mixed 1/2 | single_observation | descriptive |
| sqli | query | partial | 5/6 | canonical blocked 3/3; case_variant blocked 1/1; url_double passed 0/1; url_single blocked 1/1 | single_observation | descriptive |

### Cells this run did not measure

- command_injection|body_form: the plan placed no probe of class command_injection in the body_form transport, so the cell has no reading to report
- command_injection|body_json: the plan placed no probe of class command_injection in the body_json transport, so the cell has no reading to report
- command_injection|cookie: the plan placed no probe of class command_injection in the cookie transport, so the cell has no reading to report
- command_injection|header: the plan placed no probe of class command_injection in the header transport, so the cell has no reading to report
- command_injection|path: the plan placed no probe of class command_injection in the path transport, so the cell has no reading to report
- command_injection|query: the plan placed no probe of class command_injection in the query transport, so the cell has no reading to report
- crlf_injection|body_form: the plan placed no probe of class crlf_injection in the body_form transport, so the cell has no reading to report
- crlf_injection|body_json: the plan placed no probe of class crlf_injection in the body_json transport, so the cell has no reading to report
- crlf_injection|cookie: the plan placed no probe of class crlf_injection in the cookie transport, so the cell has no reading to report
- crlf_injection|header: the plan placed no probe of class crlf_injection in the header transport, so the cell has no reading to report
- crlf_injection|path: the plan placed no probe of class crlf_injection in the path transport, so the cell has no reading to report
- crlf_injection|query: the plan placed no probe of class crlf_injection in the query transport, so the cell has no reading to report
- ldap_injection|body_form: the plan placed no probe of class ldap_injection in the body_form transport, so the cell has no reading to report
- ldap_injection|body_json: the plan placed no probe of class ldap_injection in the body_json transport, so the cell has no reading to report
- ldap_injection|cookie: the plan placed no probe of class ldap_injection in the cookie transport, so the cell has no reading to report
- ldap_injection|header: the plan placed no probe of class ldap_injection in the header transport, so the cell has no reading to report
- ldap_injection|path: the plan placed no probe of class ldap_injection in the path transport, so the cell has no reading to report
- ldap_injection|query: the plan placed no probe of class ldap_injection in the query transport, so the cell has no reading to report
- path_traversal|body_form: the plan placed no probe of class path_traversal in the body_form transport, so the cell has no reading to report
- path_traversal|body_json: the plan placed no probe of class path_traversal in the body_json transport, so the cell has no reading to report
- path_traversal|cookie: the plan placed no probe of class path_traversal in the cookie transport, so the cell has no reading to report
- path_traversal|header: the plan placed no probe of class path_traversal in the header transport, so the cell has no reading to report
- path_traversal|path: the plan placed no probe of class path_traversal in the path transport, so the cell has no reading to report
- path_traversal|query: the plan placed no probe of class path_traversal in the query transport, so the cell has no reading to report
- and 21 further unmeasured cell(s) of the authorized grid (the matrix denominator excludes all of them)

## Findings

### BYP-G-DEV-SQLI-Q-TAUTO - encoding_bypass_pattern (`medium`, priority medium)

- Scope: encoding family G-DEV-SQLI-Q-TAUTO (sqli x query) on /api/search: canonical refused, url_double handled ordinarily
- Grid position: class=sqli vector=query encoding=case_variant
- Claim: descriptive at evidence level single_observation, attribution undetermined, basis http_only
- **Observed:** within probe family G-DEV-SQLI-Q-TAUTO, 1/1 (100%) valid canonical-form trials produced the block shape and 1/3 (33%) valid encoding replicas were handled ordinarily (url_double). The replicas are DEV-SQLI-Q-02, DEV-SQLI-Q-03, DEV-SQLI-Q-06, authored from the same canonical form "' or 1=1 xammu-probe".
- **Inferred:** the difference is the encoding of the payload, not its meaning, which is compatible with the decoding applied before matching being shallower than the encoding applied to the probe; the run cannot see how many decode passes the engine makes
- **Missing evidence:** This run supplies the response side only. What is missing is repetition: a second authorized round of the same cell, so the difference is shown to survive rather than to be one exchange. Recorded by the evidence profile: to raise the evidence level: a valid positive control (a payload this run recorded as rejected) and a valid negative control (a benign reference this run recorded as ordinarily handled); to raise the evidence level: the same reading reproduced by two or more valid trials inside this run.; the number of normalisation passes the engine applies is not observable from a response, so the decoding depth is reasoned about from this difference and never measured directly
- **Limitations:**
  - does not show any encoded payload gets through: it shows these encodings of this family were not refused
  - does not identify which component decodes; an origin-side normalisation would produce the same readings and is not excluded
  - 0 inconclusive and 0 invalid trial(s) are outside this count
- Measured impact: 1 of 4 valid trial(s); population `group:G-DEV-SQLI-Q-TAUTO`.
- Alternatives evaluated:
  - waf: supported -- the run contains both a refused exchange and an ordinarily handled one, and the calibration pair on the same route separates the two shapes
    - test that would resolve it: authorized exchange that reaches the origin without the front end, or the engine's own rule configuration
  - origin_application: ruled_out -- a valid benign exchange on the same route returned the origin's ordinary shape, so the origin answers this path when it is not rejecting
    - test that would resolve it: authorized request to the origin directly, bypassing the front end
  - reverse_proxy_or_cdn: not_ruled_out -- the authorization covers one destination; nothing in the run distinguishes a proxy or CDN layer from the engine it forwards to, so a refusal at an earlier hop would look identical here
    - test that would resolve it: response header comparison across an authorized direct-origin exchange, or the operator's topology
  - rate_limiting_or_throttling: ruled_out -- no exchange in scope returned 429, and the refused responses carry the interstitial shape rather than a throttling one
    - test that would resolve it: status and Retry-After inspection already performed on every exchange
  - test_harness_artifact: ruled_out -- the same client, body shape and route produced both readings, and the calibration pair moved with the payload rather than with the transport
    - test that would resolve it: replay of one refused and one passed exchange from the journal with the same client
  - framework_input_normalization: not_ruled_out -- a framework that decodes or rejects the payload before the engine sees it can produce the same reading difference; this run cannot tell the two apart because only the response is authorized evidence
    - test that would resolve it: the origin's own error shape for the same payload, or its request pipeline configuration
  - application_authorization: unevaluable -- no authorized exchange carries an authenticated session, so an authorization layer in front of the handler cannot be evaluated at all
    - test that would resolve it: an authorized authenticated request reproducing both readings
- Recommendation: normalise to a fixed depth before matching, then re-run this family: if the difference disappears the cause was decoding depth; add the encodings that walked past to the review list either way
- Priority basis: 33 percentage points measured over 4 valid trials: below the 50-point/6-trial threshold for high
- Engineer note: these encodings of a signature the engine already detects were not refused; an operator hardening rule coverage should treat url_double as the test cases
- Reproduce: `xammu validate --finding BYP-G-DEV-SQLI-Q-TAUTO --run demo-lab --authorization AUTH-SMOKE-LOCAL-001 --issuer-keyring trust/issuers --corpus corpus --class sqli --vector query,body_json,cookie`
- Regression: `xammu lab test --scenario encoding-bypass-g-dev-sqli-q-tauto`
- Evidence profile: `3e30898c-9d46-4318-bb1e-dc07039fad4f`; observations: 2ca238a9-6c75-4ce6-b0e8-0884367d537e, 32138c3e-d324-4107-b7c7-8eda0e0b3887, 4d114f33-0072-4be2-9c63-186e0c4cf6e6, 56fdbe55-9e35-4e74-9b42-64e0d24243b2

### OVB-informative_either - over_blocking (`medium`, priority medium)

- Scope: legitimate traffic on query (10 exchange(s) in the measured population)
- Grid position: class=sqli vector=query encoding=-
- Claim: descriptive at evidence level replicated_with_valid_controls, attribution undetermined, basis http_only
- **Observed:** 2/10 (20%) valid exchanges the corpus defines as legitimate were refused. The refused shapes are "search \"widget sets\"" (CAL-OVB-Q-02 in query, expected informative_either); "the user's cart" (CAL-OVB-Q-01 in query, expected informative_either). Every one of them is declared to be handled ordinarily (informative_either).
- **Inferred:** the refusal follows the content of the legitimate request rather than its transport, which is compatible with a signature that matches ordinary text -- the declared expectation for these probes is informative_either, so this run measured the opposite
- **Missing evidence:** This run supplies the response side only. What is missing is an independently authorized round, which would raise the claim from association to attribution. Recorded by the evidence profile: to raise the evidence level: repetition across two separately authorized rounds; one run cannot manufacture this.; the matched rule and its condition list are inside the engine, so only the configuration export or a hit counter shows which rule refused each shape
- **Limitations:**
  - the measured population is the corpus's legitimate set, not the target's real traffic: the rate is over what XAMMU sent, and a real client mix would produce a different one
  - does not show any legitimate request is blocked in production, only that these shapes were refused in this run
  - 0 inconclusive and 0 invalid trial(s) are outside this count
  - a refusal could also come from a layer in front of the engine; the alternatives list keeps that open rather than closing it
- Measured impact: 2 of 10 valid trial(s); population `run:demo-lab/round:round-1/controls`.
- Alternatives evaluated:
  - waf: supported -- the run contains both a refused exchange and an ordinarily handled one, and the calibration pair on the same route separates the two shapes
    - test that would resolve it: authorized exchange that reaches the origin without the front end, or the engine's own rule configuration
  - origin_application: ruled_out -- a valid benign exchange on the same route returned the origin's ordinary shape, so the origin answers this path when it is not rejecting
    - test that would resolve it: authorized request to the origin directly, bypassing the front end
  - reverse_proxy_or_cdn: not_ruled_out -- the authorization covers one destination; nothing in the run distinguishes a proxy or CDN layer from the engine it forwards to, so a refusal at an earlier hop would look identical here
    - test that would resolve it: response header comparison across an authorized direct-origin exchange, or the operator's topology
  - rate_limiting_or_throttling: ruled_out -- no exchange in scope returned 429, and the refused responses carry the interstitial shape rather than a throttling one
    - test that would resolve it: status and Retry-After inspection already performed on every exchange
  - test_harness_artifact: ruled_out -- the same client, body shape and route produced both readings, and the calibration pair moved with the payload rather than with the transport
    - test that would resolve it: replay of one refused and one passed exchange from the journal with the same client
  - framework_input_normalization: not_ruled_out -- a framework that decodes or rejects the payload before the engine sees it can produce the same reading difference; this run cannot tell the two apart because only the response is authorized evidence
    - test that would resolve it: the origin's own error shape for the same payload, or its request pipeline configuration
  - application_authorization: unevaluable -- no authorized exchange carries an authenticated session, so an authorization layer in front of the handler cannot be evaluated at all
    - test that would resolve it: an authorized authenticated request reproducing both readings
- Recommendation: review the allowlist and the literal matches behind the refused legitimate shapes; each one is a legitimate client that will be refused in production
- Priority basis: 20 percentage points measured over 10 valid trials: below the 50-point/6-trial threshold for high
- Engineer note: these 2 legitimate shape(s) are refused; each is a client that will be refused in production, and the review question is the allowlist rather than the rule coverage
- Reproduce: `xammu validate --finding OVB-informative_either --run demo-lab --authorization AUTH-SMOKE-LOCAL-001 --issuer-keyring trust/issuers --corpus corpus --class sqli --vector query,body_json,cookie`
- Regression: `xammu lab test --scenario over-blocking-informative-either`
- Evidence profile: `4a1c071e-b564-482f-bc66-6fc72244699d`; observations: 08e4a926-1339-4948-9daa-cdde1a683321, 75560b24-82c7-4d46-85f4-ae148b20dd95

### UND-class-command_injection - undetermined_area (`low`, priority low)

- Scope: attack class command_injection: unmeasured in this run
- Grid position: class=command_injection vector=- encoding=-
- Claim: descriptive at evidence level none, attribution undetermined, basis none
- **Observed:** the authorization covers attack class "command_injection". No exchange in this run carried that class. the probe partition carries 3 item(s) of class "command_injection" and this run planned or sent none of them. The pass measured 1 class(es).
- **Inferred:** nothing is inferred about how "command_injection" is handled. The absence is in this run's coverage, not in the engine's behaviour: no exchange was measured, so the class is unmeasured rather than examined
- **Missing evidence:** corpus items of class "command_injection" that pass the inertness gate, plus a plan that sends them under this authorization
- **Limitations:**
  - an unmeasured class is not an unguarded class
  - the reason code distinguishes a corpus that has nothing sendable from a run that sent nothing; it does not explain why the corpus has nothing
- Measured impact: 0 of 0 valid trial(s); population ``.
- Alternatives evaluated:
  - waf: unevaluable -- no valid reading exists for this zone, so no behaviour of the engine is in evidence: the authorization covers attack class "command_injection". No exchange in this run carried that class. the probe partition carries 3 item(s) of class "command_injection" and this run planned or sent none of them. The pass measured 1 class(es).
    - test that would resolve it: an authorized exchange that produces one valid reading
  - origin_application: unevaluable -- the origin's own handling is equally unobserved: the absence of a reading says nothing about either side of the path
    - test that would resolve it: a valid reading, or an authorized direct-origin exchange
  - test_harness_artifact: not_ruled_out -- the reason this zone has no reading has not been separated from a failure of the run itself; the typed reason code states what was recorded, not what caused it
    - test that would resolve it: re-run of the planned exchange under the same authorization
- Recommendation: either add gated items of class "command_injection" to the probe partition and re-authorize, or carry the class as explicitly out of coverage in the report instead of leaving the reader to notice its absence
- Priority basis: no measurement exists for this zone, so nothing was ranked: an undetermined area is always low because the finding reports the absence of a quantity rather than its size
- Engineer note: the matrix row for "command_injection" is empty by construction: this build's inertness gate refuses the shapes that would demonstrate it, which is a coverage decision and not a result
- Reproduce: `xammu validate --finding UND-class-command_injection --run demo-lab --authorization AUTH-SMOKE-LOCAL-001 --issuer-keyring trust/issuers --corpus corpus --class sqli --vector query,body_json,cookie`
- Regression: `xammu playbook --partition development --class command_injection --authorization AUTH-SMOKE-LOCAL-001 --issuer-keyring trust/issuers --corpus corpus`
- Evidence profile: none: this finding states an absence, so no C-08 profile was compiled; observations: absence:demo-lab/round-1/class-command_injection

### UND-class-crlf_injection - undetermined_area (`low`, priority low)

- Scope: attack class crlf_injection: unmeasured in this run
- Grid position: class=crlf_injection vector=- encoding=-
- Claim: descriptive at evidence level none, attribution undetermined, basis none
- **Observed:** the authorization covers attack class "crlf_injection". No exchange in this run carried that class. the probe partition carries 3 item(s) of class "crlf_injection" and this run planned or sent none of them. The pass measured 1 class(es).
- **Inferred:** nothing is inferred about how "crlf_injection" is handled. The absence is in this run's coverage, not in the engine's behaviour: no exchange was measured, so the class is unmeasured rather than examined
- **Missing evidence:** corpus items of class "crlf_injection" that pass the inertness gate, plus a plan that sends them under this authorization
- **Limitations:**
  - an unmeasured class is not an unguarded class
  - the reason code distinguishes a corpus that has nothing sendable from a run that sent nothing; it does not explain why the corpus has nothing
- Measured impact: 0 of 0 valid trial(s); population ``.
- Alternatives evaluated:
  - waf: unevaluable -- no valid reading exists for this zone, so no behaviour of the engine is in evidence: the authorization covers attack class "crlf_injection". No exchange in this run carried that class. the probe partition carries 3 item(s) of class "crlf_injection" and this run planned or sent none of them. The pass measured 1 class(es).
    - test that would resolve it: an authorized exchange that produces one valid reading
  - origin_application: unevaluable -- the origin's own handling is equally unobserved: the absence of a reading says nothing about either side of the path
    - test that would resolve it: a valid reading, or an authorized direct-origin exchange
  - test_harness_artifact: not_ruled_out -- the reason this zone has no reading has not been separated from a failure of the run itself; the typed reason code states what was recorded, not what caused it
    - test that would resolve it: re-run of the planned exchange under the same authorization
- Recommendation: either add gated items of class "crlf_injection" to the probe partition and re-authorize, or carry the class as explicitly out of coverage in the report instead of leaving the reader to notice its absence
- Priority basis: no measurement exists for this zone, so nothing was ranked: an undetermined area is always low because the finding reports the absence of a quantity rather than its size
- Engineer note: the matrix row for "crlf_injection" is empty by construction: this build's inertness gate refuses the shapes that would demonstrate it, which is a coverage decision and not a result
- Reproduce: `xammu validate --finding UND-class-crlf_injection --run demo-lab --authorization AUTH-SMOKE-LOCAL-001 --issuer-keyring trust/issuers --corpus corpus --class sqli --vector query,body_json,cookie`
- Regression: `xammu playbook --partition development --class crlf_injection --authorization AUTH-SMOKE-LOCAL-001 --issuer-keyring trust/issuers --corpus corpus`
- Evidence profile: none: this finding states an absence, so no C-08 profile was compiled; observations: absence:demo-lab/round-1/class-crlf_injection

### UND-class-ldap_injection - undetermined_area (`low`, priority low)

- Scope: attack class ldap_injection: unmeasured in this run
- Grid position: class=ldap_injection vector=- encoding=-
- Claim: descriptive at evidence level none, attribution undetermined, basis none
- **Observed:** the authorization covers attack class "ldap_injection". No exchange in this run carried that class. the probe partition carries 1 item(s) of class "ldap_injection" and this run planned or sent none of them. The pass measured 1 class(es).
- **Inferred:** nothing is inferred about how "ldap_injection" is handled. The absence is in this run's coverage, not in the engine's behaviour: no exchange was measured, so the class is unmeasured rather than examined
- **Missing evidence:** corpus items of class "ldap_injection" that pass the inertness gate, plus a plan that sends them under this authorization
- **Limitations:**
  - an unmeasured class is not an unguarded class
  - the reason code distinguishes a corpus that has nothing sendable from a run that sent nothing; it does not explain why the corpus has nothing
- Measured impact: 0 of 0 valid trial(s); population ``.
- Alternatives evaluated:
  - waf: unevaluable -- no valid reading exists for this zone, so no behaviour of the engine is in evidence: the authorization covers attack class "ldap_injection". No exchange in this run carried that class. the probe partition carries 1 item(s) of class "ldap_injection" and this run planned or sent none of them. The pass measured 1 class(es).
    - test that would resolve it: an authorized exchange that produces one valid reading
  - origin_application: unevaluable -- the origin's own handling is equally unobserved: the absence of a reading says nothing about either side of the path
    - test that would resolve it: a valid reading, or an authorized direct-origin exchange
  - test_harness_artifact: not_ruled_out -- the reason this zone has no reading has not been separated from a failure of the run itself; the typed reason code states what was recorded, not what caused it
    - test that would resolve it: re-run of the planned exchange under the same authorization
- Recommendation: either add gated items of class "ldap_injection" to the probe partition and re-authorize, or carry the class as explicitly out of coverage in the report instead of leaving the reader to notice its absence
- Priority basis: no measurement exists for this zone, so nothing was ranked: an undetermined area is always low because the finding reports the absence of a quantity rather than its size
- Engineer note: the matrix row for "ldap_injection" is empty by construction: this build's inertness gate refuses the shapes that would demonstrate it, which is a coverage decision and not a result
- Reproduce: `xammu validate --finding UND-class-ldap_injection --run demo-lab --authorization AUTH-SMOKE-LOCAL-001 --issuer-keyring trust/issuers --corpus corpus --class sqli --vector query,body_json,cookie`
- Regression: `xammu playbook --partition development --class ldap_injection --authorization AUTH-SMOKE-LOCAL-001 --issuer-keyring trust/issuers --corpus corpus`
- Evidence profile: none: this finding states an absence, so no C-08 profile was compiled; observations: absence:demo-lab/round-1/class-ldap_injection

### UND-class-path_traversal - undetermined_area (`low`, priority low)

- Scope: attack class path_traversal: unmeasured in this run
- Grid position: class=path_traversal vector=- encoding=-
- Claim: descriptive at evidence level none, attribution undetermined, basis none
- **Observed:** the authorization covers attack class "path_traversal". No exchange in this run carried that class. the probe partition carries 3 item(s) of class "path_traversal" and this run planned or sent none of them. The pass measured 1 class(es).
- **Inferred:** nothing is inferred about how "path_traversal" is handled. The absence is in this run's coverage, not in the engine's behaviour: no exchange was measured, so the class is unmeasured rather than examined
- **Missing evidence:** corpus items of class "path_traversal" that pass the inertness gate, plus a plan that sends them under this authorization
- **Limitations:**
  - an unmeasured class is not an unguarded class
  - the reason code distinguishes a corpus that has nothing sendable from a run that sent nothing; it does not explain why the corpus has nothing
- Measured impact: 0 of 0 valid trial(s); population ``.
- Alternatives evaluated:
  - waf: unevaluable -- no valid reading exists for this zone, so no behaviour of the engine is in evidence: the authorization covers attack class "path_traversal". No exchange in this run carried that class. the probe partition carries 3 item(s) of class "path_traversal" and this run planned or sent none of them. The pass measured 1 class(es).
    - test that would resolve it: an authorized exchange that produces one valid reading
  - origin_application: unevaluable -- the origin's own handling is equally unobserved: the absence of a reading says nothing about either side of the path
    - test that would resolve it: a valid reading, or an authorized direct-origin exchange
  - test_harness_artifact: not_ruled_out -- the reason this zone has no reading has not been separated from a failure of the run itself; the typed reason code states what was recorded, not what caused it
    - test that would resolve it: re-run of the planned exchange under the same authorization
- Recommendation: either add gated items of class "path_traversal" to the probe partition and re-authorize, or carry the class as explicitly out of coverage in the report instead of leaving the reader to notice its absence
- Priority basis: no measurement exists for this zone, so nothing was ranked: an undetermined area is always low because the finding reports the absence of a quantity rather than its size
- Engineer note: the matrix row for "path_traversal" is empty by construction: this build's inertness gate refuses the shapes that would demonstrate it, which is a coverage decision and not a result
- Reproduce: `xammu validate --finding UND-class-path_traversal --run demo-lab --authorization AUTH-SMOKE-LOCAL-001 --issuer-keyring trust/issuers --corpus corpus --class sqli --vector query,body_json,cookie`
- Regression: `xammu playbook --partition development --class path_traversal --authorization AUTH-SMOKE-LOCAL-001 --issuer-keyring trust/issuers --corpus corpus`
- Evidence profile: none: this finding states an absence, so no C-08 profile was compiled; observations: absence:demo-lab/round-1/class-path_traversal

### UND-class-ssrf - undetermined_area (`low`, priority low)

- Scope: attack class ssrf: unmeasured in this run
- Grid position: class=ssrf vector=- encoding=-
- Claim: descriptive at evidence level none, attribution undetermined, basis none
- **Observed:** the authorization covers attack class "ssrf". No exchange in this run carried that class. the probe partition carries 1 item(s) of class "ssrf" and this run planned or sent none of them. The pass measured 1 class(es).
- **Inferred:** nothing is inferred about how "ssrf" is handled. The absence is in this run's coverage, not in the engine's behaviour: no exchange was measured, so the class is unmeasured rather than examined
- **Missing evidence:** corpus items of class "ssrf" that pass the inertness gate, plus a plan that sends them under this authorization
- **Limitations:**
  - an unmeasured class is not an unguarded class
  - the reason code distinguishes a corpus that has nothing sendable from a run that sent nothing; it does not explain why the corpus has nothing
- Measured impact: 0 of 0 valid trial(s); population ``.
- Alternatives evaluated:
  - waf: unevaluable -- no valid reading exists for this zone, so no behaviour of the engine is in evidence: the authorization covers attack class "ssrf". No exchange in this run carried that class. the probe partition carries 1 item(s) of class "ssrf" and this run planned or sent none of them. The pass measured 1 class(es).
    - test that would resolve it: an authorized exchange that produces one valid reading
  - origin_application: unevaluable -- the origin's own handling is equally unobserved: the absence of a reading says nothing about either side of the path
    - test that would resolve it: a valid reading, or an authorized direct-origin exchange
  - test_harness_artifact: not_ruled_out -- the reason this zone has no reading has not been separated from a failure of the run itself; the typed reason code states what was recorded, not what caused it
    - test that would resolve it: re-run of the planned exchange under the same authorization
- Recommendation: either add gated items of class "ssrf" to the probe partition and re-authorize, or carry the class as explicitly out of coverage in the report instead of leaving the reader to notice its absence
- Priority basis: no measurement exists for this zone, so nothing was ranked: an undetermined area is always low because the finding reports the absence of a quantity rather than its size
- Engineer note: the matrix row for "ssrf" is empty by construction: this build's inertness gate refuses the shapes that would demonstrate it, which is a coverage decision and not a result
- Reproduce: `xammu validate --finding UND-class-ssrf --run demo-lab --authorization AUTH-SMOKE-LOCAL-001 --issuer-keyring trust/issuers --corpus corpus --class sqli --vector query,body_json,cookie`
- Regression: `xammu playbook --partition development --class ssrf --authorization AUTH-SMOKE-LOCAL-001 --issuer-keyring trust/issuers --corpus corpus`
- Evidence profile: none: this finding states an absence, so no C-08 profile was compiled; observations: absence:demo-lab/round-1/class-ssrf

### UND-class-xss - undetermined_area (`low`, priority low)

- Scope: attack class xss: unmeasured in this run
- Grid position: class=xss vector=- encoding=-
- Claim: descriptive at evidence level none, attribution undetermined, basis none
- **Observed:** the authorization covers attack class "xss". No exchange in this run carried that class. the probe partition carries 7 item(s) of class "xss" and this run planned or sent none of them. The pass measured 1 class(es).
- **Inferred:** nothing is inferred about how "xss" is handled. The absence is in this run's coverage, not in the engine's behaviour: no exchange was measured, so the class is unmeasured rather than examined
- **Missing evidence:** corpus items of class "xss" that pass the inertness gate, plus a plan that sends them under this authorization
- **Limitations:**
  - an unmeasured class is not an unguarded class
  - the reason code distinguishes a corpus that has nothing sendable from a run that sent nothing; it does not explain why the corpus has nothing
- Measured impact: 0 of 0 valid trial(s); population ``.
- Alternatives evaluated:
  - waf: unevaluable -- no valid reading exists for this zone, so no behaviour of the engine is in evidence: the authorization covers attack class "xss". No exchange in this run carried that class. the probe partition carries 7 item(s) of class "xss" and this run planned or sent none of them. The pass measured 1 class(es).
    - test that would resolve it: an authorized exchange that produces one valid reading
  - origin_application: unevaluable -- the origin's own handling is equally unobserved: the absence of a reading says nothing about either side of the path
    - test that would resolve it: a valid reading, or an authorized direct-origin exchange
  - test_harness_artifact: not_ruled_out -- the reason this zone has no reading has not been separated from a failure of the run itself; the typed reason code states what was recorded, not what caused it
    - test that would resolve it: re-run of the planned exchange under the same authorization
- Recommendation: either add gated items of class "xss" to the probe partition and re-authorize, or carry the class as explicitly out of coverage in the report instead of leaving the reader to notice its absence
- Priority basis: no measurement exists for this zone, so nothing was ranked: an undetermined area is always low because the finding reports the absence of a quantity rather than its size
- Engineer note: the matrix row for "xss" is empty by construction: this build's inertness gate refuses the shapes that would demonstrate it, which is a coverage decision and not a result
- Reproduce: `xammu validate --finding UND-class-xss --run demo-lab --authorization AUTH-SMOKE-LOCAL-001 --issuer-keyring trust/issuers --corpus corpus --class sqli --vector query,body_json,cookie`
- Regression: `xammu playbook --partition development --class xss --authorization AUTH-SMOKE-LOCAL-001 --issuer-keyring trust/issuers --corpus corpus`
- Evidence profile: none: this finding states an absence, so no C-08 profile was compiled; observations: absence:demo-lab/round-1/class-xss

### UND-class-xxe - undetermined_area (`low`, priority low)

- Scope: attack class xxe: unmeasured in this run
- Grid position: class=xxe vector=- encoding=-
- Claim: descriptive at evidence level none, attribution undetermined, basis none
- **Observed:** the authorization covers attack class "xxe". No exchange in this run carried that class. the probe partition carries 1 item(s) of class "xxe" and this run planned or sent none of them. The pass measured 1 class(es).
- **Inferred:** nothing is inferred about how "xxe" is handled. The absence is in this run's coverage, not in the engine's behaviour: no exchange was measured, so the class is unmeasured rather than examined
- **Missing evidence:** corpus items of class "xxe" that pass the inertness gate, plus a plan that sends them under this authorization
- **Limitations:**
  - an unmeasured class is not an unguarded class
  - the reason code distinguishes a corpus that has nothing sendable from a run that sent nothing; it does not explain why the corpus has nothing
- Measured impact: 0 of 0 valid trial(s); population ``.
- Alternatives evaluated:
  - waf: unevaluable -- no valid reading exists for this zone, so no behaviour of the engine is in evidence: the authorization covers attack class "xxe". No exchange in this run carried that class. the probe partition carries 1 item(s) of class "xxe" and this run planned or sent none of them. The pass measured 1 class(es).
    - test that would resolve it: an authorized exchange that produces one valid reading
  - origin_application: unevaluable -- the origin's own handling is equally unobserved: the absence of a reading says nothing about either side of the path
    - test that would resolve it: a valid reading, or an authorized direct-origin exchange
  - test_harness_artifact: not_ruled_out -- the reason this zone has no reading has not been separated from a failure of the run itself; the typed reason code states what was recorded, not what caused it
    - test that would resolve it: re-run of the planned exchange under the same authorization
- Recommendation: either add gated items of class "xxe" to the probe partition and re-authorize, or carry the class as explicitly out of coverage in the report instead of leaving the reader to notice its absence
- Priority basis: no measurement exists for this zone, so nothing was ranked: an undetermined area is always low because the finding reports the absence of a quantity rather than its size
- Engineer note: the matrix row for "xxe" is empty by construction: this build's inertness gate refuses the shapes that would demonstrate it, which is a coverage decision and not a result
- Reproduce: `xammu validate --finding UND-class-xxe --run demo-lab --authorization AUTH-SMOKE-LOCAL-001 --issuer-keyring trust/issuers --corpus corpus --class sqli --vector query,body_json,cookie`
- Regression: `xammu playbook --partition development --class xxe --authorization AUTH-SMOKE-LOCAL-001 --issuer-keyring trust/issuers --corpus corpus`
- Evidence profile: none: this finding states an absence, so no C-08 profile was compiled; observations: absence:demo-lab/round-1/class-xxe

### UND-unplanned-authorization_gap - undetermined_area (`low`, priority low)

- Scope: probes not run in partition development: 24 item(s)
- Claim: descriptive at evidence level none, attribution undetermined, basis none
- **Observed:** 24 corpus item(s) in partition development were not planned by this run under reason code "authorization_gap": DEV-CMD-P-01, DEV-CMD-Q-01, DEV-CMD-Q-02, DEV-CRLF-H-01, DEV-CRLF-H-02, DEV-HDR-POL-01, DEV-LDAP-Q-01, DEV-SQLI-F-01, DEV-SQLI-M-01, DEV-SQLI-Q-04, DEV-SQLI-Q-05, DEV-SQLI-QD-02, DEV-SSRF-Q-01, DEV-TRAV-P-01, DEV-TRAV-Q-01, DEV-TRAV-Q-02, DEV-XSS-JS-01, DEV-XSS-JS-02, DEV-XSS-JS-03, DEV-XSS-Q-01, DEV-XSS-Q-02, DEV-XSS-Q-03, DEV-XSS-Q-04, DEV-XXE-Q-01. The selection recorded: attack class command_injection is not in the authorization; attack class crlf_injection is not in the authorization; attack class ldap_injection is not in the authorization; vector body_form is not in the authorization; vector multipart_form is not in the authorization; encoding whitespace_variant is not in the authorization; encoding comment_insertion is not in the authorization; encoding html_entity_numeric is not in the authorization; attack class ssrf is not in the authorization; attack class path_traversal is not in the authorization; attack class xss is not in the authorization; attack class xxe is not in the authorization
- **Inferred:** nothing is inferred from these items: they were never sent, so they contribute no trial to any rate in this report, and no cell of the coverage matrix is closed by them
- **Missing evidence:** the exchanges themselves: a larger authorized budget, a wider authorization, or a later run that plans the remaining cells
- **Limitations:**
  - the exclusion list is the selection's own record; this finding adds no measurement to it
  - a cell left unmeasured cannot be compared in the matrix, which is why those rows stay empty rather than inferred
- Measured impact: 0 of 0 valid trial(s); population ``.
- Alternatives evaluated:
  - waf: unevaluable -- no valid reading exists for this zone, so no behaviour of the engine is in evidence: 24 corpus item(s) in partition development were not planned by this run under reason code "authorization_gap": DEV-CMD-P-01, DEV-CMD-Q-01, DEV-CMD-Q-02, DEV-CRLF-H-01, DEV-CRLF-H-02, DEV-HDR-POL-01, DEV-LDAP-Q-01, DEV-SQLI-F-01, DEV-SQLI-M-01, DEV-SQLI-Q-04, DEV-SQLI-Q-05, DEV-SQLI-QD-02, DEV-SSRF-Q-01, DEV-TRAV-P-01, DEV-TRAV-Q-01, DEV-TRAV-Q-02, DEV-XSS-JS-01, DEV-XSS-JS-02, DEV-XSS-JS-03, DEV-XSS-Q-01, DEV-XSS-Q-02, DEV-XSS-Q-03, DEV-XSS-Q-04, DEV-XXE-Q-01. The selection recorded: attack class command_injection is not in the authorization; attack class crlf_injection is not in the authorization; attack class ldap_injection is not in the authorization; vector body_form is not in the authorization; vector multipart_form is not in the authorization; encoding whitespace_variant is not in the authorization; encoding comment_insertion is not in the authorization; encoding html_entity_numeric is not in the authorization; attack class ssrf is not in the authorization; attack class path_traversal is not in the authorization; attack class xss is not in the authorization; attack class xxe is not in the authorization
    - test that would resolve it: an authorized exchange that produces one valid reading
  - origin_application: unevaluable -- the origin's own handling is equally unobserved: the absence of a reading says nothing about either side of the path
    - test that would resolve it: a valid reading, or an authorized direct-origin exchange
  - test_harness_artifact: not_ruled_out -- the reason this zone has no reading has not been separated from a failure of the run itself; the typed reason code states what was recorded, not what caused it
    - test that would resolve it: re-run of the planned exchange under the same authorization
- Recommendation: raise the request budget or accept a narrower matrix and say so; either way the report carries the unrun list rather than dropping it
- Priority basis: no measurement exists for this zone, so nothing was ranked: an undetermined area is always low because the finding reports the absence of a quantity rather than its size
- Engineer note: this is where the budget went. A reader who compares two runs with different budgets has to see this number to compare them honestly
- Reproduce: `xammu validate --finding UND-unplanned-authorization_gap --run demo-lab --authorization AUTH-SMOKE-LOCAL-001 --issuer-keyring trust/issuers --corpus corpus --class sqli --vector query,body_json,cookie`
- Regression: `xammu playbook --partition development --authorization AUTH-SMOKE-LOCAL-001 --issuer-keyring trust/issuers --corpus corpus`
- Evidence profile: none: this finding states an absence, so no C-08 profile was compiled; observations: absence:demo-lab/round-1/unplanned-authorization_gap

### UND-vector-body_form - undetermined_area (`low`, priority low)

- Scope: transport body_form: unmeasured in this run
- Grid position: class=- vector=body_form encoding=-
- Claim: descriptive at evidence level none, attribution undetermined, basis none
- **Observed:** the authorization covers the "body_form" transport. No exchange in this run placed a probe there. the probe partition carries 1 item(s) for the "body_form" transport and this run sent none of them: DEV-SQLI-F-01
- **Inferred:** nothing is inferred about inspection of the "body_form" transport. Every asymmetry this run measured excludes it, so a comparison involving it is outside this report
- **Missing evidence:** at least one valid exchange placing a probe in the "body_form" transport, with the same controls the measured transports used
- **Limitations:**
  - an unmeasured transport is not an uninspected transport
  - the coverage matrix in this report shows this transport as unmeasured rather than inferring a reading for it
- Measured impact: 0 of 0 valid trial(s); population ``.
- Alternatives evaluated:
  - waf: unevaluable -- no valid reading exists for this zone, so no behaviour of the engine is in evidence: the authorization covers the "body_form" transport. No exchange in this run placed a probe there. the probe partition carries 1 item(s) for the "body_form" transport and this run sent none of them: DEV-SQLI-F-01
    - test that would resolve it: an authorized exchange that produces one valid reading
  - origin_application: unevaluable -- the origin's own handling is equally unobserved: the absence of a reading says nothing about either side of the path
    - test that would resolve it: a valid reading, or an authorized direct-origin exchange
  - test_harness_artifact: not_ruled_out -- the reason this zone has no reading has not been separated from a failure of the run itself; the typed reason code states what was recorded, not what caused it
    - test that would resolve it: re-run of the planned exchange under the same authorization
- Recommendation: plan the "body_form" items that exist in the partition, or state in the report that the transport was never placed
- Priority basis: no measurement exists for this zone, so nothing was ranked: an undetermined area is always low because the finding reports the absence of a quantity rather than its size
- Engineer note: the reader who needs the "body_form" rows of the matrix is the one who will ask why they are empty; this finding is that answer, in advance
- Reproduce: `xammu validate --finding UND-vector-body_form --run demo-lab --authorization AUTH-SMOKE-LOCAL-001 --issuer-keyring trust/issuers --corpus corpus --class sqli --vector query,body_json,cookie`
- Regression: `xammu playbook --partition development --vector body_form --authorization AUTH-SMOKE-LOCAL-001 --issuer-keyring trust/issuers --corpus corpus`
- Evidence profile: none: this finding states an absence, so no C-08 profile was compiled; observations: absence:demo-lab/round-1/vector-body_form

### UND-vector-header - undetermined_area (`low`, priority low)

- Scope: transport header: unmeasured in this run
- Grid position: class=- vector=header encoding=-
- Claim: descriptive at evidence level none, attribution undetermined, basis none
- **Observed:** the authorization covers the "header" transport. No exchange in this run placed a probe there. the probe partition carries 3 item(s) for the "header" transport and this run sent none of them: DEV-CRLF-H-01, DEV-CRLF-H-02, DEV-HDR-POL-01
- **Inferred:** nothing is inferred about inspection of the "header" transport. Every asymmetry this run measured excludes it, so a comparison involving it is outside this report
- **Missing evidence:** at least one valid exchange placing a probe in the "header" transport, with the same controls the measured transports used
- **Limitations:**
  - an unmeasured transport is not an uninspected transport
  - the coverage matrix in this report shows this transport as unmeasured rather than inferring a reading for it
- Measured impact: 0 of 0 valid trial(s); population ``.
- Alternatives evaluated:
  - waf: unevaluable -- no valid reading exists for this zone, so no behaviour of the engine is in evidence: the authorization covers the "header" transport. No exchange in this run placed a probe there. the probe partition carries 3 item(s) for the "header" transport and this run sent none of them: DEV-CRLF-H-01, DEV-CRLF-H-02, DEV-HDR-POL-01
    - test that would resolve it: an authorized exchange that produces one valid reading
  - origin_application: unevaluable -- the origin's own handling is equally unobserved: the absence of a reading says nothing about either side of the path
    - test that would resolve it: a valid reading, or an authorized direct-origin exchange
  - test_harness_artifact: not_ruled_out -- the reason this zone has no reading has not been separated from a failure of the run itself; the typed reason code states what was recorded, not what caused it
    - test that would resolve it: re-run of the planned exchange under the same authorization
- Recommendation: plan the "header" items that exist in the partition, or state in the report that the transport was never placed
- Priority basis: no measurement exists for this zone, so nothing was ranked: an undetermined area is always low because the finding reports the absence of a quantity rather than its size
- Engineer note: the reader who needs the "header" rows of the matrix is the one who will ask why they are empty; this finding is that answer, in advance
- Reproduce: `xammu validate --finding UND-vector-header --run demo-lab --authorization AUTH-SMOKE-LOCAL-001 --issuer-keyring trust/issuers --corpus corpus --class sqli --vector query,body_json,cookie`
- Regression: `xammu playbook --partition development --vector header --authorization AUTH-SMOKE-LOCAL-001 --issuer-keyring trust/issuers --corpus corpus`
- Evidence profile: none: this finding states an absence, so no C-08 profile was compiled; observations: absence:demo-lab/round-1/vector-header

### UND-vector-path - undetermined_area (`low`, priority low)

- Scope: transport path: unmeasured in this run
- Grid position: class=- vector=path encoding=-
- Claim: descriptive at evidence level none, attribution undetermined, basis none
- **Observed:** the authorization covers the "path" transport. No exchange in this run placed a probe there. the probe partition carries 2 item(s) for the "path" transport and this run sent none of them: DEV-CMD-P-01, DEV-TRAV-P-01
- **Inferred:** nothing is inferred about inspection of the "path" transport. Every asymmetry this run measured excludes it, so a comparison involving it is outside this report
- **Missing evidence:** at least one valid exchange placing a probe in the "path" transport, with the same controls the measured transports used
- **Limitations:**
  - an unmeasured transport is not an uninspected transport
  - the coverage matrix in this report shows this transport as unmeasured rather than inferring a reading for it
- Measured impact: 0 of 0 valid trial(s); population ``.
- Alternatives evaluated:
  - waf: unevaluable -- no valid reading exists for this zone, so no behaviour of the engine is in evidence: the authorization covers the "path" transport. No exchange in this run placed a probe there. the probe partition carries 2 item(s) for the "path" transport and this run sent none of them: DEV-CMD-P-01, DEV-TRAV-P-01
    - test that would resolve it: an authorized exchange that produces one valid reading
  - origin_application: unevaluable -- the origin's own handling is equally unobserved: the absence of a reading says nothing about either side of the path
    - test that would resolve it: a valid reading, or an authorized direct-origin exchange
  - test_harness_artifact: not_ruled_out -- the reason this zone has no reading has not been separated from a failure of the run itself; the typed reason code states what was recorded, not what caused it
    - test that would resolve it: re-run of the planned exchange under the same authorization
- Recommendation: plan the "path" items that exist in the partition, or state in the report that the transport was never placed
- Priority basis: no measurement exists for this zone, so nothing was ranked: an undetermined area is always low because the finding reports the absence of a quantity rather than its size
- Engineer note: the reader who needs the "path" rows of the matrix is the one who will ask why they are empty; this finding is that answer, in advance
- Reproduce: `xammu validate --finding UND-vector-path --run demo-lab --authorization AUTH-SMOKE-LOCAL-001 --issuer-keyring trust/issuers --corpus corpus --class sqli --vector query,body_json,cookie`
- Regression: `xammu playbook --partition development --vector path --authorization AUTH-SMOKE-LOCAL-001 --issuer-keyring trust/issuers --corpus corpus`
- Evidence profile: none: this finding states an absence, so no C-08 profile was compiled; observations: absence:demo-lab/round-1/vector-path

### ASY-G-DEV-GEN-SENTINEL-queryvsbody_json - vector_asymmetry (`low`, priority low)

- Scope: family G-DEV-GEN-SENTINEL ("xammu-probe-token") compared across query and body_json on /api/search
- Grid position: class=sqli vector=body_json encoding=canonical
- Claim: descriptive at evidence level replicated_within_run, attribution undetermined, basis http_only
- **Observed:** one payload family, two transports: 1/1 (100%) valid trials of "xammu-probe-token" placed in query produced the block shape refusals, and 0/1 (0%) valid trials of the same family placed in body_json produced ordinary handling. Expectations behind these probes: lab-rule-table:GENERIC-001, lab-rule-table:coverage:json_body_uninspected.
- **Inferred:** the payload is constant across the comparison, so the difference is in the transport: this is compatible with inspection being configured for query and not for body_json, and incompatible with an explanation that rests on the payload's content
- **Missing evidence:** This run supplies the response side only. What is missing is a valid control pair inside the profile, so the reading is anchored against ordinary handling rather than against expectation. Recorded by the evidence profile: to raise the evidence level: a valid positive control (a payload this run recorded as rejected) and a valid negative control (a benign reference this run recorded as ordinarily handled).; the cell pair sqli|body_json|canonical|/api/search and sqli|query|canonical|/api/search is the comparison, so an engine configuration export naming per-transport inspection would settle it
- **Limitations:**
  - does not show the body_json transport is unexamined by every rule: it shows this one family was not refused there
  - the two transports are different request shapes; an origin-side router that handles them apart is not excluded
  - 0 inconclusive and 0 invalid trial(s) are outside this count
  - does not show any real payload reaches the origin: only that these probes were handled ordinarily
- Measured impact: 0 of 2 valid trial(s); population `group:G-DEV-GEN-SENTINEL`.
- Alternatives evaluated:
  - waf: supported -- the run contains both a refused exchange and an ordinarily handled one, and the calibration pair on the same route separates the two shapes
    - test that would resolve it: authorized exchange that reaches the origin without the front end, or the engine's own rule configuration
  - origin_application: ruled_out -- a valid benign exchange on the same route returned the origin's ordinary shape, so the origin answers this path when it is not rejecting
    - test that would resolve it: authorized request to the origin directly, bypassing the front end
  - reverse_proxy_or_cdn: not_ruled_out -- the authorization covers one destination; nothing in the run distinguishes a proxy or CDN layer from the engine it forwards to, so a refusal at an earlier hop would look identical here
    - test that would resolve it: response header comparison across an authorized direct-origin exchange, or the operator's topology
  - rate_limiting_or_throttling: ruled_out -- no exchange in scope returned 429, and the refused responses carry the interstitial shape rather than a throttling one
    - test that would resolve it: status and Retry-After inspection already performed on every exchange
  - test_harness_artifact: ruled_out -- the same client, body shape and route produced both readings, and the calibration pair moved with the payload rather than with the transport
    - test that would resolve it: replay of one refused and one passed exchange from the journal with the same client
  - routing_divergence: not_ruled_out -- the finding compares locations, not payloads: a router or framework that maps one transport to a different handler would produce the same difference before any engine saw the request
    - test that would resolve it: origin-side access log entry for both placements, showing which handler received each
- Recommendation: compare inspection coverage for the body_json transport against the transport it differs from in the engine's configuration; the decision to hand to the operator is whether body_json traffic is meant to be inspected at all
- Priority basis: 100 percentage points measured over 2 valid trials: too small a difference, too few trials, or both, to rank above low
- Engineer note: inspection differs by transport for this family: the body_json side is where the operator's coverage decision has to be checked, because the same bytes are refused at query
- Reproduce: `xammu validate --finding ASY-G-DEV-GEN-SENTINEL-queryvsbody_json --run demo-lab --authorization AUTH-SMOKE-LOCAL-001 --issuer-keyring trust/issuers --corpus corpus --class sqli --vector query,body_json,cookie`
- Regression: `xammu lab test --scenario vector-asymmetry-g-dev-gen-sentinel`
- Evidence profile: `9bd86f2f-f05e-4e69-8caa-35e9f5ee31a3`; observations: 2edccecd-8e37-47f1-a323-975445a7fae7, 53d7604a-a6fc-4ed6-93d2-ae6da1f19054


## Counted views (distributions)

**Behavioural signal of every exchange the pass classified in run demo-lab** (behavioral_signal)

- compatible_block 6; compatible_normal 5; indeterminate 0 (excluded from the denominator); rate_limited 0; transport_error 0; not_measured 0
- denominator: 11
- basis: every probe exchange in 7 graded cell(s), valid or not, counted once: 11 exchange(s) in all. The denominator excludes the 0 indeterminate one(s) - exchanges the classifier could not place on either side of the agreement - and nothing else, so the 0 rate-limited and 0 transport-failed exchange(s) stay inside it: the run reached a state worth naming even though the defence never saw a probe. That makes this denominator 11, while every refusal rate elsewhere in this report is over the 11 valid trial(s) alone. The two are different arithmetic on purpose and neither is a correction of the other: this view answers what the exchanges were, a finding answers what the defence did with probe traffic it could read.

**Attribution status of each graded cell** (attribution_status)

- undetermined 7 (excluded from the denominator); compatible 0; probable_without_corroboration 0; supported_by_logs 0; confirmed_by_correlated_evidence 0; not_attributable_to_waf 0
- denominator: 0
- basis: one entry per cell the pass graded (7). A cell with no attribution record is counted as undetermined, which is the bucket excluded from the denominator: absence of attribution cannot be read as evidence that the defence did something.

**Evidence basis behind each attribution** (evidence_basis)

- none 0 (excluded from the denominator); http_only 7; http_plus_valid_control 0; http_plus_independent_rounds 0; http_plus_correlated_logs 0; http_plus_configuration_export 0; not_applicable 0
- denominator: 7
- basis: one entry per graded cell (7). "none" is the bucket kept out of the denominator: an attribution resting on no evidence is not a grade. 0 cell(s) cite a source outside the HTTP response (filter logs or a configuration export), which is the only way a claim in this report can rise above what a response shows.

**Outcome of each hypothesis the pass formed** (hypothesis_outcome)

- supported 0; refuted 7; inconclusive 0 (excluded from the denominator)
- denominator: 7
- basis: the 7 cell(s) that produced a hypothesis; 0 cell(s) produced none and are reported as undetermined areas instead, because an absence of measurement is not an outcome. inconclusive is excluded from the denominator.

**Verdict of every encoding row of the coverage matrix** (coverage_verdict)

- blocked 3; passed 3; mixed 1; indeterminate 0 (excluded from the denominator); not_measured 0
- denominator: 7
- basis: the 7 encoding row(s) of the matrix over 3 cell(s). indeterminate rows are excluded from the denominator: a row whose valid trials produced neither refusals nor ordinary handling measured nothing, and counting it would inflate the coverage claim.

## Residual risk: three statements kept apart

#### Conditional risk (measured, bounded)

Conditional exposure from finding BYP-G-DEV-SQLI-Q-TAUTO (encoding_bypass_pattern): the difference is the encoding of the payload, not its meaning, which is compatible with the decoding applied before matching being shallower than the encoding applied to the probe; the run cannot see how many decode passes the engine makes. The rate behind it is 1 of 4 valid trial(s), so the exposure is bounded by that measurement: it does not extend to encodings, transports or paths this run did not place a probe in, and it is not a claim that any payload reaches an application.

- Scope: encoding family G-DEV-SQLI-Q-TAUTO (sqli x query) on /api/search: canonical refused, url_double handled ordinarily
- Evidence: 3e30898c-9d46-4318-bb1e-dc07039fad4f; 2ca238a9-6c75-4ce6-b0e8-0884367d537e; 32138c3e-d324-4107-b7c7-8eda0e0b3887; 4d114f33-0072-4be2-9c63-186e0c4cf6e6; 56fdbe55-9e35-4e74-9b42-64e0d24243b2
- Verify: `xammu validate --finding BYP-G-DEV-SQLI-Q-TAUTO --run demo-lab --authorization AUTH-SMOKE-LOCAL-001 --issuer-keyring trust/issuers --corpus corpus --class sqli --vector query,body_json,cookie`
- What was not tested:
  - does not show any encoded payload gets through: it shows these encodings of this family were not refused
  - does not identify which component decodes; an origin-side normalisation would produce the same readings and is not excluded
  - 0 inconclusive and 0 invalid trial(s) are outside this count
  - 25 cell(s) of the authorized grid have no valid reading, so the difference BYP-G-DEV-SQLI-Q-TAUTO states is not known to hold or fail outside the cells listed here

#### Condition not demonstrated (evidence gap)

Not demonstrated: that the handling measured here is the work of a perimeter rule rather than of the origin application, a cache, a rate limiter or this harness. The strongest evidence grade in this report is "replicated_with_valid_controls" across 7 cell(s), 0 of which cite a source outside the response, and 1 round(s) contributed readings. The rung above needs independent rounds and corroboration; what is missing, in the words of the finding that got closest (BYP-G-DEV-SQLI-Q-TAUTO): This run supplies the response side only. What is missing is repetition: a second authorized round of the same cell, so the difference is shown to survive rather than to be one exchange. Recorded by the evidence profile: to raise the evidence level: a valid positive control (a payload this run recorded as rejected) and a valid negative control (a benign reference this run recorded as ordinarily handled); to raise the evidence level: the same reading reproduced by two or more valid trials inside this run.; the number of normalisation passes the engine applies is not observable from a response, so the decoding depth is reasoned about from this difference and never measured directly.

- Scope: attribution of every behavioural claim in run demo-lab against authorization AUTH-SMOKE-LOCAL-001
- Evidence: runs/demo-lab/manifest.json; distribution:attribution_status; distribution:evidence_basis; BYP-G-DEV-SQLI-Q-TAUTO; OVB-informative_either; UND-class-command_injection; UND-class-crlf_injection; UND-class-ldap_injection; UND-class-path_traversal; UND-class-ssrf; UND-class-xss; UND-class-xxe; UND-unplanned-authorization_gap; UND-vector-body_form; UND-vector-header; and 2 further finding ref(s)
- Verify: `xammu playbook --partition development --authorization AUTH-SMOKE-LOCAL-001 --round round-2 --authorization AUTH-SMOKE-LOCAL-001 --issuer-keyring trust/issuers --corpus corpus --class sqli --vector query,body_json,cookie`
- What was not tested:
  - a second round under its own authorization, which is the only way an in-run repetition becomes independent reproduction
  - the filter logs or rule configuration of the engine, which nothing in this run reads
  - the origin's own behaviour when the same exchange arrives without the perimeter in front of it
  - 25 cell(s) the plan never placed, where the question cannot even be asked

#### Undeterminable (not answerable from a response)

Undeterminable from this evidence, in the run's own words (UND-class-command_injection): nothing is inferred about how "command_injection" is handled. The absence is in this run's coverage, not in the engine's behaviour: no exchange was measured, so the class is unmeasured rather than examined. What would settle it: corpus items of class "command_injection" that pass the inertness gate, plus a plan that sends them under this authorization. The run cannot supply that from a response, which is why the zone stays open in the report instead of being closed by an inference.

- Scope: attack class command_injection: unmeasured in this run
- Evidence: absence:demo-lab/round-1/class-command_injection
- Verify: `xammu validate --finding UND-class-command_injection --run demo-lab --authorization AUTH-SMOKE-LOCAL-001 --issuer-keyring trust/issuers --corpus corpus --class sqli --vector query,body_json,cookie`
- What was not tested:
  - an unmeasured class is not an unguarded class
  - the reason code distinguishes a corpus that has nothing sendable from a run that sent nothing; it does not explain why the corpus has nothing
  - 25 cell(s) of the authorized grid have no valid reading, so the difference UND-class-command_injection states is not known to hold or fail outside the cells listed here

## Unevaluated zones

- **attack class command_injection: unmeasured in this run** (reason `not_yet_attempted`)
  - Detail: the authorization covers attack class "command_injection". No exchange in this run carried that class. the probe partition carries 3 item(s) of class "command_injection" and this run planned or sent none of them. The pass measured 1 class(es).
  - Remediation: either add gated items of class "command_injection" to the probe partition and re-authorize, or carry the class as explicitly out of coverage in the report instead of leaving the reader to notice its absence
  - Reproduce: `xammu validate --finding UND-class-command_injection --run demo-lab --authorization AUTH-SMOKE-LOCAL-001 --issuer-keyring trust/issuers --corpus corpus --class sqli --vector query,body_json,cookie`
  - Planned requests not spent: 0
- **attack class crlf_injection: unmeasured in this run** (reason `not_yet_attempted`)
  - Detail: the authorization covers attack class "crlf_injection". No exchange in this run carried that class. the probe partition carries 3 item(s) of class "crlf_injection" and this run planned or sent none of them. The pass measured 1 class(es).
  - Remediation: either add gated items of class "crlf_injection" to the probe partition and re-authorize, or carry the class as explicitly out of coverage in the report instead of leaving the reader to notice its absence
  - Reproduce: `xammu validate --finding UND-class-crlf_injection --run demo-lab --authorization AUTH-SMOKE-LOCAL-001 --issuer-keyring trust/issuers --corpus corpus --class sqli --vector query,body_json,cookie`
  - Planned requests not spent: 0
- **attack class ldap_injection: unmeasured in this run** (reason `not_yet_attempted`)
  - Detail: the authorization covers attack class "ldap_injection". No exchange in this run carried that class. the probe partition carries 1 item(s) of class "ldap_injection" and this run planned or sent none of them. The pass measured 1 class(es).
  - Remediation: either add gated items of class "ldap_injection" to the probe partition and re-authorize, or carry the class as explicitly out of coverage in the report instead of leaving the reader to notice its absence
  - Reproduce: `xammu validate --finding UND-class-ldap_injection --run demo-lab --authorization AUTH-SMOKE-LOCAL-001 --issuer-keyring trust/issuers --corpus corpus --class sqli --vector query,body_json,cookie`
  - Planned requests not spent: 0
- **attack class path_traversal: unmeasured in this run** (reason `not_yet_attempted`)
  - Detail: the authorization covers attack class "path_traversal". No exchange in this run carried that class. the probe partition carries 3 item(s) of class "path_traversal" and this run planned or sent none of them. The pass measured 1 class(es).
  - Remediation: either add gated items of class "path_traversal" to the probe partition and re-authorize, or carry the class as explicitly out of coverage in the report instead of leaving the reader to notice its absence
  - Reproduce: `xammu validate --finding UND-class-path_traversal --run demo-lab --authorization AUTH-SMOKE-LOCAL-001 --issuer-keyring trust/issuers --corpus corpus --class sqli --vector query,body_json,cookie`
  - Planned requests not spent: 0
- **attack class ssrf: unmeasured in this run** (reason `not_yet_attempted`)
  - Detail: the authorization covers attack class "ssrf". No exchange in this run carried that class. the probe partition carries 1 item(s) of class "ssrf" and this run planned or sent none of them. The pass measured 1 class(es).
  - Remediation: either add gated items of class "ssrf" to the probe partition and re-authorize, or carry the class as explicitly out of coverage in the report instead of leaving the reader to notice its absence
  - Reproduce: `xammu validate --finding UND-class-ssrf --run demo-lab --authorization AUTH-SMOKE-LOCAL-001 --issuer-keyring trust/issuers --corpus corpus --class sqli --vector query,body_json,cookie`
  - Planned requests not spent: 0
- **attack class xss: unmeasured in this run** (reason `not_yet_attempted`)
  - Detail: the authorization covers attack class "xss". No exchange in this run carried that class. the probe partition carries 7 item(s) of class "xss" and this run planned or sent none of them. The pass measured 1 class(es).
  - Remediation: either add gated items of class "xss" to the probe partition and re-authorize, or carry the class as explicitly out of coverage in the report instead of leaving the reader to notice its absence
  - Reproduce: `xammu validate --finding UND-class-xss --run demo-lab --authorization AUTH-SMOKE-LOCAL-001 --issuer-keyring trust/issuers --corpus corpus --class sqli --vector query,body_json,cookie`
  - Planned requests not spent: 0
- **attack class xxe: unmeasured in this run** (reason `not_yet_attempted`)
  - Detail: the authorization covers attack class "xxe". No exchange in this run carried that class. the probe partition carries 1 item(s) of class "xxe" and this run planned or sent none of them. The pass measured 1 class(es).
  - Remediation: either add gated items of class "xxe" to the probe partition and re-authorize, or carry the class as explicitly out of coverage in the report instead of leaving the reader to notice its absence
  - Reproduce: `xammu validate --finding UND-class-xxe --run demo-lab --authorization AUTH-SMOKE-LOCAL-001 --issuer-keyring trust/issuers --corpus corpus --class sqli --vector query,body_json,cookie`
  - Planned requests not spent: 0
- **probes not run in partition development: 24 item(s)** (reason `authorization_gap`)
  - Detail: 24 corpus item(s) in partition development were not planned by this run under reason code "authorization_gap": DEV-CMD-P-01, DEV-CMD-Q-01, DEV-CMD-Q-02, DEV-CRLF-H-01, DEV-CRLF-H-02, DEV-HDR-POL-01, DEV-LDAP-Q-01, DEV-SQLI-F-01, DEV-SQLI-M-01, DEV-SQLI-Q-04, DEV-SQLI-Q-05, DEV-SQLI-QD-02, DEV-SSRF-Q-01, DEV-TRAV-P-01, DEV-TRAV-Q-01, DEV-TRAV-Q-02, DEV-XSS-JS-01, DEV-XSS-JS-02, DEV-XSS-JS-03, DEV-XSS-Q-01, DEV-XSS-Q-02, DEV-XSS-Q-03, DEV-XSS-Q-04, DEV-XXE-Q-01. The selection recorded: attack class command_injection is not in the authorization; attack class crlf_injection is not in the authorization; attack class ldap_injection is not in the authorization; vector body_form is not in the authorization; vector multipart_form is not in the authorization; encoding whitespace_variant is not in the authorization; encoding comment_insertion is not in the authorization; encoding html_entity_numeric is not in the authorization; attack class ssrf is not in the authorization; attack class path_traversal is not in the authorization; attack class xss is not in the authorization; attack class xxe is not in the authorization
  - Remediation: raise the request budget or accept a narrower matrix and say so; either way the report carries the unrun list rather than dropping it
  - Reproduce: `xammu validate --finding UND-unplanned-authorization_gap --run demo-lab --authorization AUTH-SMOKE-LOCAL-001 --issuer-keyring trust/issuers --corpus corpus --class sqli --vector query,body_json,cookie`
  - Planned requests not spent: 24
- **transport body_form: unmeasured in this run** (reason `not_yet_attempted`)
  - Detail: the authorization covers the "body_form" transport. No exchange in this run placed a probe there. the probe partition carries 1 item(s) for the "body_form" transport and this run sent none of them: DEV-SQLI-F-01
  - Remediation: plan the "body_form" items that exist in the partition, or state in the report that the transport was never placed
  - Reproduce: `xammu validate --finding UND-vector-body_form --run demo-lab --authorization AUTH-SMOKE-LOCAL-001 --issuer-keyring trust/issuers --corpus corpus --class sqli --vector query,body_json,cookie`
  - Planned requests not spent: 0
- **transport header: unmeasured in this run** (reason `not_yet_attempted`)
  - Detail: the authorization covers the "header" transport. No exchange in this run placed a probe there. the probe partition carries 3 item(s) for the "header" transport and this run sent none of them: DEV-CRLF-H-01, DEV-CRLF-H-02, DEV-HDR-POL-01
  - Remediation: plan the "header" items that exist in the partition, or state in the report that the transport was never placed
  - Reproduce: `xammu validate --finding UND-vector-header --run demo-lab --authorization AUTH-SMOKE-LOCAL-001 --issuer-keyring trust/issuers --corpus corpus --class sqli --vector query,body_json,cookie`
  - Planned requests not spent: 0
- **transport path: unmeasured in this run** (reason `not_yet_attempted`)
  - Detail: the authorization covers the "path" transport. No exchange in this run placed a probe there. the probe partition carries 2 item(s) for the "path" transport and this run sent none of them: DEV-CMD-P-01, DEV-TRAV-P-01
  - Remediation: plan the "path" items that exist in the partition, or state in the report that the transport was never placed
  - Reproduce: `xammu validate --finding UND-vector-path --run demo-lab --authorization AUTH-SMOKE-LOCAL-001 --issuer-keyring trust/issuers --corpus corpus --class sqli --vector query,body_json,cookie`
  - Planned requests not spent: 0

## Evidence and reproducibility

- Manifest: `runs/demo-lab/manifest.json` (digest `sha256:d51e4a9291a9d11c72605beb7cd46204281ff72dc32eb470f420456f1d34df88`)
- Verify: `xammu verify --run demo-lab --authorization AUTH-SMOKE-LOCAL-001 --issuer-keyring trust/issuers --corpus corpus --class sqli --vector query,body_json,cookie`
- Observations: 23 across round(s) round-1
- Corpus: `git:94fa0c85c0aaade1bbf2a4f3657872e8de41618e corpus-digest:d93614af49de417046bc744e92f90071384b8181f9dba6c7a6329ab06c909ec7`; detector set: `sha256:9f00fd1a1303e9f05f7c28cd01d5d5929f27aa187d5914d542fb30231f5b093a`; tool: `xammu-1.0.0`; generated by: `unknown`

## Declared out of scope

- application_vulnerabilities_not_evaluated
- no_exploitation_performed
- routes_not_proved_are_not_covered
- origin_behaviour_beyond_observed_responses_not_evaluated
- no_attestation_that_the_waf_is_secure
- not_a_replacement_for_a_penetration_test

## Contract versions

C-01 (raw_observation)=1.0.0; C-02 (transient_capture)=1.0.0; C-03 (signature_analysis)=1.0.0; C-04 (behavioral_classification)=1.0.0; C-05 (attribution)=1.0.0; C-06 (attribution_status)=1.0.0; C-07 (hypothesis)=1.0.0; C-08 (evidence_profile)=1.0.0; C-09 (profiling_authorization)=1.0.0; C-10 (validation_authorization)=1.0.0; C-11 (run_profile)=1.0.0; C-12 (integrity_manifest)=1.0.0; C-13 (corpus_item)=1.0.0; C-14 (corpus_partition)=1.0.0; C-15 (report)=1.0.0; C-16 (discovery_finding)=1.0.0
