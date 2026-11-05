# WAF effectiveness — run waf-effectiveness-2026-11-05-r7

- authorization: `AUTH-EFFECTIVENESS-LOCAL-002`
- corpus digest: `sha256:377882d1ccaea712fdee69f8ec96a46c7976a565658c32a3e8c4082dd06eeefd`
- cases: 600
- generated: 2026-11-05T22:26:51Z

## Confusion matrix

| TP | FN | FP | TN | excluded |
|---:|---:|---:|---:|---:|
| 300 | 0 | 0 | 300 | 0 |

## Rates

| metric | value |
|---|---:|
| TPR (recall) | 100.00% |
| FPR | 0.00% |
| Precision | 100.00% |
| F1 | 100.00% |
| MCC | 1.000 |

## WAF fingerprint

- policy: `xammu-waf-fingerprint/1.0.0`
- baseline outcomes observed: 600; with signature evidence: 600

### `xammu-reference-waf` — confidence `high`

- conclusive outcomes with evidence: 600
- evidence:
  - `error_page:reference-block-marker` (error_page, identifying) — the repository's reference fixture sets this marker itself; see examples/reference-waf
  - `header:x-xammu-reference-action` (header, identifying) — the repository's reference fixture sets this marker itself; see examples/reference-waf
  - `header:server` (header, identifying) — the repository's reference fixture sets this marker itself; see examples/reference-waf
- recommendation basis: generic candidate only: no cited vendor-specific technique is available
- candidate stack: `url_encode_double` → `case_switch` — generic representation-shifting candidate; no vendor-specific bypass knowledge is asserted

Support is categorical: `high` needs two evidence kinds and an identifying signature, `medium` one identifying kind, `low` supporting or excluded-only evidence, `none` no match. Candidate stacks are hypotheses to measure, not asserted bypasses.

## Baseline vs tamper

- tamper stack: `url_encode_double` → `case_switch`
- selection basis: auto: vendor=xammu-reference-waf confidence=high; generic representation-shifting candidate; no vendor-specific bypass knowledge is asserted

| class | baseline TPR (n) | tamper TPR (n) | delta |
|---|---:|---:|---:|
| sqli | 100.00% (30) | 96.67% (30) | -3.33 pp |
| xss | 100.00% (30) | 96.67% (30) | -3.33 pp |
| path_traversal | 100.00% (30) | 96.67% (30) | -3.33 pp |
| command_injection | 100.00% (30) | 93.33% (30) | -6.67 pp |
| ssrf | 100.00% (30) | 100.00% (30) | 0.00 pp |
| ldap_injection | 100.00% (30) | 96.67% (30) | -3.33 pp |
| nosql_injection | 100.00% (30) | 96.67% (30) | -3.33 pp |
| xxe | 100.00% (30) | 96.67% (30) | -3.33 pp |
| crlf_injection | 100.00% (30) | 80.00% (30) | -20.00 pp |
| ssti | 100.00% (30) | 96.67% (30) | -3.33 pp |
| all attack classes | 100.00% (300) | 95.00% (300) | -5.00 pp |

TPR denominators are conclusive attack cases in each arm; excluded cases are not in them. Delta is tamper minus baseline in percentage points.

False-positive cost: baseline FPR 0.00% (FP 0, TN 300) versus tamper FPR 0.00% (FP 0, TN 299).

## By class

| class | kind | TP | FN | FP | TN | excl | TPR | FPR | Precision | F1 | MCC | n | p50 | p95 | p99 |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| sqli | attack | 30 | 0 | 0 | 0 | 0 | 100.00% | n/a | 100.00% | 100.00% | n/a | 30 | 0 ms | 0 ms | 1 ms |
| xss | attack | 30 | 0 | 0 | 0 | 0 | 100.00% | n/a | 100.00% | 100.00% | n/a | 30 | 0 ms | 0 ms | 0 ms |
| path_traversal | attack | 30 | 0 | 0 | 0 | 0 | 100.00% | n/a | 100.00% | 100.00% | n/a | 30 | 0 ms | 1 ms | 1 ms |
| command_injection | attack | 30 | 0 | 0 | 0 | 0 | 100.00% | n/a | 100.00% | 100.00% | n/a | 30 | 0 ms | 0 ms | 2 ms |
| ssrf | attack | 30 | 0 | 0 | 0 | 0 | 100.00% | n/a | 100.00% | 100.00% | n/a | 30 | 0 ms | 0 ms | 1 ms |
| ldap_injection | attack | 30 | 0 | 0 | 0 | 0 | 100.00% | n/a | 100.00% | 100.00% | n/a | 30 | 0 ms | 0 ms | 0 ms |
| nosql_injection | attack | 30 | 0 | 0 | 0 | 0 | 100.00% | n/a | 100.00% | 100.00% | n/a | 30 | 0 ms | 0 ms | 0 ms |
| xxe | attack | 30 | 0 | 0 | 0 | 0 | 100.00% | n/a | 100.00% | 100.00% | n/a | 30 | 0 ms | 0 ms | 0 ms |
| crlf_injection | attack | 30 | 0 | 0 | 0 | 0 | 100.00% | n/a | 100.00% | 100.00% | n/a | 30 | 0 ms | 0 ms | 0 ms |
| ssti | attack | 30 | 0 | 0 | 0 | 0 | 100.00% | n/a | 100.00% | 100.00% | n/a | 30 | 0 ms | 0 ms | 0 ms |
| benign_text | benign | 0 | 0 | 0 | 60 | 0 | n/a | 0.00% | n/a | n/a | n/a | 60 | 0 ms | 0 ms | 0 ms |
| benign_json | benign | 0 | 0 | 0 | 60 | 0 | n/a | 0.00% | n/a | n/a | n/a | 60 | 0 ms | 0 ms | 1 ms |
| benign_form | benign | 0 | 0 | 0 | 50 | 0 | n/a | 0.00% | n/a | n/a | n/a | 50 | 0 ms | 0 ms | 1 ms |
| benign_query | benign | 0 | 0 | 0 | 59 | 0 | n/a | 0.00% | n/a | n/a | n/a | 59 | 0 ms | 0 ms | 0 ms |
| benign_header | benign | 0 | 0 | 0 | 40 | 0 | n/a | 0.00% | n/a | n/a | n/a | 40 | 0 ms | 0 ms | 0 ms |
| benign_cookie | benign | 0 | 0 | 0 | 30 | 0 | n/a | 0.00% | n/a | n/a | n/a | 30 | 0 ms | 0 ms | 0 ms |
| benign_path | benign | 0 | 0 | 0 | 1 | 0 | n/a | 0.00% | n/a | n/a | n/a | 1 | 0 ms | 0 ms | 0 ms |

## Latency

| population | n | p50 | p95 | p99 | sample |
|---|---:|---:|---:|---:|---|
| all conclusive | 600 | 0 ms | 0 ms | 1 ms | sufficient |

Percentiles use nearest rank. `n` is the number of conclusive exchanges; excluded ones are not timed into the result.

## Notes and limits

- The top-level matrix is the baseline arm; arms publishes each arm separately.
- Delta in the comparison table is tamper TPR minus baseline TPR in percentage points; it is arithmetic over the two matrices, not an estimated effect size.
- TPR and FPR describe agreement with this corpus, on this target, in this window; they are not a claim of absolute efficacy.
- 429 is pacing, never a block (criterion 24): it is excluded and counted with the other inconclusive outcomes.
- A zero-denominator metric is null; no value is invented.
- Percentiles use nearest rank; p99 is marked insufficient below 100 samples and every summary below 20 samples.
- OWASP references are declarative labels, not severity scores: sqli=A03:2021-Injection, xss=A03:2021-Injection, path_traversal=A01:2021-Broken Access Control, command_injection=A03:2021-Injection, ssrf=A10:2021-Server-Side Request Forgery, ldap_injection=A03:2021-Injection, nosql_injection=A03:2021-Injection, xxe=A05:2021-Security Misconfiguration, crlf_injection=A03:2021-Injection, ssti=A03:2021-Injection.
