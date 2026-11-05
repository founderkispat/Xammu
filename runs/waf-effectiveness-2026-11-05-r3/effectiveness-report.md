# WAF effectiveness — run waf-effectiveness-2026-11-05-r3

- authorization: `AUTH-EFFECTIVENESS-LOCAL-001`
- corpus digest: `sha256:377882d1ccaea712fdee69f8ec96a46c7976a565658c32a3e8c4082dd06eeefd`
- cases: 600
- generated: 2026-11-05T20:00:48Z

## Confusion matrix

| TP | FN | FP | TN | excluded |
|---:|---:|---:|---:|---:|
| 25 | 275 | 8 | 292 | 0 |

## Rates

| metric | value |
|---|---:|
| TPR (recall) | 8.33% |
| FPR | 2.67% |
| Precision | 75.76% |
| F1 | 15.02% |
| MCC | 0.124 |

## By class

| class | kind | TP | FN | FP | TN | excl | TPR | FPR | Precision | F1 | MCC | n | p50 | p95 | p99 |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| sqli | attack | 8 | 22 | 0 | 0 | 0 | 26.67% | n/a | 100.00% | 42.11% | n/a | 30 | 0 ms | 0 ms | 0 ms |
| xss | attack | 2 | 28 | 0 | 0 | 0 | 6.67% | n/a | 100.00% | 12.50% | n/a | 30 | 0 ms | 0 ms | 0 ms |
| path_traversal | attack | 1 | 29 | 0 | 0 | 0 | 3.33% | n/a | 100.00% | 6.45% | n/a | 30 | 0 ms | 0 ms | 0 ms |
| command_injection | attack | 1 | 29 | 0 | 0 | 0 | 3.33% | n/a | 100.00% | 6.45% | n/a | 30 | 0 ms | 0 ms | 3 ms |
| ssrf | attack | 0 | 30 | 0 | 0 | 0 | 0.00% | n/a | n/a | n/a | n/a | 30 | 0 ms | 0 ms | 0 ms |
| ldap_injection | attack | 1 | 29 | 0 | 0 | 0 | 3.33% | n/a | 100.00% | 6.45% | n/a | 30 | 0 ms | 0 ms | 0 ms |
| nosql_injection | attack | 7 | 23 | 0 | 0 | 0 | 23.33% | n/a | 100.00% | 37.84% | n/a | 30 | 0 ms | 0 ms | 0 ms |
| xxe | attack | 5 | 25 | 0 | 0 | 0 | 16.67% | n/a | 100.00% | 28.57% | n/a | 30 | 0 ms | 0 ms | 4 ms |
| crlf_injection | attack | 0 | 30 | 0 | 0 | 0 | 0.00% | n/a | n/a | n/a | n/a | 30 | 0 ms | 1 ms | 6 ms |
| ssti | attack | 0 | 30 | 0 | 0 | 0 | 0.00% | n/a | n/a | n/a | n/a | 30 | 0 ms | 0 ms | 0 ms |
| benign_text | benign | 0 | 0 | 5 | 55 | 0 | n/a | 8.33% | 0.00% | n/a | n/a | 60 | 0 ms | 0 ms | 0 ms |
| benign_json | benign | 0 | 0 | 0 | 60 | 0 | n/a | 0.00% | n/a | n/a | n/a | 60 | 0 ms | 0 ms | 0 ms |
| benign_form | benign | 0 | 0 | 0 | 50 | 0 | n/a | 0.00% | n/a | n/a | n/a | 50 | 0 ms | 0 ms | 0 ms |
| benign_query | benign | 0 | 0 | 3 | 56 | 0 | n/a | 5.08% | 0.00% | n/a | n/a | 59 | 0 ms | 0 ms | 1 ms |
| benign_header | benign | 0 | 0 | 0 | 40 | 0 | n/a | 0.00% | n/a | n/a | n/a | 40 | 0 ms | 0 ms | 0 ms |
| benign_cookie | benign | 0 | 0 | 0 | 30 | 0 | n/a | 0.00% | n/a | n/a | n/a | 30 | 0 ms | 0 ms | 0 ms |
| benign_path | benign | 0 | 0 | 0 | 1 | 0 | n/a | 0.00% | n/a | n/a | n/a | 1 | 0 ms | 0 ms | 0 ms |

## Latency

| population | n | p50 | p95 | p99 | sample |
|---|---:|---:|---:|---:|---|
| all conclusive | 600 | 0 ms | 0 ms | 1 ms | sufficient |

Percentiles use nearest rank. `n` is the number of conclusive exchanges; excluded ones are not timed into the result.

## Notes and limits

- TPR and FPR describe agreement with this corpus, on this target, in this window; they are not a claim of absolute efficacy.
- 429 is pacing, never a block (criterion 24): it is excluded and counted with the other inconclusive outcomes.
- A zero-denominator metric is null; no value is invented.
- Percentiles use nearest rank; p99 is marked insufficient below 100 samples and every summary below 20 samples.
- OWASP references are declarative labels, not severity scores: sqli=A03:2021-Injection, xss=A03:2021-Injection, path_traversal=A01:2021-Broken Access Control, command_injection=A03:2021-Injection, ssrf=A10:2021-Server-Side Request Forgery, ldap_injection=A03:2021-Injection, nosql_injection=A03:2021-Injection, xxe=A05:2021-Security Misconfiguration, crlf_injection=A03:2021-Injection, ssti=A03:2021-Injection.
