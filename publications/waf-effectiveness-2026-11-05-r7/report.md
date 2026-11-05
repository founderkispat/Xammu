# XAMMU effectiveness gate report - run waf-effectiveness-2026-11-05-r7

## 1. Executive summary

- Verdict: **PASS**
- Failed checks: none
- Policy: `sha256:8fdd3a47858e0d9b8f12d63f6ae09c2baf090578cd0be44eced054f847a82ea9` (xammu.policy/v1)
- TPR: 1 (100.00%); FPR: 0 (0.00%); Precision: 1 (100.00%); F1: 1 (100.00%); MCC: 1 (100.00%)
- Latency: p50 0.00, p95 0.00, p99 1.00 ms over n=600 (n>=100, p99 stable)
- Fingerprint: xammu-reference-waf=high (n=600)
- Target: the repository's reference fixture, calibrated against this corpus; these figures demonstrate the pipeline, not a real product's efficacy.

The run meets the thresholds configured for this corpus and this origin. That is a policy decision over 6 applicable check(s), not a general security assertion.

## 2. Scope and evidence

| Field | Value |
| --- | --- |
| Source kind | effectiveness |
| Run | waf-effectiveness-2026-11-05-r7 |
| Bundle | runs/waf-effectiveness-2026-11-05-r7 |
| Manifest sha256 | sha256:07e6ccab529c0992a9a3bed87bed62348bd85b1858fca90cec41a46a6fee9497 |
| Manifest signer key id | edabfbcda5eb8f56 |
| Authorization | AUTH-EFFECTIVENESS-LOCAL-002 |
| Corpus digest | sha256:377882d1ccaea712fdee69f8ec96a46c7976a565658c32a3e8c4082dd06eeefd |
| Cases measured | 600 |
| Arms | baseline, tamper |

The artifacts below are the files the signed manifest covers; the gate read exactly these digests.

| Artifact | sha256 |
| --- | --- |
| effectiveness_cases.jsonl | sha256:8dec4e25fc2f577bbee6a469b8f69c6982ba639efabc0c794105afdb01194431 |
| effectiveness_metrics.jsonl | sha256:a12998a5415e585bd261f1c799481ddfe363b3f6c4d614927e89533412a73995 |
| effectiveness_outcomes.jsonl | sha256:d846464378bef72eb8b542f489d5de15d4a55291505f01368215cc2aa131624a |

## 3. Metrics

### Confusion matrix

| TP | FN | FP | TN | Excluded | Cases |
| --- | --- | --- | --- | --- | --- |
| 300 | 0 | 0 | 300 | 0 | 600 |

Excluded exchanges are reported beside the matrix and never inside a denominator. A null rate means the denominator was zero.

### Rates

| Metric | Value | Denominator |
| --- | --- | --- |
| TPR | 1 (100.00%) | 300 attacks: 300 caught (TP), 0 missed (FN) |
| FPR | 0 (0.00%) | 300 benign: 0 blocked (FP), 300 allowed (TN) |
| Precision | 1 (100.00%) | 300 blocks: 300 true (TP), 0 false (FP) |
| F1 | 1 (100.00%) | harmonic mean of TPR and Precision |
| MCC | 1 (100.00%) | all four cells of the matrix |

### By class

| Class | Kind | TP | FN | FP | TN | Excluded | TPR | FPR | Precision | OWASP |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| benign_cookie | benign | 0 | 0 | 0 | 30 | 0 | n/a | 0 (0.00%) | n/a | - |
| benign_form | benign | 0 | 0 | 0 | 50 | 0 | n/a | 0 (0.00%) | n/a | - |
| benign_header | benign | 0 | 0 | 0 | 40 | 0 | n/a | 0 (0.00%) | n/a | - |
| benign_json | benign | 0 | 0 | 0 | 60 | 0 | n/a | 0 (0.00%) | n/a | - |
| benign_path | benign | 0 | 0 | 0 | 1 | 0 | n/a | 0 (0.00%) | n/a | - |
| benign_query | benign | 0 | 0 | 0 | 59 | 0 | n/a | 0 (0.00%) | n/a | - |
| benign_text | benign | 0 | 0 | 0 | 60 | 0 | n/a | 0 (0.00%) | n/a | - |
| command_injection | attack | 30 | 0 | 0 | 0 | 0 | 1 (100.00%) | n/a | 1 (100.00%) | A03:2021-Injection |
| crlf_injection | attack | 30 | 0 | 0 | 0 | 0 | 1 (100.00%) | n/a | 1 (100.00%) | A03:2021-Injection |
| ldap_injection | attack | 30 | 0 | 0 | 0 | 0 | 1 (100.00%) | n/a | 1 (100.00%) | A03:2021-Injection |
| nosql_injection | attack | 30 | 0 | 0 | 0 | 0 | 1 (100.00%) | n/a | 1 (100.00%) | A03:2021-Injection |
| path_traversal | attack | 30 | 0 | 0 | 0 | 0 | 1 (100.00%) | n/a | 1 (100.00%) | A01:2021-Broken Access Control |
| sqli | attack | 30 | 0 | 0 | 0 | 0 | 1 (100.00%) | n/a | 1 (100.00%) | A03:2021-Injection |
| ssrf | attack | 30 | 0 | 0 | 0 | 0 | 1 (100.00%) | n/a | 1 (100.00%) | A10:2021-Server-Side Request Forgery |
| ssti | attack | 30 | 0 | 0 | 0 | 0 | 1 (100.00%) | n/a | 1 (100.00%) | A03:2021-Injection |
| xss | attack | 30 | 0 | 0 | 0 | 0 | 1 (100.00%) | n/a | 1 (100.00%) | A03:2021-Injection |
| xxe | attack | 30 | 0 | 0 | 0 | 0 | 1 (100.00%) | n/a | 1 (100.00%) | A05:2021-Security Misconfiguration |

### Latency

| Population | n | p50 ms | p95 ms | p99 ms | Sufficiency |
| --- | --- | --- | --- | --- | --- |
| all conclusive exchanges | 600 | 0.00 | 0.00 | 1.00 | n>=100, p99 stable |

### Arms

| Arm | Tamper stack | Cases | TPR | FPR | Precision | n |
| --- | --- | --- | --- | --- | --- | --- |
| baseline | none | 600 | 1 (100.00%) | 0 (0.00%) | 1 (100.00%) | 600 |
| tamper | url_encode_double+case_switch | 600 | 0.95 (95.00%) | 0 (0.00%) | 1 (100.00%) | 599 |

### Baseline vs tamper

| Class | Baseline TPR | Baseline n | Tamper TPR | Tamper n | Delta | Note |
| --- | --- | --- | --- | --- | --- | --- |
| all attack classes | 100.00% | 300 | 95.00% | 300 | -5.00 pp | - |
| command_injection | 100.00% | 30 | 93.33% | 30 | -6.67 pp | - |
| crlf_injection | 100.00% | 30 | 80.00% | 30 | -20.00 pp | - |
| ldap_injection | 100.00% | 30 | 96.67% | 30 | -3.33 pp | - |
| nosql_injection | 100.00% | 30 | 96.67% | 30 | -3.33 pp | - |
| path_traversal | 100.00% | 30 | 96.67% | 30 | -3.33 pp | - |
| sqli | 100.00% | 30 | 96.67% | 30 | -3.33 pp | - |
| ssrf | 100.00% | 30 | 100.00% | 30 | 0.00 pp | - |
| ssti | 100.00% | 30 | 96.67% | 30 | -3.33 pp | - |
| xss | 100.00% | 30 | 96.67% | 30 | -3.33 pp | - |
| xxe | 100.00% | 30 | 96.67% | 30 | -3.33 pp | - |

## 4. Controls with evidence

| Control | Expectation | Observed | Evidence | Status |
| --- | --- | --- | --- | --- |
| comparison.base_vs_tamper | informational: tamper minus baseline, no threshold | baseline TPR 100.00% (n=300); tamper TPR 95.00% (n=300); delta -5.00 pp | effectiveness_metrics.jsonl (E-03 comparison) | info |
| effectiveness.excluded_ratio | <= 0 | 0/600 = 0 (0.00%) | effectiveness_metrics.jsonl | pass |
| effectiveness.fpr | <= 0.05 | 0 (0.00%) | effectiveness_metrics.jsonl | pass |
| effectiveness.precision | >= 0.7 | 1 (100.00%) | effectiveness_metrics.jsonl | pass |
| effectiveness.tpr | >= 0.8 | 1 (100.00%) | effectiveness_metrics.jsonl | pass |
| evidence.manifest | manifest, inventory, merkle root and hash chains verify; signer identity anchored by a trusted key | n/a | manifest.json | pass |
| evidence.rederive | E-03 recomputes from E-01/E-02 and matches the journaled record and the published metrics document | n/a | effectiveness_cases.jsonl, effectiveness_outcomes.jsonl, effectiveness_metrics.jsonl | pass |
| fingerprint.attribution | informational: categorical support, not a probability | xammu-reference-waf=high | effectiveness_metrics.jsonl (E-03 fingerprint) | info |

## 5. Sealed C-16 findings

This bundle publishes no C-16 finding.

## 6. Explicit limits

- The gate reads sealed evidence; it sends no traffic and does not modify the bundle.
- Rates describe agreement with this corpus, on this target, in this window; they are not a claim of absolute efficacy.
- The verdict is a policy decision over declared thresholds; it does not state that the WAF is secure.
- A zero-denominator metric is null: the check fails with reason "no denominator" and the null is never read as zero or one.
- C-16 priorities are high, medium and low; XAMMU does not add a critical level the evidence does not have.
- The SARIF document is validated structurally against 2.1.0, not against the complete OASIS JSON Schema.
- E-03 is recomputed from the E-01 case list and the E-02 outcome journal before any threshold is evaluated; a disagreement is exit 2, not a verdict.
- Fingerprint support is a categorical reading of observed signatures, not a probability and not a product claim.
- The target identified as the repository's reference fixture, a WAF calibrated against this inert corpus. Its rates show that the pipeline measures; they are not the efficacy of any real product.

## 7. Reproduction and seal

Verify the sealed evidence:

```
xammu verify --store runs/waf-effectiveness-2026-11-05-r7
```

Verify this delivery and its Ed25519 envelope:

```
xammu verify --publication publications/waf-effectiveness-2026-11-05-r7 --trust-key FILE
```

The envelope (`publication.json`, `xammu.publication/v1`) is signed by ed25519 over sha256(canonical-json(publication minus signature_base64, public_key_base64 and signer_key_id)) over sha256(canonical-json(publication minus the signature fields)). It lists every delivered file with its sha256, including this document. A document cannot contain the digest of the envelope that hashes it, so the envelope digest is not printed here: `verify --publication` recomputes it, prints it, and refuses any file that no longer matches.

