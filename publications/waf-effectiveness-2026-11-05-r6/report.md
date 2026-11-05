# XAMMU effectiveness gate report - run waf-effectiveness-2026-11-05-r6

## 1. Executive summary

- Verdict: **FAIL**
- Failed checks: effectiveness.tpr
- Policy: `sha256:8fdd3a47858e0d9b8f12d63f6ae09c2baf090578cd0be44eced054f847a82ea9` (xammu.policy/v1)
- TPR: 0.08333333333333333 (8.33%); FPR: 0.02666666666666667 (2.67%); Precision: 0.7575757575757576 (75.76%); F1: 0.15015015015015012 (15.02%); MCC: 0.12427976460351192 (12.43%)
- Latency: p50 0.00, p95 1.00, p99 1.00 ms over n=600 (n>=100, p99 stable)
- Fingerprint: xammu-lab-waf=high (n=33)

The run does not meet the thresholds configured for this corpus and this origin. The verdict is a policy decision over the sealed evidence, not a claim that the target is exploitable.

## 2. Scope and evidence

| Field | Value |
| --- | --- |
| Source kind | effectiveness |
| Run | waf-effectiveness-2026-11-05-r6 |
| Bundle | runs/waf-effectiveness-2026-11-05-r6 |
| Manifest sha256 | sha256:03adcedc1648487327c0334119e458a54ba30456119289c895dd99d266fddb0d |
| Manifest signer key id | edabfbcda5eb8f56 |
| Authorization | AUTH-EFFECTIVENESS-LOCAL-002 |
| Corpus digest | sha256:377882d1ccaea712fdee69f8ec96a46c7976a565658c32a3e8c4082dd06eeefd |
| Cases measured | 600 |
| Arms | baseline, tamper |

The artifacts below are the files the signed manifest covers; the gate read exactly these digests.

| Artifact | sha256 |
| --- | --- |
| effectiveness_cases.jsonl | sha256:f53d274458af13ca944da14a8c82d9d0f3511384eeff1ace19a79aa5795c7b1d |
| effectiveness_metrics.jsonl | sha256:db286d33a174a06ad52a9b87486737faedfec40c132e2ee1702d82a936cdd267 |
| effectiveness_outcomes.jsonl | sha256:9ff6f73afc830d0a34f85beaab39856c3e8cf3012609f933b905a9b032320c27 |

## 3. Metrics

### Confusion matrix

| TP | FN | FP | TN | Excluded | Cases |
| --- | --- | --- | --- | --- | --- |
| 25 | 275 | 8 | 292 | 0 | 600 |

Excluded exchanges are reported beside the matrix and never inside a denominator. A null rate means the denominator was zero.

### Rates

| Metric | Value | Denominator |
| --- | --- | --- |
| TPR | 0.08333333333333333 (8.33%) | 300 attacks: 25 caught (TP), 275 missed (FN) |
| FPR | 0.02666666666666667 (2.67%) | 300 benign: 8 blocked (FP), 292 allowed (TN) |
| Precision | 0.7575757575757576 (75.76%) | 33 blocks: 25 true (TP), 8 false (FP) |
| F1 | 0.15015015015015012 (15.02%) | harmonic mean of TPR and Precision |
| MCC | 0.12427976460351192 (12.43%) | all four cells of the matrix |

### By class

| Class | Kind | TP | FN | FP | TN | Excluded | TPR | FPR | Precision | OWASP |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| benign_cookie | benign | 0 | 0 | 0 | 30 | 0 | n/a | 0 (0.00%) | n/a | - |
| benign_form | benign | 0 | 0 | 0 | 50 | 0 | n/a | 0 (0.00%) | n/a | - |
| benign_header | benign | 0 | 0 | 0 | 40 | 0 | n/a | 0 (0.00%) | n/a | - |
| benign_json | benign | 0 | 0 | 0 | 60 | 0 | n/a | 0 (0.00%) | n/a | - |
| benign_path | benign | 0 | 0 | 0 | 1 | 0 | n/a | 0 (0.00%) | n/a | - |
| benign_query | benign | 0 | 0 | 3 | 56 | 0 | n/a | 0.05084745762711865 (5.08%) | 0 (0.00%) | - |
| benign_text | benign | 0 | 0 | 5 | 55 | 0 | n/a | 0.08333333333333333 (8.33%) | 0 (0.00%) | - |
| command_injection | attack | 1 | 29 | 0 | 0 | 0 | 0.03333333333333333 (3.33%) | n/a | 1 (100.00%) | A03:2021-Injection |
| crlf_injection | attack | 0 | 30 | 0 | 0 | 0 | 0 (0.00%) | n/a | n/a | A03:2021-Injection |
| ldap_injection | attack | 1 | 29 | 0 | 0 | 0 | 0.03333333333333333 (3.33%) | n/a | 1 (100.00%) | A03:2021-Injection |
| nosql_injection | attack | 7 | 23 | 0 | 0 | 0 | 0.23333333333333334 (23.33%) | n/a | 1 (100.00%) | A03:2021-Injection |
| path_traversal | attack | 1 | 29 | 0 | 0 | 0 | 0.03333333333333333 (3.33%) | n/a | 1 (100.00%) | A01:2021-Broken Access Control |
| sqli | attack | 8 | 22 | 0 | 0 | 0 | 0.26666666666666666 (26.67%) | n/a | 1 (100.00%) | A03:2021-Injection |
| ssrf | attack | 0 | 30 | 0 | 0 | 0 | 0 (0.00%) | n/a | n/a | A10:2021-Server-Side Request Forgery |
| ssti | attack | 0 | 30 | 0 | 0 | 0 | 0 (0.00%) | n/a | n/a | A03:2021-Injection |
| xss | attack | 2 | 28 | 0 | 0 | 0 | 0.06666666666666667 (6.67%) | n/a | 1 (100.00%) | A03:2021-Injection |
| xxe | attack | 5 | 25 | 0 | 0 | 0 | 0.16666666666666666 (16.67%) | n/a | 1 (100.00%) | A05:2021-Security Misconfiguration |

### Latency

| Population | n | p50 ms | p95 ms | p99 ms | Sufficiency |
| --- | --- | --- | --- | --- | --- |
| all conclusive exchanges | 600 | 0.00 | 1.00 | 1.00 | n>=100, p99 stable |

### Arms

| Arm | Tamper stack | Cases | TPR | FPR | Precision | n |
| --- | --- | --- | --- | --- | --- | --- |
| baseline | none | 600 | 0.08333333333333333 (8.33%) | 0.02666666666666667 (2.67%) | 0.7575757575757576 (75.76%) | 600 |
| tamper | url_encode_double+sql_comment | 600 | 0 (0.00%) | 0 (0.00%) | n/a | 600 |

### Baseline vs tamper

| Class | Baseline TPR | Baseline n | Tamper TPR | Tamper n | Delta | Note |
| --- | --- | --- | --- | --- | --- | --- |
| all attack classes | 8.33% | 300 | 0.00% | 300 | -8.33 pp | - |
| command_injection | 3.33% | 30 | 0.00% | 30 | -3.33 pp | - |
| crlf_injection | 0.00% | 30 | 0.00% | 30 | 0.00 pp | - |
| ldap_injection | 3.33% | 30 | 0.00% | 30 | -3.33 pp | - |
| nosql_injection | 23.33% | 30 | 0.00% | 30 | -23.33 pp | - |
| path_traversal | 3.33% | 30 | 0.00% | 30 | -3.33 pp | - |
| sqli | 26.67% | 30 | 0.00% | 30 | -26.67 pp | - |
| ssrf | 0.00% | 30 | 0.00% | 30 | 0.00 pp | - |
| ssti | 0.00% | 30 | 0.00% | 30 | 0.00 pp | - |
| xss | 6.67% | 30 | 0.00% | 30 | -6.67 pp | - |
| xxe | 16.67% | 30 | 0.00% | 30 | -16.67 pp | - |

## 4. Controls with evidence

| Control | Expectation | Observed | Evidence | Status |
| --- | --- | --- | --- | --- |
| comparison.base_vs_tamper | informational: tamper minus baseline, no threshold | baseline TPR 8.33% (n=300); tamper TPR 0.00% (n=300); delta -8.33 pp | effectiveness_metrics.jsonl (E-03 comparison) | info |
| effectiveness.excluded_ratio | <= 0 | 0/600 = 0 (0.00%) | effectiveness_metrics.jsonl | pass |
| effectiveness.fpr | <= 0.05 | 0.02666666666666667 (2.67%) | effectiveness_metrics.jsonl | pass |
| effectiveness.precision | >= 0.7 | 0.7575757575757576 (75.76%) | effectiveness_metrics.jsonl | pass |
| effectiveness.tpr | >= 0.8 | 0.08333333333333333 (8.33%) | effectiveness_metrics.jsonl | fail |
| evidence.manifest | manifest, inventory, merkle root and hash chains verify; signer identity anchored by a trusted key | n/a | manifest.json | pass |
| evidence.rederive | E-03 recomputes from E-01/E-02 and matches the journaled record and the published metrics document | n/a | effectiveness_cases.jsonl, effectiveness_outcomes.jsonl, effectiveness_metrics.jsonl | pass |
| fingerprint.attribution | informational: categorical support, not a probability | xammu-lab-waf=high | effectiveness_metrics.jsonl (E-03 fingerprint) | info |

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

## 7. Reproduction and seal

Verify the sealed evidence:

```
xammu verify --store runs/waf-effectiveness-2026-11-05-r6
```

Verify this delivery and its Ed25519 envelope:

```
xammu verify --publication publications/waf-effectiveness-2026-11-05-r6 --trust-key FILE
```

The envelope (`publication.json`, `xammu.publication/v1`) is signed by ed25519 over sha256(canonical-json(publication minus signature_base64, public_key_base64 and signer_key_id)) over sha256(canonical-json(publication minus the signature fields)). It lists every delivered file with its sha256, including this document. A document cannot contain the digest of the envelope that hashes it, so the envelope digest is not printed here: `verify --publication` recomputes it, prints it, and refuses any file that no longer matches.

