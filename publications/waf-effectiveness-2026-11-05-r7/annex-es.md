# Anexo técnico - Eficacia del borde defensivo

Documento generado por XAMMU a partir de un bundle de evidencia sellado. Copia las cifras y los campos de evidencia del documento de gate; no los recalcula.

Run: waf-effectiveness-2026-11-05-r7. Bundle: runs/waf-effectiveness-2026-11-05-r7


## 1. Datos del engagement

| Campo | Valor |
| --- | --- |
| Cliente | No indicado |
| Engagement | No indicado |
| Preparado por | No indicado |
| Run | waf-effectiveness-2026-11-05-r7 |
| Tipo de fuente | effectiveness |
| Bundle | runs/waf-effectiveness-2026-11-05-r7 |
| Digest del manifiesto | sha256:07e6ccab529c0992a9a3bed87bed62348bd85b1858fca90cec41a46a6fee9497 |
| Clave firmante del manifiesto | edabfbcda5eb8f56 |
| Política (sha256) | sha256:8fdd3a47858e0d9b8f12d63f6ae09c2baf090578cd0be44eced054f847a82ea9 |
| Esquema del documento | xammu.gate/v1 |
| Herramienta | xammu-1.0.0 |
| Autorización | AUTH-EFFECTIVENESS-LOCAL-002 |
| Digest del corpus | sha256:377882d1ccaea712fdee69f8ec96a46c7976a565658c32a3e8c4082dd06eeefd |
| Casos medidos | 600 |


## 2. Veredicto

- Veredicto: **cumple** (`pass`)
- El veredicto es una decisión de política sobre los umbrales configurados para este corpus y este origen; no es una afirmación de seguridad general.


## 3. Métricas


### Matriz de confusión

| TP | FN | FP | TN | Excluidas | Casos |
| --- | --- | --- | --- | --- | --- |
| 300 | 0 | 0 | 300 | 0 | 600 |

Las pruebas excluidas se informan al lado de la matriz y nunca dentro de un denominador. Una tasa nula significa que el denominador era cero.


### Tasas

| Métrica | Valor |
| --- | --- |
| TPR | 1 (100.00%) |
| FPR | 0 (0.00%) |
| Precisión | 1 (100.00%) |
| F1 | 1 (100.00%) |
| MCC | 1 (100.00%) |


### Por clase

| Clase | TP | FN | FP | TN | TPR | FPR | Precisión | OWASP |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| benign_cookie | 0 | 0 | 0 | 30 | n/a | 0 (0.00%) | n/a |  |
| benign_form | 0 | 0 | 0 | 50 | n/a | 0 (0.00%) | n/a |  |
| benign_header | 0 | 0 | 0 | 40 | n/a | 0 (0.00%) | n/a |  |
| benign_json | 0 | 0 | 0 | 60 | n/a | 0 (0.00%) | n/a |  |
| benign_path | 0 | 0 | 0 | 1 | n/a | 0 (0.00%) | n/a |  |
| benign_query | 0 | 0 | 0 | 59 | n/a | 0 (0.00%) | n/a |  |
| benign_text | 0 | 0 | 0 | 60 | n/a | 0 (0.00%) | n/a |  |
| inyección de comandos | 30 | 0 | 0 | 0 | 1 (100.00%) | n/a | 1 (100.00%) | A03:2021-Injection |
| inyección CRLF | 30 | 0 | 0 | 0 | 1 (100.00%) | n/a | 1 (100.00%) | A03:2021-Injection |
| inyección LDAP | 30 | 0 | 0 | 0 | 1 (100.00%) | n/a | 1 (100.00%) | A03:2021-Injection |
| inyección NoSQL | 30 | 0 | 0 | 0 | 1 (100.00%) | n/a | 1 (100.00%) | A03:2021-Injection |
| travesía de rutas | 30 | 0 | 0 | 0 | 1 (100.00%) | n/a | 1 (100.00%) | A01:2021-Broken Access Control |
| inyección SQL | 30 | 0 | 0 | 0 | 1 (100.00%) | n/a | 1 (100.00%) | A03:2021-Injection |
| SSRF | 30 | 0 | 0 | 0 | 1 (100.00%) | n/a | 1 (100.00%) | A10:2021-Server-Side Request Forgery |
| inyección de plantillas (SSTI) | 30 | 0 | 0 | 0 | 1 (100.00%) | n/a | 1 (100.00%) | A03:2021-Injection |
| XSS | 30 | 0 | 0 | 0 | 1 (100.00%) | n/a | 1 (100.00%) | A03:2021-Injection |
| XXE | 30 | 0 | 0 | 0 | 1 (100.00%) | n/a | 1 (100.00%) | A05:2021-Security Misconfiguration |


### Latencias

| Población | n | p50 ms | p95 ms | p99 ms | Suficiencia |
| --- | --- | --- | --- | --- | --- |
| intercambios concluyentes | 600 | 0.00 | 0.00 | 1.00 | n>=100, p99 estable |


### Brazos

| Brazo | Pila de tamper | Casos | TPR | FPR | Precisión | n |
| --- | --- | --- | --- | --- | --- | --- |
| baseline | ninguno | 600 | 1 (100.00%) | 0 (0.00%) | 1 (100.00%) | 600 |
| tamper | url_encode_double+case_switch | 600 | 0.95 (95.00%) | 0 (0.00%) | 1 (100.00%) | 599 |


### Base frente a tamper

| Clase | TPR base | n base | TPR tamper | n tamper | Delta | Nota |
| --- | --- | --- | --- | --- | --- | --- |
| all attack classes | 100.00% | 300 | 95.00% | 300 | -5.00 pp |  |
| inyección de comandos | 100.00% | 30 | 93.33% | 30 | -6.67 pp |  |
| inyección CRLF | 100.00% | 30 | 80.00% | 30 | -20.00 pp |  |
| inyección LDAP | 100.00% | 30 | 96.67% | 30 | -3.33 pp |  |
| inyección NoSQL | 100.00% | 30 | 96.67% | 30 | -3.33 pp |  |
| travesía de rutas | 100.00% | 30 | 96.67% | 30 | -3.33 pp |  |
| inyección SQL | 100.00% | 30 | 96.67% | 30 | -3.33 pp |  |
| SSRF | 100.00% | 30 | 100.00% | 30 | 0.00 pp |  |
| inyección de plantillas (SSTI) | 100.00% | 30 | 96.67% | 30 | -3.33 pp |  |
| XSS | 100.00% | 30 | 96.67% | 30 | -3.33 pp |  |
| XXE | 100.00% | 30 | 96.67% | 30 | -3.33 pp |  |


## 4. Controles con evidencia

| Control | Expectativa | Observado | Evidencia | Estado |
| --- | --- | --- | --- | --- |
| comparison.base_vs_tamper | informational: tamper minus baseline, no threshold | baseline TPR 100.00% (n=300); tamper TPR 95.00% (n=300); delta -5.00 pp | effectiveness_metrics.jsonl (E-03 comparison) | informativo |
| effectiveness.excluded_ratio | <= 0 | 0/600 = 0 (0.00%) | effectiveness_metrics.jsonl | cumple |
| effectiveness.fpr | <= 0.05 | 0 (0.00%) | effectiveness_metrics.jsonl | cumple |
| effectiveness.precision | >= 0.7 | 1 (100.00%) | effectiveness_metrics.jsonl | cumple |
| effectiveness.tpr | >= 0.8 | 1 (100.00%) | effectiveness_metrics.jsonl | cumple |
| evidence.manifest | manifest, inventory, merkle root and hash chains verify; signer identity anchored by a trusted key | n/a | manifest.json | cumple |
| evidence.rederive | E-03 recomputes from E-01/E-02 and matches the journaled record and the published metrics document | n/a | effectiveness_cases.jsonl, effectiveness_outcomes.jsonl, effectiveness_metrics.jsonl | cumple |
| fingerprint.attribution | informational: categorical support, not a probability | xammu-reference-waf=high | effectiveness_metrics.jsonl (E-03 fingerprint) | informativo |


## 5. Hallazgos C-16 sellados

Este bundle no publica hallazgos C-16.


## 6. Límites explícitos

- The gate reads sealed evidence; it sends no traffic and does not modify the bundle.
- Rates describe agreement with this corpus, on this target, in this window; they are not a claim of absolute efficacy.
- The verdict is a policy decision over declared thresholds; it does not state that the WAF is secure.
- A zero-denominator metric is null: the check fails with reason "no denominator" and the null is never read as zero or one.
- C-16 priorities are high, medium and low; XAMMU does not add a critical level the evidence does not have.
- The SARIF document is validated structurally against 2.1.0, not against the complete OASIS JSON Schema.
- E-03 is recomputed from the E-01 case list and the E-02 outcome journal before any threshold is evaluated; a disagreement is exit 2, not a verdict.
- Fingerprint support is a categorical reading of observed signatures, not a probability and not a product claim.
- The target identified as the repository's reference fixture, a WAF calibrated against this inert corpus. Its rates show that the pipeline measures; they are not the efficacy of any real product.


## 7. Reproducción y sello

Verificar la evidencia sellada:

```
xammu verify --store runs/waf-effectiveness-2026-11-05-r7
```

Verificar esta entrega y su sobre Ed25519:

```
xammu verify --publication publications/waf-effectiveness-2026-11-05-r7 --trust-key FILE
```

El sobre `publication.json` (xammu.publication/v1) firma con Ed25519 sobre sha256(canonical-json(publication sin los campos de firma)). Lista cada archivo entregado con su sha256, incluido este anexo. Un documento no puede contener el digest del sobre que lo hashea: `verify --publication` lo recomputa, lo imprime y rechaza cualquier archivo que ya no coincida.

