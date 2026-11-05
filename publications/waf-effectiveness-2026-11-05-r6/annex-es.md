# Anexo técnico - Eficacia del borde defensivo

Documento generado por XAMMU a partir de un bundle de evidencia sellado. Copia las cifras y los campos de evidencia del documento de gate; no los recalcula.

Run: waf-effectiveness-2026-11-05-r6. Bundle: runs/waf-effectiveness-2026-11-05-r6


## 1. Datos del engagement

| Campo | Valor |
| --- | --- |
| Cliente | No indicado |
| Engagement | No indicado |
| Preparado por | No indicado |
| Run | waf-effectiveness-2026-11-05-r6 |
| Tipo de fuente | effectiveness |
| Bundle | runs/waf-effectiveness-2026-11-05-r6 |
| Digest del manifiesto | sha256:03adcedc1648487327c0334119e458a54ba30456119289c895dd99d266fddb0d |
| Clave firmante del manifiesto | edabfbcda5eb8f56 |
| Política (sha256) | sha256:8fdd3a47858e0d9b8f12d63f6ae09c2baf090578cd0be44eced054f847a82ea9 |
| Esquema del documento | xammu.gate/v1 |
| Herramienta | xammu-1.0.0 |
| Autorización | AUTH-EFFECTIVENESS-LOCAL-002 |
| Digest del corpus | sha256:377882d1ccaea712fdee69f8ec96a46c7976a565658c32a3e8c4082dd06eeefd |
| Casos medidos | 600 |


## 2. Veredicto

- Veredicto: **no cumple** (`fail`)
- El veredicto es una decisión de política sobre los umbrales configurados para este corpus y este origen; no es una afirmación de seguridad general.


## 3. Métricas


### Matriz de confusión

| TP | FN | FP | TN | Excluidas | Casos |
| --- | --- | --- | --- | --- | --- |
| 25 | 275 | 8 | 292 | 0 | 600 |

Las pruebas excluidas se informan al lado de la matriz y nunca dentro de un denominador. Una tasa nula significa que el denominador era cero.


### Tasas

| Métrica | Valor |
| --- | --- |
| TPR | 0.08333333333333333 (8.33%) |
| FPR | 0.02666666666666667 (2.67%) |
| Precisión | 0.7575757575757576 (75.76%) |
| F1 | 0.15015015015015012 (15.02%) |
| MCC | 0.12427976460351192 (12.43%) |


### Por clase

| Clase | TP | FN | FP | TN | TPR | FPR | Precisión | OWASP |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| benign_cookie | 0 | 0 | 0 | 30 | n/a | 0 (0.00%) | n/a |  |
| benign_form | 0 | 0 | 0 | 50 | n/a | 0 (0.00%) | n/a |  |
| benign_header | 0 | 0 | 0 | 40 | n/a | 0 (0.00%) | n/a |  |
| benign_json | 0 | 0 | 0 | 60 | n/a | 0 (0.00%) | n/a |  |
| benign_path | 0 | 0 | 0 | 1 | n/a | 0 (0.00%) | n/a |  |
| benign_query | 0 | 0 | 3 | 56 | n/a | 0.05084745762711865 (5.08%) | 0 (0.00%) |  |
| benign_text | 0 | 0 | 5 | 55 | n/a | 0.08333333333333333 (8.33%) | 0 (0.00%) |  |
| inyección de comandos | 1 | 29 | 0 | 0 | 0.03333333333333333 (3.33%) | n/a | 1 (100.00%) | A03:2021-Injection |
| inyección CRLF | 0 | 30 | 0 | 0 | 0 (0.00%) | n/a | n/a | A03:2021-Injection |
| inyección LDAP | 1 | 29 | 0 | 0 | 0.03333333333333333 (3.33%) | n/a | 1 (100.00%) | A03:2021-Injection |
| inyección NoSQL | 7 | 23 | 0 | 0 | 0.23333333333333334 (23.33%) | n/a | 1 (100.00%) | A03:2021-Injection |
| travesía de rutas | 1 | 29 | 0 | 0 | 0.03333333333333333 (3.33%) | n/a | 1 (100.00%) | A01:2021-Broken Access Control |
| inyección SQL | 8 | 22 | 0 | 0 | 0.26666666666666666 (26.67%) | n/a | 1 (100.00%) | A03:2021-Injection |
| SSRF | 0 | 30 | 0 | 0 | 0 (0.00%) | n/a | n/a | A10:2021-Server-Side Request Forgery |
| inyección de plantillas (SSTI) | 0 | 30 | 0 | 0 | 0 (0.00%) | n/a | n/a | A03:2021-Injection |
| XSS | 2 | 28 | 0 | 0 | 0.06666666666666667 (6.67%) | n/a | 1 (100.00%) | A03:2021-Injection |
| XXE | 5 | 25 | 0 | 0 | 0.16666666666666666 (16.67%) | n/a | 1 (100.00%) | A05:2021-Security Misconfiguration |


### Latencias

| Población | n | p50 ms | p95 ms | p99 ms | Suficiencia |
| --- | --- | --- | --- | --- | --- |
| intercambios concluyentes | 600 | 0.00 | 1.00 | 1.00 | n>=100, p99 estable |


### Brazos

| Brazo | Pila de tamper | Casos | TPR | FPR | Precisión | n |
| --- | --- | --- | --- | --- | --- | --- |
| baseline | ninguno | 600 | 0.08333333333333333 (8.33%) | 0.02666666666666667 (2.67%) | 0.7575757575757576 (75.76%) | 600 |
| tamper | url_encode_double+sql_comment | 600 | 0 (0.00%) | 0 (0.00%) | n/a | 600 |


### Base frente a tamper

| Clase | TPR base | n base | TPR tamper | n tamper | Delta | Nota |
| --- | --- | --- | --- | --- | --- | --- |
| all attack classes | 8.33% | 300 | 0.00% | 300 | -8.33 pp |  |
| inyección de comandos | 3.33% | 30 | 0.00% | 30 | -3.33 pp |  |
| inyección CRLF | 0.00% | 30 | 0.00% | 30 | 0.00 pp |  |
| inyección LDAP | 3.33% | 30 | 0.00% | 30 | -3.33 pp |  |
| inyección NoSQL | 23.33% | 30 | 0.00% | 30 | -23.33 pp |  |
| travesía de rutas | 3.33% | 30 | 0.00% | 30 | -3.33 pp |  |
| inyección SQL | 26.67% | 30 | 0.00% | 30 | -26.67 pp |  |
| SSRF | 0.00% | 30 | 0.00% | 30 | 0.00 pp |  |
| inyección de plantillas (SSTI) | 0.00% | 30 | 0.00% | 30 | 0.00 pp |  |
| XSS | 6.67% | 30 | 0.00% | 30 | -6.67 pp |  |
| XXE | 16.67% | 30 | 0.00% | 30 | -16.67 pp |  |


## 4. Controles con evidencia

| Control | Expectativa | Observado | Evidencia | Estado |
| --- | --- | --- | --- | --- |
| comparison.base_vs_tamper | informational: tamper minus baseline, no threshold | baseline TPR 8.33% (n=300); tamper TPR 0.00% (n=300); delta -8.33 pp | effectiveness_metrics.jsonl (E-03 comparison) | informativo |
| effectiveness.excluded_ratio | <= 0 | 0/600 = 0 (0.00%) | effectiveness_metrics.jsonl | cumple |
| effectiveness.fpr | <= 0.05 | 0.02666666666666667 (2.67%) | effectiveness_metrics.jsonl | cumple |
| effectiveness.precision | >= 0.7 | 0.7575757575757576 (75.76%) | effectiveness_metrics.jsonl | cumple |
| effectiveness.tpr | >= 0.8 | 0.08333333333333333 (8.33%) | effectiveness_metrics.jsonl | falla |
| evidence.manifest | manifest, inventory, merkle root and hash chains verify; signer identity anchored by a trusted key | n/a | manifest.json | cumple |
| evidence.rederive | E-03 recomputes from E-01/E-02 and matches the journaled record and the published metrics document | n/a | effectiveness_cases.jsonl, effectiveness_outcomes.jsonl, effectiveness_metrics.jsonl | cumple |
| fingerprint.attribution | informational: categorical support, not a probability | xammu-lab-waf=high | effectiveness_metrics.jsonl (E-03 fingerprint) | informativo |


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


## 7. Reproducción y sello

Verificar la evidencia sellada:

```
xammu verify --store runs/waf-effectiveness-2026-11-05-r6
```

Verificar esta entrega y su sobre Ed25519:

```
xammu verify --publication publications/waf-effectiveness-2026-11-05-r6 --trust-key FILE
```

El sobre `publication.json` (xammu.publication/v1) firma con Ed25519 sobre sha256(canonical-json(publication sin los campos de firma)). Lista cada archivo entregado con su sha256, incluido este anexo. Un documento no puede contener el digest del sobre que lo hashea: `verify --publication` lo recomputa, lo imprime y rechaza cualquier archivo que ya no coincida.

