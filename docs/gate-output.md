# Salidas del gate de eficacia

`xammu gate` lee un bundle sellado, aplica una política declarada y escribe documentos que un
pipeline puede consumir. No envía tráfico, no modifica el bundle y no inventa campos: cada cifra de
las salidas es un campo de E-03 o de `findings.jsonl`, y cada control cita la línea del journal que
lo sostiene. Este documento describe el formato de esas salidas; el contrato de la fase está en
[`audit-handoff.md`](audit-handoff.md) §15.

## 1. Códigos de salida y archivos

| salida | significado | archivos |
| --- | --- | --- |
| `0` | todos los checks aplicables cumplen la política | según `--format` |
| `1` | un check no la cumple; es un resultado sobre el objetivo | según `--format` |
| `2` | el gate no pudo evaluar: bandera inválida, política ilegible, bundle que no verifica, E-03 que no re-deriva | ninguno |

| `--format` | archivo | contenido |
| --- | --- | --- |
| `json` | `gate.json` | documento `xammu.gate/v1`, fuente autoritativa |
| `yaml` | `gate.yaml` | la misma información indexada, parseable por `internal/yamlish` |
| `sarif` | `results.sarif` | SARIF 2.1.0 con un resultado por check fallido y por finding C-16 |
| `markdown` | `report.md` | informe de siete secciones |
| `annex` | `annex-es.md` o `annex-en.md` | anexo de eficacia en el idioma pedido |
| `all` | los seis documentos + `publication.json` | entrega sellada; exige `--out` y `--signing-key` |

`--format all` es la única forma de entregar un documento sellado. Sin `--out` no hay entrega; sin
`--signing-key` se rechaza antes de escribir nada, porque una entrega sin firma no es una entrega
sellada. La clave privada no se copia al directorio de salida ni al bundle.

## 2. `gate.json` (`xammu.gate/v1`)

Esquema publicado en `schemas/xammu-gate-v1.schema.json`. Dos evaluaciones del mismo bundle y la
misma política producen bytes idénticos: no hay campo de reloj en el documento. Las colecciones son
mapas indexados por id para que el orden sea estable y para que el YAML del proyecto pueda
representarlas.

| campo | contenido |
| --- | --- |
| `schema_version` | `xammu.gate/v1` |
| `tool_version` | la misma versión que firma el binario |
| `source.kind` | `effectiveness` o `profiling` |
| `source.run_id`, `source.bundle` | qué evidencia se evaluó y dónde está |
| `source.manifest_sha256`, `source.manifest_signer_key_id` | el manifiesto que el gate leyó |
| `source.artifacts` | cada artefacto inventariado y su sha256 |
| `policy` | la política normalizada y su sha256, embebida para que el veredicto se reproduzca sin el archivo |
| `verdict` | `pass` o `fail` |
| `checks` | un objeto por check con `id`, `applies`, `status`, `threshold`, `observed`, `reason`, `evidence` y `line` |
| `metrics` | E-03 completo: counts, rates, clases, latencias, brazos, comparación y fingerprint |
| `findings` | los C-16 sellados, indexados por referencia, con `observed`/`inferred`/`evidence missing` |
| `controls` | una fila de informe por check más los controles informativos (`info`) |
| `limits` | la lista explícita que el informe imprime en §6 |
| `not_applicable` | por qué un check no aplica |

Checks posibles: `evidence.manifest`, `evidence.rederive`, `effectiveness.tpr`,
`effectiveness.fpr`, `effectiveness.precision`, `effectiveness.excluded_ratio`,
`findings.priority`. Un check que no aplica lleva `applies: false`, `status: not_applicable` y una
razón; nunca se cuenta como pasado. Una métrica con denominador cero es `null`: el check falla con
`reason: "no denominator"` y `observed: "n/a"`, nunca con `0`.

`metrics.fingerprint` conserva las firmas observadas como evidencia (`signature`, `kind`,
`strength`, `detail`) y el apoyo categórico por vendor. Es una lectura categórica, no una
probabilidad ni una afirmación de producto. Si el vendor identificado es el fixture de referencia,
`limits` incluye la frase que separa la demostración de la eficacia de un WAF real.

## 3. `gate.yaml`

Es una representación **indexada**, no una copia literal del JSON: los arrays de E-03 se convierten
en mapas con la misma clave que el JSON usa para indexarlos. Conserva todos los campos; el JSON es
la fuente autoritativa y el YAML es lo que consumen GitLab, Azure y Jenkins sin escribir un parser
de JSON. El test vuelve a parsear el YAML con `internal/yamlish` y compara estructura y valores.

## 4. `results.sarif`

SARIF 2.1.0: `$schema` y `version` fijos, un run, `tool.driver.name = "XAMMU"` y la versión del
binario. `invocations[0].exitCode` publica el código real (0 o 1); `executionSuccessful` es `true`
porque el gate sí pudo evaluar — un 2 no produce SARIF.

| check fallido | regla SARIF | nivel |
| --- | --- | --- |
| `effectiveness.tpr` | `XAMMU-EFF-TPR` | `error` |
| `effectiveness.fpr` | `XAMMU-EFF-FPR` | `error` |
| `effectiveness.precision` | `XAMMU-EFF-PRECISION` | `error` |
| `effectiveness.excluded_ratio` | `XAMMU-EFF-EXCLUDED` | `error` |
| `findings.priority` | una regla `XAMMU-FINDING-<TIPO>` por finding que alcanza la prioridad | `high` → `error`, `medium` → `warning`, `low` → `note` |

Cada resultado lleva `ruleId`, `level`, `message` con el valor observado, el umbral y el artefacto de
evidencia, una `location` que apunta a un journal inventariado y una línea real (`effectiveness_metrics.jsonl`
o `findings.jsonl`), y `partialFingerprints` con un sha256 estable para que Code Scanning no duplique
el mismo problema entre corridas. Un run que pasa produce `results: []`: SARIF enumera problemas; el
JSON enumera todos los checks.

La forma se valida estructuralmente en test y en `scripts/gate-demo.sh`: versión, `$schema`, cada
`ruleId` declarado en `tool.driver.rules`, vocabulario de `level` y ubicación en un journal del
inventario. No se valida contra el JSON Schema completo de OASIS para no añadir una dependencia; la
ingesta en Code Scanning es la validación real y se documenta como tal.

## 5. `report.md`

Siete secciones, en orden: resumen ejecutivo (veredicto, checks fallidos, tasas con denominador,
latencias con `n`, fingerprint y la frase que separa medición de política); alcance y evidencia
(C-09, digest del corpus, brazos, run id, digests de los artefactos); métricas (matriz de confusión,
tasas, tabla por clase, latencias); controles con evidencia (expectativa/umbral, observado, evidencia
y estado, con `info` para los informativos); hallazgos C-16 sellados; límites explícitos; y
reproducción y sello. Los valores nulos se imprimen `n/a`. No hay puntuaciones, CVSS ni severidades
que la evidencia no tenga.

## 6. Anexo ES/EN

`annex-es.md` y `annex-en.md` renderizan el mismo documento en dos idiomas: mismas cifras, mismos
campos de evidencia y mismos estados, traducidos sólo los rótulos y la prosa. `--format all` escribe
ambos; `--format annex --lang es|en` escribe uno. Los valores citados de la evidencia no se traducen
ni se reescriben.

## 7. `publication.json` (`xammu.publication/v1`)

Esquema en `schemas/xammu-publication-v1.schema.json`. Es el sobre que convierte seis documentos
sueltos en una entrega:

| campo | contenido |
| --- | --- |
| `schema_version`, `tool_version`, `created_at` | identidad del sobre |
| `source` | `kind`, `run_id`, ruta relativa del bundle, `manifest_sha256`, `manifest_signer_key_id`, `manifest_signature_valid`, `manifest_signer_anchored` |
| `policy_sha256` | la política que produjo el veredicto |
| `verdict`, `exit_code` | la decisión que la entrega publica |
| `files` | cada documento entregado con `path`, `sha256` y `bytes` |
| `algorithm`, `signer_key_id`, `public_key_base64`, `signature_base64` | material de firma |
| `signing_rule` | la regla, dentro del documento |

La firma es Ed25519 sobre `sha256(canonical-json(publication sin signature_base64,
public_key_base64 ni signer_key_id))`. El sobre es la única pieza con hora de sellado.

**Ciclo resuelto.** El informe y el anexo no pueden contener el digest del sobre que los hashea. En
su lugar citan la regla de firma, la ruta `publication.json` y el comando `verify --publication`; el
sobre lista sus digests, y `verify` imprime el digest del sobre al comprobarlo.

## 8. Qué comprueba `verify --publication`

| check | qué prueba |
| --- | --- |
| `publication_schema`, `publication_tool_version`, `publication_algorithm` | que el sobre declara lo que este binario sabe leer |
| `publication_public_key` | que la clave pública decodifica y corresponde al id del firmante |
| `publication_signature` | Ed25519 sobre el material canónico |
| `publication_files` | que el sobre enumera archivos |
| `delivery_files_unchanged`, `delivery_files_all_listed` | que cada archivo listado conserva su sha256 y que no hay documentos extra |
| `publication_manifest_signed`, `publication_manifest_signature` | que el manifiesto de origen está firmado y el sobre lo refleja |
| `gate_document_readable`, `gate_document_matches_envelope` | que `gate.json` decodifica y coincide con lo que el sobre declara |
| `checks_reproduce_from_gate_json`, `verdict_reproduces_from_checks` | que el veredicto se re-deriva de los checks y de la política embebida; un veredicto re-firmado que sus checks no producen se rechaza |
| `source_bundle_verifies`, `source_manifest_sha256`, `source_identity` | que el bundle nombrado verifica, coincide con el digest y con la clave declarados |

`--trust-key` ancla la **identidad del sobre**: una clave distinta hace fallar
`signer_is_trusted`; sin clave se informa que la identidad no está anclada, igual que `verify` con
los bundles. El manifiesto de origen debe verificar y coincidir con el digest y la clave que el
sobre declara; su identidad se informa como anclada sólo cuando la misma clave lo firmó. La firma
prueba quién firmó la entrega, no que las lecturas sean correctas: eso lo sostienen los controles y
los comandos de reproducción del informe.

## 9. Límites

- El gate lee evidencia sellada; no sustituye a `verify --rederive`. Un bundle que no re-deriva es
  salida 2, no un veredicto.
- `«crítico»` no existe en C-16: la política usa `high|medium|low` y un archivo que escriba
  `critical` se rechaza explicándolo.
- El SARIF se valida estructuralmente, no contra el JSON Schema completo de OASIS.
- El YAML es una representación indexada; el JSON es la fuente.
- Los umbrales son del engagement: `policies/effectiveness-reference.yaml` es una referencia de
  demostración, no un mínimo universal.
- Las cifras de una corrida contra `examples/reference-waf` demuestran la tubería, no la eficacia de
  ningún producto; el informe lo declara en el resumen y en los límites.
- La custodia y rotación de la clave de firma son H-09 de la Fase 4.
