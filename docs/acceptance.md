# Matriz de aceptación — XAMMU v1.0.0

Este documento responde a una sola pregunta: **¿cuáles de los 29 criterios de la sección 8 del
handoff están verificados, con qué prueba, y cuáles no se reclaman?** No sustituye a la prueba:
cada fila nombra el test o el artefacto que la sostiene, y el comando para repetirla está en §4.

Estado global a 2026-11-05: **23 criterios verificados por test, 3 verificados con vocabulario o
comando distinto al del handoff, 1 verificado por revisión documental y 2 que este repositorio no
puede cerrar por sí solo** (CI limpio y prueba con ingeniero externo). Los dos últimos están
declarados como brechas en §9, no contados como cumplidos. La suite local: 346 funciones de prueba
en 19 paquetes, sin fallos.

---

## 1. Cómo leer los estados

| estado | significado |
| --- | --- |
| ✅ | hay un test automatizado que falla si la propiedad se rompe |
| ◐ | la propiedad está verificada, pero el nombre o la forma del comando difiere del handoff; la equivalencia está en §3 |
| ○ | la propiedad es documental y se verificó leyendo los artefactos citados; automatizarla no probaría más |
| ⚠ | **no se reclama**: requiere un CI limpio o una persona externa, y este repositorio no puede aportarlos |

Un criterio ⚠ no es un criterio fallido; es un criterio cuya evidencia no existe todavía. La regla
del handoff —«un criterio fallido bloquea la entrega»— se aplica a los 27 primeros; los dos ⚠ se
declaran en cada entrega hasta que se cierren.

---

## 2. Los 29 criterios

### 2.1 Funcionalidad end-to-end

| # | criterio | prueba / evidencia | estado |
| --- | --- | --- | --- |
| 1 | `xammu profile` ejecuta contra el laboratorio y produce un `run_profile` `COMPLETED` | `cmd/xammu/run_test.go: TestEndToEndRunSealsSignsAndPublishesCommandsThatWork`; el bundle `runs/demo-lab` es un run completado contra el WAF del fixture (23 de 48 peticiones) y `runs/demo-origin` contra el origen (14 de 48) | ◐ (`run` en lugar de `profile`) |
| 2 | `xammu playbook` genera hipótesis desde el perfil | `cmd/xammu/cli_test.go: TestPlaybookPlansAndSendsNothing`; las hipótesis se derivan del perfil al re-derivar un bundle sellado (`internal/inference/inference_test.go: TestEndToEndRoundProducesCheckableRecords`) | ◐ (`playbook` planifica y no envía; la hipótesis es un artefacto del bundle) |
| 3 | `xammu validate` ejecuta una hipótesis con autorización | `cmd/xammu/cli_test.go: TestRederiveNeedsThePermissionThatPaidForIt`; `internal/contracts/contracts_test.go: TestValidationAuthorizationIsImmutableAndScoped`; `internal/httpclient/httpclient_test.go: TestValidationAuthorizationLimitsProbes`; `validate --finding BYP-G-DEV-SQLI-Q-TAUTO` ejecutado sobre `runs/demo-lab` | ◐ (re-derivación de sólo lectura + `run --validation` para una ronda nueva) |
| 4 | `xammu report --format human` produce el informe de 7.2 | `cmd/xammu/cli_test.go: TestReportFormatNamesTheHumanDocument`; `internal/report/report_test.go: TestJSONRoundTripsAndMarkdownCarriesEverySection` | ✅ |
| 5 | `xammu report --format json` produce un C-15 válido | `internal/report/report_test.go: TestBuildIssuesAValidC15` | ✅ |
| 6 | `xammu verify <manifest>` detecta alteración | `cmd/xammu/cli_test.go: TestVerifyCatchesEvidenceDamage`; `internal/integrity/tamper_test.go`: `TestEditedRecordBreaksChain`, `TestRemovedRecordBreaksChain`, `TestInsertedRecordBreaksChain`, `TestReorderedRecordsBreakChain`, `TestTruncatedTailPassesChainButFailsTheManifest`, `TestForgedChainValidAppendIsCaughtByManifest`, `TestReSignedWithForeignKeyFailsTrustCheck`; `cmd/xammu/run_test.go: TestEndToEndRederiveCatchesAEditedReport` | ✅ |
| 7 | `xammu lab up/down/test` levanta un laboratorio reproducible en CI limpio | `lab/build.sh`, `lab/verify.sh` (134/134 comprobaciones, documentadas en `lab/README.md:147,166`), `lab/teardown.sh`; `cmd/xammu/cli_test.go: TestLabCommandsPreviewInsteadOfActing` cubre sólo la superficie CLI; `.github/workflows/ci.yml` versiona el workflow pero no ejecuta el laboratorio Docker | ⚠ workflow sin corrida externa y laboratorio sin re-ejecución en esta máquina (no hay daemon de Docker) |

### 2.2 Utilidad

| # | criterio | prueba / evidencia | estado |
| --- | --- | --- | --- |
| 8 | el informe responde a las 7 preguntas de la sección 2 | `internal/contracts/contracts_test.go: TestReportCoversAllSevenQuestions`; `internal/report/report_test.go: TestAReportOfOnlyAbsencesStillAnswersEveryQuestion`; `cmd/xammu/utility_test.go: TestTheDemonstrationBundlePassesTheUtilityGate` | ✅ |
| 9 | cada `discovery_finding` lleva los 4 campos de honestidad de C-16 | `internal/contracts/contracts_test.go: TestFindingRequiresAllFourHonestyFields`, `TestUndeterminedAreaCarriesNoInference` | ✅ |
| 10 | cada finding tiene `reproduction_command` ejecutable | `internal/contracts/contracts_test.go: TestFindingReproductionCommandIsScoped`; `internal/discover/discover_test.go: TestPublishedCommandsCarryTheirOwnScope`, `TestEveryPublishedRegressionStepResolves`; el comando publicado del finding `BYP-G-DEV-SQLI-Q-TAUTO` se ejecutó y devolvió la misma afirmación | ✅ |
| 11 | cada finding tiene `security_engineer_note` en lenguaje no críptico | `internal/contracts/contracts_test.go: TestFindingRequiresEngineerNote` (exige nota no vacía); la claridad se revisó leyendo `runs/demo-lab/report.md` — sin ingeniero externo, que es el criterio 16 | ✅ (presencia automatizada; legibilidad revisada por el equipo) |
| 12 | matriz de cobertura clase × vector presente en todo informe | `internal/contracts/contracts_test.go: TestReportRequiresCoverageMatrix`; `internal/report/report_test.go: TestMatrixHolesAreNamedAndMeasuredCellsHaveDenominators` | ✅ |
| 13 | falsos positivos medidos con población y denominador | `internal/discover/discover_test.go: TestOverBlockingIsMeasuredOverTheLegitimatePopulation`, `TestCoverageGapIsPublishedWithItsDenominator`; `internal/report/report_test.go: TestMatrixHolesAreNamedAndMeasuredCellsHaveDenominators` | ✅ |
| 14 | zonas no evaluadas siempre presentes, aunque sea «ninguna» | `internal/contracts/contracts_test.go: TestReportAlwaysDeclaresUnevaluated`; `internal/report/report_test.go: TestEveryUnmeasuredCellIsADeclaredZone` | ✅ |
| 15 | riesgo residual en 3 escenarios separados | `internal/report/report_test.go: TestResidualRiskStaysThreeSeparateStatements`; `internal/contracts/contracts_test.go: TestReportRequiresThreeSeparateScenarios` | ✅ |
| 16 | un ingeniero externo lee el output y explica los hallazgos sin ayuda | protocolo listo en §5; **no ejecutado** | ⚠ |

### 2.3 Honestidad epistémica

| # | criterio | prueba / evidencia | estado |
| --- | --- | --- | --- |
| 17 | ningún `raw_observation` contiene interpretación | `internal/contracts/contracts_test.go: TestRawObservationRejectsInterpretiveFields`, `TestRawObservationRejectsOutOfRangeStatus`; la denylist se aplica también sobre JSON desconocido (`InterpretiveKeysInJSON`) | ✅ |
| 18 | `behavioral_classification` no implica causa | `internal/classifier/classifier_test.go: TestClassificationCarriesNoCause`; `internal/contracts/contracts_test.go: TestClassificationRejectsCauseVocabulary` | ✅ |
| 19 | `confirmed_by_correlated_evidence` no se emite sin las 3 condiciones | `internal/contracts/contracts_test.go: TestConfirmedAttributionNeedsThreeConditions`; `internal/attributor/attributor_test.go: TestConfirmationNeedsTwoRoundsNotReplicas`, `TestC05NeverEmitsConfirmation`; `internal/hypothesis/hypothesis_test.go: TestHypothesisCannotCertifyItsOwnConfirmation`; `internal/inference/inference_test.go: TestCorroborationRaisesTheGradeWithoutInventingEvidence` | ✅ |
| 20 | `attribution_confidence` no existe en v1.0.0 | `internal/contracts/forbidden_source_test.go: TestNoForbiddenIdentifierInTheShippedTree` (recorre `cmd/` e `internal/` con `go/ast`) | ✅ |
| 21 | escalar numérico no existe en v1.0.0 | `internal/contracts/forbidden_source_test.go: TestNoNumericScaleIsDeclaredAnywhere`, `TestNoForbiddenJSONKeyInAStructTag`; `internal/contracts/contracts_test.go: TestForbiddenVocabularyAbsentFromContractKeys` | ✅ |
| 22 | `docker-compose.yml` no se presenta como prueba de reproducibilidad | revisión documental: `lab/compose.yaml:26-33` (bloque `REPRODUCIBILITY`: «a compose file alone is never accepted as proof»), `lab/DIGESTS.txt:4-7`, `README.md` §3 y `lab/README.md` §1 | ○ |
| 23 | métricas no mezclan inconcluyentes con válidos | `internal/contracts/contracts_test.go: TestDistributionCannotMixInconclusiveIntoDenominator`, `TestEvidenceProfileDenominatorExcludesInconclusive`; `internal/report/report_test.go: TestDistributionArithmeticCannotAbsorbTheIndeterminateBucket`; `internal/hypothesis/hypothesis_test.go: TestDenominatorIsValidTrialsOnly` | ✅ |

### 2.4 Seguridad operativa

| # | criterio | prueba / evidencia | estado |
| --- | --- | --- | --- |
| 24 | `429` detiene la ejecución y no se clasifica como `signal_block` | `internal/classifier/classifier_test.go: TestRateLimitedIsNeverABlock`; `internal/inference/inference_test.go: TestRateLimitedExchangeIsPacingNotProtection`; `internal/httpclient/httpclient_test.go: TestRateLimitedResponseHaltsTheClient`; `internal/orchestrator/orchestrator_test.go: TestExecuteRunsThePlanAndStopsOnARateLimit`, `TestHaltFromAControlProbeIsResumableButARateLimitIsNot` | ✅ |
| 25 | un destino no autorizado nunca recibe la solicitud | los cinco casos JAVI-020 en `internal/httpclient/httpclient_test.go`: `TestUnauthorizedHostNeverReceivesRequest`, `TestUnauthorizedPathNeverReceivesRequest`, `TestPathEscapeIsRefused`, `TestResolvedAddressOutsideAuthorizedRangeIsRefused`, `TestRedirectToUnauthorizedHostIsNotFetched`; además `TestSchemeMismatchIsRefused`, `TestUnauthorizedMethodIsRefused` | ✅ |
| 26 | presupuesto agotado produce `TRUNCATED`, nunca `COMPLETED` | `internal/orchestrator/orchestrator_test.go: TestSpentBudgetIsNeverCompleted`; `internal/contracts/contracts_test.go: TestBudgetExhaustionCannotBeCompleted` | ✅ |
| 27 | ninguna solicitud sale de un estado terminal | `internal/orchestrator/orchestrator_test.go: TestNoRequestLeavesANonExecutingRun`, `TestUnplannedProbeNeverLeaves`; `internal/contracts/contracts_test.go: TestTerminalStateHasNoExit` | ✅ |
| 28 | el reinicio respeta el estado persistido y la integridad | `internal/orchestrator/orchestrator_test.go: TestResumeContinuesTheSameRunOnTheSameBudget`, `TestResumeOfAnUnplannedRunKeepsItPlannable`, `TestResumeRefusesEvidenceItNoLongerRecognises`; `internal/integrity/tamper_test.go: TestReopenContinuesChain`, `TestTruncatedTailPassesChainButFailsTheManifest` | ✅ |
| 29 | el único punto de conexión es `internal/httpclient` | `internal/httpclient/egress_test.go: TestOnlyTheEgressOpensConnections`, `TestNoDotImportOfTheNetworkPackages` (recorren `cmd/` e `internal/` y fallan ante cualquier `Dial*`, `Listen*`, `http.Client` o dot-import de red fuera del egress) | ✅ |

---

## 2.5 Fase 1 — medición de eficacia

La Fase 1 no añade criterios a los 29 del handoff: añade una pregunta nueva y su propia tabla de
aceptación, definida en `docs/audit-handoff.md` §13.5. Se repite aquí con la evidencia ejecutada.

| punto | criterio | prueba / evidencia | estado |
| --- | --- | --- | --- |
| 1.1 | ≥300 casos de ataque en 10 clases, YAML validado y puerta aplicada | `corpus/effectiveness/attacks` (300); `internal/effectiveness/corpus_test.go: TestRepositoryCorpusLoadsAndMeetsTheFloor`; `cmd/xammu/effectiveness_test.go: TestEffectivenessCheckIsGateSurface` | ✅ |
| 1.2 | ≥300 casos benignos con procedencia citada | `corpus/effectiveness/benign` (300); la procedencia se exige en `case_test.go: TestValidateRefusesAmbiguousCases`; el conjunto se carga en el mismo test de corpus | ✅ |
| 1.3 | corrida bajo presupuesto con observación de estado, veredicto, latencia, cabeceras y huella | `runs/waf-effectiveness-2026-11-05-r3`: 600/600 conclusivos, 0 exclusiones; `internal/effectiveness/run_test.go`, `outcome_test.go`, `request_test.go` | ✅ |
| 1.4 | TPR/FPR/Precision/F1/MCC y p50/p95/p99, `verify` en verde y `--rederive` sin discrepancias | `verify --store runs/waf-effectiveness-2026-11-05-r3 --rederive` y `effectiveness report --store ... --rederive`, ambos en verde; `cmd/xammu/effectiveness_test.go: TestEffectivenessEndToEndRunVerifyReport`; `internal/effectiveness/metrics_test.go` | ✅ |
| regresión | tests de métricas, carga, ejecución y CLI; `go test ./...` en verde | suite completa, incluidos `cmd/xammu/effectiveness_test.go` y los seis tests nuevos de `internal/effectiveness` | ✅ |

Resultado de aceptación (loopback, 2026-11-05): **TP 25 / FN 275 / FP 8 / TN 292 / 0 excluidos**;
TPR 8,33 %, FPR 2,67 %, Precision 75,76 %, F1 15,02 %, MCC 0,124; latencia global p50/p95/p99 de
0/0/1 ms. Las tasas describen acuerdo con este corpus en este target y esta ventana, no eficacia
absoluta; el detalle por clase está en `runs/waf-effectiveness-2026-11-05-r3/effectiveness-report.md`.

## 2.6 Fase 2 — evasión y fingerprinting

La Fase 2 tampoco añade criterios a los 29 del handoff. Su tabla de aceptación está en
`docs/audit-handoff.md` §14.8; aquí se repite con la evidencia ejecutada.

| punto | criterio | prueba / evidencia | estado |
| --- | --- | --- | --- |
| 2.1 | pilas de 1–3 primitivas, `auto` y forzada, autorización por primitiva, ida y vuelta y marcador; `chunked` excluido con motivo | `internal/tamper/tamper_test.go`; `internal/contracts/contracts_test.go: TestAuthorizationTamperVocabularyIsClosed`; `cmd/xammu/effectiveness_test.go: TestEffectivenessRunRefusesAnUnauthorizedTamper`; `effectiveness tampers` | ✅ |
| 2.1 medición | corrida con línea base y brazo tamper; TPR base vs tamper por clase y global, con denominadores y exclusiones | `runs/waf-effectiveness-2026-11-05-r6`: 600 + 600 solicitudes, 0 excluidos; `internal/effectiveness/metrics_test.go`, `run_test.go` | ✅ |
| 2.2 | fingerprint con vendor, apoyo categórico y evidencia enumerada; multi-vendor y `unknown` contemplados | `internal/fingerprint/fingerprint_test.go`; `r6` identifica `xammu-lab-waf` con apoyo `high` y 33 outcomes con evidencia | ✅ |
| 2.2 recomendación | pilas candidatas adjuntas a la identificación, con base declarada y sin afirmaciones de bypass | `internal/fingerprint/signatures.go: CandidateStacks`; `docs/waf-signatures.md`; sección «WAF fingerprint» del informe de `r6` | ✅ |
| informe | Markdown y JSON muestran fingerprint y tabla comparativa; `verify --rederive` en verde | `cmd/xammu/effectiveness_phase2_test.go: TestEffectivenessRunSelectsTheLabStackAndPublishesTheComparison`; `verify --store runs/waf-effectiveness-2026-11-05-r6 --rederive --trust-key trust/waf-effectiveness.pub` | ✅ |
| regresión | `go test ./...` en verde y el bundle de Fase 1 sigue re-derivando sin discrepancias | suite completa; `internal/effectiveness/read_test.go: TestPhase1BundleStillRederives`; `verify --store runs/waf-effectiveness-2026-11-05-r3 --rederive` | ✅ |

Resultado de aceptación (loopback, 2026-11-05): línea base **TP 25 / FN 275 / FP 8 / TN 292** y
brazo tamper **TP 0 / FN 300 / FP 0 / TN 300**, 0 excluidos en ambos. El TPR baja de 8,33 % a
0,00 % y el FPR de 2,67 % a 0,00 % con `url_encode_double → sql_comment`: la pila evita tanto las
detecciones como los falsos positivos, que es un resultado de ceguera, no de mejora. El fingerprint
identifica el WAF del laboratorio con apoyo `high`; las pilas se publican como candidatas a medir.
El detalle está en `runs/waf-effectiveness-2026-11-05-r6/effectiveness-report.md`.

## 2.7 Fase 3 — gate de CI/CD, informe y entrega sellada

La Fase 3 tampoco amplía los 29 criterios. Su contrato está en `docs/audit-handoff.md` §15 y su
aceptación, con la evidencia ejecutada, en §15.11; aquí se resume la prueba de cada punto.

| punto | criterio | prueba / evidencia | estado |
| --- | --- | --- | --- |
| 3.1 JSON | `schema_version` presente; bytes idénticos en dos evaluaciones; campos de E-03 representados | `internal/gate/gate_test.go: TestJSONIsDeterministic`; el documento emitido lleva todas las claves de `MetricsView`; `schemas/xammu-gate-v1.schema.json` | ✅ |
| 3.1 YAML | el documento emitido se re-parsea con `internal/yamlish` y coincide con el JSON | `gate_test.go: TestYAMLRoundTripsThroughTheRepositoryParser` | ✅ |
| 3.1 SARIF | versión y `$schema` correctos, cada `ruleId` declarado, `level` en `error|warning|note`, ubicación en un journal inventariado | `gate_test.go: TestSARIFCarriesOneResultPerFailedCheck`, `TestSARIFReportsOneResultPerFindingAtTheFloor`, `TestSARIFIsEmptyWhenEveryCheckPasses`; `scripts/gate-demo.sh` repite la comprobación de forma | ✅ |
| 3.2 umbrales | r6 sale 1 por `effectiveness.tpr`; r7 sale 0; un TPR nulo falla con `no denominator`; una política con `critical` sale 2 | `policies/effectiveness-reference.yaml`; `TestNullRateFailsWithNoDenominatorInsteadOfZero`; ejecución manual del caso `critical` | ✅ |
| 3.2 hallazgos | `fail_on_priority: medium` sobre `runs/demo-lab` sale 1 por sus 2 hallazgos; SARIF con un resultado por hallazgo citando `findings.jsonl` | `policies/profiling-demo.yaml`; gate sobre `runs/demo-lab` (`XAMMU-FINDING-ENCODING_BYPASS_PATTERN`, `XAMMU-FINDING-OVER_BLOCKING`) | ✅ |
| 3.3 informe | siete secciones, nulos `n/a`, controles con evidencia y límites; el fixture de referencia se declara en resumen y límites | `publications/waf-effectiveness-2026-11-05-r7/report.md`; `internal/gate/report_test.go` | ✅ |
| 3.3 anexo | `annex-es.md` y `annex-en.md` con las mismas cifras y campos; solo cambia el idioma | `internal/annex/effectiveness_test.go`; los dos archivos de la entrega de r7 | ✅ |
| 3.3 sello | `publication.json` Ed25519, `verify --publication` sale 0, un byte alterado sale 1, otra clave de confianza sale 1, sin clave se informa no anclado | `internal/gate/publication_test.go`; `verify --publication publications/...-r6|r7 --trust-key trust/waf-effectiveness.pub` | ✅ |
| demostración | r7 contra `examples/reference-waf`: preflight 600/600, TPR base 100,00 %, tamper 95,00 %, gate r6 = 1 y r7 = 0 | `examples/reference-waf/waf_test.go`; `runs/waf-effectiveness-2026-11-05-r7`; `scripts/gate-demo.sh` | ✅ |
| pipeline | GitHub con `upload-sarif`, snippets de GitLab, Azure y Jenkins; demostración enganchada a CI | `examples/ci`; `scripts/gate-demo.sh` en `scripts/ci-local.sh` y `.github/workflows/ci.yml` | ✅ |
| regresión | `go test ./...` en verde; r3, r6 y r7 re-derivan; corpus y `lab/waf` intactos; sin dependencias externas | suite completa; `verify --rederive` sobre los tres bundles | ✅ |

Resultado de aceptación (loopback, 2026-11-05): r7 mide **TP 300 / FN 0 / FP 0 / TN 300** en la
línea base y **TP 285 / FN 15 / FP 0 / TN 300** con `url_encode_double → case_switch`, 0 excluidos
en ambos. El gate falla r6 (TPR 8,33 % < 80 %) y pasa r7 con 6 checks aplicables. Las cifras
describen el fixture de referencia, calibrado contra este corpus; no son eficacia de un WAF real.
Los sobres de ambas entregas verifican con `trust/waf-effectiveness.pub`.

---

## 3. Equivalencia de vocabulario

El handoff nombra cuatro comandos que no existen con esa forma. La equivalencia no es un alias de
conveniencia: cada diferencia tiene una razón de seguridad, y `README.md` §11 la resume.

| handoff | implementado | por qué no es idéntico |
| --- | --- | --- |
| `xammu profile` | `xammu run --authorization FILE --authorize REF` | `run` es la única acción que envía; la segunda bandera obliga a nombrar el permiso que se tiene en la mano. Un `profile` sin autorización explícita sería más cómodo y menos auditable. |
| `xammu playbook` | `xammu playbook --authorization FILE --corpus DIR [plan flags]` | el comando existe y **planifica sin enviar**. No «genera hipótesis»: las hipótesis nacen de un perfil medido, y un playbook previo a la medición no tiene perfil del que derivarlas. La derivación ocurre al sellar o re-derivar el bundle (`internal/inference`). |
| `xammu validate --hypothesis REF` | `xammu validate --finding REF` (re-derivación de sólo lectura) **y** `xammu run --validation FILE --parent-run ID` (ronda C-10) | validar una hipótesis puede significar releerla o volver a medirla. La primera no envía nada y no necesita permiso de envío; la segunda es un run nuevo y exige su propia autorización C-10 inmutable. |
| `xammu lab up/down/test` | `lab/build.sh`, `lab/verify.sh`, `lab/teardown.sh`; `xammu lab scenarios`; `xammu lab test --scenario NOMBRE [--apply]` | `lab test` sin `--apply` sólo describe; únicamente `--apply` toca Docker. El levantamiento real es el par `build.sh` + `verify.sh`, que es donde vive la prueba de reproducibilidad. |

Ninguna equivalencia amplía el comportamiento del handoff: `playbook` y `validate` no envían,
`run` exige más permiso del que el handoff pedía, y `lab test` por defecto no actúa.

---

## 4. CI y la secuencia local equivalente

El repositorio versiona `.github/workflows/ci.yml`, con las acciones de terceros fijadas por SHA.
El workflow ejecuta `gofmt -l`, `go vet`, `go test -race ./...`, `govulncheck` como herramienta,
gitleaks sobre árbol e historial y `scripts/release.sh`; en un tag `v*` añade SBOM CycloneDX y firma
keyless con cosign. **No se ha ejecutado en un runner externo**: el push y `id-token: write`
requieren aprobación externa, así que el criterio 7 y el ítem 13 de §8 siguen en ⚠.

La evidencia local se produce con dos scripts, en este orden:

```bash
cd /d/Xammu
bash scripts/ci-local.sh       # espejo local del workflow; lista cada SKIP
bash scripts/certify.sh        # aceptación interna completa
```

`ci-local.sh` ejecuta formato, vet, build, suite, `-race` si hay cgo, `govulncheck` y gitleaks si
están en `PATH`, el build reproducible, `scripts/gate-demo.sh` y SBOM si Syft está instalado.
Escribe `dist/ci-local-<UTC>.txt` y el resultado declara cuántos checks se saltaron y por qué. La
secuencia manual equivalente, paso a paso, es la siguiente; cualquier fallo detiene la entrega:

```bash
cd /d/Xammu

gofmt -l cmd internal          # debe imprimir nada
go vet ./...
go build ./...
go test ./...                  # 428 funciones de prueba, 23 paquetes

go run ./cmd/xammu corpus check --corpus corpus
go run ./cmd/xammu lab scenarios

bash scripts/gate-demo.sh      # r6 = 1, r7 = 0, SARIF con forma, entregas que verifican

go run ./cmd/xammu verify --run demo-lab \
  --authorization AUTH-SMOKE-LOCAL-001 --authorizations authorizations \
  --issuer-keyring trust/issuers \
  --corpus corpus --class sqli --vector query,body_json,cookie
go run ./cmd/xammu verify --run demo-origin \
  --authorization AUTH-SMOKE-ORIGIN-001 --authorizations authorizations \
  --issuer-keyring trust/issuers \
  --corpus corpus --class sqli --vector query

# Requiere Docker con daemon: no forma parte de la secuencia local de arriba.
cd lab && bash build.sh && bash verify.sh && bash teardown.sh
```

Notas para quien repita esto:

- `go test ./...` cubre los 26 criterios ✅/◐ de §2. `cmd/xammu/run_test.go` levanta un perímetro
  en proceso con `httptest`; los tests de integridad escriben bundles en un directorio temporal.
  Ninguno requiere el laboratorio.
- `-race` no se ejecutó en la máquina de entrega si su toolchain no tiene cgo; el workflow lo
  ejecuta en `ubuntu-latest`. `ci-local.sh` lo intenta y lo declara como `SKIP` si falta.
- La secuencia **no** re-ejecuta `lab/verify.sh`: esta máquina no tiene daemon de Docker. La
  corrida 134/134 registrada en `lab/DIGESTS.txt` pertenece a la máquina que la generó y así se
  declara en `README.md` §3.
- Las autorizaciones de demostración caducan el **2026-10-29**. Después de esa fecha los dos
  comandos `run` que produjeron los bundles se rechazan por caducidad; `report`, `validate` y
  `verify` siguen funcionando porque re-derivan de la evidencia sellada.
- La firma keyless y el SBOM del release **no** se producen en local: dependen del token OIDC del
  workflow. Sin una corrida sobre un tag no existe `.sigstore.json` que verificar.

---

## 5. Protocolo de la prueba de utilidad (criterio 16)

El criterio 16 no se puede automatizar: pregunta si una persona entiende el output. Este es el
protocolo acordado; **no se ejecutó**, y por eso el criterio figura como ⚠.

**Participante.** Un ingeniero de ciberseguridad externo al equipo, con experiencia en WAF, proxies
o análisis de tráfico, que no haya participado en el diseño de XAMMU ni leído este repositorio.

**Material entregado.** Sólo dos cosas: `runs/demo-lab/report.md` y `runs/demo-origin/report.md`
impresos o en terminal. Nada de README, matrices ni explicación oral.

**Tarea, sin ayuda del equipo:**

1. Elegir tres hallazgos, uno de cada tipo entre `encoding_bypass_pattern`, `over_blocking` y
   `vector_asymmetry`, y explicar para cada uno: qué se observó, qué se infiere, qué falta y qué
   no afirma.
2. Elegir una zona no evaluada (`undetermined_area`) y explicar por qué no se puede concluir nada
   sobre ella.
3. Decir qué haría el lunes con dos de los hallazgos.
4. Ejecutar un `reproduction_command` publicado tal cual y comprobar que devuelve la misma
   afirmación. En los bundles de demostración, sellados antes de 0.1, hay que añadir
   `--issuer-keyring trust/issuers` al comando; el material entregado lo indica.

**Criterio de éxito.** El participante nombra correctamente los tres tipos, distingue observación
de inferencia en al menos dos, identifica el motivo tipado de la zona no evaluada y propone una
acción coherente. Si necesita que el equipo le explique un término del informe, la prueba falla
aunque todos los tests pasen.

**Registro.** Se anota fecha, perfil del participante, las tres explicaciones literales, los
comandos ejecutados y el veredicto. Ese registro es el único documento que puede cerrar el
criterio 16; hasta entonces, la entrega lo declara abierto.

---

## 6. Qué garantiza `verify` y qué no

`verify` ejecuta estas comprobaciones y las reporta una por una
(`internal/integrity/manifest.go: Verify`):

| comprobación | qué afirma |
| --- | --- |
| `contract_valid` | el manifiesto satisface C-12 |
| `public_key_decodes` | la clave pública decodifica y su ID coincide con el firmante declarado |
| `signer_is_trusted` | **falla si no se pasó `--trust-key`**: con clave es identidad anclada; sin ella la firma es sólo autoconsistente |
| `payload_digest_recomputed` | el digest del payload recomputa |
| `signature_valid` | la firma Ed25519 verifica sobre el material de firma |
| `inventory_readable` | los artefactos del bundle se pueden enumerar |
| `no_unlisted_files` / `no_missing_files` / `no_modified_files` | el inventario firmado coincide exactamente con el disco |
| `merkle_root_matches` | el Merkle root recomputa sobre los archivos actuales |
| `observation_chain_head` / `chain_head_is_last_record` / `observation_count_matches` | el head firmado es la última línea y el conteo coincide |
| `hash_chain_intact` | la cadena de hashes de todos los journals no tiene cortes |

**No garantiza:**

- **que las lecturas sean correctas.** Una sonda registrada con su status y sus señales es
  evidencia de lo que llegó, no una conclusión de lo que significa;
- **quién firmó**, salvo con `--trust-key` obtenida por un canal independiente. El propio comando
  lo dice al terminar y hay tests que lo fijan (`TestVerifyStatesWhatTheSignatureDoesNotCover`,
  `TestVerifyAnchorednessIsNotFailure`);
- **que el permiso fuera válido al ejecutar**, salvo la firma: al pasar `--authorization` junto a
  `--issuer-keyring`, `verify` comprueba el sidecar y el fingerprint del permiso, pero la caducidad
  y el alcance se comprueban en `run`, no al verificar;
- **nada sobre `report.md` / `report.json`.** Se generan después del sellado y quedan fuera del
  inventario firmado: la firma compromete la evidencia, no el documento. `report --rederive` vuelve
  a emitirlo y compara; una diferencia es un defecto de la cadena, no una lectura.

---

## 7. Definición de terminado (§9) y la desviación de §9.3

| # | condición de §9 | estado |
| --- | --- | --- |
| 1 | los 29 criterios pasan en CI contra laboratorio limpio | ⚠ workflow versionado sin corrida externa; §4 es la secuencia local y los 27 criterios no-⚠ están verdes |
| 2 | un ingeniero externo explica tres hallazgos y una zona no evaluada sin ayuda | ⚠ protocolo en §5, no ejecutado |
| 3 | el informe de laboratorio incluye `coverage_gap`, `over_blocking`, `vector_asymmetry` y `undetermined_area` | ✅ **en dos ejecuciones**: `runs/demo-lab` aporta `encoding_bypass_pattern`, `over_blocking`, `vector_asymmetry` y 11 `undetermined_area`; `runs/demo-origin` aporta 3 `coverage_gap` y 13 `undetermined_area` |
| 4 | `xammu verify` pasa sobre el manifiesto de demostración | ✅ sobre los dos manifiestos (`runs/demo-lab`, `runs/demo-origin`) |
| 5 | la guía de laboratorio permite reconstruirlo sin decisiones no documentadas | ✅ `lab/README.md` (comportamientos, límites, `file:línea`, 134/134 en `:147,166`) + `DIGESTS.txt` + `verify.sh`; con la salvedad de que `verify.sh` no se re-ejecutó en esta máquina |
| 6 | la lista de §10 está marcada con pruebas reales, no con documentación | ✅ §8 de este documento |

### La desviación de §9.3, declarada

La condición 3 pide los cuatro tipos **en un informe**. Con este fixture, un solo run no puede
producirlos, y la razón es estructural:

1. `coverage_gap` exige que una celda contradiga la expectativa declarada del corpus con controles
   válidos. El WAF es coherente con su propia tabla de reglas: bloquea lo que declara bloquear y
   reenvía lo que declara no inspeccionar. Sólo el origen sin defensa contradice las expectativas
   del corpus, y el origen nunca rechaza, así que no puede producir los otros tres tipos.
2. v1 es un objetivo por ejecución. Mezclar WAF y origen en un run rompería la atribución.
3. La alternativa —declarar `expect_block` para una celda que el WAF no inspecciona a propósito—
   se rechazó: falsearía la expectativa del corpus para fabricar el hallazgo que falta.

Los cuatro tipos están demostrados por el laboratorio en dos ejecuciones autorizadas por separado
(`AUTH-SMOKE-LOCAL-001` para el WAF, `AUTH-SMOKE-ORIGIN-001` para el origen), cada una reproducible
y verificable por sí sola. La entrega lo declara en `README.md` §4 en lugar de presentar como
cumplida una condición que la redacción original pedía en singular.

---

## 8. Lista de verificación de entrega (§10)

| # | ítem | evidencia | estado |
| --- | --- | --- | --- |
| 1 | inventario C-01…C-16 implementado, versionado y validado | `internal/contracts/contracts_test.go: TestEveryContractHasAValidator`, `TestFixturesAreValid`, `TestManifestPinsEveryContractVersion` | ✅ |
| 2 | manifiesto firmado con detección de alteración (JAVI-019) | `internal/integrity/tamper_test.go` (7 casos de alteración y re-firma) | ✅ |
| 3 | cliente HTTP con validación de destino efectivo (JAVI-020) | `internal/httpclient/httpclient_test.go` (5 casos + método, esquema, presupuesto) | ✅ |
| 4 | `attribution_confidence` eliminado; sólo `attribution_status` (JAVI-021) | `internal/contracts/forbidden_source_test.go: TestNoForbiddenIdentifierInTheShippedTree` | ✅ |
| 5 | tabla exhaustiva de transiciones y pruebas de recuperación (JAVI-022) | `internal/contracts/contracts_test.go: TestTransitionTableIsExhaustive`; tests de reanudación en `internal/orchestrator` | ✅ |
| 6 | protocolo de partición del corpus con detector de solapamiento | `internal/corpus/corpus_test.go: TestOverlapDetectorNamesTheCollisionItFinds`, `TestPartitionRequiresChecksAgainstEveryOther` | ✅ |
| 7 | métricas con denominadores explícitos | `TestDistributionCannotMixInconclusiveIntoDenominator`, `TestOverBlockingIsMeasuredOverTheLegitimatePopulation` | ✅ |
| 8 | laboratorio reproducible por tercero sin decisiones no documentadas | `lab/README.md` + `lab/DIGESTS.txt` + `lab/verify.sh` (134/134 documentadas en `lab/README.md:166`; no re-ejecutadas aquí) | ✅ con salvedad declarada |
| 9 | informe de 5 dimensiones + 3 escenarios + zonas no evaluadas | `internal/report/report_test.go`; los dos bundles de demostración | ✅ |
| 10 | `discovery_finding` (C-16) con los 4 campos de honestidad y nota | `TestFindingRequiresAllFourHonestyFields`, `TestFindingRequiresEngineerNote` | ✅ |
| 11 | matriz de cobertura clase × vector en todo informe | `TestReportRequiresCoverageMatrix` | ✅ |
| 12 | falsos positivos medidos con población y denominador | `TestOverBlockingIsMeasuredOverTheLegitimatePopulation` | ✅ |
| 13 | los 29 criterios de aceptación pasan en CI | `.github/workflows/ci.yml` existe y `scripts/ci-local.sh` pasa en la máquina de entrega; el workflow no se ejecutó en GitHub | ⚠ ver §2 |
| 14 | prueba de utilidad con ingeniero externo | — | ⚠ ver §5 |
| 15 | el laboratorio produce los 4 tipos de finding en la ejecución de demostración | `runs/demo-lab` + `runs/demo-origin` | ✅ (desviación de §9.3, §7) |
| 16 | `xammu verify` pasa sobre el manifiesto de demostración | ambos bundles | ✅ |

---

## 9. Brechas declaradas

Estas son las únicas afirmaciones que la entrega **no** hace. Están también en `README.md` §12.

1. **No hay corrida de CI en un runner externo.** `.github/workflows/ci.yml` está versionado y
   `scripts/ci-local.sh` pasa en la máquina de entrega, pero el workflow no se ejecutó en GitHub:
   hacer push y habilitar `id-token: write` requiere aprobación externa. El criterio 7 y el ítem 13
   de §8 siguen abiertos hasta esa corrida.
2. **No hay prueba con ingeniero externo.** El protocolo de §5 está listo; el criterio 16 y el
   ítem 14 de §8 no se reclaman.
3. **`lab/verify.sh` no se re-ejecutó en esta máquina.** El resultado 134/134 pertenece a la
   corrida documentada en `lab/README.md:147,166`; aquí no hay daemon de Docker. El procedimiento
   y los digests están versionados y la afirmación está acotada a esa corrida.
4. **La condición §9.3 se cumple en dos runs, no en uno.** La razón es estructural (§7) y la
   alternativa habría falsificado el corpus. Quien lea «un informe con los cuatro tipos» debe leer
   «una demostración con los cuatro tipos, en dos ejecuciones autorizadas y verificables».
5. **Las autorizaciones de demostración caducan el 2026-10-29.** Reproducir los bundles con `run`
   deja de ser posible después de esa fecha; verificarlos y re-leerlos, no.
6. **La firma de los bundles no está anclada.** Se generaron con claves efímeras que no se
   versionan; `verify` lo declara («no trusted key supplied»). Anclar la identidad exige una clave
   obtenida por un canal independiente.
7. **El release todavía no tiene artefacto firmado.** El workflow firma binario, checksum y SBOM
   con cosign keyless sobre un tag `v*`, pero no se ha ejecutado. Hasta entonces solo existen el
   binario y su `.sha256` locales; no hay `.sigstore.json` ni SBOM publicados.
