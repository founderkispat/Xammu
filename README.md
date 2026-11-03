# XAMMU v1.0.0

**Perfilado de comportamiento defensivo a través de un único egress autorizado.**

XAMMU mide cómo una defensa perimetral trata solicitudes concretas y publica hallazgos que un
ingeniero puede usar. Envía sólo sondas inertes con forma de marcador, por un único
canal autorizado, y no afirma nada que la medición no sostenga: cada hallazgo declara qué se
observó, qué se infiere, qué falta y qué no puede saberse.

> Estado a 2026-10-28: **entrega funcional en revisión**, no un producto aprobado. La suite
> local está verde y los dos bundles de demostración verifican; quedan declarados dos criterios
> que este repositorio no puede cerrar por sí solo (CI y prueba con ingeniero externo) en
> [`docs/acceptance.md`](docs/acceptance.md).

---

## 1. Qué es y qué no es

**Es** un perfilador conductual de una sola pasada por objetivo:

- construye un plan a partir de un corpus inerte y una autorización C-09 firmada;
- envía cada sonda por **un único cliente HTTP** (`internal/httpclient`), que valida destino,
  método, esquema, ruta, presupuesto y caducidad antes de abrir el socket;
- registra la evidencia en un bundle append-only con cadena de hashes y manifiesto Ed25519;
- deriva señales, atribución, hipótesis y hallazgos C-16 sin inventar evidencia;
- publica un informe de cinco dimensiones con comandos de reproducción ejecutables.

**No es**, y estas negaciones son vinculantes:

- **no es un escáner de vulnerabilidades ni evalúa la aplicación**; ningún informe puede
  presentarse como evaluación de seguridad de un WAF;
- **no explota nada**: la puerta de inertez del corpus se ejecuta al cargar y no hay bandera
  que la salte; una sonda que pueda ejecutar algo no llega al transporte;
- **no ensancha el alcance**: las banderas de plan *estrechan* la autorización, nunca la
  amplían; un destino fuera de la C-09 no recibe la solicitud;
- **no usa `attribution_confidence` ni ninguna escala numérica**; la fuerza vive en un enum
  ordinal y en alternativas evaluadas;
- **no emite `confirmed_by_correlated_evidence`** sin las tres condiciones de C-06 (fuente
  externa que concuerda, reproducción en rondas independientes y controles válidos);
- **no integra SIEM, base de datos, frontend ni multiusuario**; v1 es CLI monousuario con
  archivos y manifiesto, un objetivo por ejecución.

---

## 2. Arranque rápido — sin levantar nada

Estos comandos se ejecutaron en esta máquina y no envían una sola solicitud: leen el corpus o
re-derivan bundles ya sellados.

```bash
cd /d/Xammu

# qué es este binario, qué contratos y detectores lleva
go run ./cmd/xammu version

# la puerta de inertez sobre el corpus completo (35 + 25 + 8 ítems)
go run ./cmd/xammu corpus check --corpus corpus

# los diez escenarios de laboratorio y el comando que publicó cada uno
go run ./cmd/xammu lab scenarios

# verificar el bundle del WAF (13 artefactos firmados, 23 observaciones)
go run ./cmd/xammu verify --run demo-lab \
  --authorization AUTH-SMOKE-LOCAL-001 --authorizations authorizations \
  --corpus corpus --class sqli --vector query,body_json,cookie

# el informe humano del mismo bundle
go run ./cmd/xammu report --run demo-lab \
  --authorization AUTH-SMOKE-LOCAL-001 --authorizations authorizations \
  --corpus corpus --format human

# reproducir un hallazgo concreto: el comando que el propio informe publica
go run ./cmd/xammu validate --finding BYP-G-DEV-SQLI-Q-TAUTO --run demo-lab \
  --authorization AUTH-SMOKE-LOCAL-001 --corpus corpus
```

Salida esperada del último comando:

```
BYP-G-DEV-SQLI-Q-TAUTO       agrees: type encoding_bypass_pattern, descriptive, evidence single_observation

every named finding came back from the sealed evidence with the same claim, the same grade and
the same missing evidence.
```

`verify` termina explicitando lo que **no** demuestra: la firma se comprobó contra la clave
pública del propio manifiesto, así que la identidad no está anclada salvo que se pase
`--trust-key`; y la verificación no dice si las lecturas son correctas, sólo que la evidencia se
compromete a sí misma. Los detalles, en [`docs/acceptance.md`](docs/acceptance.md#6-qué-garantiza-verify-y-qué-no).

Las autorizaciones de demostración caducan el **2026-10-29**. Después de esa fecha `run` rechaza
una ejecución nueva; `report`, `validate` y `verify` siguen re-derivando del bundle sellado y el
informe declara que el permiso venció.

---

## 3. El laboratorio

El fixture vive en [`lab/`](lab/README.md). Se reconstruye con Docker:

```bash
cd /d/Xammu/lab
bash build.sh        # construye origen y WAF, reescribe DIGESTS.txt
bash verify.sh       # arranca, afirma B1-B5 + S + K, hace teardown
bash teardown.sh
```

- La corrida registrada en `lab/README.md:147` es **134/134** comprobaciones. En esta máquina no
  se re-ejecutó: no hay daemon de Docker disponible. El registro y el procedimiento están
  documentados; la afirmación «134/134» pertenece a esa corrida, no a esta sesión.
- **`compose.yaml` no es la prueba de reproducibilidad.** La prueba son `DIGESTS.txt` (IDs de
  imagen y huellas de fuentes, generados por `build.sh`) y `verify.sh` (que los coteja contra
  los contenedores en ejecución). El propio `compose.yaml` lo declara.
- El laboratorio no publica puertos y su red es `internal: true`: las comprobaciones corren
  dentro de `netrunner`. XAMMU mide desde el host contra los **binarios del fixture** en
  `127.0.0.1:8081` (origen) y `127.0.0.1:8099` (WAF); el manifiesto de escenarios lo declara
  con `run_mode: host`.
- Para repetir una **lectura** en el host:

  ```bash
  ORIGIN_LISTEN_ADDR=":8081" go run ./lab/origin   # terminal 1
  WAF_LISTEN_ADDR=":8099" WAF_ORIGIN_URL="http://127.0.0.1:8081" go run ./lab/waf   # terminal 2
  ```

- Para repetir el **comportamiento del fixture**, usa compose y `verify.sh`, o
  `xammu lab test --scenario NOMBRE --apply` (la única forma en que `lab test` toca Docker; sin
  `--apply` sólo describe).

El fixture imita *una* configuración plausible —inspección sólo de query string, una única pasada
de decodificación, body JSON no inspeccionado— y nada más. No compara productos ni autoriza a
escribir «el WAF X es inseguro».

---

## 4. Los dos bundles de demostración (y la desviación declarada de §9.3)

| bundle | destino | autorización | peticiones | tipos de hallazgo |
| --- | --- | --- | --- | --- |
| `runs/demo-lab` | `http://127.0.0.1:8099` (WAF) | `AUTH-SMOKE-LOCAL-001` | 23 de 48 | `encoding_bypass_pattern` 1, `over_blocking` 1, `vector_asymmetry` 1, `undetermined_area` 11 |
| `runs/demo-origin` | `http://127.0.0.1:8081` (origen solo) | `AUTH-SMOKE-ORIGIN-001` | 14 de 48 | `coverage_gap` 3, `undetermined_area` 13 |

Comandos que produjeron cada bundle (requieren el fixture en el host; las claves de firma son
efímeras y no se versionan):

```bash
MSYS_NO_PATHCONV=1 go run ./cmd/xammu run \
  --authorization authorizations/smoke-local.json --authorize AUTH-SMOKE-LOCAL-001 \
  --corpus corpus --runs-dir runs --run demo-lab --budget 48 \
  --path /api/search --class sqli --vector query,body_json,cookie \
  --signing-key "$TEMP/xammu-demo-lab.ed25519"

MSYS_NO_PATHCONV=1 go run ./cmd/xammu run \
  --authorization AUTH-SMOKE-ORIGIN-001 --authorize AUTH-SMOKE-ORIGIN-001 \
  --authorizations authorizations --corpus corpus --runs-dir runs --run demo-origin \
  --class sqli --vector query --target http://127.0.0.1:8081 \
  --signing-key "$TEMP/xammu-demo-origin.ed25519"
```

### Por qué son dos informes y no uno

La definición de terminado (§9.3) pide un informe con `coverage_gap`, `over_blocking`,
`vector_asymmetry` y `undetermined_area`. Con este fixture, **un solo informe no puede contener
los cuatro**, y la razón es estructural, no una excusa:

1. `coverage_gap` exige que una celda contradiga la expectativa declarada del corpus con
   controles válidos. El WAF es **coherente con su propia tabla de reglas**: bloquea lo que
   declara bloquear y reenvía lo que declara no inspeccionar, así que no contradice ninguna
   expectativa. El único objetivo que las contradice es el **origen sin defensa**, que reenvía
   todo lo que el corpus espera bloqueado.
2. El origen nunca rechaza, así que no puede producir `over_blocking`, `vector_asymmetry` ni
   `encoding_bypass_pattern`.
3. v1 es **un objetivo por ejecución** (§11). Un run que mezclara WAF y origen mediría dos cosas
   a la vez y rompería la atribución.

Los cuatro tipos exigidos están demostrados por el laboratorio, en dos ejecuciones autorizadas y
verificables por separado. La alternativa —declarar `expect_block` para una celda que el WAF no
inspecciona a propósito— se rechazó: falsearía la expectativa del corpus para fabricar un
hallazgo. Queda escrito aquí porque la entrega no puede presentar como cumplido lo que la
redacción original pedía en singular.

---

## 5. La escalera de evidencia

La fuerza de una afirmación se deriva de sus cuentas, nunca se elige. El techo de claim lo fija
C-08 a partir del nivel; C-07 además impide que una hipótesis certifique su propia confirmación.

| nivel C-08 | qué lo alcanza | techo de claim |
| --- | --- | --- |
| `none` | ninguna prueba válida | ninguno: es una zona no evaluada, no una hipótesis |
| `single_observation` | una observación válida | `descriptive` |
| `replicated_within_run` | la misma forma repetida en la ronda | `association` |
| `replicated_with_valid_controls` | repetición + control positivo y negativo válidos | `association` |
| `replicated_independent_rounds` | reproducción en rondas autorizadas por separado | `attribution` |
| `correlated_independent_evidence` | una fuente fuera de HTTP (logs, configuración) que concuerda | `confirmed_attribution` |

`confirmed_attribution` no se emite nunca desde una hipótesis: C-07 lo degrada a `attribution`
porque una afirmación no puede certificarse a sí misma. La confirmación es una determinación de
C-06 sobre tres condiciones, y hay un test que la exige
(`TestConfirmedAttributionNeedsThreeConditions`).

Los cuatro tipos de claim son `descriptive`, `association`, `attribution` y
`confirmed_attribution`. No existe ningún valor numérico de confianza, riesgo o severidad; dos
tests de arquitectura fallan si alguien los reintroduce en el árbol (`§9`, criterios 20-21).

---

## 6. Los seis tipos de `discovery_finding` (C-16)

Todo finding lleva obligatoriamente los cuatro campos de honestidad (`what_was_observed`,
`what_is_inferred`, `what_evidence_is_missing`, `limitations`), una nota para el ingeniero y un
comando de reproducción ligado a una autorización o a un run existente.

| tipo | cuándo se publica | qué no dice |
| --- | --- | --- |
| `coverage_gap` | una celda que el corpus declara `expect_block` no produjo rechazo en pruebas válidas, con los controles que hacen la comparación interpretable | que la aplicación sea explotable |
| `over_blocking` | tráfico que el corpus define como legítimo fue rechazado; numerador y denominador sobre esa población | que todo el tráfico legítimo esté roto |
| `vector_asymmetry` | la misma familia de payload se trata distinto en dos transportes | qué componente inspecciona cada transporte |
| `encoding_bypass_pattern` | la forma canónica es rechazada y una réplica de codificación de la misma familia se maneja normalmente | cuántas pasadas de decodificación aplica el motor |
| `configuration_concern` | un rechazo sigue a una política nombrada sobre la solicitud (nombre de cabecera, valor protocolariamente válido) y no al casado de una firma | que la política sea incorrecta por sí sola |
| `undetermined_area` | una celda sin lectura válida, con un motivo tipado (`origin_unstable`, `rate_limited`, `transport_failure`, `not_yet_attempted`, `authorization_gap`, `corpus_gap`, `inconclusive_signal`) | nada: no lleva afirmación de riesgo |

Los tipos medidos llevan `measured_impact` con población, numerador, denominador y las pruebas
excluidas por inconclusas o inválidas. Los de ausencia llevan un motivo tipado y ningún claim.

---

## 7. Anatomía de un bundle

Un run completado escribe trece artefactos y los firma:

```
run.json  plan.jsonl  observations.jsonl  captures.jsonl  analyses.jsonl
classifications.jsonl  attributions.jsonl  status_records.jsonl
evidence_profiles.jsonl  hypotheses.jsonl  findings.jsonl  run_profiles.jsonl  notes.jsonl
manifest.json
```

- Cada journal es append-only y encadenado: quitar, editar, reordenar o insertar una línea rompe
  la cadena (`internal/integrity`).
- `manifest.json` fija los hashes, el head de la cadena, el Merkle root, las versiones de los 16
  contratos y la firma Ed25519. La clave privada vive fuera del bundle; un test comprueba que
  ningún bundle contiene una (`TestBundleContainsNoPrivateKey`).
- `report.md` y `report.json` se generan **después** del sellado y quedan fuera del inventario
  firmado: la firma compromete la evidencia, no el documento. `--rederive` vuelve a emitirlo y lo
  compara con el anterior; una diferencia es un defecto de la cadena, no una lectura.

---

## 8. Qué garantiza `verify` y qué no

Garantiza: el manifiesto satisface C-12, la firma Ed25519 es válida, el payload recomputa, todos
los artefactos listados existen y ningún archivo no listado aparece, el Merkle root recomputa, la
cadena de observaciones es íntegra y el head del manifiesto coincide con la última línea.

No garantiza: que las lecturas sean correctas, ni quién firmó, salvo que se pase `--trust-key`
con una clave obtenida por un canal independiente. `verify` lo dice al terminar, y el código
también: `TestVerifyStatesWhatTheSignatureDoesNotCover` y `TestVerifyAnchorednessIsNotFailure`.

---

## 9. Mapa de paquetes

| paquete | responsabilidad |
| --- | --- |
| `internal/contracts` | C-01…C-16: tipos, validadores, enums y denylists epistémicas |
| `internal/httpclient` | el único egress: validación de destino, presupuesto, pacing, 429 |
| `internal/orchestrator` | máquina de estados C-11, plan firmado, reanudación, sellado |
| `internal/integrity` | journals append-only, cadena de hashes, manifiesto, firma |
| `internal/observer` | análisis de la respuesta mientras el cuerpo está en memoria |
| `internal/classifier` | C-04: señal conductual, sin causa; 429 y 5xx nunca son bloqueo/paso |
| `internal/attributor` | C-05/C-06: grado derivado de condiciones y alternativas evaluadas |
| `internal/hypothesis` | C-07: afirmación, predicciones, falsificador, escalera de evidencia |
| `internal/inference` | orquesta la derivación por celda y re-deriva bundles sellados |
| `internal/corpus` | carga, puerta de inertez, particiones, selección cobertura-primero |
| `internal/discover` | C-16: los seis tipos de finding y sus reglas de publicación |
| `internal/report` | C-15: cinco dimensiones, matriz, riesgo residual, zonas no evaluadas |
| `internal/labctl` | manifiesto de escenarios y puente de vocabulario del fixture |
| `cmd/xammu` | CLI: `run`, `playbook`, `report`, `verify`, `validate`, `corpus`, `lab` |

---

## 10. Vocabulario: handoff → CLI

| handoff | implementado | por qué |
| --- | --- | --- |
| `xammu profile` | `xammu run --authorization FILE --authorize REF` | perfilar es la única acción que envía; la segunda bandera obliga a nombrar el permiso que se tiene en la mano |
| `xammu report --format human` | idéntico | `human` y `markdown` son el mismo documento; aceptar ambos mantiene el comando del handoff ejecutable |
| `xammu validate --hypothesis REF` | `xammu validate --finding REF` (re-derivación de sólo lectura) + `xammu run --validation FILE --parent-run ID` (ejecuta una ronda C-10) | `validate` nunca envía; una ronda de hipótesis es un `run` y necesita su propia autorización |
| `xammu lab up/down/test` | `lab/build.sh`, `verify.sh`, `teardown.sh`; `xammu lab scenarios`; `xammu lab test --scenario [--apply]` | `lab test` sin `--apply` describe; sólo `--apply` toca Docker |

La equivalencia completa y el estado de cada criterio están en
[`docs/acceptance.md`](docs/acceptance.md).

---

## 11. Límites declarados

- **Un objetivo por ejecución.** No hay perfilado multi-objetivo ni comparación entre hosts en un
  mismo run.
- **Sólo HTTP(S) observado.** No hay sniffing, ni análisis de tráfico en vivo, ni integración SIEM.
- **Retención digest-only por defecto en producción.** El cuerpo completo sale del proceso antes
  de la clasificación; el journal conserva digest y, como máximo, los bytes autorizados.
- **La autorización manda.** Presupuesto, métodos, clases, vectores, codificaciones, rutas,
  CIDRs y caducidad salen de la C-09; las banderas sólo recortan.
- **La sonda `/..%2F..%2F` se rechaza en planificación** porque su ruta queda fuera de los
  prefijos autorizados. Es comportamiento correcto de la política de destino y no se relaja; un
  plan de matriz completa que incluya esa sonda se rechaza en `CAL-POS-P-01` y debe estrecharse.
- **Sin CI configurado.** La secuencia local equivalente está en `docs/acceptance.md` §4.
- **Sin prueba de utilidad con ingeniero externo.** El protocolo está en `docs/acceptance.md` §5;
  la prueba no se ejecutó y el criterio 16 no se reclama.

---

## 12. Auditar este repositorio en 10 minutos

1. `go test ./...` — 279 tests en 14 paquetes; ninguna suite roja.
2. `sed -n '1,80p' docs/acceptance.md` — los 29 criterios con su prueba y lo que falta.
3. `go run ./cmd/xammu verify --run demo-lab --authorization AUTH-SMOKE-LOCAL-001 --authorizations authorizations --corpus corpus --class sqli --vector query,body_json,cookie`
4. `go run ./cmd/xammu report --run demo-origin --authorization AUTH-SMOKE-ORIGIN-001 --authorizations authorizations --corpus corpus --format human` — los tres `coverage_gap`.
5. Abre un finding de `runs/demo-lab/report.md` y ejecuta su `reproduction_command` tal cual.
6. Lee `internal/httpclient/egress_test.go` y `internal/contracts/forbidden_source_test.go`: los
   invariantes de «un solo egress» y «ninguna escala numérica» son tests, no prosa.

---

## 13. Documentos

- [`docs/acceptance.md`](docs/acceptance.md) — matriz de los 29 criterios, definición de
  terminado, desviación de §9.3, protocolo de la prueba de utilidad y qué garantiza `verify`.
- [`lab/README.md`](lab/README.md) — reconstrucción del fixture, comportamientos, límites y
  decisiones documentadas.
- [`corpus/README.md`](corpus/README.md) — particiones, controles de calibración y límites del
  corpus.
