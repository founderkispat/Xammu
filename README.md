# XAMMU v1.0.0

**Perfilado de comportamiento defensivo a través de un único egress autorizado.**

XAMMU mide cómo una defensa perimetral trata solicitudes concretas y publica hallazgos que un
ingeniero puede usar. Envía sólo sondas inertes con forma de marcador, por un único
canal autorizado, y no afirma nada que la medición no sostenga: cada hallazgo declara qué se
observó, qué se infiere, qué falta y qué no puede saberse.

> Estado a 2026-11-05: **entrega funcional en revisión**, no un producto aprobado. La suite
> local está verde, los dos bundles de demostración verifican y las fases 1 y 2 de eficacia (§8)
> y la fase 3 (gate, informe y entrega sellada) se aceptaron en local; quedan declarados dos
> criterios que este repositorio no puede cerrar por sí solo (CI y prueba con ingeniero externo)
> en [`docs/acceptance.md`](docs/acceptance.md).

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
# --trust-key fija el firmante del bundle; --issuer-keyring fija al emisor del permiso
go run ./cmd/xammu verify --run demo-lab \
  --authorization AUTH-SMOKE-LOCAL-001 --authorizations authorizations \
  --issuer-keyring trust/issuers \
  --corpus corpus --class sqli --vector query,body_json,cookie \
  --trust-key trust/demo-lab.pub

# el informe humano del mismo bundle
go run ./cmd/xammu report --run demo-lab \
  --authorization AUTH-SMOKE-LOCAL-001 --authorizations authorizations \
  --issuer-keyring trust/issuers \
  --corpus corpus --format human

# leer una celda concreta: sus ensayos, su lectura y sus atribuciones
go run ./cmd/xammu report --run demo-lab \
  --authorization AUTH-SMOKE-LOCAL-001 --authorizations authorizations \
  --issuer-keyring trust/issuers --corpus corpus \
  --cell 'sqli|query|canonical|/api/search'
```

Salida esperada del último comando (extracto):

```
cell cell:sqli|query|canonical|/api/search on http://127.0.0.1:8099
  3 trial(s): 3 valid, 0 inconclusive, 0 invalid
  readings: signal_block=3
  rounds: round-1 | runs: demo-lab
```

Cada hallazgo del informe publica su `reproduction_command`, ejecutable tal cual. En los bundles
sellados antes de 0.1 ese comando no incluye `--issuer-keyring`; al pegarlo, añade
`--issuer-keyring trust/issuers`. `validate` compara el comando publicado con el re-derivado y
señala esa diferencia de texto, no una lectura distinta.

`verify` termina explicitando lo que **no** demuestra: la firma se comprobó contra la clave
pública del propio manifiesto, así que la identidad no está anclada salvo que se pase
`--trust-key`; y la verificación no dice si las lecturas son correctas, sólo que la evidencia se
compromete a sí misma. Los detalles, en [`docs/acceptance.md`](docs/acceptance.md#6-qué-garantiza-verify-y-qué-no).

Toda C-09 y C-10 se verifica contra un anillo de claves públicas que el operador nombra con
`--issuer-keyring DIR`; no hay valor por defecto ni descubrimiento desde el documento. Una
autorización sin su sidecar `<archivo>.sig` se rechaza antes de planificar. Para firmar un permiso
que ya escribiste, con la clave privada del emisor fuera del árbol:

```bash
go run ./cmd/xammu authorization sign \
  --authorization authorizations/mi-permiso.json \
  --signing-key /ruta/fuera/del/arbol/emisor.ed25519
```

El comando imprime la huella derivada de la clave; ese valor es el que debe llevar
`issuer_key_fingerprint` en la C-09. La clave privada del emisor de demostración no se conserva:
los sidecars de `authorizations/` se firmaron con una semilla efímera y sólo se publicó
`trust/issuers/demo-issuer.pub`.

Las autorizaciones de demostración caducan el **2026-10-29**. Después de esa fecha `run` rechaza
una ejecución nueva; `report`, `validate` y `verify` siguen re-derivando del bundle sellado y el
informe declara que el permiso venció. Los bundles sellados antes de 0.1 publican comandos de
reproducción sin `--issuer-keyring`; al pegarlos, añade `--issuer-keyring trust/issuers`.

### Anexo para el cliente (ES/EN)

`report` también produce el anexo técnico que se adjunta al informe de auditoría, en Markdown o
en HTML autocontenido:

```bash
# anexo en español, con los datos del engagement
go run ./cmd/xammu report --run demo-lab \
  --authorization AUTH-SMOKE-LOCAL-001 --authorizations authorizations \
  --issuer-keyring trust/issuers \
  --corpus corpus --format annex --lang es \
  --client "Cliente de ejemplo" --engagement "Auditoría WAF" \
  --prepared-by "Izkuna" --out salida/

# el mismo anexo en inglés, como página HTML
go run ./cmd/xammu report --run demo-lab \
  --authorization AUTH-SMOKE-LOCAL-001 --authorizations authorizations \
  --issuer-keyring trust/issuers \
  --corpus corpus --format annex-html --lang en --out salida/
```

`--out` escribe `annex-es.md` o `annex-en.html` y **no** publica `report.json`: el anexo es una
vista, no un documento sellado. Traduce la estructura, las etiquetas y las indicaciones; los
campos de evidencia de cada hallazgo (`what_was_observed`, `what_is_inferred`,
`what_evidence_is_missing`, limitaciones, recomendaciones y comandos) se citan verbatim del
registro C-16 para que una traducción no altere lo observado. Todas las cifras salen del C-15
re-derivado. `--lang`, `--client`, `--engagement` y `--prepared-by` sólo se aceptan con
`annex` o `annex-html`; con cualquier otro formato `report` los rechaza como error de uso.

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
  --issuer-keyring trust/issuers \
  --corpus corpus --runs-dir runs --run demo-lab --budget 48 \
  --path /api/search --class sqli --vector query,body_json,cookie \
  --signing-key "$TEMP/xammu-demo-lab.ed25519"

MSYS_NO_PATHCONV=1 go run ./cmd/xammu run \
  --authorization AUTH-SMOKE-ORIGIN-001 --authorize AUTH-SMOKE-ORIGIN-001 \
  --authorizations authorizations --issuer-keyring trust/issuers \
  --corpus corpus --runs-dir runs --run demo-origin \
  --class sqli --vector query --target http://127.0.0.1:8081 \
  --signing-key "$TEMP/xammu-demo-origin.ed25519"
```

Las dos C-09 están firmadas y sus sidecars se versionan; la semilla del emisor de demostración no
se conserva, así que los comandos se pueden repetir con el anillo publicado, pero no volver a
firmar cambiando el permiso.

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
3. v1 es **un objetivo por ejecución** (§12). Un run que mezclara WAF y origen mediría dos cosas
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

## 8. Eficacia del WAF (fases 1 y 2)

La Fase 1 añade la pregunta que el perfilado no respondía: **¿en qué grado la defensa coincide con
las etiquetas del corpus?** No es una puntuación de eficacia absoluta; es acuerdo medido sobre un
corpus, un target y una ventana, publicado con su incertidumbre y reproducible desde el bundle.

La Fase 2 añade dos preguntas sobre la misma evidencia: **¿qué cambia el TPR cuando el payload
atraviesa una pila de re-codificaciones?** y **¿qué capa defensiva se observa, con qué evidencia y
con qué apoyo categórico?** No introduce explotación: cada tamper es una re-codificación de un
valor que la puerta ya admitió, y el valor transformado se vuelve a pasar por la puerta.

- **Corpus:** 300 casos de ataque (10 clases × 30) y 300 benignos con procedencia citada. Cada
  ataque pasa la misma puerta de inertitud y lleva el marcador `xammu-probe`; los benignos pasan la
  puerta salvo la exigencia de marcador, porque deben parecer tráfico real.
- **Ejecución:** `effectiveness run` usa el mismo `httpclient`, la misma C-09 firmada y el mismo
  presupuesto que `run`. Cada caso se coloca en query, JSON, form, path, header o cookie con una de
  las diez codificaciones declaradas; el veredicto observado se clasifica antes de tocar el cuerpo.
- **Métricas:** TP/FN/FP/TN, TPR, FPR, Precision, F1 y MCC; latencias p50/p95/p99 por clase y
  globales con `n` y aviso de muestra insuficiente. Un denominador cero produce `null`, nunca un
  número inventado. 429 se excluye como *pacing* (criterio 24); 5xx, otros 4xx, redirecciones y
  errores de transporte también se excluyen y se cuentan por motivo.
- **Brazos:** un ensayo es (caso, brazo). `baseline` es exactamente la Fase 1; `tamper` aplica una
  pila de 1 a 3 primitivas (`url_encode`, `url_encode_double`, `base64`, `unicode_escape`,
  `case_switch`, `sql_comment`, `whitespace_variant`, `html_entity`). `auto` elige la primera pila
  candidata del vendor identificado con apoyo `medium` o `high`, filtrada por `allowed_tampers` de
  la C-09; `none` corre solo la línea base. `chunked` no existe como primitiva: cambiar el encuadre
  sería smuggling, no evasión.
- **Fingerprinting:** la evidencia se atribuye en la captura (cabecera, cookie, página de error o
  comportamiento) y E-03 la agrega por vendor con apoyo categórico `high`/`medium`/`low`/`none`.
  El cuerpo no se serializa y de las cookies solo se guarda el nombre. La tabla y sus bases están
  en [`docs/waf-signatures.md`](docs/waf-signatures.md).
- **Reproducción:** `--rederive` recalcula E-03 desde los journals E-01/E-02 y compara con el E-03
  journalizado y con el documento publicado. Una diferencia es un fallo.

```powershell
# auditar el corpus sin enviar nada
go run ./cmd/xammu effectiveness check --corpus corpus/effectiveness

# ver el vocabulario de tamper y las pilas candidatas (solo lectura)
go run ./cmd/xammu effectiveness tampers

# corrida de aceptación de Fase 1 (regresión, solo línea base)
go run ./cmd/xammu effectiveness run `
  --authorization authorizations/effectiveness-local.json `
  --issuer-keyring trust/issuers `
  --authorize AUTH-EFFECTIVENESS-LOCAL-001 `
  --target http://127.0.0.1:8099 `
  --run waf-effectiveness-2026-11-05-r3

# corrida de aceptación de Fase 2 (línea base + brazo tamper, 1200 solicitudes)
go run ./cmd/xammu effectiveness run `
  --authorization authorizations/effectiveness-local-002.json `
  --issuer-keyring trust/issuers `
  --authorize AUTH-EFFECTIVENESS-LOCAL-002 `
  --target http://127.0.0.1:8099 `
  --run waf-effectiveness-2026-11-05-r6 `
  --budget 1200

# verificar la evidencia y reproducir las métricas
go run ./cmd/xammu verify --store runs/waf-effectiveness-2026-11-05-r6 --rederive `
  --trust-key trust/waf-effectiveness.pub `
  --authorization authorizations/effectiveness-local-002.json --issuer-keyring trust/issuers
go run ./cmd/xammu effectiveness report --store runs/waf-effectiveness-2026-11-05-r6 `
  --format both --rederive
```

Aceptación local del 2026-11-05, sobre el fixture del repositorio:

| corrida | solicitudes | TP | FN | FP | TN | excluidos |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `r3` línea base (Fase 1) | 600 | 25 | 275 | 8 | 292 | 0 |
| `r6` línea base (Fase 2) | 600 | 25 | 275 | 8 | 292 | 0 |
| `r6` brazo tamper | 600 | 0 | 300 | 0 | 300 | 0 |

En `r6`, el fingerprint identifica `xammu-lab-waf` con apoyo `high` (cabecera + página de error;
33 outcomes con evidencia) y `auto` elige `url_encode_double → sql_comment`. El TPR cae de 8,33 %
a 0,00 % y el FPR de 2,67 % a 0,00 %: la pila no mejora la defensa, la deja ciega también ante los
benignos que antes marcaba como falso positivo. Es una medición de este fixture en esta ventana, no
una afirmación sobre WAF reales. El detalle por clase está en
`runs/waf-effectiveness-2026-11-05-r6/effectiveness-report.md`.

El bundle de eficacia cambia la forma: `effectiveness_cases.jsonl`, `effectiveness_outcomes.jsonl`
y `effectiveness_metrics.jsonl` son la evidencia firmada; `effectiveness-metrics.json` y
`effectiveness-report.md` se publican después del sellado y `--rederive` los compara. El origen del
laboratorio sirve una sola ruta, así que la población benigna lleva un único caso de path y
compensa con búsquedas: un caso que sólo pudiera devolver 404 mediría la ruta ausente, no el WAF.

Una pila tamper que borra el marcador en línea (`base64`) añade la cabecera `X-Xammu-Probe:
<case-id>` y se registra con `marker_header: true`; `auto` nunca la usa y el informe publica el
confundidor. Los casos benignos no llevan marcador por diseño: la puerta lo tolera al cargarlos y
también al re-admitir su valor transformado, sin relajar ninguna otra regla.

---

## Gate de CI/CD y entregables (fase 3)

La Fase 3 convierte la medición en un artefacto que una tubería puede consumir: un documento
versionado, un SARIF para Code Scanning, un informe profesional y una entrega firmada. El gate no
envía tráfico: lee un bundle sellado, aplica una política declarada y devuelve un código de salida.
La política no se descubre: sin `--policy` el comando se niega a ejecutarse.

```powershell
# el bundle que falla la política (r6, TPR 8,33 %) sale 1
go run ./cmd/xammu gate --store runs/waf-effectiveness-2026-11-05-r6 `
  --policy policies/effectiveness-reference.yaml --format markdown

# el bundle que la cumple (r7) sale 0 y escribe la entrega completa firmada
go run ./cmd/xammu gate --store runs/waf-effectiveness-2026-11-05-r7 `
  --policy policies/effectiveness-reference.yaml --format all `
  --out publications/waf-effectiveness-2026-11-05-r7 `
  --signing-key .xammu-signing.ed25519 --trust-key trust/waf-effectiveness.pub

# verificar la entrega: esquema, firma del sobre, sha256 de cada archivo y del manifiesto
go run ./cmd/xammu verify --publication publications/waf-effectiveness-2026-11-05-r7 `
  --trust-key trust/waf-effectiveness.pub
```

- **Códigos de salida:** `0` todos los checks aplicables cumplen la política; `1` un check falla
  (es un resultado sobre el objetivo); `2` el gate no pudo evaluar (CLI, bundle, política o
  evidencia) y el defecto es de la herramienta.
- **Documentos:** `gate --format json` es la fuente autoritativa (`xammu.gate/v1`, esquema en
  `schemas/`); `yaml` indexa los mismos valores; `sarif` produce un resultado por check fallido y
  por finding C-16 sellado; `markdown` es el informe de siete secciones; `annex` y `all` añaden el
  anexo ES/EN. `--format all` exige `--out` y `--signing-key`: sin firma no hay entrega sellada.
- **Entrega sellada:** seis documentos más `publication.json` (`xammu.publication/v1`). El sobre
  firma con Ed25519 sobre `sha256(canonical-json(publication sin los campos de firma))`, lista cada
  archivo con su sha256 y nombra el manifiesto de origen, su digest y su firmante. `verify
  --publication` re-deriva el veredicto desde `gate.json` y la política embebida, así que un
  veredicto re-firmado que sus propios checks no producen se rechaza.
- **Confianza:** `--trust-key` ancla la **identidad del sobre**. El manifiesto de origen debe
  verificar y coincidir con el digest y la clave que el sobre declara; su identidad solo se informa
  como anclada cuando la misma clave lo firmó. La clave privada no se copia al bundle ni a la
  entrega, y `.xammu-signing.ed25519` no está en el árbol.
- **Fingerprint en el informe:** si el objetivo se identifica como el fixture de referencia, el
  resumen y los límites lo dicen: esas cifras demuestran la tubería, no la eficacia de un producto.
- **Pipeline de ejemplo:** [`examples/ci`](examples/ci) declara la ingesta en GitHub Code Scanning,
  GitLab, Azure Pipelines y Jenkins. `scripts/gate-demo.sh` comprueba sin red que r6 sale 1, r7 sale
  0, los SARIF declaran cada regla que citan y ambas entregas publicadas verifican; corre dentro de
  `scripts/ci-local.sh` y del workflow activo.

**El WAF de referencia separado del laboratorio.** `examples/reference-waf` es un fixture de
demostración —no una modificación de `lab/waf` ni una recomendación de producto— que escucha en
`127.0.0.1:8099`, reenvía al mismo origen y usa la misma C-09 `AUTH-EFFECTIVENESS-LOCAL-002` con
`--budget 1200`. Sus reglas son compuestas (marcador **y** forma de la clase), normaliza con hasta
tres pasadas de percent-decode y minúsculas, y bloquea con 403 y `XAMMU-REFERENCE-WAF-BLOCK` sin
ejecutar nada. Un test carga los 600 casos y exige 300 bloqueos de ataque y 300 pasos benignos antes
de gastar una sola solicitud.

| corrida | solicitudes | TP | FN | FP | TN | TPR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `r7` línea base | 600 | 300 | 0 | 0 | 300 | 100,00 % |
| `r7` brazo tamper (`url_encode_double → case_switch`) | 600 | 285 | 15 | 0 | 300 | 95,00 % |

Con `policies/effectiveness-reference.yaml` (umbrales fijados **antes** de la corrida), `r6` sale 1
por `effectiveness.tpr` y `r7` sale 0 con 6 checks aplicables. La comparación base vs tamper entra
como control informativo: 100,00 % → 95,00 %, delta −5,00 pp. El fingerprint identifica
`xammu-reference-waf` con apoyo `high`; la pila candidata es la genérica de cambio de representación,
porque no se publica conocimiento de bypass del fixture. Los sobres de r6 y r7 se publican en
`publications/` y verifican con `trust/waf-effectiveness.pub`.

---

## 9. Qué garantiza `verify` y qué no

Garantiza: el manifiesto satisface C-12, la firma Ed25519 es válida, el payload recomputa, todos
los artefactos listados existen y ningún archivo no listado aparece, el Merkle root recomputa, la
cadena de observaciones es íntegra y el head del manifiesto coincide con la última línea.

No garantiza: que las lecturas sean correctas, ni quién firmó, salvo que se pase `--trust-key`
con una clave obtenida por un canal independiente. `verify` lo dice al terminar, y el código
también: `TestVerifyStatesWhatTheSignatureDoesNotCover` y `TestVerifyAnchorednessIsNotFailure`.

---

## 10. Mapa de paquetes

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
| `internal/effectiveness` | corpus de eficacia, ejecución por brazos, observación y métricas E-01/E-02/E-03 |
| `internal/tamper` | primitivas de re-codificación, pilas de 1–3 y conservación del marcador |
| `internal/fingerprint` | tabla de firmas de WAF, atribución por respuesta y apoyo categórico |
| `internal/annex` | anexo de cliente ES/EN y vista de eficacia, desde el mismo documento |
| `internal/gate` | política, checks, JSON/YAML/SARIF, informe de siete secciones y sobre `xammu.publication/v1` |
| `internal/yamlish` | parser YAML restringido: documentos, mapas, escalares; rechaza lo que no soporta |
| `examples/reference-waf` | fixture de demostración con reglas compuestas y preflight sobre los 600 casos |
| `cmd/xammu` | CLI: `run`, `playbook`, `report`, `verify`, `validate`, `corpus`, `lab`, `effectiveness`, `gate` |

---

## 11. Vocabulario: handoff → CLI

| handoff | implementado | por qué |
| --- | --- | --- |
| `xammu profile` | `xammu run --authorization FILE --authorize REF` | perfilar es la única acción que envía; la segunda bandera obliga a nombrar el permiso que se tiene en la mano |
| `xammu report --format human` | idéntico | `human` y `markdown` son el mismo documento; aceptar ambos mantiene el comando del handoff ejecutable |
| anexo de cliente | `xammu report --format annex\|annex-html --lang es\|en` | no está en el handoff: es el primer entregable de Izkuna, derivado del mismo C-15 y con los campos de evidencia verbatim |
| `xammu validate --hypothesis REF` | `xammu validate --finding REF` (re-derivación de sólo lectura) + `xammu run --validation FILE --parent-run ID` (ejecuta una ronda C-10) | `validate` nunca envía; una ronda de hipótesis es un `run` y necesita su propia autorización |
| `xammu lab up/down/test` | `lab/build.sh`, `verify.sh`, `teardown.sh`; `xammu lab scenarios`; `xammu lab test --scenario [--apply]` | `lab test` sin `--apply` describe; sólo `--apply` toca Docker |

La equivalencia completa y el estado de cada criterio están en
[`docs/acceptance.md`](docs/acceptance.md).

---

## 12. Límites declarados

- **Un objetivo por ejecución.** No hay perfilado multi-objetivo ni comparación entre hosts en un
  mismo run.
- **Sólo HTTP(S) observado.** No hay sniffing, ni análisis de tráfico en vivo, ni integración SIEM.
- **Retención digest-only por defecto en producción.** El cuerpo completo sale del proceso antes
  de la clasificación; el journal conserva digest y, como máximo, los bytes autorizados.
- **Cabeceras sensibles fuera de la evidencia.** `set-cookie`, `cookie`, `authorization`,
  `proxy-authorization`, `x-api-key` y `x-auth-token` se guardan como `[redacted]` con un digest
  salado por ejecución; `--sensitive-header NAME` añade nombres y nunca quita. El valor no se
  escribe en ningún artefacto y el salt no se serializa, así que dos runs no permiten correlacionar
  el mismo valor. Los digests tampoco se pueden recalcular después: es la propiedad buscada.
- **La autorización manda.** Presupuesto, métodos, clases, vectores, codificaciones, rutas,
  CIDRs y caducidad salen de la C-09; las banderas sólo recortan.
- **El anillo de emisores es tuyo.** `--issuer-keyring` no tiene valor por defecto: la clave
  pública debe llegar por un canal independiente del permiso. La semilla del emisor de
  demostración no se conserva, así que esos sidecars no se pueden regenerar.
- **La sonda `/..%2F..%2F` se rechaza en planificación** porque su ruta queda fuera de los
  prefijos autorizados. Es comportamiento correcto de la política de destino y no se relaja; un
  plan de matriz completa que incluya esa sonda se rechaza en `CAL-POS-P-01` y debe estrecharse.
- **CI versionado, aún sin corrida en GitHub.** `.github/workflows/ci.yml` ejecuta `gofmt`, `vet`,
  `go test -race`, `govulncheck`, gitleaks sobre árbol e historial y el build reproducible; en un tag
  `v*` añade SBOM CycloneDX y firma keyless de binario, checksum y SBOM con cosign. Las acciones de
  terceros están fijadas por SHA. El workflow **no se ha ejecutado en un runner externo**: hacer push
  y habilitar `id-token: write` requiere aprobación. La evidencia local es `scripts/ci-local.sh`,
  que imprime `SKIP` para lo que no puede ejecutar.
- **Sin artefacto de release firmado todavía.** `scripts/release.sh` produce el binario y su
  `.sha256`; la firma y el SBOM solo se publican cuando el workflow corre sobre un tag. Sin esa
  corrida no hay `.sigstore.json` que verificar.
- **Sin prueba de utilidad con ingeniero externo.** El protocolo está en `docs/acceptance.md` §5;
  la prueba no se ejecutó y el criterio 16 no se reclama.

---

## 13. Auditar este repositorio en 10 minutos

1. `bash scripts/certify.sh` — formato, vet, build, suite completa, `corpus check`,
   `effectiveness check`, `verify` de los dos bundles de demostración y del bundle de eficacia,
   anexos ES/EN, build reproducible byte a byte y hash del árbol; escribe la evidencia
   en `dist/certification-<UTC>.txt`. Solo `go test ./...` son 428 funciones en 23 paquetes.
2. `bash scripts/ci-local.sh` — espejo local de `.github/workflows/ci.yml`: formato, vet, suite,
   `-race` si hay cgo, `govulncheck` y gitleaks si están en `PATH`, build reproducible, la
   demostración del gate y SBOM si Syft está instalado. Escribe `dist/ci-local-<UTC>.txt` y cada
   `SKIP` queda contado en el resultado.
3. `sed -n '1,80p' docs/acceptance.md` — los 29 criterios con su prueba y lo que falta.
4. `go run ./cmd/xammu verify --run demo-lab --authorization AUTH-SMOKE-LOCAL-001 --authorizations authorizations --issuer-keyring trust/issuers --corpus corpus --class sqli --vector query,body_json,cookie --trust-key trust/demo-lab.pub`
5. `go run ./cmd/xammu report --run demo-origin --authorization AUTH-SMOKE-ORIGIN-001 --authorizations authorizations --issuer-keyring trust/issuers --corpus corpus --format human` — los tres `coverage_gap`.
6. Abre un finding de `runs/demo-lab/report.md` y ejecuta su `reproduction_command`; si el bundle
   se selló antes de 0.1, añade `--issuer-keyring trust/issuers` al comando publicado.
7. Lee `internal/httpclient/egress_test.go` y `internal/contracts/forbidden_source_test.go`: los
   invariantes de «un solo egress» y «ninguna escala numérica» son tests, no prosa.

---

## 14. Documentos

- [`docs/audit-handoff.md`](docs/audit-handoff.md) — handoff de auditoría: qué hace XAMMU, cómo y por qué,
  alcance incluido y excluido, análisis de seguridad de la infraestructura, hallazgos priorizados y mejoras.
- [`docs/certification.md`](docs/certification.md) — expediente de aceptación interna de Izkuna:
  artefacto y anclaje por hash, cómo reproducirla, invariantes de seguridad, modelo de amenaza,
  límites, brechas abiertas y tabla de firma.
- [`docs/acceptance.md`](docs/acceptance.md) — matriz de los 29 criterios, definición de
  terminado, desviación de §9.3, protocolo de la prueba de utilidad y qué garantiza `verify`.
- [`docs/gate-output.md`](docs/gate-output.md) — formato de `gate.json`, `gate.yaml`, `results.sarif`,
  `report.md`, los anexos y `publication.json`, y qué comprueba `verify --publication`.
- [`examples/ci`](examples/ci) — workflow de GitHub Code Scanning y snippets de GitLab, Azure
  Pipelines y Jenkins para consumir el código de salida, la política y el SARIF.
- [`examples/reference-waf`](examples/reference-waf) — fixture de demostración fail/pass, con su
  preflight sobre los 600 casos y sus límites declarados.
- [`lab/README.md`](lab/README.md) — reconstrucción del fixture, comportamientos, límites y
  decisiones documentadas.
- [`corpus/README.md`](corpus/README.md) — particiones, controles de calibración y límites del
  corpus.
