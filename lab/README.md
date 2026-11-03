# Laboratorio XAMMU v1.0.0 — guía de reconstrucción

Este archivo es el único entregable documental del laboratorio. Su criterio de aceptación es el *definition-of-done* del proyecto: «la guía de laboratorio permite a un tercero reconstruirlo sin decisiones no documentadas». Todo lo afirmado aquí está en `compose.yaml`, `DIGESTS.txt`, `build.sh`, `verify.sh`, `teardown.sh`, `origin/` y `waf/`; los `file:línea` citados son comprobables. Donde el código no lo afirma, se dice «no documentado». `rules.go:44` remite explícitamente a este archivo para explicar su invariant central; esa remisión se cierra en la sección 3.

## 1. Qué es y qué NO es este laboratorio

**Es** un banco de pruebas con comportamiento deliberadamente evadible, cuyas lagunas están fijadas en una tabla de reglas escrita a mano y en un conjunto de sondas cerrado. Su única función es demostrar que los detectores de XAMMU detectan: si el perfilador no produce el conjunto de hallazgos de la sección 2, el defecto está en XAMMU, no en el laboratorio.

**No es**, y estas negaciones son vinculantes:

- **No es un benchmark de ningún WAF comercial.** No compara productos ni clasifica a nadie. Ambas imágenes lo declaran en sus labels: `ai.xammu.lab.not-a-benchmark="true"` (`origin/Dockerfile:38`, `waf/Dockerfile:26`).
- **No es una afirmación de seguridad sobre ningún sistema.** Ninguna respuesta de este laboratorio autoriza a escribir «el WAF X es inseguro». El fixture imita *una* configuración plausible —inspección sólo sobre *query string*, normalización de una pasada, *body parsing* desactivado— y nada más.
- **No es un exploit ni contiene exploits.** Las sondas conservan los rasgos léxicos que casa cada firma y eliminan todo lo que pudiera ejecutarse: `XSS-001` es una apertura de etiqueta sin manejador ni cierre; `XSS-002` es un prefijo de esquema con la zona tras los dos puntos vacía; `CMD-001` nombra un separador, nunca un binario; `TRAVERSAL-001` referencia una ruta que no existe en ningún lado. La regla de proyecto es absoluta y está escrita en `verify.sh:43`: *si un payload puede explotar, no entra al corpus*, coherente con la puerta de inertez del corpus (`CorpusItem.Inertness`, `Verdict: InertVerified`, en `internal/contracts`).
- **XAMMU perfila comportamiento defensivo y nunca explota.** No hay ninguna ruta del laboratorio que un tercero pueda usar para comprometer algo: el origen no rechaza nada (`origin/main.go:179-181`), su única «base de datos» es un eco JSON, y la zona de administración devuelve un 502 constante.
- **Un tercero no puede describir las lagunas de este fixture como vulnerabilidades reales.** La brecha del cuerpo JSON es una decisión de configuración del proxy de pruebas, anotada tal cual en `rules.go:131-135`. Redactarla como riesgo contra un producto real sería una atribución falsa, y el contrato C-16 la rechazaría (techo de `claim_type: association` con `attribution_status: compatible`).

**Prueba de reproducibilidad.** El criterio 22 del proyecto es vinculante aquí: `docker-compose.yml` **nunca** se presenta como prueba de reproducibilidad. La prueba son dos artefactos comprobables: `DIGESTS.txt` (los IDs de imagen registrados por `build.sh`) y `verify.sh` (ejecutable, que los coteja contra los contenedores **en ejecución** y reafirma los cinco comportamientos). El propio `compose.yaml` lo declara en sus líneas 26-33 y `DIGESTS.txt` en las 4-7. Un archivo de composición con `DIGESTS.txt` desactualizado o sin una corrida verde de `verify.sh` no demuestra nada.

## 2. Los cinco comportamientos esperados

Cada comportamiento tiene una fila en `rules.go` (o un paso explícito de `inspect.go`) y un tipo de hallazgo esperado del contrato C-16 (`internal/contracts/enums.go:281-287`).

| # | comportamiento | regla o mecanismo | por qué es determinista | tipo de hallazgo esperado |
|---|---|---|---|---|
| 1 | Sonda con forma SQL bloqueada en *query* y reenviada en `json_body` | `SQLI-001` casa en query; **ninguna** fila lista `VectorJSONBody` (`rules.go:148-154`, `inspect.go:276-283`) | La ausencia es estructural: `UninspectedVectors()` es el complemento de `InspectedVectors()` sobre `AllVectors` (`rules.go:260-275`) y el proceso la autodeclara | `vector_asymmetry` (el WAF es coherente con su propia tabla: §2.1). El `coverage_gap` de la misma célula sólo aparece midiendo el **baseline sin defensa** (§2.6) |
| 2 | XSS canónica bloqueada, single-encoded bloqueada, **double-encoded reenviada** | `XSS-001`/`XSS-002`/`SQLI-001`/`SQLI-003`/`TRAVERSAL-001`/`CMD-001` evaluadas sobre `Candidate.Decoded()` (`inspect.go:41-68`) | Una sola pasada de decodificación, sin bucle y sin caso especial por profundidad (sección 3) | `encoding_bypass_pattern` |
| 3 | Valores de cabeceras personalizadas y nombres de cookie fuera de política nunca inspeccionados | `DiagnosticHeaderPrefixes` (`rules.go:298`), `InspectedCookiePrefixes` (`rules.go:305`), `POLICY-HEADER-NAME` (`inspect.go:151-165`) | Prefijos y tabla son literales fijos; el veredicto se decide por **nombre**, nunca por valor | `coverage_gap` (+ `vector_asymmetry` en el par mismo-token/distinto-nombre) |
| 4 | Texto legítimo con un apóstrofo suyo bloqueado mientras las 10 `protectedContractions` pasan | `SQLI-001` con `Allowlist: protectedContractions` (`rules.go:114-116,148-154`); `SQLI-002` para comilla doble | Corpus y allowlist fijos, sin heurística: 6/6 pasan, 6/6 se bloquean, tasa exacta `0.500` (`verify.sh:353-378`) | `over_blocking` |
| 5 | `/api/admin` y `/api/admin/*` respondidos 502 por el origen: el control negativo es inválido | `handleAdmin` (`origin/main.go:152-164`), alcanzada por el proxy sin intervención | Sin estado, sin log, sin azar: probe y control dan el mismo 502, así que la comparación no discrimina | `undetermined_area` |

### 2.1 Comportamiento 1 — hueco de vector (`json_body`)

`SQLI-001` (`rules.go:148-154`) es un `regexRule` con `Pattern: '` y `Vectors: [query_string]`. La sonda `q=%27%20or%201%3d1%20xammu-probe` decodifica una vez a `' or 1=1 xammu-probe`, casa, y el paso 2 de `inspectRequest` devuelve 403 atribuido a `SQLI-001`. El cuerpo idéntico `{"q": "' or 1=1 xammu-probe"}` se reenvía: `jsonBodyValues()` se invoca **sólo para contabilidad** y sus candidatos se anotan en `coverage.NotInspected` con el motivo literal `no rule in rules.go lists the json_body vector` (`inspect.go:280`). `verify.sh` lo fija en 15 comprobaciones del bloque B1, incluida la que exige que la *signature* del valor del cuerpo sea idéntica a la del valor bloqueado en query.

Tres detalles que un tercero tendría que adivinar si no se escriben:

- El control existe y es duro: el mismo cuerpo enviado directo a `http://origin:8081/api/search` devuelve 200 (`verify.sh:250-251`) porque el origen **nunca** rechaza nada. Sin ese control, «200» no probaría nada.
- El hueco afecta sólo a cuerpos JSON. Un cuerpo `application/x-www-form-urlencoded` ni siquiera se contabiliza —`jsonBodyValues` exige media `application/json` o `+json` (`inspect.go:398-402`)— y por tanto no aparece en `not_inspected`. `verify.sh:266-267` afirma que pasa (200) pero no lo contabiliza.
- La traducción de vocabulario no es manual: el fixture llama `json_body`/`query_string` a sus vectores y el contrato XAMMU usa `body_json`/`query` (`enums.go:236-244`), y el puente vive en código, en `internal/labctl/vocabulary.go`. Un nombre que el puente no conoce **no se deja pasar**: `Vector()` y `Encoding()` devuelven error, porque un transporte que conserva la ortografía del fixture llega invisible a quien compara dos corridas. `lab/scenarios.json` declara los pares que este build entiende y `xammu lab scenarios` los imprime.

Hallazgo publicado por una corrida contra el WAF: **`vector_asymmetry`**, no `coverage_gap`. La diferencia importa y es el punto del fixture: el WAF bloquea en query y reenvía en el cuerpo *de forma coherente con su propia tabla de reglas*, así que ningún reading contradice la expectativa declarada del corpus y `coverageGaps` no dispara. El `coverage_gap` de la misma célula exige medir el mismo corpus contra el origen, donde la expectativa declarada sí se contradice; eso es §2.6.

### 2.2 Comportamiento 2 — bypass por codificación

Las gradaciones que `verify.sh` afirma con `--only B2`:

| entrada (`q=`, `x=`, `t=`, `c=`) | tras UNA decodificación | veredicto | regla |
|---|---|---|---|
| `<xammu-probe-script` | igual | 403 | `XSS-001` |
| `javascript:xammu-probe` | igual | 403 | `XSS-002` |
| `'+or+1=1+xammu-probe` | `' or 1=1 xammu-probe` | 403 | `SQLI-001` |
| `%3Cxammu-probe-script%3E` | `<xammu-probe-script` | 403 | `XSS-001` |
| `%27%20or%201%3d1%20xammu-probe` | `' or 1=1 xammu-probe` | 403 | `SQLI-001` |
| `%6aavascript%3Axammu-probe` | `javascript:xammu-probe` | 403 | `XSS-002` |
| `%2e%2e%2f%2e%2e%2fxammu-probe` | `../../xammu-probe` | 403 | `TRAVERSAL-001` |
| `%3b%20xammu-probe%20%3b` | `; xammu-probe ;` | 403 | `CMD-001` |
| `%253Cxammu-probe-script%253E` | `%3Cxammu-probe-script%3E` | **200** | — |
| `%2527%2520or%25201%253d1%2520xammu-probe` | `%27%20or%201%3d1%20xammu-probe` | **200** | — |
| `%252e%252e%252f%252e%252e%252fxammu-probe` | `%2e%2e%2f%2e%2e%2fxammu-probe` | **200** | — |

El doblemente codificado sobrevive a la pasada conservando sus propios escapes: no queda apóstrofo literal, ni espacio, ni `=`, así que tampoco `SQLI-003` (`(?:'|%27|--|#|;)\s*(?:or|and)\s*1\s*=\s*1`) puede casar. La alternativa `%27` de `SQLI-003` existe para entradas *parcialmente* codificadas; no vuelve a colapsar un valor ya doblemente codificado, porque el emparejamiento ocurre después de la única pasada.

El origen corrobora la profundidad por su cuenta: `POST /internal/normalize` devuelve `received=`, `after_one_decode=` y, sólo en el caso doble, `a_second_decode_would_yield=` con la coletilla «origin does NOT perform a second decode» (`origin/main.go:249-340`). `verify.sh` lo convierte en tres comprobaciones de B2, una de ellas negativa: el single-encoded **no** produce `a_second_decode_would_yield`.

Hallazgo esperado: `encoding_bypass_pattern`, con `Encoding: url_single` frente a `url_double` (`enums.go:256-274`).

### 2.3 Comportamiento 3 — vectores nunca inspeccionados

Son tres mecanismos distintos y hay que mantenerlos separados:

- **Valores de cabeceras de diagnóstico.** `DiagnosticHeaderPrefixes = {"x-lab-probe-", "x-xammu-"}`; sus valores se materializan como candidatos del vector `header_value_uninspected` y van a `not_inspected` (`inspect.go:253-260,318-344`). Por eso `X-Lab-Probe-Payload: ' or 1=1 xammu-probe` pasa (200) y el mismo centinela en `User-Agent` se bloquea (403, `GENERIC-001`): **el hueco es específico, no «las cabeceras no se miran»**, y esa distinción está anotada en `rules.go:312-314`.
- **Nombres de cookie fuera de política.** `InspectedCookiePrefixes = {"lab_probe", "xammu-"}`. `lab_probe_payload=xammu-probe-token` → 403 `GENERIC-001`; `xammu_probe_payload=xammu-probe-token` → 200. El prefijo es `xammu-` con guion, no `xammu_`. El mismo token, bloqueado en un nombre e ignorado en el otro: es la evidencia de `vector_asymmetry` más limpia del laboratorio. En el nombre inspeccionado también casa `TRAVERSAL-001` cuando el valor es un traversal (`verify.sh:317-319`).
- **La política por nombre de cabecera.** `POLICY-HEADER-NAME` (`rules.go:287-293`, `inspect.go:151-165`) se evalúa en el paso 1, **antes** que toda la tabla, así que siempre gana en atribución. Casa por presencia del nombre sin tocar el valor: `X-Lab-Probe-Transfer-Encoding: chunked` (valor protocolariamente válido e inocuo) se bloquea, la variante en minúsculas también, y el casi-acierto `X-Lab-Probe-Transfer-Encoded` no —coincidencia exacta de nombre, no de prefijo—.
- Limitación honesta: el origen sólo devuelve en `params.headers` las cabeceras con prefijo `x-lab-` (`origin/main.go:224`), así que la llegada al origen de una cabecera `x-xammu-…` **no es observable** desde la respuesta y `verify.sh` no la afirma.

### 2.4 Comportamiento 4 — sobre-bloqueo medible

`SQLI-001` lleva `Allowlist: protectedContractions...`, y `Rule.Matches` (`rules.go:85-103`) sale antes si el candidato —ya decodificado una vez y en minúsculas— contiene alguna de esas literales. El fixture imita a un administrador que añadió excepciones de frase para las contracciones inglesas más comunes y nada más. Las 10: `don't`, `it's`, `can't`, `won't`, `i'm`, `let's`, `that's`, `there's`, `what's`, `isn't`.

El corpus que ejecuta `verify.sh` tiene 12 términos: 6 contracciones protegidas (200) y 6 textos legítimos bloqueados (403). La tasa de falsos positivos se fija como valor exacto `0.500`, calculado por la propia prueba, y las atribuciones se exigen por nombre: `O%27Brien` → `SQLI-001`, `%22quoted%20phrase%22` → `SQLI-002`. Que el sobre-bloqueo es del WAF y no de la aplicación se prueba enviando las dos consultas bloqueadas directo al origen: ambas devuelven 200.

Un tercero debe saber que **4 de las 10 contracciones (`that's`, `there's`, `what's`, `isn't`) están en la tabla pero no se ejercitan en `verify.sh`**: su comportamiento se deduce del código, pero no está afirmado por la prueba.

Hallazgo esperado: `over_blocking`. El contrato C-16 exige `measured_impact` con población y denominador para los hallazgos de cobertura (`contracts/finding.go:189-197`); por eso la tasa se mide sobre un corpus cerrado de 12 términos y no se estima.

### 2.5 Comportamiento 5 — zona no evaluada

`handleAdmin` responde 502 JSON con `source: "origin"` y `error: "upstream_unavailable"` para `/api/admin` y para cualquier ruta con prefijo `/api/admin/` (`origin/main.go:152-164`), en GET y en POST, anidado o con segmentos codificados. El WAF la reenvía sin intervenir: el 502 no lleva `X-Lab-Waf-Rule` ni el token de bloqueo, y `verify.sh` lo comprueba.

Lo que invalida la zona es el par probe/control: una sonda bloqueable en un path de admin **sí** produce su 403 (la zona no está exenta), pero una sonda limpia y su control producen el mismo 502, así que ninguna diferencia observable es atribuible a una decisión defensiva. El perfilador debe declarar la zona como no evaluada en lugar de puntuarla.

Hallazgo esperado: `undetermined_area`, que el contrato obliga a `claim_type: descriptive` y `attribution_status: undetermined`, con `unevaluated_reason` obligatorio (`contracts/finding.go:170-185`). Qué código asigna XAMMU está implementado, no supuesto: `internal/inference/cell_records.go` comprueba **antes** que nada si todas las pruebas de la célula vienen de un origen en 5xx (`everyTrialFromAFailingOrigin`) y entonces tipifica `origin_unstable`; `statusTally` añade los códigos observados al detalle para que el 502 no viaje como una cifra sin explicación. El clasificador cierra la otra mitad (`internal/classifier/classifier.go:203`): un 5xx que ningún detector lee como rechazo **nunca** es manejo ordinario, porque un destino roto no es una abstención del front end y llamarlo normal convierte una zona no medida en una cobertura limpia. `control_invalid` queda para el caso en que el control mismo no es válido, que no es éste.

### 2.6 El baseline sin defensa: dónde aparecen los `coverage_gap`

Los cinco comportamientos de arriba describen el WAF. Una sexta lectura, que no es un comportamiento del fixture sino su complemento, mide el **origen solo**: es la única forma de que el tipo `coverage_gap` aparezca con este corpus, porque el corpus declara `expect_block` para las sondas de query y el origen las reenvía todas.

- Autorización propia: `authorizations/smoke-origin-baseline.json` (`AUTH-SMOKE-ORIGIN-001`), que cubre el puerto 8081 y nada más. Está separada de `AUTH-SMOKE-LOCAL-001` a propósito: un permiso que cubre WAF y origen a la vez permitiría presentar como «el front end no bloquea» una lectura en la que no hubo front end.
- Comando: `xammu run --authorization AUTH-SMOKE-ORIGIN-001 --authorize AUTH-SMOKE-ORIGIN-001 --authorizations authorizations --corpus corpus --class sqli --vector query --target http://origin:8081` (desde `netrunner`, que es quien resuelve `origin`).
- Lectura publicada: `coverage_gap` sobre `sqli × query × {canonical, case_variant, url_single}` en `/api/search`. El WAF responde 403 a las tres y el origen 200 con su forma JSON normal; la contradicción con `expect_block` es lo que el detector mide.
- Lo que **no** prueba: que el origen sea explotable. El 200 del origen es la respuesta de una aplicación de juguete que nunca rechaza nada, y por eso el hallazgo es `coverage_gap` —la expectativa declarada no se cumple— y no una afirmación sobre vulnerabilidad. Las limitaciones del hallazgo lo dicen en cada corrida.

Los diez escenarios que citan los informes de este laboratorio —y sus comprobaciones, una por una— están en `lab/scenarios.json`; `xammu lab scenarios` los lista y `xammu lab test --scenario NAME` dice exactamente qué ejecutaría.

## 3. La invariant de carga: decodificación exacta una vez

`rules.go:44-52` la enuncia como el diseño crucial del fixture:

> *a candidate is percent-decoded EXACTLY ONCE before Pattern is evaluated.*

Su implementación es literal: `Candidate.Decoded()` (`inspect.go:41-68`) hace **un único** `url.QueryUnescape` (query) o `url.PathUnescape` (resto), devuelve una nota con lo hecho (`decoded_once`, `decoded_once_no_change`, `malformed_percent_escape:left_candidate_unjudged`) y no existe ningún bucle de normalización. `coverage.DecodePasses` es la constante 1 (`inspect.go:109-116`) y `verify.sh` exige que `/__lab/info` lo declare.

Esto es lo que convierte el bypass de 2.2 en **una propiedad de configuración** y no en un truco de laboratorio: normalizar una sola vez es el comportamiento por defecto razonable de un WAF de producción, y el patrón que lo sigue —un valor que conserva sus propios escapes tras la única pasada— es exactamente lo que un perfilador debe aprender a buscar. Que el fixture no tenga caso especial para la doble codificación es demostrable, no una afirmación de buena fe:

- Ninguna `Pattern` de la tabla contiene `%25` ni la palabra `double`. Todas las apariciones de `double` y `25` en `rules.go` están en comentarios que documentan la consecuencia (`:49-51`, `:141-144`) y en la `Description` de `SQLI-002`, «bare double quote», que habla del carácter `"` y no de profundidad de codificación.
- No hay ninguna segunda llamada a `Decoded()` en el camino de decisión. El único lugar con profundidad multi-pasada es `SignatureOf` (`inspect.go:479-491`, bucle de hasta 8 colapsos), y su propio comentario dice lo contrario: sólo se usa para contabilidad; el emparejamiento sigue siendo de una pasada.
- Tampoco hay plegado en el transporte: el motor nunca reescribe la petición (`inspect.go:1-5`) y el *director* del proxy conserva path y *raw query* byte a byte, con `req.Host = ""` para que el destino salga de `WAF_ORIGIN_URL` (`proxy.go:98-105`). Lo que envía el cliente es lo que lee el origen, así que el bypass no puede achacarse a una re-codificación del proxy.
- Consecuencia ortogonal y también determinista: si el escape es *malformed*, `judged` es `false` y el candidato queda sin juzgar (`inspect.go:173-176`) en vez de adivinarse. Es una segunda clase de evasión, declarada.
- Detalle que hay que conocer para no asustarse ante una diferencia: la pasada de query además traduce `+` a espacio *dentro de la misma pasada*; el resto de vectores no. Por eso `q='+or+1=1…` se bloquea mientras un `+` en el valor de una cookie permanece literal.

Si un lector sospecha que el laboratorio está amañado, la comprobación que resuelve la duda es ésta: la tabla no menciona la doble codificación; sólo la menciona la documentación, que es donde debe estar.

## 4. Anclaje de control: `GENERIC-001`

`GENERIC-001` (`rules.go:210-221`) es un `keywordRule` con patrón `xammu-probe-token` —obsérvese el sufijo `-token`: la sola palabra `xammu-probe` **no** la activa— y `Vectors: [path, query_string, header, cookie]`, es decir, todos los vectores inspeccionados **menos** `json_body`. Su propósito real, dicho sin adornos, es doble:

1. **Decidir si hubo o no decisión defensiva.** Un rechazo es siempre 403 + `text/html; charset=utf-8` + `XAMMU-LAB-WAF-BLOCK` dentro del `<title>`; un reenvío es la respuesta JSON del origen con `"source": "origin"`. El bloque S de `verify.sh` fija que los tres estados (bloqueo, error de origen, tráfico limpio) se distinguen por clase de estado, `Content-Type`, `Server` y longitud de cuerpo; el bloque K añade que el bloqueo **sigue produciéndose** sin cabeceras giveaway.
2. **Demostrar que un transporte no fue leído.** Un centinela que viaja en el cuerpo JSON y llega al origen prueba que el *body vector* no se inspeccionó, porque esa misma cadena está bloqueada incondicionalmente en cualquier vector que el fixture sí lee. Esa comparación es lo que vuelve medible —en lugar de assertiva— la afirmación del comportamiento 1.

El límite, y es el punto honesto de esta sección: **desde evidencia HTTP el perfilador no puede distinguir «inspeccionado y aprobado» de «no inspeccionado».** Ambas producen el mismo 200 del origen. Lo que las distingue en este fixture es `/__lab/coverage`, con sus campos `would_match_rule` y `vector_inspected` calculados por `shadowMatch` (`coverage.go:104-109,346-358`) —y leer eso está prohibido en la sección 7, porque sería leer configuración, no perfilar comportamiento—. Por lo tanto, un hallazgo derivado del centinela lleva `attribution_status: compatible` y nada más: «la observación es compatible con comportamiento de WAF pero no excluye alternativas; evidencia HTTP sólo» (`enums.go:113-115`), con techo de claim `association`.

Firmeza empírica: `verify.sh` afirma la asimetría del centinela entre `User-Agent` (403) y `X-Lab-Probe-Payload` (200), entre nombres de cookie (403/200), y que el centinela en query da 403 con cuerpo HTML. El caso literal «centinela dentro del cuerpo JSON hasta el origen» **no** está afirmado con el token en el cuerpo: B1 lo afirma con la sonda de forma SQL. La conclusión para el centinela se sigue del código (ninguna fila lista `json_body`), pero conviene saber que la prueba no lo ejercita.

## 5. Cómo reconstruirlo

### 5.1 Requisitos

- **Docker Desktop** con **Compose v2+** (`docker compose`, no `docker-compose`) y **buildx** (viene con Docker Desktop). Es el único requisito duro de `build.sh` y `verify.sh`.
- **Git Bash en Windows.** Los tres scripts son POSIX (`#!/usr/bin/env bash`, `set -euo pipefail` / `set -uo pipefail`) y están en **LF** —verificado en `build.sh`, `verify.sh`, `teardown.sh`, `compose.yaml` y `DIGESTS.txt`—. Un checkout con `core.autocrlf` que inyecte CR rompe las comparaciones de `verify.sh`.
- **Go en el host: no es necesario** para reconstruir. La compilación ocurre dentro de los Dockerfiles multi-etapa contra un `golang:1.27-alpine` fijado por digest; `build.sh:4-8` lo declara y el script no invoca el `go` del host. Un toolchain local sólo hace falta para compilar o revisar el código a mano. (Nota: el comentario de `build.sh:7` alude a un `./lint.sh` opcional; **ese archivo no existe en el laboratorio y su comportamiento no está documentado**, y `build.sh` no lo llama.)

### 5.2 Comandos, en este orden y nada más

```bash
cd /d/Xammu/lab
bash build.sh        # compila las 2 imágenes y reescribe DIGESTS.txt
bash verify.sh       # arranca, afirma B1-B5 + S + K, hace teardown. 134/134
bash teardown.sh     # parada idempotente y limpia (aunque verify.sh ya la hizo)
```

Variantes documentadas en `verify.sh:9-12`:

```bash
KEEP_LAB=1 bash verify.sh     # deja el laboratorio vivo para inspección manual
bash verify.sh --no-down      # equivalente
bash verify.sh --only B2      # un solo bloque: B1 B2 B3 B4 B5 S K
bash teardown.sh --rmi        # además elimina las imágenes; exige volver a build.sh
```

Qué hace cada uno:

- `build.sh`: comprueba que los digestos base fijados en los Dockerfiles son los que el registro sirve realmente (`:47-70`; aborta si upstream se movió), tira del runner declarado en `compose.yaml`, construye ambas imágenes con `--pull=true --platform linux/amd64 --provenance=false --sbom=false`, y **reescribe** `DIGESTS.txt` (no añade: es idempotente).
- `verify.sh`: `docker compose down --remove-orphans` y luego `up -d --wait --wait-timeout 120`; afirma `healthy` en los 4 contenedores; lee los `image_id` de `DIGESTS.txt` y los coteja contra `.Image` de los contenedores **en ejecución**; ejecuta las sondas **dentro** de `netrunner` (`docker compose exec -T netrunner`); termina con `teardown.sh`.
- `teardown.sh`: hace `down` dos veces (por proyecto y por archivo), borra los 4 contenedores por nombre y la red `xammu-lab-net`, y luego **reporta en vez de asumir**: cualquier residuo se nombra y el script sale 1.

Total esperado de una corrida completa: **134 comprobaciones** (UP 10, B1 15, B2 17, B3 16, B4 20, B5 13, S 13, K 28, DOWN 2). Con `--only X` el total es menor porque `ck` filtra por sección: no compare totales entre modos.

Y el lado de XAMMU, que es una cosa distinta de reconstruir el fixture:

```bash
cd /d/Xammu
go run ./cmd/xammu lab scenarios                       # las 10 escenas, con tipo, sondas y comando que las publicó
go run ./cmd/xammu lab test --scenario NOMBRE           # qué ejecutaría; no ejecuta nada
go run ./cmd/xammu lab test --scenario NOMBRE --apply   # construye, arranca y corre los checks en netrunner
```

Sin `--apply` el comando sólo lee el manifiesto y describe; `--apply` es la única forma en que toca Docker, porque levantar un perímetro en una máquina es una acción y no una lectura. Cada nombre que un informe publica existe en `scenarios.json`, y hay un test (`internal/discover/lab_names_test.go`) que falla si un nombre citado deja de existir o si una escena del manifiesto no la cita ningún hallazgo medido.

### 5.3 Qué contiene `DIGESTS.txt` en la corrida registrada

No se edita a mano; `build.sh` lo regenera. Extracto verbatim del estado que pasó 134/134:

```
[images]
xammu-lab-origin:1.0.0  image_id=sha256:94286dbfb8a0991002b27caf47814b2b47fe77028e6c899fabec08d2b5a5d209
xammu-lab-waf:1.0.0     image_id=sha256:7ea3616a1070243aaa01c3d7b143ac0d8c05bb5bcaf253a566e04eedf0f1a8be

[manifest_digests]
# Recorded only when buildx reported one; 'not_reported' means the local
# docker-driver build returned no OCI manifest digest. Nothing here is guessed.
xammu-lab-origin:1.0.0  manifest=sha256:94286dbfb8a0991002b27caf47814b2b47fe77028e6c899fabec08d2b5a5d209
xammu-lab-waf:1.0.0     manifest=sha256:7ea3616a1070243aaa01c3d7b143ac0d8c05bb5bcaf253a566e04eedf0f1a8be

[pinned_base_images]
# The FROM lines of origin/Dockerfile and waf/Dockerfile, verified against the
# registry at build time. ./build.sh aborts if they no longer match.
  docker.io/library/alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc
  docker.io/library/golang:1.27-alpine@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb

[runner_image]
# Declared in compose.yaml, pulled not built. Pinned by digest at point of use.
  docker.io/curlimages/curl@sha256:d9b4541e214bcd85196d6e92e2753ac6d0ea699f0af5741f8c6cccbfcf00ef4b
```

Lectura honesta de ese bloque:

- La identidad autoritativa de una imagen construida en local es el **`image_id`** (sha256 del *config* de imagen). Eso es lo que compara `verify.sh`.
- `manifest=` se toma del campo `containerimage.digest` del metadata-file de buildx **sólo si buildx lo reportó**; si no, se escribe literalmente `not_reported`. **Nada de eso se adivina**, y esa es la frase que hay que citar cuando alguien pregunte por qué falta un digest. En la corrida registrada buildx sí reportó uno y coincide con el `image_id`; `verify.sh` nunca afirma los manifest, así que la coincidencia no carga ninguna demostración.
- `[source_fingerprints]` guarda el sha256 de los 8 ficheros que entran a las imágenes más los 2 Dockerfiles —p. ej. `waf/rules.go` → `5d62a3f7dd27bbcff8e86ea321182ab3f6a13aa5fcff42e24f0f716e8fbed83a`, `origin/main.go` → `8e05c879cbc786e40810014dc583673f5a726dfcd1054a5e000ff4d67fc434e9`—, para que un cambio de código sea visible sin reconstruir.
- `[image_metadata]` fija `size_bytes` (origin 21567056, waf 22949303), `created`, `docker=Docker version 29.8.2, build 7fc2dff`, `platform=linux/amd64`, la línea de compilación (`CGO_ENABLED=0 -trimpath -buildid= -s -w`), `attestations=provenance=false,sbom=false` y `store=overlayfs`.
- Los labels `ai.xammu.lab.behaviors` de cada imagen dicen dónde vive cada comportamiento: el origen aporta `B5-undetermined-area` y el papel de control en `B3`; el WAF aporta los cinco.

Alcance real de la promesa de reproducibilidad, dicho con precisión: lo que `build.sh` demuestra y `verify.sh` coteja es que **dos construcciones consecutivas de fuentes idénticas en esta máquina resuelven al mismo ID** (con `--provenance=false --sbom=false`; con los valores por defecto cada rebuild acuñaba un ID nuevo —`b397a888 -> 64a72698`— con config byte a byte idéntico, medido en `build.sh:86-97`). El laboratorio **no** afirma que el mismo ID vaya a salir en cualquier otra versión de Docker o de BuildKit: por eso el flujo correcto en una máquina nueva es `build.sh` (reescribe `DIGESTS.txt`) **y después** `verify.sh`.

### 5.4 Re-pinning de imágenes base

Procedimiento copiado verbatim de `[repin_procedure]` en `DIGESTS.txt` (y de `build.sh:182-186`):

```
1. docker buildx imagetools inspect <image>:<tag>   # list current manifest digests
2. replace the sha256 in origin/Dockerfile AND waf/Dockerfile (both must match)
3. ./build.sh    # rewrites this file, aborting if a pin no longer resolves
4. ./verify.sh   # asserts the running containers match this file
```

Restricciones que hay que respetar porque están en el código, no son sugerencias:

- Los digestos base viven **en los Dockerfiles**, no en `compose.yaml` ni en este archivo. Ambos Dockerfiles deben coincidir, o `build.sh` aborta.
- Si se cambia un pin cambian las dos `image_id`: `build.sh` es obligatorio antes de `verify.sh`, y `verify.sh` fallará si alguien edita el pin sin re-ejecutar el build.
- La verificación contra el registro es de **pertenencia**, no de igualdad del primer `RepoDigest`: una imagen tirada por digest puede registrar varios (el *index* y el manifiesto de plataforma), como explica `build.sh:58-68`. Esto es una corrección real, no cosmética.
- `verify.sh` **no** invoca `build.sh`; el comentario de `build.sh:96-97` lo afirma y no se cumple en el estado actual del repo (véase §9).
- El runner (`curlimages/curl@sha256:d9b4541e…`) se declara fijado por digest en el punto de uso (`compose.yaml:125`) y se comprueba en el preflight de `build.sh:72-75`. No se construye.

## 6. Decisiones que un tercero tendría que adivinar sin este archivo

Cada punto es una decisión presente en el repo cuya **razón** sólo está en los comentarios de los ficheros. Aquí se consolidan.

1. **Red `internal: true` y cero puertos publicados.** El requisito era «sin puertos publicados en 0.0.0.0» y se satisface en la forma más fuerte: ningún servicio declara `ports:`. No es decoración: con `internal: true` Docker no asigna puerta de enlace por defecto, así que un puerto publicado **de todos modos sería inalcanzable**. Eso se **verificó en esta máquina, no se supuso**: un contenedor alpine en la red interna con `127.0.0.1:28642` publicado devolvió «connection refused» (curl exit 7) desde el host (`compose.yaml:15-24`). Consecuencia operativa: **las sondas corren dentro de la red**, en `netrunner` (`verify.sh:105-139`), y nada que no esté ya en `xammu-lab-net` puede hablar con el laboratorio. Quien intente `curl localhost:8080` no está ante un bug: está ante el diseño.
2. **Endurecimiento del contenedor** (`x-lab-defaults`, `compose.yaml:37-55`, aplicado a los cuatro servicios):
   - `security_opt: [no-new-privileges:true]` — ningún binario setuid puede escalar dentro.
   - `cap_drop: [ALL]` — los binarios Go escuchan en puertos > 1024, así que no hace falta ninguna capacidad; sin `CAP_NET_*` el fixture no puede sniffar ni reescribir tráfico, lo cual sería una vía para *falsificar* evidencia.
   - `read_only: true` + `tmpfs: /tmp:size=16m,mode=1777` — el único lugar escribible muere con el contenedor. No hay **ningún** mount de host en el archivo y ningún secreto es alcanzable desde ningún contenedor; los 16 MB son los que usan `/tmp/b` y `/tmp/h` de `netrunner`.
   - `pids_limit: 128` — un bucle de sondas descontrolado no agota el daemon.
   - `restart: "no"` — un fixture que muere no resucita en silencio: la corrida se queda fallando en vez de esconderse.
   - `init: true` — *reaping* de zombis y SIGTERM correcto en los cierres.
   - `logging: json-file`, `max-size: 1m`, `max-file: 2` — disco acotado; el log no es evidencia de nada.
   - Usuarios numéricos no root: `USER 65534:65534` en ambos Dockerfiles y `user: "1000:1000"` para `netrunner` en compose. `origin/Dockerfile:43-46` da la razón: 65534 es el `nobody` preexistente de alpine, así que no se crea ningún usuario en el build y el contenedor no necesita escribir `/etc/passwd`, lo cual importa precisamente porque el sistema de ficheros raíz es read-only.
3. **Origen y WAF en contenedores separados.** Razones verificables: (a) el sobre-bloqueo debe ser atribuible al WAF y no a la aplicación, así que falta un testigo que nunca rechaza nada (`origin/main.go:179-181`); (b) los valores `Server` deben poder distinguirse (`xammu-lab-waf/1.0` frente a `xammu-lab-origin/1.0`, `origin/main.go:29-32`) y el bloque S lo afirma; (c) `verify.sh` necesita sondas directas al origen como controles en B1, B4 y B5; (d) el 502 de B5 tiene que ser un fallo **upstream**, no una decisión defensiva.
4. **`waf-stripped` es la misma `image_id` con una variable de entorno.** `compose.yaml:98-113` re-declara `image: xammu-lab-waf:1.0.0` sin bloque `build:` y cambia sólo `LAB_STRIP_WAF_MARKER_HEADERS=1` (y `LAB_STRIP_WAF_TRACE_HEADERS=1`). Una segunda imagen sería un segundo binario que comparar y rompería la demostración: `verify.sh:443` exige que el ID del contenedor *stripped* sea **igual** al `want_waf` de `DIGESTS.txt`, y las 20 comprobaciones `parity` exigen que los 10 estados de los cinco comportamientos coincidan entre ambos servicios. El punto: la señal de rechazo vive en el cuerpo, no en una cabecera.
5. **`allowedHosts`: por qué el fixture no es un *open relay*.** `handleProxied` rechaza con 403 `relay_refused` cualquier *absolute-form request target* cuyo host no esté en `allowedHosts` (`localhost, 127.0.0.1, origin, waf, ::1, [::1]`) **antes** de inspeccionar nada (`proxy.go:164-173`, `rules.go:327-340`; `hostIsAllowed` normaliza mayúsculas, puerto y corchetes). Además el `Transport` del proxy y el `coverageClient` fijan `Proxy: nil`, de modo que nunca se reenvía a través de un proxy ambiental (`proxy.go:110`, `coverage.go:176-182`). Nota: el rechazo de relay usa el JSON `not_evaluated`, sin token de bloqueo —no es una decisión defensiva y un perfilador no debe leerlo como tal—.
6. **`DecomposedHeaders` excluye `cookie` del emparejamiento por valor de cabecera** (`rules.go:307-325`; `isDecomposedHeader` en `inspect.go:361-368`). La lista es `cookie, content-type, content-length, host, connection, accept-encoding, transfer-encoding, upgrade, te`. Sin esta exclusión toda cabecera `Cookie` se evaluaría dos veces —una como cabecera y otra como cookies— y **cualquier** Cookie con el centinela triparía `GENERIC-001` ya como cabecera: la asimetría por nombre de cookie del comportamiento 3 sería inobservable. Igualmente importante es lo que **no** está en la lista: `User-Agent`, `Accept`, `Referer` y cualquier cabecera ordinaria conservan su valor en scope, que es la razón por la que el hueco de cabeceras es un hueco documentado y no una coartada general.
7. **Orden de evaluación, que fija la atribución.** Paso 1: políticas por nombre de cabecera (siempre gana). Paso 2: bucle *externo* sobre la tabla de reglas en el orden declarado y bucle *interno* sobre los candidatos (`inspect.go:168-192`), es decir: **gana la regla más arriba en la tabla con independencia del transporte que la active**. Paso 3: `default_forward`. Por eso `'+or+1=1…` se atribuye a `SQLI-001` y no a `SQLI-003`, y por eso `lab_probe_payload=%2e%2e%2f…` se atribuye a `TRAVERSAL-001` y no a `COOKIE-001`. Sin este orden escrito, la regla atribuida sería una adivinanza.
8. **Cuatro decisiones que eliminan ruido.** El origen no usa `http.ServeMux`: emite 301 para rutas no limpias y un 3xx en medio de una medición la contamina; el dispatch es explícito y **el laboratorio nunca responde con una redirección** (`origin/main.go:107-126`). El motor no reescribe la petición. `maxInspectedBody` y `maxBodyBytes` son ambos 1 MiB, un valor fijo para todas las rutas, «para que el tamaño del cuerpo no pueda convertirse en una variable no documentada en un experimento» (`inspect.go:26-28`, `origin/main.go:34-36`). Y el `requestID` del intersticial se deriva de la decisión y de la línea de petición (`proxy.go:220-231`), no de un aleatorio ni del reloj: es reproducible y deliberadamente corto para que la **longitud del cuerpo** siga siendo una señal utilizable.
9. **Healthchecks heredadas del `HEALTHCHECK` de la imagen** en origen y WAF (`origin/Dockerfile:52-53`, `waf/Dockerfile:44-45`); en `compose.yaml` sólo `netrunner` declara uno explícito y `waf-stripped` hereda el de la imagen. Un tercero no debe «arreglar» esto añadiendo `healthcheck:` en compose: cambiaría el ID de la imagen derivada y rompería `verify.sh`. El healthcheck de `netrunner` es un round trip real (resuelve y alcanza a ambos WAF y al origen) porque es la propiedad de la que dependen todas las sondas (`compose.yaml:114-146`).

## 7. Qué NO debe hacerse con este laboratorio

1. **No usar `/__lab/info` ni `/__lab/coverage` como insumo del perfilador.** Existen para depuración humana y para el autotest del propio laboratorio (`verify.sh` los emplea en los bloques UP y B1). Son *configuración del fixture*, no *comportamiento observado*: un hallazgo derivado de ellos es lectura de configuración, no perfilado conductual, y **es inválido**. En particular `would_match_rule` —calculado por `shadowMatch`, `coverage.go:346-358`— es literalmente «lo que habría dicho una regla si este transporte se hubiera mirado»; un perfilador real nunca tiene esa respuesta. La tabla de reglas, los allowlists y los prefijos que expone `/__lab/info`, y su campo `server`, tampoco son señales de clasificación.
2. **No usar las cabeceras de traza como clasificador.** `X-Lab-Waf-Rule` y `X-Lab-Waf-Vector` existen para ayudar a un humano; `LAB_STRIP_WAF_TRACE_HEADERS` las apaga y `verify.sh` las usa **sólo para nombrar** la regla detrás de una decisión ya tomada por estado y cuerpo (`verify.sh:100-104`). Copiar `RulesByID()`, `protectedContractions`, `InspectedCookiePrefixes` o la tabla completa en los detectores de XAMMU como oráculo invalida todo el ejercicio: el detector ya sabría la respuesta y no se estaría midiendo nada.
3. **No publicar puertos para llegar desde fuera.** Ni `ports:`, ni quitar `internal: true`, ni un sidecar de rebote. La red interna es el control de alcance: expuesto, el laboratorio deja de ser un banco cerrado y pasa a ser un servicio accesible con un WAF deliberadamente evadible delante de una aplicación. Las sondas van en `netrunner`.
4. **No presentar métricas del laboratorio como cobertura de producción.** La tasa `0.500` es sobre **12 términos de un corpus fijo de textos en inglés**, no sobre el tráfico de nadie. Los `134/134` son comprobaciones del *fixture*, no pruebas del detector. El `coverage_gap` del cuerpo JSON es una propiedad de `rules.go`, no una cota de nada.
5. **No ensanchar el corpus con payloads funcionales ni «arreglar» los huecos.** Añadir una firma que case la doble codificación destruye el comportamiento 2; añadir `json_body` a una regla destruye el 1; hacer que el origen rechace algo destruye la atribución del 4. El laboratorio pierde su valor exactamente cuando se vuelve bueno.
6. **Expectativa correcta sobre rondas.** Como la tabla de reglas es fija y las respuestas son estables, **una corrida del laboratorio debe reproducir el mismo conjunto de hallazgos ronda tras ronda**. El propio laboratorio lo hace comprobable: el bloque S exige que la longitud del cuerpo del intersticial sea idéntica entre dos peticiones iguales y `handleAdmin` no tiene estado, log ni azar. Si XAMMU produce un conjunto distinto sobre este fixture, **es un defecto de XAMMU a investigar, no ruido que promediar**. No se admiten corridas descartadas «por atípicas».
7. **No editar `DIGESTS.txt` a mano.** Es salida generada; el archivo lo dice en su línea 7 y `verify.sh` fallaría de todos modos contra los contenedores reales.

## 8. Tolerancias conocidas

Temporizadores presentes en los ficheros (ninguno es ajustable sin editar):

| dónde | parámetro | valor |
|---|---|---|
| `verify.sh:205` | `compose up -d --wait-timeout` | 120 s para que los 4 contenedores estén `healthy`; si no, exit 3 |
| `origin/Dockerfile:52`, `waf/Dockerfile:44` | `HEALTHCHECK` de las imágenes | `interval=3s timeout=2s start-period=3s retries=20` |
| `compose.yaml:143-146` | healthcheck de `netrunner` | `interval=5s timeout=16s retries=6 start-period=3s`, con 3 curls de `--max-time 5` seriales |
| `verify.sh:106` | sonda de respuesta | `curl --max-time 20` |
| `verify.sh:146`, `verify.sh:166` | `/__lab/coverage` y `/internal/normalize` | `curl --max-time 25` |
| `proxy.go:111-120` | transporte del proxy | dial 5 s, keepalive 30 s, `ResponseHeaderTimeout` 10 s, `ExpectContinueTimeout` 1 s, 16 idle conns / 60 s |
| `coverage.go:176-182` | cliente interno de `/__lab/coverage` | timeout total 10 s, dial 5 s |
| `waf/main.go:54-61,80` | servidor WAF | `ReadHeaderTimeout` 5 s, read/write 30 s, idle 60 s; cierre graceful 5 s |
| `origin/main.go:41-47,65` | servidor origen | `ReadHeaderTimeout` 5 s, read/write 15 s; cierre graceful 3 s |
| `inspect.go:28`, `origin/main.go:36` | cuerpo | 1 MiB (`maxInspectedBody` / `maxBodyBytes`) |
| `compose.yaml:51-55` | logs | 1 MiB por fichero, 2 ficheros |

Qué esperar en una máquina lenta:

- **El primer `build.sh` es lo más caro** (compilación Go dentro del contenedor, dos imágenes) y no fija ningún timeout: pueden ser varios minutos. Los rebuilds van por caché de BuildKit, que invalida por contenido, así que una capa cacheada sigue siendo el mismo digest (`build.sh:84-85`).
- Los `retries=20` con `interval=3s` de las imágenes dan ~60 s de margen por servicio antes de marcar `unhealthy`; el techo global lo pone `--wait-timeout 120`. Si una máquina no llega, el síntoma es un exit 3 con las últimas 25 líneas de `/tmp/lab-up.log`, no un fallo de comportamiento.
- El healthcheck de `netrunner` es el único con timeout generoso (16 s) porque ejecuta 3 curls seriales de hasta 5 s: en máquina lenta es el primero en rozar su ventana, y una falsa «lab no healthy» suele ser DNS del overlay, no el WAF.
- Un `--max-time` agotado produce `code=000` en el primer campo de la sonda (`verify.sh:115`), reportado como FAIL con `actual=000`. `000` es un problema de transporte o de lentitud, no un comportamiento del fixture.
- `verify.sh` hace `down --remove-orphans` antes de `up` (`:204`) y `teardown.sh` es idempotente: un laboratorio medio levantado de una corrida interrumpida **no** obliga a reiniciar nada.
- `teardown.sh` no fija `--timeout` ni en `down` ni en `docker rm -f`: el período de gracia es el valor por defecto de Docker, que en este laboratorio no está documentado. Con `restart: "no"` e `init: true` los dos procesos Go atienden SIGTERM, así que la parada es limpia en la práctica y el bloque DOWN (2 comprobaciones) lo confirma.

Rarezas del banco de pruebas que hay que conocer para no malinterpretarlas:

- **`curl -H "Nombre:"` elimina la cabecera en vez de enviarla vacía.** Por eso la comprobación de `X-Lab-Probe-Transfer-Encoding:` con valor vacío espera 200: es un hecho sobre el *harness*, documentado explícitamente en `verify.sh:334-338`, no un hueco del fixture.
- Los valores viajan por variables de entorno hasta `netrunner`, y el JSON de cobertura/normalización **conserva los espacios interiores** (`tr -d '\r\t'`, sin `-s ' '`) porque los documentos se imprimen con sangrado y patrones como `"signature": "' or 1=1 xammu-probe"` sólo casan si los espacios sobreviven (`verify.sh:141-163`). Compactar espacios en una refactorización rompería en silencio las comparaciones más importantes.
- `has()` mide **presencia, no recuento**: la misma firma aparece dos veces en el documento de cobertura (contabilidad y check por valor), y un recuento exacto sería propiedad del *layout* del informe, no del WAF (`verify.sh:177-184`).
- Un cuerpo **JSON de más de 1 MiB se trunca** en el proxy: `jsonBodyValues` lee con `io.LimitReader(r.Body, 1 MiB)` y reemplaza el cuerpo por un *replay* de esos bytes (`inspect.go:407-411`), así que el resto del stream no llega al origen. `verify.sh` no ejercita este caso y el comentario «the upstream still receives the exact bytes» sólo vale por debajo de 1 MiB: trátelo como **límite**, no como comportamiento probado. Los cuerpos que no son JSON no se bufferizan y se reenvían intactos.
- El bloque B2 imprime su cabecera `section` dos veces (`verify.sh:272,274`): es cosmético y no añade comprobaciones.

## 9. Lo que este archivo no puede cerrar

Para que el criterio «cero decisiones no documentadas» no se falsee a sí mismo, las lagunas encontradas al documentar quedan declaradas, no rellenadas con suposiciones:

- `build.sh:96-97` afirma que «`./build.sh` is re-run by `./verify.sh`'s identity check». **No es cierto en el estado actual**: `verify.sh` no invoca `build.sh`; lee `DIGESTS.txt` y lo compara con los contenedores en ejecución. No se modificó nada: esta guía describe el comportamiento real.
- El `./lint.sh` opcional al que se refiere `build.sh:7` **no existe** en el laboratorio. Su comportamiento: no documentado.
- `[image_metadata].store=overlayfs` en la corrida registrada difiere del *containerd image store* con el que `build.sh:86-92` describe su medición sobre las attestations. Ambas banderas (`--provenance=false --sbom=false`) se mantienen y `verify.sh` pasa con ellas; la diferencia de *store* no afecta al contrato, pero la coincidencia numérica entre `manifest` e `image_id` en `overlayfs` no está explicada en ningún fichero: no documentado.
- **`verify.sh` no se ejecutó en la máquina donde se escribió `scenarios.json`**: no había daemon de Docker disponible. Las 38 comprobaciones del manifiesto se ejecutaron contra los mismos binarios del fixture levantados en el host (`origin` en `127.0.0.1:8081`, `waf` en `:8099`, `waf-stripped` en `:8098` con las mismas variables de entorno que `compose.yaml`), reescribiendo sólo los nombres de servicio por sus direcciones. Las comprobaciones son las mismas; lo que falta es la prueba de que el manifiesto se ejecuta **dentro** de compose, que es lo que `xammu lab test --scenario NAME --apply` hará la primera vez que se corra con Docker.
- **Los comandos `run` se midieron en el host, y el manifiesto ahora lo dice** (`run_mode: host`). No es un detalle: las autorizaciones casan el destino **por nombre de host** (`internal/httpclient/policy.go:178`), así que `--target http://waf:8080` sería rechazado como fuera de alcance por una C-09 que nombra `127.0.0.1`, y un perfilador en el host no puede alcanzar los servicios de compose porque el laboratorio no publica puertos. Las comprobaciones van por el camino inverso: usan los nombres de servicio y corren en `netrunner`. Un lector que quiera repetir una **lectura** levanta los dos binarios en el host; quien quiera repetir el **comportamiento del fixture** usa compose y `verify.sh`.
- **Cobertura de controles incompleta en dos vectores, y por razones distintas.** En `path` existe el control positivo (`CAL-POS-P-01`) pero no hay negativo ni benignos, así que `--class path_traversal --vector path` se rechaza al planificar con «no negative control … only 0 benign reference(s)»; además la C-09 del laboratorio no podría alojar esa sonda de traversal porque su prefijo cae fuera de `path_prefixes`. En `body_json` y `body_form` el problema es el contrario y es irreducible: el fixture **no bloquea nada** en esos transportes, así que no existe control positivo honesto. Un plan que incluya el cuerpo sigue siendo válido —los controles de query lo sostienen— pero la célula del cuerpo nunca podrá pasar de `replicated_within_run`, y un plan *sólo* de cuerpo se rechaza entero con «no positive control». Fingir un control positivo sería mentir sobre el fixture; queda declarado y no se rellena.

---

Recordatorio que `verify.sh` imprime al final de cada corrida, y con el que debe citarse cualquier resultado de este laboratorio:

> *this fixture has deliberately known-bypassable behaviour. It is a test harness for XAMMU's detectors, not a benchmark of any commercial WAF.*
