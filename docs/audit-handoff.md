# Handoff de auditoría — XAMMU v1.0.0

| campo | valor |
| --- | --- |
| Documento | Informe de auditoría interna y handoff técnico |
| Fecha | 2026-11-05 |
| Base revisada | `09d434f` (`main`), que incluye 0.1 (`72c7867`) y 0.2 (`09d434f`), más el conjunto 0.3 pendiente de commit: `.github/workflows/ci.yml`, `scripts/ci-local.sh` y documentación |
| Árbol de trabajo | Limpio de secretos; 0.3 pendiente de commit; bundles demo sin cambios |
| Método | Revisión estática de rutas críticas, ejecución de la suite, `go vet`, `gofmt`, `scripts/certify.sh`, `scripts/ci-local.sh`, `verify` con `--trust-key`, gitleaks 8.30.1 sobre árbol e historial, y lectura del modelo de amenaza documentado |
| Herramientas | Go 1.27.3 windows/amd64; gitleaks 8.30.1; govulncheck 1.9.0 |
| Evidencia | `dist/certification-<UTC>.txt` (`RESULT: PASSED`), `dist/ci-local-<UTC>.txt` (`PASSED WITH 3 SKIPS`), gitleaks 8.30.1 sobre árbol e historial sin fugas |
| Naturaleza | Auditoría interna. **No** es una certificación externa, un pentest ni una prueba de conformidad legal |

> El ancla definitiva es el `source tree sha256` que imprime `scripts/certify.sh` en la última corrida
> archivada con la entrega. Como este documento vive bajo `docs/`, cualquier hash citado aquí queda
> obsoleto al editarlo: el archivo de evidencia es el que se archiva, no esta línea.

---

## 0. Veredicto en una página

XAMMU es una herramienta **defensiva de descubrimiento de comportamiento** para un único egress autorizado.
No busca vulnerabilidades: mide cómo un WAF o front-end trata tráfico **inerte y marcado** frente a su tráfico
de referencia, y publica hallazgos con la evidencia separada de la inferencia. Su diseño es inusualmente
conservador y honesto. Las dos debilidades altas de la revisión original —la autorización C-09 sin firma y
la retención completa de cabeceras— se cerraron en 0.1 y 0.2. Lo que queda pendiente es la evidencia externa
de la cadena de build (CI, SBOM y firma de release) y los riesgos de medición de fases posteriores.

**Apto para:** engagements internos o de cliente con autorización escrita, un solo target por ejecución,
presupuesto y ventana declarados, y revisión humana de los hallazgos.

**No apto para:** escaneo de vulnerabilidades, explotación, pruebas de autenticación o lógica de negocio,
barrido masivo, benchmarking de WAF comerciales, ni como sustituto de un pentest o de una certificación externa.

**Tres fortalezas**
1. Un solo camino de salida a red, con validación de destino, DNS anti-rebinding, redirecciones revalidadas y
   presupuesto por proceso (`internal/httpclient`).
2. Evidencia sellada con cadenas de hash, Merkle y Ed25519; `verify` distingue integridad de identidad y
   `--trust-key` es opcional y explícito.
3. Honestidad estructural: C-16 obliga a separar observado, inferido y evidencia faltante; no existen
   puntuaciones de confianza ni CVSS inventados; los informes declaran lo que no prueban.

**Tres riesgos principales**
1. **H-03 (Medio):** las anclas de confianza de los demos son TOFU; prueban continuidad, no identidad.
2. **H-04/H-10 (Medio/Bajo):** el workflow de CI, el SBOM y la firma keyless están implementados, pero
   no se ejecutaron en GitHub; todavía no hay un artefacto de release firmado.
3. **H-05 (Medio):** el presupuesto y la tasa no se coordinan entre procesos que comparten una C-09.

---

## 1. Qué hace XAMMU

### 1.1 Propósito

XAMMU perfila el comportamiento de una defensa perimetral (WAF, CDN, proxy inverso) enviando sondas
**inertes** —reconocibles por un token marcador— a través de **un único cliente autorizado**, y comparando la
respuesta de la defensa con la de un control de calibración. El resultado no es «hay una vulnerabilidad», sino
«esta defensa trata de forma distinta este transporte/clase/codificación, y esto es lo que la evidencia permite
y no permite afirmar».

### 1.2 Qué mide

Vocabulario cerrado de C-16 (`internal/contracts/enums.go:289`):

| tipo de hallazgo | significado operativo |
| --- | --- |
| `over_blocking` | la defensa bloquea tráfico que la referencia trata como limpio |
| `coverage_gap` | una celda autorizada no recibe inspección efectiva o no produce lectura |
| `vector_asymmetry` | el mismo token se trata distinto según transporte o nombre de slot |
| `encoding_bypass_pattern` | una codificación cambia el veredicto de la defensa |
| `configuration_concern` | patrón de configuración observable con impacto defensivo |
| `undetermined_area` | el run no puede decidir con la evidencia disponible |

Cada hallazgo declara además `claim_type` (`descriptive`, `association`, `attribution` o
`confirmed_attribution`),
`attribution_status`, `evidence_level`, `evidence_basis`, alternativas evaluadas, evidencia faltante y
limitaciones (`internal/contracts/finding.go:16-49`).

### 1.3 Ciclo de una ejecución

1. **Carga del corpus** por la puerta de inertitud; si la puerta no puede aplicarse, el corpus no se carga.
2. **Construcción y validación del plan** contra la C-09: orígenes, métodos, clases, vectores, codificaciones,
   rutas y presupuesto. `playbook` se detiene aquí y no envía nada.
3. **Apertura del run** con `--authorize REF` repetido y comprobación de ventana antes de cualquier socket.
4. **Ejecución** por el egress único: una petición cada vez, con límite de tasa, presupuesto, cortacircuitos,
   parada ante 429 y revalidación de cada redirección.
5. **Observación**: se guarda el cuerpo sólo según retención, se calculan digests y se aplican cinco detectores.
6. **Inferencia y descubrimiento**: clasificación, atribución, hipótesis y C-16.
7. **Sellado**: cadenas de hash, Merkle, manifiesto firmado con Ed25519; la clave privada queda fuera.
8. **Publicación**: C-15 en Markdown/JSON, anexo de cliente ES/EN (Markdown o HTML autocontenido) y comandos
   de reproducción ligados a la autorización y a las flags que produjeron la evidencia.

### 1.4 Entregables

- Bundle de evidencia firmado (13 archivos inventariados en los demos).
- `report.md` / `report.json` (C-15) con cinco dimensiones: cobertura, comportamiento, atribución,
  descubrimiento y riesgo residual separado en tres afirmaciones (`internal/report/risk.go:13`).
- Anexo de cliente en español o inglés; los campos de evidencia C-16 se citan verbatim.
- Comandos de reproducción ejecutables, no instrucciones genéricas.

---

## 2. Cómo lo hace

### 2.1 Arquitectura

| paquete | responsabilidad |
| --- | --- |
| `cmd/xammu` | superficie CLI; ninguna otra ruta envía tráfico |
| `internal/contracts` | C-01…C-16, validación, vocabularios cerrados, prohibición de scores |
| `internal/corpus` | carga, puerta de inertitud, particiones, colocación de sondas |
| `internal/httpclient` | egress único, política de destino, ledger, límites |
| `internal/orchestrator` | máquina de estados, autorización, ejecución, reanudación |
| `internal/observer` | retención, detectores, análisis de firma |
| `internal/inference` | journal, celdas, atribución, hipótesis |
| `internal/discover` | hallazgos C-16, alternativas, comandos |
| `internal/report` | C-15, matriz, distribuciones, riesgo residual |
| `internal/annex` | vista de cliente ES/EN, Markdown y HTML |
| `internal/integrity` | hash chains, Merkle, manifiesto, firma, verificación |
| `internal/labctl` | manifiesto del laboratorio y pasos de compose |

### 2.2 Egress único

Controles verificados en `internal/httpclient`:

- `Proxy: nil`: no se hereda `HTTP_PROXY` (`client.go:114-125`).
- TLS mínimo 1.2 y `InsecureSkipVerify` nunca activado (`client.go:120`, `client.go:284`).
- Resolución DNS validada contra IPs/CIDR autorizados y conexión a la IP ya comprobada, no a la que el
  resolver elija después (`client.go:324-361`).
- Redirecciones revalidadas salto a salto con límite (`policy.go:225-230`).
- Ruta comprobada en forma cruda, limpiada y desescapada (`policy.go:196-221`).
- Métodos y sondas de validación en lista blanca; cabeceras hop-by-hop filtradas.
- Ledger de presupuesto por proceso; 429 detiene el run; cortacircuitos por fallos de transporte.
- Tope de cuerpo y digest; el cuerpo no se serializa (`contracts/observation.go:115-128`).

### 2.3 Puerta de inertitud

`corpus.Load` exige token marcador y aplica reglas que rechazan material de explotación, secretos, rutas
sensibles y utilidades de red (`internal/corpus/corpus.go:132`, `internal/corpus/inert.go`). No existe flag
para saltarla: cualquier comando que necesite corpus lo carga por esta función.

### 2.4 Autorización y alcance

- C-09 se valida como contrato antes de usarse (`cmd/xammu/load.go:59-82`).
- `run` exige `--authorization` y `--authorize REF`; el segundo debe coincidir exactamente.
- La ventana se comprueba antes del plan y otra vez en la máquina de estados
  (`cmd/xammu/run.go:59-84`, `internal/orchestrator/run.go:223`).
- Un solo target por ejecución: si hay varios orígenes, hay que nombrar uno; el binding se valida en
  `internal/orchestrator/run.go:191`.
- Las flags estrechan; no existe una flag que amplíe scope, presupuesto o métodos.
- Los runs no se sobrescriben (`cmd/xammu/run.go:238-252`).

### 2.5 Evidencia y sellado

- Cada stream tiene cadena de hash; el manifiesto publica cabeza de cadena, Merkle root, número de archivos y
  digests (`internal/integrity/manifest.go:124-209`).
- Firma Ed25519 sobre el payload; el manifiesto lleva sólo la clave pública.
- `seal` rechaza una clave privada dentro del directorio firmado (`cmd/xammu/run.go:289,316`).
- `verify` comprueba hashes, Merkle, cadena, conteos, firma y, si se aporta, `--trust-key`.
- `--rederive` re-emite el informe desde la evidencia sellada y reporta divergencias.

### 2.6 Informe y anexo

- C-15 se valida antes de publicarse y se vuelve a validar al releerlo.
- El anexo es una **vista** del mismo informe: traduce estructura y etiquetas, pero cita verbatim los campos
  de evidencia C-16; HTML escapa todo el contenido (`internal/annex/annex.go`).
- Los archivos de informe se escriben `0640`; el anexo, `0640`.
- Los comandos de reproducción repiten las flags no por defecto y la autorización que pagó la evidencia.

---

## 3. Por qué está diseñado así

1. **Evidencia antes que narrativa.** El informe separa lo observado de lo inferido porque un WAF que devuelve
   403 no prueba, por sí solo, que la defensa haya entendido la petición.
2. **Un solo egress.** Toda la superficie de red vive en un paquete; el resto del árbol no puede abrir sockets.
   Esto hace auditable la pregunta «¿qué puede enviar este binario?».
3. **La puerta de inertitud no es opcional.** Si el corpus pudiera cargarse sin ella, el marcador y las reglas
   de exclusión serían decorativos.
4. **Fricción deliberada.** Repetir la referencia de la autorización y negarse a sobrescribir bundles convierte
   errores de operador en negativas visibles, no en accidentes silenciosos.
5. **Honestidad sobre los límites.** No hay CVSS, severidad numérica ni confianza inventada; hay niveles de
   evidencia y afirmaciones explícitas de lo que falta. Los dos criterios de aceptación que el repositorio no
   puede cerrar (CI limpio y prueba con ingeniero externo) se declaran como brechas.

Tradeoffs asumidos: sin proxy corporativo, sin autenticación/sesión, sin multi-target, sin explotación, sin
benchmark. Son restricciones de alcance, no carencias accidentales.

---

## 4. Alcance

### 4.1 Incluido

- Perfilado HTTP/HTTPS de **un** origen autorizado por ejecución.
- Clases, vectores y codificaciones del vocabulario C-09.
- Comparación contra partición de calibración y control.
- Detección de diferencias de tratamiento, atribución gradual y publicación de hallazgos C-16.
- Evidencia reproducible, firmada y verificable; anexo de cliente ES/EN.
- Laboratorio Docker con comportamientos conocidos para probar que los detectores detectan.

### 4.2 Excluido explícitamente

- Explotación de vulnerabilidades o confirmación de exploitabilidad.
- Pruebas de autenticación, autorización de aplicación, sesión, CSRF o lógica de negocio.
- Fuzzing, crawling, descubrimiento de endpoints, escaneo de puertos o de infraestructura.
- Pruebas de carga, denegación de servicio o tráfico masivo.
- Evaluación de la seguridad de la aplicación de origen.
- Benchmarking de WAF comerciales o afirmaciones de superioridad.
- Prueba de que una defensa «no tiene» una debilidad donde no se envió tráfico.
- Certificación externa, conformidad legal o validez ante un regulador.

### 4.3 Condiciones de uso

- Autorización C-09 escrita, con scope, ventana, presupuesto, métodos, retención y contacto de parada.
- Un target por run; el operador repite la referencia de la autorización.
- El operador custodia la clave de firma fuera del repositorio y del bundle.
- Los bundles pueden contener metadatos del target; su compartición es una decisión del engagement.

### 4.4 Estado de aceptación

`docs/acceptance.md` declara 23 criterios verificados por test, 3 con vocabulario equivalente, 1 por revisión
documental y **2 no reclamados** (CI limpio y prueba con ingeniero externo). 0.3 implementa el workflow de CI
y el espejo local, pero el CI limpio sigue sin reclamarse hasta que exista una corrida en GitHub. La suite
local es de 346 funciones en 19 paquetes, sin fallos.

---

## 5. Infraestructura

### 5.1 Modelo de despliegue

XAMMU es un **binario CLI local**. No hay servidor, base de datos, cola, panel ni puerto a la escucha; el único
listener del repositorio está en el laboratorio (`lab/origin/main.go:52`, `lab/waf/main.go:67`). El estado vive
en archivos: corpus, autorizaciones, bundles y `dist/`.

Superficie de entrada: argumentos CLI, JSON de autorización, corpus JSONL, bundles al leer, manifiesto y
`--trust-key`. Superficie de salida: red autorizada y archivos locales.

### 5.2 Cadena de build

- **Cero dependencias Go externas**: `go.mod` sólo declara el módulo; `go list -m all` devuelve `xammu`.
  Esto elimina la mayor parte del riesgo de supply chain de módulos.
- Build reproducible: `CGO_ENABLED=0`, `-trimpath`, `-buildvcs=false`, sin build id; dos builds comparados
  byte a byte (`scripts/release.sh:27-39`).
- Certificación interna: `gofmt`, `vet`, build, suite, `corpus check`, `verify` de ambos demos con ancla,
  anexos y hash del árbol (`scripts/certify.sh`).
- **CI versionada (0.3), sin corrida externa.** `.github/workflows/ci.yml` ejecuta `gofmt`, `vet`,
  `go test -race`, `govulncheck` como herramienta, gitleaks sobre árbol e historial y el build reproducible;
  en un tag `v*` añade SBOM y firma keyless. Las acciones están fijadas por SHA. No se ha ejecutado en GitHub:
  `scripts/ci-local.sh` es la evidencia disponible.

### 5.3 Repositorio y distribución

- Repositorio Git con remoto GitHub; bundles demo y autorizaciones de demostración versionados.
- `.gitignore` excluye binarios, `dist/`, `*.ed25519` y `*.key`.
- `.gitattributes` fija LF para fuentes y documentos y `-text` para `runs/**`, de modo que la evidencia sellada
  no se convierta al hacer checkout.
- La release produce binario + `.sha256`. El workflow de un tag `v*` añade SBOM CycloneDX y firma
  keyless de binario, checksum y SBOM; esa ruta no se ha ejecutado todavía, así que no hay `.sigstore.json`
  ni procedencia publicados.

### 5.4 Laboratorio

`lab/compose.yaml` aplica defensas razonables para un fixture: red `internal: true` sin puertos publicados,
`read_only`, `cap_drop: ALL`, `no-new-privileges`, `pids_limit`, `tmpfs` de 16 MB y `netrunner` como usuario
1000. Las imágenes base están pinneadas por digest (`lab/origin/Dockerfile:11,31`, `lab/waf/Dockerfile:7,19`).

Riesgo operativo: `xammu lab --apply` invoca Docker Compose con el daemon del operador; el daemon es
equivalente a root en el host. El laboratorio debe correr en un host dedicado o con Docker rootless.

### 5.5 Claves y confianza

- Clave de firma: seed Ed25519 en archivo, `0600`, directorio `0700`; por defecto `.xammu-signing.ed25519` en el
  cwd. `seal` impide que quede dentro del bundle.
- `trust/*.pub` contiene claves públicas extraídas de los manifiestos de demostración: ancla **TOFU**. Prueba
  que un bundle no fue re-firmado con otra clave, no que la clave pertenezca a una identidad verificada.
- No hay rotación, revocación ni custodia en HSM/DPAPI documentada más allá de la recomendación operativa.

### 5.6 Datos y retención

- El cuerpo de respuesta se retiene según `retention_policy`; por defecto `digest_only`. El cuerpo en memoria
  nunca se serializa (`contracts/observation.go:128`).
- Las cabeceras de respuesta se guardan con su valor **salvo las sensibles** (`set-cookie`, `cookie`,
  `authorization`, `proxy-authorization`, `x-api-key`, `x-auth-token` y las añadidas con
  `--sensitive-header`): para ellas se conserva el nombre, el valor se sustituye por `[redacted]` y
  se guarda un digest salado por run (`internal/contracts/redaction.go`,
  `internal/httpclient/client.go`).
- Los bundles pueden contener rutas, cabeceras no sensibles, estados y digests del target; no contienen
  la clave privada ni el valor de una cabecera sensible.

---

## 6. Análisis de seguridad

### 6.1 Superficie de ataque

| superficie | entrada | control actual | riesgo residual |
| --- | --- | --- | --- |
| Red | URL construida desde C-09 y corpus | egress único, IP validada, TLS, redirects | bajo |
| Autorización | JSON C-09/C-10 | validación estructural y de ventana | **alto (H-01)** |
| Corpus | JSONL | puerta de inertitud, vocabularios cerrados | bajo |
| Bundle leído | JSONL, manifiesto, `--trust-key` | validación de contratos, hashes, firma | bajo |
| Sistema de archivos | `--run`, `--store`, `--out`, `--signing-key` | `seal` protege la clave; no hay contención de `--run` | bajo (H-06) |
| Subproceso | `docker compose` en `lab --apply` | argv sin shell, opt-in | informativo |
| Dependencias | stdlib Go | cero módulos externos | bajo |
| Build/distribución | scripts locales y workflow | build reproducible, acciones por SHA, gitleaks/govulncheck, SBOM y firma en tags | medio (workflow sin corrida externa) |

### 6.2 Controles verificados

| control | evidencia |
| --- | --- |
| Sin proxy ambiental ni TLS inseguro | `internal/httpclient/client.go:114-125,284` y tests de egress |
| DNS anti-rebinding | `internal/httpclient/policy.go:235-273` |
| Redirecciones revalidadas | `internal/httpclient/policy.go:225-230` |
| Path traversal denegado | `internal/httpclient/policy.go:196-221` |
| La inertitud no se puede saltar | `internal/corpus/corpus.go:132` y tests del gate |
| Autorización antes de enviar | `cmd/xammu/run.go:59-84`, `internal/orchestrator/run.go:223` |
| Un target por run | `internal/orchestrator/run.go:191` |
| Sin sobrescritura de bundles | `cmd/xammu/run.go:238-252` |
| Clave privada fuera del bundle | `cmd/xammu/run.go:316-338`, `TestSigningKeyMustLiveOutsideTheBundle` |
| Cuerpo no serializado | `internal/contracts/observation.go:128` |
| Informe y anexo con permisos restrictivos | `cmd/xammu/bundle.go:179-185`, `cmd/xammu/read.go:119-124` |
| HTML del anexo escapado | `internal/annex/annex_test.go` |
| Sin secretos en árbol ni historial | gitleaks 8.30.1 sobre historial completo, 0 fugas |
| CI con cadena de suministro fijada | `.github/workflows/ci.yml`: acciones por SHA, herramientas por versión, gitleaks verificado por checksum; `scripts/ci-local.sh` |
| Sin dependencias externas | `go.mod`, `go list -m all` |
| Base de laboratorio pinneada | `lab/DIGESTS.txt`, Dockerfiles |

### 6.3 Hallazgos

Severidad: **Alto** = rompe una garantía central o expone datos sensibles en condiciones realistas;
**Medio** = defensa en profundidad o garantía parcial; **Bajo** = higiene o endurecimiento;
**Informativo** = limitación aceptada o riesgo operativo documentado.

#### H-01 — La autorización no está firmada ni se verifica (Alto)

- **Evidencia:** `cmd/xammu/main.go:1-2` afirma que sólo se envía «through an authorization someone signed».
  `ProfilingAuthorization` exige `issuer_key_fingerprint` (`internal/contracts/authorization.go:74,162`) pero
  ninguna ruta lo compara con una clave; `ValidationAuthorization.ImmutabilityDigest`
  (`authorization.go:96,231`) sólo se valida como formato de digest, nunca se recalcula.
- **Impacto:** cualquiera que pueda escribir un JSON puede fabricar una C-09/C-10 válida y autorizar tráfico.
  El control real es «un humano con acceso de escritura al archivo», no una firma. En un engagement con varias
  personas o un repositorio compartido, la atribución de quién autoró qué no está criptográficamente probada.
- **Recomendación:** firmar C-09 y C-10 con Ed25519 y verificar contra claves de emisor fijadas fuera del
  repositorio; o, como mínimo, recalcular `immutability_digest` y corregir el encabezado para no afirmar una
  firma que no existe. Añadir un test que falle si una autorización alterada sigue siendo aceptada.
- **Estado (2026-11-05): cerrado en 0.1.** Sidecar Ed25519, keyring obligatorio, huella derivada, payload
  canónico con dominio y verificación antes del socket; demos firmados. Evidencia en §10.1.1.

#### H-02 — Cabeceras de respuesta retenidas completas (Alto)

- **Evidencia:** `internal/httpclient/client.go:371-382` guarda `Name` y `Value` de cada cabecera;
  `contracts/observation.go:104-108` los persiste. La retención sólo limita el cuerpo.
- **Impacto:** un target puede devolver `Set-Cookie`, tokens de sesión, trazas internas o cabeceras de
  infraestructura en respuestas de error. Esos valores acaban en el bundle y pueden viajar al anexo de cliente.
  En pruebas con autenticación delegada o cookies de sesión, el bundle se convierte en un portador de secretos.
- **Recomendación:** política de retención de cabeceras independiente; por defecto guardar sólo nombre y digest
  de valor para `Set-Cookie`, `Authorization`, `Proxy-Authorization`, `X-Api-Key` y prefijos sensibles;
  permitir valor completo sólo con autorización explícita. Añadir test de que un `Set-Cookie` no aparece en claro.
- **Estado (2026-11-05): cerrado en 0.2.** Lista base redactada en captura, `--sensitive-header` sólo amplía,
  marcador y digest salado por run con salt no serializado. Evidencia en §10.2.1.

#### H-03 — Anclas de confianza TOFU (Medio)

- **Evidencia:** `trust/README.md` y `docs/certification.md` declaran que las claves se extrajeron de los
  propios manifiestos.
- **Impacto:** `verify --trust-key` detecta una re-firma posterior con otra clave, pero no prueba que la clave
  original pertenezca a Izkuna. Un primer bundle malicioso ancla su propia clave.
- **Recomendación:** registrar la clave pública por un canal independiente (acta de entrega, correo firmado,
  repositorio de claves) y versionar su huella en el expediente del engagement. Para releases, firmar el binario
  con la misma identidad y publicar la huella.

#### H-04 — Sin CI ni escaneo continuo de vulnerabilidades (Medio)

- **Evidencia:** no existe `.github/`; `govulncheck` no está instalado; la certificación es manual.
- **Impacto:** una regresión de seguridad o una vulnerabilidad de la stdlib de Go puede pasar desapercibida
  hasta la siguiente ejecución manual. El riesgo de dependencias es bajo (cero módulos), pero no nulo (stdlib,
  imágenes base, acciones de CI futuras).
- **Recomendación:** workflow mínimo con `gofmt -l`, `go vet`, `go test -count=1`, `govulncheck ./...`,
  gitleaks y `git diff --exit-code` tras clonar; publicar el artefacto de certificación. Añadir `-race` en la
  suite.
- **Estado (2026-11-05): implementado en 0.3; corrida externa pendiente.** `.github/workflows/ci.yml` y
  `scripts/ci-local.sh` cubren esos checks. Hacer push requiere aprobación externa, así que el CI limpio
  sigue sin reclamarse. Evidencia en §10.3.1.

#### H-05 — Presupuesto y tasa no se coordinan entre procesos (Medio)

- **Evidencia:** el ledger y el limitador viven en memoria por proceso (`internal/httpclient/ledger.go`);
  no hay lock por autorización ni reserva atómica compartida.
- **Impacto:** dos runs simultáneos con la misma C-09 pueden duplicar la tasa agregada y el total de peticiones
  percibido por el target, aunque cada proceso respete su copia del límite. En un engagement con SLA de tasa,
  esto es un incumplimiento silencioso.
- **Recomendación:** lock de sistema por `ref`+origen con reserva atómica del presupuesto, o declarar y
  verificar «un run a la vez por autorización». Documentarlo en las reglas de engagement.

#### H-06 — `--run` no contiene el identificador al directorio de runs (Bajo)

- **Evidencia:** `filepath.Join(p.runsDir, p.runID)` sin rechazar separadores ni `..`
  (`cmd/xammu/plan.go:119-129`).
- **Impacto:** `--run ../../ruta` lee un directorio fuera de `runs/`. El operador ya puede usar `--store`, así
  que el impacto real es bajo; el riesgo aparece si un revisor ejecuta un comando de reproducción copiado de un
  bundle no confiable.
- **Recomendación:** rechazar IDs con `/`, `\`, `..` o volumen absoluto, o resolver la ruta y exigir que quede
  contenida en `runsDir`.

#### H-07 — La identidad del corpus es el commit HEAD del repositorio (Bajo)

- **Evidencia:** `internal/report/evidence.go:58-81` sube directorios hasta encontrar `.git/HEAD` y publica ese
  commit como `corpus_commit_ref`.
- **Impacto:** cualquier commit cambia la identidad del corpus aunque el corpus no cambie; un corpus sucio no
  se distingue del commit. La reproducibilidad declarada es más débil de lo que sugiere el nombre.
- **Recomendación:** publicar `git rev-parse HEAD:corpus` (subárbol) más un indicador de árbol sucio, o el hash
  de contenido que ya existe como fallback cuando no hay Git.

#### H-08 — Controles declarados pero no aplicados (Bajo)

- **Evidencia:** `RequireTLS` se calcula (`internal/httpclient/policy.go:55,102,137`) pero no se consulta en
  ninguna ruta de decisión. El `http.Transport` no fija `MaxResponseHeaderBytes`
  (`internal/httpclient/client.go:114-125`).
- **Impacto:** hoy el esquema del origen ya obliga a HTTPS, por lo que no hay bypass; el campo muerto puede
  inducir a error en una revisión futura. Las cabeceras de respuesta no tienen tope explícito de tamaño.
- **Recomendación:** aplicar `RequireTLS` antes del envío o eliminarlo; fijar `MaxResponseHeaderBytes` a un
  valor acorde con el presupuesto de memoria.

#### H-09 — Custodia y ciclo de vida de la clave de firma (Bajo)

- **Evidencia:** la clave por defecto vive en el cwd (`cmd/xammu/plan.go:105`); no hay rotación, revocación ni
  identificación de clave más allá del key id del manifiesto.
- **Impacto:** copia accidental, pérdida o reutilización entre engagements. La clave firmó bundles de demo y
  podría firmar evidencia de cliente.
- **Recomendación:** exigir `--signing-key` explícito en producción, documentar custodia (DPAPI/HSM/almacén del
  sistema), soportar rotación con key id y publicar la huella en el expediente.

#### H-10 — Release sin firma, SBOM ni procedencia (Bajo)

- **Evidencia:** `scripts/release.sh` genera binario y `.sha256`; no hay `cosign`/`minisign`, SBOM ni
  proveniencia SLSA.
- **Impacto:** un consumidor no puede verificar autoría del binario, sólo su hash publicado en el mismo canal.
- **Recomendación:** firmar el binario y el checksum, adjuntar SBOM (`syft`) y, si se adopta CI, proveniencia.
- **Estado (2026-11-05): implementado en 0.3; artefacto todavía no publicado.** El job de tag genera SBOM
  CycloneDX, firma keyless con cosign y verifica las firmas; no se ejecutó porque no hubo push. Evidencia
  en §10.3.1.

#### H-11 — Sin fuzzing de parsers (Bajo)

- **Evidencia:** hay tests unitarios y de contrato, pero no targets `go test -fuzz` para JSONL, manifiesto,
  claves hex o política de rutas.
- **Impacto:** un bundle o corpus malformado podría provocar pánico o consumo de memoria en una ruta de lectura.
- **Recomendación:** fuzz de `contracts.Validate`, `integrity.ReadManifest`, `decodeHexKey` y `Scope.CheckRequest`.

#### H-12 — El laboratorio depende del daemon Docker (Informativo)

- **Evidencia:** `xammu lab --apply` ejecuta `docker compose` (`cmd/xammu/lab.go:211-235`); el compose está
  endurecido, pero el daemon es equivalente a root.
- **Impacto:** un host de laboratorio comprometido o compartido amplía el blast radius.
- **Recomendación:** host dedicado o Docker rootless; no ejecutar `--apply` en estaciones con datos de cliente.

#### H-13 — Riesgo de privacidad en el nombre del operador (Bajo)

- **Evidencia:** `generatedBy` usa `XAMMU_OPERATOR`, `USERNAME` o `USER` (`cmd/xammu/load.go:354-364`).
- **Impacto:** el nombre de cuenta del sistema puede terminar en un informe entregable sin que el operador lo
  haya decidido.
- **Recomendación:** en anexos de cliente, exigir `--prepared-by` explícito o declarar «no indicado» en lugar de
  leer el entorno.

#### H-14 — Dos criterios de aceptación no reclamados (Informativo)

- **Evidencia:** `docs/acceptance.md:10` declara CI limpio y prueba con ingeniero externo como brechas.
- **Impacto:** la entrega es aceptación interna; no hay validación independiente.
- **Recomendación:** cerrar ambas antes de presentar XAMMU como «certificado» ante un cliente; mientras tanto,
  usar la fórmula «aceptación interna de Izkuna».

---

## 7. Mejoras priorizadas

### P0 — antes de usar con datos de cliente

1. ✅ **Firmar y verificar C-09/C-10** (H-01). Cerrado en 0.1; la frase «authorization someone signed» ya
   está respaldada por firma y keyring.
2. ✅ **Retención de cabeceras sensibles** (H-02): valor sustituido por marcador y digest salado en captura.
   Cerrado en 0.2.
3. ◐ **Registrar la clave pública por canal independiente** y dejar de presentar `trust/` como identidad (H-03).
   El keyring es obligatorio y no tiene valor por defecto, pero el canal independiente sigue siendo operativo.
4. ✅ **CI mínimo con gitleaks, vet, test, govulncheck y verificación de fin de línea** (H-04). Workflow y
   espejo local implementados en 0.3; la corrida en GitHub requiere aprobación externa.

### P1 — siguiente iteración

5. Lock de presupuesto por autorización/origen (H-05).
6. Contención de `--run` y validación de IDs (H-06).
7. Identidad del corpus por subárbol + estado sucio (H-07).
8. Aplicar o retirar `RequireTLS`; tope de cabeceras (H-08).
9. ✅ Firma de release + SBOM (H-10). Implementado en 0.3; los artefactos se publican al correr el workflow
   sobre un tag.
10. `--prepared-by` explícito para anexos (H-13).

### P2 — endurecimiento continuo

11. Fuzz targets de parsers (H-11).
12. Rotación/revocación de claves y custodia documentada (H-09).
13. Laboratorio en host dedicado/rootless (H-12).
14. Cerrar los dos criterios de aceptación pendientes (H-14).

---

## 8. Limitaciones de esta auditoría

- **Estática y de caja blanca.** Se revisaron rutas críticas y se ejecutó la suite; no se hizo una revisión
  línea a línea de los ~15 paquetes.
- **Sin prueba dinámica del laboratorio.** No se ejecutó `lab test --apply` ni se enviaron sondas a ningún
  target en esta sesión.
- **Sin pentest externo.** No se contrató revisión independiente; H-14 sigue abierto.
- **Vulnerabilidades de la stdlib, sin runner limpio.** `govulncheck` 1.9.0 se ejecutó localmente con Go
  1.27.3 y está en el workflow; no hay una corrida en un runner de GitHub. Con Go 1.27.0 el escaneo
  encontraba 9 vulnerabilidades de la stdlib que afectaban rutas del cliente HTTP; 1.27.3 las corrige.
  La ausencia de dependencias externas reduce, pero no elimina, el riesgo de la stdlib.
- **Firma keyless no ejercitada.** El job de release usa cosign keyless y publica certificado y firma en el
  log público de Rekor; no se ejecutó. La alternativa con clave en secreto de CI no se implementó.
- **Confianza TOFU.** Las anclas de los demos no prueban identidad.
- **Sin revisión legal.** El documento no valida el marco contractual ni la normativa aplicable al engagement.

---

## 9. Cómo reproducir la evidencia

```bash
# suite y certificación interna
bash scripts/certify.sh

# CI local: espejo del workflow; lista cada SKIP
bash scripts/ci-local.sh

# el workflow remoto solo corre con push; requiere aprobación externa

# verificación de los bundles con ancla fuera del bundle
go run ./cmd/xammu verify --run demo-lab \
  --authorization AUTH-SMOKE-LOCAL-001 --authorizations authorizations \
  --corpus corpus --class sqli --vector query,body_json,cookie \
  --trust-key trust/demo-lab.pub
go run ./cmd/xammu verify --run demo-origin \
  --authorization AUTH-SMOKE-ORIGIN-001 --authorizations authorizations \
  --corpus corpus --trust-key trust/demo-origin.pub

# secretos (árbol e historial)
gitleaks dir . --redact
gitleaks git . --redact

# reproducibilidad del binario
bash scripts/release.sh
```

Salida esperada: `RESULT: PASSED` en `certify.sh` y en `ci-local.sh` (con los `SKIP` que el host no pueda
ejecutar), `signer_is_trusted` en ambos bundles, gitleaks sin fugas y dos builds idénticos byte a byte.
Un `SKIP` no cuenta como pase.

---

## 10. Plan de Fase 0 (P0) — aprobado; 0.1, 0.2 y 0.3 implementados

> **Estado (2026-11-05):** las cinco decisiones recomendadas se confirmaron y **0.1, 0.2 y 0.3 están
> implementados** con la evidencia de §10.1.1, §10.2.1 y §10.3.1. 0.3 se cierra en código; la primera
> corrida del workflow en GitHub (push y `id-token: write`) sigue pendiente de aprobación externa, y por
> eso este documento **todavía no dice P0 cerrado**. No se inicia Fase 1 hasta esa corrida y la
> actualización de §10.4. La regla de trabajo sigue siendo una fase por commit, con tests verdes, README
> y handoff actualizados.

### 10.0 Regla de ejecución

- Una fase a la vez; Fase 0 se divide en tres commits independientes (0.1, 0.2, 0.3), cada uno con tests
  verdes, README y este handoff actualizados.
- Ningún cambio de Fase 1 se mezcla con Fase 0.
- Si una solución propuesta roza una restricción innegociable, se detiene y se reporta; no se rodea.

### 10.1 Verificación criptográfica de C-09/C-10 (H-01)

**Problema confirmado.** Las autorizaciones de demostración declaran
`"issuer_key_fingerprint": "ed25519:7f3a...c1"`, un valor de relleno que ninguna clave produce. No existe
firma en el documento ni sidecar, y `immutability_digest` sólo se valida como formato.

**Diseño propuesto.**

1. **Sobre separado `<autorizacion>.sig`** (JSON: `version`, `key_id`, `signature` en base64, `signed_at`).
   Se elige sobre un campo embebido para no cambiar el esquema C-09/C-10 ni invalidar los bundles existentes.
2. **Payload canónico**: decodificación estricta (`DisallowUnknownFields`), re-marshal determinista de la
   estructura, y mensaje con separación de dominio: `XAMMU-AUTH-v1\0` + etiqueta del contrato + `\0` + bytes.
   Para C-10, `immutability_digest` se recalcula con ese campo vacío y se incluye en el payload firmado.
3. **Keyring del emisor**: `--issuer-keyring DIR` con archivos `*.pub` en hex (Ed25519). Sin valor por
   defecto y sin descubrimiento desde la autorización ni desde el bundle: si no se aporta keyring, la
   comprobación falla con mensaje explícito. Esto elimina el TOFU en la ruta de autorización.
4. **Huella derivada**: `issuer_key_fingerprint` se recalcula desde la clave y debe coincidir; deja de ser
   texto libre. Se reutiliza el `keyID` de `internal/integrity`.
5. **Puntos de aplicación**: `run` verifica antes de planificar y antes del primer socket; `report`,
   `validate` y `verify --rederive` verifican al cargar la autorización. Cualquier fallo termina con exit 1
   y un mensaje que nombra la comprobación fallida (clave ausente, huella distinta, firma inválida, digest
   de inmutabilidad distinto).
6. **Migración**: regenerar las dos autorizaciones demo con huellas reales y sus `.sig`; publicar
   `trust/issuers/demo-issuer.pub` etiquetada como **clave de demostración**, no como identidad de Izkuna.
   No hace falta re-sellar bundles: la autorización no se copia dentro.
7. **Compatibilidad**: los bundles antiguos siguen leyéndose; el cambio afecta a la carga de autorizaciones,
   no a C-01…C-16. Si se prefiere firma embebida, hay que subir `SchemaVersion` a 1.1.0 y asumir que
   `--rederive` de los demos actuales divergirá por versión.

**Archivos previstos:** `internal/contracts/canonical.go` (nuevo), `internal/integrity/authsig.go` (nuevo),
`cmd/xammu/load.go`, `cmd/xammu/read.go` (verify), `cmd/xammu/run.go`, `cmd/xammu/plan.go`,
`cmd/xammu/main.go`, `authorizations/*.json` + `*.sig`, `trust/issuers/`, tests en
`cmd/xammu/cli_test.go`, `internal/contracts/`, `internal/integrity/`.

**Tests que deben fallar si el bug vuelve.**

- Firma válida aceptada; clave distinta rechazada; campo alterado rechazado; firma alterada rechazada.
- Sin `.sig`, sin keyring, o con huella que no derive de la clave: rechazo explícito.
- Campo desconocido en la autorización: rechazo (no se firma lo que no se entiende).
- C-10 con `immutability_digest` manipulado: rechazo.
- `verify --rederive` con autorización manipulada: exit 1 y mensaje que nombra la comprobación.
- `run` con autorización no firmada: exit 1 **antes** de abrir socket (se conserva el canario de tests).

#### 10.1.1 Cierre de 0.1 — decisiones y evidencia

**Decisiones confirmadas.** Sidecar separado (sin cambio de esquema); keyring obligatorio, sin valor
por defecto ni descubrimiento; huella derivada de la clave que verificó; payload canónico con
separación de dominio y de contrato; digest de C-10 recomputado antes de verificar la firma; y un
comando adicional `xammu authorization sign` para que el operador produzca el sidecar sin escribir
criptografía a mano.

**Implementado.** `internal/contracts/canonical.go`; `internal/integrity/authsig.go` (firma, sidecar,
keyring, huella); carga y verificación en `cmd/xammu/load.go`; `cmd/xammu/authorization.go`;
`--issuer-keyring` en `run`, `playbook`, `report`, `validate` y `verify`; decodificación estricta de
C-09/C-10; sidecars y huellas reales en `authorizations/`; `trust/issuers/demo-issuer.pub`.

**Pruebas.** `internal/integrity/authsig_test.go` cubre firma válida, clave distinta, campo alterado,
firma alterada, contrato distinto, versión desconocida, sidecar ausente o con campos desconocidos,
keyring vacío/malformado y huella derivada. `cmd/xammu/authsig_test.go` cubre el firmante, el rechazo
de campos desconocidos, C-10 firmada/unsigned/digest manipulado/campo manipulado/firma alterada/emisor
fuera del anillo, `run` sin socket con C-09 inválida (canario), y `verify` con autorización manipulada
(exit 1, sin línea `authorization_signature`). Suites: **296 funciones, 15 paquetes, todas verdes**.

**Límites aceptados y declarados.**

- La semilla del emisor de demostración se generó para firmar los dos permisos y **no se conserva**:
  los sidecars verifican, pero no se pueden regenerar.
- Los bundles `runs/demo-lab` y `runs/demo-origin` se sellaron antes de 0.1: los comandos que
  publican no incluyen `--issuer-keyring`. Ejecutarlos requiere añadir el anillo; `verify --rederive`
  sobre esos bundles mostraría esa diferencia de texto, no una lectura distinta. Regenerarlos exige
  el fixture Docker y una corrida nueva, que no forma parte de 0.1.
- El keyring no crea el canal independiente: fija la confianza que el operador ya obtuvo. Para un
  engagement, el `.pub` se registra en el acta o en un repositorio de claves externo.

### 10.2 Retención de cabeceras sensibles (H-02) — cerrado (0.2)

**Problema confirmado.** `collectHeaders` persiste nombre y valor de todas las cabeceras de respuesta; la
retención sólo gobierna el cuerpo.

**Diseño propuesto.**

1. **Lista base sensible** (case-insensitive): `set-cookie`, `cookie`, `authorization`,
   `proxy-authorization`, `x-api-key`, `x-auth-token`.
2. **Ampliación por CLI**: `--sensitive-header NAME` repetible en `run`; se registra en la evidencia para
   que la política sea auditable. No amplía scope; sólo aumenta la redacción.
3. **Redacción en captura**: para una cabecera sensible se conserva el nombre, se sustituye el valor por
   un marcador y se guarda `sha256(salt || lower(name) || 0x00 || value)`, con un salt aleatorio de 32
   bytes por ejecución, idéntico para todo el run. El salt **no se serializa**.
4. **Consecuencia documentada**: los digests permiten correlacionar el mismo valor dentro del run, pero no
   se pueden recalcular después; el valor ya no existe. Es la propiedad de privacidad buscada.
5. **Compatibilidad**: se añade un campo opcional `redacted` a `HeaderEntry`; los bundles antiguos siguen
   validando. No se requiere subir `SchemaVersion` si el campo es opcional, pero se documenta la extensión.
6. **Detectores**: sólo consumen `content-type`, `server` y `retry-after`; ninguno necesita el valor de una
   cabecera sensible, por lo que la redacción no altera la clasificación.

**Archivos previstos:** `internal/httpclient/client.go`, `internal/observer/observer.go`,
`internal/contracts/observation.go`, `cmd/xammu/run.go`, `cmd/xammu/plan.go`, tests de CLI y de observer.

**Tests que deben fallar si el bug vuelve.**

- Un bundle generado con `Set-Cookie: session=secreto` no contiene `secreto` en ningún archivo.
- Dos cabeceras sensibles con el mismo valor producen el mismo digest dentro del run.
- Dos runs distintos producen digests distintos para el mismo valor (salt aleatorio).
- `Server` y `Content-Type` conservan su valor; la clasificación no cambia.
- `--sensitive-header` amplía la lista y queda registrado.

#### 10.2.1 Cierre de 0.2 — decisiones y evidencia

**Implementado.** `internal/contracts/redaction.go` (lista base, `HeaderRedactor`, salt de 32 bytes,
digest `sha256(salt || lower(name) || 0x00 || value)`, nombres normalizados y validados);
`HeaderEntry.Redacted` opcional con validación que exige marcador y digest bien formado
(`internal/contracts/observation.go`); captura redactada en `collectHeaders`
(`internal/httpclient/client.go`), de modo que el valor no llega a existir como entrada;
`orchestrator.Config.SensitiveHeaders` y un redactor creado una vez por run en `newClient`;
`--sensitive-header` repetible en `planFlags` (por tanto aceptado por `run`, `playbook`, `report`,
`verify` y `validate`) y publicado en `engagementFlags`; línea de política al inicio de `run`.

**Pruebas.** `internal/contracts/redaction_test.go` cubre las seis cabeceras base en cualquier
capitalización, la lista ampliada, la estabilidad intra-run y la divergencia entre runs, nombres
inválidos y la validación del campo `redacted`. `internal/httpclient/redaction_test.go` cubre la
captura, el valor repetido, la extensión por nombre y el salt por cliente.
`cmd/xammu/redaction_test.go` ejecuta un run real: recorre todos los archivos del bundle y no
encuentra `secreto`; comprueba en las observaciones que `Set-Cookie` y la cabecera añadida llevan
marcador y que `Server` conserva `lab-edge`; y verifica que el comando de reproducción del informe
publica `--sensitive-header`. Suites: **306 funciones, 15 paquetes, todas verdes**.

**Límites aceptados y declarados.**

- El salt no se serializa, así que los digests no se pueden recalcular después del run. Correlacionan
  dentro del run y no entre runs; se documenta como propiedad, no como carencia.
- Un run reanudado recibe un salt nuevo, de modo que la correlación se corta en la reanudación. No
  hay comando de reanudación en la CLI, pero `orchestrator.Load` acepta la misma política por
  `ResumeOptions.SensitiveHeaders`.
- Redactar por CLI una cabecera que un detector consume (`server`, `content-type`, `retry-after`)
  elimina ese dato de la evidencia registrada y puede cambiar la clasificación re-derivada. La lista
  base no incluye ninguna de las tres; la consecuencia se declara aquí en vez de prohibir la bandera.
- Los bundles anteriores a 0.2 siguen validando porque `redacted` es opcional; en ellos un
  `Set-Cookie` puede seguir en claro y `verify` no lo oculta.

### 10.3 CI mínimo, release firmada y SBOM (H-04/H-10)

**Diseño propuesto.**

1. **GitHub Actions** (`.github/workflows/ci.yml`): `gofmt -l`, `go vet`, `go test -race ./...`,
   `govulncheck` (ejecutado como herramienta, sin añadirlo a `go.mod`), gitleaks sobre árbol e historial,
   y `scripts/release.sh` con comparación byte a byte de dos builds.
2. **SBOM** con Syft (SPDX o CycloneDX) y **firma** de binario, checksum y SBOM con cosign keyless
   (`id-token: write`). Alternativa sin OIDC: minisign con clave en secreto de CI.
3. **Sin dependencias al binario**: todas las herramientas viven en el runner; `go.mod` sigue sin módulos
   externos. Las acciones de terceros se fijan por SHA, no por etiqueta.
4. **Verificación local**: `scripts/ci-local.sh` ejecuta lo que no requiere GitHub (vet, test, gitleaks,
   build reproducible, SBOM si Syft está instalado).
5. **Límite honesto**: la reproducibilidad se prueba en el mismo host/OS; no se afirma reproducibilidad
   cruzada Windows/Linux.

**Requiere aprobación externa:** hacer push del workflow a GitHub y, si se usa keyless, habilitar
`id-token: write`. Sin push, la evidencia es `scripts/ci-local.sh` en verde.

#### 10.3.1 Cierre de 0.3 — implementación y evidencia local

**Implementado.** `.github/workflows/ci.yml` con dos jobs. `verify` (push, pull request y manual) ejecuta
`gofmt -l`, `go vet`, `go test -race ./...`, `govulncheck` v1.9.0 instalado con `go install` (sin entrar en
`go.mod`), gitleaks 8.30.1 descargado y verificado por sha256, y `scripts/release.sh`. `release` (solo tags
`v*`) comprueba que el tag coincide con `ToolVersion`, construye, genera SBOM CycloneDX con Syft v1.56.0
mediante `anchore/sbom-action`, firma binario, checksum y SBOM con cosign keyless y verifica las firmas
recién creadas. Las acciones están fijadas por SHA (`actions/checkout` v4.2.2, `actions/setup-go` v5.6.0,
`actions/upload-artifact` v4.6.2, `anchore/sbom-action` v0.20.6, `sigstore/cosign-installer` v3.8.2).
Permisos: `contents: read` global; `id-token: write` solo en `release`. `scripts/ci-local.sh` reproduce los
checks locales, imprime `SKIP` por cada uno que no puede ejecutar y lo cuenta en el resultado.

**Por qué Go 1.27.3.** El escaneo con el toolchain local anterior (1.27.0) encontró 9 vulnerabilidades de
la stdlib que afectaban rutas del cliente HTTP (`crypto/x509`, HTTP/2 y `net/http`), corregidas en
1.27.2/1.27.3. El workflow fija 1.27.3 y la verificación local se repitió con él: `No vulnerabilities found`.

**Evidencia local (2026-11-05).**

- `scripts/ci-local.sh`: `RESULT: PASSED WITH 3 SKIPS` — `-race` (el host no tiene compilador C), SBOM
  (sin Syft) y firma keyless (sin cosign ni OIDC). Los tres los ejecuta el workflow.
- `scripts/certify.sh`: `RESULT: PASSED`; dos builds idénticos byte a byte; `verify` de ambos bundles;
  anexos ES/EN.
- Binario local: `9f228fec0bf7b16c1e6d987f8791315319e185ed21b4d48f069f4344fdd8c4e7` (Windows amd64,
  `dist/xammu-1.0.0-windows-amd64.exe.sha256`). El release de CI producirá un binario Linux distinto.
- gitleaks 8.30.1 sobre árbol e historial completo: 0 fugas.
- Evidencia archivada en `dist/ci-local-<UTC>.txt` y `dist/certification-<UTC>.txt`.

**Límites aceptados y declarados.**

- **El workflow no se ha ejecutado en GitHub.** Sin push ni `id-token: write` no hay corrida limpia, SBOM
  publicado ni `.sigstore.json`. El criterio 7 y el ítem 13 de §8 siguen en ⚠; la fila 0.3 de §10.4 queda ◐.
- **Firma keyless y Rekor.** El certificado y la firma se publican en el log público de transparencia. No se
  firma ningún dato del cliente, solo el binario, su checksum y el SBOM del propio binario.
- **Reproducibilidad acotada al host.** El workflow compara dos builds en el mismo runner Linux; no se
  afirma reproducibilidad cruzada Windows/Linux.
- **Syft se fija en v1.56.0.** El SBOM describe el binario Go y sus módulos, no el host.

### 10.4 Criterio de aceptación de Fase 0

| punto | evidencia exigida |
| --- | --- |
| 0.1 | ✅ suite nueva en verde (296 funciones); `verify` con autorización manipulada sale 1 con mensaje explícito; `run` rechaza antes del socket; demos firmados con sidecars y anillo publicado. **Salvedad:** los comandos dentro de los bundles son anteriores a 0.1 y no citan el anillo; regenerarlos exige el fixture Docker (§10.1.1) |
| 0.2 | ✅ `TestSensitiveResponseHeadersNeverReachTheBundle` recorre el bundle y no encuentra el valor; `TestSensitiveHeadersAreRedactedAtCapture` prueba el marcador, el digest salado y que `Server`/`Content-Type` conservan valor; la política se publica en el comando de reproducción y en el handoff §10.2.1 |
| 0.3 | ◐ `scripts/ci-local.sh` en verde con los `SKIP` declarados; dos builds idénticos; `.sha256` local; `.sig` y SBOM **pendientes** de la primera corrida del workflow (push con aprobación externa) |
| handoff | este documento actualizado con estado **P0 cerrado** y evidencia enlazada |

### 10.5 Riesgos y decisiones abiertas

- **Distribución de claves.** El mecanismo puede exigir un keyring independiente, pero no puede crear el
  canal independiente. Para los demos, la clave pública se etiqueta como demostración; para un engagement,
  la huella debe registrarse en el acta o en un repositorio de claves fuera del bundle.
- **Salt no persistido.** Es la opción más protectora, pero impide recalcular los digests a posteriori. Se
  documenta como propiedad, no como carencia.
- **Firma sidecar vs embebida.** La sidecar evita romper esquema y demos; la embebida es más atómica pero
  obliga a subir versión. La recomendación es sidecar.
- **CI y firma.** Requieren push y posiblemente secretos; no se harán sin aprobación.
- **Notas para fases posteriores (no se implementan ahora).** Fase 1 pide YAML: la stdlib no lo parsea, así
  que hará falta aprobar una dependencia o definir un subconjunto propio. «Severidad esperada» no puede ser
  un score inventado: será una referencia declarativa a OWASP, no un CVSS calculado. El tamper «chunked»
  de Fase 2 choca con el filtrado hop-by-hop anti-smuggling y no debería implementarse como tal. TPR/FPR
  miden acuerdo con etiquetas del corpus, no eficacia absoluta; p99 con N pequeño debe reportar N y marcar
  muestra insuficiente.

---

## 11. Anexo A — Invariantes y su prueba

| invariante | prueba o artefacto |
| --- | --- |
| Sólo `run` envía tráfico | `TestReadCommandsNeverConnect`, `TestPlaybookPlansAndSendsNothing` |
| La inertitud no se puede saltar | tests de `internal/corpus`, `corpus check` |
| Flags estrechan, no amplían | `TestResolveScopeNarrowsNeverWidens` |
| Autorización antes de la primera petición | `TestRunRefusesBeforeTouchingAnything`, `TestRunRefusesAnExpiredAuthorization` |
| Autorización firmada y verificada contra un anillo del operador | `TestRunRefusesAnAuthorizationBeforeTheSocket`, `TestValidationAuthorizationIsImmutableAndSigned`, `TestAuthorizationSignatureBindsDocumentKindAndKey`, `TestVerifyReportsATamperedAuthorizationAsAFailure` |
| Un target por run | `bindTarget` y tests de orquestador |
| Bundle no se sobrescribe | `TestRefuseOverwrite` |
| Clave fuera del bundle | `TestSigningKeyMustLiveOutsideTheBundle`, `assertNoPrivateKeys` |
| Manifiesto detecta daño | `TestVerifyCatchesEvidenceDamage`, `TestVerifyStatesWhatTheSignatureDoesNotCover` |
| Anexo no inventa cifras ni confianza | `TestAnnexNumbersComeFromTheReport`, `TestNoForbiddenIdentifierInTheShippedTree` |
| HTML del anexo escapado | `TestAnnexHTMLIsEscaped` |
| Un valor sensible no llega a la evidencia | `TestSensitiveResponseHeadersNeverReachTheBundle`, `TestSensitiveHeadersAreRedactedAtCapture`, `TestRawObservationEnforcesTheRedactionClaim` |
| Sin secretos versionados | gitleaks (árbol e historial) |
| Build reproducible | `scripts/release.sh`, `scripts/certify.sh` |
| Workflow y herramientas fijados por SHA/versión | `.github/workflows/ci.yml`, `scripts/ci-local.sh` |
| Release con SBOM y firma keyless | job `release` sobre tags `v*`; **pendiente de corrida** (§10.3.1) |

## 12. Anexo B — Glosario

- **C-09:** autorización de perfilado (scope, ventana, presupuesto, retención).
- **C-10:** autorización de validación de una hipótesis contra un target y una lista de sondas.
- **C-15:** contrato del informe.
- **C-16:** contrato del hallazgo, con campos de honestidad y comando de reproducción.
- **TOFU:** *trust on first use*; la clave se acepta la primera vez y sólo se detectan cambios posteriores.
- **Inertitud:** propiedad de una sonda de ser diagnóstica y no explotable, verificada por la puerta.
- **Bundle:** directorio de evidencia sellado con manifiesto firmado.
- **Celda:** combinación de clase, vector y codificación medida en una ejecución.

---

## 13. Fase 1 — Medición de eficacia del WAF

**Estado:** Fase 1 cerrada en código y en aceptación local el 2026-11-05. Este apartado se escribió
antes del código de efectividad; los resultados ejecutados están en §13.6.

### 13.1 Objetivo y límites

Medir, con evidencia sellada y reproducible, en qué grado el WAF autorizado coincide con las etiquetas
declarativas de un corpus de ataque y de un corpus benigno. La métrica **no** es una afirmación de eficacia
absoluta: TPR/FPR describen acuerdo con el corpus en el target y la ventana observados. El tool sigue sin
explotar: cada caso de ataque pasa la misma puerta de inertitud que una sonda diagnóstica, y los benignos
pasan la puerta salvo la exigencia de marcador, porque su propósito es parecer tráfico real.

Restricciones que se conservan sin excepción: un solo origen por corrida, un solo egress, revalidación DNS y
de redirecciones, rechazo de travesía en la ruta, puerta de inertitud no omitible, autorización verificada
antes del primer socket, clave privada fuera del bundle, cuerpo no serializado, cero dependencias Go
externas. `playbook` sigue sin enviar; sólo `effectiveness run` envía, y sólo bajo una C-09 vigente.

### 13.2 Corpus (1.1 y 1.2)

- **Formato:** YAML en el subconjunto documentado por `internal/yamlish` (documentos `---`, mapas con
  sangría de dos espacios, listas de escalares, comillas y comentarios; los bloques `|`/`>` se rechazan).
  No se añade dependencia YAML. Lo que el subconjunto no soporta se rechaza como error de carga, no se
  aproxima.
- **Ataque:** 10 clases × 30 casos = **300**. Clases: `sqli`, `xss`, `path_traversal`,
  `command_injection`, `ssrf`, `ssti`, `ldap_injection`, `nosql_injection`, `xxe`, `crlf_injection`.
  Se añade `ssti` al vocabulario C-09/C-16; las autorizaciones existentes siguen siendo válidas porque el
  vocabulario sólo se amplía.
- **Benigno:** **300** casos: 60 textos de dominio público citados (Project Gutenberg), 60 JSON válidos,
  50 formularios, 59 búsquedas legítimas, 40 cabeceras normales, 30 cookies y 1 ruta. El origen del
  laboratorio sirve una sola ruta (`/api/search`), así que un único caso de path es concluyente; el
  resto de la población compensa con query. Un caso de path que sólo pudiera devolver 404 mediría la
  ruta ausente, no el WAF, y por eso no se incluye.
- **Campos de un caso:** `id`, `kind` (`attack`/`benign`), `class`, `payload`, `vector`, `encoding`,
  `parameter`, `method`, `path`, `expect` (`blocked`/`allowed`), `owasp`, `provenance`, `rationale`.
  `owasp` es una referencia declarativa (p. ej. `A03:2021-Injection`), **nunca** un CVSS ni una severidad
  numérica inventada.
- **Puerta:** cada caso de ataque exige el marcador `xammu-probe` y pasa las 19 reglas; cada benigno pasa
  las mismas reglas con la excepción de marcador ya existente. El veredicto y la versión de puerta se
  registran en el bundle.
- **Escalabilidad:** un archivo por clase/categoría; añadir casos no cambia código. El objetivo operativo es
  2.800+ casos sin tocar el motor.

### 13.3 Ejecución y observación (1.3)

- Reutiliza `httpclient` (scope, DNS anti-rebinding, redirecciones revalidadas, límite de cuerpo) y
  `corpus.Place` para colocar el valor en query, `body_json`, `body_form`, path, header o cookie.
- Presupuesto y ventana de la C-09; se detiene al agotarlos. Un fallo de transporte no se convierte en
  «bloqueado»: se registra como inconcluso y se excluye de las métricas.
- Observa: estado HTTP, veredicto `blocked`/`allowed`, latencia total, cabeceras de seguridad presentes,
  huella del WAF (cabecera `Server`, marcador de bloqueo en cuerpo, cabeceras propias), clase de error.
- **Veredicto:** `blocked` si 403/406, cierre de conexión o cuerpo con marcador de bloqueo del laboratorio;
  `allowed` si 2xx/3xx no bloqueante. 429 es *pacing*, nunca bloqueo (criterio 24): se registra como
  `excluded`, igual que otros 4xx, 5xx, redirecciones y errores de transporte.
- La corrida escribe `effectiveness_cases`, `effectiveness_outcomes` y `effectiveness_metrics` en el journal
  encadenado; sella y firma el manifiesto con la misma regla que `run`.
- La latencia se toma de `Transport.TotalMS`, un campo opcional nuevo de C-01 poblado por el cliente; los
  bundles anteriores siguen siendo válidos porque el campo ausente se lee como 0.

### 13.4 Métricas (1.4)

- TP: ataque bloqueado; FN: ataque permitido; FP: benigno bloqueado; TN: benigno permitido.
- TPR = TP/(TP+FN); FPR = FP/(FP+TN); Precision = TP/(TP+FP); F1 = 2·P·TPR/(P+TPR);
  MCC = (TP·TN−FP·FN)/√((TP+FP)(TP+FN)(TN+FP)(TN+FN)). Si un denominador es cero, el valor es `null`
  con una nota; no se inventa un número.
- Latencias p50/p95/p99 por clase y globales, con `n` y `sufficient_sample` (n≥20). Percentil por rango
  más cercano sobre la muestra ordenada; con n<100, p99 se publica marcado como muestra insuficiente.
- Salida humana (tabla) y JSON; las cifras salen del bundle sellado, no de la memoria del proceso.
- `effectiveness report --rederive` relee E-01/E-02, recalcula E-03 y compara con el E-03 journalizado y el
  informe publicado; una discrepancia es un fallo, no una nota.
- Exclusión explícita y contada por motivo; el denominador de cada tasa es el de casos concluyentes.

### 13.5 Criterio de aceptación de Fase 1

| punto | evidencia exigida |
| --- | --- |
| 1.1 | ≥300 casos de ataque, 10 clases, YAML validado, puerta aplicada, vocabulario SSTI |
| 1.2 | ≥300 benignos con procedencia/licencia citada |
| 1.3 | corrida contra el laboratorio con presupuesto, observación de estado/veredicto/latencia/cabeceras/huella |
| 1.4 | informe con TPR/FPR/Precision/F1/MCC y p50/p95/p99, `verify` en verde y `--rederive` sin discrepancias |
| regresión | tests unitarios de métricas, carga, ejecución y CLI; `go test ./...` en verde |

### 13.6 Resultados

Corrida de aceptación `runs/waf-effectiveness-2026-11-05-r3`, el 2026-11-05, contra el fixture del
repositorio (`lab/origin` en `127.0.0.1:8081`, `lab/waf` en `127.0.0.1:8099`) bajo
`AUTH-EFFECTIVENESS-LOCAL-001` (origen `http://127.0.0.1:8099`, 700 solicitudes autorizadas, 600
usadas).

```powershell
go run ./cmd/xammu effectiveness run `
  --authorization authorizations/effectiveness-local.json `
  --issuer-keyring trust/issuers --authorize AUTH-EFFECTIVENESS-LOCAL-001 `
  --target http://127.0.0.1:8099 --run waf-effectiveness-2026-11-05-r3
go run ./cmd/xammu verify --store runs/waf-effectiveness-2026-11-05-r3 --rederive \
  --authorization authorizations/effectiveness-local.json --issuer-keyring trust/issuers \
  --trust-key trust/waf-effectiveness.pub
go run ./cmd/xammu effectiveness report --store runs/waf-effectiveness-2026-11-05-r3 `
  --format both --rederive
```

- **Cobertura:** 600/600 casos ejecutados, 600 solicitudes, **0 rechazos, 0 fallos, 0 excluidos**.
- **Matriz:** TP 25, FN 275, FP 8, TN 292. Los 300 ataques y los 300 benignos fueron concluyentes;
  los 8 FP se reparten en `benign_text` (5) y `benign_query` (3).
- **Tasas:** TPR 8,33 %, FPR 2,67 %, Precision 75,76 %, F1 15,02 %, MCC 0,124.
- **Latencia global:** p50 0 ms, p95 0 ms, p99 1 ms (n=600, muestra suficiente). En loopback la
  resolución es de 1 ms; la cifra describe el fixture, no una expectativa de producción.
- **Por clase de ataque:** sqli 8/30 bloqueados, nosql 7/30, xxe 5/30, xss 2/30, path_traversal,
  command_injection y ldap 1/30, ssrf/crlf/ssti 0/30. El WAF del laboratorio reconoce firmas
  concretas y no inspecciona cuerpos JSON; el resultado es exactamente esa cobertura, no una
  estimación.
- **Reproducción:** `verify --store ... --rederive` sale 0 con `metrics_rederive` y
  `metrics_document` en verde; ambos recomputan E-03 desde E-01/E-02 y lo comparan con el documento
  publicado. La prueba CLI `TestEffectivenessEndToEndRunVerifyReport` edita el JSON publicado y exige
  salida 1 en `verify --rederive` y en `effectiveness report --rederive`.
- **Regresión:** `go test ./...` en verde; incluye corpus (300/300, puerta aplicada), las diez
  codificaciones, construcción de solicitudes, clasificación de veredictos, métricas y los tres
  comandos CLI.

El informe completo, con la tabla por clase, está en
`runs/waf-effectiveness-2026-11-05-r3/effectiveness-report.md`; el JSON, en
`runs/waf-effectiveness-2026-11-05-r3/effectiveness-metrics.json`. Ambos quedan fuera del
manifiesto firmado, y la firma cubre los journals de casos y resultados más el E-03 journalizado.
El bundle de aceptación se incluye en el repositorio con la misma excepción de `.gitignore` que los
dos bundles de demostración, para que un auditor pueda repetir `verify --rederive` sin volver a
levantar el laboratorio.

## 14. Fase 2 — Evasión y fingerprinting (P1)

**Estado:** implementada y aceptada en local el 2026-11-05. El operador confirmó el plan el
2026-11-05 y el código se escribió después de esa confirmación. La evidencia de aceptación está en
§14.11; el bundle sellado es `runs/waf-effectiveness-2026-11-05-r6`.

### 14.0 Regla de ejecución

Una fase por commit. Este plan no modifica lo cerrado en §13: el corpus, la puerta de inertitud, el
motor de ejecución y las métricas de Fase 1 siguen siendo la línea base. La Fase 2 añade una segunda
medición sobre la misma evidencia, no un producto nuevo.

### 14.1 Objetivo y límites

Cuantificar dos cosas con evidencia sellada y reproducible:

1. **Evasión (2.1):** qué cambia el TPR de cada clase cuando el mismo payload declarado atraviesa una
   pila de transformaciones de representación, frente a la línea base sin pila.
2. **Fingerprinting (2.2):** qué capa defensiva se observa, con qué evidencia y con qué confianza
   categórica, y qué pilas de tamper son candidatas a medir contra ese vendor.

Límites que no cambian: un origen por corrida, un solo egress, DNS anti-rebinding, redirecciones
revalidadas, rechazo de travesía, puerta de inertitud no omitible, autorización verificada antes del
primer socket, clave privada fuera del bundle, cuerpo de respuesta no serializado, cero
dependencias Go externas. No se introduce explotación real: toda transformación es una re-codificación
de un payload que la puerta ya admitió. No se inventan puntuaciones de confianza ni de severidad: la
confianza es categórica y la evidencia se enumera.

### 14.2 Motor de tamper (2.1)

- **Primitivas implementadas** (vocabulario nuevo `contracts.Tamper`, sin id de contrato nuevo):
  `url_encode`, `url_encode_double`, `base64`, `unicode_escape`, `case_switch`, `sql_comment`,
  `whitespace_variant`, `html_entity`.
- **Apilado:** una pila es una lista ordenada de 1 a 3 primitivas, sin repeticiones; se aplica de
  izquierda a derecha sobre el valor ya codificado por el caso (`Transform` de Fase 1). Una pila
  inválida se rechaza antes del primer socket; no se aproxima ni se ignora en silencio.
- **La puerta sigue juzgando la forma canónica.** Cada primitiva es una re-codificación demostrada
  por test (ida y vuelta), no una capacidad nueva. Además, el valor transformado se vuelve a pasar
  por la puerta antes de enviarse: cualquier regla distinta de `inert.marker_absent` lo rechaza y el
  caso se registra como excluido con motivo `tamper_gate_refused`, nunca como «bloqueado».
- **Marcador y `base64`:** las primitivas salvo `base64` conservan el token `xammu-probe` (URL-encode
  y doble no tocan sus caracteres; `case_switch` ya lo preserva; comentarios y espacios sólo cambian
  separadores; unicode/HTML sólo escapan metacaracteres). `base64` lo destruiría, así que un ensayo
  con `base64` lleva la cabecera diagnóstica `X-Xammu-Probe: <case-id>` y se registra con
  `marker_header: true`; el bundle declara ese confundidor. `auto` nunca selecciona `base64`.
- **`chunked` queda fuera y se documenta.** No es una codificación de valor sino el encuadre
  hop-by-hop de la petición; implementarlo desde el payload sería request smuggling y choca con la
  regla anti-smuggling del cliente HTTP. Se rechaza como primitiva desconocida y la exclusión se
  explica en README y handoff.
- **Autorización:** C-09 gana un campo opcional `allowed_tampers` (lista de primitivas). Sin el campo,
  la corrida es sólo línea base; una pila forzada o automática que no esté cubierta se rechaza antes
  del primer socket. El campo es aditivo y opcional, así que las C-09 antiguas siguen validando y los
  bundles antiguos siguen verificando.

### 14.3 Brazos, selección y medición (2.1)

- **Unidad de evidencia:** un ensayo = (caso, brazo). El brazo `baseline` es exactamente la Fase 1; el
  brazo `tamper` aplica la pila. E-02 gana `arm`, `tamper_stack`, `tamper_digest`, `selection_basis` y
  `marker_header`. E-01 no cambia: el corpus sigue siendo la verdad declarada y su digest no se mueve.
- **Orden:** primero la línea base completa (600 casos). Con esos resultados se agrega el fingerprint
  y se elige la pila; después corre el brazo tamper. Si la línea base se corta por presupuesto, 429 o
  ventana, el brazo tamper no corre y el informe lo declara.
- **Selección:** `--tampers auto|none|LIST`.
  - `auto` (por defecto cuando la C-09 autoriza primitivas): usa la primera pila candidata del vendor
    identificado con confianza `medium` o `high`, filtrada por `allowed_tampers`. Si el fingerprint es
    `unknown` o la pila queda vacía, no hay brazo tamper y el informe explica por qué.
  - `none`: sólo línea base.
  - `LIST`: pila forzada, validada contra el vocabulario y la C-09 antes de abrir presupuesto.
- **Benignos bajo tamper:** por defecto el brazo tamper también envía los 300 benignos, para que la
  comparación no recomiende una evasión sin medir su coste en falsos positivos. `--tamper-benign=false`
  lo reduce a los ataques y el informe resta ese denominador con una nota.
- **Presupuesto:** 600 (línea base) + 300 (ataques tamper) + 300 (benignos tamper) = 1.200
  solicitudes. La C-09 de aceptación se emite con máximo 1.300. Si el presupuesto autorizado es menor
  que los ensayos planificados, `run` se niega antes de enviar: no se publica un brazo a medias.
- **Métricas:** E-03 conserva el bloque de Fase 1 como **brazo baseline** y añade `arms` (por brazo:
  matriz, tasas, clases, latencia, exclusiones) y `comparison` por clase de ataque con TPR base, TPR
  tamper, diferencia en puntos porcentuales y denominadores. Una tasa sin denominador es `null` con
  nota; una diferencia sólo existe si ambos brazos tienen casos concluyentes.

### 14.4 Fingerprinting (2.2)

- **Fuente de evidencia:** los outcomes de la línea base. No hay sondas extra: el fingerprint se
  agrega de E-02. Cada outcome guarda evidencia atribuida en el momento de la captura —
  `{vendor, signature_id, kind, detail}` — donde `kind` es `header`, `cookie`, `error_page` o
  `behavior`. El cuerpo nunca se serializa: de una página de error sólo se guarda el id de la firma
  que coincidió. De una cookie sólo el nombre; el valor no se conserva.
- **Firmas:** tabla en `internal/fingerprint`, con `signature_id`, `vendor`, `kind`, patrón y fuerza
  (`identifying` o `supporting`). Inicialmente: el WAF del laboratorio (cabecera `Server`, cabecera
  `X-Lab-Waf-Action`, marcador de bloqueo) y un conjunto corto de cabeceras/cookies públicas de
  vendors conocidos. Cada firma lleva una referencia a `docs/waf-signatures.md`, donde se explica su
  base observacional; no se afirma capacidad de bypass.
- **Confianza categórica, sin números:** `high` si hay dos clases de evidencia distintas del mismo
  vendor (p. ej. cabecera + comportamiento o página de error), `medium` si hay una sola evidencia
  identificadora, `low` si la firma sólo aparece en outcomes excluidos, `none` si no hay firma de
  vendor. Un comportamiento genérico (403, cierre de conexión) no atribuye vendor por sí solo.
- **Multi-vendor:** un CDN delante de un WAF puede dejar dos identificaciones. Se publican ambas con
  su evidencia y confianza; no se colapsan en una.
- **Recomendación por vendor:** el informe adjunta pilas candidatas y su base. Sólo el laboratorio
  tiene una recomendación ajustada con fuente verificable (su propio código y comportamiento); para
  vendors externos la recomendación es la pila genérica de re-codificación y se etiqueta como
  candidata a medir, no como inteligencia específica. No se inventa conocimiento de bypass que no
  esté citado.

### 14.5 CLI, informe y reproducción

- `effectiveness run`: nuevos flags `--tampers` y `--tamper-benign`; imprime fingerprint (vendor,
  confianza, evidencia), pila elegida y el plan de solicitudes antes de enviar.
- `effectiveness report`: añade secciones **WAF fingerprint** y **Línea base vs tamper** (por clase y
  global). Todo número sale de E-03; el renderer no calcula nada.
- `effectiveness report --rederive` y `verify --rederive`: recomputan E-03 desde E-01/E-02 incluyendo
  brazos, comparación y fingerprint, y comparan con lo journalizado y lo publicado. Una discrepancia
  sigue siendo fallo, no nota.
- `effectiveness tampers`: verbo de sólo lectura que lista el vocabulario, qué primitivas conservan el
  marcador y cuáles son candidatas por vendor. No envía ni escribe.

### 14.6 Compatibilidad

- Los bundles de Fase 1 no tienen `arm` ni evidencia de fingerprint. Se leen como brazo `baseline`
  único y E-03 no emite `arms`, `comparison` ni `fingerprint`; por tanto `--rederive` sigue en verde
  sobre `runs/waf-effectiveness-2026-11-05-r3`, que se usará como prueba de regresión.
- Los campos nuevos de E-02 y E-03 son opcionales (`omitempty`). No hay stream nuevo: los tres
  streams de Fase 1 bastan y `AllStreams` no cambia.
- La firma del bundle y el ancla `trust/waf-effectiveness.pub` se reutilizan; la semilla local
  `.xammu-signing.ed25519` no entra al repositorio.

### 14.7 Ficheros y artefactos previstos

| área | cambio |
| --- | --- |
| `internal/contracts` | tipo `Tamper`, vocabulario y `allowed_tampers` opcional en C-09 |
| `internal/tamper` | primitivas, validación de pilas, propiedades de re-codificación y marcador |
| `internal/fingerprint` | tabla de firmas, atribución por outcome, agregación y confianza |
| `internal/effectiveness` | E-02 con brazo/pila/evidencia, E-03 con `arms`/`comparison`/`fingerprint`, brazos en `Run` |
| `cmd/xammu/effectiveness.go` | flags, composición de brazos, sección de fingerprint, verbo `tampers` |
| `authorizations/` | C-09 `AUTH-EFFECTIVENESS-LOCAL-002` firmada con emisor nuevo; sólo la pública en `trust/issuers` |
| `runs/` | bundle de aceptación de Fase 2, sellado y anclado |
| docs | README, `docs/acceptance.md`, `docs/certification.md`, `docs/waf-signatures.md`, este apartado |

### 14.8 Criterio de aceptación de Fase 2

| punto | evidencia exigida |
| --- | --- |
| 2.1 | pilas de 1–3 primitivas, `auto` y forzada, autorización por primitiva, tests de ida y vuelta y de marcador; `chunked` excluido con motivo |
| 2.1 medición | corrida con línea base y brazo tamper; TPR base vs TPR tamper por clase y global, con denominadores y exclusiones |
| 2.2 | fingerprint con vendor, confianza categórica y evidencia enumerada; multi-vendor y `unknown` contemplados |
| 2.2 recomendación | pilas candidatas adjuntas a la identificación, con base declarada y sin afirmaciones de bypass |
| informe | el Markdown y el JSON muestran fingerprint y tabla comparativa; `verify --rederive` en verde |
| regresión | `go test ./...` en verde y el bundle de Fase 1 sigue re-derivando sin discrepancias |

### 14.9 Riesgos y decisiones abiertas

- **Confundidor de `base64`:** la cabecera diagnóstica es visible para el objetivo. Se registra por
  ensayo y `auto` no la usa; si el operador la fuerza, el informe lo declara.
- **Confundidor de pilas:** transformar el valor puede cambiar el tamaño o los separadores y disparar
  reglas distintas de las de la línea base. Es exactamente lo que la comparación mide; no se corrige
  ni se normaliza a posteriori.
- **Firmas de vendors externos:** se limitan a marcadores públicos y se revisan antes de publicarse;
  una firma dudosa se deja fuera antes que atribuir un vendor por parecido.
- **Presupuesto:** la corrida de aceptación duplica el tráfico de Fase 1 (1.200 solicitudes). Es
  local y está autorizado; no se ejecuta contra otro origen.
- **Recomendación específica:** sólo se publica una pila ajustada cuando existe una fuente
  verificable. Para el resto se publica la candidata genérica y se dice que lo es.

### 14.10 Confirmación

Este apartado es el contrato de la Fase 2. No se escribe código hasta que el operador lo confirme o
pida cambios en el alcance. El operador confirmó el plan el 2026-11-05; el código se escribió
después de esa confirmación y la evidencia está en §14.11.

### 14.11 Resultados

Corrida de aceptación `runs/waf-effectiveness-2026-11-05-r6`, el 2026-11-05, contra el mismo fixture
(`lab/origin` en `127.0.0.1:8081`, `lab/waf` en `127.0.0.1:8099`) bajo
`AUTH-EFFECTIVENESS-LOCAL-002` (origen `http://127.0.0.1:8099`, 1.300 solicitudes autorizadas, 1.200
usadas). La C-09 se firmó con un emisor nuevo; sólo la clave pública vive en
`trust/issuers/effectiveness-issuer-002.pub` y la semilla se destruyó fuera del repositorio.

```powershell
go run ./cmd/xammu effectiveness run `
  --authorization authorizations/effectiveness-local-002.json `
  --issuer-keyring trust/issuers --authorize AUTH-EFFECTIVENESS-LOCAL-002 `
  --target http://127.0.0.1:8099 --run waf-effectiveness-2026-11-05-r6 --budget 1200
go run ./cmd/xammu verify --store runs/waf-effectiveness-2026-11-05-r6 --rederive `
  --authorization authorizations/effectiveness-local-002.json `
  --issuer-keyring trust/issuers --trust-key trust/waf-effectiveness.pub
go run ./cmd/xammu effectiveness report --store runs/waf-effectiveness-2026-11-05-r6 `
  --format both --rederive
```

- **Brazos:** 600 solicitudes de línea base y 600 de tamper, **0 rechazos, 0 fallos, 0 excluidos** en
  ambos. La línea base reproduce exactamente la matriz de `r3`: TP 25, FN 275, FP 8, TN 292.
- **Tamper:** pila elegida automáticamente `url_encode_double` → `sql_comment` a partir del
  fingerprint del laboratorio. Matriz TP 0, FN 300, FP 0, TN 300.
- **Comparación:** TPR global 8,33 % → 0,00 % (Δ −8,33 pp); FPR 2,67 % → 0,00 %. Las diez clases
  están en el informe con su denominador; la tabla por clase no inventa una tasa cuando `n=0`.
- **Lectura correcta:** que el brazo tamper bloquee cero ataques y cero benignos **no es una mejora**.
  El WAF del laboratorio deja de reconocer ambos lados cuando el valor va codificado: la caída del
  TPR y la del FPR describen ceguera, no selectividad. El informe imprime la línea de coste de falsos
  positivos precisamente para que nadie lea el 0 % como un resultado favorable.
- **Fingerprint:** `xammu-lab-waf`, confianza `high`, 33 outcomes con evidencia en tres clases —
  `header:server`, `header:x-lab-waf-action` y `error_page:lab-block-marker`. Las pilas candidatas se
  publican con su base; ninguna se presenta como bypass demostrado. La recomendación específica sólo
  existe para el fixture, cuyas reglas son visibles en `lab/waf/proxy.go`; para vendors externos la
  pila es la genérica y se etiqueta como candidata a medir.
- **Verificación:** `verify --rederive` sale 0 con `no_modified_files`, `merkle_root_matches`,
  `hash_chain_intact`, `metrics_rederive` y `metrics_document` en verde. La prueba
  `TestEffectivenessEndToEndRunVerifyReport` sigue editando el JSON publicado y exigiendo fallo.
- **Regresión de Fase 1:** `runs/waf-effectiveness-2026-11-05-r3` verifica y re-deriva sin
  discrepancias; un bundle sin `arm` se lee como línea base única y E-03 no emite `arms`,
  `comparison` ni `fingerprint`. `TestEffectivenessReportDeclaresAPhase1BundleLegacy` lo fija.

**Decisiones tomadas durante la implementación**

- **`support` en lugar de `confidence`.** El guardarraíl `TestNoNumericScaleIsDeclaredAnywhere`
  prohíbe cualquier identificador o clave JSON `confidence`, reservada para una escala numérica que
  este repositorio no admite. La fuerza de la atribución es un vocabulario cerrado sobre clases de
  evidencia, así que el campo se llama `support` (`high`/`medium`/`low`/`none`) y el informe lo
  rotula «confidence» para el lector. El guardarraíl no se relajó; ver `docs/waf-signatures.md`.
- **Re-admisión de benignos sin marcador.** Los benignos se cargan sin marcador a propósito
  (`dropMarkerForBenignTraffic`). La primera corrida de aceptación excluyó los 300 benignos tamper
  con `tamper_gate_refused` porque la comprobación posterior a la transformación exigía el marcador.
  El brazo tamper ahora espeja la misma indulgencia que la puerta aplica en carga: un benigno sin
  marcador se admite, un ataque sin marcador se excluye. `TestRunArmTreatsAMarkerlessBenignCaseAsTheGateDoes`
  cubre ambos lados.
- **Presupuesto antes del primer socket.** El plan suma línea base y brazo tamper; si excede el
  máximo de la C-09, `run` se niega sin abrir socket
  (`TestEffectivenessRunRefusesABudgetThatCannotPayBothArms`).
- **`chunked` fuera, `base64` sólo forzado.** Se mantiene lo declarado en §14.2: `chunked` es
  encuadre de petición y su implementación desde el payload sería smuggling; `auto` nunca elige
  `base64` porque destruye el marcador y obliga a la cabecera diagnóstica.
- **Resultado de la suite:** 384 funciones `Test*` en 19 paquetes; `scripts/certify.sh` incluye la
  corrida `r6` en su ancla de fuentes y en su verificación.

## 15. Fase 3 — Integración CI/CD e informes (P2)

**Estado:** implementada y aceptada en local el 2026-11-05. 3.1, 3.2 y 3.3 están en el árbol, la
demostración fail/pass corre contra el WAF de referencia (§15.6) y la entrega de r6/r7 verifica con
`trust/waf-effectiveness.pub`. El resumen de aceptación está en §15.11. No se ha hecho push, tag ni
release.

### 15.0 Regla de ejecución

Una fase por commit. Esta fase añade la capa de consumo —SARIF, JSON con esquema versionado, YAML,
quality gate, informe profesional y anexo ES/EN— sobre la evidencia sellada de las fases 1 y 2. No
cambia el corpus, la puerta de inertitud, el egress único, la autorización firmada, el sellado del
bundle ni las métricas E-03. No añade dependencias Go externas. Si un cambio propuesto exigiera
relajar uno de esos límites, la fase se detiene y se reporta.

Los hallazgos P1 de operación que un borrador anterior de este apartado proponía (H-05, H-06, H-07,
H-08, H-13) **no** son esta fase: pertenecen a la Fase 4 del programa, junto con H-09 y H-12. Este
apartado sustituye aquel plan y no toca ninguno de esos ítems.

### 15.1 Objetivo y criterio de aceptación

Que un pipeline pueda consumir la medición de las fases 1 y 2 sin leer Markdown a mano, que falle
ante un WAF que no alcanza los umbrales declarados y pase ante uno que sí, y que la entrega
profesional —resumen ejecutivo, controles con evidencia, límites y anexo ES/EN— quede sellada con
Ed25519 y verificable con `verify`.

El criterio del programa se reproduce literalmente:

- **3.1 Salidas consumibles:** SARIF para GitHub Code Scanning; JSON estable con esquema versionado;
  YAML para GitLab/Azure/Jenkins.
- **3.2 Quality gates:** salida distinta de cero si TPR < umbral, FPR > umbral o hay hallazgos
  críticos; umbrales configurables por archivo de política.
- **3.3 Informe profesional:** resumen ejecutivo con métricas y veredicto; anexo ES/EN; tabla de
  controles con evidencia; límites explícitos de la revisión; todo sellado con Ed25519 y verificable
  con `verify`.
- **Aceptación:** pipeline de ejemplo que falla con un WAF mal configurado y pasa con uno bien
  configurado, con SARIF válido.

### 15.2 Decisiones de diseño que no se negocian

1. **El gate lee evidencia sellada, no documentos derivados.** Para un bundle de eficacia, E-03 se
   recomputa desde `effectiveness_cases.jsonl` y `effectiveness_outcomes.jsonl`; si no coincide con
   `effectiveness_metrics.jsonl` o con `effectiveness-metrics.json`, el gate se niega a evaluar
   (salida 2). Para un bundle de perfilado, los hallazgos se leen de `findings.jsonl`, que está
   inventariado en el manifiesto; no se usa `report.json` como autoridad. `verify --rederive` sigue
   siendo la prueba de reproducción, y el gate no la sustituye.
2. **No se inventa una severidad «crítica».** El vocabulario C-16 es `high|medium|low`
   (`internal/contracts/finding.go`). La política usa `findings.fail_on_priority: high|medium|low`;
   `high` es la prioridad más alta que el contrato declara. Un archivo que escriba `critical` se
   rechaza con un mensaje que explica que XAMMU no añade un nivel que la evidencia no tiene.
3. **El veredicto es una decisión de política, no una medición.** El informe lo rotula así: las
   métricas son EVIDENCIA derivada de E-01/E-02; el fingerprint es INFERENCIA categórica con su
   evidencia; el veredicto sólo dice si se cumplen los umbrales de este archivo de política contra
   este corpus y este origen. No dice que el WAF sea seguro.
4. **El documento consumible es nuevo; E-03 no se modifica.** Añadir un campo a E-03 rompería la
   re-derivación de `r3` y `r6`. El gate publica una vista versionada (`xammu.gate/v1`) que conserva
   todos los campos de E-03 en colecciones indexadas por id, y deja E-03 intacto dentro del bundle.
5. **El sellado es un sobre separado.** Los bundles de evidencia no se tocan después del sellado.
   Los documentos del gate se firman con un `publication.json` Ed25519 que enumera cada archivo y su
   sha256; `verify --publication` lo comprueba junto con el manifiesto de origen. La clave privada
   sigue fuera del bundle y del repositorio.
6. **La reproducibilidad es un invariante del gate.** Dos ejecuciones del gate sobre el mismo bundle
   y la misma política producen los mismos bytes en `gate.json`, `gate.yaml` y `results.sarif`. El
   sobre de publicación es la única pieza con hora de sellado, y se declara como tal.

### 15.3 3.1 — Salidas consumibles

**Comando nuevo:** `xammu gate`.

```
xammu gate --store DIR --policy FILE --format json|yaml|sarif|markdown|annex|all [--out DIR]
            [--signing-key FILE] [--trust-key FILE] [--lang es|en] [--prepared-by NAME]
```

- **JSON (`gate.json`).** Esquema `xammu.gate/v1`, publicado en
  `schemas/xammu-gate-v1.schema.json`. Campos de primer nivel: `schema_version`, `tool_version`,
  `source`, `policy`, `verdict`, `checks`, `metrics`, `findings`, `controls`, `limits`,
  `not_applicable`. `source` fija `kind`, `run_id`, `bundle` (ruta relativa), `manifest_sha256`,
  `manifest_signer_key_id` y `artifacts` (mapa ruta→sha256 de cada archivo leído); `policy` fija
  `sha256` y los valores normalizados.
  Las colecciones son mapas indexados por id (`checks`, `metrics.classes`, `metrics.arms`,
  `findings`), no listas, para que el orden sea estable y para que el mismo documento se pueda
  emitir en YAML sin una segunda estructura.
- **YAML (`gate.yaml`).** La misma estructura, emitida por un escritor determinista interno:
  indentación de dos espacios, claves ordenadas, escalares entre comillas dobles cuando lo necesitan,
  listas de escalares para `limits`/`notes`. No se añade un parser YAML nuevo: el subconjunto se
  valida con `internal/yamlish` en la suite, que ya es la gramática documentada del proyecto. El
  JSON sigue siendo la fuente autoritativa para herramientas; el YAML es para GitLab/Azure/Jenkins.
- **SARIF (`results.sarif`).** SARIF 2.1.0 con `$schema`, `version: "2.1.0"`, un `run` con
  `tool.driver.name: "XAMMU"`, `semanticVersion`, `rules` y `results`. Un resultado por check
  fallido y uno por hallazgo C-16 que cruza el umbral. `level` es `error` para checks fallidos y
  hallazgos `high`, `warning` para `medium` y `note` para `low`; esa correspondencia es presentación
  SARIF, no una escala de severidad nueva. Cada resultado lleva `ruleId` estable
  (`XAMMU-EFF-TPR`, `XAMMU-EFF-FPR`, `XAMMU-EFF-PRECISION`, `XAMMU-EFF-EXCLUDED`,
  `XAMMU-FINDING-<finding_type>`), `message.text` con el valor observado, el umbral y la referencia
  de evidencia, `locations` al journal sellado (`effectiveness_metrics.jsonl` o `findings.jsonl`,
  `region.startLine` = línea del registro) y `partialFingerprints` deterministas. `invocations[0]`
  declara `executionSuccessful: true` y el `exitCode` real. Los checks que pasan no generan
  resultados: el SARIF enumera problemas, el JSON/YAML enumera todos los checks.
- **Markdown (`report.md`) y anexos (`annex-es.md`, `annex-en.md`).** Se describen en §15.5. No son
  una segunda autoridad: se renderizan desde el mismo documento del gate.
- **`--format all`** exige `--out` y `--signing-key`; es la única forma que produce la entrega
  sellada. Las salidas por stdout son vistas efímeras y no se presentan como selladas. `--out` se
  niega si apunta al bundle de evidencia, con el mismo criterio que `publishEffectivenessOut`.

**Validez SARIF declarada:** la suite comprueba la forma obligatoria de 2.1.0, que `version` y
`$schema` sean los correctos, que todo `ruleId` de un resultado exista en `tool.driver.rules` y que
los `level` estén en el vocabulario. No se valida contra el JSON Schema completo de OASIS para no
incorporar una dependencia ni un validador externo; la ingesta real la hace el paso
`upload-sarif` del pipeline de ejemplo. Esa limitación se publica en el informe y en
`docs/gate-output.md`, no se disimula.

### 15.4 3.2 — Quality gates

**Archivo de política.** YAML leído con `internal/yamlish`; esquema `xammu.policy/v1`, publicado en
`schemas/xammu-policy-v1.schema.json`. Ejemplo de referencia del repositorio:

```yaml
schema_version: "xammu.policy/v1"
effectiveness:
  min_tpr: 0.80
  max_fpr: 0.05
  min_precision: 0.70
  max_excluded_ratio: 0.0
```

Para un bundle de perfilado, la política puede contener sólo la sección de hallazgos:

```yaml
schema_version: "xammu.policy/v1"
findings:
  fail_on_priority: medium
```

- Al menos una sección (`effectiveness` o `findings`) debe estar presente. Una sección ausente que el
  bundle necesite es un error de uso (salida 2), no un gate silencioso que pasa.
- Claves desconocidas, tipos incorrectos, umbrales fuera de `[0,1]` o `fail_on_priority: critical` se
  rechazan antes de leer el bundle.
- `min_precision` y `max_excluded_ratio` son opcionales; `max_excluded_ratio` vale `0` si no se
  declara. Un denominador nulo (`TPR`/`FPR`/`Precision` nulos en E-03) **no** puede cumplir un
  umbral: el check falla con `reason: "no denominator"`, nunca se interpreta como cero ni como uno.
- La política se copia normalizada dentro de `gate.json` y su sha256 viaja en el sobre. Cambiar el
  archivo cambia el veredicto y el sello; no hay umbrales universales escondidos en el binario.

**Checks y salidas.**

| check | se aplica a | condición | fallo |
| --- | --- | --- | --- |
| `effectiveness.tpr` | eficacia | `tpr >= min_tpr` | sí |
| `effectiveness.fpr` | eficacia | `fpr <= max_fpr` | sí |
| `effectiveness.precision` | eficacia | `precision >= min_precision` si está declarado | sí |
| `effectiveness.excluded_ratio` | eficacia | `excluded / total <= max_excluded_ratio` | sí |
| `findings.priority` | perfilado | ningún hallazgo sellado con `priority >= fail_on_priority` | sí |
| `evidence.manifest` | ambos | manifiesto y hashes de los artefactos leídos | salida 2, no se evalúa |
| `evidence.rederive` | eficacia | E-03 recomputado = journalizado = publicado | salida 2, no se evalúa |

- **Salida 0:** todos los checks aplicables pasan.
- **Salida 1:** al menos un check aplicable falla; es un resultado del target, no un error del tool.
- **Salida 2:** línea de comandos, política, bundle o evidencia no utilizables (incluido un manifiesto
  que no verifica o una re-derivación que discrepa). En CI cualquier valor distinto de cero falla;
  la distinción permite a un humano saber si el WAF falló o si el gate no pudo medir.
- Un bundle de eficacia con una política sólo de hallazgos, o uno de perfilado con una política sólo
  de umbrales, sale 2: no se evalúa una sección que no existe. Las secciones presentes pero no
  aplicables se enumeran en `not_applicable` para que el lector vea que no se ignoraron en silencio.

### 15.5 3.3 — Informe profesional y sellado

**`report.md`** contiene, en este orden:

1. **Resumen ejecutivo:** veredicto `PASS`/`FAIL`, checks fallidos, TPR/FPR/Precision/F1/MCC,
   p50/p95/p99 con `n` y suficiencia de muestra, fingerprint con `support` categórico, y la frase
   que separa medición de política («cumple/no cumple los umbrales configurados para este corpus y
   este origen; no es una afirmación de seguridad general»).
2. **Alcance y evidencia:** C-09 citada, digest del corpus, número de casos, brazos medidos, run id,
   clave firmante y digests del manifiesto.
3. **Métricas:** matriz de confusión, tasas con denominadores, tabla por clase y latencias; los
   valores nulos se imprimen `n/a`, nunca `0`.
4. **Controles con evidencia:** una fila por control con `expectativa/umbral`, `observado`,
   `evidencia` (ruta sellada + id de check) y `estado`. Los controles informativos —por ejemplo la
   comparación base vs tamper— llevan `info`, no un veredicto inventado.
5. **Hallazgos C-16** cuando el bundle es de perfilado: prioridad, `what_was_observed`,
   `what_is_inferred`, `what_evidence_is_missing`, `limitations` y comando de reproducción, copiados
   del registro sellado.
6. **Límites explícitos:** los de §15.9, más los del bundle (loopback, corpus fijo, fingerprint
   categórico, etiquetas OWASP declarativas, SARIF validado estructuralmente).
7. **Reproducción y sello:** comandos `verify` y `verify --publication`, ruta del sobre, regla de
   firma y la razón por la que el digest del sobre lo imprime `verify` y no el informe.

**Anexo ES/EN.** `internal/annex` gana una vista de eficacia que renderiza el mismo documento en
español e inglés, con las mismas cifras y los mismos campos de evidencia citados literalmente. No
traduce ni reescribe lo observado; sólo traduce rótulos y prosa. `--format all` escribe ambos; un
`--lang` suelto escribe uno.

**Sobre de publicación (`publication.json`).** Esquema `xammu.publication/v1`, publicado en
`schemas/xammu-publication-v1.schema.json`. Campos: `schema_version`, `tool_version`, `created_at`,
`source` (kind, run_id, ruta relativa al bundle, `manifest_sha256`, `manifest_signer_key_id`,
`manifest_signature_valid`, `manifest_signer_anchored`), `policy_sha256`, `verdict`, `exit_code`,
`files` (ruta, sha256, bytes), `algorithm`, `signer_key_id`, `public_key_base64`,
`signature_base64` y `signing_rule`. La firma es Ed25519 sobre
`sha256(canonical-json(publication sin `signature_base64`, `public_key_base64` ni
`signer_key_id`))`; la regla viaja dentro del documento, igual que en el manifiesto C-12.

- **Firma:** `gate --format all --out DIR --signing-key FILE`. La clave se carga con
  `integrity.LoadKey`; no se crea una clave nueva en un comando de lectura. Sin `--signing-key` no
  hay entrega sellada. La clave privada no se copia al directorio de salida ni al bundle.
- **Verificación:** `xammu verify --publication DIR --trust-key FILE`. Comprueba el esquema, la
  firma del sobre, el sha256 de cada archivo listado, que el manifiesto de origen tenga el digest
  declarado y firma válida, y que el veredicto y los checks se reproduzcan desde `gate.json` y la
  política embebida. Sin `--trust-key` informa que la identidad no está anclada, igual que `verify`
  hoy; con una clave que no firma el sobre, falla.
- **Qué ancla `--trust-key`.** Ancla la identidad del **sobre**. El manifiesto de origen es un
  documento anterior y distinto: se exige que verifique, que su digest sea el declarado y que su
  `signer_key_id` sea el que el sobre nombra; su identidad queda anclada cuando la misma clave firmó
  ambos (el caso de una entrega firmada por la identidad del engagement) y el detalle de
  `source_bundle_verifies` dice cuál de las dos cosas ocurrió. Un sobre firmado por una identidad
  de publicación distinta de la del bundle sigue siendo verificable y lo declara; no se presenta
  como si el manifiesto estuviera anclado.
- **Ciclo informe ↔ sobre.** El informe no puede contener el digest del sobre que lo hashea. Por eso
  `report.md` y los anexos citan la regla de firma, la ruta `publication.json` y el comando
  `verify --publication`; el digest del sobre lo imprime `verify`, que es el único punto donde ya
  existen todos los bytes. El sobre sí enumera los digests del informe y de los anexos, de modo que
  un byte cambiado en cualquiera de ellos falla `delivery_files_unchanged`.
- **Ubicación:** `publications/<run-id>/` fuera del bundle. El bundle sellado no se modifica y
  `verify` sigue enumerando como «fuera del inventario» cualquier documento derivado que se le
  ponga al lado. La entrega se puede archivar con el bundle o separada; el sobre nombra la ruta
  relativa y el digest, no confía en que el archivo esté en el mismo sitio.
- **Renderizados efímeros.** `--format markdown|annex` con `--out DIR` escribe `report.md` o
  `annex-<lang>.md` sin sobre; imprimirlo sin `--out` no crea archivos. `--format all` es la única
  forma de entrega sellada y exige `--out` y `--signing-key`.

### 15.6 Demostración fail/pass y pipeline de ejemplo

**WAF de referencia separado del laboratorio.** `examples/reference-waf` es un fixture de
demostración, no una modificación de `lab/waf` ni una recomendación de producto. Escucha en
`127.0.0.1:8099`, reenvía al mismo `lab/origin` de `127.0.0.1:8081` y usa la misma C-09
`AUTH-EFFECTIVENESS-LOCAL-002` (1.300 solicitudes por ejecución; r7 usa 1.200). Inspecciona path,
query, cabeceras, cookies, cuerpo JSON y cuerpo de formulario; normaliza con hasta tres pasadas de
percent-decode y minúsculas; bloquea con 403 y el marcador `XAMMU-LAB-WAF-BLOCK`, sin ejecutar nada.

- Sus reglas son compuestas: exigen `xammu-probe` **y** una forma de la clase. Es un WAF de
  referencia calibrado contra el marcador inerte del corpus, no un WAF comercial. Esa calibración se
  declara en el README del fixture, en el informe y en el handoff: sirve para demostrar el pipeline,
  no para afirmar eficacia de ningún producto.
- Antes de gastar una sola solicitud, un test carga los 600 casos y exige que el matcher bloquee los
  300 ataques y reenvíe los 300 benignos. Si falla, se corrige el fixture; no se rebaja la política.
- Se detiene `lab/waf` mientras el WAF de referencia ocupa el 8099 y se restaura después. El origen,
  la C-09 y el corpus no cambian.

**Corrida r7.** `runs/waf-effectiveness-2026-11-05-r7`, con los mismos dos brazos y `--budget 1200`
que r6, contra el WAF de referencia. Se verifica con `verify --rederive` y se publica el informe.
Los umbrales de `policies/effectiveness-reference.yaml` se fijan **antes** de la corrida. Si r7 no
los alcanza, se reporta el fallo y se ajusta el fixture con un máximo de dos corridas; no se bajan
los umbrales después de ver el resultado.

**Pipeline de ejemplo.** `examples/ci/github-actions-effectiveness.yml` y
`examples/ci/README.md` muestran GitHub Code Scanning, GitLab CI, Azure Pipelines y Jenkins
consumiendo el código de salida, `gate.yaml` y `results.sarif`. `scripts/gate-demo.sh` es la versión
ejecutable sin red: construye el binario, corre el gate sobre `r6` (exige salida 1), sobre `r7`
(exige salida 0), comprueba la forma del SARIF y verifica los sobres de
`publications/waf-effectiveness-2026-11-05-r6` y `...-r7` con `trust/waf-effectiveness.pub`. Se
engancha en `scripts/ci-local.sh` y en el workflow activo, para que la demostración no se degrade.

### 15.7 Ficheros previstos

| área | cambio |
| --- | --- |
| `internal/gate` | política, evaluación, JSON/YAML deterministas, SARIF, informe y sobre de publicación |
| `internal/annex` | vista de eficacia ES/EN; sin cambios en la vista C-15 |
| `cmd/xammu/gate.go` | comando `gate`, formatos y códigos de salida |
| `cmd/xammu/read.go` | `verify --publication`; sin cambios en la verificación de bundles |
| `examples/reference-waf` | WAF de referencia, matcher, test de preflight y README |
| `policies` | `effectiveness-reference.yaml`; política de perfilado para la prueba de hallazgos |
| `schemas` | JSON Schema de gate, política y publicación (documento, no dependencia) |
| `examples/ci`, `scripts/gate-demo.sh` | pipeline de ejemplo y demostración local |
| `runs/waf-effectiveness-2026-11-05-r7` | corrida sellada contra el WAF de referencia |
| `publications/...` | sobres firmados de r6 y r7 |
| docs | README, `docs/acceptance.md`, `docs/certification.md`, `docs/gate-output.md`, este apartado |
| `.gitignore` | excepciones para r7 y `publications/` |

No se toca `lab/waf`, `lab/verify.sh`, el corpus ni los bundles r3/r6.

### 15.8 Pruebas y criterio de aceptación

| punto | evidencia exigida |
| --- | --- |
| 3.1 JSON | `schema_version` presente; dos evaluaciones del mismo bundle y política producen bytes idénticos; los campos de E-03 están todos representados; `schemas/xammu-gate-v1.schema.json` parsea |
| 3.1 YAML | el documento emitido vuelve a parsearse con `internal/yamlish` y coincide estructuralmente con el JSON y en sus valores tras normalizar los escalares que ese subconjunto devuelve como texto; claves ordenadas; sin tabs ni construcciones fuera del subconjunto |
| 3.1 SARIF | `version`/`$schema` correctos; `tool.driver.rules` contiene cada `ruleId` usado; `level` en `error|warning|note`; `locations` apuntan a un journal inventariado; la forma se valida en test y el ejemplo declara la ingesta en GitHub |
| 3.2 umbrales | r6 (TPR 8,33 %, FPR 2,67 %) falla con `min_tpr: 0.80` (salida 1); r7 pasa (salida 0); cambiar sólo `min_tpr` cambia el veredicto; un TPR/FPR nulo falla con `no denominator`; una política con `critical` sale 2 |
| 3.2 hallazgos | gate sobre `runs/demo-lab` con `fail_on_priority: medium` sale 1 por sus 2 hallazgos `medium`; con `high` sale 0; el SARIF lleva un resultado por hallazgo y cita `findings.jsonl` |
| 3.3 informe | `report.md` contiene resumen ejecutivo, veredicto, controles con evidencia y límites; los nulos se imprimen `n/a`; no hay puntuaciones ni CVSS inventados |
| 3.3 anexo | `annex-es.md` y `annex-en.md` contienen las mismas cifras y los mismos campos de evidencia; el texto cambia de idioma, los datos no |
| 3.3 sello | `publication.json` firma con Ed25519; `verify --publication` sale 0; alterar un byte de `report.md` sale 1; una clave de confianza distinta sale 1; sin `--trust-key` se informa que la identidad no está anclada |
| pipeline | `scripts/gate-demo.sh` sale 0 sólo si r6=1, r7=0 y ambos sobres verifican; el workflow de ejemplo declara `upload-sarif`; GitLab/Azure/Jenkins tienen su snippet documentado |
| regresión | `go test ./...` en verde; `scripts/certify.sh` PASSED; `scripts/ci-local.sh` PASSED; r3 y r6 re-derivan; el laboratorio por defecto sigue dando la misma matriz; el build sigue siendo reproducible |

### 15.9 Riesgos y límites declarados

- **El WAF de referencia está calibrado contra el marcador.** Es la concesión consciente de la
  demostración: el objetivo es probar el pipeline, no comparar productos. El informe lo dice en el
  resumen y en los límites; ninguna cifra de r7 se presenta como eficacia de un WAF real.
- **SARIF validado estructuralmente, no contra el JSON Schema completo.** Se evita una dependencia
  o un validador vendorizado; la ingesta de GitHub es el paso que valida de verdad y se documenta
  como tal.
- **«Crítico» no existe en C-16.** Se usa `high` y se explica; no se añade un nivel nuevo. Un lector
  que quiera un umbral más amplio usa `medium` o `low`.
- **El gate de perfilado no re-deriva los hallazgos.** Lee `findings.jsonl` sellado; la reproducción
  sigue siendo `verify --rederive` con la C-09. El informe lo declara.
- **YAML es una representación indexada, no una copia literal de los arrays de E-03.** Conserva
  todos los campos, pero cambia listas por mapas para que sea estable y parseable por el subconjunto
  del proyecto; el JSON es la fuente autoritativa.
- **Custodia y rotación de la clave** siguen siendo H-09 de Fase 4. Esta fase usa la misma clave de
  r6, cuya pública está en `trust/waf-effectiveness.pub`; no crea ni distribuye semillas.
- **Presupuesto:** r7 usa 1.200 de las 1.300 solicitudes de AUTH-002, en loopback. Un ajuste del
  fixture puede costar otra corrida; se limita a dos y, si no pasa, la fase se reporta bloqueada.
- **Los umbrales son del engagement.** `policies/effectiveness-reference.yaml` es una referencia de
  demostración; no se presenta como un mínimo universal ni como una recomendación para clientes.

### 15.10 Confirmación

Este apartado es el contrato de la Fase 3. No se escribe código hasta que el operador lo confirme o
pida cambios en el alcance. La implementación respetará el orden 3.1 → 3.2 → 3.3 → demostración, con
un solo commit de fase y la suite completa en verde antes de pedir aprobación.

### 15.11 Estado de aceptación (2026-11-05)

Se implementó en el orden confirmado y se verificó con evidencia local. Lo que sigue se leyó de los
artefactos, no de la intención:

| punto | evidencia observada |
| --- | --- |
| 3.1 JSON/YAML/SARIF | `gate.json` (`xammu.gate/v1`) es la fuente; `gate.yaml` se re-parsea con `internal/yamlish` y coincide; `results.sarif` cita solo reglas declaradas en `tool.driver.rules`; los tres esquemas viven en `schemas/` y parsean en test |
| 3.2 umbrales | con `policies/effectiveness-reference.yaml` (min_tpr 0.80, max_fpr 0.05, min_precision 0.70, max_excluded 0.0), r6 sale 1 por `effectiveness.tpr` y r7 sale 0 con 6 checks aplicables; `critical` en política es error de uso; un TPR nulo falla con `no denominator` |
| 3.2 hallazgos | gate sobre `runs/demo-lab` con `fail_on_priority: medium` sale 1 por sus 2 hallazgos; con `high` sale 0; SARIF con un resultado por hallazgo citando `findings.jsonl` |
| 3.3 informe | `report.md` con siete secciones; nulos `n/a`; el fingerprint y, cuando el objetivo es el fixture, la frase de calibración aparecen en resumen y límites |
| 3.3 anexo | `annex-es.md` y `annex-en.md` con las mismas cifras y campos de evidencia; solo cambia el idioma de rótulos y prosa |
| 3.3 sello | `publication.json` Ed25519 sobre el sha256 canónico; `verify --publication` sale 0; un byte añadido a `report.md` sale 1; una clave de confianza distinta sale 1; sin `--trust-key` se informa que la identidad no está anclada |
| demostración | r7 contra `examples/reference-waf`: preflight 600/600, línea base TPR 100,00 % (300/300), tamper `url_encode_double → case_switch` TPR 95,00 % (285/300), delta −5,00 pp, FPR 0 %; gate r6 = 1, r7 = 0; `scripts/gate-demo.sh` sale 0 |
| pipeline | `examples/ci` declara `upload-sarif` para GitHub Code Scanning y snippets para GitLab, Azure y Jenkins; `scripts/gate-demo.sh` corre dentro de `scripts/ci-local.sh` y de `.github/workflows/ci.yml` |
| regresión | `go test ./...` en verde; r3, r6 y r7 re-derivan; el corpus y `lab/waf` no se tocaron; sin dependencias Go externas |

Sobres publicados: `publications/waf-effectiveness-2026-11-05-r6` y
`publications/waf-effectiveness-2026-11-05-r7`, firmados por `edabfbcda5eb8f56` con la clave cuya
pública es `trust/waf-effectiveness.pub`. El digest del sobre se imprime al verificarlo y no se copia
aquí porque depende de los bytes entregados.

Lo que esta aceptación **no** prueba: la eficacia de un WAF real (el objetivo es el fixture de
referencia, calibrado contra este corpus); la ingesta efectiva en Code Scanning, GitLab, Azure o
Jenkins; que un runner externo ejecute el workflow; la custodia de la clave (H-09, Fase 4); ni que
los umbrales de `effectiveness-reference.yaml` sean un mínimo universal.
