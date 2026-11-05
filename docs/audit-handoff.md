# Handoff de auditoría — XAMMU v1.0.0

| campo | valor |
| --- | --- |
| Documento | Informe de auditoría interna y handoff técnico |
| Fecha | 2026-11-05 |
| Base revisada | `bdcb145901e196b8b52995674dcb8a97f29c101f` (`main`) más el conjunto de entrega pendiente de commit: anexo ES/EN, expediente de certificación, anclas `trust/`, guía de clave fuera del bundle y `.gitattributes` |
| Árbol de trabajo | Limpio de secretos; 9 archivos modificados y 9 nuevos listos para commit; bundles demo sin cambios |
| Método | Revisión estática de rutas críticas, ejecución de la suite, `go vet`, `gofmt`, `scripts/certify.sh`, `verify` con `--trust-key`, gitleaks 8.30.1 sobre árbol e historial, y lectura del modelo de amenaza documentado |
| Herramientas | Go 1.27.0 windows/amd64; gitleaks 8.30.1 |
| Evidencia | `dist/certification-20261105T182628Z.txt` (RESULT: PASSED), `dist/gitleaks-worktree.json` y `dist/gitleaks-history.json` (vacíos) |
| Naturaleza | Auditoría interna. **No** es una certificación externa, un pentest ni una prueba de conformidad legal |

> Ancla de árbol de la certificación citada: `188d68c07c9f443ae9f7bfccf7df09039d79e169a15e2e897996c0b54baea12c`.
> Ese hash se calculó antes de añadir este documento; como el propio handoff vive bajo `docs/`, volver a
> ejecutar `scripts/certify.sh` después del commit produce el ancla definitiva de la entrega.

---

## 0. Veredicto en una página

XAMMU es una herramienta **defensiva de descubrimiento de comportamiento** para un único egress autorizado.
No busca vulnerabilidades: mide cómo un WAF o front-end trata tráfico **inerte y marcado** frente a su tráfico
de referencia, y publica hallazgos con la evidencia separada de la inferencia. Su diseño es inusualmente
conservador y honesto; su principal debilidad de seguridad no está en el egress ni en el sellado, sino en la
**autorización C-09**: se valida estructuralmente, pero no se verifica ninguna firma, aunque el encabezado del
programa afirma que se envía «only through an authorization someone signed».

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
1. **H-01 (Alto):** la autorización no está firmada ni se verifica; `issuer_key_fingerprint` es texto libre.
2. **H-02 (Alto):** se journalizan valores completos de cabeceras de respuesta, incluido `Set-Cookie`, mientras
   la política de retención sólo gobierna el cuerpo.
3. **H-03 (Medio):** las anclas de confianza de los demos son TOFU; prueban continuidad, no identidad.

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
documental y **2 no reclamados** (CI limpio y prueba con ingeniero externo). La suite local es de 296 funciones
en 15 paquetes, sin fallos.

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
- **No hay CI** (`.github` no existe). La certificación se ejecuta a mano en un host.

### 5.3 Repositorio y distribución

- Repositorio Git con remoto GitHub; bundles demo y autorizaciones de demostración versionados.
- `.gitignore` excluye binarios, `dist/`, `*.ed25519` y `*.key`.
- `.gitattributes` fija LF para fuentes y documentos y `-text` para `runs/**`, de modo que la evidencia sellada
  no se convierta al hacer checkout.
- La release produce binario + `.sha256`; **no** hay firma de artefacto, SBOM ni procedencia.

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
- Las **cabeceras de respuesta sí se guardan completas** (nombre y valor), con digest adicional
  (`internal/httpclient/client.go:371-382`).
- Los bundles pueden contener rutas, cabeceras, estados y digests del target; no contienen la clave privada.

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
| Build/distribución | scripts locales | build reproducible, sin firma de release | medio (H-04/H-10) |

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
| Sin secretos en árbol ni historial | gitleaks 8.30.1, 2 commits, 0 fugas |
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

#### H-02 — Cabeceras de respuesta retenidas completas (Alto)

- **Evidencia:** `internal/httpclient/client.go:371-382` guarda `Name` y `Value` de cada cabecera;
  `contracts/observation.go:104-108` los persiste. La retención sólo limita el cuerpo.
- **Impacto:** un target puede devolver `Set-Cookie`, tokens de sesión, trazas internas o cabeceras de
  infraestructura en respuestas de error. Esos valores acaban en el bundle y pueden viajar al anexo de cliente.
  En pruebas con autenticación delegada o cookies de sesión, el bundle se convierte en un portador de secretos.
- **Recomendación:** política de retención de cabeceras independiente; por defecto guardar sólo nombre y digest
  de valor para `Set-Cookie`, `Authorization`, `Proxy-Authorization`, `X-Api-Key` y prefijos sensibles;
  permitir valor completo sólo con autorización explícita. Añadir test de que un `Set-Cookie` no aparece en claro.

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

1. **Firmar y verificar C-09/C-10** (H-01). Sin esto, la frase «authorization someone signed» debe eliminarse.
2. **Retención de cabeceras sensibles** (H-02): digest por defecto para `Set-Cookie` y credenciales.
3. **Registrar la clave pública por canal independiente** y dejar de presentar `trust/` como identidad (H-03).
4. **CI mínimo con gitleaks, vet, test, govulncheck y verificación de fin de línea** (H-04).

### P1 — siguiente iteración

5. Lock de presupuesto por autorización/origen (H-05).
6. Contención de `--run` y validación de IDs (H-06).
7. Identidad del corpus por subárbol + estado sucio (H-07).
8. Aplicar o retirar `RequireTLS`; tope de cabeceras (H-08).
9. Firma de release + SBOM (H-10).
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
- **Sin `govulncheck`.** No estaba instalado; la ausencia de dependencias externas reduce, pero no elimina, el
  riesgo de stdlib.
- **Confianza TOFU.** Las anclas de los demos no prueban identidad.
- **Sin revisión legal.** El documento no valida el marco contractual ni la normativa aplicable al engagement.

---

## 9. Cómo reproducir la evidencia

```bash
# suite y certificación interna
bash scripts/certify.sh

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

Salida esperada: `RESULT: PASSED`, `signer_is_trusted` en ambos bundles, `no leaks found` y dos builds
idénticos byte a byte.

---

## 10. Plan de Fase 0 (P0) — aprobado; 0.1 cerrado

> **Estado (2026-11-05):** las cinco decisiones recomendadas se confirmaron y **0.1 está cerrado**
> con la evidencia de §10.1.1. 0.2 y 0.3 siguen pendientes; no se inicia Fase 1 hasta que este
> documento diga **P0 cerrado**. La regla de trabajo sigue siendo una fase por commit, con tests
> verdes, README y handoff actualizados.

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

### 10.2 Retención de cabeceras sensibles (H-02)

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

### 10.4 Criterio de aceptación de Fase 0

| punto | evidencia exigida |
| --- | --- |
| 0.1 | ✅ suite nueva en verde (296 funciones); `verify` con autorización manipulada sale 1 con mensaje explícito; `run` rechaza antes del socket; demos firmados con sidecars y anillo publicado. **Salvedad:** los comandos dentro de los bundles son anteriores a 0.1 y no citan el anillo; regenerarlos exige el fixture Docker (§10.1.1) |
| 0.2 | test que recorre el bundle y no encuentra el valor literal; detectores intactos; política documentada |
| 0.3 | CI o `ci-local.sh` en verde; dos builds idénticos; `.sig`, `.sha256` y SBOM publicados; comandos de verificación documentados |
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
| Sin secretos versionados | gitleaks (árbol e historial) |
| Build reproducible | `scripts/release.sh`, `scripts/certify.sh` |

## 12. Anexo B — Glosario

- **C-09:** autorización de perfilado (scope, ventana, presupuesto, retención).
- **C-10:** autorización de validación de una hipótesis contra un target y una lista de sondas.
- **C-15:** contrato del informe.
- **C-16:** contrato del hallazgo, con campos de honestidad y comando de reproducción.
- **TOFU:** *trust on first use*; la clave se acepta la primera vez y sólo se detectan cambios posteriores.
- **Inertitud:** propiedad de una sonda de ser diagnóstica y no explotable, verificada por la puerta.
- **Bundle:** directorio de evidencia sellado con manifiesto firmado.
- **Celda:** combinación de clase, vector y codificación medida en una ejecución.
