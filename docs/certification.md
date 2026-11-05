# Certificación interna de XAMMU v1.0.0

Este documento es el expediente de aceptación interna de XAMMU para Izkuna. Responde a una
pregunta concreta: **¿qué versión exacta del artefacto se aceptó, con qué evidencia, bajo qué
invariantes y con qué límites?** No es una certificación de terceros, no es una atestación de
cumplimiento y no convierte a XAMMU en un escáner de vulnerabilidades.

- Artefacto: XAMMU v1.0.0 (`xammu-1.0.0`, esquema C-15 1.0.0).
- Alcance: el árbol de `D:\Xammu` y el binario que produce `scripts/release.sh`.
- Estado de la matriz de aceptación: [`docs/acceptance.md`](acceptance.md) — 23 criterios ✅,
  3 ◐ por vocabulario, 1 ○ documental y 2 ⚠ que este repositorio no puede cerrar solo.
- Evidencia ejecutable: `bash scripts/certify.sh`, que escribe
  `dist/certification-<UTC>.txt` y termina con `RESULT: PASSED`.

---

## 1. Qué significa «certificada» aquí

| expresión | lo que sí significa | lo que no significa |
| --- | --- | --- |
| certificación interna | Izkuna acepta una versión concreta tras ejecutar y revisar la evidencia de §3 | que un tercero haya auditado el binario |
| build reproducible | dos compilaciones del mismo árbol producen bytes idénticos en el mismo host | que cualquier host y cualquier toolchain produzcan el mismo hash |
| evidencia sellada | los bundles de demostración se comprometen con una cadena de hashes y una firma Ed25519 | que las lecturas del WAF sean correctas, ni quién firmó |
| permiso firmado | toda C-09/C-10 exige un sidecar Ed25519 y un emisor presente en el anillo que nombra el operador | que ese emisor sea una identidad del mundo real: la clave pública tiene que llegar por un canal independiente |
| anexo técnico | un documento de cliente derivado del C-15, con los campos de evidencia verbatim | una certificación del WAF del cliente |

La firma de los bundles se verifica contra la clave pública incluida en el propio manifiesto. Sin
una clave de confianza obtenida por un canal independiente, la verificación prueba integridad, no
identidad. Esa distinción está impresa por `xammu verify` y se repite en la sección 8 del anexo.

La firma de las autorizaciones es una cadena distinta: un sidecar `<archivo>.sig` cubre el payload
canónico con separación de dominio y de contrato, y se verifica contra `--issuer-keyring DIR`. No
hay anillo por defecto ni descubrimiento desde el documento; el fingerprint de la C-09 se deriva de
la clave que verificó, nunca se acepta el texto declarado.

---

## 2. Artefacto aceptado y anclaje

La unidad certificada es el **árbol fuente más el binario**:

1. El árbol se identifica con un `sha256` calculado sobre `cmd/`, `internal/`, `corpus/`, `lab/`,
   `docs/`, `scripts/`, `authorizations/` (permisos y sus `.sig`), `trust/`, `go.mod`, `README.md`,
   `LICENSE` y los dos bundles de demostración. Lo imprime `scripts/certify.sh` como
   `source tree sha256`.
2. El binario se construye con `scripts/release.sh`: `CGO_ENABLED=0`, `-trimpath`,
   `-buildvcs=false`, `-ldflags "-s -w -buildid="`, dos compilaciones comparadas byte a byte, y
   `dist/xammu-1.0.0-<os>-<arch>[.exe].sha256`. La ruta de release del workflow añade SBOM
   CycloneDX y firma keyless de binario, checksum y SBOM; esa ruta no se ha ejecutado todavía.
3. El árbol vive en un repositorio Git (`main`). El commit es el ancla primaria; el hash del árbol
   que imprime `scripts/certify.sh` comprueba que lo compilado es lo aceptado, aunque el workspace
   se copie fuera de Git.

Una entrega se acepta solo si el aprobador archiva, junto al binario, el
`dist/certification-<UTC>.txt` de la corrida que revisó.

---

## 3. Cómo se reproduce la aceptación

Requisitos: Go 1.27.3 (la versión fijada en el workflow) en `PATH`, Bash y `sha256sum`. En Windows,
Git Bash. No requiere Docker, red, ni un objetivo real.

```bash
cd /d/Xammu
bash scripts/certify.sh
```

`scripts/ci-local.sh` es el espejo local de `.github/workflows/ci.yml`: formato, vet, build, suite,
`-race` si hay cgo, `govulncheck` y gitleaks si están en `PATH`, build reproducible y SBOM si Syft
está instalado. Imprime `SKIP` por cada check que no puede ejecutar y lo cuenta en el resultado. El
workflow de GitHub no se ha ejecutado todavía; sin push, la evidencia es local.

La corrida ejecuta, en este orden, y falla en el primer desacuerdo:

1. `gofmt -l cmd internal` debe salir vacío.
2. `go vet ./...`.
3. `go build ./...`.
4. `go test ./... -count=1`.
5. `go run ./cmd/xammu corpus check --corpus corpus` (la puerta de inertez).
6. `verify` de `runs/demo-lab` y `runs/demo-origin` contra sus manifiestos firmados, con las
   claves fijadas en `trust/` (`--trust-key`) y el anillo de emisores de permisos
   (`--issuer-keyring trust/issuers`).
7. Anexo ES en Markdown desde `demo-lab` y anexo EN en HTML desde `demo-origin`, con hash de cada
   archivo.
8. Construcción reproducible y hash del binario.
9. Hash del árbol fuente.

Salida esperada: secciones `== 1.` a `== 5.` y `RESULT: PASSED`. La última sección del archivo
declara lo que la corrida **no** prueba.

---

## 4. Evidencia de la suite local

| propiedad | cómo se comprueba | resultado esperado |
| --- | --- | --- |
| suite completa | `go test ./... -count=1` | 306 funciones de prueba en 15 paquetes, sin fallos |
| cabeceras sensibles | `go test ./cmd/xammu/ ./internal/httpclient/ ./internal/contracts/` | el valor literal no aparece en ningún artefacto; digests salados estables dentro del run y distintos entre runs; `Server` y `Content-Type` intactos |
| firmas de autorización | `go test ./cmd/xammu/ ./internal/integrity/` | sidecar válido aceptado; campo, firma, contrato, clave o emisor alterados rechazados; `run` no abre socket con una C-09 inválida |
| criterios del handoff | [`acceptance.md`](acceptance.md) §2 | 29 criterios clasificados; ninguno ⚠ contado como cumplido |
| inertez del corpus | `xammu corpus check --corpus corpus` | tres particiones cargadas, sin fugas entre particiones |
| integridad de evidencias | `xammu verify --run demo-lab` y `demo-origin` | `no_modified_files`, `merkle_root_matches`, `hash_chain_intact` en verde |
| re-derivación | `xammu verify --rederive` con la autorización del run | los hallazgos publicados se re-derivan sin divergencias |
| anexo de cliente | `go test ./internal/annex/` y `./cmd/xammu/` | estructura ES/EN, escape HTML, cifras del informe y evidencia verbatim |
| no hay escalas numéricas | `internal/contracts/forbidden_source_test.go` | ninguna puntuación ni confianza numérica en contratos y código |
| un solo egress | `internal/httpclient/egress_test.go` | ninguna otra ruta de red en el árbol |
| cadena de CI fijada | revisión de `.github/workflows/ci.yml`; `scripts/ci-local.sh` | acciones de terceros por SHA, herramientas por versión, `go.mod` sin dependencias externas; gitleaks y `govulncheck` se ejecutan si están disponibles |
| vulnerabilidades de la stdlib | `govulncheck` 1.9.0 con Go 1.27.3 | `No vulnerabilities found`; con 1.27.0 el mismo escaneo encontraba 9 vulnerabilidades que afectaban al cliente HTTP |

El conteo «306 funciones» cuenta funciones `Test*`, no subcasos; los subcasos se ejecutan dentro de
cada función y su fallo tumba la suite igual.

---

## 5. Invariantes de seguridad

Estas propiedades son la razón por la que la herramienta puede usarse en un engagement. Cada una
tiene una prueba o una comprobación de aceptación; ninguna depende de que alguien recuerde la prosa.

| invariante | implementación | evidencia |
| --- | --- | --- |
| La puerta de inertez es precondición de carga y ninguna bandera la salta | `internal/corpus/corpus.go:128` (`Load` corre la puerta antes de devolver el corpus) | `go test ./internal/corpus/`; `corpus check` |
| Solo hay un cliente de red autorizado | `internal/httpclient` es el único paquete que abre conexiones | `internal/httpclient/egress_test.go` |
| Las banderas recortan, nunca amplían | el plan se construye contra la C-09 y se rechaza si excede presupuesto, clases, vectores, rutas, CIDRs o métodos | `internal/orchestrator/plan.go` y sus tests |
| `run` exige `--authorization` y `--authorize`, y una C-09 vigente | pre-check en `cmd/xammu/run.go:70`; re-check durante la ejecución en `internal/orchestrator/run.go:230` | tests de CLI y de orquestador |
| Una autorización sin firma, alterada o de un emisor fuera del anillo no llega a planificar | sidecar Ed25519 separado, dominio y etiqueta de contrato, fingerprint derivado, digest C-10 recomputado (`cmd/xammu/load.go`, `internal/integrity/authsig.go`) | `TestRunRefusesAnAuthorizationBeforeTheSocket`, `TestValidationAuthorizationIsImmutableAndSigned`, `TestAuthorizationSignatureBindsDocumentKindAndKey`, `TestVerifyReportsATamperedAuthorizationAsAFailure` |
| Una ejecución mide un solo objetivo | la C-09 y el perfil fijan un `TargetOrigin` | `internal/orchestrator` y `cmd/xammu` |
| `report`, `verify` y `validate` no escriben en el bundle | abren el store para lectura y derivan en memoria | `cmd/xammu/read.go`; pruebas de re-derivación |
| La clave privada nunca entra al bundle | el seed vive fuera; `seal` rechaza una ruta de clave dentro del directorio que firma; el manifiesto solo lleva la pública | `TestSigningKeyMustLiveOutsideTheBundle` y `assertNoPrivateKeys` en `cmd/xammu/run_test.go` |
| Los comandos publicados están atados a una autorización o a un run | C-16 rechaza un `reproduction_command` sin `--authorization` ni `--run` | `internal/contracts/finding.go` |
| La cadena de build no admite acciones mutables | `.github/workflows/ci.yml` fija cada acción por SHA y cada herramienta por versión; `go.mod` sigue sin módulos externos | revisión del workflow; `go list -m all`; `scripts/ci-local.sh` |
| El informe declara lo que no evalúa | los seis `RequiredOutOfScope` son obligatorios en C-15 | `internal/contracts/report.go` |
| El anexo no mide ni parafrasea la evidencia | comparte un solo recorrido para Markdown y HTML; los campos C-16 se copian literales | `internal/annex/annex_test.go` |
| Nada se envía fuera DEL alcance autorizado | política de destino y refusal de rutas no cubiertas | `internal/httpclient/policy.go`; el rechazo de `/..%2F..%2F` es intencional |
| Un valor sensible no llega a la evidencia | lista base de cabeceras, `--sensitive-header` sólo amplía, marcador y digest salado por run, salt no serializado (`internal/contracts/redaction.go`, `internal/httpclient/client.go`) | `TestSensitiveResponseHeadersNeverReachTheBundle`, `TestSensitiveHeadersAreRedactedAtCapture`, `TestRawObservationEnforcesTheRedactionClaim` |

La sonda `/..%2F..%2F` se rechaza porque su ruta queda fuera de los prefijos autorizados. Es
comportamiento correcto y no se relajó para que el laboratorio midiera «más»: medir fuera del
permiso no es una capacidad, es un incidente.

---

## 6. Modelo de amenaza (resumen)

| activo | amenaza | mitigación | límite declarado |
| --- | --- | --- | --- |
| alcance autorizado | una bandera o un comando reproducido envía fuera del permiso | C-09 obligatoria, banderas que solo recortan, comandos atados a autorización/run | una C-09 mal emitida por un humano no se detecta; el permiso es la autoridad |
| disponibilidad del objetivo | sondas que dañan o saturan | sondas inertes verificadas, presupuesto, rate limit, circuit breaker | el corpus no puede probar que un tercero no modificó el binario |
| evidencia | edición posterior del bundle | cadena de hashes, Merkle, firma Ed25519, re-derivación | sin ancla de confianza externa, la firma no prueba identidad |
| datos del cliente | fuga de capturas o del nombre del cliente | retención digest-only por defecto; cookies y credenciales de respuesta sustituidas por marcador y digest salado; el anexo no se guarda en el bundle | el operador decide qué metadatos escribe en `--client`; un valor marcado no se puede recuperar del digest |
| clave de firma | robo del seed | el seed vive fuera del árbol y se ignora por `.gitignore` | la custodia del archivo es responsabilidad del operador |
| lectura del informe | un documento que exagera lo medido | C-16 exige cuatro campos de honestidad; C-15 exige los disclaimers; sin puntuaciones | la redacción sigue siendo responsabilidad del revisor humano |
| cadena de build | una acción o herramienta de CI sustituida | acciones fijadas por SHA, herramientas por versión (gitleaks además por checksum), `go.mod` sin módulos externos, SBOM y firma keyless en tags | el workflow no se ha ejecutado; la firma keyless publica certificado y firma en el log público de Rekor |

Fuera del modelo: compromiso del host del operador, del compilador o de la cadena de custodia
física; ataques de red entre el operador y el objetivo; evaluación de la lógica de la aplicación.

---

## 7. Uso autorizado

Procedimiento mínimo para un engagement de Izkuna:

1. Emitir una C-09 con un solo origen, presupuesto, clases, vectores, rutas, CIDRs y caducidad.
2. `xammu playbook --authorization FILE --corpus corpus` para revisar el costo y el alcance sin
   enviar nada.
3. `xammu run --authorization FILE --authorize REF --run ID ...` solo con la autorización en mano.
4. `xammu verify --run ID ...` sobre el bundle sellado.
5. `xammu report --run ID ... --format human` para el informe técnico interno.
6. `xammu report --run ID ... --format annex|annex-html --lang es|en --client ... --out DIR` para
   el anexo que se adjunta al entregable del cliente.

Reglas de entrega:

- El anexo se adjunta al informe de auditoría; no lo sustituye.
- El anexo declara que no certifica la seguridad del WAF ni evalúa vulnerabilidades de la
  aplicación, y que una ejecución mide un objetivo.
- Las prioridades no son CVSS. Los campos de evidencia se citan en el idioma del registro C-16.
- Una autorización vencida impide ejecuciones nuevas, no invalida la evidencia ya sellada.

---

## 8. Límites y brechas abiertas

- **CI versionado sin corrida externa.** `.github/workflows/ci.yml` contiene la cadena completa y
  `scripts/ci-local.sh` pasa en la máquina de entrega, pero no hay una corrida limpia en un runner
  de GitHub. Criterio 7 sigue en ⚠. El workflow tampoco levanta el laboratorio Docker.
- **Release sin firma ejecutada.** El workflow firma binario, checksum y SBOM con cosign keyless
  sobre un tag `v*`, pero no se ha ejecutado. Sin esa corrida no existe `.sigstore.json` ni SBOM
  publicado; `scripts/release.sh` solo produce binario y `.sha256`.
- **Sin prueba con ingeniero externo.** El protocolo está en [`acceptance.md`](acceptance.md) §5;
  no se ejecutó. Criterio 16 sigue en ⚠.
- **Ancla de confianza por TOFU.** `trust/demo-lab.pub` y `trust/demo-origin.pub` fijan la clave
  fuera del bundle, así que un manifiesto re-firmado con otra clave falla `signer_is_trusted`.
  Pero las claves se obtuvieron del propio manifiesto: anclan sustituciones futuras, no prueban la
  identidad real del firmante. Para un engagement, la clave se registra por un canal independiente
  y ese registro es el que se pasa a `--trust-key` ([`trust/README.md`](../trust/README.md)).
- **Autorizaciones de demostración vencidas.** `AUTH-SMOKE-LOCAL-001` y `AUTH-SMOKE-ORIGIN-001`
  caducaron el 2026-10-29. `run` rechaza ejecuciones nuevas; `report`, `verify` y `validate`
  siguen funcionando sobre la evidencia sellada.
- **El salt de redacción no se conserva.** Los digests de cabeceras sensibles correlacionan el mismo
  valor dentro de un run y no se pueden recalcular después. Es la propiedad de privacidad buscada,
  no una carencia: recalcular exigiría guardar el salt y el valor.
- **La semilla del emisor de demostración no se conserva.** Los sidecars de `authorizations/`
  verifican contra `trust/issuers/demo-issuer.pub`, pero no se pueden regenerar ni firmar permisos
  nuevos con esa identidad. Es deliberado: una semilla versionada habría convertido el anillo en
  una copia del permiso.
- **Los comandos publicados por los bundles de demostración son anteriores a 0.1.** No incluyen
  `--issuer-keyring`; al ejecutarlos tal cual hay que añadir el anillo. `verify --rederive` sobre
  esos bundles mostraría esa diferencia de texto, no una lectura distinta. Regenerarlos exige el
  fixture Docker y una nueva corrida.
- **Un solo host probado.** La reproducibilidad se comprobó en MINGW64/Windows amd64 con Go 1.27.3.
  Otro host o toolchain puede producir otro binario; el hash de §2 identifica el artefacto que se
  aceptó, no una promesa de reproducibilidad universal. El workflow compara dos builds en un único
  runner Linux; no afirma reproducibilidad cruzada Windows/Linux.
- **Laboratorio Docker no re-ejecutado en esta corrida.** Los bundles existentes se verificaron;
  reconstruir el fixtures exige Docker y no forma parte de `certify.sh`.
- **Desviación de §9.3.** Se cubren cuatro tipos de hallazgo entre dos corridas autorizadas, no en
  una sola; está declarada en [`acceptance.md`](acceptance.md) §7.
- **Incidente de integridad resuelto el 2026-11-05.** Un proceso de Windows convirtió los 13
  artefactos inventariados de ambos bundles a CRLF. Se restauraron los bytes LF cuyo `sha256`
  coincide con el manifiesto, y `verify` volvió a pasar en los dos bundles. El incidente confirma
  por qué `verify` es parte de cada corrida y no un paso opcional.

---

## 9. Disparadores de recertificación

Hay que repetir `scripts/certify.sh`, revisar §4–§5 y registrar una nueva aceptación cuando:

- cambie cualquier archivo bajo `cmd/`, `internal/`, `corpus/`, `lab/`, `scripts/`,
  `authorizations/`, `trust/`, `docs/`, `README.md` o los bundles de demostración;
- cambie la versión de Go o las banderas de `scripts/release.sh`;
- cambie `.github/workflows/ci.yml`, `scripts/ci-local.sh` o la versión fijada de una acción o
  herramienta de CI;
- se añada una clase, un vector, una codificación, un tipo de hallazgo o un contrato;
- se modifique la política de destino, la puerta de inertez o el modelo de autorización;
- ocurra un incidente de integridad, una sonda no inerte o una ejecución fuera de alcance;
- transcurran doce meses desde la aceptación anterior.

---

## 10. Aceptación

| rol | nombre | fecha | evidencia revisada | firma |
| --- | --- | --- | --- | --- |
| Responsable de seguridad de Izkuna |  |  | `dist/certification-<UTC>.txt` |  |
| Mantenedor de XAMMU |  |  | hash del árbol + hash del binario |  |
| Aprobación de entrega |  |  | informe del engagement + anexo |  |

La aceptación se registra sobre el `dist/certification-<UTC>.txt` archivado. Si el archivo no está,
la aceptación no existe, por la misma razón por la que un informe sin bundle no es un informe.
