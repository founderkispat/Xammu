# Registro de anclas de confianza

Este archivo fija, para cada clave pública de `trust/`, su **key id**, su **huella** y la
**procedencia** con la que llegó al repositorio. El objetivo es que un revisor pueda comparar el
`signer_key_id` de un manifiesto o el `issuer_key_fingerprint` de una autorización contra una tabla
que existe fuera del artefacto que está verificando.

La procedencia de todas las claves es **TOFU** (*trust on first use*): se obtuvieron del propio
bundle, permiso o sello que ahora verifican, y ningún tercero las publicó por un canal
independiente. Por eso ninguna fila se marca como verificada por un tercero. La Etapa 2 prepara el
registro; la confirmación humana por un canal distinto del repositorio sigue pendiente y es la que
cerraría A-03.

## 1. Claves registradas

Las fechas son las del alta del archivo en `trust/` (primer commit que lo contiene), no la fecha en
que se generó la semilla, que el repositorio no puede demostrar.

| Archivo | Key id | Huella (`ed25519:<sha256>`) | Alta en `trust/` | Procedencia | Estado | Evidencia que firma |
| --- | --- | --- | --- | --- | --- | --- |
| `demo-lab.pub` | `dbbad598a2f83c1c` | `ed25519:dbbad598a2f83c1c7728755fbf0921058977a5517cdba2b9a5e8f60ce6941457` | 2026-11-05 | TOFU: extraída del manifiesto del bundle demo | pendiente de confirmación independiente | `runs/demo-lab/manifest.json` (`signer_key_id`) |
| `demo-origin.pub` | `c5a544e4dda71185` | `ed25519:c5a544e4dda71185e62571760e0a6fdff0832862fcfa26613303cbaed5e0dc96` | 2026-11-05 | TOFU: extraída del manifiesto del bundle demo | pendiente de confirmación independiente | `runs/demo-origin/manifest.json` (`signer_key_id`) |
| `waf-effectiveness.pub` | `edabfbcda5eb8f56` | `ed25519:edabfbcda5eb8f566903744f87c8315dc69f21db2e684f8c1fe97195ec25e5cd` | 2026-11-05 | TOFU: generada en el host de desarrollo y publicada con el mismo commit | pendiente de confirmación independiente | manifiestos de `runs/waf-effectiveness-*`; sobres de `publications/waf-effectiveness-2026-11-05-r6` y `-r7`; gates de `dist/gate-demo/r6` y `r7` |
| `issuers/demo-issuer.pub` | `1b0181da5dab0590` | `ed25519:1b0181da5dab0590d20de4f0bfdbfd39262a290c07d664cc0b9e80978e39355c` | 2026-11-05 | TOFU: la semilla se generó para firmar los dos permisos demo y no se conserva | pendiente de confirmación independiente; sin semilla, no puede firmar permisos nuevos | `authorizations/smoke-local.json`, `authorizations/smoke-origin-baseline.json` (`issuer_key_fingerprint`) |
| `issuers/effectiveness-issuer.pub` | `7aa1afc9d6072c57` | `ed25519:7aa1afc9d6072c5714967edc6bb70767c27b145f1dc26f5accb0f29c4d1cf289` | 2026-11-05 | TOFU: publicada junto al permiso que firmó | pendiente de confirmación independiente | `authorizations/effectiveness-local.json` (`issuer_key_fingerprint`) |
| `issuers/effectiveness-issuer-002.pub` | `686ba64e18dd9752` | `ed25519:686ba64e18dd975287bcdd70e7b63cfd59bf359b8cf5ea51a03212767ba747c5` | 2026-11-05 | TOFU: rotación de la anterior; la semilla se destruyó fuera del repositorio | pendiente de confirmación independiente; sin semilla, no puede firmar permisos nuevos | `authorizations/effectiveness-local-002.json` (`issuer_key_fingerprint`) |

## 2. Cómo se usa el registro

- `--trust-key trust/<clave>.pub` ancla la verificación de un bundle o de un sobre. El cargador
  deriva la huella de la clave que verificó; un manifiesto que nombre otra clave falla
  `signer_is_trusted` aunque traiga una firma autoconsistente.
- `--issuer-keyring trust/issuers` es el anillo que permite considerar firmada una autorización
  C-09/C-10. Sin él, una autorización no se considera firmada y nada se envía bajo ella.
- El **key id** es el prefijo de 16 hex de la huella. Es lo que el manifiesto y el sobre registran
  como `signer_key_id`; la huella completa es lo que las autorizaciones registran como
  `issuer_key_fingerprint`.

## 3. Cómo se recalcula

`xammu key inspect` espera una **semilla**, no una clave pública: pasarle un `.pub` derivaría otra
clave y produciría una huella que no corresponde. Para comprobar una fila, se hashean los 32 bytes
que el archivo contiene en hexadecimal:

```bash
xxd -r -p trust/demo-lab.pub | sha256sum
# dbbad598a2f83c1c7728755fbf0921058977a5517cdba2b9a5e8f60ce6941457
```

La huella es `ed25519:` seguido de ese hexadecimal; el key id son sus 16 primeros caracteres. Las
huellas de esta tabla coinciden con las que los artefactos ya citan (`authorizations/*.json`,
`publications/*/publication.json`, `publications/*/gate.json`), y esa coincidencia es comprobable
sin confiar en este documento.

## 4. Qué prueba y qué no

**Prueba** que el ancla publicada aquí es la clave que verificó el artefacto: cambiar una fila sin
cambiar el `.pub` hace que las comprobaciones de §3 dejen de coincidir, y editar el `.pub` para que
`verify` pase convierte el ancla en una copia del manifiesto y elimina la única comprobación que
aporta.

**No prueba** que el firmante sea una identidad del mundo real, ni que la semilla viviera en un host
limpio. Para un engagement con cliente, la pública se registra por un canal independiente del
bundle y ese registro es el que se usa con `--trust-key`; la rotación, revocación e incidente están
en [`docs/key-custody.md`](../docs/key-custody.md).

## 5. Regla de cambio

Una fila se añade al registrar una clave nueva; nunca se edita para que una verificación pase. Una
clave retirada conserva su fila con el estado `retirada` y la evidencia que firmó, porque la
evidencia sellada sigue verificando con ella.
