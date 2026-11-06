# Custodia y rotación de claves

Este documento describe qué claves usa XAMMU, dónde viven, cómo se registran, cómo se rotan y qué
ocurre si una se compromete. Separa lo que el binario **hace cumplir** (bits de permiso, lectura de
sólo semillas existentes, verificación por clave pública) de lo que **declara como límite** (no hay
HSM, no hay CRL, no hay re-firma).

## 1. Qué claves existen

| Clave | Para qué | Dónde se pasa | Se publica |
| --- | --- | --- | --- |
| Emisora de permisos | firma C-09/C-10 (`authorization sign`) | `--signing-key` | su `.pub` en el anillo `--issuer-keyring` y la huella en el permiso |
| Firmante de bundles | firma `manifest.json` de `run` y `effectiveness` | `--signing-key` | la pública viaja dentro del manifiesto; el ancla se registra aparte |
| Firmante de publicación | firma `publication.json` de `gate --format all` | `--signing-key` | su pública, para `verify --publication --trust-key` |
| Anclas de confianza | verificar, no firmar | `--trust-key FILE`, `--issuer-keyring DIR` | directorio `trust/` del compromiso |

Todas son Ed25519. Una semilla son 32 bytes en hexadecimal: 64 caracteres, sin prefijo ni
metadatos. La clave pública son 32 bytes (64 hex) y su `sha256` completo es la huella que las
autorizaciones citan como `issuer_key_fingerprint` (`ed25519:<64 hex>`).

## 2. Almacenamiento

- La semilla es un archivo fuera del repositorio y fuera del bundle. Nunca se copia al bundle: el
  manifiesto sólo contiene la clave **pública** en base64 y el `signer_key_id`.
- Si el archivo no existe, `run` y `effectiveness` lo crean con `0600` en Unix
  (`integrity.LoadOrCreateKey`). La creación es la única operación que escribe una semilla.
- La ruta es lo único que aparece en `argv`; la semilla no se pasa por argumento, variable de
  entorno ni entrada estándar. Un listado de procesos puede mostrar la **ruta**, nunca el material.
- El default de demostración (`.xammu-signing.ed25519` en el directorio actual) existe para que el
  laboratorio funcione sin configuración. En producción se exige `--signing-key` explícito y una
  ubicación de custodia, no el directorio de trabajo.
- XAMMU **no** implementa DPAPI, HSM, KMS ni firma externa: sólo lee y escribe un archivo. Esas
  opciones son compatibles (la semilla puede montarse desde el almacén del sistema o firmarse en un
  host separado y traer sólo el resultado), pero hoy el binario no las conoce. Documentarlas como
  «soportadas» sería inventar capacidad.

Comprobación de custodia de un archivo existente:

```bash
xammu key inspect --key /custodia/engagement-2026-q4.ed25519
```

Salida (sin la semilla):

```
key /custodia/engagement-2026-q4.ed25519 (read only; nothing was created)
  algorithm    ed25519
  key id       3f1c9a0b7d2e4c58
  public key   <64 hex>
  fingerprint  ed25519:<64 hex>
  file mode    0600 (owner-only)
  seed         not printed; it stays in the file named above
```

`key inspect` usa `LoadKey`: una ruta inexistente es un error de uso (salida 2) y no crea nada. En
Windows no imprime el modo, porque los bits POSIX no aplican; la custodia allí depende de las ACL
del directorio, que el binario no inspecciona.

## 3. Registro

1. Generar la clave fuera de banda (por ejemplo, con `xammu run --signing-key RUTA` en un host de
   custodia, o con cualquier generador Ed25519 que produzca una semilla de 32 bytes en hex).
2. Ejecutar `key inspect` y publicar en el expediente el **key id** y la **huella**.
3. Publicar la clave pública como `trust/<nombre>.pub` (64 hex) por un canal independiente del
   bundle y del permiso. Ese archivo es el ancla que un revisor usa con `--trust-key`.
4. Añadir su fila a [`trust/registry.md`](../trust/registry.md) con key id, huella, fecha de alta,
   procedencia y estado. Una clave sin fila no está registrada, aunque el `.pub` exista.
5. El manifiesto de cada bundle registra `signer_key_id`; el sobre de publicación registra
   `signer_key_id`. Un revisor compara ambos con la huella publicada y con la fila del registro.

El ancla no se descubre nunca desde el bundle, la autorización ni el directorio de trabajo: se pasa
explícitamente, y `verify` sin `--trust-key` informa `signer_is_trusted` como no comprobado.

## 4. Rotación

Rotar es empezar a firmar con una clave nueva, no reescribir el pasado.

1. Crear la clave nueva en su ubicación de custodia (`--signing-key RUTA-NUEVA`).
2. `xammu key inspect --key RUTA-NUEVA` y registrar key id y huella en el expediente.
3. Publicar la pública nueva en `trust/` y distribuirla por el canal independiente.
4. Las ejecuciones nuevas usan la clave nueva. Los bundles anteriores **no se re-firman**: se
   verifican con la pública que los firmó, que se conserva.
5. Declarar la ventana en el expediente: bundles firmados hasta la fecha X con la clave A,
   posteriores con la clave B.

`verify --trust-key` no cambia retroactivamente: la confianza es del revisor y de la pública que
elija. Un bundle antiguo sigue verificando mientras se conserve su ancla; eso es una propiedad, no
un defecto.

## 5. Revocación

No existe una CRL y este documento no inventa una. Revocar una clave significa:

- retirar su pública del conjunto que se distribuye a revisores nuevos;
- declarar qué evidencia firmó y desde cuándo deja de aceptarse para entregas nuevas;
- mantener la pública retirada disponible para quien deba auditar evidencia ya sellada.

La evidencia ya sellada sigue verificando con la pública retirada. Ocultarlo no cambia el hecho;
declararlo permite que un revisor decida. Si la retirada responde a un compromiso, la medición se
repite con la clave nueva y el informe nuevo cita la ventana afectada.

## 6. Incidente de compromiso

1. Retirar la pública del conjunto distribuido y marcar el key id como no confiable.
2. Identificar los bundles que citan ese `signer_key_id` (está en cada `manifest.json` y en cada
   sobre) y anotar su intervalo de fechas.
3. Repetir la medición con una clave nueva y un ancla publicada por el canal independiente.
4. Declarar en el handoff que la autenticidad de los bundles del intervalo depende de la ventana
   de compromiso: la firma prueba integridad, no que el firmante no estuviera comprometido.

## 7. Límites declarados

- El binario no implementa HSM, KMS, DPAPI ni firma remota; no hay atestación de que la semilla
  viva donde el operador dice.
- Los bits `0600` se aplican al crear la semilla; si una copia posterior queda con permisos
  amplios, XAMMU sólo lo advierte en `key inspect`, no lo corrige.
- No hay caducidad de clave ni de evidencia. La vigencia la decide el contrato del engagement.
- No hay re-firma ni migración de bundles: rotar cambia lo que se firma a partir de ese momento.
- Una firma Ed25519 demuestra integridad y posesión de la clave privada en el momento del sellado.
  No demuestra que el host estuviera limpio ni que el operador fuera la persona prevista.
