# Anclajes de confianza

El registro de key ids, huellas y procedencia de cada clave pública de esta carpeta está en
[`registry.md`](registry.md). Ese registro no sustituye a la verificación: la huella se recalcula
desde el `.pub` y se compara con la que cita el artefacto.

## Emisores de permisos (`issuers/`)

`issuers/demo-issuer.pub` es la clave pública del emisor que firmó las C-09 de demostración en
`authorizations/*.json` (sidecars `.sig`). `run`, `playbook`, `report`, `validate` y `verify` la
reciben con `--issuer-keyring trust/issuers`; sin ese anillo una autorización no se considera
firmada y nada se envía bajo ella.

La semilla privada del emisor se generó para firmar los dos permisos y **no se conserva**. Por eso
los sidecars publicados verifican, pero no se pueden regenerar ni firmar permisos nuevos con esa
identidad. Para un engagement, la clave del emisor se genera fuera del árbol, su `.pub` se publica
por un canal independiente del permiso y la semilla se custodia aparte:

```bash
xammu authorization sign --authorization C-09.json --signing-key emisor.ed25519
```

La huella que imprime el firmante (`ed25519:<sha256 de la clave pública>`) es la que la C-09 debe
llevar en `issuer_key_fingerprint`; el cargador la deriva de la clave que verificó y rechaza
cualquier otro valor.

## Bundles de demostración

`demo-lab.pub` y `demo-origin.pub` contienen la clave pública Ed25519 en hexadecimal que firmó
cada bundle. Se extrajeron de su manifiesto el 2026-11-05 y se fijaron aquí para que `verify`
tenga un ancla fuera del bundle:

```bash
xammu verify --run demo-lab --trust-key trust/demo-lab.pub ...
xammu verify --run demo-origin --trust-key trust/demo-origin.pub ...
```

## Qué prueba

Un bundle cuyo manifiesto nombre otra clave falla `signer_is_trusted` aunque traiga una firma
autoconsistente. Eso es exactamente la sustitución de manifiesto que este archivo impide.

## Qué no prueba

Que el firmante del laboratorio sea una identidad del mundo real. Las claves se fijaron por
**TOFU** (*trust on first use*): se obtuvieron del propio bundle y ningún tercero las publicó.
Para un engagement con cliente, la clave pública se registra por un canal independiente del
bundle y ese registro es el que se usa con `--trust-key`.

## Regla de cambio

Una clave se reemplaza solo con una corrida nueva y una aceptación registrada. Nunca se edita un
`.pub` para que `verify` pase: eso convierte el ancla en una copia del manifiesto y elimina la
única comprobación que aporta.

El ciclo completo —almacenamiento, registro, rotación, revocación e incidente— está en
[`docs/key-custody.md`](../docs/key-custody.md). `xammu key inspect --key FILE` publica el key id y
la huella que deben coincidir con esta carpeta, sin imprimir nunca la semilla.
