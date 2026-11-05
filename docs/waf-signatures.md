# Firmas de fingerprinting de WAF

Este documento es la base observacional de la tabla que vive en
`internal/fingerprint/signatures.go`. El informe de eficacia publica, por cada vendor, la evidencia
que coincidió y el grado de apoyo categórico; este archivo explica de dónde sale cada firma y qué
no afirma.

## Regla de admisión

Una firma entra en la tabla solo si cumple las tres condiciones:

1. **Es un marcador público y estable** del producto, no una semejanza: una cabecera documentada,
   una cookie con prefijo propio o una página de error que se identifica por nombre.
2. **Se puede citar.** Cada firma lleva una base en `SignatureBasis`; si no hay fuente, no entra.
3. **No afirma capacidad de bypass.** La tabla atribuye una capa defensiva; no dice qué la evade.

Un `403`, un cierre de conexión o un texto genérico de error **no** atribuyen vendor. La ausencia
de coincidencia se publica como vendor `unknown` con apoyo `none`, no como un producto probable.

## Apoyo categórico, sin números

El campo serializado se llama `support` y no `confidence` porque el repositorio reserva esa clave
para una escala numérica que JAVI-021 prohíbe; el informe la rotula como «confidence» en prosa. El
valor es una categoría cerrada, derivada de las clases de evidencia, no una probabilidad:

| apoyo | regla |
| --- | --- |
| `high` | al menos dos clases de evidencia del mismo vendor (`header`, `cookie`, `error_page` o `behavior`) y al menos una firma `identifying` |
| `medium` | una sola clase de evidencia con al menos una firma `identifying` |
| `low` | solo firmas `supporting`, o firmas presentes únicamente en outcomes excluidos |
| `none` | ninguna firma del vendor; se publica como `unknown` |

Dos cabeceras del mismo vendor siguen siendo una sola clase (`header`); por eso el laboratorio, que
emite `Server`, `X-Lab-Waf-Action` y el marcador de bloqueo, alcanza `high` (cabecera + página de
error), no por contar tres marcas.

## Tabla publicada

| id | vendor | clase | fuerza | observable | base | límite |
| --- | --- | --- | --- | --- | --- | --- |
| `lab-server` | `xammu-lab-waf` | header | identifying | `Server` contiene `xammu-lab-waf` | el fixture del repositorio lo emite en `lab/waf/proxy.go` | solo el laboratorio |
| `lab-action` | `xammu-lab-waf` | header | identifying | `X-Lab-Waf-Action` contiene `reject` | ídem | solo el laboratorio |
| `lab-block-marker` | `xammu-lab-waf` | error_page | identifying | cuerpo contiene `XAMMU-LAB-WAF-BLOCK` | ídem | solo el laboratorio; del cuerpo solo se guarda el id de firma |
| `cloudflare-ray` | `cloudflare` | header | identifying | cabecera `cf-ray` | identificador de petición documentado por Cloudflare | no distingue plan ni reglas activas |
| `sucuri-id` | `sucuri` | header | identifying | cabecera `x-sucuri-id` | cabecera de proxy documentada por Sucuri | no prueba que el WAF esté inspeccionando |
| `sucuri-cache` | `sucuri` | header | supporting | cabecera `x-sucuri-cache` | ídem | por sí sola no atribuye; solo suma clase |
| `imperva-incap` | `imperva` | cookie | identifying | cookie con prefijo `incap_ses_` | cookie de sesión de Imperva en sitios protegidos | solo se conserva el nombre, nunca el valor |
| `imperva-iinfo` | `imperva` | header | supporting | cabecera `x-iinfo` | cabecera de diagnóstico de Imperva | supporting: no atribuye por sí sola |
| `modsecurity-credit` | `modsecurity` | error_page | identifying | cuerpo contiene `ModSecurity` | las páginas de error de ModSecurity se identifican por nombre | motor, no necesariamente el proveedor del borde |
| `akamai-grn` | `akamai` | header | supporting | cabecera `akamai-grn` | cabecera de diagnóstico de Akamai | supporting |
| `akamai-transformed` | `akamai` | header | supporting | cabecera `x-akamai-transformed` | ídem | supporting |

## Pilas candidatas por vendor

La recomendación adjunta al fingerprint es una **hipótesis a medir**, no inteligencia de evasión:

- `xammu-lab-waf` recibe dos pilas ajustadas porque sus reglas son visibles en este repositorio:
  `url_encode_double → sql_comment` y `case_switch → whitespace_variant`. La corrida de aceptación
  mide la primera; no se afirma que funcione fuera del fixture.
- Cualquier otro vendor recibe una única pila genérica de cambio de representación
  (`url_encode_double → case_switch`) etiquetada como genérica. No se publica conocimiento de
  bypass específico que no esté citado.
- `unknown` no recibe pila: sin vendor no hay candidata que medir, y `auto` no selecciona nada.

`base64` nunca está en una candidata automática: borra el marcador en línea y obliga a una cabecera
diagnóstica visible (`X-Xammu-Probe`), que se registra como confundidor. `chunked` no existe en el
vocabulario: cambiar el encuadre de la petición sería smuggling, no evasión.

## Dónde se guarda y qué no

- La evidencia se atribuye **en el momento de la captura** y se guarda en E-02 como
  `{vendor, signature, kind, strength, detail}`. El cuerpo de la respuesta no se serializa; de una
  página de error solo queda el id de la firma que coincidió.
- De una cookie solo se conserva el nombre. De una cabecera, el nombre y el id de firma; el valor
  no viaja a la evidencia.
- E-03 agrega los outcomes de la línea base y publica `policy`, `observed_outcomes`,
  `outcomes_with_evidence` y un `Finding` por vendor. La agregación es una tabla sobre E-02: un
  lector puede re-derivarla sin volver a mirar el objetivo.
- Un bundle de Fase 1 no tiene evidencia de fingerprint; el informe lo declara en lugar de insinuar
  que no había defensa.

## Cómo se revisa una firma nueva

1. Verificar que el marcador es público y estable, y escribir la base en `SignatureBasis`.
2. Clasificarla como `identifying` solo si pertenece a un vendor concreto; en caso contrario,
   `supporting`.
3. Añadir un caso en `internal/fingerprint/fingerprint_test.go` que pruebe la atribución y que el
   detalle no filtre valores.
4. Actualizar esta tabla. Una firma dudosa se deja fuera antes que atribuir un vendor por parecido.

La corrida de aceptación `runs/waf-effectiveness-2026-11-05-r6` identifica `xammu-lab-waf` con
apoyo `high` y 33 outcomes con evidencia; el detalle está en
`runs/waf-effectiveness-2026-11-05-r6/effectiveness-report.md`.
