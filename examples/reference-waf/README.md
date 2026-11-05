# WAF de referencia (fixture de Fase 3)

Este directorio no es un producto ni una recomendación. Es un proxy inverso de demostración que
escucha en `127.0.0.1:8099`, reenvía al origen del laboratorio en `127.0.0.1:8081` y aplica reglas
**compuestas**: una petición se bloquea sólo cuando el marcador `xammu-probe` y una forma de la
clase aparecen en el **mismo valor normalizado**. Sirve para que el gate de Fase 3 tenga un target
que cumple la política de referencia y para demostrar el pipeline completo, no para comparar
productos.

## Qué mide y qué no

- **Mide** si el pipeline distingue un WAF que cumple los umbrales (`r7`, PASS) de uno que no
  (`r6`, FAIL) sobre el mismo corpus, la misma C-09 y el mismo presupuesto.
- **No mide** eficacia comercial. Las reglas están escritas contra el corpus inerte de este
  repositorio y son visibles aquí; un lector no puede extrapolar las cifras a otro WAF ni a otro
  tráfico.
- El fixture **no explota nada**: lee valores, los normaliza con hasta tres pasadas de
  percent-decode y minúsculas, y responde 403 con una página que contiene `XAMMU-REFERENCE-WAF-BLOCK`.
  Un cuerpo que no parsea se inspecciona igual como texto; no se ejecuta ni se reenvía transformado.

## Reglas

| id | clase | forma exigida junto al marcador |
| --- | --- | --- |
| `REF-SQLI` | `sqli` | comilla, `--`, `or`, `and`, `having`, `order by`, `returning`, `like` |
| `REF-XSS` | `xss` | `<` o `javascript:` |
| `REF-TRAVERSAL` | `path_traversal` | `..` |
| `REF-CMD` | `command_injection` | `;`, `&&`, `\|`, `${`, salto de línea o `2>` |
| `REF-SSRF` | `ssrf` | `//`, `http:`, `https:`, `localhost`, `127.` o `[::1]` |
| `REF-CRLF` | `crlf_injection` | `\r` o `\n` después de decodificar |
| `REF-LDAP` | `ldap_injection` | `*`, `(` o `)` |
| `REF-XXE` | `xxe` | declaración XML, `<` o `&` |
| `REF-NOSQL` | `nosql_injection` | `$`, `\|\|` o comilla |
| `REF-SSTI` | `ssti` | `{` o `<%` |

El marcador sin forma se reenvía (es una sonda que el fixture no sabe clasificar); una forma sin
marcador también (puede ser tráfico legítimo con una comilla). Esa conjunción es lo que permite
bloquear los 300 ataques y reenviar los 300 benignos sin aflojar ninguna regla.

## Preflight antes de enviar nada

`go test ./examples/reference-waf` carga los 600 casos con la misma puerta de inertitud, construye
la petición exacta que enviaría `effectiveness run` y la pasa por el handler real sobre loopback.
Exige 300 respuestas 403 y 300 respuestas del origen. Si el matcher no coincide con las etiquetas
del corpus, el fixture se corrige; no se rebaja la política ni el corpus.

## Ejecución local

```powershell
# origen del laboratorio
go build -o dist/lab-origin.exe ./lab/origin
dist/lab-origin.exe

# fixture de referencia (otra terminal)
go build -o dist/reference-waf.exe ./examples/reference-waf
dist/reference-waf.exe

# corrida r7 contra el fixture, con los umbrales fijados antes de medir
go run ./cmd/xammu effectiveness run `
  --authorization authorizations/effectiveness-local-002.json `
  --issuer-keyring trust/issuers `
  --authorize AUTH-EFFECTIVENESS-LOCAL-002 `
  --target http://127.0.0.1:8099 `
  --run waf-effectiveness-2026-11-05-r7 `
  --budget 1200
```

Variables: `REFERENCE_WAF_LISTEN_ADDR` (por defecto `127.0.0.1:8099`) y
`REFERENCE_WAF_ORIGIN_URL` (por defecto `http://127.0.0.1:8081`). `-info` imprime la configuración
resuelta y `GET /__reference/info` publica las reglas del proceso vivo.

## Límites declarados

- Es un fixture: sus reglas y su calibración están en este repositorio y no representan a ningún
  vendor.
- Corre en loopback sobre HTTP, sin TLS ni red externa.
- No afirma resistencia a evasión fuera de las re-codificaciones que declara el corpus.
