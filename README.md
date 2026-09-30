# @noticias — síntesis de prensa con alertas

Monitor de medios (RSS) con webapp móvil: agrupa la misma historia entre
medios, detecta noticias en desarrollo, alertas por reglas con color,
lector interno, estadísticas y exportación. Un solo archivo Python,
cero framework web, datos en JSONL. Powered by Olmeca Code.

**Setup**: `cp config.ejemplo.json config.json` y edita fuentes/reglas.

## Fuentes configuradas (`config.json`)

| Medio | Feed RSS | Categoría |
|---|---|---|
| Tabasco HOY | `tabascohoy.com/feed/` | prensa |
| El Heraldo de Tabasco | `oem.com.mx/elheraldodetabasco/rss.xml` | prensa |
| Novedades de Tabasco | `novedadesdetabasco.com.mx/feed/` | prensa |
| El Momento Tabasco | `elmomentotabasco.mx/feed/` | prensa |
| El Chapucero | `elchapucero.com/feed/` | prensa_independiente (filtrado) |
| López-Dóriga | `lopezdoriga.com/feed/` | prensa_independiente (filtrado) |
| Quadratín | `quadratin.com.mx/feed/` | nacional (filtrado) |

Notas:
- Quadratín **no tiene edición Tabasco** (sus ediciones son Michoacán,
  Guerrero, Morelos, etc.) — se usa el feed nacional filtrado.
- XEVT, xeva.com.mx y tabasco.gob.mx no exponen RSS público.
- La Saga (`lasaga.news`) no responde (bloqueo tipo Cloudflare).

## Filtro `solo_si_menciona` (por fuente)

Los medios **nacionales** llevan esta lista: solo pasan notas que
mencionen alguna de esas palabras (municipios/ríos de Tabasco).
Los locales no la necesitan — todo su contenido es de Tabasco.

```json
"solo_si_menciona": ["tabasco", "villahermosa", "cárdenas", "comalcalco",
                     "dos bocas", "usumacinta", "ujat", "grijalva"]
```

Ojo: matchea subcadenas normalizadas — "Cárdenas" también detecta el
municipio tabasqueño y al político Lázaro Cárdenas; afina la lista
según ruido real.

## Cómo funcionan las alertas

Cada regla tiene `requiere_todas` (mínimo 2 palabras/frases — una sola
genera ruido). La nota dispara si contiene **todas**. La comparación
ignora mayúsculas y acentos (`"Olán"` matchea `olan`, `OLÁN`...).
Las reglas llevan `color` para el badge (opcional, auto si falta).

```json
{ "nombre": "Olán en Suiza", "requiere_todas": ["olán", "suiza"] }
```

- `["inundación"]` → cualquier nota que mencione inundaciones (muy amplio)
- `["tabasco", "inundación"]` → solo si menciona AMBAS (más preciso)
- `["dos bocas"]` → frase exacta

## Uso

```bash
.venv/bin/python monitor.py                          # una pasada
.venv/bin/python monitor.py --web 8080 --loop 15     # webapp + scraper cada 15 min
.venv/bin/python monitor.py --loop 15 --resumir      # + resumen IA con Ollama
```

## Webapp (mobile-first, PWA)

`--web` levanta `http://0.0.0.0:8080` (accesible en la red local):

- `/` **Destacadas** — misma historia cubierta por varios medios,
  agrupada por similitud de titular (Jaccard), con versiones por medio
- `/alertas` **Alertas** — agrupadas por regla con badge de color,
  match directo + "cobertura relacionada" (mismo tema, sin match)
- `/noticias` (logo **@noticias**) — feed de todas las notas capturadas
- `/fuentes` — CRUD de feeds RSS desde la web
- `/stats` — notas por medio/día, salud de feeds, exportar reporte .txt
- `/config` (botón en Alertas) — reglas de alerta: nombre, palabras
  (mínimo 2), color del badge; backfill sobre notas ya guardadas
- `/nota?u=` — lector interno: la nota se abre dentro de la app
- `/acerca` — versión, arquitectura y estado de la base de datos
- Buscador en el navbar sobre noticias y alertas

Retención: noticias/alertas 7 días, dedup 30 días.
Sin login: cualquiera en la red puede entrar — para uso privado o red local.

## Alertas por correo (SMTP)

En `config.json` → bloque `correo`. Con Gmail: genera una
**contraseña de aplicación** (myaccount.google.com → Seguridad →
verificación en 2 pasos → contraseñas de aplicación) y ponla en
`password`. Cambia `habilitado` a `true`. Cada alerta manda un correo
con titular, link y resumen IA al `destinatario`.

## Seguimiento de autores

`seguir_autores` en `config.json`: lista de nombres de columnistas.
Si el RSS trae autor y coincide, dispara alerta "Autor seguido".

## Datos

- `noticias.jsonl` — todas las notas (7 días de retención)
- `alertas.jsonl` — historial de alertas (7 días; el de reglas borradas
  se oculta en la vista pero queda para `/exportar`)
- `vistos.json` — dedup con timestamps (30 días)
- `clusters.json` — estado de "noticia en desarrollo"
- `fuentes_estado.json` — salud por feed
- `config.json` — fuentes y reglas (ignorado en git; usa `config.ejemplo.json`)

## Ideas para extender

- Login por cliente con reglas propias (multi-tenant: SQLite + Flask)
- HTTPS + dominio propio en la NUC (Tailscale/Caddy)
- Notificaciones push/WhatsApp al disparar alerta
- Clasificación con Ollama: "¿esta nota es sobre seguridad? sí/no"
