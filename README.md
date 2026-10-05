# @noticias — síntesis de prensa con alertas

Monitor de medios (RSS) con webapp móvil: agrupa la misma historia entre
medios, detecta noticias en desarrollo, alertas por reglas con color,
lector interno, estadísticas y exportación. Un solo archivo Python,
cero framework web, datos en JSONL. Powered by Olmeca Code.

**Setup**: `cp config.ejemplo.json config.json` y edita fuentes/reglas.

## Fuentes configuradas (`config.json`)

85 fuentes agrupadas por `categoria` (se muestran como dropdowns
plegables en `/fuentes`) — **todas RSS/HTML directo, cero agregadores**:

| Categoría | # | Ejemplos |
|---|---|---|
| quintana_roo | 25 | El Quequi (+secciones), Por Esto, Quadratín, Noticias Tulum, Luces, Riviera Maya News, Yucatán… |
| prensa | 18 | Tabasco HOY, El Heraldo, Novedades, Diario Presente, Tabasco al Día, El Sureste… |
| nacional | 25 | Jornada, Reforma, El Financiero, Expansión, 24H, Informador, Norte, Debate… |
| deportes | 7 | ESPN, Récord, Marca, AS… |
| internacional | 4 | BBC, NYT, El País, El Mundo |
| oficial | 2 | Congreso Tabasco, Gobierno QRoo |
| prensa_independiente | 4 | López-Dóriga, Contralínea, Periodistas de a Pie, Reporteros en Movimiento |

QRoo lleva portadas **y secciones municipales** (Cancún, Tulum,
municipios) como feeds separados `Medio · Sección`.

Tipos de fuente: RSS directo y `html` (scraping de portada).
**Sin Google News**: sus links son redirects JS que el servidor no
puede seguir — la nota nunca se abre en el lector. Solo entran
medios con feed propio; si un medio cierra su RSS, sale del catálogo.

Notas:
- Quadratín **no tiene edición Tabasco** (sus ediciones son Michoacán,
  Guerrero, Morelos, etc.) — se usa el feed nacional filtrado.
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
municipio tabasqueño y al político homónimo; afina la lista
según ruido real.

## Cómo funcionan las alertas

Cada regla tiene `requiere_todas` (mínimo 2 palabras/frases — una sola
genera ruido). La nota dispara si contiene **todas**. La comparación
ignora mayúsculas y acentos (`"Cárdenas"` matchea `cardenas`, `CÁRDENAS`...).
Las reglas llevan `color` para el badge (opcional, auto si falta).

```json
{ "nombre": "Inundaciones", "requiere_todas": ["tabasco", "inundación"] }
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
- `/noticias` (logo **@noticias**) — feed paginado (100 por página)
- `/fuentes` — checkboxes por usuario agrupados en dropdowns por
  categoría (todas/solo esta); CRUD de feeds y usuarios solo admin,
  con dot de salud por fuente
- `/stats` — notas por medio/día, salud de feeds, exportar reporte .txt
- `/config` (botón en Alertas) — reglas de alerta: nombre, palabras
  (mínimo 2), color del badge; backfill sobre notas ya guardadas
- `/nota?u=` — lector interno: la nota se abre dentro de la app;
  si la página original trae video, el botón lo anuncia
  ("Ver nota y video en el sitio original")
- `/acerca` — versión, arquitectura y estado de la base de datos
- Buscador en el navbar sobre noticias y alertas

Retención: noticias/alertas **sin límite** (`RETENCION_DIAS=0`),
dedup 30 días. Login con cookie firmada: usuarios con reglas propias
+ invitados demo (24h, solo lectura — no pueden tocar reglas).
En producción: `https://noticias.unknownshoppers.com` vía cloudflared
(systemd `monitor.service` + `cloudflared.service` en la NUC).

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

- `noticias.jsonl` — todas las notas (retención sin límite)
- `alertas.jsonl` — historial de alertas (sin límite; el de reglas
  borradas se oculta en la vista pero queda para `/exportar`)
- `vistos.json` — dedup con timestamps (30 días)
- `clusters.json` — estado de "noticia en desarrollo"
- `fuentes_estado.json` — salud por feed
- `config.json` — fuentes y reglas (ignorado en git; usa `config.ejemplo.json`)

## Ideas para extender

- Login por cliente con reglas propias (multi-tenant: SQLite + Flask)
- HTTPS + dominio propio en la NUC (Tailscale/Caddy)
- Notificaciones push/WhatsApp al disparar alerta
- Clasificación con Ollama: "¿esta nota es sobre seguridad? sí/no"
# anoticias
