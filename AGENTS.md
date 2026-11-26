# monitor_noticias — @noticias / TweetDeck (PIRIA)

App monolítica `monitor.py` (stdlib http.server, sin framework). Datos en JSON/JSONL
en el mismo directorio: `redaccion.jsonl`, `usuarios.json`, `seguimientos.jsonl`,
`chats.json`, `chat_msg.jsonl`, `asistente_*.json`, `actividad.jsonl`,
`demo_ips.json`, `rl_auto.json`, `config.json`.

Contexto: empezó como monitor automatizado (cuentas dedicadas + crontabs),
pivotó a colector tipo TweetDeck, y en el corte final (nov 2026) quedó SOLO
como "el tweetdeck" = la mesa de trabajo de comunicación social:

- **redacción** — publicaciones multimedia por áreas (`/redaccion`, `/area`,
  `/redaccion/reporte`, `/bitacora`, asignaciones manuales, favoritos)
- **social** — chat por canales (`/chat`)
- **IA** — asistente con citas sobre publicaciones (`/asistente`,
  `/asistente/nota`) — `_llm()` va Gemini→Ollama
- **admin** — `/usuarios` (gestión de perfiles), `/analitica` (uso)

Sin scraping, sin feeds, sin loops: el contenido lo suben los humanos.
Todo lo demás se archivó en `legacy/`:

- `monitor_scraping_extraido.py` — scraping cuentas/portadas (playwright)
- `anoticias_extraido.py` — producto @noticias: síntesis, correos Brevo/SMTP
- `visor_extraido.py` — colector+visor: revisar(), feeds, vistas de noticias,
  reglas/alertas, lector /nota, buscador (no se importa, solo referencia)
- `datos_visor/` — noticias.jsonl, alertas.jsonl, vistos.json, clusters.json,
  fuentes_estado.json, wp_scan.json, portadas_estado.json, sintesis.jsonl,
  shots/, portadas/, schedule.html

## Correr / verificar

```bash
.venv/bin/python -m py_compile monitor.py          # syntax check
.venv/bin/python monitor.py --web 8080             # dashboard local
sudo systemctl restart monitor.service             # producción (systemd, User=t800)
```

## Deploy remoto (SSH)

El servicio corre desde ESTE directorio. Flujo:

1. En cualquier máquina: `git clone https://github.com/unknownshopper/anoticias.git`,
   editar, `git push`.
2. En este equipo: `ssh t800@192.168.1.86` (LAN) o `ssh t800@100.82.221.5` (Tailscale)
   luego `cd ~/Desktop/SISTA/monitor_noticias && ./deploy.sh`
   (deploy.sh = `git pull --ff-only` + `sudo systemctl restart monitor.service`).
3. `monitor.service` ya NO lleva `--loop`/`--resumir` — solo `--web 8080`.
   Si el ExecStart instalado en systemd difiere, copiar el del repo.

## Convenciones

- Vistas devuelven fragmentos HTML; `render_pagina()` las envuelve en `PAGINA`
  (template con `{{ }}` — todo literal JS/CSS dentro lleva llaves dobles).
- `_RED_CSS` = estilos del módulo redacción; `PAGINA` = chrome global (nav sticky).
- Publicaciones de redacción: `_pub_card()` (tarjeta), `vista_publicacion()`
  (nota completa), `aplicar_accion_redaccion()` (POSTs → redirect `volver`).
- Polling vivo: `/redaccion/contador` (nuevas pubs) usa marcadores
  `visto_redaccion`/`visto_area` del perfil — los escribe `_marcar_visto()`.
- IA: `_llm()` (Gemini→Ollama), `_asistente_responder()`, `vista_nota_ia()`;
  citas `[id]` se validan contra ids reales antes de renderizar.
- `normalizar`/`termino_en`/`fmt_fecha`/`_marcar_visto` = helpers rescatados
  del visor — los usa el asistente y las tarjetas de redacción.
