# monitor_noticias — PIRIA / Redacción TSJT

App monolítica `monitor.py` (stdlib http.server, sin framework). Datos en JSON/JSONL
en el mismo directorio: `redaccion.jsonl`, `usuarios.json`, `seguimientos.json`,
`chats.json`, `chat_msg.jsonl`, `asistente_*.json`, `config.json`.

Contexto: empezó como monitor automatizado (cuentas dedicadas + crontabs) y
pivotó a colector tipo TweetDeck operado por el equipo de comunicación social.
Los artefactos de esa era están archivados en `legacy/` (scripts de login
FB/X, sesiones, CSVs de unfollow, backups `.bak`, logs y reportes viejos).
Ojo: `monitor.py` aún contiene el subsistema de scraping dormido
(portadas FB/X/kiosko, pool de sesiones, playwright) — está apagado por
`pausar_scraping`/`fb_pausa`/`fb_posts_pausa` en config.json y sus mensajes
referencian `fb_login.py`/`x_login.py`, que ahora viven en `legacy/`.

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

## Convenciones

- Vistas devuelven fragmentos HTML; `render_pagina()` las envuelve en `PAGINA`
  (template con `{{ }}` — todo literal JS/CSS dentro lleva llaves dobles).
- `_RED_CSS` = estilos del módulo redacción; `PAGINA` = chrome global (nav sticky).
- Publicaciones de redacción: `_pub_card()` (tarjeta), `vista_publicacion()`
  (nota completa), `aplicar_accion_redaccion()` (POSTs → redirect `volver`).
- IA: `_llm()` (Gemini→Ollama), `_asistente_responder()`, `vista_nota_ia()`;
  citas `[id]` se validan contra ids reales antes de renderizar.
