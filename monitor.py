#!/usr/bin/env python3
"""
Monitor de noticias del TSJT (Poder Judicial de Tabasco) con alertas y síntesis ejecutivas.

Uso:
    python monitor.py              # revisa una vez
    python monitor.py --loop 15    # revisa cada 15 minutos
    python monitor.py --resumir    # resume alertas con Ollama (local)
    python monitor.py --todo       # muestra TODOS los titulares (sin filtrar)
    python monitor.py --web        # dashboard en http://localhost:8080
    python monitor.py --web 9000   # dashboard en otro puerto
"""

import argparse
import base64
import calendar
import hashlib
import hmac
import html
import io
import ipaddress
import json
import re
import secrets
import socket
import subprocess
import sys
import threading
import time
import unicodedata
from collections import Counter
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs, quote

import requests
from PIL import Image, ImageDraw, ImageFont

socket.setdefaulttimeout(20)  # red: ninguna llamada se cuelga para siempre

BASE = Path(__file__).parent
CONFIG = BASE / "config.json"
USUARIOS = BASE / "usuarios.json"    # reglas + fuentes ocultas + expira, por email
ACTIVIDAD = BASE / "actividad.jsonl"  # {ts, email, ruta} por cada página vista
SECRET = BASE / "secret.txt"    # llave HMAC para firmar cookies de sesión
OG_PNG = BASE / "brand" / "02port.jpg"  # tarjeta de preview para compartir links
RL_AUTO_FILE = BASE / "rl_auto.json"  # IPs con login exitoso
_RL_HITS: dict = {}
_RL_SKIP_IPS: set = set()
_RL_SKIP_MT: float = 0
_RL_AUTO: set = set()
_RL_AUTO_LOADED = False
DEMO_HORAS = 24        # demo que REGALA el admin a un correo real (botón)
VERSION = "1.0.0"


def normalizar(texto: str) -> str:
    """Minúsculas y sin acentos, para que 'Cárdenas' matchee 'cardenas'."""
    texto = texto.lower()
    return "".join(
        c for c in unicodedata.normalize("NFD", texto)
        if unicodedata.category(c) != "Mn"
    )


_RX_TERMINO: dict = {}


def termino_en(termino_norm: str, t_norm: str) -> bool:
    """El término ya normalizado aparece como PALABRA/frase completa
    en el texto normalizado — 'prada' no debe prenderse dentro de
    'comprada'; 'garcia serrano' sigue siendo frase exacta."""
    rx = _RX_TERMINO.get(termino_norm)
    if rx is None:
        if len(_RX_TERMINO) > 4000:
            _RX_TERMINO.clear()
        rx = _RX_TERMINO[termino_norm] = re.compile(
            r"(?<!\w)" + re.escape(termino_norm) + r"(?!\w)")
    return bool(rx.search(t_norm))


def _marcar_visto(email: str, clave: str):
    """El usuario está viendo esta sección: su globito vuelve a 0."""
    usuarios = cargar_usuarios()
    if email in usuarios:
        usuarios[email][clave] = \
            datetime.now().isoformat(timespec="seconds")
        guardar_usuarios(usuarios)


def cargar_usuarios() -> dict:
    """{email: {'reglas': [...], 'fuentes_ocultas': [...], 'expira': ts}}"""
    for path in (USUARIOS, USUARIOS.with_suffix(".json.bak")):
        if not path.exists():
            continue
        try:
            datos = json.loads(path.read_text())
            if isinstance(datos, dict):
                return datos   # .bak rescata si el principal truncó
        except Exception:
            continue
    return {}


def guardar_usuarios(usuarios: dict):
    """Write atómico + .bak del último estado — un restart a mitad de
    write_text() dejaba el JSON truncado y cargar_usuarios devolvía {}
    (padrón 'borrado': los usuarios perdían la contraseña)."""
    txt = json.dumps(usuarios, ensure_ascii=False, indent=2)
    try:
        if USUARIOS.exists():
            USUARIOS.with_suffix(".json.bak").write_text(
                USUARIOS.read_text())
    except Exception:
        pass
    tmp = USUARIOS.with_suffix(".tmp")
    tmp.write_text(txt)
    tmp.replace(USUARIOS)


def es_admin(email: str, cfg: dict) -> bool:
    return email in cfg.get("admins", [])


def _secreto() -> bytes:
    """Clave para firmar cookies; se genera una vez en secret.txt."""
    if not SECRET.exists():
        SECRET.write_text(secrets.token_hex(32))
    return SECRET.read_text().strip().encode()


def hash_password(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()


def firma_cookie(email: str) -> str:
    return hmac.new(_secreto(), email.encode(), hashlib.sha256).hexdigest()


def password_valida(email: str, pw: str, cfg: dict) -> bool:
    """La contraseña del perfil; el admin también puede entrar con
    'admin_password' de config.json (útil para el primer acceso)."""
    perfil = cargar_usuarios().get(email)
    esperado = perfil.get("password", "") if perfil else ""
    if not esperado and es_admin(email, cfg):
        esperado = hash_password(cfg.get("admin_password", ""))
    return bool(esperado) and hmac.compare_digest(esperado, hash_password(pw))


def home_usuario(email: str) -> str:
    """Landing del perfil — 'home' en usuarios.json manda; si no, el
    producto redacción: supervisión → tablero de columnas, colaborador
    → su área; el resto cae al tablero (el monitor clásico murió)."""
    if "@demo.local" in email:
        return "/redaccion"   # invitado: deck en solo lectura
    prof = cargar_usuarios().get(email) or {}
    home = prof.get("home", "")
    if home.startswith("/") and not home.startswith("//"):
        return home
    try:
        cfg = json.loads(CONFIG.read_text())
    except Exception:
        cfg = {}
    if es_supervisor(email, cfg):
        return "/redaccion"
    if area_de_usuario(email, cfg):
        return "/area"
    return "/redaccion"


def resolver_usuario(headers, cfg: dict) -> str:
    """Quién es: header de Cloudflare Access, o cookie de sesión firmada.
    Sin ninguno -> '' (el handler muestra el login)."""
    # el header solo es confiable si Cloudflare Access está activado —
    # si no, cualquiera que llegue al puerto podría suplantar usuarios
    if cfg.get("cf_access"):
        email = headers.get(
            "Cf-Access-Authenticated-User-Email", "").strip().lower()
        if email:
            return email
    for parte in headers.get("Cookie", "").split(";"):
        k, _, v = parte.strip().partition("=")
        if k == "s" and "." in v:
            email, sig = v.rsplit(".", 1)
            if hmac.compare_digest(sig, firma_cookie(email)) \
                    and email in cargar_usuarios():
                return email
            break
    return ""


def perfil_usuario(email: str, cfg: dict) -> dict:
    """Perfil del usuario; se autocrea en el primer acceso. Al admin se le
    siembran las reglas globales de config.json (migración del MVP)."""
    usuarios = cargar_usuarios()
    if email not in usuarios:
        if "@demo.local" in email:
            # guest ya purgado/expirado — recrearlo aquí lo haría
            # permanente (expira=0): devuelve perfil vacío efímero
            return {"reglas": [], "fuentes_ocultas": [], "expira": 0}
        usuarios[email] = {
            "reglas": list(cfg.get("alertas", [])) if es_admin(email, cfg) else [],
            "fuentes_ocultas": [],
            "expira": 0,
            "password": "",
        }
        guardar_usuarios(usuarios)
    return usuarios[email]


def nivel_usuario(email: str) -> str:
    """'supervision' o 'operacion' (default) — el campo lo asigna el
    admin al crear el usuario (alertas colaborativas, 20/oct)."""
    return (cargar_usuarios().get(email) or {}).get(
        "nivel", "operacion")


def proyectos_usuario(email: str) -> list:
    """Proyectos del usuario (puede estar en varios: ['tsjt','qroo']).
    Lee 'proyectos' (lista); migra del campo viejo 'proyecto' (str)."""
    u = cargar_usuarios().get(email) or {}
    ps = u.get("proyectos")
    if ps is None:
        s = u.get("proyecto", "")
        ps = [s] if s else []
    return ps


def es_supervisor(email: str, cfg: dict) -> bool:
    """Admin o nivel supervisión (Paolo): supervisa TODOS los
    proyectos — ve quién creó cada alerta y edita/borra resúmenes."""
    return es_admin(email, cfg) or nivel_usuario(email) == "supervision"


def registrar_actividad(email: str, ruta: str, nota_u: str = "",
                        ref: str = "", q: str = ""):
    """Bitácora: quién vio qué, cuándo, de dónde llegó y qué buscó."""
    try:
        with ACTIVIDAD.open("a") as f:
            f.write(json.dumps(
                {"ts": datetime.now().isoformat(timespec="seconds"),
                 "email": email, "ruta": ruta, "u": nota_u, "ref": ref,
                 "q": q},
                ensure_ascii=False) + "\n")
    except Exception:
        pass


def purgar_usuarios():
    """Borra perfiles de invitado cuyo demo ya expiró."""
    usuarios = cargar_usuarios()
    vivos = {e: u for e, u in usuarios.items()
             if not u.get("expira") or u["expira"] > time.time()}
    if len(vivos) != len(usuarios):
        guardar_usuarios(vivos)
        print(f"[usuarios] {len(usuarios) - len(vivos)} demo(s) expiradas")


def fmt_fecha(iso: str) -> str:
    """'2026-09-30T02:41:00' -> '30/09/2026 02:41' — año siempre visible,
    evita confusiones con alertas de otros años."""
    try:
        d = datetime.fromisoformat(iso)
        return d.strftime("%d/%m/%Y %H:%M")
    except Exception:
        return iso[:16]


def fmt_relativo(iso: str) -> str:
    """'5min', '3h', '2d', '1sem', '3mes', '1a' — fecha compacta para
    metas de tarjetas (la absoluta queda en el title)."""
    try:
        s = (datetime.now()
             - datetime.fromisoformat(str(iso)[:19])).total_seconds()
    except Exception:
        return ""
    s = max(0, s)
    if s < 3600:
        return f"{max(1, int(s // 60))}min"
    if s < 86400:
        return f"{int(s // 3600)}h"
    if s < 604800:
        return f"{int(s // 86400)}d"
    if s < 2592000:
        return f"{int(s // 604800)}sem"
    if s < 31536000:
        return f"{int(s // 2592000)}mes"
    return f"{int(s // 31536000)}a"


def _rl_auto_ips() -> set:
    """IPs exentas por login exitoso — persistidas en disco porque el
    servicio se reinicia en cada deploy y la lista en memoria se
    borraba, devolviendo a todo el equipo a la ventana de 10/min."""
    global _RL_AUTO_LOADED, _RL_AUTO
    if not _RL_AUTO_LOADED:
        _RL_AUTO_LOADED = True
        try:
            _RL_AUTO = set(json.loads(RL_AUTO_FILE.read_text()))
        except Exception:
            _RL_AUTO = set()
    return _RL_AUTO


def _rl_auto_add(ip: str):
    _rl_auto_ips().add(ip)
    try:
        RL_AUTO_FILE.write_text(json.dumps(sorted(_RL_AUTO)))
    except Exception:
        pass


_RL_FAIL: dict = {}   # email → [ts de logins fallidos]


def _login_bloqueado(email: str) -> bool:
    """Fuerza bruta por CUENTA: >8 fallos en 10 min congela ese email.
    La defensa real contra bots (que rotan IPs) sin castigar a una
    oficina entera que comparte una sola IP pública."""
    ahora = time.time()
    fails = [t for t in _RL_FAIL.get(email, []) if ahora - t < 600]
    _RL_FAIL[email] = fails
    return len(fails) >= 8


def _login_fallo(email: str):
    _RL_FAIL.setdefault(email, []).append(time.time())


def ratelimit_ok(ip: str, limite: int = 120, ventana: int = 60) -> bool:
    """True si la IP sigue bajo el límite en la ventana (segundos).
    cfg.ratelimit_skip = ["1.2.3.4"] exenta IPs fijas (la del admin)."""
    global _RL_SKIP_IPS, _RL_SKIP_MT
    try:
        mt = CONFIG.stat().st_mtime
        if mt != _RL_SKIP_MT:
            _RL_SKIP_MT = mt
            _RL_SKIP_IPS = set(json.loads(CONFIG.read_text())
                               .get("ratelimit_skip") or [])
    except Exception:
        pass
    if ip in _RL_SKIP_IPS or ip in _rl_auto_ips():
        return True
    ahora = time.time()
    hits = [t for t in _RL_HITS.get(ip, []) if ahora - t < ventana]
    if len(hits) >= limite:
        _RL_HITS[ip] = hits
        return False
    hits.append(ahora)
    _RL_HITS[ip] = hits
    # poda: solo crece bajo ataque sostenido; normal = poquitas IPs
    if len(_RL_HITS) > 5000:
        for k in [k for k, v in _RL_HITS.items() if ahora - v[-1] > 300]:
            del _RL_HITS[k]
    return True


def _gemini_key(cfg: dict) -> str:
    return cfg.get("gemini", {}).get("api_key", "")


def _llm(cfg: dict, prompt: str, timeout: int = 120) -> str:
    """Gemini (AI Studio, free tier) si hay api_key en config; si no,
    o si falla, Ollama local. El guard de RAM solo aplica al modelo
    local — la API no carga nada en la NUC."""
    if _gemini_key(cfg):
        modelo = cfg["gemini"].get("modelo", "gemini-3.1-flash-lite")
        for intento in range(2):
            try:
                r = requests.post(
                    "https://generativelanguage.googleapis.com/v1beta/"
                    f"models/{modelo}:generateContent",
                    params={"key": _gemini_key(cfg)},
                    json={"contents": [{"parts": [{"text": prompt}]}]},
                    timeout=timeout)
                # modelos "thinking": parts puede traer el
                # pensamiento primero — tomar el último con texto
                parts = (r.json()["candidates"][0]["content"]
                         .get("parts") or [])
                txt = "".join(
                    p.get("text", "") for p in parts
                    if not p.get("thought")).strip()
                if txt:
                    return txt
                print("[llm] gemini vacío")
            except Exception as e:
                print(f"[llm] gemini intento {intento+1}: {e}")
            if intento == 0:
                time.sleep(15)   # 503 por saturación — un respiro
        print("[llm] gemini agotado — caigo a ollama")
    if _mem_disponible_gb() < 4:
        return ""   # solo ollama come RAM — API no necesita margen
    try:
        r = requests.post(
            cfg["ollama"]["url"],
            json={"model": cfg["ollama"]["modelo"], "prompt": prompt,
                  "stream": False},
            timeout=timeout)
        return r.json().get("response", "").strip()
    except Exception as e:
        return f"(no se pudo resumir: {e})"


def _gemini_transcribir(cfg: dict, ruta, mime: str) -> str:
    """Transcripción de audio/video con Gemini multimodal (inline,
    ≤18 MB). Devuelve el texto hablado o ''."""
    key = _gemini_key(cfg)
    if not key or ruta.stat().st_size > 18 * 1024 * 1024:
        return ""
    data = base64.b64encode(ruta.read_bytes()).decode()
    prompt = ("Transcribe este audio/video en español. Devuelve SOLO "
              "el texto hablado; si es largo, con marcas de tiempo "
              "aproximadas. Si no hay voz, describe brevemente el "
              "contenido en una línea.")
    modelos = [cfg.get("gemini", {}).get("modelo_transcripcion",
                                        cfg["gemini"].get(
                                            "modelo", "")),
               "gemini-2.5-flash", "gemini-2.0-flash"]
    for modelo in modelos:
        if not modelo:
            continue
        try:
            r = requests.post(
                "https://generativelanguage.googleapis.com/v1beta/"
                f"models/{modelo}:generateContent",
                params={"key": key},
                json={"contents": [{"parts": [
                    {"inline_data": {"mime_type": mime, "data": data}},
                    {"text": prompt}]}]},
                timeout=180)
            parts = (r.json()["candidates"][0]["content"]
                     .get("parts") or [])
            txt = "".join(p.get("text", "") for p in parts
                          if not p.get("thought")).strip()
            if txt:
                return txt
        except Exception as e:
            print(f"[transcribir] {modelo}: {e}")
    return ""


def _transcribir_adjuntos(cfg: dict, pid: str):
    """Background: transcribe los adjuntos audio/video de una
    publicación y guarda el texto en media[].texto (reescribe el
    jsonl). Se llama en thread al publicar."""
    posts = cargar_publicaciones()
    p = next((x for x in posts if x.get("id") == pid), None)
    if not p:
        return
    cambio = False
    for m in p.get("media") or []:
        if m.get("tipo") not in ("audio", "video") or m.get("texto"):
            continue
        src = m.get("src", "")
        fp = RED_MEDIA / Path(src).name if src.startswith("/media/") \
            else None
        if not fp or not fp.is_file():
            continue
        mime = CTYPE_POR_EXT.get(fp.suffix.lower(),
                                 "application/octet-stream")
        txt = _gemini_transcribir(cfg, fp, mime)
        # fallback: wav/ogg que el modelo no trague → mp3 con ffmpeg
        if not txt and fp.suffix.lower() not in (".mp3", ".mp4", ".m4a"):
            try:
                tmp = fp.with_suffix(".mp3")
                subprocess.run(
                    ["ffmpeg", "-y", "-i", str(fp), "-vn",
                     "-acodec", "libmp3lame", "-q:a", "4",
                     str(tmp)], check=True,
                    capture_output=True, timeout=120)
                txt = _gemini_transcribir(cfg, tmp, "audio/mpeg")
            except Exception as e:
                print(f"[transcribir] ffmpeg {fp.name}: {e}")
        if txt:
            m["texto"] = txt[:4000]
            cambio = True
            print(f"[transcribir] {pid}: {len(txt)} chars")
    if cambio:
        _reescribir_publicaciones(posts)


def _mem_disponible_gb() -> float:
    """GiB realmente disponibles (MemAvailable de /proc/meminfo).
    El NUC se congeló cargando llama3.2 con ~3 GB libres y swap lleno —
    con menos de 4 GB no se dispara Ollama y se reintenta luego."""
    try:
        for l in Path("/proc/meminfo").read_text().splitlines():
            if l.startswith("MemAvailable:"):
                return int(l.split()[1]) / 1048576
    except Exception:
        pass
    return 99.0




PAGINA = """<!DOCTYPE html>
<!--email_off-->   <!-- Cloudflare: NO ofuscar correos (los ve el admin) -->
<html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<!-- refresh automático desactivado (22/nov): la redacción usa
     polling inteligente; si se reactiva, restaurar el meta tag -->
<meta name="theme-color" content="#1a237e">
<meta name="mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<meta name="apple-mobile-web-app-title" content="@noticias">
<link rel="manifest" href="/manifest.webmanifest">
<link rel="icon" type="image/png" href="/icon3.png">
<link rel="apple-touch-icon" href="/icon3.png">
<meta property="og:type" content="website">
<meta property="og:site_name" content="@noticias">
<meta property="og:title" content="{og_title}">
<meta property="og:description" content="{og_desc}">
<meta property="og:image" content="{og_img}">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="{og_title}">
<meta name="twitter:description" content="{og_desc}">
<meta name="twitter:image" content="{og_img}">
<title>@noticias — Monitor de prensa TSJT</title>
<style>
  * {{ box-sizing: border-box; }}
  body {{ font-family: system-ui, sans-serif; margin: 0; background: #f6f7f9;
         font-size: 17px; line-height: 1.45; }}
  nav {{ background: #1a237e; color: #fff; padding: .7rem 1rem .5rem;
        position: sticky; top: 0; z-index: 10; }}
  .nav-top {{ display: flex; align-items: center; gap: .8rem; }}
  .nav-user {{ color: #9fa8da; font-size: .85rem; margin-left: auto;
      margin-right: .4rem; }}
  nav .logo {{ font-weight: 800; font-size: 1.35rem; letter-spacing: .02em;
              color: #fff; text-decoration: none; }}
  .nav-tabs {{ display: flex; gap: .1rem; margin-top: .5rem;
              overflow-x: auto; -webkit-overflow-scrolling: touch;
              scrollbar-width: none; -ms-overflow-style: none; }}
  .nav-tabs::-webkit-scrollbar {{ display: none; }}
  .nav-tabs a {{ color: #c5cae9; text-decoration: none; font-size: 1rem;
         padding: .55rem .7rem; border-radius: 6px; white-space: nowrap; }}
  .nav-tabs a:hover, .nav-tabs a:active {{ color: #fff; background: #3949ab; }}
  .nav-tabs a.on {{ color: #fff; background: #3949ab; font-weight: 700; }}
  .tab-badge {{ display: inline-block; min-width: 1.05rem; margin-left: .35rem;
       padding: .05rem .32rem; border-radius: 9px; background: #e53935;
       color: #fff; font-size: .68rem; font-weight: 700; text-align: center; }}
  .salir-top {{ color: #7986cb; text-decoration: none; font-size: .9rem;
      padding: .5rem .2rem .5rem .6rem; white-space: nowrap; }}
  .salir-top:active {{ color: #fff; }}
  nav form {{ margin-left: auto; display: flex; gap: .4rem; flex: 1 1 200px;
            max-width: 320px; }}
  nav input {{ padding: .55rem .7rem; border-radius: 6px; border: none;
              font-size: 1rem; flex: 1; min-width: 0; }}
  main {{ max-width: 900px; margin: 0 auto; padding: 1rem; }}
  main.wide {{ max-width: none; padding: 1rem 1.2rem; }}

  /* Tarjeta = área de toque completa (dedos, no mouse) */
  .card {{ display: block; background: #fff; border-left: 5px solid #d32f2f;
         border-radius: 8px; padding: 1rem 1.1rem; margin: .9rem 0;
         box-shadow: 0 1px 4px #0002; color: inherit; text-decoration: none;
         position: relative; }}
  /* imprimir/PDF por tarjeta de síntesis — píldora arriba-derecha */
  .btn-imp {{ position: absolute; top: .7rem; right: .9rem; z-index: 1;
             font-size: .6rem; font-weight: 600; letter-spacing: .05em;
             text-transform: uppercase; color: #3949ab;
             border: 1px solid #c5cae9; border-radius: 999px;
             padding: .28rem .75rem; background: #fafbff;
             text-decoration: none; transition: all .15s; }}
  .btn-imp:hover {{ background: #1a237e; color: #fff;
                   border-color: #1a237e; }}
  @media print {{ .btn-imp {{ display: none; }}
                  .blk-refs > * {{ display: block !important; }}
                  .blk-refs > summary {{ display: none; }} }}
  .card:active {{ background: #f0f4ff; }}
  /* clearfix: sin esto el thumb flotante se sale por abajo/derecha
     cuando el texto de la tarjeta es más corto que la imagen */
  .card::after {{ content: ""; display: table; clear: both; }}
  .card img.thumb {{ width: 78px; height: 78px; object-fit: cover;
                   border-radius: 6px; float: right; margin: 0 0 .4rem .9rem; }}
  /* cluster de Interés: mosaico 2×2 en el mismo slot del thumb */
  .thumb-grid {{ float: right; width: 78px; height: 78px;
      display: grid; grid-template-columns: 1fr 1fr;
      grid-template-rows: 1fr 1fr; gap: 2px; border-radius: 6px;
      overflow: hidden; margin: 0 0 .4rem .9rem; }}
  .thumb-grid img {{ width: 100%; height: 100%; object-fit: cover; }}
  .card.grupo {{ border-left-color: #455a64; }}
  .grupo-item {{ display: block; padding: .45rem 0;
      border-top: 1px solid #eee; text-decoration: none;
      color: #263238; font-size: .85rem; line-height: 1.35; }}
  .grupo-item:hover {{ background: #f5f7fa; }}
  .card.top img.thumb {{ width: 110px; height: 84px; }}
  .card .meta {{ color: #666; font-size: .85rem; margin-bottom: .2rem; }}
  .card .titulo {{ font-weight: 600; display: block; margin: .15rem 0; }}
  .card .resumen {{ color: #444; font-style: italic; margin: .4rem 0 0; }}
  .card.redes {{ border-left-color: #1565c0; }}
  .card.desarrollo {{ border-left-color: #ef6c00; }}
  .card.nota {{ border-left-color: #90a4ae; }}
  .card.top {{ border-left-color: #7b1fa2; }}

  details {{ margin: .5rem 0 0; }}
  .col-card {{ background: #fff; border-left: 5px solid #455a64;
             border-radius: 8px; margin: .7rem 0; box-shadow: 0 1px 4px #0002; }}
  .col-card > summary {{ cursor: pointer; padding: .8rem 1rem;
                       display: flex; align-items: baseline; gap: .8rem;
                       flex-wrap: wrap; list-style: none; }}
  .col-card > summary::-webkit-details-marker {{ display: none; }}
  .col-card > summary::after {{ content: "▾"; margin-left: auto; color: #90a4ae; }}
  .col-card[open] > summary::after {{ content: "▴"; }}
  .col-nom {{ font-weight: 700; font-size: 1.05rem; }}
  .col-list {{ border-top: 1px solid #eceff1; padding: .2rem .5rem .6rem; }}
  .col-fila {{ display: flex; gap: .8rem; padding: .45rem .5rem;
             color: inherit; text-decoration: none; border-radius: 6px; }}
  .col-fila:hover {{ background: #f4f6f8; }}
  .col-fecha {{ color: #78909c; font-size: .8rem; white-space: nowrap;
              min-width: 6.5rem; padding-top: .1rem; }}
  .col-tit {{ font-weight: 500; }}
  .col-bloq {{ display: flex; flex-direction: column; gap: .15rem; }}
  .col-res {{ font-weight: 400; font-size: .8rem; color: #78909c;
             line-height: 1.3; }}
  .col-pay {{ margin-left: auto; align-self: flex-start; flex-shrink: 0;
             font-size: .68rem; font-weight: 600; color: #b45309;
             background: #fef3c7; border: 1px solid #fcd34d;
             border-radius: 999px; padding: .12rem .5rem;
             white-space: nowrap; }}
  summary {{ cursor: pointer; color: #1565c0; font-size: 1rem;
           padding: .5rem 0; }}
  details .variante {{ display: block; padding: .55rem 0; border-top: 1px solid #eee; }}
  h1 {{ font-size: 1.35rem; margin: .6rem 0 1rem; }}
  a {{ color: #1565c0; }}

  table {{ width: 100%; border-collapse: collapse; background: #fff;
         border-radius: 8px; overflow: hidden; }}
  td, th {{ padding: .6rem .7rem; border-bottom: 1px solid #eee; text-align: left; }}
  input[type=text], input[type=email], input[type=password],
  select {{ padding: .6rem .7rem; border: 1px solid #ccc;
           border-radius: 6px; font-size: 1rem; width: 100%; }}
  button {{ padding: .6rem 1rem; background: #1a237e; color: #fff; border: none;
           border-radius: 6px; cursor: pointer; font-size: 1rem; min-height: 44px; }}
  .btn-rojo {{ background: #c62828; }}
  .btn-linea {{ background: none; border: 1px solid #1a237e; color: #1a237e; }}

  /* Lector interno de la nota */
  .lector {{ background: #fff; border-radius: 8px; padding: 1.2rem;
            box-shadow: 0 1px 4px #0002; }}
  .lector img.hero {{ width: 100%; border-radius: 8px; margin: .6rem 0; }}
  .lector .lede {{ font-weight: 600; font-size: 1.05rem; color: #333; }}
  .lector p {{ margin: .7rem 0; }}
  .lector .origen {{ display: inline-block; margin-top: 1rem; }}
  .lector .compartir {{ display: inline-block; margin-top: 1rem;
      margin-left: .5rem; background: none; color: #1a237e;
      border: 1px solid #1a237e; padding: .5rem .9rem; border-radius: 8px;
      font-size: .9rem; cursor: pointer; min-height: 40px; }}
  .lector .compartir.cargando {{ opacity: .6; pointer-events: none; }}
  select, input[type=text] {{ border: 1px solid #ccc; }}
  footer {{ text-align: center; padding: 1.5rem 1rem 2rem; }}
  footer .about {{ color: #c3c9d4; font-weight: 800; font-size: 1.1rem;
                  text-decoration: none; padding: .4rem .8rem; }}
  footer .about:active {{ color: #1a237e; }}
  .badge {{ display: inline-block; padding: .2rem .6rem; border-radius: 12px;
           color: #fff; font-size: .75rem; font-weight: 700;
           vertical-align: middle; }}
  input[type=color] {{ width: 44px; height: 44px; border: 1px solid #ccc;
                      border-radius: 6px; padding: 2px; background: #fff;
                      cursor: pointer; vertical-align: middle; }}

  /* Editor de reglas: cada regla es una tarjeta con su color de badge */
  .card.regla {{ border-left-color: #1a237e; }}
  .card.regla:active {{ background: #fff; }}
  .card.regla label {{ display: block; font-size: .75rem; font-weight: 700;
      color: #666; margin: .8rem 0 .25rem; text-transform: uppercase;
      letter-spacing: .04em; }}
  .card.regla label:first-of-type {{ margin-top: .6rem; }}
  .regla-pie {{ display: flex; gap: .5rem; align-items: center;
      margin-top: .9rem; }}
  .regla-pie button {{ flex: 1; }}
  .regla-pie input[type=color] {{ flex: 0 0 44px; }}

  /* Selección de fuentes: filas tap-friendly; admin puede editar inline */
  .fuente-row {{ background: #fff; border-radius: 8px; margin: .45rem 0;
      box-shadow: 0 1px 4px #0001; }}
  .fuente-check {{ display: flex; align-items: center; gap: .7rem;
      padding: .8rem 1rem; font-weight: 600; cursor: pointer; }}
  .fuente-check input[type=checkbox] {{ width: 24px; height: 24px;
      accent-color: #1a237e; flex: 0 0 auto; }}
  .fuente-check .meta {{ font-weight: 400; }}
  .fuente-check.master {{ background: none; box-shadow: none;
      padding: .25rem .4rem; margin: 0 0 .1rem; font-size: .85rem;
      font-weight: 700; color: #03055B; gap: .5rem; }}
  .fuente-check.master input {{ width: 18px; height: 18px; }}
  .fuente-edit {{ padding: 0 1rem; margin: 0; }}
  .fuente-edit  .meta {{ font-size: .8rem; color: #666; }}
  /* Chip del medio emisor: tag sólido arriba-izquierda de la tarjeta */
  .meta2 {{ display: flex; align-items: baseline; gap: .6rem;
      flex-wrap: wrap; margin-bottom: .2rem; }}
  .meta2 .meta {{ font-size: .72rem; color: #999; }}
  .chip-fuente {{ display: inline-block; background: #1a237e; color: #fff;
      font-size: .66rem; font-weight: 700; text-transform: uppercase;
      letter-spacing: .06em; padding: .22rem .55rem; border-radius: 10px; }}
  .chip-creador {{ display: inline-flex; align-items: center; gap: .3rem;
      background: #fff8e1; color: #7a5d00; border: 1px solid #e8d48a;
      font-size: .66rem; font-weight: 700; padding: .18rem .55rem;
      border-radius: 10px; vertical-align: 1px; }}
  .chip-creador::before {{ content: ''; width: 6px; height: 6px;
      border-radius: 50%; background: #f9a825; flex: 0 0 auto; }}
  .chip-pals {{ display: inline-block; background: #eceff1; color: #546e7a;
      font-size: .64rem; font-weight: 600; font-style: italic;
      padding: .18rem .55rem; border-radius: 10px; vertical-align: 1px; }}
  .ico-origen {{ display: inline-block; font-size: .56rem; font-weight: 700;
      line-height: 1; padding: 2px 4px; border-radius: 3px; margin-left: 3px;
      vertical-align: middle; }}
  .ico-x {{ background: #000; color: #fff; }}
  .ico-fb {{ background: #1877f2; color: #fff; }}
  .ico-web {{ background: #eceff1; color: #78909c; }}
  .tabs-cat {{ display: flex; gap: .5rem; margin: .5rem 0 1rem;
      flex-wrap: wrap; }}
  .tab-cat {{ padding: .45rem .95rem; border-radius: 20px; font-size: .85rem;
      font-weight: 600; text-decoration: none; color: #1a237e;
      border: 1px solid #c5cae9; background: #fff; min-height: 36px;
      display: inline-flex; align-items: center; }}
  .tab-cat.on {{ background: #1a237e; color: #fff; border-color: #1a237e; }}
  .fuente-edit summary {{ font-size: .8rem; color: #1565c0;
      padding: .4rem 0 .7rem; }}
  .fuente-edit[open] summary {{ border-bottom: 1px solid #eee;
      margin-bottom: .4rem; }}
  .fuente-edit label {{ display: block; font-size: .75rem; font-weight: 700;
      color: #666; margin: .8rem 0 .25rem; text-transform: uppercase;
      letter-spacing: .04em; }}
  .fuente-edit .regla-pie {{ padding-bottom: .9rem; }}
  /* Dropdown que engloba toda la lista de fuentes */
  .fuentes-all {{ margin: 0; }}
  .fuentes-all > summary {{ background: #1a237e; color: #fff;
      border-radius: 8px; padding: 1rem 1.1rem; font-weight: 700;
      font-size: 1.05rem; list-style: none; }}
  .fuentes-all > summary::after {{ content: " ▾"; }}
  .fuentes-all[open] > summary::after {{ content: " ▴"; }}
  .fuentes-all > summary .meta {{ color: #c5cae9; }}
  .fuentes-all[open] {{ background: #fff; border-radius: 8px;
      padding: .4rem .6rem .8rem; box-shadow: 0 1px 4px #0001; }}
  .fuentes-all[open] > summary {{ margin: -.4rem -.6rem .5rem;
      border-radius: 8px 8px 0 0; }}

  /* Fuentes agrupadas por categoría (dropdown) */
  .fuentes-cat {{ background: #fff; border-radius: 8px; margin: .5rem 0;
      box-shadow: 0 1px 4px #0001; padding: 0 .6rem .8rem; }}
  .fuentes-cat > summary {{ font-weight: 700; font-size: 1rem;
      padding: .9rem 1rem; cursor: pointer; list-style: none;
      color: #03055B; user-select: none; }}
  .fuentes-cat > summary::after {{ content: " ▾"; color: #666; }}
  .fuentes-cat[open] > summary::after {{ content: " ▴"; }}
  .fuentes-cat > summary .meta {{ color: #666; font-weight: 400; }}
  .fuentes-cat > summary .cat-check {{ width: 20px; height: 20px;
      accent-color: #1a237e; margin-right: .6rem; vertical-align: -3px; }}
  .fuentes-cat > summary .cat-solo {{ font-size: .75rem; color: #1565c0;
      text-decoration: none; margin-left: .5rem; }}
  .dot {{ width: 10px; height: 10px; border-radius: 50%;
      flex: 0 0 auto; margin-right: .15rem; }}
  .dot-ok {{ background: #2e7d32; }}
  .dot-err {{ background: #d32f2f; }}

  /* Móvil: tabla de reglas se apila */
  @media (max-width: 600px) {{
    nav .logo {{ font-size: 1.15rem; }}
    table, thead, tbody, tr, td {{ display: block; width: 100%; }}
    thead {{ display: none; }}
    tr {{ border-bottom: 2px solid #ddd; padding: .4rem 0; }}
    td {{ border: none; }}
    td button {{ margin-right: .5rem; }}
    /* las tablas de stats sí se quedan en columnas, solo compactas */
    table.fija {{ display: table; }}
    table.fija thead {{ display: table-header-group; }}
    table.fija tbody {{ display: table-row-group; }}
    table.fija tr {{ display: table-row; border-bottom: none; padding: 0; }}
    table.fija td, table.fija th {{ display: table-cell;
        padding: .45rem .4rem; font-size: .9rem; }}
  }}
  .tabla-scroll {{ overflow-x: auto; }}
  table.ana {{ min-width: 640px; font-size: .82rem; }}
  table.ana td, table.ana th {{ padding: .4rem .5rem; }}
  .kpi-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: .7rem; margin: .8rem 0; }}
  .kpi {{ background: #fff; border-left: 4px solid #1a237e; padding: .8rem; border-radius: 8px; box-shadow: 0 1px 4px #0001; }}
  .kpi big {{ display: block; font-size: 1.6rem; font-weight: 700; color: #1a237e; }}
  .kpi .label {{ font-size: .68rem; color: #666; text-transform: uppercase; letter-spacing: .04em; }}
  .chart {{ display: flex; align-items: flex-end; gap: .4rem; height: 110px; padding: .6rem 0 1.4rem; background: #fff; border-radius: 8px; box-shadow: 0 1px 4px #0001; }}
  .bar {{ flex: 1; min-width: 18px; background: #1a237e; border-radius: 4px 4px 0 0; position: relative; opacity: .85; transition: opacity .2s; }}
  .bar:hover {{ opacity: 1; }}
  .bar span {{ position: absolute; bottom: -1.3rem; left: 0; right: 0; text-align: center; font-size: .6rem; color: #666; }}
  .bar:hover::after {{ content: attr(data-n); position: absolute; top: -1.4rem; left: 50%; transform: translateX(-50%); background: #1a237e; color: #fff; padding: .15rem .35rem; border-radius: 4px; font-size: .65rem; }}
  .mini-grid {{ display: grid; grid-template-columns: repeat(2, 1fr); gap: .8rem; margin: 1rem 0; }}
  .mini-grid > .card:nth-child(1), .mini-grid > .card:nth-child(4) {{ grid-column: 1 / -1; }}
  @media (max-width: 600px) {{ .mini-grid {{ grid-template-columns: 1fr; }} .mini-grid > .card:nth-child(1) {{ grid-column: 1; }} .mini-grid > .card:nth-child(4) {{ grid-column: 1; }} }}
  .mini-grid .card {{ margin: 0; overflow: hidden; }}
  .mini-grid table {{ font-size: .78rem; table-layout: fixed; width: 100%; }}
  .mini-grid td {{ word-break: break-word; overflow-wrap: anywhere; }}
  .mini-grid td:nth-child(2) {{ text-align: right; }}
  .alertas {{ font-size: .8rem; }}
  .alertas td:first-child {{ font-weight: 600; color: #1a237e; white-space: nowrap; vertical-align: top; width: 25%; }}
  .alertas td:nth-child(2) {{ text-align: left; vertical-align: top; }}
  .alerts-items {{ list-style: none; padding: 0; margin: 0; }}
  .alerts-items li {{ padding: .2rem 0 .2rem 1.2rem; position: relative; }}
  .alerts-items li.meta {{ color: #999; }}
  .alert-dot {{ position: absolute; left: 0; top: .35rem; width: 10px; height: 10px; border-radius: 50%; display: inline-block; }}
  .mini-grid th {{ font-size: .65rem; color: #666; text-align: left; }}
  .mini-grid th:nth-child(2) {{ text-align: center; }}
  .mini-grid th:nth-child(3) {{ text-align: right; }}
  .busqs-list {{ font-size: .8rem; }}
  .busqs-top {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: .3rem; gap: .4rem; }}
  .busqs-top .meta {{ flex: 1; }}
  .busqs-top button {{ font-size: .65rem; color: #333; padding: .15rem .45rem; border: 1px solid #ddd; background: #f5f5f5; border-radius: 4px; cursor: pointer; white-space: nowrap; }}
  .busqs-top button:hover {{ background: #eee; }}
  .busq-header, .busq-fila summary {{ display: flex; justify-content: space-between; align-items: baseline; gap: .5rem; padding: .35rem 0; }}
  .busq-fila summary {{ color: #333; font-size: .85rem; cursor: pointer; }}
  .busq-fila summary:hover {{ background: #f7f7f7; }}
  .busq-header {{ font-size: .65rem; color: #666; border-bottom: 1px solid #ddd; text-transform: uppercase; letter-spacing: .03em; }}
  .busq-quién {{ flex: 0 0 35%; min-width: 0; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
  .busq-q {{ flex: 1 1 auto; min-width: 0; word-break: break-word; padding: 0 .4rem; }}
  .busq-n {{ flex: 0 0 2.2rem; text-align: right; }}
  .busq-fila {{ border-bottom: 1px solid #eee; }}
  .busq-fila[open] {{ padding-bottom: .4rem; }}
  .busq-hits {{ font-size: .74rem; padding: .2rem .4rem .2rem 1.2rem; margin: 0; color: #444; }}
  .busq-hits li {{ margin: .15rem 0; }}
  .busq-hits a {{ word-break: break-word; }}
  #loader {{ position: fixed; top: 0; left: 0; width: 100%; height: 100%;
              background: #f6f7f9cc; display: none; align-items: center;
              justify-content: center; z-index: 9999; }}
  #loader .card {{ background: #fff; padding: 1.5rem 2rem; border-radius: 10px;
                   box-shadow: 0 4px 20px #0003; text-align: center; }}
  #loader .spinner {{ width: 36px; height: 36px; border: 4px solid #1a237e33;
                      border-top-color: #1a237e; border-radius: 50%;
                      animation: spin 1s linear infinite; margin: 0 auto .8rem; }}
  @keyframes spin {{ to {{ transform: rotate(360deg); }} }}
  #loader .txt {{ color: #1a237e; font-weight: 600; }}
  .trending {{ display: flex; flex-wrap: wrap; gap: .5rem; margin: .8rem 0 1.2rem; }}
  .trending a {{ text-decoration: none; }}
  .chip-trend {{ display: inline-block; background: #7b1fa2; color: #fff;
      font-size: .72rem; font-weight: 600; text-transform: uppercase;
      letter-spacing: .03em; padding: .3rem .7rem; border-radius: 14px; }}
  .chip-trend:hover {{ background: #6a1b9a; }}
  /* ── tema espacial Trillian ── */
  body {{ background: #04050d; color: #dfe4ff; }}
  body::before {{ content: ''; position: fixed; inset: 0; z-index: -2;
    pointer-events: none;
    background:
      radial-gradient(ellipse 80% 55% at 70% -10%, #1a237e55, transparent 60%),
      radial-gradient(ellipse 60% 45% at 10% 110%, #4a148c44, transparent 60%),
      linear-gradient(180deg, #05060f 0%, #0a0e24 55%, #04050d 100%); }}
  body::after {{ content: ''; position: fixed; inset: 0; z-index: -1;
    pointer-events: none; opacity: .8;
    background-image:
      radial-gradient(1px 1px at 12% 22%, #ffffffcc 50%, transparent 51%),
      radial-gradient(1.4px 1.4px at 68% 12%, #9fd8ff88 50%, transparent 51%),
      radial-gradient(1px 1px at 84% 64%, #ffffffbb 50%, transparent 51%),
      radial-gradient(2px 2px at 32% 78%, #b388ff66 50%, transparent 51%),
      radial-gradient(1px 1px at 55% 45%, #ffffffaa 50%, transparent 51%),
      radial-gradient(1.6px 1.6px at 8% 88%, #69f0ae66 50%, transparent 51%),
      radial-gradient(1px 1px at 92% 30%, #ffffff99 50%, transparent 51%),
      radial-gradient(1.2px 1.2px at 45% 8%, #ffd54f88 50%, transparent 51%);
    background-size: 460px 460px, 560px 560px, 380px 380px,
                     640px 640px, 520px 520px, 600px 600px,
                     500px 500px, 720px 720px; }}
  .card, nav, header, footer {{
    background: rgba(13, 18, 48, .78) !important;
    border-color: #2c3a72 !important; color: #dfe4ff;
    backdrop-filter: blur(10px); }}
  a {{ color: #8ab4ff; }}
  a:hover {{ color: #c3d0ff; }}
  .meta, .meta2, small {{ color: #9aa3c7 !important; }}
  input[type=text], input[type=email], input[type=password],
  input[type=search], textarea, select {{
    background: #0d1330 !important; color: #eef1ff !important;
    border-color: #33415f !important; }}
  ::-webkit-scrollbar-thumb {{ background: #2c3a72; }}
  .tema-btn {{ background: rgba(255,255,255,.07); border: 1px solid #3a4a80;
    color: #cfd6ff; border-radius: 8px; width: 30px; height: 30px;
    cursor: pointer; font-size: .95rem; line-height: 1; }}
  .tema-btn:hover {{ border-color: #7c4dff; box-shadow: 0 0 10px #7c4dff55; }}
  /* tema claro — revierte el espacio al look clásico claro */
  html.tema-claro body {{ background: #f6f7f9; color: #222; }}
  html.tema-claro body::before, html.tema-claro body::after {{ display: none; }}
  html.tema-claro .card, html.tema-claro nav, html.tema-claro header,
  html.tema-claro footer {{ background: #fff !important;
    border-color: #ddd !important; color: #222; backdrop-filter: none; }}
  html.tema-claro a {{ color: #1a237e; }}
  html.tema-claro .meta, html.tema-claro .meta2, html.tema-claro small {{
    color: #666 !important; }}
  html.tema-claro input[type=text], html.tema-claro input[type=email],
  html.tema-claro input[type=password], html.tema-claro input[type=search],
  html.tema-claro textarea, html.tema-claro select {{
    background: #fff !important; color: #222 !important;
    border-color: #ccc !important; }}
  html.tema-claro .tema-btn {{ background: #fff; border-color: #ccc;
    color: #1a237e; }}
</style></head><body>
<nav>
  <div class="nav-top">
    <a class="logo" href="/">@noticias</a>
    <span class="nav-user" title="{usuario}">{usuario_html}</span>
    <button id="tema-toggle" class="tema-btn" title="Cambiar tema">◐</button>
    <a href="/salir" class="salir-top" title="Cerrar sesión">salir</a>
  </div>
  <div class="nav-tabs">
    {tabs_base}
    {tabs_reg}
    {admin_tabs}
  </div>
</nav>
<main{main_cls}>
{contenido}
</main>
<div id="loader"><div class="card"><div class="spinner"></div><div class="txt" id="loader-txt">Cargando...</div></div></div>
<footer><a href="/acerca" class="about">@</a> <a href="https://unknownshopper.github.io/PIRIA" class="about" target="_blank" rel="noopener" title="PIRIA">PIRIA</a></footer>
<script>
function showLoader(msg) {{
  var l = document.getElementById('loader');
  if (!l) return;
  document.getElementById('loader-txt').textContent = msg || 'Cargando...';
  l.style.display = 'flex';
}}
// bloques de enlaces de síntesis: Chrome no expande <details>
// cerrado con CSS — abrir al imprimir y restaurar después
window.addEventListener('beforeprint', function() {{
  document.querySelectorAll('details.blk-refs').forEach(function(d) {{
    if (!d.open) d.dataset._cerrado = '1';
    d.open = true;
  }});
}});
window.addEventListener('afterprint', function() {{
  document.querySelectorAll('details.blk-refs').forEach(function(d) {{
    if (d.dataset._cerrado) {{ d.open = false; delete d.dataset._cerrado; }}
  }});
}});
window.addEventListener('pageshow', function() {{
  var l = document.getElementById('loader');
  if (l) l.style.display = 'none';
}});
// tab activo: marca el link del nav según la ruta actual
var _tab = location.pathname;
document.querySelectorAll('.nav-tabs a').forEach(function(a) {{
  if (a.getAttribute('href') === _tab) a.classList.add('on');
}});
// tab activo siempre a la vista: al cargar salta directo; tras ~2.5s
// sin tocar la barra (dedo o stylus) regresa con scroll suave
var _tabs = document.querySelector('.nav-tabs');
var _activo = _tabs && _tabs.querySelector('a.on');
if (_tabs && _activo) {{
  _activo.scrollIntoView({{inline:'center', block:'nearest'}});
  var _tNav;
  var _rearmarNav = function() {{
    clearTimeout(_tNav);
    _tNav = setTimeout(function() {{
      _activo.scrollIntoView({{behavior:'smooth', inline:'center',
                              block:'nearest'}});
    }}, 2500);
  }};
  ['scroll','touchstart','pointerdown'].forEach(function(ev) {{
    _tabs.addEventListener(ev, _rearmarNav, {{passive: true}});
  }});
}}
// alto del nav fijo → los encabezados sticky (columnas del deck en
// móvil) se acomodan justo debajo sin taparse
var _navEl = document.querySelector('nav');
function _navH() {{
  if (_navEl) document.documentElement.style.setProperty(
    '--navh', _navEl.offsetHeight + 'px');
}}
_navH(); addEventListener('resize', _navH);
</script>
<script>
/* toggle de tema — oscuro espacial por defecto, 'claro' revierte;
   persiste en localStorage del navegador */
(function(){{
  var k='tema@noticias';
  if(localStorage.getItem(k)==='claro')document.documentElement.classList.add('tema-claro');
  var b=document.getElementById('tema-toggle');
  if(b)b.addEventListener('click',function(){{
    var c=document.documentElement.classList.toggle('tema-claro');
    localStorage.setItem(k,c?'claro':'oscuro');
  }});
}})();
</script>
<script>
/* .media-strip (miniaturas de las tarjetas):
   - arrastrar con el mouse mueve el scroll horizontal
   - la rueda del mouse sobre la tira scrollea en horizontal */
document.addEventListener('pointerdown',function(e){{
  var s=e.target.closest('.media-strip');if(!s)return;
  var sx=e.clientX,sl=s.scrollLeft,drag=false;
  function mv(ev){{
    var dx=ev.clientX-sx;
    if(Math.abs(dx)>4){{drag=true;s.classList.add('dragging')}}
    if(drag)s.scrollLeft=sl-dx;}}
  function up(){{
    s.classList.remove('dragging');
    document.removeEventListener('pointermove',mv);
    document.removeEventListener('pointerup',up);}}
  document.addEventListener('pointermove',mv);
  document.addEventListener('pointerup',up);
}});
document.addEventListener('wheel',function(e){{
  var s=e.target.closest('.media-strip');if(!s)return;
  if(Math.abs(e.deltaY)>Math.abs(e.deltaX)){{
    e.preventDefault();s.scrollLeft+=e.deltaY;}}}},
  {{passive:false}});
</script>
</body></html>"""


def _escribir_json(path: Path, data):
    """Write atómico (tmp + replace) — el bug que 'borró' usuarios.json:
    write_text() a medias tras un restart/corte dejaba el archivo
    truncado y el lector devolvía default como si estuviera vacío."""
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2))
    tmp.replace(path)


def cargar_json(path: Path, default):
    """JSON tolerante: si el archivo quedó truncado/corrupto (p. ej. corte
    de luz a mitad de una escritura), regresa default en vez de tronar."""
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text())
    except Exception:
        return default


def leer_jsonl(path: Path, limite: int = 0) -> list:
    if not path.exists():
        return []
    lineas = [l for l in path.read_text().splitlines() if l.strip()]
    if limite:
        lineas = lineas[-limite:]
    filas = []
    for l in lineas:
        try:
            filas.append(json.loads(l))
        except json.JSONDecodeError:
            pass  # línea truncada por corte de luz / escritura a medias
    return filas


LOGIN = """<!DOCTYPE html>
<html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="theme-color" content="#1a237e">
<link rel="icon" type="image/png" href="/icon3.png">
<meta property="og:type" content="website">
<meta property="og:site_name" content="@noticias">
<meta property="og:title" content="@noticias — Visor y colector de noticias">
<meta property="og:description" content="La mesa de trabajo de comunicación social: cada área publica, supervisión asigna y mide. Contenido 100% humano.">
<meta property="og:image" content="{base}/og.png">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:image" content="{base}/og.png">
<title>@noticias — Entrar</title>
<style>
  * { box-sizing: border-box; }
  body { font-family: system-ui, sans-serif; margin: 0; min-height: 100vh;
         background: #f6f7f9; display: flex; align-items: center;
         justify-content: center; padding: 1rem; }
  .login { width: 100%; max-width: 360px; text-align: center; }
  .logo { font-size: 3.2rem; font-weight: 800; color: #1a237e;
          letter-spacing: -.02em; margin: 0; }
  .tag { color: #666; font-size: .95rem; margin: .3rem 0 2rem; }
  form { margin: 0; }
  input { width: 100%; padding: .9rem 1rem; border: 1px solid #ccc;
          border-radius: 8px; font-size: 1rem; margin-bottom: .7rem; }
  button { width: 100%; padding: .9rem 1rem; background: #1a237e; color: #fff;
           border: none; border-radius: 8px; font-size: 1.05rem;
           font-weight: 600; cursor: pointer; min-height: 48px; }
  .error { color: #c62828; font-size: .9rem; margin-bottom: .8rem; }
  .demo { margin-top: 1.6rem; text-align: left; }
  .demo h3 { font-size: .78rem; color: #888; text-transform: uppercase;
             letter-spacing: .06em; margin: 0 0 .5rem; font-weight: 600; }
  .demo-grid { display: grid; grid-template-columns: 1fr 1fr; gap: .4rem; }
  .demo-grid button { background: #eef1f8; color: #1a237e; font-weight: 500;
                      font-size: .82rem; padding: .55rem .4rem; margin: 0;
                      border: 1px solid #d5d9ec; border-radius: 8px;
                      min-height: 0; }
  .demo-grid button:hover { background: #1a237e; color: #fff; }
  .pie { color: #c3c9d4; font-size: .8rem; margin-top: 2.5rem; }
</style></head><body>
<div class="login">
  <p class="logo">@noticias</p>
  <p class="tag">Visor y colector de noticias — redacción por áreas</p>
  {error}
  <form method="post" action="/login">
    <input type="email" name="email" placeholder="Usuario (correo)"
           autocomplete="username" required>
    <input type="password" name="password" placeholder="Contraseña"
           autocomplete="current-password" required>
    <button>Entrar</button>
  </form>
  {demo}
  <p class="pie">Powered by <a href="https://unknownshopper.github.io/PIRIA" target="_blank" rel="noopener" style="color:#c3c9d4">PIRIA</a></p>
</div>
</body></html>"""


MANTENIMIENTO = """<!DOCTYPE html>
<html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="theme-color" content="#1a237e">
<link rel="icon" type="image/png" href="/icon3.png">
<meta property="og:type" content="website">
<meta property="og:site_name" content="@noticias">
<meta property="og:title" content="@noticias — Visor y colector de noticias">
<meta property="og:description" content="La mesa de trabajo de comunicación social: cada área publica, supervisión asigna y mide. Contenido 100% humano.">
<meta property="og:image" content="{base}/og.png">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="@noticias — Visor y colector de noticias">
<meta name="twitter:description" content="La mesa de trabajo de comunicación social: cada área publica, supervisión asigna y mide.">
<meta name="twitter:image" content="{base}/og.png">
<title>@noticias — Visor y colector de noticias</title>
<style>
  * { box-sizing: border-box; }
  body { font-family: system-ui, sans-serif; margin: 0; min-height: 100vh;
         background: #f6f7f9; display: flex; align-items: center;
         justify-content: center; padding: 1rem; }
  .box { width: 100%; max-width: 400px; text-align: center;
         background: #fff; border: 1px solid #e4e6ef;
         border-radius: 16px; padding: 2.6rem 1.8rem;
         box-shadow: 0 10px 30px rgba(26,35,126,.07); }
  .logo { font-size: 2.6rem; font-weight: 800; color: #1a237e;
          letter-spacing: -.02em; margin: 0 0 .4rem; }
  h1 { font-size: 1.05rem; color: #333; margin: .6rem 0 .8rem; }
  .pitch { color: #777; font-size: .9rem; line-height: 1.55;
           margin: 0 0 1.4rem; }
  ul.puntos { text-align: left; color: #555; font-size: .86rem;
              line-height: 1.6; margin: 0 0 1.8rem; padding-left: 1.2rem; }
  ul.puntos li { margin-bottom: .45rem; }
  ul.puntos b { color: #1a237e; }
  a.btn { display: inline-block; padding: .85rem 2.2rem; background: #1a237e;
          color: #fff; border-radius: 10px; text-decoration: none;
          font-weight: 600; font-size: 1rem; }
  a.btn:hover { background: #283593; }
  .pie { color: #c3c9d4; font-size: .75rem; margin-top: 2rem; }
</style></head><body>
<div class="box">
  <p class="logo">@noticias</p>
  <h1>Visor y colector de noticias</h1>
  <p class="pitch">La mesa de trabajo de comunicación social:
     el contenido lo genera el equipo, no un scraper.</p>
  <ul class="puntos">
    <li><b>Redacción por áreas</b> — cada área publica sus notas con
        foto, video, audio y enlace en un tablero de columnas.</li>
    <li><b>Asignaciones</b> — supervisión destaca una nota y la asigna
        a uno, varios o todos los colaboradores.</li>
    <li><b>Bitácora</b> — seguimiento de eventos: quién cubre, qué se
        pidió y qué se entregó.</li>
    <li><b>Chat + asistente IA</b> — coordinación interna y un asistente
        que responde citando las publicaciones reales del equipo.</li>
    <li><b>Reporte</b> — producción por colaborador y por área, para
        medir el ritmo del equipo.</li>
  </ul>
  <a class="btn" href="/login">Entrar</a>
  <p class="pie">Powered by PIRIA</p>
</div>
</body></html>"""


def vista_login(base: str, error: str = "") -> bytes:
    err = (f"<p class='error'>{html.escape(error)}</p>" if error else "")
    # la grilla de acceso rápido quedó fuera — era para la demo con
    # gente inventada; el login es email + password
    return (LOGIN.replace("{error}", err)
                 .replace("{base}", base)
                 .replace("{demo}", "")).encode()


def cookie_sesion(email: str, https: bool) -> str:
    seguro = "; Secure" if https else ""
    return (f"s={email}.{firma_cookie(email)}; Path=/; HttpOnly; "
            f"SameSite=Lax{seguro}")


PALETA = ["#1a237e", "#1565c0", "#00695c", "#ef6c00", "#ad1457",
          "#4527a0", "#2e7d32", "#c62828", "#00838f", "#5d4037"]


def vista_landing(base: str) -> bytes:
    """Raíz pública — propuesta del producto (visor y colector de
    noticias) con acceso directo al login."""
    return MANTENIMIENTO.replace("{base}", base).encode()


def vista_instructivo(base: str) -> bytes:
    """Tour técnico público: cada sección con su captura real + el porqué
    detrás. Las imágenes se regeneran con shots.py al cambiar el diseño."""
    SECCIONES = [
        ("redaccion", "Redacción — el tablero de columnas",
         "El corazón del sistema: una columna por evento/tema y dentro "
         "las publicaciones del equipo. Cada tarjeta lleva autor, hora, "
         "texto y multimedia (foto, video, audio, PDF). Supervisión ve "
         "todas las columnas; cada área ve su feed."),
        ("area", "Mi área — el feed del colaborador",
         "Cada colaborador pertenece a un área (prensa, tv, radio, "
         "redes…). En 'Mi área' publica sus notas, ve lo de su equipo y "
         "recibe los avisos que le asigna supervisión."),
        ("asignaciones", "Asignaciones — avisos manuales",
         "Supervisión selecciona publicaciones y las asigna a uno, "
         "varios o todos los colaboradores de un área. El colaborador "
         "las ve en su bandeja de avisos y las marca como hechas."),
        ("bitacora", "Bitácora — seguimiento de eventos",
         "Registro de eventos de cobertura: quién va, qué se pidió y "
         "qué se entregó. Las publicaciones se vinculan al evento que "
         "reportan."),
        ("chat", "Chat — canales internos",
         "Mensajería del equipo por canales. Sin salir del tablero: "
         "se coordina la cobertura en el mismo lugar donde se publica."),
        ("asistente", "Asistente IA",
         "Preguntas sobre las publicaciones del equipo con contexto "
         "real: cita las notas internas que usó para responder. "
         "Gemini primero, Ollama local de respaldo."),
        ("reporte", "Reporte — producción por colaborador",
         "Cuántas publicaciones hizo cada colaborador en las últimas "
         "horas, por área. La herramienta de supervisión para medir "
         "el ritmo del equipo."),
        ("analitica", "Analítica — solo admin",
         "Bitácora de uso por usuario: sesiones, tiempo dentro y "
         "última actividad."),
    ]
    bloques = "".join(f"""
  <h2 id="{k}">{i + 1}. {t}</h2>
  <p>{d}</p>"""
        for i, (k, t, d) in enumerate(SECCIONES))
    doc = f"""<!DOCTYPE html>
<html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="theme-color" content="#1a237e">
<link rel="icon" type="image/png" href="/icon3.png">
<title>Instructivo — @noticias</title>
<style>
  * {{ box-sizing: border-box; }}
  body {{ font-family: system-ui, sans-serif; margin: 0; color: #222;
         background: #f6f7f9; font-size: 16px; line-height: 1.5; }}
  nav {{ background: #1a237e; padding: .8rem 1.2rem; display: flex;
        justify-content: space-between; align-items: center;
        position: sticky; top: 0; z-index: 9; }}
  nav .logo {{ color: #fff; font-weight: 800; font-size: 1.3rem;
              text-decoration: none; }}
  nav a.entrar {{ color: #fff; border: 1px solid #ffffff55;
      border-radius: 6px; padding: .4rem .9rem; text-decoration: none;
      font-size: .85rem; }}
  .wrap {{ max-width: 460px; margin: 0 auto; padding: 1.5rem 1rem 3rem; }}
  h1 {{ color: #1a237e; font-size: 1.6rem; }}
  h2 {{ color: #1a237e; font-size: 1.15rem; margin: 2rem 0 .5rem; }}
  p {{ color: #444; font-size: .95rem; margin: .5rem 0 0; }}
  img.shot {{ width: 100%; max-height: 560px; object-fit: cover;
      object-position: top; border-radius: 10px;
      box-shadow: 0 2px 10px #0002; border: 1px solid #e3e6ef;
      background: #fff; }}
  code {{ background: #eceff5; padding: 0 .3rem; border-radius: 4px;
         font-size: .85em; }}
  .tech {{ background: #fff; border-radius: 8px; padding: 1rem 1.2rem;
      box-shadow: 0 1px 4px #0001; }}
  .tech li {{ margin: .4rem 0; font-size: .9rem; color: #444; }}
</style></head><body>
<nav><a class="logo" href="/">@noticias</a>
<a class="entrar" href="/login">Entrar</a></nav>
<div class="wrap">
<h1>Cómo funciona</h1>
<p>La mesa de trabajo del equipo de comunicación social: cada área
publica, supervisión asigna y mide — todo en el mismo tablero.</p>
{bloques}
<h2>Por dentro</h2>
<div class="tech"><ul>
  <li>Python puro — <code>http.server</code> con hilos, cero framework</li>
  <li>Contenido 100% humano: lo publican los colaboradores, no hay
      scraping ni feeds externos</li>
  <li>Datos en JSONL append-only — cero base de datos externa</li>
  <li>Asistente con Gemini → Ollama local de respaldo</li>
  <li>Sesiones con cookies firmadas HMAC; demos de 24h autodestruibles</li>
  <li>Servido por Cloudflare Tunnel</li>
</ul></div>
</div></body></html>"""
    return doc.encode()


def icono_png() -> bytes:
    """Ícono de la app: cuadrado navy con una '@' blanca dibujada a mano
    (aro exterior + cuenco de la 'a' + vástago con cola). PNG 192x192
    construido sin dependencias externas."""
    import struct, zlib
    W = H = 192
    cx = cy = 96
    filas = b""
    for y in range(H):
        filas += b"\x00"
        for x in range(W):
            # cuadrado opaco: iOS/Android le aplican su propia máscara
            d2 = (x - cx) ** 2 + (y - cy) ** 2
            aro = 52 * 52 <= d2 <= 68 * 68            # aro exterior
            bx, by = x - (cx - 6), y - (cy - 10)      # origen del 'a'
            d2i = bx * bx + by * by
            bowl = 12 * 12 <= d2i <= 26 * 26          # cuenco del 'a'
            stem = 13 <= bx <= 27 and -26 <= by <= 38  # vástago derecho
            hook = 28 <= by <= 42 and 13 <= bx <= 44   # cola inferior
            if aro or bowl or stem or hook:
                filas += b"\xff\xff\xff\xff"          # '@' blanca
            else:
                filas += b"\x1a\x23\x7e\xff"          # navy #1a237e
    def chunk(tipo, datos):
        c = struct.pack(">I", len(datos)) + tipo + datos
        return c + struct.pack(">I", zlib.crc32(tipo + datos) & 0xFFFFFFFF)
    png = (b"\x89PNG\r\n\x1a\n"
           + chunk(b"IHDR", struct.pack(">IIBBBBB", W, H, 8, 6, 0, 0, 0))
           + chunk(b"IDAT", zlib.compress(filas, 9))
           + chunk(b"IEND", b""))
    return png


MANIFEST = json.dumps({
    "id": "/",
    "name": "@noticias",
    "short_name": "@noticias",
    "description": "@noticias — redacción de comunicación social por áreas",
    "lang": "es-MX",
    "start_url": "/",
    "scope": "/",
    "display": "standalone",
    "display_override": ["standalone"],
    "background_color": "#f6f7f9",
    "theme_color": "#1a237e",
    "prefer_related_applications": False,
    "icons": [
        {"src": "/icon3.png", "sizes": "192x192", "type": "image/png",
         "purpose": "any"},
        {"src": "/icon3.png", "sizes": "512x512", "type": "image/png",
         "purpose": "any"},
        {"src": "/icon3.png", "sizes": "512x512", "type": "image/png",
         "purpose": "maskable"},
    ],
}).encode()


_ICONO = None  # cache del PNG generado


def vista_usuarios(email: str) -> str:
    """Gestión de perfiles (solo admin): crear, nivel, proyectos,
    password, demo 24h, eliminar. Antes vivía dentro de /fuentes."""
    cfg = json.loads(CONFIG.read_text())
    usuarios = cargar_usuarios()
    cards_u = ""
    for u_email, u in sorted(usuarios.items()):
        expira = u.get("expira", 0)
        tipo = ("admin" if es_admin(u_email, cfg)
                else f"demo hasta {fmt_fecha(datetime.fromtimestamp(expira).isoformat())}"
                if expira else "usuario")
        proy = ", ".join(proyectos_usuario(u_email))
        niv = u.get("nivel", "operacion")
        etiqueta = f"{proy or 'sin proyecto'} · {niv}"
        sel_niv = ("<select name='nivel'>"
                   + "".join(
                       f"<option value='{v}'"
                       f"{' selected' if niv == v else ''}>{t}</option>"
                       for v, t in (("operacion", "Operación"),
                                    ("supervision", "Supervisión")))
                   + "</select>")
        form = ""
        if es_admin(u_email, cfg):
            # degradar a operador — su perfil queda y ya se le pueden
            # asignar proyectos/nivel; protege al último admin y a
            # uno mismo
            if u_email != email and len(cfg.get("admins", [])) > 1:
                form = (
                    f"<form method='post' action='/usuarios'>"
                    f"<input type='hidden' name='email' "
                    f"value='{html.escape(u_email, quote=True)}'>"
                    f"<div class='regla-pie'>"
                    f"<button name='accion' value='quitar_admin' "
                    f"onclick=\"return confirm('¿Quitar admin a "
                    f"{html.escape(u_email)}? Pasa a operador.')\">"
                    f"Quitar admin → operador</button></div></form>")
        else:
            form = (
                f"<form method='post' action='/usuarios'>"
                f"<input type='hidden' name='email' value='{html.escape(u_email, quote=True)}'>"
                f"<label>Proyectos</label>"
                f"<input type='text' name='proyecto' "
                f"value='{html.escape(proy, quote=True)}' "
                f"placeholder='tsjt, qroo…'>"
                f"<label>Nivel</label>{sel_niv}"
                f"<div class='regla-pie'>"
                f"<button name='accion' value='perfil'>Guardar perfil</button>"
                f"</div>"
                f"<label>Nueva contraseña</label>"
                f"<input type='text' name='password' "
                f"placeholder='dejar vacío para no cambiar'>"
                f"<div class='regla-pie'>"
                f"<button name='accion' value='password'>Cambiar clave</button>"
                + (f"<button name='accion' value='quitar_demo'>Quitar demo</button>"
                   if expira else
                   f"<button class='btn-linea' name='accion' value='demo24'>Demo {DEMO_HORAS}h</button>")
                + "<button class='btn-rojo' name='accion' value='eliminar' "
                  "onclick=\"return confirm('¿Eliminar este perfil?')\">Eliminar</button>"
                  "</div></form>")
        cards_u += f"""<div class="card regla" style="border-left-color:#4527a0">
  <strong>{html.escape(u_email)}</strong>
  <span class="meta"> · {tipo} · {html.escape(etiqueta)}</span>
  {form}
</div>"""
    return f"""
<h1>Usuarios</h1>
<p class="meta">Perfiles con acceso por login. "demo" = perfil temporal
que se autodestruye al expirar.</p>
<div class="card regla" style="border-left-color:#2e7d32">
  <strong>Crear usuario</strong>
  <form method="post" action="/usuarios">
    <label>Correo</label>
    <input type="email" name="email" placeholder="correo@ejemplo.com" required>
    <label>Contraseña inicial</label>
    <input type="text" name="password" required>
    <label>Proyectos <span class="meta">(equipos — separa con coma si son varios)</span></label>
    <input type="text" name="proyecto" placeholder="tsjt, qroo…">
    <label>Nivel</label>
    <select name="nivel">
      <option value="operacion">Operación</option>
      <option value="supervision">Supervisión</option>
    </select>
    <div class="regla-pie">
      <button name="accion" value="crear">Crear usuario</button>
    </div>
  </form>
</div>
{cards_u}"""


def vista_acerca() -> str:
    """Página 'Acerca de': versión, crédito, arquitectura y estado de datos."""
    def peso(path: Path) -> str:
        if not path.exists():
            return "-"
        kb = path.stat().st_size / 1024
        return f"{kb:.0f} KB" if kb < 1024 else f"{kb/1024:.1f} MB"

    archivos = "".join(
        f"<tr><td>{nombre}</td><td>{peso(p)}</td>"
        f"<td>{len(leer_jsonl(p)) if p.suffix == '.jsonl' else '-'}</td></tr>"
        for nombre, p in [
            ("redaccion.jsonl", REDACCION),
            ("seguimientos.jsonl", SEGUIMIENTOS),
            ("chat_msg.jsonl", CHAT_MSG),
            ("actividad.jsonl", ACTIVIDAD),
            ("usuarios.json", USUARIOS),
            ("config.json", CONFIG),
        ]
    )
    cfg = json.loads(CONFIG.read_text())
    usuarios = cargar_usuarios()
    return f"""
<h1>@noticias <span class="meta">v{VERSION}</span></h1>
<p class="meta">La mesa de trabajo de comunicación social: cada área publica,
supervisión asigna y mide.<br>
Hecho con: 1 archivo Python + requests + JSONL en disco.
Mucho con muy poco.<br>
Powered by <a href="https://unknownshopper.github.io/PIRIA" target="_blank" rel="noopener"><strong>PIRIA</strong></a>.</p>

<div class="card top">
  <span class="titulo">Arquitectura</span>
  <div class="meta" style="margin-top:.4rem">
    Contenido 100% humano — los colaboradores publican, no hay scraping ·<br>
    redacción por áreas: columnas de eventos, multimedia, asignaciones ·<br>
    bitácora de cobertura + chat interno + asistente IA (Gemini→Ollama) ·<br>
    webapp: http.server multi-hilo, cero dependencias web
  </div>
</div>

<h2>Base de datos</h2>
<p class="meta">JSONL en disco — cero motor externo.</p>
<table class="fija"><tr><th>Archivo</th><th>Tamaño</th><th>Registros</th></tr>
{archivos}</table>

<h2>Equipo</h2>
<p class="meta">{len(usuarios)} usuarios
· {len(areas_redaccion(cfg))} áreas de redacción</p>"""


def vista_analitica() -> str:
    """Panel admin: quién entró, cuánto estuvo.
    Sesión = secuencia de hits con <30 min entre ellos; tiempo ≈ suma de
    gaps (cada gap se corta a 5 min para no inflar lecturas largas)."""
    eventos = leer_jsonl(ACTIVIDAD, limite=20000)
    por_usuario = {}
    for e in eventos:
        por_usuario.setdefault(e["email"] or "(anónimos)", []).append(e)

    def resumen(evs):
        """Sesiones, minutos y referrers de un usuario."""
        ts = sorted(datetime.fromisoformat(e["ts"]) for e in evs)
        sesiones, mins = 1, 0.0
        for a, b in zip(ts, ts[1:]):
            gap = (b - a).total_seconds() / 60
            if gap > 30:
                sesiones += 1
            else:
                mins += min(gap, 5)
        refs = Counter(
            urlparse(e["ref"]).netloc for e in evs
            if e.get("ref") and "unknownshoppers" not in e["ref"]
            and "localhost" not in e["ref"])
        return ts[0], ts[-1], sesiones, mins, refs

    ahora = datetime.now()
    hoy = ahora.date()
    hace7 = ahora - timedelta(days=7)

    def fila(email, evs):
        primero, ultimo, ses, mins, refs = resumen(evs)
        en_linea = (ahora - ultimo).total_seconds() < 600
        dot = ("<span style='color:#2e7d32' title='en línea'>●</span> "
               if en_linea else "")
        via = ", ".join(d for d, _ in refs.most_common(2)) or "—"
        return (f"<tr><td>{dot}{html.escape(email)}</td>"
                f"<td>{ses}</td><td>~{mins:.0f}</td>"
                f"<td class='meta'>{html.escape(via)}</td>"
                f"<td class='meta'>{ultimo:%d/%m %H:%M}</td></tr>")

    reales, demos, anon = [], [], []
    activos_ahora = 0
    for email, evs in por_usuario.items():
        (demos if "@demo.local" in email
         else anon if email == "(anónimos)" else reales).append((email, evs))
        if resumen(evs)[1] > ahora - timedelta(minutes=10):
            activos_ahora += 1
    reales.sort(key=lambda x: -resumen(x[1])[1].timestamp())
    demos.sort(key=lambda x: -resumen(x[1])[1].timestamp())

    # --- Panel enriquecido ---
    eventos_7d = [e for e in eventos if datetime.fromisoformat(e["ts"]) > hace7]
    eventos_hoy = [e for e in eventos if datetime.fromisoformat(e["ts"]).date() == hoy]
    refs_7d = Counter(
        urlparse(e["ref"]).netloc for e in eventos_7d
        if e.get("ref") and "unknownshoppers" not in e["ref"]
        and "localhost" not in e["ref"])

    visitas_hoy = len(eventos_hoy)

    por_dia = Counter()
    for e in eventos:
        d = datetime.fromisoformat(e["ts"]).date()
        if hace7.date() <= d <= hoy:
            por_dia[d] += 1
    dias = [hoy - timedelta(days=i) for i in range(7)]
    dias.reverse()
    max_ev = max(por_dia.values() or [1])
    barras = "".join(
        f"<div class='bar' style='height:{por_dia[d]/max_ev*100}%' "
        f"data-n='{por_dia[d]}'><span>{d:%d/%m}</span></div>" for d in dias)
    chart = f"<div class='chart'>{barras}</div>"

    def mini_tabla(titulo, items, cls=""):
        filas = "".join(
            f"<tr><td>{html.escape(str(k)[:40])}</td>"
            f"<td>{html.escape(str(v))}</td></tr>"
            for k, v in items)
        return (f'<div class="card top"><span class="meta">{html.escape(titulo)}</span>'
                f'<table class="fija {cls}">{filas}</table></div>')

    kpi_grid = f'''<div class="kpi-grid">
  <div class="kpi"><big>{activos_ahora}</big><span class="label">Activos ahora</span></div>
  <div class="kpi"><big>{visitas_hoy}</big><span class="label">Eventos hoy</span></div>
</div>'''

    tops = (f'<div class="mini-grid">'
            f'{mini_tabla("Top referrers (7d)", refs_7d.most_common(7))}'
            f'</div>')
    panel = f"<h2>Últimos 7 días</h2>{kpi_grid}<h3>Actividad por día</h3>{chart}{tops}"

    tabla = """<div class="tabla-scroll"><table class="fija ana">
<tr><th>Usuario</th><th>Ses.</th><th>Min</th><th>Vía</th><th>Último</th></tr>
{filas}</table></div>"""

    cuerpo = (tabla.format(filas="".join(fila(*r) for r in reales + anon)
                           ) if reales or anon else
              "<p class='meta'>Sin actividad aún.</p>")
    if demos:
        cuerpo += (f"<details><summary>demos ({len(demos)}) — "
                   "autodestruibles a las 24h</summary>"
                   + tabla.format(filas="".join(fila(*r) for r in demos))
                   + "</details>")
    return (f"<h1>Analítica</h1>"
            f"<p class='meta'>{len(eventos)} eventos registrados. "
            f"Los demos quedan colapsados abajo; los anónimos son clics "
            f"de links compartidos.</p>{panel}{cuerpo}")


# ===================== REDACCIÓN — feed interno por áreas =====================
# Modelo @Noticias colaborativo: cada área de comunicación social
# (prensa, tv, radio, redes, digital…) tiene colaboradores que
# publican notas con foto/video/enlace/location/urgente. Paolo
# (supervisión) ve todo en columnas; cada área ve su feed + el
# general, con avisos de asignaciones e interés. No hay scraping:
# el contenido lo suben los humanos.
REDACCION = BASE / "redaccion.jsonl"      # publicaciones internas
RED_MEDIA = BASE / "redaccion_media"      # archivos subidos
MEDIA_MAX = 40 * 1024 * 1024              # 40 MB por archivo
TIPO_POR_EXT = {**{e: "img" for e in
                   (".jpg", ".jpeg", ".png", ".gif", ".webp")},
                **{e: "video" for e in (".mp4", ".webm", ".mov",
                                        ".m4v")},
                **{e: "audio" for e in (".mp3", ".ogg", ".wav",
                                        ".m4a", ".aac")},
                ".pdf": "doc"}
MIME_POR_EXT = {"image/jpeg": ".jpg", "image/png": ".png",
                "image/gif": ".gif", "image/webp": ".webp",
                "video/mp4": ".mp4", "video/webm": ".webm",
                "video/quicktime": ".mov", "application/pdf": ".pdf",
                "audio/mpeg": ".mp3", "audio/ogg": ".ogg",
                "audio/wav": ".wav", "audio/x-wav": ".wav",
                "audio/mp4": ".m4a", "audio/aac": ".aac"}
CTYPE_POR_EXT = {".jpg": "image/jpeg", ".jpeg": "image/jpeg",
                 ".png": "image/png", ".gif": "image/gif",
                 ".webp": "image/webp", ".mp4": "video/mp4",
                 ".webm": "video/webm", ".mov": "video/quicktime",
                 ".m4v": "video/mp4", ".pdf": "application/pdf",
                 ".mp3": "audio/mpeg", ".ogg": "audio/ogg",
                 ".wav": "audio/wav", ".m4a": "audio/mp4",
                 ".aac": "audio/aac"}


def _red_cfg(cfg: dict) -> dict:
    return cfg.get("redaccion") or {}


def areas_redaccion(cfg: dict) -> list:
    """Áreas en config.json → redaccion.areas
    [{id, nombre, miembros:[emails]}]."""
    return _red_cfg(cfg).get("areas") or []


def areas_de_usuario(email: str, cfg: dict) -> list:
    """TODAS las áreas del usuario (multi-rol): perfil 'area'/'areas'
    (str o lista) + cada área que lo liste en 'miembros'."""
    perfil = cargar_usuarios().get(email) or {}
    areas = areas_redaccion(cfg)
    aids = set(perfil.get("areas") or [])
    aid = perfil.get("area")
    if isinstance(aid, list):
        aids.update(aid)
    elif aid:
        aids.add(aid)
    return [a for a in areas
            if a.get("id") in aids or email in (a.get("miembros") or [])]


def area_de_usuario(email: str, cfg: dict):
    """Primera área del usuario (compat) — ver areas_de_usuario."""
    areas = areas_de_usuario(email, cfg)
    return areas[0] if areas else None


def _red_nombre(email: str) -> str:
    u = cargar_usuarios().get(email) or {}
    return u.get("nombre") or email.split("@")[0]


def _post_id() -> str:
    return ("r" + datetime.now().strftime("%Y%m%d%H%M%S")
            + secrets.token_hex(3))


def cargar_publicaciones() -> list:
    """Más reciente primero."""
    return sorted(leer_jsonl(REDACCION),
                  key=lambda p: p.get("ts", ""), reverse=True)


def _guardar_publicacion(p: dict):
    RED_MEDIA.mkdir(exist_ok=True)
    with REDACCION.open("a", encoding="utf-8") as f:
        f.write(json.dumps(p, ensure_ascii=False) + "\n")


def _reescribir_publicaciones(posts: list):
    tmp = REDACCION.with_suffix(".tmp")
    tmp.write_text("".join(
        json.dumps(p, ensure_ascii=False) + "\n" for p in posts),
        encoding="utf-8")
    tmp.replace(REDACCION)


SEGUIMIENTOS = BASE / "seguimientos.jsonl"   # eventos de bitácora


def cargar_seguimientos() -> list:
    """Más reciente primero."""
    return sorted(leer_jsonl(SEGUIMIENTOS),
                  key=lambda s: s.get("ts", ""), reverse=True)


def _guardar_seguimiento(s: dict):
    with SEGUIMIENTOS.open("a", encoding="utf-8") as f:
        f.write(json.dumps(s, ensure_ascii=False) + "\n")


def _reescribir_seguimientos(ss: list):
    tmp = SEGUIMIENTOS.with_suffix(".tmp")
    tmp.write_text("".join(
        json.dumps(s, ensure_ascii=False) + "\n" for s in ss),
        encoding="utf-8")
    tmp.replace(SEGUIMIENTOS)


def _usuarios_reales() -> list:
    """[(email, nombre)] de usuarios reales (sin demo), ordenados."""
    return sorted(
        ((e, (u.get("nombre") or e.split("@")[0]))
         for e, u in cargar_usuarios().items()
         if e and "@demo.local" not in e),
        key=lambda t: t[1].lower())


def parse_multipart(cuerpo: bytes, boundary: str) -> dict:
    """multipart/form-data mínimo → {campo: [(filename, content_type,
    bytes)]}. filename='' en campos de texto."""
    sep = ("--" + boundary).encode()
    campos = {}
    for trozo in cuerpo.split(sep):
        if not trozo or trozo in (b"--", b"--\r\n"):
            continue
        trozo = trozo.strip(b"\r\n")
        if not trozo or trozo == b"--":
            continue
        head, _, data = trozo.partition(b"\r\n\r\n")
        if not data:
            continue
        if data.endswith(b"\r\n"):
            data = data[:-2]
        disp = ctype = ""
        for ln in head.decode("utf-8", "replace").split("\r\n"):
            low = ln.lower()
            if low.startswith("content-disposition"):
                disp = ln
            elif low.startswith("content-type"):
                ctype = ln.split(":", 1)[1].strip()
        m = re.search(r'name="([^"]+)"', disp)
        if not m:
            continue
        fm = re.search(r'filename="([^"]*)"', disp)
        campos.setdefault(m.group(1), []).append(
            (fm.group(1) if fm else "", ctype, data))
    return campos


def _guardar_media(post_id: str, idx: int, filename: str,
                   ctype: str, data: bytes):
    """Adjunto → redaccion_media/; devuelve {src,tipo,nombre} o None."""
    if not data or len(data) > MEDIA_MAX:
        return None
    ctype = ctype.split(";")[0].strip().lower()
    ext = MIME_POR_EXT.get(ctype, "")
    if not ext:
        _, _, e = filename.rpartition(".")
        e = ("." + e.lower()) if e else ""
        ext = e if e in TIPO_POR_EXT else ""
    if not ext:
        return None
    nombre = f"{post_id}_{idx}{ext}"
    (RED_MEDIA / nombre).write_bytes(data)
    return {"src": f"/media/{nombre}", "tipo": TIPO_POR_EXT[ext],
            "nombre": filename or nombre}


def _thumb_src(src: str) -> str:
    """Miniatura cacheada (~360px) para adjuntos /media/ de imagen.
    Las tarjetas del deck cargan el thumb en vez del original —
    las portadas pesan ~800KB y sin thumb el scroll se arrastra."""
    if not src.startswith("/media/"):
        return src
    nombre = Path(src[len("/media/"):]).name
    ext = Path(nombre).suffix.lower()
    if ext not in (".jpg", ".jpeg", ".png", ".webp", ".gif", ".bmp"):
        return src
    thumb_dir = RED_MEDIA / "_thumbs"
    thumb = thumb_dir / f"{Path(nombre).stem}_s{ext}"
    if not thumb.is_file():
        try:
            thumb_dir.mkdir(exist_ok=True)
            from PIL import Image
            im = Image.open(RED_MEDIA / nombre)
            im.thumbnail((360, 360))
            if im.mode in ("RGBA", "P", "LA") \
                    and ext in (".jpg", ".jpeg"):
                im = im.convert("RGB")
            im.save(thumb, quality=72)
        except Exception:
            return src
    return f"/media/_thumbs/{thumb.name}"


def _media_html(media: list, compact: bool = False,
                nota_url: str = "") -> str:
    out = []
    strip = []   # buffer de miniaturas — en modo compacto van todas a
                 # una tira con scroll horizontal: la tarjeta no crece
                 # sin importar cuántas imágenes tenga la nota

    def flush():
        if strip:
            out.append("<div class='media-strip'>"
                       + "".join(strip) + "</div>")
            strip.clear()

    for m in media or []:
        src = html.escape(m.get("src", ""), quote=True)
        if not src:
            continue
        if m.get("tipo") == "video":
            poster = m.get("poster") or ""
            if compact and poster:
                # tarjeta: poster como miniatura en la tira; el video
                # completo vive en la nota
                psrc = html.escape(_thumb_src(poster), quote=True)
                strip.append(
                    f"<a href='{nota_url or src}' target='_blank' "
                    f"rel='noopener'><img src='{psrc}' loading='lazy' "
                    f"style='width:120px;height:120px;object-fit:cover;"
                    f"border-radius:8px;display:block'></a>")
            elif compact:
                flush()
                out.append(f"<video src='{src}' controls preload='none' "
                           f"style='max-width:200px;max-height:140px;"
                           f"border-radius:8px;margin:.3rem 0 0 0;"
                           f"background:#000'></video>")
            else:
                flush()
                out.append(f"<video src='{src}' controls preload='metadata' "
                           f"poster='{html.escape(poster, quote=True)}' "
                           f"style='max-width:100%;border-radius:8px;"
                           f"margin:.3rem 0;background:#000'></video>")
        elif m.get("tipo") == "audio":
            flush()
            # radio/podcast: el reproductor + el texto de la tarjeta
            # da el contexto de a qué pertenece el audio
            out.append(
                f"<div style='background:rgba(124,77,255,.12);border:"
                f"1px solid #3a4a80;border-radius:10px;"
                f"padding:.45rem .6rem;margin:.35rem 0'>"
                f"<div class='meta' style='font-size:.62rem;margin-bottom:"
                f".2rem'>♪ audio — {html.escape(m.get('nombre') or 'clip')}</div>"
                f"<audio src='{src}' controls preload='none' "
                f"style='width:100%;height:32px'></audio></div>")
        # transcripción del adjunto (si el LLM ya la generó)
        if m.get("texto"):
            flush()
            out.append(
                f"<details style='margin-top:.3rem'><summary style='"
                f"font-size:.68rem;cursor:pointer;color:#666'>"
                f"transcripción</summary><div style='white-space:"
                f"pre-wrap;font-size:.75rem;background:rgba(0,0,0,.3);"
                f"border-left:3px solid #7c4dff;padding:.4rem .6rem;"
                f"margin-top:.25rem;border-radius:0 8px 8px 0'>"
                f"{html.escape(m['texto'])}</div></details>")
        elif m.get("tipo") == "doc":
            flush()
            out.append(f"<a href='{src}' target='_blank' "
                       f"rel='noopener' style='font-size:.8rem'>"
                       f"ver archivo adjunto →</a>")
        elif m.get("tipo") in (None, "", "img"):
            if compact:
                isrc = html.escape(_thumb_src(src), quote=True)
                strip.append(f"<a href='{src}' target='_blank' "
                             f"rel='noopener'><img src='{isrc}' "
                             f"loading='lazy' "
                             f"style='width:120px;height:120px;object-fit:"
                             f"cover;border-radius:8px;display:block'></a>")
            else:
                flush()
                out.append(f"<a href='{src}' target='_blank' "
                           f"rel='noopener'><img src='{src}' "
                           f"loading='lazy' "
                           f"style='max-width:220px;max-height:220px;"
                           f"border-radius:8px;margin:.3rem .3rem 0 0;"
                           f"object-fit:cover'></a>")
    flush()
    return "".join(out)


def _area_icono(aid: str, size: int = 11) -> str:
    """Icono SVG por medio — sustituye el texto del área en tarjetas
    y encabezados para no repetir 'INSTAGRAM'/'FACEBOOK' en cada post."""
    s = f"width='{size}' height='{size}'"
    sw = "stroke='currentColor' fill='none' stroke-width='1.4'"
    paths = {
        "tv": (f"<svg viewBox='0 0 16 16' {s}><rect x='1.5' y='2.5' "
               f"width='13' height='9' rx='1.5' {sw}/>"
               f"<path d='M6 5.5l4.5 2.5L6 10.5z' fill='currentColor'/></svg>"),
        "radio": (f"<svg viewBox='0 0 16 16' {s}><circle cx='8' cy='11' "
                  f"r='1.3' fill='currentColor'/><path d='M4.6 9.6a5 5 0 "
                  f"017 0M2.6 7.2a8 8 0 0111 0' stroke='currentColor' "
                  f"fill='none' stroke-width='1.3' stroke-linecap='round'/>"
                  f"</svg>"),
        "facebook": (f"<svg viewBox='0 0 16 16' {s}><text x='8' y='12.5' "
                     f"font-size='12' font-weight='700' text-anchor='middle' "
                     f"fill='currentColor'>f</text></svg>"),
        "x": (f"<svg viewBox='0 0 16 16' {s}><text x='8' y='12.5' "
              f"font-size='11' font-weight='700' text-anchor='middle' "
              f"fill='currentColor'>𝕏</text></svg>"),
        "instagram": (f"<svg viewBox='0 0 16 16' {s}><rect x='1.8' y='1.8' "
                      f"width='12.4' height='12.4' rx='3.5' {sw}/>"
                      f"<circle cx='8' cy='8' r='3' {sw}/>"
                      f"<circle cx='11.6' cy='4.4' r='.9' fill='currentColor'/>"
                      f"</svg>"),
        "tiktok": (f"<svg viewBox='0 0 16 16' {s}><text x='8' y='12.5' "
                   f"font-size='11' font-weight='700' text-anchor='middle' "
                   f"fill='currentColor'>♪</text></svg>"),
        "prensa": (f"<svg viewBox='0 0 16 16' {s}><rect x='1.5' y='3' "
                   f"width='13' height='10' rx='1' {sw}/>"
                   f"<path d='M4 6.5h8M4 9h8M4 11.5h5' stroke='currentColor' "
                   f"stroke-width='1.2' stroke-linecap='round'/></svg>"),
        "prensa_digital": (f"<svg viewBox='0 0 16 16' {s}><rect x='1.5' "
                           f"y='2.5' width='13' height='8.5' rx='1' {sw}/>"
                           f"<path d='M5.5 14h5M8 11v3' stroke='currentColor' "
                           f"stroke-width='1.3' stroke-linecap='round'/>"
                           f"<circle cx='8' cy='6.8' r='2' {sw}/>"
                           f"</svg>"),
    }
    return paths.get(aid, paths["prensa"])


def _pub_card(p: dict, email: str, cfg: dict, ret: str = "/redaccion"
              ) -> str:
    """Tarjeta de publicación — la usan la vista supervisor (columnas)
    y la vista de área. En /redaccion lleva checkbox de selección
    (compartir/asignar en lote desde la barra); acciones por tarjeta:
    ver noticia, marcar asignación hecha/pendiente (supervisión o el
    asignado), solicitar unirse al seguimiento."""
    area = next((a for a in areas_redaccion(cfg)
                 if a.get("id") == p.get("area")), {})
    anombre = html.escape(area.get("nombre") or p.get("area") or "?")
    urgente = ("<span style='background:#b03a2e;color:#fff;font-size:"
               ".62rem;font-weight:700;border-radius:8px;padding:1px 7px;"
               "margin-left:.4rem'>URGENTE</span>" if p.get("urgente")
               else "")
    sup = es_supervisor(email, cfg)
    ia_btn = (f"<a class='rb-ia' href='/asistente/nota?id={p.get('id')}' "
              f"title='Contexto IA de esta nota'>✦</a>" if sup else "")
    meta = (f"<span class='chip-fuente' title='{anombre}' "
            f"style='font-size:.6rem;padding:1px 6px;display:inline-flex;"
            f"align-items:center'>"
            f"{_area_icono(p.get('area',''))}</span> "
            f"{html.escape(p.get('nombre') or _red_nombre(p.get('usuario','')))} · "
            f"<span title='{html.escape(fmt_fecha(p.get('ts','')))}'>"
            f"{fmt_relativo(p.get('ts',''))}</span>{urgente}{ia_btn}"
            f"{(' · 💬' + str(len(p.get('comentarios') or []))) if p.get('comentarios') else ''}")
    # la tarjeta es solo titular + resumen (2 líneas) — la cuartilla
    # completa vive en /redaccion/nota
    titulo_c = (p.get("titulo") or "").strip()
    resumen_c = (p.get("resumen") or "").strip()
    if not resumen_c:
        resumen_c = re.sub(r"\s+", " ", p.get("texto", "")).strip()
    cuerpo = (f"<div class='red-tit'>{html.escape(titulo_c)}</div>"
              f"<div class='red-snip'>{html.escape(resumen_c)}</div>"
              if titulo_c else
              f"<div class='red-snip'>{html.escape(resumen_c)}</div>")
    # el enlace externo ya no se muestra en la tarjeta — vive en la
    # vista de nota; aquí solo queda el botón compartir
    loc = p.get("location") or ""
    loc_h = (f"<div class='meta' style='font-size:.72rem;margin-top:.3rem'>"
             f"ubicación: {html.escape(loc)}</div>" if loc else "")
    nota_url = (f"/redaccion/nota?id={p.get('id')}" if p.get("id") else "")
    media_h = _media_html(p.get("media"), compact=True,
                          nota_url=nota_url)

    # ── acciones ──
    sup = es_supervisor(email, cfg)
    ico_doc = ("<svg viewBox='0 0 16 16' width='11' height='11'>"
               "<path d='M4 1.5h5.5L13 5v9.5H4z'/><path d='M9.5 1.5V5H13'"
               "/></svg>")
    es_demo = "@demo.local" in (email or "")
    pid = p.get("id")
    # "ver más" va junto al texto (debajo del resumen), no en la
    # barra de acciones — despliega la cuartilla en la misma tarjeta
    bloques_txt = [b.strip() for b in
                   re.split(r"\n\s*\n", p.get("texto") or "")
                   if b.strip()]
    ver_mas = ""
    if len(bloques_txt) > 1 or len(p.get("texto") or "") > 240:
        ver_mas = ("<details class='red-mas'><summary class='red-mas-s' "
                   "title='Leer la nota completa aquí'>ver más</summary>"
                   "<div class='red-leido'>"
                   + "".join("<p>" + html.escape(b).replace("\n", "<br>")
                             + "</p>" for b in bloques_txt)
                   + "</div></details>")

    secundario = []
    segs = cargar_seguimientos()
    # checkbox de selección del tablero (compartir/asignar en lote
    # desde la barra de herramientas) — solo en /redaccion
    sel_box = (f"<input type='checkbox' class='red-sel' value='{pid}' "
               f"title='Seleccionar para compartir / asignar'>"
               if ret == "/redaccion" and not es_demo else "")
    # la tarjeta se puede arrastrar a la columna ★ Favoritos —
    # personal por usuario real (invitados demo no tienen favoritos)
    drag_attr = (" draggable='true'" if ret == "/redaccion"
                 and not es_demo else "")

    acciones = [
        f"<a class='rb' href='/redaccion/nota?id={pid}' "
        f"title='Ver la nota completa'>{ico_doc} ver noticia</a>"]
    if not es_demo:
        es_fav = email in (p.get("favoritos") or [])
        acciones.append(
            f"<button type='button' class='rb red-star"
            f"{' on' if es_fav else ''}' data-pid='{pid}' "
            f"title='{'Quitar de' if es_fav else 'Agregar a'} "
            f"favoritos'>{'★' if es_fav else '☆'}</button>")

    # ── asignaciones VAN PRIMERO: quién la tiene asignada y en qué
    # estado va es lo operativo — se pinta arriba de la tarjeta ──
    asig_h = ""
    asignaciones = p.get("asignaciones") or []
    if asignaciones:
        filas = []
        for i, a in enumerate(asignaciones):
            pend = a.get("estado", "pendiente") == "pendiente"
            # el toggle de estado es solo de supervisión (Paolo):
            # un icono — ⭕ pendiente / ✅ hecho — al frente de la fila
            toggle = (f"<form method='post' action='/redaccion/asignacion'"
                      f" style='display:inline'><input type='hidden' "
                      f"name='id' value='{p.get('id')}'>" f"<input type='hidden' name='volver' value='{ret}'>"
                      f"<input type='hidden' name='idx' value='{i}'>"
                      f"<input type='hidden' name='estado' value='"
                      f"{'hecho' if pend else 'pendiente'}'>"
                      f"<button class='rb' title='"
                      f"{'marcar hecho' if pend else 'reabrir'}'>"
                      f"{'⭕' if pend else '✅'}</button>"
                      f"</form>" if sup else "")
            filas.append(
                f"<div class='red-asign-f'>{toggle}"
                f"<b>{html.escape(_red_nombre(a.get('para','')))}"
                f"</b> · <span title='{html.escape(fmt_fecha(a.get('ts','')))}'>"
                f"{fmt_relativo(a.get('ts',''))}</span> · "
                f"<span style='color:{'#e6a23c' if pend else '#4caf7d'}'>"
                f"{'pendiente' if pend else 'hecho'}</span> "
                f"{html.escape(a.get('nota',''))}</div>")
        asig_h = ("<div class='red-asign'>"
                  + "".join(filas) + "</div>")

    # ── unirse al seguimiento: el colaborador SOLICITA; aprueba el
    # autor de la nota, el creador del evento o supervisión ──
    s_ev = next((s for s in segs if s.get("id") == p.get("evento")),
                None)
    involucr = (email == p.get("usuario")
                or any(a.get("para") == email
                       for a in (p.get("asignaciones") or []))
                or email in ((s_ev or {}).get("miembros") or []))
    sols_vivas = ([x for x in (p.get("solicitudes") or [])
                   if x.get("estado") == "pendiente"]
                  + [x for x in ((s_ev or {}).get("solicitudes") or [])
                     if x.get("estado") == "pendiente"])
    if not sup and not es_demo and not involucr and not any(
            x.get("de") == email for x in sols_vivas):
        acciones.append(
            f"<form method='post' action='/redaccion/solicitar' "
            f"style='display:inline'><input type='hidden' name='id' "
            f"value='{p.get('id')}'>" f"<input type='hidden' name='volver' value='{ret}'>"
            f"<button class='rb' style='border-style:dashed' "
            f"title='Pedir unirte al seguimiento de esta nota'>"
            "+ unirse</button></form>")
    # solicitudes pendientes a nivel NOTA: las resuelve el autor o sup
    for x in sols_vivas:
        if x.get("de") == email:
            continue
        # solo las guardadas en la nota (no las del evento, esas van
        # en la columna de bitácora)
        if not any(y is x for y in (p.get("solicitudes") or [])):
            continue
        if not (sup or email == p.get("usuario")):
            continue
        secundario.append(
            f"<div style='font-size:.72rem;margin-top:.3rem'>"
            f"✋ {html.escape(_red_nombre(x.get('de','')))} pide unirse "
            f"al seguimiento "
            f"<form method='post' action='/redaccion/resolver' "
            f"style='display:inline'><input type='hidden' name='id' "
            f"value='{p.get('id')}'>" f"<input type='hidden' name='volver' value='{ret}'>"
            f"<input type='hidden' name='de' "
            f"value='{html.escape(x.get('de',''), quote=True)}'>"
            f"<input type='hidden' name='op' value='aceptar'>"
            f"<button class='rb' style='font-size:.62rem;padding:2px 8px'>"
            f"✓ aceptar</button></form>"
            f"<form method='post' action='/redaccion/resolver' "
            f"style='display:inline'><input type='hidden' name='id' "
            f"value='{p.get('id')}'>" f"<input type='hidden' name='volver' value='{ret}'>"
            f"<input type='hidden' name='de' "
            f"value='{html.escape(x.get('de',''), quote=True)}'>"
            f"<input type='hidden' name='op' value='rechazar'>"
            f"<button class='rb' style='font-size:.62rem;padding:2px 8px'>"
            f"✗</button></form></div>")

    sec = "".join(secundario)
    return (f"<div class='red-post' id='p-{p.get('id')}'{drag_attr}"
            f" style='"
            f"background:rgba(255,255,255,.05);border:1px solid #2c3a72;"
            f"border-radius:10px;padding:.55rem .65rem;"
            f"margin-bottom:.55rem'>"
            f"<div class='meta' style='font-size:.68rem'>{meta}"
            f"{sel_box}</div>{asig_h}"
            f"<div style='font-size:.85rem;margin-top:.25rem'>{cuerpo}"
            f"</div>{ver_mas}{media_h}{loc_h}"
            f"<div class='red-act'>{''.join(acciones)}</div>"
            + (f"<div class='red-sub'>{sec}</div>" if sec else "")
            + "</div>")


_RED_CSS = """
<style>
/* desktop: deck horizontal — las áreas son columnas de alto fijo;
   la página NO scrollea vertical, cada columna scrollea sus posts
   por dentro (estilo TweetDeck). Las columnas se reordenan arrastrando */
.red-board{display:flex;gap:14px;overflow-x:auto;align-items:stretch;
  height:calc(100vh - 185px);padding-bottom:6px;scrollbar-width:thin;
  scrollbar-color:#2c3a72 transparent}
.red-board::-webkit-scrollbar{height:6px}
.red-board::-webkit-scrollbar-thumb{background:#2c3a72;
  border-radius:3px}
/* barra de desplazamiento horizontal propia, encima de los
   encabezados — sincronizada con el scroll del board */
.red-xbar{position:relative;height:10px;margin:2px 2px 8px;
  border-radius:6px;background:rgba(255,255,255,.05);
  border:1px solid #2c3a72;cursor:pointer;flex:none}
.red-xbar .red-xthumb{position:absolute;top:1px;bottom:1px;left:0;
  min-width:26px;border-radius:4px;
  background:linear-gradient(90deg,#3949ab,#7c4dff);
  box-shadow:0 0 8px #7c4dff66;touch-action:none}
.red-xbar .red-xthumb:active{background:linear-gradient(90deg,
  #5c6bc0,#9d7bff)}
.red-col{background:rgba(15,20,52,.72);border:1px solid #2c3a72;
  border-radius:12px;padding:10px;min-width:0;flex:0 0 340px;
  display:flex;flex-direction:column;height:100%;
  backdrop-filter:blur(10px);box-shadow:0 6px 24px #0006}
.red-col.drag{opacity:.4}
/* encabezado de columna = banda con peso propio, no solo texto:
   más alto, letra mayor, fondo con gradiente y borde */
.red-col h2{font-size:1.05rem;font-weight:700;letter-spacing:.02em;
  margin:.15rem 0 .7rem;padding:.55rem .65rem;flex:none;color:#fff;
  display:flex;align-items:center;gap:.5rem;cursor:pointer;
  user-select:none;border-radius:9px;border:1px solid #3a4a80;
  background:linear-gradient(180deg,rgba(120,140,255,.18),
  rgba(120,140,255,.06));
  box-shadow:inset 0 1px 0 rgba(255,255,255,.09)}
.red-col h2::before{content:'⠿';color:#4a5a9e;font-size:.9rem}
.red-col h2::after{content:'◂';color:#8a93b8;font-size:.75rem;
  transition:transform .15s}
.red-col h2 .head-right{margin-left:auto;display:inline-flex;
  align-items:center;gap:.4rem}
.red-col h2 .area-ico{display:inline-flex;align-items:center;
  color:#9aa3c7}
.red-col.closed .posts{display:none}
/* al plegar, solo queda el h2 (lomo vertical en escritorio) — también
   cubre bloques extra como en bitácora (subtítulo, equipo, form) */
.red-col.closed>*:not(h2){display:none}
.red-col .posts{flex:1;overflow-y:auto;min-height:0}
.red-col .posts::-webkit-scrollbar{width:8px}
.red-col .posts::-webkit-scrollbar-thumb{background:#2c3a72;
  border-radius:4px}
.red-tabs{display:flex;gap:.4rem;margin:.4rem 0 .8rem;flex-wrap:wrap}
.red-tabs a{font-size:.75rem;padding:3px 10px;border-radius:12px;
  border:1px solid #33415f;text-decoration:none;color:#aeb8e8;
  background:rgba(255,255,255,.04)}
.red-tabs a.on{background:#3949ab;color:#fff;border-color:#5c6bc0}
.red-form{background:rgba(15,20,52,.72);border:1px solid #2c3a72;
  border-radius:12px;padding:.8rem;margin-bottom:1rem;max-width:640px}
.red-form input[type=text],.red-form textarea,.red-form select{
  width:100%;box-sizing:border-box;font-size:.85rem;padding:.4rem;
  border:1px solid #33415f;border-radius:8px;margin:.25rem 0;
  background:#0d1330;color:#eef1ff}
.red-form textarea{min-height:90px;resize:vertical}
/* feeds de una sola columna (/area): línea de lectura cómoda */
.red-post{max-width:720px;position:relative}
/* botones de acción de redacción */
.rb{display:inline-flex;align-items:center;justify-content:center;
  gap:5px;font-size:.76rem;padding:0 12px;height:29px;
  border-radius:15px;border:1px solid #3a4a80;
  background:rgba(255,255,255,.06);color:#cfd6ff;
  cursor:pointer;line-height:1;font-family:inherit;white-space:nowrap;
  text-decoration:none;vertical-align:middle;box-sizing:border-box;
  backdrop-filter:blur(6px)}
.rb:hover{border-color:#7c4dff;color:#fff;background:rgba(124,77,255,.18);
  text-decoration:none;box-shadow:0 0 12px #7c4dff44}
.rb.on{background:#3949ab;border-color:#7c4dff;color:#fff}
.rb:disabled{opacity:.45;cursor:default}
.rb:disabled:hover{border-color:#3a4a80;color:#cfd6ff;
  background:rgba(255,255,255,.06);box-shadow:none}
.rb svg{display:block;flex:none}
.rb-n{background:#b03a2e;color:#fff;border-radius:8px;padding:0 5px;
  font-size:.62rem;font-weight:700;margin-left:2px;line-height:1.5}
/* barra de acciones del tablero — botones grandes con presencia;
   .rtb.acc marca la acción principal (asignar) */
.red-bar{display:flex;gap:.45rem;align-items:center;flex-wrap:wrap;
  margin:.15rem 0 .8rem}
.rtb{display:inline-flex;align-items:center;justify-content:center;
  gap:6px;height:34px;padding:0 16px;font-size:.82rem;font-weight:600;
  letter-spacing:.01em;border-radius:10px;border:1px solid #4a5aa0;
  background:linear-gradient(180deg,rgba(120,140,255,.16),
  rgba(120,140,255,.05));color:#e6eaff;cursor:pointer;line-height:1;
  font-family:inherit;white-space:nowrap;text-decoration:none;
  box-sizing:border-box;transition:border-color .15s,box-shadow .15s,
  background .15s;
  box-shadow:inset 0 1px 0 rgba(255,255,255,.08),0 2px 8px rgba(0,0,0,.3)}
.rtb:hover{border-color:#8f6bff;color:#fff;
  background:linear-gradient(180deg,rgba(124,77,255,.32),
  rgba(124,77,255,.14));box-shadow:0 0 14px #7c4dff66;
  text-decoration:none}
.rtb:disabled{opacity:.4;cursor:default}
.rtb:disabled:hover{border-color:#4a5aa0;color:#e6eaff;
  background:linear-gradient(180deg,rgba(120,140,255,.16),
  rgba(120,140,255,.05));
  box-shadow:inset 0 1px 0 rgba(255,255,255,.08),0 2px 8px rgba(0,0,0,.3)}
.rtb.acc{background:linear-gradient(180deg,#5e35d8,#4527a0);
  border-color:#8f6bff;color:#fff}
.rtb.acc:hover{background:linear-gradient(180deg,#6d46e8,#512da8);
  border-color:#8f6bff;color:#fff;box-shadow:0 0 16px #7c4dff88}
.red-selpill{display:none;align-items:center;height:26px;padding:0 10px;
  border-radius:13px;background:#3949ab;color:#fff;font-size:.72rem;
  font-weight:700;letter-spacing:.02em}
.rb-det{display:inline-block}
.rb-det>summary{list-style:none}
.rb-det>summary::-webkit-details-marker{display:none}
.rb-form{display:flex;gap:.35rem;margin-top:.45rem;flex-wrap:wrap;
  align-items:center}
.rb-form select,.rb-form input{font-size:.75rem;padding:4px 6px;
  border:1px solid #33415f;border-radius:8px;font-family:inherit;
  background:#0d1330;color:#eef1ff}
.rb-form input[name=nota]{width:130px}
/* barra de acciones de la tarjeta: primaria en fila, detalles abajo */
.red-act{display:flex;gap:.35rem;flex-wrap:wrap;align-items:center;
  margin-top:.45rem}
.red-act form{display:inline-flex;margin:0}
.red-act .rb-det{margin:0}
/* "ver más" junto al texto — expande la cuartilla en la tarjeta */
.red-mas{margin:.2rem 0 .35rem}
.red-mas>summary{list-style:none;cursor:pointer;font-size:.75rem;
  color:#8ab4ff;display:inline-flex;align-items:center;gap:.3rem;
  user-select:none}
.red-mas>summary::-webkit-details-marker{display:none}
.red-mas>summary::after{content:'▾';font-size:.6rem;
  transition:transform .15s}
.red-mas[open]>summary::after{transform:rotate(180deg)}
.red-mas .red-leido{margin-top:.45rem;font-size:.8rem;line-height:1.6;
  color:#c6cdea;background:rgba(255,255,255,.04);
  border:1px solid #2c3a72;border-radius:10px;padding:.6rem .8rem}
.red-mas .red-leido p{margin:0 0 .7em}
/* selección del tablero + menú asignar en lote (supervisión) */
.red-sel{float:right;margin:1px 0 0 .4rem;accent-color:#7c8cf8;
  cursor:pointer}
#red-asig{position:relative;vertical-align:middle}
#red-asig>summary{height:34px;box-sizing:border-box}
.red-asig-menu{position:absolute;top:calc(100% + 6px);left:0;z-index:40;
  min-width:300px;background:rgba(13,18,48,.97);
  border:1px solid #3a4a80;border-radius:10px;padding:.6rem;
  display:flex;flex-direction:column;gap:.45rem;text-align:left;
  box-shadow:0 10px 30px #000a;backdrop-filter:blur(8px);
  cursor:default;text-transform:none}
.red-asig-menu form{display:flex;flex-direction:column;gap:.45rem;
  margin:0}
.red-asig-us{max-height:180px;overflow-y:auto;display:flex;
  flex-direction:column;gap:.2rem;padding-right:.3rem}
.red-asig-u{display:flex;gap:.4rem;align-items:baseline;
  font-size:.78rem;font-weight:400;cursor:pointer}
/* columna ★ favoritos + arrastre de tarjetas (usuarios reales) */
.red-favcol h2 .red-nom{color:#f6c344}
.red-favcol.drop-ok{outline:2px dashed #f6c344;outline-offset:2px;
  border-radius:8px}
.red-post.drag-card{opacity:.45}
.red-post[draggable=true]{cursor:grab}
.red-star.on{color:#f6c344}
.red-sub{margin-top:.35rem}
.red-sub .rb{font-size:.7rem;height:24px;padding:0 10px}
/* bloque de asignaciones al tope de la tarjeta */
.red-asign{margin:.45rem 0 .15rem;padding:.4rem .55rem .25rem;
  border-left:3px solid #7c4dff;border-radius:0 8px 8px 0;
  background:rgba(124,77,255,.09)}
.red-asign-f{font-size:.72rem;margin:.1rem 0 .3rem;
  display:flex;align-items:center;gap:.3rem;flex-wrap:wrap}
.red-asign-f .rb{font-size:.8rem;height:20px;padding:0 5px;
  border-radius:10px}
/* píldora flotante "N nuevas" — aparece sola cuando el polling
   detecta publicaciones recientes; entra con un slide-up suave */
.red-pill{position:fixed;bottom:1.2rem;left:50%;z-index:60;
  transform:translateX(-50%);display:inline-flex;align-items:center;
  gap:.45rem;padding:.65rem 1.4rem;border-radius:24px;
  background:linear-gradient(135deg,#1a237e 0%,#3949ab 55%,#7c4dff 100%);
  color:#fff;text-decoration:none;font-size:.85rem;font-weight:600;
  box-shadow:0 8px 24px rgba(26,35,126,.4),0 0 0 1px #ffffff22 inset;
  animation:redpill .45s cubic-bezier(.2,.9,.3,1.2)}
.red-pill::before{content:'✦';color:#ffd54f;font-size:.95rem}
@keyframes redpill{from{opacity:0;transform:translate(-50%,14px) scale(.9)}
  to{opacity:1;transform:translate(-50%,0) scale(1)}}
@media (min-width:761px){
  /* columna colapsada = tile angosta vertical; las abiertas absorben
     el ancho (flex-basis 340px vs 54px) y quedan agrupadas a la izq. */
  .red-col{position:relative;transition:flex-basis .2s,padding .2s}
  .red-col h2::before{order:-2}
  .red-col h2::after{order:-1}
  .red-col.closed{flex:0 0 56px;padding:12px 5px;align-items:center}
  /* tile plegada: columna explícita — icono, contador, badge y el
     nombre en vertical ocupando el resto de la altura (lomo) */
  .red-col.closed h2{display:flex;flex-direction:column;
    align-items:center;justify-content:flex-start;height:100%;
    margin:0;font-size:.78rem;gap:.3rem}
  .red-col.closed h2::before,.red-col.closed h2::after{content:''}
  /* display:contents desarma el wrapper → cada pieza es ítem de la
     columna: contador+badge arriba, luego icono, luego nombre */
  .red-col.closed h2 .head-right{display:contents;margin:0}
  .red-col.closed .red-n{order:-4;display:inline;font-weight:700;
    color:#7cc4ff;font-size:.9rem}
  .red-col.closed .red-nuevas{order:-3;position:static;font-size:0}
  .red-col.closed .red-nuevas::before{content:'';display:block;
    width:9px;height:9px;border-radius:50%;background:#b03a2e}
  .red-col.closed .area-ico{order:-2;margin-left:0;color:#9aa3c7}
  .red-col.closed .red-nom{order:0;writing-mode:vertical-rl;
    transform:rotate(180deg);display:flex;align-items:center;
    color:#dfe4ff;overflow-wrap:anywhere}
  .red-col.closed:hover{background:rgba(58,73,171,.35)}
}
@media (max-width:760px){
  /* móvil: acordeón vertical — cada medio es una tarjeta cerrada;
     al tocar el encabezado se despliega su info (dropdown) */
  .red-xbar{display:none}
  /* overflow:visible — el overflow-x:auto de escritorio convierte al
     board en scroll container y rompe el sticky del h2 de columna */
  .red-board{display:block;height:auto;overflow:visible}
  .red-col{display:block;height:auto;flex:none;margin-bottom:10px;
    background:rgba(15,20,52,.72);border-color:#2c3a72}
  .red-col .posts{display:none;overflow:visible;flex:none}
  .red-col.open .posts{display:block}
  .red-col h2{color:#eef1ff;cursor:pointer;user-select:none;
    /* encabezado sticky: al bajar por las notas de la columna, el
       título del medio queda fijo bajo el nav para poder plegarla */
    position:sticky;top:var(--navh,0px);z-index:6;
    margin:-10px -10px .6rem;padding:12px 10px;
    background:rgba(15,20,52,.94);backdrop-filter:blur(10px);
    border-bottom:1px solid #2c3a72;border-radius:12px 12px 0 0}
  .red-col h2::before{content:''}
  .red-col h2::after{content:'▸';float:right;color:#8a93b8;
    transition:transform .15s}
  .red-col.open h2::after{content:'▾'}
  html.tema-claro .red-col h2{background:#f4f4f6}
  main.wide{padding:.6rem .5rem}
}
/* tema claro — mismas piezas en look clásico */
html.tema-claro .red-col{background:#f4f4f6;border-color:#e2e2e8;
  box-shadow:none;backdrop-filter:none}
html.tema-claro .red-col h2{color:#1a237e;
  background:linear-gradient(180deg,#fff,#e8ecf8);
  border-color:#c5cbe8;box-shadow:none}
html.tema-claro .red-col h2::before{color:#bbb}
html.tema-claro .red-col h2::after{color:#999}
html.tema-claro .red-col h2 .area-ico{color:#5a5a6e}
html.tema-claro .red-tabs a{background:#fff;border-color:#ccc;
  color:#444}
html.tema-claro .red-tabs a.on{background:#1a237e;color:#fff;
  border-color:#1a237e}
html.tema-claro .red-form{background:#f4f4f6;border-color:#e2e2e8}
html.tema-claro .red-form input[type=text],
html.tema-claro .red-form textarea,html.tema-claro .red-form select{
  background:#fff;color:#222;border-color:#ccc}
html.tema-claro .rb{background:#fff;border-color:#d0d0dc;color:#444;
  backdrop-filter:none}
html.tema-claro .rb:hover{border-color:#1a237e;color:#1a237e;
  background:#fff;box-shadow:none}
html.tema-claro .rb.on{background:#1a237e;border-color:#1a237e;
  color:#fff}
html.tema-claro .rtb{background:linear-gradient(180deg,#fff,#eceff8);
  border-color:#b8bedd;color:#333;
  box-shadow:inset 0 1px 0 #fff,0 1px 4px rgba(0,0,0,.12)}
html.tema-claro .rtb:hover{border-color:#1a237e;color:#1a237e;
  background:linear-gradient(180deg,#fff,#e3e7f6);box-shadow:none}
html.tema-claro .rtb.acc{background:linear-gradient(180deg,#3949ab,#283593);
  border-color:#3949ab;color:#fff}
html.tema-claro .rtb.acc:hover{background:#303f9f;color:#fff}
html.tema-claro .red-selpill{background:#1a237e}
html.tema-claro .rb-form select,html.tema-claro .rb-form input{
  background:#fff;color:#222;border-color:#ccc}
html.tema-claro .red-asig-menu{background:#fff;border-color:#d0d0dc;
  box-shadow:0 10px 30px rgba(0,0,0,.15)}
html.tema-claro .red-mas>summary{color:#5c6bc0}
html.tema-claro .red-mas .red-leido{background:#fafafa;
  border-color:#e2e2e8;color:#444}
html.tema-claro .red-post{background:#fff !important;
  border-color:#eee !important}
html.tema-claro .red-col.closed .red-n{color:#1a237e}
html.tema-claro .red-col.closed .red-nom{color:#333}
html.tema-claro .red-col.closed:hover{background:#e9e9f0}
html.tema-claro .red-col.closed .area-ico{color:#777}
html.tema-claro .red-pill{box-shadow:0 8px 24px rgba(26,35,126,.3)}
html.tema-claro .red-xbar{background:#ececf2;border-color:#d0d0dc}
html.tema-claro .red-xbar .red-xthumb{
  background:linear-gradient(90deg,#3949ab,#7c4dff)}
/* vista de nota — artículo completo */
.nota-kicker{display:flex;align-items:center;gap:.4rem;
  font-size:.68rem;font-weight:700;letter-spacing:.12em;
  text-transform:uppercase;color:#8a93b8}
.nota-kicker .area-ico, .nota-kicker svg{color:#7c4dff}
.nota-titulo{font-size:1.45rem;line-height:1.25;margin:.5rem 0 .4rem;
  color:#eef1ff;font-weight:800}
.nota-resumen{font-size:.95rem;line-height:1.6;color:#b9c2ea;
  border-left:3px solid #7c4dff;padding:.15rem 0 .15rem .8rem;
  margin:.4rem 0 .8rem;font-style:italic}
.nota-meta{display:flex;flex-wrap:wrap;gap:.3rem .9rem;align-items:center;
  font-size:.75rem;color:#9aa3c7;border-top:1px solid #2c3a72;
  border-bottom:1px solid #2c3a72;padding:.5rem 0;margin-bottom:.9rem}
.nota-meta a{color:#8ab4ff}
.nota-cuerpo{font-size:.92rem;line-height:1.7;color:#dfe4ff}
.nota-cuerpo p{margin:0 0 .95em}
/* tarjeta del deck: titular + resumen de 2 líneas */
.red-tit{font-weight:700;font-size:.85rem;line-height:1.3;
  color:#eef1ff;margin-top:.2rem}
.red-snip{font-size:.78rem;line-height:1.45;color:#9aa3c7;margin-top:.15rem;
  display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;
  overflow:hidden}
/* tira de miniaturas: una sola fila con scroll — la tarjeta no
   crece aunque la nota tenga 10 fotos */
.media-strip{display:flex;gap:.35rem;overflow-x:auto;
  padding:.35rem 0 .15rem;margin:.3rem 0 0;scrollbar-width:none;
  cursor:grab;user-select:none}
.media-strip::-webkit-scrollbar{display:none}
.media-strip a{flex:none;display:block}
.media-strip.dragging{cursor:grabbing}
.media-strip.dragging a{pointer-events:none}
.nota-rel-t{font-size:.8rem;margin:1.2rem 0 .4rem;color:#8a93b8;
  letter-spacing:.05em;text-transform:uppercase}
.rel-nota{display:flex;flex-direction:column;gap:.15rem;
  padding:.55rem .7rem;margin:.3rem 0;border-radius:10px;
  border:1px solid #2c3a72;background:rgba(255,255,255,.04);
  text-decoration:none;transition:border-color .15s}
.rel-nota:hover{border-color:#7c4dff}
.rel-t{font-size:.82rem;color:#dfe4ff;font-weight:600;line-height:1.35}
.rel-m{font-size:.68rem;color:#8a93b8;display:flex;align-items:center;
  gap:.3rem}
/* comentarios del equipo en la nota */
.com-item{border:1px solid #2c3a72;border-radius:10px;
  padding:.5rem .7rem;margin:.4rem 0;background:rgba(255,255,255,.03)}
.com-head{display:flex;gap:.5rem;align-items:baseline}
.com-head b{font-size:.78rem;color:#cfd6ff}
.com-head .meta{font-size:.65rem}
.com-txt{font-size:.82rem;color:#dfe4ff;margin-top:.2rem;
  white-space:pre-wrap;line-height:1.5}
html.tema-claro .com-item{border-color:#e2e2e8;background:#fafafa}
html.tema-claro .com-head b{color:#333}
html.tema-claro .com-txt{color:#444}
html.tema-claro .nota-kicker{color:#777}
html.tema-claro .nota-kicker svg{color:#5c6bc0}
html.tema-claro .nota-titulo{color:#1a237e}
html.tema-claro .nota-resumen{color:#444;border-left-color:#5c6bc0}
html.tema-claro .nota-meta{color:#666;border-color:#e2e2e8}
html.tema-claro .nota-meta a{color:#1a237e}
html.tema-claro .nota-cuerpo{color:#333}
html.tema-claro .red-tit{color:#1a237e}
html.tema-claro .red-snip{color:#666}
html.tema-claro .nota-rel-t{color:#999}
html.tema-claro .rel-nota{border-color:#e2e2e8;background:#fafafa}
html.tema-claro .rel-nota:hover{border-color:#5c6bc0}
html.tema-claro .rel-t{color:#1a237e}
html.tema-claro .rel-m{color:#888}
/* asistente IA */
.asis-log{display:flex;flex-direction:column;gap:.55rem;
  max-width:780px;margin-bottom:.8rem}
.asis-msg{max-width:85%;padding:.6rem .8rem;border-radius:12px;
  font-size:.85rem;line-height:1.55}
.asis-q{align-self:flex-end;background:#3949ab;color:#fff;
  border-bottom-right-radius:4px}
.asis-a{align-self:flex-start;background:rgba(255,255,255,.06);
  border:1px solid #2c3a72;color:#dfe4ff;
  border-bottom-left-radius:4px;backdrop-filter:blur(6px)}
.asis-quien{font-size:.62rem;font-weight:700;letter-spacing:.08em;
  text-transform:uppercase;color:#8a93b8;margin-bottom:.2rem}
.asis-sugs{display:flex;gap:.4rem;flex-wrap:wrap}
/* estrellita IA en la meta de la tarjeta */
.rb-ia{display:inline-flex;align-items:center;justify-content:center;
  width:16px;height:16px;border-radius:50%;margin-left:.35rem;
  color:#ffd54f;font-size:.72rem;text-decoration:none;
  border:1px solid #ffd54f55;vertical-align:middle}
.rb-ia:hover{background:#ffd54f22;box-shadow:0 0 8px #ffd54f66;
  text-decoration:none}
html.tema-claro .asis-q{background:#5c6bc0}
html.tema-claro .asis-a{background:#fff;border-color:#e2e2e8;
  color:#333}
</style>"""


_RED_XBAR_JS = """<script>
/* scrollbar horizontal superior sincronizada con .red-board:
   el thumb se puede arrastrar y el board scrollea (y viceversa) */
(function(){
var bar=document.querySelector('.red-xbar');
var board=document.querySelector('.red-board');
if(!bar||!board)return;
var th=bar.querySelector('.red-xthumb');
function layout(){
  var sw=board.scrollWidth,cw=board.clientWidth;
  if(sw<=cw){bar.style.display='none';return}
  bar.style.display='block';
  var tw=Math.max(26,cw/sw*cw),mx=cw-tw;
  th.style.width=tw+'px';
  th.style.left=(board.scrollLeft/Math.max(1,sw-cw)*mx)+'px';}
board.addEventListener('scroll',layout);
window.addEventListener('resize',layout);
layout();
var drag=false,sx=0,sl=0;
th.addEventListener('pointerdown',function(e){
  drag=true;sx=e.clientX;sl=board.scrollLeft;
  th.setPointerCapture(e.pointerId);e.preventDefault();});
th.addEventListener('pointermove',function(e){
  if(!drag)return;
  var sw=board.scrollWidth,cw=board.clientWidth,mx=cw-th.offsetWidth;
  if(mx<=0)return;
  board.scrollLeft=sl+(e.clientX-sx)/mx*(sw-cw);});
th.addEventListener('pointerup',function(){drag=false});
th.addEventListener('pointercancel',function(){drag=false});
})();
</script>"""


def _board_wrap(cols_html: str) -> str:
    """Envoltura del deck: barra de scroll superior + board + JS
    de sincronización. La usan Redacción y Bitácora."""
    return ("<div class='red-xbar'><div class='red-xthumb'></div></div>"
            f"<div class='red-board'>{cols_html}</div>"
            + _RED_XBAR_JS)


def vista_redaccion(email: str) -> str:
    """Vista supervisor: una columna por área, cronológico descendente,
    scroll horizontal en desktop. Cada tarjeta muestra cuántas
    publicaciones son nuevas desde la última visita del usuario."""
    cfg = json.loads(CONFIG.read_text())
    areas = areas_redaccion(cfg)
    if not areas:
        return ("<h1>Redacción</h1><p class='meta'>Sin áreas "
                "configuradas — agrega <code>redaccion.areas</code> en "
                "config.json (id, nombre, miembros).</p>")
    visto = ((cargar_usuarios().get(email) or {})
             .get("visto_redaccion", ""))
    # orden de columnas personalizado por usuario (drag & drop)
    orden = ((cargar_usuarios().get(email) or {})
             .get("red_orden") or [])
    colapsadas = set(((cargar_usuarios().get(email) or {})
                      .get("red_colapsadas") or []))
    areas = sorted(
        areas, key=lambda a: orden.index(a.get("id"))
        if a.get("id") in orden else 999)
    posts = cargar_publicaciones()
    nuevas_total = 0
    cols = []
    for a in areas:
        ps = [p for p in posts if p.get("area") == a.get("id")][:80]
        nuevas = sum(1 for p in ps if p.get("ts", "") > visto)
        nuevas_total += nuevas
        badge = (f" <span class='meta red-nuevas' style='color:#b03a2e;"
                 f"font-weight:700'>● {nuevas} nueva"
                 f"{'s' if nuevas != 1 else ''}</span>" if nuevas else "")
        cards = "".join(_pub_card(p, email, cfg, ret='/redaccion') for p in ps) \
            or "<p class='meta'>sin publicaciones</p>"
        cls = "red-col closed" if a.get("id") in colapsadas \
            else "red-col"
        cols.append(
            f"<div class='{cls}' data-area='{html.escape(a.get('id',''), quote=True)}'>"
            f"<h2><span class='red-nom'>"
            f"{html.escape(a.get('nombre',''))}</span>"
            f" <span class='meta red-n' style='font-weight:400'>"
            f"{len(ps)}</span>"
            f"<span class='head-right'>{badge}"
            f"<span class='area-ico'>"
            f"{_area_icono(a.get('id'), 14)}</span></span></h2>"
            f"<div class='posts'>{cards}</div></div>")
    ultimo = posts[0].get("ts", "") if posts else ""
    sup = es_supervisor(email, cfg)
    es_demo = "@demo.local" in (email or "")
    # ── columna ★ Favoritos — personal por usuario real: cada quien
    # arrastra tarjetas de cualquier medio a la suya; es la ÚNICA
    # columna que acepta drops. Invitados demo no la tienen ──
    if not es_demo:
        fav_posts = [p for p in posts
                     if email in (p.get("favoritos") or [])][:80]
        fav_cards = "".join(
            _pub_card(p, email, cfg, ret='/redaccion')
            for p in fav_posts) or (
            "<p class='meta red-fav-empty'>arrastra notas aquí "
            "o usa la ☆ de cada tarjeta</p>")
        fav_col = (
            "<div class='red-col red-favcol' data-area='favoritos'>"
            "<h2><span class='red-nom'>★ Favoritos</span>"
            f" <span class='meta red-n' style='font-weight:400'>"
            f"{len(fav_posts)}</span></h2>"
            f"<div class='posts'>{fav_cards}</div></div>")
        if "favoritos" in orden:
            fpos = orden.index("favoritos")
            ins = sum(1 for a in areas
                      if a.get("id") in orden
                      and orden.index(a["id"]) < fpos)
        else:
            ins = 0
        cols.insert(min(ins, len(cols)), fav_col)
    # barra de acciones del tablero: selección múltiple → compartir
    # (copia enlaces al portapapeles) / asignar (N notas × M
    # colaboradores × evento opcional, creable al vuelo)
    sel_bar = ""
    if not es_demo:
        sel_bar += ("<span class='red-selpill' id='red-sel'></span>"
                    "<button class='rtb' id='red-copy' disabled "
                    "title='Copiar los enlaces de las notas "
                    "seleccionadas'>⧉ compartir</button>")
    if sup:
        checks = "".join(
            f"<label class='red-asig-u'><input type='checkbox' "
            f"name='para' value='{html.escape(e, quote=True)}'> "
            f"{html.escape(n)} <span class='meta'>"
            f"({html.escape(e)})</span></label>"
            for e, n in _usuarios_reales())
        ops_ev = "".join(
            f"<option value='{html.escape(s.get('id'), quote=True)}'>"
            f"{html.escape(s.get('nombre', ''))}</option>"
            for s in cargar_seguimientos())
        sel_bar += (
            "<details class='rb-det' id='red-asig'>"
            "<summary class='rtb acc' title='Asignar las notas "
            "seleccionadas a colaboradores'>➤ asignar "
            "<span id='red-asig-n' class='rb-n'></span></summary>"
            "<div class='red-asig-menu'>"
            "<form method='post' action='/redaccion/asignar' "
            "id='red-asig-form'>"
            "<input type='hidden' name='volver' value='/redaccion'>"
            "<div id='red-asig-ids'></div>"
            "<div class='red-asig-us'>" + checks + "</div>"
            "<button type='button' class='rb' id='red-asig-todos' "
            "style='font-size:.62rem;align-self:flex-start'>"
            "seleccionar / quitar todos</button>"
            "<input name='nota' placeholder='nota para los asignados'>"
            "<select name='evento' title='Evento / seguimiento'>"
            "<option value=''>sin evento</option>" + ops_ev +
            "<option value='__nuevo__'>+ nuevo evento…</option>"
            "</select>"
            "<input name='evento_nuevo' "
            "placeholder='nombre del evento nuevo' "
            "style='display:none'>"
            "<button class='rb'>asignar</button></form></div>"
            "</details>"
            "<a class='rtb' href='/bitacora' "
            "title='Eventos / seguimientos'>≡ eventos</a>")
    return (_RED_CSS +
            f"<div class='meta' style='margin:.2rem 0 .7rem;font-size:.82rem'>"
            f"{len(areas)} medios · {len(posts)} publicaciones · "
            f"{nuevas_total} nuevas desde tu última visita · última "
            f"{fmt_fecha(ultimo) if ultimo else '—'} · arrastra ⠿ para "
            f"reordenar</div>"
            "<div class='red-bar'>"
            "<button class='rtb' id='red-tgl'>⇕ plegar todo</button>"
            "<button class='rtb' id='red-inicio' "
            "title='Volver al inicio — columnas a la izquierda y "
            "publicaciones arriba'>↺ inicio</button>"
            + sel_bar + "</div>"
            + _board_wrap("".join(cols))
            + "<script>"
            "var _drag=null;"
            "if(matchMedia('(pointer:fine)').matches){"
            "document.querySelectorAll('.red-col').forEach("
            "function(c){c.setAttribute('draggable','true');"
            "c.addEventListener('dragstart',function(e){"
            "_drag=c;c.classList.add('drag');"
            "e.dataTransfer.effectAllowed='move'});"
            "c.addEventListener('dragend',function(){"
            "c.classList.remove('drag');_guardarOrden()});"
            "c.addEventListener('dragover',function(e){"
            "if(!_drag)return;"
            "e.preventDefault();"
            "var r=this.getBoundingClientRect();"
            "board.insertBefore(_drag,(e.clientX-r.left)>r.width/2?"
            "this.nextSibling:this)});});}"
            "var board=document.querySelector('.red-board');"
            "function _guardarOrden(){"
            "if(!board)return;"
            "var ids=[...board.querySelectorAll('.red-col')]"
            ".map(function(c){return c.dataset.area});"
            "fetch('/redaccion/orden',{method:'POST',"
            "headers:{'Content-Type':'application/x-www-form-urlencoded'},"
            "body:'orden='+ids.join(',')});}"
            "function _guardarColapsadas(){"
            "var ids=[...document.querySelectorAll('.red-col.closed')]"
            ".map(function(c){return c.dataset.area});"
            "fetch('/redaccion/colapsar',{method:'POST',"
            "headers:{'Content-Type':'application/x-www-form-urlencoded'},"
            "body:'cols='+ids.join(',')});}"
            "var _tgl=document.getElementById('red-tgl');"
            "function _syncTgl(){if(!_tgl)return;"
            "var abiertas=document.querySelectorAll("
            "'.red-col:not(.closed)').length;"
            "_tgl.textContent=abiertas?'⇕ plegar todo':'⇕ expandir todo'}"
            "if(_tgl)_tgl.addEventListener('click',function(){"
            "var cerrar=document.querySelectorAll("
            "'.red-col:not(.closed)').length>0;"
            "document.querySelectorAll('.red-col').forEach("
            "function(c){if(matchMedia('(max-width:760px)').matches){"
            "c.classList.toggle('open',!cerrar)}"
            "else{c.classList.toggle('closed',cerrar)}});"
            "_guardarColapsadas();_syncTgl();});"
            "_syncTgl();"
            "var _ini=document.getElementById('red-inicio');"
            "if(_ini)_ini.addEventListener('click',function(){"
            "if(board)board.scrollLeft=0;"
            "document.querySelectorAll('.red-col .posts')"
            ".forEach(function(s){s.scrollTop=0});"
            "window.scrollTo(0,0)});"
            "document.querySelectorAll('.red-col').forEach("
            "function(c){var h=c.querySelector('h2');if(!h)return;"
            "h.addEventListener('click',function(){"
            "if(matchMedia('(max-width:760px)').matches){"
            "c.classList.toggle('open')}"
            "else{c.classList.toggle('closed');_guardarColapsadas()}});});"
            # selección múltiple: checkbox por tarjeta → compartir
            # (copiar enlaces) y asignar en lote
            "function _selIds(){return [].slice.call("
            "document.querySelectorAll('.red-sel:checked'))"
            ".map(function(c){return c.value})}"
            "function _syncSel(){var n=_selIds().length;"
            "var b=document.getElementById('red-sel');"
            "if(b){b.textContent=n?'☑ '+n+' seleccionada'"
            "+(n>1?'s':''):'';"
            "b.style.display=n?'inline-flex':'none'}"
            "var cp=document.getElementById('red-copy');"
            "if(cp)cp.disabled=!n;}"
            "document.addEventListener('change',function(e){"
            "var t=e.target;if(!t||!t.classList)return;"
            "if(t.classList.contains('red-sel'))_syncSel();"
            "if(t.name=='para'&&t.closest('#red-asig-form')){"
            "var n=t.closest('form').querySelectorAll("
            "'input[name=para]:checked').length;"
            "var bn=document.getElementById('red-asig-n');"
            "if(bn)bn.textContent=n?'· '+n:'';}});"
            "var _cp=document.getElementById('red-copy');"
            "if(_cp)_cp.addEventListener('click',function(){"
            "var ids=_selIds();if(!ids.length)return;"
            "navigator.clipboard.writeText(ids.map(function(i){"
            "return location.origin+'/redaccion/nota?id='+i})"
            ".join('\\n'));"
            "var b=this;"
            "b.textContent='✓ '+ids.length+' enlace'"
            "+(ids.length>1?'s':'');"
            "setTimeout(function(){b.textContent='⧉ compartir'},"
            "1600);});"
            "var _af=document.getElementById('red-asig-form');"
            "if(_af){_af.addEventListener('submit',function(e){"
            "var ids=_selIds();"
            "if(!ids.length){e.preventDefault();return}"
            "var box=document.getElementById('red-asig-ids');"
            "box.innerHTML='';"
            "ids.forEach(function(i){var h=document.createElement"
            "('input');h.type='hidden';h.name='id';h.value=i;"
            "box.appendChild(h)});});"
            "var _tb=document.getElementById('red-asig-todos');"
            "if(_tb)_tb.addEventListener('click',function(){"
            "var cs=_af.querySelectorAll('input[name=para]');"
            "var all=true;"
            "cs.forEach(function(c){if(!c.checked)all=false});"
            "cs.forEach(function(c){c.checked=!all});"
            "var n=_af.querySelectorAll('input[name=para]:checked')"
            ".length;"
            "var bn=document.getElementById('red-asig-n');"
            "if(bn)bn.textContent=n?'· '+n:'';});"
            "var _evs=_af.querySelector('select[name=evento]');"
            "var _en=_af.querySelector('input[name=evento_nuevo]');"
            "if(_evs&&_en)_evs.addEventListener('change',function(){"
            "_en.style.display=_evs.value=='__nuevo__'?'block':'none'"
            "});}"
            "document.addEventListener('click',function(e){"
            "var d=document.getElementById('red-asig');"
            "if(d&&d.open&&!d.contains(e.target))d.open=false;});"
            # favoritos: arrastre de tarjetas → solo la columna
            # ★ Favoritos acepta drops (herramienta de supervisión)
            "var _cardPid=null;"
            "var _favc=document.querySelector("
            "'.red-col[data-area=favoritos]');"
            "document.addEventListener('dragstart',function(e){"
            "var card=e.target.closest&&e.target.closest('.red-post');"
            "if(!card||card.getAttribute('draggable')!=='true'){"
            "_cardPid=null;return;}"
            "e.stopPropagation();_drag=null;"
            "if(e.target.closest("
            "'a,button,summary,input,select,textarea')){"
            "_cardPid=null;return;}"
            "_cardPid=card.id.slice(2);"
            "e.dataTransfer.effectAllowed='copy';"
            "card.classList.add('drag-card');},true);"
            "document.addEventListener('dragend',function(e){"
            "[].forEach.call(document.querySelectorAll('.drag-card'),"
            "function(c){c.classList.remove('drag-card')});"
            "_cardPid=null;},true);"
            "function _favSync(){if(!_favc)return;"
            "var n=_favc.querySelectorAll('.posts .red-post').length;"
            "var t=_favc.querySelector('.red-n');if(t)t.textContent=n;}"
            "function _favAdd(pid){if(!_favc)return;"
            "var posts=_favc.querySelector('.posts');"
            "if(!posts||posts.querySelector('#p-'+pid))return;"
            "var card=document.getElementById('p-'+pid);"
            "if(!card)return;"
            "var cl=card.cloneNode(true);"
            "cl.classList.remove('drag-card');"
            "posts.insertBefore(cl,posts.firstChild);"
            "var emp=posts.querySelector('.red-fav-empty');"
            "if(emp)emp.remove();_favSync();}"
            "if(_favc){"
            "_favc.addEventListener('dragover',function(e){"
            "if(!_cardPid)return;"
            "e.preventDefault();e.stopPropagation();"
            "e.dataTransfer.dropEffect='copy';"
            "_favc.classList.add('drop-ok');},true);"
            "_favc.addEventListener('dragleave',function(){"
            "_favc.classList.remove('drop-ok')});"
            "_favc.addEventListener('drop',function(e){"
            "if(!_cardPid)return;"
            "e.preventDefault();e.stopPropagation();"
            "_favc.classList.remove('drop-ok');"
            "var pid=_cardPid;"
            "fetch('/redaccion/favorito',{method:'POST',"
            "headers:{'Content-Type':'application/x-www-form-urlencoded'"
            "},body:'id='+pid+'&op=add'});"
            "[].forEach.call(document.querySelectorAll("
            "'.red-star[data-pid=\"'+pid+'\"]'),function(b){"
            "b.classList.add('on');b.textContent='★';});"
            "_favAdd(pid)});}"
            # estrella ☆/★ por tarjeta — mismo toggle sin arrastrar
            "document.addEventListener('click',function(e){"
            "var st=e.target.closest&&e.target.closest('.red-star');"
            "if(!st)return;"
            "var pid=st.dataset.pid;var on=st.classList.contains('on');"
            "fetch('/redaccion/favorito',{method:'POST',"
            "headers:{'Content-Type':'application/x-www-form-urlencoded'"
            "},body:'id='+pid+'&op='+(on?'del':'add')});"
            "[].forEach.call(document.querySelectorAll("
            "'.red-star[data-pid=\"'+pid+'\"]'),function(b){"
            "b.classList.toggle('on',!on);"
            "b.textContent=on?'☆':'★';});"
            "if(!_favc)return;"
            "var posts=_favc.querySelector('.posts');"
            "if(!posts)return;"
            "var c=posts.querySelector('#p-'+pid);"
            "if(on){if(c)c.remove();_favSync();}"
            "else{_favAdd(pid);}});"
            "</script>" + _RED_POLL_JS.replace("CTX", "tablero")
            .replace("VER", version_redaccion()))


def _form_publicar(email: str, cfg: dict) -> str:
    """Formulario multipart para publicar. Multi-rol: si el usuario
    pertenece a varias áreas elige en cuál publicar; supervisión sin
    área elige de todo el catálogo."""
    areas_u = areas_de_usuario(email, cfg)
    sup = es_supervisor(email, cfg)
    sel_area = ""
    if len(areas_u) > 1:
        ops = "".join(
            f"<option value='{html.escape(a.get('id',''), quote=True)}'>"
            f"{html.escape(a.get('nombre',''))}</option>" for a in areas_u)
        sel_area = ("<label class='meta'>Publicar en</label>"
                    f"<select name='area'>{ops}</select>")
    elif not areas_u and sup:
        ops = "".join(
            f"<option value='{html.escape(a.get('id',''), quote=True)}'>"
            f"{html.escape(a.get('nombre',''))}</option>"
            for a in areas_redaccion(cfg))
        sel_area = ("<label class='meta'>Área</label>"
                    f"<select name='area'>{ops}</select>")
    elif not areas_u:
        return ("<div class='red-form'><p class='meta'>No tienes un "
                "área asignada — pide al admin que te agregue a "
                "<code>redaccion.areas[].miembros</code> o pon "
                "<code>area</code>/<code>areas</code> en tu perfil.</p>"
                "</div>")
    etiqueta = ("Publicar en " + html.escape(
        areas_u[0].get("nombre", "")) if len(areas_u) == 1
        else "Publicar")
    return ("<div class='red-form'><h2 style='font-size:.95rem;margin:"
            f".1rem 0 .5rem'>{etiqueta}</h2>"
            "<form method='post' action='/publicar' "
            "enctype='multipart/form-data'>"
            + sel_area +
            "<input type='text' name='titulo' placeholder='titular "
            "(opcional — si lo dejas vacío se toma del texto)'>"
            "<textarea name='texto' required placeholder='nota de la "
            "publicación…'></textarea>"
            "<input type='text' name='enlace' placeholder='enlace "
            "(opcional)'>"
            "<input type='text' name='location' placeholder='ubicación "
            "(opcional)'>"
            "<input type='file' name='archivos' multiple "
            "accept='image/*,video/*,audio/*,.pdf' "
            "style='font-size:.8rem'>"
            "<div style='margin-top:.5rem;display:flex;gap:1rem;"
            "align-items:center'>"
            "<label style='font-size:.8rem'><input type='checkbox' "
            "name='urgente' value='1'> URGENTE</label>"
            "<button style='padding:.45rem 1.2rem;border-radius:10px;"
            "border:none;background:#1a237e;color:#fff;cursor:pointer'>"
            "Publicar</button></div></form></div>")


def vista_area(email: str, v: str = "area", msg: str = "",
               a_sel: str = "") -> str:
    """Vista del colaborador: publicar, su feed de área, avisos
    (asignaciones pendientes + interés) y feed general. Multi-rol:
    si pertenece a varias áreas, chips para cambiar de una a otra."""
    cfg = json.loads(CONFIG.read_text())
    areas_u = areas_de_usuario(email, cfg)
    area = next((x for x in areas_u if x.get("id") == a_sel), None) \
        or (areas_u[0] if areas_u else None)
    posts = cargar_publicaciones()
    mis_eventos = [s for s in cargar_seguimientos()
                   if email in (s.get("miembros") or [])]
    tabs = [("area", "Mi área"), ("avisos", "Avisos"),
            ("general", "Feed general"), ("mias", "Mis publicaciones")]
    if mis_eventos:
        tabs.append(("eventos", "Eventos"))
    nav = "".join(
        f"<a href='/area?v={k}' class='{'on' if v == k else ''}'>"
        f"{html.escape(t)}</a>" for k, t in tabs)
    chips = ""
    if len(areas_u) > 1:
        chips = ("<div class='red-tabs'>" + "".join(
            f"<a href='/area?v=area&a={html.escape(x.get('id',''), quote=True)}'"
            f" class='{'on' if area and x.get('id') == area.get('id') else ''}'>"
            f"{html.escape(x.get('nombre',''))}</a>" for x in areas_u)
            + "</div>")
    out = [_RED_CSS,
           "<h1>Mi área</h1>",
           (f"<p class='meta' style='color:#b03a2e'>{html.escape(msg)}"
            "</p>" if msg else ""),
           f"<div class='red-tabs'>{nav}</div>",
           chips,
           _RED_POLL_JS.replace("CTX", "area")
           .replace("VER", version_redaccion())]

    if v == "avisos":
        mios = [p for p in posts
                if any(a.get("para") == email and
                       a.get("estado", "pendiente") == "pendiente"
                       for a in (p.get("asignaciones") or []))]
        cuerpo = ("".join(_pub_card(p, email, cfg, ret='/area') for p in mios)
                  or "<p class='meta'>Sin avisos — aquí llegan las "
                     "asignaciones pendientes.</p>")
        out.append(f"<h2 style='font-size:1rem'>Avisos "
                   f"({len(mios)})</h2>{cuerpo}")
        return "".join(out)

    out.append(_form_publicar(email, cfg))

    if v == "mias":
        ps = [p for p in posts if p.get("usuario") == email][:100]
        out.append(f"<h2 style='font-size:1rem'>Mis publicaciones "
                   f"({len(ps)})</h2>"
                   + ("".join(_pub_card(p, email, cfg, ret='/area') for p in ps)
                      or "<p class='meta'>Aún no publicas nada.</p>"))
        return "".join(out)

    if v == "eventos":
        bloques = []
        for s in mis_eventos:
            pts = [p for p in posts if p.get("evento") == s.get("id")]
            prio = s.get("prioridad", "media")
            pcolor = _PRIO_COLOR.get(prio, "#666")
            bloque = (
                f"<div class='red-form' style='margin-bottom:.8rem'>"
                f"<b>{html.escape(s.get('nombre',''))}</b> "
                f"<span style='color:{pcolor};font-size:.68rem'>"
                f"● {html.escape(prio)}</span> "
                f"<span class='meta'>({len(pts)} notas)</span>"
                + (f"<div class='meta' style='margin-top:.2rem'>"
                   f"objetivo: {html.escape(s.get('objetivo',''))}</div>"
                   if s.get("objetivo") else "")
                + "</div>"
                + ("".join(_pub_card(p, email, cfg, ret='/area') for p in pts)
                   or "<p class='meta'>Este evento aún no tiene notas "
                      "ligadas.</p>"))
            bloques.append(bloque)
        out.append("<h2 style='font-size:1rem'>Mis eventos "
                   f"({len(mis_eventos)})</h2>" + "".join(bloques))
        return "".join(out)

    if v == "general":
        ps = posts[:150]
        out.append(f"<h2 style='font-size:1rem'>Feed general "
                   f"({len(ps)})</h2>"
                   + ("".join(_pub_card(p, email, cfg, ret='/area') for p in ps)
                      or "<p class='meta'>Sin publicaciones todavía.</p>"))
        return "".join(out)

    # vista por defecto: el área del usuario
    if not area:
        out.append("<p class='meta'>No perteneces a ninguna área "
                   "configurada — usa las pestañas para ver el feed "
                   "general.</p>")
        ps = posts[:80]
        out.append("<h2 style='font-size:1rem'>Feed general</h2>"
                   + ("".join(_pub_card(p, email, cfg, ret='/area') for p in ps)
                      or "<p class='meta'>Sin publicaciones todavía.</p>"))
        return "".join(out)
    ps = [p for p in posts if p.get("area") == area.get("id")][:100]
    out.append(f"<h2 style='font-size:1rem'>{html.escape(area.get('nombre',''))}"
               f" — publicaciones ({len(ps)})</h2>"
               + ("".join(_pub_card(p, email, cfg, ret='/area') for p in ps)
                  or "<p class='meta'>Tu área aún no tiene "
                     "publicaciones.</p>"))
    return "".join(out)


def publicar_redaccion(partes: dict, email: str) -> str:
    """POST /publicar (multipart): crea la publicación del área del
    usuario. Devuelve la URL de regreso."""
    cfg = json.loads(CONFIG.read_text())
    RED_MEDIA.mkdir(exist_ok=True)

    def campo(n: str) -> str:
        vals = partes.get(n) or []
        if not vals:
            return ""
        data = vals[0][2]
        return data.decode("utf-8", "replace").strip() if data else ""

    texto = campo("texto")
    # si viene de bitácora, la nota queda ligada al evento
    evento = (campo("evento") or "").strip()
    back = "/bitacora" if evento else "/area"
    if not texto:
        return back + "?msg=" + quote("La publicación necesita texto")
    sel = campo("area")
    areas_u = areas_de_usuario(email, cfg)
    # multi-rol: el área elegida debe ser una de las suyas
    area = next((a for a in areas_u if a.get("id") == sel), None)
    if not area and areas_u and not sel:
        area = areas_u[0]
    if not area:
        area = next((a for a in areas_redaccion(cfg)
                     if a.get("id") == sel), None)
        if not area or not es_supervisor(email, cfg):
            return back + "?msg=" + quote("No tienes área asignada")
    pid = _post_id()
    media = []
    for i, (fn, ct, data) in enumerate(partes.get("archivos") or []):
        if not fn:
            continue
        m = _guardar_media(pid, i, fn, ct, data)
        if m:
            media.append(m)
    enlace = campo("enlace")
    p = {"id": pid,
         "ts": datetime.now().isoformat(timespec="seconds"),
         "usuario": email,
         "nombre": _red_nombre(email),
         "area": area.get("id"),
         "titulo": campo("titulo"),
         "texto": texto,
         "urgente": campo("urgente") == "1",
         "enlace": enlace if enlace.startswith("http") else "",
         "location": campo("location"),
         "media": media,
         "asignaciones": []}
    if evento:
        p["evento"] = evento
    _guardar_publicacion(p)
    # transcripción en segundo plano para audio/video subidos
    if any(m.get("tipo") in ("audio", "video") for m in media):
        threading.Thread(target=_transcribir_adjuntos,
                         args=(cfg, pid), daemon=True,
                         name=f"transcribe-{pid}").start()
    return ("/bitacora?msg=" + quote("Nota agregada al evento")
            if evento else "/area?msg=" + quote("Publicación enviada"))


def aplicar_accion_redaccion(ruta: str, form: dict, email: str) -> str:
    """POSTs urlencoded de redacción: interés, asignar, estado de
    asignación. Devuelve la URL de regreso."""
    cfg = json.loads(CONFIG.read_text())
    if "@demo.local" in (email or ""):
        return "/redaccion"   # invitados: solo lectura, sin acciones
    # 'volver' = página desde la que se envió el form (deck, mi área,
    # bitácora) — el POST regresa ahí en vez de mandar siempre a /area
    volver = form.get("volver", [""])[0]
    if not (volver.startswith("/") and not volver.startswith("//")):
        volver = ""
    if ruta.endswith("/orden"):
        # drag & drop del tablero: orden de columnas por usuario
        ids = [x.strip() for x in
               (form.get("orden") or [""])[0].split(",")
               if x.strip()]
        usuarios = cargar_usuarios()
        if email in usuarios:
            usuarios[email]["red_orden"] = ids
            guardar_usuarios(usuarios)
        return "/redaccion"
    if ruta.endswith("/colapsar"):
        # columnas plegadas del tablero — preferencia por usuario
        ids = [x.strip() for x in
               (form.get("cols") or [""])[0].split(",")
               if x.strip()]
        usuarios = cargar_usuarios()
        if email in usuarios:
            usuarios[email]["red_colapsadas"] = ids
            guardar_usuarios(usuarios)
        return "/redaccion"
    if ruta.endswith("/bitacora/nuevo"):
        # crear evento/seguimiento — solo supervisión
        if not es_supervisor(email, cfg):
            return "/bitacora"
        nombre = form.get("nombre", [""])[0].strip()[:120]
        if nombre:
            _guardar_seguimiento({
                "id": "s" + secrets.token_hex(4),
                "nombre": nombre,
                "objetivo": form.get("objetivo", [""])[0].strip()[:300],
                "prioridad": form.get("prioridad", ["media"])[0],
                "por": email,
                "ts": datetime.now().isoformat(timespec="seconds"),
                "miembros": []})
        return "/bitacora"
    if ruta.endswith("/bitacora/miembro"):
        # agregar/quitar usuario del equipo de un evento — supervisión
        if not es_supervisor(email, cfg):
            return "/bitacora"
        sid = form.get("sid", [""])[0].strip()
        para = form.get("para", [""])[0].strip().lower()
        op = form.get("op", [""])[0]
        ss = cargar_seguimientos()
        s = next((x for x in ss if x.get("id") == sid), None)
        usuarios = cargar_usuarios()
        if s and para in usuarios and "@demo.local" not in para:
            miembros = s.setdefault("miembros", [])
            if op == "add" and para not in miembros:
                miembros.append(para)
            elif op == "del" and para in miembros:
                miembros.remove(para)
            _reescribir_seguimientos(ss)
        return "/bitacora"
    if ruta.endswith("/bitacora/resolver"):
        # aceptar/rechazar solicitud de unión a un evento — la
        # resuelve el creador del evento o supervisión
        sid = form.get("sid", [""])[0].strip()
        de = form.get("de", [""])[0].strip().lower()
        op = form.get("op", [""])[0]
        ss = cargar_seguimientos()
        s = next((x for x in ss if x.get("id") == sid), None)
        if s and (es_supervisor(email, cfg)
                  or s.get("por") == email):
            for x in (s.get("solicitudes") or []):
                if x.get("de") == de and x.get("estado") == "pendiente":
                    x["estado"] = "aceptada" if op == "aceptar" \
                        else "rechazada"
                    if op == "aceptar":
                        miembros = s.setdefault("miembros", [])
                        if de not in miembros:
                            miembros.append(de)
                    break
            _reescribir_seguimientos(ss)
        return "/bitacora"
    pid = form.get("id", [""])[0]
    posts = cargar_publicaciones()
    p = next((x for x in posts if x.get("id") == pid), None)
    if not p:
        return "/area?msg=" + quote("Publicación no encontrada")

    if ruta.endswith("/bitacora/vincular"):
        # ligar/quitar la nota de un evento — solo supervisión
        if not es_supervisor(email, cfg):
            return "/bitacora"
        ev = form.get("evento", [""])[0].strip()
        validos = {s.get("id") for s in cargar_seguimientos()}
        if ev and ev not in validos:
            return "/bitacora"
        if ev:
            p["evento"] = ev
        else:
            p.pop("evento", None)
        _reescribir_publicaciones(posts)
        return "/bitacora"

    if ruta.endswith("/solicitar"):
        # pedir unirse al seguimiento de una nota — si la nota tiene
        # evento la solicitud va al equipo del evento; si no, queda
        # en la nota y la resuelve su autor o supervisión
        if email == p.get("usuario") or any(
                a.get("para") == email
                for a in (p.get("asignaciones") or [])):
            return "/area"
        ev = p.get("evento")
        ss = cargar_seguimientos()
        s = next((x for x in ss if x.get("id") == ev), None) if ev \
            else None
        if s is not None:
            sols = s.setdefault("solicitudes", [])
            if not any(x.get("de") == email
                       and x.get("estado") == "pendiente"
                       for x in sols):
                sols.append({"de": email,
                             "ts": datetime.now().isoformat(
                                 timespec="seconds"),
                             "estado": "pendiente"})
            _reescribir_seguimientos(ss)
        else:
            sols = p.setdefault("solicitudes", [])
            if not any(x.get("de") == email
                       and x.get("estado") == "pendiente"
                       for x in sols):
                sols.append({"de": email,
                             "ts": datetime.now().isoformat(
                                 timespec="seconds"),
                             "estado": "pendiente"})
            _reescribir_publicaciones(posts)
        return volver or ("/redaccion" if es_supervisor(email, cfg)
                          else "/area")

    if ruta.endswith("/resolver"):
        # aceptar/rechazar solicitud a nivel NOTA — autor o supervisión
        de = form.get("de", [""])[0].strip().lower()
        op = form.get("op", [""])[0]
        if not (es_supervisor(email, cfg)
                or email == p.get("usuario")):
            return "/area"
        sols = p.get("solicitudes") or []
        for x in sols:
            if x.get("de") == de and x.get("estado") == "pendiente":
                x["estado"] = "aceptada" if op == "aceptar" \
                    else "rechazada"
                if op == "aceptar":
                    p.setdefault("asignaciones", []).append({
                        "para": de, "por": email,
                        "ts": datetime.now().isoformat(
                            timespec="seconds"),
                        "estado": "pendiente",
                        "nota": "se unió al seguimiento"})
                break
        _reescribir_publicaciones(posts)
        return volver or ("/redaccion" if es_supervisor(email, cfg)
                          else "/area")

    if ruta.endswith("/comentar"):
        # nota del equipo sobre una publicación — la ven todos los
        # que abran la nota; guests (demo) no pueden comentar
        texto = form.get("texto", [""])[0].strip()[:500]
        if texto:
            p.setdefault("comentarios", []).append({
                "de": email,
                "ts": datetime.now().isoformat(timespec="seconds"),
                "texto": texto})
            _reescribir_publicaciones(posts)
        return volver or f"/redaccion/nota?id={pid}"

    if ruta.endswith("/asignar"):
        # asignar es privilegio de supervisión (Paolo/admin).
        # Multi-selección del tablero: N notas × M colaboradores;
        # 'evento' puede ser uno existente o '__nuevo__' + nombre
        # (el evento se crea al vuelo, igual que en /bitacora)
        if not es_supervisor(email, cfg):
            return "/area?msg=" + quote("Solo supervisión asigna")
        usuarios = cargar_usuarios()
        paras = [x.strip().lower() for x in form.get("para", [])
                 if x.strip().lower() in usuarios
                 and "@demo.local" not in x.strip().lower()]
        ids = [x for x in form.get("id", []) if x]
        if not paras or not ids:
            return "/area?msg=" + quote(
                "Faltan destinatarios o notas seleccionadas")
        nota = form.get("nota", [""])[0].strip()[:200]
        ev = form.get("evento", [""])[0].strip()
        if ev == "__nuevo__":
            nombre_ev = form.get("evento_nuevo", [""])[0].strip()[:120]
            ev = ""
            if nombre_ev:
                ev = "s" + secrets.token_hex(4)
                _guardar_seguimiento({
                    "id": ev, "nombre": nombre_ev, "objetivo": "",
                    "prioridad": "media", "por": email,
                    "ts": datetime.now().isoformat(timespec="seconds"),
                    "miembros": []})
        if ev:
            ss = cargar_seguimientos()
            s = next((x for x in ss if x.get("id") == ev), None)
            if s:
                miembros = s.setdefault("miembros", [])
                for para in paras:
                    if para not in miembros:
                        miembros.append(para)
                _reescribir_seguimientos(ss)
            else:
                ev = ""
        ts_a = datetime.now().isoformat(timespec="seconds")
        por_id = {x.get("id"): x for x in posts}
        for pid2 in ids:
            p2 = por_id.get(pid2)
            if not p2:
                continue
            if ev:
                p2["evento"] = ev
            for para in paras:
                if any(a.get("para") == para
                       and a.get("estado", "pendiente") == "pendiente"
                       for a in (p2.get("asignaciones") or [])):
                    continue
                p2.setdefault("asignaciones", []).append({
                    "para": para, "por": email, "ts": ts_a,
                    "estado": "pendiente", "nota": nota})
        _reescribir_publicaciones(posts)
        return volver or "/redaccion"

    if ruta.endswith("/favorito"):
        # ★ personal — la columna Favoritos del tablero; solo usuarios
        # reales (los invitados demo no tienen favoritos)
        if "@demo.local" in email:
            return "/area"
        favs = p.setdefault("favoritos", [])
        if form.get("op", ["add"])[0] == "del":
            if email in favs:
                favs.remove(email)
        elif email not in favs:
            favs.append(email)
        _reescribir_publicaciones(posts)
        return volver or "/redaccion"

    # /asignacion: marcar hecha/pendiente — supervisión o el asignado
    try:
        idx = int(form.get("idx", ["0"])[0])
    except ValueError:
        return "/area"
    asignaciones = p.get("asignaciones") or []
    if not (0 <= idx < len(asignaciones)):
        return "/area"
    a = asignaciones[idx]
    if not es_supervisor(email, cfg):
        return "/area?msg=" + quote("Solo supervisión cierra asignaciones")
    a["estado"] = form.get("estado", ["hecho"])[0] \
        if form.get("estado", [""])[0] in ("hecho", "pendiente") \
        else "hecho"
    _reescribir_publicaciones(posts)
    return volver or ("/redaccion" if es_supervisor(email, cfg)
                      else "/area?v=avisos")


_RED_REP_CACHE = {}   # horas -> (ts_epoch, texto) — el LLM tarda;
                      # 10 min de caché por rango evita regenerar


def reporte_redaccion(cfg: dict, horas: int) -> str:
    """Reporte IA de las publicaciones de las últimas `horas` horas.
    Usa _llm (Gemini free tier; si no hay key o falla, Ollama local)."""
    ahora = time.time()
    hit = _RED_REP_CACHE.get(horas)
    if hit and ahora - hit[0] < 600:
        return hit[1]
    corte = (datetime.now() - timedelta(hours=horas))\
        .isoformat(timespec="seconds")
    posts = [p for p in cargar_publicaciones()
             if p.get("ts", "") >= corte][:150]
    if not posts:
        return "(sin publicaciones en ese rango)"
    areas = {a.get("id"): a.get("nombre", a.get("id"))
             for a in areas_redaccion(cfg)}
    lineas = []
    for p in posts:
        urg = " · URGENTE" if p.get("urgente") else ""
        # transcripciones de audio/video: el LLM las usa como fuente
        trans = " ".join(
            (m.get("texto") or "")[:400]
            for m in (p.get("media") or []) if m.get("texto"))
        lineas.append(
            f"- [{areas.get(p.get('area'), p.get('area'))}] "
            f"{p.get('nombre') or _red_nombre(p.get('usuario',''))} · "
            f"{fmt_fecha(p.get('ts',''))}{urg} · "
            f"{p.get('texto','')[:300]}"
            + (f" [transcripción: {trans}]" if trans else ""))
    prompt = (
        "Eres el editor de la redacción de un equipo de comunicación "
        "social. Con base en estas publicaciones internas de las "
        f"últimas {horas} horas, escribe un reporte ejecutivo en "
        "español: primero lo URGENTE si lo hay, luego un párrafo de "
        "contexto de qué dominó, y viñetas por tema o área. Tono "
        "sobrio de nota informativa, máximo 250 palabras, sin "
        "inventar datos.\n\n" + "\n".join(lineas))
    txt = _llm(cfg, prompt, timeout=180)
    if not txt:
        txt = "(el modelo no respondió — intenta de nuevo)"
    _RED_REP_CACHE[horas] = (ahora, txt)
    return txt


def vista_reporte_redaccion(email: str, horas: int = 6) -> str:
    """Tab Reporte: rango 1/3/6/12/24 h → resumen IA de lo publicado.
    No navega a otro lado: genera (o sirve cache) en la misma vista."""
    cfg = json.loads(CONFIG.read_text())
    horas = horas if horas in (1, 3, 6, 12, 24) else 6
    chips = "".join(
        f"<a href='/redaccion/reporte?h={h}' "
        f"class='{'on' if h == horas else ''}'>{h} h</a>"
        for h in (1, 3, 6, 12, 24))
    txt = reporte_redaccion(cfg, horas)
    return (_RED_CSS
            + f"<div class='red-tabs'>{chips}"
              f"<a href='/redaccion'>← tablero</a></div>"
            + f"<h2 style='font-size:1rem;margin:.2rem 0 .6rem'>"
              f"Reporte de las últimas {horas} horas</h2>"
            + "<div class='red-form' style='max-width:none'>"
            + f"<div style='white-space:pre-wrap;font-size:.9rem;"
              f"line-height:1.55'>{html.escape(txt)}</div></div>")


_PRIO_COLOR = {"alta": "#b03a2e", "media": "#b8860b", "baja": "#2e7d32"}


def _bit_item(p: dict, email: str, cfg: dict,
              seguimientos: list) -> str:
    """Tarjeta de nota dentro de una columna de bitácora + control para
    moverla a otro seguimiento (o quitarla)."""
    opciones = ("<option value=''>— sin evento —</option>" + "".join(
        f"<option value='{html.escape(s.get('id'), quote=True)}'"
        f"{' selected' if p.get('evento') == s.get('id') else ''}>"
        f"{html.escape(s.get('nombre', ''))}</option>"
        for s in seguimientos))
    vincular = (
        "<details class='rb-det' style='margin-bottom:.4rem'>"
        "<summary class='rb' style='font-size:.68rem'>"
        "⇄ mover a evento</summary>"
        f"<form method='post' action='/bitacora/vincular' "
        f"class='rb-form'><input type='hidden' name='id' "
        f"value='{p.get('id')}'>"
        f"<select name='evento' style='min-width:170px'>{opciones}</select>"
        "<button class='rb'>mover</button></form></details>")
    return vincular + _pub_card(p, email, cfg, ret='/bitacora')


def _form_nota_evento(s: dict, email: str, cfg: dict) -> str:
    """En cada columna de bitácora: publicar una nota directo al
    evento — texto + titular + enlace + archivo (foto/video/audio/
    doc) + urgente. La nota aparece en la columna y en su área."""
    if "@demo.local" in (email or ""):
        return ""
    areas_u = areas_de_usuario(email, cfg)
    if not areas_u and not es_supervisor(email, cfg):
        return ""
    cat = areas_u if areas_u else areas_redaccion(cfg)
    if not cat:
        return ""
    sel = "".join(
        f"<option value='{html.escape(a.get('id',''), quote=True)}'>"
        f"{html.escape(a.get('nombre',''))}</option>" for a in cat)
    return ("<details class='rb-det' style='margin:.35rem 0 .2rem'>"
            "<summary class='rb' style='font-size:.68rem'>"
            "+ nota al evento</summary>"
            "<form method='post' action='/bitacora/nota' "
            "enctype='multipart/form-data' class='rb-form' "
            "style='flex-direction:column;align-items:stretch'>"
            f"<input type='hidden' name='evento' "
            f"value='{html.escape(s.get('id'), quote=True)}'>"
            f"<select name='area' style='width:100%'>{sel}</select>"
            "<input type='text' name='titulo' "
            "placeholder='titular (opcional)'>"
            "<textarea name='texto' required "
            "placeholder='nota del evento…' "
            "style='min-height:56px'></textarea>"
            "<input type='text' name='enlace' "
            "placeholder='enlace / url (opcional)'>"
            "<input type='file' name='archivos' multiple "
            "accept='image/*,video/*,audio/*,.pdf' "
            "style='font-size:.72rem'>"
            "<div style='display:flex;gap:.6rem;align-items:center'>"
            "<label style='font-size:.72rem'><input type='checkbox' "
            "name='urgente' value='1'> URGENTE</label>"
            "<button class='rb'>publicar en el evento</button></div>"
            "</form></details>")


def vista_bitacora(email: str) -> str:
    """Tab Bitácora (supervisión) en formato deck: una columna por
    evento/seguimiento — encabezado con nombre, objetivo, prioridad e
    involucrados; debajo las notas ligadas a ese evento, y una columna
    final 'Por revisar' con lo que tiene interés/asignación sin evento."""
    cfg = json.loads(CONFIG.read_text())
    posts = cargar_publicaciones()
    seguimientos = cargar_seguimientos()
    por_evento = {s.get("id"): [] for s in seguimientos}
    por_revisar = []
    for p in posts:
        ev = p.get("evento")
        if ev in por_evento:
            por_evento[ev].append(p)
        elif p.get("asignaciones"):
            por_revisar.append(p)

    n_pend = sum(1 for p in posts for a in (p.get("asignaciones") or [])
                 if a.get("estado", "pendiente") == "pendiente")
    stats = (f"<div class='meta' style='margin:.2rem 0 .7rem;"
             f"font-size:.82rem'>{len(seguimientos)} eventos · "
             f"{sum(len(v) for v in por_evento.values())} notas ligadas · "
             f"{len(por_revisar)} por revisar · {n_pend} asignaciones "
             f"pendientes</div>")

    # ── formulario de nuevo evento ──
    nuevo = (
        "<form method='post' action='/bitacora/nuevo' "
        "class='red-form' style='display:flex;gap:.5rem;flex-wrap:wrap;"
        "align-items:center;max-width:none'>"
        "<b style='font-size:.82rem'>+ nuevo evento</b>"
        "<input type='text' name='nombre' placeholder='nombre del evento' "
        "required style='width:220px;margin:0'>"
        "<input type='text' name='objetivo' "
        "placeholder='objetivo / nota del seguimiento' "
        "style='width:280px;margin:0'>"
        "<select name='prioridad' style='width:auto;margin:0'>"
        "<option value='media'>prioridad media</option>"
        "<option value='alta'>prioridad alta</option>"
        "<option value='baja'>prioridad baja</option></select>"
        "<button class='rb'>crear</button></form>")

    cols = []

    def _col(titulo_html: str, subt: str, pts: list,
             debajo: str = "", cls_extra: str = "") -> str:
        cards = "".join(_bit_item(p, email, cfg, seguimientos)
                        for p in pts) \
            or "<p class='meta' style='padding:.4rem'>sin notas</p>"
        return (f"<div class='red-col {cls_extra}'>"
                f"<h2><span class='red-nom'>{titulo_html}</span></h2>"
                f"<div class='meta' style='font-size:.7rem;margin:-.3rem 0 "
                f".6rem'>{subt}</div>{debajo}"
                f"<div class='posts'>{cards}</div></div>")

    def _equipo_html(s: dict) -> str:
        """Chips de miembros del evento + formulario para agregar/quitar."""
        sid = html.escape(s.get("id"), quote=True)
        partes = []
        for m in (s.get("miembros") or []):
            partes.append(
                f"<form method='post' action='/bitacora/miembro' "
                f"style='display:inline'>"
                f"<input type='hidden' name='sid' value='{sid}'>"
                f"<input type='hidden' name='para' "
                f"value='{html.escape(m, quote=True)}'>"
                f"<input type='hidden' name='op' value='del'>"
                f"<button class='rb' title='Quitar del evento' "
                f"style='font-size:.6rem;padding:1px 7px'>"
                f"{html.escape(_red_nombre(m))} ×</button></form>")
        restantes = [(e, n) for e, n in _usuarios_reales()
                     if e not in (s.get("miembros") or [])]
        if restantes:
            ops = "".join(
                f"<option value='{html.escape(e, quote=True)}'>"
                f"{html.escape(n)}</option>" for e, n in restantes)
            partes.append(
                f"<form method='post' action='/bitacora/miembro' "
                f"style='display:inline-flex;gap:.2rem'>"
                f"<input type='hidden' name='sid' value='{sid}'>"
                f"<input type='hidden' name='op' value='add'>"
                f"<select name='para' style='font-size:.62rem;"
                f"padding:1px 3px;max-width:110px'>{ops}</select>"
                f"<button class='rb' title='Agregar al evento' "
                f"style='font-size:.6rem;padding:1px 7px'>+</button>"
                f"</form>")
        # solicitudes de unión pendientes — las acepta/declina el
        # creador del evento o supervisión
        sols = "".join(
            f"<form method='post' action='/bitacora/resolver' "
            f"style='display:inline'>"
            f"<input type='hidden' name='sid' value='{sid}'>"
            f"<input type='hidden' name='de' "
            f"value='{html.escape(x.get('de',''), quote=True)}'>"
            f"<input type='hidden' name='op' value='{op}'>"
            f"<button class='rb' title='{tit}' "
            f"style='font-size:.6rem;padding:1px 7px'>{lbl}</button>"
            f"</form>"
            for x in (s.get("solicitudes") or [])
            if x.get("estado") == "pendiente"
            for op, lbl, tit in (
                ("aceptar", f"✓ {html.escape(_red_nombre(x.get('de','')))}",
                 "Aceptar — entra al equipo"),
                ("rechazar", "✗", "Rechazar solicitud")))
        if sols:
            partes.append(
                "<span style='color:#b8860b'>✋ solicitudes:</span> "
                + sols)
        return ("<div class='meta' style='font-size:.68rem;display:flex;"
                "flex-wrap:wrap;gap:.25rem;align-items:center;margin:"
                ".15rem 0 .55rem'>equipo: " + "".join(partes) + "</div>")

    for s in seguimientos:
        pts = por_evento.get(s.get("id"), [])
        prio = s.get("prioridad", "media")
        pcolor = _PRIO_COLOR.get(prio, "#666")
        titulo = (html.escape(s.get("nombre", "Evento"))
                  + f" <span style='color:{pcolor};font-size:.68rem'>"
                  f"● {html.escape(prio)}</span>")
        subt = html.escape(s.get("objetivo", ""))[:140]
        cols.append(_col(titulo, subt, pts,
                         debajo=(_equipo_html(s)
                                 + _form_nota_evento(s, email, cfg))))

    # columna "Por revisar": interés/asignaciones sin evento ligado
    cols.append(_col(
        "Por revisar", "notas con interés o seguimiento sin evento",
        por_revisar))

    # plegado de columnas: mismo comportamiento que el tablero
    # (click en el título o "plegar todo"); en bitácora el estado no se
    # persiste — es una vista de trabajo de una sola visita
    bit_js = (
        "<script>"
        "var _bt=document.getElementById('bit-tgl');"
        "function _bitSync(){if(!_bt)return;"
        "var a=document.querySelectorAll('.red-col:not(.closed)').length;"
        "_bt.textContent=a?'⇕ plegar todo':'⇕ expandir todo'}"
        "if(_bt)_bt.addEventListener('click',function(){"
        "var cerrar=document.querySelectorAll("
        "'.red-col:not(.closed)').length>0;"
        "document.querySelectorAll('.red-col').forEach(function(c){"
        "if(matchMedia('(max-width:760px)').matches){"
        "c.classList.toggle('open',!cerrar)}"
        "else{c.classList.toggle('closed',cerrar)}});_bitSync()});"
        "var _bi=document.getElementById('bit-inicio');"
        "if(_bi)_bi.addEventListener('click',function(){"
        "var b=document.querySelector('.red-board');"
        "if(b)b.scrollLeft=0;"
        "document.querySelectorAll('.red-col .posts').forEach("
        "function(s){s.scrollTop=0});window.scrollTo(0,0)});"
        "document.querySelectorAll('.red-col').forEach(function(c){"
        "var h=c.querySelector('h2');if(!h)return;"
        "h.addEventListener('click',function(){"
        "if(matchMedia('(max-width:760px)').matches){"
        "c.classList.toggle('open')}"
        "else{c.classList.toggle('closed')}})});"
        "_bitSync();</script>")
    return (_RED_CSS
            + "<div class='red-tabs'><a href='/redaccion'>← tablero</a>"
              "<a href='/redaccion/reporte'>Reporte</a></div>"
            + "<h2 style='font-size:1rem;margin:.2rem 0 .4rem'>Bitácora</h2>"
            + stats + nuevo
            + "<div class='red-bar'>"
            + "<button class='rtb' id='bit-tgl'>⇕ plegar todo</button>"
            + "<button class='rtb' id='bit-inicio' title='Columnas a la "
              "izquierda y notas arriba'>↺ inicio</button></div>"
            + _board_wrap("".join(cols)) + bit_js
            + _RED_POLL_JS.replace("CTX", "tablero")
            .replace("VER", version_redaccion()))


def contador_redaccion(email: str, ctx: str) -> int:
    """Publicaciones nuevas desde la última visita del usuario en ese
    contexto ('tablero' = /redaccion, 'area' = /area). Solo cuenta —
    no marca visto (eso lo hace la vista al renderizar)."""
    cfg = json.loads(CONFIG.read_text())
    perfil = cargar_usuarios().get(email) or {}
    visto = perfil.get("visto_redaccion" if ctx == "tablero"
                       else "visto_area", "")
    areas_u = areas_de_usuario(email, cfg)
    posts = cargar_publicaciones()
    if ctx == "area":
        ids = {a.get("id") for a in areas_u}
        posts = [p for p in posts if p.get("area") in ids]
    return sum(1 for p in posts if p.get("ts", "") > visto)


def version_redaccion() -> str:
    """Huella corta del estado vivo del módulo: cambia si hay notas
    nuevas, se mueven de evento, se tocan asignaciones o cambian los
    eventos mismos — el polling la compara para avisar "hay cambios"
    en pestañas que quedaron abiertas con HTML viejo."""
    h = hashlib.sha1()
    for p in cargar_publicaciones():
        h.update(json.dumps([p.get("id"), p.get("evento"),
                             p.get("asignaciones")],
                            sort_keys=True, default=str).encode())
    for s in cargar_seguimientos():
        h.update(json.dumps(s, sort_keys=True, default=str).encode())
    return h.hexdigest()[:16]


_RED_POLL_JS = """
<script>
/* polling inteligente: cada 45s pregunta si hay publicaciones nuevas
   O si el estado cambió (asignaciones/eventos desde otra sesión);
   muestra un botón flotante — NO recarga a ciegas */
var _ver='VER';
setInterval(function(){
  fetch('/redaccion/contador?ctx=CTX').then(function(r){return r.json()})
  .then(function(d){
    if((d.n>0||d.v!==_ver)&&!document.getElementById('red-nuevas')){
      var b=document.createElement('a');b.id='red-nuevas';b.href='#';
      b.className='red-pill';
      b.textContent=d.n>0?d.n+' nueva'+(d.n>1?'s':'')+' — actualizar'
        :'hubo cambios — actualizar';
      b.onclick=function(e){e.preventDefault();location.reload()};
      document.body.appendChild(b);}}).catch(function(){});
},45000);
</script>"""


def vista_publicacion(email: str, pid: str) -> str:
    """Nota completa en formato reporte: texto íntegro, media grande,
    transcripción, enlace/ubicación, asignaciones e interés."""
    cfg = json.loads(CONFIG.read_text())
    posts = cargar_publicaciones()
    p = next((x for x in posts if x.get("id") == pid), None)
    if not p:
        return ("<h1>Nota no encontrada</h1><p class='meta'>La "
                "publicación no existe o fue eliminada.</p>")
    area = next((a for a in areas_redaccion(cfg)
                 if a.get("id") == p.get("area")), {})
    anombre = html.escape(area.get("nombre") or p.get("area") or "?")
    urgente = ("<span style='background:#b03a2e;color:#fff;font-size:"
               ".68rem;font-weight:700;border-radius:8px;padding:2px 9px;"
               "margin-left:.5rem'>URGENTE</span>" if p.get("urgente")
               else "")
    # titular/resumen: campos propios si existen; si no, se derivan
    # del texto (posts viejos no traen metadatos de nota)
    texto = p.get("texto", "")
    titulo = (p.get("titulo") or "").strip()
    resumen = (p.get("resumen") or "").strip()
    if not titulo:
        primera = texto.strip().split("\n", 1)[0]
        titulo = primera[:90] if primera else "(sin titular)"
    titulo_h = html.escape(titulo)
    lead_h = (f"<p class='nota-resumen'>{html.escape(resumen)}</p>"
              if resumen else "")
    # cuerpo en párrafos — la nota completa es una cuartilla, no una
    # sola línea corrida
    bloques = [b.strip() for b in re.split(r"\n\s*\n", texto)
               if b.strip()] or [texto]
    cuerpo = "".join("<p>" + html.escape(b).replace("\n", "<br>")
                     + "</p>" for b in bloques)

    # media a tamaño reporte — varias imágenes van en grid 2 col.
    # para no estirar la nota completa en vertical
    n_img = sum(1 for m in (p.get("media") or [])
                if m.get("tipo") in (None, "", "img"))
    media_h = []
    for m in p.get("media") or []:
        src = html.escape(m.get("src", ""), quote=True)
        if not src:
            continue
        if m.get("tipo") == "video":
            media_h.append(
                f"<video src='{src}' controls preload='metadata' "
                f"style='width:100%;max-width:760px;border-radius:10px;"
                f"margin:.4rem 0'></video>")
        elif m.get("tipo") == "audio":
            media_h.append(
                f"<div style='background:#f0f1f5;border-radius:10px;"
                f"padding:.6rem .8rem;margin:.4rem 0;max-width:480px'>"
                f"<div class='meta' style='font-size:.65rem;margin-bottom:"
                f".25rem'>♪ audio — {html.escape(m.get('nombre') or 'clip')}"
                f"</div><audio src='{src}' controls preload='none' "
                f"style='width:100%;height:36px'></audio></div>")
        elif m.get("tipo") == "doc":
            media_h.append(
                f"<a href='{src}' target='_blank' rel='noopener' "
                f"style='font-size:.85rem'>ver archivo adjunto →</a>")
        else:
            w = "width:48%;margin:.4rem 1% .4rem 0" \
                if n_img > 1 else "max-width:100%;margin:.4rem 0"
            media_h.append(
                f"<a href='{src}' target='_blank' rel='noopener' "
                f"style='display:inline-block;vertical-align:top;{w}'>"
                f"<img src='{src}' loading='lazy' "
                f"style='width:100%;max-height:480px;object-fit:cover;"
                f"border-radius:10px;display:block'></a>")
        if m.get("texto"):
            media_h.append(
                f"<details open style='margin:.4rem 0;max-width:720px'>"
                f"<summary style='font-size:.72rem;cursor:pointer;"
                f"color:#1a237e;font-weight:600'>transcripción "
                f"(generada por IA)</summary><div style='white-space:"
                f"pre-wrap;font-size:.82rem;background:#fafafa;border-left:"
                f"3px solid #1a237e;padding:.6rem .8rem;margin-top:.3rem;"
                f"border-radius:0 8px 8px 0;line-height:1.5'>"
                f"{html.escape(m['texto'])}</div></details>")

    enlace = p.get("enlace") or ""
    loc = p.get("location") or ""

    # asignaciones + interés en formato reporte
    sup = es_supervisor(email, cfg)
    asignaciones = p.get("asignaciones") or []
    asign_h = ""
    if asignaciones:
        filas = []
        for i, a in enumerate(asignaciones):
            pend = a.get("estado", "pendiente") == "pendiente"
            filas.append(
                f"<div style='font-size:.78rem;margin-top:.3rem'>"
                f"→ <b>{html.escape(_red_nombre(a.get('para','')))}</b>"
                f" · {fmt_fecha(a.get('ts',''))} · "
                f"<span style='color:{'#b8860b' if pend else '#2e7d32'}'>"
                f"{'pendiente' if pend else 'hecho'}</span> "
                f"{html.escape(a.get('nota',''))}</div>")
        asign_h = ("<h3 style='font-size:.85rem;margin-top:1rem'>"
                   "Seguimiento</h3>" + "".join(filas))
    autor = html.escape(p.get("nombre")
                        or _red_nombre(p.get("usuario", "")))
    # fila meta estilo nota periodística: autor · fecha · ubicación ·
    # enlace · compartir — todo lo que hace "completa" la pieza
    meta_bits = [f"✍ {autor}", f"🕐 {fmt_fecha(p.get('ts',''))}"]
    if p.get("fuente"):
        meta_bits.append(f"📰 {html.escape(p['fuente'])}")
    if loc:
        meta_bits.append(f"📍 {html.escape(loc)}")
    if enlace:
        meta_bits.append(
            f"<a href='{html.escape(enlace, quote=True)}' "
            f"target='_blank' rel='noopener'>enlace original →</a>")
    meta_bits.append(
        "<button class='rb' style='height:24px;font-size:.68rem' "
        "onclick=\"navigator.clipboard.writeText(location.href);"
        "this.textContent='✓ enlace copiado'\">compartir</button>")
    meta_row = ("<div class='nota-meta'>"
                + "<span>·</span>".join(meta_bits) + "</div>")

    # notas relacionadas: (a) las otras publicaciones de la misma
    # historia (familia — la nota salió en varios medios) y (b) notas
    # de otras historias que comparten palabras clave del titular
    nombres_area = {a.get("id"): a.get("nombre", "")
                    for a in areas_redaccion(cfg)}
    claves = {w for w in normalizar(titulo).split() if len(w) > 4}
    rel_map = {}
    for q in posts:
        if q.get("id") == p.get("id"):
            continue
        if p.get("familia") and q.get("familia") == p.get("familia"):
            rel_map[q["id"]] = (0, q)
            continue
        tq = set(normalizar(q.get("titulo") or "").split())
        if len(claves & {w for w in tq if len(w) > 4}) >= 2:
            rel_map[q["id"]] = (1, q)
    def _ts_desc(t):
        return t[1].get("ts", "")
    fam = sorted((t for t in rel_map.values() if t[0] == 0),
                 key=_ts_desc, reverse=True)
    otras = sorted((t for t in rel_map.values() if t[0] == 1),
                   key=_ts_desc, reverse=True)
    rel = (fam + otras)[:6]
    rel_h = ""
    if rel:
        filas_rel = []
        for _, q in rel:
            qt = html.escape((q.get("titulo") or "")[:80])
            qa = html.escape(nombres_area.get(q.get("area"),
                                              q.get("area") or "?"))
            filas_rel.append(
                f"<a class='rel-nota' href='/redaccion/nota?id="
                f"{q.get('id')}'>"
                f"<span class='rel-t'>{qt}</span>"
                f"<span class='rel-m'>{_area_icono(q.get('area'),10)} "
                f"{qa} · {html.escape(q.get('nombre') or '')} · "
                f"{fmt_fecha(q.get('ts',''))}</span></a>")
        rel_h = ("<h3 class='nota-rel-t'>Notas relacionadas</h3>"
                 + "".join(filas_rel))

    # ── notas del equipo sobre la publicación ──
    comentarios = p.get("comentarios") or []
    com_items = "".join(
        f"<div class='com-item'><div class='com-head'>"
        f"<b>{html.escape(_red_nombre(c.get('de', '')))}</b>"
        f"<span class='meta'>{fmt_fecha(c.get('ts', ''))}</span></div>"
        f"<div class='com-txt'>{html.escape(c.get('texto', ''))}</div>"
        f"</div>" for c in comentarios[-30:])
    com_form = ("" if "@demo.local" in (email or "") else
                f"<form method='post' action='/redaccion/comentar' "
                f"class='rb-form' style='margin-top:.55rem'>"
                f"<input type='hidden' name='id' value='{p.get('id')}'>"
                f"<input type='hidden' name='volver' "
                f"value='/redaccion/nota?id={p.get('id')}'>"
                f"<input name='texto' required maxlength='500' "
                f"placeholder='Deja una nota para el equipo…' "
                f"style='flex:1;min-width:180px'>"
                f"<button class='rb'>comentar</button></form>")
    com_h = ("<h3 class='nota-rel-t'>Notas del equipo"
             + (f" ({len(comentarios)})" if comentarios else "")
             + "</h3>"
             + (com_items or "<p class='meta'>Aún no hay notas.</p>")
             + com_form)

    return (_RED_CSS +
            "<p class='meta' style='margin:.2rem 0'><a href='javascript:"
            "history.back()' style='color:#1a237e;text-decoration:none'>"
            "← volver</a></p>"
            "<article class='red-form nota' style='max-width:780px'>"
            f"<div class='nota-kicker'>{_area_icono(p.get('area'),12)} "
            f"{anombre}{urgente}</div>"
            f"<h1 class='nota-titulo'>{titulo_h}</h1>"
            + lead_h + meta_row +
            f"<div class='nota-cuerpo'>{cuerpo}</div>"
            + "".join(media_h) + asign_h + rel_h + com_h +
            "</article>")


# ── asistente IA de la redacción ─────────────────────────────────
# chat para supervisión: recupera las notas más relevantes por
# palabra clave y las manda como contexto a _llm (Gemini → Ollama)

def _chat_path(email: str):
    safe = re.sub(r"[^a-z0-9@._-]", "_", (email or "").lower())
    return BASE / f"asistente_{safe}.json"


def _chat_cargar(email: str) -> list:
    try:
        return json.loads(_chat_path(email).read_text())
    except Exception:
        return []


def _chat_guardar(email: str, msgs: list):
    try:
        _chat_path(email).write_text(
            json.dumps(msgs[-15:], ensure_ascii=False))
    except Exception:
        pass


_STOP_ASIS = {
    "que","los","las","una","uno","unos","unas","con","por","para",
    "del","como","mas","más","sus","este","esta","esto","hay","fue",
    "son","ser","sea","sobre","entre","desde","hasta","donde","cuando",
    "quien","cual","cuales","cómo","muy","ya","han","era","the","and",
    "of","in","on","at","to","a","y","o","e","u","de","en","el","la",
    "lo","un","al","es","se","su","me","te","le","nos","les","mi",
    "tu","mis","tus","no","si","sí","ni","pero","porque","pues",
    "aunque","mientras","durante","tras","ante","bajo","sin","segun",
    "según","hacia","nota","notas","noticia","noticias","publicacion",
    "publicación","redacción","redaccion","hay","tienen","tener"}


def _asistente_responder(pregunta: str, cfg: dict):
    """Devuelve (respuesta_texto, notas_contexto). Recuperación por
    palabra clave sobre titulo/resumen/texto/fuente — sin embeddings,
    suficiente para la demo."""
    posts = cargar_publicaciones()
    agujas = [t for t in _agujas_buscar(pregunta)
              if t not in _STOP_ASIS and len(t) > 2]
    if not agujas:
        return ("Escribe una pregunta con términos concretos — por "
                "ejemplo un lugar, persona o tema de la cobertura.", [])
    scored = []
    for p in posts:
        txt = normalizar(" ".join(
            str(p.get(k) or "") for k in
            ("titulo", "resumen", "texto", "fuente")))
        sc = sum(1 for t in agujas if termino_en(t, txt))
        if sc:
            scored.append((sc, p))
    scored.sort(key=lambda x: -x[0])
    # prioridad: notas que cubren TODAS las agujas; si ninguna, las
    # de mayor coincidencia parcial
    completos = [p for sc, p in scored if sc == len(agujas)]
    top = (completos or [p for _, p in scored])[:6]
    if not top:
        return ("No encontré notas relacionadas con esa pregunta en "
                "la redacción — prueba con otros términos.", [])
    ctx = []
    for p in top:
        ctx.append(
            f"[{p.get('id')}] {p.get('titulo') or ''} | "
            f"{p.get('area','')} | {p.get('fuente','')} | "
            f"{fmt_fecha(p.get('ts',''))} | por {p.get('nombre','')}\n"
            f"{(p.get('resumen') or '')}\n"
            f"{(p.get('texto') or '')[:700]}")
    prompt = (
        "Eres el asistente de la redacción del TSJT (Tabasco). "
        "Respondes preguntas de supervisión sobre las notas internas "
        "de la redacción. Reglas: español, directo, máximo 150 "
        "palabras; cita las notas por su id entre corchetes [id] "
        "cuando las uses; si te preguntan si una nota está relacionada "
        "con otra, explica por qué (mismo tema, misma familia, mismo "
        "evento); si no hay base en las notas, dilo claro. "
        "NUNCA inventes datos ni ids de notas que no estén en la "
        "lista — si no sabes, dilo.\n\n"
        f"PREGUNTA: {pregunta}\n\nNOTAS DE LA REDACCIÓN:\n\n"
        + "\n\n---\n\n".join(ctx))
    resp = _llm(cfg, prompt, timeout=90)
    if not resp or resp.startswith("(no se pudo"):
        resp = ("El modelo no respondió a tiempo — intenta de nuevo "
                "en un momento.")
    # anti-alucinación: cualquier [id] citado que NO esté entre las
    # notas del contexto se invalida — el LLM no puede fabricar
    # referencias
    validos = {str(p.get("id")) for p in top}
    resp = re.sub(
        r"\[(r?[a-z0-9]{6,})\]",
        lambda m: m.group(0) if m.group(1) in validos
        else "[id no válido]", resp)
    return resp, top


def vista_asistente(email: str) -> str:
    """Chat IA para supervisión: historial + caja de pregunta. Las
    respuestas citan las notas usadas como contexto con links."""
    msgs = _chat_cargar(email)
    burbujas = []
    nombres_area = {a.get("id"): a.get("nombre", "")
                    for a in areas_redaccion(
                        json.loads(CONFIG.read_text()))}
    for m in msgs:
        quien = "tú" if m.get("rol") == "q" else "asistente"
        cls = "asis-q" if m.get("rol") == "q" else "asis-a"
        cuerpo = m.get("texto", "")
        # el LLM a veces escribe markdown — normalizar: [[id]](url) y
        # [id](url) → [id]; **negrita** → <b>
        cuerpo = re.sub(r"\[\[\s*([^\]]+?)\s*\]\]\([^)]*\)",
                        r"[\1]", cuerpo)
        cuerpo = re.sub(r"\[\s*([^\]]+?)\s*\]\([^)]*\)",
                        r"[\1]", cuerpo)
        cuerpo = html.escape(cuerpo)
        cuerpo = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", cuerpo)
        # citas [id] → botón "ver nota"
        def _link(mm):
            return (f"<a class='rb' style='height:20px;font-size:.62rem;"
                    f"padding:0 8px;margin:0 2px;display:inline-block' "
                    f"href='/redaccion/nota?id={mm.group(1)}'>"
                    f"ver nota</a>")
        cuerpo = re.sub(r"\[(r?[a-z0-9]{6,})\]", _link, cuerpo)
        burbujas.append(
            f"<div class='asis-msg {cls}'><div class='asis-quien'>"
            f"{quien}</div><div>{cuerpo}</div></div>")
    chips = "".join(
        f"<button class='rb' style='height:22px;font-size:.68rem' "
        f"onclick=\"document.getElementById('asis-q').value='{html.escape(q, quote=True)}';"
        f"document.getElementById('asis-f').submit()\">{html.escape(q)}</button>"
        for q in ["¿Qué notas hay sobre Sheinbaum?",
                  "¿Qué está pasando con la Resistencia Cívica?",
                  "¿Qué notas comparten tema entre sí?"])
    return (_RED_CSS +
            "<h2 style='font-size:1rem;margin:.2rem 0 .6rem'>"
            "Asistente de la redacción</h2>"
            "<div class='meta' style='margin-bottom:.7rem;font-size:.78rem'>"
            "Pregunta sobre la cobertura — el asistente busca en las "
            "notas publicadas y responde con contexto.</div>"
            "<div class='asis-log'>" + "".join(burbujas) +
            ("<p class='meta'>sin conversación todavía — haz la "
             "primera pregunta ↓</p>" if not burbujas else "")
            + "</div>"
            f"<div class='asis-sugs'>{chips}</div>"
            "<form method='post' action='/asistente' id='asis-f' "
            "style='display:flex;gap:.5rem;margin-top:.6rem'>"
            "<input type='text' name='pregunta' id='asis-q' required "
            "placeholder='pregunta sobre la cobertura…' "
            "style='flex:1'>"
            "<button class='rb' style='height:34px'>preguntar</button>"
            "</form>"
            "<div class='meta' style='font-size:.68rem;margin-top:.6rem'>"
            "respuesta generada con IA a partir de las notas "
            "publicadas — los ids citados siempre llevan a su fuente; "
            "verifica antes de circular.</div>")


_IA_CACHE = {}


def vista_nota_ia(email: str, pid: str) -> str:
    """Contexto IA de UNA nota (botón ✦ de la tarjeta): resumen del
    caso + por qué se relaciona con otras notas. Cacheado por id —
    no se gasta LLM dos veces en la misma pieza."""
    cfg = json.loads(CONFIG.read_text())
    posts = cargar_publicaciones()
    p = next((x for x in posts if x.get("id") == pid), None)
    if not p:
        return ("<h1>Nota no encontrada</h1><p class='meta'>La "
                "publicación no existe.</p>")
    if pid not in _IA_CACHE:
        # candidatas relacionadas: misma familia + titular con
        # palabras clave compartidas
        claves = {w for w in normalizar(p.get("titulo") or "").split()
                  if len(w) > 4}
        rel = []
        for q in posts:
            if q.get("id") == pid:
                continue
            if p.get("familia") and q.get("familia") == p.get("familia"):
                rel.append(q)
                continue
            tq = set(normalizar(q.get("titulo") or "").split())
            if len(claves & {w for w in tq if len(w) > 4}) >= 2:
                rel.append(q)
        rel = rel[:5]
        area = next((a for a in areas_redaccion(cfg)
                     if a.get("id") == p.get("area")), {})
        rel_txt = "\n".join(
            f"[{q.get('id')}] {q.get('titulo','')} | "
            f"{q.get('area','')} | {q.get('fuente','')} | "
            f"{fmt_fecha(q.get('ts',''))}" for q in rel) or "(ninguna)"
        prompt = (
            "Eres el asistente de la redacción del TSJT. En 3-5 líneas "
            "resume el contexto de esta nota y explica con qué otras "
            "notas se relaciona (mismo tema, familia o evento). "
            "Cita notas relacionadas por su id entre corchetes [id]. "
            "Español, directo.\n\n"
            f"NOTA [{pid}] {p.get('titulo','')} | "
            f"{area.get('nombre', p.get('area',''))} | "
            f"{p.get('fuente','')} | {fmt_fecha(p.get('ts',''))} | "
            f"por {p.get('nombre','')}\n"
            f"{(p.get('resumen') or '')}\n"
            f"{(p.get('texto') or '')[:900]}\n\n"
            f"NOTAS RELACIONADAS CANDIDATAS:\n{rel_txt}")
        resp = _llm(cfg, prompt, timeout=90) \
            or "El modelo no respondió — intenta de nuevo."
        # anti-alucinación: solo los ids que el modelo realmente vio
        # (la nota + las relacionadas candidatas) pueden citarse
        validos = {str(pid)} | {str(q.get("id")) for q in rel}
        resp = re.sub(
            r"\[(r?[a-z0-9]{6,})\]",
            lambda m: m.group(0) if m.group(1) in validos
            else "[id no válido]", resp)
        _IA_CACHE[pid] = resp
    resp = _IA_CACHE[pid]
    # normalizar markdown del LLM y convertir citas en botones
    resp = re.sub(r"\[\[\s*([^\]]+?)\s*\]\]\([^)]*\)", r"[\1]", resp)
    resp = re.sub(r"\[\s*([^\]]+?)\s*\]\([^)]*\)", r"[\1]", resp)
    cuerpo = html.escape(resp)
    cuerpo = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", cuerpo)
    def _link(mm):
        return (f"<a class='rb' style='height:20px;font-size:.62rem;"
                f"padding:0 8px;margin:0 2px;display:inline-block' "
                f"href='/redaccion/nota?id={mm.group(1)}'>"
                f"ver nota</a>")
    cuerpo = re.sub(r"\[(r?[a-z0-9]{6,})\]", _link, cuerpo)
    cuerpo = cuerpo.replace("\n", "<br>")
    return (_RED_CSS +
            "<p class='meta' style='margin:.2rem 0'><a href='javascript:"
            "history.back()' style='color:#1a237e;text-decoration:none'>"
            "← volver</a></p>"
            "<article class='red-form nota' style='max-width:780px'>"
            f"<h1 class='nota-titulo' style='font-size:1.1rem'>"
            f"{html.escape(p.get('titulo') or '')}</h1>"
            "<div class='asis-a' style='margin:.8rem 0'>"
            "<div class='asis-quien'>✦ contexto IA</div>"
            f"<div>{cuerpo}</div></div>"
            "<div class='meta'><a class='rb' "
            f"href='/redaccion/nota?id={pid}'>ver noticia completa →</a>"
            "</div></article>")


# ── chat interno de la redacción ──────────────────────────────────
# canales en chats.json, mensajes en chat_msg.jsonl ({canal,de,ts,
# texto}). 'general' existe siempre y es visible para todos; los demás
# canales los crea supervisión. Lectura para todos, escritura solo
# usuarios reales (demo guest = solo lectura).
CHAT_JSON = BASE / "chats.json"
CHAT_MSG = BASE / "chat_msg.jsonl"


def cargar_canales() -> list:
    try:
        cs = json.loads(CHAT_JSON.read_text()).get("canales", [])
    except Exception:
        cs = []
    if not any(c.get("id") == "general" for c in cs):
        cs.insert(0, {"id": "general", "nombre": "General",
                      "ts": datetime.now().isoformat(timespec="seconds")})
        _guardar_canales(cs)
    return cs


def _guardar_canales(cs: list):
    _escribir_json(CHAT_JSON, {"canales": cs})


def cargar_msgs(canal: str, limite: int = 300) -> list:
    out = []
    try:
        for ln in CHAT_MSG.read_text().splitlines():
            try:
                m = json.loads(ln)
            except Exception:
                continue
            if m.get("canal") == canal:
                out.append(m)
    except FileNotFoundError:
        pass
    return out[-limite:]


def agregar_msg(canal: str, de: str, texto: str):
    with CHAT_MSG.open("a") as f:
        f.write(json.dumps(
            {"canal": canal, "de": de,
             "ts": datetime.now().isoformat(timespec="seconds"),
             "texto": texto}, ensure_ascii=False) + "\n")


def _chat_burbuja(m: dict, email: str) -> str:
    mio = m.get("de") == email
    quien = html.escape(_red_nombre(m.get("de", "")))
    hora = fmt_fecha(m.get("ts", ""))
    return (f"<div class='chat-msg{' mio' if mio else ''}'>"
            f"<div class='chat-quien'>{quien} · {hora}</div>"
            f"<div class='chat-txt'>{html.escape(m.get('texto', ''))}"
            f"</div></div>")


def _chat_css() -> str:
    return """
<style>
.chat-wrap{display:flex;gap:.8rem;align-items:stretch;height:70vh;
  max-width:1000px}
.chat-side{flex:0 0 190px;display:flex;flex-direction:column;gap:.35rem;
  overflow-y:auto}
.chat-side a{display:block;padding:.5rem .7rem;border-radius:10px;
  border:1px solid #2c3a72;background:rgba(255,255,255,.04);
  color:#cfd6ff;text-decoration:none;font-size:.82rem}
.chat-side a.on{border-color:#7c4dff;background:rgba(124,77,255,.15);
  color:#fff;font-weight:600}
.chat-main{flex:1;display:flex;flex-direction:column;min-width:0;
  border:1px solid #2c3a72;border-radius:12px;background:rgba(15,20,52,.6);
  overflow:hidden}
.chat-hilo{flex:1;overflow-y:auto;padding:.7rem;display:flex;
  flex-direction:column;gap:.45rem}
.chat-msg{max-width:78%;padding:.45rem .7rem;border-radius:12px;
  background:rgba(255,255,255,.06);border:1px solid #2c3a72;
  align-self:flex-start}
.chat-msg.mio{align-self:flex-end;background:rgba(57,73,171,.35);
  border-color:#5c6bc0}
.chat-quien{font-size:.62rem;color:#8a93b8;margin-bottom:.15rem}
.chat-txt{font-size:.85rem;color:#eef1ff;white-space:pre-wrap;
  line-height:1.45;word-break:break-word}
.chat-form{display:flex;gap:.4rem;padding:.55rem;border-top:1px solid
  #2c3a72}
.chat-form input{flex:1;font-size:.85rem;padding:.5rem .7rem;border-radius:
  10px;border:1px solid #33415f;background:#0d1330;color:#eef1ff}
.chat-nuevo{display:flex;gap:.35rem;margin-top:.5rem}
.chat-nuevo input{flex:1;font-size:.78rem;padding:.4rem .6rem;border-radius:
  8px;border:1px solid #33415f;background:#0d1330;color:#eef1ff}
.chat-vacio{color:#8a93b8;font-size:.8rem;text-align:center;
  margin:auto}
html.tema-claro .chat-side a{background:#fff;color:#444;
  border-color:#e2e2e8}
html.tema-claro .chat-side a.on{background:#1a237e;color:#fff;
  border-color:#1a237e}
html.tema-claro .chat-main{background:#fff;border-color:#e2e2e8}
html.tema-claro .chat-msg{background:#f4f4f6;border-color:#e2e2e8}
html.tema-claro .chat-msg.mio{background:#e8eaf6;border-color:#9fa8da}
html.tema-claro .chat-txt{color:#333}
html.tema-claro .chat-quien{color:#999}
html.tema-claro .chat-form{border-color:#e2e2e8}
html.tema-claro .chat-form input,html.tema-claro .chat-nuevo input{
  background:#fff;color:#222;border-color:#ccc}
@media (max-width:760px){.chat-wrap{flex-direction:column;height:auto}
  .chat-side{flex-direction:row;overflow-x:auto;flex:none}
  .chat-side a{white-space:nowrap}.chat-main{min-height:50vh}}
</style>"""


def vista_chat(email: str, canal: str = "general") -> str:
    cfg = json.loads(CONFIG.read_text())
    canales = cargar_canales()
    if canal not in {c.get("id") for c in canales}:
        canal = "general"
    msgs = cargar_msgs(canal)
    es_demo = "@demo.local" in (email or "")
    sup = es_supervisor(email, cfg)

    items = "".join(
        f"<a href='/chat?c={c.get('id')}' "
        f"class='{'on' if c.get('id') == canal else ''}'>"
 f"{html.escape(c.get('nombre') or c.get('id'))}</a>"
        for c in canales)
    # supervisión crea canales nuevos
    nuevo = ("" if es_demo or not sup else
             "<form method='post' action='/chat/canal' class='chat-nuevo'>"
             "<input name='nombre' placeholder='nuevo canal…' "
             "maxlength='40' required>"
             "<button class='rb'>+</button></form>")

    hilo = "".join(_chat_burbuja(m, email) for m in msgs) or \
        "<div class='chat-vacio'>Sin mensajes todavía — rompe el hielo.</div>"
    form = ("" if es_demo else
            "<form method='post' action='/chat/enviar' class='chat-form'>"
            f"<input type='hidden' name='canal' value='{canal}'>"
            "<input name='texto' placeholder='Escribe al equipo…' "
            "autocomplete='off' required maxlength='1000'>"
            "<button class='rb'>enviar</button></form>")

    js = f"""
<script>
var _chatUlt = {len(msgs)};
var _chatCanal = {canal!r};
function _chatPoll(){{
  fetch('/chat/hilo?c='+encodeURIComponent(_chatCanal)
        +'&desde='+_chatUlt)
  .then(function(r){{return r.json()}}).then(function(d){{
    if(!d.n)return;
    var h=document.getElementById('chat-hilo');if(!h)return;
    var tmp=document.createElement('div');tmp.innerHTML=d.html;
    while(tmp.firstChild)h.appendChild(tmp.firstChild);
    _chatUlt=d.idx;
    h.scrollTop=h.scrollHeight;
    var vac=h.querySelector('.chat-vacio');if(vac)vac.remove();
  }}).catch(function(){{}});
}}
setInterval(_chatPoll,8000);
var _ch=document.getElementById('chat-hilo');
if(_ch)_ch.scrollTop=_ch.scrollHeight;
var _ci=document.querySelector('.chat-form input[name=texto]');
if(_ci)_ci.focus();
</script>"""

    return (_chat_css() + _RED_CSS +
            "<h2 style='font-size:1rem;margin:.2rem 0 .6rem'>Chat de la "
            "redacción</h2>"
            "<div class='chat-wrap'>"
            f"<div class='chat-side'>{items}{nuevo}</div>"
            "<div class='chat-main'>"
            f"<div class='chat-hilo' id='chat-hilo'>{hilo}</div>"
            f"{form}</div></div>" + js)


def _chat_hilo_html(canal: str, desde: int, email: str) -> dict:
    """Mensajes del canal a partir del índice 'desde' → HTML + nuevo
    índice. Índice (no timestamp) porque dos mensajes pueden caer en
    el mismo segundo y se perdería el segundo."""
    msgs = cargar_msgs(canal, limite=500)
    nuevos = msgs[int(desde):] if desde.isdigit() else msgs
    html_ = "".join(_chat_burbuja(m, email) for m in nuevos)
    return {"n": len(nuevos), "html": html_, "idx": len(msgs)}


def aplicar_accion_chat(ruta: str, form: dict, email: str) -> str:
    """POSTs del chat → redirect de regreso."""
    cfg = json.loads(CONFIG.read_text())
    canales = cargar_canales()
    ids = {c.get("id") for c in canales}
    if ruta.endswith("/chat/canal"):
        if not es_supervisor(email, cfg):
            return "/chat"
        nombre = form.get("nombre", [""])[0].strip()[:40]
        if nombre:
            cid = re.sub(r"[^a-z0-9]+", "-",
                         normalizar(nombre)).strip("-") or \
                "c" + secrets.token_hex(3)
            if cid not in ids:
                canales.append({"id": cid, "nombre": nombre,
                                "ts": datetime.now().isoformat(
                                    timespec="seconds")})
                _guardar_canales(canales)
                return f"/chat?c={cid}"
        return "/chat"
    # /chat/enviar
    if "@demo.local" in (email or ""):
        return "/chat"
    canal = form.get("canal", ["general"])[0]
    if canal not in ids:
        canal = "general"
    texto = form.get("texto", [""])[0].strip()[:1000]
    if texto:
        agregar_msg(canal, email, texto)
    return f"/chat?c={canal}"


def render_pagina(contenido: str, q: str = "", base: str = "",
                  og_img: str = "", wide: bool = False,
                  usuario: str = "", og_title: str = "",
                  og_desc: str = "") -> bytes:
    cfg = json.loads(CONFIG.read_text())
    # Seguimiento (radar de perfiles FB) fuera del nav — las 38
    # fuentes fb están muertas (cuentas perdidas, fb_pausa);
    # la ruta sigue viva por URL para consultar el histórico
    admin_tabs = ('<a href="/usuarios">Usuarios</a>'
                  '<a href="/analitica">Analítica</a>'
                  if usuario and es_admin(usuario, cfg) else "")
    # redacción es el producto: supervisión y colaboradores ven SOLO
    # sus secciones — el monitor de prensa quedó muerto (scrapeo
    # pausado): sus tabs salen del menú para todos (las rutas viejas
    # siguen vivas por URL)
    en_redaccion = bool(usuario) and (
        "@demo.local" in usuario
        or es_supervisor(usuario, cfg) or area_de_usuario(usuario, cfg))
    tabs_base = ""
    if usuario and "@demo.local" in usuario:
        # invitado: deck + chat (solo lectura) en modo demo
        tabs_reg = ('<a href="/redaccion">Redacción</a>'
                    '<a href="/chat">Chat</a>')
        admin_tabs = ""
    elif en_redaccion:
        tabs_reg = ""
        admin_tabs = ""
        if es_supervisor(usuario, cfg) \
                or area_de_usuario(usuario, cfg):
            tabs_reg += '<a href="/redaccion">Redacción</a>'
        if area_de_usuario(usuario, cfg):
            tabs_reg += '<a href="/area">Mi área</a>'
        tabs_reg += '<a href="/redaccion/reporte">Reporte</a>'
        tabs_reg += '<a href="/chat">Chat</a>'
        if es_supervisor(usuario, cfg):
            tabs_reg += '<a href="/bitacora">Bitácora</a>'
            tabs_reg += '<a href="/asistente">Asistente</a>'
    else:
        tabs_reg = ""
    # nombre en el header: perfil 'nombre' si lo trae, si no el
    # local-part del email (paolo@… → paolo); guest → invitado
    if usuario:
        if "@demo.local" in usuario:
            nombre_u = "invitado"
        else:
            nombre_u = ((cargar_usuarios().get(usuario) or {})
                        .get("nombre") or usuario.split("@")[0])
    else:
        nombre_u = ""
    return PAGINA.format(contenido=contenido, q=html.escape(q),
                         base=base, admin_tabs=admin_tabs,
                         main_cls=' class="wide"' if wide else "",
                         # refresh ciego cada 60s: solo para el producto
                         # viejo — redacción usa polling inteligente
                         refresh_tag=("" if en_redaccion else
                                      '<meta http-equiv="refresh" '
                                      'content="60">'),
                         tabs_base=tabs_base,
                         tabs_reg=tabs_reg, usuario=html.escape(usuario),
                         usuario_html=html.escape(nombre_u),
                         og_title=html.escape(og_title or
                             "@noticias — Monitor de prensa TSJT"),
                         og_desc=html.escape(og_desc or
                             "Monitor de noticias del Poder Judicial de "
                             "Tabasco: prensa del Magistrado Presidente y "
                             "el TSJT, alertas por tema y síntesis "
                             "ejecutivas. Powered by PIRIA."),
                         og_img=html.escape(og_img or
                             f"{base}/og.png")).encode()


def aplicar_accion_usuarios(form: dict, email: str) -> bool:
    """POST /usuarios (solo admin): crear, password, demo 24h, eliminar."""
    cfg = json.loads(CONFIG.read_text())
    if not es_admin(email, cfg):
        return False
    usuarios = cargar_usuarios()
    objetivo = form.get("email", [""])[0].strip().lower()
    accion = form.get("accion", [""])[0]
    pw = form.get("password", [""])[0]

    # varios proyectos: 'tsjt, qroo' — el operador puede estar en 2+
    proyectos = [p.strip().lower() for p in
                 form.get("proyecto", [""])[0].split(",") if p.strip()]
    nivel = form.get("nivel", [""])[0].strip().lower()
    if nivel not in ("operacion", "supervision"):
        nivel = "operacion"
    if accion == "crear" and objetivo and pw and objetivo not in usuarios:
        usuarios[objetivo] = {
            "reglas": [], "fuentes_ocultas": [], "expira": 0,
            "password": hash_password(pw),
            "proyectos": proyectos, "nivel": nivel,
        }
    elif accion == "perfil" and objetivo in usuarios \
            and not es_admin(objetivo, cfg):
        # reasignar equipo/nivel — admin define quién supervisa y a
        # qué proyectos pertenece cada operador
        usuarios[objetivo]["proyectos"] = proyectos
        usuarios[objetivo].pop("proyecto", None)  # migra campo viejo
        usuarios[objetivo]["nivel"] = nivel
    elif accion == "quitar_admin" and objetivo != email \
            and objetivo in cfg.get("admins", []) \
            and len(cfg["admins"]) > 1:
        # lo baja de admin a operador: su perfil (reglas, proyectos)
        # queda intacto y ahora se le puede asignar equipo/nivel
        cfg["admins"].remove(objetivo)
        _escribir_json(CONFIG, cfg)
        usuarios.setdefault(objetivo, {}).setdefault(
            "nivel", "operacion")
    elif accion == "password" and objetivo in usuarios and pw:
        usuarios[objetivo]["password"] = hash_password(pw)
    elif not objetivo or es_admin(objetivo, cfg):
        return True  # no tocar al admin
    elif accion == "eliminar":
        usuarios.pop(objetivo, None)
    elif objetivo in usuarios:
        if accion == "demo24":
            usuarios[objetivo]["expira"] = time.time() + DEMO_HORAS * 3600
        elif accion == "quitar_demo":
            usuarios[objetivo]["expira"] = 0
    guardar_usuarios(usuarios)
    return True


def servir_web(puerto: int):
    class Handler(BaseHTTPRequestHandler):
        def send_response(self, code, message=None):
            """Seguridad básica en TODA respuesta (HTML, redirects, PNGs).
            CSP permite inline (la app vive de <style>/onclick) pero fija
            frame-ancestors para que nadie nos incruste en un iframe."""
            super().send_response(code, message)
            for k, v in (
                ("X-Content-Type-Options", "nosniff"),
                ("X-Frame-Options", "DENY"),
                ("Referrer-Policy", "strict-origin-when-cross-origin"),
                ("Permissions-Policy", "camera=(), microphone=(), geolocation=()"),
                ("Strict-Transport-Security", "max-age=31536000"),
                ("Content-Security-Policy",
                 "default-src 'self'; img-src 'self' https: data:; "
                 "style-src 'self' 'unsafe-inline'; "
                 "script-src 'unsafe-inline' https://static.cloudflareinsights.com; "
                 "frame-ancestors 'none'; base-uri 'self'"),
            ):
                self.send_header(k, v)

        def _base(self) -> str:
            """URL absoluta del server según el Host del request
            (sirve igual por IP local, dominio o túnel https)."""
            proto = self.headers.get("X-Forwarded-Proto", "")
            if not proto:
                # Cloudflare Tunnel manda el scheme en Cf-Visitor (JSON)
                cfv = self.headers.get("Cf-Visitor", "")
                proto = "https" if '"scheme":"https"' in cfv else "http"
            return proto + "://" + self.headers.get(
                "Host", f"localhost:{puerto}")

        def _html(self, contenido, code: int = 200):
            if isinstance(contenido, str):
                contenido = contenido.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(contenido)

        def _usuario(self) -> str:
            cfg = json.loads(CONFIG.read_text())
            return resolver_usuario(self.headers, cfg)

        def do_GET(self):
            ruta = urlparse(self.path)
            params = parse_qs(ruta.query)
            base = self._base()
            email = self._usuario()
            ip = self.headers.get("Cf-Connecting-Ip", "") or \
                self.client_address[0]
            # autenticado = sesión firmada: el límite por IP es para
            # anónimos/flood — un usuario logueado detrás de NAT
            # compartido (oficina) no debe chocar con sus colegas.
            # Los assets no cuentan: una página con galería son
            # decenas de requests legítimas de imágenes por carga.
            es_asset = re.search(r"\.(?:png|jpe?g|webp|gif|svg|ico|"
                                 r"css|js|woff2?)$", ruta.path, re.I)
            if not email and not es_asset and not ratelimit_ok(ip):
                self._html("<h1 style='font-family:system-ui;padding:2rem'>"
                           "Demasiadas solicitudes — espera un minuto.</h1>"
                           .encode(), 429)
                return
            if ruta.path not in ("/icon.png", "/icon3.png", "/og.png",
                                 "/manifest.webmanifest", "/sw.js"):
                registrar_actividad(
                    email, ruta.path, params.get("u", [""])[0],
                    self.headers.get("Referer", ""), "")
            if not email and ruta.path == "/":
                # anónimo en la raíz: la landing es la cara del producto
                self._html(vista_landing(base))
                return
            if not email and not (
                    ruta.path in ("/icon.png", "/icon3.png", "/og.png",
                                  "/manifest.webmanifest", "/sw.js",
                                  "/instructivo")
                    or ruta.path.startswith("/brand/")):
                # sin sesión: cualquier ruta muestra el login
                self._html(vista_login(base))
                return
            if ruta.path == "/salir":
                self.send_response(303)
                self.send_header("Location", "/")
                self.send_header("Set-Cookie", "s=; Path=/; Max-Age=0")
                self.end_headers()
                return
            if ruta.path == "/":
                self.send_response(303)
                self.send_header(
                    "Location", home_usuario(email))
                self.end_headers()
            elif ruta.path == "/redaccion":
                cfg_r = json.loads(CONFIG.read_text())
                if not email or not ("@demo.local" in email
                                     or es_supervisor(email, cfg_r)
                                     or area_de_usuario(email, cfg_r)):
                    self.send_response(303)
                    self.send_header("Location", "/area")
                    self.end_headers()
                    return
                self._html(render_pagina(
                    vista_redaccion(email), base=base, usuario=email,
                    wide=True,
                    og_title="Redacción — @noticias",
                    og_desc="Feed interno por área de comunicación "
                            "social."))
                _marcar_visto(email, "visto_redaccion")
            elif ruta.path == "/redaccion/nota":
                if not email:
                    self.send_response(303)
                    self.send_header("Location", "/area")
                    self.end_headers()
                    return
                self._html(render_pagina(
                    vista_publicacion(email, params.get("id", [""])[0]),
                    base=base, usuario=email, wide=True,
                    og_title="Nota — @noticias"))
            elif ruta.path == "/redaccion/contador":
                # polling del deck: {"n": nuevas desde la última vista}
                email_c = email
                if not email_c:
                    self.send_response(403)
                    self.end_headers()
                    return
                n = contador_redaccion(
                    email_c, params.get("ctx", ["tablero"])[0])
                self.send_response(200)
                self.send_header("Content-Type",
                                 "application/json; charset=utf-8")
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(json.dumps(
                    {"n": n, "v": version_redaccion()}).encode())
            elif ruta.path == "/asistente/nota":
                email = self._usuario()
                cfg_a = json.loads(CONFIG.read_text())
                if not email or "@demo.local" in email \
                        or not es_supervisor(email, cfg_a):
                    self.send_response(303)
                    self.send_header("Location", "/redaccion")
                    self.end_headers()
                    return
                self._html(render_pagina(
                    vista_nota_ia(email, params.get("id", [""])[0]),
                    base=base, usuario=email))
            elif ruta.path == "/asistente":
                email = self._usuario()
                cfg_a = json.loads(CONFIG.read_text())
                if not email or "@demo.local" in email \
                        or not es_supervisor(email, cfg_a):
                    self.send_response(303)
                    self.send_header("Location", "/redaccion")
                    self.end_headers()
                    return
                self._html(render_pagina(vista_asistente(email),
                                         base=base, usuario=email))
            elif ruta.path == "/redaccion/reporte":
                cfg_r = json.loads(CONFIG.read_text())
                if not email or "@demo.local" in email or not (
                        es_supervisor(email, cfg_r)
                        or area_de_usuario(email, cfg_r)):
                    self.send_response(303)
                    self.send_header("Location", "/area")
                    self.end_headers()
                    return
                try:
                    h = int(params.get("h", ["6"])[0])
                except (ValueError, IndexError):
                    h = 6
                self._html(render_pagina(
                    vista_reporte_redaccion(email, h), base=base,
                    usuario=email, wide=True,
                    og_title="Reporte — @noticias"))
            elif ruta.path == "/bitacora":
                cfg_b = json.loads(CONFIG.read_text())
                if not email or "@demo.local" in email or not (
                        es_supervisor(email, cfg_b)
                        or area_de_usuario(email, cfg_b)):
                    self.send_response(303)
                    self.send_header("Location", "/area")
                    self.end_headers()
                    return
                self._html(render_pagina(
                    vista_bitacora(email), base=base, usuario=email,
                    wide=True, og_title="Bitácora — @noticias"))
            elif ruta.path == "/chat":
                if not email:
                    self.send_response(303)
                    self.send_header("Location", "/area")
                    self.end_headers()
                    return
                self._html(render_pagina(
                    vista_chat(email, params.get("c", ["general"])[0]),
                    base=base, usuario=email, wide=True,
                    og_title="Chat — @noticias"))
            elif ruta.path == "/chat/hilo":
                # polling del chat: JSON con burbujas nuevas
                if not email:
                    self.send_response(403)
                    self.end_headers()
                    return
                d = _chat_hilo_html(
                    params.get("c", ["general"])[0],
                    params.get("desde", ["0"])[0], email)
                body = json.dumps(d, ensure_ascii=False).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            elif ruta.path == "/area":
                if not email or "@demo.local" in email:
                    self.send_response(303)
                    self.send_header("Location", "/area")
                    self.end_headers()
                    return
                self._html(render_pagina(
                    vista_area(email, params.get("v", ["area"])[0],
                               params.get("msg", [""])[0],
                               params.get("a", [""])[0]),
                    base=base, usuario=email, wide=True,
                    og_title="Mi área — @noticias"))
                _marcar_visto(email, "visto_area")
            elif ruta.path.startswith("/media/"):
                # adjuntos de redacción — cualquier usuario logueado
                # (invitados incluidos: es solo lectura del deck)
                if not email:
                    self.send_response(403)
                    self.end_headers()
                    return
                nombre = ruta.path[len("/media/"):]
                fp = (RED_MEDIA / nombre).resolve()
                base_media = RED_MEDIA.resolve()
                if not str(fp).startswith(str(base_media) + "/") \
                        or not fp.is_file():
                    self.send_error(404)
                    return
                ext = fp.suffix.lower()
                self.send_response(200)
                self.send_header("Content-Type",
                                 CTYPE_POR_EXT.get(ext,
                                                  "application/octet-stream"))
                self.send_header("Content-Length", str(fp.stat().st_size))
                self.send_header("Cache-Control",
                                 "private, max-age=86400")
                self.end_headers()
                self.wfile.write(fp.read_bytes())
            elif ruta.path in ("/stats", "/analitica"):
                cfg_g = json.loads(CONFIG.read_text())
                if not es_admin(email, cfg_g):
                    self._html(render_pagina(
                        "<h1>Solo admin</h1>", base=base, usuario=email), 403)
                else:
                    self._html(render_pagina(vista_analitica(), base=base,
                                             usuario=email))
            elif ruta.path == "/usuarios":
                cfg_g = json.loads(CONFIG.read_text())
                if not es_admin(email, cfg_g):
                    self._html(render_pagina(
                        "<h1>Solo admin</h1>", base=base, usuario=email), 403)
                else:
                    self._html(render_pagina(vista_usuarios(email),
                                             base=base, usuario=email))
            elif ruta.path == "/instructivo":
                self._html(vista_instructivo(base))
            elif ruta.path.startswith("/brand/"):
                p = (BASE / ruta.path.lstrip("/")).resolve()
                if p.parent == (BASE / "brand") and p.suffix in (
                        ".jpg", ".jpeg", ".png") and p.exists():
                    self.send_response(200)
                    self.send_header("Content-Type",
                                     "image/jpeg" if p.suffix
                                     in (".jpg", ".jpeg")
                                     else "image/png")
                    self.send_header("Cache-Control",
                                     "public, max-age=86400")
                    self.end_headers()
                    self.wfile.write(p.read_bytes())
                else:
                    self.send_error(404)
            elif ruta.path == "/acerca":
                self._html(render_pagina(vista_acerca(), base=base,
                                         usuario=email))
            elif ruta.path == "/manifest.webmanifest":
                self.send_response(200)
                self.send_header("Content-Type", "application/manifest+json")
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(MANIFEST)
            elif ruta.path == "/sw.js":
                # scope raíz; no-store para que updatefound lo detecte
                self.send_response(200)
                self.send_header("Content-Type",
                                 "application/javascript; charset=utf-8")
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write((BASE / "sw.js").read_bytes())
            elif ruta.path == "/og.png" and OG_PNG.exists():
                self.send_response(200)
                mime_og = "image/jpeg" if OG_PNG.suffix in \
                    (".jpg", ".jpeg") else "image/png"
                self.send_header("Content-Type", mime_og)
                self.send_header("Cache-Control", "public, max-age=86400")
                self.end_headers()
                self.wfile.write(OG_PNG.read_bytes())
            elif ruta.path in ("/icon.png", "/icon3.png"):
                global _ICONO
                if _ICONO is None:
                    # icon3.png horneado con PIL si existe; si no, '@' a mano
                    icono = BASE / "icon3.png"
                    _ICONO = (icono.read_bytes() if icono.exists()
                              else icono_png())
                self.send_response(200)
                self.send_header("Content-Type", "image/png")
                self.send_header("Cache-Control", "public, max-age=86400")
                self.end_headers()
                self.wfile.write(_ICONO)
            else:
                self._html(render_pagina("<h1>404</h1><p>Ruta no existe.</p>",
                                         base=base, usuario=email), 404)

        def do_POST(self):
            ruta = urlparse(self.path)
            ip = self.headers.get("Cf-Connecting-Ip", "") or \
                self.client_address[0]
            # /login: 30/min por IP — la fuerza bruta la frena el bloqueo
            # por cuenta (_login_bloqueado); una IP generosa no asfixia a
            # una oficina compartiendo NAT.
            limite = 30 if ruta.path == "/login" else 120
            if not ratelimit_ok(ip, limite=limite):
                self._html("<h1 style='font-family:system-ui;padding:2rem'>"
                           "Demasiadas solicitudes — espera un minuto.</h1>",
                           429)
                return
            largo = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(largo) if largo else b""
            if ruta.path in ("/publicar", "/bitacora/nota"):
                # multipart (subida de archivos) — no pasa por parse_qs
                email = self._usuario()
                ctype = self.headers.get("Content-Type", "")
                destino = "/redaccion"
                if email and "@demo.local" not in email \
                        and "multipart/form-data" in ctype \
                        and "boundary=" in ctype:
                    boundary = ctype.split("boundary=", 1)[1]\
                        .strip().strip('"')
                    destino = publicar_redaccion(
                        parse_multipart(raw, boundary), email)
                self.send_response(303)
                self.send_header("Location", destino)
                self.end_headers()
                return
            form = parse_qs(raw.decode("utf-8", "replace")) if largo else {}
            https = self._base().startswith("https")

            if ruta.path == "/login":
                cfg = json.loads(CONFIG.read_text())
                email = form.get("email", [""])[0].strip().lower()
                pw = form.get("password", [""])[0]
                if email and _login_bloqueado(email):
                    self._html("<h1 style='font-family:system-ui;"
                               "padding:2rem'>Demasiados intentos en esa "
                               "cuenta — espera unos minutos.</h1>", 429)
                elif email and password_valida(email, pw, cfg):
                    perfil_usuario(email, cfg)  # autocrear en el primer login
                    _RL_FAIL.pop(email, None)
                    # la IP que ya entró con password correcta queda
                    # exenta — el ISP rota la IP pública y el skip-list
                    # de config se queda viejo (429 en login, añejo).
                    # Persiste en disco: cada deploy reinicia el proceso
                    _rl_auto_add(ip)
                    self.send_response(303)
                    self.send_header("Location",
                                     home_usuario(email))
                    self.send_header("Set-Cookie",
                                     cookie_sesion(email, https))
                    self.end_headers()
                else:
                    if email:
                        _login_fallo(email)
                    self._html(vista_login(self._base(),
                                           "Correo o contraseña "
                                           "incorrectos."))
                return
            if ruta.path == "/demo_entrar":
                # acceso rápido sin password — solo con demo_login:true
                cfg_d = json.loads(CONFIG.read_text())
                email = form.get("email", [""])[0].strip().lower()
                usuarios = cargar_usuarios()
                if cfg_d.get("demo_login") and email in usuarios \
                        and "@demo.local" not in email:
                    self.send_response(303)
                    self.send_header("Location", home_usuario(email))
                    self.send_header("Set-Cookie",
                                     cookie_sesion(email, https))
                    self.end_headers()
                else:
                    self._html(vista_login(self._base(),
                                           "Acceso demo no disponible."))
                return
            if ruta.path == "/asistente":
                email = self._usuario()
                cfg_a = json.loads(CONFIG.read_text())
                if not email or "@demo.local" in email \
                        or not es_supervisor(email, cfg_a):
                    self.send_response(303)
                    self.send_header("Location", "/redaccion")
                    self.end_headers()
                    return
                pregunta = (form.get("pregunta") or [""])[0].strip()[:500]
                if pregunta:
                    msgs = _chat_cargar(email)
                    msgs.append({"rol": "q", "texto": pregunta})
                    resp, top = _asistente_responder(pregunta, cfg_a)
                    if top:
                        resp += ("\n\nNotas usadas como contexto:\n"
                                 + "\n".join(
                                     f"- [{p.get('id')}] "
                                     f"{(p.get('titulo') or '')[:70]}"
                                     for p in top))
                    msgs.append({"rol": "a", "texto": resp})
                    _chat_guardar(email, msgs)
                self.send_response(303)
                self.send_header("Location", "/asistente")
                self.end_headers()
                return
            if ruta.path in ("/chat/enviar", "/chat/canal"):
                email = self._usuario()
                if not email:
                    self.send_response(303)
                    self.send_header("Location", "/area")
                    self.end_headers()
                    return
                destino = aplicar_accion_chat(ruta.path, form, email)
                self.send_response(303)
                self.send_header("Location", destino)
                self.end_headers()
                return
            if ruta.path in ("/redaccion/favorito",
                             "/redaccion/asignar",
                             "/redaccion/asignacion",
                             "/redaccion/comentar",
                             "/redaccion/orden",
                             "/redaccion/colapsar",
                             "/bitacora/nuevo",
                             "/bitacora/vincular",
                             "/bitacora/miembro",
                             "/bitacora/resolver",
                             "/redaccion/solicitar",
                             "/redaccion/resolver"):
                email = self._usuario()
                if not email or "@demo.local" in email:
                    self.send_response(303)
                    self.send_header("Location", "/area")
                    self.end_headers()
                    return
                destino = aplicar_accion_redaccion(ruta.path, form, email)
                self.send_response(303)
                self.send_header("Location", destino)
                self.end_headers()
                return
            if ruta.path == "/usuarios":
                email = self._usuario()
                if not email:
                    self.send_response(303)
                    self.send_header("Location", "/")
                    self.end_headers()
                    return
                if not aplicar_accion_usuarios(form, email):
                    self.send_response(403)
                    self.end_headers()
                    return
                self.send_response(303)
                self.send_header("Location", "/usuarios")
                self.end_headers()
            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, *a):
            pass  # silenciar logs de acceso

    # 0.0.0.0 = accesible desde otros dispositivos en la red local
    # (celular, tablet). Sin login todavía: quien tenga la IP puede entrar.
    # ThreadingHTTPServer: atiende varios clientes a la vez (gabinete completo)
    servidor = ThreadingHTTPServer(("0.0.0.0", puerto), Handler)
    print(f"Dashboard: http://localhost:{puerto}\n")
    threading.Thread(target=servidor.serve_forever, daemon=True).start()


def main():
    ap = argparse.ArgumentParser(
        description="@noticias — redacción por áreas (tweetdeck)")
    ap.add_argument("--web", type=int, nargs="?", const=8080, metavar="PUERTO",
                    help="dashboard web en localhost:PUERTO (default 8080)")
    args = ap.parse_args()

    purgar_usuarios()
    usuarios = cargar_usuarios()
    print(f"Usuarios: {len(usuarios)}\n")

    if args.web:
        servir_web(args.web)
        # Solo servidor web: mantener vivo hasta Ctrl+C
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            return 0


if __name__ == "__main__":
    sys.exit(main())
    sys.exit(main())

if __name__ == "__main__":
    sys.exit(main())
    sys.exit(main())
