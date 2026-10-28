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
import smtplib
import socket
import subprocess
import sys
import threading
import time
import random
import unicodedata
from collections import Counter
from datetime import datetime, timedelta
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs, quote, urljoin, unquote
import urllib.robotparser as robotparser

import feedparser
import requests
from PIL import Image, ImageDraw, ImageFont, ImageFilter

socket.setdefaulttimeout(20)  # feedparser no trae timeout; evita que se cuelgue

BASE = Path(__file__).parent
CONFIG = BASE / "config.json"
VISTOS = BASE / "vistos.json"      # enlaces ya procesados (para no repetir alertas)
ALERTAS = BASE / "alertas.jsonl"   # historial de alertas (una por línea, JSON)
NOTICIAS = BASE / "noticias.jsonl" # feed completo: todas las notas capturadas
CLUSTERS = BASE / "clusters.json"  # estado de "noticia en desarrollo"
ESTADO_FUENTES = BASE / "fuentes_estado.json"  # salud por feed (stats)
USUARIOS = BASE / "usuarios.json"    # reglas + fuentes ocultas + expira, por email
ACTIVIDAD = BASE / "actividad.jsonl"  # {ts, email, ruta} por cada página vista
SECRET = BASE / "secret.txt"    # llave HMAC para firmar cookies de sesión
OG_PNG = BASE / "brand" / "02port.jpg"  # tarjeta de preview para compartir links
PORTADAS_DIR = BASE / "portadas"  # PNGs del día + PDFs por sección
ESTADO_PORTADAS = BASE / "portadas_estado.json"  # {"fecha": YYYY-MM-DD}
MAX_NOTICIAS = 2000
RETENCION_DIAS = 0        # 0 = sin purga: conservamos todo el historial
RETENCION_VISTOS_DIAS = 30  # dedupe de enlaces: 30 días evita re-alertas
RETENCION_TXT = (f"{RETENCION_DIAS} días" if RETENCION_DIAS > 0
                 else "sin límite")
VERSION = "0.9.0"


def normalizar(texto: str) -> str:
    """Minúsculas y sin acentos, para que 'Cárdenas' matchee 'cardenas'."""
    texto = texto.lower()
    return "".join(
        c for c in unicodedata.normalize("NFD", texto)
        if unicodedata.category(c) != "Mn"
    )


def _canon_medio(m: str) -> str:
    """Nombre del medio canónico para dedup: 'LatinUS', 'latinus.us' y
    'Latinus' son la misma casa editorial (GN no es consistente)."""
    m = normalizar(m).strip()
    if "." in m:
        m = m.split(".")[0]          # dominio → primer label
    return re.sub(r"[^a-z0-9]", "", m)


def cargar_vistos() -> dict:
    """{link: timestamp}. El formato viejo era una lista de links: se migra."""
    datos = cargar_json(VISTOS, {})
    if isinstance(datos, list):
        return {u: time.time() for u in datos}
    return datos


def guardar_vistos(vistos: dict):
    """Poda vistos a RETENCION_VISTOS_DIAS y tope de 40000 enlaces.
    22/oct: el write NO-atómico truncó el archivo (dedup ciego un día
    entero — notas repetidas a los 3 días); y al ritmo actual
    (~8k/día) el tope 8k hacía que un link 'expirara' en <24h."""
    ahora = time.time()
    limpio = {k: v for k, v in vistos.items()
              if ahora - v < RETENCION_VISTOS_DIAS * 86400}
    if len(limpio) > 40000:
        limpio = dict(list(limpio.items())[-40000:])
    _escribir_json(VISTOS, limpio)


# ---- Multi-tenant: un perfil por usuario autenticado ----

DEMO_HORAS = 24  # demo que REGALA el admin a un correo real (botón)
DEMO_MINUTOS = 5      # la demo abierta /invitado dura esto
DEMO_BLOQUEO_MIN = 60  # la IP no puede pedir otra demo hasta pasar esto
DEMO_IPS = BASE / "demo_ips.json"  # {ip: ts última demo} — cool-down persistente


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
    """Landing del perfil — 'home' en usuarios.json (p. ej. '/interes'
    para quien solo consume la lista judicial). Solo rutas internas."""
    home = (cargar_usuarios().get(email) or {}).get("home", "")
    return home if home.startswith("/") and not home.startswith("//") \
        else "/noticias"


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


def fuentes_visibles(perfil: dict, cfg: dict) -> set:
    """Fuentes que el usuario ve en su feed: todas menos las que ocultó.
    (modelo por exclusión: una fuente nueva del admin aparece sola)
    EXCEPTO 'deportes': esa categoría es opt-in — apagada por default,
    solo entran las que el usuario marcó expresamente."""
    ocultas = set(perfil.get("fuentes_ocultas", []))
    dep_on = set(perfil.get("deportes_visibles", []))
    return {f["nombre"] for f in cfg["fuentes"]
            if f["nombre"] not in ocultas
            and (f.get("categoria") != "deportes"
                 or f["nombre"] in dep_on)}


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


def iso_fecha(entrada) -> str:
    """Fecha de la entrada RSS en ISO; published_parsed si existe.
    published_parsed viene en UTC: calendar.timegm, NO mktime (que lo
    tomaría como hora local y la adelantaría). Fechas futuras se
    recortan a ahora — algunos feeds publican fecha programada."""
    pp = entrada.get("published_parsed") or entrada.get("updated_parsed")
    if pp:
        try:
            ts = calendar.timegm(pp)
            # archivo republicado (SDP/Reforma re-publican notas de
            # 2009): >30 días atrás ensucia 'Por día' y el feed — vale
            # la fecha en que la capturamos, no la original
            if ts > time.time() or ts < time.time() - 30 * 86400:
                ts = time.time()
            return datetime.fromtimestamp(ts).isoformat(
                timespec="seconds")
        except Exception:
            pass
    return datetime.now().isoformat(timespec="seconds")


def fmt_fecha(iso: str) -> str:
    """'2026-09-30T02:41:00' -> '30/09/2026 02:41' — año siempre visible,
    evita confusiones con alertas de otros años."""
    try:
        d = datetime.fromisoformat(iso)
        return d.strftime("%d/%m/%Y %H:%M")
    except Exception:
        return iso[:16]


def purgar():
    """Retención: noticias y alertas solo RETENCION_DIAS días.
    Registros sin fecha parseable se conservan (no borramos a ciegas).
    RETENCION_DIAS <= 0 desactiva la purga por completo."""
    if RETENCION_DIAS <= 0:
        return
    ahora = time.time()
    for path in (NOTICIAS, ALERTAS):
        if not path.exists():
            continue
        limpio = []
        for l in path.read_text().splitlines():
            if not l.strip():
                continue
            try:
                ts = datetime.fromisoformat(json.loads(l)["fecha"]).timestamp()
            except Exception:
                ts = ahora
            if ahora - ts < RETENCION_DIAS * 86400:
                limpio.append(l)
        path.write_text("\n".join(limpio) + ("\n" if limpio else ""))


def registrar_alerta(alerta: dict, cfg: dict):
    """Guarda la alerta en alertas.jsonl, notifica escritorio y manda correo."""
    with ALERTAS.open("a") as f:
        f.write(json.dumps(alerta, ensure_ascii=False) + "\n")
    try:
        subprocess.run(
            ["notify-send", f"ALERTA: {alerta['reglas']}", alerta["titulo"]],
            timeout=5, capture_output=True,
        )
    except Exception:
        pass  # notify-send no está en todos los entornos
    enviar_correo(cfg, alerta)


def guardar_noticia(nota: dict):
    """Guarda cada nota capturada en noticias.jsonl (capped)."""
    with NOTICIAS.open("a") as f:
        f.write(json.dumps(nota, ensure_ascii=False) + "\n")


def _mandar_brevo_api(correo: dict, msg) -> None:
    """Fallback sin IPs autorizadas: POST /v3/smtp/email con api-key.
    Brevo exige IP autorizada para SMTP y UNINET rota la IP pública
    (apagones) → los envíos morían con 525; la API autentica por key.
    300 correos/día en el plan Free — sobra para alertas+PDFs+cierre."""
    key = correo.get("api_key")
    if not key:
        raise RuntimeError("sin correo.api_key para fallback API")
    payload = {"sender": {"email": correo.get("remitente",
                                                 correo["usuario"])},
               "to": [{"email": a.strip()}
                      for a in str(msg["To"]).split(",")],
               "subject": str(msg["Subject"])}
    for p in msg.walk():
        if p.get_content_maintype() == "multipart":
            continue
        if "attachment" in str(p.get("Content-Disposition", "")):
            payload.setdefault("attachment", []).append({
                "name": p.get_filename() or "adjunto",
                "content": base64.b64encode(
                    p.get_payload(decode=True)).decode()})
        elif p.get_content_type() == "text/plain":
            payload["textContent"] = \
                p.get_payload(decode=True).decode("utf-8")
        elif p.get_content_type() == "text/html":
            payload["htmlContent"] = \
                p.get_payload(decode=True).decode("utf-8")
    r = requests.post("https://api.brevo.com/v3/smtp/email",
                      headers={"api-key": key,
                               "Accept": "application/json"},
                      json=payload, timeout=40)
    if r.status_code not in (200, 201):
        raise RuntimeError(
            f"API Brevo {r.status_code}: {r.text[:150]}")


def _mandar_msg(correo: dict, msg, timeout: int = 20):
    """SMTP primero; si falla (525 Unauthorized IP al rotar la IP de
    UNINET en un apagón, timeout, etc.) → API REST de Brevo con
    correo.api_key — no depende de la IP pública."""
    puerto = correo.get("smtp_port", 465)
    try:
        if puerto == 587:   # STARTTLS (Brevo)
            with smtplib.SMTP(correo["smtp_host"], puerto,
                              timeout=timeout) as s:
                s.starttls()
                s.login(correo["usuario"], correo["password"])
                s.send_message(msg)
        else:               # SSL directo (Gmail 465)
            with smtplib.SMTP_SSL(correo["smtp_host"], puerto,
                                  timeout=timeout) as s:
                s.login(correo["usuario"], correo["password"])
                s.send_message(msg)
    except Exception as e:
        print(f"    [correo] SMTP falló ({e}) → intento API Brevo")
        _mandar_brevo_api(correo, msg)


def enviar_correo(cfg: dict, alerta: dict):
    """Manda correo de alerta vía SMTP si está habilitado en config.

    Para Gmail: activa 'contraseña de aplicación' en tu cuenta,
    smtp_host smtp.gmail.com, puerto 465 (SSL).
    """
    correo = cfg.get("correo", {})
    if not correo.get("habilitado"):
        return
    if alerta.get("categoria") == "desarrollo":
        return   # cluster que crece → un correo por ciclo = spam;
                 # es señal de dashboard, no regla del usuario
    # alertas de un usuario van a SU correo; las colectivas a todo el proyecto
    dests = set()
    if alerta.get("usuario") and "@" in alerta["usuario"]:
        dests.add(alerta["usuario"])
    for p in alerta.get("proyectos", []):
        for email in cargar_usuarios():
            if "@" in email and p in proyectos_usuario(email):
                dests.add(email)
    if not dests:
        d = correo.get("destinatario", "")
        if "@" in d:
            dests.add(d)
    if not any("@" in d for d in dests):
        return
    try:
        cuerpo = (
            f"Regla disparada: {alerta['reglas']}\n"
            f"Fuente: {alerta['fuente']}\n"
            f"Fecha: {alerta['fecha']}\n\n"
            f"{alerta['titulo']}\n{alerta['link']}\n\n"
            f"{alerta.get('resumen_ia', '')}"
        )
        msg = MIMEText(cuerpo, "plain", "utf-8")
        msg["Subject"] = f"[Monitor] {alerta['reglas']}: {alerta['titulo'][:80]}"
        msg["From"] = correo.get("remitente", correo["usuario"])
        msg["To"] = ", ".join(sorted(dests))
        _mandar_msg(correo, msg)
        print("    ✉ correo enviado")
    except Exception as e:
        print(f"    [!] correo falló: {e}")


def url_https(url: str) -> str:
    """Sube http→https: evita 'Mixed Content' cuando la página va por TLS."""
    return "https://" + url[7:] if url.startswith("http://") else url


# ---- Rate limit por IP (login fuerza bruta + flood de requests) ----
_RL_HITS: dict = {}
_RL_SKIP_IPS: set = set()
_RL_SKIP_MT: float = 0


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
    if ip in _RL_SKIP_IPS:
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


def url_es_segura(link: str) -> bool:
    """Anti-SSRF: /nota y /captura son públicos y el servidor baja la URL
    que le pongan. Solo http(s) y hosts que resuelvan a IP GLOBAL —
    bloquea localhost, redes privadas (router, NAS), link-local y
    metadatos de nube."""
    try:
        host = urlparse(link).hostname
        if not host or urlparse(link).scheme not in ("http", "https"):
            return False
        return ipaddress.ip_address(socket.gethostbyname(host)).is_global
    except Exception:
        return False


def extraer_imagen(entrada) -> str:
    """Busca imagen en media:content, media:thumbnail, enclosures o el HTML
    del summary. Devuelve URL o ''."""
    for media in entrada.get("media_content", []):
        if media.get("url", "").startswith("http"):
            return media["url"]
    for th in entrada.get("media_thumbnail", []):
        if th.get("url", "").startswith("http"):
            return th["url"]
    for enc in entrada.get("enclosures", []):
        if enc.get("type", "").startswith("image"):
            return enc.get("href") or enc.get("url", "")
    # último recurso: primer <img> en el HTML del resumen/contenido
    for campo in ("summary", "content"):
        html_txt = entrada.get(campo, "")
        if isinstance(html_txt, list):  # content viene como lista
            html_txt = " ".join(c.get("value", "") for c in html_txt)
        m = re.search(r'<img[^>]+src=["\'](http[^"\']+)', html_txt)
        if m:
            return m.group(1)
    return ""


def extraer_og_image(link: str) -> str:
    """Fallback: abre la página de la nota y saca el meta og:image.
    Los RSS de estos medios casi no traen imagen; el og:image sí existe."""
    try:
        r = requests.get(link, timeout=10,
                         headers={"User-Agent": "Mozilla/5.0"})
        m = re.search(
            r'<meta[^>]+property=["\']og:image["\'][^>]+content=["\']([^"\']+)',
            r.text,
        ) or re.search(
            r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+property=["\']og:image["\']',
            r.text,
        )
        if m and m.group(1).startswith("http"):
            return m.group(1)
    except Exception:
        pass
    return ""


def extraer_og_desc(link: str) -> str:
    """og:description de la nota — el lede real. Para columnas cuyo
    resumen RSS es boilerplate ('Templo Mayor 2026-10-09 · Reforma')."""
    try:
        r = requests.get(link, timeout=10,
                         headers={"User-Agent": "Mozilla/5.0"})
        m = re.search(
            r'<meta[^>]+property=["\']og:description["\']'
            r'[^>]+content=["\']([^"\']+)', r.text
        ) or re.search(
            r'<meta[^>]+content=["\']([^"\']+)["\']'
            r'[^>]+property=["\']og:description["\']', r.text)
        if m:
            return re.sub(r"<[^>]+>", "",
                          html.unescape(m.group(1))).strip()
    except Exception:
        pass
    return ""


_RX_CUERPO_NOTA = re.compile(
    r'<(?:div|article|section)[^>]+class=["\'][^"\']*'
    r"(?:post-text|post-content|entry-content|article-body|"
    r"cuerpo-nota|note-body|post-body|content-nota)"
    r'[^"\']*["\'][^>]*>', re.I)


def extraer_lead_html(link: str) -> str:
    """Primer ~400c del cuerpo real de la nota — para fuentes 'html'
    cuyo índice solo entrega el titular y cuyo og:description repite
    el título (TSJ Tabasco). Busca contenedores típicos de body."""
    try:
        r = requests.get(link, timeout=10,
                         headers={"User-Agent": "Mozilla/5.0"})
        m = _RX_CUERPO_NOTA.search(r.text)
        if not m:
            return ""
        # el body empieza tras la etiqueta; 8KB alcanzan para el lead
        txt = re.sub(r"<[^>]+>", " ", r.text[m.end():m.end() + 8192])
        return " ".join(html.unescape(txt).split())[:400]
    except Exception:
        return ""


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


def coincide(texto: str, regla: dict) -> bool:
    """Match flexible: con 3+ términos basta que aparezcan TODOS MENOS
    UNO (la nota 'Pepín López Obrador' alerta la regla 'Ramiro, Obrador,
    Pepin' aunque falte 'Ramiro'). Con 1-2 términos se exigen todos.
    '/' sigue siendo sinónimos dentro de un término."""
    t = normalizar(texto)
    palabras = regla["requiere_todas"]
    hits = sum(1 for p in palabras
               if any(termino_en(normalizar(v), t)
                      for v in p.split("/")))
    min_hits = len(palabras) if len(palabras) <= 2 \
        else len(palabras) - 1
    return hits >= min_hits


def fetch_telegram(canal: str) -> list:
    """Lee los últimos posts de un canal PÚBLICO de Telegram via t.me/s/.
    Devuelve lista de {'link', 'title', 'summary'} igual que un feed RSS."""
    url = f"https://t.me/s/{canal}"
    try:
        r = requests.get(url, timeout=15, headers={"User-Agent": "Mozilla/5.0"})
    except Exception:
        return []
    posts = re.findall(
        r'tgme_widget_message_text[^>]*>(.*?)</div>.*?'
        r'tgme_widget_message_date[^>]*href="(https://t\.me/[^"]+)"',
        r.text, re.S,
    )
    entradas = []
    for texto_html, link in posts:
        texto = re.sub(r"<[^>]+>", " ", texto_html).strip()
        if texto:
            entradas.append({"link": link, "title": texto[:120], "summary": texto})
    return entradas


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


def resumir_ollama(cfg: dict, titulo: str, resumen: str) -> str:
    """Pide al LLM un resumen de una línea (opcional, --resumir)."""
    prompt = (
        "Resume en una sola frase en español esta noticia. "
        "Solo el resumen, sin comillas ni introducción.\n\n"
        f"Título: {titulo}\nTexto: {resumen[:1500]}"
    )
    return _llm(cfg, prompt, timeout=120)


def resumir_ollama_seguro(cfg, titulo, resumen) -> str:
    """resumir_ollama con guard de memoria: evita cargar llama3.2 con
    RAM al límite (el NUC se congeló así). Devuelve "" si no hay margen.
    Con Gemini configurado el guard no aplica — la API no usa RAM."""
    if not _gemini_key(cfg) and _mem_disponible_gb() < 4:
        return ""
    return resumir_ollama(cfg, titulo, resumen)


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


def _norm_titulo(t: str) -> set:
    """Tokens del título sin acentos/puntuación — base del dedup de
    notas repetidas (el mismo suceso redactado distinto por cada
    medio)."""
    import unicodedata
    t = unicodedata.normalize("NFKD", t or "")
    t = "".join(c for c in t if not unicodedata.combining(c))
    return set(re.sub(r"[^a-z0-9]+", " ", t.lower()).split())


def _dedup_notas(notas: list, umbral: float = 0.7) -> list:
    """Quita notas cuyo título traslape ≥`umbral` (Jaccard) con otra ya
    aceptada — la misma nota en 4 medios entraba 4 veces a la
    síntesis."""
    vistos, out = [], []
    for n in notas:
        toks = _norm_titulo(n.get("titulo", ""))
        if toks and any(len(toks & v) / max(len(toks | v), 1) >= umbral
                        for v in vistos):
            continue
        vistos.append(toks)
        out.append(n)
    return out


def _prio_interes(n: dict) -> int:
    """Jerarquía del usuario (15/oct): 1º Reséndez Y todo el Poder
    Judicial de Tabasco (TSJT, magistrados, juzgados, actores de la
    lista); 2º Javier May y actividades de gobierno; 3º el resto.
    Ordena [N#] y guía al modelo al protagonista."""
    t = normalizar(n["titulo"] + " " + (n.get("resumen") or ""))
    if re.search(r"resendez|magistrad[oa]\s+presidente", t):
        return 0
    # poder judicial Tabasco: siglas, institución y nombres de la
    # lista de interés — 'fiscalía' NO: es órgano del ejecutivo
    if re.search(r"\btsjt?\b|poder judicial|tribunal superior|"
                 r"consejo de la judicatura|judicatura|juzgad|"
                 r"magistrad|sindicato del tribunal|"
                 r"voluntariado del tribunal|oficial mayor|"
                 r"osfe|\btet\b|balcazar|donaciano|quen|"
                 r"rabago|orrico|garcia mollinedo|german garcia|"
                 r"glori|paola hernandez", t):
        return 1
    # gobierno del estado: gobernador, palacio, municipios
    if re.search(r"javier may|gobernador|gobierno del estado|"
                 r"palacio de gobierno|secretaria de gobierno|"
                 r"gobierno de tabasco|ayuntamiento|municipal|"
                 r"fiscal[ií]a|\bsspc\b", t):
        return 2
    return 3


def generar_sintesis(cfg: dict, franja: str) -> str:
    """Síntesis ejecutiva de la franja (Gemini API → Ollama fallback):
    'matutina' cubre 21:00 de ayer → 09:00; 'vespertina' 09:00 →
    15:00; 'nocturna' 15:00 → 21:00. Solo notas de la lista de
    interés judicial (tope ~60 para no reventar el contexto del 3B)."""
    if not _gemini_key(cfg) and _mem_disponible_gb() < 4:
        return ""   # sin margen para el modelo — reintenta en otro ciclo
    ahora = datetime.now()
    if franja == "matutina":
        desde = (ahora - timedelta(days=1)).replace(
            hour=21, minute=0, second=0)
    elif franja == "mediodia":
        # desde el cierre del día anterior — cubre noche + mañana
        desde = (ahora - timedelta(days=1)).replace(
            hour=17, minute=0, second=0)
    elif franja == "nocturna":
        desde = ahora.replace(hour=15, minute=0, second=0)
    elif franja in ("semanal", "dominical"):
        # sábado/domingo → cubre la semana en curso: lunes 00:00
        desde = (ahora - timedelta(days=ahora.weekday())).replace(
            hour=0, minute=0, second=0)
    else:   # vespertina
        desde = ahora.replace(hour=9, minute=0, second=0)
    # la semanal junta 6 días de material — doble de notas que una
    # franja diaria (llama3.2 lo tolera con títulos, no con resúmenes)
    sel = _sel_interes_extendida(
        desde, limite=150 if franja in ("semanal", "dominical") else 60)
    if not sel:
        return ""
    if franja in ("semanal", "dominical"):
        # recirculaciones GN: el feed reporta fecha de RE-indexación,
        # no la de publicación real — una nota de julio/2025 no puede
        # colarse al reporte de esta semana. Solo se verifican las que
        # llegaron vía Google News (RSS propio trae pubDate real)
        lim_dia = desde.strftime("%Y-%m-%d")
        verif = []
        for n in sel:
            if "GN" not in (n.get("via") or ""):
                verif.append(n)
                continue
            fr_ = _fecha_real_pagina(n["link"])
            if fr_ and fr_[:10] < lim_dia:
                print(f"[sintesis] recirculación GN descartada "
                      f"({fr_[:10]}): {n['titulo'][:60]}")
                continue
            verif.append(n)
        sel = verif
        if not sel:
            return ""
    # jerarquía institucional: numerar [N#] en ese orden guía al
    # modelo a escribir por relevancia — Reséndez siempre arriba
    sel.sort(key=_prio_interes)
    if franja == "dominical":
        # análisis del tema rector de la semana: se toma el tier más
        # alto con material (Reséndez siempre si hubo; si no, cae al
        # siguiente — fallback explícito, nunca fuerza un texto vacío)
        mejor = _prio_interes(sel[0])
        sel = [n for n in sel if _prio_interes(n) == mejor][:30]
    lineas = "\n".join(
        f"- [N{i+1}|{n.get('categoria', '')}|{n['fuente']}] "
        f"{n['titulo']}"
        + (f" — {n['resumen'][:280]}" if n.get("resumen") else "")
        for i, n in enumerate(sel))
    nombre = {"matutina": "matutina (lo ocurrido desde ayer 21:00)",
              "mediodia": "de mediodía (desde ayer 17:00 "
                          "hasta hoy al mediodía)",
              "vespertina": "vespertina (hoy 09:00 a 15:00)",
              "semanal": "SEMANAL — balance de la semana "
                          "(lunes a hoy sábado al mediodía)",
              "nocturna": "nocturna — cierre del día "
                          "(hoy 15:00 a 21:00)"}.get(
                  franja, franja)
    if franja == "dominical":
        prompt = (
            "Eres el analista político-judicial del Poder Judicial del "
            "Estado de Tabasco. Escribe un ANÁLISIS DOMINICAL: la "
            "lectura editorial de fin de semana sobre el tema rector "
            "que muestran estas notas de la semana (prioridad siempre "
            "al Magistrado Presidente Efraín Reséndez y al TSJT).\n"
            "Formato exacto, con estos subtítulos en mayúsculas:\n"
            "- EL TEMA: qué pasó esta semana, en un párrafo.\n"
            "- LA SITUACIÓN: contexto y actores involucrados, según "
            "las notas.\n"
            "- A FAVOR / EN CONTRA: fuerzas, lecturas o bandos que se "
            "observan en la cobertura (si aplica).\n"
            "- QUÉ OBSERVAR: qué viene o qué se debe vigilar la "
            "próxima semana.\n"
            "- PROFUNDIDAD: reporte enriquecido — desarrolla cada "
            "sección con el detalle que permita el material (varios "
            "párrafos por sección si hay suficientes notas); cruza "
            "actores, fechas y hechos entre notas distintas.\n"
            "- REGLA DURA: usa SOLO los hechos literales de las notas. "
            "PROHIBIDO inventar citas, cifras, nombres o hechos. Si un "
            "subtítulo no tiene material real, omítelo.\n"
            "- Cada párrafo cierra con [N#] de la nota que lo "
            "sustenta. Sin introducción ni despedida.\n\n" + lineas)
    else:
        prompt = (
        "Eres el analista de comunicación social del Poder Judicial del "
        "Estado de Tabasco. Redacta la SÍNTESIS EJECUTIVA " + nombre +
        " con estas notas, al estilo de un reporte profesional de "
        "monitoreo de medios. Formato exacto:\n"
        "- Subtítulos de sección en mayúsculas, en este orden y solo si "
        "hay material REAL en las notas: PODER JUDICIAL DE TABASCO, "
        "JUSTICIA Y SEGURIDAD EN TABASCO, COLUMNAS Y OPINIÓN, "
        "REDES SOCIALES (esta última para notas con categoria "
        "'redes' o 'x' — cita quién publicó y de qué habla).\n"
        "- Bajo cada sección, UN bullet '•' por cada nota o tema "
        "distinto — no agrupes varias notas en un bullet ni repitas la "
        "misma en dos secciones. Cada bullet lleva el dato concreto: "
        "quién, qué y dónde (nombre del actor y municipio/sala si "
        "aparece). 'Dónde' es el lugar del hecho, NUNCA la sede del "
        "medio que publica. 2-3 líneas máximo por bullet.\n"
        "- Cada bullet TERMINA con el identificador de la nota que lo "
        "sustenta: [N#]. Si un tema junta varias notas, usa la "
        "principal.\n"
        "- PRIORIDAD de agenda: primero lo del Magistrado Presidente "
        "del TSJT (Efraín Reséndez) y del Poder Judicial del Estado; "
        "después el Gobernador (Javier May); luego el resto.\n"
        + (
            "- SEMANAL: la sección PODER JUDICIAL DE TABASCO abre con "
            "un párrafo 'Destaque de la semana' que resume en 3-4 "
            "líneas las actividades del Magistrado Presidente Efraín "
            "Reséndez y del TSJT; los bullets siguen después.\n"
            if franja == "semanal" else "")
        + "- REGLA DURA: usa SOLO los hechos literales de las notas. "
        "PROHIBIDO inventar citas textuales, usuarios de redes "
        "(@alguien), cifras, nombres o hechos. No escribas 'no se "
        "tienen noticias' — si una sección no tiene material, omítela.\n"
        "- Sin introducción ni cierre.\n\n" + lineas)
    texto = _llm(cfg, prompt, timeout=480)
    if not texto or texto.startswith("(no se pudo"):
        return ""
    # perspectiva nacional-vs-Tabasco: la vespertina cierra el medio
    # día — el post del poli sale de aquí; el cierre nocturno genera
    # la suya aparte
    perspectiva = ""
    if franja == "vespertina":
        try:
            perspectiva = _perspectiva_dia(cfg, ahora)
        except Exception as exc:
            print(f"[síntesis] perspectiva falló ({exc})")
    with SINTESIS.open("a") as f:
        f.write(json.dumps({
            "fecha": ahora.isoformat(timespec="seconds"),
            "franja": franja, "texto": texto,
            "perspectiva": perspectiva,
            "n_notas": len(sel),
            "notas": [{"f": n.get("fuente", ""),
                       "t": n.get("titulo", ""),
                       "u": n.get("link", "")} for n in sel]},
            ensure_ascii=False) + "\n")
    _poda_sintesis()           # la nueva desbanca a la anterior
    return texto


def _perspectiva_dia(cfg: dict, ahora: datetime) -> str:
    """'Perspectiva' para @elpolidelanoche: el LLM elige la nota de
    mayor impacto nacional vs la de mayor impacto en Tabasco y las
    contrasta en un post ≤280 — voz de observador externo (sin firma
    institucional). El Jaccard de titulares no sirve aquí: cada medio
    redacta distinto la misma historia, así que la selección de
    'impacto' la hace el modelo leyendo la agenda del día."""
    # ventana 24h: historias de ayer que siguen vigentes compiten —
    # el modelo ve la fecha de cada titular y valora continuidad
    desde = (ahora - timedelta(hours=24)).isoformat()
    notas = [n for n in _noticias_cache()
             if n.get("fecha", "") >= desde]
    # piezas fijas no son 'impacto': crucigramas, programas diarios,
    # columnas firmadas, parte meteorológico — y timestamps crudos
    # que el scraper traga como título ("hace aproximadamente...")
    fijo = re.compile(
        r"crucigrama|hor[oó]scopo|sudoku|cartelera|jugar|loter[ií]a|"
        r"latinus|programaci[oó]n|dosis|editorial del d[ií]a|escribe|"
        r"chubascos|pron[oó]stico|onda tropical|clima|frente fr[ií]o|"
        r"lluvia|pasarela|concierto|festival|"
        r"mlb|nfl|liga|liga mx|serie mundial|deport|remonta|f[uú]tbol|"
        r"^(hace |aproximadamente|hace \d)")

    def _agenda(cats, tope):
        pool = [n for n in notas
                if n.get("categoria") in cats
                and not fijo.search(normalizar(n.get("titulo", "")))]
        pool = _dedup_notas(pool)
        # cobertura: cuántos tokens del titular aparecen en otros
        # titulares del pool — la nota grande la republican varios
        # medios con redacciones distintas (bloqueo, imss, paseo...);
        # una agenda de nota única puntúa bajo
        df = {}
        toks = []
        for n in pool:
            t = {w for w in normalizar(n.get("titulo", "")).split()
                 if len(w) >= 5}
            toks.append(t)
            for w in t:
                df[w] = df.get(w, 0) + 1
        cub = [sum(1 for w in t if df[w] >= 3) for t in toks]
        # bonus institucional: el núcleo del producto es judicial
        # (tsjt, poder judicial, fiscalía); 'efraín' solo suma con
        # contexto judicial — el técnico de Pumas también se llama
        # Efraín Juárez y está en la agenda nacional
        inst = re.compile(
            r"tsjt|tribunal|poder judicial|fiscal[ií]a|iepc|magistrad")
        efr = re.compile(r"efra[ií]n")
        for i, n in enumerate(pool):
            nt = normalizar(n.get("titulo", ""))
            if inst.search(nt):
                cub[i] += 3 + (2 if efr.search(nt) else 0)
        # sort estable: pre-orden por fecha conserva 'reciente
        # primero' dentro del mismo score de cobertura
        par = sorted(zip(cub, pool),
                     key=lambda c: c[1].get("fecha", ""), reverse=True)
        par.sort(key=lambda c: -c[0])
        pool = [p for _, p in par]
        # reparto por bloques de 6 h: con cientos de notas al día,
        # un corte de 'más recientes' nunca llega a la historia de
        # ayer que sigue vigente — cada bloque aporta su agenda y
        # el modelo decide el impacto con la fecha a la vista
        por_bloque = max(4, tope // 4)
        vistos_b = {}
        sel = []
        for n in pool:
            try:
                b = int((ahora - datetime.fromisoformat(
                    n["fecha"])).total_seconds() // 21600)
            except ValueError:
                b = 0
            if vistos_b.get(b, 0) >= por_bloque:
                continue
            vistos_b[b] = vistos_b.get(b, 0) + 1
            sel.append(n)
            if len(sel) >= tope:
                break
        sel.sort(key=lambda n: n.get("fecha", ""), reverse=True)
        return "\n".join(
            f"- [{n['fecha'][5:16].replace('T', ' ')}] {n['titulo']}"
            for n in sel)

    ag_nac = _agenda({"nacional", "internacional"}, 24)
    # Tabasco real: solo prensa local + voceros oficiales —
    # quintana_roo trae cable/farándula genérico y seguimiento
    # mete scraps de perfiles (hasta timestamps como titular)
    ag_reg = _agenda({"prensa", "oficial"}, 28)
    if not ag_nac or not ag_reg:
        return ""
    txt = _llm(cfg,
               "Escribe UN post de X (máximo 270 caracteres) para una "
               "cuenta de observación política independiente. De las "
               "listas de titulares de las últimas 24 h (cada uno con "
               "su fecha), elige UNA noticia de mayor impacto nacional "
               "y UNA de mayor impacto en Tabasco — descarta "
               "pronósticos, deportes y piezas de opinión; una historia "
               "de ayer que sigue activa vale como continuidad de la "
               "agenda de hoy. Contrástalas: qué acapara allá vs "
               "aquí.\n\n"
               "TITULARES NACIONALES/INTERNACIONALES:\n" + ag_nac +
               "\n\nTITULARES TABASCO:\n" + ag_reg + "\n\n"
               "Reglas: tono de analista sobrio, tercera persona, sin "
               "emojis, sin hashtags, sin firmas ni @menciones, sin "
               "inventar datos que no estén en los titulares. Devuelve "
               "SOLO el post.",
               timeout=240)
    txt = re.sub(r'^["\']|["\']$', "", txt.strip())
    if len(txt) > 280:
        txt = txt[:277].rsplit(" ", 1)[0] + "…"
    return txt


def _sel_interes_extendida(desde: datetime, limite: int = 60) -> list:
    """Notas de la lista de interés desde 'desde', deduplicadas; si hay
    <5 la ventana se extiende hacia atrás (72 h máx.) para no salir
    vaga — misma regla para síntesis y monólogo."""
    sel = _dedup_notas(
        [n for n in _noticias_cache()
         if n.get("fecha", "") >= desde.isoformat()
         and coincide_interes(n)])[:limite]
    intentos = 0
    while len(sel) < 5 and intentos < 6:
        intentos += 1
        desde = desde - timedelta(hours=12)
        sel = _dedup_notas(
            [n for n in _noticias_cache()
             if n.get("fecha", "") >= desde.isoformat()
             and coincide_interes(n)])[:limite]
    # posts de redes que DISPARARON alguna regla (alertas.jsonl) entran
    # a la selección aunque no sean de interés judicial — la síntesis
    # puede citar al menos uno cuando hay ruido social relevante
    alertados = {a["link"] for a in leer_jsonl(ALERTAS)
                 if a.get("fecha", "") >= desde.isoformat()}
    if alertados:
        en_sel = {n["link"] for n in sel}
        sel += [n for n in _noticias_cache()
                if n.get("categoria") in ("redes", "x")
                and n["link"] in alertados
                and n["link"] not in en_sel
                # ancla local — 'noticia en desarrollo' nacional
                # (Macron/Francia) no sirve al reporte del TSJT
                and ("tabasco" in normalizar(
                    n["titulo"] + " " + (n.get("resumen") or ""))
                    or coincide_interes(n))
                and n.get("fecha", "") >= desde.isoformat()][:4]
    return sel


_GENERANDO = set()          # franjas con Ollama corriendo ahora


def _poda_sintesis():
    """Deja solo la entrada más reciente por franja — sin archivo
    histórico: máximo 4 tarjetas (matutina, vespertina, nocturna,
    cierre), siempre la última de cada una."""
    if not SINTESIS.exists():
        return
    mejor = {}
    for l in SINTESIS.read_text(encoding="utf-8").splitlines():
        try:
            e = json.loads(l)
        except Exception:
            continue
        f = e.get("franja", "")
        if f not in mejor or e.get("fecha", "") > mejor[f][0]:
            mejor[f] = (e.get("fecha", ""), l)
    out = sorted((p[1] for p in mejor.values()),
                 key=lambda l: json.loads(l).get("fecha", ""))
    SINTESIS.write_text("\n".join(out) + "\n", encoding="utf-8")


def _gen_bg(fn, key: str, *args):
    """Wrapper del hilo de generación — quita el flag al terminar
    (éxito o excepción) para que el botón se rehabilite solo."""
    try:
        fn(*args)
    finally:
        _GENERANDO.discard(key)


def generar_cierre(cfg: dict) -> str:
    """CIERRE DIARIO — solo on-demand (botón admin, /resumenes).
    Monólogo de host repasando lo de interés del día; cada segmento
    cierra con [N#] → misma trazabilidad que la síntesis."""
    if not _gemini_key(cfg) and _mem_disponible_gb() < 4:
        print("[cierre] RAM insuficiente para ollama — se omite")
        return ""
    ahora = datetime.now()
    sel = sorted(_sel_interes_extendida(ahora.replace(
        hour=0, minute=0, second=0)),
        key=_prio_interes)[:15]   # Reséndez entra aunque haya >15
    if not sel:
        print("[cierre] sin notas de interés hoy — abortado")
        return ""
    lineas = "\n".join(
        f"- [N{i+1}|{n.get('categoria', '')}|{n['fuente']}] "
        f"{n['titulo']}"
        + (f" — {n['resumen'][:280]}" if n.get("resumen") else "")
        for i, n in enumerate(sel))
    prompt = (
        "Eres el redactor de comunicación social del Poder Judicial de "
        "Tabasco. Escribe la TARJETA DE DISCURSO de cierre del día: el "
        "briefing que un vocero usaría para informar a su superior lo "
        "relevante del día, usando SOLO estas notas:\n" + lineas + "\n\n"
        "Reglas:\n"
        "- Tono: institucional e impersonal — tercera persona siempre; "
        "cero 'yo', cero saludos, cero despedidas de conductor, cero "
        "preguntas retóricas.\n"
        "- Estilo: informe asertivo que expone hechos y resalta la "
        "labor de las instituciones y sus titulares; frases que un "
        "vocero pueda leer textualmente ante un superior.\n"
        "- TITULAR: si entre las notas hay actividad del Magistrado "
        "Presidente Efraín Reséndez Bocanegra o del Tribunal Superior "
        "de Justicia, el briefing ABRE con ella — es el tema rector "
        "del día, no un punto más.\n"
        "- PROHIBIDAS las acotaciones escénicas: nada de (risas), "
        "(aplausos), (pausa) ni similares.\n"
        "- PROHIBIDO inventar datos, citas, cifras o personajes que no "
        "estén en las notas.\n"
        "- De 6 a 10 segmentos, párrafos cortos de 2-3 líneas.\n"
        "- Si hay notas de categoria 'redes' o 'x' (publicaciones en "
        "Facebook/X), reserva UN segmento para la más relevante, "
        "citando quién publicó.\n"
        "- Cierra cada segmento con [N#] — el número de la nota que lo "
        "justifica.\n"
        "- Sin títulos ni subtítulos: texto continuo de briefing. "
        "Termina con un cierre sobrio de una línea, sin despedida "
        "personal."
    )
    texto = _llm(cfg, prompt, timeout=480)
    if not texto or texto.startswith("(no se pudo"):
        print("[cierre] respuesta vacía del LLM")
        return ""
    # versión para X: la CONCLUSIÓN de la tarjeta adaptada a un post
    # ≤280 (el primer post real salió así y es el formato deseado) —
    # el modelo sigue caliente (KEEP_ALIVE), costo ~2s
    post_x = ""
    try:
        post_x = _llm(cfg,
                      "Este briefing institucional termina con una "
                      "conclusión ('En conclusion…' o similar). "
                      "Reescríbela como UN post de X de máximo "
                      "270 caracteres: tono sobrio, tercera "
                      "persona, sin hashtags inventados, sin "
                      "emojis, sin nombres que no estén en el "
                      "texto. Si menciona al Poder Judicial del "
                      "Estado de Tabasco, firma @tsj_tabasco. "
                      "Devuelve SOLO el post, nada más.\n\n"
                      + texto[-2500:],
                      timeout=240)
        post_x = re.sub(r'^["\']|["\']$', "", post_x.strip())
        if len(post_x) > 280:
            post_x = post_x[:277].rsplit(" ", 1)[0] + "…"
    except Exception as exc:
        print(f"[cierre] post_x falló ({exc}) — no se guarda")
        post_x = ""
    try:
        perspectiva = _perspectiva_dia(cfg, ahora)
    except Exception as exc:
        print(f"[cierre] perspectiva falló ({exc})")
        perspectiva = ""
    with open(SINTESIS, "a", encoding="utf-8") as f:
        print(f"[cierre] guardado — {len(texto)} chars")
        f.write(json.dumps(
            {"fecha": ahora.isoformat(timespec="seconds"),
             "franja": "cierre", "texto": texto,
             "post_x": post_x, "perspectiva": perspectiva,
             "n_notas": len(sel),
             "notas": [{"f": n.get("fuente", ""),
                        "t": n.get("titulo", ""),
                        "u": n.get("link", "")} for n in sel]},
            ensure_ascii=False) + "\n")
    _poda_sintesis()           # la nueva desbanca a la anterior
    return texto


# reporte express: un proceso por usuario, cancelable desde la UI
_REPORTE_EXPRESS = {}


def _worker_reporte_express(email: str, cfg: dict):
    """Hilo del reporte: el usuario pudo cancelar a media generación —
    si la marca ya está puesta al terminar el LLM, el PDF se desecha."""
    st = _REPORTE_EXPRESS.setdefault(
        email, {"estado": "generando", "pdf": None})
    try:
        texto = generar_reporte_express(cfg)
        if st.get("estado") == "cancelado":
            return
        if not texto:
            st["estado"] = "error"
            return
        ahora_r = datetime.now()
        st["pdf"] = _texto_pdf(
            "Reporte express — monitoreo de medios",
            ahora_r.strftime("%d/%m/%Y · %H:%M h"), texto)
        if st.get("estado") == "cancelado":
            st["pdf"] = None
            return
        st["estado"] = "listo"
    except Exception as e:
        print(f"[reporte-express] {email}: {e}")
        st["estado"] = "error"


def _vista_reporte_progreso(estado: str) -> str:
    """Pantalla de espera con spinner + cancelar; el JS consulta el
    estado y salta a la descarga cuando el PDF está listo."""
    return (
        "<style>.spin{width:36px;height:36px;border:4px solid #1a237e33;"
        "border-top-color:#1a237e;border-radius:50%;"
        "animation:spin 1s linear infinite;margin:0 auto}</style>"
        "<div class='card' style='text-align:center;padding:2.5rem'>"
        "<div class='spin'></div>"
        "<h1 style='margin-top:1rem'>Generando reporte express…</h1>"
        "<p class='meta'>El modelo redacta el informe con la "
        "información capturada hasta ahora — puede tardar ~1 min.</p>"
        "<a href='/resumenes-pdf?op=cancelar'>"
        "<button class='btn-linea'>Cancelar</button></a></div>"
        "<script>setInterval(function(){"
        "fetch('/resumenes-pdf?op=estado').then(r=>r.json())"
        ".then(function(d){"
        " if(d.e==='listo'){location='/resumenes-pdf?op=descargar'}"
        " else if(d.e==='error'){location='/resumenes?msg='"
        "   +encodeURIComponent('No se pudo generar — sin material o "
        "el modelo no respondió.')}"
        " else if(d.e==='cancelado'){location='/resumenes'}"
        "})},2000);</script>")


def generar_reporte_express(cfg: dict) -> str:
    """REPORTE EXPRESS — on-demand, a la hora en que se pide. El LLM
    escribe un informe breve e imprimible con la info del día hasta
    ese momento (notas de interés + síntesis ya generadas)."""
    ahora = datetime.now()
    sel = sorted(_sel_interes_extendida(ahora.replace(
        hour=0, minute=0, second=0)),
        key=_prio_interes)[:15]
    hoy = ahora.strftime("%Y-%m-%d")
    sint_hoy = [e for e in leer_jsonl(SINTESIS)
                if e.get("fecha", "").startswith(hoy)]
    if not sel and not sint_hoy:
        return ""
    lineas = "\n".join(
        f"- [N{i+1}|{n.get('categoria', '')}|{n['fuente']}] "
        f"{n['titulo']}"
        + (f" — {n['resumen'][:280]}" if n.get("resumen") else "")
        for i, n in enumerate(sel))
    bloque_s = "\n".join(
        f"· {e.get('franja', '').upper()} "
        f"({e.get('fecha', '')[11:16]}): "
        f"{e.get('texto', '')[:900]}" for e in sint_hoy)
    prompt = (
        "Eres el redactor de comunicación social del Poder Judicial de "
        f"Tabasco. Son las {ahora.strftime('%H:%M')} — escribe un "
        "REPORTE EXPRESS imprimible de media a una cuartilla: el estado "
        "del monitoreo de medios a esta hora, usando SOLO este "
        "material:\n\n"
        "NOTAS DE INTERÉS DE HOY:\n" + (lineas or "(ninguna)") +
        "\n\nSÍNTESIS YA GENERADAS HOY:\n" + (bloque_s or "(ninguna)") +
        "\n\nReglas:\n"
        "- Tono: informe institucional, tercera persona, sin saludos "
        "ni despedidas.\n"
        "- Estructura: 1 párrafo de panorama, luego hasta 5 puntos "
        "con lo relevante (los del TSJ/Reséndez primero), y una línea "
        "final de vigilancia ('se continuará el monitoreo de…').\n"
        "- PROHIBIDO inventar datos, citas, cifras o nombres que no "
        "estén en el material.\n"
        "- Marca entre corchetes la hora de publicación cuando la "
        "sepa la síntesis; sin etiquetas [N#] en el texto final.\n"
        "- Sin títulos ni subtítulos dentro del cuerpo — el "
        "encabezado lo pone el PDF.")
    texto = _llm(cfg, prompt, timeout=480)
    if not texto or texto.startswith("(no se pudo"):
        return ""
    return texto


def _texto_pdf(titulo: str, subtitulo: str, cuerpo: str) -> bytes:
    """Texto → PDF multipágina con PIL/DejaVu (~A4 a 150dpi). El
    mismo truco imgs[0].save(PDF, save_all) del PDF de portadas."""
    from PIL import ImageDraw, ImageFont
    W, H, MX, MY = 1240, 1754, 90, 80
    _FD = "/usr/share/fonts/truetype/dejavu/"
    f_t = ImageFont.truetype(_FD + "DejaVuSans-Bold.ttf", 44)
    f_s = ImageFont.truetype(_FD + "DejaVuSans.ttf", 26)
    f_b = ImageFont.truetype(_FD + "DejaVuSans.ttf", 28)

    def _pagina():
        im = Image.new("RGB", (W, H), "#ffffff")
        return im, ImageDraw.Draw(im)

    def _wrap(draw, texto, font, ancho):
        for par in texto.split("\n"):
            if not par.strip():
                yield None            # salto de párrafo
                continue
            linea = ""
            for pal in par.split():
                prueba = (linea + " " + pal).strip()
                if draw.textlength(prueba, font=font) <= ancho:
                    linea = prueba
                else:
                    yield linea
                    linea = pal
            yield linea

    paginas = []
    im, draw = _pagina()
    y = MY
    draw.text((MX, y), titulo, font=f_t, fill="#1a237e")
    y += 62
    draw.text((MX, y), subtitulo, font=f_s, fill="#555555")
    y += 52
    draw.line((MX, y, W - MX, y), fill="#1a237e", width=3)
    y += 30
    for linea in _wrap(draw, cuerpo, f_b, W - 2 * MX):
        if linea is None:
            y += 22
            continue
        if y > H - MY - 40:
            paginas.append(im)
            im, draw = _pagina()
            y = MY
        draw.text((MX, y), linea, font=f_b, fill="#222222")
        y += 40
    paginas.append(im)
    buf = io.BytesIO()
    paginas[0].save(buf, "PDF", save_all=True,
                    append_images=paginas[1:], title=titulo,
                    author="@noticias", creator="Olmeca Code")
    for im in paginas:
        im.close()
    return buf.getvalue()


def enviar_cierre_mail(cfg: dict, texto_cierre: str):
    """Correo del cierre del día (programado 17:00): el briefing más
    la síntesis de mediodía — el día completo."""
    correo = cfg.get("correo", {})
    if not correo.get("habilitado"):
        return
    dests = set()
    d = correo.get("destinatario", "")
    if "@" in d:
        dests.add(d)
    for a in cfg.get("admins", []):
        if "@" in a:
            dests.add(a)
    for email in cargar_usuarios():
        if "@" in email and not email.endswith("@demo.local") \
                and proyectos_usuario(email):
            dests.add(email)
    if not dests:
        return
    ultimas = {}
    for e in leer_jsonl(SINTESIS):
        if e.get("franja") == "mediodia":
            ultimas[e["franja"]] = e
    partes = [f"CIERRE DEL DÍA — {datetime.now():%d/%m/%Y %H:%M}",
              "=" * 52, "", texto_cierre]
    for fr in ("mediodia",):
        e = ultimas.get(fr)
        if not e:
            continue
        partes += ["", "=" * 52,
                   f"SÍNTESIS {fr.upper()} — {e['fecha'][:16]}",
                   "=" * 52, "", e.get("texto", "")]
    try:
        msg = MIMEText("\n".join(partes), "plain", "utf-8")
        msg["Subject"] = (f"[Monitor] Cierre del día "
                          f"{datetime.now():%d/%m/%Y}")
        msg["From"] = correo.get("remitente", correo["usuario"])
        msg["To"] = ", ".join(sorted(dests))
        _mandar_msg(correo, msg)
        print("[cierre] ✉ mail enviado")
    except Exception as e:
        print(f"[cierre] mail falló: {e}")


def _cierre_programado(cfg: dict) -> str:
    """Cierre automático de las 21:03 = generar + mail. El botón
    manual llama generar_cierre directo — sin mail (re-pruebas)."""
    texto = generar_cierre(cfg)
    if texto:
        enviar_cierre_mail(cfg, texto)
    return texto


def toca_sintesis(franja: str) -> bool:
    """True si pasó la hora de la franja y aún no hay síntesis de hoy."""
    ahora = datetime.now()
    # CANON: lun-vie → digests matutina 09:00 / vespertina 15:00 /
    # nocturna 21:00 (concentrado fiel de lo publicado, imprimible)
    # + análisis mediodía 12:00 y cierre 17:00; sábado → solo
    # semanal 12:00; domingo → solo análisis dominical 10:00.
    hora = {"matutina": 9 * 60, "mediodia": 12 * 60,
            "vespertina": 15 * 60, "cierre": 17 * 60,
            "nocturna": 21 * 60,
            "semanal": 12 * 60, "dominical": 10 * 60}.get(franja, -1)
    if hora < 0 or ahora.hour * 60 + ahora.minute < hora:
        return False
    wd = ahora.weekday()
    if franja == "semanal" and wd != 5:
        return False   # balance semanal: solo sábados al mediodía
    if franja == "dominical" and wd != 6:
        return False   # análisis editorial: solo domingos
    if franja in ("matutina", "mediodia", "vespertina",
                  "cierre", "nocturna") and wd >= 5:
        return False   # fin de semana no hay digests ni cierres
    hoy = ahora.strftime("%Y-%m-%d")
    return not any(e.get("franja") == franja
                   and e.get("fecha", "").startswith(hoy)
                   for e in leer_jsonl(SINTESIS))


PATRON_NOTA_HTML = re.compile(
    r'<a[^>]+href=["\']([^"\']*/[^/"\']+/\d{3,}/[^/"\']+/?)["\'][^>]*>'
    r"(.*?)</a>", re.I | re.S)


def resolver_link_gn(link: str) -> str:
    """news.google.com/rss/articles/ID → URL real del medio.
    GN solo ofrece el redirect JS; el batchexecute Fbv4je con la firma
    y timestamp de la página devuelve el enlace directo. Falla → el
    link original (mejor una tarjeta GN que nada)."""
    try:
        if "news.google.com/rss/articles/" not in link:
            return link
        art = link.split("articles/", 1)[1].split("?")[0]
        s = requests.Session()
        ua = {"User-Agent": "Mozilla/5.0"}
        r = s.get(link, timeout=15, headers=ua)
        sig = re.search(r'data-n-a-sg="([^"]+)"', r.text)
        ts = re.search(r'data-n-a-ts="([^"]+)"', r.text)
        if not (sig and ts):
            return link
        inner = json.dumps(["garturlreq", [
            ["es-ES", "ES", ["FINANCE_TOP_INDICES", "WEB_TEST_1_0_0"],
             None, None, 1, 1, "ES:es", None, 180, None, None, None,
             None, None, 0, None, None, [int(ts.group(1)), 0]],
            "es-ES", "ES", 1, [2, 3, 4, 8], 1, 0, "655000234", 0, 0,
            None, 0], art, int(ts.group(1)), sig.group(1)])
        freq = json.dumps([[["Fbv4je", inner, None, "generic"]]])
        resp = s.post(
            "https://news.google.com/_/DotsSplashUi/data/batchexecute",
            data={"f.req": freq}, timeout=15,
            headers={**ua, "Content-Type":
                     "application/x-www-form-urlencoded;charset=UTF-8",
                     "Referer": link})
        m = re.search(r'\\"garturlres\\",\\"(https?://[^"\\]+)',
                      resp.text)
        if not m:
            m = re.search(r'"garturlres","(https?://[^"\\]+)',
                          resp.text)
        return m.group(1) if m else link
    except Exception:
        return link


_MESES_ES = {"enero": 1, "febrero": 2, "marzo": 3, "abril": 4,
             "mayo": 5, "junio": 6, "julio": 7, "agosto": 8,
             "septiembre": 9, "setiembre": 9, "octubre": 10,
             "noviembre": 11, "diciembre": 12}
_RX_FECHA_ES = re.compile(
    r"(\d{1,2})\s+de\s+([a-záéíóúñ]+)\s+(?:de|del)\s+(\d{4})", re.I)


def _fecha_cerca(doc: str, pos: int) -> tuple:
    """Fecha '19 de Octubre de 2026' en una ventana alrededor del
    anchor — el card del listado la trae junto al link (TSJ Tabasco).
    Devuelve published_parsed o None."""
    win = doc[max(0, pos - 1500):pos + 2500]
    m = _RX_FECHA_ES.search(win)
    if not m:
        return None
    mes = _MESES_ES.get(m.group(2).lower())
    if not mes:
        return None
    try:
        # mediodía local evita cruzar el día al convertir a epoch
        return datetime(int(m.group(3)), mes, int(m.group(1)),
                        12, 0).timetuple()
    except ValueError:
        return None


def extraer_notas_html(doc: str, base: str) -> list:
    """De HTML plano extrae enlaces-título de notas del patrón
    /seccion/123456/slug[/] — típico de sitios sin RSS (XEVA, TSJ
    Tabasco). El mismo link suele salir 3 veces (imagen, título,
    botón): se queda el anchor con más texto; si ninguno trae texto
    se usa el slug como título."""
    por_link = {}
    for m in PATRON_NOTA_HTML.finditer(doc):
        link = urljoin(base, html.unescape(m.group(1)))
        titulo = re.sub(r"<[^>]+>", " ", m.group(2))
        titulo = " ".join(html.unescape(titulo).split())
        if not titulo or titulo == por_link.get(link, ("",))[0]:
            continue
        # quedarse con el anchor de más texto (h5 > botón)
        if len(titulo) > len(por_link.get(link, ("",))[0]):
            por_link[link] = (titulo, m.start())
    notas = []
    for link, (titulo, pos) in por_link.items():
        if len(titulo) < 15:
            # sin texto de anchor → el slug como título legible
            slug = unquote(link.rstrip("/").rsplit("/", 1)[-1])
            titulo = slug.replace("-", " ").replace("_", " ").strip()
            if len(titulo) < 15:
                continue
        ent = {"link": link, "title": titulo, "summary": ""}
        fp = _fecha_cerca(doc, pos)
        if fp:
            ent["published_parsed"] = fp
        notas.append(ent)
    return notas


def resolver_feed(url: str) -> tuple:
    """Valida una URL de fuente. Devuelve (url_final, tipo, error).
    RSS/Atom directo → 'rss'. HTML con <link rel=alternate> → el feed
    detectado como 'rss'. HTML con enlaces /seccion/id/slug → 'html'.
    Atajos: 'gn:búsqueda' → feed RSS de Google News por tema;
    'x:handle' o x.com/handle → timeline vía espejos Nitter.
    Así se puede pegar la portada y se decide solo."""
    low = url.lower().strip()
    if low.startswith("x:") or re.match(
            r"^https?://(www\.)?(x|twitter)\.com/[A-Za-z0-9_]+/?$", low):
        h = low[2:] if low.startswith("x:") else url.split("/")[-1] \
            or url.split("/")[-2]
        h = h.strip().lstrip("@")
        if re.fullmatch(r"[A-Za-z0-9_]{1,15}", h):
            return f"x:{h}", "x", ""
        return None, None, "handle de X inválido"
    if low.startswith("gn:"):
        q = quote(url[3:].strip())
        url = ("https://news.google.com/rss/search?q=" + q
               + "&hl=es-419&gl=MX&ceid=MX:es-419")
    try:
        d = feedparser.parse(url)
        if d.entries:
            return url, "rss", ""
    except Exception as e:
        return None, None, f"no responde ({e})"
    try:
        doc = requests.get(url, timeout=10,
                           headers={"User-Agent": "Mozilla/5.0"}).text
        for m in re.finditer(
                r'<link[^>]+type=["\']application/(?:rss|atom)\+xml["\'][^>]*>',
                doc, re.I):
            h = re.search(r'href=["\']([^"\']+)', m.group(0), re.I)
            if h:
                cand = urljoin(url, html.unescape(h.group(1)))
                try:
                    if feedparser.parse(cand).entries:
                        return cand, "rss", ""
                except Exception:
                    continue
        # sin RSS declarado: ¿sitio con enlaces de nota /seccion/id/slug?
        if len(extraer_notas_html(doc, url)) >= 3:
            return url, "html", ""
    except Exception:
        pass
    return None, None, "no parece un feed RSS — ¿es la portada del sitio?"


# espejos Nitter para el tipo 'x' — la API oficial es de pago y el
# syndication público murió (404). Son frágiles: rotar si uno cae.
_NITTER_HOSTS = (
    "nitter.tiekoetter.com", "xcancel.com", "nitter.poast.org",
    "lightbrd.com", "nuku.trabun.org", "nitter.space")


def _handle_x(url: str) -> str:
    handle = re.sub(r"^x:", "", url.strip(), flags=re.I)
    handle = re.sub(r"^https?://(www\.)?(x|twitter)\.com/", "", handle)
    handle = handle.strip("/").split("/")[0].lstrip("@")
    return handle if re.fullmatch(r"[A-Za-z0-9_]{1,15}", handle) else ""


def _scrapear_x_posts(handle: str) -> list:
    """Timeline de X con sesión guardada (x_session.json) — anónimo
    X solo enseña login-wall. handle='home' → pestaña 'Siguiendo'
    del feed propio (todo lo que sigue el poli, atribuido por autor)."""
    if not X_SESSION.exists():
        return []
    # 'buscar:<query>' → pestaña Latest de la búsqueda global: revela
    # quién publica sobre el actor sin tener que seguir ni listar cada
    # cuenta (técnica acordada 22/oct — una carga de página por pasada)
    buscar = handle.lower().startswith("buscar:")
    es_home = handle.lower() == "home"
    if buscar:
        target = "https://x.com/search?q=" + quote(handle[7:]) + "&f=live"
    else:
        target = ("https://x.com/home" if es_home
                else f"https://x.com/{handle}")
    posts = []
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            br = _launch(p)
            pg = br.new_context(
                storage_state=str(X_SESSION)).new_page()
            # ritmo humano (tropicalización 22/oct): pausa variable
            # antes de navegar — nada de ir de perfil en perfil en
            # ráfaga metronómica
            pg.wait_for_timeout(random.randint(2500, 5500))
            pg.goto(target, wait_until="domcontentloaded", timeout=45000)
            pg.wait_for_timeout(random.randint(4000, 7500))
            if "login" in pg.url:
                br.close()
                print(f"[!] X sesión caída — re-correr x_login.py")
                return []
            if es_home:
                # 'Para ti' es default — cambiar a 'Siguiendo'
                try:
                    pg.get_by_role("tab", name=re.compile(
                        r"siguiendo|following", re.I)).first\
                        .click(timeout=8000)
                    pg.wait_for_timeout(4000)
                except Exception:
                    pass   # si no hay tab, queda 'Para ti' (ruido)
            # scroll profundo con extracción INCREMENTAL: X desmonta del
            # DOM los tweets que salen de pantalla — 4 giros al final
            # solo veían ~7. Extrae en cada giro y acumula por link;
            # sigue hasta ~30 únicos o 2 giros sin carga nueva
            js_tweets = """() => {
                const out = [];
                for (const t of document.querySelectorAll(
                        'article[data-testid="tweet"]')) {
                    // ad promocionado: entra al feed sin seguir la
                    // cuenta — placementTracking o etiqueta Ad/Publicidad
                    if (t.querySelector(
                            '[data-testid="placementTracking"]')
                        || Array.from(t.querySelectorAll('span'))
                            .some(s => ['Ad','Publicidad']
                                .includes((s.textContent||'').trim())))
                        continue;
                    const a = t.querySelector('a[href*="/status/"]');
                    const link = a ? a.href.split('?')[0] : '';
                    if (!link) continue;
                    const tt = t.querySelector(
                        'div[data-testid="tweetText"]');
                    const tm = t.querySelector('time');
                    // media real del post (foto adjunta) — el avatar
                    // NO (og:image de X siempre devuelve el perfil);
                    // fallback: card del link compartido (img del
                    // artículo, ej. 'De xevt.com')
                    const phs = Array.from(t.querySelectorAll(
                        'div[data-testid="tweetPhoto"] img'))
                        .map(i => i.src)
                        .filter(s => s && s.includes('media'));
                    const card = t.querySelector(
                        'div[data-testid="card.wrapper"] img');
                    out.push({link: link,
                              autor: (link.split('/')[3] || ''),
                              txt: tt ? tt.innerText : '',
                              img: phs.length ? phs[0]
                                              : (card ? card.src : ''),
                              imgs: phs.length ? phs
                                               : (card ? [card.src] : []),
                              time: tm ? (tm.dateTime || '') : ''});
                }
                return out;
            }"""
            posts, vistos, quieto, prev = [], set(), 0, -1
            for _ in range(15):
                for tw in pg.evaluate(js_tweets):
                    if tw["link"] not in vistos:
                        vistos.add(tw["link"])
                        posts.append(tw)
                if len(posts) >= 30 or quieto >= 2:
                    break
                quieto = quieto + 1 if len(posts) <= prev else 0
                prev = len(posts)
                pg.mouse.wheel(0, random.randint(2400, 3400))
                pg.wait_for_timeout(random.randint(1500, 3200))
            br.close()
    except Exception:
        return []
    if posts:
        _aviso_x_sesion(ok=True)   # sesión viva — levanta el flag
    else:
        # login ok pero 0 articles: layout cambió o rate-limit —
        # sin esto un feed vacío pasa por 'todo bien'
        print(f"[x] @{handle}: 0 posts extraídos")
    out = []
    for p_ in posts:
        if (p_.get("link") or "").endswith("/analytics"):
            continue   # ad promocionado — CTA 'view analytics'
        txt = " ".join((p_.get("txt") or "").split())
        try:
            pp = datetime.fromisoformat(
                p_["time"].replace("Z", "+00:00")).timetuple() \
                if p_.get("time") else None
        except Exception:
            pp = None
        ent = {"link": p_["link"], "title": txt[:140] or "post",
               "summary": txt, "published_parsed": pp,
               "_autor": "@" + p_["autor"] if p_.get("autor")
                         else ""}
        # imgs[] = TODAS las fotos del tweet (multi-foto: portada +
        # contraportada); img = solo la 1ª (fallback extractor viejo)
        fotos = p_.get("imgs") or ([p_["img"]] if p_.get("img") else [])
        if fotos:
            ent["media_content"] = [{"url": html.unescape(u)}
                                    for u in fotos if u]
        out.append(ent)
    return out


def _feed_x(url: str, cfg: dict) -> list:
    """Timeline de X. Fuente.url = 'x:handle' o 'x:buscar:<query>'.
    Solo ingiere posts cuyo autor esté en x_permitidos; las otras
    cuentas se ignoran aunque aparezcan en el feed."""
    permitidos = {p.lower().lstrip("@") for p in cfg.get("x_permitidos", [])}
    if url.strip().lower().startswith("x:buscar:"):
        q = url.strip()[9:]
        posts = _scrapear_x_posts("buscar:" + q) if q else []
        return [p for p in posts
                if p.get("_autor", "").lstrip("@").lower() in permitidos]
    handle = _handle_x(url)
    if not handle:
        return []
    for host in _NITTER_HOSTS:
        try:
            d = feedparser.parse(f"https://{host}/{handle}/rss")
            if d.entries:
                for e in d.entries:
                    if e.get("link"):
                        e["link"] = re.sub(r"^https?://[^/]+/",
                                           "https://x.com/", e["link"])
                        autor = (e["link"].split("/")[3] or "").lower()
                        e["_autor"] = "@" + autor
                return [e for e in d.entries
                        if (e.get("_autor") or "").lstrip("@").lower()
                        in permitidos]
        except Exception:
            continue
    posts = _scrapear_x_posts(handle)
    return [p for p in posts
            if p.get("_autor", "").lstrip("@").lower() in permitidos]


def revisar(cfg: dict, mostrar_todo: bool, resumir: bool) -> int:
    vistos = cargar_vistos()
    usuarios = cargar_usuarios()
    alertas = 0
    # salud por fuente para el tab de estadísticas
    estado = cargar_json(ESTADO_FUENTES, {})
    # imagen que ya salió en ≥3 notas = logo/placeholder reciclado,
    # no foto del artículo (ej. ícono de GN en "Latinus Diario")
    frecuencia_img = Counter(n.get("imagen", "")
                             for n in leer_jsonl(NOTICIAS, limite=300))
    # dedup por (título, medio): el agregador (GN) a veces devuelve la
    # misma nota 2-3 veces con link distinto → triples falsos. El medio
    # va en la clave para NO borrar cobertura real multi-medio.
    titulos_vistos = {(normalizar(n["titulo"]), _canon_medio(n["fuente"]))
                      for n in _noticias_cache()[-5000:]}

    now = time.time()
    delay = cfg.get("delay_fuentes", 1)
    agent = cfg.get(
        "user_agent",
        "OlmecaCode-Monitor/1.0 (+mailto:the@unknownshoppers.com)")
    # X con ritmo propio: ~6 handles × Playwright cada 15 min era
    # mucho desgaste de sesión/CPU — pasa cada 30 min; el resto del
    # ciclo (RSS) sigue a los 15
    global _ULT_X, _X_ESP
    # intervalo jittered 45-75 min — metrónomo exacto es huella de bot
    correr_x = now - _ULT_X >= _X_ESP
    if correr_x:
        _ULT_X = now
        _X_ESP = random.randint(45, 75) * 60
    for i, fuente in enumerate(
            random.sample(list(cfg["fuentes"]), len(cfg["fuentes"]))):
        if fuente.get("activa") is False:
            continue   # apagada en catálogo (ej. bloque QRoo en esta instancia)
        if fuente.get("tipo") == "fb":
            continue   # la raspa chucky cada 4h — sin feed que pedir
        if fuente.get("tipo") == "x" and not correr_x:
            continue
        st = estado.setdefault(fuente["nombre"], {"ok": 0, "err": 0, "ultimo_ok": ""})
        # respetar robots.txt; cachear 24h
        if "crawl_delay" not in st or now - st.get("robots_checked", 0) > 86400:
            try:
                rp_url = urljoin(fuente["url"], "/robots.txt")
                r = requests.get(rp_url, timeout=10,
                                 headers={"User-Agent": agent})
                if r.status_code == 200:
                    rp = robotparser.RobotFileParser()
                    rp.parse(r.text.splitlines())
                    cd = rp.crawl_delay(agent)
                    st["crawl_delay"] = float(cd) if cd else 0
                else:
                    st["crawl_delay"] = 0
            except Exception:
                st["crawl_delay"] = 0
            st["robots_checked"] = now
        if i > 0:
            time.sleep(max(delay, st.get("crawl_delay", 0)))

        last_mod = st.get("last_modified")
        etag = st.get("etag")
        if fuente.get("tipo") == "telegram":
            entradas = fetch_telegram(fuente["canal"])
        elif fuente.get("tipo") == "wpjson":
            # WordPress REST API — para medios con RSS muerto o listados
            # JS (En Cambio /opinion/). Fuente.url = endpoint posts con
            # categories/per_page/_fields ya armados
            try:
                r = requests.get(fuente["url"], timeout=15,
                                 headers={"User-Agent": agent})
                posts = r.json() if r.status_code == 200 else []
            except Exception as e:
                st["err"] += 1
                print(f"[!] {fuente['nombre']}: error de red ({e})")
                continue
            if not posts:
                st["err"] += 1
                print(f"[!] {fuente['nombre']}: wp-json sin posts")
                continue
            entradas = []
            for p in posts:
                try:
                    pp = time.gmtime(time.mktime(time.strptime(
                        p.get("date", ""), "%Y-%m-%dT%H:%M:%S")))
                except Exception:
                    pp = None
                entradas.append({
                    "link": p.get("link", ""),
                    "title": html.unescape(re.sub(
                        r"<[^>]+>", "",
                        p.get("title", {}).get("rendered", ""))),
                    "summary": re.sub(
                        r"<[^>]+>", " ",
                        p.get("excerpt", {}).get("rendered", "")),
                    "published_parsed": pp})
            st["ok"] += 1
            st["ultimo_ok"] = datetime.now().isoformat(timespec="seconds")
        elif fuente.get("tipo") == "x":
            entradas = _feed_x(fuente["url"], cfg)
            if not entradas:
                st["err"] += 1
                print(f"[!] {fuente['nombre']}: espejos X sin respuesta")
                continue
            st["ok"] += 1
            st["ultimo_ok"] = datetime.now().isoformat(timespec="seconds")
        elif fuente.get("tipo") == "html":
            try:
                headers = {"User-Agent": agent}
                if last_mod:
                    headers["If-Modified-Since"] = last_mod
                if etag:
                    headers["If-None-Match"] = etag
                r = requests.get(fuente["url"], timeout=15, headers=headers)
                if r.status_code == 304:
                    st["ok"] += 1
                    st["ultimo_ok"] = datetime.now().isoformat(timespec="seconds")
                    continue
                doc = r.text
                entradas = extraer_notas_html(doc, fuente["url"])
                if r.headers.get("Last-Modified"):
                    st["last_modified"] = r.headers["Last-Modified"]
                if r.headers.get("ETag"):
                    st["etag"] = r.headers["ETag"]
            except Exception as e:
                st["err"] += 1
                print(f"[!] {fuente['nombre']}: error de red ({e})")
                continue
            if not entradas:
                st["err"] += 1
                print(f"[!] {fuente['nombre']}: no se encontraron notas")
                continue
            st["ok"] += 1
            st["ultimo_ok"] = datetime.now().isoformat(timespec="seconds")
        else:
            try:
                feed = feedparser.parse(fuente["url"], agent=agent,
                                        etag=etag or "", modified=last_mod or "")
            except Exception as e:
                st["err"] += 1
                print(f"[!] {fuente['nombre']}: error de red ({e})")
                continue
            status = getattr(feed, "status", 0)
            if status == 304:
                st["ok"] += 1
                st["ultimo_ok"] = datetime.now().isoformat(timespec="seconds")
                continue
            if feed.bozo and not feed.entries:
                st["err"] += 1
                print(f"[!] {fuente['nombre']}: no se pudo leer el feed")
                continue
            st["ok"] += 1
            st["ultimo_ok"] = datetime.now().isoformat(timespec="seconds")
            st["last_modified"] = getattr(feed, "modified", st.get("last_modified"))
            st["etag"] = getattr(feed, "etag", st.get("etag"))
            entradas = feed.entries

        nuevas = 0
        for entrada in entradas:
            link = entrada.get("link", "")
            if not link or link in vistos:
                continue
            solo_l = fuente.get("solo_link")
            if solo_l and not re.search(solo_l, link):
                continue
            vistos[link] = time.time()
            nuevas += 1

            titulo = re.sub(r"^\s*<!\[CDATA\[(.*)\]\]>\s*$", r"\1",
                            entrada.get("title", "(sin título)"))
            resumen = re.sub(r"<[^>]+>", " ", entrada.get("summary", ""))
            autor = entrada.get("author", "")
            imagen = url_https(extraer_imagen(entrada))

            # Google News agrega, no publica: el medio real viene en
            # <source>. Le atribuimos la nota a él y limpiamos el
            # sufijo " - Medio" que GN pega al titular.
            medio = ""
            # posts del feed 'Siguiendo' (x:home) se atribuyen al autor
            # real — 'X · Siguiendo' queda como agregador en 'via'.
            # TODO pasa a la base (los ~1200 follows = radar para
            # alertas/Interés); el tab /x filtra por x_permitidos
            if fuente.get("tipo") == "x" and entrada.get("_autor"):
                medio = entrada["_autor"]
            if "news.google.com" in fuente["url"]:
                src = entrada.get("source") or {}
                medio = (src.get("title") or src.get("value") or "").strip()
                if medio and titulo.endswith(f" - {medio}"):
                    titulo = titulo[: -len(medio) - 3]
            # fuente html sin RSS: el índice solo da el titular — el
            # lead (que trae el nombre, p.ej. 'Reséndez Bocanegra' en
            # boletines del TSJ) hace falta para interés y alertas
            if fuente.get("traer_resumen") and not resumen:
                resumen = extraer_lead_html(link) \
                    or extraer_og_desc(link)
            texto = f"{titulo} {resumen} {autor}"

            # algunas fuentes publican "páginas edición" (índice del día,
            # no artículo): 'Latinus Diario: 30 de septiembre', 'EDICION
            # DEL 2 DE JULIO' — se ignoran por regex en config
            ign = fuente.get("ignorar_titulo")
            if ign and re.search(ign, titulo, re.I):
                continue

            # inclusión por título: columnas con ediciones regionales
            # (Trascendió Monterrey/Puebla…) solo quedan si el titular
            # es el esperado
            solo_t = fuente.get("solo_titulo")
            if solo_t and not re.search(solo_t, titulo, re.I):
                continue

            # inclusión por autor: feeds que mezclan columnistas
            # (Crónica firma 'Pepe Grillo' — GN lo contaminaba porque el
            # nombre va en los site_keywords de TODO el sitio)
            solo_a = fuente.get("solo_autor")
            if solo_a and solo_a not in normalizar(autor):
                continue

            # mismo titular DEL MISMO medio con link distinto = nota
            # repetida (GN la da más de una vez); si es de OTRO medio
            # es cobertura real y entra al cluster
            clave = (normalizar(titulo),
                     _canon_medio(medio or fuente["nombre"]))
            # 'columnas' repite título cada edición (Sacapuntas, ¿Será?)
            # — el link único ya garantiza dedup real
            if clave in titulos_vistos \
                    and fuente.get("categoria") != "columnas":
                continue
            titulos_vistos.add(clave)

            # Filtro por fuente PRIMERO: solo gastamos la petición og:image
            # en notas que sí van a quedar
            solo = fuente.get("solo_si_menciona")
            if solo and not any(normalizar(p) in normalizar(texto) for p in solo):
                continue
            # X: su og:image es siempre el avatar del autor — inútil;
            # el media real lo extrae el scraper del DOM del tweet
            if not imagen and not re.search(
                    r"(x|twitter)\.com/", link):
                imagen = url_https(extraer_og_image(link))
            if imagen and frecuencia_img[imagen] >= 3:
                imagen = ""

            # links de GN son redirects JS — resolver al URL real del
            # medio para que /nota abra el artículo y no la tarjeta GN.
            # Dos entradas GN pueden resolver al MISMO artículo → dedup
            if "news.google.com" in fuente["url"]:
                real = resolver_link_gn(link)
                if real != link:
                    if real in vistos:
                        continue
                    link = real
                    vistos[link] = time.time()

            # resumen boilerplate del agregador (Reforma solo entrega
            # 'Título · Medio') → lede real del og:description
            if fuente.get("categoria") == "columnas":
                boiler = len(normalizar(resumen)) <= (
                    len(normalizar(titulo))
                    + len(normalizar(medio or fuente["nombre"])) + 12)
                if boiler:
                    resumen = extraer_og_desc(link) or resumen

            # Guardar TODA nota que pasa el filtro → alimenta la sección
            # "Últimas noticias" del dashboard
            nota = {
                "fecha": iso_fecha(entrada),
                "fuente": medio or fuente["nombre"],
                "via": fuente["nombre"] if medio else "",  # agregador que la trajo
                "categoria": fuente.get("categoria", "prensa"),
                "paywall": bool(fuente.get("paywall")),
                "autor": autor,
                "titulo": titulo,
                "resumen": resumen,
                "link": link,
                "imagen": imagen,
            }
            guardar_noticia(nota)

            # Alertas por usuario: cada perfil tiene SUS reglas y solo
            # matchea sobre fuentes que no ocultó. "Autor seguido" es global.
            autor_hit = normalizar(autor) in {
                normalizar(a) for a in cfg.get("seguir_autores", [])
            } if autor else False
            # project-first: una regla PERSONAL dispara por sus palabras;
            # una regla COMPARTIDA (proyecto asignado) solo dispara si la
            # nota es de interés del proyecto — evita flood de info basura
            hits_usuario = []
            for email, perfil in usuarios.items():
                if fuente["nombre"] not in fuentes_visibles(perfil, cfg):
                    continue
                rule_hits = [r for r in perfil.get("reglas", [])
                             if coincide(texto, r)
                             and (not r.get("proyecto")
                                  or coincide_interes(nota))]
                if rule_hits:
                    hits = [r["nombre"] for r in rule_hits]
                    proys = {r.get("proyecto") for r in rule_hits if r.get("proyecto")}
                    hits_usuario.append((email, hits, proys))

            if mostrar_todo:
                print(f"  · [{fuente['nombre']}] {titulo}")
            if autor_hit or hits_usuario:
                resumen_ia = resumir_ollama(cfg, titulo, resumen) if resumir else ""
                base_alerta = {
                    "fecha": datetime.now().isoformat(timespec="seconds"),
                    "fuente": medio or fuente["nombre"],
                    "via": fuente["nombre"] if medio else "",
                    "categoria": fuente.get("categoria", "prensa"),
                    "autor": autor,
                    "titulo": titulo,
                    "link": link,
                    "imagen": imagen,
                    "resumen_ia": resumen_ia,
                }
                if autor_hit:
                    alertas += 1
                    alerta = dict(base_alerta, reglas=f"Autor seguido: {autor}")
                    registrar_alerta(alerta, cfg)
                    print(f"\n*** ALERTA: {alerta['reglas']} ***")
                    print(f"    {titulo}\n    {link}")
                for email, hits, proys in hits_usuario:
                    alertas += 1
                    alerta = dict(base_alerta, reglas=", ".join(hits),
                                  usuario=email,
                                  proyectos=sorted(proys))
                    registrar_alerta(alerta, cfg)
                    print(f"\n*** ALERTA ({email}): {alerta['reglas']} ***")
                    print(f"    {titulo}\n    {link}")
                    if resumen_ia:
                        print(f"    → {resumen_ia}")

        print(f"[{datetime.now():%H:%M:%S}] {fuente['nombre']}: {nuevas} notas nuevas")

    guardar_vistos(vistos)
    _escribir_json(ESTADO_FUENTES, estado)
    # NO reescribir CONFIG: el ciclo solo lee cfg — volcar la copia en
    # memoria pisaba altas de fuentes/perfiles hechas mientras corría
    alertas += detectar_desarrollo(cfg, resumir)
    purgar()
    purgar_usuarios()
    # escaneo del archivo WP de los medios (1 vez al día, en hilo aparte):
    # el RSS solo trae título+resumen — las reglas con menciones en el
    # cuerpo de la nota nunca dispararían sin esto (el caso Efraín)
    ultimo_scan = cargar_json(WP_SCAN, {}).get("ts", 0)
    if time.time() - ultimo_scan > 86400:
        threading.Thread(target=wp_scan_reglas, args=(cfg,), daemon=True,
                         name="wp-scan").start()
    return alertas


WP_SCAN = BASE / "wp_scan.json"   # {ts, hosts:[dominios con API WP viva]}
SINTESIS = BASE / "sintesis.jsonl"  # síntesis IA: 2/día (9:00 y 16:00)


def _limpia_html(h: str) -> str:
    return html.unescape(re.sub(r"<[^>]+>", " ", h or "")).strip()


def wp_scan_reglas(cfg: dict):
    """Una vez al día consulta /wp-json/wp/v2/posts?search= de cada medio:
    encuentra notas cuyo CUERPO menciona las palabras de las reglas —
    el feed RSS nunca las traería (título/resumen no las contienen).
    Sin spam: escribe noticia+alerta directo, sin notify-send/correo."""
    import concurrent.futures
    usuarios = cargar_usuarios()
    queries = set()
    for perfil in usuarios.values():
        for r in perfil.get("reglas", []):
            # solo reglas de 2+ palabras: una sola palabra común ("efrain")
            # en el CUERPO de la nota = ruido seguro (Efraín Juárez, Pumas)
            if len(r.get("requiere_todas", [])) >= 2:
                queries.add(" ".join(r["requiere_todas"]))
    if not queries:
        WP_SCAN.write_text(json.dumps({"ts": time.time(), "hosts": []}))
        return

    estado = cargar_json(WP_SCAN, {})
    hosts = estado.get("hosts", [])
    doms = {}
    for f in cfg["fuentes"]:
        m = re.search(r"https?://([^/]+)", f["url"])
        if m:
            doms.setdefault(re.sub(r"^www\.", "", m.group(1)), f)

    def probar_host(dom):
        """Descubre/verifica hosts con wp-json; devuelve la base o None."""
        for h in (dom, f"www.{dom}"):
            try:
                r = requests.get(
                    f"https://{h}/wp-json/wp/v2/posts",
                    params={"per_page": 1, "search": "x"},
                    timeout=8, headers={"User-Agent": "Mozilla/5.0"})
                if r.status_code == 200 and isinstance(r.json(), list):
                    return h
            except Exception:
                continue
        return None

    with concurrent.futures.ThreadPoolExecutor(16) as ex:
        vivos = [h for h in ex.map(probar_host, doms) if h]
    hosts = sorted(set(hosts) & set(vivos) | set(vivos))
    print(f"[wp-scan] {len(hosts)} medios con API WP viva")

    exist = {n.get("link") for n in _noticias_cache()}
    vistos = cargar_vistos()

    def buscar(dom_q):
        host_q, q = dom_q
        try:
            r = requests.get(
                f"https://{host_q}/wp-json/wp/v2/posts",
                params={"search": q, "per_page": 30, "_embed": ""},
                timeout=10, headers={"User-Agent": "Mozilla/5.0"})
            if r.status_code != 200 or not isinstance(r.json(), list):
                return []
            return r.json()
        except Exception:
            return []

    trabajo = [(h, q) for h in hosts for q in queries]
    nuevas, alertas_n = [], []
    with concurrent.futures.ThreadPoolExecutor(16) as ex:
        for posts in ex.map(buscar, trabajo):
            for p in posts:
                link = p.get("link", "")
                if not link or link in exist or link in vistos:
                    continue
                titulo = _limpia_html(p.get("title", {}).get("rendered", ""))
                resumen = _limpia_html(
                    p.get("excerpt", {}).get("rendered", ""))[:400]
                cuerpo = _limpia_html(p.get("content", {}).get("rendered", ""))
                texto = normalizar(titulo + " " + resumen + " " + cuerpo)
                dom = re.sub(r"^www\.", "", urlparse(link).netloc)
                base = doms.get(dom, {"nombre": dom, "categoria": "prensa"})
                hits_usuario = []
                for email, perfil in usuarios.items():
                    if base["nombre"] not in fuentes_visibles(perfil, cfg):
                        continue
                    hits = [r["nombre"] for r in perfil.get("reglas", [])
                            if all(any(termino_en(normalizar(v), texto)
                                       for v in w.split("/"))
                                   for w in r.get("requiere_todas", []))]
                    if hits:
                        hits_usuario.append((email, ", ".join(hits)))
                if not hits_usuario:
                    continue
                exist.add(link)
                vistos[link] = time.time()
                img = ""
                try:
                    img = p["_embedded"]["wp:featuredmedia"][0].get(
                        "source_url", "")
                except Exception:
                    pass
                nota = {
                    "fecha": (p.get("date") or "")[:19],
                    "fuente": base["nombre"], "via": "wp-archivo",
                    "categoria": base.get("categoria", "prensa"),
                    "autor": "", "titulo": titulo, "resumen": resumen,
                    "link": link, "imagen": img,
                }
                nuevas.append(nota)
                # alerta solo si la nota es reciente: el archivo WP trae
                # historia completa y reglas genéricas inundarían la vista
                try:
                    fecha_ts = datetime.fromisoformat(nota["fecha"]).timestamp()
                except Exception:
                    fecha_ts = 0
                if time.time() - fecha_ts > 14 * 86400:
                    continue
                for email, regs in hits_usuario:
                    alertas_n.append({
                        "fecha": nota["fecha"], "fuente": base["nombre"],
                        "categoria": nota["categoria"], "autor": "",
                        "reglas": regs, "titulo": titulo, "link": link,
                        "imagen": img, "resumen_ia": "", "usuario": email})

    for n in nuevas:
        guardar_noticia(n)
    if alertas_n:
        with ALERTAS.open("a") as f:
            for a in alertas_n:
                f.write(json.dumps(a, ensure_ascii=False) + "\n")
        guardar_vistos(vistos)
    WP_SCAN.write_text(json.dumps(
        {"ts": time.time(), "hosts": hosts}, indent=0))
    print(f"[wp-scan] {len(nuevas)} notas por regla, {len(alertas_n)} alertas")


def _slug_portada(nombre: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", normalizar(nombre)).strip("-")


def _dir_dia(fecha=None) -> Path:
    """portadas/oct/06/ — árbol mes/día: las capturas del día se
    guardan ahí para cotejar contra días anteriores (y como fallback de
    ayer)."""
    f = fecha or datetime.now()
    meses = ("ene", "feb", "mar", "abr", "may", "jun",
             "jul", "ago", "sep", "oct", "nov", "dic")
    return PORTADAS_DIR / meses[f.month - 1] / f"{f.day:02d}"


def _portada_img(slug: str, dia: Path = None) -> Path:
    """La captura del diario puede ser .png (screenshot) o .jpg (kiosko/FB)."""
    d = dia or _dir_dia()
    for ext in (".png", ".jpg", ".jpeg"):
        p = d / f"{slug}{ext}"
        if p.exists():
            return p
    return d / f"{slug}.png"


def _bajar_portada_kiosko(m: dict):
    """img.kiosko.net/YYYY/MM/DD/mx/{slug}.750.jpg — la portada impresa real
    (resuelve a Reforma/Milenio/etc. que bloquean al bot). Solo HOY: si
    aún no publican, devuelve None y el medio queda pendiente — traer la
    de ayer la guardaría como si fuera de hoy y bloquearía reintentos."""
    f = datetime.now()
    slug = str(m["kiosko"]).rstrip("/").rsplit("/", 1)[-1] \
                                .removesuffix(".html")
    # .jpg = imagen completa (~960px), .750.jpg = preview — probar ambos
    urls = [f"https://img.kiosko.net/{f:%Y/%m/%d}/mx/{slug}{s}"
            for s in (".jpg", ".750.jpg")]
    for url in urls:
        try:
            r = requests.get(url, timeout=15,
                             headers={"User-Agent": "Mozilla/5.0"})
            if r.status_code == 200 and len(r.content) > 20000:
                return r.content
        except Exception:
            pass
    return None


_OG_IMG = 'property="og:image"[^>]*content="([^"]+)"'


def _portada_flip(url: str):
    """Flipbook del impreso. Excélsior: la página del lector lista las
    páginas en /large/ — _001A.jpg es la primera plana en alta res.
    Presente: diariopresente.mx/edicionimpresa enlaza el fliphtml5 del
    día (…/Presente-DD-MM-AAAA/) — files/large/<hash>.webp = portada."""
    h = {"User-Agent": "Mozilla/5.0"}
    try:
        r = requests.get(url, timeout=15, headers=h)
        pags = sorted(set(re.findall(
            r'https?://[^"\' ]+/large/[^"\' ]+\.jpg', r.text)))
        if pags:
            ir = requests.get(pags[0], timeout=30, headers=h)
            if ir.status_code == 200 and len(ir.content) > 100000:
                return ir.content
            return None
        # fliphtml5: link del libro de HOY en la página (fecha en slug)
        hoy = datetime.now()
        for link in re.findall(
                r'https?://online\.fliphtml5\.com/[^"\' ]+', r.text):
            if f"{hoy.day:02d}-{hoy.month:02d}-{hoy.year}" not in link:
                continue
            bk = requests.get(link, timeout=15, headers=h)
            p1 = re.search(r'files/large/[^"\' ]+\.webp', bk.text)
            if not p1:
                continue
            ir = requests.get(link.rstrip("/") + "/" + p1.group(0),
                              timeout=30, headers=h)
            if ir.status_code == 200 and len(ir.content) > 30000:
                # webp → jpeg para que el archivo .jpg sea válido
                im = Image.open(io.BytesIO(ir.content)).convert("RGB")
                buf = io.BytesIO()
                im.save(buf, "JPEG", quality=90)
                return buf.getvalue()
    except Exception:
        pass
    return None


def _portada_issuu(handle: str):
    """Issuu: handle de perfil → atom trae el doc del día con la miniatura
    page_1_thumb_large.jpg. URL de doc directa (/u/docs/slug) → og:image
    del doc (Contraréplica: slug fechado predecible, llega antes que el
    índice del medio)."""
    UA = {"User-Agent": "Mozilla/5.0"}
    try:
        if "/docs/" in handle:
            url = handle if handle.startswith("http") else "https://" + handle
            r = requests.get(url, timeout=15, headers=UA)
            if r.status_code != 200:
                return None
            m = re.search(
                r"https://image\.isu\.pub/[^\"'<> ]+/jpg/page_1(?:_thumb_large)?\.jpg",
                r.text) or re.search(r'og:image[^>]+content="([^"]+)"', r.text)
            if not m:
                return None
            url_img = m.group(1) if m.lastindex else m.group(0)
        else:
            r = requests.get(f"https://issuu.com/{handle}/atom",
                             timeout=12, headers=UA)
            m = re.search(
                r"https://image\.isu\.pub/[^\"'<> ]+/jpg/page_1_thumb_large\.jpg",
                r.text)
            if not m:
                return None
            url_img = m.group(0)
        ir = requests.get(url_img.replace("_thumb_large", ""),
                          timeout=20, headers=UA)
        if ir.status_code == 200 and len(ir.content) > 100000:
            return ir.content
    except Exception:
        pass
    return None


FB_SESSION = BASE / "fb_session.json"
FB_SESSION_REDES = BASE / "fb_session_redes.json"  # chucky — posts


def _fb_pausa() -> bool:
    """Kill-switch del usuario: fb_pausa=true en config suspende
    TODO contacto con FB — ni sesiones ni plugin anónimo ni posts.
    (22/oct: chucky cayó a verificación video-selfie; FB en modo
    hostil, cortar todo tráfico)."""
    return bool(cargar_json(CONFIG, {}).get("fb_pausa"))


def _fb_marcar_muerta(nombre: str):
    """Sesión caída hoy (checkpoint/ban) → la saca del pool el resto
    del día; nadie vuelve a gastar navegaciones probándola."""
    hoy = datetime.now().strftime("%Y-%m-%d")
    est = cargar_json(ESTADO_PORTADAS, {})
    fm = est.setdefault("fb_muertas", {})
    if fm.get("d") != hoy:
        est["fb_muertas"] = {"d": hoy, "sesiones": []}
        fm = est["fb_muertas"]
    if nombre not in fm["sesiones"]:
        fm["sesiones"].append(nombre)
        _guardar_portadas(est)


def _fb_sesiones(rol: str = "portadas") -> list:
    """Pool UNIFICADO de cuentas FB (incluye fb_session_redes).
    Turno diario rotativo (regla del usuario, 22/oct): portadas
    arranca con pool[día % n], posts con pool[(día+1) % n] — cuentas
    distintas cada jornada, el resto descansa como respaldo.
    Las marcadas muertas hoy se filtran; una caída salta a la
    siguiente sana automáticamente."""
    pool = sorted(BASE.glob("fb_session*.json"),
                  key=lambda f: (f.name != "fb_session.json", f.name))
    hoy = datetime.now().strftime("%Y-%m-%d")
    est = cargar_json(ESTADO_PORTADAS, {})
    fm = est.get("fb_muertas", {})
    if fm.get("d") == hoy:
        muertas = fm.get("sesiones", [])
        pool = [f for f in pool if f.name not in muertas]
    if not pool:
        return []
    n = len(pool)
    d = datetime.now().timetuple().tm_yday
    i = d % n if rol == "portadas" else (d + 1) % n
    return pool[i:] + pool[:i]   # primero la del turno
X_SESSION = BASE / "x_session.json"              # X — timeline
X_POSTS = BASE / "x_posts.jsonl"               # log de publicados
_ULT_FB_POSTS = 0.0        # epoch de la última pasada de chucky
_ULT_X = 0.0               # epoch de la última pasada de fuentes tipo x
_X_ESP = 30 * 60           # segundos hasta el próximo barrido x (jittered)
_FB_POSTS_CORRIENDO = False


def _post_x(texto: str) -> bool:
    """Publica un post en X con la sesión guardada (x_session.json).
    Disparo manual desde la tarjeta de Cierre — no es cron: X marca
    publicación bot periódica como actividad automatizada."""
    if not X_SESSION.exists() or not texto.strip():
        return False
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            br = _launch(p)
            pg = br.new_context(
                storage_state=str(X_SESSION)).new_page()
            pg.goto("https://x.com/compose/post",
                    wait_until="domcontentloaded", timeout=45000)
            pg.wait_for_timeout(5000)
            if "login" in pg.url:
                br.close()
                print("[!] X sesión caída al postear — x_login.py")
                return False
            tb = "div[data-testid='tweetTextarea_0']"
            pg.locator(tb).first.click(timeout=10000)
            pg.locator(tb).first.fill(texto[:280])
            pg.wait_for_timeout(1200)
            pg.locator("button[data-testid='tweetButton']").first\
                .click(timeout=10000)
            pg.wait_for_timeout(5000)
            # el composer se cierra/limpia al postear; si el texto
            # sigue ahí el click no pegó
            quedo = pg.evaluate(
                "() => {const e=document.querySelector("
                "\"div[data-testid='tweetTextarea_0']\");"
                "return e ? (e.innerText||'').trim() : '';}")
            br.close()
            ok = not quedo
            print(f"[x] post {'enviado' if ok else 'NO confirmado'}"
                  f" — {len(texto)} chars")
            return ok
    except Exception:
        print(f"[x] error posteando: {e}")
        return False


def _x_publicado(fecha: str, tipo: str = "cierre") -> bool:
    """¿La síntesis con esta fecha ya se posteó en X? `tipo` distingue
    el post institucional (default 'cierre') de la perspectiva del
    poli — entradas viejas del log sin tipo cuentan como cierre."""
    return any(p.get("fecha") == fecha and p.get("ok")
               and p.get("tipo", "cierre") == tipo
               for p in leer_jsonl(X_POSTS))


def _fb_sesion_caido(pg) -> bool:
    """True si FB redirigió al login/checkpoint — la sesión caducó o
    la cuenta cayó en revisión."""
    try:
        u = pg.url
        return ("login" in u or "checkpoint" in u or
                "two_factor" in u)
    except Exception:
        return False


def _aviso_fb_sesion():
    """Un aviso por día: flag en portadas_estado.json (visible en
    /horarios), correo si el SMTP está habilitado, y log."""
    hoy = datetime.now().strftime("%Y-%m-%d")
    est = cargar_json(ESTADO_PORTADAS, {})
    if est.get("fb_sesion", {}).get("alertado") == hoy:
        return
    print("  [!] SESIÓN FB CAÍDA — checkpoint/login detectado; "
          "las portadas FB saldrán en modo anónimo (600px)")
    est["fb_sesion"] = {"estado": "caida", "alertado": hoy}
    _guardar_portadas(est)
    try:
        cfg = cargar_json(CONFIG, {})
        enviar_correo(cfg, {
            "reglas": "FB sesión caduca",
            "fuente": "portadas",
            "fecha": hoy,
            "titulo": "La sesión de Facebook caducó o cayó en checkpoint",
            "link": "",
            "resumen_ia": "Corre `.venv/bin/python fb_login.py` para "
                          "renovar fb_session.json. Mientras, las "
                          "capturas FB salen anónimas (~600px)."})
    except Exception:
        pass


def _aviso_x_sesion(ok: bool = False):
    """Sesión X: ok=False marca caída (login-wall visto) con aviso
    diario como FB; ok=True limpia el flag al volver a extraer
    posts — el estado vive en portadas_estado.json → /salud."""
    try:
        hoy = datetime.now().strftime("%Y-%m-%d")
        est = cargar_json(ESTADO_PORTADAS, {})
        if ok:
            if est.pop("x_sesion", None):
                _guardar_portadas(est)
            return
        if est.get("x_sesion", {}).get("alertado") == hoy:
            return
        est["x_sesion"] = {"estado": "caida", "alertado": hoy}
        _guardar_portadas(est)
        cfg = cargar_json(CONFIG, {})
        enviar_correo(cfg, {
            "reglas": "X sesión caduca",
            "fuente": "portadas",
            "fecha": hoy,
            "titulo": "La sesión de X (@elpolidelanoche) cayó al login",
            "link": "",
            "resumen_ia": "Corre `.venv/bin/python x_login.py` para "
                          "renovar x_session.json. Mientras: radar X "
                          "vacío y portada de XEVT sin captura."})
    except Exception:
        pass


def _imagenes_fb_visores(pg, post_url: str) -> list:
    """Con sesión: el post enlaza cada foto a su visor /photo/?fbid=&set=,
    que sirve la imagen ~1050px (el feed anónimo topea en 600)."""
    out = []
    try:
        pg.goto(post_url, wait_until="domcontentloaded", timeout=45000)
        pg.wait_for_timeout(6000)
        if _fb_sesion_caido(pg):
            _aviso_fb_sesion()
            return []
        # si el candidato YA es un visor /photo?fbid= (el timeline real
        # enlaza cada foto directo, no al permalink del post), la foto
        # ES la página: tomar el <img> más grande de una vez
        def _img_mayor():
            # solo imgs del visor/main — el documento entero carga el
            # feed lateral (flyers, posts sugeridos ajenos) y ganaban
            # por tamaño (11/oct: flyer TramitaMóvil, post de Reddit)
            return pg.evaluate("""() => {
                let best = null, area = 0;
                for (const sel of ['div[role="dialog"] img',
                                   'div[role="main"] img',
                                   'main img']) {
                    for (const i of document.querySelectorAll(sel)) {
                        const s = i.src || '';
                        if (!/scontent/.test(s)) continue;
                        const a = i.naturalWidth * i.naturalHeight;
                        if (a > area) { area = a; best = s; }
                    }
                    if (best) return best;
                }
                return null;
            }""")
        if "fbid=" in post_url:
            src = _img_mayor()
            if src:
                ir = requests.get(src, timeout=20,
                                  headers={"User-Agent": "Mozilla/5.0"})
                if ir.status_code == 200 and len(ir.content) > 40000:
                    out.append(ir.content)
        hrefs = pg.eval_on_selector_all(
            'div[role="main"] a[href*="/photo"],'
            + 'div[role="article"] a[href*="/photo"],'
            + 'main a[href*="/photo"]',
            "els => els.map(e => e.href)")
        vistos = set()
        # set=a.* = álbum/avatar — último recurso si no hubo pcb
        for paso in (0, 1):
            if paso == 1 and out:
                break
            for href in hrefs:
                fid = re.search(r'fbid=(\d+)', href)
                if not fid or fid.group(1) in vistos:
                    continue
                if "&set=a." in href and paso == 0:
                    continue
                vistos.add(fid.group(1))
                try:
                    pg.goto(href, wait_until="domcontentloaded",
                            timeout=45000)
                    pg.wait_for_timeout(4500)
                    src = _img_mayor()
                    if not src:
                        continue
                    ir = requests.get(src, timeout=20,
                                      headers={"User-Agent": "Mozilla/5.0"})
                    if ir.status_code == 200 and len(ir.content) > 40000:
                        out.append(ir.content)
                except Exception:
                    continue
                if len(out) >= 4:
                    break
    except Exception:
        pass
    return out


def _imagenes_fb_post(url: str) -> list:
    """Post/share de FB → TODAS las fotos adjuntas (TAD mete las 2
    portadas en el mismo post). Dedup por id de foto. Con sesión
    (fb_session.json) abre el visor de cada foto en alta res; sin
    sesión cae a la versión del feed (~600px)."""
    if _fb_pausa():
        return []
    try:
        for i, ses in enumerate(_fb_sesiones()):
            try:
                if i:                    # cuenta previa falló — pausa
                    time.sleep(random.randint(8, 15))
                from playwright.sync_api import sync_playwright
                with sync_playwright() as p:
                    br = _launch(p)
                    pg = br.new_context(
                        storage_state=str(ses)).new_page()
                    pg.wait_for_timeout(random.randint(2500, 5000))
                    imgs = _imagenes_fb_visores(pg, url)
                    br.close()
                if imgs:
                    return imgs
            except Exception:
                pass
        r = requests.get(url, timeout=15, headers={
            "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 "
                          "like Mac OS X) AppleWebKit/605.1.15"})
        vistos, urls = set(), []
        for u in re.findall(r'(https://scontent[^"\'\\ ]+)', r.text):
            u = html.unescape(u)
            fid = re.search(r'/(\d{8,}_\d{10,}_\d{10,})_n\.', u)
            if not fid or fid.group(1) in vistos:
                continue
            vistos.add(fid.group(1))
            urls.append(u)
        imgs = []
        for u in urls[:4]:
            ir = requests.get(u, timeout=15,
                              headers={"User-Agent": "Mozilla/5.0"})
            if ir.status_code == 200 and len(ir.content) > 30000:
                imgs.append(ir.content)
        return imgs
    except Exception:
        return []


def _og_imagen(url: str):
    """og:image de una URL de FB → bytes JPG."""
    try:
        r = requests.get(url, timeout=15, headers={
            "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 "
                          "like Mac OS X) AppleWebKit/605.1.15"})
        og = re.search(_OG_IMG, r.text)
        if not og:
            return None
        ir = requests.get(html.unescape(og.group(1)), timeout=15,
                          headers={"User-Agent": "Mozilla/5.0"})
        if ir.status_code == 200 and len(ir.content) > 20000:
            return ir.content
    except Exception:
        pass
    return None


def _bajar_portada_fb(m: dict) -> list:
    """FB: share/post directo → TODAS sus fotos (lista de JPGs). Si es
    página → plugin timeline público (sin login): post DE HOY cuyo texto
    diga portada/edición/primera plana (TAD publica ~medianoche)."""
    if _fb_pausa():
        return []
    if datetime.now().hour < 5:
        return []   # FB se scrapea de 5 am a cierre (regla 22/oct):
                    # antes de esa hora no hay posts nuevos indexados
                    # y cada visita quema las cuentas para nada
    fb = m["fb"]
    if "/share/" in fb or "/posts/" in fb or "/photo" in fb:
        return _imagenes_fb_post(fb)
    # página → plugin la carga por URL completa url-encoded (sirve tanto
    # para facebook.com/slug como para profile.php?id=… del XHVX)
    pagina_fb = quote(fb.split("#")[0], safe="")
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return []
    hoy = datetime.now()
    meses = "enero febrero marzo abril mayo junio julio agosto " \
        "septiembre octubre noviembre diciembre".split()
    fecha_txt = f"{hoy.day} de {meses[hoy.month - 1]}"
    plugin = ("https://www.facebook.com/plugins/page.php?href="
              f"{pagina_fb}"
              "&tabs=timeline&width=500&height=900&hide_cover=true")
    candidata = ""
    txt_sel = ""
    try:
        with sync_playwright() as p:
            br = _launch(p)
            pg = None
            for ses in _fb_sesiones():
                # ritmo humano (regla del usuario): nada de ráfagas —
                # cada navegación de cuenta lleva pausa aleatoria
                pg = br.new_context(
                    storage_state=str(ses)).new_page()
                pg.wait_for_timeout(random.randint(2500, 5000))
                if random.random() < 0.15:
                    # disfraz de lector: a veces pasar por la home
                    # primero — un humano no entra directo al timeline
                    pg.goto("https://www.facebook.com/",
                            wait_until="domcontentloaded",
                            timeout=30000)
                    pg.wait_for_timeout(random.randint(2000, 4500))
                pg.goto(fb.split("#")[0], wait_until="domcontentloaded",
                        timeout=45000)
                if _fb_sesion_caido(pg):
                    print(f"[fb] sesión {ses.name} caída "
                          f"(checkpoint/ban) — pruebo siguiente cuenta")
                    _fb_marcar_muerta(ses.name)
                    pg.context.close()
                    pg = None
                    time.sleep(random.randint(8, 15))
                    continue
                break
            if pg is None:
                if _fb_sesiones():
                    _aviso_fb_sesion()   # TODAS las cuentas caídas
                # cae al plugin anónimo
                pg = br.new_page()
                pg.goto(plugin, wait_until="domcontentloaded",
                        timeout=30000)
            pg.wait_for_timeout(6000)
            prev = -1
            # giros y pausas variables — scroll de lector, no de bot
            for _ in range(random.randint(6, 14)):
                pg.evaluate(
                    "for (const el of document.querySelectorAll('*')) "
                    "if (el.scrollHeight > el.clientHeight + 50) "
                    "el.scrollTop += 2500;")
                pg.wait_for_timeout(random.randint(1200, 3200))
                n = pg.evaluate("document.querySelectorAll('img').length")
                if n == prev:
                    break
                prev = n
            # por ARTÍCULO primero: su innerText es el post real — el
            # barrido global de anchors atrapa también el grid
            # 'Photos See all photos' y ese texto inútil ganaba la
            # dedup por href (Ahora Noticias 15/oct: su plana de hoy
            # existía pero solo se veía el módulo de fotos)
            posts = pg.evaluate("""() => {
                const NL = String.fromCharCode(10), seen = new Set(), out = [];
                for (const art of document.querySelectorAll(
                        'div[role="article"]')) {
                    const t = art.innerText || '';
                    if (t.length < 40) continue;
                    const canon = art.querySelector(
                        'a[href*="/posts/"],a[href*="story_fbid"],'
                        + 'a[href*="/permalink/"]')
                        || art.querySelector('a[href*="/photo"]');
                    if (!canon || seen.has(canon.href)) continue;
                    seen.add(canon.href);
                    const own = art.querySelector(
                        'a[href*="facebook.com/"]'
                        + ':not([href*="/posts/"]):not([href*="/photos/"])'
                        + ':not([href*="/photo?"]):not([href*="/reels"])'
                        + ':not([href*="/watch"]):not([href*="/groups"])'
                        + ':not([href*="/hashtag"])');
                    let owner = '';
                    if (own) {
                        const seg = own.pathname.split('/')
                            .filter(Boolean);
                        owner = seg.length === 1 ? seg[0] : '';
                    }
                    let feed_img = '';
                    for (const im of art.querySelectorAll(
                            'img[src*="scontent"],'
                          + 'img[src*="fbcdn"]')) {
                        if (im.naturalWidth >= 400
                                && !im.src.includes('emoji')) {
                            feed_img = im.src; break;
                        }
                    }
                    out.push({href: canon.href, owner: owner,
                              img: feed_img,
                              txt: t.split(NL).join(' ').slice(0, 300)});
                }
                return out;
            }""")
            posts += pg.evaluate("""() => {
                const NL = String.fromCharCode(10), seen = new Set(
                    window.__vistos || []), out = [];
                for (const a of document.querySelectorAll(
                        'a[href*="/posts/"], a[href*="/photos/"], '
                    + 'a[href*="/photo"], a[href*="story_fbid"]')) {
                    // los /photo?fbid=N distan solo por query — dedup
                    // por href completo o el primero (avatar del
                    // header) se come a todas las fotos del post
                    const k = a.href;
                    if (seen.has(k)) continue; seen.add(k);
                    // el texto del post queda en un ancestro ancho;
                    // el primer contenedor con >40 chars se cortaba
                    // antes del body — subir hasta >250 (o 10 niveles)
                    let n = a, txt = '';
                    for (let i = 0; i < 10 && n; i++) {
                        n = n.parentElement;
                        if (!n) break;
                        const t = n.innerText || '';
                        if (t.length > txt.length) txt = t;
                        if (t.length > 250) break;
                    }
                    // autor del post: primer link de perfil dentro del
                    // bloque — con sesión el timeline cuela posts
                    // 'sugeridos' de páginas ajenas
                    let owner = '';
                    if (n) {
                        const own = n.querySelector(
                            'a[href*="facebook.com/"]'
                            + ':not([href*="/posts/"]):not([href*="/photos/"])'
                            + ':not([href*="/photo?"]):not([href*="/reels"])'
                            + ':not([href*="/watch"]):not([href*="/groups"])'
                            + ':not([href*="/hashtag"])');
                        if (own) {
                            const seg = own.pathname.split('/')
                                .filter(Boolean);
                            owner = seg.length === 1 ? seg[0] : '';
                        }
                    }
                    // img del feed dentro del post — respaldo cuando
                    // el visor del permalink no entrega nada (res
                    // menor, ~600px, pero pasa los filtros)
                    let feed_img = '';
                    if (n) {
                        for (const im of n.querySelectorAll(
                                'img[src*="scontent"],'
                              + 'img[src*="fbcdn"]')) {
                            if (im.naturalWidth >= 400
                                    && !im.src.includes('emoji')) {
                                feed_img = im.src; break;
                            }
                        }
                    }
                    out.push({href: a.href, owner: owner,
                              img: feed_img,
                              txt: txt.split(NL).join(' ').slice(0, 300)});
                }
                return out;
            }""")
        # dedup por href — la entrada de artículo va primero y su
        # texto es el del post; el anchor suelto del grid de fotos
        # comparte el mismo href y se descarta aquí
        _vistos = set()
        posts = [p_ for p_ in posts
                 if not (p_["href"] in _vistos
                         or _vistos.add(p_["href"]))]
        por_texto = False
        cand = []            # [(href, txt)] — TAD puede subir las 2
        # planas en posts SEPARADOS: no cortar en la primera
        meses_pat = "|".join(meses)
        # slug de la página del medio — los posts 'sugeridos' de páginas
        # ajenas que el timeline con sesión cuela se descartan por autor
        segs = [s for s in urlparse(
            fb.split("#")[0]).path.split("/") if s]
        slug_page = normalizar(segs[0]) if segs \
            and segs[0] != "profile.php" else ""

        def _post_viejo(txt_n: str) -> bool:
            """Texto fechado en otro día ('9 de octubre') = edición
            vieja — sin este guard el scraper escrolea hasta una
            portada de días atrás y la cuela como la de hoy."""
            fechas_post = {(int(dd), meses.index(mm) + 1)
                           for dd, mm in re.findall(
                               rf"(\d{{1,2}})\s+de\s+({meses_pat})",
                               txt_n)}
            return bool(fechas_post) and \
                (hoy.day, hoy.month) not in fechas_post

        for post in posts:
            if slug_page and post.get("owner") \
                    and normalizar(post["owner"]) != slug_page:
                continue        # post 'sugerido' de otra página
            # '#' fuera: '#Jueves 15 de #Octubre' debe casar con la
            # fecha '15 de octubre' (Ahora, 15/oct — el hashtag la
            # partía y el post pasaba por viejo/no-fechado)
            txt = normalizar(post["txt"]).replace("#", " ")
            # el plugin renderiza en EN ó ES según locale del CDN —
            # "3 hours ago"/"3h" vale igual que "hace 3 horas"; pero
            # >8h ya es el post de AYER (las portadas se suben 4-6am)
            _h = re.search(r"(\d+)\s*(?:h|hr|hrs|hora|horas)\b", txt)
            # fb_horas: XEVA sube la plana la tarde anterior (~14h);
            # el tope default de 8h es para portadas de la madrugada.
            # 'día' SOLO como sello temporal ('1 día', '2d', 'a day
            # ago', 'ayer') — la palabra en el caption ('empezar tu
            # día', Ahora 15/oct) no puede tumbar la frescura
            reciente = bool(re.search(
                r"hace|\bago\b|\d+\s*(h|hr|hrs|hora|horas|min|minute)s?\b",
                txt)) and not re.search(
                r"\bayer\b|\byesterday\b|\b\d+\s*d[ií]as?\b"
                r"|\b\d+\s*days?\b|\b\d+\s*d\b", txt) \
                and (not _h
                     or int(_h.group(1)) <= m.get("fb_horas", 8))
            fechas = (normalizar(fecha_txt),              # 5 de octubre
                      normalizar(fecha_txt.replace(
                          str(hoy.day), f"{hoy.day:02d}")))  # 05 de octubre
            # typo del medio ('17 de junio' en octubre — Ahora 17/oct)
            # no tumba un post reciente: 'hace 42 min' no puede ser
            # de junio; el guard solo opera en posts SIN frescura
            if _post_viejo(txt) and not reciente:
                continue
            # 'hoy' en el texto NO es frescura — el post fijado de
            # ayer ('#EnPortada hoy', 1d) se colaba y repetía edición
            if re.search(r"portada|primera plana|edici[oó]n|bolet[ií]n",
                         txt) and \
                    (reciente or any(f in txt for f in fechas)):
                cand.append((post["href"], post["txt"]))
                por_texto = True
                continue
            # fb_primero: la página sube la portada como primer post con
            # foto de la madrugada sin texto identificable (XEVT) —
            # hasta 3 frescos: si el último es un flyer la plana queda
            # abajo y el filtro de formato decide cuál sirve.
            # fb_texto (CORAT/Ahora/Índigo): la página publica bait sin
            # caption — sin la palabra 'portada/edición' no se acepta
            if m.get("fb_primero") and not m.get("fb_texto") \
                    and not por_texto and len(cand) < 3 and reciente:
                cand.append((post["href"], post["txt"]))
    except Exception:
        return []
    if not cand:
        # diagnóstico: 0 posts vistos = sesión/plugin no rindió; >0 =
        # el post existe pero no pasó el filtro de texto/frescura
        print(f"[fb] {m['nombre']}: sin candidata "
              f"({len(posts)} posts vistos)")
        return []
    print(f"[fb] {m['nombre']}: {len(cand)} post(s) → {cand[0][1][:90]}")
    # un post con N fotos se reparte en varios links /photo que
    # comparten el texto del artículo — juntar los fbid de CADA post
    # candidato (TAD a veces mete las 2 planas en el mismo post y
    # otras en posts separados)
    cands = []
    for href, txt_sel in cand:
        if href not in cands:
            cands.append(href)
        if "fbid=" in href:
            for p_ in posts:
                if p_["txt"] == txt_sel and p_["href"] != href \
                        and "fbid=" in p_["href"] \
                        and "&set=a." not in p_["href"] \
                        and p_["href"] not in cands:
                    cands.append(p_["href"])
    imgs = []
    for u in cands[:6]:
        for b in _imagenes_fb_post(u):
            if len(imgs) < 4 and b not in imgs:
                imgs.append(b)
    if not imgs:
        # el visor del permalink falló → img ya renderizada en el
        # feed del post candidato (menor res pero sirve de respaldo)
        feed = {p_["href"]: p_.get("img") for p_ in posts}
        for u in cands[:6]:
            src = feed.get(u)
            if not src:
                continue
            try:
                r = requests.get(html.unescape(src), timeout=15,
                                 headers={"User-Agent": "Mozilla/5.0"})
                if r.status_code == 200 and len(r.content) > 30000:
                    imgs.append(r.content)
            except Exception:
                pass
    if imgs and m.get("fb_primero") and not por_texto:
        # fallback sin texto identificable: exigir formato angosto de
        # primera plana — flyers verticales (donación ISSET 0.8) no son
        # portada. Si el post dijo 'portada/boletín/edición + hoy',
        # confiamos en el texto aunque la imagen sea 0.8
        imgs = [b for b in imgs
                if _es_portada(b, 1.15, 1.6) and _texto_denso(b)]
    return imgs


def _bajar_portada_x(m: dict) -> list:
    """X: media del tweet de HOY (@xevtfm publica su plana ahí cuando
    su FB tarda). Sesión x_session.json; la img del DOM viene chica —
    pedir name=large. published_parsed es UTC → fecha local."""
    handle = str(m.get("x", "")).lstrip("@").strip()
    if not handle or not X_SESSION.exists():
        return []
    try:
        posts = _scrapear_x_posts(handle)
    except Exception:
        return []
    hoy = datetime.now().date()
    imgs = []
    for p_ in posts:
        if p_.get("_autor", "").lower() != f"@{handle}".lower():
            continue                    # retweets/ads
        pp = p_.get("published_parsed")
        if not pp or datetime.fromtimestamp(
                calendar.timegm(pp)).date() != hoy:
            continue                    # solo tweets de hoy
        # el medio tuitea titulares con foto todo el día — sin este
        # candado entraban memes/comunicados/fotos de nota como
        # 'portada' (16/oct: Levi's, FGET, gato). Pasa si el texto
        # anuncia plana o la imagen misma ya luce de primera plana
        txt = normalizar(p_.get("summary") or p_.get("title") or "")
        # medios multi-sede (El Momento postea la plana de Tabasco,
        # Metropolitano, Veracruz, QRoo...): x_filtro exige que el
        # texto nombre ESTA edición — si no, bajaría la de otro estado
        fil = normalizar(m.get("x_filtro", ""))
        if fil and fil not in txt:
            continue
        dice_portada = any(
            t in txt for t in ("portada", "edicion impresa",
                               "edicion digital", "primera plana",
                               "boletin", "hoy en", "contraportada"))
        for mc in p_.get("media_content") or []:
            u = html.unescape(mc["url"])
            u = re.sub(r"name=\w+", "name=large", u) \
                if "name=" in u else \
                u + ("&" if "?" in u else "?") + "name=large"
            try:
                r = requests.get(u, timeout=15)
            except Exception:
                continue
            if r.status_code == 200 and len(r.content) > 30000 \
                    and r.content not in imgs and \
                    (dice_portada or (_es_portada(r.content, 1.15, 1.6)
                                      and _texto_denso(r.content))):
                imgs.append(r.content)
        if len(imgs) >= 3:
            break
    return imgs


def toca_fb_posts() -> bool:
    """Posts cada 4 h y solo si hay cuenta sana en el pool — ritmo
    tranquilo para no quemar las cuentas."""
    return (not _fb_pausa()
            and bool(_fb_sesiones("posts"))
            and time.time() - _ULT_FB_POSTS >= 4 * 3600)


def _texto_post(lines: list, autor: str) -> tuple:
    """(titulo, cuerpo) de las líneas de un article de FB: salta
    boilerplate (nombre, 'Seguir', contadores, 'hace 2 h') hasta la
    primera línea sustantiva; corta antes de los botones de acción."""
    meta = {"seguir", "mensaje", "buscar", "ver todas las fotos",
            "fotos", "videos", "menciones", "resenas", "reseñas",
            "me gusta", "comentar", "compartir", "enviar"}
    au = normalizar(autor)
    resto, titulo = [], ""
    for l in lines:
        ln = normalizar(l).strip("· ").lower()
        if not ln or ln in meta or ln == au:
            continue
        if re.fullmatch(r"(hace\s+)?[\d.,]+\s*(mil\s+)?"
                        r"(min|h|d|hora?s?|minutos?|dias?|días?|"
                        r"seguidores|seguidos|semanas?)\b.*", ln):
            continue
        if re.fullmatch(r"[\d.,]+\s*(mil\s+)?(seguidores|seguidos|"
                        r"me gusta|comentarios|compartidos)", ln):
            continue
        resto.append(l)
    if not resto:
        return "", ""
    titulo = resto[0][:140]
    cuerpo = " ".join(resto[1:6])[:600]
    return titulo, cuerpo


def scrapear_posts_fb(cfg: dict):
    """Chucky: timeline de fuentes tipo 'fb' → posts como notas.
    Dedup por link; filtro de autor (posts 'sugeridos' de páginas
    ajenas se descartan); una instancia a la vez."""
    global _ULT_FB_POSTS, _FB_POSTS_CORRIENDO
    if _FB_POSTS_CORRIENDO or cfg.get("fb_posts_pausa") \
            or _fb_pausa():
        return
    _FB_POSTS_CORRIENDO = True
    _ULT_FB_POSTS = time.time()
    try:
        fuentes_fb = [f for f in cfg["fuentes"]
                      if f.get("tipo") == "fb"]
        if not fuentes_fb:
            return
        # clave canónica del post: /photo dedup por fbid (los params
        # __cft__/s= cambian por sesión y el mismo post colaba N veces);
        # el resto por path sin query
        def _clave_link(u: str) -> str:
            m = re.search(r"[?&]fbid=(\d+)", u)
            if m:
                return "fbid:" + m.group(1)
            return u.split("?")[0].rstrip("/")
        links_vistos = {_clave_link(n.get("link", ""))
                        for n in _noticias_cache()}
        from playwright.sync_api import sync_playwright
        nuevas = 0
        stats_pag = {}   # página → {x: extraídos, n: nuevos, r: razones}

        def _fecha_fb(lines: list):
            """Publicación real, no hora de scrapeo: el DOM trae el
            timestamp relativo ('19 h', '1d', 'a day ago', 'ayer') en
            las primeras líneas del article."""
            ahora = datetime.now()
            for l in lines[:8]:
                s = normalizar(l)
                m = re.search(r"(\d+)\s*min\b", s)
                if m:
                    return ahora - timedelta(minutes=int(m.group(1)))
                if re.search(r"an hour ago|hace una hora", s):
                    return ahora - timedelta(hours=1)
                m = re.search(r"(\d+)\s*h\b", s)
                if m:
                    return ahora - timedelta(hours=int(m.group(1)))
                if re.search(r"a day ago|hace un dia|ayer", s):
                    return ahora - timedelta(days=1)
                m = re.search(r"(\d+)\s*d\b", s)
                if m:
                    return ahora - timedelta(days=min(
                        int(m.group(1)), 14))
            return ahora

        with sync_playwright() as p:
            br = _launch(p)
            pg = None
            for ses in _fb_sesiones("posts"):
                pg = br.new_context(
                    storage_state=str(ses)).new_page()
                pg.wait_for_timeout(random.randint(2500, 5000))
                pg.goto("https://www.facebook.com/",
                        wait_until="domcontentloaded", timeout=30000)
                if _fb_sesion_caido(pg):
                    print(f"[fb-posts] sesión {ses.name} caída "
                          f"(checkpoint/ban) — pruebo siguiente")
                    _fb_marcar_muerta(ses.name)
                    pg.context.close()
                    pg = None
                    time.sleep(random.randint(8, 15))
                    continue
                break
            if pg is None:
                print("[fb-posts] TODAS las cuentas caídas — "
                      "sin barrido esta pasada")
                return
            for fuente in fuentes_fb:
                url = fuente["url"].split("#")[0]
                segs = [s for s in urlparse(url).path.split("/") if s]
                slug = (normalizar(segs[0]) if segs
                        and segs[0] != "profile.php" else "")
                try:
                    pg.goto(url, wait_until="domcontentloaded",
                            timeout=45000)
                    if _fb_sesion_caido(pg):
                        print("[fb-posts] sesión cayó a mitad del "
                              "barrido — la próxima pasada usa "
                              "otra cuenta")
                        break
                    pg.wait_for_timeout(5000)
                    prev = -1
                    posts_dict = {}
                    textos_vistos = set()
                    _JS_EXTRACT = """() => {
                        // desde cada permalink limpio hacia ARRIBA hasta
                        // el contenedor con timestamp ('19 h', 'hace')
                        // — los posts aquí NO son role=article (eso es
                        // el comment); el grid de 'Fotos' no tiene
                        // timestamp y muere solo
                        const out = [], seen = new Set();
                        for (const a of document.querySelectorAll(
                                'a[href*="/posts/"],'
                              + 'a[href*="story_fbid"],'
                              + 'a[href*="/permalink/"],'
                              + 'a[href*="/photo/?fbid="],'
                              + 'a[href*="/videos/"],'
                              + 'a[href*="/reel/"],'
                              + 'a[href*="pfbid"]')) {
                            let h = a.href;
                            if (h.includes('comment_id')) continue;
                            // '/reel/?s=tab' es nav — permalink de reel
                            // lleva ID numérico o pfbid
                            if (h.includes('/reel/')
                                    && !/reel\\/(\\d|pfbid)/.test(h))
                                continue;
                            if (seen.has(h)) continue;
                            let n = a.closest('[role="article"]');
                            if (!n) {
                                let c = a;
                                for (let i = 0; i < 10 && c; i++) {
                                    c = c.parentElement;
                                    if (!c) break;
                                    const t = c.innerText || '';
                                    if (/\\b\\d+\\s*(min|h|d)\\b|hace/i
                                            .test(t)
                                            && t.length > 60) {
                                        n = c; break;
                                    }
                                    if (t.length > 3000) break;
                                }
                            }
                            if (!n) continue;
                            seen.add(h);
                            // permalink del post dentro del contenedor:
                            // el anchor que nos trajo puede ser el
                            // /photo de la imagen — ese abre el visor,
                            // no la publicación
                            const canon = n.querySelector(
                                'a[href*="/posts/"],a[href*="pfbid"],'
                              + 'a[href*="/permalink/"]');
                            if (canon) {
                                h = canon.href;
                            }
                            let owner = '';
                            for (const o of n.querySelectorAll(
                                    'a[href*="facebook.com/"]')) {
                                const seg = new URL(o.href).pathname
                                    .split('/').filter(Boolean);
                                if (seg.length === 1 &&
                                    !/posts|photos|photo|reels|watch|groups|hashtag|permalink|reel|videos/
                                    .test(seg[0])) {
                                    owner = seg[0]; break;
                                }
                            }
                            const lines = (n.innerText || '')
                                .split(String.fromCharCode(10))
                                .map(s => s.trim())
                                .filter(Boolean).slice(0, 20);
                            // fotos del post: adjuntas bajo link
                            // /photo + imgs grandes (scontent) del
                            // contenedor — el avatar (≈40px) muere por
                            // el filtro de tamaño
                            const imgs = [];
                            for (const im of n.querySelectorAll(
                                    'a[href*="/photo"] img,'
                                  + 'a[href*="/photos"] img,'
                                  + 'img[src*="scontent"]')) {
                                const r = im.getBoundingClientRect();
                                if (r.width > 150 && im.src
                                        && !imgs.includes(im.src))
                                    imgs.push(im.src);
                            }
                            out.push({href: h, owner, lines,
                                      imgs: imgs.slice(0, 4)});
                        }
                        return out;
                    }"""
                    # click a 'Ver más' solo en fuentes con expandir —
                    # texto completo de los posts largos sin multiplicar
                    # la interacción con FB en todas las páginas
                    _JS_VERMAS = """() => {
                        let n = 0;
                        for (const art of document.querySelectorAll(
                                'div[role="article"]'))
                            for (const b of art.querySelectorAll(
                                    'div[role="button"],a[role="link"]')) {
                                const t = (b.textContent||'').trim();
                                if ((t === 'See more' || t === 'Ver más'
                                        || t === 'Ver mas')
                                        && b.offsetParent) {
                                    try { b.click(); n++; } catch(e) {}
                                }
                            }
                        return n;
                    }"""
                    # perfiles personales también expanden 'Ver más' —
                    # los comunicados largos (Ochoa Vidal/SUTAPJET)
                    # llegaban cortados al primer párrafo.
                    # 15/oct: default ON — nota a medias en Interés le
                    # resta credibilidad al producto; expandir:false
                    # queda como opt-out por fuente
                    expandir = fuente.get("expandir") is not False \
                        or bool(fuente.get("perfil"))
                    for _ in range(10):
                        pg.evaluate(
                            "for (const el of "
                            "document.querySelectorAll('*')) "
                            "if (el.scrollHeight > el.clientHeight+50) "
                            "el.scrollTop += 2200;")
                        pg.wait_for_timeout(1300)
                        if expandir:
                            try:
                                pg.evaluate(_JS_VERMAS)
                                pg.wait_for_timeout(700)
                            except Exception:
                                pass
                        try:
                            n = pg.evaluate(
                                "document.querySelectorAll("
                                "'a[href*=\"/posts/\"],a[href*=\"pfbid\"]"
                                ",a[href*=\"/permalink/\"]').length")
                        except Exception:
                            n = prev  # si el evaluate falla, sigue
                        # FB virtualiza el DOM — los articles vienen y
                        # van; acumular en cada paso o la ventana final
                        # puede quedar VACÍA (10 scrolls → 0 posts)
                        # última extracción gana — las pasadas
                        # posteriores al clic en 'Ver más' traen el
                        # texto completo, no el párrafo truncado
                        for post in pg.evaluate(_JS_EXTRACT):
                            posts_dict[post["href"]] = post
                        if n == prev:
                            break
                        prev = n
                    posts = list(posts_dict.values())
                    st = stats_pag.setdefault(
                        fuente["nombre"],
                        {"x": len(posts), "n": 0, "r": Counter()})
                    st["x"] = len(posts)
                    for post in posts[:20]:
                        clave = _clave_link(post["href"])
                        if clave in links_vistos:
                            st["r"]["visto"] += 1
                            continue
                        if slug and post.get("owner") \
                                and normalizar(post["owner"]) != slug:
                            st["r"]["ajeno"] += 1
                            continue   # post sugerido de otra página
                        # card de presentación de la página: bio
                        # (seguidores/hablando de esto) sin timestamp —
                        # los links /photo del módulo intro trepan a él
                        _ls = post.get("lines", [])
                        if any(re.search(
                                r"seguidores|hablando de esto|"
                                r"informaci[oó]n de contacto", l,
                                re.I) for l in _ls) and not any(
                                re.search(
                                    r"\b\d+\s*(min|h|d)\b|hace\b|ayer",
                                    l, re.I) for l in _ls):
                            st["r"]["bio"] += 1
                            continue
                        # PERFIL personal: filtro duro — su timeline
                        # mezcla compartidos de otras cuentas, módulos
                        # sugeridos y bio-cards. Solo pasa si el header
                        # del post comparte ≥2 tokens con el nombre de
                        # la cuenta y ninguna línea es boilerplate
                        if fuente.get("perfil"):
                            hdr = normalizar(
                                _ls[0] if _ls else "")
                            nom = {t for t in normalizar(
                                fuente["nombre"]).split()
                                if len(t) > 3}
                            if len({t for t in hdr.split()
                                    if t in nom}) < 2:
                                st["r"]["perfil"] += 1
                                continue   # post compartido/ajeno
                            if any(re.search(
                                    r"seguidores|hablando de esto|"
                                    r"informaci[oó]n de contacto|"
                                    r"indicador de estado", l, re.I)
                                    for l in _ls):
                                st["r"]["bio"] += 1
                                continue   # bio-card con timestamp
                        # lines[0] es el encabezado-autor del article
                        # (nombre público de la página — no el caption)
                        titulo, cuerpo = _texto_post(
                            post["lines"][1:] or [], fuente["nombre"])
                        if len(titulo) < 25:
                            st["r"]["sin-texto"] += 1
                            continue   # post sin texto útil
                        req = fuente.get("requiere")
                        if req and normalizar(req) not in normalizar(
                                f"{titulo} {cuerpo}"):
                            st["r"]["requiere"] += 1
                            continue   # la página mezcla columnas —
                            # solo las marcadas (ej. 'templo mayor')
                        clave_t = normalizar(titulo)[:80]
                        if clave_t in textos_vistos:
                            st["r"]["dup"] += 1
                            continue   # mismo post por otro permalink
                        textos_vistos.add(clave_t)
                        links_vistos.add(clave)
                        guardar_noticia({
                            "fecha": _fecha_fb(
                                post.get("lines", []))
                            .isoformat(timespec="seconds"),
                            "fuente": fuente["nombre"],
                            "via": "", "categoria": fuente.get(
                                "categoria", "columnas"),
                            "paywall": False,
                            "autor": fuente["nombre"],
                            "titulo": titulo,
                            "resumen": cuerpo,
                            "link": post["href"],
                            "imagen": (post.get("imgs")
                                       or [""])[0]})
                        nuevas += 1
                        st["n"] += 1
                except Exception as e:
                    print(f"[fb-posts] {fuente['nombre']}: {e}")
                pg.wait_for_timeout(4000)   # respiro entre páginas
            br.close()
        # telemetría: sin esto '0 nuevos' no distingue páginas vacías
        # (sesión muerta) de filtros que todo lo rechazan — /salud lo
        # muestra y el log resume los motivos dominantes
        try:
            vacias = [k for k, v in stats_pag.items() if not v["x"]]
            razones = Counter()
            for v in stats_pag.values():
                razones.update(v["r"])
            print(f"[fb-posts] {nuevas} posts nuevos "
                  f"de {len(fuentes_fb)} páginas"
                  f" ({len(vacias)} vacías"
                  + (f", rechazos: {dict(razones)}"
                     if razones else "") + ")")
            est = cargar_json(ESTADO_PORTADAS, {})
            est["fb_posts"] = {
                "fecha": datetime.now().strftime("%Y-%m-%d %H:%M"),
                "nuevas": nuevas, "vacias": vacias,
                "razones": dict(razones),
                "paginas": {k: {"x": v["x"], "n": v["n"],
                                "r": dict(v["r"])}
                            for k, v in stats_pag.items()}}
            _guardar_portadas(est)
        except Exception as e:
            print(f"[fb-posts] telemetría: {e}")
    finally:
        _FB_POSTS_CORRIENDO = False


_MESES_EN = ("Jan", "Feb", "Mar", "Apr", "May", "Jun",
             "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
_MESES_PORTADA = ("enero", "febrero", "marzo", "abril", "mayo",
                  "junio", "julio", "agosto", "septiembre", "octubre",
                  "noviembre", "diciembre")
_DIAS_PORTADA = ("lunes", "martes", "miercoles", "jueves",
                 "viernes", "sabado", "domingo")


def _sin_acentos(s: str) -> str:
    return unicodedata.normalize("NFD", s).encode("ascii", "ignore").decode()


def _tokens_fecha(hoy: datetime = None) -> set:
    """Todas las formas en que los medios escriben la fecha de hoy en
    URLs/filenames: 2026-10-07, 07-10-26, 07-octubre-2026,
    martes-06-de-octubre-de-2026, 7-de-octubre-de-2026, …"""
    h = hoy or datetime.now()
    mes = _MESES_PORTADA[h.month - 1]
    return {
        f"{h.year}-{h.month:02d}-{h.day:02d}",            # 2026-10-07
        f"{h.day:02d}-{h.month:02d}-{h.year}",            # 07-10-2026
        f"{h.day:02d}-{h.month:02d}-{h.year % 100:02d}",  # 07-10-26
        f"{h.day:02d}-{mes}-{h.year}",                    # 07-octubre-2026
        f"{h.day:02d}-{mes[:3]}-{h.year}",                # 07-oct-2026
        f"{h.day}-de-{mes}-de-{h.year}",                  # 7-de-octubre-de-2026
        f"{h.day:02d}-de-{mes}-de-{h.year}",              # 07-de-octubre-de-2026
        f"{mes}-{h.day}-de-{h.year}",                    # octubre-7-de-2026 (issuu)
        f"{mes[:3]}-{h.day}-de-{h.year}",                 # oct-7-de-2026
        f"{_DIAS_PORTADA[h.weekday()]}-{h.day:02d}-de-{mes}-de-{h.year}",
        f"{_DIAS_PORTADA[h.weekday()]}-{h.day:02d}-de-{mes[:5]}",  # martes-06-de-octub (slug issuu trunca)
        f"{h.day:02d}-de-{mes[:5]}",               # 06-de-octub
        f"{h.year}/{h.month:02d}/{h.day:02d}",            # 2026/10/07
        f"{h.year}/{h.month:02d}/{h.day}",                 # 2026/10/7 (Heraldo)
        f"{h.day:02d}/{mes}/{h.year}",                    # 07/octubre/2026
        f"{h.day:02d}/{mes[:3]}/{h.year}",                 # 07/oct/2026
        f"{h.day} {_MESES_EN[h.month - 1]} {h.year}",     # 8 Oct 2026 (pressreader)
        f"{h.day:02d} {_MESES_EN[h.month - 1]} {h.year}", # 08 Oct 2026
    }


def _con_fecha(txt: str, toks: set) -> bool:
    # '_' y espacios cuentan como separador (cr_cdmx_octubre_7_de_2026)
    t = re.sub(r'[_\s]+', '-', _sin_acentos(txt).lower())
    # (?!\d): '2026/10/8' no debe matchear dentro de
    # 'uploads/2026/10/839934717_…' (foto de nota, no portada)
    return any(re.search(re.escape(k) + r'(?!\d)', t) for k in toks)


def _imagen_portada_grande(imgs: list, toks: set,
                           solo_fecha: bool = False) -> bytes:
    """De una lista de URLs de imagen toma la de portada, pide la
    original sin -WxH y la devuelve como bytes si es válida. Con
    solo_fecha=True exige la fecha en el nombre (índices que reciclan
    nombres PORTADA-* con fecha de AYER, como tabascohoy/basta); en un
    post ya fechado basta que diga 'portada'."""
    buenas = [u for u in imgs
              if not re.search(r'logo|icon|banner|avatar|favicon|qr', u, re.I)]
    por = [u for u in buenas if _con_fecha(u, toks)]
    if not solo_fecha and not por:
        por = [u for u in buenas if 'portada' in _sin_acentos(u).lower()]
    for cand in (por or ([] if solo_fecha else buenas)):
        for u in (re.sub(r'-\d+x\d+(?=\.(?:jpe?g|png|webp))', '', cand),
                  cand):
            try:
                r = requests.get(u, timeout=20,
                                 headers={"User-Agent": "Mozilla/5.0"})
            except Exception:
                continue
            if len(r.content) > 30000:
                try:
                    Image.open(io.BytesIO(r.content)).verify()
                except Exception:
                    continue
                return r.content
    return None


def _portada_fecha(m: dict) -> list:
    """'edicion': índice cuyos posts son la edición del día, con URL o
    imagen fechada — Tabasco HOY (/edicion-digital/AAAA-MM-DD/), Diario
    Basta (igual), Diario de México (/edicion-impresa-DD-MM-AA), Diario
    de Tabasco (PORTADA-DD-MES-AAAA.jpg directo en la home)."""
    try:
        h = datetime.now()
        toks = _tokens_fecha(h)
        base = m["edicion"].rstrip("/")
        UA = {"User-Agent": "Mozilla/5.0"}
        cands = [f"{base}/{h.year}-{h.month:02d}-{h.day:02d}/"]
        if "{" in m["edicion"]:
            # plantilla con fecha: issuu.com/lajornadaonline/
            # docs/diario{ddmmyyyy} → diario08102026; Momento Tabasco
            # /uploads/{yyyy}/{mm}/TABASCO-{ddmmyy}.webp → imagen directa
            cands.insert(0, m["edicion"].format(
                ddmmyyyy=f"{h.day:02d}{h.month:02d}{h.year}",
                yyyymmdd=f"{h.year}{h.month:02d}{h.day:02d}",
                ddmmaa=f"{h.day:02d}{h.month:02d}{h.year % 100:02d}",
                yyyy=f"{h.year}", mm=f"{h.month:02d}",
                ddmmyy=f"{h.day:02d}{h.month:02d}{h.year % 100:02d}"))
        try:
            url_idx = cands[0] if "{" in m["edicion"] else m["edicion"]
            idx = requests.get(url_idx, timeout=15, headers=UA)
        except Exception:
            idx = None
        # la plantilla resolvió a la imagen misma — la fecha ya va
        # implícita en la URL (solo existe la de hoy, ayer da 404)
        if idx is not None and idx.status_code == 200 \
                and (idx.headers.get("content-type") or "").startswith(
                    "image/") and len(idx.content) > 30000:
            return [idx.content]
        if idx is not None and idx.status_code == 200:
            # 1) imagen fechada ya en la página (caso Diario de Tabasco) —
            #    aquí exigimos la fecha: el índice puede reciclar el
            #    nombre PORTADA-… de ayer antes de publicar la nueva
            imgs = re.findall(r'https?://[^"\' ]+\.(?:jpe?g|png|webp)',
                              idx.text)
            if b := _imagen_portada_grande(imgs, toks, solo_fecha=True):
                return [b]
            # 1b) tags <img> cuya alt/title lleven la fecha — Diario
            #     Avance: title="07/OCTUBRE/2026" + srcset hasta 2048px
            for tag in re.findall(r'<img[^>]+>', idx.text):
                if not _con_fecha(tag, toks):
                    continue
                cands_img = re.findall(
                    r'(?:src|srcset)="([^"]+)"', tag)
                srcs = []
                for c in cands_img:
                    srcs += [s.strip().split(' ')[0]
                             for s in c.split(',') if s.strip()]
                # la variante más ancha del srcset primero
                srcs = list(dict.fromkeys(srcs))
                if b := _imagen_portada_grande(
                        [re.sub(r'\?[^ ]*$', '', s) for s in srcs],
                        toks, solo_fecha=False):
                    return [b]
            # links fechados del índice (DMx: edicion-impresa-DD-MM-AA;
            # los embeds issuu van en src= de iframe — Contraréplica)
            for u in re.findall(r'(?:href|src)="([^"]+)"',
                                idx.text):
                # solo links que huelan a edición — los posts sueltos
                # /2026/10/08/nota llevan foto de nota, no portada
                if _con_fecha(u, toks) and re.search(
                        r'edicion|impresa|portada|issuu|flip|hemero'
                        r'|epaper|tapas|diario-digital|pdf', u, re.I):
                    cands.append(u if u.startswith("http")
                                 else urljoin(m["edicion"], u))
            # visores primero: el og:image de un ARTÍCULO fechado es
            # la foto de la nota, no la portada (Heraldo mezcla ambos)
            cands.sort(key=lambda u: 0 if re.search(
                r'issuu|flipsnack|fliphtml5|anyflip|pubhtml5', u)
                else 1)
        # 2) posts del día — el path ISO directo corre aunque el índice
        #    esté caído (Tabasco HOY, Basta: /edicion-digital/AAAA-MM-DD/)
        for pag in cands[:5]:
            try:
                # embed issuu → página pública del doc, que sí trae el
                # thumb en HTML (e.issuu.com/embed.html?d=D&u=U)
                m_emb = re.search(
                    r'issuu\.com/embed\.html\?d=([^&]+)&u=([^&\'" ]+)', pag)
                if m_emb:
                    pag = (f"https://issuu.com/{m_emb.group(2)}"
                           f"/docs/{m_emb.group(1)}")
                r = requests.get(pag, timeout=15, headers=UA)
            except Exception:
                continue
            if r.status_code != 200:
                continue
            # flipsnack publica su cover en og:image sin extensión —
            # en una página fechada el og:image ES la portada
            og = re.search(_OG_IMG, r.text)
            if og and re.search(
                    r'issuu|flipsnack|fliphtml5|anyflip|pubhtml5', pag):
                ir = requests.get(html.unescape(og.group(1)),
                                  timeout=20, headers=UA)
                if ir.status_code == 200 and len(ir.content) > 60000:
                    try:
                        Image.open(io.BytesIO(ir.content)).verify()
                        return [ir.content]
                    except Exception:
                        pass
            issuu_imgs = re.findall(
                r'https://image\.isu\.pub/[^"\' ]+?\.jpg', r.text)
            if issuu_imgs:
                full = issuu_imgs[0].replace('_thumb_large', '')
                ir = requests.get(full, timeout=20, headers=UA)
                if ir.status_code == 200 and len(ir.content) > 60000:
                    return [ir.content]
            imgs = re.findall(r'https?://[^"\' ]+\.(?:jpe?g|png|webp)',
                              r.text)
            if b := _imagen_portada_grande(imgs, toks):
                # sin 'portada' ni fecha en la URL la imagen pudo ser
                # banner o foto de nota (Fonacot 1600x197, foto 1196x781)
                if _es_portada(b):
                    return [b]
    except Exception:
        pass
    return []


def _portada_calameo(m: dict) -> list:
    """'calameo': página del medio que enlaza su doc Calaméo del día
    (Ahora Noticias → calameo.com/read/<bkcode>). El JSONP de
    d.calameo.com trae nombre fechado ('Jueves 08 De Octubre De 2026')
    y url.poster = i.calameoassets.com/<key>/large.jpg — www y p.
    calameoassets.com dan 403 desde aquí, d. e i. no."""
    try:
        UA = {"User-Agent": "Mozilla/5.0"}
        r = requests.get(m["calameo"], timeout=20, headers=UA)
        bk = re.search(r'calameo\.com/read/([a-z0-9]+)', r.text, re.I) \
            or re.search(r'bkcode=([a-z0-9]+)', r.text, re.I)
        if not bk:
            return []
        j = requests.get(
            f"https://d.calameo.com/3.0.0/book.php?callback=eval"
            f"&bkcode={bk.group(1)}", timeout=20, headers=UA)
        mjs = re.search(r'eval\((.*)', j.text)
        if not mjs:
            return []
        d = json.loads(mjs.group(1).rstrip(');'))
        c = d.get("content", {})
        # frescura: el nombre del doc lleva la fecha de la edición
        if not _con_fecha(str(c.get("name", "")), _tokens_fecha()):
            return []
        poster = c.get("url", {}).get("poster") or \
            c.get("url", {}).get("thumbnail") or ""
        if poster.startswith("//"):
            poster = "https:" + poster
        if not poster:
            return []
        ir = requests.get(poster, timeout=20, headers=UA)
        if ir.status_code == 200 and len(ir.content) > 30000:
            return [ir.content]
    except Exception:
        pass
    return []


def _portada_json(m: dict) -> list:
    """'json': endpoint JSON con la portada del día (Ovaciones publica
    jsonportadaedicionimpresa.json con portada.imagen_original)."""
    try:
        UA = {"User-Agent": "Mozilla/5.0"}
        data = requests.get(m["json"], timeout=15, headers=UA).json()
        por = data.get("portada") or data
        img = por.get("imagen_original") or por.get("imagen_thumb")
        if not img:
            return []
        # frescura: si la URL de la imagen trae fecha propia
        # (…/edicionimpresa/AAAA/MM/DD/uuid.jpg) debe ser HOY — un
        # updated_at fresco con imagen de ayer = no publicaron
        h = datetime.now()
        if re.search(r"/\d{4}/\d{2}/\d{2}/", img):
            if f"/{h:%Y/%m/%d}/" not in img:
                return []
        else:
            toks = _tokens_fecha()
            pista = " ".join(str(por.get(k) or data.get(k) or "")
                             for k in ("fecha", "date", "updated_at"))
            if not _con_fecha(pista + " " + img, toks):
                return []
        r = requests.get(img, timeout=20, headers=UA)
        if len(r.content) > 30000:
            return [r.content]
    except Exception:
        pass
    return []


def _portada_adobe(m: dict, png: Path) -> bool:
    """Unomásuno: la home enlaza un PDF compartido en acrobat.adobe.com
    (/id/urn:aaid:...). El visor WASM pide la página 0 como jpeg a
    cdn-sharing.adobecc.com — interceptamos esa respuesta directo."""
    try:
        r = requests.get(m["url"], timeout=15,
                         headers={"User-Agent": "Mozilla/5.0"})
        mm = re.search(
            r'https://acrobat\.adobe\.com/id/urn:[^"\'\s<>?]+', r.text)
        if not mm:
            return False
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            br = _launch(p)
            pg = br.new_page()
            try:
                with pg.expect_response(
                        lambda r:
                        "cdn-sharing.adobecc.com/rendition/" in r.url
                        and "page=0" in r.url, timeout=45000) as ri:
                    pg.goto(mm.group(0), wait_until="commit",
                            timeout=30000)
                img = ri.value.body()
            finally:
                br.close()
        if len(img) < 30000:
            return False
        Image.open(io.BytesIO(img)).convert("RGB").save(png, "PNG")
        return _img_ok(png)
    except Exception:
        return False


def _portada_pdf(m: dict, png: Path) -> tuple:
    """Medios que publican el ejemplar completo en PDF (El Día): busca el
    link .pdf en su web, lo baja y renderiza la página 1 con pdftoppm.
    Devuelve (ok, fallback_url) — el post "edición impresa" sirve de
    página alterna para el screenshot cuando el PDF ya no existe."""
    fallback = ""
    try:
        r = requests.get(m["url"], timeout=15,
                         headers={"User-Agent": "Mozilla/5.0"})
        dom = re.search(r"https?://([^/]+)", m["url"]).group(1)
        clave = _slug_portada(m["nombre"]).replace("-", "")[:8]  # "unomasun"
        # preferir PDFs del mismo dominio con el nombre del medio en el
        # archivo — evita el PDF del papel hermano del grupo editorial
        cands = re.findall(r'https?://[^"\'\s<>]+\.pdf', r.text)
        url_pdf = ""
        for u in cands:
            # solo el nombre de archivo — el dominio siempre "contiene"
            # la clave (elindependiente.mx) y ganaba el MEDIAKIT
            if dom in u and clave in normalizar(u.split("/")[-1]):
                url_pdf = u
                break
        if not url_pdf:
            # archivo fechado: /edicion-impresa/AAAA/MM/DD/... (El
            # Independiente) — el post de hoy lleva el PDF del ejemplar
            hoy_dir = datetime.now().strftime("/%Y/%m/%d/")
            posts = [u for u in
                     re.findall(r'href="([^"]+)"', r.text)
                     if hoy_dir in u]
            if posts:
                rp2 = requests.get(posts[0], timeout=15,
                                   headers={"User-Agent": "Mozilla/5.0"})
                fallback = posts[0]
                cand = re.findall(r'https?://[^"\'\s<>]+\.pdf', rp2.text)
                for u in cand:
                    if dom in u and "edicion" in normalizar(u):
                        url_pdf = u
                        break
                if not url_pdf:
                    for u in cand:
                        if dom in u:
                            url_pdf = u
                            break
        if not url_pdf and not m.get("pdf_estricto"):
            # pdf_estricto (El Independiente): cualquier PDF del dominio
            # puede ser MEDIAKIT/publicidad — solo vale el post fechado
            for u in cands:
                if dom in u:
                    url_pdf = u
                    break
        if not url_pdf:
            # el home es SPA: busca el post "edición impresa" vía WP API
            # (Unomásuno publica un post diario con el PDF del ejemplar)
            rs = requests.get(f"https://{dom}/wp-json/wp/v2/posts",
                              params={"search": "edicion impresa",
                                      "per_page": 5}, timeout=15,
                              headers={"User-Agent": "Mozilla/5.0"})
            if rs.status_code == 200 and isinstance(rs.json(), list):
                hoy_p = datetime.now().strftime("%Y-%m-%d")
                for post in rs.json():
                    # solo edición de hoy — la de ayer/3 sept NO sirve
                    if not post.get("date", "").startswith(hoy_p):
                        continue
                    fallback = post.get("link", "") or fallback
                    cand = re.findall(r'https?://[^"\'\s<>]+\.pdf',
                                      json.dumps(post))
                    for u in cand:
                        if dom in u and clave in normalizar(
                                u.split("/")[-1]):
                            url_pdf = u
                            break
                    if not url_pdf:  # filename sin nombre del medio
                        for u in cand:
                            if dom in u:
                                url_pdf = u
                                break
                    if url_pdf:
                        break
        if not url_pdf:
            # PDF detrás del visor de Adobe (Unomásuno comparte su
            # ejemplar vía acrobat.adobe.com, no hay .pdf directo)
            if _portada_adobe(m, png):
                return True, fallback
            return False, fallback
        # URL fechada /AAAA/MM/DD/ pero de AYER = edición vieja (24 Horas
        # sube el PDF ~7am): mejor reintentar en la siguiente corrida
        d = re.search(r"/20\d\d/\d\d/\d\d/", url_pdf)
        if d and d.group(0)[1:-1] != \
                datetime.now().strftime("%Y/%m/%d"):
            return False, fallback
        tmp = png.parent / "_tmp.pdf"
        rp = requests.get(url_pdf, timeout=40,
                          headers={"User-Agent": "Mozilla/5.0"})
        if rp.status_code != 200 or len(rp.content) < 50000:
            return False, fallback
        tmp.write_bytes(rp.content)
        prefijo = str(png.with_suffix(""))
        subprocess.run(["pdftoppm", "-f", "1", "-l", "1", "-png", "-r", "110",
                        str(tmp), prefijo], timeout=30, capture_output=True)
        tmp.unlink(missing_ok=True)
        # pdftoppm nombra prefijo-1.png o prefijo-01.png según el padding
        salidas = sorted(png.parent.glob(f"{png.stem}-*.png"))
        if salidas:
            salidas[0].replace(png)
            return True, fallback
    except Exception:
        pass
    return False, fallback


_BLOQ_ADS = re.compile(
    r"googlesyndication|doubleclick|adservice|adnxs|taboola|outbrain|"
    r"amazon-adsystem|criteo|scorecardresearch|facebook\.net|connect\.facebook|"
    r"googletagmanager|google-analytics|pubmatic|openx|smartadserver|"
    r"teads|mgid|revcontent|contextual\.media\.net|ads\.|\.ad\.|tracker",
    re.I)


def _shot_playwright(url: str, png: Path):
    """Screenshot con playwright: bloquea redes de ads a nivel red (nunca
    pintan), espera DOM+lazy-load, cierra consentimientos y mata overlays
    (modal de publicidad/paywall que cubre la portada)."""
    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        browser = _launch(p)
        page = browser.new_page(
            viewport={"width": 1280, "height": 2600},
            device_scale_factor=2,   # screenshots 2× — texto legible en A4
            user_agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                       "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")
        # el ad-block viaja en la capa de red: los banners ni cargan
        page.route("**/*",
                   lambda r: r.abort()
                   if _BLOQ_ADS.search(r.request.url)
                   else r.continue_())
        try:
            page.goto(url, wait_until="domcontentloaded", timeout=30000)
            page.wait_for_timeout(4000)   # primer render + recursos
        except Exception:
            pass
        for sel in ("button:has-text('Aceptar')", "button:has-text('Acepto')",
                    "button:has-text('Accept')", "#didomi-notice-agree-btn"):
            try:
                page.click(sel, timeout=700)
            except Exception:
                pass
        _KILL_POPUP = """() => {
            for (const el of document.querySelectorAll('*')) {
                const s = getComputedStyle(el);
                if ((s.position === 'fixed' || s.position === 'absolute') &&
                    parseInt(s.zIndex || 0) > 50 &&
                    el.clientWidth > innerWidth * .45 &&
                    el.clientHeight > innerHeight * .25)
                    el.remove();
            }
            document.body.style.overflow = 'auto';
            document.documentElement.style.overflow = 'auto';
        }"""
        page.evaluate(_KILL_POPUP)
        for _ in range(3):                # scroll profundo → lazy-load
            page.mouse.wheel(0, 1600)
            page.wait_for_timeout(1200)
        page.mouse.wheel(0, -99999)       # de regreso arriba del todo
        page.wait_for_timeout(1000)
        page.keyboard.press("Escape")     # cierra modal que reaparezca
        page.wait_for_timeout(600)
        page.evaluate(_KILL_POPUP)        # 2º pase: popups que salen tarde
        page.wait_for_timeout(400)
        # muros anti-bot: no guardar el "Algo ha salido mal" como portada
        titulo = (page.title() or "").lower()
        cuerpo_txt = page.evaluate("document.body ? "
                                   "document.body.innerText.slice(0,400) "
                                   ": ''").lower()
        if re.search(r"algo ha salido mal|request blocked|access denied|"
                     r"403 error|verify you|not authorized|"
                     r"something went wrong|bloqueada por|"
                     r"security verification|security service to protect|"
                     r"bluestack|cloudfront.*error",
                     titulo + " " + cuerpo_txt):
            browser.close()
            raise RuntimeError("bloqueado por anti-bot")
        page.screenshot(path=str(png))
        browser.close()


_PAT_BLOQ_HTTP = re.compile(
    r"algo ha salido mal|request blocked|access denied|"
    r"something went wrong|security verification|"
    r"security service to protect|bluestack|cloudfront.*error", re.I)


def _url_bloqueada(url: str) -> bool:
    """Check anti-bot para el fallback chromium (que no inspecciona DOM):
    trae el HTML con requests y busca firma de página de bloqueo."""
    try:
        r = requests.get(url, timeout=15,
                         headers={"User-Agent": "Mozilla/5.0 (X11; Linux "
                                  "x86_64) AppleWebKit/537.36 (KHTML, like "
                                  "Gecko) Chrome/126.0.0.0 Safari/537.36"})
        return bool(_PAT_BLOQ_HTTP.search(r.text[:30000]))
    except Exception:
        return False


def _launch(p):
    """Playwright sin browsers propios → usa el google-chrome del
    sistema; si existiera el bundle de playwright también sirve."""
    try:
        return p.chromium.launch()
    except Exception:
        return p.chromium.launch(channel="chrome")


def _shot_img_mayor(url: str, png: Path, toks=None):
    """Visores tipo PressReader: la portada es el <img> más grande del
    canvas — screenshot del elemento solo, sin la UI del lector.
    Si se pasan `toks`, exige que el texto de la página lleve la
    fecha de hoy — PR muestra '7 Oct 2026' hasta que sube la nueva
    edición y sin esto capturaríamos la de ayer."""
    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        browser = _launch(p)
        page = browser.new_page(
            viewport={"width": 1280, "height": 1400},
            device_scale_factor=2,   # screenshots 2× — texto legible en A4
            user_agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                       "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")
        page.route("**/*",
                   lambda r: r.abort()
                   if _BLOQ_ADS.search(r.request.url)
                   else r.continue_())
        page.goto(url, wait_until="domcontentloaded", timeout=30000)
        if toks is not None:
            page.wait_for_timeout(4000)
            try:
                txt = page.evaluate("document.body.innerText")
                if not _con_fecha(txt, toks):
                    browser.close()
                    return   # edición vieja aún — no capturar
            except Exception:
                pass
        best_src = None
        # poll: el <img> de la portada tarda en cargar (lazy) — hasta 30s
        for _ in range(30):
            page.wait_for_timeout(1000)
            els = page.locator("img")
            best_src, best_w = None, 0
            for i in range(els.count()):
                e = els.nth(i)
                try:
                    nw = e.evaluate("el => el.naturalWidth")
                    if nw and nw > best_w:
                        best_w, best_src = nw, e.get_attribute("src")
                except Exception:
                    pass
            if best_w >= 500:
                break
        if best_src and not best_src.startswith("data:"):
            # sube el scale del CDN (preview chico → alta resolución)
            for u in (re.sub(r"scale=\d+", "scale=150", best_src),
                      best_src):
                try:
                    r = page.request.get(
                        u, headers={"Referer": url.rsplit("/", 1)[0] + "/"})
                    if r.ok and len(r.body()) > 40000:
                        png.write_bytes(r.body())
                        browser.close()
                        return
                except Exception:
                    pass
        page.screenshot(path=str(png))   # último recurso
        browser.close()


def _img_ok(path: Path) -> bool:
    """Rechaza capturas en blanco/negras (bloqueo anti-bot renderizado,
    placeholder de kiosko): si la imagen es casi monocromática no es
    una portada."""
    try:
        if not path.exists() or path.stat().st_size < 10000:
            return False
        img = Image.open(path).convert("L").resize((96, 96))
        lo, hi = img.getextrema()
        px = list(img.get_flattened_data()
                  if hasattr(img, "get_flattened_data")
                  else img.getdata())
        mean = sum(px) / len(px)
        blanco = sum(1 for v in px if v > 240) / len(px)
        # monocromática (placeholder), negra (video/fondo) o ~toda blanca
        # (página de bloqueo/security-check son texto suelto sobre blanco)
        return (hi - lo) > 25 and mean > 40 and blanco < 0.93
    except Exception:
        return False


def _es_hoy(path: Path) -> bool:
    return path.exists() and \
        datetime.fromtimestamp(path.stat().st_mtime).date() == \
        datetime.now().date()


# NO WEB SHOTS — orden del usuario: ningún medio puede caer a
# screenshot de homepage; solo impresas reales (kiosko/fb/issuu/etc).
# Las estrategias que SI capturan la propia portada (PR visor,
# img_portada, pdf) no son screenshots de homepage y siguen activas.
_WEB_SHOTS = False


def _tiene_img_hoy(base: Path) -> bool:
    """Impresa o shot principal del medio, de HOY y no blanco/negro."""
    return any(_es_hoy(c) and _img_ok(c)
               for c in (base.with_suffix(".jpg"),
                         base.with_suffix(".png")))


def _es_doble(m: dict) -> bool:
    """Medios con portada impresa también llevan captura de su web —
    salvo `solo_impresa` (Excélsior: su /impreso es una galería de
    secciones, no portada; CORAT: su sitio murió, solo vale FB)."""
    if m.get("solo_impresa"):
        return False
    return any(m.get(k) for k in ("kiosko", "fb", "issuu", "flip",
                                  "pr", "pdf"))


def _medio_listo(m: dict, base: Path, tardia: bool) -> bool:
    """¿Este medio ya tiene todo lo de HOY? En pase tardío las dobles
    también deben traer su -web.png."""
    if not _tiene_img_hoy(base):
        return False
    # fotos_min: posts FB con N portadas (TAD publica 2) — si solo cayó
    # 1, sigue pendiente para que el siguiente intento traiga el resto
    n_min = int(m.get("fotos_min", 0))
    if n_min > 1:
        n_img = 1 + sum(1 for _ in base.parent.glob(f"{base.name}-[0-9].jpg"))
        if n_img < n_min:
            return False
    if _WEB_SHOTS:
        web = base.with_name(base.name + "-web.png")
        # los dobles (impresa+web) exigen las dos: la web se captura en
        # cuanto aparece la impresa, a cualquier hora de la ventana
        if _es_doble(m) and not (_es_hoy(web) and _img_ok(web)):
            return False
    return True


def _captura_medio(m: dict, base: Path, tardia: bool,
                   cfg: dict = None) -> bool:
    """Intenta las estrategias del medio. `tardia` = pase cercano al
    cierre (≥ hora_web): recién ahí se tiran screenshots web — a las
    00:30 la homepage todavía muestra la portada de ayer o popups de
    madrugada."""
    data = []
    src_fb = False
    src_edic = False
    tiene_impresa = False
    img_ok = _tiene_img_hoy(base)
    if not img_ok:
        if m.get("kiosko") and not data:
            b = _bajar_portada_kiosko(m)
            data = [b] if b else []
        if m.get("edicion") and not data:
            data = _portada_fecha(m)
            src_edic = bool(data)
        if m.get("json") and not data:
            data = _portada_json(m)
        if m.get("flowpaper") and not data:
            b = _portada_flowpaper(m)
            data = [b] if b else []
        if m.get("fb") and not data:
            data = _bajar_portada_fb(m)
            src_fb = bool(data)
            if not data:
                print(f"[fb] {m['nombre']}: sin portada usable "
                      "(sin post de hoy o 0 imágenes bajadas)")
        if m.get("x") and not data:
            data = _bajar_portada_x(m)
            src_fb = bool(data)   # media social: mismo filtro
            if not data:
                print(f"[x] {m['nombre']}: sin portada usable "
                      "(sin tweet de hoy con media)")
        if m.get("calameo") and not data:
            data = _portada_calameo(m)
        if m.get("issuu") and not data:
            # la URL puede llevar plantilla de fecha:
            # cr_cdmx_{mmmm}_{d}_de_{aaaa} → cr_cdmx_octubre_8_de_2026
            hu = datetime.now()
            slug_iss = str(m["issuu"]).format(
                d=hu.day, dd=f"{hu.day:02d}",
                mmmm=_MESES_PORTADA[hu.month - 1], aaaa=hu.year)
            b = _portada_issuu(
                slug_iss.rstrip("/").rsplit("/", 1)[-1])
            data = [b] if b else []
        if m.get("flip") and not data:
            b = _portada_flip(m["flip"])
            data = [b] if b else []
        if m.get("pr") and not data:
            # pressreader: el <img> mayor de su visor es la portada —
            # pero PR muestra la edición de AYER hasta ~1am: si la
            # imagen es la misma de ayer no vale, sigue pendiente
            png_pr = base.with_suffix(".png")
            try:
                _shot_img_mayor(m["pr"], png_pr, _tokens_fecha())
                if _img_ok(png_pr) and png_pr.stat().st_size > 40000 \
                        and not _misma_img_ayer(png_pr, base.name) \
                        and _vision_es_portada(
                            cfg, png_pr.read_bytes()) is not False:
                    tiene_impresa = True
                else:
                    png_pr.unlink(missing_ok=True)
            except Exception:
                pass
        if data:
            base.with_suffix(".png").unlink(missing_ok=True)
            n_ok = 0
            for i, d in enumerate(data):
                # nombre SECUENCIAL de aceptadas — si la 1ª se rechaza,
                # la 2ª toma {slug}.jpg (antes quedaban huérfanos
                # {slug}-2.jpg sin {slug}.jpg: medio invisible)
                nom = base.name if n_ok == 0 else f"{base.name}-{n_ok + 1}"
                f = base.parent / f"{nom}.jpg"
                # kiosko a veces sirve la portada de AYER bajo la URL de
                # hoy — bytes idénticos a la ÚLTIMA edición conocida =
                # no es edición nueva; FB la re-encodea (bytes cambian)
                # → comparar también visual a 64×64 (CORAT/XHVX
                # repitieron la del jueves posteada a las 23h)
                ayer = _ultima_img_previa(f.stem)
                if ayer is not None and ayer.read_bytes() == d:
                    continue
                f.write_bytes(d)
                # forma 1.15 para fb/edicion (portadas reales llegan a
                # 1.26 — Sol del Sureste 11/oct); fb además exige
                # densidad de texto (memes/fotos de feed se cuelan)
                # visión SOLO si pasó las guardas baratas — un meme ya
                # rechazado no debe gastar una llamada a Gemini
                guardas = _img_ok(f) \
                        and ((not src_fb and not src_edic)
                             or _es_portada(d, 1.15)) \
                        and (not src_fb or _texto_denso(d)) \
                        and not _misma_img_ayer(f, f.stem) \
                        and not _img_repetida_hoy(f, base.name) \
                        and not _img_repetida_propia(f, base.name)
                vis = _vision_es_portada(cfg, d) if guardas else None
                # fb/x es el canal más ruidoso (flyers, memes, fotos
                # de nota): con Gemini configurado se exige veredicto
                # POSITIVO — si la API falla la candidata se descarta
                # y el medio reintenta en el siguiente pase, en vez de
                # colar basura (20/oct: meme 'Canada' en XEVT, foto de
                # costales en XHVX pasaron con vision=None). Sin key
                # configurada se mantiene el comportamiento permisivo.
                if src_fb and cfg and _gemini_key(cfg):
                    veredicto = vis is True
                else:
                    veredicto = vis is not False
                if guardas and veredicto:
                    n_ok += 1
                else:
                    print(f"[portadas] {m['nombre']} ✗ candidata "
                          f"descartada — guardas={guardas} visión={vis}")
                    f.unlink(missing_ok=True)
            tiene_impresa = n_ok > 0
        elif tiene_impresa:
            pass   # pr ya escribió su PNG arriba
        elif m.get("pdf"):
            # PDF del ejemplar → página 1 (es del día, puede ir temprano)
            png = base.with_suffix(".png")
            ok, _ = _portada_pdf(m, png)
            # El Día cuelga el PDF de AYER hasta después de la 1am —
            # mismo guard que PR: si es la edición de ayer, no vale
            if ok and _misma_img_ayer(png, base.name):
                png.unlink(missing_ok=True)
                ok = False
            if ok and _vision_es_portada(
                    cfg, png.read_bytes()) is False:
                png.unlink(missing_ok=True)
                ok = False
            tiene_impresa = ok and _img_ok(png)
        if _WEB_SHOTS and not tiene_impresa and tardia \
                and not m.get("solo_impresa"):
            # último recurso: screenshot de la web — solo en el pase
            # tardío, de madrugada la home muestra la edición de ayer
            png = base.with_suffix(".png")
            url_tiro = m["url"]
            if m.get("pdf"):
                _, fb2 = _portada_pdf(m, png)
                if _img_ok(png) and not _misma_img_ayer(
                        png, base.name):
                    tiene_impresa = True
                else:
                    url_tiro = fb2 or url_tiro
            if not tiene_impresa:
                try:
                    _shot_playwright(url_tiro, png)
                except RuntimeError:
                    pass   # anti-bot: no caer al chromium ciego que sí
                           # guarda la página de bloqueo
                except Exception:
                    # chromium ciego: playwright falló (timeout/crash)
                    # — verifica por HTTP que no sea página de bloqueo
                    if not _url_bloqueada(url_tiro):
                        subprocess.run(
                            ["chromium", "--headless", "--no-sandbox",
                             "--disable-gpu", "--hide-scrollbars",
                             "--window-size=1280,2600",
                             f"--screenshot={png}", url_tiro],
                            timeout=45, capture_output=True)
                if not _img_ok(png):
                    png.unlink(missing_ok=True)
    # doble portada: con impresa (jpg/pdf) también portada web — solo en
    # el pase tardío, antes la home sigue mostrando la edición de ayer
    tiene_impresa = tiene_impresa or _tiene_img_hoy(base)
    if _WEB_SHOTS and tiene_impresa and _es_doble(m):
        # web apenas cayó la impresa: el sitio ya muestra la edición
        # del día — no hay que esperar a hora_web
        web = base.with_name(base.name + "-web.png")
        imp = _portada_img(base.name)
        web_vieja = (not _es_hoy(web)) or (
            imp.exists() and web.exists()
            and web.stat().st_mtime < imp.stat().st_mtime)
        if web_vieja:
            try:
                url_web = m.get("url_web2") or m["url"]
                if m.get("img_portada"):
                    _shot_img_mayor(url_web, web)
                else:
                    _shot_playwright(url_web, web)
                if not _img_ok(web) or web.stat().st_size < 40000:
                    web.unlink(missing_ok=True)
            except Exception:
                web.unlink(missing_ok=True)
    return _tiene_img_hoy(base)


def _portada_flowpaper(m: dict):
    """Lectores FlowPaper tras Cloudflare (Capital Índigo): la edición es
    un PDF fechado que el visor baja con pdf.js. requests no pasa el
    challenge — Playwright entra al visor, espera CF y pide el PDF con
    fetch dentro del mismo origen.
    m['flowpaper']    = plantilla del PDF con {aaaa} {mm} {dd} {aaaammdd}
    m['flowpaper_visor'] = página del lector (default: /…/index.html del
                           directorio del PDF)"""
    import base64, subprocess, tempfile
    h = datetime.now()
    url_pdf = m["flowpaper"].format(
        aaaa=h.year, mm=f"{h.month:02d}", dd=f"{h.day:02d}",
        aaaammdd=f"{h:%Y%m%d}")
    visor = m.get("flowpaper_visor") or \
        url_pdf.rsplit("/", 3)[0] + "/index.html"
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            br = _launch(p)
            pg = br.new_page(
                user_agent="Mozilla/5.0 (X11; Linux x86_64) "
                           "AppleWebKit/537.36 (KHTML, like Gecko) "
                           "Chrome/126.0.0.0 Safari/537.36")
            pg.goto(visor, wait_until="domcontentloaded",
                    timeout=45000)
            pg.wait_for_timeout(9000)   # CF managed challenge auto-pasa
            host = url_pdf.split("/")[2]
            fr = next((f for f in pg.frames if host in f.url), pg)
            b64 = fr.evaluate("""async (u) => {
                const r = await fetch(u);
                if (!r.ok) return 'ERR' + r.status;
                const buf = await r.arrayBuffer();
                let bin = ''; const b = new Uint8Array(buf);
                for (let i = 0; i < b.length; i += 8192)
                    bin += String.fromCharCode.apply(
                        null, b.subarray(i, i + 8192));
                return btoa(bin);
            }""", url_pdf)
            br.close()
        if b64.startswith("ERR"):
            return None
        pdf = base64.b64decode(b64)
        if len(pdf) < 200000 or not pdf.startswith(b"%PDF"):
            return None
        tmp_pdf = Path(tempfile.mktemp(suffix=".pdf"))
        tmp_pdf.write_bytes(pdf)
        tmp_out = str(tmp_pdf) + "_p1"
        subprocess.run(["pdftoppm", "-f", "1", "-l", "1", "-jpeg",
                        "-r", "110", str(tmp_pdf), tmp_out],
                       timeout=60, capture_output=True)
        tmp_pdf.unlink(missing_ok=True)
        for gen in Path(tempfile.gettempdir()).glob(
                Path(tmp_out).name + "*"):
            data = gen.read_bytes()
            gen.unlink(missing_ok=True)
            if len(data) > 60000:
                return data
    except Exception:
        pass
    return None


def _es_vertical(b: bytes) -> bool:
    try:
        im = Image.open(io.BytesIO(b))
        return im.height > im.width
    except Exception:
        return False


def _es_portada(b: bytes, r_min: float = 1.3,
                r_max: float = 0) -> bool:
    """Vertical Y angosta — proporción de primera plana (~0.55–0.77
    w/h). Un flyer vertical 4:5 o cuadrado (600x750 = 0.8, posts de
    evento) NO es portada aunque sea alto; ni tampoco un reel
    DEMASIADO alto (h/w>1.6 = stories/bait, no plana impresa).
    r_min menor (1.15) descarta solo lo landscape; r_max=0 desactiva
    el techo."""
    try:
        im = Image.open(io.BytesIO(b))
        r = im.height / im.width
        return r >= r_min and (not r_max or r <= r_max)
    except Exception:
        return False


def _img_repetida_hoy(nuevo: Path, propio: str) -> bool:
    """La misma imagen ya capturada HOY de OTRO medio = gráfica viral
    compartida entre páginas (el 11/oct 'Piden ayuda Lenín' cayó como
    portada en El Heraldo, El Sol y XEVT). Comparación visual 64×64
    contra todo lo del día, excluyendo los archivos del propio medio."""
    try:
        a = Image.open(nuevo).convert("L").resize((64, 64))
        pa = list(a.getdata())
    except Exception:
        return False
    for f in sorted(nuevo.parent.glob("*.*")):
        if f.suffix not in (".jpg", ".png"):
            continue
        if f.stem == propio or f.stem.startswith(propio + "-"):
            continue
        try:
            b = Image.open(f).convert("L").resize((64, 64))
            diff = sum(abs(p - q) for p, q in zip(pa, b.getdata()))
            if diff / (64 * 64) < 8:
                return True
        except Exception:
            continue
    return False


def _texto_denso(b: bytes) -> bool:
    """Densidad de bordes — una primera plana está saturada de texto
    chico (0.19–0.31 en las portadas reales); fotos/flyers/memes
    quedan <=0.15 la mayoría. Guard extra para posts FB: la forma
    vertical sola no distingue plana de gráfica social."""
    try:
        im = Image.open(io.BytesIO(b)).convert("L")
        w, h = im.size
        im = im.resize((400, max(1, int(400 * h / w))))
        px = list(im.filter(ImageFilter.FIND_EDGES).getdata())
        return sum(1 for v in px if v > 40) / len(px) >= 0.15
    except Exception:
        return False


def _img_repetida_propia(nuevo: Path, propio: str) -> bool:
    """La misma imagen ya quedó guardada HOY del MISMO medio a otra
    resolución — FB sirve la plana dos veces (feed + visor) y el 15/oct
    xhvx.jpg y xhvx-3.jpg eran la misma plana. Misma comparación visual
    64×64 de _img_repetida_hoy pero solo contra los archivos propios."""
    try:
        a = Image.open(nuevo).convert("L").resize((64, 64))
        pa = list(a.getdata())
    except Exception:
        return False
    for f in sorted(nuevo.parent.glob(f"{propio}*.*")):
        if f == nuevo or f.suffix not in (".jpg", ".png"):
            continue
        try:
            b = Image.open(f).convert("L").resize((64, 64))
            diff = sum(abs(p - q) for p, q in zip(pa, b.getdata()))
            if diff / (64 * 64) < 8:
                return True
        except Exception:
            continue
    return False


def _vision_es_portada(cfg: dict, b: bytes):
    """Gemini vision: ¿es una primera plana? Veredicto final para TODA
    imagen candidata — ratio + densidad no distinguen flyer de plana
    (15/oct: flyer de Melania y comunicados SEDENA/secundaria colados
    como portada por XHVX/XEVT). Regresa True/False; None si no se pudo
    consultar → NO bloquea la imagen."""
    if not cfg or not _gemini_key(cfg):
        return None
    mime = "image/png" if b[:4] == b"\x89PNG" else "image/jpeg"
    r = None
    for intento in range(3):
        # la API falla en ráfagas (429/5xx) — un None transitorio no
        # debe descartar una portada real (Capital Índigo 20/oct: el
        # post #EnPortada se rechazó 4 veces con vision=None)
        try:
            r = requests.post(
                "https://generativelanguage.googleapis.com/v1beta/"
                f"models/{cfg['gemini'].get('modelo', 'gemini-3.1-flash-lite')}"
                ":generateContent",
                params={"key": _gemini_key(cfg)},
                json={"contents": [{"parts": [
                    {"text": "¿Esta imagen es la PORTADA o PRIMERA PLANA "
                             "de un medio de noticias — un diario impreso "
                             "O la portada digital de un noticiero "
                             "(cabecera del medio, fecha o número de "
                             "edición y varios titulares/notas)? "
                             "Comunicados, flyers, promocionales, memes o "
                             "fotos sueltas NO son portadas. "
                             "Responde solo SI o NO."},
                    {"inline_data": {"mime_type": mime,
                                     "data": base64.b64encode(b).decode()}
                     }]}]},
                timeout=60)
            if r.status_code == 200:
                break
            r = None
        except Exception:
            r = None
        if intento < 2:
            time.sleep(4)
    if r is None:
        return None
    try:
        parts = (r.json()["candidates"][0]["content"].get("parts") or [])
        txt = "".join(p.get("text", "") for p in parts
                      if not p.get("thought")).strip().lower()
        # Gemini a veces decora la respuesta ('**SÍ.**', '- NO.') —
        # sin esta limpieza caía a None y se descartaban portadas
        # reales (Capital Índigo 20/oct)
        txt = re.sub(r"^[^a-záéíóúñ]+", "", txt)
        if txt.startswith(("si", "sí")):
            return True
        if txt.startswith("no"):
            return False
        return None
    except Exception:
        return None


def _ultima_img_previa(nombre_base: str):
    """Última imagen de este medio en días anteriores — camina hasta 10
    días hacia atrás. Si ayer no se capturó NADA (medio sin edición el
    sábado), su última portada conocida queda en anteayer — comparar
    contra ella evita aceptar la misma edición como 'nueva' al día
    siguiente."""
    for i in range(1, 11):
        d = _dir_dia(datetime.now() - timedelta(days=i))
        for ext in (".jpg", ".png"):
            f = d / f"{nombre_base}{ext}"
            if f.exists():
                return f
    return None


def _misma_img_ayer(nuevo: Path, nombre_base: str) -> bool:
    """True si la imagen recién capturada es visualmente la misma que
    la ÚLTIMA edición conocida — PressReader muestra la edición de ayer
    hasta la 1am; y un medio que no publicó ayer (sin archivo en el
    dir de ayer) no debe colar su portada vieja como nueva: comparar
    píxeles a 64x64 grises (los PNG/JPG nunca son byte-idénticos entre
    estrategias)."""
    ayer = _ultima_img_previa(nombre_base)
    if ayer is None or not nuevo.exists():
        return False
    try:
        a = Image.open(nuevo).convert("L").resize((64, 64))
        b = Image.open(ayer).convert("L").resize((64, 64))
        diff = sum(abs(p - q) for p, q in zip(a.getdata(), b.getdata()))
        return diff / (64 * 64) < 8   # <8/255 por píxel = misma edición
    except Exception:
        return False


def capturar_portadas(cfg: dict):
    """Recolector incremental 00:30→06:45: para cada medio sin imagen de
    HOY intenta su estrategia; los que ya tienen se saltan. No arma PDF
    ni manda correo — eso pasa a la hora_pdf con lo recolectado."""
    medios = cfg.get("portadas", {}).get("medios", [])
    if not medios:
        return
    dia = _dir_dia()
    dia.mkdir(parents=True, exist_ok=True)
    ahora = datetime.now()
    tardia = ahora.hour * 60 + ahora.minute >= \
        _hhmm(cfg.get("portadas", {}), "hora_web", "05:45")
    fallos = []
    port = cfg.get("portadas", {})
    ahora_m = ahora.hour * 60 + ahora.minute
    # reconciliación: un evento ok de hoy sin archivo en disco es una
    # captura descartada a mano (borrada por mala) — el timeline no
    # debe contarla ni presumir que el medio ya cayó
    hoy_s = ahora.strftime("%Y-%m-%d")
    slugs = {m["nombre"]: _slug_portada(m["nombre"]) for m in medios}
    est0 = cargar_json(ESTADO_PORTADAS, {})
    sucio = False
    for e in est0.get("eventos", []):
        if e.get("d") == hoy_s and e.get("ok") \
                and e.get("m") in slugs \
                and not _tiene_img_hoy(dia / slugs[e["m"]]):
            e["ok"] = False
            e["borrada"] = True
            sucio = True
    if sucio:
        _guardar_portadas(est0)
    # orden barajeado cada ola — el mismo orden siempre a la
    # misma hora es huella de bot (regla ritmo humano, 22/oct)
    for m in random.sample(medios, len(medios)):
        if not _en_ventana(m, port, ahora_m):
            continue   # fuera de su ventana propia
        base = dia / _slug_portada(m["nombre"])
        if _medio_listo(m, base, tardia):
            continue   # ya tiene su imagen de hoy
        est = cargar_json(ESTADO_PORTADAS, {})
        stamps = est.setdefault("cap_medios", {})
        try:
            ult = datetime.fromisoformat(stamps.get(base.name,
                                                  "2000-01-01"))
        except Exception:
            ult = datetime(2000, 1, 1)
        es_fb = bool(m.get("fb"))
        # medios FB: intervalo propio ~30 min + jitter (26-38) — la
        # rampa de 5-20 min era volumen muerto contra el lag de
        # indexación de FB y es lo que quemó a juan
        intervalo = (stamps.get(base.name + "_j", 30) if es_fb
                     else _cada_efectivo(m, port, ahora))
        if (ahora - ult).total_seconds() < intervalo * 60:
            continue   # le toca más tarde
        stamps[base.name] = ahora.isoformat()
        if es_fb:
            stamps[base.name + "_j"] = random.randint(26, 38)
        hoy = ahora.strftime("%Y-%m-%d")
        # conserva ~7 días de eventos — histórico para ver patrones de
        # publicación de cada medio
        limite = (ahora - timedelta(days=7)).strftime("%Y-%m-%d")
        evs = [e for e in est.get("eventos", []) if e.get("d") >= limite]
        stale = False
        try:
            ok = bool(_captura_medio(m, base, tardia, cfg))
            if ok and _img_repetida(base, ahora):
                ok, stale = False, True
        except Exception:
            ok = False
        ev = {"d": hoy, "t": ahora.strftime("%H:%M"),
              "m": m["nombre"], "ok": ok}
        if stale:
            ev["stale"] = True   # kiosko&co repitieron la plana de ayer
        evs.append(ev)
        est["eventos"] = evs[-3000:]
        _guardar_portadas(est)
        if not ok:
            fallos.append(m["nombre"])
    print(f"[portadas] corrida{' tardía' if tardia else ''}, "
          f"pendientes fallidos: {fallos or 'ninguno'}")
    # salud de fuentes: 1 cálculo diario (recorre noticias.jsonl)
    if est.get("salud", {}).get("fecha") != ahora.strftime("%Y-%m-%d"):
        est["salud"] = _salud_fuentes(cfg, ahora)
        _guardar_portadas(est)
    escribir_schedule_portadas(cfg)   # refresca línea de tiempo


def _cada_efectivo(m: dict, port: dict, ahora: datetime = None) -> int:
    """cada_min del medio comprimido cerca del cierre: ≤90 min al
    hora_cierre toca cada 20, a ≤45 min cada 5 — los medios lentos de
    publicar (kiosko 404, FB tardío) tienen más oportunidades."""
    cada = int(m.get("cada_min", 55))
    ahora = ahora or datetime.now()
    ahora_m = ahora.hour * 60 + ahora.minute
    fin1 = _hora_pdf_hoy(port, ahora)
    # antes del 1er PDF: rampa a tope (los lentos tienen más chances);
    # después: modo tranquilo — 30 min fijos hasta el cierre, no hace
    # falta martillar FB/kiosko cada 5 min para el 2º PDF
    if ahora_m >= fin1:
        return min(cada, 30)
    restan = fin1 - ahora_m
    if restan <= 45:
        return min(cada, 5)
    if restan <= 90:
        return min(cada, 20)
    return cada


def _img_repetida(base: Path, ahora: datetime) -> bool:
    """Kiosko&co sirven 'la última publicada': un medio sin edición de
    hoy (festivo, edición tardía) regresa el archivo de ayer byte por
    byte — Expreso guardó la de DOMINGO un lunes. True si la captura es
    idéntica a la de ayer → se borra y el medio queda pendiente (puede
    publicar tarde)."""
    hoy = _portada_img(base.name, base.parent)
    ayer = _portada_img(base.name, _dir_dia(ahora - timedelta(days=1)))
    if not (hoy.exists() and ayer.exists()):
        return False
    if hoy.read_bytes() != ayer.read_bytes():
        return False
    print(f"[portadas] {base.name}: imagen idéntica a la de ayer — "
          "descartada como 'sin edición de hoy'")
    hoy.unlink()
    return True


def _salud_fuentes(cfg: dict, ahora: datetime) -> dict:
    """Días sin publicar por fuente activa — una fuente callada suele
    ser feed roto, login-wall o sitio muerto (así se descubre sin que
    alguien la revise a mano). Umbrales: rss/html/x ≥3 días, fb ≥7
    (sus posts se barren cada ~4 h y hay páginas que postean poco)."""
    ult = {}
    try:
        for n in _noticias_cache():
            f, fe = n.get("fuente"), n.get("fecha") or ""
            if f and fe > ult.get(f, ""):
                ult[f] = fe
    except Exception:
        pass
    calladas, vistos = [], set()
    activas = [f for f in cfg.get("fuentes", [])
               if f.get("activa") is not False]
    # x:home atribuye sus notas al @autor — su 'última' es la más
    # reciente de cualquier nota @
    ult_radar = max((fe for f, fe in ult.items() if f.startswith("@")),
                    default="")
    for f in activas:
        nom = f.get("nombre") or f.get("url", "")
        if nom in vistos:        # fuentes duplicadas en cfg: 1 reporte
            continue
        vistos.add(nom)
        if f.get("tipo") == "x":
            if str(f.get("url", "")).lower().startswith("x:home"):
                fe = ult_radar
            else:   # las notas de un handle guardan fuente='@handle'
                fe = ult.get("@" + _handle_x(f.get("url", "")), "")
        else:
            fe = ult.get(nom, "")
        try:
            dias = (ahora - datetime.fromisoformat(fe[:19])).days
        except Exception:
            dias = -1            # jamás ha dado una nota
        umbral = 7 if f.get("tipo") == "fb" else 3
        if dias < 0 or dias >= umbral:
            calladas.append({"f": nom, "dias": dias,
                             "tipo": f.get("tipo", "rss"),
                             "ult": fe[:16] or "—"})
    calladas.sort(key=lambda x: x["dias"])
    return {"fecha": ahora.strftime("%Y-%m-%d"),
            "activas": len(activas), "calladas": calladas}


def _merge_eventos(a: list, b: list) -> list:
    """Unión de eventos sin duplicados — el timeline no pierde pins
    aunque el servicio tenga en RAM un estado más viejo que el disco.
    Una mutación en `b` (ok→borrada al descartar una captura mala) pisa
    la versión vieja de `a` con mismo (d,t,m): sin esto el ok=True
    original resucita y el medio fantasma queda 'capturado'."""
    pisados = {(e.get('d'), e.get('t'), e.get('m'))
               for e in b if e.get('borrada')}
    seen, out = set(), []
    for e in a + b:
        if (e.get('d'), e.get('t'), e.get('m')) in pisados \
                and not e.get('borrada'):
            continue
        k = (e.get('d'), e.get('t'), e.get('m'), e.get('ok'))
        if k not in seen:
            seen.add(k)
            out.append(e)
    return out


def _descartar_portada(nombre: str) -> str:
    """'Recapturar': el admin vio que la imagen del día es mala (banner,
    anuncio, edición vieja) — borra sus archivos, libera el sello y el
    evento queda descartado. Si el medio sigue en ventana, la próxima
    corrida lo reintenta solo."""
    if not nombre:
        return "medio vacío"
    hoy_s = datetime.now().strftime("%Y-%m-%d")
    slug = _slug_portada(nombre)
    n = 0
    for f in _dir_dia().glob(f"{slug}*"):
        if f.is_file() and f.suffix != ".pdf":
            f.unlink(missing_ok=True)
            n += 1
    est = cargar_json(ESTADO_PORTADAS, {})
    est.get("cap_medios", {}).pop(slug, None)
    for e in est.get("eventos", []):
        if e.get("d") == hoy_s and e.get("m") == nombre:
            e["ok"] = False
            e["borrada"] = True
    _guardar_portadas(est)
    return (f"{nombre}: {n} archivo(s) descartado(s) — "
            "reintenta en la próxima corrida")


def _guardar_portadas(est: dict):
    """Escritura atómica (tmp + rename) con merge contra disco: fusiona
    eventos y conserva el timestamp más reciente por medio en
    cap_medios — evita que un proceso con estado viejo pise registros
    nuevos (el write-race que borró pins del timeline)."""
    en_disco = cargar_json(ESTADO_PORTADAS, {})
    en_disco['eventos'] = _merge_eventos(
        en_disco.get('eventos', []), est.get('eventos', []))[-3000:]
    cap = en_disco.setdefault('cap_medios', {})
    for k, v in est.get('cap_medios', {}).items():
        if isinstance(v, str):
            if v > str(cap.get(k, '') or ''):
                cap[k] = v
        else:
            cap[k] = v
    for k, v in est.items():
        if k not in ('eventos', 'cap_medios'):
            en_disco[k] = v
    tmp = ESTADO_PORTADAS.with_suffix('.tmp')
    tmp.write_text(json.dumps(en_disco))
    tmp.replace(ESTADO_PORTADAS)


def _pagina_portada_pdf(sec: str, n_medios: int):
    """Página de portada del PDF — brand/02port.jpg arriba (la pieza ya
    dice PORTADAS · NACIONAL|TABASCO) y sobre papel muestreado de la
    propia imagen: sección, fecha y conteo. Sin el asset, portada
    institucional generada."""
    from PIL import ImageDraw, ImageFont
    hoy = datetime.now()
    fecha = f"{hoy.day} de {_MESES_PORTADA[hoy.month - 1]} de {hoy.year}"
    dia_sem = _DIAS_PORTADA[hoy.weekday()].capitalize()
    asset = BASE / "brand" / "02port.jpg"
    if asset.exists():
        arte = Image.open(asset).convert("RGB")
        arte = arte.resize((1240, int(arte.height * 1240 / arte.width)),
                           Image.LANCZOS)
        W, H = 1240, 1754   # proporción carta/vertical
        fondo = arte.getpixel((12, arte.height - 12))  # crema de la pieza
        img = Image.new("RGB", (W, H), fondo)
        img.paste(arte, (0, 0))
        dr = ImageDraw.Draw(img)
        try:
            fb = ImageFont.truetype("DejaVuSans-Bold.ttf",
                                    int(W * 0.052))
            fm = ImageFont.truetype("DejaVuSans.ttf",
                                    int(W * 0.032))
            fs = ImageFont.truetype("DejaVuSans.ttf",
                                    int(W * 0.026))
        except Exception:
            fb = fm = fs = ImageFont.load_default()
        navy = (43, 57, 79)      # azul pizarra de la tipografía de la pieza
        cy = arte.height + (H - arte.height) * 0.55
        dr.text((W / 2, cy - 80), sec.upper(), font=fb, fill=navy,
                anchor="mm")
        dr.text((W / 2, cy), f"{dia_sem}, {fecha}", font=fm,
                fill=navy, anchor="mm")
        dr.text((W / 2, cy + 60), f"{n_medios} medios", font=fs,
                fill=navy, anchor="mm")
        return img
    W, H = 1240, 1754   # proporción carta/vertical como las portadas
    img = Image.new("RGB", (W, H), (250, 250, 250))
    dr = ImageDraw.Draw(img)
    try:
        fb = ImageFont.truetype("DejaVuSans-Bold.ttf", 96)
        fm = ImageFont.truetype("DejaVuSans.ttf", 44)
        fs = ImageFont.truetype("DejaVuSans.ttf", 30)
    except Exception:
        fb = fm = fs = ImageFont.load_default()
    titulo = "PORTADAS NACIONAL" if sec == "nacional" \
        else "PORTADAS TABASCO"
    negro, gris, esm = (9, 9, 11), (82, 82, 91), (52, 211, 153)
    def centro(txt, y, fnt, fill=negro):
        dr.text((W / 2, y), txt, font=fnt, fill=fill, anchor="mm")
    centro("SERVICIO DE MONITOR DE PRENSA", H * 0.36, fm, gris)
    centro(titulo, H * 0.46, fb)
    dr.line((W * 0.28, H * 0.505, W * 0.72, H * 0.505),
            fill=esm, width=6)
    centro(dia_sem, H * 0.56, fm, gris)
    centro(fecha, H * 0.61, fm)
    centro(f"{n_medios} medios", H * 0.68, fs, gris)
    return img


def _armar_pdf_portadas(medios: list, sec: str, dia,
                        fecha=None) -> tuple:
    """Arma el PDF de `sec` con las imágenes guardadas en `dia` (dir
    portadas/mes/dd). Regresa (bytes, fallos) — sin tocar disco ni
    correo; lo usan la emisión programada y el endpoint 'en vivo'."""
    imgs = []
    fallos = []
    for m in medios:
        if m.get("seccion", "nacional") != sec:
            continue
        slug = _slug_portada(m["nombre"])
        # impresa(s) primero — los posts FB traen portada-2, etc.
        extras = sorted(dia.glob(f"{slug}-[0-9].jpg"))
        tiene = False
        web = [] if m.get("solo_impresa") else [dia / f"{slug}-web.png"]
        for cand in ([_portada_img(slug, dia)] + extras + web):
            if cand.exists() and _img_ok(cand):
                try:
                    imgs.append(Image.open(cand).convert("RGB"))
                    tiene = True
                except Exception:
                    pass
        if not tiene:
            fallos.append(m["nombre"])
    if not imgs:
        return None, fallos
    f = fecha or datetime.now()
    portada = _pagina_portada_pdf(sec, len(imgs))
    imgs = [portada] + imgs
    # ancho uniforme: kiosko/shots/fb varían (800-2550px) y el PDF
    # quedaba con páginas de tamaños distintos — la mediana del día
    # minimiza reescalado (la mayoría ya va en su tamaño)
    from statistics import median
    W = int(median(im.width for im in imgs))
    imgs = [im.resize((W, round(im.height * W / im.width)),
                      Image.LANCZOS) if im.width != W else im
            for im in imgs]
    buf = io.BytesIO()
    imgs[0].save(
        buf, "PDF", save_all=True, append_images=imgs[1:],
        title=f"Portadas {sec.capitalize()} — {f.strftime('%d/%m/%Y')}",
        author="@noticias", subject="Portadas de medios impresos",
        keywords="portadas, prensa, Tabasco, monitoreo de medios",
        creator="Olmeca Code")
    for i in imgs:
        i.close()
    return buf.getvalue(), fallos


def generar_pdfs_portadas(cfg: dict, marca: str = "pdf_fecha"):
    """Hora_pdf (06:30): arma los PDFs con lo recolectado, los manda
    por correo y lista los que no respondieron.
    `marca` = llave del estado que registra qué emisión ya salió."""
    medios = cfg.get("portadas", {}).get("medios", [])
    escribir_schedule_portadas(cfg)   # schedule.html siempre al día
    hoy = datetime.now().strftime("%Y-%m-%d")
    fallos = []
    pdfs = {}
    dia = _dir_dia()
    for sec in ("nacional", "tabasco"):
        data, f = _armar_pdf_portadas(medios, sec, dia)
        fallos += f
        if data:
            dia.mkdir(parents=True, exist_ok=True)
            pdf = dia / f"portadas_{sec}_{hoy}.pdf"
            pdf.write_bytes(data)
            pdfs[sec] = pdf
    enviar_portadas(cfg, pdfs, fallos)
    est = cargar_json(ESTADO_PORTADAS, {})
    est[marca] = hoy
    _guardar_portadas(est)
    print(f"[portadas] {len(pdfs)} PDFs enviados ({marca}), fallos: "
          f"{fallos or 'ninguno'}")


def limpiar_portadas():
    """19:00 — conserva solo los últimos 7 días de subcarpetas; las
    imágenes de cada día se quedan para cotejar contra ayer."""
    if not PORTADAS_DIR.exists():
        return
    import shutil
    # día dirs = portadas/<mes>/<dd> — retiene los 7 más recientes
    dias = sorted((d for d in PORTADAS_DIR.glob("*/*")
                   if d.is_dir()),
                  key=lambda p: p.stat().st_mtime, reverse=True)
    n = 0
    for d in dias[7:]:   # >7 días → fuera
        shutil.rmtree(d, ignore_errors=True)
        n += 1
    for mes in PORTADAS_DIR.iterdir():   # carpeta de mes vacía → fuera
        if mes.is_dir() and not any(mes.iterdir()):
            mes.rmdir()
    # legado: imágenes sueltas en la raíz de corridas anteriores
    for f in PORTADAS_DIR.glob("*.*"):
        if f.suffix in (".jpg", ".jpeg", ".png"):
            f.unlink(missing_ok=True)
    print(f"[portadas] limpieza: {n} carpetas viejas fuera, "
          f"{len(dias[:7])} días conservados")


def enviar_portadas(cfg: dict, pdfs: dict, fallos: list):
    correo = cfg.get("correo", {})
    if not correo.get("habilitado"):
        return
    dests = set()
    for d in (cfg.get("portadas", {}).get("destinatario", ""),
              correo.get("destinatario", "")):
        if "@" in d:
            dests.add(d)
    for a in cfg.get("admins", []):
        if "@" in a:
            dests.add(a)
    for email in cargar_usuarios():
        if "@" in email and not email.endswith("@demo.local") \
                and proyectos_usuario(email):
            dests.add(email)
    if not dests:
        return
    hoy = datetime.now().strftime("%d/%m/%Y")
    msg = MIMEMultipart()
    msg["Subject"] = f"[Monitor] Portadas {hoy}"
    msg["From"] = correo.get("remitente", correo["usuario"])
    msg["To"] = ", ".join(sorted(dests))
    cuerpo = (f"Primeras planas del {hoy}.\n\n"
              + (f"No respondieron: {', '.join(fallos)}." if fallos else ""))
    msg.attach(MIMEText(cuerpo, "plain", "utf-8"))
    for sec, pdf in pdfs.items():
        parte = MIMEApplication(pdf.read_bytes(), _subtype="pdf")
        parte.add_header("Content-Disposition", "attachment",
                         filename=pdf.name)
        msg.attach(parte)
    try:
        _mandar_msg(correo, msg, timeout=30)
    except Exception as e:
        print(f"[portadas] correo falló: {e}")


def _min(s: str) -> int:
    """'HH:MM' → minutos del día (valor directo, no de config)."""
    h, mm = map(int, s.split(":"))
    return h * 60 + mm


def _ventana_medio(m: dict, port: dict) -> tuple:
    """(desde, hasta) en minutos para este medio. cap_desde/cap_hasta
    sobreescriben la ventana global; los medios solo-web no arrancan
    antes de hora_web (de madrugada la home trae la edición vieja)."""
    # edicion/json/calameo también validan fecha — pueden intentarse
    # desde madrugada sin riesgo de agarrar la edición vieja
    impresa = any(m.get(k) for k in
                  ("kiosko", "fb", "issuu", "flip", "pr", "pdf",
                   "edicion", "json", "calameo", "flowpaper"))
    desde = _min(m.get("cap_desde") or port.get("hora_desde", "00:30"))
    hasta = _min(m.get("cap_hasta") or port.get("hora_cierre")
                 or port.get("hora_pdf", "06:30"))
    hasta = max(hasta, _hora_pdf_hoy(port))
    if not impresa:
        desde = max(desde, _hhmm(port, "hora_web", "05:45"))
    return desde, hasta


def _en_ventana(m: dict, port: dict, ahora_m: int) -> bool:
    # pausa de un solo día (ej. el medio no publicó hoy) — la fecha
    # vencida queda inerte, no hay que quitarla
    if m.get("skip_hoy") == datetime.now().strftime("%Y-%m-%d"):
        return False
    desde, hasta = _ventana_medio(m, port)
    return desde <= ahora_m <= hasta


def _reglas_medio(m: dict) -> str:
    """Texto de reglas de captura — alimenta la columna Reglas de
    schedule.html (se regenera en cada generar_pdfs_portadas)."""
    r = []
    if m.get("kiosko"):
        r.append("JPG fechado de hoy/ayer en Kiosko")
    if m.get("fb"):
        r.append("Post de hoy con texto 'portada/edición'")
    if m.get("issuu"):
        r.append("Doc más reciente del perfil Issuu")
    if m.get("flip"):
        r.append("Página _001A del flipbook del día")
    if m.get("pr"):
        r.append("Imagen mayor del visor PressReader")
    if m.get("pdf"):
        r.append("PDF con fecha de hoy en la URL")
        if m.get("pdf_estricto"):
            r.append("solo PDF del post fechado")
    if m.get("solo_impresa"):
        r.append("sin captura web")
    if not any(m.get(k) for k in
               ("kiosko", "fb", "issuu", "flip", "pr", "pdf")):
        r.append("Screenshot de la portada web")
    r.append("blanco/negro/bloqueo → descarta y reintenta")
    if m.get("cap_desde") or m.get("cap_hasta"):
        r.append(f"ventana propia {m.get('cap_desde','—')}–"
                 f"{m.get('cap_hasta','—')}")
    if m.get("regla"):   # nota editable desde /horarios
        r.insert(0, m["regla"])
    return " · ".join(r)


def escribir_schedule_portadas(cfg: dict):
    """Regenera schedule.html con los horarios y reglas vigentes —
    corre junto a generar_pdfs_portadas para que nunca se desactualice."""
    port = cfg.get("portadas", {})
    medios = port.get("medios", [])
    if not medios:
        return
    desde = port.get("hora_desde", "00:30")
    pdf = port.get("hora_pdf", "06:45")
    limpia = port.get("hora_limpia", "19:00")

    TIPOS = (("web", "Web (screenshot)"), ("kiosko", "Kiosko.net"),
             ("edicion", "Edición digital"), ("json", "API/JSON"),
             ("fb", "Facebook"), ("issuu", "Issuu"), ("flip", "Flipbook"),
             ("calameo", "Calaméo"), ("pr", "PressReader"),
             ("pdf", "PDF diario"))

    def tipo_medio(m):
        for k in ("kiosko", "edicion", "json", "fb", "issuu", "flip",
                  "calameo", "pr", "pdf"):
            if m.get(k):
                return k
        return "web"

    def origen_medio(m):
        for k in ("fb", "flip", "calameo", "pr", "issuu",
                  "edicion", "json", "kiosko"):
            if m.get(k):
                return str(m[k])
        return str(m.get("url", ""))

    def url_origen(m):
        """URL completa de dónde se baja — resuelve slugs a su sitio."""
        if m.get("kiosko"):
            return f"https://www.kiosko.net/mx/np/{m['kiosko']}.html"
        if m.get("issuu"):
            return f"https://issuu.com/{m['issuu']}"
        return origen_medio(m)

    def sel_tipo(actual):
        return "".join(
            f"<option value='{v}'{' selected' if v == actual else ''}>"
            f"{et}</option>" for v, et in TIPOS)

    def sel_sec(actual):
        return "".join(
            f"<option value='{v}'{' selected' if v == actual else ''}>"
            f"{v}</option>" for v in ("nacional", "tabasco"))

    # fila editable: nombre/sección/origen/horario/regla + checkbox borrar
    def fila(i, m):
        d, h = _ventana_medio(m, port)
        cada = m.get("cada_min", "")
        return (
            f"<tr><td><input name='n{i}' "
            f"value='{html.escape(m['nombre'], quote=True)}' "
            "style='width:9rem'>"
            f"<select name='s{i}'>{sel_sec(m.get('seccion','nacional'))}"
            "</select></td>"
            f"<td><select name='t{i}'>{sel_tipo(tipo_medio(m))}</select>"
            f"<input name='o{i}' inputmode='url' "
            f"value='{html.escape(url_origen(m), quote=True)}' "
            f"title='{html.escape(url_origen(m), quote=True)}' "
            "style='width:100%;min-width:15rem'></td>"
            f"<td><input type='time' name='d{i}' "
            f"value='{d//60:02d}:{d%60:02d}'>→"
            f"<input type='time' name='h{i}' "
            f"value='{h//60:02d}:{h%60:02d}'>"
            f"<br><small>cada</small> <input type='number' name='c{i}' "
            f"min='5' max='240' value='{cada}' placeholder='55' "
            "style='width:3.5rem'> <small>min</small></td>"
            f"<td><input name='r{i}' style='width:100%' "
            f"value='{html.escape(m.get('regla',''), quote=True)}' "
            f"placeholder='{_reglas_medio(m).split(' · ')[0] if not m.get('regla') else ''}'></td>"
            f"<td><label><input type='checkbox' name='del{i}' "
            "value='1'> borrar</label></td></tr>")

    def tabla(sec, titulo):
        rows = "".join(fila(i, m) for i, m in enumerate(medios)
                       if m.get("seccion") == sec)
        return (f"<h2>{titulo}</h2><table><thead><tr><th>Medio</th>"
                f"<th>Origen</th><th>Horario</th><th>Regla</th>"
                f"<th></th></tr></thead><tbody>{rows}</tbody></table>")

    # línea de tiempo del ciclo nocturno: ticks cada 55 min desde la
    # apertura hasta la hora del PDF; dots por evento (azul=capturado,
    # rojo=fallo); tick ámbar = hora cumplida sin corrida registrada
    ahora = datetime.now()
    ahora_m = ahora.hour * 60 + ahora.minute
    d0 = _min(desde)
    pdf2 = port.get("hora_pdf2")
    d1 = _min(pdf2) if pdf2 else _min(pdf)   # eje hasta el 2º PDF
    span = max(d1 - d0, 1)
    est_tl = cargar_json(ESTADO_PORTADAS, {})
    hoy_s = ahora.strftime("%Y-%m-%d")
    evs_tl = [e for e in est_tl.get("eventos", []) if e.get("d") == hoy_s]

    def _pct(mm):
        return max(0.0, min(100.0, (mm - d0) * 100.0 / span))

    tl = ("<div style='position:relative;height:240px;margin:14px 0 2px'>"
          "<div style='position:absolute;top:210px;left:0;right:0;"
          "height:4px;background:#e5e5e5;border-radius:2px'></div>")
    t = d0
    while t <= d1 + 1:
        paso = t <= ahora_m
        hubo = any(_min(str(e.get("t", "00:00"))) >= t for e in evs_tl)
        color = "#0a7a2f" if (paso and hubo) else \
                ("#d97706" if paso else "#9ca3af")
        tl += (
            f"<div title='corrida {t//60:02d}:{t%60:02d}' style="
            f"'position:absolute;left:{_pct(t):.2f}%;top:206px;width:12px;"
            "height:12px;margin-left:-6px;border-radius:50%;"
            f"background:{color}'></div>"
            f"<span style='position:absolute;left:{_pct(t):.2f}%;top:228px;"
            "transform:translateX(-50%);font-size:.68rem;color:#666'>"
            f"{t//60:02d}:{t%60:02d}</span>")
        t += 55
    # ticks de emisión: 1er PDF en hora_pdf y 2º en hora_pdf2
    marcas_pdf = [(_min(pdf), "pdf_fecha")]
    if pdf2:
        marcas_pdf.append((_min(pdf2), "pdf_fecha2"))
    for mm_pdf, marca_pdf in marcas_pdf:
        paso = mm_pdf <= ahora_m
        pdf_ok = est_tl.get(marca_pdf) == hoy_s
        color = "#0a7a2f" if pdf_ok else \
                ("#d97706" if paso else "#9ca3af")
        tl += (
            f"<div title='PDF {mm_pdf//60:02d}:{mm_pdf%60:02d} — envío ~"
            f"{(mm_pdf+5)//60:02d}:{(mm_pdf+5)%60:02d}' style="
            f"'position:absolute;left:{_pct(mm_pdf):.2f}%;top:202px;"
            f"width:16px;height:16px;margin-left:-8px;border-radius:50%;"
            f"background:{color}'></div>"
            f"<span style='position:absolute;left:{_pct(mm_pdf):.2f}%;"
            f"top:{228}px;transform:translateX(-50%);font-size:.68rem;"
            f"color:#666'>{mm_pdf//60:02d}:{mm_pdf%60:02d} PDF</span>")
    # pines: solo capturas logradas — eventos cercanos (≤10 min) se
    # agrupan en UN cluster: etiqueta compacta HH:MM ×N (los nombres en
    # el tooltip y en la leyenda desplegable de abajo) — sin clusters,
    # la ola de las ~06:00 empalma 20 etiquetas diagonales ilegibles
    _vistos_ok = set()
    oks = sorted(
        (mm, nm)
        for e in evs_tl if e.get("ok")
        for mm, nm in [(_min(str(e.get("t", "00:00"))),
                        str(e.get("m", "")))]
        if d0 <= mm <= d1 + 60
        and nm not in _vistos_ok and not _vistos_ok.add(nm))
    clusters = []
    for mm, nombre in oks:
        if clusters and mm - clusters[-1][0] <= 10:
            clusters[-1][1].append((mm, nombre))
        else:
            clusters.append((mm, [(mm, nombre)]))
    grupos = []   # [(min_repr, [(mm, nombre), ...])]
    for _mm0, items in clusters:
        mms = sorted(m for m, _ in items)
        grupos.append((mms[len(mms) // 2], items))
    # niveles en escalera para clusters pegados (calculo de drcha→izqda)
    niveles = [0] * len(grupos)
    for i in range(len(grupos) - 2, -1, -1):
        xi = _pct(grupos[i][0])
        xn = _pct(grupos[i + 1][0])
        if xn - xi < 9:
            niveles[i] = niveles[i + 1] + 1
    for (mm, nombres), nivel in zip(grupos, niveles):
        x = _pct(mm)
        polo_top = 206 - 34 - nivel * 30
        polo_h = 34 + nivel * 30
        solo = [n for _, n in nombres]
        etq = (html.escape(solo[0]) if len(solo) == 1
               else f"{mm // 60:02d}:{mm % 60:02d} ×{len(solo)}")
        tl += (
            f"<div title='{html.escape(' · '.join(solo))}' style="
            f"'position:absolute;left:{x:.2f}%;top:206px;width:9px;"
            "height:9px;margin-left:-4px;border-radius:50%;"
            "background:#2563eb'></div>"
            f"<div style='position:absolute;left:{x:.2f}%;"
            f"top:{polo_top}px;width:1.5px;height:{polo_h}px;"
            "background:#2563eb'></div>"
            f"<span style='position:absolute;left:{x:.2f}%;"
            f"top:{polo_top}px;transform-origin:left bottom;"
            "transform:rotate(-55deg);width:120px;"
            "font-size:.6rem;color:#2563eb;font-weight:600'>"
            f"{etq}</span>")
    # leyenda: cada captura con su hora real, agrupada por cluster
    if grupos:
        n_olas = sum(1 for _, items in grupos if len(items) > 1)
        dia_leg = _dir_dia()

        def _n_planas(nombre: str) -> int:
            s = _slug_portada(nombre)
            return sum(1 for f in dia_leg.glob(f"{s}*.*")
                       if not f.name.endswith("-web.png"))

        items_leg = "".join(
            f"<li><b>{e_mm // 60:02d}:{e_mm % 60:02d}</b> "
            f"{html.escape(e_n)}"
            + (f" <b style='color:#2563eb'>×{n}</b>"
               if (n := _n_planas(e_n)) > 1 else "")
            + " <form method='post' action='/portadas/recapturar' "
              "style='display:inline'><input type='hidden' name='m' "
              f"value='{html.escape(e_n)}'>"
              "<button title='Descartar y recapturar' style='border:0;"
              "background:none;cursor:pointer;color:#dc2626;"
              "font-size:.7rem;padding:0'>&#8635;</button></form>"
            + "</li>"
            for _mm, items in grupos for e_mm, e_n in sorted(items))
        tl += ("</div><details open style='font-size:.75rem;color:#333;"
               "margin:0 0 4px'><summary style='cursor:pointer'>"
               f"Capturas de hoy — {sum(len(i) for _, i in grupos)} "
               f"medios en {n_olas} olas</summary><ul style='margin:4px "
               f"0 0;padding-left:18px;line-height:1.6'>"
               f"{items_leg}</ul></details><div>")
    # pendientes: medios sin su material de hoy completo
    dia_tl = _dir_dia()
    tardia_tl = ahora_m >= _hhmm(port, "hora_web", "05:45")
    listos = {m["nombre"] for m in medios
              if _tiene_img_hoy(dia_tl / _slug_portada(m["nombre"]))
              or (dia_tl / f"{_slug_portada(m['nombre'])}-web.png").exists()}
    pend = [m["nombre"] for m in medios
            if _en_ventana(m, port, ahora_m)
            and m["nombre"] not in listos]
    n_tab = sum(1 for m in medios
                if m.get("seccion") == "tabasco"
                and m["nombre"] in listos)
    n_nac = sum(1 for m in medios
                if m.get("seccion") == "nacional"
                and m["nombre"] in listos)
    tl += ("<p style='font-size:.9rem;margin:6px 0 2px;font-weight:600'>"
           f"<b style='color:#0a7a2f'>{len(listos)} de {len(medios)}</b> "
           f"medios capturados — {n_nac} nacionales · {n_tab} tabasco"
           "</p>")
    tl += "</div>"
    if pend:
        tl += ("<p style='font-size:.8rem;margin:0 0 12px'>"
               "<b style='color:#dc2626'>Pendientes:</b> "
               + ", ".join(html.escape(n) for n in pend) + "</p>")

    # historial: matriz medio × día con la hora de la captura ok —
    # portadas_estado.json conserva ~7 días de eventos
    hist_tbl = ""
    evs_all = est_tl.get("eventos", [])
    dias_h = sorted({e.get("d", "") for e in evs_all})[-7:]
    if dias_h:
        ok_h = {}
        for e in evs_all:
            if e.get("ok"):
                ok_h.setdefault((e["m"], e["d"]),
                                str(e.get("t", ""))[:5])
        cab = "".join(
            f"<th style='min-width:3.2rem;text-align:center'>"
            f"{d[8:10]}/{d[5:7]}</th>"
            for d in dias_h)
        filas = ""
        for m in medios:
            filas += ("<tr><td style='white-space:nowrap'>"
                      f"{html.escape(m['nombre'])}</td>")
            for d in dias_h:
                hh = ok_h.get((m["nombre"], d))
                filas += (f"<td style='text-align:center;color:#0a7a2f'>"
                          f"{hh}</td>" if hh else
                          "<td style='text-align:center;color:#ddd'>"
                          "&#183;</td>")
            filas += "</tr>"
        hist_tbl = (f"<h2>Historial — {len(dias_h)} días</h2>"
                    "<table style='font-size:.75rem'>"
                    f"<thead><tr><th>Medio</th>{cab}</tr></thead>"
                    f"<tbody>{filas}</tbody></table>")

    html_doc = (
        "<!DOCTYPE html>\n<html lang=\"es\"><head><meta charset=\"utf-8\">\n"
        "<title>Horario de captura — Portadas</title>\n"
        "<style>\n"
        "body{font-family:system-ui,sans-serif;max-width:980px;margin:32px auto;"
        "color:#1a1a1a;padding:0 16px}\n"
        "h1{font-size:1.4rem;border-bottom:3px solid #b03a2e;padding-bottom:8px}\n"
        "h2{font-size:1.05rem;margin:28px 0 8px;color:#b03a2e}\n"
        "table{width:100%;border-collapse:collapse;font-size:.85rem}\n"
        "th{background:#b03a2e;color:#fff;text-align:left;padding:6px 10px}\n"
        "td{border-bottom:1px solid #e5e5e5;padding:6px 10px;vertical-align:top}\n"
        "tr:nth-child(even){background:#faf7f6}\n"
        ".nota{font-size:.8rem;color:#666;margin-top:24px;line-height:1.5}\n"
        "</style></head><body>\n"
        "<h1>Horario de captura de portadas</h1>\n"
        "<div id='aviso'></div>"
        "<script>var q=new URLSearchParams(location.search).get('msg');"
        "if(q){document.getElementById('aviso').innerHTML='"
        "<p style=color:#0a7a2f;font-weight:600>'+q+'</p>';}</script>"
        f"<p>Ventana incremental <b>{desde} → {pdf}</b> con reintentos "
        f"por medio. Las capturas web ocurren apenas se detecte la "
        f"<b>portada</b>. El PDF se genera y envía a las <b>{pdf}</b> · "
        f"limpieza de imágenes a las <b>{limpia}</b>.</p>\n"
        + tl
        # un solo form para ambas tablas: postea al dashboard. Servido
        # desde /schedule el action es relativo; si se abre como file://
        # o en otro puerto, el JS lo apunta al :8080
        + "<form method='post' action='/horarios'>"
        + tabla("nacional", "Nacionales") + tabla("tabasco", "Tabasco")
        # alta de fuente nueva: mismos campos con prefijo n_
        + "<h2>Agregar fuente</h2><table><tbody><tr>"
        "<td><input name='n_nombre' placeholder='Nombre del medio' "
        "style='width:9rem'><select name='n_sec'>"
        "<option value='nacional'>nacional</option>"
        "<option value='tabasco'>tabasco</option></select></td>"
        f"<td><select name='n_tipo'>{sel_tipo('web')}</select>"
        "<input name='n_origen' inputmode='url' style='width:100%' "
        "placeholder='URL o slug — fb: fanpage · kiosko: mx_slug'></td>"
        "<td><input type='time' name='n_desde'>→"
        "<input type='time' name='n_hasta'>"
        "<br><small>cada</small> <input type='number' name='n_cada' "
        "min='5' max='240' placeholder='55' style='width:3.5rem'> "
        "<small>min</small></td>"
        "<td><input name='n_regla' style='width:100%' "
        "placeholder='regla opcional'></td><td></td></tr>"
        "</tbody></table>"
        "<button style='margin:1rem 0;padding:.5rem 1.5rem;background:"
        "#b03a2e;color:#fff;border:0;border-radius:6px;font-size:1rem'>"
        "Agregar fuente</button></form>"
        + hist_tbl +
        "<script>"
        # el editor vive en el dashboard (:8080) — el archivo servido
        # por otro puerto/file redirige ahí para que la cookie valga
        "if(location.port&&location.port!=='8080'){"
        "location.replace('http://'+location.hostname+':8080'"
        "+location.pathname+location.search);}"
        # auto-guardado: al salir del campo se manda solo ese campo
        # (handler acepta forms parciales). n_* se guardan con el botón
        "document.querySelectorAll('input[name],select[name]')"
        ".forEach(function(el){"
        "if(el.name.indexOf('n_')===0)return;"
        "el.addEventListener('change',function(){"
        "var fd=new FormData();"
        "if(el.type==='checkbox'){if(!el.checked)return;"
        "fd.append(el.name,'1');}else{fd.append(el.name,el.value);}"
        "el.style.outline='2px solid #b03a2e';"
        "fetch('/horarios',{method:'POST',body:fd,"
        "headers:{'X-Requested-With':'fetch'}})"
        ".then(function(r){"
        "el.style.outline=r.ok?'2px solid #0a7a2f':'2px solid red';"
        "if(r.ok&&el.name.indexOf('del')===0)location.reload();})"
        ".catch(function(){el.style.outline='2px solid red';});});"
        "</script>"
        "<p class=\"nota\">Aplica en el siguiente ciclo — sin reiniciar. "
        "El fin de ventana lo marca el PDF de las 06:45. Las capturas "
        "que salen en blanco, negro o página de bloqueo se descartan y "
        "el medio queda pendiente para el siguiente reintento.</p>\n"
        "</body></html>")
    (BASE / "schedule.html").write_text(html_doc)


def _hhmm(port: dict, clave: str, default: str) -> int:
    """'HH:MM' → minutos del día."""
    try:
        hh, mm = map(int, port.get(clave, default).split(":"))
        return hh * 60 + mm
    except Exception:
        hh, mm = map(int, default.split(":"))
        return hh * 60 + mm


def _dia_portadas(port: dict, ahora: datetime = None) -> bool:
    """False los días sin corrida — dias_off=[6] apaga los domingos."""
    ahora = ahora or datetime.now()
    return ahora.weekday() not in (port.get("dias_off") or [])


def _hora_pdf_hoy(port: dict, ahora: datetime = None) -> int:
    """Minutos de la hora del PDF: sábado puede correr más tarde
    (hora_pdf_sab) — los medios publican la impresa más tarde."""
    ahora = ahora or datetime.now()
    if ahora.weekday() == 5 and port.get("hora_pdf_sab"):
        return _hhmm(port, "hora_pdf_sab", "09:00")
    return _hhmm(port, "hora_pdf", "06:30")


def toca_captura_portadas(cfg: dict) -> bool:
    """Ventana de recolección [hora_desde, hora_cierre): corre cada ~55 min
    mientras falte algún medio — kiosko sale de madrugada, FB a las
    00:0x, issuu/pdf cuando lo suban."""
    port = cfg.get("portadas", {})
    medios = port.get("medios", [])
    if not medios or not _dia_portadas(port):
        return False
    ahora = datetime.now()
    cierre = max(_hhmm(port, "hora_cierre", "08:45"),
                 _hora_pdf_hoy(port, ahora))
    if not (_hhmm(port, "hora_desde", "00:30")
            <= ahora.hour * 60 + ahora.minute < cierre):
        return False
    ahora_m = ahora.hour * 60 + ahora.minute
    tardia = ahora_m >= _hhmm(port, "hora_web", "05:45")
    est = cargar_json(ESTADO_PORTADAS, {})
    stamps = est.get("cap_medios", {})
    for m in medios:
        if not _en_ventana(m, port, ahora_m):
            continue   # ese medio no corre a esta hora
        slug = _slug_portada(m["nombre"])
        if _medio_listo(m, _dir_dia() / slug, tardia):
            continue
        try:
            ult = datetime.fromisoformat(stamps.get(slug, "2000-01-01"))
        except Exception:
            ult = datetime(2000, 1, 1)
        cada = _cada_efectivo(m, port, ahora)
        if (ahora - ult).total_seconds() >= cada * 60:
            return True    # falta alguno y ya le toca → corre
    return False


def marcar_captura_portadas():
    est = cargar_json(ESTADO_PORTADAS, {})
    est["cap_last"] = datetime.now().isoformat()
    _guardar_portadas(est)


def toca_pdf_portadas(cfg: dict) -> bool:
    """hora_pdf (06:30; sábado hora_pdf_sab) → arma PDFs + envía
    una vez al día."""
    port = cfg.get("portadas", {})
    if not port.get("medios") or not _dia_portadas(port):
        return False
    ahora = datetime.now()
    est = cargar_json(ESTADO_PORTADAS, {})
    return est.get("pdf_fecha") != ahora.strftime("%Y-%m-%d") and \
        ahora.hour * 60 + ahora.minute >= _hora_pdf_hoy(port, ahora)


def toca_pdf_portadas2(cfg: dict) -> bool:
    """hora_pdf2 (09:00) → 2ª emisión con los medios tardíos (kiosko
    indexa después del cierre del 1er PDF). Solo corre si ya salió el
    de hora_pdf — si el servicio estuvo caído, el 1er PDF tiene
    prioridad."""
    port = cfg.get("portadas", {})
    if not port.get("medios") or not port.get("hora_pdf2") \
            or not _dia_portadas(port):
        return False
    ahora = datetime.now()
    hoy = ahora.strftime("%Y-%m-%d")
    est = cargar_json(ESTADO_PORTADAS, {})
    return est.get("pdf_fecha") == hoy and \
        est.get("pdf_fecha2") != hoy and \
        ahora.hour * 60 + ahora.minute >= _hhmm(
            port, "hora_pdf2", "09:00")


def toca_limpia_portadas(cfg: dict) -> bool:
    """hora_limpia (19:00) → depura las imágenes del día."""
    port = cfg.get("portadas", {})
    if not _dia_portadas(port):
        return False
    ahora = datetime.now()
    est = cargar_json(ESTADO_PORTADAS, {})
    return est.get("limpia_fecha") != ahora.strftime("%Y-%m-%d") and \
        ahora.hour * 60 + ahora.minute >= _hhmm(port, "hora_limpia", "19:00")


def marcar_limpia_portadas():
    est = cargar_json(ESTADO_PORTADAS, {})
    est["limpia_fecha"] = datetime.now().strftime("%Y-%m-%d")
    _guardar_portadas(est)


def checar_ip_correo():
    """Una vez al día: IP pública saliente vs la autorizada en Brevo
    (correo.ip_autorizada). Si cambió, evento rojo en la timeline de
    /portadas — se ve ahí antes de que falle el envío de las 06:45
    (error 525 'Unauthorized IP')."""
    try:
        est = cargar_json(ESTADO_PORTADAS, {})
        hoy = datetime.now().strftime("%Y-%m-%d")
        if est.get("ip_fecha") == hoy:
            return
        esperada = (json.loads(CONFIG.read_text())
                    .get("correo", {}).get("ip_autorizada", ""))
        if not esperada:
            return
        ip = requests.get("https://api.ipify.org",
                          timeout=10).text.strip()
        est["ip_vista"], est["ip_fecha"] = ip, hoy
        if ip != esperada and est.get("ip_avisada") != ip:
            est["ip_avisada"] = ip
            est.setdefault("eventos", []).append(
                {"d": hoy, "t": datetime.now().strftime("%H:%M"),
                 "m": f"IP pública cambió → {ip} (Brevo autoriza "
                      f"{esperada}) — re-autorizar o el correo falla",
                 "ok": False})
            print(f"[correo] IP pública cambió: {ip} ≠ {esperada}")
        _guardar_portadas(est)
    except Exception as e:
        print(f"[correo] check IP falló: {e}")


def vista_portadas(sec: str, dia: str = "", admin: bool = False,
                   logueado: bool = False) -> str:
    """Tab Portadas: grid de las capturas por sección; ?dia=oct/06
    navega subcarpetas para cotejar un día contra otro."""
    cfg = json.loads(CONFIG.read_text())
    port = cfg.get("portadas", {})
    medios = [m for m in port.get("medios", [])
              if m.get("seccion", "nacional") == sec]
    est_v = cargar_json(ESTADO_PORTADAS, {})
    ultima = est_v.get("pdf_fecha", "")
    # avisos de salud: sesión FB caída + fuentes calladas (cálculo
    # diario de _salud_fuentes — así se ve sin abrir logs)
    hoy_s = datetime.now().strftime("%Y-%m-%d")
    avisos = ""
    fb_st = est_v.get("fb_sesion", {}) if admin else {}
    if fb_st.get("estado") == "caida" and fb_st.get("alertado") == hoy_s:
        avisos += ("<p class='meta' style='color:#b71c1c'>⚠ Sesión de "
                   "Facebook caída — corre fb_login.py; las capturas FB "
                   "salen anónimas mientras.</p>")
    if admin and est_v.get("x_sesion", {}).get("estado") == "caida":
        avisos += ("<p class='meta' style='color:#b71c1c'>⚠ Sesión de "
                   "X caída — corre x_login.py; XEVT queda sin portada "
                   "y el radar X vacío.</p>")
    sal = est_v.get("salud", {}) if admin else {}
    call = sal.get("calladas") or []
    if call:
        lista = ", ".join(
            f"{c['f']} ({'nunca' if c['dias'] < 0 else str(c['dias']) + 'd'})"
            for c in call[:10])
        avisos += (f"<p class='meta' style='color:#d97706'>Fuentes "
                   f"calladas — {len(call)} de {sal.get('activas', '?')} "
                   f"activas sin notas: {lista}"
                   f"{'…' if len(call) > 10 else ''}</p>")
    # día seleccionado (?dia=oct/06) — default hoy
    dia_sel = dia if re.fullmatch(r"[a-z]{3}/\d{2}", dia) \
        else str(_dir_dia().relative_to(PORTADAS_DIR))
    dir_sel = PORTADAS_DIR / dia_sel
    dias = sorted((f"{m.name}/{d.name}"
                   for m in PORTADAS_DIR.iterdir() if m.is_dir()
                   for d in m.iterdir() if d.is_dir()),
                  key=lambda x: (PORTADAS_DIR / x).stat().st_mtime,
                  reverse=True) if PORTADAS_DIR.exists() else []
    tabs_dia = ("<div class='tabs-cat'>" + "".join(
        f"<a class='tab-cat{' on' if d == dia_sel else ''}' "
        f"href='/portadas?sec={sec}&dia={d}'>{d}</a>" for d in dias)
        + "</div>") if dias else ""
    # un solo botón PDF: se arma al click con lo capturado de ese
    # día (los tardíos entran hasta ~9am); solo usuarios con sesión
    pdf_block = (f"<p class='meta'>PDF: <a class='tab-cat on' "
                 f"href='/portadas-pdf?sec={sec}&dia={dia_sel}' "
                 f"target='_blank'>{dia_sel}</a></p>"
                 if logueado else "")
    tabs = ("<div class='tabs-cat'>"
            + f"<a class='tab-cat{' on' if sec != 'tabasco' else ''}' "
              "href='/portadas?sec=nacional'>Nacional</a>"
            + f"<a class='tab-cat{' on' if sec == 'tabasco' else ''}' "
              "href='/portadas?sec=tabasco'>Tabasco</a></div>")
    # orden: la captura más reciente arriba; sin captura al final
    _m_idx = {m: f"{i + 1:02d}" for i, m in enumerate(
        ("ene", "feb", "mar", "abr", "may", "jun",
         "jul", "ago", "sep", "oct", "nov", "dic"))}
    _dia_key = "-" + _m_idx.get(dia_sel.split("/")[0], "") \
        + "-" + dia_sel.split("/")[-1]     # "oct/19" → "-10-19"
    _hora_ev = {}
    for ev in est_v.get("eventos", []):
        if ev.get("ok") and str(ev.get("d", "")).endswith(_dia_key):
            _hora_ev[ev.get("m", "")] = ev.get("t", "")
    medios.sort(key=lambda m: _hora_ev.get(m["nombre"], ""),
                reverse=True)
    cards = ""
    for m in medios:
        slug = _slug_portada(m["nombre"])
        img_f = _portada_img(slug, dir_sel)
        web_f = dir_sel / f"{slug}-web.png"
        tag = lambda p, rotulo: (
            f"<span class='meta'>{rotulo}</span>"
            f"<img src='/portadas/{dia_sel}/{p.name}?v={ultima}' "
            "loading='lazy' "
            "style='width:100%;border-radius:6px;margin:.15rem 0 .4rem'>"
            if p.exists() else "")
        if not img_f.exists():
            continue   # pendientes no se muestran — al publicar, la
            # portada aparece sola con badge RECIENTE 15 min
        reciente = ""
        if datetime.now().timestamp() - img_f.stat().st_mtime < 900:
            reciente = (" <span style='background:#2e7d32;color:#fff;"
                        "font-size:.65rem;font-weight:700;padding:1px "
                        "7px;border-radius:9px;vertical-align:2px'>"
                        "RECIENTE</span>")
        img = tag(img_f, "Impresa")
        # extras de FB/posts (segunda portada, contra, interior) —
        # el PDF ya las lleva, la vista no las mostraba
        for i, ex in enumerate(
                sorted(dir_sel.glob(f"{slug}-[0-9].jpg")), 2):
            img += tag(ex, f"Impresa {i}")
        img += tag(web_f, "Web")
        # medios solo-FB (El Sol del Sureste) no tienen 'url' — el
        # link apunta a su fanpage; sin ninguna fuente se omite
        url_m = m.get("url") or m.get("fb") or ""
        link_m = (f"<a href='{html.escape(url_m)}' target='_blank' "
                  "rel='noopener' class='meta' "
                  "style='display:block;margin:.15rem 0'>"
                  "abrir en el medio ↗</a>" if url_m else "")
        cards += (f"<div class='card' style='border-left-color:#7b1fa2'>"
                  f"<b>{html.escape(m['nombre'])}</b>{reciente}"
                  f"{link_m}{img}</div>")
    return (f"<h1>Portadas — {sec.title()} — {dia_sel}</h1>"
            f"{tabs}{tabs_dia}"
            f"<p class='meta'>Capturas del {ultima or '—'} · se regeneran a "
            f"las {html.escape(port.get('hora', '06:30'))}.</p>"
            + avisos + pdf_block + cards)


def vista_salud(admin: bool = True) -> str:
    """Tab Salud (admin): diagnóstico del sistema sin abrir logs —
    sesiones de terceros, medios de portadas que repiten/fallan y
    fuentes de notas calladas."""
    cfg = json.loads(CONFIG.read_text())
    est = cargar_json(ESTADO_PORTADAS, {})
    ahora = datetime.now()
    hoy_s = ahora.strftime("%Y-%m-%d")
    out = ["<h1>Salud del sistema</h1>"]

    # ── sesiones de terceros ──
    def _sesion(nom, path, extra=""):
        if not path.exists():
            return (f"<tr><td>{nom}</td><td style='color:#b71c1c'>"
                    f"SIN ARCHIVO</td><td>—</td><td>{extra}</td></tr>")
        edad = int((time.time() - path.stat().st_mtime) / 86400)
        color = "#0a7a2f" if edad <= 2 else "#d97706"
        return (f"<tr><td>{nom}</td><td style='color:{color}'>"
                f"{'ok' if edad <= 2 else 'vieja'}</td>"
                f"<td>hace {edad}d</td><td>{extra}</td></tr>")
    fb_extra = ""
    if est.get("fb_sesion", {}).get("estado") == "caida" \
            and est["fb_sesion"].get("alertado") == hoy_s:
        fb_extra = ("<b style='color:#b71c1c'>CHECKPOINT HOY</b> — "
                    "corre fb_login.py")
    x_extra = ""
    if est.get("x_sesion", {}).get("estado") == "caida":
        x_extra = ("<b style='color:#b71c1c'>LOGIN-WALL</b> — "
                   "corre x_login.py (radar X vacío, XEVT sin captura)")
    ses = ("<h2>Sesiones</h2><table><tr><th>Sesión</th><th>Estado</th>"
           "<th>Edad</th><th>Nota</th></tr>"
           + _sesion("FB · juan (portadas)", FB_SESSION, fb_extra)
           + _sesion("FB · chucky (posts)", FB_SESSION_REDES)
           + _sesion("X · @elpolidelanoche", X_SESSION, x_extra)
           + "</table>")
    out.append(ses)

    # ── chucky: rendimiento del barrido de posts ──
    fbp = est.get("fb_posts") or {}
    if fbp:
        pags = fbp.get("paginas", {})
        cero = [k for k, v in pags.items()
                if v["x"] and not v["n"]]
        rz = " · ".join(f"{k}: {v}" for k, v in
                        (fbp.get("razones") or {}).items())
        filas_p = "".join(
            f"<tr><td>{html.escape(k)}</td><td>{v['x']}</td>"
            f"<td>{' · '.join(f'{a}:{b}' for a, b in v['r'].items()) or '—'}"
            f"</td></tr>"
            for k, v in sorted(pags.items(),
                               key=lambda kv: -kv[1]["x"])
            if v["x"] and not v["n"])
        out.append(
            f"<h2>Chucky · posts FB</h2>"
            f"<p class='meta'>última pasada {fbp.get('fecha', '?')} — "
            f"{fbp.get('nuevas', 0)} nuevos · rechazos: {rz or '—'}</p>"
            + (f"<p><b style='color:#b71c1c'>{len(fbp.get('vacias', []))}"
               f" páginas vacías</b> (0 posts extraídos = sesión muerta "
               f"o página sin feed): "
               f"{html.escape(', '.join(fbp.get('vacias', [])[:20]))}"
               + ("…" if len(fbp.get('vacias', [])) > 20 else "")
               + "</p>" if fbp.get("vacias") else "")
            + (f"<details><summary>{len(cero)} páginas extrajeron "
               f"pero nada pasó los filtros</summary>"
               f"<table><tr><th>Página</th><th>Extraídos</th>"
               f"<th>Rechazos</th></tr>{filas_p}</table></details>"
               if cero else ""))

    # ── portadas: semana en problemas ──
    evs = [e for e in est.get("eventos", [])
           if e.get("d", "") >=
           (ahora - timedelta(days=7)).strftime("%Y-%m-%d")]
    stale = sorted({e["m"] for e in evs if e.get("stale")})
    ok_dia = {(e["m"], e["d"]) for e in evs if e.get("ok")}
    # faltas por medio: días del último rango sin captura exitosa.
    # 'hoy' se excluye — la edición puede estar aún en ventana; y
    # dias_off (domingo) no cuenta como inasistencia
    dias7 = [(ahora - timedelta(days=k)).strftime("%Y-%m-%d")
             for k in range(1, 8)]
    faltas = []
    off = set(cfg["portadas"].get("dias_off") or [])
    for m in cfg["portadas"]["medios"]:
        faltan = [d[5:] for d in dias7
                  if datetime.strptime(d, "%Y-%m-%d").weekday() not in off
                  and (m["nombre"], d) not in ok_dia]
        if faltan:
            faltas.append((m["nombre"], faltan))
    faltas.sort(key=lambda x: -len(x[1]))
    bloque = "<h2>Portadas · 7 días</h2><table>"
    if stale:
        bloque += (f"<tr><td><b>Plana repetida (stale)</b></td>"
                   f"<td style='color:#d97706'>{', '.join(stale)}</td>"
                   "</tr>")
    if faltas:
        bloque += ("<tr><th>Medio</th><th>Faltas</th>"
                   "<th>Fechas sin portada</th></tr>"
                   + "".join(
                       f"<tr><td>{html.escape(nom)}</td>"
                       f"<td style='color:#b71c1c'><b>{len(f)}</b></td>"
                       f"<td class='meta'>{', '.join(f)}</td></tr>"
                       for nom, f in faltas))
    else:
        bloque += "<tr><td>Sin faltas en la semana</td></tr>"
    bloque += "</table>"
    out.append(bloque)

    # ── fuentes calladas (diagnóstico interno — solo admin) ──
    if not admin:
        return "".join(out)
    sal = est.get("salud") or _salud_fuentes(cfg, ahora)
    call = sal.get("calladas", [])
    filas = "".join(
        f"<tr><td>{html.escape(c['f'])}</td><td>{c['tipo']}</td>"
        f"<td style='color:{'#b71c1c' if c['dias'] < 0 else '#d97706'}'>"
        f"{'nunca' if c['dias'] < 0 else str(c['dias']) + ' días'}</td>"
        f"<td class='meta'>{html.escape(c.get('ult', '—'))}</td></tr>"
        for c in call)
    out.append(
        f"<h2>Fuentes calladas — {len(call)} de "
        f"{sal.get('activas', '?')} activas</h2>"
        f"<p class='meta'>umbrales: rss/html/x ≥3 días sin nota · "
        f"fb ≥7 días · 'nunca' = jamás ha producido (feed roto o "
        f"nombre desajustado) · calculado {sal.get('fecha', '?')}</p>"
        + (f"<table><tr><th>Fuente</th><th>Tipo</th><th>Sin notas</th>"
           f"<th>Última</th></tr>{filas}</table>" if filas
           else "<p>Todas las fuentes activas producen.</p>"))
    return "".join(out)


def aplicar_accion_horarios(form: dict) -> str:
    """POST /horarios: CRUD de medios de portadas — nombre, sección,
    tipo de origen (web/kiosko/edicion/json/fb/issuu/flip/pr/pdf),
    URL/slug, cap_desde/cap_hasta, cada_min, regla; alta con campos n_*
    y baja con del{i}. Regenera schedule.html."""
    cfg = json.loads(CONFIG.read_text())
    medios = cfg.get("portadas", {}).get("medios", [])
    hhmm = re.compile(r"^\d{1,2}:\d{2}$")
    CLAVES_ORIGEN = ("kiosko", "edicion", "json", "fb", "issuu", "flip",
                     "calameo", "pr", "flowpaper")

    def pone_hora(m, campo, clave):
        if campo not in form:
            return
        v = form[campo][0].strip()
        if v and hhmm.match(v):
            m[clave] = v
        else:
            m.pop(clave, None)

    def pone_origen(m, tipo, valor):
        """tipo select: web/pdf → url; el resto → su clave de estrategia.
        Limpia las demás claves de origen para no mezclar métodos."""
        valor = valor.strip()
        for k in CLAVES_ORIGEN + ("pdf",):
            if k != tipo:
                m.pop(k, None)
        if tipo == "web":
            if valor:
                m["url"] = valor
        elif tipo == "pdf":
            m["pdf"] = True
            if valor:
                m["url"] = valor
        else:
            # kiosko/issuu guardan slug — si pegan URL completa se
            # extrae (kiosko: .../mx_reforma.html → mx_reforma;
            # issuu: issuu.com/handle → handle). fb/flip/pr sí son
            # URLs completas y se guardan tal cual.
            if tipo in ("kiosko", "issuu") and "/" in valor:
                valor = valor.rstrip("/").rsplit("/", 1)[-1]
                valor = valor.removesuffix(".html")
            if valor:
                m[tipo] = valor
            if tipo == "fb" and not m.get("url"):
                # fb necesita url para el fallback/registro — usa la
                # misma fanpage si no hay sitio
                m["url"] = valor

    nuevos, borrados = [], 0
    for i, m in enumerate(medios):
        if form.get(f"del{i}", [""])[0] == "1":
            borrados += 1
            continue   # no se agrega a nuevos = borrado
        if f"n{i}" in form and form[f"n{i}"][0].strip():
            m["nombre"] = form[f"n{i}"][0].strip()[:80]
        if f"s{i}" in form and form[f"s{i}"][0] in ("nacional", "tabasco"):
            m["seccion"] = form[f"s{i}"][0]
        pone_hora(m, f"d{i}", "cap_desde")
        pone_hora(m, f"h{i}", "cap_hasta")
        if f"c{i}" in form:
            # tolerante: "30", "30 min", "cada 30" → 30; solo un número
            # válido 5–240 guarda, lo demás restaura el default
            num = re.search(r"\d+", form[f"c{i}"][0])
            if num and 5 <= int(num.group()) <= 240:
                m["cada_min"] = int(num.group())
            else:
                m.pop("cada_min", None)
        if f"t{i}" in form:
            tipo = form[f"t{i}"][0]
            if tipo in ("web", "pdf") + CLAVES_ORIGEN:
                pone_origen(m, tipo, form.get(f"o{i}", [""])[0])
        elif f"o{i}" in form:
            # form sin select de tipo: actualiza el campo vivo
            v = form[f"o{i}"][0].strip()
            for k in CLAVES_ORIGEN:
                if m.get(k):
                    if v:
                        m[k] = v
                    else:
                        m.pop(k, None)
                    break
            else:
                if v:
                    m["url"] = v
        if f"r{i}" in form:
            r = form[f"r{i}"][0].strip()
            if r:
                m["regla"] = r[:200]
            else:
                m.pop("regla", None)
        nuevos.append(m)
    medios[:] = nuevos

    # alta: nueva fuente desde el form n_*
    if form.get("n_nombre", [""])[0].strip():
        tipo = form.get("n_tipo", ["web"])[0]
        origen = form.get("n_origen", [""])[0].strip()
        nuevo = {"nombre": form["n_nombre"][0].strip()[:80],
                 "seccion": form.get("n_sec", ["nacional"])[0]
                 if form.get("n_sec", [""])[0] in ("nacional", "tabasco")
                 else "nacional",
                 "url": origen}
        pone_origen(nuevo, tipo, origen)
        for campo, clave in (("n_desde", "cap_desde"),
                             ("n_hasta", "cap_hasta")):
            v = form.get(campo, [""])[0].strip()
            if v and hhmm.match(v):
                nuevo[clave] = v
        c = re.search(r"\d+", form.get("n_cada", [""])[0])
        if c and 5 <= int(c.group()) <= 240:
            nuevo["cada_min"] = int(c.group())
        r = form.get("n_regla", [""])[0].strip()
        if r:
            nuevo["regla"] = r[:200]
        medios.append(nuevo)

    _escribir_json(CONFIG, cfg)
    escribir_schedule_portadas(cfg)
    return f"Guardado ({borrados} borrados)"


def detectar_desarrollo(cfg: dict, resumir: bool) -> int:
    """Noticia en desarrollo: un cluster que CRECE entre ciclos dispara alerta.

    Guarda en clusters.json cuántas versiones tenía cada historia; si en
    este ciclo apareció con más versiones (o nació ya con >=3), alerta.
    """
    noticias = leer_jsonl(NOTICIAS, limite=300)
    if not noticias:
        return 0

    previo = cargar_json(CLUSTERS, {})

    estado = {}
    nuevas_alertas = 0
    for rep, cluster in agrupar_noticias(noticias):
        seed = cluster[0]["link"]          # la nota más vieja = ID estable
        estado[seed] = len(cluster)
        antes = previo.get(seed, 0)
        crecio = antes > 0 and len(cluster) > antes
        nacio_grande = antes == 0 and len(cluster) >= 3
        if crecio or nacio_grande:
            nuevas_alertas += 1
            fuentes = sorted({n["fuente"] for n in cluster})
            alerta = {
                "fecha": datetime.now().isoformat(timespec="seconds"),
                "fuente": ", ".join(fuentes),
                "categoria": "desarrollo",
                "autor": "",
                "reglas": f"Noticia en desarrollo ({antes}→{len(cluster)} medios)",
                "titulo": rep["titulo"],
                "link": rep["link"],
                "imagen": rep.get("imagen", ""),
                "resumen_ia": resumir_ollama_seguro(cfg, rep["titulo"],
                                             " ".join(n["titulo"] for n in cluster))
                              if resumir else "",
            }
            registrar_alerta(alerta, cfg)
            print(f"\n*** EN DESARROLLO: {alerta['titulo'][:80]} "
                  f"({len(cluster)} medios) ***")

    CLUSTERS.write_text(json.dumps(estado, ensure_ascii=False, indent=0))
    return nuevas_alertas


_LOCK_REVISAR = threading.Lock()


def ciclo_ahora() -> bool:
    """Corre un ciclo de revisión inmediato (al guardar una regla, etc.).
    El lock evita que se solape con el ciclo periódico del --loop.
    Devuelve False si ya había un ciclo corriendo."""
    if not _LOCK_REVISAR.acquire(blocking=False):
        return False
    try:
        cfg = json.loads(CONFIG.read_text())
        revisar(cfg, mostrar_todo=False, resumir=False)
        return True
    except Exception as e:
        print(f"ciclo on-demand falló: {e}")
        return False
    finally:
        _LOCK_REVISAR.release()


PAGINA = """<!DOCTYPE html>
<!--email_off-->   <!-- Cloudflare: NO ofuscar correos (los ve el admin) -->
<html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="60">
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
</style></head><body>
<nav>
  <div class="nav-top">
    <a class="logo" href="/noticias">@noticias</a>
    <form method="get" action="/buscar" role="search"
          onsubmit="showLoader('Buscando...')">
      <input type="text" name="q" placeholder="buscar nota... (&quot;frase exacta&quot;)" value="{q}">
      <button>Buscar</button>
    </form>
    <span class="nav-user" title="{usuario}">{usuario_html}</span>
    <a href="/salir" class="salir-top" title="Cerrar sesión">salir</a>
  </div>
  <div class="nav-tabs">
    <a href="/noticias">Noticias</a>
    <a href="/alertas">Alertas</a>
    <a href="/portadas">Portadas</a>
    {tabs_reg}
    {admin_tabs}
  </div>
</nav>
<main>
{contenido}
</main>
<div id="loader"><div class="card"><div class="spinner"></div><div class="txt" id="loader-txt">Cargando...</div></div></div>
<footer><a href="/acerca" class="about">@</a> <a href="https://olmecacode.pages.dev/" class="about" target="_blank" rel="noopener" title="Olmeca Code">OC</a></footer>
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
document.addEventListener('click', function(e) {{
  var a = e.target.closest('a[href^="/nota?"], a[href^="/buscar?"]');
  if (!a) return;
  var msg = a.getAttribute('data-loading') ||
            (a.getAttribute('href').startsWith('/buscar')
             ? 'Buscando...' : 'Cargando nota...');
  showLoader(msg);
}});
// tab activo: marca el link del nav según la ruta actual
var _mapa = {{'/':'/noticias','/nota':'/noticias','/buscar':'/noticias',
             '/destacadas':'/noticias','/schedule':'/portadas'}};
var _tab = _mapa[location.pathname] || location.pathname;
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
// Contador en el ícono anclado (Badging API; solo aplica si la PWA
// está instalada en el menú de inicio — en navegador normal se ignora)
// + globito por tab con notas nuevas desde la última visita a cada una
fetch("/badge").then(r => r.json()).then(d => {{
  if ("setAppBadge" in navigator)
    d.n ? navigator.setAppBadge(d.n) : navigator.clearAppBadge();
  var t = d.t || {{}};
  document.querySelectorAll('.nav-tabs a').forEach(function(a) {{
    var n = t[a.getAttribute('href')];
    var old = a.querySelector('.tab-badge'); if (old) old.remove();
    if (n) {{
      var b = document.createElement('span');
      b.className = 'tab-badge';
      b.textContent = n > 99 ? '99+' : n;
      a.appendChild(b);
    }}
  }});
}}).catch(() => {{}});
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


_NOTICIAS_CACHE = {"m": 0.0, "ns": []}


def _noticias_cache() -> list:
    """noticias.jsonl entero cacheado por mtime — 60 MB en RAM UNA
    vez, no por cada render/badge (el 'tardísimo' al cambiar de tab
    era reparsear el archivo en cada vista). Se invalida solo cuando
    el archivo cambia (una nota nueva = mtime nuevo)."""
    try:
        m = NOTICIAS.stat().st_mtime
    except OSError:
        return []
    if _NOTICIAS_CACHE["m"] != m:
        _NOTICIAS_CACHE["ns"] = leer_jsonl(NOTICIAS, limite=0)
        _NOTICIAS_CACHE["m"] = m
    return _NOTICIAS_CACHE["ns"]


LOGIN = """<!DOCTYPE html>
<html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="theme-color" content="#1a237e">
<link rel="icon" type="image/png" href="/icon3.png">
<meta property="og:type" content="website">
<meta property="og:site_name" content="@noticias">
<meta property="og:title" content="@noticias — Monitor de prensa TSJT">
<meta property="og:description" content="Monitor de noticias del Poder Judicial de Tabasco: prensa del TSJT, alertas por tema y síntesis ejecutivas.">
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
  .inv { margin-top: 1.4rem; }
  .inv button { background: none; border: 1px solid #1a237e;
                color: #1a237e; font-weight: 500; }
  .error { color: #c62828; font-size: .9rem; margin-bottom: .8rem; }
  .pie { color: #c3c9d4; font-size: .8rem; margin-top: 2.5rem; }
</style></head><body>
<div class="login">
  <p class="logo">@noticias</p>
  <p class="tag">Síntesis de prensa con alertas en tiempo real</p>
  {error}
  <form method="post" action="/login">
    <input type="email" name="email" placeholder="Usuario (correo)"
           autocomplete="username" required>
    <input type="password" name="password" placeholder="Contraseña"
           autocomplete="current-password" required>
    <button>Entrar</button>
  </form>
  <form class="inv" method="post" action="/invitado">
    <button>Entrar como invitado</button>
  </form>
  <p class="pie">Powered by <a href="https://olmecacode.pages.dev/" target="_blank" rel="noopener" style="color:#c3c9d4">Olmeca Code</a></p>
</div>
</body></html>"""


def vista_login(base: str, error: str = "") -> bytes:
    err = (f"<p class='error'>{html.escape(error)}</p>" if error else "")
    return (LOGIN.replace("{error}", err)
                 .replace("{base}", base)).encode()


def badge_count(email: str) -> int:
    """Alertas (propias + globales) más nuevas que su última visita a
    /alertas. Sin visita previa: las de las últimas 24h."""
    cfg = json.loads(CONFIG.read_text())
    perfil = perfil_usuario(email, cfg)
    visto = perfil.get("visto_alertas") or \
        (datetime.now() - timedelta(hours=24)).isoformat(timespec="seconds")
    return sum(1 for a in leer_jsonl(ALERTAS)
               if (not a.get("usuario") or a["usuario"] == email)
               and a["fecha"] > visto)


def badge_counts(email: str) -> dict:
    """Globitos por tab: notas nuevas desde la última visita a cada
    sección. 'n' = alertas (Badging API); 't' = {ruta: cuenta} que el
    JS pinta sobre el tab. Sin visita previa: ventana de 24 h."""
    cfg = json.loads(CONFIG.read_text())
    perfil = perfil_usuario(email, cfg)
    ahora = datetime.now()

    def _v(clave: str) -> str:
        return perfil.get(clave) or \
            (ahora - timedelta(hours=24)).isoformat(timespec="seconds")

    vis = fuentes_visibles(perfil, cfg)
    vn, vi, vx, vs, vt = (_v("visto_noticias"), _v("visto_interes"),
                          _v("visto_x"), _v("visto_seguimiento"),
                          _v("visto_telegram"))
    x_ok = {_handle_x(u).lower()
            for u in cfg.get("x_permitidos", [])} - {""}
    tg_f = {f["nombre"] for f in cfg.get("fuentes", [])
            if f.get("tipo") == "telegram"}
    cn = ci = cx = cs = ct = 0
    for n in _noticias_cache():
        f = n["fecha"]
        if not (f > vn or f > vi or f > vx or f > vs or f > vt):
            continue
        if f > vs and n.get("categoria") == "seguimiento":
            cs += 1
        if f > vx and str(n.get("fuente", "")).lstrip("@").lower() \
                in x_ok:
            cx += 1
        if n["fuente"] not in vis and n.get("via") not in vis:
            continue
        if f > vt and (n["fuente"] in tg_f
                       or "t.me/" in (n.get("link") or "")):
            ct += 1
        if f > vn and n.get("categoria") != "seguimiento":
            cn += 1
        if f > vi and coincide_interes(n):
            ci += 1
    return {"n": badge_count(email),
            "t": {"/noticias": cn, "/interes": ci, "/x": cx,
                  "/telegram": ct, "/seguimiento": cs}}


def _marcar_visto(email: str, clave: str):
    """El usuario está viendo esta sección: su globito vuelve a 0."""
    usuarios = cargar_usuarios()
    if email in usuarios:
        usuarios[email][clave] = \
            datetime.now().isoformat(timespec="seconds")
        guardar_usuarios(usuarios)


def cookie_sesion(email: str, https: bool) -> str:
    seguro = "; Secure" if https else ""
    return (f"s={email}.{firma_cookie(email)}; Path=/; HttpOnly; "
            f"SameSite=Lax{seguro}")


PALETA = ["#1a237e", "#1565c0", "#00695c", "#ef6c00", "#ad1457",
          "#4527a0", "#2e7d32", "#c62828", "#00838f", "#5d4037"]


def color_regla(nombre: str, colores: dict) -> str:
    """Color de la regla: el elegido en /config o uno estable de la paleta.
    (crc32, no hash(): hash() varía entre reinicios del proceso)"""
    import zlib
    base = nombre.split(" (")[0]
    return colores.get(base) or PALETA[zlib.crc32(base.encode()) % len(PALETA)]


def badge_regla(nombre: str, colores: dict) -> str:
    base = nombre.split(" (")[0]
    return (f"<span class='badge' "
            f"style='background:{color_regla(nombre, colores)}'>"
            f"{html.escape(base)}</span>")


def _autor_limpio(n: dict) -> str:
    """Autor solo si aporta: si es el nombre del medio (Novedades feed
    rellena 'NOVEDADES') o está vacío, no se muestra."""
    au = (n.get("autor") or "").strip()
    if not au or normalizar(au) in normalizar(n.get("fuente", "")) \
            or normalizar(n.get("fuente", "")) in normalizar(au):
        return ""
    return f" · {html.escape(au)}"


def _ico_origen(n: dict) -> str:
    """Mini-glyph del canal junto al badge del medio: 𝕏 / f / web."""
    if (n.get("categoria") == "x"
            or str(n.get("fuente", "")).startswith("@")):
        return "<span class='ico-origen ico-x' title='X'>𝕏</span>"
    if n.get("categoria") == "redes":
        return "<span class='ico-origen ico-fb' title='Facebook'>f</span>"
    return ("<span class='ico-origen ico-web' title='Web / RSS'>"
            "web</span>")


def tarjeta_alerta(a: dict, colores: dict, pals: str = "",
                   creador: str = "") -> str:
    """Tarjeta completa = link; badge de regla con su color; borde del mismo."""
    autor = _autor_limpio(a)
    color = color_regla(a["reglas"], colores)
    return (
        f"<a class='card {html.escape(a.get('categoria', 'prensa'))}' "
        f"style='border-left-color:{color}' "
        f"href='/nota?u={quote(a['link'], safe='')}'>"
        + (f"<img class='thumb' src='{html.escape(url_https(html.unescape(a['imagen'])))}' loading='lazy' "
           f"onerror='this.remove()'>" if a.get("imagen") else "")
        + f"<div class='meta2'><span class='chip-fuente'>"
        f"{html.escape(a['fuente'])}</span>{_ico_origen(a)}"
        f"<span class='meta'>{fmt_fecha(a['fecha'])}{autor}</span></div>"
        f"{badge_regla(a['reglas'], colores)} "
        + (f"<span class='chip-creador' "
           f"title='Creador de la regla'>{html.escape(creador)}"
           f"</span> " if creador else "")
        + (f"<span class='chip-pals' "
           f"title='Palabras de la regla'>{html.escape(pals)}</span> "
           if pals else "")
        + f"<span class='titulo'>{html.escape(a['titulo'])}</span>"
        + (f"<p class='resumen'>{html.escape(a['resumen_ia'])}</p>" if a.get("resumen_ia") else "")
        + "</a>"
    )


STOPWORDS = {"el", "la", "los", "las", "de", "del", "en", "y", "a", "un",
             "una", "por", "con", "para", "que", "se", "su", "al", "es",
             "ante", "tras", "este", "esta", "como", "más", "no", "su"}


def _plural_tok(p: str) -> str:
    """'centros'→'centro', 'pilares'→'pilar': sin el folding, la misma
    historia en plural/singular perdía ~15% de Jaccard."""
    if len(p) > 5 and p.endswith("es"):
        return p[:-2]
    if len(p) > 4 and p.endswith("s"):
        return p[:-1]
    return p


def tokens_titulo(titulo: str) -> set:
    """Palabras significativas del titular para comparar similitud."""
    return {_plural_tok(p)
            for p in re.findall(r"[a-z0-9]+", normalizar(titulo))
            if len(p) > 3 and p not in STOPWORDS}


def agrupar_noticias(noticias: list, umbral: float = 0.45,
                     ventana_dias: int = 5) -> list:
    """Agrupa notas con titulares similares (misma historia, varios medios).

    Compara pares por similitud de Jaccard sobre tokens del titular.
    La ventana temporal evita falsos clusters: titulares periódicos tipo
    "Latinus Diario: 22 de septiembre" son "la misma historia" por Jaccard
    pero ocurrieron meses aparte — misma noticia = misma época.
    Devuelve clusters ordenados por número de notas (mayor cobertura = más
    destacada), con el titular más largo como representante.
    """

    def _ts(n):
        try:
            return datetime.fromisoformat(n["fecha"]).timestamp()
        except Exception:
            return None

    # dedupe: misma fuente + mismo titular = la misma nota con URL distinta
    # (pasa cuando el medio republica la nota bajo otra URL/categoría)
    MESES = ("enero febrero marzo abril mayo junio julio agosto "
             "septiembre setiembre octubre noviembre diciembre").split()
    RE_FECHA = re.compile(
        r"\b\d{1,2}\s+de\s+(?:" + "|".join(MESES) + r")\b")

    def _base_y_fechas(n):
        """(titulo sin fechas ni dígitos, firmas de fecha del titulo).
        Dos titulares con la misma base pero fecha distinta son EDICIONES
        diferentes ('Latinus Diario: 30 de septiembre' vs '2 de octubre'),
        no la misma historia."""
        norm = normalizar(n["titulo"])
        sigs = set(RE_FECHA.findall(norm))
        base = RE_FECHA.sub("", norm)
        sigs |= set(re.findall(r"\b\d{4}[- ]\d{1,2}[- ]\d{1,2}\b", base))
        sigs |= set(re.findall(r"\b\d+\b", base))
        base = re.sub(r"\d+|\b(?:" + "|".join(MESES) + r")\b", "", base)
        return " ".join(base.split()), sigs

    unicos, claves = [], set()
    for n in noticias:
        # medio canónico: 'LatinUS'/'latinus.us'/'Latinus' = 1 medio
        k = (_canon_medio(n["fuente"]), normalizar(n["titulo"]))
        if k not in claves:
            claves.add(k)
            unicos.append(n)
    items = [(n, tokens_titulo(n["titulo"]), _ts(n), *_base_y_fechas(n))
             for n in unicos]
    usado = [False] * len(items)
    grupos = []
    for i, (ni, ti, fi, base_i, sigs_i) in enumerate(items):
        if usado[i] or not ti:
            continue
        cluster = [ni]
        usado[i] = True
        for j in range(i + 1, len(items)):
            nj, tj, fj, base_j, sigs_j = items[j]
            if usado[j] or not tj:
                continue
            if (fi and fj and
                    abs(fi - fj) > ventana_dias * 86400):
                continue
            # misma base pero fecha/números distintos = ediciones
            # diferentes ("Latinus Diario: 30 de septiembre" vs
            # "2 de octubre", "3 muertos" vs "5 muertos")
            if base_i == base_j and sigs_i != sigs_j:
                continue
            jaccard = len(ti & tj) / len(ti | tj)
            if jaccard >= umbral:
                cluster.append(nj)
                usado[j] = True
        if len(cluster) > 1:
            # representante = el titular más largo del grupo
            rep = max(cluster, key=lambda n: len(n["titulo"]))
            grupos.append((rep, cluster))
    return sorted(grupos, key=lambda g: -len(g[1]))


def _fusionar_temas(ordenadas: list, clusters: list) -> list:
    """2ª vuelta de agrupación para Interés: Jaccard exige titulares
    parecidos, pero la prensa local reescribe la historia completa
    ('inaugura Centro DIF Pilares' vs 'apuesta por duplicar centros
    Pilares' = 0.23). Une grupos —incluidas notas sueltas— cuando el
    MISMO actor de la lista aparece en ambos Y comparten un token
    raro presente en TODAS las notas de cada grupo (df ≤3 entre
    grupos: 'pilar' sí; 'inaugura'/'agua' con df 5 ya son genéricos
    y abrían la puerta a notas ajenas). Además la nota más reciente
    de cada grupo debe estar dentro de la misma ventana de 5 días —
    sin eso 'agua en Comalcalco' juntaba julio con octubre."""
    grupos = [list(c) for _, c in clusters]
    cubiertas = {n["link"] for c in grupos for n in c}
    grupos += [[n] for n in ordenadas if n["link"] not in cubiertas]
    if len(grupos) < 2:
        return clusters

    def _fmax(g):
        f = []
        for n in g:
            try:
                f.append(datetime.fromisoformat(n["fecha"]).timestamp())
            except Exception:
                pass
        return max(f) if f else 0

    actor_g, comun_g, fmax_g = [], [], []
    for g in grupos:
        ac = Counter(t for n in g for t in _interes_match(n))
        actor_g.append(ac.most_common(1)[0][0] if ac else "")
        comunes = tokens_titulo(g[0]["titulo"])
        for n in g[1:]:
            comunes &= tokens_titulo(n["titulo"])
        comun_g.append(comunes)
        fmax_g.append(_fmax(g))
    df = Counter(t for ts in comun_g for t in ts)
    ventana_s = 5 * 86400

    def _compatible(i, j):
        return (actor_g[i] and actor_g[i] == actor_g[j]
                and abs(fmax_g[i] - fmax_g[j]) <= ventana_s
                and any(df[t] <= 3 for t in comun_g[i] & comun_g[j]))

    # sin cadenas: un suelto solo se anexa a un cluster ya formado
    # (si 'puenteara' entre clusters volvía el mega-cluster de
    # 'javier may' — May+feria→May+queso→May+sheinbaum)
    res = []
    usados = set()
    bases = [i for i, g in enumerate(grupos) if len(g) > 1]
    for i in bases:
        if i in usados:
            continue
        cur = list(grupos[i])
        usados.add(i)
        for j in bases:
            if j not in usados and _compatible(i, j):
                cur.extend(grupos[j])
                usados.add(j)
        res.append((i, cur))
    pareja = set()
    solos = [i for i, g in enumerate(grupos) if len(g) == 1]
    for i in solos:
        if i in pareja:
            continue
        dest = next((cur for bi, cur in res if _compatible(i, bi)),
                    None)
        if dest is not None:
            dest.extend(grupos[i])
            pareja.add(i)
            continue
        for j in solos:
            if j <= i or j in pareja:
                continue
            if _compatible(i, j):
                res.append((i, grupos[i] + grupos[j]))
                pareja.update((i, j))
                break
    return [c for _, c in res]


def tarjeta_destacada(rep: dict, cluster: list) -> str:
    fuentes = sorted({n["fuente"] for n in cluster})
    variantes = "".join(
        f"<a class='variante meta' href='/nota?u={quote(n['link'], safe='')}'>"
        f"<span class='chip-fuente'>{html.escape(n['fuente'])}</span>{_ico_origen(n)} "
        f"{fmt_fecha(n['fecha'])} · {html.escape(n['titulo'][:110])}</a>"
        for n in sorted(cluster, key=lambda n: n["fecha"], reverse=True)
    )
    resumen = (f"{len(cluster)} versiones de {fuentes[0]}"
               if len(fuentes) == 1 else
               f"{len(cluster)} versiones · {len(fuentes)} medios: "
               f"{', '.join(fuentes)}")
    return (
        f"<div class='card top'>"
        + (f"<img class='thumb' src='{html.escape(url_https(rep['imagen']))}' loading='lazy' "
           f"onerror='this.remove()'>" if rep.get("imagen") else "")
        + f"<a href='/nota?u={quote(rep['link'], safe='')}' "
        f"style='text-decoration:none;color:inherit'>"
        f"<span class='titulo'>{html.escape(rep['titulo'])}</span></a>"
        f"<div class='meta'>{html.escape(resumen)}</div>"
        f"<details><summary>Ver las {len(cluster)} versiones ▾</summary>{variantes}</details>"
        f"</div>"
    )


def tarjeta_noticia(n: dict, extra: str = "") -> str:
    autor = _autor_limpio(n)
    img = n.get("imagen", "")
    # avatar de X (og:image = perfil) no es media del post — fuera
    if "profile_images" in img:
        img = ""
    img = html.unescape(img)   # '&amp;' literal guardado en jsonl
    return (
        f"<a class='card nota' href='/nota?u={quote(n['link'], safe='')}'"
        f">"+ (f"<img class='thumb' src='{html.escape(url_https(img))}' loading='lazy' "
           f"onerror='this.remove()'>" if img else "")
        + f"<div class='meta2'><span class='chip-fuente'>"
        f"{html.escape(n['fuente'])}</span>{_ico_origen(n)}"
        f"<span class='meta'>{fmt_fecha(n['fecha'])}{autor}</span></div>"
        f"<span class='titulo'>{html.escape(n['titulo'])}</span>"
        + (f"<p style='font-size:.68rem;color:#2e7d32;margin:.2rem 0 0'>"
           f"{html.escape(extra)}</p>" if extra else "")
        + "</a>"
    )


_SIGLAS_INT = {"tsj", "tsjt", "dif", "pjf", "oaj", "ine", "sutapjet"}


def _forma_token(tok: str, cluster: list) -> str:
    """Casing dominante del token en los titulares — DIF/PILARES
    conservan sus mayúsculas; 'centros' sale capitalizado."""
    c = Counter()
    for x in cluster:
        for w in re.findall(r"[A-Za-zÁÉÍÓÚÜÑáéíóúüñ']+", x["titulo"]):
            if normalizar(w) == tok:
                c[w] += 1
    if not c:
        return tok.capitalize()
    forma = c.most_common(1)[0][0]
    return forma if forma.isupper() else forma.capitalize()


def _titulo_grupo(cluster: list) -> str:
    """'Javier May · Centros DIF Pilares': actor de la lista de
    interés + los tokens que comparten TODOS los titulares. Mejor
    encabezado de cluster que copiar el titular de un solo medio."""
    rep = max(cluster, key=lambda n: len(n["titulo"]))
    comunes = tokens_titulo(rep["titulo"])
    for x in cluster:
        if x is not rep:
            comunes &= tokens_titulo(x["titulo"])
    if not comunes:
        return ""
    actores = Counter()
    for x in cluster:
        for t in _interes_match(x):
            actores[t] += 1
    actor = actores.most_common(1)[0][0] if actores else ""
    toks_actor = set(normalizar(actor).split())
    tema = [t for t in comunes if t not in toks_actor]
    orden_rep = {t: i for i, t in enumerate(
        re.findall(r"[a-z0-9]+", normalizar(rep["titulo"])))}
    tema.sort(key=lambda t: orden_rep.get(t, 99))
    tema_txt = " ".join(_forma_token(t, cluster) for t in tema[:5])
    if not tema_txt:
        return ""   # actor solo no dice tema — mejor el titular rep
    actor_txt = " ".join(
        w.upper() if w in _SIGLAS_INT else w.capitalize()
        for w in actor.split())
    return f"{actor_txt} · {tema_txt}" if actor_txt else tema_txt


def tarjeta_grupo(cluster: list) -> str:
    """Tarjeta de cluster en Interés: un tema, N medios. Mosaico 2×2
    en el slot del thumb (1 imagen = thumb normal) y dropdown con el
    titular de cada nota — no el titular de un solo medio."""
    orden = sorted(cluster, key=lambda n: n["fecha"], reverse=True)
    rep = orden[0]
    titulo_g = _titulo_grupo(cluster) or rep["titulo"]
    imgs, vistos = [], set()
    for n in orden:
        i = html.unescape(n.get("imagen", ""))
        if i and "profile_images" not in i and i not in vistos:
            vistos.add(i)
            imgs.append(i)
    if len(imgs) > 1:
        celda = "".join(
            f"<img src='{html.escape(url_https(u))}' loading='lazy'"
            f" onerror='this.remove()'>" for u in imgs[:4])
        thumb = f"<div class='thumb-grid'>{celda}</div>"
    elif imgs:
        thumb = (f"<img class='thumb' "
                 f"src='{html.escape(url_https(imgs[0]))}'"
                 f" loading='lazy' onerror='this.remove()'>")
    else:
        thumb = ""
    medios = len({n["fuente"] for n in orden})
    items = "".join(
        f"<a class='grupo-item' "
        f"href='/nota?u={quote(n['link'], safe='')}'>"
        f"<span class='chip-fuente' style='font-size:.6rem;"
        f"padding:1px 6px'>{html.escape(n['fuente'])}</span>"
        f"{_ico_origen(n)}"
        f" {html.escape(n['titulo'])}"
        f" <span class='meta'>{fmt_fecha(n['fecha'])}</span></a>"
        for n in orden)
    terminos = sorted({t for n in orden for t in _interes_match(n)})
    return (
        f"<div class='card nota grupo'>{thumb}"
        f"<div class='meta2'><span class='chip-fuente' "
        f"style='background:#455a64'>{medios} medios</span>"
        f"<span class='meta'>{fmt_fecha(rep['fecha'])}</span></div>"
        f"<span class='titulo'>{html.escape(titulo_g)}</span>"
        f"<details class='grupo-det'><summary class='grupo-tog'>"
        f"{len(orden)} notas · ver titulares</summary>{items}</details>"
        f"<p style='font-size:.68rem;color:#2e7d32;margin:.2rem 0 0'>"
        f"encontró: {html.escape(', '.join(terminos))}</p></div>")


INTERES_FUERTES = [
    # nombres propios — bastan solos
    "efrain resendez", "resendez bocanegra", "carlos efrain",
    "mario balcazar",
    "paola hernandez garcia",
    "donaciano quen", "quen perez",
    "juan pablo rabago", "rabago contreras",
    "paolo orrico", "orrico julien",
    "german garcia mollinedo", "garcia mollinedo", "german garcia",
    "gustavo glori tellechea", "gustavo glori",
    "jose ramiro lopez obrador", "pepin lopez obrador",
    "javier may", "javier may rodriguez", 


    # TSJ Tabasco inequívoco
    "tribunal superior de justicia de tabasco",
    "poder judicial de tabasco",
    "sindicato del tribunal superior de justicia de tabasco",
    "voluntariado del tribunal superior de justicia",
    "magistrados del tsj", "magistrados de tsj",
    "magistrados tabasco", "judicial tabasco",
]
# nombres propios COMUNES (homónimos frecuentes) — solo cuentan con
# ancla Tabasco/TSJ o en prensa local: 'Paola Hernández' a secas en
# una nota de K-dramas de Vanguardia (15/oct) era homónima del medio
# artístico, no la del TSJ
INTERES_FUERTES_CTX = ["paola hernandez"]
# \b en nombres: 'javier may' como substring crudo colaría
# 'Mayagoitia'/'Javier Mayor'
INTERES_DEBILES_TEMA = [
    # temas abstractos: sin 'tabasco' explícito pueden ser de otro
    # estado o de la reforma federal — no cuentan
    "reforma judicial", "poder judicial",
    "administracion judicial", "disciplina judicial",
    # OAJ es órgano FEDERAL del PJF — sin ancla Tabasco colaba notas
    # de la reforma federal como si fueran del TSJT
    "organo de administracion judicial",
    "organos de administracion judicial",
    # TDJ también es FEDERAL (disciplina del PJF) — solo cuenta si la
    # nota la amarra a Tabasco
    "tribunal de disciplina",
]
INTERES_DEBILES_ACTOR = [
    # actores judiciales: en prensa local el 'magistrado'/'juzgado'/
    # 'tribunal' es casi siempre el de Tabasco — basta medio local
    "magistrad", "tribunal superior de justicia",
    "juzgad", "oficial mayor",
    "sindicato del tribunal", "voluntariado del tribunal",
    "presidente del tribunal", "presidenta del tribunal",
    "titular del poder judicial",
    "oficial mayor del tribunal",
]
INTERES_TABASCO = ["tabasco", "villahermosa", "resendez"]
RX_TSJ = re.compile(r"\btsjt?\b")
# menciones al magistrado/TSJ — compuerta única: el tab Telegram solo
# enseña posts con una de estas, y 'javier may' SOLO no entra a
# Interés sin tocar una (regla del usuario 22/oct: el sistema es un
# monitor de Carlos Efraín Reséndez Bocanegra)
RX_RESENDEZ = re.compile(
    r"resendez|poder judicial|tribunal superior|magistrad|judicatur")
# 'Tribunal Superior de Justicia de Guerrero/CDMX/…' — no es el TSJT
RX_TSJ_OTRO = re.compile(
    r"tribunal superior de justicia (?:de|del) (?!tabasco\b)\w+")
# estados/tribunales ajenos — 'jueza de Zacatecas', 'TEEY de Yucatán',
# poder judicial de Quintana Roo: sin ancla TSJT → fuera
INTERES_AJENOS = [
    "aguascalientes", "baja california", "campeche", "chiapas",
    "chihuahua", "coahuila", "colima", "durango", "guanajuato",
    "guerrero", "hidalgo", "jalisco", "estado de mexico", "edomex",
    "cdmx", "ciudad de mexico", "michoacan", "morelos", "nayarit",
    "nuevo leon", "oaxaca", "puebla", "queretaro", "quintana roo",
    "san luis potosi", "sinaloa", "sonora", "tamaulipas", "tlaxcala",
    "veracruz", "yucatan", "zacatecas", "teey", "teez",
    "tribunal electoral del estado de yucatan",
]
# ── listas de interés extensibles desde config.json['interes'] ──
# claves opcionales: fuertes, debiles_tema, debiles_actor, tabasco,
# ajenos (listas de frases) y siglas_fuertes/siglas_tema (\b crudo).
# Los regex se compilan por demanda y se cachean por mtime — editar
# config.json basta, sin restart ni cambios de código.
_INTERES_RX: dict = {"m": -1.0, "d": {}}


def _interes_listas() -> dict:
    """Listas base + extras de config.json['interes'] con los regex
    compilados — mtime de config invalida el cache."""
    try:
        m = CONFIG.stat().st_mtime
    except OSError:
        m = 0.0
    if _INTERES_RX["m"] != m:
        try:
            _cfg = json.loads(CONFIG.read_text())
            ext = _cfg.get("interes", {})
        except Exception:
            _cfg, ext = {}, {}
        def L(base, clave):
            # 'quitar_<clave>' resta términos base — edición desde el
            # panel /interes sin tocar código
            q = {normalizar(t)
                 for t in ext.get("quitar_" + clave, [])}
            return [t for t in list(base)
                    + [str(x) for x in ext.get(clave, [])]
                    if normalizar(t) not in q]
        d = {
            "fuertes": L(INTERES_FUERTES, "fuertes"),
            "debiles_tema": L(INTERES_DEBILES_TEMA, "debiles_tema"),
            "debiles_actor": L(INTERES_DEBILES_ACTOR, "debiles_actor"),
            "tabasco": L(INTERES_TABASCO, "tabasco"),
            "ajenos": L(INTERES_AJENOS, "ajenos"),
        }
        # siglas tabasqueñas inequívocas — \b obligatorio ('tet' como
        # substring colaría 'teta'); TET = Tribunal Electoral de Tabasco,
        # OSFE = órgano estatal de fiscalización
        def S(clave, default):
            # defaults + extras mezclados — antes ext.get() or default
            # y al agregar una sigla desaparecían tet/osfe
            q = {normalizar(t)
                 for t in ext.get("quitar_" + clave, [])}
            return [str(t) for t in list(default)
                    + [str(x) for x in ext.get(clave, [])]
                    if normalizar(t) not in q]
        sig_f_raw = S("siglas_fuertes", ["tet", "osfe"])
        sig_t_raw = S("siglas_tema", ["tdj"])
        d["siglas_fuertes"], d["siglas_tema"] = sig_f_raw, sig_t_raw
        sig_f = [re.escape(t) for t in sig_f_raw]
        sig_t = [re.escape(t) for t in sig_t_raw]
        # handles X configurados = voces locales (XEVT, TabascoHOY,
        # columnistas) — sus posts cuentan como prensa local para el
        # ancla de los términos débiles; x:home es el radar, no
        d["x_locales"] = {
            _handle_x(f.get("url", "")).lower()
            for f in _cfg.get("fuentes", [])
            if f.get("tipo") == "x"
            and not str(f.get("url", "")).lower().startswith(
                "x:home")} - {""}
        d["fuertes_ctx"] = L(INTERES_FUERTES_CTX, "fuertes_ctx")
        d["rx_fuertes"] = re.compile(r"\b(?:" + "|".join(
            re.escape(t) for t in d["fuertes"]) + r")\b")
        # lista vacía → regex que nunca matchea (un '(?:)' vacío
        # encontraría '' en TODAS las notas y todo sería 'interés')
        f_ctx = [re.escape(t) for t in d["fuertes_ctx"]]
        d["rx_fuertes_ctx"] = re.compile(
            r"\b(?:" + "|".join(f_ctx) + r")\b" if f_ctx
            else r"(?!x)x")
        d["rx_siglas_f"] = re.compile(r"\b(?:" + "|".join(sig_f) + r")\b")
        d["rx_siglas_t"] = re.compile(r"\b(?:" + "|".join(sig_t) + r")\b")
        d["rx_ajenos"] = re.compile(r"\b(?:" + "|".join(
            re.escape(t) for t in d["ajenos"]) + r")\b")
        d["rx_hl"] = re.compile(
            r"\b(" + "|".join(
                _pat_interes(t) for t in sorted(
                    d["fuertes"] + d["fuertes_ctx"] + d["debiles_tema"]
                    + d["debiles_actor"] + d["tabasco"],
                    key=len, reverse=True))
            + r"|tsjt?|" + "|".join(sig_f + sig_t) + r")", re.I)
        _INTERES_RX.update({"m": m, "d": d})
    return _INTERES_RX["d"]


_RX_ACENTOS = {"a": "[aá]", "e": "[eé]", "i": "[ií]",
               "o": "[oó]", "u": "[uúü]", "n": "[nñ]"}


def _pat_interes(t: str) -> str:
    """Regex insensible a acentos para un término de la lista;
    palabra sola admite sufijo (magistrad → magistrado/a/s)."""
    pat = "".join(_RX_ACENTOS.get(c, re.escape(c)) for c in t)
    return pat + (r"\w*" if " " not in t else "")


def _resaltar_interes(txt_html: str) -> str:
    """<mark> sobre los términos de interés dentro de texto ya
    escapado — el cliente ve de un vistazo por qué entró cada dato."""
    return _interes_listas()["rx_hl"].sub(
        r"<mark style='background:#fff59d;padding:0 1px'>\1</mark>",
        txt_html)


def coincide_interes(nota: dict) -> bool:
    """True si la nota toca la lista de interés judicial-Tabasco."""
    return bool(_interes_match(nota))


_MATCH_CACHE = {"mt": 0.0, "m": {}}


def _interes_match(nota: dict) -> list:
    """Memo de _interes_match_scan por link — el regex completo de
    ~94k notas tardaba ~8s por vista; con cache una sola vez por
    versión del archivo (una nota nueva = mtime nuevo = re-scan)."""
    try:
        mt = NOTICIAS.stat().st_mtime
    except OSError:
        mt = 0.0
    if _MATCH_CACHE["mt"] != mt:
        _MATCH_CACHE["mt"], _MATCH_CACHE["m"] = mt, {}
    key = nota.get("link") or nota.get("titulo", "")
    if key not in _MATCH_CACHE["m"]:
        _MATCH_CACHE["m"][key] = _interes_match_scan(nota)
    return _MATCH_CACHE["m"][key]


def _interes_match_scan(nota: dict) -> list:
    """Lista de términos de la lista de interés que activaron la nota —
    vacío si no es de interés. Sirve para justificar cada nota en la
    vista ('encontró: resendez bocanegra').

    Nombres propios y siglas TSJ entran solos; términos genéricos
    ('reforma judicial', 'poder judicial', 'sindicato del tribunal')
    requieren contexto Tabasco en la misma nota — una reforma judicial
    nacional o el poder judicial de otro estado NO deben aparecer."""
    # SIN fuente/via: el nombre del medio ('Tabasco HOY') no puede
    # aportar el contexto Tabasco — una nota de la CDMX publicada en
    # un medio tabasqueño NO es de interés judicial local
    res = str(nota.get("resumen") or "")
    # boilerplate WP: '…apareció primero en Tabasco HOY' mete el nombre
    # del medio al resumen y falsea el contexto Tabasco
    res = re.split(
        r"apareci[oó] primero en|first appeared on|the post\b",
        res, flags=re.I)[0]
    # byline 'REDACCIÓN/QUADRATÍN TABASCO' al final del resumen — misma
    # contaminación de contexto que el boilerplate WP
    res = re.split(r"redacci[oó]n\s*/", res, flags=re.I)[0]
    texto = normalizar(
        f"{nota.get('titulo') or ''} {res} {nota.get('autor') or ''}")
    # contexto Tabasco solo en titulo+resumen — el autor puede ser el
    # propio medio ('Ahora Tabasco') y también falsea el contexto
    texto_ctx = normalizar(f"{nota.get('titulo') or ''} {res}")
    # 'local' = prensa Tabasco + fuentes oficiales — QUINTANA ROO NO:
    # el usuario lo definió — una nota de QRoo solo es de interés si
    # menciona Tabasco/TSJ o un nombre de la lista, no por su tribunal
    li = _interes_listas()
    local = nota.get("categoria") in ("prensa", "oficial")
    fnt = str(nota.get("fuente") or "")
    if not local and fnt.startswith("@"):
        # post de un handle X configurado = prensa local — su propio
        # timeline es el ancla Tabasco
        local = fnt[1:].lower() in li.get("x_locales", ())
    hay_tab = any(c in texto_ctx for c in li["tabasco"])
    hits = li["rx_fuertes"].findall(texto)
    hits += li["rx_siglas_f"].findall(texto)
    # nombres propios entran siempre — si Reséndez/Orrico sale en
    # una nota de otro estado, el nombre manda sobre las guardias
    # EXCEPTO 'javier may': solo cuenta junto al magistrado/TSJ
    # ('no nos interesa a menos que se incluya a Efraín' — 22/oct);
    # si solo hay hits de May sigue evaluando abajo, no regresa aún
    if hits and (not all(h.startswith("javier may") for h in hits)
                 or RX_RESENDEZ.search(texto)):
        return hits
    # nombres comunes ('paola hernandez' sin apellido completo): la
    # nota debe anclarse a Tabasco/TSJ o venir de prensa local — en
    # nacional/espectáculos casi seguro es homónimo
    hits = li["rx_fuertes_ctx"].findall(texto)
    if hits and (hay_tab or local or RX_TSJ.search(texto)):
        return hits
    # la nota es de OTRO poder judicial (TSJ de Guerrero, de la
    # Ciudad de México…) y no nombra Tabasco → no es de interés
    if RX_TSJ_OTRO.search(texto) and "tabasco" not in texto_ctx:
        return []
    # judicial de otro estado sin ancla TSJT (jueza de Zacatecas,
    # TEEY de Yucatán, poder judicial de Quintana Roo…) → fuera.
    # 'tabasco'/'villahermosa'/'resendez'/'tsj' en el texto la rescata
    if li["rx_ajenos"].search(texto) and not (
            hay_tab or RX_TSJ.search(texto)):
        return []
    if RX_TSJ.search(texto) and (local or hay_tab):
        return ["tsj"]
    hits = [t for t in li["debiles_tema"] if t in texto]
    hits += li["rx_siglas_t"].findall(texto)
    # temas ('fiscalización', 'reforma judicial') exigen ancla
    # Tabasco EN EL TEXTO — la prensa local también corre notas
    # federales (Senado/ASF/ANAM) y 'local' solo las colaba
    if hits and hay_tab:
        return hits
    hits = [t for t in li["debiles_actor"] if t in texto]
    if hits and (hay_tab or local):
        return hits
    return []


def vista_columnas(email: str) -> str:
    """Sección Columnas: una tarjeta desplegable por columna política
    (categoria 'columnas'). La entrega más reciente queda a la vista y
    el histórico se despliega — algunas publican cada 2-3 días."""
    cfg = json.loads(CONFIG.read_text())
    cols = [f for f in cfg["fuentes"]
            if f.get("categoria") == "columnas"]
    nombres = {f["nombre"] for f in cols}
    # selección del usuario SÍ filtra (objetivo: solo lo marcado), pero
    # con transparencia — cada tarjeta oculta se señala en vez de
    # quedar en '0 entregas' fantasma
    ocultas = set(perfil_usuario(email, cfg).get("fuentes_ocultas", []))
    n_sel = sum(1 for f in cols if f["nombre"] not in ocultas)
    por_col: dict = {}
    for n in _noticias_cache():
        clave = n.get("via") or n.get("fuente", "")
        if clave in nombres:
            por_col.setdefault(clave, []).append(n)

    def _fila(n: dict, col_nombre: str = "", paywall: bool = False) -> str:
        res = ""
        # columnas de título fijo ('Templo Mayor 2026-10-09') no dicen de
        # qué tratan — el resumen indexado da el adelanto
        if col_nombre and col_nombre.lower() in n["titulo"].lower() \
                and n.get("resumen"):
            res = (f"<span class='col-res'>"
                   f"{html.escape(n['resumen'][:160])}…</span>")
        pw = "<span class='col-pay'>suscripción</span>" if paywall else ""
        hits = ", ".join(_interes_match(n))
        kw = (f"<span style='font-size:.65rem;color:#2e7d32'>"
              f"encontró: {html.escape(hits)}</span>" if hits
              else "<span style='font-size:.62rem;color:#bbb;"
                   "border:1px solid #ddd;border-radius:8px;"
                   "padding:0 5px'>irrelevante</span>")
        return (f"<a class='col-fila' "
                f"href='/nota?u={quote(n['link'], safe='')}'"
                f"><span class='col-fecha'>{fmt_fecha(n['fecha'])}</span>"
                f"<span class='col-bloq'><span class='col-tit'>"
                f"{html.escape(n['titulo'])}</span>{res}{kw}</span>"
                f"{pw}</a>")

    bloques = []
    for f in cols:
        oculta = f["nombre"] in ocultas
        _vl = set()
        # TODAS las entregas de la columna — coincide_interes aquí
        # solo alimenta el chip 'encontró:'; filtrar vaciaba la
        # sección porque las columnas son opinión política nacional
        entradas = [] if oculta else [
            n for n in sorted(
                por_col.get(f["nombre"], []),
                key=lambda n: n["fecha"], reverse=True)
            if not (n["link"] in _vl or _vl.add(n["link"]))]
        ultima = fmt_fecha(entradas[0]["fecha"]) if entradas \
            else "sin capturas aún"
        medio = f["nombre"].split("·")[-1].strip()
        columna = f["nombre"].split("·")[0].strip()
        cab = (f"<summary><span class='col-nom'>{html.escape(columna)}"
               f"</span><span class='meta'>{html.escape(medio)} · "
               + ("fuente oculta en tu selección"
                  if oculta else
                  f"{len(entradas)} entregas · última {ultima}")
               + "</span></summary>")
        cuerpo = "".join(
            _fila(n, columna, f.get("paywall", False))
            for n in entradas[:40]) \
            or ("<p class='meta'>Oculta en tu selección — actívala en "
                "<a href='/fuentes'>Fuentes</a> para verla aquí.</p>"
                if oculta
                else "<p class='meta'>Aún no captura — esperando la "
                     "próxima entrega.</p>")
        bloques.append((entradas[0]["fecha"] if entradas else "",
                        f"<details class='col-card'>{cab}"
                        f"<div class='col-list'>{cuerpo}</div></details>"))
    bloques.sort(key=lambda b: b[0], reverse=True)
    cards = "".join(b for _, b in bloques)
    return (f"<h1>Columnas</h1><p class='meta'>{len(cols)} columnas "
            f"en seguimiento · {n_sel} en tu selección</p>" + cards)


def vista_destacadas(email: str, cat: str = "") -> str:
    cfg = json.loads(CONFIG.read_text())
    vis = fuentes_visibles(perfil_usuario(email, cfg), cfg)
    noticias = [n for n in _noticias_cache()
                if n["fuente"] in vis or n.get("via") in vis]
    if cat:
        noticias = [n for n in noticias if n.get("categoria") == cat]
    # recorta DESPUÉS de filtrar: con categoría chica el limite
    # anterior vaciaba el pool y no quedaba con qué clusterear
    destacadas = agrupar_noticias(noticias[-2000:])[:15]

    def tab(href, label, activo):
        return (f"<a class='tab-cat{' on' if activo else ''}' "
                f"href='{href}'>{label}</a>")

    tabs = ("<div class='tabs-cat'>"
            + tab("/destacadas", "Todas", not cat)
            + tab("/destacadas?cat=prensa", "Tabasco", cat == "prensa")
            + tab("/destacadas?cat=quintana_roo", "Península",
                  cat == "quintana_roo")
            + tab("/destacadas?cat=nacional", "Nacional",
                  cat == "nacional")
            + tab("/destacadas?cat=columnas", "Columnas",
                  cat == "columnas")
            + tab("/destacadas?cat=regional", "Regional",
                  cat == "regional") + "</div>")
    cards = "".join(tarjeta_destacada(rep, c) for rep, c in destacadas)
    return ("<h1>Lo más destacado</h1>" + tabs + cards if cards
            else "<h1>Lo más destacado</h1>" + tabs +
                 "<p>Aún no hay historias repetidas entre medios.</p>")


def tarjeta_grupo_alerta(regla: str, items: list, colores: dict,
                         relacionadas: list = None,
                         pals: str = "", creador: str = "",
                         propio: bool = True) -> str:
    """Una tarjeta por regla: badge + último titular + notas que dispararon
    + cobertura relacionada (mismo tema, sin match directo)."""
    relacionadas = relacionadas or []
    if len(items) == 1 and not relacionadas:
        return tarjeta_alerta(items[0], colores, pals, creador)
    cat = items[-1].get("categoria", "prensa")
    color = color_regla(regla, colores)
    ultima = max(items, key=lambda a: a["fecha"])["fecha"]

    def variante(n):
        return (f"<a class='variante meta' href='/nota?u={quote(n['link'], safe='')}'>"
                f"<span class='chip-fuente'>{html.escape(n['fuente'])}</span>{_ico_origen(n)} "
                f"{fmt_fecha(n['fecha'])} · {html.escape(n['titulo'][:95])}</a>")

    hits_html = "".join(variante(a) for a in
                        sorted(items, key=lambda a: a["fecha"], reverse=True))
    rel_html = ""
    if relacionadas:
        lista = "".join(variante(n) for n in
                        sorted(relacionadas, key=lambda a: a["fecha"],
                               reverse=True))
        rel_html = (
            f"<details><summary>Cobertura relacionada del tema "
            f"({len(relacionadas)}) ▾</summary>"
            f"<div class='meta' style='padding:.3rem 0'>"
            f"Mismo contexto, sin match directo de la regla:</div>{lista}</details>")

    reciente = max(items, key=lambda a: a["fecha"])
    ultima_img = next((a["imagen"] for a in
                       sorted(items, key=lambda a: a["fecha"], reverse=True)
                       if a.get("imagen")), "")
    return (
        f"<div class='card {html.escape(cat)}' style='border-left-color:{color}'>"
        + (f"<img class='thumb' src='{html.escape(url_https(ultima_img))}' loading='lazy' "
           f"onerror='this.remove()'>" if ultima_img else "")
        + badge_regla(regla, colores)
        + (f"<span class='chip-creador' "
           f"title='Creador de la regla'>{html.escape(creador)}"
           f"</span>" if creador else "")
        + (f"<span class='chip-pals' "
           f"title='Palabras de la regla'>{html.escape(pals)}</span>"
           if pals else "")
        + f"<span class='titulo'>{html.escape(reciente['titulo'])}</span>"
        + f"<div class='meta'>{len(items)} notas dispararon esta regla · "
        f"última: {fmt_fecha(ultima)}</div>"
        f"<details><summary>Ver las {len(items)} notas ▾</summary>{hits_html}</details>"
        f"{rel_html}"
        # rastrear solo en reglas propias — la de un compañero vive
        # en su perfil y no la puede rastrear quien no la creó
        + (f"<form method='post' action='/alertas/rastrear' "
           f"style='margin-top:.4rem'>"
           f"<input type='hidden' name='regla' "
           f"value='{html.escape(regla)}'>"
           f"<button class='btn-linea' style='font-size:.72rem;"
           f"padding:.2rem .6rem'>⌕ buscar más en el archivo de "
           f"los medios</button></form>" if propio else "")
        + "</div>"
    )


def cobertura_relacionada(items: list, noticias: list) -> list:
    """Notas del MISMO TEMA que no matchearon la regla: comparten algún
    token distintivo (palabra rara: aparece en <=5 notas) con los titulares
    que sí dispararon la alerta."""
    frecuencia = Counter()
    tokens_n = {}
    for n in noticias:
        t = tokens_titulo(n["titulo"])
        tokens_n[n["link"]] = t
        frecuencia.update(t)
    distintivos = {t for t, c in frecuencia.items() if c <= 5}

    links_hit = {a["link"] for a in items}
    tokens_hit = set()
    for a in items:
        tokens_hit |= tokens_titulo(a["titulo"])
    tema = tokens_hit & distintivos
    if not tema:
        return []
    if len(tema) == 1:
        # tema de una sola palabra: vale solo si está en TODOS los
        # titulares que dispararon — un raro compartido por azar
        # ('centro' = centro de votación, Centroamérica…) no basta
        for a in items:
            tema &= tokens_titulo(a["titulo"])
        if not tema:
            return []
        return [n for n in noticias
                if n["link"] not in links_hit
                and tema <= tokens_n[n["link"]]]
    # ≥2 tokens distintivos compartidos — uno solo es ruido
    return [n for n in noticias
            if n["link"] not in links_hit
            and len(tokens_n[n["link"]] & tema) >= 2]


# ── rastreo de archivo: jalar notas viejas desde el sitio del medio ──
_RASTREO = {}   # email → {"en_curso": bool, "encontradas": int, "regla": str}


def _base_sitio(url: str) -> str:
    """'https://sitio.com/feed/' → 'https://sitio.com' — base para el
    buscador ?s= propio del medio (WordPress y la mayoría de CMS)."""
    return re.sub(r"/(feed/?|rss/?|atom/?|feed/atom/?|wp-json/?)$",
                  "", url.rstrip("/"))


def _fecha_archivo(txt: str, url: str) -> str:
    """Fecha de la nota: meta published_time → <time datetime> →
    /YYYY/MM/DD/ en la URL. Devuelve ISO sortable o ''."""
    f = (_meta(txt, "article:published_time")
         or _meta(txt, "datePublished")
         or _meta(txt, "date"))
    if not f:
        m = re.search(r'<time[^>]+datetime=["\']([^"\']+)', txt, re.I)
        f = m.group(1) if m else ""
    if not f:
        m = re.search(r"/(20\d{2})/(\d{2})/(\d{2})/", url)
        f = f"{m.group(1)}-{m.group(2)}-{m.group(3)}" if m else ""
    try:
        return datetime.fromisoformat(
            f.replace("Z", "+00:00")).strftime("%Y-%m-%dT%H:%M:%S")
    except Exception:
        m = re.match(r"(20\d{2}-\d{2}-\d{2})", f)
        return f"{m.group(1)}T00:00:00" if m else ""


def _fecha_real_pagina(url: str) -> str:
    """Baja la página y devuelve la fecha REAL de publicación
    (meta published_time → <time> → /YYYY/MM/DD/). Google News
    re-emite notas viejas con la fecha en que las re-indexó, no
    la de publicación — esta verificación descubre esas
    recirculaciones. Devuelve '' si no se pudo comprobar."""
    try:
        r = requests.get(url, timeout=(4, 8), stream=True,
                         headers={"User-Agent": "Mozilla/5.0"})
        r.raise_for_status()
        trozos, total = [], 0
        for chunk in r.iter_content(65536, decode_unicode=False):
            trozos.append(chunk)
            total += len(chunk)
            if total >= 900_000:   # los meta de fecha viven en <head>
                break
        r.close()
        return _fecha_archivo(
            b"".join(trozos).decode("utf-8", "ignore"), url)
    except Exception:
        return ""


def _nota_archivo(url: str, f: dict) -> dict:
    """Descarga la nota EN EL SITIO DEL MEDIO y extrae titulo/resumen/
    imagen/fecha de sus meta tags — nada de Google."""
    try:
        r = requests.get(url, timeout=12,
                         headers={"User-Agent": "Mozilla/5.0"})
        if r.status_code != 200 or len(r.text) < 500:
            return {}
    except Exception:
        return {}
    titulo = _meta(r.text, "og:title") or _meta(r.text, "twitter:title")
    if not titulo:
        m = re.search(r"<title[^>]*>(.*?)</title>", r.text, re.S | re.I)
        titulo = m.group(1) if m else ""
    titulo = html.unescape(re.sub(r"<[^>]+>", "", titulo)).strip()
    # sufijo editorial: 'Titular - Tabasco HOY' → queda solo el titular
    titulo = re.sub(r"\s*[—–\-|]\s*" + re.escape(f["nombre"]) +
                    r"\s*$", "", titulo, flags=re.I)
    if len(titulo) < 20:
        return {}
    resumen = _meta(r.text, "og:description") or \
        _meta(r.text, "description")
    resumen = re.sub(r"<[^>]+>", "",
                     html.unescape(resumen)).strip()[:500]
    fecha = _fecha_archivo(r.text, url)
    if not fecha:
        return {}
    return {"titulo": titulo, "link": url, "resumen": resumen,
            "fecha": fecha, "fuente": f["nombre"],
            "categoria": f.get("categoria", "prensa"),
            "imagen": _meta(r.text, "og:image"), "autor": "",
            "via": "archivo"}


def _candidatos_busqueda(f: dict, termino: str, limite: int = 12) -> list:
    """Resultados del buscador DEL PROPIO MEDIO. Primero la API WP
    (/wp-json/wp/v2/search — JSON confiable en sitios WordPress); si
    no existe, el ?s= clásico con extracción de enlaces."""
    base = _base_sitio(f["url"])
    if not base.startswith("http"):
        return []
    dom = urlparse(base).netloc
    # ── WP REST search — la vía limpia ──
    try:
        r = requests.get(f"{base}/wp-json/wp/v2/search",
                         params={"search": termino, "per_page": 20},
                         timeout=12,
                         headers={"User-Agent": "Mozilla/5.0"})
        if (r.status_code == 200
                and r.headers.get("Content-Type", "").startswith(
                    "application/json")):
            urls = []
            for h in r.json():
                u = h.get("url", "").split("#")[0]
                if urlparse(u).netloc.removeprefix("www.") == \
                        dom.removeprefix("www.") and u not in urls \
                        and h.get("type") in ("post", "page", ""):
                    urls.append(u)
            if urls:
                return urls[:limite]
    except Exception:
        pass
    # ── fallback: ?s= HTML genérico ──
    try:
        r = requests.get(f"{base}/?s={quote(termino)}", timeout=12,
                         headers={"User-Agent": "Mozilla/5.0"})
        if r.status_code != 200:
            return []
    except Exception:
        return []
    out, vistos = [], set()
    for m in re.finditer(
            r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>(.*?)</a>',
            r.text, re.S | re.I):
        u = html.unescape(m.group(1)).split("#")[0]
        txt = re.sub(r"\s+", " ", html.unescape(
            re.sub(r"<[^>]+>", " ", m.group(2)))).strip()
        if (urlparse(u).netloc.removeprefix("www.") ==
                dom.removeprefix("www.") and u not in vistos
                and 35 < len(txt) < 170
                and not re.search(
                    r"/(categor|tag|author|feed|wp-content|wp-includes"
                    r"|page/|comment|search|tag/|\.xml)|\.(jpg|jpeg|png"
                    r"|gif|css|js|svg|webp)(\?|$)", u, re.I)):
            vistos.add(u)
            out.append(u)
            if len(out) >= limite:
                break
    return out


def rastrear_archivo(email: str, regla_nom: str, cfg: dict):
    """Hilo: por cada fuente consulta SU buscador con los términos de
    la regla, descarga cada candidato del sitio original y guarda en
    NOTICIAS + ALERTAS las que de verdad cumplen la regla (sin correo
    ni notify — es archivo, no noticia fresca)."""
    st = _RASTREO[email]
    try:
        perfil = perfil_usuario(email, cfg)
        regla = next((r for r in perfil.get("reglas", [])
                      if r["nombre"] == regla_nom), {})
        pals = regla.get("requiere_todas", [])
        if not pals:
            return
        termino = " ".join(p.split("/")[0] for p in pals)
        conocidos = {n["link"] for n in _noticias_cache()}
        for f in cfg.get("fuentes", []):
            if st.get("estado") == "cancelado":
                break
            for u in _candidatos_busqueda(f, termino):
                if u in conocidos or st.get("estado") == "cancelado":
                    continue
                conocidos.add(u)
                nota = _nota_archivo(u, f)
                if not nota:
                    continue
                t = normalizar(f"{nota['titulo']} "
                               f"{nota.get('resumen','')}")
                if not coincide(t, regla):
                    continue
                guardar_noticia(nota)
                a = dict(nota)
                a["reglas"] = regla_nom
                a["usuario"] = email
                with ALERTAS.open("a") as fh:
                    fh.write(json.dumps(a, ensure_ascii=False) + "\n")
                st["encontradas"] += 1
        st["estado"] = "listo"
    except Exception as e:
        print(f"[rastreo] {email}: {e}")
        st["estado"] = "error"
    finally:
        st["en_curso"] = False


def vista_alertas(email: str, msg: str = "") -> str:
    """Alertas agrupadas por regla: cada regla = un cluster con todas sus notas.
    Muestra las alertas DEL USUARIO (usuario=email) + las globales (sin
    usuario). Solo reglas que SIGUEN activas en su perfil (borrar una
    regla esconde su historial; sigue en el archivo para /exportar).
    La supervisión de todos los usuarios va en /analitica, no aquí."""
    cfg = json.loads(CONFIG.read_text())
    perfil = perfil_usuario(email, cfg)
    usuarios_all = cargar_usuarios()
    superv = es_supervisor(email, cfg)
    mis_proys = set(proyectos_usuario(email))
    # alcance POR REGLA: cada regla lleva 'proyecto' — vacío = personal
    # (solo la ve su dueño); con proyecto = la ven los miembros de ese
    # equipo; supervisor/admin lo ve todo y con su creador
    reglas_vis = {}
    for d, u in usuarios_all.items():
        for r in u.get("reglas", []):
            if (superv or d == email
                    or (r.get("proyecto") or "") in mis_proys):
                reglas_vis[(r["nombre"], d)] = r
    # alertas sin regla ('Autor seguido', 'Noticia en desarrollo') son
    # personales — solo el dueño y supervisores las ven
    dueños_esp = set(usuarios_all) if superv else {email}
    reglas = perfil.get("reglas", [])
    colores = {r["nombre"]: r.get("color", "")
               for r in reglas_vis.values()}

    def _revalida(a: dict, r: dict) -> bool:
        """La regla pudo editarse ('efrain/resendez' OR → 'efrain' Y
        'resendez'): el match guardado en ALERTAS solo vale si sigue
        cumpliendo la forma actual de la regla."""
        t_a = normalizar(f"{a.get('titulo','')} {a.get('resumen','')} "
                         f"{a.get('autor','')}")
        pals = [[normalizar(v) for v in p.split("/")]
                for p in r.get("requiere_todas", [])]
        min_h = len(pals) if len(pals) <= 2 else len(pals) - 1
        return bool(pals) and sum(
            1 for p in pals
            if any(termino_en(v, t_a) for v in p)) >= min_h

    alertas = []
    for a in leer_jsonl(ALERTAS):
        dueño = a.get("usuario", "")
        base = a["reglas"].split(" (")[0]
        r_obj = reglas_vis.get((base, dueño or email))
        if r_obj:
            # la alerta es visible si SU regla es visible para mí
            if _revalida(a, r_obj):
                alertas.append((a, dueño))
        elif base.startswith("Autor seguido"):
            if not dueño or dueño in dueños_esp:
                alertas.append((a, dueño))
        elif base.startswith("Noticia en desarrollo"):
            # solo entra si la historia en sí matchea alguna regla activa
            if (not dueño or dueño in dueños_esp) and \
                    any(coincide(a["titulo"], r) for r in reglas):
                alertas.append((a, dueño))

    grupos = {}
    for a, dueño in alertas:
        # 'Noticia en desarrollo (0→5 medios)' -> agrupa por 'Noticia en desarrollo';
        # la tupla (regla, dueño) separa reglas homónimas de distintos usuarios
        grupos.setdefault((a["reglas"].split(" (")[0], dueño), []).append(a)
    vis = fuentes_visibles(perfil, cfg)
    noticias = [n for n in _noticias_cache() if n["fuente"] in vis or n.get("via") in vis]
    # coincidencias retroactivas: notas del archivo que cumplen la regla
    # pero nunca dispararon (publicadas antes de crearla, o resumen
    # que llegó después) — la tarjeta muestra la cobertura real
    regs = []
    for (nom, d), r in reglas_vis.items():
        pals = [[normalizar(v) for v in p.split("/")]
                for p in r.get("requiere_todas", [])]
        if pals:
            regs.append((nom, d, pals,
                         len(pals) if len(pals) <= 2
                         else len(pals) - 1))
    if regs:
        links_g = {(nom, d): {a["link"] for a in grupos.get((nom, d), [])}
                   for nom, d, _, _ in regs}
        for n in noticias:
            t = normalizar(f"{n['titulo']} {n.get('resumen','')} "
                           f"{n.get('autor','')}")
            for nombre, d, pals, min_h in regs:
                if (n["link"] not in links_g[(nombre, d)]
                        and coincide_interes(n)
                        and sum(1 for p in pals
                                if any(termino_en(v, t) for v in p))
                        >= min_h):
                    a = dict(n)
                    a["reglas"] = nombre
                    grupos.setdefault((nombre, d), []).append(a)
                    links_g[(nombre, d)].add(n["link"])
    ordenadas = sorted(
        grupos.items(),
        key=lambda kv: max(a["fecha"] for a in kv[1]),
        reverse=True,
    )
    boton = ("<p><a href='/config'><button class='btn-linea'>"
             "Personalizar alertas</button></a></p>")
    # palabras de cada regla (por dueño), para mostrarlas junto al badge
    pals_regla = {(nom, d): " + ".join(r.get("requiere_todas", []))
                  for (nom, d), r in reglas_vis.items()}

    def _creador(d: str) -> str:
        """Chip '· por fulano' — visible siempre para supervisor/admin
        (Paolo ve quién creó qué alerta) y en reglas ajenas del proyecto."""
        if d and (superv or d != email):
            return d.split("@")[0]
        return ""

    cards = "".join(
        tarjeta_grupo_alerta(regla, items, colores,
                             cobertura_relacionada(items, noticias),
                             pals_regla.get((regla, dueño), ""),
                             _creador(dueño),
                             dueño in ("", email))
        for (regla, dueño), items in ordenadas
    )
    # regla activa sin coincidencias: tarjeta en 0 — el usuario ve
    # que está guardada y vigilando, no que se perdió
    cards += "".join(
        f"<div class='card' style='border-left-color:"
        f"{color_regla(nom, colores)};opacity:.75'>"
        f"{badge_regla(nom, colores)}"
        + (f"<span class='chip-creador' title='Creador de la regla'>"
           f"{html.escape(d.split('@')[0])}</span>" if d and
           (superv or d != email) else "")
        + f"<span class='chip-pals' title='Palabras de la regla'>"
        f"{html.escape(pals_regla.get((nom, d), ''))}</span>"
        f"<span class='meta'>0 notas — vigilando: te avisará apenas "
        "salga una que cumpla todas las palabras.</span>"
        + (f"<form method='post' action='/alertas/rastrear' "
           f"style='margin-top:.4rem'>"
           f"<input type='hidden' name='regla' value='{html.escape(nom)}'>"
           f"<button class='btn-linea' style='font-size:.72rem;"
           f"padding:.2rem .6rem'>⌕ buscar en el archivo de "
           f"los medios</button></form>" if d == email else "")
        + "</div>"
        for (nom, d) in reglas_vis
        if (nom, d) not in grupos)
    # rastreo del archivo en curso: aviso + auto-reload
    rast = _RASTREO.get(email, {})
    if rast.get("en_curso"):
        banner_r = (
            "<div class='card' style='border-left-color:#1a237e'>"
            "<b>⏳ Rastreando los sitios de los medios…</b> "
            "<span class='meta'>la página se recarga sola cada 20 s "
            "— las notas encontradas van cayendo abajo.</span></div>"
            "<script>setTimeout(function(){location.reload()},"
            "20000)</script>")
    elif rast.get("estado") == "listo":
        banner_r = (
            "<div class='card' style='border-left-color:#2e7d32'>"
            f"<b>Rastreo terminado</b> — {rast.get('encontradas', 0)} "
            f"nota(s) del archivo se sumaron a "
            f"«{html.escape(rast.get('regla', ''))}».</div>")
        _RASTREO.pop(email, None)   # el aviso se muestra una vez
    elif rast.get("estado") == "error":
        banner_r = ("<div class='card' style='border-left-color:#b71c1c'>"
                    "<b>El rastreo falló</b> — reintenta en unos "
                    "minutos.</div>")
        _RASTREO.pop(email, None)
    else:
        banner_r = ""
    banner = banner_r
    if msg.isdigit():
        n = int(msg)
        banner = ("<div class='card' style='border-left-color:#2e7d32'>"
                  f"<b>Regla guardada</b> — {n} nota(s) del archivo ya "
                  "coinciden.</div>" if n else
                  "<div class='card' style='border-left-color:#2e7d32'>"
                  "<b>Regla guardada.</b> El archivo no trajo coincidencias "
                  "— te avisará apenas salga una nota que cumpla todas "
                  "las palabras.</div>")
    return (("<h1>Alertas</h1>" + banner + boton + cards) if cards
            else "<h1>Alertas</h1>" + banner + boton +
                 "<p>Sin alertas todavía. Crea reglas en Personalizar alertas.</p>")


def trending_chips(noticias: list) -> str:
    """Devuelve un string con chips <a> de los temas más repetidos."""
    STOPWORDS = {
        "para", "como", "pero", "puede", "pueden", "cuando", "donde", "quien",
        "quienes", "cuyo", "cuya", "sobre", "entre", "bajo", "ante", "tras",
        "desde", "hasta", "durante", "hacia", "segun", "mientras", "ademas",
        "tambien", "mismo", "misma", "mismos", "mismas", "tanto", "tanta",
        "parte", "partes", "año", "años", "ano", "anos", "mes", "meses",
        "dias", "dia", "nacional", "gobierno", "estado", "estados", "pais",
        "mexico", "mundo", "contra",
        "hora", "horas", "ayer", "hoy", "mañana", "manana", "aqui", "alla",
        "fue", "sera", "seran", "estan", "estaran", "habra", "hace", "hacia",
        "dijo", "dice", "dieron", "señala", "señalo", "indica", "indico",
        "afirma", "asegura", "pesar", "pese", "luego", "ahora", "antes",
        "despues", "cabe", "gran", "mayor", "menor", "nuevo", "nueva",
        "nuevos", "nuevas", "hizo", "hace", "del", "los", "las", "por",
        "con", "una", "mas", "sus", "sin", "son", "han", "sido", "tres",
        "dos", "cada", "tras", "sino", "solo", "solamente", "tan", "muy",
        "mas", "menos", "bien", "mal", "tal", "tales", "otro", "otra",
        "otros", "otras", "este", "esta", "estos", "estas", "ese", "esa",
        "esos", "esas", "aquel", "aquella", "aun", "aunque", "debido",
        "debida", "pues", "porque", "ya", "todavia", "aun", "sigue",
        "sigue", "caso", "casos", "hecho", "hechos", "informo", "informa",
        "segun", "tipo", "tipos", "forma", "formas", "manera", "maneras",
    }

    def palabras(titulo):
        return [w for w in re.findall(r"[a-zñ]+", normalizar(titulo))
                if len(w) > 3 and w not in STOPWORDS]

    bigrams = Counter()
    for n in sorted(noticias, key=lambda n: n["fecha"], reverse=True)[:150]:
        words = palabras(n["titulo"])
        bigrams.update({f"{w1} {w2}"
                        for w1, w2 in zip(words, words[1:])
                        if w1 != w2})
    top = bigrams.most_common(6)
    return "".join(
        f"<a class='chip-trend' href='/buscar?q={quote(tema, safe='')}'>"
        f"{html.escape(tema.title())}</a>"
        for tema, _ in top)


def vista_noticias(email: str, pagina: int = 1, dia: str = "") -> str:
    cfg = json.loads(CONFIG.read_text())
    vis = fuentes_visibles(perfil_usuario(email, cfg), cfg)
    noticias = [n for n in _noticias_cache()
                if (n["fuente"] in vis or n.get("via") in vis)
                and (dia or n.get("categoria")
                     not in ("columnas", "x", "seguimiento"))
                and (not dia or n["fecha"].startswith(dia))]
    ordenadas = sorted(noticias, key=lambda n: n["fecha"], reverse=True)
    chips = trending_chips(noticias)
    trending = f"<div class='trending'>{chips}</div>" if chips else ""
    total = len(noticias)
    por_pagina = 100
    total_paginas = max(1, (total + por_pagina - 1) // por_pagina)
    pagina = max(1, min(pagina, total_paginas))
    inicio = (pagina - 1) * por_pagina
    fin = min(inicio + por_pagina, total)
    notas_pag = ordenadas[inicio:fin]
    cards = "".join(tarjeta_noticia(n) for n in notas_pag)
    info = f"{inicio + 1}-{fin} de {total}"
    nav = ""
    if total_paginas > 1:
        dia_q = f"&dia={dia}" if dia else ""
        ant = (f"<a href='/noticias?p={pagina - 1}{dia_q}'>← Anterior</a>"
               if pagina > 1 else "<span>← Anterior</span>")
        sig = (f"<a href='/noticias?p={pagina + 1}{dia_q}'>Siguiente →</a>"
               if pagina < total_paginas else "<span>Siguiente →</span>")
        nav = (f"<div class='paginacion'>{ant} "
               f"<span class='pag-info'>{info}</span> {sig}</div>")
    tit = (f"Noticias del {dia}"
           if dia else "Últimas noticias")
    return (f"<h1>{tit}</h1>"
            f"<p class='meta'>{info} notas</p>"
            f"{trending}{nav}{cards}{nav}" if cards
            else f"<h1>{tit}</h1><p>Sin noticias todavía.</p>")


def vista_x(email: str) -> str:
    """Tab X: posts de cuentas seguidas (categoria 'x', fuentes tipo
    'x' vía espejos Nitter). Feed cronológico sin clustering — son
    posts, no cobertura."""
    cfg = json.loads(CONFIG.read_text())
    vis = fuentes_visibles(perfil_usuario(email, cfg), cfg)
    # REGLA MADRE: el tab X es radar de Reséndez/TSJ — el feed general
    # sigue en /noticias; aquí solo posts de interés judicial
    posts = sorted((n for n in _noticias_cache()
                    if (n["fuente"] in vis or n.get("via") in vis)
                    and n.get("categoria") == "x"
                    and coincide_interes(n)),
                   key=lambda n: n["fecha"], reverse=True)
    # el feed 'Siguiendo' trae ~1200 cuentas (de todo): el tab solo
    # muestra autores aprobados — el resto igual se ingirió y ya pasó
    # por alertas/Interés
    permitidos = {h.lower().lstrip("@") for h in
                  cfg.get("x_permitidos", [])}
    posts = [n for n in posts
             if not n["fuente"].startswith("@")
             or n["fuente"][1:].lower() in permitidos]

    # 'Lo más comentado': clustering del radar de interés (los ~1,100
    # follows filtrados por coincide_interes) — mismo tema judicial
    # repetido en varias cuentas = de qué se habla hoy en el TSJT
    h24 = (datetime.now() - timedelta(hours=24)).isoformat()
    radar = [n for n in _noticias_cache()
             if n.get("categoria") == "x" and n.get("fecha", "") > h24
             and coincide_interes(n)]
    clusters = []
    for rep, c in agrupar_noticias(radar, ventana_dias=1):
        if len(c) < 2:
            continue
        # copypasta bot: ≥4 posts y casi todo el texto idéntico entre
        # cuentas distintas — campaña coordinada, no conversación
        # (X los banea rápido: por eso el link ya no muestra nada)
        textos = {normalizar(n["titulo"])[:120] for n in c}
        if len(c) >= 4 and len(textos) <= 2:
            continue
        # ancla local: toca la lista de interés, menciona Tabasco, o
        # lo publica una cuenta local SIN que el tema sea de otro
        # estado — XEVT republicando notas de Manzanillo/Colima no
        # vuelve relevante el tema por ser un medio tabasqueño
        def _ancla(n):
            txt = normalizar(n["titulo"] + " " + (n.get("resumen") or ""))
            return (coincide_interes(n)
                    or any(g in txt for g in ("tabasco", "villahermosa"))
                    or (n["fuente"].lower().lstrip("@") in permitidos
                        and not _interes_listas()["rx_ajenos"].search(
                            txt)))
        if not any(_ancla(n) for n in c):
            continue
        clusters.append((rep, c))

    def _run_comun(a: str, b: str) -> int:
        """Palabras del run contiguo común más largo entre dos
        titulares — mide si hablan del mismo asunto con distinto
        actor/hashtag."""
        ta, tb = a.split(), b.lower()
        for L in range(min(len(ta), 20), 3, -1):
            for i in range(len(ta) - L + 1):
                if " ".join(ta[i:i + L]).lower() in tb:
                    return L
        return 0

    # fusión: dos clusters cuyos representantes comparten un run largo
    # son EL MISMO tema partido por hashtag/nombre distinto
    # (#EntérateTH vs #Rumboal2027 — ambos 'registro p/Coordinación')
    fus = []
    for rep, c in clusters:
        for j, (r2, c2) in enumerate(fus):
            if _run_comun(rep["titulo"], r2["titulo"]) >= 6:
                fus[j] = (r2 if len(r2["titulo"]) >= len(rep["titulo"])
                          else rep, c2 + c)
                break
        else:
            fus.append((rep, c))
    clusters = fus[:12]

    def _tema_cluster(c: list) -> str:
        """Etiqueta del tema: la frase contigua más larga presente en
        TODOS los posts del cluster — no el titular de un solo post
        ('José Del Carmen anunció registro' esconde que el tema real es
        'registros para la Coordinación Municipal')."""
        if len(c) < 2:
            return c[0]["titulo"]
        toks = [n["titulo"].split() for n in c]
        # el titular más largo como base del n-grama — no el primero
        base, otros = max(toks, key=len), [
            " ".join(t).lower() for t in toks]
        mejor = ""
        # n-grama común más largo (4+ palabras), de mayor a menor
        for L in range(min(len(base), 15), 3, -1):
            for i in range(len(base) - L + 1):
                g = " ".join(base[i:i + L]).lower()
                if len(g) > len(mejor) and all(
                        g in o for o in otros):
                    mejor = " ".join(base[i:i + L])
            if mejor:
                break
        # hashtag común a todos como prefijo del tema
        ht = [t for t in set(base) if t.startswith("#")
              and all(t.lower() in o for o in otros)]
        etiqueta = mejor or c[0]["titulo"]
        if ht and ht[0].lower() not in mejor.lower():
            etiqueta = f"{ht[0]} {etiqueta}"
        return etiqueta[:130]
    trend = ""
    if clusters:
        filas = "".join(
            f"<details class='card' style='border-left-color:#1da1f2'>"
            f"<summary><b>{len(c)} posts</b> · "
            f"{html.escape(_tema_cluster(c))} · "
            f"<span class='meta'>{', '.join(sorted({n['fuente'] for n in c}))}</span>"
            f"</summary>"
            + "".join(
                f"<p style='margin:.4rem 0 .4rem 1rem'>"
                f"<a href='/nota?u={quote(n['link'], safe='')}'>"
                f"{html.escape(n['titulo'][:140])}</a> "
                f"<span class='meta'>{n['fuente']} · "
                f"{fmt_fecha(n['fecha'])}</span></p>"
                for n in sorted(c, key=lambda n: n['fecha'],
                                reverse=True))
            + "</details>"
            for rep, c in clusters)
        trend = (f"<h2 style='margin:1rem 0 .4rem'>Lo más comentado "
                 f"en tu red · 24 h</h2>{filas}")

    cards = "".join(tarjeta_noticia(n) for n in posts)
    return (f"<h1>X</h1><p class='meta'>{len(posts)} posts</p>"
            f"{trend}<h2 style='margin:1rem 0 .4rem'>Cronológico</h2>{cards}"
            if cards
            else "<h1>X</h1><p class='meta'>Aún no hay posts capturados "
                 "— agrega cuentas en Fuentes con tipo 'x' (x:handle). "
                 "</p>")


def vista_telegram(email: str) -> str:
    """Tab Telegram: RADAR de menciones — solo posts que tocan al
    magistrado/TSJ, vengan del canal que vengan (local o foráneo).
    El contenido general del canal no interesa; el sistema es un
    monitor de Efraín Reséndez (regla del usuario 22/oct)."""
    cfg = json.loads(CONFIG.read_text())
    vis = fuentes_visibles(perfil_usuario(email, cfg), cfg)
    tg = {f["nombre"] for f in cfg.get("fuentes", [])
          if f.get("tipo") == "telegram"}
    posts = sorted(
        (n for n in _noticias_cache()
         if (n["fuente"] in tg or n.get("via") in tg
             or "t.me/" in (n.get("link") or ""))
         and (n["fuente"] in vis or n.get("via") in vis
              or "t.me/" in (n.get("link") or ""))
         and RX_RESENDEZ.search(
             normalizar((n["titulo"] or "")
                        + " " + (n.get("resumen") or "")))),
        key=lambda n: n["fecha"], reverse=True)[:200]
    if not posts:
        return ("<h1>Telegram</h1><p class='meta'>Sin menciones del "
                "magistrado/TSJ en los canales rastreados — el radar "
                "solo muestra posts que lo tocan, no el feed del "
                "canal.</p>")
    por_canal = {}
    for n in posts:
        por_canal.setdefault(n["fuente"], []).append(n)
    resumen = " · ".join(f"{html.escape(k)} ({len(v)})"
                         for k, v in sorted(
                             por_canal.items(),
                             key=lambda kv: -len(kv[1])))
    cards = "".join(tarjeta_noticia(n) for n in posts)
    return (f"<h1>Telegram</h1><p class='meta'>{len(posts)} posts · "
            f"{len(por_canal)} canales</p>"
            f"<p class='meta'>{resumen}</p>"
            f"<h2 style='margin:1rem 0 .4rem'>Cronológico</h2>{cards}")


def vista_interes(email: str, pagina: int = 1) -> str:
    """Sección Interés: notas (Tabasco o nacional) que tocan los temas
    y nombres de la lista judicial — coincide_interes hace el filtro
    de dos niveles."""
    cfg = json.loads(CONFIG.read_text())
    vis = fuentes_visibles(perfil_usuario(email, cfg), cfg)
    noticias = [n for n in _noticias_cache()
                if (n["fuente"] in vis or n.get("via") in vis)
                and coincide_interes(n)]
    # misma historia en varios medios → UNA tarjeta-grupo (mosaico +
    # dropdown); umbral más laxo que el global: la prensa local
    # reescribe mucho el mismo titular. La tarjeta toma la posición
    # de la nota más reciente del cluster
    ordenadas = sorted(noticias, key=lambda n: n["fecha"], reverse=True)
    clusters = _fusionar_temas(
        ordenadas, agrupar_noticias(ordenadas, umbral=0.32))
    en_grupo = {}
    for gi, cluster in enumerate(clusters):
        for n in cluster:
            en_grupo[n["link"]] = gi
    emitidos = set()
    planos = []
    for n in ordenadas:
        gi = en_grupo.get(n["link"])
        if gi is not None:
            if gi in emitidos:
                continue
            emitidos.add(gi)
            planos.append(tarjeta_grupo(clusters[gi]))
        else:
            planos.append(tarjeta_noticia(
                n, "encontró: " + ", ".join(_interes_match(n))))
    total = len(planos)
    por_pagina = 100
    total_paginas = max(1, (total + por_pagina - 1) // por_pagina)
    pagina = max(1, min(pagina, total_paginas))
    inicio = (pagina - 1) * por_pagina
    fin = min(inicio + por_pagina, total)
    cards = "".join(planos[inicio:fin])
    info = f"{inicio + 1}-{fin} de {total}" if total else "0"
    nav = ""
    if total_paginas > 1:
        ant = (f"<a href='/interes?p={pagina - 1}'>← Anterior</a>"
               if pagina > 1 else "<span>← Anterior</span>")
        sig = (f"<a href='/interes?p={pagina + 1}'>Siguiente →</a>"
               if pagina < total_paginas else "<span>Siguiente →</span>")
        nav = (f"<div class='paginacion'>{ant} "
               f"<span class='pag-info'>{info}</span> {sig}</div>")
    # panel admin: catálogo editable de palabras de interés —
    # colapsable; × quita (base→lista 'quitar_', extra→se borra) y el
    # input agrega; efecto inmediato vía cache-mtime
    panel = ""
    if es_admin(email, cfg):
        li = _interes_listas()
        grupos = [("fuertes", "Fuertes — bastan solos"),
                  ("siglas_fuertes", "Siglas fuertes"),
                  ("debiles_actor", "Actores — prensa local"),
                  ("debiles_tema", "Temas — requieren ancla Tabasco"),
                  ("siglas_tema", "Siglas tema"),
                  ("tabasco", "Ancla geográfica"),
                  ("ajenos", "Otros estados — excluyen")]
        bloques = ""
        for clave, titulo in grupos:
            chips_w = "".join(
                f"<form method='post' action='/interes/palabras' "
                f"style='display:inline'>"
                f"<input type='hidden' name='lista' value='{clave}'>"
                f"<input type='hidden' name='accion' value='quitar'>"
                f"<button name='termino' "
                f"value='{html.escape(t, quote=True)}' "
                f"class='chip-fuente' style='cursor:pointer;margin:2px' "
                f"title='quitar'>{html.escape(t)} ×</button></form>"
                for t in li[clave])
            bloques += (
                f"<p class='meta' style='margin:.6rem 0 .2rem'>"
                f"<b>{titulo}</b></p><div>{chips_w}"
                f"<form method='post' action='/interes/palabras' "
                f"style='display:inline;margin-left:.3rem'>"
                f"<input type='hidden' name='lista' value='{clave}'>"
                f"<input type='hidden' name='accion' value='agregar'>"
                f"<input name='termino' placeholder='agregar…' "
                f"style='font-size:.75rem;width:150px;padding:2px 6px'>"
                f"<button style='font-size:.75rem'>＋</button>"
                f"</form></div>")
        panel = (
            f"<details style='margin-bottom:1rem'>"
            f"<summary class='btn-linea' style='display:inline-block;"
            f"cursor:pointer'>Palabras de interés — administrar</summary>"
            f"<div class='card' style='margin-top:.5rem'>{bloques}"
            f"<p class='meta'>clic en una palabra la quita · los cambios "
            f"aplican al instante</p></div></details>")
    return (f"<h1>Notas de interés</h1>"
            f"<p class='meta'>{info} notas · poder judicial y "
            "actores del TSJ Tabasco</p>" + panel
            + f"{nav}{cards}{nav}" if cards
            else "<h1>Notas de interés</h1>" + panel +
                 "<p>Aún no cae ninguna nota de la lista.</p>")


def vista_seguimiento(email: str, pagina: int = 1) -> str:
    """Seguimiento: radar de perfiles personales de FB
    (categoria 'seguimiento') — cronológico plano, con filtro duro
    en el scraper (compartidos/bio-cards no entran). Sin filtro de
    interés en la vista: sección en prueba solo para admin — el
    filtro llegó a esconder publicaciones correctas. No pasa por
    fuentes_visibles: es una sección propia, no el feed."""
    noticias = [n for n in _noticias_cache()
                if n.get("categoria") == "seguimiento"]
    ordenadas = sorted(noticias, key=lambda n: n["fecha"],
                       reverse=True)
    total = len(ordenadas)
    por_pagina = 100
    total_paginas = max(1, (total + por_pagina - 1) // por_pagina)
    pagina = max(1, min(pagina, total_paginas))
    inicio = (pagina - 1) * por_pagina
    fin = min(inicio + por_pagina, total)
    cards = "".join(tarjeta_noticia(n)
                    for n in ordenadas[inicio:fin])
    info = f"{inicio + 1}-{fin} de {total}" if total else "0"
    nav = ""
    if total_paginas > 1:
        ant = (f"<a href='/seguimiento?p={pagina - 1}'>← Anterior</a>"
               if pagina > 1 else "<span>← Anterior</span>")
        sig = (f"<a href='/seguimiento?p={pagina + 1}'>Siguiente →</a>"
               if pagina < total_paginas
               else "<span>Siguiente →</span>")
        nav = (f"<div class='paginacion'>{ant} "
               f"<span class='pag-info'>{info}</span> {sig}</div>")
    return (f"<h1>Seguimiento</h1>"
            f"<p class='meta'>{info} posts · perfiles personales de "
            "FB bajo radar — solo lo que pasa el filtro de "
            "interés</p>"
            f"{nav}{cards}{nav}" if cards
            else "<h1>Seguimiento</h1><p class='meta'>Aún no hay "
                 "posts — chucky raspa los perfiles cada 4 h.</p>")


def _chip_nota(n: dict) -> tuple:
    """(badge_fuente, enlace_nota) por separado — el badge abre el
    bullet y 'nota →' cierra como invitación al lector; el sitio
    original solo se alcanza desde dentro de /nota."""
    if not n or not n.get("u"):
        return "", ""
    t = html.escape(n.get("t", ""), quote=True)
    fnt = html.escape(n.get("f", ""))
    badge = (f"<span class='chip-fuente' title='{t}'"
             f" style='font-size:.6rem;padding:1px 6px;"
             f"margin-right:.35rem'>{fnt}</span>")
    link = (f" <a href='/nota?u={quote(n['u'], safe='')}' title='{t}'"
            f" style='font-size:.7rem;font-weight:600;color:#b03a2e;"
            f"background:#fdecea;border:1px solid #f0b8b3;"
            f"border-radius:10px;padding:1px 8px;text-decoration:none;"
            f"white-space:nowrap'>nota&nbsp;→</a>"
            # el URL real va oculto en pantalla pero APARECE al
            # imprimir/exportar a PDF (reporte de entrega, 20/oct)
            f"<span class='url-print' style='display:none'>"
            f"{html.escape(n['u'])}</span>")
    return badge, link


def _link_nota(bullet: str, notas_ref: list) -> str:
    """Chip ↗ con la fuente si el bullet coincide (Jaccard ≥0.35) con
    alguna nota que alimentó la síntesis."""
    toks = _norm_titulo(bullet)
    mejor, mejor_j = None, 0.35
    for n in notas_ref:
        tn = _norm_titulo(n.get("t", ""))
        if not tn:
            continue
        j = len(toks & tn) / max(len(toks | tn), 1)
        if j > mejor_j:
            mejor, mejor_j = n, j
    return _chip_nota(mejor) if mejor else ("", "")


def _cuerpo_sintesis(texto: str, notas_ref: list) -> str:
    """Renderiza el texto de una síntesis a HTML: encabezados de
    sección, bullets con chip de fuente y párrafos — compartido por
    la tarjeta del dashboard y el reporte imprimible."""
    cuerpo = ""
    _toks_vistos = []   # dedup de bullets al render — las síntesis
    # viejas repiten la misma nota en 2-3 secciones
    for p in texto.split("\n"):
        p = p.strip()
        if not p:
            continue
        # TODAS las citas [N#] del bloque — la dominical referencia
        # varias notas por párrafo a media frase; antes solo se
        # resolvía enlace si UN [N#] cerraba la línea, así que en la
        # dominical no salía ni un solo enlace
        refs = []
        for mm in re.finditer(r"[\[(]N(\d+)(?:\|[^\])]*)?[\])]", p):
            k = int(mm.group(1)) - 1
            if 0 <= k < len(notas_ref) and k not in refs:
                refs.append(k)
        sec = re.fullmatch(r"\*\*(.+?)\*\*", p)
        if sec or (p.isupper() and len(p) > 3):
            cuerpo += (f"<h3 style='margin:1rem 0 .4rem;color:#1a237e;"
                       f"font-size:.95rem;letter-spacing:.05em'>"
                       f"{html.escape(sec.group(1) if sec else p)}"
                       f"</h3>")
        elif re.match(
                r"^no (hay|se (tienen|encuentran|han|mencionan|"
                r"presentan|detectaron|incluye))", p, flags=re.I):
            continue   # relleno del modelo — sección sin material
        elif re.match(r"^[•*\-—]\s|^[•*\-—]?\s*•", p):
            plano = re.sub(r"^[•\-—]\s*", "", p)
            # [N#], [N#|cat|fuente] o (N#) al final → chip
            m_id = re.search(
                r"[\[(]N(\d+)(?:\|[^\])]*)?[\])]\s*$", plano)
            nota_idx = None
            if m_id:
                plano = plano[:m_id.start()].rstrip()
                k = int(m_id.group(1)) - 1
                if 0 <= k < len(notas_ref):
                    nota_idx = notas_ref[k]
            toks = _norm_titulo(plano)
            if any(len(toks & v) / max(len(toks | v), 1) >= 0.7
                   for v in _toks_vistos):
                continue   # bullet repetido — se omite
            _toks_vistos.append(toks)
            txt = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>",
                         html.escape(plano))
            txt = txt.replace("**", "")   # asteriscos huérfanos
            txt = _resaltar_interes(txt)
            badge_n, link_n = (_chip_nota(nota_idx) if nota_idx
                               else _link_nota(p, notas_ref))
            cuerpo += (f"<p style='margin:.3rem 0;padding-left:1rem;"
                       f"border-left:3px solid #e0e0e0'>• {badge_n}"
                       f"{txt}{link_n}</p>")
        else:
            # párrafos también pueden cerrar con [N#] o (N#)
            m_id = re.search(
                r"[\[(]N(\d+)(?:\|[^\])]*)?[\])]\s*$", p)
            nota_idx = None
            if m_id:
                p = p[:m_id.start()].rstrip()
                k = int(m_id.group(1)) - 1
                if 0 <= k < len(notas_ref):
                    nota_idx = notas_ref[k]
            txt = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>",
                         html.escape(p))
            badge_n, link_n = (_chip_nota(nota_idx) if nota_idx
                               else _link_nota(p, notas_ref))
            cuerpo += (f"<p style='margin:.35rem 0'>{badge_n}"
                       f"{_resaltar_interes(txt)}{link_n}</p>")
        # bloque de enlaces por párrafo/sección — colapsado en
        # pantalla (<details>), el CSS de impresión lo expande para
        # que salgan todos en el PDF: un renglón por cita [N#]
        if refs:
            lin = "<br>".join(
                f"<a href='/nota?u={quote(notas_ref[k]['u'], safe='')}'"
                f" style='color:#6b6b8a;text-decoration:none'>"
                f"[N{k + 1}] {html.escape(notas_ref[k].get('f', ''))}"
                f" — {html.escape(notas_ref[k]['u'])}</a>"
                for k in refs if notas_ref[k].get("u"))
            if lin:
                cuerpo += (
                    f"<details class='blk-refs' style='margin:.05rem 0 "
                    f".55rem'><summary style='cursor:pointer;font-size:"
                    f".66rem;color:#888'>enlaces ({len(refs)})</summary>"
                    f"<div style='font-size:.62rem;color:#777;"
                    f"line-height:1.45;word-break:break-all'>{lin}</div>"
                    f"</details>")
    return cuerpo


def vista_resumenes(email: str, msg: str = "", dia: str = "") -> str:
    """Síntesis ejecutivas indexadas por día — como las portadas:
    tabs de fecha, siempre abre el día en curso y permite ver los
    resúmenes y cierres de días anteriores."""
    cfg_r = json.loads(CONFIG.read_text())
    admin_v = es_admin(email, cfg_r)
    # supervisión (Paolo): edita/borra/publica síntesis como el admin —
    # publicar en X sigue siendo exclusivo del admin
    sup_v = es_supervisor(email, cfg_r)
    # nombre de fuente → (categoría, tipo) para el cuadro por medio
    cat_f = {}
    for f in cfg_r.get("fuentes", []):
        cat_f[f["nombre"].lower()] = (f.get("categoria", "prensa"),
                                      f.get("tipo", "rss"))

    def _cat_fuente(nombre: str) -> tuple:
        n = nombre.lower()
        if nombre.startswith("@"):
            return ("x", "x")          # posts X → fuente=@autor
        if n in cat_f:
            return cat_f[n]
        for nom, ct in cat_f.items():
            if nom in n or n in nom:
                return ct
        return ("prensa", "rss")
    entradas = leer_jsonl(SINTESIS)
    # cronológico real, más reciente arriba — a las 21:10 queda
    # cierre → nocturna → vespertina → matutina
    entradas.sort(key=lambda e: e.get("fecha", ""), reverse=True)
    # index por día (?dia=YYYY-MM-DD) — default: el día en curso
    hoy_s = datetime.now().strftime("%Y-%m-%d")
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", dia or ""):
        dia = hoy_s
    dias = sorted({e.get("fecha", "")[:10] for e in entradas},
                  reverse=True)[:10]
    if hoy_s not in dias:
        dias = [hoy_s] + dias
    tabs_dia = ("<div class='tabs-cat'>" + "".join(
        f"<a class='tab-cat{' on' if d == dia else ''}' "
        f"href='/resumenes?dia={d}'>"
        f"{'hoy ' if d == hoy_s else ''}{d[8:10]}/{d[5:7]}</a>"
        for d in dias) + "</div>")
    entradas = [e for e in entradas
                if e.get("fecha", "").startswith(dia)]
    cards = ""
    for e in entradas[:30]:
        # borradores privados (mediodía) — solo admin los ve hasta
        # que los publique para paolo y demás
        if e.get("privado") and not admin_v:
            continue
        fecha = e.get("fecha", "")[:16].replace("T", " ")
        franja = e.get("franja", "")
        badge = ("<span style='background:#1a237e;color:#fff;padding:2px 8px;"
                 "border-radius:10px;font-size:.7rem'>"
                 + {"cierre": "CIERRE DIARIO",
                    "mediodia": "MEDIODÍA",
                    "semanal": "SEMANAL",
                    "dominical": "ANÁLISIS DOMINICAL"}.get(
                     franja, franja.upper()) + "</span>")
        if e.get("privado"):
            badge += ("<span style='background:#c62828;color:#fff;"
                      "padding:2px 8px;border-radius:10px;"
                      "font-size:.7rem;margin-left:.3rem'>PRIVADO"
                      "</span>")
        notas_ref = e.get("notas", [])
        cuerpo = _cuerpo_sintesis(e.get("texto", ""), notas_ref)
        fuentes = sorted({n.get("f", "") for n in notas_ref} - {""})
        detalle = ""
        if fuentes:
            detalle = (f"<p class='meta'>interés encontrado en "
                       f"{len(fuentes)} fuentes: "
                       f"{html.escape(', '.join(fuentes[:8]))}"
                       f"{'…' if len(fuentes) > 8 else ''}</p>")
        chips = (f"{e.get('n_notas', 0)} notas de interés"
                 + (f" · {len(fuentes)} fuentes" if fuentes else ""))
        ctrl = ""
        if sup_v:
            ffecha = html.escape(e.get("fecha", ""), quote=True)
            if e.get("privado"):
                # borrador de mediodía — el admin decide cuándo la
                # ve paolo y demás usuarios
                ctrl += (
                    f"<form method='post' "
                    f"action='/resumenes/editar' style='display:inline'>"
                    f"<input type='hidden' name='fecha' "
                    f"value='{ffecha}'>"
                    f"<button name='accion' value='publicar' "
                    f"style='font-size:.75rem;background:#2e7d32'>"
                    f"Publicar a usuarios</button></form>")
            ctrl += (
                f"<details style='margin-top:.6rem'>"
                f"<summary class='meta' style='cursor:pointer'>"
                f"editar / borrar</summary>"
                f"<form method='post' action='/resumenes/editar' "
                f"style='margin-top:.5rem'>"
                f"<input type='hidden' name='fecha' value='{ffecha}'>"
                f"<textarea name='texto' rows='9' style='width:100%;"
                f"font-size:.85rem'>{html.escape(e.get('texto', ''))}"
                f"</textarea>"
                f"<button name='accion' value='guardar'>Guardar"
                f"</button> "
                f"<button class='btn-rojo' name='accion' value='borrar' "
                f"onclick=\"return confirm('¿Borrar esta síntesis?')\">"
                f"Borrar</button></form></details>")
            # publicar en X — solo admin (ni paolo): el post_x viene
            # pre-generado con el cierre, editable antes de publicar;
            # publicado = marca, no re-publicable
            if franja == "cierre" and admin_v:
                ffecha2 = html.escape(e.get("fecha", ""), quote=True)
                if _x_publicado(e.get("fecha", "")):
                    ctrl += ("<p class='meta' style='color:#2e7d32'>"
                             "✓ publicado en X</p>")
                else:
                    px = html.escape(e.get("post_x", ""))
                    ctrl += (
                        f"<details style='margin-top:.6rem'>"
                        f"<summary class='meta' style='cursor:pointer'>"
                        f"publicar en X</summary>"
                        f"<form method='post' "
                        f"action='/resumenes/publicar-x' "
                        f"style='margin-top:.5rem'>"
                        f"<input type='hidden' name='fecha' "
                        f"value='{ffecha2}'>"
                        f"<textarea name='texto' rows='3' maxlength='280' "
                        f"style='width:100%;font-size:.85rem' "
                        f"placeholder='post para X (≤280)'>"
                        f"{px}</textarea>"
                        f"<button onclick=\"return confirm("
                        f"'¿Publicar en @elpolidelanoche?')\">"
                        f"Publicar</button></form></details>")
            # perspectiva nacional-vs-Tabasco (la vespertina y el
            # cierre la generan) — segundo post del poli, marcado
            # 'perspectiva' en x_posts para no chocar con el cierre
            if e.get("perspectiva"):
                if _x_publicado(e.get("fecha", ""), "perspectiva"):
                    ctrl += ("<p class='meta' style='color:#2e7d32'>"
                             "✓ perspectiva publicada</p>")
                else:
                    ps = html.escape(e["perspectiva"])
                    ff_p = html.escape(e.get("fecha", ""), quote=True)
                    ctrl += (
                        f"<details style='margin-top:.6rem'>"
                        f"<summary class='meta' style='cursor:pointer'>"
                        f"perspectiva del día (poli)</summary>"
                        f"<form method='post' "
                        f"action='/resumenes/publicar-x' "
                        f"style='margin-top:.5rem'>"
                        f"<input type='hidden' name='fecha' "
                        f"value='{ff_p}'>"
                        f"<input type='hidden' name='tipo' "
                        f"value='perspectiva'>"
                        f"<textarea name='texto' rows='3' maxlength='280' "
                        f"style='width:100%;font-size:.85rem' "
                        f"placeholder='perspectiva para X (≤280)'>"
                        f"{ps}</textarea>"
                        f"<button onclick=\"return confirm("
                        f"'¿Publicar en @elpolidelanoche?')\">"
                        f"Publicar</button></form></details>")
        # imprimir/PDF por tarjeta — para todos los registrados: el
        # reporte imprimible ya existía pero solo con checkboxes y
        # solo para admin; ahora cada tarjeta lleva su atajo directo
        imp = (f"<a class='btn-imp' "
               f"href='/resumenes/reporte?"
               f"sel={quote(e.get('fecha', ''), safe='')}' "
               f"target='_blank'>imprimir / PDF</a>")
        cards += (f"<div class='card'><div class='meta'>{badge} {fecha} · "
                  f"{chips}</div>{imp}{cuerpo}{detalle}{ctrl}</div>")
    # cuadro general al tope — conteo por tipo de medio de TODAS las
    # tarjetas vigentes (estilo síntesis ejecutiva); 'redes' queda en
    # 0 hasta que jalemos notas de FB — hoy solo sirven para portadas
    def _grupo(ct: tuple) -> str:
        c, tipo = ct
        if c == "x" or tipo == "x":
            return "X"
        if tipo == "fb" or c in ("redes", "facebook", "instagram"):
            return "Facebook"
        if c == "columnas":
            return "Columnas"
        return "Portales de Internet"
    conteo_g = Counter(_grupo(_cat_fuente(n.get("f", "")))
                       for e in entradas for n in e.get("notas", []))
    cuadro_g = ""
    if conteo_g:
        td_e = "style='border:1px solid #c5cae9;padding:4px 14px'"
        td_n = ("style='border:1px solid #c5cae9;padding:4px 14px;"
                "text-align:center;font-weight:600'")
        filas = "".join(
            f"<tr><td {td_e}>{g}</td>"
            f"<td {td_n}>{conteo_g[g]:02d}</td></tr>"
            for g in ("Portales de Internet", "Facebook", "X",
                      "Columnas") if conteo_g.get(g))
        cuadro_g = (
            f"<details style='margin:.4rem 0 1rem'>"
            f"<summary style='font-size:.8rem;color:#5c6bc0;"
            f"cursor:pointer'>Notas por medio</summary>"
            f"<table style='border-collapse:collapse;font-size:.74rem;"
            f"margin:.4rem 0;width:260px'>"
            f"<tr><th style='background:#1a237e;color:#fff;padding:5px "
            f"14px;text-align:left;border:1px solid #1a237e'>Medio</th>"
            f"<th style='background:#1a237e;color:#fff;padding:5px 14px;"
            f"border:1px solid #1a237e'>Notas</th></tr>"
            f"{filas}</table></details>")
    # selector descargar/imprimir — solo admin (paolo entrega el reporte)
    selector = ""
    if admin_v and entradas:
        opts = "".join(
            f"<label class='fuente-check' style='display:block'>"
            f"<input type='checkbox' name='sel' checked "
            f"value='{html.escape(e.get('fecha', ''), quote=True)}'> "
            f"{e.get('franja', '').upper() or 'SÍNTESIS'} · "
            f"{e.get('fecha', '')[:16].replace('T', ' ')}</label>"
            for e in entradas[:30])
        selector = (
            f"<details style='margin:.8rem 0 0'>"
            f"<summary style='font-size:.8rem;color:#5c6bc0;"
            f"cursor:pointer'>Descargar / imprimir</summary>"
            f"<form method='get' action='/resumenes/reporte' "
            f"target='_blank' style='margin-top:.6rem'>{opts}"
            f"<div class='regla-pie'><button>Generar reporte</button>"
            f"</div></form></details>")
    aviso = (f"<p class='meta' style='color:#1a237e'>{html.escape(msg)}</p>"
             if msg else "")
    # herramientas admin plegadas — la lectura diaria manda; se abre
    # sola mientras algo se genera (auto-reload cada 30 s)
    acciones = ""
    if admin_v:
        if _GENERANDO:
            botones = (
                "<span class='meta' style='color:#1a237e'>"
                "⏳ generando — la página se recarga sola"
                "</span>"
                "<script>setTimeout(function(){location.reload()},"
                "30000)</script>")
        else:
            botones = (
                "<form method='post' action='/resumenes/generar' "
                "style='display:flex;gap:.6rem;margin:.5rem 0 0'>"
                "<button class='btn-linea' style='font-size:.78rem;"
                "padding:.3rem .8rem'>Generar ahora</button>"
                "<button class='btn-linea' name='franja' "
                "value='cierre' style='font-size:.78rem;"
                "padding:.3rem .8rem'>Cierre diario</button>"
                "</form>")
        acciones = (
            f"<details{' open' if _GENERANDO else ''} "
            f"style='margin:.7rem 0 .3rem'>"
            f"<summary style='font-size:.8rem;color:#5c6bc0;"
            f"cursor:pointer'>Acciones</summary>{botones}</details>")
    # reporte express PDF — solo dirección (paolo) y admin
    btn_pdf = ""
    if admin_v or email == "paolo@anoticias.com":
        btn_pdf = ("<p class='meta'>Reporte express: "
                   "<a class='tab-cat on' href='/resumenes-pdf' "
                   "onclick=\"showLoader('Generando reporte express "
                   "— puede tardar ~1 min...')\">PDF del día ↗</a>"
                   " — se arma al click con la información capturada "
                   "hasta ahora.</p>")
    return (f"<h1>Síntesis Diaria "
            f"{dia[8:10]}/{dia[5:7]}/{dia[2:4]}</h1>" + aviso
            + tabs_dia
            + "<p class='meta'>Digests matutina 9:00 h, vespertina "
              "15:00 h y nocturna 21:00 h · análisis mediodía 12:00 h "
              "y cierre 17:00 h.</p>" + cuadro_g
            + btn_pdf + acciones + selector
            + (cards or "<p>Sin síntesis este día.</p>"))


def vista_reporte_resumenes(sel: list, admin: bool = False) -> str:
    """Reporte imprimible de entrega: encabezado con fecha larga +
    cuadro por tipo de medio + las síntesis elegidas (checkboxes en
    /resumenes). El botón Imprimir/PDF usa el diálogo del navegador."""
    cfg_r = json.loads(CONFIG.read_text())
    cat_f = {f["nombre"].lower(): (f.get("categoria", "prensa"),
                                   f.get("tipo", "rss"))
             for f in cfg_r.get("fuentes", [])}

    def _cat(nombre: str) -> tuple:
        n = nombre.lower()
        if nombre.startswith("@"):
            return ("x", "x")
        if n in cat_f:
            return cat_f[n]
        for nom, ct in cat_f.items():
            if nom in n or n in nom:
                return ct
        return ("prensa", "rss")

    entradas = leer_jsonl(SINTESIS)
    if not admin:
        # borradores privados nunca llegan al reporte — aunque el
        # usuario adivine la fecha en ?sel=
        entradas = [e for e in entradas if not e.get("privado")]
    if sel:
        sel_set = set(sel)
        entradas = [e for e in entradas if e.get("fecha") in sel_set]
    entradas.sort(key=lambda e: {"matutina": 0, "vespertina": 1,
                                 "nocturna": 2, "semanal": 3,
                                 "cierre": 4}
                  .get(e.get("franja", ""), 9))

    def _grupo(ct: tuple) -> str:
        c, tipo = ct
        if c == "x" or tipo == "x":
            return "X"
        if tipo == "fb" or c in ("redes", "facebook", "instagram"):
            return "Facebook"
        if c == "columnas":
            return "Columnas"
        return "Portales de Internet"
    conteo = Counter(_grupo(_cat(n.get("f", "")))
                     for e in entradas for n in e.get("notas", []))
    td_e = "border:1px solid #c5cae9;padding:4px 14px"
    filas = "".join(
        f"<tr><td style='{td_e}'>{g}</td>"
        f"<td style='{td_e};text-align:center;font-weight:600'>"
        f"{conteo[g]:02d}</td></tr>"
        for g in ("Portales de Internet", "Facebook", "X", "Columnas")
        if conteo.get(g))
    cuadro = (f"<table style='border-collapse:collapse;font-size:.78rem;"
              f"margin:.8rem 0 1.2rem;width:280px'>"
              f"<tr><th style='background:#1a237e;color:#fff;padding:5px"
              f" 14px;text-align:left'>Medio</th>"
              f"<th style='background:#1a237e;color:#fff;padding:5px "
              f"14px'>Notas</th></tr>{filas}</table>") if conteo else ""

    meses = ("enero febrero marzo abril mayo junio julio agosto "
             "septiembre octubre noviembre diciembre").split()
    hoy = datetime.now()
    fecha_larga = f"{hoy.day} de {meses[hoy.month - 1]} de {hoy.year}"
    secciones = ""
    for e in entradas:
        fr = {"cierre": "CIERRE DIARIO"}.get(
            e.get("franja", ""), e.get("franja", "").upper()) \
            or "SÍNTESIS"
        secciones += (
            f"<section style='margin-bottom:1.6rem'>"
            f"<h2 style='color:#1a237e;border-bottom:2px solid #1a237e;"
            f"padding-bottom:.2rem;font-size:1rem'>{fr} · "
            f"{e.get('fecha', '')[:16].replace('T', ' ')} h</h2>"
            + _cuerpo_sintesis(e.get("texto", ""),
                               e.get("notas", []))
            + "</section>")
    qs = "&".join("sel=" + quote(s, safe="") for s in sel)
    return f"""<!doctype html>
<html lang="es"><head><meta charset="utf-8">
<title>Síntesis ejecutiva — {fecha_larga}</title>
<style>
  body {{ font-family: Georgia, 'Times New Roman', serif; margin: 0;
         padding: 2rem; max-width: 800px; color: #111; font-size: .95rem;
         line-height: 1.55; }}
  h1 {{ font-size: 1.35rem; color: #1a237e; margin: 0; }}
  .sub {{ color: #555; font-size: .82rem; margin: .2rem 0 .8rem; }}
  .toolbar {{ position: sticky; top: 0; background: #f4f4f8;
    padding: .6rem; margin: -2rem -2rem 1rem; border-bottom:
    1px solid #ddd; display: flex; gap: .6rem; }}
  .toolbar button {{ font: inherit; padding: .35rem 1rem;
    border: 1px solid #1a237e; background: #fff; color: #1a237e;
    cursor: pointer; border-radius: 4px; }}
  mark {{ background: #fff3a0; padding: 0 .1em; }}
  a {{ color: #1a237e; }}
  @media print {{ .toolbar {{ display: none }}
                  body {{ padding: 0 }}
                  .url-print {{ display: block !important;
                    font-size: .62rem; color: #555;
                    word-break: break-all }}
                  .blk-refs > * {{ display: block !important; }}
                  .blk-refs > summary {{ display: none; }}
                  .blk-refs {{ border: none; }} }}
  @page {{ margin: 1.8cm; }}
</style></head><body>
<div class="toolbar">
  <button onclick="window.print()">Imprimir / guardar PDF</button>
  <a href="/resumenes/reporte?{qs}&fmt=png"><button>Descargar PNG</button></a>
</div>
<h1>SÍNTESIS DE NOTICIAS DEL {fecha_larga.upper()}</h1>
<p class="sub">Monitor de medios — matutina 9:00 h, vespertina 15:00 h,
nocturna 21:00 h, cierre del día 21:03 h · {datetime.now().strftime('%d/%m/%Y %H:%M')}</p>
{cuadro}
{secciones or "<p>Sin síntesis seleccionadas.</p>"}
<script>
// Chrome no expande <details> cerrado con CSS — abrir al
// imprimir y restaurar después
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
</script>
</body></html>"""


def _reporte_png(doc_html: str) -> bytes:
    """Renderiza el reporte a PNG con Playwright (chucky no — es solo
    un render local, sin sesión)."""
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            br = _launch(p)
            pg = br.new_page(viewport={"width": 900})
            pg.set_content(doc_html, wait_until="load")
            pg.wait_for_timeout(400)
            # los bloques de enlaces colapsados deben verse en la
            # imagen — el screenshot no dispara beforeprint
            pg.eval_on_selector_all(
                "details.blk-refs", "els => els.forEach(d => d.open = true)")
            png = pg.screenshot(full_page=True)
            br.close()
            return png
    except Exception as e:
        print(f"[reporte] png falló: {e}")
        return b""


def _agujas_buscar(q: str) -> list:
    """Parte la consulta en agujas: frases 'entre comillas' son substring
    exacto; palabras sueltas hacen AND en cualquier orden.
    'german "garcia serrano" tabasco' → ['german','garcia serrano','tabasco']"""
    return [normalizar(m.group(1) or m.group(2))
            for m in re.finditer(r'"([^"]+)"|(\S+)', q)
            if (m.group(1) or m.group(2)).strip()]


_BUSCAR_CACHE: dict = {}


def _notas_texto(vis: set) -> list:
    """(nota, texto_normalizado) de todas las noticias, cacheado por
    mtime del jsonl — antes cada búsqueda re-leía y re-normalizaba
    ~50k notas; el texto se recalcula solo cuando cambia el archivo."""
    global _BUSCAR_CACHE
    mt = NOTICIAS.stat().st_mtime if NOTICIAS.exists() else 0
    if _BUSCAR_CACHE.get("mt") != mt:
        notas = _noticias_cache()
        textos = {n["link"]: normalizar(
            n["titulo"] + " " + n["fuente"] + " "
            + (n.get("autor") or "") + " "
            + (n.get("resumen") or "")) for n in notas}
        _BUSCAR_CACHE = {"mt": mt, "notas": notas, "textos": textos}
    return [(n, _BUSCAR_CACHE["textos"].get(n["link"], ""))
            for n in _BUSCAR_CACHE["notas"]
            if n["fuente"] in vis or n.get("via") in vis]


def busqueda_viva_wp(q: str, cfg: dict, ya: set) -> list:
    """Consulta en vivo el archivo WordPress de cada medio del catálogo:
    encuentra notas que el feed RSS no capturó (el cliente quiere TODO).
    AND de palabras sobre el título, mismo criterio que la búsqueda local.
    Solo los hosts con API WP viva (wp_scan.json, escaneo diario) —
    antes pegaba a ~100 dominios ×2 hosts y la página se colgaba ~1min."""
    import concurrent.futures
    nom_por_dom = {}
    for f in cfg["fuentes"]:
        m = re.search(r"https?://([^/]+)", f["url"])
        if m:
            nom_por_dom.setdefault(
                re.sub(r"^www\.", "", m.group(1)), f["nombre"])
    # lista del escaneo diario; si no existe todavía, no buscar en vivo
    # (mejor sin 'en el archivo' que colgar la búsqueda 1 min)
    hosts_vivos = cargar_json(WP_SCAN, {}).get("hosts", [])
    if not hosts_vivos:
        return []
    doms = []
    for h in hosts_vivos:
        dom = re.sub(r"^www\.", "", h)
        nom = nom_por_dom.get(dom)
        if nom:
            doms.append((h, nom))
    terms = _agujas_buscar(q)
    if not terms:
        return []

    def probe(host_nombre):
        host, nombre = host_nombre
        try:
            r = requests.get(
                f"https://{host}/wp-json/wp/v2/search",
                params={"search": q, "per_page": 10},
                timeout=2.5, headers={"User-Agent": "Mozilla/5.0"})
            if r.status_code != 200:
                return []
            data = r.json()
            if not isinstance(data, list):
                return []
            return [{"titulo": html.unescape(it.get("title", "")),
                     "link": it.get("url", ""), "fuente": nombre}
                    for it in data
                    if it.get("url") and it.get("url") not in ya
                    and all(termino_en(t, normalizar(it.get("title", "")))
                            for t in terms)]
        except Exception:
            return []

    with concurrent.futures.ThreadPoolExecutor(16) as ex:
        out = []
        for hits in ex.map(probe, doms):
            out.extend(hits)
    return out[:60]


def busqueda_deep(q: str, ya: set) -> list:
    """DEEP SEARCH: sale de nuestra base — consulta el RSS de Google
    News por el término (mismo mecanismo que las fuentes 'gn:').
    Trae notas de CUALQUIER medio, esté o no en el catálogo; no se
    guardan en la base — son consulta, no ingesta."""
    import feedparser
    if not q.strip():
        return []
    url = ("https://news.google.com/rss/search?q=" + quote(q)
           + "&hl=es-419&gl=MX&ceid=MX:es-419")
    try:
        r = requests.get(url, timeout=8,
                         headers={"User-Agent": "Mozilla/5.0"})
        if r.status_code != 200:
            return []
        feed = feedparser.parse(r.content)
    except Exception:
        return []
    out, vistos = [], set(ya)
    for e in feed.entries:
        link = e.get("link", "")
        if not link or link in vistos:
            continue
        vistos.add(link)
        # fecha legible si GN la trae parseable
        ftxt = ""
        if e.get("published_parsed"):
            try:
                ftxt = fmt_fecha(datetime(
                    *e.published_parsed[:6]).isoformat())
            except Exception:
                pass
        src = getattr(e.get("source"), "title", "") or ""
        out.append({"titulo": html.unescape(e.get("title", "")),
                    "link": link, "fuente": src or "Google News",
                    "fecha": ftxt})
        if len(out) >= 40:
            break
    return out


def vista_buscar(q: str, email: str, deep: bool = False) -> str:
    agujas = _agujas_buscar(q)      # AND; "frase entre comillas" exacta
    cfg = json.loads(CONFIG.read_text())
    vis = fuentes_visibles(perfil_usuario(email, cfg), cfg)
    notas_txt = _notas_texto(vis)   # cache mtime — la parte lenta
    noticias = [n for n, _ in notas_txt]
    alertas = [a for a in leer_jsonl(ALERTAS)
               if not a.get("usuario") or a["usuario"] == email]
    hits_n = [n for n, txt in notas_txt
              if all(termino_en(t, txt) for t in agujas)]
    hits_a = [a for a in alertas if all(
        termino_en(t, normalizar(a["titulo"] + " " + a["reglas"]
                                 + " " + (a.get("autor") or "")))
        for t in agujas)]
    # si la alerta ya está como noticia en resultados, no duplicar
    links_n = {n["link"] for n in hits_n}
    hits_a = [a for a in hits_a if a["link"] not in links_n]
    # archivo vivo de los medios (WP): pesca notas que el feed no trajo
    vivos = busqueda_viva_wp(q, cfg, links_n | {a["link"] for a in hits_a}) \
        if q.strip() else []
    vivo_html = "".join(
        f"<div class='card'><a href='/nota?u={quote(h['link'], safe='')}'>"
        f"{html.escape(h['titulo'])}</a>"
        f"<div class='meta'>{html.escape(h['fuente'])} · en el medio ↗</div>"
        f"</div>" for h in vivos)
    # DEEP SEARCH (?deep=1): sale a Google News — medios fuera del
    # catálogo y hasta fuera del radar; links directos (no pasan por
    # /nota: son URLs redirect de GN que no se pueden re-leer)
    externos = busqueda_deep(
        q, links_n | {a["link"] for a in hits_a}
        | {v["link"] for v in vivos}) if deep else []
    deep_html = "".join(
        f"<div class='card'><a href='{html.escape(h['link'], quote=True)}'"
        f" target='_blank' rel='noopener'>"
        f"{html.escape(h['titulo'])}</a>"
        f"<div class='meta'>{html.escape(h['fuente'])}"
        f"{' · ' + h['fecha'] if h['fecha'] else ''} · web externa ↗</div>"
        f"</div>" for h in externos)
    colores = {r["nombre"]: r.get("color", "") for r in perfil_usuario(email, cfg).get("reglas", [])}
    chips = trending_chips(noticias)
    regresar = (f"<a class='chip-trend' href='/noticias' "
                f"style='background:#1a237e'>← Todas</a>")
    trending = f"<div class='trending'>{regresar}{chips}</div>" if chips else ""
    # botón siempre visible: la base ya buscó; deep sale fuera
    q_enc = quote(q)
    btn_deep = (f"<p class='meta' style='margin:.6rem 0'>"
                f"<a href='/buscar?q={q_enc}&deep=1'>"
                f"<button class='btn-linea' style='font-size:.75rem'>"
                f"⌕ Deep search — Google News y toda la web</button></a>"
                f" <span style='font-size:.7rem;color:#888'>(tarda unos "
                f"segundos; sale de la base)</span></p>"
                if not deep else
                f"<p class='meta' style='margin:.6rem 0'>"
                f"<a href='/buscar?q={q_enc}'>"
                f"<button class='btn-linea' style='font-size:.75rem'>"
                f"← solo base local</button></a></p>")
    return (f"<h1>Buscar: {html.escape(q)}</h1>"
            f"{trending}"
            f"<p class='meta'>{len(hits_n)} notas · {len(hits_a)} alertas"
            f" · frase exacta: \"entre comillas\"</p>"
            f"{btn_deep}"
            + "".join(card for _, card in sorted(
                [(a["fecha"], tarjeta_alerta(a, colores)) for a in hits_a]
                + [(n["fecha"], tarjeta_noticia(n)) for n in hits_n],
                key=lambda x: x[0], reverse=True))
            + (f"<h2>En el archivo de los medios ({len(vivos)})</h2>"
               + vivo_html if vivos else "")
            + (f"<h2>Deep search — web externa ({len(externos)})</h2>"
               + (deep_html or "<p class='meta'>Google News no trajo "
                 "nada para este término.</p>")
               if deep else ""))


def vista_config(email: str) -> str:
    cfg = json.loads(CONFIG.read_text())
    perfil = perfil_usuario(email, cfg)
    reglas = perfil.get("reglas", [])
    if perfil.get("expira"):  # demo: solo lectura
        return """
<h1>Mis reglas de alerta</h1>
<div class="card" style="border-left-color:#1a237e">
  <b>La demo es solo lectura.</b> Las alertas requieren una cuenta —
  pídele al admin que te cree una para armar tus reglas.
</div>"""
    mis_proys = proyectos_usuario(email)

    def _sel_alcance(actual: str = "") -> str:
        """Alcance de la regla: personal (solo tú) o compartida con
        uno de TUS proyectos — sus miembros la ven con tu nombre."""
        return ("<select name='proyecto' title='Alcance de la alerta'>"
                + f"<option value=''{' selected' if not actual else ''}>"
                  "Personal</option>"
                + "".join(
                    f"<option value='{html.escape(p, quote=True)}'"
                    f"{' selected' if p == actual else ''}>"
                    f"Proyecto {html.escape(p)}</option>"
                    for p in mis_proys)
                + "</select>")

    cards = "".join(
        f"""<div class="card regla" style="border-left-color:{color}">
  <span class="badge" style="background:{color}">{html.escape(r['nombre'])}</span>
  <form method="post" action="/config">
    <input type="hidden" name="idx" value="{i}">
    <label>Nombre de la regla</label>
    <input type="text" name="nombre" value="{html.escape(r['nombre'], quote=True)}" required>
    <label>Palabras clave (separadas por coma)</label>
    <input type="text" name="palabras"
           value="{html.escape(', '.join(r['requiere_todas']), quote=True)}" required>
    <p class="meta" style="margin:.2rem 0">Coma = palabras a buscar ·
    con 3+ basta que falte UNA · <b>/</b> = sinónimos
    (ej: <code>villahermosa/tabasco</code>)</p>
    <div class="regla-pie">
      <input type="color" name="color" value="{color}" title="Color del badge">
      {_sel_alcance(r.get('proyecto', ''))}
      <button name="accion" value="editar">Guardar</button>
      <button class="btn-rojo" name="accion" value="borrar"
              onclick="return confirm('¿Borrar esta regla?')">Borrar</button>
    </div>
  </form>
</div>"""
        for i, r in enumerate(reglas)
        for color in [r.get("color") or color_regla(r["nombre"], {})]
    )
    nota_alcance = ("<p class='meta'><b>Personal</b> = solo tú la ves · "
                    "<b>Proyecto</b> = la ven tus compañeros de ese "
                    "equipo, con tu nombre.</p>" if mis_proys else "")
    return f"""
<h1>Mis reglas de alerta</h1>
<p class="meta">Una regla dispara si la nota contiene TODAS sus palabras/frases
(mínimo 2 — una sola palabra genera demasiado ruido). Solo tú las editas.
Los cambios aplican al guardar — el backfill es inmediato y dispara un
ciclo de revisión para noticias nuevas.</p>
{nota_alcance}
<h2>Nueva regla</h2>
<div class="card regla">
  <form method="post" action="/config">
    <label>Nombre de la regla</label>
    <input type="text" name="nombre" placeholder="Ej: inundaciones" required>
    <label>Palabras requeridas (todas, separadas por coma)</label>
    <input type="text" name="palabras" placeholder="tabasco, inundación — sinónimos con /: tabasco/villahermosa" required>
    <div class="regla-pie">
      <input type="color" name="color" value="#1a237e" title="Color del badge">
      {_sel_alcance()}
      <button name="accion" value="agregar">Agregar regla</button>
    </div>
  </form>
</div>
<h2>Reglas activas</h2>
{cards or "<p class='meta'>Aún no tienes reglas.</p>"}"""


def _meta(html_txt: str, prop: str) -> str:
    """Extrae content de un meta tag (og:*/name=*) en cualquier orden."""
    m = re.search(
        rf'<meta[^>]+(?:property|name)=["\']{prop}["\'][^>]*content=["\']([^"\']+)',
        html_txt, re.I,
    ) or re.search(
        rf'<meta[^>]+content=["\']([^"\']+)["\'][^>]*(?:property|name)=["\']{prop}["\']',
        html_txt, re.I,
    )
    return m.group(1) if m else ""


def vista_nota(link: str, captura: bool = False) -> tuple:
    """Lector interno: trae la nota y la muestra dentro de la app.
    Devuelve (html, meta) — meta alimenta los OG de la vista pública
    (iframe no sirve: la mayoría de los sitios manda X-Frame-Options=DENY)."""
    dominio = urlparse(link).netloc
    if "news.google.com" in dominio:
        # link de agregador: el servidor no puede resolverlo al artículo
        # real (GN redirige con JS) — pero el navegador del usuario sí.
        # Mostramos tarjeta con datos de la nota almacenada + botón.
        nota = next((n for n in _noticias_cache()
                     if n["link"] == link), {})
        t = nota.get("titulo", "")
        f = nota.get("fuente", "")
        img = nota.get("imagen", "")
        res = nota.get("resumen", "")
        aut = nota.get("autor", "")
        return ("<div class='lector'>"
                "<a href='javascript:history.back()'>← Regresar</a>"
                f"<h1>{html.escape(t or 'Nota vía Google News')}</h1>"
                f"<div class='meta'>Fuente: {html.escape(f)}"
                + (f" · Por {html.escape(aut)}" if aut else "")
                + " · vía Google News</div>"
                + (f"<img class='hero' src='{html.escape(url_https(img))}' "
                   f"onerror='this.remove()'>" if img else "")
                + (f"<p class='lede'>{html.escape(res[:600])}</p>" if res else "")
                + "<p class='meta'>Indexada a través de Google News — al "
                  "abrirla, Google te lleva directo al artículo del medio.</p>"
                + f"<a class='origen' href='{html.escape(link)}' "
                  f"target='_blank' rel='noopener'>Abrir la nota en el medio ↗</a></div>",
                {"titulo": t, "imagen": img,
                 "desc": "Nota vía Google News", "dominio": dominio})
    if re.search(r"(^|\.)(x|twitter)\.com$", dominio):
        # el post ES el contenido — x.com anónimo solo enseña el
        # login-wall ('age-restricted'). Servir el texto guardado.
        nota = next((n for n in _noticias_cache()
                     if n["link"] == link), {})
        t = nota.get("resumen") or nota.get("titulo", "")
        aut = nota.get("fuente", "")
        img = nota.get("imagen", "")
        # avatar guardado de antes del fix (og:image de X = perfil):
        # no es media del post — fuera
        if "profile_images" in img:
            img = ""
        return ("<div class='lector'>"
                "<a href='javascript:history.back()'>← Regresar</a>"
                f"<h1>{html.escape(t[:140] or 'Post en X')}</h1>"
                f"<div class='meta'>Fuente: {html.escape(aut)}"
                f" · {html.escape(dominio)} · "
                f"{html.escape(fmt_fecha(nota.get('fecha', '')))}</div>"
                + (f"<img class='hero' src='{html.escape(url_https(img))}' "
                   f"onerror='this.remove()'>" if img else "")
                + (f"<p class='lede'>{html.escape(t)}</p>" if t else "")
                + f"<a class='origen' href='{html.escape(link)}' "
                  f"target='_blank' rel='noopener'>Abrir en X ↗</a></div>",
                {"titulo": t[:140], "imagen": img,
                 "desc": t[:200], "dominio": dominio})
    try:
        # (4s conexión, 8s por lectura) + tope 1.5MB: un medio que
        # entrega el body a gotas podía colgar el lector minutos —
        # timeout=12 solo acotaba CADA op de socket, no el total
        r = requests.get(link, timeout=(4, 8), stream=True,
                         headers={"User-Agent": "Mozilla/5.0"})
        r.raise_for_status()
        trozos, total = [], 0
        for chunk in r.iter_content(65536, decode_unicode=False):
            trozos.append(chunk)
            total += len(chunk)
            if total >= 1_500_000:
                break
        r.close()
        r._content = b"".join(trozos)
    except Exception as e:
        # el medio bloquea al servidor (403/WAF) — intentar con r.jina.ai
        # (lector de artículos web, sin redes sociales)
        nota = next((n for n in _noticias_cache()
                     if n["link"] == link), {})
        jtxt = ""
        try:
            jurl = "https://r.jina.ai/http://" + quote(link, safe="/:")
            rj = requests.get(jurl, timeout=(4, 12),
                              headers={"User-Agent": "Mozilla/5.0"})
            if rj.status_code == 200:
                jtxt = rj.text.strip()
                # si Jina también recibió el muro del WAF, no sirve
                if any(m in jtxt for m in
                       ("Algo ha salido mal", "Este sitio web se protege",
                        "403: Forbidden", "403 Client Error", "Forbidden")):
                    jtxt = ""
        except Exception:
            pass
        t = nota.get("titulo", "")
        img = nota.get("imagen", "")
        res = nota.get("resumen", "")
        aut = nota.get("autor", "")
        cuerpo = (f"<p class='lede'>{html.escape(res[:600])}</p>" if res else "")
        if jtxt:
            cuerpo += ("<h2 style='font-size:1.1rem;margin:1.4rem 0 .6rem;'>"
                       "Texto extraído del artículo</h2>"
                       f"<div style='white-space:pre-wrap;line-height:1.6;"
                       f"font-size:1rem;color:#222;'>"
                       f"{html.escape(jtxt)}</div>")
            explica = "<p class='meta'>El medio bloqueó al lector; se recuperó " \
                      "el texto vía Jina AI.</p>"
        else:
            explica = (f"<p class='meta'>El medio bloqueó la lectura "
                       f"({html.escape(str(e))}) — el texto completo está en "
                       "el sitio original.</p>")
        return ("<div class='lector'>"
                "<a href='javascript:history.back()'>← Regresar</a>"
                f"<h1>{html.escape(t or 'No se pudo cargar la nota')}</h1>"
                f"<div class='meta'>Fuente: "
                f"{html.escape(nota.get('fuente') or dominio)}"
                + (f" · Por {html.escape(aut)}" if aut else "")
                + "</div>"
                + (f"<img class='hero' src='{html.escape(url_https(img))}' "
                   f"onerror='this.remove()'>" if img else "")
                + cuerpo
                + explica
                + f"<a class='origen' href='{html.escape(link)}' "
                  f"target='_blank' rel='noopener'>Abrir en "
                  f"{html.escape(dominio)} ↗</a></div>",
                {"titulo": t, "imagen": img,
                 "desc": (jtxt or res)[:200], "dominio": dominio})

    titulo = _meta(r.text, "og:title") or _meta(r.text, "twitter:title") or ""
    if not titulo:
        m = re.search(r"<title[^>]*>(.*?)</title>", r.text, re.S | re.I)
        titulo = m.group(1).strip() if m else link
    titulo = html.unescape(re.sub(r"<[^>]+>", "", titulo)).strip()
    imagen = _meta(r.text, "og:image") or _meta(r.text, "twitter:image")
    if imagen and imagen.startswith("/"):
        imagen = urljoin(link, imagen)   # og:image relativo → absoluto
    desc = _meta(r.text, "og:description") or _meta(r.text, "description")
    if desc:
        # &lt;/B&gt; literal del medio (Reforma escapa dos veces) — unescape
        # y limpiar cualquier tag residual para que no salga crudo
        desc = re.sub(r"<[^>]+>", "", html.unescape(desc)).strip()
        # a veces el description es el menú, no la nota (Poder y Crítica)
        _dt = desc.split()
        if re.search(r"\bno results?\b|\bview all\b|^\s*login\b",
                     desc, re.I) or (
                len(_dt) >= 15 and
                sum(1 for t in _dt
                    if re.fullmatch(r"[A-ZÁÉÍÓÚÑÜ0-9.,#-]+", t))
                / len(_dt) > 0.5):
            desc = ""
    meta = {"titulo": titulo, "imagen": imagen, "desc": desc,
            "dominio": dominio}

    # byline: autor que vino en el feed → si no, metas de la página
    # (article:author / author / twitter:creator) — muchos medios
    # publican 'Redacción' o nada: se muestra lo que haya
    nota_guardada = next((n for n in _noticias_cache()
                          if n["link"] == link), {})
    autor = (nota_guardada.get("autor")
             or _meta(r.text, "article:author")
             or _meta(r.text, "author")
             or _meta(r.text, "twitter:creator")
             or "")
    autor = re.sub(r"^(por|by)\s+", "", autor, flags=re.I).strip()
    # x.com/fb no entregan og:image (login-wall) — usar la imagen que
    # el scraper sí capturó con el post; unescape: las URLs quedaron
    # guardadas con '&amp;' literal (innerHTML)
    imagen = imagen or html.unescape(
        nota_guardada.get("imagen", ""))
    meta["imagen"] = imagen
    datos = f"Fuente: {html.escape(nota_guardada.get('fuente') or dominio)}"
    if autor:
        datos += f" · Por {html.escape(autor)}"
    if nota_guardada.get("fecha"):
        datos += f" · {fmt_fecha(nota_guardada['fecha'])}"

    # párrafos del cuerpo: filtrar menús/pies (textos cortos) y duplicados
    # — primero limpiar <script>/<style>: los ads los meten dentro de <p>
    #   y el regex los volcaba como texto plano (googletag de Crónica)
    doc_p = re.sub(r"<script[\s\S]*?</script>", " ", r.text, flags=re.I)
    doc_p = re.sub(r"<style[\s\S]*?</style>", " ", doc_p, flags=re.I)
    doc_p = re.sub(r"<!--[\s\S]*?-->", " ", doc_p)
    paras, vistos_p = [], set()
    for p in re.findall(r"<p[^>]*>(.*?)</p>", doc_p, re.S | re.I):
        txt = re.sub(r"<[^>]+>", " ", p)
        txt = html.unescape(re.sub(r"\s+", " ", txt)).strip()
        if len(txt) <= 60 or txt in vistos_p:
            continue
        # nav/footer: párrafos que son casi puros <a> (menús de WP se
        # meten en <p>) o boilerplate editorial — no son cuerpo
        links_txt = " ".join(re.findall(
            r"<a[^>]*>(.*?)</a>", p, re.S | re.I))
        links_txt = re.sub(r"<[^>]+>", " ", links_txt)
        links_txt = len(html.unescape(re.sub(r"\s+", " ", links_txt)).strip())
        if links_txt / len(txt) > 0.45:
            continue
        if re.search(r"derechos reservados|©\s*\d{4}|todos los derechos",
                     txt, re.I):
            continue
        # menú del sitio volcado dentro de un <p> (Poder y Crítica):
        # el párrafo mezcla 'Login ESTADOS CDMX CAMPECHE…' con la nota —
        # los detecta la ráfaga de tokens en MAYÚSCULAS y la basura
        # típica de buscador interno ('No Result', 'View All Result')
        toks = txt.split()
        if re.search(r"\bno results?\b|\bview all\b|^\s*login\b|"
                     r"username or email|reset your password|"
                     r"\blog in\b|\bsign up\b|\bsuscr[ií]bete\b|"
                     r"\binicia sesi[oó]n\b|\bcrea una cuenta\b",
                     txt, re.I) or (
                len(toks) >= 15 and
                sum(1 for t in toks
                    if re.fullmatch(r"[A-ZÁÉÍÓÚÑÜ0-9.,#-]+", t))
                / len(toks) > 0.5):
            continue
        # teaser de 'notas relacionadas' colado en el artículo:
        # párrafo completo que termina truncado con '…' o '...'
        if len(txt) > 100 and txt.endswith(("…", "...")):
            continue
        paras.append(txt)
        vistos_p.add(txt)
        if len(paras) >= 15:
            break

    cuerpo = (f"<p class='lede'>{html.escape(desc)}</p>" if desc else "") \
        + "".join(f"<p>{html.escape(p)}</p>" for p in paras)
    if not cuerpo:
        cuerpo = ("<p class='meta'>El sitio no permitió extraer el texto.</p>")

    # fuente paywalled → avisar que solo hay lede
    if nota_guardada.get("paywall"):
        cuerpo += ("<p class='meta' style='color:#b45309;font-weight:600'>"
                   "SUSCRIPCIÓN REQUERIDA — el medio solo publica el "
                   "adelanto; el texto completo es de pago.</p>")

    # ¿la página original tiene video? metas, tag <video> o players conocidos
    hay_video = bool(re.search(
        r'og:video|twitter:player|<video[\s>]|\.m3u8|'
        r'youtube\.com/embed|vimeo\.com|jwplayer|brightcove', r.text, re.I))

    return (
        "<div class='lector'>"
        f"<a href='javascript:history.back()'>← Regresar</a>"
        f"<h1>{html.escape(titulo)}</h1>"
        f"<div class='meta'>{datos}</div>"
        + (f"<img class='hero' src='{html.escape(url_https(imagen))}' "
           f"onerror='this.remove()'>" if imagen else "")
        + cuerpo
        + f"<a class='origen' href='{html.escape(link)}' "
          f"target='_blank' rel='noopener'>"
          f"{'Ver nota y video en el sitio original ↗' if hay_video else 'Ver en el sitio original ↗'}</a>"
        + (f" <a class='compartir' href='/captura.png?u={quote(link, safe='')}' "
             f"download='captura.png' "
             f"onclick=\"this.textContent='Creando imagen...'; "
             f"this.classList.add('cargando'); "
             f"setTimeout(() => {{ this.textContent='PNG'; "
             f"this.classList.remove('cargando'); }}, 5000)\">PNG</a>" if captura
             else f" <a class='compartir' href='#' onclick='return false;' "
                  f"style='opacity:.45; cursor:not-allowed' "
                  f"title='Solo usuarios registrados'>PNG</a>")
        + " <button class='compartir' type='button' onclick=\""
          "if(navigator.share){navigator.share({title:document.title,url:location.href})}"
          "else{navigator.clipboard.writeText(location.href);"
          "this.textContent='¡Enlace copiado!'}\">Compartir</button>"
        + "</div>", meta
    )


NOTA_PUB = """<!DOCTYPE html>
<html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="theme-color" content="#1a237e">
<link rel="icon" type="image/png" href="/icon3.png">
<meta property="og:type" content="article">
<meta property="og:site_name" content="@noticias">
<meta property="og:url" content="{base}/nota?u={url_esc}">
<meta property="og:title" content="{og_titulo}">
<meta property="og:description" content="{og_desc}">
<meta property="og:image" content="{og_img}">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:image" content="{og_img}">
<title>{titulo_pag} — @noticias</title>
<style>
  * {{ box-sizing: border-box; }}
  body {{ font-family: system-ui, sans-serif; margin: 0; background: #f6f7f9;
         font-size: 17px; line-height: 1.45; }}
  nav {{ background: #1a237e; color: #fff; padding: .8rem 1rem;
        display: flex; align-items: center; justify-content: space-between;
        position: sticky; top: 0; }}
  nav .logo {{ color: #fff; text-decoration: none; font-weight: 800;
              font-size: 1.3rem; letter-spacing: .02em; }}
  nav .entrar {{ color: #fff; text-decoration: none; border: 1px solid #ffffff55;
      border-radius: 6px; padding: .4rem .9rem; font-size: .85rem; }}
  main {{ max-width: 720px; margin: 0 auto; padding: 1rem; }}
  .lector {{ background: #fff; border-radius: 8px; padding: 1.2rem;
            box-shadow: 0 1px 4px #0002; }}
  .lector img.hero {{ width: 100%; border-radius: 8px; margin: .6rem 0; }}
  .lector .lede {{ font-weight: 600; font-size: 1.05rem; color: #333; }}
  .lector p {{ margin: .7rem 0; }}
  .lector .meta {{ font-size: .8rem; color: #666; }}
  .lector .origen, .origen {{ display: inline-block; margin-top: 1rem;
      background: #1a237e; color: #fff; text-decoration: none;
      padding: .7rem 1.1rem; border-radius: 8px; font-weight: 600; }}
  .compartir {{ display: inline-block; margin-top: 1rem; margin-left: .5rem;
      background: none; color: #1a237e; border: 1px solid #1a237e;
      padding: .7rem 1.1rem; border-radius: 8px; font-weight: 600;
      font-size: 1rem; cursor: pointer; }}
  .cta {{ background: #fff; border: 1px solid #dfe3ee; border-radius: 8px;
         padding: 1.2rem; text-align: center; margin: 1.2rem 0; color: #444; }}
  .cta a, .cta .cta-btn {{ display: inline-block; margin-top: .7rem;
      background: #1a237e; color: #fff; text-decoration: none; border: 0;
      padding: .7rem 1.4rem; border-radius: 8px; font-weight: 600;
      font-size: 1rem; cursor: pointer; }}
</style></head><body>
<nav><a class="logo" href="/">@noticias</a><a class="entrar" href="/noticias">Entrar</a></nav>
<main>{contenido}
<div class="cta"><b>@noticias</b> — monitor de prensa con alertas personales<br>
<form method="post" action="/invitado"><button class="cta-btn">Probar gratis — demo 24h</button></form><br>
<a href="/" style="background:none;color:#1a237e;padding:.3rem;font-size:.85rem">conocer más →</a></div>
</main></body></html>"""


def vista_nota_publica(link: str, base: str) -> bytes:
    """Versión pública del lector — compartible sin sesión.
    Los OG son del artículo original: WhatsApp muestra titular+foto
    de la nota con nuestra marca y dominio."""
    contenido, meta = vista_nota(link)
    return NOTA_PUB.format(
        base=base,
        url_esc=quote(link, safe=""),
        og_titulo=html.escape(meta.get("titulo") or "@noticias", quote=True),
        og_desc=html.escape(meta.get("desc")[:200], quote=True),
        og_img=html.escape(url_https(meta.get("imagen") or "") or f"{base}/og.png",
                           quote=True),
        titulo_pag=html.escape((meta.get("titulo") or "nota")[:70]),
        contenido=contenido,
    ).encode()


CAPTURA_PUB = """<!DOCTYPE html>
<html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="theme-color" content="#7b1fa2">
<link rel="icon" type="image/png" href="/icon3.png">
<title>Captura — @noticias</title>
<style>
  * {{ box-sizing: border-box; }}
  body {{ font-family: system-ui, sans-serif; margin: 0; background: #f6f7f9;
         font-size: 17px; line-height: 1.5; }}
  main {{ max-width: 720px; margin: 0 auto; padding: 1rem; }}
  .acciones {{ text-align: center; margin: 1rem 0; }}
  .acciones button {{ background: #7b1fa2; color: #fff; border: 0;
      padding: .8rem 1.2rem; border-radius: 8px; font-weight: 600;
      font-size: 1rem; cursor: pointer; }}
  .acciones a {{ display: inline-block; margin-left: .5rem; color: #7b1fa2;
      text-decoration: none; font-size: .9rem; }}
  .card {{ background: #fff; border-left: 6px solid #7b1fa2; border-radius: 8px;
           padding: 1.5rem; box-shadow: 0 4px 14px #0002; }}
  .brand {{ color: #7b1fa2; font-weight: 800; font-size: .85rem;
            margin-bottom: .5rem; letter-spacing: .02em; }}
  .titulo {{ font-size: 1.6rem; font-weight: 700; color: #111; margin: 0 0 .6rem; line-height: 1.25; }}
  .meta {{ color: #666; font-size: .85rem; margin: .8rem 0; }}
  .chip {{ display: inline-block; background: #7b1fa2; color: #fff;
           padding: .2rem .6rem; border-radius: 12px; font-size: .75rem;
           margin-right: .4rem; text-transform: uppercase; }}
  .resumen {{ font-size: 1.05rem; line-height: 1.55; color: #333; margin-top: 1rem; }}
  .pie {{ display: flex; justify-content: space-between; align-items: center;
          margin-top: 1.5rem; padding-top: 1rem; border-top: 1px solid #e5e5e5;
          color: #666; font-size: .8rem; }}
  @media print {{ .acciones {{ display: none; }} body {{ background: #fff; }}
                 main {{ padding: 0; max-width: none; }}
                 .card {{ box-shadow: none; }} }}
</style></head><body>
<main>
<div class="acciones">
  <button type="button" onclick="window.print()">Guardar como PDF</button>
  <a href="{original}" target="_blank" rel="noopener">Ver original ↗</a>
</div>
<div class="card">
  <div class="brand">@noticias</div>
  <h1 class="titulo">{titulo}</h1>
  <div class="meta"><span class="chip">{fuente}</span>{fecha}</div>
  <p class="resumen">{resumen}</p>
  <div class="pie"><span>Fuente: {dominio}</span><span>@noticias</span></div>
</div>
</main>
</body></html>"""


def vista_captura(link: str) -> bytes:
    """Página imprimible/PDF de una nota enmarcada en @noticias."""
    contenido, meta = vista_nota(link)
    titulo = (meta.get("titulo") or link)[:120]
    dominio = meta.get("dominio") or urlparse(link).netloc or "—"
    fuente = (dominio.split(".")[0] or dominio)
    desc = (meta.get("desc") or "").strip()
    if len(desc) < 80:
        m = re.search(r"<p[^>]*>(.*?)</p>", contenido, re.S | re.I)
        if m:
            txt = re.sub(r"<[^>]+>", " ", m.group(1))
            desc = html.unescape(re.sub(r"\s+", " ", txt)).strip()
    resumen = (desc or "Sin resumen disponible.")[:500]
    fecha = datetime.now()
    return CAPTURA_PUB.format(
        titulo=html.escape(titulo),
        dominio=html.escape(dominio),
        fuente=html.escape(fuente),
        resumen=html.escape(resumen),
        fecha=f"{fecha:%d/%m/%Y %H:%M}",
        original=html.escape(link),
    ).encode()


def _wrap_lines(text: str, font, max_w: int, draw):
    words = text.split()
    lines, cur = [], ""
    for w in words:
        test = f"{cur} {w}".strip() if cur else w
        bbox = draw.textbbox((0, 0), test, font=font)
        if bbox[2] - bbox[0] <= max_w:
            cur = test
        else:
            if cur:
                lines.append(cur)
            wb = draw.textbbox((0, 0), w, font=font)
            if wb[2] - wb[0] > max_w:
                chunk = ""
                for ch in w:
                    nt = chunk + ch
                    nb = draw.textbbox((0, 0), nt, font=font)
                    if nb[2] - nb[0] > max_w:
                        if chunk:
                            lines.append(chunk)
                        chunk = ch
                    else:
                        chunk = nt
                if chunk:
                    lines.append(chunk)
                cur = ""
            else:
                cur = w
    if cur:
        lines.append(cur)
    return lines


def captura_png(link: str) -> bytes:
    """Genera un PNG de la nota enmarcada en @noticias."""
    W = 1200
    M = 80
    max_w = W - 2 * M
    paths = {
        "title": "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        "body": "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    }
    try:
        f_title = ImageFont.truetype(paths["title"], 48)
        f_header = ImageFont.truetype(paths["title"], 42)
        f_meta = ImageFont.truetype(paths["body"], 24)
        f_body = ImageFont.truetype(paths["body"], 26)
        f_small = ImageFont.truetype(paths["body"], 20)
    except Exception:
        f_title = f_header = f_meta = f_body = f_small = ImageFont.load_default()

    contenido, meta = vista_nota(link)
    titulo = (meta.get("titulo") or link).strip()
    dominio = meta.get("dominio") or urlparse(link).netloc or "—"
    fuente = (dominio.split(".")[0] or dominio).upper()
    imagen_url = meta.get("imagen", "")
    foto, foto_h, foto_w = None, 0, 0
    if imagen_url and url_es_segura(imagen_url):
        try:
            r = requests.get(imagen_url, timeout=10,
                             headers={"User-Agent": "Mozilla/5.0"})
            r.raise_for_status()
            foto = Image.open(io.BytesIO(r.content)).convert("RGB")
            max_img_w = 900
            max_img_h = 400
            ratio = min(max_img_w / foto.width, max_img_h / foto.height, 1.0)
            foto_w = int(foto.width * ratio)
            foto_h = int(foto.height * ratio)
            foto = foto.resize((foto_w, foto_h), Image.LANCZOS)
        except Exception:
            foto = None

    paras = []
    for p in re.findall(r"<p[^>]*>(.*?)</p>", contenido, re.S | re.I):
        txt = re.sub(r"<[^>]+>", " ", p)
        txt = html.unescape(re.sub(r"\s+", " ", txt)).strip()
        if txt:
            paras.append(txt)
    if not paras:
        paras = [meta.get("desc") or "Sin contenido extraído."]

    dummy = Image.new("RGB", (W, 4000), "white")
    draw = ImageDraw.Draw(dummy)
    title_lines = _wrap_lines(titulo, f_title, max_w, draw)
    body_groups = []
    for p in paras:
        body_groups.append(_wrap_lines(p, f_body, max_w, draw))

    y = 0
    header_h = 110
    y += header_h
    y += 60  # margin below header
    y += len(title_lines) * 58
    y += 40  # after title
    y += 40  # meta line
    y += 30  # separator
    if foto:
        y += foto_h + 30
    for lines in body_groups:
        y += len(lines) * 38 + 20
    y += 30  # before footer
    y += 40  # footer
    y += 80  # bottom margin
    H = max(600, int(y))

    img = Image.new("RGB", (W, H), "#f6f7f9")
    draw = ImageDraw.Draw(img)

    # header
    draw.rectangle([0, 0, W, header_h], fill="#1a237e")
    draw.text((M, 30), "@noticias", font=f_header, fill="white")

    y = header_h + 60
    for line in title_lines:
        draw.text((M, y), line, font=f_title, fill="#111111")
        y += 58
    y += 30

    # meta chip + date
    cb = draw.textbbox((0, 0), fuente, font=f_small)
    chip_w = (cb[2] - cb[0]) + 24
    chip_h = 34
    draw.rounded_rectangle([M, y, M + chip_w, y + chip_h], radius=17, fill="#7b1fa2")
    draw.text((M + 12, y + 7), fuente, font=f_small, fill="white")
    fecha = f"{datetime.now():%d/%m/%Y %H:%M}"
    draw.text((M + chip_w + 18, y + 7), fecha, font=f_small, fill="#666666")
    y += 50

    # separator
    draw.line([(M, y), (W - M, y)], fill="#dddddd", width=1)
    y += 30

    # imagen principal
    if foto:
        x_img = M + (max_w - foto_w) // 2
        img.paste(foto, (x_img, y))
        y += foto_h + 30

    # body
    for lines in body_groups:
        for line in lines:
            draw.text((M, y), line, font=f_body, fill="#222222")
            y += 38
        y += 20  # paragraph spacing

    # footer
    y += 20
    draw.line([(M, y), (W - M, y)], fill="#dddddd", width=1)
    y += 24
    left = f"Fuente: {dominio}"
    right = "@noticias"
    draw.text((M, y), left, font=f_small, fill="#666666")
    rb = draw.textbbox((0, 0), right, font=f_small)
    draw.text((W - M - (rb[2] - rb[0]), y), right, font=f_small, fill="#666666")

    bio = io.BytesIO()
    img.save(bio, format="PNG", optimize=True, compress_level=9)
    return bio.getvalue()


LANDING = """<!DOCTYPE html>
<html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="theme-color" content="#1a237e">
<link rel="icon" type="image/png" href="/icon3.png">
<title>@noticias — monitor de prensa con alertas</title>
<meta property="og:type" content="website">
<meta property="og:site_name" content="@noticias">
<meta property="og:title" content="@noticias — monitor de prensa con alertas personales">
<meta property="og:description" content="Todas las notas de tus fuentes en un solo feed. Alertas por palabra clave, historias agrupadas entre medios y links que se comparten bonito.">
<meta property="og:image" content="{base}/og.png">
<style>
  * { box-sizing: border-box; }
  body { font-family: system-ui, sans-serif; margin: 0; color: #222;
         background: #f6f7f9; font-size: 17px; line-height: 1.5; }
  nav { background: #1a237e; padding: .8rem 1.2rem; display: flex;
        justify-content: space-between; align-items: center;
        position: sticky; top: 0; }
  nav .logo { color: #fff; font-weight: 800; font-size: 1.3rem;
              text-decoration: none; }
  nav .entrar { color: #fff; border: 1px solid #ffffff55; border-radius: 6px;
      padding: .4rem .9rem; text-decoration: none; font-size: .85rem; }
  .hero { background: #1a237e; color: #fff; text-align: center;
          padding: 3.5rem 1.2rem 2.8rem; }
  .hero h1 { font-size: 2.1rem; margin: 0 0 .6rem; line-height: 1.2; }
  .hero p { color: #c5cae9; max-width: 560px; margin: 0 auto 1.6rem; }
  .btn { display: inline-block; background: #fff; color: #1a237e;
         font-weight: 700; border: 0; padding: .85rem 1.6rem;
         border-radius: 8px; font-size: 1rem; cursor: pointer;
         text-decoration: none; }
  .hero .mini { display: block; margin-top: .7rem; color: #9fa8da;
                font-size: .8rem; }
  .wrap { max-width: 720px; margin: 0 auto; padding: 1.5rem 1.2rem 3rem; }
  h2 { font-size: 1.35rem; margin: 2rem 0 .8rem; color: #1a237e; }
  .feat { background: #fff; border-radius: 8px; margin: .7rem 0;
          box-shadow: 0 1px 4px #0001; border-left: 4px solid #1a237e; }
  .feat summary { list-style: none; cursor: pointer; padding: 1rem 1.2rem;
      font-weight: 700; display: flex; justify-content: space-between;
      align-items: center; }
  .feat summary::-webkit-details-marker { display: none; }
  .feat summary::after { content: "▾"; color: #1a237e; font-size: .9rem;
      transition: transform .15s; }
  .feat[open] summary::after { transform: rotate(180deg); }
  .feat .cuerpo { padding: 0 1.2rem 1.1rem; }
  .feat .cuerpo p { color: #555; font-size: .93rem; margin: 0 0 .7rem; }
  .feat img { width: 100%; max-height: 360px; object-fit: cover;
      object-position: top; border-radius: 8px; border: 1px solid #e3e6ef;
      display: block; }
  .feat .mas { font-size: .82rem; color: #1a237e; }
  .cta2 { text-align: center; margin-top: 2.5rem; }
</style></head><body>
<nav><a class="logo" href="/">@noticias</a>
<a class="entrar" href="/noticias">Entrar</a></nav>
<div class="hero">
  <h1>Toda la prensa que te importa,<br>en un solo feed</h1>
  <p>Monitoreamos los medios que eliges y te avisamos al instante
     cuando sale el tema que te interesa. Sin ruido, sin scroll infinito,
     sin algoritmo que decida por ti.</p>
  <form method="post" action="/invitado">
    <button class="btn">Probar gratis — demo 24h</button>
  </form>
  <span class="mini">sin registro · sin correo · entras en un clic<br>
  <a href="/instructivo" style="color:#9fa8da">o ve el instructivo con capturas →</a></span>
</div>
<div class="wrap">
  <h2>Qué hace — toca cada tarjeta</h2>
  <details class="feat"><summary>🚨 Alertas personales</summary>
    <div class="cuerpo"><p>Crea reglas con tus palabras clave — tu tema, tu
    colonia, tu sector. Cada nota que las cumpla entra a Alertas al
    momento, con el color que elegiste.</p>
    <img src="/shots/alertas.png" loading="lazy" alt="Alertas">
    <a class="mas" href="/instructivo#alertas">más detalle →</a></div>
  </details>
  <details class="feat"><summary>🧵 Noticia en desarrollo</summary>
    <div class="cuerpo"><p>Cuando varios medios cubren lo mismo, lo
    agrupamos: un titular y todas las versiones desplegables.</p>
    <img src="/shots/destacadas.png" loading="lazy" alt="Destacadas">
    <a class="mas" href="/instructivo#destacadas">más detalle →</a></div>
  </details>
  <details class="feat"><summary>📰 Tus fuentes, tu feed</summary>
    <div class="cuerpo"><p>El catálogo lo curamos nosotros; tú eliges qué
    medios ver. Prensa local, nacional e independiente.</p>
    <img src="/shots/feed.png" loading="lazy" alt="Feed">
    <a class="mas" href="/instructivo#feed">más detalle →</a></div>
  </details>
  <details class="feat"><summary>🔗 Comparte con preview</summary>
    <div class="cuerpo"><p>Cada nota se lee dentro de la app y se comparte
    con foto y titular en WhatsApp — quien lo abre, aterriza aquí.</p>
    <img src="/shots/nota.png" loading="lazy" alt="Lector">
    <a class="mas" href="/instructivo#nota">más detalle →</a></div>
  </details>
  <details class="feat"><summary>🔎 Archivo buscable</summary>
    <div class="cuerpo"><p>Siete días de notas a una búsqueda de
    distancia.</p>
    <img src="/shots/buscar.png" loading="lazy" alt="Búsqueda">
    <a class="mas" href="/instructivo#buscar">más detalle →</a></div>
  </details>
  <details class="feat"><summary>⚙️ Reglas en un minuto</summary>
    <div class="cuerpo"><p>Nombre + palabras + color. Al guardar, el
    backfill rescana el archivo y ya estás alertando.</p>
    <img src="/shots/reglas.png" loading="lazy" alt="Reglas">
    <a class="mas" href="/instructivo#reglas">más detalle →</a></div>
  </details>
  <details class="feat"><summary>📱 Instálala como app</summary>
    <div class="cuerpo"><p>PWA con contador de alertas en el ícono. Se
    siente nativa — agrégala a tu pantalla de inicio.</p></div>
  </details>
  <div class="cta2">
    <form method="post" action="/invitado">
      <button class="btn" style="background:#1a237e;color:#fff">
        Entrar como invitado →</button>
    </form>
  </div>
</div>
</body></html>"""


def vista_landing(base: str) -> bytes:
    """Landing pública — el pitch para prospectos. Reemplaza al login
    como cara del sitio para quien llega sin sesión."""
    return LANDING.replace("{base}", base).encode()


def vista_instructivo(base: str) -> bytes:
    """Tour técnico público: cada sección con su captura real + el porqué
    detrás. Las imágenes se regeneran con shots.py al cambiar el diseño."""
    SECCIONES = [
        ("feed", "El feed — tus fuentes en una sola fila",
         "Todas las notas de los medios que elegiste, de la más reciente a "
         "la más antigua. Cada tarjeta lleva el chip del medio, fecha/hora "
         "de publicación y foto. Tocar una tarjeta abre el lector interno, "
         "no el sitio original — la navegación nunca te saca de la app."),
        ("nota", "Lector interno y links compartibles",
         "Extraemos titular, foto y cuerpo de la nota y la servimos bajo "
         "nuestro dominio. El botón Compartir copia el enlace interno: en "
         "WhatsApp sale con preview de la nota (Open Graph por artículo) y "
         "quien lo abre cae en la vista pública con llamada a probar el demo."),
        ("alertas", "Alertas — tu radar personal",
         "Cada usuario define reglas de palabras clave. Cuando una nota "
         "las cumple todas, entra a Alertas al instante — con el color que "
         "le asignaste para distinguir temas de un vistazo."),
        ("reglas", "Configurar reglas es trivial",
         "Nombre + palabras separadas por coma (todas deben aparecer) + "
         "color. Se guarda y aplica en el momento: el backfill rescana el "
         "archivo reciente en segundo plano."),
        ("destacadas", "Noticia en desarrollo",
         "Cuando varios medios cubren la misma historia la agrupamos en "
         "una tarjeta: un titular representativo y las demás versiones "
         "desplegables. La portada se ve una vez, no diez."),
        ("buscar", "Buscador de archivo",
         "Siete días de notas indexadas — una búsqueda contra títulos, "
         "fuentes y tus alertas. Resultados del más reciente al más viejo."),
        ("fuentes", "Fuentes — catálogo curado, feed personal",
         "El admin mantiene el catálogo (RSS directo o sitios sin feed, "
         "con autodetección). Cada usuario solo prende/apaga qué medios "
         "ver. Checkboxes, nada más."),
        ("analitica", "Analítica — solo admin",
         "Bitácora de uso por usuario: sesiones, tiempo dentro, qué notas "
         "abrió y cuántas veces. Incluye anónimos — mide cuántos clics "
         "generan los links compartidos."),
        ("stats", "Stats — salud del sistema",
         "Estado por fuente (última captura OK, errores), tamaños de los "
         "JSONL y conteos globales. El tablero de operación del admin."),
    ]
    bloques = "".join(f"""
  <h2 id="{k}">{i + 1}. {t}</h2>
  <a href="/shots/{k}.png"><img class="shot" src="/shots/{k}.png"
       loading="lazy" alt="{t}"></a>
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
<a class="entrar" href="/noticias">Entrar</a></nav>
<div class="wrap">
<h1>Cómo funciona, pantalla por pantalla</h1>
<p>Capturas reales del sistema — no mockups. Se regeneran con
<code>shots.py</code> cada vez que cambia el diseño.</p>
{bloques}
<h2>Por dentro</h2>
<div class="tech"><ul>
  <li>Python puro — <code>http.server</code> con hilos, cero framework</li>
  <li>Fuentes RSS/Atom vía <code>feedparser</code> + scraper propio para
      sitios sin feed (patrón <code>/seccion/id/slug</code>)</li>
  <li>Autodetección de feed: pegas la portada y se resuelve solo</li>
  <li>Datos en JSONL append-only — cero base de datos externa</li>
  <li>Sesiones con cookies firmadas HMAC; demos de 24h autodestruibles</li>
  <li>PWA instalable con badge de alertas en el ícono</li>
  <li>Servido por Cloudflare Tunnel</li>
</ul></div>
</div></body></html>"""
    return doc.encode()


def vista_fuentes(email: str, msg: str = "") -> str:
    """Fuentes: todos eligen cuáles ver en su feed (checkboxes).
    Solo admin agrega/edita/borra del catálogo maestro y gestiona usuarios."""
    cfg = json.loads(CONFIG.read_text())
    perfil = perfil_usuario(email, cfg)
    ocultas = set(perfil.get("fuentes_ocultas", []))
    dep_on = set(perfil.get("deportes_visibles", []))
    admin = es_admin(email, cfg)
    estado = cargar_json(ESTADO_FUENTES, {})
    intervalo = cfg.get("intervalo", 15)
    cats = sorted({f.get("categoria", "prensa") for f in cfg["fuentes"]}
                  | {"prensa", "prensa_independiente", "nacional",
                     "deportes", "internacional", "oficial",
                     "quintana_roo", "columnas", "redes", "x"})

    # --- lista unificada: checkbox (mi feed) + dropdown de edición (admin) ---
    # los inputs de edición llevan form='sf{i}' → se envían con su propio
    # form aunque vivan dentro del form de selección (HTML lo permite)
    filas = ""
    forms_ocultos = ""
    # agrupar por categoría; i conserva el índice real en config["fuentes"]
    por_cat = {}
    for i, f in enumerate(cfg["fuentes"]):
        por_cat.setdefault(f.get("categoria", "prensa"), []).append((i, f))
    for cat in sorted(por_cat, key=lambda c: normalizar(c)):
        sources = por_cat[cat]
        cat_label = html.escape(cat.replace("_", " ").title())
        cat_attr = html.escape(cat, quote=True)
        cat_checked = " checked" if all(
            f["nombre"] not in ocultas
            and (cat != "deportes" or f["nombre"] in dep_on)
            for _, f in sources) else ""
        filas += (f"<details class='fuentes-cat'>"
                  f"<summary><input type='checkbox' class='cat-check' "
                  f"data-cat='{cat_attr}' "
                  f"onclick='event.stopPropagation()' "
                  f"onchange='selCat(this)'{cat_checked}>"
                  f" {cat_label} <span class='meta'>({len(sources)})</span>"
                  f" <a class='cat-solo' href='#' data-cat='{cat_attr}' "
                  f"onclick='event.stopPropagation(); soloCat(this.dataset.cat);return false'>"
                  f"solo</a></summary>")
        for i, f in sorted(sources, key=lambda t: normalizar(t[1]["nombre"])):
            edicion = ""
            if admin:
                opciones = "".join(
                    f"<option value='{c}'{' selected' if f.get('categoria') == c else ''}>{c}</option>"
                    for c in cats
                )
                edicion = f"""<details class="fuente-edit"><summary>Editar</summary>
    <label>Nombre del medio</label>
    <input form="sf{i}" type="text" name="nombre"
           value="{html.escape(f['nombre'], quote=True)}" required>
    <label>URL del RSS</label>
    <input form="sf{i}" type="text" name="url" inputmode="url"
           value="{html.escape(f['url'], quote=True)}" required>
    <label>Categoría</label>
    <select form="sf{i}" name="categoria" style="width:100%">{opciones}</select>
    <label>Página de Facebook <span class="meta">(opcional — chucky raspa sus posts)</span></label>
    <input form="sf{i}" type="text" name="fb" inputmode="url"
           placeholder="https://www.facebook.com/pagina"
           value="{html.escape(f.get('fb', ''), quote=True)}">
    <label>Filtro — solo notas que mencionen (vacío = pasa todo)</label>
    <input form="sf{i}" type="text" name="filtro" placeholder="tabasco, villahermosa"
           value="{html.escape(', '.join(f.get('solo_si_menciona', [])), quote=True)}">
    <div class="regla-pie">
      <button form="sf{i}" name="accion" value="editar">Guardar</button>
      <button form="sf{i}" class="btn-rojo" name="accion" value="borrar"
              onclick="return confirm('¿Quitar esta fuente para TODOS?')">Borrar</button>
    </div>
  </details>"""
                forms_ocultos += (
                    f"<form id='sf{i}' method='post' action='/fuentes'>"
                    f"<input type='hidden' name='idx' value='{i}'></form>")
            dot = ""
            if admin:
                es = estado.get(f["nombre"], {})
                last_ok = es.get("ultimo_ok", "")
                try:
                    ts_ok = datetime.fromisoformat(last_ok).timestamp()
                except Exception:
                    ts_ok = 0
                # dos ciclos de gracia antes de marcarla como caída
                roja = not last_ok or (
                    es.get("err", 0) and time.time() - ts_ok > intervalo * 60 * 2)
                dot = (f"<span class='dot {'dot-ok' if not roja else 'dot-err'}' "
                       f"title='{html.escape(last_ok or 'sin datos')}'>"
                       f"</span>")
            filas += f"""<div class="fuente-row">
  <label class="fuente-check"><input type="checkbox" name="ver"
      data-cat="{cat_attr}"
      value="{html.escape(f['nombre'], quote=True)}"
      onchange="syncUp()"
      {'' if f['nombre'] in ocultas
        or (f.get('categoria') == 'deportes'
            and f['nombre'] not in dep_on)
        else ' checked'}>
    {dot}{html.escape(f['nombre'])}
    <span class="meta"> · {html.escape(f.get('categoria', 'prensa'))}</span></label>
  {edicion}
</div>"""
        filas += "</details>"

    aviso = (f"<div class='card' style='border-left-color:#d32f2f'>"
             f"<b>URL rechazada:</b> {html.escape(msg)}</div>" if msg else "")
    todas_dep = all(f["nombre"] in dep_on for f in cfg["fuentes"]
                    if f.get("categoria") == "deportes")
    seleccion = f"""
<h1>Fuentes</h1>
{aviso}
<p class="meta">Marca los medios que quieres ver en Destacadas, Noticias
y Buscar. <b>Deportes viene apagada</b> — márquela si la quiere.</p>
<form method="post" action="/fuentes">
  <label class="fuente-check master"><input type="checkbox" id="sel-todo"
      {'checked' if not ocultas and todas_dep else ''}
      onclick="document.querySelectorAll('input[name=ver], .cat-check').forEach(c=>c.checked=this.checked)">
    <span class="meta">todas ({len(cfg['fuentes'])})</span></label>
  {filas}
  <p><button name="accion" value="seleccion">Guardar mi selección</button></p>
</form>
{forms_ocultos}""" + """
<script>
function selCat(input) {
  var cat = input.dataset.cat;
  document.querySelectorAll(
    'input[name=ver][data-cat="' + cat + '"]'
  ).forEach(function(c) { c.checked = input.checked; });
  syncUp();
}
function syncUp() {
  document.querySelectorAll('.cat-check').forEach(function(cat) {
    var kids = document.querySelectorAll(
      'input[name=ver][data-cat="' + cat.dataset.cat + '"]');
    cat.checked = kids.length > 0 &&
      Array.prototype.every.call(kids, function(c) { return c.checked; });
  });
  var all = document.querySelectorAll('input[name=ver]');
  var master = document.getElementById('sel-todo');
  if (master) master.checked = all.length > 0 &&
    Array.prototype.every.call(all, function(c) { return c.checked; });
}
function soloCat(cat) {
  document.querySelectorAll('input[name=ver]').forEach(function(c) { c.checked = false; });
  document.querySelectorAll(
    'input[name=ver][data-cat="' + cat + '"]'
  ).forEach(function(c) { c.checked = true; });
  syncUp();
}
</script>"""
    if not admin:
        return seleccion

    opciones_nueva = "".join(f"<option value='{c}'>{c}</option>" for c in cats)
    catalogo = f"""
<h2>Agregar fuente (admin)</h2>
<p class="meta">Alta aquí y aparece seleccionable para TODOS los usuarios.</p>
<div class="card regla" style="border-left-color:#2e7d32">
  <form method="post" action="/fuentes">
    <label>Nombre del medio</label>
    <input type="text" name="nombre" placeholder="Ej: Mural" required>
    <label>URL del RSS <span class="meta">(o la portada — se autodetecta; o <code>gn:tema</code>; o página de <b>Facebook</b> → la raspa chucky)</span></label>
    <input type="text" name="url" placeholder="https://…  o  gn:efraín tabasco  o  https://facebook.com/pagina" inputmode="url" required>
    <label>Página de Facebook <span class="meta">(opcional — si además del sitio tiene página)</span></label>
    <input type="text" name="fb" inputmode="url" placeholder="https://www.facebook.com/pagina">
    <label>Categoría</label>
    <select name="categoria" style="width:100%">{opciones_nueva}</select>
    <label>Filtro — solo notas que mencionen (opcional)</label>
    <input type="text" name="filtro" placeholder="tabasco, villahermosa">
    <div class="regla-pie">
      <button name="accion" value="agregar">Agregar fuente</button>
    </div>
  </form>
</div>"""

    # --- usuarios registrados (solo admin): una tarjeta por perfil ---
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
  <span class="meta"> · {len(u.get('reglas', []))} reglas · {tipo} · {html.escape(etiqueta)}</span>
  {form}
</div>"""
    gestion = f"""
<h2>Usuarios (admin)</h2>
<p class="meta">Perfiles con acceso por login. "demo" = perfil temporal
que se autodestruye al expirar.</p>
<div class="card regla" style="border-left-color:#2e7d32">
  <strong>Crear usuario</strong>
  <form method="post" action="/usuarios">
    <label>Correo</label>
    <input type="email" name="email" placeholder="correo@ejemplo.com" required>
    <label>Contraseña inicial</label>
    <input type="text" name="password" required>
    <label>Proyectos <span class="meta">(equipos: solo ve alertas de sus proyectos — separa con coma si son varios)</span></label>
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

    return seleccion + catalogo + gestion


def vista_stats() -> str:
    """Estadísticas: totales, notas por fuente, por día, salud de feeds."""
    noticias = _noticias_cache()
    alertas = leer_jsonl(ALERTAS)
    estado = cargar_json(ESTADO_FUENTES, {})

    por_fuente = Counter(n["fuente"] for n in noticias)
    por_dia = Counter(n["fecha"][:10] for n in noticias)

    # link directo al medio: @cuenta → su X, medio configurado → su sitio
    cfg = json.loads(CONFIG.read_text())
    url_medio = {f["nombre"]: f["url"] for f in cfg.get("fuentes", [])
                 if not f["url"].startswith(("https://x.com/",
                                             "https://nitter"))}

    def celda_medio(fuente: str) -> str:
        nombre = html.escape(fuente)
        if fuente.startswith("@"):
            return (f'<a href="https://x.com/{fuente[1:]}" '
                    f'target="_blank">{nombre}</a>')
        if fuente in url_medio:
            return (f'<a href="{html.escape(url_medio[fuente])}" '
                    f'target="_blank">{nombre}</a>')
        return nombre

    filas_fuente = "".join(
        f"<tr><td>{celda_medio(fuente)}</td><td>{total}</td>"
        f"<td>{estado.get(fuente, {}).get('ok', 0)}</td>"
        f"<td>{estado.get(fuente, {}).get('err', 0)}</td>"
        f"<td>{fmt_fecha(estado.get(fuente, {}).get('ultimo_ok', '') or '-')}</td></tr>"
        for fuente, total in por_fuente.most_common()
    )
    filas_dia = "".join(
        f"<tr><td><a href='/noticias?dia={dia}'>{dia}</a></td>"
        f"<td>{total}</td></tr>"
        for dia, total in sorted(por_dia.items(), reverse=True)
    )

    return f"""
<h1>Estadísticas</h1>
<div class="card top">
  <span class="titulo">{len(noticias)} notas · {len(alertas)} alertas ·
  {len(por_fuente)} medios activos</span>
  <div class="meta">Retención: {RETENCION_TXT} (noticias/alertas) ·
  {RETENCION_VISTOS_DIAS} días (deduplicación)</div>
</div>
<h2>Por medio</h2>
<table class="fija"><tr><th>Medio</th><th>Notas</th><th>Feeds OK</th><th>Errores</th><th>Último OK</th></tr>
{filas_fuente}</table>
<h2>Por día</h2>
<table class="fija"><tr><th>Fecha</th><th>Notas</th></tr>
{filas_dia}</table>
<h2>Exportar</h2>
<p><a href="/exportar"><button>Descargar reporte completo (.txt)</button></a></p>"""


def exportar_reporte() -> bytes:
    """Registro completo en texto claro con formato: alertas + noticias."""
    noticias = _noticias_cache()
    alertas = leer_jsonl(ALERTAS)
    hoy = datetime.now().strftime("%Y-%m-%d %H:%M")

    txt = [f"@noticias — REPORTE DE MONITOREO", f"Generado: {hoy}",
           f"Ventana: {RETENCION_TXT}", "=" * 60, ""]

    txt += ["ALERTAS DISPARADAS", "-" * 60]
    por_regla = {}
    for a in alertas:
        por_regla.setdefault(a["reglas"], []).append(a)
    for regla, items in por_regla.items():
        txt.append(f"\n## {regla} ({len(items)} alertas)")
        for a in items:
            txt += [f"  [{fmt_fecha(a['fecha'])}] {a['fuente']}",
                    f"      {a['titulo']}", f"      {a['link']}"]
            if a.get("resumen_ia"):
                txt.append(f"      → {a['resumen_ia']}")
    txt.append("")

    txt += ["TODAS LAS NOTAS CAPTURADAS", "-" * 60]
    por_fuente = {}
    for n in noticias:
        por_fuente.setdefault(n["fuente"], []).append(n)
    for fuente, items in sorted(por_fuente.items()):
        txt.append(f"\n## {fuente} ({len(items)} notas)")
        for n in items:
            txt += [f"  [{fmt_fecha(n['fecha'])}] {n['titulo']}",
                    f"      {n['link']}"]

    return "\n".join(txt).encode("utf-8")


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
    "description": "Monitor de prensa del TSJT: noticias, alertas y síntesis ejecutivas",
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


def vista_acerca() -> str:
    """Página 'Acerca de': versión, crédito, arquitectura y estado de datos."""
    try:
        act = fmt_fecha(datetime.fromtimestamp(
            NOTICIAS.stat().st_mtime).isoformat())
    except Exception:
        act = "-"

    def peso(path: Path) -> str:
        if not path.exists():
            return "-"
        kb = path.stat().st_size / 1024
        return f"{kb:.0f} KB" if kb < 1024 else f"{kb/1024:.1f} MB"

    archivos = "".join(
        f"<tr><td>{nombre}</td><td>{peso(p)}</td>"
        f"<td>{len(leer_jsonl(p)) if p.suffix == '.jsonl' else '-'}</td></tr>"
        for nombre, p in [
            ("noticias.jsonl", NOTICIAS), ("alertas.jsonl", ALERTAS),
            ("vistos.json", VISTOS), ("clusters.json", CLUSTERS),
            ("config.json", CONFIG),
        ]
    )
    cfg = json.loads(CONFIG.read_text())
    usuarios = cargar_usuarios()
    total_reglas = sum(len(u.get("reglas", [])) for u in usuarios.values())
    return f"""
<h1>@noticias <span class="meta">v{VERSION} — MVP</span></h1>
<p class="meta">Síntesis de prensa digital con alertas en tiempo real.<br>
Hecho con: 1 archivo Python + feedparser + requests + JSONL en disco.
Mucho con muy poco.<br>
Powered by <a href="https://olmecacode.pages.dev/" target="_blank" rel="noopener"><strong>Olmeca Code</strong></a>.</p>

<div class="card top">
  <span class="titulo">Arquitectura</span>
  <div class="meta" style="margin-top:.4rem">
    Scraper RSS (feedparser) cada 15 min → noticias.jsonl →<br>
    clustering por similitud de titulares (Jaccard) → destacadas ·<br>
    detección de noticia en desarrollo por crecimiento de cluster ·<br>
    reglas de alerta por coincidencia de palabras (mín. 2) ·<br>
    resúmenes opcionales con Ollama local (llama3.2) ·<br>
    webapp: http.server multi-hilo, cero dependencias web ·<br>
    retención: {RETENCION_TXT} noticias/alertas · {RETENCION_VISTOS_DIAS} días dedupe
  </div>
</div>

<h2>Base de datos</h2>
<p class="meta">JSONL en disco — cero motor externo. Última captura: {act}</p>
<table class="fija"><tr><th>Archivo</th><th>Tamaño</th><th>Registros</th></tr>
{archivos}</table>

<h2>Monitoreo</h2>
<p class="meta">{len(cfg['fuentes'])} fuentes RSS · {len(usuarios)} usuarios
· {total_reglas} reglas de alerta (todas las cuentas)
· {len(cfg.get('seguir_autores', []))} autores seguidos</p>"""


def vista_analitica() -> str:
    """Panel admin: quién entró, cuánto estuvo, qué notas abrió.
    Sesión = secuencia de hits con <30 min entre ellos; tiempo ≈ suma de
    gaps (cada gap se corta a 5 min para no inflar lecturas largas)."""
    titulos = {n["link"]: n["titulo"]
               for n in leer_jsonl(NOTICIAS, limite=MAX_NOTICIAS)}
    eventos = leer_jsonl(ACTIVIDAD, limite=20000)
    por_usuario = {}
    for e in eventos:
        por_usuario.setdefault(e["email"] or "(anónimos)", []).append(e)

    def resumen(evs):
        """Sesiones, minutos, notas, búsquedas y referrers de un usuario."""
        ts = sorted(datetime.fromisoformat(e["ts"]) for e in evs)
        sesiones, mins = 1, 0.0
        for a, b in zip(ts, ts[1:]):
            gap = (b - a).total_seconds() / 60
            if gap > 30:
                sesiones += 1
            else:
                mins += min(gap, 5)
        notas = Counter(e["u"] for e in evs
                        if e["ruta"] == "/nota" and e["u"])
        busqs = [e["q"] for e in evs if e.get("q")]
        refs = Counter(
            urlparse(e["ref"]).netloc for e in evs
            if e.get("ref") and "unknownshoppers" not in e["ref"]
            and "localhost" not in e["ref"])
        return ts[0], ts[-1], sesiones, mins, notas, busqs, refs

    ahora = datetime.now()
    hoy = ahora.date()
    hace7 = ahora - timedelta(days=7)

    def fila(email, evs):
        primero, ultimo, ses, mins, notas, busqs, refs = resumen(evs)
        en_linea = (ahora - ultimo).total_seconds() < 600
        dot = ("<span style='color:#2e7d32' title='en línea'>●</span> "
               if en_linea else "")
        top_nota = notas.most_common(1)[0] if notas else None
        nota_txt = (f"<a class='variante meta' "
                    f"href='/nota?u={quote(top_nota[0], safe='')}' "
                    f"title='{html.escape(top_nota[0])}'>"
                    f"{html.escape(titulos.get(top_nota[0], '…')[:38])}"
                    f" ({top_nota[1]}×)</a>" if top_nota else "—")
        via = ", ".join(d for d, _ in refs.most_common(2)) or "—"
        return (f"<tr><td>{dot}{html.escape(email)}</td>"
                f"<td>{ses}</td><td>~{mins:.0f}</td>"
                f"<td>{sum(notas.values())}</td><td>{nota_txt}</td>"
                f"<td>{html.escape(', '.join(dict.fromkeys(busqs))[:40]) or '—'}"
                f"</td><td class='meta'>{html.escape(via)}</td>"
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
    busqs_7d = Counter(e["q"] for e in eventos_7d if e.get("q"))
    busqs_usuario = {}
    for e in eventos_7d:
        if e.get("q"):
            busqs_usuario.setdefault(e["q"], Counter()).update(
                [e.get("email") or "(anónimos)"])
    notas_por_usuario = {}
    for e in eventos:
        if e["ruta"] == "/nota" and e["u"]:
            notas_por_usuario.setdefault(e.get("email") or "(anónimos)", []).append(e)
    for u in notas_por_usuario:
        notas_por_usuario[u].sort(key=lambda x: x["ts"])
    notas_7d = Counter(e["u"] for e in eventos_7d if e["ruta"] == "/nota" and e["u"])
    refs_7d = Counter(
        urlparse(e["ref"]).netloc for e in eventos_7d
        if e.get("ref") and "unknownshoppers" not in e["ref"]
        and "localhost" not in e["ref"])
    usuarios = cargar_usuarios()

    def _fmt_alerta(r):
        nombre = r.get("nombre") or r.get("palabras") or "—"
        reqs = ", ".join(r.get("requiere_todas", []))
        return f"{nombre} ({reqs})" if reqs else nombre

    def _dot(color):
        c = html.escape(color or "#1a237e")
        return f"<span class='alert-dot' style='background:{c}'></span>"

    alertas_filas = []
    for email, datos in sorted(usuarios.items()):
        if "@demo.local" in email:
            continue
        reglas = datos.get("reglas", [])
        items = "".join(
            f"<li>{_dot(r.get('color', '#1a237e'))} "
            f"{html.escape(_fmt_alerta(r))}</li>"
            for r in reglas) or "<li class='meta'>—</li>"
        alertas_filas.append(
            f"<tr><td>{html.escape(email)}</td>"
            f"<td><ul class='alerts-items'>{items}</ul></td></tr>")
    alertas_card = (f'<div class="card top">'
                    f'<span class="meta">Alertas por usuario</span>'
                    f'<table class="fija alertas">'
                    f'<tr><th>Usuario</th><th>Alertas</th></tr>'
                    f'{"".join(alertas_filas)}</table></div>')

    visitas_hoy = len(eventos_hoy)
    busquedas_hoy = sum(1 for e in eventos_hoy if e.get("q"))
    notas_hoy = sum(1 for e in eventos_hoy if e["ruta"] == "/nota" and e["u"])

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
  <div class="kpi"><big>{busquedas_hoy}</big><span class="label">Búsquedas hoy</span></div>
  <div class="kpi"><big>{notas_hoy}</big><span class="label">Notas abiertas hoy</span></div>
</div>'''

    top_busqs = [
        (q, c, busqs_usuario[q].most_common(1)[0][0],
         busqs_usuario[q].most_common(1)[0][1])
        for q, c in busqs_7d.most_common(7)]

    def detalle_busq(q, u, uc):
        hits = sorted(
            (e for e in eventos_7d
             if e.get("q") == q and (e.get("email") or "(anónimos)") == u),
            key=lambda e: e["ts"])
        notas_u = notas_por_usuario.get(u, [])
        filas = []
        for s in hits:
            ts = datetime.fromisoformat(s["ts"])
            nxt = next((e for e in notas_u if e["ts"] > s["ts"]), None)
            if nxt:
                nts = datetime.fromisoformat(nxt["ts"])
                nota = nxt["u"]
                nota_txt = (f"<a class='variante' href='/nota?u={quote(nota, safe='')}'>"
                            f"{html.escape(titulos.get(nota, nota)[:45])}</a>")
                nota_hora = f"{nts:%H:%M}"
            else:
                nota_txt = "—"
                nota_hora = "sin nota"
            filas.append(f"<li class='meta'>{ts:%H:%M} &rarr; {nota_hora}: {nota_txt}</li>")
        return f"<ul class='busq-hits'>{''.join(filas)}</ul>"

    busqs_items = []
    for q, c, u, uc in top_busqs:
        det = detalle_busq(q, u, uc)
        busqs_items.append(
            f"<details class='busq-fila'>"
            f"<summary><span class='busq-quién'>{html.escape(u)}</span>"
            f"<span class='busq-q'>{html.escape(q)}</span>"
            f"<span class='busq-n'>{uc}</span></summary>"
            f"{det}</details>")
    busqs_card = (f'<div class="card top busqs-list">'
                  f'<div class="busqs-top"><span class="meta">Top búsquedas (7d)</span>'
                  f'<button type="button" onclick="var all=document.querySelectorAll(\'.busq-fila\'), abrir=Array.from(all).some(d=>!d.open); all.forEach(d=>d.open=abrir); this.textContent=abrir?\'Colapsar todo\':\'Expandir todo\'">Expandir todo</button></div>'
                  f'<div class="busq-header"><span class="busq-quién">Quién</span>'
                  f'<span class="busq-q">Búsqueda</span>'
                  f'<span class="busq-n">N</span></div>'
                  f'{"".join(busqs_items)}</div>')

    top_notas = [(titulos.get(u, u)[:45], c) for u, c in notas_7d.most_common(7)]
    tops = (f'<div class="mini-grid">'
            f'{busqs_card}'
            f'{mini_tabla("Top referrers (7d)", refs_7d.most_common(7))}'
            f'{mini_tabla("Top notas abiertas (7d)", top_notas)}'
            f'{alertas_card}</div>')
    panel = f"<h2>Últimos 7 días</h2>{kpi_grid}<h3>Actividad por día</h3>{chart}{tops}"

    tabla = """<div class="tabla-scroll"><table class="fija ana">
<tr><th>Usuario</th><th>Ses.</th><th>Min</th><th>Notas</th>
<th>Top nota</th><th>Buscó</th><th>Vía</th><th>Último</th></tr>
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


def render_pagina(contenido: str, q: str = "", base: str = "",
                  og_img: str = "",
                  usuario: str = "", og_title: str = "",
                  og_desc: str = "") -> bytes:
    cfg = json.loads(CONFIG.read_text())
    # Seguimiento (radar de perfiles FB) fuera del nav — las 38
    # fuentes fb están muertas (cuentas perdidas, fb_pausa);
    # la ruta sigue viva por URL para consultar el histórico
    admin_tabs = ('<a href="/horarios">Horarios</a>'
                  '<a href="/salud">Salud</a>'
                  '<a href="/stats">Stats</a>'
                  '<a href="/analitica">Analítica</a>'
                  if usuario and es_admin(usuario, cfg) else "")
    # guests (demo 24h): solo noticias/alertas/portadas — el producto
    # judicial (interés, columnas, síntesis, fuentes) es de pago
    # tab X oculto mientras la sesión está pausada
    tabs_reg = ('<a href="/telegram">TG</a>'
                '<a href="/columnas">Columnas</a>'
                '<a href="/interes">Interés</a>'
                '<a href="/resumenes">Resúmenes</a>'
                '<a href="/fuentes">Fuentes</a>'
                if "@demo.local" not in usuario else "")
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
                         tabs_reg=tabs_reg, usuario=html.escape(usuario),
                         usuario_html=html.escape(nombre_u),
                         og_title=html.escape(og_title or
                             "@noticias — Monitor de prensa TSJT"),
                         og_desc=html.escape(og_desc or
                             "Monitor de noticias del Poder Judicial de "
                             "Tabasco: prensa del Magistrado Presidente y "
                             "el TSJT, alertas por tema y síntesis "
                             "ejecutivas. Powered by Olmeca Code."),
                         og_img=html.escape(og_img or
                             f"{base}/og.png")).encode()


def aplicar_accion_fuentes(form: dict, email: str):
    """POST /fuentes: 'seleccion' guarda MI feed; agregar/editar/borrar
    del catálogo maestro solo admin."""
    cfg = json.loads(CONFIG.read_text())
    accion = form.get("accion", [""])[0]

    if accion == "seleccion" or not es_admin(email, cfg):
        if accion == "seleccion":
            usuarios = cargar_usuarios()
            perfil = usuarios.setdefault(
                email, {"reglas": [], "fuentes_ocultas": [], "expira": 0})
            vistas = set(form.get("ver", []))
            perfil["fuentes_ocultas"] = [
                f["nombre"] for f in cfg["fuentes"] if f["nombre"] not in vistas]
            # deportes es opt-in: se guarda la lista de las marcadas
            perfil["deportes_visibles"] = [
                f["nombre"] for f in cfg["fuentes"]
                if f.get("categoria") == "deportes"
                and f["nombre"] in vistas]
            guardar_usuarios(usuarios)
        return

    def datos_fuente():
        f = {
            "nombre": form.get("nombre", [""])[0].strip(),
            "url": form.get("url", [""])[0].strip(),
            "tipo": "rss",
            "categoria": form.get("categoria", ["prensa"])[0],
        }
        fb = form.get("fb", [""])[0].strip()
        if "facebook.com" in f["url"]:
            f["tipo"] = "fb"           # fuente que ES la página de FB
        elif f["url"].lower().startswith("x:") \
                or re.match(r"^https?://(www\.)?(x|twitter)\.com/",
                            f["url"]):
            f["tipo"] = "x"            # timeline de X vía Nitter
        elif fb and "facebook.com" in fb:
            f["fb"] = fb               # página FB complementaria
        filtro = [p.strip() for p in form.get("filtro", [""])[0].split(",") if p.strip()]
        if filtro:
            f["solo_si_menciona"] = filtro
        return f

    error = ""
    if accion == "agregar":
        f = datos_fuente()
        if f["nombre"] and (f["url"].startswith("http")
                            or f["url"].lower().startswith("x:")):
            if f["tipo"] == "fb":
                # página FB — no hay feed que resolver; chucky la raspa
                if f["url"] in {x["url"] for x in cfg["fuentes"]}:
                    error = "esa fuente ya está en el catálogo"
                else:
                    cfg["fuentes"].append(f)
            else:
                url_ok, tipo, error = resolver_feed(f["url"])
                if url_ok and url_ok in {x["url"] for x in cfg["fuentes"]}:
                    error = "esa fuente ya está en el catálogo"
                    url_ok = None
                if url_ok:
                    f["url"], f["tipo"] = url_ok, tipo
                    cfg["fuentes"].append(f)
            if f.get("tipo") == "x" and url_ok != "x:home":
                # el handle entra a la lista blanca del tab /x — los
                # posts se atribuyen a @autor y sin esto no se ven
                h = _handle_x(url_ok or f["url"])
                if h and h not in cfg.setdefault("x_permitidos", []):
                    cfg["x_permitidos"].append(h)
        else:
            error = "nombre y URL http(s) obligatorios"
    elif accion == "editar":
        try:
            idx = int(form.get("idx", ["-1"])[0])
            f = datos_fuente()
            # el form no edita estos flags — conservar los que traía
            for flag in ("activa", "expandir", "perfil"):
                if cfg["fuentes"][idx].get(flag) is not None:
                    f[flag] = cfg["fuentes"][idx][flag]
            if f["nombre"] and (f["url"].startswith("http")
                                or f["url"].lower().startswith("x:")):
                if f["tipo"] == "fb":
                    if f["url"] in {
                            x["url"] for j, x in enumerate(cfg["fuentes"])
                            if j != idx}:
                        error = "esa fuente ya está en el catálogo"
                    else:
                        cfg["fuentes"][idx] = f
                else:
                    url_ok, tipo, error = resolver_feed(f["url"])
                    if url_ok and url_ok in {
                            x["url"] for j, x in enumerate(cfg["fuentes"])
                            if j != idx}:
                        error = "esa fuente ya está en el catálogo"
                        url_ok = None
                    if url_ok:
                        f["url"], f["tipo"] = url_ok, tipo
                        cfg["fuentes"][idx] = f
        except (ValueError, IndexError):
            pass
    elif accion == "borrar":
        try:
            del cfg["fuentes"][int(form.get("idx", ["-1"])[0])]
        except (ValueError, IndexError):
            pass
    _escribir_json(CONFIG, cfg)
    # alta/cambio de fuente → ciclo inmediato para verla ya en el feed
    if not error:
        threading.Thread(target=ciclo_ahora, daemon=True).start()
    return error


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


def backfill_regla(regla: dict, email: str) -> int:
    """Al crear/editar una regla, revisa las noticias YA guardadas y
    registra alertas retroactivas DEL USUARIO (sin notificar ni correo).
    Devuelve cuántas coincidencias históricas se agregaron."""
    ya = {(a["link"], a["reglas"], a.get("usuario", ""))
          for a in leer_jsonl(ALERTAS)}
    n = 0
    with ALERTAS.open("a") as f:
        for nota in _noticias_cache():
            if (nota["link"], regla["nombre"], email) in ya:
                continue
            texto = (f"{nota['titulo']} {nota.get('resumen', '')} "
                     f"{nota.get('autor', '')}")
            # project-first: regla personal = libre; compartida = interés
            if coincide(texto, regla) and (
                    not regla.get("proyecto")
                    or coincide_interes(nota)):
                alerta = {
                    "fecha": nota["fecha"],
                    "fuente": nota["fuente"],
                    "via": nota.get("via", ""),
                    "categoria": nota.get("categoria", "prensa"),
                    "autor": nota.get("autor", ""),
                    "reglas": regla["nombre"],
                    "titulo": nota["titulo"],
                    "link": nota["link"],
                    "imagen": nota.get("imagen", ""),
                    "resumen_ia": "",
                    "usuario": email,
                }
                f.write(json.dumps(alerta, ensure_ascii=False) + "\n")
                ya.add((nota["link"], regla["nombre"], email))
                n += 1
    # UN solo correo-digest con el batch — el usuario pidió '1 solo
    # correo con todo el batch de resultados' al crear la alerta;
    # en vivo ya va un correo por cada alerta nueva
    if n:
        _enviar_digest_regla(regla, email, n)
    # al admin siempre le llega aviso de regla creada — aunque el
    # batch salga en 0 (así ve qué andan monitoreando los usuarios)
    _aviso_admin_regla(regla, email, n)
    return n


def _aviso_admin_regla(regla: dict, email: str, n: int) -> None:
    """Correo al admin cada vez que un usuario crea/edita una alerta —
    quien evalúa el sistema queda al tanto de qué reglas se dan de
    alta, quién las hizo y cuánto material de interés traen."""
    cfg = cargar_json(CONFIG, {})
    correo = cfg.get("correo", {})
    if not correo.get("habilitado"):
        return
    admins = [a for a in cfg.get("admins", []) if "@" in a]
    if not admins:
        return
    try:
        cuerpo = (
            f"{email} creó/editó la alerta «{regla['nombre']}».\n\n"
            f"Términos: {' + '.join(regla.get('requiere_todas', []))}\n"
            f"Coincidencias en el archivo: {n}\n\n"
                "Reglas PERSONALES disparan por palabras tal cual; "
                "reglas COMPARTIDAS de proyecto exigen que la nota "
                "también sea de interés del proyecto.")
        msg = MIMEText(cuerpo, "plain", "utf-8")
        msg["Subject"] = (f"[Monitor] Nueva alerta de "
                          f"{email.split('@')[0]}: «{regla['nombre']}» "
                          f"({n} coincidencias)")
        msg["From"] = correo.get("remitente", correo["usuario"])
        msg["To"] = ", ".join(admins)
        _mandar_msg(correo, msg)
        print(f"    ✉ aviso de regla → admin ({n} notas)")  # noqa
    except Exception as e:
        print(f"    [!] aviso de regla falló: {e}")


def _enviar_digest_regla(regla: dict, email: str, n: int) -> None:
    """Un solo correo-resumen al crear/editar la regla con el total
    de coincidencias de interés halladas en el archivo."""
    correo = cargar_json(CONFIG, {}).get("correo", {})
    if not correo.get("habilitado") or "@" not in email:
        return
    try:
        # las últimas 15 coincidencias de la regla para que el correo
        # enseñe de qué trata sin volverse un muro
        muestra = [a for a in leer_jsonl(ALERTAS, limite=400)
                   if a.get("usuario") == email
                   and a.get("reglas") == regla["nombre"]][-15:]
        cuerpo = (
            f"Tu regla «{regla['nombre']}» encontró {n} nota(s) de "
            "interés en el archivo del monitor.\n\n"
            + "\n".join(
                f"• {a['fecha'][:10]} — {a['titulo']}\n  {a['link']}"
                for a in muestra)
            + (f"\n\n… y {n - len(muestra)} más en el tab Alertas del "
               "monitor." if n > len(muestra) else "")
            + "\n\nA partir de ahora te llegará un correo por cada "
              "alerta nueva que dispare la regla.")
        msg = MIMEText(cuerpo, "plain", "utf-8")
        msg["Subject"] = (f"[Monitor] «{regla['nombre']}»: "
                          f"{n} coincidencias de interés")
        msg["From"] = correo.get("remitente", correo["usuario"])
        msg["To"] = email
        _mandar_msg(correo, msg)
        print(f"    ✉ digest de regla → {email} ({n} notas)")
    except Exception as e:
        print(f"    [!] digest de regla falló: {e}")


def aplicar_accion_config(form: dict, email: str) -> str:
    """POST /config: agregar, editar o borrar reglas de alerta DEL USUARIO.
    Devuelve la ruta a donde redirigir (/alertas tras agregar, para ver
    las coincidencias históricas al instante)."""
    cfg = json.loads(CONFIG.read_text())
    usuarios = cargar_usuarios()
    perfil = usuarios.setdefault(
        email, {"reglas": [], "fuentes_ocultas": [], "expira": 0})
    accion = form.get("accion", [""])[0]
    # la demo (guest, expira>0) es solo lectura: no toca reglas
    if perfil.get("expira"):
        return "/config"
    destino = "/config"
    # alcance de la regla: solo se acepta un proyecto del que el
    # usuario es miembro (nadie mete alertas a un proyecto ajeno)
    proy = form.get("proyecto", [""])[0].strip().lower()
    if proy not in proyectos_usuario(email):
        proy = ""
    if accion == "agregar":
        nombre = form.get("nombre", [""])[0].strip()
        palabras = [p.strip() for p in form.get("palabras", [""])[0].split(",") if p.strip()]
        # mínimo 2 palabras/frases: una sola dispara ruido puro
        if nombre and len(palabras) >= 2:
            regla = {"nombre": nombre, "requiere_todas": palabras,
                     "color": form.get("color", [""])[0],
                     "proyecto": proy}
            perfil["reglas"].append(regla)
            n = backfill_regla(regla, email)
            destino = f"/alertas?msg={n}"
    elif accion == "borrar":
        try:
            del perfil["reglas"][int(form.get("idx", ["-1"])[0])]
        except (ValueError, IndexError):
            pass
    elif accion == "editar":
        try:
            idx = int(form.get("idx", ["-1"])[0])
            nombre = form.get("nombre", [""])[0].strip()
            palabras = [p.strip() for p in form.get("palabras", [""])[0].split(",") if p.strip()]
            if nombre and len(palabras) >= 2:
                regla = {"nombre": nombre, "requiere_todas": palabras,
                         "color": form.get("color", [""])[0],
                         "proyecto": proy}
                perfil["reglas"][idx] = regla
                n = backfill_regla(regla, email)
                destino = f"/alertas?msg={n}"
        except (ValueError, IndexError):
            pass
    guardar_usuarios(usuarios)
    if accion in ("agregar", "editar"):
        # aplica al instante: backfill ya quedó; un ciclo revisa noticias nuevas
        threading.Thread(target=ciclo_ahora, daemon=True).start()
    return destino


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
            # Los assets no cuentan: la página de portadas sola son ~40
            # requests legítimas de imágenes por carga.
            es_asset = re.search(r"\.(?:png|jpe?g|webp|gif|svg|ico|"
                                 r"css|js|woff2?)$", ruta.path, re.I)
            if not email and not es_asset and not ratelimit_ok(ip):
                self._html("<h1 style='font-family:system-ui;padding:2rem'>"
                           "Demasiadas solicitudes — espera un minuto.</h1>"
                           .encode(), 429)
                return
            if (ruta.path not in ("/icon.png", "/icon3.png", "/og.png",
                                  "/manifest.webmanifest", "/badge",
                                  "/sw.js", "/captura.png")
                    and not ruta.path.startswith("/shots/")):
                registrar_actividad(
                    email, ruta.path, params.get("u", [""])[0],
                    self.headers.get("Referer", ""),
                    params.get("q", [""])[0] if ruta.path == "/buscar"
                    else "")
            # invitados demo: sin secciones del producto judicial —
            # escribir la URL a mano no las abre
            if (email and "@demo.local" in email
                    and ruta.path in ("/interes", "/columnas",
                                      "/resumenes", "/fuentes")):
                self.send_response(303)
                self.send_header("Location", "/noticias")
                self.end_headers()
                return
            if not email and ruta.path == "/":
                # anónimo en la raíz: la landing es la cara del producto
                self._html(vista_landing(base))
                return
            if ruta.path == "/propuesta":
                # propuesta de servicio TSJ — documento público con
                # botón de descarga PDF (sin sesión)
                doc = BASE / "propuesta_portadas.html"
                if doc.exists():
                    self.send_response(200)
                    self.send_header("Content-Type",
                                     "text/html; charset=utf-8")
                    self.end_headers()
                    self.wfile.write(doc.read_bytes())
                else:
                    self.send_error(404)
                return
            if not email and not (
                    ruta.path in ("/icon.png", "/icon3.png", "/og.png",
                                  "/manifest.webmanifest", "/sw.js",
                                  "/nota",
                                  "/instructivo", "/captura", "/propuesta",
                                  "/portadas")
                    or ruta.path.startswith(("/shots/", "/portadas/",
                                             "/brand/"))):
                if ruta.path in ("/portadas-pdf",
                                 "/resumenes-pdf"):
                    self._html(
                        "<div style='font-family:system-ui;padding:3rem;"
                        "text-align:center'><h1>Disponible para usuarios "
                        "registrados</h1><p class='meta'>La descarga de "
                        "PDF requiere credenciales.</p>"
                        "<a href='/'>Iniciar sesión</a></div>")
                else:
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
            elif ruta.path == "/destacadas":
                self._html(render_pagina(
                    vista_destacadas(email, params.get("cat", [""])[0]),
                    base=base, usuario=email,
                    og_title="Destacadas — @noticias",
                    og_desc="Los temas que dominan la conversación "
                            "mediática del día."))
            elif ruta.path == "/alertas":
                msg = params.get("msg", [""])[0]
                self._html(render_pagina(vista_alertas(email, msg),
                                         base=base, usuario=email))
                # ya las vio: el contador del ícono vuelve a 0
                _marcar_visto(email, "visto_alertas")
            elif ruta.path == "/noticias":
                try:
                    p = int(params.get("p", ["1"])[0])
                except (ValueError, IndexError):
                    p = 1
                dia = params.get("dia", [""])[0]
                if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", dia):
                    dia = ""
                self._html(render_pagina(
                    vista_noticias(email, p, dia), base=base,
                    usuario=email,
                    og_title="Noticias — @noticias",
                    og_desc="Feed general de la prensa monitoreada, "
                            "en tiempo real."))
                _marcar_visto(email, "visto_noticias")
            elif ruta.path == "/x":
                self._html(render_pagina(
                    "<h1>Radar X</h1>"
                    "<p class='meta'>Sección temporalmente oculta.</p>",
                    base=base, usuario=email,
                    og_title="Radar X — @noticias",
                    og_desc="Sección temporalmente oculta."))
            elif ruta.path == "/telegram":
                self._html(render_pagina(
                    vista_telegram(email), base=base, usuario=email,
                    og_title="Telegram — @noticias",
                    og_desc="Mensajes de los canales de Telegram "
                            "monitoreados."))
                _marcar_visto(email, "visto_telegram")
            elif ruta.path == "/seguimiento":
                # sección en prueba — solo admin mientras afinamos
                # el filtro de seguimientos
                if not es_admin(email, json.loads(
                        CONFIG.read_text())):
                    self.send_response(303)
                    self.send_header("Location", "/noticias")
                    self.end_headers()
                    return
                try:
                    p = int(params.get("p", ["1"])[0])
                except (ValueError, IndexError):
                    p = 1
                self._html(render_pagina(
                    vista_seguimiento(email, p), base=base,
                    usuario=email))
                _marcar_visto(email, "visto_seguimiento")
            elif ruta.path == "/buscar":
                q = params.get("q", [""])[0]
                self._html(render_pagina(
                    vista_buscar(q, email,
                                 deep=params.get("deep", [""])[0] == "1"),
                    q=q, base=base, usuario=email))
            elif ruta.path == "/config":
                self._html(render_pagina(vista_config(email), base=base,
                                         usuario=email))
            elif ruta.path == "/fuentes":
                msg = params.get("msg", [""])[0]
                self._html(render_pagina(vista_fuentes(email, msg), base=base,
                                         usuario=email))
            elif ruta.path in ("/schedule", "/schedule.html"):
                doc = BASE / "schedule.html"
                if doc.exists():
                    self.send_response(200)
                    self.send_header("Content-Type",
                                     "text/html; charset=utf-8")
                    self.send_header("Cache-Control", "no-store")
                    self.end_headers()
                    self.wfile.write(doc.read_bytes())
                else:
                    self.send_error(404)
            elif ruta.path == "/horarios":
                cfg_h = json.loads(CONFIG.read_text())
                if not es_admin(email, cfg_h):
                    self._html(render_pagina("<h1>Solo admin</h1>",
                                             base=base, usuario=email))
                else:
                    # el editor es schedule.html — se regenera en cada
                    # GET para que la línea de tiempo esté al momento
                    escribir_schedule_portadas(cfg_h)
                    doc = BASE / "schedule.html"
                    if doc.exists():
                        self.send_response(200)
                        self.send_header("Content-Type",
                                         "text/html; charset=utf-8")
                        self.send_header("Cache-Control", "no-store")
                        self.end_headers()
                        self.wfile.write(doc.read_bytes())
                    else:
                        self.send_error(404)
            elif ruta.path == "/salud":
                # diagnóstico del sistema — solo admin
                if not es_admin(email, json.loads(
                        CONFIG.read_text())):
                    self._html(render_pagina("<h1>Solo admin</h1>",
                                             base=base, usuario=email))
                else:
                    self._html(render_pagina(vista_salud(),
                                             base=base, usuario=email))
            elif ruta.path == "/columnas":
                self._html(render_pagina(vista_columnas(email),
                                         base=base, usuario=email,
                                         og_title="Columnas — @noticias",
                                         og_desc="Opinión y columnas de la prensa "
                                                 "monitoreada."))
            elif ruta.path == "/interes":
                self._html(render_pagina(vista_interes(
                    email, int(params.get("p", ["1"])[0])),
                    base=base, usuario=email,
                    og_title="Interés — @noticias",
                    og_desc="Agenda de prensa del TSJT: notas del "
                            "Magistrado Presidente, el Poder Judicial "
                            "y actores clave.",
                    og_img=f"{base}/brand/01int.jpg"))
                _marcar_visto(email, "visto_interes")
            elif ruta.path == "/resumenes":
                self._html(render_pagina(vista_resumenes(
                    email, params.get("msg", [""])[0],
                    params.get("dia", [""])[0]),
                    base=base, usuario=email,
                    og_title="Síntesis — @noticias",
                    og_desc="Síntesis ejecutivas de prensa: mediodía, "
                            "cierre, semanal y dominical, con citas a "
                            "cada nota.",
                    og_img=f"{base}/brand/01res.jpg"))
            elif ruta.path == "/resumenes/reporte":
                # reporte imprimible: para todos los registrados —
                # paolo imprime las tarjetas para su entrega diaria;
                # fuera solo demo/anónimo
                if not email or "@demo.local" in email:
                    self.send_response(303)
                    self.send_header("Location", "/resumenes")
                    self.end_headers()
                    return
                doc = vista_reporte_resumenes(
                    params.get("sel", []),
                    admin=es_admin(email, json.loads(
                        CONFIG.read_text())))
                if params.get("fmt", [""])[0] == "png":
                    png = _reporte_png(doc)
                    if png:
                        self.send_response(200)
                        self.send_header("Content-Type", "image/png")
                        self.send_header(
                            "Content-Disposition",
                            'attachment; filename="sintesis_'
                            + datetime.now().strftime("%Y%m%d_%H%M")
                            + '.png"')
                        self.end_headers()
                        self.wfile.write(png)
                    else:
                        self._html(doc)   # fallback al HTML imprimible
                else:
                    self._html(doc)
            elif ruta.path == "/portadas-pdf":
                # PDF 'en vivo': se arma al momento con todo lo que ya
                # cayó en el día — distinto del snapshot enviado 06:30
                cfg_p = json.loads(CONFIG.read_text())
                sec = params.get("sec", ["tabasco"])[0]
                dia_s = params.get("dia", [""])[0]
                dir_d = (PORTADAS_DIR / dia_s
                         if re.fullmatch(r"[a-z]{3}/\d{2}", dia_s)
                         else _dir_dia())
                data, _f = _armar_pdf_portadas(
                    cfg_p.get("portadas", {}).get("medios", []),
                    sec, dir_d)
                if data:
                    self.send_response(200)
                    self.send_header("Content-Type", "application/pdf")
                    _nom_dia = dia_s.replace("/", "-") or \
                        datetime.now().strftime("%Y-%m-%d")
                    self.send_header(
                        "Content-Disposition",
                        f'inline; filename="portadas_{sec}_'
                        f'{_nom_dia}.pdf"')
                    self.send_header("Cache-Control", "no-store")
                    self.end_headers()
                    self.wfile.write(data)
                else:
                    self.send_error(404)
            elif ruta.path == "/resumenes-pdf":
                # reporte express del día — solo paolo y admin;
                # async: arranca hilo, la UI consulta estado y puede
                # cancelar (el resultado del LLM se desecha)
                cfg_r = json.loads(CONFIG.read_text())
                if not (es_admin(email, cfg_r)
                        or email == "paolo@anoticias.com"):
                    self._html(
                        "<div style='font-family:system-ui;padding:3rem;"
                        "text-align:center'><h1>Solo personal "
                        "autorizado</h1><p class='meta'>El reporte "
                        "express está reservado para dirección y "
                        "administración.</p>"
                        "<a href='/resumenes'>Volver</a></div>")
                    return
                st_r = _REPORTE_EXPRESS.get(email, {})
                op = params.get("op", [""])[0]
                if op == "estado":
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Cache-Control", "no-store")
                    self.end_headers()
                    self.wfile.write(json.dumps(
                        {"e": st_r.get("estado", "idle")}).encode())
                elif op == "cancelar":
                    st_r["estado"] = "cancelado"
                    st_r["pdf"] = None
                    self.send_response(303)
                    self.send_header("Location", "/resumenes")
                    self.end_headers()
                elif op == "descargar":
                    if st_r.get("estado") == "listo" and \
                            st_r.get("pdf"):
                        self.send_response(200)
                        self.send_header("Content-Type",
                                         "application/pdf")
                        self.send_header(
                            "Content-Disposition",
                            'inline; filename="reporte_express_'
                            f'{datetime.now().strftime("%Y-%m-%d")}'
                            '.pdf"')
                        self.send_header("Cache-Control", "no-store")
                        self.end_headers()
                        self.wfile.write(st_r["pdf"])
                        st_r.clear()   # consumo único
                    else:
                        self.send_response(303)
                        self.send_header("Location", "/resumenes-pdf")
                        self.end_headers()
                else:
                    if st_r.get("estado") != "generando":
                        _REPORTE_EXPRESS[email] = {
                            "estado": "generando", "pdf": None}
                        threading.Thread(
                            target=_worker_reporte_express,
                            args=(email, cfg_r), daemon=True,
                            name="reporte-express").start()
                    self._html(render_pagina(
                        _vista_reporte_progreso("generando"),
                        base=base, usuario=email))
            elif ruta.path == "/portadas":
                sec = params.get("sec", ["tabasco"])[0]
                self._html(render_pagina(
                    vista_portadas(sec, params.get("dia", [""])[0],
                                   admin=es_admin(email, json.loads(
                                       CONFIG.read_text())),
                                   logueado=bool(email)),
                    base=base, usuario=email,
                    og_title="Portadas de prensa — Nacional y Tabasco",
                    og_desc="Primeras planas de diarios nacionales y de "
                            "Tabasco, actualizadas cada mañana.",
                    og_img=f"{base}/brand/01port.jpg"))
            elif ruta.path.startswith("/portadas/"):
                p = (PORTADAS_DIR / ruta.path.split("/", 2)[2]).resolve()
                tipos = {".png": "image/png", ".jpg": "image/jpeg",
                         ".jpeg": "image/jpeg", ".pdf": "application/pdf"}
                raiz = PORTADAS_DIR.resolve()
                if p.suffix == ".pdf" and not email:
                    # descarga de PDF solo con credenciales
                    self._html(
                        "<div style='font-family:system-ui;padding:3rem;"
                        "text-align:center'><h1>Disponible para usuarios "
                        "registrados</h1><p class='meta'>La descarga del "
                        "PDF de portadas requiere credenciales.</p>"
                        "<a href='/'>Iniciar sesión</a></div>")
                elif p.is_relative_to(raiz) and p != raiz \
                        and p.is_file() and p.suffix in tipos:
                    self.send_response(200)
                    self.send_header("Content-Type", tipos[p.suffix])
                    self.send_header("Cache-Control", "max-age=300")
                    self.end_headers()
                    self.wfile.write(p.read_bytes())
                else:
                    self.send_error(404)
            elif ruta.path == "/stats" or ruta.path == "/analitica":
                cfg_g = json.loads(CONFIG.read_text())
                if not es_admin(email, cfg_g):
                    self._html(render_pagina(
                        "<h1>Solo admin</h1>", base=base, usuario=email), 403)
                elif ruta.path == "/stats":
                    self._html(render_pagina(vista_stats(), base=base,
                                             usuario=email))
                else:
                    self._html(render_pagina(vista_analitica(), base=base,
                                             usuario=email))
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
            elif ruta.path.startswith("/shots/"):
                p = (BASE / ruta.path.lstrip("/")).resolve()
                if p.parent == (BASE / "shots") and p.suffix == ".png" \
                        and p.exists():
                    self.send_response(200)
                    self.send_header("Content-Type", "image/png")
                    self.send_header("Cache-Control",
                                     "public, max-age=3600")
                    self.end_headers()
                    self.wfile.write(p.read_bytes())
                else:
                    self.send_error(404)
            elif ruta.path == "/acerca":
                self._html(render_pagina(vista_acerca(), base=base,
                                         usuario=email))
            elif ruta.path == "/nota":
                u = params.get("u", [""])[0]
                if not u:
                    self._html(render_pagina("<h1>Sin URL</h1>", base=base,
                                             usuario=email))
                elif email:
                    es_real = "@demo.local" not in email
                    nota, _ = vista_nota(u, captura=es_real)
                    self._html(render_pagina(nota, base=base, usuario=email))
                else:
                    # vista pública — el enlace compartido ES la publicidad
                    self._html(vista_nota_publica(u, base))
            elif ruta.path == "/captura":
                u = params.get("u", [""])[0]
                if not u:
                    self._html(render_pagina("<h1>Sin URL</h1>", base=base,
                                             usuario=email))
                else:
                    self._html(vista_captura(u))
            elif ruta.path == "/captura.png":
                u = params.get("u", [""])[0]
                if not u:
                    self.send_error(400)
                    return
                if not email or "@demo.local" in email:
                    self._html(render_pagina(
                        "<h1>Solo usuarios registrados</h1>",
                        base=base, usuario=email), 403)
                    return
                try:
                    png = captura_png(u)
                except Exception as e:
                    self._html(render_pagina(
                        f"<h1>Error al generar captura</h1>"
                        f"<p class='meta'>{html.escape(str(e))}</p>",
                        base=base, usuario=email), 500)
                    return
                dominio = urlparse(u).netloc or "noticia"
                nombre = f"captura_{dominio.replace('/', '_')}_{datetime.now():%Y%m%d_%H%M%S}.png"
                self.send_response(200)
                self.send_header("Content-Type", "image/png")
                self.send_header("Content-Disposition",
                                 f'attachment; filename="{nombre}"')
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(png)
            elif ruta.path == "/exportar":
                cfg = json.loads(CONFIG.read_text())
                perfil = perfil_usuario(email, cfg)
                if perfil.get("expira"):
                    self._html(render_pagina(
                        "<h1>Solo usuarios</h1>"
                        "<p class='meta'>El reporte es para usuarios "
                        "registrados — pide una cuenta al admin.</p>",
                        base=base, usuario=email), 403)
                    return
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Disposition",
                                 "attachment; filename=noticias_reporte.txt")
                self.end_headers()
                self.wfile.write(exportar_reporte())
            elif ruta.path == "/badge":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(
                    json.dumps(badge_counts(email)).encode())
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
            # auth: 10 intentos/min — frena fuerza bruta y farm de invitados
            limite = 10 if ruta.path in ("/login", "/invitado") else 120
            if not ratelimit_ok(ip, limite=limite):
                self._html("<h1 style='font-family:system-ui;padding:2rem'>"
                           "Demasiadas solicitudes — espera un minuto.</h1>",
                           429)
                return
            largo = int(self.headers.get("Content-Length", 0))
            form = parse_qs(self.rfile.read(largo).decode()) if largo else {}
            https = self._base().startswith("https")

            if ruta.path == "/login":
                cfg = json.loads(CONFIG.read_text())
                email = form.get("email", [""])[0].strip().lower()
                pw = form.get("password", [""])[0]
                if email and password_valida(email, pw, cfg):
                    perfil_usuario(email, cfg)  # autocrear en el primer login
                    self.send_response(303)
                    self.send_header("Location",
                                     home_usuario(email))
                    self.send_header("Set-Cookie",
                                     cookie_sesion(email, https))
                    self.end_headers()
                else:
                    self._html(vista_login(self._base(),
                                           "Correo o contraseña "
                                           "incorrectos."))
                return
            if ruta.path == "/invitado":
                # cool-down por IP: la demo gratis no se puede re-pedir
                # en DEMO_BLOQUEO_MIN — sin esto bastaba dar POST otra vez
                ips = cargar_json(DEMO_IPS, {})
                resta = DEMO_BLOQUEO_MIN * 60 - (time.time() - ips.get(ip, 0))
                if resta > 0:
                    seg = int(resta)
                    self._html(render_pagina(
                        "<h1>Demo de invitado</h1>"
                        "<div class='card' style='text-align:center;padding:2rem'>"
                        "<p class='meta'>La sesión gratis ya se usó desde esta "
                        "conexión.</p>"
                        "<p style='font-size:2rem;font-weight:700;margin:.6rem 0'>"
                        "faltan <span id='cd'>--:--</span></p>"
                        "<p class='meta'>para renovar tu sesión de INVITADO</p>"
                        "</div>"
                        "<script>var s=" + str(seg) + ";"
                        "var e=document.getElementById('cd');"
                        "function t(){var m=Math.floor(s/60),x=s%60;"
                        "e.textContent=(m<10?'0':'')+m+':'+(x<10?'0':'')+x;"
                        "if(s>0){s--;setTimeout(t,1000);}}</script>"
                        "<script>t();</script>",
                        base=base))
                    return
                usuarios = cargar_usuarios()
                email = f"guest-{secrets.token_hex(4)}@demo.local"
                usuarios[email] = {
                    "reglas": [], "fuentes_ocultas": [],
                    "expira": time.time() + DEMO_MINUTOS * 60,
                    "password": "",
                }
                guardar_usuarios(usuarios)
                ips[ip] = time.time()
                _escribir_json(DEMO_IPS, ips)
                self.send_response(303)
                self.send_header("Location", home_usuario(email))
                self.send_header("Set-Cookie", cookie_sesion(email, https))
                self.end_headers()
                return

            if ruta.path == "/alertas/rastrear":
                email = self._usuario()
                if not email or "@demo.local" in email:
                    self.send_response(303)
                    self.send_header("Location", "/alertas")
                    self.end_headers()
                    return
                regla_nom = form.get("regla", [""])[0]
                cfg_r = json.loads(CONFIG.read_text())
                perfil = perfil_usuario(email, cfg_r)
                if (regla_nom in {r["nombre"]
                                  for r in perfil.get("reglas", [])}
                        and not _RASTREO.get(email, {}).get("en_curso")):
                    _RASTREO[email] = {"en_curso": True,
                                       "encontradas": 0,
                                       "regla": regla_nom,
                                       "estado": "rastreando"}
                    threading.Thread(
                        target=rastrear_archivo,
                        args=(email, regla_nom, cfg_r), daemon=True,
                        name="rastreo").start()
                self.send_response(303)
                self.send_header("Location", "/alertas")
                self.end_headers()
                return

            if ruta.path == "/resumenes/editar":
                email = self._usuario()
                cfg_e = json.loads(CONFIG.read_text())
                if not email or not es_supervisor(email, cfg_e):
                    self.send_response(303)
                    self.send_header("Location", "/resumenes")
                    self.end_headers()
                    return
                fecha_t = form.get("fecha", [""])[0]
                accion = form.get("accion", [""])[0]
                out = []
                for l in SINTESIS.read_text(
                        encoding="utf-8").splitlines():
                    try:
                        e = json.loads(l)
                    except Exception:
                        out.append(l)
                        continue
                    if e.get("fecha") == fecha_t:
                        if accion == "guardar":
                            e["texto"] = form.get("texto", [""])[0].strip()
                            out.append(json.dumps(e, ensure_ascii=False))
                        # 'borrar' → la línea simplemente no vuelve
                    else:
                        out.append(l)
                SINTESIS.write_text("\n".join(out) + "\n",
                                    encoding="utf-8")
                self.send_response(303)
                self.send_header("Location", "/resumenes")
                self.end_headers()
                return

            if ruta.path == "/interes/palabras":
                email = self._usuario()
                cfg_i = json.loads(CONFIG.read_text())
                if email and es_admin(email, cfg_i):
                    lista = form.get("lista", [""])[0]
                    term = form.get("termino", [""])[0].strip()
                    accion = form.get("accion", [""])[0]
                    listas_ok = {"fuertes", "siglas_fuertes",
                                 "debiles_tema", "siglas_tema",
                                 "debiles_actor", "tabasco", "ajenos"}
                    if lista in listas_ok and term:
                        inter = cfg_i.setdefault("interes", {})
                        extras = inter.setdefault(lista, [])
                        quitar = inter.setdefault("quitar_" + lista, [])
                        n_t = normalizar(term)
                        if accion == "agregar":
                            quitar[:] = [t for t in quitar
                                         if normalizar(t) != n_t]
                            if all(normalizar(t) != n_t
                                   for t in extras):
                                extras.append(term)
                        elif accion == "quitar":
                            if any(normalizar(t) == n_t for t in extras):
                                extras[:] = [t for t in extras
                                             if normalizar(t) != n_t]
                            else:
                                quitar.append(term)
                        _escribir_json(CONFIG, cfg_i)
                self.send_response(303)
                self.send_header("Location", "/interes")
                self.end_headers()
                return

            if ruta.path == "/resumenes/publicar-x":
                email = self._usuario()
                cfg_x = json.loads(CONFIG.read_text())
                if not email or not es_admin(email, cfg_x):
                    self.send_response(303)
                    self.send_header("Location", "/resumenes")
                    self.end_headers()
                    return
                texto_x = form.get("texto", [""])[0].strip()[:280]
                fecha_x = form.get("fecha", [""])[0]
                tipo_x = form.get("tipo", ["cierre"])[0]
                ok = texto_x and not _x_publicado(fecha_x, tipo_x) \
                    and _post_x(texto_x)
                with open(X_POSTS, "a", encoding="utf-8") as f:
                    f.write(json.dumps(
                        {"fecha": fecha_x, "texto": texto_x, "ok": ok,
                         "tipo": tipo_x,
                         "ts": datetime.now().isoformat(
                             timespec="seconds")},
                        ensure_ascii=False) + "\n")
                self.send_response(303)
                self.send_header("Location", "/resumenes")
                self.end_headers()
                return

            if ruta.path == "/resumenes/generar":
                email = self._usuario()
                if not email or "@demo.local" in email:
                    self.send_response(303)
                    self.send_header("Location", "/noticias")
                    self.end_headers()
                    return
                cfg_s = json.loads(CONFIG.read_text())
                if not es_admin(email, cfg_s):
                    self.send_response(303)
                    self.send_header("Location", "/resumenes")
                    self.end_headers()
                    return
                if form.get("franja", [""])[0] == "cierre":
                    if "cierre" not in _GENERANDO:
                        _GENERANDO.add("cierre")
                        threading.Thread(target=_gen_bg,
                                         args=(generar_cierre, "cierre",
                                               cfg_s),
                                         daemon=True, name="cierre").\
                            start()
                else:
                    h = datetime.now().hour
                    wd = datetime.now().weekday()
                    franja = ("semanal" if wd == 5 else
                              "dominical" if wd == 6 else
                              "mediodia" if h < 15 else "mediodia")
                    if franja not in _GENERANDO:
                        _GENERANDO.add(franja)
                        threading.Thread(target=_gen_bg,
                                         args=(generar_sintesis, franja,
                                               cfg_s, franja),
                                         daemon=True, name="sintesis").\
                            start()
                self.send_response(303)
                self.send_header(
                    "Location",
                    "/resumenes?msg=" + quote(
                        "Generando síntesis — recarga en ~1 minuto"))
                self.end_headers()
                return

            if ruta.path == "/portadas/recapturar":
                email = self._usuario()
                cfg_r = json.loads(CONFIG.read_text())
                if not email or not es_admin(email, cfg_r):
                    self.send_response(403)
                    self.end_headers()
                    return
                msg = _descartar_portada(
                    form.get("m", [""])[0])
                self.send_response(303)
                self.send_header("Location", "/schedule?msg="
                                 + quote(msg))
                self.end_headers()
                return

            if ruta.path == "/horarios":
                email = self._usuario()
                cfg_h = json.loads(CONFIG.read_text())
                if not email or not es_admin(email, cfg_h):
                    self.send_response(403)
                    self.end_headers()
                    return
                msg = aplicar_accion_horarios(form)
                if self.headers.get("X-Requested-With") == "fetch":
                    self.send_response(200)
                    self.send_header("Content-Type",
                                     "text/plain; charset=utf-8")
                    self.end_headers()
                    self.wfile.write(msg.encode())
                else:
                    self.send_response(303)
                    self.send_header("Location", "/schedule?msg="
                                     + quote(msg))
                    self.end_headers()
                return
            if ruta.path in ("/config", "/fuentes", "/usuarios"):
                email = self._usuario()
                if not email:
                    self.send_response(303)
                    self.send_header("Location", "/")
                    self.end_headers()
                    return
                if ruta.path == "/config":
                    destino = aplicar_accion_config(form, email)
                elif ruta.path == "/fuentes":
                    err = aplicar_accion_fuentes(form, email)
                    destino = "/fuentes" + ("?msg=" + quote(err) if err else "")
                else:
                    if not aplicar_accion_usuarios(form, email):
                        self.send_response(403)
                        self.end_headers()
                        return
                    destino = "/fuentes"
                self.send_response(303)
                self.send_header("Location", destino)
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
    ap = argparse.ArgumentParser(description="Monitor de noticias con alertas por palabras clave")
    ap.add_argument("--loop", type=int, metavar="MIN", help="revisar cada N minutos")
    ap.add_argument("--resumir", action="store_true", help="resumir alertas con Ollama")
    ap.add_argument("--todo", action="store_true", help="mostrar todos los titulares")
    ap.add_argument("--web", type=int, nargs="?", const=8080, metavar="PUERTO",
                    help="dashboard web en localhost:PUERTO (default 8080)")
    args = ap.parse_args()

    cfg = json.loads(CONFIG.read_text())
    usuarios = cargar_usuarios()
    print(f"Fuentes: {len(cfg['fuentes'])} | Usuarios: {len(usuarios)}\n")

    if args.web:
        servir_web(args.web)
        if not args.loop:
            # Solo servidor web: mantener vivo hasta Ctrl+C
            try:
                while True:
                    time.sleep(3600)
            except KeyboardInterrupt:
                return 0

    if args.loop:
        while True:
            # recargar config cada ciclo: reglas editadas en el dashboard
            # aplican sin reiniciar
            cfg = json.loads(CONFIG.read_text())
            # portadas primero: horas clavadas (00:30→06:45); revisar se
            # atasca ~4 min barriendo 95 feeds y desfasaba el PDF
            if toca_captura_portadas(cfg):
                threading.Thread(target=capturar_portadas, args=(cfg,),
                                 daemon=True, name="portadas").start()
                marcar_captura_portadas()
            if toca_pdf_portadas(cfg):
                threading.Thread(target=generar_pdfs_portadas,
                                 args=(cfg,), daemon=True,
                                 name="portadas-pdf").start()
            if toca_pdf_portadas2(cfg):
                threading.Thread(target=generar_pdfs_portadas,
                                 args=(cfg, "pdf_fecha2"), daemon=True,
                                 name="portadas-pdf2").start()
            if toca_limpia_portadas(cfg):
                limpiar_portadas()
                marcar_limpia_portadas()
            checar_ip_correo()   # 1×/día: avisa si la IP de Brevo cambió
            for franja in ("matutina", "mediodia", "vespertina",
                           "nocturna", "semanal", "dominical"):
                if toca_sintesis(franja):
                    threading.Thread(target=generar_sintesis,
                                     args=(cfg, franja), daemon=True,
                                     name=f"sintesis-{franja}").start()
            # cierre del día: automático 17:00 lun-vie — genera la
            # tarjeta y la manda por mail (el post a X sigue siendo
            # botón — humano)
            if toca_sintesis("cierre") and "cierre" not in _GENERANDO:
                _GENERANDO.add("cierre")
                threading.Thread(target=_gen_bg,
                                 args=(_cierre_programado, "cierre",
                                       cfg),
                                 daemon=True, name="cierre").start()
            # chucky: posts de las fuentes tipo fb, cada 4 h
            if toca_fb_posts():
                threading.Thread(target=scrapear_posts_fb,
                                 args=(cfg,), daemon=True,
                                 name="fb-posts").start()
            with _LOCK_REVISAR:
                revisar(cfg, args.todo, args.resumir)
            # siesta adaptativa: en la ventana portadas (00:10→07:00)
            # despierta cada 5 min — corridas, rampa de reintentos y el
            # PDF de las 06:45 no se desfasan hasta 14 min con el loop
            # fijo de 15; fuera de la zona conserva el ritmo normal
            ahora_m = datetime.now().hour * 60 + datetime.now().minute
            _p = cfg.get("portadas", {})
            en_zona = (_hhmm(_p, "hora_desde", "00:30") - 20
                       <= ahora_m
                       < _hhmm(_p, "hora_pdf2",
                               _p.get("hora_pdf", "06:45")) + 15)
            siesta = 5 if en_zona else args.loop
            print(f"\n--- durmiendo {siesta} min ---")
            time.sleep(siesta * 60)
    else:
        n = revisar(cfg, args.todo, args.resumir)
        print(f"\nTotal alertas: {n}")


if __name__ == "__main__":
    sys.exit(main())
