#!/usr/bin/env python3
"""
Monitor de noticias locales con alertas por palabras clave.

Uso:
    python monitor.py              # revisa una vez
    python monitor.py --loop 15    # revisa cada 15 minutos
    python monitor.py --resumir    # resume alertas con Ollama (local)
    python monitor.py --todo       # muestra TODOS los titulares (sin filtrar)
    python monitor.py --web        # dashboard en http://localhost:8080
    python monitor.py --web 9000   # dashboard en otro puerto
"""

import argparse
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
import unicodedata
from collections import Counter
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs, quote, urljoin
import urllib.robotparser as robotparser

import feedparser
import requests
from PIL import Image, ImageDraw, ImageFont

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
OG_PNG = BASE / "og.png"        # tarjeta de preview para compartir links
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


def cargar_vistos() -> dict:
    """{link: timestamp}. El formato viejo era una lista de links: se migra."""
    datos = cargar_json(VISTOS, {})
    if isinstance(datos, list):
        return {u: time.time() for u in datos}
    return datos


def guardar_vistos(vistos: dict):
    """Poda vistos a RETENCION_VISTOS_DIAS y tope de 8000 enlaces."""
    ahora = time.time()
    limpio = {k: v for k, v in vistos.items()
              if ahora - v < RETENCION_VISTOS_DIAS * 86400}
    if len(limpio) > 8000:
        limpio = dict(list(limpio.items())[-8000:])
    VISTOS.write_text(json.dumps(limpio, indent=0))


# ---- Multi-tenant: un perfil por usuario autenticado ----

DEMO_HORAS = 24  # cuánto dura el perfil de invitado


def cargar_usuarios() -> dict:
    """{email: {'reglas': [...], 'fuentes_ocultas': [...], 'expira': ts}}"""
    if not USUARIOS.exists():
        return {}
    try:
        datos = json.loads(USUARIOS.read_text())
        return datos if isinstance(datos, dict) else {}
    except Exception:
        return {}


def guardar_usuarios(usuarios: dict):
    USUARIOS.write_text(json.dumps(usuarios, ensure_ascii=False, indent=2))


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
        usuarios[email] = {
            "reglas": list(cfg.get("alertas", [])) if es_admin(email, cfg) else [],
            "fuentes_ocultas": [],
            "expira": 0,
            "password": "",
        }
        guardar_usuarios(usuarios)
    return usuarios[email]


def fuentes_visibles(perfil: dict, cfg: dict) -> set:
    """Fuentes que el usuario ve en su feed: todas menos las que ocultó.
    (modelo por exclusión: una fuente nueva del admin aparece sola)"""
    ocultas = set(perfil.get("fuentes_ocultas", []))
    return {f["nombre"] for f in cfg["fuentes"] if f["nombre"] not in ocultas}


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
            ts = min(calendar.timegm(pp), time.time())
            return datetime.fromtimestamp(ts).isoformat(timespec="seconds")
        except Exception:
            pass
    return datetime.now().isoformat(timespec="seconds")


def fmt_fecha(iso: str) -> str:
    """'2026-09-30T02:41:00' -> '30/09 02:41' para mostrar en tarjetas."""
    try:
        d = datetime.fromisoformat(iso)
        return d.strftime("%d/%m %H:%M")
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


def enviar_correo(cfg: dict, alerta: dict):
    """Manda correo de alerta vía SMTP si está habilitado en config.

    Para Gmail: activa 'contraseña de aplicación' en tu cuenta,
    smtp_host smtp.gmail.com, puerto 465 (SSL).
    """
    correo = cfg.get("correo", {})
    if not correo.get("habilitado"):
        return
    # alertas de un usuario van a SU correo; las globales al destinatario fijo
    destinatario = alerta.get("usuario") or correo.get("destinatario", "")
    if not destinatario or "@" not in destinatario:
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
        msg["From"] = correo["usuario"]
        msg["To"] = destinatario
        with smtplib.SMTP_SSL(correo["smtp_host"], correo.get("smtp_port", 465), timeout=20) as s:
            s.login(correo["usuario"], correo["password"])
            s.send_message(msg)
        print("    ✉ correo enviado")
    except Exception as e:
        print(f"    [!] correo falló: {e}")


def url_https(url: str) -> str:
    """Sube http→https: evita 'Mixed Content' cuando la página va por TLS."""
    return "https://" + url[7:] if url.startswith("http://") else url


# ---- Rate limit por IP (login fuerza bruta + flood de requests) ----
_RL_HITS: dict = {}


def ratelimit_ok(ip: str, limite: int = 120, ventana: int = 60) -> bool:
    """True si la IP sigue bajo el límite en la ventana (segundos)."""
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


def coincide(texto: str, regla: dict) -> bool:
    """True si TODAS las palabras/frases de la regla aparecen en el texto.
    Cada palabra admite sinónimos con '/': 'villahermosa/tabasco'
    cuenta como un término que matchea cualquiera de las variantes."""
    t = normalizar(texto)
    return all(
        any(normalizar(v) in t for v in p.split("/"))
        for p in regla["requiere_todas"])


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


def resumir_ollama(cfg: dict, titulo: str, resumen: str) -> str:
    """Pide a Ollama un resumen de una línea (opcional, --resumir)."""
    prompt = (
        "Resume en una sola frase en español esta noticia. "
        "Solo el resumen, sin comillas ni introducción.\n\n"
        f"Título: {titulo}\nTexto: {resumen[:1500]}"
    )
    try:
        r = requests.post(
            cfg["ollama"]["url"],
            json={"model": cfg["ollama"]["modelo"], "prompt": prompt, "stream": False},
            timeout=120,
        )
        return r.json().get("response", "").strip()
    except Exception as e:
        return f"(no se pudo resumir: {e})"


PATRON_NOTA_HTML = re.compile(
    r'<a[^>]+href=["\']([^"\']*/[^/"\']+/\d{3,}/[^/"\']+)["\'][^>]*>'
    r"(.*?)</a>", re.I | re.S)


def extraer_notas_html(doc: str, base: str) -> list:
    """De HTML plano extrae enlaces-título de notas del patrón
    /seccion/123456/slug — típico de sitios sin RSS (XEVA, etc.)."""
    notas = []
    vistos = set()
    for href, texto in PATRON_NOTA_HTML.findall(doc):
        link = urljoin(base, html.unescape(href))
        titulo = re.sub(r"<[^>]+>", " ", texto).strip()
        titulo = " ".join(titulo.split())
        if len(titulo) < 15 or link in vistos:
            continue
        vistos.add(link)
        notas.append({"link": link, "title": titulo, "summary": ""})
    return notas


def resolver_feed(url: str) -> tuple:
    """Valida una URL de fuente. Devuelve (url_final, tipo, error).
    RSS/Atom directo → 'rss'. HTML con <link rel=alternate> → el feed
    detectado como 'rss'. HTML con enlaces /seccion/id/slug → 'html'.
    Atajo: 'gn:búsqueda' → feed RSS de Google News por tema.
    Así se puede pegar la portada y se decide solo."""
    if url.lower().startswith("gn:"):
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


def revisar(cfg: dict, mostrar_todo: bool, resumir: bool) -> int:
    vistos = cargar_vistos()
    usuarios = cargar_usuarios()
    alertas = 0
    # salud por fuente para el tab de estadísticas
    estado = cargar_json(ESTADO_FUENTES, {})

    now = time.time()
    delay = cfg.get("delay_fuentes", 1)
    agent = cfg.get(
        "user_agent",
        "OlmecaCode-Monitor/1.0 (+mailto:the@unknownshoppers.com)")
    for i, fuente in enumerate(cfg["fuentes"]):
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
            vistos[link] = time.time()
            nuevas += 1

            titulo = entrada.get("title", "(sin título)")
            resumen = re.sub(r"<[^>]+>", " ", entrada.get("summary", ""))
            autor = entrada.get("author", "")
            imagen = url_https(extraer_imagen(entrada))

            # Google News agrega, no publica: el medio real viene en
            # <source>. Le atribuimos la nota a él y limpiamos el
            # sufijo " - Medio" que GN pega al titular.
            medio = ""
            if "news.google.com" in fuente["url"]:
                src = entrada.get("source") or {}
                medio = (src.get("title") or src.get("value") or "").strip()
                if medio and titulo.endswith(f" - {medio}"):
                    titulo = titulo[: -len(medio) - 3]
            texto = f"{titulo} {resumen} {autor}"

            # Filtro por fuente PRIMERO: solo gastamos la petición og:image
            # en notas que sí van a quedar
            solo = fuente.get("solo_si_menciona")
            if solo and not any(normalizar(p) in normalizar(texto) for p in solo):
                continue
            if not imagen:
                imagen = url_https(extraer_og_image(link))

            # Guardar TODA nota que pasa el filtro → alimenta la sección
            # "Últimas noticias" del dashboard
            nota = {
                "fecha": iso_fecha(entrada),
                "fuente": medio or fuente["nombre"],
                "via": fuente["nombre"] if medio else "",  # agregador que la trajo
                "categoria": fuente.get("categoria", "prensa"),
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
            hits_usuario = []
            for email, perfil in usuarios.items():
                if fuente["nombre"] in set(perfil.get("fuentes_ocultas", [])):
                    continue
                hits = [r["nombre"] for r in perfil.get("reglas", [])
                        if coincide(texto, r)]
                if hits:
                    hits_usuario.append((email, hits))

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
                for email, hits in hits_usuario:
                    alertas += 1
                    alerta = dict(base_alerta, reglas=", ".join(hits),
                                  usuario=email)
                    registrar_alerta(alerta, cfg)
                    print(f"\n*** ALERTA ({email}): {alerta['reglas']} ***")
                    print(f"    {titulo}\n    {link}")
                    if resumen_ia:
                        print(f"    → {resumen_ia}")

        print(f"[{datetime.now():%H:%M:%S}] {fuente['nombre']}: {nuevas} notas nuevas")

    guardar_vistos(vistos)
    ESTADO_FUENTES.write_text(json.dumps(estado, ensure_ascii=False, indent=0))
    alertas += detectar_desarrollo(cfg, resumir)
    purgar()
    purgar_usuarios()
    return alertas


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
                "resumen_ia": resumir_ollama(cfg, rep["titulo"],
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
<meta property="og:title" content="@noticias — Síntesis de prensa con alertas">
<meta property="og:description" content="Monitor de medios en tiempo real: destacadas, alertas por tema, noticias y estadísticas. Powered by Olmeca Code.">
<meta property="og:image" content="{base}/og.png">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="@noticias — Síntesis de prensa con alertas">
<meta name="twitter:description" content="Monitor de medios en tiempo real. Powered by Olmeca Code.">
<meta name="twitter:image" content="{base}/og.png">
<title>@noticias — Síntesis de prensa</title>
<style>
  * {{ box-sizing: border-box; }}
  body {{ font-family: system-ui, sans-serif; margin: 0; background: #f6f7f9;
         font-size: 17px; line-height: 1.45; }}
  nav {{ background: #1a237e; color: #fff; padding: .7rem 1rem .5rem;
        position: sticky; top: 0; z-index: 10; }}
  .nav-top {{ display: flex; align-items: center; gap: .8rem; }}
  nav .logo {{ font-weight: 800; font-size: 1.35rem; letter-spacing: .02em;
              color: #fff; text-decoration: none; }}
  .nav-tabs {{ display: flex; gap: .1rem; margin-top: .5rem;
              overflow-x: auto; -webkit-overflow-scrolling: touch; }}
  .nav-tabs a {{ color: #c5cae9; text-decoration: none; font-size: 1rem;
         padding: .55rem .7rem; border-radius: 6px; white-space: nowrap; }}
  .nav-tabs a:hover, .nav-tabs a:active {{ color: #fff; background: #3949ab; }}
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
         box-shadow: 0 1px 4px #0002; color: inherit; text-decoration: none; }}
  .card:active {{ background: #f0f4ff; }}
  .card img.thumb {{ width: 78px; height: 78px; object-fit: cover;
                   border-radius: 6px; float: right; margin: 0 0 .4rem .9rem; }}
  .card.top img.thumb {{ width: 110px; height: 84px; }}
  .card .meta {{ color: #666; font-size: .85rem; margin-bottom: .2rem; }}
  .card .titulo {{ font-weight: 600; display: block; margin: .15rem 0; }}
  .card .resumen {{ color: #444; font-style: italic; margin: .4rem 0 0; }}
  .card.redes {{ border-left-color: #1565c0; }}
  .card.desarrollo {{ border-left-color: #ef6c00; }}
  .card.nota {{ border-left-color: #90a4ae; }}
  .card.top {{ border-left-color: #7b1fa2; }}

  details {{ margin: .5rem 0 0; }}
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
    <form method="get" action="/buscar" role="search">
      <input type="text" name="q" placeholder="buscar nota..." value="{q}">
      <button>Buscar</button>
    </form>
    <a href="/salir" class="salir-top" title="Cerrar sesión">salir</a>
  </div>
  <div class="nav-tabs">
    <a href="/destacadas">Destacadas</a>
    <a href="/noticias">Noticias</a>
    <a href="/alertas">Alertas</a>
    <a href="/fuentes">Fuentes</a>
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
// Contador en el ícono anclado (Badging API; solo aplica si la PWA
// está instalada en el menú de inicio — en navegador normal se ignora)
fetch("/badge").then(r => r.json()).then(d => {{
  if ("setAppBadge" in navigator)
    d.n ? navigator.setAppBadge(d.n) : navigator.clearAppBadge();
}}).catch(() => {{}});
</script>
</body></html>"""


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
<meta property="og:title" content="@noticias — Síntesis de prensa con alertas">
<meta property="og:description" content="Monitor de medios en tiempo real: destacadas, alertas por tema, noticias y estadísticas.">
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


def tarjeta_alerta(a: dict, colores: dict) -> str:
    """Tarjeta completa = link; badge de regla con su color; borde del mismo."""
    autor = _autor_limpio(a)
    color = color_regla(a["reglas"], colores)
    return (
        f"<a class='card {html.escape(a.get('categoria', 'prensa'))}' "
        f"style='border-left-color:{color}' "
        f"href='/nota?u={quote(a['link'], safe='')}'>"
        + (f"<img class='thumb' src='{html.escape(url_https(a['imagen']))}' loading='lazy' "
           f"onerror='this.remove()'>" if a.get("imagen") else "")
        + f"<div class='meta2'><span class='chip-fuente'>"
        f"{html.escape(a['fuente'])}</span>"
        f"<span class='meta'>{fmt_fecha(a['fecha'])}{autor}</span></div>"
        f"{badge_regla(a['reglas'], colores)} "
        f"<span class='titulo'>{html.escape(a['titulo'])}</span>"
        + (f"<p class='resumen'>{html.escape(a['resumen_ia'])}</p>" if a.get("resumen_ia") else "")
        + "</a>"
    )


STOPWORDS = {"el", "la", "los", "las", "de", "del", "en", "y", "a", "un",
             "una", "por", "con", "para", "que", "se", "su", "al", "es",
             "ante", "tras", "este", "esta", "como", "más", "no", "su"}


def tokens_titulo(titulo: str) -> set:
    """Palabras significativas del titular para comparar similitud."""
    return {p for p in re.findall(r"[a-z0-9]+", normalizar(titulo))
            if len(p) > 3 and p not in STOPWORDS}


def agrupar_noticias(noticias: list, umbral: float = 0.45) -> list:
    """Agrupa notas con titulares similares (misma historia, varios medios).

    Compara pares por similitud de Jaccard sobre tokens del titular.
    Devuelve clusters ordenados por número de notas (mayor cobertura = más
    destacada), con el titular más largo como representante.
    """
    # dedupe: misma fuente + mismo titular = la misma nota con URL distinta
    # (pasa cuando el medio republica la nota bajo otra URL/categoría)
    unicos, claves = [], set()
    for n in noticias:
        k = (n["fuente"], normalizar(n["titulo"]))
        if k not in claves:
            claves.add(k)
            unicos.append(n)
    items = [(n, tokens_titulo(n["titulo"])) for n in unicos]
    usado = [False] * len(items)
    grupos = []
    for i, (ni, ti) in enumerate(items):
        if usado[i] or not ti:
            continue
        cluster = [ni]
        usado[i] = True
        for j in range(i + 1, len(items)):
            nj, tj = items[j]
            if usado[j] or not tj:
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


def tarjeta_destacada(rep: dict, cluster: list) -> str:
    fuentes = sorted({n["fuente"] for n in cluster})
    variantes = "".join(
        f"<a class='variante meta' href='/nota?u={quote(n['link'], safe='')}'>"
        f"<span class='chip-fuente'>{html.escape(n['fuente'])}</span> "
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


def tarjeta_noticia(n: dict) -> str:
    autor = _autor_limpio(n)
    return (
        f"<a class='card nota' href='/nota?u={quote(n['link'], safe='')}'>"
        + (f"<img class='thumb' src='{html.escape(url_https(n['imagen']))}' loading='lazy' "
           f"onerror='this.remove()'>" if n.get("imagen") else "")
        + f"<div class='meta2'><span class='chip-fuente'>"
        f"{html.escape(n['fuente'])}</span>"
        f"<span class='meta'>{fmt_fecha(n['fecha'])}{autor}</span></div>"
        f"<span class='titulo'>{html.escape(n['titulo'])}</span>"
        + "</a>"
    )


def vista_destacadas(email: str) -> str:
    cfg = json.loads(CONFIG.read_text())
    vis = fuentes_visibles(perfil_usuario(email, cfg), cfg)
    noticias = [n for n in leer_jsonl(NOTICIAS, limite=300) if n["fuente"] in vis or n.get("via") in vis]
    destacadas = agrupar_noticias(noticias)[:15]
    cards = "".join(tarjeta_destacada(rep, c) for rep, c in destacadas)
    return ("<h1>Lo más destacado</h1>" + cards if cards
            else "<h1>Lo más destacado</h1>"
                 "<p>Aún no hay historias repetidas entre medios.</p>")


def tarjeta_grupo_alerta(regla: str, items: list, colores: dict,
                         relacionadas: list = None) -> str:
    """Una tarjeta por regla: badge + último titular + notas que dispararon
    + cobertura relacionada (mismo tema, sin match directo)."""
    relacionadas = relacionadas or []
    if len(items) == 1 and not relacionadas:
        return tarjeta_alerta(items[0], colores)
    cat = items[-1].get("categoria", "prensa")
    color = color_regla(regla, colores)
    ultima = max(items, key=lambda a: a["fecha"])["fecha"]

    def variante(n):
        return (f"<a class='variante meta' href='/nota?u={quote(n['link'], safe='')}'>"
                f"<span class='chip-fuente'>{html.escape(n['fuente'])}</span> "
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
        + f"<span class='titulo'>{html.escape(reciente['titulo'])}</span>"
        + f"<div class='meta'>{len(items)} notas dispararon esta regla · "
        f"última: {fmt_fecha(ultima)}</div>"
        f"<details><summary>Ver las {len(items)} notas ▾</summary>{hits_html}</details>"
        f"{rel_html}</div>"
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
    return [n for n in noticias
            if n["link"] not in links_hit and tokens_n[n["link"]] & tema]


def vista_alertas(email: str, msg: str = "") -> str:
    """Alertas agrupadas por regla: cada regla = un cluster con todas sus notas.
    Muestra las alertas DEL USUARIO (usuario=email) + las globales (sin
    usuario). Solo reglas que SIGUEN activas en su perfil (borrar una
    regla esconde su historial; sigue en el archivo para /exportar).
    La supervisión de todos los usuarios va en /analitica, no aquí."""
    cfg = json.loads(CONFIG.read_text())
    perfil = perfil_usuario(email, cfg)
    reglas = perfil.get("reglas", [])
    reglas_vivas = {r["nombre"] for r in reglas}
    colores = {r["nombre"]: r.get("color", "") for r in reglas}
    alertas = []
    for a in leer_jsonl(ALERTAS):
        dueño = a.get("usuario", "")
        if dueño and dueño != email:
            continue  # alerta privada de otro usuario
        base = a["reglas"].split(" (")[0]
        if base in reglas_vivas or base.startswith("Autor seguido"):
            alertas.append(a)
        elif base.startswith("Noticia en desarrollo"):
            # solo entra si la historia en sí matchea alguna regla activa
            if any(coincide(a["titulo"], r) for r in reglas):
                alertas.append(a)

    grupos = {}
    for a in alertas:
        # 'Noticia en desarrollo (0→5 medios)' -> agrupa por 'Noticia en desarrollo'
        grupos.setdefault(a["reglas"].split(" (")[0], []).append(a)
    ordenadas = sorted(
        grupos.items(),
        key=lambda kv: max(a["fecha"] for a in kv[1]),
        reverse=True,
    )
    boton = ("<p><a href='/config'><button class='btn-linea'>"
             "Personalizar alertas</button></a></p>")
    vis = fuentes_visibles(perfil, cfg)
    noticias = [n for n in leer_jsonl(NOTICIAS) if n["fuente"] in vis or n.get("via") in vis]
    cards = "".join(
        tarjeta_grupo_alerta(regla, items, colores,
                             cobertura_relacionada(items, noticias))
        for regla, items in ordenadas
    )
    banner = ""
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


def vista_noticias(email: str, pagina: int = 1) -> str:
    cfg = json.loads(CONFIG.read_text())
    vis = fuentes_visibles(perfil_usuario(email, cfg), cfg)
    noticias = [n for n in leer_jsonl(NOTICIAS, limite=0) if n["fuente"] in vis or n.get("via") in vis]
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
        ant = (f"<a href='/noticias?p={pagina - 1}'>← Anterior</a>"
               if pagina > 1 else "<span>← Anterior</span>")
        sig = (f"<a href='/noticias?p={pagina + 1}'>Siguiente →</a>"
               if pagina < total_paginas else "<span>Siguiente →</span>")
        nav = (f"<div class='paginacion'>{ant} "
               f"<span class='pag-info'>{info}</span> {sig}</div>")
    return (f"<h1>Últimas noticias</h1>"
            f"<p class='meta'>{info} notas</p>"
            f"{trending}{nav}{cards}{nav}" if cards
            else "<h1>Últimas noticias</h1><p>Sin noticias todavía.</p>")


def vista_buscar(q: str, email: str) -> str:
    terms = normalizar(q).split()          # AND de palabras, cualquier orden
    cfg = json.loads(CONFIG.read_text())
    vis = fuentes_visibles(perfil_usuario(email, cfg), cfg)
    noticias = [n for n in leer_jsonl(NOTICIAS, limite=0) if n["fuente"] in vis or n.get("via") in vis]
    alertas = [a for a in leer_jsonl(ALERTAS)
               if not a.get("usuario") or a["usuario"] == email]
    hits_n = [n for n in noticias if all(
        t in normalizar(n["titulo"] + " " + n["fuente"]
                        + " " + (n.get("autor") or "")
                        + " " + (n.get("resumen") or "")) for t in terms)]
    hits_a = [a for a in alertas if all(
        t in normalizar(a["titulo"] + " " + a["reglas"]
                        + " " + (a.get("autor") or "")) for t in terms)]
    # si la alerta ya está como noticia en resultados, no duplicar
    links_n = {n["link"] for n in hits_n}
    hits_a = [a for a in hits_a if a["link"] not in links_n]
    colores = {r["nombre"]: r.get("color", "") for r in perfil_usuario(email, cfg).get("reglas", [])}
    chips = trending_chips(noticias)
    regresar = (f"<a class='chip-trend' href='/noticias' "
                f"style='background:#1a237e'>← Todas</a>")
    trending = f"<div class='trending'>{regresar}{chips}</div>" if chips else ""
    return (f"<h1>Buscar: {html.escape(q)}</h1>"
            f"{trending}"
            f"<p class='meta'>{len(hits_n)} notas · {len(hits_a)} alertas</p>"
            + "".join(tarjeta_alerta(a, colores) for a in
                      sorted(hits_a, key=lambda a: a["fecha"], reverse=True))
            + "".join(tarjeta_noticia(n) for n in
                      sorted(hits_n, key=lambda n: n["fecha"], reverse=True)))


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
    cards = "".join(
        f"""<div class="card regla" style="border-left-color:{color}">
  <span class="badge" style="background:{color}">{html.escape(r['nombre'])}</span>
  <form method="post" action="/config">
    <input type="hidden" name="idx" value="{i}">
    <label>Nombre de la regla</label>
    <input type="text" name="nombre" value="{html.escape(r['nombre'], quote=True)}" required>
    <label>Palabras que deben aparecer TODAS (separadas por coma)</label>
    <input type="text" name="palabras"
           value="{html.escape(', '.join(r['requiere_todas']), quote=True)}" required>
    <p class="meta" style="margin:.2rem 0">Coma = todas deben aparecer ·
    <b>/</b> = sinónimos (ej: <code>villahermosa/tabasco</code>)</p>
    <div class="regla-pie">
      <input type="color" name="color" value="{color}" title="Color del badge">
      <button name="accion" value="editar">Guardar</button>
      <button class="btn-rojo" name="accion" value="borrar"
              onclick="return confirm('¿Borrar esta regla?')">Borrar</button>
    </div>
  </form>
</div>"""
        for i, r in enumerate(reglas)
        for color in [r.get("color") or color_regla(r["nombre"], {})]
    )
    return f"""
<h1>Mis reglas de alerta</h1>
<p class="meta">Una regla dispara si la nota contiene TODAS sus palabras/frases
(mínimo 2 — una sola palabra genera demasiado ruido). Son personales:
nadie más ve ni edita las tuyas. Los cambios aplican al guardar — el
backfill es inmediato y dispara un ciclo de revisión para noticias nuevas.</p>
<h2>Nueva regla</h2>
<div class="card regla">
  <form method="post" action="/config">
    <label>Nombre de la regla</label>
    <input type="text" name="nombre" placeholder="Ej: inundaciones" required>
    <label>Palabras requeridas (todas, separadas por coma)</label>
    <input type="text" name="palabras" placeholder="tabasco, inundación — sinónimos con /: tabasco/villahermosa" required>
    <div class="regla-pie">
      <input type="color" name="color" value="#1a237e" title="Color del badge">
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
    try:
        r = requests.get(link, timeout=12,
                         headers={"User-Agent": "Mozilla/5.0"})
        r.raise_for_status()
    except Exception as e:
        return (f"<div class='lector'><h2>No se pudo cargar la nota</h2>"
                f"<p class='meta'>{html.escape(str(e))}</p>"
                f"<a class='origen' href='{html.escape(link)}' "
                f"target='_blank' rel='noopener'>Abrir en {html.escape(dominio)} ↗</a></div>",
                {"titulo": "", "imagen": "", "desc": "", "dominio": dominio})

    titulo = _meta(r.text, "og:title") or _meta(r.text, "twitter:title") or ""
    if not titulo:
        m = re.search(r"<title[^>]*>(.*?)</title>", r.text, re.S | re.I)
        titulo = m.group(1).strip() if m else link
    imagen = _meta(r.text, "og:image") or _meta(r.text, "twitter:image")
    if imagen and imagen.startswith("/"):
        imagen = urljoin(link, imagen)   # og:image relativo → absoluto
    desc = _meta(r.text, "og:description") or _meta(r.text, "description")
    meta = {"titulo": titulo, "imagen": imagen, "desc": desc,
            "dominio": dominio}

    # párrafos del cuerpo: filtrar menús/pies (textos cortos) y duplicados
    paras, vistos_p = [], set()
    for p in re.findall(r"<p[^>]*>(.*?)</p>", r.text, re.S | re.I):
        txt = re.sub(r"<[^>]+>", " ", p)
        txt = html.unescape(re.sub(r"\s+", " ", txt)).strip()
        if len(txt) > 60 and txt not in vistos_p:
            paras.append(txt)
            vistos_p.add(txt)
        if len(paras) >= 15:
            break

    cuerpo = (f"<p class='lede'>{html.escape(desc)}</p>" if desc else "") \
        + "".join(f"<p>{html.escape(p)}</p>" for p in paras)
    if not cuerpo:
        cuerpo = ("<p class='meta'>El sitio no permitió extraer el texto.</p>")

    # ¿la página original tiene video? metas, tag <video> o players conocidos
    hay_video = bool(re.search(
        r'og:video|twitter:player|<video[\s>]|\.m3u8|'
        r'youtube\.com/embed|vimeo\.com|jwplayer|brightcove', r.text, re.I))

    return (
        "<div class='lector'>"
        f"<a href='javascript:history.back()'>← Regresar</a>"
        f"<h1>{html.escape(titulo)}</h1>"
        f"<div class='meta'>Fuente original: {html.escape(dominio)}</div>"
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
    admin = es_admin(email, cfg)
    estado = cargar_json(ESTADO_FUENTES, {})
    intervalo = cfg.get("intervalo", 15)
    cats = sorted({f.get("categoria", "prensa") for f in cfg["fuentes"]}
                  | {"prensa", "prensa_independiente", "nacional",
                     "deportes", "internacional", "oficial",
                     "quintana_roo"})

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
            f["nombre"] not in ocultas for _, f in sources) else ""
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
      onchange="if(!this.checked)document.getElementById('sel-todo').checked=false"
      {'' if f['nombre'] in ocultas else ' checked'}>
    {dot}{html.escape(f['nombre'])}
    <span class="meta"> · {html.escape(f.get('categoria', 'prensa'))}</span></label>
  {edicion}
</div>"""
        filas += "</details>"

    aviso = (f"<div class='card' style='border-left-color:#d32f2f'>"
             f"<b>URL rechazada:</b> {html.escape(msg)}</div>" if msg else "")
    seleccion = f"""
<h1>Fuentes</h1>
{aviso}
<p class="meta">Marca los medios que quieres ver en Destacadas, Noticias
y Buscar.</p>
<form method="post" action="/fuentes">
  <label class="fuente-check master"><input type="checkbox" id="sel-todo"
      {'checked' if not ocultas else ''}
      onclick="document.querySelectorAll('.fuente-row .fuente-check input').forEach(c=>c.checked=this.checked)">
    <span class="meta">todas</span></label>
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
}
function soloCat(cat) {
  document.querySelectorAll('input[name=ver]').forEach(function(c) { c.checked = false; });
  document.querySelectorAll(
    'input[name=ver][data-cat="' + cat + '"]'
  ).forEach(function(c) { c.checked = true; });
  var master = document.getElementById('sel-todo');
  if (master) master.checked = false;
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
    <label>URL del RSS <span class="meta">(o la portada — se autodetecta; o <code>gn:tema</code> para Google News por búsqueda)</span></label>
    <input type="text" name="url" placeholder="https://…  o  gn:efraín tabasco" inputmode="url" required>
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
        form = ""
        if not es_admin(u_email, cfg):
            form = (
                f"<form method='post' action='/usuarios'>"
                f"<input type='hidden' name='email' value='{html.escape(u_email, quote=True)}'>"
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
  <span class="meta"> · {len(u.get('reglas', []))} reglas · {tipo}</span>
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
    <div class="regla-pie">
      <button name="accion" value="crear">Crear usuario</button>
    </div>
  </form>
</div>
{cards_u}"""

    return seleccion + catalogo + gestion


def vista_stats() -> str:
    """Estadísticas: totales, notas por fuente, por día, salud de feeds."""
    noticias = leer_jsonl(NOTICIAS)
    alertas = leer_jsonl(ALERTAS)
    estado = cargar_json(ESTADO_FUENTES, {})

    por_fuente = Counter(n["fuente"] for n in noticias)
    por_dia = Counter(n["fecha"][:10] for n in noticias)

    filas_fuente = "".join(
        f"<tr><td>{html.escape(fuente)}</td><td>{total}</td>"
        f"<td>{estado.get(fuente, {}).get('ok', 0)}</td>"
        f"<td>{estado.get(fuente, {}).get('err', 0)}</td>"
        f"<td>{fmt_fecha(estado.get(fuente, {}).get('ultimo_ok', '') or '-')}</td></tr>"
        for fuente, total in por_fuente.most_common()
    )
    filas_dia = "".join(
        f"<tr><td>{dia}</td><td>{total}</td></tr>"
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
    noticias = leer_jsonl(NOTICIAS)
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
    "name": "@noticias",
    "short_name": "@noticias",
    "start_url": "/",
    "display": "standalone",
    "background_color": "#f6f7f9",
    "theme_color": "#1a237e",
    "icons": [
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
                  usuario: str = "") -> bytes:
    cfg = json.loads(CONFIG.read_text())
    admin_tabs = ('<a href="/stats">Stats</a>'
                  '<a href="/analitica">Analítica</a>'
                  if usuario and es_admin(usuario, cfg) else "")
    return PAGINA.format(contenido=contenido, q=html.escape(q),
                         base=base, admin_tabs=admin_tabs).encode()


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
            guardar_usuarios(usuarios)
        return

    def datos_fuente():
        f = {
            "nombre": form.get("nombre", [""])[0].strip(),
            "url": form.get("url", [""])[0].strip(),
            "tipo": "rss",
            "categoria": form.get("categoria", ["prensa"])[0],
        }
        filtro = [p.strip() for p in form.get("filtro", [""])[0].split(",") if p.strip()]
        if filtro:
            f["solo_si_menciona"] = filtro
        return f

    error = ""
    if accion == "agregar":
        f = datos_fuente()
        if f["nombre"] and f["url"].startswith("http"):
            url_ok, tipo, error = resolver_feed(f["url"])
            if url_ok and url_ok in {x["url"] for x in cfg["fuentes"]}:
                error = "esa fuente ya está en el catálogo"
                url_ok = None
            if url_ok:
                f["url"], f["tipo"] = url_ok, tipo
                cfg["fuentes"].append(f)
        else:
            error = "nombre y URL http(s) obligatorios"
    elif accion == "editar":
        try:
            idx = int(form.get("idx", ["-1"])[0])
            f = datos_fuente()
            if f["nombre"] and f["url"].startswith("http"):
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
    CONFIG.write_text(json.dumps(cfg, ensure_ascii=False, indent=2))
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

    if accion == "crear" and objetivo and pw and objetivo not in usuarios:
        usuarios[objetivo] = {
            "reglas": [], "fuentes_ocultas": [], "expira": 0,
            "password": hash_password(pw),
        }
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
        for nota in leer_jsonl(NOTICIAS):
            if (nota["link"], regla["nombre"], email) in ya:
                continue
            texto = (f"{nota['titulo']} {nota.get('resumen', '')} "
                     f"{nota.get('autor', '')}")
            if coincide(texto, regla):
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
    return n


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
    if accion == "agregar":
        nombre = form.get("nombre", [""])[0].strip()
        palabras = [p.strip() for p in form.get("palabras", [""])[0].split(",") if p.strip()]
        # mínimo 2 palabras/frases: una sola dispara ruido puro
        if nombre and len(palabras) >= 2:
            regla = {"nombre": nombre, "requiere_todas": palabras,
                     "color": form.get("color", [""])[0]}
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
                         "color": form.get("color", [""])[0]}
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

        def _html(self, contenido: bytes, code: int = 200):
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
            if not ratelimit_ok(ip):
                self._html("<h1 style='font-family:system-ui;padding:2rem'>"
                           "Demasiadas solicitudes — espera un minuto.</h1>"
                           .encode(), 429)
                return
            if (ruta.path not in ("/icon.png", "/icon3.png", "/og.png",
                                  "/manifest.webmanifest", "/badge",
                                  "/captura.png")
                    and not ruta.path.startswith("/shots/")):
                registrar_actividad(
                    email, ruta.path, params.get("u", [""])[0],
                    self.headers.get("Referer", ""),
                    params.get("q", [""])[0] if ruta.path == "/buscar"
                    else "")
            if not email and ruta.path == "/":
                # anónimo en la raíz: la landing es la cara del producto
                self._html(vista_landing(base))
                return
            if not email and not (
                    ruta.path in ("/icon.png", "/icon3.png", "/og.png",
                                  "/manifest.webmanifest", "/nota",
                                  "/instructivo", "/captura")
                    or ruta.path.startswith("/shots/")):
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
                self.send_header("Location", "/noticias")
                self.end_headers()
            elif ruta.path == "/destacadas":
                self._html(render_pagina(vista_destacadas(email), base=base,
                                         usuario=email))
            elif ruta.path == "/alertas":
                msg = params.get("msg", [""])[0]
                self._html(render_pagina(vista_alertas(email, msg),
                                         base=base, usuario=email))
                # ya las vio: el contador del ícono vuelve a 0
                usuarios = cargar_usuarios()
                if email in usuarios:
                    usuarios[email]["visto_alertas"] = \
                        datetime.now().isoformat(timespec="seconds")
                    guardar_usuarios(usuarios)
            elif ruta.path == "/noticias":
                try:
                    p = int(params.get("p", ["1"])[0])
                except (ValueError, IndexError):
                    p = 1
                self._html(render_pagina(vista_noticias(email, p), base=base,
                                         usuario=email))
            elif ruta.path == "/buscar":
                q = params.get("q", [""])[0]
                self._html(render_pagina(vista_buscar(q, email), q=q,
                                         base=base, usuario=email))
            elif ruta.path == "/config":
                self._html(render_pagina(vista_config(email), base=base,
                                         usuario=email))
            elif ruta.path == "/fuentes":
                msg = params.get("msg", [""])[0]
                self._html(render_pagina(vista_fuentes(email, msg), base=base,
                                         usuario=email))
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
                    json.dumps({"n": badge_count(email)}).encode())
            elif ruta.path == "/manifest.webmanifest":
                self.send_response(200)
                self.send_header("Content-Type", "application/manifest+json")
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(MANIFEST)
            elif ruta.path == "/og.png" and OG_PNG.exists():
                self.send_response(200)
                self.send_header("Content-Type", "image/png")
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
                    self.send_header("Location", "/noticias")
                    self.send_header("Set-Cookie",
                                     cookie_sesion(email, https))
                    self.end_headers()
                else:
                    self._html(vista_login(self._base(),
                                           "Correo o contraseña "
                                           "incorrectos."))
                return
            if ruta.path == "/invitado":
                usuarios = cargar_usuarios()
                email = f"guest-{secrets.token_hex(4)}@demo.local"
                usuarios[email] = {
                    "reglas": [], "fuentes_ocultas": [],
                    "expira": time.time() + DEMO_HORAS * 3600,
                    "password": "",
                }
                guardar_usuarios(usuarios)
                self.send_response(303)
                self.send_header("Location", "/noticias")
                self.send_header("Set-Cookie", cookie_sesion(email, https))
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
            with _LOCK_REVISAR:
                revisar(cfg, args.todo, args.resumir)
            print(f"\n--- durmiendo {args.loop} min ---")
            time.sleep(args.loop * 60)
    else:
        n = revisar(cfg, args.todo, args.resumir)
        print(f"\nTotal alertas: {n}")


if __name__ == "__main__":
    sys.exit(main())
    sys.exit(main())

if __name__ == "__main__":
    sys.exit(main())
    sys.exit(main())
    sys.exit(main())
    sys.exit(main())

if __name__ == "__main__":
    sys.exit(main())
    sys.exit(main())
