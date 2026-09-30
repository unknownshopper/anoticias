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
import html
import json
import re
import smtplib
import socket
import subprocess
import sys
import threading
import time
import unicodedata
from collections import Counter
from datetime import datetime
from email.mime.text import MIMEText
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from time import mktime
from urllib.parse import urlparse, parse_qs, quote

import feedparser
import requests

socket.setdefaulttimeout(20)  # feedparser no trae timeout; evita que se cuelgue

BASE = Path(__file__).parent
CONFIG = BASE / "config.json"
VISTOS = BASE / "vistos.json"      # enlaces ya procesados (para no repetir alertas)
ALERTAS = BASE / "alertas.jsonl"   # historial de alertas (una por línea, JSON)
NOTICIAS = BASE / "noticias.jsonl" # feed completo: todas las notas capturadas
CLUSTERS = BASE / "clusters.json"  # estado de "noticia en desarrollo"
ESTADO_FUENTES = BASE / "fuentes_estado.json"  # salud por feed (stats)
MAX_NOTICIAS = 2000
RETENCION_DIAS = 7        # noticias y alertas se borran a la semana
RETENCION_VISTOS_DIAS = 30  # enlaces ya procesados duran más (evita re-alertas)
VERSION = "0.9.0"


def normalizar(texto: str) -> str:
    """Minúsculas y sin acentos, para que 'Olán' matchee 'olan' y 'OLÁN'."""
    texto = texto.lower()
    return "".join(
        c for c in unicodedata.normalize("NFD", texto)
        if unicodedata.category(c) != "Mn"
    )


def cargar_vistos() -> dict:
    """{link: timestamp}. El formato viejo era una lista de links: se migra."""
    if not VISTOS.exists():
        return {}
    datos = json.loads(VISTOS.read_text())
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


def iso_fecha(entrada) -> str:
    """Fecha de la entrada RSS en ISO; published_parsed si existe."""
    pp = entrada.get("published_parsed") or entrada.get("updated_parsed")
    if pp:
        try:
            return datetime.fromtimestamp(mktime(pp)).isoformat(timespec="seconds")
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
    Registros sin fecha parseable se conservan (no borramos a ciegas)."""
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
        msg["To"] = correo["destinatario"]
        with smtplib.SMTP_SSL(correo["smtp_host"], correo.get("smtp_port", 465), timeout=20) as s:
            s.login(correo["usuario"], correo["password"])
            s.send_message(msg)
        print("    ✉ correo enviado")
    except Exception as e:
        print(f"    [!] correo falló: {e}")


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
    """True si TODAS las palabras/frases de la regla aparecen en el texto."""
    t = normalizar(texto)
    return all(normalizar(p) in t for p in regla["requiere_todas"])


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


def revisar(cfg: dict, mostrar_todo: bool, resumir: bool) -> int:
    vistos = cargar_vistos()
    alertas = 0
    # salud por fuente para el tab de estadísticas
    estado = json.loads(ESTADO_FUENTES.read_text()) if ESTADO_FUENTES.exists() else {}

    for fuente in cfg["fuentes"]:
        st = estado.setdefault(fuente["nombre"], {"ok": 0, "err": 0, "ultimo_ok": ""})
        if fuente.get("tipo") == "telegram":
            entradas = fetch_telegram(fuente["canal"])
        else:
            try:
                feed = feedparser.parse(fuente["url"])
            except Exception as e:
                st["err"] += 1
                print(f"[!] {fuente['nombre']}: error de red ({e})")
                continue
            if feed.bozo and not feed.entries:
                st["err"] += 1
                print(f"[!] {fuente['nombre']}: no se pudo leer el feed")
                continue
            st["ok"] += 1
            st["ultimo_ok"] = datetime.now().isoformat(timespec="seconds")
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
            imagen = extraer_imagen(entrada)
            texto = f"{titulo} {resumen} {autor}"

            # Filtro por fuente PRIMERO: solo gastamos la petición og:image
            # en notas que sí van a quedar
            solo = fuente.get("solo_si_menciona")
            if solo and not any(normalizar(p) in normalizar(texto) for p in solo):
                continue
            if not imagen:
                imagen = extraer_og_image(link)

            # Guardar TODA nota que pasa el filtro → alimenta la sección
            # "Últimas noticias" del dashboard
            nota = {
                "fecha": iso_fecha(entrada),
                "fuente": fuente["nombre"],
                "categoria": fuente.get("categoria", "prensa"),
                "autor": autor,
                "titulo": titulo,
                "link": link,
                "imagen": imagen,
            }
            guardar_noticia(nota)

            # Alertas: por palabras clave O por autor seguido
            reglas_hit = [r["nombre"] for r in cfg["alertas"] if coincide(texto, r)]
            autor_hit = normalizar(autor) in {
                normalizar(a) for a in cfg.get("seguir_autores", [])
            } if autor else False

            if mostrar_todo:
                print(f"  · [{fuente['nombre']}] {titulo}")
            if reglas_hit or autor_hit:
                alertas += 1
                reglas = list(reglas_hit)
                if autor_hit:
                    reglas.append(f"Autor seguido: {autor}")
                alerta = {
                    "fecha": datetime.now().isoformat(timespec="seconds"),
                    "fuente": fuente["nombre"],
                    "categoria": fuente.get("categoria", "prensa"),
                    "autor": autor,
                    "reglas": ", ".join(reglas),
                    "titulo": titulo,
                    "link": link,
                    "imagen": imagen,
                    "resumen_ia": resumir_ollama(cfg, titulo, resumen) if resumir else "",
                }
                registrar_alerta(alerta, cfg)
                print(f"\n*** ALERTA: {alerta['reglas']} ***")
                print(f"    {titulo}")
                print(f"    {link}")
                if alerta["resumen_ia"]:
                    print(f"    → {alerta['resumen_ia']}")

        print(f"[{datetime.now():%H:%M:%S}] {fuente['nombre']}: {nuevas} notas nuevas")

    guardar_vistos(vistos)
    ESTADO_FUENTES.write_text(json.dumps(estado, ensure_ascii=False, indent=0))
    alertas += detectar_desarrollo(cfg, resumir)
    purgar()
    return alertas


def detectar_desarrollo(cfg: dict, resumir: bool) -> int:
    """Noticia en desarrollo: un cluster que CRECE entre ciclos dispara alerta.

    Guarda en clusters.json cuántas versiones tenía cada historia; si en
    este ciclo apareció con más versiones (o nació ya con >=3), alerta.
    """
    noticias = leer_jsonl(NOTICIAS, limite=300)
    if not noticias:
        return 0

    previo = {}
    if CLUSTERS.exists():
        previo = json.loads(CLUSTERS.read_text())

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


PAGINA = """<!DOCTYPE html>
<html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="60">
<meta name="theme-color" content="#1a237e">
<meta name="mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<meta name="apple-mobile-web-app-title" content="@noticias">
<link rel="manifest" href="/manifest.webmanifest">
<link rel="icon" type="image/png" href="/icon.png">
<link rel="apple-touch-icon" href="/icon.png">
<meta property="og:type" content="website">
<meta property="og:site_name" content="@noticias">
<meta property="og:title" content="@noticias — Síntesis de prensa con alertas">
<meta property="og:description" content="Monitor de medios en tiempo real: destacadas, alertas por tema, noticias y estadísticas. Powered by Olmeca Code.">
<meta property="og:image" content="{base}/icon.png">
<meta property="og:image:width" content="192">
<meta property="og:image:height" content="192">
<meta name="twitter:card" content="summary">
<meta name="twitter:title" content="@noticias — Síntesis de prensa con alertas">
<meta name="twitter:description" content="Monitor de medios en tiempo real. Powered by Olmeca Code.">
<meta name="twitter:image" content="{base}/icon.png">
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
  input[type=text] {{ padding: .6rem .7rem; border: 1px solid #ccc;
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
  select, input[type=text] {{ padding: .6rem .7rem; border: 1px solid #ccc;
                     border-radius: 6px; font-size: 1rem; }}
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
</style></head><body>
<nav>
  <div class="nav-top">
    <a class="logo" href="/noticias">@noticias</a>
    <form action="/buscar" method="get">
      <input type="text" name="q" placeholder="buscar nota..." value="{q}">
      <button>Buscar</button>
    </form>
  </div>
  <div class="nav-tabs">
    <a href="/">Destacadas</a>
    <a href="/alertas">Alertas</a>
    <a href="/fuentes">Fuentes</a>
    <a href="/stats">Stats</a>
  </div>
</nav>
<main>
{contenido}
</main>
<footer><a href="/acerca" class="about">@</a></footer>
</body></html>"""


def leer_jsonl(path: Path, limite: int = 0) -> list:
    if not path.exists():
        return []
    lineas = [l for l in path.read_text().splitlines() if l.strip()]
    if limite:
        lineas = lineas[-limite:]
    return [json.loads(l) for l in lineas]


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


def tarjeta_alerta(a: dict, colores: dict) -> str:
    """Tarjeta completa = link; badge de regla con su color; borde del mismo."""
    autor = f" · {html.escape(a['autor'])}" if a.get("autor") else ""
    color = color_regla(a["reglas"], colores)
    return (
        f"<a class='card {html.escape(a.get('categoria', 'prensa'))}' "
        f"style='border-left-color:{color}' "
        f"href='/nota?u={quote(a['link'], safe='')}'>"
        + (f"<img class='thumb' src='{html.escape(a['imagen'])}' loading='lazy' "
           f"onerror='this.remove()'>" if a.get("imagen") else "")
        + f"<div class='meta'>{fmt_fecha(a['fecha'])} · "
        f"{html.escape(a['fuente'])}{autor}</div>"
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
        f"{html.escape(n['fuente'])}: {html.escape(n['titulo'][:110])}</a>"
        for n in cluster
    )
    resumen = (f"{len(cluster)} versiones de {fuentes[0]}"
               if len(fuentes) == 1 else
               f"{len(cluster)} versiones · {len(fuentes)} medios: "
               f"{', '.join(fuentes)}")
    return (
        f"<div class='card top'>"
        + (f"<img class='thumb' src='{html.escape(rep['imagen'])}' loading='lazy' "
           f"onerror='this.remove()'>" if rep.get("imagen") else "")
        + f"<a href='/nota?u={quote(rep['link'], safe='')}' "
        f"style='text-decoration:none;color:inherit'>"
        f"<span class='titulo'>{html.escape(rep['titulo'])}</span></a>"
        f"<div class='meta'>{html.escape(resumen)}</div>"
        f"<details><summary>Ver las {len(cluster)} versiones ▾</summary>{variantes}</details>"
        f"</div>"
    )


def tarjeta_noticia(n: dict) -> str:
    autor = f" · {html.escape(n['autor'])}" if n.get("autor") else ""
    return (
        f"<a class='card nota' href='/nota?u={quote(n['link'], safe='')}'>"
        + (f"<img class='thumb' src='{html.escape(n['imagen'])}' loading='lazy' "
           f"onerror='this.remove()'>" if n.get("imagen") else "")
        + f"<div class='meta'>{fmt_fecha(n['fecha'])} · "
        f"{html.escape(n['fuente'])}{autor}</div>"
        f"<span class='titulo'>{html.escape(n['titulo'])}</span>"
        + "</a>"
    )


def vista_destacadas() -> str:
    noticias = leer_jsonl(NOTICIAS, limite=300)
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
                f"{fmt_fecha(n['fecha'])} · {html.escape(n['fuente'])}: "
                f"{html.escape(n['titulo'][:95])}</a>")

    hits_html = "".join(variante(a) for a in reversed(items))
    rel_html = ""
    if relacionadas:
        lista = "".join(variante(n) for n in reversed(relacionadas))
        rel_html = (
            f"<details><summary>Cobertura relacionada del tema "
            f"({len(relacionadas)}) ▾</summary>"
            f"<div class='meta' style='padding:.3rem 0'>"
            f"Mismo contexto, sin match directo de la regla:</div>{lista}</details>")

    ultima_img = next((a["imagen"] for a in reversed(items) if a.get("imagen")), "")
    return (
        f"<div class='card {html.escape(cat)}' style='border-left-color:{color}'>"
        + (f"<img class='thumb' src='{html.escape(ultima_img)}' loading='lazy' "
           f"onerror='this.remove()'>" if ultima_img else "")
        + badge_regla(regla, colores)
        + f"<span class='titulo'>{html.escape(items[-1]['titulo'])}</span>"
        + f"<div class='meta'>{len(items)} notas dispararon esta regla · "
        f"última: {fmt_fecha(ultima)}</div>"
        f"<details><summary>Ver las {len(items)} notas ▾</summary>{hits_html}</details>"
        f"{rel_html}</div>"
    )


def cobertura_relacionada(items: list, noticias: list) -> list:
    """Notas del MISMO TEMA que no matchearon la regla: comparten algún
    token distintivo (palabra rara: aparece en <=5 notas) con los titulares
    que sí dispararon la alerta. Ej. las notas de Olán sin 'Andy'."""
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


def vista_alertas() -> str:
    """Alertas agrupadas por regla: cada regla = un cluster con todas sus notas.
    Solo muestra alertas de reglas que SIGUEN activas en config (borrar una
    regla esconde su historial; sigue en el archivo para /exportar)."""
    cfg = json.loads(CONFIG.read_text())
    reglas_vivas = {r["nombre"] for r in cfg["alertas"]}
    colores = {r["nombre"]: r.get("color", "") for r in cfg["alertas"]}
    alertas = []
    for a in leer_jsonl(ALERTAS):
        base = a["reglas"].split(" (")[0]
        if base in reglas_vivas or base.startswith("Autor seguido"):
            alertas.append(a)
        elif base.startswith("Noticia en desarrollo"):
            # solo entra si la historia en sí matchea alguna regla activa
            if any(coincide(a["titulo"], r) for r in cfg["alertas"]):
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
    noticias = leer_jsonl(NOTICIAS)
    cards = "".join(
        tarjeta_grupo_alerta(regla, items, colores,
                             cobertura_relacionada(items, noticias))
        for regla, items in ordenadas
    )
    return ("<h1>Alertas</h1>" + boton + cards if cards
            else "<h1>Alertas</h1>" + boton +
                 "<p>Sin alertas todavía. Crea reglas en Personalizar alertas.</p>")


def vista_noticias() -> str:
    noticias = leer_jsonl(NOTICIAS, limite=300)
    cards = "".join(tarjeta_noticia(n) for n in reversed(noticias[-150:]))
    return (f"<h1>Últimas noticias</h1><p class='meta'>{len(noticias)} notas</p>" + cards if cards
            else "<h1>Últimas noticias</h1><p>Sin noticias todavía.</p>")


def vista_buscar(q: str) -> str:
    qn = normalizar(q)
    noticias = leer_jsonl(NOTICIAS, limite=0)
    alertas = leer_jsonl(ALERTAS)
    hits_n = [n for n in noticias if qn in normalizar(n["titulo"] + n["fuente"])]
    hits_a = [a for a in alertas if qn in normalizar(a["titulo"] + a["reglas"])]
    cfg = json.loads(CONFIG.read_text())
    colores = {r["nombre"]: r.get("color", "") for r in cfg["alertas"]}
    return (f"<h1>Buscar: {html.escape(q)}</h1>"
            f"<p class='meta'>{len(hits_n)} notas · {len(hits_a)} alertas</p>"
            + "".join(tarjeta_alerta(a, colores) for a in reversed(hits_a))
            + "".join(tarjeta_noticia(n) for n in reversed(hits_n)))


def vista_config() -> str:
    cfg = json.loads(CONFIG.read_text())
    filas = "".join(
        f"<tr>"
        f"<td><input form='f{i}' type='text' name='nombre' "
        f"value='{html.escape(r['nombre'], quote=True)}'></td>"
        f"<td><input form='f{i}' type='text' name='palabras' size='45' "
        f"value='{html.escape(', '.join(r['requiere_todas']), quote=True)}'></td>"
        f"<td><input form='f{i}' type='color' name='color' "
        f"value='{r.get('color') or color_regla(r['nombre'], {})}'></td>"
        f"<td><form id='f{i}' method='post' action='/config' style='display:inline'>"
        f"<input type='hidden' name='idx' value='{i}'></form>"
        f"<button form='f{i}' name='accion' value='editar'>guardar</button> "
        f"<button form='f{i}' class='btn-rojo' name='accion' value='borrar'>borrar</button></td>"
        f"</tr>"
        for i, r in enumerate(cfg["alertas"])
    )
    return f"""
<h1>Reglas de alerta</h1>
<p class="meta">Una regla dispara si la nota contiene TODAS sus palabras/frases
(mínimo 2 — una sola palabra genera demasiado ruido).
Edita en línea y da "guardar". Los cambios aplican en el siguiente ciclo
del scraper (sin reiniciar).</p>
<h2>Nueva regla</h2>
<form method="post" action="/config">
  <input type="text" name="nombre" placeholder="Nombre de la regla" required>
  <input type="text" name="palabras" placeholder="palabra1, palabra2, ..."
         size="40" required>
  <input type="color" name="color" value="#1a237e" title="Color del badge">
  <button name="accion" value="agregar">Agregar regla</button>
</form>
<h2>Reglas activas</h2>
<table><tr><th>Nombre</th><th>Palabras requeridas (todas, separadas por coma)</th><th>Color</th><th></th></tr>
{filas}</table>"""


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


def vista_nota(link: str) -> str:
    """Lector interno: trae la nota y la muestra dentro de la app.
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
                f"target='_blank' rel='noopener'>Abrir en {html.escape(dominio)} ↗</a></div>")

    titulo = _meta(r.text, "og:title") or _meta(r.text, "twitter:title") or ""
    if not titulo:
        m = re.search(r"<title[^>]*>(.*?)</title>", r.text, re.S | re.I)
        titulo = m.group(1).strip() if m else link
    imagen = _meta(r.text, "og:image") or _meta(r.text, "twitter:image")
    desc = _meta(r.text, "og:description") or _meta(r.text, "description")

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

    return (
        "<div class='lector'>"
        f"<a href='javascript:history.back()'>← Regresar</a>"
        f"<h1>{html.escape(titulo)}</h1>"
        f"<div class='meta'>Fuente original: {html.escape(dominio)}</div>"
        + (f"<img class='hero' src='{html.escape(imagen)}' "
           f"onerror='this.remove()'>" if imagen else "")
        + cuerpo
        + f"<a class='origen' href='{html.escape(link)}' "
          f"target='_blank' rel='noopener'>Ver en el sitio original ↗</a>"
        + "</div>"
    )


def vista_fuentes() -> str:
    """Tab de gestión de feeds RSS: agregar, editar en línea, borrar."""
    cfg = json.loads(CONFIG.read_text())
    cats = ["prensa", "prensa_independiente", "nacional"]

    def fila(i, f):
        opciones = "".join(
            f"<option value='{c}'{' selected' if f.get('categoria') == c else ''}>{c}</option>"
            for c in cats
        )
        return (
            f"<tr>"
            f"<td><input form='sf{i}' name='nombre' value='{html.escape(f['nombre'], quote=True)}'></td>"
            f"<td><input form='sf{i}' name='url' size='45' value='{html.escape(f['url'], quote=True)}'></td>"
            f"<td><select form='sf{i}' name='categoria'>{opciones}</select></td>"
            f"<td><input form='sf{i}' name='filtro' size='20' "
            f"value='{html.escape(', '.join(f.get('solo_si_menciona', [])), quote=True)}'></td>"
            f"<td><form id='sf{i}' method='post' action='/fuentes' style='display:inline'>"
            f"<input type='hidden' name='idx' value='{i}'></form>"
            f"<button form='sf{i}' name='accion' value='editar'>guardar</button> "
            f"<button form='sf{i}' class='btn-rojo' name='accion' value='borrar'>borrar</button></td>"
            f"</tr>"
        )

    filas = "".join(fila(i, f) for i, f in enumerate(cfg["fuentes"]))
    opciones_nueva = "".join(f"<option value='{c}'>{c}</option>" for c in cats)
    return f"""
<h1>Fuentes RSS</h1>
<p class="meta">Medios monitoreados. "Filtro" = palabras locales obligatorias
para medios nacionales (vacío = pasa todo). Cambios aplican en el siguiente ciclo.</p>
<table><tr><th>Nombre</th><th>URL del RSS</th><th>Categoría</th><th>Filtro (solo si menciona)</th><th></th></tr>
{filas}</table>
<h2>Agregar fuente</h2>
<form method="post" action="/fuentes">
  <input type="text" name="nombre" placeholder="Nombre del medio" required>
  <input type="text" name="url" placeholder="https://.../rss" size="45" required>
  <select name="categoria">{opciones_nueva}</select>
  <input type="text" name="filtro" placeholder="filtro opcional: tabasco, villahermosa" size="30">
  <button name="accion" value="agregar">Agregar fuente</button>
</form>"""


def vista_stats() -> str:
    """Estadísticas: totales, notas por fuente, por día, salud de feeds."""
    noticias = leer_jsonl(NOTICIAS)
    alertas = leer_jsonl(ALERTAS)
    estado = json.loads(ESTADO_FUENTES.read_text()) if ESTADO_FUENTES.exists() else {}

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
  <div class="meta">Retención: {RETENCION_DIAS} días (noticias/alertas) ·
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
           f"Ventana: últimos {RETENCION_DIAS} días", "=" * 60, ""]

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
    """Ícono de la app: cuadrado navy con anillo blanco ('@' estilizado).
    PNG 192x192 construido a mano, sin dependencias externas."""
    import struct, zlib
    W = H = 192
    cx, cy, r_out, r_in = 96, 96, 62, 38
    filas = b""
    for y in range(H):
        filas += b"\x00"
        for x in range(W):
            # esquinas redondeadas (radio 40)
            dx = max(40 - x, 0, x - (W - 41))
            dy = max(40 - y, 0, y - (H - 41))
            fuera = dx * dx + dy * dy > 40 * 40
            if fuera:
                filas += b"\x00\x00\x00\x00"
                continue
            d2 = (x - cx) ** 2 + (y - cy) ** 2
            if r_in * r_in <= d2 <= r_out * r_out:
                filas += b"\xff\xff\xff\xff"  # anillo blanco
            else:
                filas += b"\x1a\x23\x7e\xff"  # navy #1a237e
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
        {"src": "/icon.png", "sizes": "192x192", "type": "image/png",
         "purpose": "any maskable"},
        {"src": "/icon.png", "sizes": "512x512", "type": "image/png"},
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
    return f"""
<h1>@noticias <span class="meta">v{VERSION} — MVP</span></h1>
<p class="meta">Síntesis de prensa digital con alertas en tiempo real.<br>
Hecho con: 1 archivo Python + feedparser + requests + JSONL en disco.
Mucho con muy poco.<br>
Powered by <strong>Olmeca Code</strong>.</p>

<div class="card top">
  <span class="titulo">Arquitectura</span>
  <div class="meta" style="margin-top:.4rem">
    Scraper RSS (feedparser) cada 15 min → noticias.jsonl →<br>
    clustering por similitud de titulares (Jaccard) → destacadas ·<br>
    detección de noticia en desarrollo por crecimiento de cluster ·<br>
    reglas de alerta por coincidencia de palabras (mín. 2) ·<br>
    resúmenes opcionales con Ollama local (llama3.2) ·<br>
    webapp: http.server multi-hilo, cero dependencias web ·<br>
    retención: {RETENCION_DIAS} días noticias/alertas · {RETENCION_VISTOS_DIAS} días dedupe
  </div>
</div>

<h2>Base de datos</h2>
<p class="meta">JSONL en disco — cero motor externo. Última captura: {act}</p>
<table class="fija"><tr><th>Archivo</th><th>Tamaño</th><th>Registros</th></tr>
{archivos}</table>

<h2>Monitoreo</h2>
<p class="meta">{len(cfg['fuentes'])} fuentes RSS · {len(cfg['alertas'])} reglas de alerta
· {len(cfg.get('seguir_autores', []))} autores seguidos</p>"""


def render_pagina(contenido: str, q: str = "", base: str = "") -> bytes:
    return PAGINA.format(contenido=contenido, q=html.escape(q),
                         base=base).encode()


def aplicar_accion_fuentes(form: dict):
    """POST /fuentes: agregar, editar o borrar feeds RSS."""
    cfg = json.loads(CONFIG.read_text())
    accion = form.get("accion", [""])[0]

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

    if accion == "agregar":
        f = datos_fuente()
        if f["nombre"] and f["url"].startswith("http"):
            cfg["fuentes"].append(f)
    elif accion == "editar":
        try:
            idx = int(form.get("idx", ["-1"])[0])
            f = datos_fuente()
            if f["nombre"] and f["url"].startswith("http"):
                cfg["fuentes"][idx] = f
        except (ValueError, IndexError):
            pass
    elif accion == "borrar":
        try:
            del cfg["fuentes"][int(form.get("idx", ["-1"])[0])]
        except (ValueError, IndexError):
            pass
    CONFIG.write_text(json.dumps(cfg, ensure_ascii=False, indent=2))


def backfill_regla(regla: dict) -> int:
    """Al crear/editar una regla, revisa las noticias YA guardadas y
    registra alertas retroactivas (sin notificar ni mandar correo).
    Devuelve cuántas coincidencias históricas se agregaron."""
    ya = {(a["link"], a["reglas"]) for a in leer_jsonl(ALERTAS)}
    n = 0
    with ALERTAS.open("a") as f:
        for nota in leer_jsonl(NOTICIAS):
            if (nota["link"], regla["nombre"]) in ya:
                continue
            texto = f"{nota['titulo']} {nota.get('autor', '')}"
            if coincide(texto, regla):
                alerta = {
                    "fecha": nota["fecha"],
                    "fuente": nota["fuente"],
                    "categoria": nota.get("categoria", "prensa"),
                    "autor": nota.get("autor", ""),
                    "reglas": regla["nombre"],
                    "titulo": nota["titulo"],
                    "link": nota["link"],
                    "imagen": nota.get("imagen", ""),
                    "resumen_ia": "",
                }
                f.write(json.dumps(alerta, ensure_ascii=False) + "\n")
                ya.add((nota["link"], regla["nombre"]))
                n += 1
    return n


def aplicar_accion_config(form: dict) -> str:
    """POST /config: agregar, editar o borrar reglas de alerta.
    Devuelve la ruta a donde redirigir (/alertas tras agregar, para ver
    las coincidencias históricas al instante)."""
    cfg = json.loads(CONFIG.read_text())
    accion = form.get("accion", [""])[0]
    destino = "/config"
    if accion == "agregar":
        nombre = form.get("nombre", [""])[0].strip()
        palabras = [p.strip() for p in form.get("palabras", [""])[0].split(",") if p.strip()]
        # mínimo 2 palabras/frases: una sola dispara ruido puro
        if nombre and len(palabras) >= 2:
            regla = {"nombre": nombre, "requiere_todas": palabras,
                     "color": form.get("color", [""])[0]}
            cfg["alertas"].append(regla)
            backfill_regla(regla)
            destino = "/alertas"
    elif accion == "borrar":
        try:
            del cfg["alertas"][int(form.get("idx", ["-1"])[0])]
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
                cfg["alertas"][idx] = regla
                backfill_regla(regla)
        except (ValueError, IndexError):
            pass
    CONFIG.write_text(json.dumps(cfg, ensure_ascii=False, indent=2))
    return destino


def servir_web(puerto: int):
    class Handler(BaseHTTPRequestHandler):
        def _base(self) -> str:
            """URL absoluta del server según el Host del request
            (sirve igual por IP local que por dominio)."""
            return "http://" + self.headers.get("Host", f"localhost:{puerto}")

        def _html(self, contenido: bytes, code: int = 200):
            self.send_response(code)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(contenido)

        def do_GET(self):
            ruta = urlparse(self.path)
            params = parse_qs(ruta.query)
            base = self._base()
            if ruta.path == "/":
                self._html(render_pagina(vista_destacadas(), base=base))
            elif ruta.path == "/alertas":
                self._html(render_pagina(vista_alertas(), base=base))
            elif ruta.path == "/noticias":
                self._html(render_pagina(vista_noticias(), base=base))
            elif ruta.path == "/buscar":
                q = params.get("q", [""])[0]
                self._html(render_pagina(vista_buscar(q), q=q, base=base))
            elif ruta.path == "/config":
                self._html(render_pagina(vista_config(), base=base))
            elif ruta.path == "/fuentes":
                self._html(render_pagina(vista_fuentes(), base=base))
            elif ruta.path == "/stats":
                self._html(render_pagina(vista_stats(), base=base))
            elif ruta.path == "/acerca":
                self._html(render_pagina(vista_acerca(), base=base))
            elif ruta.path == "/nota":
                u = params.get("u", [""])[0]
                nota = vista_nota(u) if u else "<h1>Sin URL</h1>"
                self._html(render_pagina(nota, base=base))
            elif ruta.path == "/exportar":
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Disposition",
                                 "attachment; filename=noticias_reporte.txt")
                self.end_headers()
                self.wfile.write(exportar_reporte())
            elif ruta.path == "/manifest.webmanifest":
                self.send_response(200)
                self.send_header("Content-Type", "application/manifest+json")
                self.end_headers()
                self.wfile.write(MANIFEST)
            elif ruta.path == "/icon.png":
                global _ICONO
                if _ICONO is None:
                    _ICONO = icono_png()
                self.send_response(200)
                self.send_header("Content-Type", "image/png")
                self.send_header("Cache-Control", "public, max-age=86400")
                self.end_headers()
                self.wfile.write(_ICONO)
            else:
                self._html(render_pagina("<h1>404</h1><p>Ruta no existe.</p>",
                                         base=base), 404)

        def do_POST(self):
            ruta = urlparse(self.path)
            if ruta.path in ("/config", "/fuentes"):
                largo = int(self.headers.get("Content-Length", 0))
                form = parse_qs(self.rfile.read(largo).decode())
                if ruta.path == "/config":
                    destino = aplicar_accion_config(form)
                else:
                    aplicar_accion_fuentes(form)
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
    print(f"Fuentes: {len(cfg['fuentes'])} | Reglas de alerta: {len(cfg['alertas'])}\n")

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
            revisar(cfg, args.todo, args.resumir)
            print(f"\n--- durmiendo {args.loop} min ---")
            time.sleep(args.loop * 60)
    else:
        n = revisar(cfg, args.todo, args.resumir)
        print(f"\nTotal alertas: {n}")


if __name__ == "__main__":
    sys.exit(main())
