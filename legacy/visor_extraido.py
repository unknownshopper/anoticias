"""Codigo extraido de monitor.py (nov 2026) — CORTE FINAL:
el producto queda como "tweetdeck" = redaccion + chat + asistente.
Aqui vive el visor/colector eliminado: revisar feeds, vistas de
noticias/x/interes/columnas/destacadas/buscar/alertas, lector de
notas, reglas, dedup, badges de feed.

ARCHIVO DE REFERENCIA — no se importa, no corre.
"""


# ─── bloque 0: monitor.py líneas 69–115 ───

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



# ─── bloque 1: monitor.py líneas 260–272 ───

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



# ─── bloque 2: monitor.py líneas 297–317 ───

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



# ─── bloque 3: monitor.py líneas 318–327 ───

def fmt_fecha(iso: str) -> str:
    """'2026-09-30T02:41:00' -> '30/09/2026 02:41' — año siempre visible,
    evita confusiones con alertas de otros años."""
    try:
        d = datetime.fromisoformat(iso)
        return d.strftime("%d/%m/%Y %H:%M")
    except Exception:
        return iso[:16]



# ─── bloque 4: monitor.py líneas 350–391 ───

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
    """Guarda la alerta en alertas.jsonl y notifica al escritorio."""
    with ALERTAS.open("a") as f:
        f.write(json.dumps(alerta, ensure_ascii=False) + "\n")
    try:
        subprocess.run(
            ["notify-send", f"ALERTA: {alerta['reglas']}", alerta["titulo"]],
            timeout=5, capture_output=True,
        )
    except Exception:
        pass  # notify-send no está en todos los entornos


def guardar_noticia(nota: dict):
    """Guarda cada nota capturada en noticias.jsonl (capped)."""
    with NOTICIAS.open("a") as f:
        f.write(json.dumps(nota, ensure_ascii=False) + "\n")



# ─── bloque 5: monitor.py líneas 392–405 ───

def url_https(url: str) -> str:
    """Sube http→https: evita 'Mixed Content' cuando la página va por TLS."""
    return "https://" + url[7:] if url.startswith("http://") else url


# ---- Rate limit por IP (login fuerza bruta + flood de requests) ----
_RL_HITS: dict = {}
_RL_SKIP_IPS: set = set()
_RL_SKIP_MT: float = 0
RL_AUTO_FILE = BASE / "rl_auto.json"  # IPs con login exitoso
_RL_AUTO: set = set()
_RL_AUTO_LOADED = False



# ─── bloque 6: monitor.py líneas 473–625 ───

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



# ─── bloque 7: monitor.py líneas 750–768 ───

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



# ─── bloque 8: monitor.py líneas 782–1700 ───

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


def _correo_entradas(cfg: dict, st: dict) -> list:
    """Buzón IMAP como fuente (9/nov): las alertas automáticas que
    llegan por correo — Grok en X, Google Alerts… — entran al
    pipeline normal (dedup, reglas, correos a operadores).

    Lectura readonly por UID creciente: nada se marca leído ni se
    borra, y st['imap_uid'] recuerda dónde quedó la última pasada.
    Devuelve [] si el buzón está vacío o deshabilitado, None si el
    login/la red falló."""
    im = cfg.get("correo_lectura") or {}
    if not (im.get("habilitado") and im.get("usuario")
            and im.get("password")):
        return []
    try:
        M = imaplib.IMAP4_SSL(im.get("host", "imap.gmail.com"),
                              int(im.get("puerto", 993)))
        M.login(im["usuario"], im["password"])
        M.select(im.get("carpeta", "INBOX"), readonly=True)
        desde = (datetime.now() - timedelta(days=3)).strftime(
            "%d-%b-%Y")
        _, data = M.uid("search", None, f"(SINCE {desde})")
        ids = data[0].split()[-50:]
        ult = int(st.get("imap_uid") or 0)
        if not ult and ids:
            # baseline: primera pasada solo siembra el UID — el buzón
            # lleva correos viejos que no son alertas nuestras
            st["imap_uid"] = int(ids[-1])
            M.logout()
            return []
        rems = [s.lower() for s in im.get("remitentes", [])]
        asunto_rx = (re.compile(im["asunto"], re.I)
                     if im.get("asunto") else None)
        ents, nuevo_ult = [], ult
        for uid in ids:
            u = int(uid)
            if u <= ult:
                continue
            nuevo_ult = max(nuevo_ult, u)
            _, msg = M.uid("fetch", uid, "(RFC822)")
            m = email_mod.message_from_bytes(msg[0][1])
            de = (m.get("From") or "").lower()
            if rems and not any(s in de for s in rems):
                continue
            subj = "".join(
                t.decode(cs or "utf-8", "replace")
                if isinstance(t, bytes) else t
                for t, cs in decode_header(m.get("Subject") or ""))
            if asunto_rx and not asunto_rx.search(subj):
                continue
            cuerpo = ""
            for parte in m.walk():
                ct = parte.get_content_type()
                if ct in ("text/plain", "text/html") and not cuerpo:
                    cuerpo = (parte.get_payload(decode=True) or b"")\
                        .decode(parte.get_content_charset("utf-8"),
                                "replace")
            cuerpo = re.sub(r"<[^>]+>", " ", cuerpo)
            cuerpo = html.unescape(re.sub(r"\s+", " ", cuerpo))[:900]
            links = [l for l in re.findall(
                r'https?://[^\s"<>()\[\]]+', cuerpo)
                if not re.search(
                    r"unsubscribe|mailto|schema\.org|w3\.org", l, re.I)]
            try:
                pp = parsedate_to_datetime(m.get("Date"))\
                    .timetuple()
            except Exception:
                pp = None
            if not links:
                links = [f"imap:{u}"]   # correo sin link rastreable
            for lnk in dict.fromkeys(links):
                h = re.search(
                    r"(?:x|twitter)\.com/([A-Za-z0-9_]{1,20})/status",
                    lnk)
                ents.append({"link": lnk.split(",")[0].rstrip(".);"),
                             "title": subj.strip() or "Alerta correo",
                             "summary": cuerpo,
                             "published_parsed": pp,
                             "_autor": f"@{h[1]}" if h else ""})
        M.logout()
        st["imap_uid"] = nuevo_ult
        return ents
    except Exception as e:
        print(f"[!] correo_lectura: {e}")
        return None


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
        "PIRIA-Monitor/1.0 (+mailto:the@unknownshoppers.com)")
    for i, fuente in enumerate(
            random.sample(list(cfg["fuentes"]), len(cfg["fuentes"]))):
        if fuente.get("activa") is False:
            continue   # apagada en catálogo (ej. bloque QRoo en esta instancia)
        if fuente.get("tipo") in ("fb", "x"):
            continue   # scraping de cuentas retirado (nov 2026) —
                       # ver legacy/anoticias_extraido.py
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
        elif fuente.get("tipo") == "imap":
            # buzón de alertas (Grok/GA) — solo corre si correo_lectura
            # está configurado; buzón vacío no es error
            entradas = _correo_entradas(cfg, st)
            if entradas is None:
                st["err"] += 1
                continue
            st["ok"] += 1
            st["ultimo_ok"] = datetime.now().isoformat(timespec="seconds")
        elif fuente.get("tipo") == "x":
            continue   # sin scraper — fuentes x quedan solo históricas
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
            if fuente.get("tipo") in ("x", "imap") \
                    and entrada.get("_autor"):
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


def vista_salud(admin: bool = True) -> str:
    """Tab Salud (admin): diagnóstico del sistema sin abrir logs —
    fuentes de notas calladas y rendimiento del colector."""
    cfg = json.loads(CONFIG.read_text())
    est = cargar_json(ESTADO_PORTADAS, {})
    ahora = datetime.now()
    out = ["<h1>Salud del sistema</h1>"]

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

# ─── bloque 9: monitor.py líneas 2282–2361 ───

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
  {demo}
  <p class="pie">Powered by <a href="https://unknownshopper.github.io/PIRIA" target="_blank" rel="noopener" style="color:#c3c9d4">PIRIA</a></p>
</div>
</body></html>"""



# ─── bloque 10: monitor.py líneas 2371–2435 ───

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



# ─── bloque 11: monitor.py líneas 2446–5117 ───

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
    # usuarios del panel de redacción: la búsqueda es solo contenido
    # propio + alertas — nada de corpus del monitor ni consultas WP
    en_red = ("@demo.local" in (email or "")
              or es_supervisor(email, cfg) or area_de_usuario(email, cfg))
    vis = fuentes_visibles(perfil_usuario(email, cfg), cfg)
    notas_txt = [] if en_red else _notas_texto(vis)   # cache mtime
    noticias = [n for n, _ in notas_txt]
    alertas = [a for a in leer_jsonl(ALERTAS)
               if not a.get("usuario") or a["usuario"] == email]
    hits_n = [n for n, txt in notas_txt
              if all(termino_en(t, txt) for t in agujas)]
    hits_a = [a for a in alertas if all(
        termino_en(t, normalizar(a["titulo"] + " " + a["reglas"]
                                 + " " + (a.get("autor") or "")))
        for t in agujas)]
    # redacción interna: las notas de los colaboradores también se
    # buscan — para el equipo, la nota propia es el resultado clave
    pubs = [p for p in cargar_publicaciones()
            if all(termino_en(t, normalizar(
                " ".join([p.get("titulo") or "", p.get("resumen") or "",
                          p.get("texto") or "", p.get("nombre") or ""])))
                for t in agujas)]
    # si la alerta ya está como noticia en resultados, no duplicar
    links_n = {n["link"] for n in hits_n}
    hits_a = [a for a in hits_a if a["link"] not in links_n]
    # archivo vivo de los medios (WP): pesca notas que el feed no trajo.
    # Solo para el monitor viejo — en redacción la búsqueda debe ser
    # instantánea (las notas propias + alertas, sin salir a la web)
    vivos = ([] if en_red or not q.strip() else
             busqueda_viva_wp(q, cfg,
                              links_n | {a["link"] for a in hits_a}))
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
    # resultados de redacción — van primero: son contenido propio
    pub_html = "".join(
        f"<div class='card'><a href='/redaccion/nota?id={p.get('id')}'>"
        f"{html.escape((p.get('titulo') or p.get('texto') or '')[:90])}"
        f"</a><div class='meta'>"
        f"{html.escape(p.get('nombre') or _red_nombre(p.get('usuario','')))}"
        f" · {fmt_fecha(p.get('ts',''))} · nota de redacción →</div>"
        f"</div>" for p in pubs)
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
            f"<p class='meta'>{len(pubs)} redacción · {len(hits_n)} "
            f"notas · {len(hits_a)} alertas"
            f" · frase exacta: \"entre comillas\"</p>"
            f"{btn_deep}"
            + (f"<h2>Redacción ({len(pubs)})</h2>" + pub_html
               if pubs else "")
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


MANTENIMIENTO = """<!DOCTYPE html>
<html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="theme-color" content="#1a237e">
<link rel="icon" type="image/png" href="/icon3.png">
<title>@noticias — Mantenimiento</title>
<style>
  * { box-sizing: border-box; }
  body { font-family: system-ui, sans-serif; margin: 0; min-height: 100vh;
         background: #f6f7f9; display: flex; align-items: center;
         justify-content: center; padding: 1rem; }
  .box { width: 100%; max-width: 380px; text-align: center;
         background: #fff; border: 1px solid #e4e6ef;
         border-radius: 16px; padding: 2.6rem 1.6rem;
         box-shadow: 0 10px 30px rgba(26,35,126,.07); }
  .logo { font-size: 2.6rem; font-weight: 800; color: #1a237e;
          letter-spacing: -.02em; margin: 0 0 .4rem; }
  h1 { font-size: 1.05rem; color: #333; margin: .6rem 0 .4rem; }
  p { color: #777; font-size: .9rem; line-height: 1.55; margin: 0 0 1.6rem; }
  a.btn { display: inline-block; padding: .85rem 2.2rem; background: #1a237e;
          color: #fff; border-radius: 10px; text-decoration: none;
          font-weight: 600; font-size: 1rem; }
  a.btn:hover { background: #283593; }
  .pie { color: #c3c9d4; font-size: .75rem; margin-top: 2rem; }
</style></head><body>
<div class="box">
  <p class="logo">@noticias</p>
  <h1>Sitio en mantenimiento</h1>
  <p>Estamos trabajando para mejorar el servicio.<br>
     Vuelve en unos minutos.</p>
  <a class="btn" href="/login">Entrar</a>
  <p class="pie">Powered by PIRIA</p>
</div>
</body></html>"""



# ─── bloque 12: monitor.py líneas 5226–5578 ───

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



# ─── bloque 13: monitor.py líneas 8745–8855 ───

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



# ─── bloque 14: monitor.py líneas 8909–8999 ───

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


