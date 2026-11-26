"""Codigo extraido de monitor.py (nov 2026) — subsistema de portadas
y scraping con cuentas FB/X de la era crontab, desactivado por
pausar_scraping/fb_pausa en config.json.

ARCHIVO DE REFERENCIA — no se importa, no corre. Para revivir
portadas hay que reintegrar estas funciones en monitor.py (git
tiene el archivo original completo de todas formas).
"""


# ─── bloque 0: monitor.py líneas 2559–2657 ───

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



# ─── bloque 1: monitor.py líneas 2662–2704 ───

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

# ─── bloque 2: monitor.py líneas 2710–2710 ───

_FB_POSTS_CORRIENDO = False

# ─── bloque 3: monitor.py líneas 2764–2800 ───

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



# ─── bloque 4: monitor.py líneas 2830–4172 ───

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
    handles = [h.lstrip("@").strip()
               for h in str(m.get("x", "")).split(",") if h.strip()]
    if not handles or not X_SESSION.exists():
        return []
    # profundidad (5/nov): en cuentas que tuitean cada pocos minutos
    # (xevtfm ~6/h) el tweet de portada queda a >30 posts del perfil —
    # 1) búsqueda 'from:handle' con términos de plana llega horas atrás;
    # 2) pestaña /media = solo tweets con foto (~4x más alcance);
    # 3) perfil como último recurso
    # handles alternos por coma (9/nov): XEVT a veces publica su plana
    # en @EmmanuelSibilla (su dueño) — se agota cada handle antes de
    # pasar al siguiente; el primero con plana usable gana
    hoy = datetime.now().date()
    for handle in handles:
        fuentes = (
            f'buscar:from:{handle} portada OR "primera plana"'
            ' OR contraportada OR "edicion impresa"'
            ' OR "edicion digital"',
            f"media:{handle}",
            handle)
        for src in fuentes:
            try:
                posts = _scrapear_x_posts(src)
            except Exception:
                continue
            imgs = _portada_imgs_de_posts(m, handle, posts, hoy)
            if imgs:
                return imgs
    return []


def _portada_imgs_de_posts(m: dict, handle: str,
                           posts: list, hoy) -> list:
    """Filtra posts del autor de hoy y baja las imágenes que pasen los
    candados de portada (texto que anuncie plana o imagen con formato
    y densidad de primera)."""
    imgs = []
    for p_ in posts:
        if p_.get("_autor", "").lower() != f"@{handle}".lower():
            continue                    # retweets/ads
        pp = p_.get("published_parsed")
        if not pp:
            continue
        # posts de hoy o desde el mediodía de ayer — varios medios
        # (Jaguar/LaDenuncia ~23:2x) tuitean la plana la víspera;
        # la pasada de 01:00 los junta con los de las 7am (7/nov)
        dt = datetime.fromtimestamp(calendar.timegm(pp))
        if dt.date() != hoy and dt < datetime.combine(
                hoy - timedelta(days=1), datetime.min.time()) \
                .replace(hour=12):
            continue
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



# ─── bloque 5: monitor.py líneas 4173–4258 ───

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



# ─── bloque 6: monitor.py líneas 4268–4328 ───

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



# ─── bloque 7: monitor.py líneas 4356–4362 ───

# NO WEB SHOTS — orden del usuario: ningún medio puede caer a
# screenshot de homepage; solo impresas reales (kiosko/fb/issuu/etc).
# Las estrategias que SI capturan la propia portada (PR visor,
# img_portada, pdf) no son screenshots de homepage y siguen activas.
_WEB_SHOTS = False



# ─── bloque 8: monitor.py líneas 4401–4928 ───

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
        if m.get("x") and not data and _x_pasada_activa(
                (cfg or {}).get("portadas") or {}):
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
        # pasada X activa: los medios-x no esperan su intervalo —
        # si el throttle los brincara, la pasada correría vacía
        pasada_x = m.get("x") and _x_pasada_activa(port, ahora_m)
        if not pasada_x and \
                (ahora - ult).total_seconds() < intervalo * 60:
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
        # auditoría de operadores: se regeneraba a mano y quedaba
        # congelada (2/nov) — misma cadencia diaria que la salud
        try:
            subprocess.run([sys.executable, str(BASE / "gen_auditoria.py")],
                           timeout=120)
        except Exception:
            pass
    escribir_schedule_portadas(cfg)   # refresca línea de tiempo



# ─── bloque 9: monitor.py líneas 4950–4967 ───

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



# ─── bloque 10: monitor.py líneas 5082–5281 ───

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
        creator="PIRIA")
    for i in imgs:
        i.close()
    return buf.getvalue(), fallos


def generar_pdfs_portadas(cfg: dict, marca: str = "pdf_fecha"):
    """Hora_pdf (06:30): arma los PDFs con lo recolectado, los manda
    por correo y lista los que no respondieron.
    `marca` = llave del estado que registra qué emisión ya salió."""
    medios = cfg.get("portadas", {}).get("medios", [])
    hoy = datetime.now().strftime("%Y-%m-%d")
    # marcar inmediatamente para evitar que el loop principal vuelva a
    # disparar otro hilo mientras este corre (el loop revisa cada 5 min)
    est = cargar_json(ESTADO_PORTADAS, {})
    est[marca] = hoy
    _guardar_portadas(est)
    escribir_schedule_portadas(cfg)   # schedule.html siempre al día
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
    print(f"[portadas] {len(pdfs)} PDFs enviados ({marca}), fallos: "
          f"{fallos or 'ninguno'}\n")


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



# ─── bloque 11: monitor.py líneas 5756–5845 ───

def toca_captura_portadas(cfg: dict) -> bool:
    """Ventana de recolección [hora_desde, hora_cierre): corre cada ~55 min
    mientras falte algún medio — kiosko sale de madrugada, FB a las
    00:0x, issuu/pdf cuando lo suban."""
    port = cfg.get("portadas", {})
    medios = port.get("medios", [])
    if not medios or not _dia_portadas(port):
        return False
    ahora = datetime.now()
    ahora_m = ahora.hour * 60 + ahora.minute
    cierre = max(_hhmm(port, "hora_cierre", "08:45"),
                 _hora_pdf_hoy(port, ahora))
    # la pasada X de cierre (ej. 08:45) corre aunque hora_cierre ya
    # haya llegado — es justo la última oportunidad del día
    if not (_hhmm(port, "hora_desde", "00:30") <= ahora_m < cierre) \
            and not _x_pasada_activa(port, ahora_m):
        return False
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
