"""Codigo extraido de monitor.py (nov 2026) — separacion de
productos: subsistema @noticias (sintesis ejecutivas, reportes,
correos Brevo/SMTP, portadas impresas, scraping X).

ARCHIVO DE REFERENCIA — no se importa, no corre. Git conserva
el monitor.py original completo.
"""


# ─── bloque 0: monitor.py líneas 398–499 ───

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



# ─── bloque 1: monitor.py líneas 942–1618 ───

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
                    author="@noticias", creator="PIRIA")
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



# ─── bloque 2: monitor.py líneas 1779–1947 ───

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
    es_media = handle.lower().startswith("media:")
    if buscar:
        target = "https://x.com/search?q=" + quote(handle[7:]) + "&f=live"
    elif es_media:
        # pestaña Media: solo tweets CON foto — para portadas da ~4x
        # más profundidad que el perfil (que mezcla retweets y texto)
        target = f"https://x.com/{handle[6:]}/media"
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



# ─── bloque 3: monitor.py líneas 2397–2397 ───

SINTESIS = BASE / "sintesis.jsonl"  # síntesis IA: 2/día (9:00 y 16:00)

# ─── bloque 4: monitor.py líneas 2535–2558 ───

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



# ─── bloque 5: monitor.py líneas 2559–2657 ───

FB_SESSION = BASE / "fb_session.json"
FB_SESSION_REDES = BASE / "fb_session_redes.json"  # chucky — posts


X_SESSION = BASE / "x_session.json"              # X — timeline
X_POSTS = BASE / "x_posts.jsonl"               # log de publicados
_ULT_X = 0.0               # epoch de la última pasada de fuentes tipo x
_X_ESP = 30 * 60           # segundos hasta el próximo barrido x (jittered)


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


def _launch(p):
    """Playwright sin browsers propios → usa el google-chrome del
    sistema; si existiera el bundle de playwright también sirve."""
    try:
        return p.chromium.launch()
    except Exception:
        return p.chromium.launch(channel="chrome")



# ─── bloque 6: monitor.py líneas 2658–2749 ───

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



# ─── bloque 7: monitor.py líneas 2796–3477 ───

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
        creator="PIRIA")
    for i in imgs:
        i.close()
    return buf.getvalue(), fallos


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
                   "edicion", "json", "calameo", "flowpaper", "x"))
    desde = _min(m.get("cap_desde") or port.get("hora_desde", "00:30"))
    hasta = _min(m.get("cap_hasta") or port.get("hora_cierre")
                 or port.get("hora_pdf", "06:30"))
    hasta = max(hasta, _hora_pdf_hoy(port))
    if not impresa:
        desde = max(desde, _hhmm(port, "hora_web", "05:45"))
    return desde, hasta


def _x_pasada_activa(port: dict, ahora_m: int = None) -> bool:
    """Compuerta X (5/nov): los medios con vía 'x' solo se intentan
    durante las pasadas configuradas en port.x_pasadas — cada marca
    abre una ventana de ~20 min (5 antes, 15 después). Fuera de ahí
    no se gasta sesión de X en reintentos que darían lo mismo:
    la búsqueda 'from:' y la pestaña /media ya llegan horas atrás."""
    pasadas = port.get("x_pasadas") or []
    if not pasadas:
        return True      # sin config → comportamiento de siempre
    if ahora_m is None:
        ahora = datetime.now()
        ahora_m = ahora.hour * 60 + ahora.minute
    for h in pasadas:
        try:
            hh, mm = map(int, str(h).split(":"))
        except Exception:
            continue
        marca = hh * 60 + mm
        if marca - 5 <= ahora_m <= marca + 15:
            return True
    return False


def _en_ventana(m: dict, port: dict, ahora_m: int) -> bool:
    # pausa de un solo día (ej. el medio no publicó hoy) — la fecha
    # vencida queda inerte, no hay que quitarla
    if m.get("skip_hoy") == datetime.now().strftime("%Y-%m-%d"):
        return False
    desde, hasta = _ventana_medio(m, port)
    if desde <= ahora_m <= hasta:
        return True
    # pasada X posterior al cap_hasta (ej. la marca de las 08:45):
    # medios con vía x pendientes entran un rato más aunque su ventana
    # ya cerró — última chance de captura antes de que acabe el día
    if m.get("x") and ahora_m > hasta and \
            _x_pasada_activa(port, ahora_m):
        return True
    return False


def _reglas_medio(m: dict) -> str:
    """Texto de reglas de captura — alimenta la columna Reglas de
    schedule.html (se regenera al guardar /horarios y en cada GET)."""
    r = []
    if m.get("kiosko"):
        r.append("JPG fechado de hoy/ayer en Kiosko")
    if m.get("fb"):
        r.append("Post de hoy con texto 'portada/edición'")
    if m.get("x"):
        r.append("Tweet de hoy con media (solo en pasadas X)")
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
    corre al guardar /horarios y en cada GET, para no desactualizarse."""
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
        ".catch(function(){el.style.outline='2px solid red';});});});"
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



# ─── bloque 8: monitor.py líneas 3478–3598 ───

def vista_portadas(sec: str, dia: str = "", admin: bool = False,
                   logueado: bool = False) -> str:
    """Tab Portadas: UNA sola grid con TODAS las capturas — locales
    primero, nacionales después. ?dia=oct/06 navega subcarpetas para
    cotejar un día contra otro. `sec` queda solo por compat de URL."""
    cfg = json.loads(CONFIG.read_text())
    port = cfg.get("portadas", {})
    medios = list(port.get("medios", []))
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
        f"href='/portadas?dia={d}'>{d}</a>" for d in dias)
        + "</div>") if dias else ""
    # PDFs por sección al click (los tardíos entran hasta ~9am); solo
    # usuarios con sesión
    pdf_block = ("<p class='meta'>PDF: "
                 + "".join(
                     f"<a class='tab-cat on' "
                     f"href='/portadas-pdf?sec={s}&dia={dia_sel}' "
                     f"target='_blank'>{s}</a> "
                     for s in ("tabasco", "nacional"))
                 + "</p>" if logueado else "")
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
    # locales primero, nacionales después; dentro de cada bloque el
    # más reciente arriba (sort estable: primero hora, luego bloque)
    medios.sort(key=lambda m: _hora_ev.get(m["nombre"], ""),
                reverse=True)
    medios.sort(
        key=lambda m: m.get("seccion", "nacional") == "nacional")
    cards = ""
    _grupo = None
    for m in medios:
        if m.get("seccion", "nacional") != _grupo:
            _grupo = m.get("seccion", "nacional")
            _rotulo = {"tabasco": "Local"}.get(_grupo, _grupo.title())
            cards += (f"<h2 style='margin:1.1rem 0 .4rem'>"
                      f"{html.escape(_rotulo)}</h2>")
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
    return (f"<h1>Portadas — {dia_sel}</h1>"
            f"{tabs_dia}"
            f"<p class='meta'>Capturas del {ultima or '—'} · se regeneran a "
            f"las {html.escape(port.get('hora', '06:30'))}.</p>"
            + avisos + pdf_block + cards)



# ─── bloque 9: monitor.py líneas 3728–3849 ───

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



# ─── bloque 10: monitor.py líneas 6292–6840 ───

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



# ─── bloque 11: monitor.py líneas 11713–11776 ───

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



# ═══ RUTAS (handlers HTTP) extraídas en segunda pasada ═══

# ─── rutas bloque 0: líneas 9207–9236 ───

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

# ─── rutas bloque 1: líneas 9418–9576 ───

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

# ─── rutas bloque 2: líneas 9874–9905 ───

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


# ─── rutas bloque 3: líneas 9939–10005 ───

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


# ─── rutas bloque 4: líneas 10006–10040 ───

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
