#!/usr/bin/env python3
"""Regenera las capturas del instructivo (shots/*.png).

Renderiza cada vista con las funciones reales de monitor.py — sin
servidor ni sesión — y las captura con chromium headless a ancho móvil.
Correlo cuando cambie el diseño:

    .venv/bin/python shots.py
"""
import html as htmlmod
import json
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import monitor  # noqa: E402  (vista_*, render_pagina, etc.)

BASE = Path(__file__).parent
SHOTS = BASE / "shots"
ADMIN = next(iter(__import__("json").loads(
    monitor.USUARIOS.read_text())))  # primer usuario = admin


# ---------------- fixtures ficticias ----------------
# El instructivo no debe salir con notas reales (violencia, accidentes):
# inventamos una mañana tranquila — aeropuertos, obras, clima, cultura.
_FUENTES = {
    "prensa": ["Tabasco Hoy", "En Cambio", "Novedades de Tabasco",
               "Diario Ahora Noticias", "Tabasco al Día"],
    "nacional": ["Reforma", "El Universal", "Milenio", "Excélsior",
                 "La Jornada", "El Financiero", "El Economista"],
    "quintana_roo": ["El Quequi", "SIPSE", "Por Esto!"],
    "deportes": ["Récord", "ESPN", "Mediotiempo"],
    "internacional": ["BBC Mundo", "El País", "Reuters"],
    "oficial": ["Gobierno de Tabasco", "Gobierno QRoo"],
}

_NOTAS = [
    ("prensa", "Tabasco Hoy",
     "Inauguran nueva sala de abordar en el aeropuerto de Villahermosa"),
    ("prensa", "En Cambio",
     "Amplían a cuatro carriles la avenida Universidad; terminan en enero"),
    ("prensa", "Novedades de Tabasco",
     "Festival del Chocolate abrirá con récord de asistentes, estiman"),
    ("prensa", "Diario Ahora Noticias",
     "Rescatan 120 nidos de tortuga en playas del litoral tabasqueño"),
    ("prensa", "Tabasco al Día",
     "Museo Carlos Pellicer estrena sala dedicada al arte olmeca"),
    ("prensa", "Tabasco Hoy",
     "Llegan lluvias moderadas el fin de semana; activan alerta pluvial"),
    ("prensa", "En Cambio",
     "Parque Tomás Garrido cierra 8 días por mantenimiento de andadores"),
    ("nacional", "Reforma",
     "AICM abre 12 nuevas rutas nacionales y recupera ocupación de 84%"),
    ("nacional", "El Universal",
     "Termina rehabilitación de la pista del aeropuerto de Villahermosa"),
    ("nacional", "Milenio",
     "Tren Maya suma estación de carga para productos del sureste"),
    ("nacional", "Excélsior",
     "Dos Bocas exporta primer cargamento de fertilizantes a Centroamérica"),
    ("nacional", "La Jornada",
     "Biblioteca Nacional digitaliza 40 mil documentos del siglo XIX"),
    ("nacional", "El Financiero",
     "Inversión extranjera en energía limpia crece 12% en el año"),
    ("nacional", "El Economista",
     "Bajará 4% el precio del boleto en rutas turísticas del sureste"),
    ("nacional", "Reforma",
     "Congreso aprueba reforma de movilidad segura para ciclistas"),
    ("nacional", "Milenio",
     "Inauguran terminal de carga en el puerto de Frontera"),
    ("quintana_roo", "El Quequi",
     "Coatzacoalcos-Cochabamba: ferrocarril cargará 3 mil toneladas más"),
    ("quintana_roo", "SIPSE",
     "Aeropuerto de Cancún estrena carrusel de equipaje automatizado"),
    ("quintana_roo", "Por Esto!",
     "Cenotes de Tulum abren temporada con protocolos de conservación"),
    ("deportes", "Récord",
     "Jaguares de Tabasco confirman pretemporada en el Centenario"),
    ("deportes", "ESPN",
     "México sede del torneo regional de voleibol de playa 2027"),
    ("internacional", "BBC Mundo",
     "Singapur inaugura la terminal aérea más eficiente del mundo"),
    ("internacional", "El País",
     "El puerto de València duplica su capacidad de contenedores"),
    ("internacional", "Reuters",
     "S&P mejora a positiva la perspectiva de infraestructura mexicana"),
    ("oficial", "Gobierno de Tabasco",
     "Diputados promueven ley de movilidad segura en el estado"),
    ("oficial", "Gobierno QRoo",
     "Abre convocatoria para becas de posgrado en tecnología"),
    ("oficial", "Gobierno de Tabasco",
     "Bomberos rescatan a perro atrapado en alcantarilla del centro"),
    ("deportes", "Mediotiempo",
     "Atleta tabasqueño rompe récord nacional en 100 metros"),
]

_ALERTAS = [
    ("Justicia", "nacional", "Reforma",
     "Poder Judicial digitaliza expedientes y audiencias virtuales"),
    ("Justicia", "prensa", "Tabasco Hoy",
     "TSJ estrena módulo de atención ciudadana en palacio judicial"),
    ("Infraestructura", "nacional", "Milenio",
     "Gobierno estatal inaugura terminal de carga en Frontera"),
    ("Infraestructura", "prensa", "En Cambio",
     "Avanza rehabilitación de la avenida Universidad; abre en enero"),
    ("Tren Maya", "oficial", "Gobierno de Tabasco",
     "Municipio coordina obras del Tren Maya en el tramo sur"),
    ("Parques", "oficial", "Gobierno de Tabasco",
     "Plan de mantenimiento llega a 14 parques urbanos del estado"),
    ("Noticia en desarrollo (2→4 medios)", "deportes", "Récord",
     "Atleta tabasqueño rompe récord nacional en 100 metros"),
    ("Noticia en desarrollo (2→4 medios)", "nacional", "El Universal",
     "Termina rehabilitación de la pista del aeropuerto de Villahermosa"),
]

_RESUMEN = ("Las autoridades informaron que la obra concluirá en los "
            "próximos meses y beneficiará a usuarios y visitantes de la "
            "región. Detallaron que el proyecto forma parte del programa "
            "de modernización anunciado a inicios de año.")


def _fixtures(tmp: Path):
    """Escribe noticias/alertas/actividad ficticias y apunta el monitor a
    ellas. Devuelve la lista de noticias (para escoger la del lector)."""
    hoy = datetime.now()
    noticias, alertas, actividad = [], [], []
    for i, (cat, fuente, titulo) in enumerate(_NOTAS):
        f = hoy - timedelta(hours=i * 3 % 26, minutes=i * 7 % 60)
        noticias.append({
            "fecha": f.isoformat(timespec="seconds"),
            "fuente": fuente, "categoria": cat, "autor": "",
            "titulo": titulo, "link": f"https://ejemplo.mx/nota-{i}",
            "imagen": "",
            "resumen_ia": _RESUMEN if i % 4 == 0 else ""})
    for i, (regla, cat, fuente, titulo) in enumerate(_ALERTAS):
        f = hoy - timedelta(hours=i * 2 % 20, minutes=i * 13 % 60)
        alertas.append({
            "fecha": f.isoformat(timespec="seconds"),
            "fuente": fuente, "categoria": cat, "autor": "",
            "reglas": regla, "titulo": titulo,
            "link": f"https://ejemplo.mx/al-{i}", "imagen": "",
            "resumen_ia": _RESUMEN})
    t0 = hoy - timedelta(hours=30)
    for i in range(42):
        email = ADMIN if i % 3 else "guest-demo@demo.local"
        ruta = ["/", "/alertas", "/nota", "/destacadas", "/buscar"][i % 5]
        ev = {"ts": (t0 + timedelta(minutes=i * 31)).isoformat(
                     timespec="seconds"),
              "email": email, "ruta": ruta, "u": "", "q": "", "ref": "",
              "ua": "Mozilla/5.0 (iPhone)"}
        if ruta == "/nota":
            ev["u"] = noticias[i % len(noticias)]["link"]
        elif ruta == "/buscar":
            ev["q"] = ["aeropuerto", "tren maya", "inundación", "puerto"][
                i % 4]
        actividad.append(ev)

    for nombre, filas in (("noticias.jsonl", noticias),
                          ("alertas.jsonl", alertas),
                          ("actividad.jsonl", actividad)):
        f = tmp / nombre
        f.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n"
                             for r in filas))
    monitor.NOTICIAS = tmp / "noticias.jsonl"
    monitor.ALERTAS = tmp / "alertas.jsonl"
    monitor.ACTIVIDAD = tmp / "actividad.jsonl"
    return noticias


def _nota_falsa(link: str, captura: bool = False):
    """Lector con artículo inventado — mismo HTML que el de verdad."""
    t = "Inauguran nueva sala de abordar en el aeropuerto de Villahermosa"
    paras = [
        "Las autoridades de aviación civil inauguraron la nueva sala de "
        "abordar del aeropuerto internacional de Villahermosa, obra que "
        "amplía la capacidad de embarque en 40% y suma seis mesas de "
        "documentación automática.",
        "La inversión, de 182 millones de pesos, incluye además la "
        "renovación del sistema de climatización, nuevas bandas de "
        "equipaje y la señalización bilingüe de todas las áreas de "
        "espera. El proyecto se ejecutó en once meses sin interrumpir "
        "las operaciones.",
        "Durante el evento se informó que la terminal conectará en "
        "diciembre con tres destinos nuevos del sureste y recuperará la "
        "ruta diaria a la capital, suspendida desde el año pasado.",
        "El titular de la dependencia aseguró que la modernización "
        "continuará con la segunda etapa, que incluye la rehabilitación "
        "de la pista de aterrizaje y la ampliación del estacionamiento "
        "de largo plazo.",
    ]
    return ("<div class='lector'>"
            "<a href='javascript:history.back()'>← Regresar</a>"
            f"<h1>{t}</h1>"
            "<div class='meta'>Fuente: Tabasco Hoy · ejemplo.mx</div>"
            + "".join(f"<p>{p}</p>" for p in paras)
            + "<a class='origen' href='https://ejemplo.mx/nota-1' "
              "target='_blank' rel='noopener'>Abrir la nota en el "
              "medio ↗</a></div>",
            {"titulo": t, "imagen": "", "desc": _RESUMEN,
             "dominio": "ejemplo.mx"})


# (nombre_archivo, html) — html se renderiza igual que en el server
def paginas(tmp: Path):
    base = "https://noticias.unknownshoppers.com"
    _fixtures(tmp)

    def pag(vista):
        return monitor.render_pagina(vista, base=base, usuario=ADMIN)

    # los badges de /alertas salen del nombre de la regla viva — el perfil
    # real trae nombres de personas; para el instructivo añadimos reglas
    # temáticas ficticias (solo existen dentro de este proceso)
    perfil_real = monitor.perfil_usuario

    def perfil_demo(email, cfg):
        p = perfil_real(email, cfg)
        p["reglas"] = (p.get("reglas") or []) + [
            {"nombre": n, "requiere_todas": [n], "color": c}
            for n, c in (("Justicia", "#1a237e"),
                         ("Infraestructura", "#7b1fa2"),
                         ("Tren Maya", "#2e7d32"),
                         ("Parques", "#00838f"))]
        return p

    monitor.perfil_usuario = perfil_demo
    original_nota = monitor.vista_nota
    monitor.vista_nota = _nota_falsa
    try:
        nota, _ = monitor.vista_nota("https://ejemplo.mx/nota-1")
        docs = {
            "feed": pag(monitor.vista_noticias(ADMIN)),
            "alertas": pag(monitor.vista_alertas(ADMIN)),
            "destacadas": pag(monitor.vista_destacadas(ADMIN)),
            "buscar": pag(monitor.vista_buscar("aeropuerto", ADMIN)),
            "reglas": pag(monitor.vista_config(ADMIN)),
            "fuentes": pag(monitor.vista_fuentes(ADMIN)),
            "nota": pag(nota),
            "stats": pag(monitor.vista_stats()),
            "analitica": pag(monitor.vista_analitica()),
            "landing": monitor.vista_landing(base),
        }
    finally:
        monitor.vista_nota = original_nota
        monitor.perfil_usuario = perfil_real
    return docs


def main():
    SHOTS.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory() as td:
        docs = paginas(Path(td))
    for nombre, doc in docs.items():
        doc = doc.decode() if isinstance(doc, bytes) else doc
        # snap chromium no ve /tmp: el HTML temporal vive en el proyecto
        tmp = SHOTS / f"_{nombre}.html"
        # los assets relativos (/icon3.png) apuntan al dominio real
        doc = doc.replace('src="/', 'src="https://noticias.unknownshoppers.com/')
        doc = doc.replace('href="/icon',
                          'href="https://noticias.unknownshoppers.com/icon')
        tmp.write_text(doc)
        subprocess.run(
            ["chromium", "--headless", "--no-sandbox",
             "--disable-gpu", "--hide-scrollbars",
             "--window-size=430,1500", "--virtual-time-budget=9000",
             f"--screenshot={SHOTS}/{nombre}.png", f"file://{tmp}"],
            check=False, capture_output=True)
        tmp.unlink()
        print("shots/" + nombre + ".png")


if __name__ == "__main__":
    main()
