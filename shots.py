#!/usr/bin/env python3
"""Regenera las capturas del instructivo (shots/*.png).

Renderiza cada vista con las funciones reales de monitor.py — sin
servidor ni sesión — y las captura con chromium headless a ancho móvil.
Correlo cuando cambie el diseño:

    .venv/bin/python shots.py
"""
import html as htmlmod
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import monitor  # noqa: E402  (vista_*, render_pagina, etc.)

BASE = Path(__file__).parent
SHOTS = BASE / "shots"
ADMIN = next(iter(__import__("json").loads(
    monitor.USUARIOS.read_text())))  # primer usuario = admin

# (nombre_archivo, html) — html se renderiza igual que en el server
def paginas():
    base = "https://noticias.unknownshoppers.com"

    def pag(vista):
        return monitor.render_pagina(vista, base=base, usuario=ADMIN)

    noticias = monitor.leer_jsonl(monitor.NOTICIAS, limite=1)
    link = noticias[-1]["link"] if noticias else "https://ejemplo.mx"
    nota, _ = monitor.vista_nota(link)
    lector = pag(nota)
    return {
        "feed": pag(monitor.vista_noticias(ADMIN)),
        "alertas": pag(monitor.vista_alertas(ADMIN)),
        "destacadas": pag(monitor.vista_destacadas(ADMIN)),
        "buscar": pag(monitor.vista_buscar("amlo", ADMIN)),
        "reglas": pag(monitor.vista_config(ADMIN)),
        "fuentes": pag(monitor.vista_fuentes(ADMIN)),
        "nota": lector,
        "stats": pag(monitor.vista_stats()),
        "analitica": pag(monitor.vista_analitica()),
        "landing": monitor.vista_landing(base),
    }


def main():
    SHOTS.mkdir(exist_ok=True)
    for nombre, doc in paginas().items():
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
