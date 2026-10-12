#!/usr/bin/env python3
"""Exporta la lista de cuentas que sigue un handle de X (x_session.json)
a x_siguiendo[_handle].csv — handle, nombre, bio.

Corre:  .venv/bin/python x_following.py [handle]
        (default elpolidelanoche → x_siguiendo.csv)

NO lee el DOM: el virtual-scroll de X solo monta ~40 celdas a la vez y
los saltos de scroll perdían bloques. Intercepta las respuestas GraphQL
'Following' — cada página trae ~20 usuarios con nombre/bio completos.
Se hace wheel moderado hasta que X deja de mandar páginas nuevas.
"""
import csv
import json
import re
import sys
import time
from pathlib import Path

BASE = Path(__file__).parent
SESION = BASE / "x_session.json"
CUENTA = sys.argv[1].lstrip("@") if len(sys.argv) > 1 \
    else "elpolidelanoche"
CSV = BASE / ("x_siguiendo.csv" if CUENTA == "elpolidelanoche"
              else f"x_siguiendo_{CUENTA}.csv")
MAX_VACIAS = 10


def _usuarios(resp_json: dict) -> list:
    """Camina el JSON de GraphQL y saca (handle, nombre, bio) de cada
    nodo __typename=='User'."""
    hallados = []

    def camina(o):
        if isinstance(o, dict):
            if o.get("__typename") == "User":
                leg = o.get("legacy", {})
                core = o.get("core", {})
                handle = (core.get("screen_name")
                          or leg.get("screen_name") or "")
                if handle:
                    hallados.append((
                        handle.lower(),
                        core.get("name") or leg.get("name") or "",
                        (leg.get("description") or "")[:200]))
            for v in o.values():
                camina(v)
        elif isinstance(o, list):
            for v in o:
                camina(v)

    camina(resp_json)
    return hallados


def main():
    if not SESION.exists():
        sys.exit("[!] no hay x_session.json — corre x_login.py primero")
    from playwright.sync_api import sync_playwright
    vistos: dict = {}
    with sync_playwright() as p:
        try:
            br = p.chromium.launch()
        except Exception:
            br = p.chromium.launch(channel="chrome")
        pg = br.new_context(storage_state=str(SESION)).new_page()

        def al_responder(resp):
            if "graphql" not in resp.url.lower() \
                    or "Following" not in resp.url:
                return
            try:
                for h, nom, bio in _usuarios(resp.json()):
                    vistos.setdefault(h, (nom, bio))
            except Exception:
                pass

        pg.on("response", al_responder)
        pg.goto(f"https://x.com/{CUENTA}/following",
                wait_until="domcontentloaded", timeout=60000)
        pg.wait_for_timeout(9000)
        if "login" in pg.url:
            br.close()
            sys.exit("[!] sesión caída — re-corre x_login.py")

        vacias = 0
        for i in range(400):
            antes = len(vistos)
            pg.mouse.wheel(0, 2500)
            pg.wait_for_timeout(2000)
            if len(vistos) == antes:
                vacias += 1
                if vacias >= MAX_VACIAS:
                    break
            else:
                vacias = 0
            if i % 10 == 0:
                print(f"  …{len(vistos)} cuentas (pasada {i})", flush=True)
        br.close()

    with CSV.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["handle", "nombre", "bio"])
        for h, (nom, bio) in sorted(vistos.items()):
            w.writerow([h, nom, bio])
    print(f"[✓] {len(vistos)} cuentas → {CSV}")


if __name__ == "__main__":
    main()
