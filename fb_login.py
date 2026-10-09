#!/usr/bin/env python3
"""Login manual de FB para guardar la sesión que usa el monitor.

Corre:  .venv/bin/python fb_login.py

Se abre un Chrome visible con facebook.com — inicia sesión con la
cuenta troll (usuario, contraseña y 2FA si pide). Cuando ya veas el
feed cargado, vuelve a esta terminal y presiona ENTER: las cookies
quedan en fb_session.json y el monitor las usa para:
  - timeline real de páginas (todos los posts, no solo el último)
  - fotos en tamaño original (view_full_size) en vez del feed 600px
La sesión dura semanas/meses; si caduca, repite este script.
"""
from playwright.sync_api import sync_playwright
from pathlib import Path

SESION = Path(__file__).parent / "fb_session.json"


def main():
    with sync_playwright() as p:
        try:
            br = p.chromium.launch(headless=False)
        except Exception:
            br = p.chromium.launch(channel="chrome", headless=False)
        ctx = br.new_context()
        pg = ctx.new_page()
        pg.goto("https://www.facebook.com/login")
        print("\n>>> Inicia sesión con la cuenta troll en el navegador.")
        print(">>> Cuando veas tu feed cargado, presiona ENTER aquí.")
        input()
        # sanity: c_user cookie = sesión real
        cookies = ctx.cookies()
        if not any(c["name"] == "c_user" for c in cookies):
            print("!! No detecté cookie c_user — ¿seguro que entraste? "
                  "Guardo de todos modos por si acaso.")
        ctx.storage_state(path=str(SESION))
        print(f"Sesión guardada en {SESION}")
        br.close()


if __name__ == "__main__":
    main()
