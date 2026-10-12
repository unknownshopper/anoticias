#!/usr/bin/env python3
"""Login manual de FB para guardar la sesión que usa el monitor.

Corre:  .venv/bin/python fb_login.py [archivo_salida.json]
        (default fb_session.json — portadas;
         cuenta de posts → fb_session_redes.json)

Se abre un Chrome visible con facebook.com — inicia sesión con la
cuenta troll (usuario, contraseña y 2FA si pide). En cuanto detecte
la cookie c_user (sesión real) guarda el storage_state y se cierra
sola — ya no hay que presionar ENTER. El monitor la usa para:
  - timeline real de páginas (todos los posts, no solo el último)
  - fotos en tamaño original (view_full_size) en vez del feed 600px
La sesión dura semanas/meses; si caduca, repite este script.
"""
import sys
import time
from playwright.sync_api import sync_playwright
from pathlib import Path

SESION = Path(__file__).parent / (
    sys.argv[1] if len(sys.argv) > 1 else "fb_session.json")


def main():
    with sync_playwright() as p:
        try:
            br = p.chromium.launch(headless=False)
        except Exception:
            br = p.chromium.launch(channel="chrome", headless=False)
        ctx = br.new_context()
        pg = ctx.new_page()
        pg.goto("https://www.facebook.com/login")
        print(f"\n>>> Inicia sesión en el navegador que se abrió.")
        print(f">>> Al entrar tu feed se guarda en {SESION.name} "
              f"y la ventana se cierra sola.")
        ok = False
        for _ in range(240):            # 20 min de espera máxima
            time.sleep(5)
            if any(c["name"] == "c_user" for c in ctx.cookies()):
                ok = True
                break
        if ok:
            ctx.storage_state(path=str(SESION))
            print(f"Sesión guardada en {SESION}")
        else:
            print("!! No detecté login en 20 min — nada se guardó.")
        br.close()


if __name__ == "__main__":
    main()
