#!/usr/bin/env python3
"""Login manual de X para guardar la sesión que usa el monitor.

Corre:  .venv/bin/python x_login.py [archivo_salida.json]
        (default x_session.json)

Se abre un Chrome visible con x.com — inicia sesión con la cuenta
dedicada (usuario, contraseña y 2FA si pide). En cuanto detecte la
cookie auth_token (sesión real) guarda el storage_state y se cierra
sola — ya no hay que presionar ENTER. El monitor la usa para el
timeline de las cuentas tipo 'x' (x:handle) — anónimo X solo muestra
login-wall.
La sesión dura semanas/meses; si caduca, repite este script.
"""
import sys
import time
from playwright.sync_api import sync_playwright
from pathlib import Path

SESION = Path(__file__).parent / (
    sys.argv[1] if len(sys.argv) > 1 else "x_session.json")


def main():
    with sync_playwright() as p:
        args = ["--disable-blink-features=AutomationControlled",
                "--no-first-run", "--no-default-browser-check"]
        # perfil persistente = navegador 'real': X no mata el input del
        # código de verificación al cambiar de ventana (anti-bot)
        perfil = Path(__file__).parent / ".x_login_profile"
        try:
            ctx = p.chromium.launch_persistent_context(
                str(perfil), headless=False, args=args)
        except Exception:
            ctx = p.chromium.launch_persistent_context(
                str(perfil), channel="chrome", headless=False, args=args)
        pg = ctx.pages[0] if ctx.pages else ctx.new_page()
        pg.goto("https://x.com/login")
        print(f"\n>>> Inicia sesión en el navegador que se abrió.")
        print(f">>> Al entrar tu feed se guarda en {SESION.name} "
              f"y la ventana se cierra sola.")
        ok = False
        for _ in range(240):            # 20 min de espera máxima
            time.sleep(5)
            if any(c["name"] == "auth_token" for c in ctx.cookies()):
                ok = True
                break
        if ok:
            ctx.storage_state(path=str(SESION))
            print(f"Sesión guardada en {SESION}")
        else:
            print("!! No detecté login en 20 min — nada se guardó.")
        ctx.close()


if __name__ == "__main__":
    main()
