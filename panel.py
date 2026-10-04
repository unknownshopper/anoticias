#!/usr/bin/env python3
"""Panel en vivo para el escritorio — usuarios conectados, notas abiertas,
referrers. Lee los mismos JSONL que el server; cero carga extra.

    python3 panel.py          # refresca cada 30s en la terminal
    ./panel.sh                # lo mismo pero en ventana zenity
"""
import json
import os
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime, timedelta
from urllib.parse import urlparse

BASE = os.path.dirname(os.path.abspath(__file__))
ACTIVIDAD = os.path.join(BASE, "actividad.jsonl")
USUARIOS = os.path.join(BASE, "usuarios.json")
ONLINE_MIN = 10   # activo si su último hit fue hace <10 min


def eventos():
    try:
        with open(ACTIVIDAD) as f:
            return [json.loads(l) for l in f if l.strip()]
    except FileNotFoundError:
        return []


def resumen():
    evs = eventos()
    ahora = datetime.now()
    corte = ahora - timedelta(minutes=ONLINE_MIN)
    ultimo = {}
    notas = Counter()
    refs = Counter()
    for e in evs:
        ts = datetime.fromisoformat(e["ts"])
        quien = e["email"] or "(anónimo)"
        if quien not in ultimo or ts > ultimo[quien]:
            ultimo[quien] = ts
        if e.get("u"):
            notas[quien] += 1
        ref = e.get("ref", "")
        if ref and "unknownshoppers" not in ref and "localhost" not in ref:
            refs[urlparse(ref).netloc] += 1
    usuarios = json.load(open(USUARIOS)) if os.path.exists(USUARIOS) else {}
    return ultimo, notas, refs, usuarios, corte


def pintar():
    ultimo, notas, refs, usuarios, corte = resumen()
    lineas = [f"  @noticias — panel en vivo   {datetime.now():%H:%M:%S}",
              "  " + "─" * 44, ""]
    conectados = {q: t for q, t in ultimo.items() if t > corte}
    if conectados:
        lineas.append("  ● EN LÍNEA (últimos 10 min)")
        for q, t in sorted(conectados.items(), key=lambda x: -x[1].timestamp()):
            demo = " [demo]" if "@demo.local" in q else ""
            lineas.append(f"    {q}{demo} — último hit {t:%H:%M}")
    else:
        lineas.append("  ○ nadie en línea")
    lineas.append("")
    lineas.append("  ÚLTIMOS VISITANTES")
    for q, t in sorted(ultimo.items(), key=lambda x: -x[1].timestamp())[:8]:
        marca = "●" if t > corte else "○"
        lineas.append(f"    {marca} {q:38} {t:%d/%m %H:%M}  {notas[q]} notas")
    if refs:
        lineas += ["", "  REFERRERS EXTERNOS"]
        for d, n in refs.most_common(5):
            lineas.append(f"    {d}  ({n}×)")
    lineas += ["", f"  {len(usuarios)} cuentas · "
               f"{sum(1 for u in usuarios.values() if u.get('expira'))} demos"]
    return "\n".join(lineas)


def main():
    if "--zenity" in sys.argv:
        proc = subprocess.Popen(
            ["zenity", "--text-info", "--title=@noticias en vivo",
             "--width=540", "--height=480", "--font=monospace"],
            stdin=subprocess.PIPE, text=True)
        try:
            while proc.poll() is None:
                proc.stdin.write(pintar() + "\f")
                proc.stdin.flush()
                time.sleep(30)
        except (BrokenPipeError, KeyboardInterrupt):
            pass
        return
    try:
        while True:
            os.system("clear")
            print(pintar())
            print("\n  ctrl+c para salir · refresco 30s")
            time.sleep(30)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
