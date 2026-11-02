#!/usr/bin/env python3
"""Regenera auditoria_tsjt.html — matriz diaria de sesiones por
operador (proyecto tsjt), con días sin actividad visibles en rojo.

Corre:  .venv/bin/python gen_auditoria.py
"""
import json
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path

BASE = Path(__file__).parent
GAP = timedelta(minutes=30)          # 1 sesión = actividad sin pausa >30 min
NOCTURNO = range(22, 24)             # 22:00-05:59 no cuenta


def carga():
    ops = {e: u for e, u in
           json.loads((BASE / "usuarios.json").read_text()).items()
           if "tsjt" in (u.get("proyectos") or [])}
    evs = []
    for l in (BASE / "actividad.jsonl").read_text().splitlines():
        try:
            e = json.loads(l)
        except Exception:
            continue
        if e.get("email") in ops:
            evs.append(e)
    return ops, evs


def sesiones_por(fe):
    """Cuenta sesiones por día: eventos ordenados, corte si gap>30min.
    Fecha de la sesión = la de su primer evento."""
    ses = defaultdict(int)
    por_dia = defaultdict(list)
    for f in sorted(fe, key=lambda f: f["ts"]):
        t = datetime.fromisoformat(f["ts"])
        if t.hour >= 22 or t.hour < 6:
            continue               # acceso nocturno: fuera
        por_dia[t.date()].append(t)
    dias = defaultdict(int)
    for d, ts in por_dia.items():
        ult = None
        for t in ts:
            if ult is None or t - ult > GAP:
                dias[d] += 1       # nueva sesión
            ult = t
    return dias


def main():
    ops, evs = carga()
    ahora = datetime.now()
    por_op = {e: [f for f in evs if f["email"] == e] for e in ops}
    ses = {e: sesiones_por(fe) for e, fe in por_op.items()}

    # rango de días: primer evento de cualquier operador → HOY, completo
    primera = min((datetime.fromisoformat(f["ts"]).date()
                   for f in evs), default=ahora.date())
    dias = []
    d = primera
    while d <= ahora.date():
        dias.append(d)
        d += timedelta(days=1)
    dias = dias[::-1]                  # hoy primero

    nombres = {e: e.split("@")[0] for e in ops}
    cols = sorted(ops, key=lambda e: nombres[e])
    mx = max((sum(s.values()) for s in ses.values()), default=1) or 1

    filas = ""
    for d in dias:
        wd = d.strftime("%a")
        tot = 0
        celdas = ""
        for e in cols:
            n = ses[e].get(d, 0)
            tot += n
            celdas += (f"<td class='cero'>·</td>" if n == 0 else
                       f"<td style='background:rgba(76,175,80,"
                       f"{0.2 + 0.6 * n / mx:.2f})'>{n}</td>")
        filas += (f"<tr><td>{d} <small>{wd}</small></td>{celdas}"
                  f"<td class='tot'>{tot}</td></tr>")

    tot_row = "".join(f"<td>{sum(ses[e].values())}</td>" for e in cols)
    filas += (f"<tr class='tot'><td>Total sesiones</td>{tot_row}"
              f"<td>{sum(sum(s.values()) for s in ses.values())}</td></tr>")

    kpi = ""
    for e in cols:
        fe = por_op[e]
        n_s = sum(ses[e].values())
        ult = max((f["ts"] for f in fe), default="—")
        kpi += (f"<div><div class='num'>{n_s}</div>"
                f"<div>sesiones de {e}</div>"
                f"<div class='meta'>{len(fe)} páginas | "
                f"último: {ult.replace('T', ' ')[:19]}</div></div>")

    detalle = ""
    for e in cols:
        u = ops[e]
        fe = por_op[e]
        detalle += (f"<h2>{e}</h2>"
                    f"<p><strong>Nivel:</strong> {u.get('nivel')} | "
                    f"<strong>Proyectos:</strong> "
                    f"{', '.join(u.get('proyectos') or [])}</p>")
        reglas = u.get("reglas") or []
        if reglas:
            detalle += f"<p><strong>Reglas creadas ({len(reglas)})</strong></p>"
            for r in reglas:
                txt = " + ".join(r.get("requiere_todas") or [])
                detalle += (f"<span class='regla' style='background:"
                            f"{r.get('color', '#555')}'>"
                            f"{r.get('nombre', '?')}: {txt}</span>")
        else:
            detalle += "<p class='meta'>No tiene reglas creadas.</p>"
        if not fe:
            detalle += ("<div class='warn'>Este operador no tiene "
                        "accesos registrados en actividad.jsonl.</div>")
            continue
        vistos = sorted(((k[6:], v.replace("T", " ")[:19])
                         for k, v in u.items()
                         if k.startswith("visto_") and v),
                        key=lambda x: x[0])
        if vistos:
            detalle += ("<br style='clear:both'>"
                        "<table><tr><th>Sección</th>"
                        "<th>Última vista</th></tr>"
                        + "".join(f"<tr><td>{s}</td><td>{v}</td></tr>"
                                  for s, v in vistos) + "</table>")
        rutas = Counter(f["ruta"] for f in fe)
        top = "".join(f"<tr><td>{r}</td><td>{n}</td></tr>"
                      for r, n in rutas.most_common(10))
        movs = "".join(f"<tr><td>{f['ts'].replace('T', ' ')[:19]}"
                       f"</td><td>{f['ruta']}</td>"
                       f"<td>{f.get('q', '')}</td></tr>"
                       for f in fe[-20:][::-1])
        detalle += (f"<p><strong>Rutas más visitadas</strong></p>"
                    f"<table><tr><th>Ruta</th><th>Veces</th></tr>"
                    f"{top}</table>"
                    f"<p><strong>Últimos 20 movimientos</strong></p>"
                    f"<table><tr><th>Fecha/Hora</th><th>Ruta</th>"
                    f"<th>Parámetro</th></tr>{movs}</table>")

    head = "".join(f"<th title='{e}'>{nombres[e]}</th>" for e in cols)
    doc = f"""<!DOCTYPE html><html lang='es'><head>
<meta charset='utf-8'><title>Auditoría TSJT — sesiones</title>
<style>
body{{font-family:system-ui,Segoe UI,Roboto,Helvetica,Arial,sans-serif;background:#f5f5f5;margin:0;padding:2rem;color:#333}}
.wrap{{max-width:1200px;margin:0 auto;background:#fff;padding:2rem;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,.08)}}
h1{{color:#1a237e;border-bottom:2px solid #1a237e;padding-bottom:.4rem}}
h2{{margin-top:2rem;color:#444}}
h3{{margin-top:1.5rem;color:#555}}
.kpi{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:1rem;margin:1.5rem 0}}
.kpi div{{background:#f0f4f8;padding:1rem;border-radius:6px}}
.kpi .num{{font-size:1.6rem;font-weight:700;color:#1a237e}}
.matrix{{overflow-x:auto}}
.matrix table{{width:100%;border-collapse:collapse;margin:1rem 0;white-space:nowrap}}
.matrix th,.matrix td{{text-align:center;padding:.5rem .4rem;border:1px solid #e0e0e0;font-size:.9rem}}
.matrix th{{background:#f0f4f8;position:sticky;top:0}}
.matrix td:first-child,.matrix th:first-child{{text-align:left;background:#f8f9fa;font-weight:600}}
.matrix .tot{{font-weight:700;background:#e3f2fd}}
.matrix .cero{{color:#b71c1c;font-weight:700;background:#ffebee}}
table{{width:100%;border-collapse:collapse;margin:1rem 0}}
th,td{{text-align:left;padding:.6rem;border-bottom:1px solid #e0e0e0}}
th{{background:#f0f4f8;font-weight:600}}
tr:hover{{background:#fafafa}}
.meta{{color:#666;font-size:.9rem}}
.regla{{padding:.2rem .5rem;border-radius:4px;margin:.1rem;display:inline-block;font-size:.88rem;color:white}}
.warn{{background:#fff3e0;padding:1rem;border-left:4px solid #ff9800;margin:1.5rem 0}}
</style></head><body><div class='wrap'>
<h1>Auditoría de operadores TSJT</h1>
<p class='meta'>Generado: {ahora:%Y-%m-%d %H:%M:%S}</p>
<p class='meta'>1 sesión = actividad continua con menos de 30 min de inactividad. Quitados accesos nocturnos (22:00-05:59).</p>
<h2>Tabla diaria de sesiones</h2>
<p class='meta'>Cada celda = cantidad de sesiones del operador ese día. Rojo = 0.</p>
<div class='matrix'>
<table><thead><tr><th>Fecha</th>
{head}<th class='tot'>Total día</th></tr></thead><tbody>
{filas}
</tbody></table></div>
<h2>Resumen por operador</h2>
<div class='kpi'>
{kpi}
</div>
{detalle}
<div class='warn'>El sistema actualmente solo registra accesos a rutas (qué abrieron y cuándo). No hay log de <em>qué crearon</em> o <em>qué borraron</em>. Si lo necesitas, se puede agregar auditoría de escritura en usuarios/config.</div>
</div></body></html>"""
    (BASE / "auditoria_tsjt.html").write_text(doc)
    print(f"auditoria_tsjt.html regenerado — "
          f"{len(evs)} eventos, {len(dias)} días")


if __name__ == "__main__":
    main()
