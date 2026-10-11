"""Migración única: reescribe los links news.google.com de noticias.jsonl
al URL real del medio (resolver_link_gn). Reescritura atómica al final."""
import json
import monitor
from pathlib import Path

F = Path(monitor.NOTICIAS)
lineas = F.read_text().splitlines()
resueltos, total = 0, 0
cache = {}

for i, ln in enumerate(lineas):
    try:
        n = json.loads(ln)
    except Exception:
        continue
    lk = n.get("link", "")
    if "news.google.com" not in lk:
        continue
    total += 1
    if lk not in cache:
        cache[lk] = monitor.resolver_link_gn(lk)
        if len(cache) % 25 == 0:
            print(f"{len(cache)}/{total}", flush=True)
    if cache[lk] != lk:
        n["link"] = cache[lk]
        n["link_gn"] = lk
        lineas[i] = json.dumps(n, ensure_ascii=False)
        resueltos += 1

tmp = F.with_suffix(".jsonl.tmp")
tmp.write_text("\n".join(lineas) + "\n")
tmp.replace(F)
print(f"listo: {resueltos}/{total} links GN resueltos")
