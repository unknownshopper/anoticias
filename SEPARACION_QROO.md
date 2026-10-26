# Separación monitor-qroo — plan de trabajo

Objetivo: el proyecto es doble. Cliente Tabasco = Efraín Reséndez (TSJ).
Cliente Quintana Roo = Jorge Portilla (candidato a alcaldía de Tulum).
Mismo código, dos instalaciones con cuentas, reglas y contenido
independientes.

## Estado actual (15/oct/2026)

- Las 30 fuentes `categoria: quintana_roo` ya están `activa: false`
  en `config.json` — no se scrapean en la instancia Tabasco. El flag
  se conserva al editar la fuente desde /fuentes (el form reconstruye
  el dict, pero `activa` se preserva explícitamente en
  `aplicar_accion_fuentes` → ramo `editar`).
- `revisar()` salta fuentes con `activa is False`.

## Paso 1 — Parametrizar lo editorial en config (hacer ANTES de clonar)

Llevar a un bloque `mercado` en config.json todo lo que hoy es
Tabasco hardcodeado en monitor.py:

- `_prio_interes`: `reséndez→0 / judicial→1 / may→2`
  → `mercado.personas_prio` (lista ordenada de regex) +
    `mercado.inst_regex`.
- `_perspectiva_dia`: bonus `tsjt|tribunal|poder judicial|fiscalía|iepc|magistrad`
  y la etiqueta "Tabasco" del prompt
  → `mercado.inst_regex` + `mercado.region_nombre`.
- Agenda regional `_agenda({"prensa","oficial"}, 28)`
  → `mercado.cats_region` (en QRoo: sus medios locales, p.ej.
  `{"prensa","oficial"}` pero con fuentes QRoo).
- Firma del post a X (`@tsj_tabasco`) → `mercado.x_firma`.
- Revisar vistas con "Tabasco" fijo (títulos, prompt, portadas
  `seccion`) → data-driven por `seccion`.

Para QRoo el equivalente editorial: Portilla/Tulum/alcaldía en
`personas_prio`; instituciones QRoo en `inst_regex`
(fiscalía QRoo, TEQRoo, ayuntamiento Tulum...).

## Paso 2 — Clonar la instancia

```
cp -a monitor_noticias monitor_qroo
```

En el clon:

- `config.json` nuevo: medios QRoo activos (los 30 apagados aquí se
  reactivan allá), bloque `mercado` QRoo, `x_firma`, puerto 8081.
- Borrar datos de la otra sede: `usuarios.json`, `noticias.jsonl`,
  `sintesis.jsonl`, `alertas*`, `portadas/`, sesiones.
- `monitor-qroo.service` (clonar monitor.service, cambiar
  WorkingDirectory, puerto :8081).
- Vhost nuevo: `qroo.unknownshoppers.com` → :8081.
  La instancia actual queda en `noticias.unknownshoppers.com`.

## Paso 3 — Cuentas dedicadas

- Sesiones FB nuevas dentro del clon (`fb_login.py` con rutas
  relativas al directorio → aislamiento por construcción).
  Regla vigente: juan=portadas, chucky=posts; QRoo necesita su propio
  par — NO reciclar las sesiones de Tabasco (aislamiento anti-ban).
- Cuenta X propia para QRoo (la marca @elpolidelanoche es Tabasco).

## Acceso por credenciales

Resuelto por arquitectura: cada instancia tiene su propio
`usuarios.json`. Una cuenta creada en QRoo no existe en el sitio
Tabasco — "credenciales por contenido" sin código extra.
Evitar la alternativa de un solo sitio con campo `mercado` por
usuario (más código, más bugs) y el path `/qroo/` (URLs absolutas
`/noticias` lo romperían).

## Riesgos

- **Gemini**: misma API key en dos instancias duplica consumo del
  free tier; las síntesis corren a la misma hora — escalonar franjas.
- **Scraping ×2**: fuentes nacionales se barren en ambas instancias;
  IP saliente compartida — vigilar rate limits FB.
- **RAM NUC**: dos loops + Playwright ×2 + Ollama; el guard de
  4 GB existe pero los procesos compiten.
