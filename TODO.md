# @noticias — Pendientes

## Dominio + deploy real (HECHO 2026-09-30)

- [x] `unknownshoppers.com` en Cloudflare (zone activa, NS `arvind/evelyn.ns.cloudflare.com`)
- [x] Nameservers cambiados en GoDaddy (propagado en minutos)
- [x] `cloudflared tunnel login` + `tunnel create noticias` → UUID `50065a63-47ef-452b-87b4-0c3def43a66e`
- [x] `~/.cloudflared/config.yml` con ingress a `noticias.unknownshoppers.com` → `localhost:8080`
- [x] `tunnel route dns` → CNAME creado
- [x] `sudo cloudflared service install` → systemd `cloudflared.service` enabled+running
  - config y credenciales copiados a `/etc/cloudflared/`
- [x] Quick tunnel (trycloudflare) y `tunnel run` manual eliminados
- [x] `https://noticias.unknownshoppers.com` → 200 OK verificado

Nota: records `mail`, `ftp`, `cpanel`, `webmail`, `webdisk`, `whm`, `cpcalendars`,
`cpcontacts` quedaron DNS-only en Cloudflare (el host de cPanel del amigo sigue igual,
`50.31.176.165`). Cloudflare solo responde DNS; el hosting no se movió.

## Migración a la NUC — HECHA

- [x] Este equipo ES la NUC: app + datos + túnel ya corren aquí
- [x] `monitor.service` systemd: autoarranque + restart on crash
- [x] `cloudflared.service` systemd: túnel persistente

## Multi-tenant (HECHO 2026-09-30)

- [x] `usuarios.json`: perfil por email — `reglas`, `fuentes_ocultas`, `expira`
- [x] Identidad: cookie de sesión firmada; header `Cf-Access-Authenticated-User-Email`
  tiene prioridad si algún día se activa Cloudflare Access
- [x] `admins` en config.json: `the@unknownshoppers.com` (se sembró con las 3 reglas viejas)
- [x] Reglas por usuario: `/config` edita las propias, backfill etiqueta `usuario` en alertas.jsonl
- [x] Feed por usuario: `/fuentes` → checkboxes de selección (todos) + CRUD catálogo (solo admin)
- [x] Gestión de usuarios en `/fuentes` (admin): demo 24h / quitar demo / eliminar
- [x] Demo autodestructible: `expira` purgado en cada ciclo del scraper
- [x] Correo por usuario: alerta con `usuario` → va a ese email
- [x] `/exportar` solo admin
- [x] Login propio (2026-09-30): `/` muestra pantalla con logo + usuario/contraseña
  + "Entrar como invitado" (guest-*@demo.local, expira 24h)
  - cookie firmada HMAC (`secret.txt`), passwords sha256 en usuarios.json
  - admin entra con `admin_password` de config.json (¡cambiarla!)
  - admin crea usuarios y resetea passwords en `/fuentes`
  - guardar regla dispara `ciclo_ahora()` — aplica al instante, no al siguiente ciclo
- [ ] OPCIONAL: Cloudflare Access encima (Zero Trust → Applications). Si se activa,
  el header tiene prioridad sobre la cookie — sirve para restringir a nivel edge.

## Sesión 2026-10-01 — fuentes, alertas y pulido

- [x] 58 fuentes en 6 categorías (deportes, internacional, oficial nuevas)
- [x] `/noticias` paginado 100 en 100 con navegación
- [x] `/fuentes`: dropdowns por categoría con "todas" / "solo esta",
  dot verde/rojo de salud por fuente (admin)
- [x] Retención sin límite (`RETENCION_DIAS=0`) — `purgar()` desactivado;
  vistos sigue en 30 días
- [x] Alertas por usuario confirmadas: `/alertas` solo las propias;
  la supervisión global va en `/analitica`
- [x] Invitados solo lectura: no crean/editan/borran reglas
- [x] Google News: nota atribuida al medio real (`entry.source`),
  `via` = feed que la trajo; sufijo " - Medio" limpio del titular;
  migración aplicada a noticias.jsonl/alertas.jsonl (1428 títulos,
  20 reatribuciones, 1426 logos GN eliminados; .bak guardados)
- [x] CSP: permite `static.cloudflareinsights.com`; imágenes http→https
  (`url_https` en captura y render) — consola limpia
- [x] Lector `/nota`: si la página original tiene video, el botón dice
  "Ver nota y video en el sitio original"

## Producto (después de la demo)

- [ ] Notificaciones reales: correo SMTP ya está, falta encenderlo / WhatsApp
- [ ] Opción regla con 1 sola palabra si el usuario insiste (hoy mínimo 2)
- [ ] Review de `solo_si_menciona` — hoy no tiene; decidir si nacionales filtran
- [ ] `bump` de versión cuando cambie algo grande (v0.9.0 → v1.0.0 al deploy)
- [ ] Lector `/nota`: el extractor de `<p>` cuela pies/menús del sitio
  (filtra solo textos <60 chars) — afinar si molesta
- [ ] Cobertura relacionada: con corpus grande el token "raro" (≤5)
  escasea — evaluar modelo por peso si se pide más amplitud

## Nice to have

- [ ] Resúmenes con Ollama activados (`--resumir`, necesita ollama corriendo)
- [ ] Favicon/ícono real con logo diseñado (hoy el `@` navy generado)
- [x] HTTPS headers de seguridad básicos (nosniff, DENY, Referrer-Policy, Permissions-Policy, HSTS, CSP)
- [ ] Widget desktop Linux: online/offline, usuarios conectados, etc.