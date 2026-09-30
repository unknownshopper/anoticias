# @noticias — Pendientes

## Mañana (dominio + deploy real)

- [ ] Mover `unknownshoppers.com` de GoDaddy a Cloudflare:
  - dash.cloudflare.com → Add site → copiar los 2 nameservers
  - En GoDaddy → DNS → Nameservers → cambiar a los de Cloudflare
  - Esperar propagación (~min-2h)
- [ ] `cloudflared tunnel login` → elegir `unknownshoppers.com`
- [ ] `cloudflared tunnel create noticias` → anotar UUID
- [ ] Crear `~/.cloudflared/config.yml` con ingress a `noticias.unknownshoppers.com`
- [ ] `cloudflared tunnel route dns noticias noticias.unknownshoppers.com`
- [ ] `sudo cloudflared service install` → túnel permanente (sobrevive reboot)
- [ ] Matar el quick tunnel (trycloudflare) y probar la URL definitiva

## Migración a la NUC

- [ ] `git clone` del repo en la NUC + `.venv` + `pip install -r requirements.txt`
- [ ] Copiar `config.json` real (reglas de gobierno — NO está en git)
- [ ] Systemd service para `monitor.py --web 8080 --loop 15`
- [ ] Reinstalar cloudflared ahí o mover el túnel

## Producto (después de la demo)

- [ ] Login por usuario (cada diputado sus propias reglas — multi-tenant)
- [ ] Notificaciones reales: correo SMTP ya está, falta encenderlo / WhatsApp
- [ ] Opción regla con 1 sola palabra si el usuario insiste (hoy mínimo 2)
- [ ] Review de `solo_si_menciona` — hoy no tiene; decidir si nacionales filtran
- [ ] `bump` de versión cuando cambie algo grande (v0.9.0 → v1.0.0 al deploy)

## Nice to have

- [ ] Resúmenes con Ollama activados (`--resumir`, necesita ollama corriendo)
- [ ] Favicon/ícono real con logo diseñado (hoy el `@` navy generado)
- [ ] HTTPS headers de seguridad básicos
