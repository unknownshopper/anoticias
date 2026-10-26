/* @noticias — service worker.
   Solo calienta los contadores de globitos por tab: en cada
   periodic-sync (o cuando el SO lo despierte) guarda /badge en
   CacheStorage para que la app abra con números frescos.
   SIN badge de ícono ni notificaciones — discreción por fuera. */
const CACHE = "badge-v1";

self.addEventListener("install", e => self.skipWaiting());
self.addEventListener("activate", e => e.waitUntil(clients.claim()));

async function refrescarBadge() {
  try {
    const r = await fetch("/badge", { credentials: "same-origin" });
    if (r.ok) {
      const c = await caches.open(CACHE);
      await c.put("/badge", r);
    }
  } catch (e) { /* sin red — la app usará lo último cacheado */ }
}

self.addEventListener("periodicsync", e => {
  if (e.tag === "badge-refresh")
    e.waitUntil(refrescarBadge());
});

self.addEventListener("message", e => {
  if (e.data === "badge-refresh") e.waitUntil(refrescarBadge());
});
