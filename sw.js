/* Sovereign Passport Portal — installability/offline shell.
 * Network-first for same-origin GETs, cache fallback. Switchboard traffic is not cached.
 */
const CACHE = 'spid-portail-v1'
const ASSETS = [
  './portail.html',
  './portail.css',
  './portail.js',
  './i18n/catalogs.js',
  './spid.i18n.js',
  './relations-client.js',
  './relations-contract.js',
  './feedback-contract.js',
  './vendor/qrcode-generator.js',
  './pwa-install.js',
  './manifest.json',
  './portail-icon-192.png',
  './portail-icon-512.png',
  './portail-icon-180.png',
  './portal-bg.jpg'
]

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE)
      .then((cache) => cache.addAll(ASSETS))
      .then(() => self.skipWaiting())
  )
})

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => Promise.all(
      keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))
    )).then(() => self.clients.claim())
  )
})

self.addEventListener('fetch', (event) => {
  const request = event.request
  if (request.method !== 'GET') return
  const url = new URL(request.url)
  if (url.origin !== self.location.origin) return
  if (url.pathname.endsWith('/sw.js')) return
  event.respondWith(
    fetch(request).then((response) => {
      if (response && response.ok) {
        const copy = response.clone()
        caches.open(CACHE).then((cache) => cache.put(request, copy)).catch(() => {})
      }
      return response
    }).catch(() => caches.match(request, { ignoreSearch: true }).then((hit) => {
      if (hit) return hit
      if (request.mode === 'navigate') return caches.match('./portail.html')
      return Response.error()
    }))
  )
})
