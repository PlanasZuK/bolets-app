// Radar de bolets (web del mòbil): funciona sense cobertura amb el que ja s'ha vist.
//  - la pàgina, el mòdul i les llibreries: primer la xarxa (per tenir la darrera versió), si no hi ha xarxa, la còpia
//  - dades del dia (d/…enc): primer la xarxa, si no, la còpia · graella i precisió: primer la còpia (no canvien)
//  - mapa de l'ICGC: primer la còpia (fins a ~4000 rajoles)
const V = 'bolets-v1', SHELL = ['./', 'index.html', 'shim.js', 'app/icon.svg', 'app/manifest.webmanifest', 'd/salt.json'];
self.addEventListener('install', e => e.waitUntil(caches.open(V).then(c => c.addAll(SHELL)).then(() => self.skipWaiting())));
self.addEventListener('activate', e => e.waitUntil(caches.keys().then(ks => Promise.all(ks.filter(k => !k.startsWith('bolets-')).map(k => caches.delete(k)))).then(() => self.clients.claim())));
async function netFirst(req, cache) {
  const c = await caches.open(cache);
  try { const r = await fetch(req); if (r.ok) c.put(req, r.clone()); return r; }
  catch (e) { const m = await c.match(req, { ignoreSearch: true }); if (m) return m; throw e; }
}
async function cacheFirst(req, cache, max) {
  const c = await caches.open(cache), m = await c.match(req);
  if (m) return m;
  const r = await fetch(req);
  if (r.ok || r.type === 'opaque') {
    c.put(req, r.clone());
    if (max) c.keys().then(ks => { if (ks.length > max) ks.slice(0, ks.length - max).forEach(k => c.delete(k)); });
  }
  return r;
}
self.addEventListener('fetch', e => {
  const req = e.request; if (req.method !== 'GET') return;
  const u = new URL(req.url);
  if (u.origin === location.origin) {
    if (/\/d\/uid\/|\/prec\/.+\.png$/.test(u.pathname)) e.respondWith(cacheFirst(req, 'bolets-fix'));
    else e.respondWith(netFirst(req, V));
    return;
  }
  if (/geoserveis\.icgc\.cat/.test(u.host)) { e.respondWith(cacheFirst(req, 'bolets-mapa', 4000)); return; }
  if (/unpkg\.com|fonts\.(googleapis|gstatic)\.com/.test(u.host)) { e.respondWith(cacheFirst(req, V)); return; }
});
