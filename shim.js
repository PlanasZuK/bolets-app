/* Servidor de butxaca: respon les mateixes peticions que l'API de l'ordinador (engine/server/pure_api.py, cerca_api.py)
   amb les dades exportades per engine/server/export_static.py i export_prec.py. L'app (radar.html) no canvia.
   Dades xifrades (AES-CBC, clau PBKDF2-SHA256 de la contrasenya); la clau derivada es desa al mòbil per fer-la servir sense xarxa. */
(function () {
'use strict';
const BASE = new URL('.', location.href).href;
const enc = new TextEncoder(), dec = new TextDecoder();
let KEY = null, M = null, U = null, HB = null, Z = null, NU = 0, NSP = 0, SP = [], SPI = {};
const VC = new Map(), PEND = new Map();
let READY, readyRes;
READY = new Promise(r => readyRes = r);

/* ── xifrat ── */
async function deriveKey(pw, salt, iter) {
  const k0 = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: b64(salt), iterations: iter, hash: 'SHA-256' }, k0, 256);
  return new Uint8Array(bits);
}
function b64(s) { const b = atob(s), a = new Uint8Array(b.length); for (let i = 0; i < b.length; i++) a[i] = b.charCodeAt(i); return a; }
function b64e(a) { let s = ''; for (const x of a) s += String.fromCharCode(x); return btoa(s); }
async function aes(raw) { return crypto.subtle.importKey('raw', raw, { name: 'AES-CBC' }, false, ['decrypt']); }
async function decryptBuf(buf) {
  const iv = new Uint8Array(buf, 0, 16), ct = new Uint8Array(buf, 16);
  return crypto.subtle.decrypt({ name: 'AES-CBC', iv }, KEY, ct);
}
async function getEnc(path) {
  const r = await fetch0(BASE + path + '.enc', { cache: 'no-cache' });
  if (!r.ok) throw new Error('falta ' + path);
  return decryptBuf(await r.arrayBuffer());
}
async function getJSON(path) { return JSON.parse(dec.decode(await getEnc(path))); }

/* ── contrasenya ── */
function gate(msg) {
  return new Promise(res => {
    const d = document.createElement('div');
    d.id = 'gate';
    d.innerHTML = `<style>#gate{position:fixed;inset:0;z-index:99999;display:grid;place-items:center;background:#0d110e;color:#e8ebe4;font:16px/1.4 -apple-system,system-ui,sans-serif;padding:24px}
#gate form{display:grid;gap:12px;width:min(340px,100%)}#gate h1{font-size:24px;margin:0}#gate input{font:inherit;padding:12px 14px;border-radius:12px;border:1px solid #39413a;background:#161b17;color:inherit}
#gate button{font:inherit;font-weight:700;padding:12px;border-radius:12px;border:0;background:#e8ebe4;color:#0d110e}#gate p{margin:0;color:#9aa49b;font-size:14px}</style>
<form><h1>Radar de bolets</h1><p>${msg || 'Escriu la contrasenya. Només cal fer-ho un cop en aquest mòbil.'}</p>
<input type="password" id="gpw" autocomplete="current-password" placeholder="Contrasenya" required><button>Entrar</button></form>`;
    document.documentElement.appendChild(d);
    d.querySelector('form').onsubmit = e => { e.preventDefault(); const v = d.querySelector('#gpw').value; d.remove(); res(v); };
    setTimeout(() => d.querySelector('#gpw').focus(), 50);
  });
}
async function unlock() {
  const S = await (await fetch0(BASE + 'd/salt.json', { cache: 'no-cache' })).json();
  let raw = null;
  try { const s = localStorage.getItem('bolets_k'); if (s) raw = b64(s); } catch (e) {}
  let msg = null;
  for (;;) {
    if (!raw) raw = await deriveKey(await gate(msg), S.salt, S.iter);
    KEY = await aes(raw);
    try { M = await getJSON('d/meta.json'); break; }
    catch (e) { raw = null; msg = 'Contrasenya incorrecta. Torna-ho a provar.'; try { localStorage.removeItem('bolets_k'); } catch (e2) {} }
  }
  try { localStorage.setItem('bolets_k', b64e(raw)); } catch (e) {}
  SP = M.especies.map(e => e.id); NSP = SP.length; NU = M.nu; SP.forEach((s, i) => SPI[s] = i);
  const ub = await getEnc('d/u.bin');
  U = { x: new Float32Array(ub, 0, NU), y: new Float32Array(ub, 4 * NU, NU), elev: new Int16Array(ub, 8 * NU, NU),
        asp: new Uint8Array(ub, 10 * NU, NU), host: new Uint8Array(ub, 11 * NU, NU), cov: new Uint8Array(ub, 12 * NU, NU), age: new Uint8Array(ub, 13 * NU, NU) };
  HB = new Uint8Array(await getEnc('d/h.bin'));
  readyRes();
  loadZ();
}
async function loadZ() {
  if (Z) return Z;
  const b = await getEnc('d/z.bin'), nz = M.zones.nz, nnz = M.zones.nnz;
  let o = 0;
  const ip = new Int32Array(b, o, nz + 1); o += 4 * (nz + 1);
  const ix = new Int32Array(b, o, nnz); o += 4 * nnz;
  const dt = new Uint8Array(b, o, nnz); o += nnz; o += (4 - o % 4) % 4;
  const lon = new Float32Array(b, o, nz); o += 4 * nz;
  const lat = new Float32Array(b, o, nz);
  Z = { ip, ix, dt, lon, lat, nz };
  return Z;
}
function vals(date) {
  if (VC.has(date)) return Promise.resolve(VC.get(date));
  if (PEND.has(date)) return PEND.get(date);
  const p = getEnc('d/v/' + date + '.bin').then(b => { const a = new Uint8Array(b); VC.set(date, a); PEND.delete(date); return a; })
    .catch(e => { PEND.delete(date); throw e; });
  PEND.set(date, p);
  return p;
}
const V = (a, s, u) => a[SPI[s] * NU + u];
const H = (s, u) => HB[SPI[s] * NU + u] / 100;

/* ── projeccions: ETRS89 UTM 31N (EPSG:25831), sèrie de Krüger ── */
const A0 = 6378137, F = 1 / 298.257222101, K0 = 0.9996, L0 = 3 * Math.PI / 180, N_ = F / (2 - F), E2 = F * (2 - F), EE = Math.sqrt(E2);
const AA = A0 / (1 + N_) * (1 + N_ * N_ / 4 + N_ ** 4 / 64);
const al = [N_ / 2 - 2 * N_ * N_ / 3 + 5 * N_ ** 3 / 16, 13 * N_ * N_ / 48 - 3 * N_ ** 3 / 5, 61 * N_ ** 3 / 240];
const be = [N_ / 2 - 2 * N_ * N_ / 3 + 37 * N_ ** 3 / 96, N_ * N_ / 48 + N_ ** 3 / 15, 17 * N_ ** 3 / 480];
const de = [2 * N_ - 2 * N_ * N_ / 3 - 2 * N_ ** 3, 7 * N_ * N_ / 3 - 8 * N_ ** 3 / 5, 56 * N_ ** 3 / 15];
function fwd(lon, lat) {
  const p = lat * Math.PI / 180, l = lon * Math.PI / 180 - L0;
  const t = Math.sinh(Math.atanh(Math.sin(p)) - EE * Math.atanh(EE * Math.sin(p)));
  const xi = Math.atan2(t, Math.cos(l)), eta = Math.atanh(Math.sin(l) / Math.sqrt(1 + t * t));
  let x = eta, y = xi;
  for (let j = 1; j <= 3; j++) { x += al[j - 1] * Math.cos(2 * j * xi) * Math.sinh(2 * j * eta); y += al[j - 1] * Math.sin(2 * j * xi) * Math.cosh(2 * j * eta); }
  return [500000 + K0 * AA * x, K0 * AA * y];
}
function inv(E, Nn) {
  const xi = Nn / (K0 * AA), eta = (E - 500000) / (K0 * AA);
  let x = xi, y = eta;
  for (let j = 1; j <= 3; j++) { x -= be[j - 1] * Math.sin(2 * j * xi) * Math.cosh(2 * j * eta); y -= be[j - 1] * Math.cos(2 * j * xi) * Math.sinh(2 * j * eta); }
  const chi = Math.asin(Math.sin(x) / Math.cosh(y));
  let p = chi; for (let j = 1; j <= 3; j++) p += de[j - 1] * Math.sin(2 * j * chi);
  return [(L0 + Math.atan2(Math.sinh(y), Math.cos(x))) * 180 / Math.PI, p * 180 / Math.PI];
}
const tile2lon = (x, z) => x / 2 ** z * 360 - 180;
const tile2lat = (y, z) => { const n = Math.PI - 2 * Math.PI * y / 2 ** z; return 180 / Math.PI * Math.atan(Math.sinh(n)); };

/* ── graella d'unitats ── */
const UC = new Map(); const UCP = new Map();
async function decodePNG(url) {
  const r = await fetch0(url); if (!r.ok) return null;
  const bm = await createImageBitmap(await r.blob());
  const c = new OffscreenCanvas(bm.width, bm.height), x = c.getContext('2d', { willReadFrequently: true });
  x.drawImage(bm, 0, 0);
  return { w: bm.width, h: bm.height, d: x.getImageData(0, 0, bm.width, bm.height).data };
}
function idGrid(img) { const n = img.w * img.h, a = new Int32Array(n), d = img.d; for (let i = 0; i < n; i++) a[i] = ((d[4 * i] << 16) | (d[4 * i + 1] << 8) | d[4 * i + 2]) - 1; return { w: img.w, h: img.h, a }; }
function getGrid(key, url) {
  if (UC.has(key)) return Promise.resolve(UC.get(key));
  if (UCP.has(key)) return UCP.get(key);
  const p = decodePNG(url).then(im => { const g = im ? idGrid(im) : null; UC.set(key, g); UCP.delete(key); if (UC.size > 40) UC.delete(UC.keys().next().value); return g; });
  UCP.set(key, p); return p;
}
let CHSET = null;
function chunkSet() { if (!CHSET) { CHSET = new Set(M.graella.peces.map(p => p[0] + '_' + p[1])); } return CHSET; }
async function uidAt(row, col) {           // fila/columna de la graella de 25 m → id d'unitat (-1 = res)
  const G = M.graella, P = G['peça'];
  if (row < 0 || col < 0 || row >= G.H || col >= G.W) return -1;
  const k = Math.floor(row / P) + '_' + Math.floor(col / P);
  if (!chunkSet().has(k)) return -1;
  const g = await getGrid('25/' + k, BASE + 'd/uid/25/' + k + '.png');
  if (!g) return -1;
  return g.a[(row % P) * g.w + (col % P)];
}
function rc(x, y) { const G = M.graella; return [Math.floor((G.y1 - y) / 25), Math.floor((x - G.x0) / 25)]; }
function cellXY(row, col) { const G = M.graella; return [G.x0 + (col + .5) * 25, G.y1 - (row + .5) * 25]; }

/* ── qualitat i colors (com pure_api) ── */
const QUAL = [[80, 'Excel·lent'], [60, 'Bona'], [40, 'Possible'], [20, 'Baixa'], [0, 'Nul·la']];
const qual = v => QUAL.find(q => v >= q[0])[1];
const hex = c => [1, 3, 5].map(i => parseInt(c.slice(i, i + 2), 16));
function gcolor(sp) { const g = M.grup_especies[sp] || 'prat'; const G = M.grups.find(x => x.id === g); return hex(G ? G.color : '#888888'); }
function chosenOf(sp, filtre) {
  if (sp && sp !== 'totes') return [sp];
  const f = (filtre || '').split(',').filter(s => SPI[s] != null);
  return f.length ? f : M.bosc.slice();
}
const LUTC = new Map();
async function lut(chosen, date) {
  const k = chosen.join(',') + '|' + date;
  if (LUTC.has(k)) return LUTC.get(k);
  const a = await vals(date), lv = new Uint8Array(NU + 1), ld = new Uint8Array(NU + 1);
  const off = chosen.map(s => SPI[s] * NU);
  for (let u = 0; u < NU; u++) { let b = 0, bi = 0; for (let i = 0; i < off.length; i++) { const v = a[off[i] + u]; if (v > b) { b = v; bi = i; } } lv[u] = b; ld[u] = bi; }
  const o = { lv, ld, cols: chosen.map(gcolor) };
  LUTC.set(k, o); if (LUTC.size > 12) LUTC.delete(LUTC.keys().next().value);
  return o;
}
function renderPx(out, i, val, base, floor) {        // _render: to de família, pàl·lid → ple → nucli fosc
  const v = Math.min(Math.max((val - floor) / (95 - floor), 0), 1);
  let r, g, b;
  if (v < .45) { const t = v / .45; r = base[0] + (255 - base[0]) * .62 * (1 - t); g = base[1] + (255 - base[1]) * .62 * (1 - t); b = base[2] + (255 - base[2]) * .62 * (1 - t); }
  else { const t = (v - .45) / .55; r = base[0] * (1 - .5 * t); g = base[1] * (1 - .5 * t); b = base[2] * (1 - .5 * t); }
  out[i] = r; out[i + 1] = g; out[i + 2] = b; out[i + 3] = val >= floor ? 26 + 229 * Math.pow(v, .85) : 0;
}
const EMPTY = (() => { const c = new OffscreenCanvas(1, 1); c.getContext('2d'); return c.convertToBlob({ type: 'image/png' }).then(b => b.arrayBuffer()); })();
async function toPNG(img) { const c = new OffscreenCanvas(256, 256); c.getContext('2d').putImageData(img, 0, 0); return (await c.convertToBlob({ type: 'image/png' })).arrayBuffer(); }

/* coordenades UTM de cada píxel de la rajola: malla 17×17 i interpolació (ràpid) */
function tileGrid(z, x, y) {
  const N = 16, P = [];
  for (let j = 0; j <= N; j++) for (let i = 0; i <= N; i++) P.push(fwd(tile2lon(x + i / N, z), tile2lat(y + j / N, z)));
  return (px, py) => {
    const fx = px / 256 * N, fy = py / 256 * N, i = Math.min(Math.floor(fx), N - 1), j = Math.min(Math.floor(fy), N - 1), tx = fx - i, ty = fy - j;
    const a = P[j * (N + 1) + i], b = P[j * (N + 1) + i + 1], c = P[(j + 1) * (N + 1) + i], d = P[(j + 1) * (N + 1) + i + 1];
    return [(a[0] * (1 - tx) + b[0] * tx) * (1 - ty) + (c[0] * (1 - tx) + d[0] * tx) * ty, (a[1] * (1 - tx) + b[1] * tx) * (1 - ty) + (c[1] * (1 - tx) + d[1] * tx) * ty];
  };
}
async function gridFor(z) {                          // nivell de la graella segons el zoom
  if (z >= 13) return null;                         // peces de 25 m
  if (z >= 10) return getGrid('100', BASE + 'd/uid/100.png');
  return getGrid('400', BASE + 'd/uid/400.png');
}
async function tile4(sp, date, z, x, y, filtre) {
  await READY;
  const chosen = chosenOf(sp, filtre), L = await lut(chosen, date), G = M.graella;
  const P = tileGrid(z, x, y), img = new ImageData(256, 256), o = img.data;
  const g = await gridFor(z), res = g ? (z >= 10 ? 100 : 400) : 25;
  const need = new Map();
  let any = false;
  const ids = new Int32Array(65536);
  for (let py = 0; py < 256; py++) for (let px = 0; px < 256; px++) {
    const [X, Y] = P(px + .5, py + .5);
    const row = Math.floor((G.y1 - Y) / res), col = Math.floor((X - G.x0) / res);
    let u = -1;
    if (g) { if (row >= 0 && col >= 0 && row < g.h && col < g.w) u = g.a[row * g.w + col]; }
    else {
      const k = Math.floor(row / G['peça']) + '_' + Math.floor(col / G['peça']);
      if (row >= 0 && col >= 0 && chunkSet().has(k)) {
        let gg = UC.get('25/' + k);
        if (gg === undefined) { if (!need.has(k)) need.set(k, getGrid('25/' + k, BASE + 'd/uid/25/' + k + '.png')); u = -2; }
        else if (gg) u = gg.a[(row % G['peça']) * gg.w + (col % G['peça'])];
      }
    }
    ids[py * 256 + px] = u;
  }
  if (need.size) { await Promise.all(need.values()); return tile4(sp, date, z, x, y, filtre); }
  for (let i = 0; i < 65536; i++) {
    const u = ids[i]; if (u < 0) continue;
    const v = L.lv[u]; if (v < 8) continue;
    any = true; renderPx(o, i * 4, v, L.cols[L.ld[u]], 8);
  }
  return any ? toPNG(img) : EMPTY;
}

/* ── precisió (blocs d'1 km amb estructura del LiDAR) ── */
let PK = null, PLIST = null;
async function precMeta() {
  if (PK) return PK;
  try { PK = await (await fetch0(BASE + 'prec/keys.json')).json(); PLIST = new Set(await (await fetch0(BASE + 'prec/list.json')).json()); }
  catch (e) { PK = { capes: [], especie: {} }; PLIST = new Set(); }
  return PK;
}
const PB = new Map(), PBP = new Map();
function precBlock(bx, by) {
  const k = bx + '_' + by;
  if (!PLIST.has(k)) return Promise.resolve(null);
  if (PB.has(k)) return Promise.resolve(PB.get(k));
  if (PBP.has(k)) return PBP.get(k);
  const p = decodePNG(BASE + 'prec/' + k + '.png').then(im => {
    let r = null;
    if (im) { const n = im.w * im.h, a = new Uint8Array(n); for (let i = 0; i < n; i++) a[i] = im.d[4 * i]; r = { w: im.w, a }; }
    PB.set(k, r); PBP.delete(k); if (PB.size > 60) PB.delete(PB.keys().next().value); return r;
  });
  PBP.set(k, p); return p;
}
const PV = new Map();
async function precField(chosen, date, bx, by) {    // V (0-100) i calor (0-1) a 4 m d'un bloc per al dia i les espècies
  const key = chosen.join(',') + '|' + date + '|' + bx + '_' + by;
  if (PV.has(key)) return PV.get(key);
  const blk = await precBlock(bx, by); if (!blk) return null;
  const pk = await precMeta(), S = blk.w, n = S * S, a = await vals(date);
  const BL = pk.bloc_m, step = pk.pas_m;
  const x0 = bx * BL, y1 = (by + 1) * BL, G = M.graella;
  const ids = new Int32Array(n);
  await ensureChunks(x0, y1 - BL, x0 + BL, y1);
  for (let j = 0; j < S; j++) for (let i = 0; i < S; i++) {
    const X = x0 + (i + .5) * step, Y = y1 - (j + .5) * step;
    ids[j * S + i] = uidSync(Math.floor((G.y1 - Y) / 25), Math.floor((X - G.x0) / 25));
  }
  const Vv = new Float32Array(n), D = new Uint8Array(n);
  chosen.forEach((s, ci) => {
    const layer = pk.especie[s]; if (layer == null) return;
    const off = SPI[s] * NU, lo = layer * n;
    for (let p = 0; p < n; p++) {
      const u = ids[p]; if (u < 0) continue;
      const b = a[off + u]; if (!b) continue;
      const v = Math.min(b * blk.a[lo + p] / 100, b * 1.15, 100);
      if (v > Vv[p]) { Vv[p] = v; D[p] = ci; }
    }
  });
  // calor: com destaca el punt sobre el seu entorn (~120 m) ponderat per la qualitat absoluta (com _pblock_calc)
  const R = 15, mu = boxBlur(Vv, S, R), mu2 = boxBlur(Vv.map(v => v * v), S, R), heat = new Float32Array(n);
  for (let p = 0; p < n; p++) {
    const sd = Math.sqrt(Math.max(mu2[p] - mu[p] * mu[p], 0)), zz = (Vv[p] - mu[p]) / (sd + 3);
    const q = Math.pow(Math.min(Math.max((Vv[p] - 25) / 50, 0), 1), .7);
    heat[p] = Math.min(Math.max(zz / 2.2, 0), 1) * q;
  }
  const o = { S, V: Vv, D, heat, ids };
  PV.set(key, o); if (PV.size > 40) PV.delete(PV.keys().next().value);
  return o;
}
function boxBlur(a, S, R) {
  const t = new Float32Array(a.length), o = new Float32Array(a.length);
  for (let j = 0; j < S; j++) { let s = 0, c = 0; for (let i = -R; i < S + R; i++) { if (i + R < S) { s += a[j * S + i + R]; c++; } if (i - R - 1 >= 0) { s -= a[j * S + i - R - 1]; c--; } if (i >= 0 && i < S) t[j * S + i] = s / c; } }
  for (let i = 0; i < S; i++) { let s = 0, c = 0; for (let j = -R; j < S + R; j++) { if (j + R < S) { s += t[(j + R) * S + i]; c++; } if (j - R - 1 >= 0) { s -= t[(j - R - 1) * S + i]; c--; } if (j >= 0 && j < S) o[j * S + i] = s / c; } }
  return o;
}
async function ensureChunks(x0, y0, x1, y1) {
  const G = M.graella, P = G['peça'], ps = [];
  const r0 = Math.floor((G.y1 - y1) / 25 / P), r1 = Math.floor((G.y1 - y0) / 25 / P), c0 = Math.floor((x0 - G.x0) / 25 / P), c1 = Math.floor((x1 - G.x0) / 25 / P);
  for (let i = r0; i <= r1; i++) for (let j = c0; j <= c1; j++) { const k = i + '_' + j; if (chunkSet().has(k) && !UC.has('25/' + k)) ps.push(getGrid('25/' + k, BASE + 'd/uid/25/' + k + '.png')); }
  await Promise.all(ps);
}
function uidSync(row, col) {
  const G = M.graella, P = G['peça'];
  if (row < 0 || col < 0 || row >= G.H || col >= G.W) return -1;
  const g = UC.get('25/' + Math.floor(row / P) + '_' + Math.floor(col / P));
  return g ? g.a[(row % P) * g.w + (col % P)] : -1;
}
async function uidFast(row, col) {
  const G = M.graella, P = G['peça'], k = Math.floor(row / P) + '_' + Math.floor(col / P);
  if (row < 0 || col < 0 || !chunkSet().has(k)) return -1;
  let g = UC.get('25/' + k); if (g === undefined) g = await getGrid('25/' + k, BASE + 'd/uid/25/' + k + '.png');
  return g ? g.a[(row % P) * g.w + (col % P)] : -1;
}
const HEAT = [[255, 236, 153], [255, 196, 61], [255, 135, 31], [232, 64, 37], [158, 17, 72]];
function heatPx(o, i, h) {
  h = Math.min(Math.max(h, 0), 1);
  const pos = Math.min(Math.max((h - .12) / .88, 0), 1) * 4, i0 = Math.min(Math.floor(pos), 3), fr = pos - i0;
  const t = Math.min(Math.max((h - .12) / .3, 0), 1), veil = 1 - t;
  for (let c = 0; c < 3; c++) o[i + c] = (HEAT[i0][c] * (1 - fr) + HEAT[i0 + 1][c] * fr) * t + [12, 16, 22][c] * veil;
  o[i + 3] = Math.min(34 * veil + t * (110 + 135 * Math.pow(Math.min(Math.max((h - .12) / .88, 0), 1), .8)), 255);
}
async function tileP(sp, date, z, x, y, filtre) {
  await READY; const pk = await precMeta();
  const chosen = chosenOf(sp, filtre), P = tileGrid(z, x, y), img = new ImageData(256, 256), o = img.data;
  const BL = pk.bloc_m || 1000, step = pk.pas_m || 4, cache = new Map();
  const corners = [P(0, 0), P(256, 0), P(0, 256), P(256, 256)];
  const bxs = corners.map(c => Math.floor(c[0] / BL)), bys = corners.map(c => Math.floor(c[1] / BL));
  for (let bx = Math.min(...bxs); bx <= Math.max(...bxs); bx++) for (let by = Math.min(...bys); by <= Math.max(...bys); by++)
    cache.set(bx + '_' + by, PLIST.has(bx + '_' + by) ? await precField(chosen, date, bx, by) : null);
  const L = await lut(chosen, date), G = M.graella;
  await ensureChunks(Math.min(...corners.map(c => c[0])), Math.min(...corners.map(c => c[1])), Math.max(...corners.map(c => c[0])), Math.max(...corners.map(c => c[1])));
  for (let py = 0; py < 256; py++) for (let px = 0; px < 256; px++) {
    const [X, Y] = P(px + .5, py + .5), bx = Math.floor(X / BL), by = Math.floor(Y / BL), f = cache.get(bx + '_' + by), i = (py * 256 + px) * 4;
    if (f) {
      const ci = Math.floor((X - bx * BL) / step), cj = Math.floor(((by + 1) * BL - Y) / step);
      if (ci >= 0 && cj >= 0 && ci < f.S && cj < f.S) heatPx(o, i, f.heat[cj * f.S + ci]);
    } else {                                        // sense bloc de precisió: quadrats de 25 m del radar
      const u = uidSync(Math.floor((G.y1 - Y) / 25), Math.floor((X - G.x0) / 25));
      if (u >= 0 && L.lv[u] >= 8) renderPx(o, i, L.lv[u], L.cols[L.ld[u]], 8);
    }
  }
  return toPNG(img);
}
maplibregl.addProtocol('rtile', async (params) => {
  const u = new URL(params.url.replace('rtile://', 'https://x/')), p = u.pathname.split('/').filter(Boolean);
  const [kind, sp, date, z, x, yy] = p, y = parseInt(yy), f = u.searchParams.get('filtre') || '';
  const data = kind === 'tilesp' ? await tileP(sp, date, +z, +x, y, f) : await tile4(sp, date, +z, +x, y, f);
  return { data };
});

/* ── noms de lloc (ICGC, directe des del mòbil) ── */
const PN = new Map();
async function placeName(lon, lat) {
  const k = lon.toFixed(3) + ',' + lat.toFixed(3);
  if (PN.has(k)) return PN.get(k);
  try {
    const r = await fetch0(`https://eines.icgc.cat/geocodificador/invers?lat=${lat}&lon=${lon}&size=1`);
    const f = (await r.json()).features[0].properties, o = [f.etiqueta || f.nom || null, f.municipi || null, f.comarca || null];
    PN.set(k, o); return o;
  } catch (e) { return [null, null, null]; }
}

/* ── respostes de l'API ── */
const today = () => { const n = new Date(); return `${n.getFullYear()}-${String(n.getMonth() + 1).padStart(2, '0')}-${String(n.getDate()).padStart(2, '0')}`; };
const ll2xy = (lon, lat) => fwd(lon, lat);
function hav(x0, y0, x1, y1) { return Math.hypot(x1 - x0, y1 - y0); }
async function apiMeta() { await READY; return M; }
async function apiTop(q) {
  await READY;
  const chosen = chosenOf(q.sp || 'totes', q.filtre), a = await vals(q.date), [x0, y0] = ll2xy(+q.w, +q.s), [x1, y1] = ll2xy(+q.e, +q.n), k = +(q.k || 6);
  const off = chosen.map(s => SPI[s] * NU), cand = [];
  for (let u = 0; u < NU; u++) {
    const X = U.x[u], Y = U.y[u]; if (X < x0 || X > x1 || Y < y0 || Y > y1) continue;
    let b = 0, bi = 0; for (let i = 0; i < off.length; i++) { const v = a[off[i] + u]; if (v > b) { b = v; bi = i; } }
    if (b >= 40) cand.push([b, u, bi]);
  }
  cand.sort((p, r) => r[0] - p[0]);
  const sep = Math.max(300, Math.hypot(x1 - x0, y1 - y0) / 9), pick = [];
  for (const c of cand) { if (pick.every(p => hav(U.x[p[1]], U.y[p[1]], U.x[c[1]], U.y[c[1]]) >= sep)) pick.push(c); if (pick.length >= k) break; }
  const zones = await Promise.all(pick.map(async ([v, u, bi]) => {
    const [lo, la] = inv(U.x[u], U.y[u]), [nm, mu, co] = await placeName(+lo.toFixed(3), +la.toFixed(3));
    return { lon: +lo.toFixed(5), lat: +la.toFixed(5), index: v, qualitat: qual(v), especie: chosen[bi], lloc: nm, municipi: mu, comarca: co };
  }));
  return { zones, demo: false };
}
function seguretat(date) {
  const obs = M.observat_fins || M.analisi[1];
  if (date <= obs) return 'dades observades';
  const k = Math.round((new Date(date + 'T12:00:00') - new Date(obs + 'T12:00:00')) / 864e5);
  return k <= 4 ? 'previsió força segura' : 'previsió incerta';
}
function why(Hv, p50) {
  if (Hv <= .01) return 'aquí no hi ha cap arbre hoste compatible';
  return p50 >= 60 ? 'previsió favorable: el sòl i la temperatura previstos són bons per fructificar' :
    p50 >= 20 ? 'previsió moderada: hi pot haver bolets, però no de forma generalitzada' : 'segons la previsió, el fong encara no fructificarà aquí aquest dia';
}
async function apiPoint(q) {
  await READY;
  const [X, Y] = ll2xy(+q.lon, +q.lat), [r, c] = rc(X, Y), u = await uidAt(r, c);
  if (u < 0) return { bosc: false, demo: false };
  const a = await vals(q.date), t = today(), fut = M.dies.filter(d => d >= t);
  const series = await Promise.all(fut.map(vals));
  const res = [];
  for (const e of M.especies) {
    const Hv = H(e.id, u); if (Hv < .05) continue;
    const p50 = V(a, e.id, u), ser = series.map(s => V(s, e.id, u));
    let bi = 0; ser.forEach((v, i) => { if (v > ser[bi]) bi = i; });
    const best = { dia: ser.length && ser[bi] >= 20 ? fut[bi] : null, serie: ser, dates: fut };
    res.push({ ...e, H: +Hv.toFixed(2), p10: p50, p50, p90: p50, qualitat: qual(p50), nivell: Math.min(5, Math.max(0, Math.floor(p50 / 20) + (p50 >= 1 ? 1 : 0))),
      seguretat: seguretat(q.date), fase: null, per_que: why(Hv, p50), millor: best });
  }
  res.sort((p, r2) => r2.p50 - p.p50);
  return { bosc: true, demo: false, altitud: U.elev[u], hoste: M.hostes[U.host[u]] || 'bosc', cobertura: U.cov[u] / 100,
    edat_bosc: U.age[u] === 255 ? null : U.age[u], especies: res, avis: M.avis };
}
async function apiNear(q) {
  await READY;
  const chosen = chosenOf(q.sp || 'totes', q.filtre), L = await lut(chosen, q.date), r = +(q.r || 1200), k = +(q.k || 5);
  const [X, Y] = ll2xy(+q.lon, +q.lat), [r0, c0] = rc(X, Y), n = Math.floor(r / 25);
  const cells = [];
  let here = 0, hereSp = null;
  await ensureChunks(X - r, Y - r, X + r, Y + r);
  for (let dr = -n; dr <= n; dr++) for (let dc = -n; dc <= n; dc++) {
    if (Math.hypot(dr, dc) * 25 > r) continue;
    const u = uidSync(r0 + dr, c0 + dc); if (u < 0) continue;
    const v = L.lv[u];
    if (dr === 0 && dc === 0) { here = v; hereSp = v > 0 ? chosen[L.ld[u]] : null; }
    if (v >= 40) cells.push([v, dr, dc, L.ld[u]]);
  }
  cells.sort((p, s) => s[0] - p[0]);
  const kept = [];
  for (const cc of cells) { if (kept.every(p => Math.hypot(p[1] - cc[1], p[2] - cc[2]) * 25 >= 150)) kept.push(cc); if (kept.length >= k) break; }
  const DIRS = ['nord', 'nord-est', 'est', 'sud-est', 'sud', 'sud-oest', 'oest', 'nord-oest'];
  const punts = kept.map(([v, dr, dc, di]) => {
    const [cx, cy] = cellXY(r0 + dr, c0 + dc), [lo, la] = inv(cx, cy), dx = cx - X, dy = cy - Y, brg = (Math.atan2(dx, dy) * 180 / Math.PI + 360) % 360;
    return { lon: +lo.toFixed(6), lat: +la.toFixed(6), index: v, qualitat: qual(v), especie: chosen[di], dist_m: Math.round(Math.hypot(dx, dy) / 10) * 10, rumb: brg, direccio: DIRS[Math.floor((brg + 22.5) / 45) % 8] };
  });
  return { aqui: { index: here, qualitat: qual(here), especie: hereSp }, punts, demo: false };
}
async function apiSpots(q) {
  await READY; const pk = await precMeta();
  const chosen = chosenOf('totes', q.filtre), [x0, y0] = ll2xy(+q.w, +q.s), [x1, y1] = ll2xy(+q.e, +q.n), k = +(q.k || 10);
  const BL = pk.bloc_m || 1000, step = pk.pas_m || 4, cand = [];
  for (let bx = Math.floor(x0 / BL); bx <= Math.floor(x1 / BL); bx++) for (let by = Math.floor(y0 / BL); by <= Math.floor(y1 / BL); by++) {
    if (!PLIST.has(bx + '_' + by)) continue;
    const f = await precField(chosen, q.date, bx, by); if (!f) continue;
    for (let j = 1; j < f.S - 1; j++) for (let i = 1; i < f.S - 1; i++) {
      const p = j * f.S + i, v = f.V[p]; if (v < 40) continue;
      if (v < f.V[p - 1] || v < f.V[p + 1] || v < f.V[p - f.S] || v < f.V[p + f.S]) continue;
      const X = bx * BL + (i + .5) * step, Y = (by + 1) * BL - (j + .5) * step;
      if (X < x0 || X > x1 || Y < y0 || Y > y1) continue;
      cand.push([v, X, Y, f.D[p], f.heat[p]]);
    }
  }
  if (!cand.length) {                                // sense precisió a la vista: millors quadrats de 25 m
    const t = await apiTop({ ...q, sp: 'totes', k });
    return { punts: t.zones.map(z => ({ lon: z.lon, lat: z.lat, index: z.index, qualitat: z.qualitat, especie: z.especie, calor: null, arbre_m: null })) };
  }
  cand.sort((p, r) => (r[0] - p[0]) || (r[4] - p[4]));            // empat (nota 100): primer el que més destaca del voltant
  const kept = [];
  for (const c of cand) { if (kept.every(p => Math.hypot(p[1] - c[1], p[2] - c[2]) >= 40)) kept.push(c); if (kept.length >= k) break; }
  return { punts: kept.map(([v, X, Y, di, h]) => { const [lo, la] = inv(X, Y); return { lon: +lo.toFixed(6), lat: +la.toFixed(6), index: +v.toFixed(1), qualitat: qual(v), especie: chosen[di], calor: +h.toFixed(2), arbre_m: null }; }) };
}
function sunrise(ds, lat, lon) {
  const d = new Date(ds + 'T12:00:00'), n = Math.round((d - new Date(d.getFullYear(), 0, 1, 12)) / 864e5) + 1, g = 2 * Math.PI / 365 * (n - 1);
  const eq = 229.18 * (.000075 + .001868 * Math.cos(g) - .032077 * Math.sin(g) - .014615 * Math.cos(2 * g) - .040849 * Math.sin(2 * g));
  const dc = .006918 - .399912 * Math.cos(g) + .070257 * Math.sin(g) - .006758 * Math.cos(2 * g) + .000907 * Math.sin(2 * g), la = lat * Math.PI / 180;
  const ha = Math.acos(Math.cos(90.833 * Math.PI / 180) / (Math.cos(la) * Math.cos(dc)) - Math.tan(la) * Math.tan(dc)) * 180 / Math.PI;
  const lastSun = (y, m) => { const x = new Date(y, m, 31, 12); x.setDate(31 - x.getDay()); return x; };
  const off = d >= lastSun(d.getFullYear(), 2) && d < lastSun(d.getFullYear(), 9) ? 120 : 60, mm = Math.round(720 - 4 * (lon + ha) - eq + off);
  return `${String(Math.floor(mm / 60)).padStart(2, '0')}:${String(mm % 60).padStart(2, '0')}`;
}
const ASPECT = ['nord', 'nord-est', 'est', 'sud-est', 'sud', 'sud-oest', 'oest', 'nord-oest'];
async function apiCerca(q) {
  await READY; const Zs = await loadZ();
  const chosen = (q.sp && q.sp !== 'totes') ? q.sp.split(',').filter(s => SPI[s] != null) : M.bosc.slice();
  if (!chosen.length) return { zones: [], motiu: 'cap espècie vàlida' };
  const t = today(), last = M.dies[M.dies.length - 1];
  let days = q.dies ? q.dies.split(',').filter(Boolean) : M.dies.filter(d => d >= t);
  days = days.filter(d => d <= last && M.dies.includes(d));
  if (!days.length) return { zones: [], motiu: 'Encara no hi ha previsió per a aquests dies.' };
  const km = +(q.km || 40), k = +(q.k || 5), [ox, oy] = ll2xy(+q.lon, +q.lat), GOOD = 60, HMIN = .3, FRAC = .25;
  const mask = new Uint8Array(NU); for (let u = 0; u < NU; u++) for (const s of chosen) if (HB[SPI[s] * NU + u] >= HMIN * 100) { mask[u] = 1; break; }
  const nz = Zs.nz, den = new Float32Array(nz), zx = new Float32Array(nz), zy = new Float32Array(nz), inside = new Uint8Array(nz);
  for (let z = 0; z < nz; z++) {
    let d = 0; for (let p = Zs.ip[z]; p < Zs.ip[z + 1]; p++) if (mask[Zs.ix[p]]) d += Zs.dt[p];
    den[z] = d; const xy = fwd(Zs.lon[z], Zs.lat[z]); zx[z] = xy[0]; zy[z] = xy[1]; inside[z] = Math.hypot(xy[0] - ox, xy[1] - oy) / 1000 <= km;
  }
  const ok = z => den[z] / 100 >= FRAC;
  const scores = [], best = new Float32Array(nz), bestI = new Uint8Array(nz);
  for (let di = 0; di < days.length; di++) {
    const L = await lut(chosen, days[di]), sc = new Float32Array(nz);
    for (let z = 0; z < nz; z++) {
      if (!ok(z) || (!inside[z] && di > 0 && best[z] < GOOD)) continue;
      let s = 0; for (let p = Zs.ip[z]; p < Zs.ip[z + 1]; p++) { const u = Zs.ix[p]; if (mask[u]) s += L.lv[u] * Zs.dt[p]; }
      sc[z] = s / Math.max(den[z], 1e-6); if (sc[z] > best[z]) { best[z] = sc[z]; bestI[z] = di; }
    }
    scores.push(sc);
  }
  const cand = []; for (let z = 0; z < nz; z++) if (inside[z] && best[z] >= GOOD) cand.push(z);
  cand.sort((p, r) => best[r] - best[p]);
  const sel = []; for (const z of cand) { if (sel.every(o => Math.hypot(zx[z] - zx[o], zy[z] - zy[o]) >= 2000)) sel.push(z); if (sel.length >= k) break; }
  const res = await Promise.all(sel.map(async z => {
    const day = days[bestI[z]], a = await vals(day), L = await lut(chosen, day);
    const spsc = {}; for (const s of chosen) { let sv = 0; for (let p = Zs.ip[z]; p < Zs.ip[z + 1]; p++) { const u = Zs.ix[p]; if (mask[u]) sv += a[SPI[s] * NU + u] * Zs.dt[p]; } spsc[s] = sv; }
    const topSp = Object.keys(spsc).reduce((p, r) => spsc[r] > spsc[p] ? r : p);
    const lon = Zs.lon[z], lat = Zs.lat[z], [nm, mu, co] = await placeName(+lon.toFixed(5), +lat.toFixed(5)), dist = Math.hypot(zx[z] - ox, zy[z] - oy) / 1000;
    // descripció física: hoste dominant, altitud, orientació, edat
    let wsum = 0, el = 0, sx = 0, sy = 0, ag = 0, agw = 0; const hw = {};
    for (let p = Zs.ip[z]; p < Zs.ip[z + 1]; p++) { const u = Zs.ix[p]; if (!mask[u]) continue; const w = Zs.dt[p]; wsum += w; el += U.elev[u] * w; const asr = U.asp[u] / 255 * 2 * Math.PI; sx += Math.sin(asr) * w; sy += Math.cos(asr) * w; hw[U.host[u]] = (hw[U.host[u]] || 0) + w; if (U.age[u] !== 255) { ag += U.age[u] * w; agw += w; } }
    const hk = Object.keys(hw).reduce((p, r) => hw[r] > hw[p] ? r : p, Object.keys(hw)[0]), asp = (Math.atan2(sx, sy) * 180 / Math.PI + 360) % 360;
    const dd = new Date(day + 'T12:00:00');
    return { lon: +lon.toFixed(6), lat: +lat.toFixed(6), nota: +best[z].toFixed(1), qualitat: qual(best[z]), dia: day, especie: topSp,
      serie: scores.map(sc => +sc[z].toFixed(1)), km: +dist.toFixed(1), cotxe_min: Math.round(dist * 1.35 / 55 * 60 / 5) * 5, sol: sunrise(day, lat, lon),
      cap_de_setmana: dd.getDay() === 0 || dd.getDay() === 6, bosc_bo: Math.round(den[z]), lloc: nm, municipi: mu, comarca: co,
      hoste: M.hostes[hk] || 'bosc', altitud: Math.round(el / Math.max(wsum, 1)), orientacio: ASPECT[Math.floor((asp + 22.5) / 45) % 8], edat_bosc: Math.round(agw ? ag / agw : 50) };
  }));
  const out = { zones: res, dies: days, radi_km: km, especies: chosen, llindar: GOOD };
  if (!res.length) {
    let mx = 0, any = false; for (let z = 0; z < nz; z++) if (inside[z] && ok(z)) { any = true; if (best[z] > mx) mx = best[z]; }
    out.millor_nota_dins = +mx.toFixed(1);
    out.motiu = any ? `Cap zona arriba a «Bona» (60) dins de ${km} km aquests dies. La millor nota és ${Math.round(mx)} (${qual(mx)}): no val la pena anar-hi.` : `No hi ha bosc adequat dins de ${km} km.`;
  }
  return out;
}
async function apiSearch(q) {
  try {
    const r = await fetch0(`https://eines.icgc.cat/geocodificador/cerca?text=${encodeURIComponent(q.q)}&size=6`), j = await r.json();
    return { results: j.features.map(f => ({ name: f.properties.etiqueta, type: (f.properties.addendum || {}).tipus, comarca: f.properties.comarca, lon: f.geometry.coordinates[0], lat: f.geometry.coordinates[1] })) };
  } catch (e) { return { results: [] }; }
}
function apiUpd() {
  return { base: M ? M.analisi[1] : null, observat_fins: M ? M.observat_fins : null, emes: M ? M.emes : null, al_dia: true, en_curs: false, pas: null, error: null, bloquejat: true, estatic: true };
}

/* ── sortides: es desen al mòbil (privat); es poden passar a l'ordinador quan hi siguis ── */
const TK = 'bolets_sortides';
const tload = () => { try { return JSON.parse(localStorage.getItem(TK) || '{}'); } catch (e) { return {}; } };
const tsave = o => { try { localStorage.setItem(TK, JSON.stringify(o)); } catch (e) {} };
function mdist(a, b, c, d) { const r = Math.PI / 180, x = (c - a) * r * Math.cos((b + d) / 2 * r), y = (d - b) * r; return 6371000 * Math.hypot(x, y); }
function trips(path, method, body) {
  const T = tload(), p = path.split('/').filter(Boolean);           // api v4 sortides [sid] [op]
  if (p[2] === 'meus-llocs') {
    const tb = [], zs = [];
    Object.values(T).forEach(s => (s.troballes || []).forEach(x => (x.zero ? zs : tb).push({ ...x, sortida_id: s.id })));
    const cl = [];
    tb.sort((a, b) => (a.t || '') < (b.t || '') ? -1 : 1).forEach(x => {
      let best = null, bd = 15; cl.forEach(k => { const d = mdist(k.lon, k.lat, x.lon, x.lat); if (d <= bd) { best = k; bd = d; } });
      if (!best) { best = { lon: x.lon, lat: x.lat, n: 0, bolets: 0, esp: {}, anys: new Set(), sort: new Set(), primera: x.t, darrera: x.t }; cl.push(best); }
      const n = best.n; best.lon = (best.lon * n + x.lon) / (n + 1); best.lat = (best.lat * n + x.lat) / (n + 1); best.n = n + 1; best.bolets += x.quantitat || 0;
      const e = x.especie || '?'; best.esp[e] = (best.esp[e] || 0) + (x.quantitat || 0); best.anys.add((x.t || '').slice(0, 4)); best.sort.add(x.sortida_id); best.darrera = x.t;
    });
    const llocs = cl.map(k => { const esp = Object.entries(k.esp).sort((a, b) => b[1] - a[1]); const zeros = new Set(zs.filter(z => mdist(k.lon, k.lat, z.lon, z.lat) <= 15).map(z => z.sortida_id)); k.sort.forEach(s => zeros.delete(s));
      return { lon: k.lon, lat: k.lat, especie: esp[0][0], especies: Object.fromEntries(esp), troballes: k.n, bolets: k.bolets, anys: k.anys.size, visites: k.sort.size, visites_zero: zeros.size, primera: k.primera, darrera: k.darrera }; })
      .sort((a, b) => b.anys - a.anys || b.visites - a.visites || b.bolets - a.bolets);
    return { llocs, radi_m: 15, privat: true };
  }
  if (method === 'GET') {
    if (p[3]) return T[p[3]] || {};
    return { sortides: Object.values(T).sort((a, b) => (b.inici || '') < (a.inici || '') ? -1 : 1).map(s => ({ id: s.id, inici: s.inici, fi: s.fi, troballes: (s.troballes || []).length })) };
  }
  const sid = p[3], op = p[4];
  if (!sid) { T[body.id] = { ...body, traca: [], troballes: [] }; tsave(T); return { ok: true, id: body.id }; }
  const s = T[sid] || (T[sid] = { id: sid, traca: [], troballes: [] });
  if (op === 'traca') s.traca.push(...(body.punts || []));
  else if (op === 'troballa') { if (!s.troballes.some(x => x.id === body.id)) s.troballes.push({ ...body, t: body.t || new Date().toISOString() }); }
  else if (op === 'fi') Object.assign(s, body);
  tsave(T);
  return { ok: true };
}

/* ── intercepta fetch('/api/…') ── */
const fetch0 = window.fetch.bind(window);
const J = (o, st) => new Response(JSON.stringify(o), { status: st || 200, headers: { 'Content-Type': 'application/json' } });
window.fetch = async function (input, init) {
  const url = typeof input === 'string' ? input : input.url;
  if (!url.startsWith('/api/')) return fetch0(input, init);
  const u = new URL(url, location.href), q = Object.fromEntries(u.searchParams), path = u.pathname, method = (init && init.method) || 'GET';
  try {
    if (path === '/api/v4/meta') return J(await apiMeta());
    if (path === '/api/v4/top') return J(await apiTop(q));
    if (path === '/api/v4/point') return J(await apiPoint(q));
    if (path === '/api/v4/near') return J(await apiNear(q));
    if (path === '/api/v4/spots') return J(await apiSpots(q));
    if (path === '/api/v4/cerca') return J(await apiCerca(q));
    if (path === '/api/v4/warm') return J({ blocs: 0 });
    if (path === '/api/v4/actualitzacio') { await READY; return J(apiUpd()); }
    if (path.startsWith('/api/v4/species/')) { await READY; return J(await getJSON('d/sp/' + path.split('/').pop() + '.json')); }
    if (path === '/api/search') return J(await apiSearch(q));
    if (path.startsWith('/api/v4/sortides') || path === '/api/v4/meus-llocs') {
      const body = init && init.body ? JSON.parse(init.body) : null; return J(trips(path, method, body));
    }
    return J({ detail: 'no disponible al mòbil' }, 404);
  } catch (e) { console.error(e); return J({ detail: String(e) }, 500); }
};
window.BOLETS_STATIC = { ready: () => READY };
unlock();
})();
