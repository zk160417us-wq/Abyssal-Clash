// Core Conflict multiplayer server. Run: npm install && npm start
// Serves the game at http://localhost:8080 and WebSocket PvP on the same port.
const http = require('http'), fs = require('fs'), path = require('path');
// ── Built-in WebSocket server (no extra libraries needed - only Node.js) ──
const EventEmitter = require('events');
class MiniSocket extends EventEmitter {
  constructor(sock) { super(); this.sock = sock; this.readyState = 1; this.buf = Buffer.alloc(0); this.frags = []; this.lastSeen = Date.now();
    sock.setNoDelay(true);
    sock.on('data', d => this._data(d));
    sock.on('close', () => this._end());
    sock.on('end', () => this._end());
    sock.on('error', e => { this.emit('error', e); this._end(); }); }
  _end() { if (this.readyState === 3) return; this.readyState = 3; this.emit('close'); }
  _data(d) {
    this.lastSeen = Date.now();
    this.buf = Buffer.concat([this.buf, d]);
    while (this.buf.length >= 2) {
      const b0 = this.buf[0], b1 = this.buf[1], fin = (b0 & 0x80) !== 0, op = b0 & 0x0f, masked = (b1 & 0x80) !== 0;
      let len = b1 & 0x7f, off = 2;
      if (len === 126) { if (this.buf.length < 4) return; len = this.buf.readUInt16BE(2); off = 4; }
      else if (len === 127) { if (this.buf.length < 10) return; len = Number(this.buf.readBigUInt64BE(2)); off = 10; }
      if (len > 1048576) { this.close(); return; }                       // 1 MB max message
      const need = off + (masked ? 4 : 0) + len; if (this.buf.length < need) return;
      let payload = this.buf.subarray(off + (masked ? 4 : 0), need);
      if (masked) { const mk = this.buf.subarray(off, off + 4); payload = Buffer.from(payload); for (let i = 0; i < payload.length; i++) payload[i] ^= mk[i & 3]; }
      this.buf = this.buf.subarray(need);
      if (op === 0x8) { this.close(); return; }                           // close
      if (op === 0x9) { this._frame(0xA, payload); continue; }            // ping -> pong
      if (op === 0xA) continue;                                           // pong
      if (op === 0x1 || op === 0x2 || op === 0x0) { this.frags.push(payload);
        if (fin) { const msg = Buffer.concat(this.frags); this.frags = []; this.emit('message', msg.toString('utf8')); } }
    }
  }
  _frame(op, data) {
    if (this.readyState !== 1) return; const len = data.length; let head;
    if (len < 126) { head = Buffer.from([0x80 | op, len]); }
    else if (len < 65536) { head = Buffer.alloc(4); head[0] = 0x80 | op; head[1] = 126; head.writeUInt16BE(len, 2); }
    else { head = Buffer.alloc(10); head[0] = 0x80 | op; head[1] = 127; head.writeBigUInt64BE(BigInt(len), 2); }
    try { this.sock.write(Buffer.concat([head, data])); } catch (e) {}
  }
  send(str) { this._frame(0x1, Buffer.from(String(str), 'utf8')); }
  ping() { this._frame(0x9, Buffer.alloc(0)); }
  close() { if (this.readyState !== 1) return; this._frame(0x8, Buffer.alloc(0)); this.readyState = 2; try { this.sock.end(); } catch (e) {} setTimeout(() => { try { this.sock.destroy(); } catch (e) {} this._end(); }, 500); }
}
class WebSocketServer extends EventEmitter {
  constructor({ server }) { super(); this.clients = new Set();
    server.on('upgrade', (req, sock) => {
      const key = req.headers['sec-websocket-key'];
      if (!key || String(req.headers.upgrade || '').toLowerCase() !== 'websocket') { sock.destroy(); return; }
      const accept = require('crypto').createHash('sha1').update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
      sock.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ' + accept + '\r\n\r\n');
      const ws = new MiniSocket(sock); this.clients.add(ws); ws.on('close', () => this.clients.delete(ws));
      this.emit('connection', ws, req);
    });
  }
}

const PORT = process.env.PORT || 8080;
const KILL_TARGET = 5, FILL_WAIT = 20, COUNTDOWN = 3, VOTE_SECONDS = 10;
const MAP_IDS = ['city', 'cyber', 'g_mobius1', 'g_mobius8', 'g_interior', 'g_pvp', 'g_arena', 'bk_fort', 'bk_yard', 'bk_toy', 'bk_dune'];
const HUB_MAX = 10;               // max players per island server

/* ─── accounts: passwords are checked on the server (scrypt-hashed in accounts.json) ─── */
const crypto = require('crypto');
// Old founder names were changed: FOZK is now ZK and FDZY is now ZY (the (FO) tag is added automatically).
// Logging in with the old name still works and goes to the new account.
const RENAMED = { fdzy: 'zy' };
const alias = n => RENAMED[n] || n;
const ACC_FILE = path.join(__dirname, 'accounts.json');
let accounts = {}; try { accounts = JSON.parse(fs.readFileSync(ACC_FILE, 'utf8')); } catch (e) { accounts = {}; }
let accTimer = null; function saveAccounts() { clearTimeout(accTimer); accTimer = setTimeout(() => fs.writeFile(ACC_FILE, JSON.stringify(accounts), () => {}), 300); cloudSave(); }
if (accounts.auraguy) { delete accounts.auraguy; setTimeout(() => saveAccounts(), 1000); }
const hashPw = (pw, salt) => crypto.scryptSync(String(pw), salt, 32).toString('hex');
// Returns the verified username, or null. First time a name is seen, it is registered with that password.
// A login key for the game to keep instead of the password. It is made from the secret scrambled password,
// so it can't be turned back into the password, and it stops working if the password is changed (RESET_PASSWORDS).
function tokenFor(n) { const a = accounts[n]; if (!a || !a.salt || !a.hash) return null; return 'tok:' + crypto.createHash('sha256').update('abyssal|' + a.salt + '|' + a.hash).digest('hex').slice(0, 48); }
// A name exactly as typed (letters, numbers, _ ; capitals kept)
const keyOf = x => String(x || '').replace(/[^A-Za-z0-9_]/g, '').slice(0, 20);
// Find an account: exact spelling first, then the old small-letter account, then a unique match ignoring capitals.
function resolveName(x) { const k = alias(keyOf(x)); if (!k || accounts[k]) return k; const l = alias(k.toLowerCase()); if (accounts[l]) return l;
  let hit = null; for (const a of Object.keys(accounts)) if (a.toLowerCase() === k.toLowerCase()) { if (hit) return k; hit = a; } return hit || k; }
// Founder/admin names and their look-alikes, and deleted names, can't be signed up in the game.
function canRegister(k) { const l = k.toLowerCase();
  if (FOUNDERS.concat(ADMINS).some(x => x.toLowerCase() === l)) return false;
  if (REMOVED.some(x => x.toLowerCase() === l)) return false; return true; }
function checkLogin(name, pass, exact) {
  const n = exact ? alias(keyOf(name)) : resolveName(name); const pw = String(pass || '');
  if (n.length < 2 || pw.length < 4) return null;
  const a = accounts[n];
  if (pw.startsWith('tok:')) { const t = tokenFor(n); if (!a || !t || t.length !== pw.length) return null; return crypto.timingSafeEqual(Buffer.from(t), Buffer.from(pw)) ? n : null; }
  if (!a) { if (!canRegister(n)) return null; const salt = crypto.randomBytes(16).toString('hex'); accounts[n] = { salt, hash: hashPw(pw, salt), created: Date.now() }; saveAccounts(); return n; }
  const h = hashPw(pw, a.salt); return crypto.timingSafeEqual(Buffer.from(h, 'hex'), Buffer.from(a.hash, 'hex')) ? n : null;
}

function authFail(ws, name) { send(ws, { type:'authFail', name: String(name || '').slice(0, 20), text:'Wrong password for "' + String(name || '').slice(0, 20) + '" on this server. That username is already taken here — log out and use another name, or type the right password.' }); }

/* ─── friends + chat ─── */
const FRIENDS_FILE = path.join(__dirname, 'friends.json');
let social = {};                                   // name -> { friends:[], incoming:[], outgoing:[] }
try { social = JSON.parse(fs.readFileSync(FRIENDS_FILE, 'utf8')); } catch (e) { social = {}; }
let saveTimer = null;
// the old "auraguy" test account is removed for good
const REMOVED = ['auraguy', 'zk', 'fozk'];
function migrateNames() {
  let changed = false;
  for (const [o, n] of Object.entries(RENAMED)) {
    if (accounts[o]) { if (!accounts[n]) accounts[n] = accounts[o]; delete accounts[o]; changed = true; }
    if (social[o]) { if (!social[n]) social[n] = social[o]; delete social[o]; changed = true; }
  }
  Object.values(social).forEach(s => ['friends','incoming','outgoing'].forEach(k => { const before = (s[k] || []).join(); s[k] = [...new Set((s[k] || []).map(alias))]; if (s[k].join() !== before) changed = true; }));
  return changed;
}
if (migrateNames()) setTimeout(() => { saveAccounts(); saveSocial(); }, 1000);
/* Owner-only password reset. Passwords are scrambled (hashed), so nobody can read them back - not even the owner.
   To give an account a NEW password, the owner adds an Environment Variable on Render:
     RESET_PASSWORDS = zk:newpassword        (several: zk:pass1,zy:pass2)
   then deploys. Remove the variable again afterwards. */
function applyResets() { const raw = process.env.RESET_PASSWORDS || ''; if (!raw.trim()) return false; let changed = false;
  raw.split(',').forEach(pair => { const i = pair.indexOf(':'); if (i < 1) return; const n = alias(keyOf(pair.slice(0, i).trim())), pw = pair.slice(i + 1).trim();
    if (!n || pw.length < 4) { console.log('  [reset] skipped "' + n + '" (password needs 4+ characters)'); return; }
    const salt = crypto.randomBytes(16).toString('hex'); accounts[n] = Object.assign(accounts[n] || { created: Date.now() }, { salt, hash: hashPw(pw, salt) }); changed = true;
    console.log('  [reset] new password set for "' + n + '"'); });
  return changed; }
/* Owner-only "start over". Add on Render:  FRESH_ACCOUNTS = zk:newpassword   (several: zk:pass1,zy:pass2)
   The OLD account is deleted (coins, items, level, friends) and a brand-new one is made with that password.
   It only happens once for each name+password, so leaving the variable there by mistake won't wipe it again. */
function applyFresh() { const raw = process.env.FRESH_ACCOUNTS || ''; if (!raw.trim()) return false; let changed = false;
  raw.split(',').forEach(pair => { const i = pair.indexOf(':'); if (i < 1) return; const n = alias(keyOf(pair.slice(0, i).trim())), pw = pair.slice(i + 1).trim();
    if (n.length < 2 || pw.length < 4) { console.log('  [fresh] skipped "' + n + '" (name needs 2+ letters, password 4+ characters)'); return; }
    const a = accounts[n]; if (a && a.freshSalt && a.freshKey === hashPw(pw, a.freshSalt)) return;          // already done
    delete social[n]; Object.values(social).forEach(s => ['friends','incoming','outgoing'].forEach(k => { s[k] = (s[k] || []).filter(x => x !== n); }));
    const salt = crypto.randomBytes(16).toString('hex'), freshSalt = crypto.randomBytes(16).toString('hex');
    accounts[n] = { created: Date.now(), salt, hash: hashPw(pw, salt), freshSalt, freshKey: hashPw(pw, freshSalt), freshAt: Date.now() };
    changed = true; console.log('  [fresh] "' + n + '" was deleted and made again as a brand-new account'); });
  return changed; }
if (applyFresh() | applyResets()) setTimeout(() => { saveAccounts(); saveSocial(); }, 1200);
REMOVED.forEach(n => { delete accounts[n]; delete social[n]; Object.values(social).forEach(s => ['friends','incoming','outgoing'].forEach(k => { s[k] = (s[k] || []).filter(x => x !== n); })); });
function saveSocial() { clearTimeout(saveTimer); saveTimer = setTimeout(() => fs.writeFile(FRIENDS_FILE, JSON.stringify(social), () => {}), 500); cloudSave(); }

/* ─── CLOUD DATABASE: accounts, game progress and friends are kept in a private GitHub Gist ───
   Render wipes files every time you deploy, so without this everyone's accounts reset.
   Setup (once): make a GitHub token with the "gist" box ticked, then in Render → Environment
   add  GITHUB_TOKEN = <your token>.  The server creates its own private gist "abyssal-clash-database". */
const https = require('https');
const GH_TOKEN = process.env.GITHUB_TOKEN || process.env.GIST_TOKEN || '';
const GH_API = process.env.GITHUB_API || 'https://api.github.com';
const DB_DESC = 'abyssal-clash-database', DB_FILE = 'abyssal-clash-db.json';
let gistId = process.env.GIST_ID || null, cloudReady = !GH_TOKEN, cloudTimer = null, cloudBusy = false, cloudDirty = false;
function gh(method, p, body, raw) {
  return new Promise((res, rej) => { const u = new URL(raw ? p : GH_API + p); const data = body ? JSON.stringify(body) : null;
    const lib = u.protocol === 'http:' ? http : https;
    const r = lib.request(u, { method, headers: { 'User-Agent': 'abyssal-clash-server', 'Accept': 'application/vnd.github+json', 'Authorization': 'Bearer ' + GH_TOKEN, ...(data ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) } : {}) } }, resp => {
      let out = ''; resp.setEncoding('utf8'); resp.on('data', c => out += c); resp.on('end', () => { if (resp.statusCode >= 300) return rej(new Error('GitHub ' + resp.statusCode + ' ' + out.slice(0, 200))); try { res(raw ? out : JSON.parse(out || '{}')); } catch (e) { rej(e); } }); });
    r.on('error', rej); r.setTimeout(20000, () => r.destroy(new Error('timeout'))); if (data) r.write(data); r.end(); });
}
async function cloudLoad() {
  if (!GH_TOKEN) { console.log('  [database] No GITHUB_TOKEN set - accounts are only saved until the next deploy.'); return; }
  try {
    if (!gistId) { for (let page = 1; page <= 5 && !gistId; page++) { const list = await gh('GET', '/gists?per_page=100&page=' + page); if (!list.length) break; const g = list.find(x => x.description === DB_DESC); if (g) gistId = g.id; } }
    if (!gistId) { const g = await gh('POST', '/gists', { description: DB_DESC, public: false, files: { [DB_FILE]: { content: JSON.stringify({ accounts, social, v: 1 }) } } }); gistId = g.id; console.log('  [database] Created a new private gist for accounts: ' + gistId); }
    else { const g = await gh('GET', '/gists/' + gistId); const f = g.files && g.files[DB_FILE];
      let txt = f ? (f.truncated ? await gh('GET', f.raw_url, null, true) : f.content) : '{}'; const db = JSON.parse(txt || '{}');
      const acc = db.accounts || {}, soc = db.social || {};
      for (const k of Object.keys(accounts)) if (!acc[k]) acc[k] = accounts[k];          // keep anyone who signed up while we were loading
      for (const k of Object.keys(social)) if (!soc[k]) soc[k] = social[k];
      accounts = acc; social = soc; REMOVED.forEach(n => { delete accounts[n]; delete social[n]; });
      if (migrateNames() | applyFresh() | applyResets()) { cloudReady = true; setTimeout(() => { saveAccounts(); saveSocial(); }, 500); }
      fs.writeFile(ACC_FILE, JSON.stringify(accounts), () => {}); fs.writeFile(FRIENDS_FILE, JSON.stringify(social), () => {});
      console.log('  [database] Loaded ' + Object.keys(accounts).length + ' accounts from the cloud.'); }
  } catch (e) { console.log('  [database] Could not reach GitHub: ' + e.message + ' (will keep trying)'); setTimeout(cloudLoad, 30000); return; }
  cloudReady = true; if (cloudDirty) cloudSave();
}
function cloudSave(now) {
  if (!GH_TOKEN) return; cloudDirty = true; if (!cloudReady || !gistId) return; clearTimeout(cloudTimer);
  cloudTimer = setTimeout(async () => { if (cloudBusy) return cloudSave(); cloudBusy = true; cloudDirty = false;
    try { await gh('PATCH', '/gists/' + gistId, { files: { [DB_FILE]: { content: JSON.stringify({ accounts, social, v: 1, saved: Date.now() }) } } }); }
    catch (e) { console.log('  [database] Save failed: ' + e.message); cloudDirty = true; setTimeout(() => cloudSave(), 15000); }
    cloudBusy = false; }, now ? 0 : 6000);
}
async function cloudFlush() { if (!GH_TOKEN || !cloudReady || !gistId || !cloudDirty) return; clearTimeout(cloudTimer);
  try { await gh('PATCH', '/gists/' + gistId, { files: { [DB_FILE]: { content: JSON.stringify({ accounts, social, v: 1, saved: Date.now() }) } } }); cloudDirty = false; } catch (e) {} }
['SIGTERM', 'SIGINT'].forEach(sig => process.on(sig, () => { console.log('  [database] Saving before shutdown...'); cloudFlush().finally(() => process.exit(0)); setTimeout(() => process.exit(0), 8000); }));
setTimeout(cloudLoad, 10);
const online = new Map();                          // name -> player (social socket)
function S(name) { return social[name] || (social[name] = { friends: [], incoming: [], outgoing: [] }); }
const cleanName = n => resolveName(n);
const cleanText = t => String(t || '').replace(/[\u0000-\u001f\u007f]/g, '').trim().slice(0, 200);
function whereOf(name) { const p = online.get(name); if (!p) return null; return p.where || 'Online'; }
function socialState(name) { const s0 = S(name);
  return { type:'socialState', friends: s0.friends.map(f => ({ name:f, online: online.has(f), where: whereOf(f) })), incoming: s0.incoming.slice(), outgoing: s0.outgoing.slice() }; }
function pushState(name) { const p = online.get(name); if (p) send(p.ws, socialState(name)); }
function notifyFriends(name) { S(name).friends.forEach(pushState); }
function rateOk(p) { const now = Date.now(); if (now - (p.lastMsg || 0) < 500) return false; p.lastMsg = now; return true; }

const PUBLIC = path.join(__dirname, 'public');
const MIME = { '.html':'text/html; charset=utf-8', '.js':'text/javascript', '.json':'application/json', '.glb':'model/gltf-binary', '.gltf':'model/gltf+json',
  '.bin':'application/octet-stream', '.png':'image/png', '.jpg':'image/jpeg', '.jpeg':'image/jpeg', '.webp':'image/webp', '.txt':'text/plain; charset=utf-8', '.css':'text/css' };
// Windows renames repeat downloads to "index (4).html", "Fox (1).glb"… Accept those names too
// (the newest copy, i.e. the highest number, wins).
function flatFile(base) {
  const exact = path.join(__dirname, base); if (fs.existsSync(exact)) return exact;
  const ext = path.extname(base), stem = base.slice(0, base.length - ext.length);
  const esc = s => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const re = new RegExp('^' + esc(stem) + ' ?\\((\\d+)\\)' + esc(ext) + '$', 'i');
  let best = null, bestN = -1;
  try { for (const n of fs.readdirSync(__dirname)) { const m = n.match(re); if (m && +m[1] > bestN) { bestN = +m[1]; best = n; } } } catch (e) {}
  return best ? path.join(__dirname, best) : exact;
}
const server = http.createServer((req, res) => {
  let p = decodeURIComponent((req.url || '/').split('?')[0]);
  if (p === '/' || p === '') p = '/index.html';
  let f = path.normalize(path.join(PUBLIC, p));
  if (!f.startsWith(PUBLIC)) { res.writeHead(403); return res.end('Forbidden'); }   // no ../ tricks
  // Flat upload (everything in one folder, e.g. on GitHub/Render): also look next to server.js,
  // but only for game files - never server.js, package.json, accounts.json or friends.json.
  if (!fs.existsSync(f)) { const base = path.basename(p);
    if (/^(index\.html|models\.json|CREDITS\.txt|[\w.-]+\.(glb|gltf|bin|png|jpg|jpeg|webp))$/i.test(base) && (p === '/index.html' || p.startsWith('/models/'))) f = flatFile(base); }
  // Any page address that isn't a real file (e.g. a link with extra text on the end) opens the game.
  if (!path.extname(p) && !fs.existsSync(f)) { f = path.join(PUBLIC, 'index.html'); if (!fs.existsSync(f)) f = flatFile('index.html'); }
  fs.stat(f, (e, st) => {
    if (e || !st.isFile()) {
      if (p === '/index.html') { res.writeHead(200, {'Content-Type':'text/plain'}); return res.end('Core Conflict server running. Put the game in public/index.html'); }
      res.writeHead(404); return res.end('Not found');
    }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(f).toLowerCase()] || 'application/octet-stream', 'Content-Length': st.size, 'Cache-Control': p.startsWith('/models/') ? 'public, max-age=3600' : 'no-cache' });
    fs.createReadStream(f).pipe(res);
  });
});
const wss = new WebSocketServer({ server });
wss.on('error', () => {});   // port errors are handled on the http server below

let nextId = 1, nextRoom = 1;
const rooms = new Map(); // id -> room (PvP matches)
const hubs = [];          // island servers, each { num, players: Map }

// ── Admins & founders ──
// Add names in Render: Environment → FOUNDERS = yourname   (and ADMINS = name1,name2)
const FOUNDERS = [...new Set(['ZK', 'zy'].concat((process.env.FOUNDERS || '').split(',').map(s => alias(keyOf(s.trim()))).filter(Boolean)))];
const ADMINS = [...new Set(['qwertyyyy', 'fluffymelon22', 'screwdier'].concat((process.env.ADMINS || '').split(',').map(s => alias(keyOf(s.trim()))).filter(Boolean)))];
function roleOf(name) { const n = alias(keyOf(name)); return FOUNDERS.includes(n) ? 'founder' : ADMINS.includes(n) ? 'admin' : null; }
/* admin abuse events: shared by everyone on the islands */
const EVENTS = {};   // kind -> end time (ms)
const EVENT_KINDS = ['abuse','2xexp','3xexp','5xexp','10xexp','2xmoney','5xmoney','10xmoney','2xdamage','5xdamage','speed','hyper','superjump','lowgrav','moongrav','godall','infammo','healing','coinrain','gemrain','tacorain','pizzarain','moneystorm','meteors','snow','rain','thunder','fog','night','bloodmoon','rainbow','aurora','earthquake','disco','fireworks','confetti','bubbles','crabrave','balloons','giantmode','tinymode','spinparty','goldrush','ghosts','slowmo','bouncy','upsidedown'];
function eventsLeft() { const now = Date.now(), out = {}; for (const k in EVENTS) { if (EVENTS[k] === Infinity) out[k] = -1; else if (EVENTS[k] > now) out[k] = EVENTS[k] - now; else delete EVENTS[k]; } return out; }   // -1 = on until an admin turns it off
function hubAll(msg) { const out = JSON.stringify(msg); for (const hb of hubs) for (const q of hb.players.values()) if (q.ws.readyState === 1) q.ws.send(out); }
function hubFor() {
  let h = hubs.find(h => h.players.size < HUB_MAX);
  if (!h) { let num = 1; while (hubs.some(x => x.num === num)) num++; h = { num, players: new Map() }; hubs.push(h); hubs.sort((a,b)=>a.num-b.num); }
  return h;
}
function hubPub(p) { return { id:p.id, name:p.name, role:p.role || roleOf(p.name), x:p.hx, y:p.hy, z:p.hz, yaw:p.hyaw, sk:p.hsk || '' }; }
function hubLeave(p) {
  const h = p.hub; if (!h) return; p.hub = null;
  h.players.delete(p.id);
  for (const q of h.players.values()) send(q.ws, { type:'hubLeft', id:p.id });
  if (h.players.size === 0) hubs.splice(hubs.indexOf(h), 1);
}

function send(ws, m) { if (ws.readyState === 1) ws.send(JSON.stringify(m)); }
function bcast(room, m, except) { for (const p of room.players.values()) if (p !== except) send(p.ws, m); }
function pub(p) { return { id:p.id, name:p.name, role:roleOf(p.name), team:p.team, x:p.x, y:p.y, z:p.z, yaw:p.yaw, hp:p.hp, kills:p.kills, deaths:p.deaths, sk:p.sk || '' }; }
function roster(room) { return [...room.players.values()].map(pub); }

/* ── TRAINING GROUNDS: one giant city, up to 100 players, everyone against everyone, no rounds ── */
const TG_MAX = 100; let nextTgTeam = 2;
function findTgRoom() {
  for (const r of rooms.values()) if (r.tg && r.players.size < TG_MAX) return r;
  const r = { id: nextRoom++, tg: true, teamSize: 50, players: new Map(), state: 'playing', scores: [0,0], timer: null, seed: 7 };
  rooms.set(r.id, r); return r;
}
function findRoom(teamSize) {
  for (const r of rooms.values()) if (r.teamSize === teamSize && r.state !== 'playing' && r.state !== 'ended' && r.players.size < teamSize * 2) return r;
  const r = { id: nextRoom++, teamSize, players: new Map(), state: 'waiting', scores: [0,0], timer: null, seed: 1 + Math.floor(Math.random() * 100000) };
  rooms.set(r.id, r); return r;
}
function pickTeam(room) {
  let a = 0, b = 0; for (const p of room.players.values()) p.team === 0 ? a++ : b++;
  return a <= b ? 0 : 1;
}
function maybeStart(room) {
  if (room.state !== 'waiting') return;
  const n = room.players.size;
  if (n >= room.teamSize * 2) return countdown(room);
  if (n >= 2 && !room.timer) room.timer = setTimeout(() => { room.timer = null; if (room.players.size >= 2) countdown(room); }, FILL_WAIT * 1000);
}
function voteTally(room) { const t = {}; room.vote.opts.forEach(o => { t[o] = 0; }); for (const v of room.vote.votes.values()) if (t[v] !== undefined) t[v]++; return t; }
function startVote(room) {
  clearTimeout(room.timer); room.timer = null; room.state = 'voting';
  const ids = MAP_IDS.slice(); for (let i = ids.length - 1; i > 0; i--) { const j = Math.floor(Math.random() * (i + 1)); [ids[i], ids[j]] = [ids[j], ids[i]]; }
  room.vote = { opts: ids.slice(0, 3), votes: new Map(), ends: Date.now() + VOTE_SECONDS * 1000 };
  bcast(room, { type:'mapVote', options:room.vote.opts, seconds:VOTE_SECONDS, tally:voteTally(room) });
  room.voteTimer = setTimeout(() => finishVote(room), VOTE_SECONDS * 1000);
}
function finishVote(room) {
  if (room.state !== 'voting') return; clearTimeout(room.voteTimer);
  const t = voteTally(room), opts = room.vote.opts, tot = opts.reduce((a, o) => a + t[o], 0); let pick = null;
  if (!tot) pick = opts[Math.floor(Math.random() * opts.length)];
  else { let r = Math.random() * tot; for (const o of opts) { r -= t[o]; if (r < 0) { pick = o; break; } } pick = pick || opts[0]; }
  room.map = pick; bcast(room, { type:'mapChosen', map:pick, tally:t });
  room.state = 'waiting'; setTimeout(() => countdown(room), 3200);      // time for the spinner to land
}
function countdown(room) {
  if (room.state !== 'waiting') return;
  if (!room.map && !room.tg) { if (room.players.size >= 2) startVote(room); return; }
  clearTimeout(room.timer); room.timer = null; room.state = 'countdown';
  let s = COUNTDOWN;
  const tick = () => {
    if (room.players.size < 2) { room.state = 'waiting'; return; }
    if (s > 0) { bcast(room, { type:'countdown', seconds:s }); s--; return setTimeout(tick, 1000); }
    room.state = 'playing';
    bcast(room, { type:'start', seed:room.seed, map:room.map || null, killTarget:KILL_TARGET, scores:room.scores, players:roster(room) });
  };
  tick();
}
function endMatch(room, winner) {
  room.state = 'ended';
  bcast(room, { type:'end', winner, scores:room.scores });
  setTimeout(() => { for (const p of room.players.values()) try { p.ws.close(); } catch(e){} rooms.delete(room.id); }, 1000);
}
function leave(p) {
  const room = p.room; if (!room || !room.players.has(p.id)) return;
  room.players.delete(p.id);
  bcast(room, { type:'left', id:p.id });
  if (room.players.size === 0) { clearTimeout(room.timer); clearTimeout(room.voteTimer); rooms.delete(room.id); return; }
  if (room.state === 'playing' && !room.tg) {
    const teams = [0,0]; for (const q of room.players.values()) teams[q.team]++;
    if (!teams[0]) endMatch(room, 1); else if (!teams[1]) endMatch(room, 0);
  }
}

/* ═══ COMMANDER BATTLES: the battle rules (same file as in the game) ═══ */
/* ═══════════ COMMANDER BATTLES · the battle rules (V101: 250 troops, 7 troop types, upgrades) ═══════════
   One copy of this code runs in the game (battles against the AI commander) and one on the server
   (Commander 1v1 against a real player), so both play by exactly the same rules.

   Every army has 250 troops to split between the troop types, plus 20 officers and 5+5 = 10 commanders,
   and you, the General, at the top. Troops wait in your RESERVE until you draw a line for them.
   Troop types (soldiers, medics and snipers are free; the others are unlocked with coins at Marshal Kane's armory):
     soldier    - riflemen, the main fighters
     medic      - heal hurt troops near them (and a little bit everybody right next to them)
     sniper     - very accurate and long range, but very slow and can't shoot while moving
     scout      - very fast and light, good for running round the side of the enemy
     shield     - carry big shields: hard to hurt from the front and they protect troops right behind them
     mg         - machine gunners: lots of bullets, not very accurate, slow
     grenadier  - throw grenades that hurt every enemy where they land
   Every line you draw is a squad with: AMOUNT, ACTION (charging / not moving / retreating while
   shooting / defending / doing nothing), DIRECTION, and TYPE (you can change the type of a line during the battle).
   Sending a line back to the reserve: its troops retreat for 3 seconds (still shooting) and then join your reserve.
   During the battle you can also retrain troops waiting in the reserve into another type.
   Upgrades (armory): every level gives a type +10% health, +8% damage and +3% accuracy (medics +12% healing).
   You win when the enemy General falls, or when the enemy has no fighting troops left.
   After 7 minutes the army with more strength left wins. */
(function (root) {
  const FIELD = { maxX: 140, maxZ: 100, deployFront: 18, deployBack: 92 };
  const CLASSES = {
    soldier:   { hp: 300, dmg: 10, range: 20, cd: 1.0,  spd: 4.2, acc: .72, value: 1 },
    medic:     { hp: 255, dmg: 4,  range: 12, cd: 1.2,  spd: 4.4, acc: .55, value: 1, heal: 12, healR: 12, healAura: 2 },
    sniper:    { hp: 210, dmg: 30, range: 52, cd: 2.8,  spd: 2.0, acc: .92, value: 1.3 },
    scout:     { hp: 200, dmg: 8,  range: 18, cd: .8,   spd: 6.6, acc: .62, value: 1 },
    shield:    { hp: 560, dmg: 7,  range: 12, cd: 1.0,  spd: 3.4, acc: .60, value: 1.4, front: .45 },
    mg:        { hp: 360, dmg: 5,  range: 28, cd: .28,  spd: 3.0, acc: .48, value: 1.5 },
    grenadier: { hp: 280, dmg: 46, range: 26, cd: 4.5,  spd: 3.6, acc: .70, value: 1.5, splash: 4.5, minR: 5 },
    officer:   { hp: 450, dmg: 12, range: 22, cd: 1.0,  spd: 4.2, acc: .75, value: 2, aura: 10, boost: .15 },
    commander: { hp: 690, dmg: 14, range: 24, cd: 1.0,  spd: 4.0, acc: .78, value: 4, aura: 14, boost: .22 },
    general:   { hp: 1260, dmg: 16, range: 24, cd: 0.9, spd: 3.8, acc: .80, value: 10, aura: 14, boost: .25 },
  };
  const LINE = ['soldier', 'medic', 'sniper', 'scout', 'shield', 'mg', 'grenadier'];   // the troop types you draw lines for
  const FREE = ['soldier', 'medic', 'sniper'];                                         // the rest are unlocked at the armory
  const ORDER = LINE.concat(['officer', 'commander', 'general']);
  const MOVES = ['charge', 'hold', 'retreat'], FIRES = ['shoot', 'defend', 'none'];
  const ARMY = { free: 250, officer: 20, commander: 10 };
  const UPG = { maxLv: 5, hp: .10, dmg: .08, acc: .03, heal: .12 };
  const MAXSQ = 24, DEFEND = .7, GEN_Y = 80, RECALL_T = 3, HEAL_CAP = 12;

  function rng(seed) { let a = seed >>> 0; return function () { a = (a + 0x6D2B79F5) | 0; let t = Math.imul(a ^ (a >>> 15), 1 | a); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; }; }
  const clampN = (v, a, b) => Math.max(a, Math.min(b, v));
  const isLeader = u => u.cls === 'officer' || u.cls === 'commander';
  const isLine = c => LINE.includes(c);

  // your armory: which types are unlocked and the upgrade level of each type
  function cleanArmy(a) {
    const out = { unlock: {}, lv: {} };
    for (const c of LINE) { out.unlock[c] = FREE.includes(c) || !!(a && a.unlock && a.unlock[c]); out.lv[c] = clampN(Math.floor(+(a && a.lv && a.lv[c]) || 0), 0, UPG.maxLv); }
    return out;
  }
  const allowedOf = army => LINE.filter(c => army.unlock[c]);
  // largest-remainder split of k over weights
  function split(k, w) { const tot = w.reduce((a, b) => a + b, 0) || 1, raw = w.map(x => k * x / tot), out = raw.map(Math.floor); let left = k - out.reduce((a, b) => a + b, 0);
    raw.map((x, i) => [x - Math.floor(x), i]).sort((a, b) => b[0] - a[0]).forEach(([, i]) => { if (left > 0) { out[i]++; left--; } }); return out; }
  // the 250 free troops always add up to 250, only using types you have
  function cleanComp(c, allowed) {
    allowed = (allowed && allowed.length ? allowed : FREE).filter(isLine);
    let w = allowed.map(k => Math.max(0, Math.floor(+(c && c[k]) || 0)));
    if (!w.some(x => x > 0)) w = allowed.map(k => k === 'soldier' ? 160 : k === 'medic' || k === 'sniper' ? 45 : 0);
    if (!w.some(x => x > 0)) w = allowed.map(() => 1);
    const n = split(ARMY.free, w), out = {}; LINE.forEach(k => out[k] = 0); allowed.forEach((k, i) => out[k] = n[i]);
    return out;
  }

  /* ── directions: 90 = straight at the enemy, 0 = right, 180 = left, 270 = straight back.
        Local coordinates: x goes across (-140..140), y is how far back from the middle line (your side is y > 0). ── */
  function dirVec(d) { const r = d * Math.PI / 180; return [Math.cos(r), -Math.sin(r)]; }
  function cleanDir(d, mv) {
    d = +d; if (!isFinite(d)) d = mv === 'retreat' ? 270 : 90;
    d = ((d % 360) + 360) % 360; if (d === 0 && mv === 'retreat') d = 360;
    if (mv === 'charge' && d > 180) d = d > 270 ? 0 : 180;
    if (mv === 'retreat' && d < 180) d = d < 90 ? 360 : 180;
    return Math.round(d * 10) / 10;
  }
  function flipFor(d, mv) { if ((mv === 'charge' && d > 180) || (mv === 'retreat' && d < 180)) return 360 - d; return d; }
  function faceVec(q) { const v = dirVec(q.dir); return q.mv === 'retreat' && q.fire !== 'none' ? [-v[0], -v[1]] : v; }

  /* ── ready-made formations (each line becomes a squad). Extra types get sensible places automatically. ── */
  const L = (x1, y1, x2, y2) => [[x1, y1], [x2, y2]];
  const PRESETS = {
    line:   { name: 'Line',        tip: 'Everyone can shoot. Strong all round.',
      strokes: { soldier: [L(-72, 24, 72, 24)], medic: [L(-56, 35, 56, 35)], sniper: [L(-48, 50, 48, 50)] } },
    wedge:  { name: 'Wedge',       tip: 'A point that punches through the middle.',
      strokes: { soldier: [[[-54, 51], [0, 21], [54, 51]]], medic: [L(-19, 50, 19, 50)], sniper: [L(-42, 62, 42, 62)] } },
    turtle: { name: 'Turtle',      tip: 'A box with snipers and medics safe inside.',
      strokes: { soldier: [[[-42, 22], [42, 22], [42, 64], [-42, 64], [-42, 22]]], medic: [L(-19, 48, 19, 48)], sniper: [L(-26, 35, 26, 35)] } },
    pincer: { name: 'Pincer',      tip: 'Two wings that swing in from the sides. Weak if the enemy smashes the middle.',
      strokes: { soldier: [[[-99, 48], [-86, 24], [-67, 19]], [[67, 19], [86, 24], [99, 48]], L(-27, 32, 27, 32)], medic: [L(-80, 40, -64, 40), L(64, 40, 80, 40), L(-10, 48, 10, 48)], sniper: [L(-26, 54, 26, 54)] },
      dirs: { soldier: [62, 118, 90], medic: [62, 118, 90] } },
    wall:   { name: 'Shield wall', tip: 'Two tight rows. Hard to break, but the back row shoots less.',
      strokes: { soldier: [L(-54, 22, 54, 22), L(-54, 26, 54, 26)], medic: [L(-42, 38, 42, 38)], sniper: [L(-48, 51, 48, 51)] } },
    column: { name: 'Spearhead',   tip: 'A narrow column. Fast to charge, but few can shoot at once.',
      strokes: { soldier: [L(-6, 21, -6, 64), L(6, 21, 6, 64)], medic: [L(-16, 38, -16, 64)], sniper: [L(19, 38, 19, 64)] } },
  };
  const lenOf = p => { let l = 0; for (let i = 1; i < p.length; i++) l += Math.hypot(p[i][0] - p[i - 1][0], p[i][1] - p[i - 1][1]); return l; };
  // where the extra troop types stand in a ready-made formation (worked out from where its soldiers stand)
  function extraStrokes(p) {
    const pts = [].concat(...p.strokes.soldier); let x0 = 1e9, x1 = -1e9, y0 = 1e9, y1 = -1e9; pts.forEach(q => { x0 = Math.min(x0, q[0]); x1 = Math.max(x1, q[0]); y0 = Math.min(y0, q[1]); y1 = Math.max(y1, q[1]); });
    const cx = (x0 + x1) / 2, w = Math.max(20, (x1 - x0) / 2), Y = v => clampN(v, FIELD.deployFront, FIELD.deployBack);
    return { shield: [L(cx - w * .7, Y(y0 - 4), cx + w * .7, Y(y0 - 4))], scout: [L(x0 - 26, Y(y0 + 8), x0 - 10, Y(y0 + 8)), L(x1 + 10, Y(y0 + 8), x1 + 26, Y(y0 + 8))],
      mg: [L(cx - w * .35, Y(y0 + 9), cx + w * .35, Y(y0 + 9))], grenadier: [L(cx - w * .45, Y(y0 + 15), cx + w * .45, Y(y0 + 15))] };
  }
  function presetLines(key, comp, mv, fire) {
    const p = PRESETS[key] || PRESETS.line, ex = extraStrokes(p), out = [];
    for (const cls of LINE) {
      const n = (comp && comp[cls]) | 0; if (!n) continue;
      const paths = (p.strokes[cls] && p.strokes[cls].length ? p.strokes[cls] : ex[cls] || PRESETS.line.strokes[cls] || PRESETS.line.strokes.soldier);
      const ns = split(n, paths.map(q => Math.max(6, lenOf(q))));
      paths.forEach((q, i) => { if (ns[i] > 0) out.push({ cls, path: JSON.parse(JSON.stringify(q)), n: ns[i], mv: mv || 'hold', fire: fire || 'shoot', dir: (p.dirs && p.dirs[cls] && p.dirs[cls][i]) || 90 }); });
    }
    return out;
  }
  function cleanPath(p, setup) {
    if (!Array.isArray(p)) return null; let q = [];
    for (const pt of p.slice(0, 300)) {
      if (!Array.isArray(pt)) continue; let x = +pt[0], y = +pt[1]; if (!isFinite(x) || !isFinite(y)) continue;
      x = clampN(x, -FIELD.maxX, FIELD.maxX); y = setup ? clampN(y, FIELD.deployFront, FIELD.deployBack) : clampN(y, -FIELD.maxZ, FIELD.maxZ);
      const l = q[q.length - 1]; if (l && Math.hypot(l[0] - x, l[1] - y) < .4) continue;
      q.push([Math.round(x * 10) / 10, Math.round(y * 10) / 10]);
    }
    if (q.length > 60) { const k = Math.ceil(q.length / 60), last = q[q.length - 1]; q = q.filter((_, i) => i % k === 0); if (q[q.length - 1] !== last) q.push(last); }
    return q.length ? q : null;
  }
  // spread k troops evenly along the drawn lines (extra rows behind when they would be too squashed)
  function along(paths, k) {
    const out = []; if (k <= 0) return out;
    const ps = (paths || []).filter(p => p && p.length); if (!ps.length) return null;
    const tot = ps.reduce((a, p) => a + lenOf(p), 0);
    if (tot < 0.5) { for (let i = 0; i < k; i++) { const p = ps[i % ps.length][0], j = Math.floor(i / ps.length), a = j * 2.4, r = j ? 1.15 * Math.sqrt(j) : 0; out.push([p[0] + Math.cos(a) * r, p[1] + Math.sin(a) * r]); } return out; }
    const rows = Math.max(1, Math.min(8, Math.ceil(1.25 / (tot / k)))), per = Math.ceil(k / rows), step = tot / per;
    for (let r = 0; r < rows && out.length < k; r++) {
      let t = step / 2 + (r % 2) * step / 2;
      for (const p of ps) for (let i = 1; i < p.length; i++) {
        const a = p[i - 1], b = p[i], l = Math.hypot(b[0] - a[0], b[1] - a[1]);
        while (t <= l && out.length < k) { const f = l ? t / l : 0; out.push([a[0] + (b[0] - a[0]) * f, a[1] + (b[1] - a[1]) * f + r * 1.5]); t += step; }
        t -= l;
      }
    }
    while (out.length < k) { const p = ps[ps.length - 1], e = p[p.length - 1]; out.push([e[0] + (out.length % 5) * .8, e[1] + 1.5]); }
    return out;
  }
  const toWorld = (side, x, y) => side ? [-x, -y] : [x, y];
  const toLocal = (side, x, z) => side ? [-x, -z] : [x, z];

  /* ── the battlefield: cover (rocks, sandbags, ruined walls, wrecks, trees) and things to look at.
        The same seed always makes the same battlefield (the server only sends the seed). ── */
  function makeEnv(seed) {
    const rand = rng((seed >>> 0) ^ 0x51ed27), cover = [], props = [];
    const both = (x, y, f) => { for (const s of [0, 1]) { const w = toWorld(s, x, y); f(w[0], w[1], s); } };
    const addC = (x, z, r, kind) => cover.push({ x: Math.round(x * 100) / 100, z: Math.round(z * 100) / 100, r, kind });
    // ruined houses: two or three broken walls
    for (let i = 0; i < 4; i++) { const x = (rand() * 2 - 1) * 105, y = 10 + rand() * 50, rot = Math.floor(rand() * 4) * Math.PI / 2, wv = 7 + rand() * 4, dv = 6 + rand() * 3, walls = rand() < .5 ? 3 : 2;
      both(x, y, (wx, wz, s) => { const r0 = rot + (s ? Math.PI : 0); props.push({ k: 'ruin', x: wx, z: wz, rot: r0, w: wv, d: dv, walls, h: 2.4 + ((i * 7) % 3) * .5 });
        const segs = [[-wv / 2, -dv / 2, wv / 2, -dv / 2], [-wv / 2, -dv / 2, -wv / 2, dv / 2], [wv / 2, -dv / 2, wv / 2, dv / 2]].slice(0, walls);
        for (const [ax, az, bx, bz] of segs) { const L2 = Math.hypot(bx - ax, bz - az), n = Math.max(2, Math.round(L2 / 1.6)); for (let k = 0; k <= n; k++) { if (k === Math.floor(n / 2) && walls === 3) continue; const lx = ax + (bx - ax) * k / n, lz = az + (bz - az) * k / n, c = Math.cos(r0), sn = Math.sin(r0); addC(wx + lx * c + lz * sn, wz - lx * sn + lz * c, .85, 'wall'); } } }); }
    // tank wrecks
    for (let i = 0; i < 3; i++) { const x = (rand() * 2 - 1) * 100, y = 4 + rand() * 30, rot = rand() * Math.PI; both(x, y, (wx, wz, s) => { props.push({ k: 'wreck', x: wx, z: wz, rot: rot + (s ? Math.PI : 0) }); addC(wx, wz, 2.7, 'wreck'); }); }
    // rocks and sandbag walls
    for (let i = 0; i < 12; i++) { const x = (rand() * 2 - 1) * 120, y = 4 + rand() * 60, kind = rand() < .5 ? 'bags' : 'rock', rot = rand() * Math.PI, sz = 1.4 + rand() * 1.4;
      both(x, y, (wx, wz, s) => { const r0 = rot + (s ? Math.PI : 0);
        if (kind === 'rock') { props.push({ k: 'rock', x: wx, z: wz, r: sz, rot: r0 }); addC(wx, wz, sz, 'rock'); }
        else { props.push({ k: 'bags', x: wx, z: wz, rot: r0, n: 4 }); for (let k = -1.5; k <= 1.5; k++) addC(wx + Math.cos(r0) * k * 1.6, wz - Math.sin(r0) * k * 1.6, 1.0, 'bags'); } }); }
    // little groups of trees (they block bullets a bit)
    for (let i = 0; i < 6; i++) { const x = (rand() < .5 ? -1 : 1) * (70 + rand() * 60), y = 6 + rand() * 80, n = 3 + Math.floor(rand() * 4);
      for (let k = 0; k < n; k++) { const tx = x + (rand() - .5) * 14, ty = y + (rand() - .5) * 14, sc = .8 + rand() * .6; both(tx, ty, (wx, wz) => { props.push({ k: 'tree', x: wx, z: wz, s: sc }); addC(wx, wz, .7, 'tree'); }); } }
    // shell craters (just to look at)
    for (let i = 0; i < 26; i++) { const x = (rand() * 2 - 1) * 130, y = (rand() * 2 - 1) * 95; props.push({ k: 'crater', x, z: y, r: 1.4 + rand() * 2.6 }); }
    // barbed wire in front of each side
    for (let i = 0; i < 5; i++) { const x = (rand() * 2 - 1) * 100, y = 14 + rand() * 6; both(x, y, (wx, wz, s) => props.push({ k: 'wire', x: wx, z: wz, rot: s ? Math.PI : 0, len: 10 + ((i * 5) % 7) })); }
    return { cover, props };
  }

  /* o: { seed, comps:[c0,c1], armies:[a0,a1] (unlocks + upgrade levels), lines:[[...],[...]], hpMul:[..] }.
     Before the first step() the battle is in SETUP: lines must be in your starting area and troops appear on them at once. */
  function createBattle(o) {
    o = o || {};
    const seed = (o.seed >>> 0) || 1, rand = rng(seed), env = makeEnv(seed);
    const S = { t: 0, seed, rand, started: false, over: false, winner: -1, reason: '', timeLimit: o.timeLimit || 420, units: [], ev: [], nades: [], cover: env.cover, props: env.props,
      sides: [0, 1].map(s => { const army = cleanArmy(o.armies && o.armies[s]), allowed = allowedOf(army);
        return { army, allowed, comp: cleanComp(o.comps && o.comps[s], allowed), hpMul: (o.hpMul && o.hpMul[s]) || 1, dmgMul: (o.dmgMul && o.dmgMul[s]) || 1, kills: 0, lost: 0, squads: [], nextSq: 1, ver: 1, map: new Map() }; }) };
    for (const s of [0, 1]) {
      const sd = S.sides[s], c = sd.comp, counts = Object.assign({}, c, { officer: ARMY.officer, commander: ARMY.commander, general: 1 });
      for (const cls of ORDER) for (let i = 0; i < (counts[cls] || 0); i++) {
        const w = toWorld(s, 0, FIELD.maxZ + 6), mhp = maxHpOf(sd, cls);
        S.units.push({ id: S.units.length, side: s, cls, hp: mhp, maxHp: mhp, x: w[0], z: w[1], lx: 0, ly: FIELD.maxZ + 6, adv: 0, sq: 0, res: isLine(cls), rec: false, recT: 0, eq: 0,
          cd: rand() * CLASSES[cls].cd, morale: 100, rout: false, dead: false, tgt: -1, retgt: 0, moving: false, fired: false, healing: false, face: s ? 0 : Math.PI, fx: 0, fz: s ? 1 : -1, deadAt: 0 });
      }
      const g = S.units.find(u => u.side === s && u.cls === 'general'); place(g, s, 0, GEN_Y, true);
      spreadLeaders(S, s);
      if (o.lines && o.lines[s]) for (const l of o.lines[s]) command(S, s, Object.assign({}, l, { op: 'add' }));
    }
    return S;
  }
  function modOf(sd, cls) { const lv = isLine(cls) ? sd.army.lv[cls] || 0 : 0; return { hp: (1 + lv * UPG.hp) * sd.hpMul, dmg: (1 + lv * UPG.dmg) * sd.dmgMul, acc: lv * UPG.acc, heal: 1 + lv * UPG.heal }; }
  function maxHpOf(sd, cls) { return Math.round(CLASSES[cls].hp * modOf(sd, cls).hp); }
  function setClass(S, u, cls) { const sd = S.sides[u.side], f = u.maxHp ? u.hp / u.maxHp : 1; u.cls = cls; u.maxHp = maxHpOf(sd, cls); u.hp = Math.max(1, Math.round(f * u.maxHp)); u.cd = CLASSES[cls].cd * S.rand(); }
  function place(u, side, lx, ly, setup) { u.lx = lx; u.ly = ly; if (setup) { const w = toWorld(side, lx, ly); u.x = w[0]; u.z = w[1]; u._px = u.x; u._pz = u.z; } }
  const reserveOf = (S, side, cls) => S.units.filter(u => u.side === side && u.cls === cls && u.res && !u.dead);
  function reserveCount(S, side) {
    const r = {}, back = {}, field = {}; LINE.forEach(k => { r[k] = 0; back[k] = 0; field[k] = 0; });
    for (const u of S.units) if (u.side === side && !u.dead && isLine(u.cls)) { if (u.res) r[u.cls]++; else if (u.rec) back[u.cls]++; else field[u.cls]++; }
    return { res: r, back, field };
  }

  /* ── the orders you give (also used by the server for 1v1) ──
     { op:'add', cls, path, n, mv, fire, dir, k }   draw a new line (k: your own number for it, sent back so you can find it)
     { op:'set', ids:[..], n, mv, fire, dir }        change lines (n only when one line is picked)
     { op:'retype', ids:[..], cls }                  turn lines into another troop type (2 seconds to swap their gear)
     { op:'recall', ids:[..] }                       send lines back to the reserve (they retreat for 3 seconds, still shooting)
     { op:'retrain', from, to, n }                   turn troops waiting in the reserve into another type */
  function command(S, side, o) {
    if (!o || S.over || (side !== 0 && side !== 1)) return null; const sd = S.sides[side], setup = !S.started;
    if (o.op === 'add') {
      const cls = sd.allowed.includes(o.cls) ? o.cls : null; if (!cls || sd.squads.length >= MAXSQ) return null;
      const path = cleanPath(o.path, setup); if (!path) return null;
      const n = Math.max(0, Math.min(reserveOf(S, side, cls).length, Math.round(+o.n) || 0)); if (!n) return null;
      const mv = MOVES.includes(o.mv) ? o.mv : 'hold', fire = FIRES.includes(o.fire) ? o.fire : 'shoot';
      const q = { id: sd.nextSq++, k: (o.k | 0) || 0, cls, path, n, mv, fire, dir: cleanDir(o.dir, mv), adv: 0 };
      sd.squads.push(q); sd.map.set(q.id, q); fill(S, side, q, setup);
      if (setup) spreadLeaders(S, side); else takeLeaders(S, side, q);
      sd.ver++; return q.id;
    }
    if (o.op === 'retrain') {
      const from = o.from, to = o.to; if (!isLine(from) || !sd.allowed.includes(to) || from === to) return null;
      const list = reserveOf(S, side, from).slice(0, Math.max(0, Math.min(ARMY.free, Math.round(+o.n) || 0)));
      list.forEach(u => setClass(S, u, to)); if (list.length) sd.ver++; return list.length;
    }
    const ids = (Array.isArray(o.ids) ? o.ids : [o.id]).slice(0, MAXSQ).map(x => x | 0);
    const qs = ids.map(id => sd.squads.find(q => q.id === id)).filter(Boolean); if (!qs.length) return null;
    if (o.op === 'set') {
      for (const q of qs) {
        if (o.n != null && qs.length === 1 && isFinite(+o.n)) {
          const n = clampN(Math.round(+o.n), 1, q.n + reserveOf(S, side, q.cls).length);
          if (n !== q.n) { bake(S, side, q); q.n = n; fill(S, side, q, setup); }
        }
        const mv = MOVES.includes(o.mv) ? o.mv : q.mv, fire = FIRES.includes(o.fire) ? o.fire : q.fire;
        let dir = o.dir != null && isFinite(+o.dir) ? +o.dir : (mv !== q.mv ? flipFor(q.dir, mv) : q.dir);
        dir = cleanDir(dir, mv);
        if (mv !== q.mv || dir !== q.dir || fire !== q.fire) { bake(S, side, q); q.mv = mv; q.dir = dir; q.fire = fire; }
        layoutLeaders(S, side, q, setup);
      }
      if (setup) spreadLeaders(S, side);
      sd.ver++; return qs.length;
    }
    if (o.op === 'retype') {
      const cls = sd.allowed.includes(o.cls) ? o.cls : null; if (!cls) return null;
      for (const q of qs) { if (q.cls === cls) continue; q.cls = cls;
        for (const u of S.units) if (u.side === side && u.sq === q.id && !u.dead && isLine(u.cls)) { setClass(S, u, cls); u.eq = setup ? 0 : 2; } }
      sd.ver++; return qs.length;
    }
    if (o.op === 'recall') { for (const q of qs) dropSquad(S, side, q, setup); if (setup) spreadLeaders(S, side); sd.ver++; return qs.length; }
    return null;
  }
  function bake(S, side, q) {
    const dv = dirVec(q.dir);
    for (const u of S.units) if (u.side === side && u.sq === q.id && !u.dead) {
      const a = isLeader(u) ? q.adv : u.adv; u.lx = clampN(u.lx + dv[0] * a, -FIELD.maxX, FIELD.maxX); u.ly = clampN(u.ly + dv[1] * a, -FIELD.maxZ, FIELD.maxZ); u.adv = 0;
    }
    if (q.adv) q.path = q.path.map(p => [clampN(p[0] + dv[0] * q.adv, -FIELD.maxX, FIELD.maxX), clampN(p[1] + dv[1] * q.adv, -FIELD.maxZ, FIELD.maxZ)]);
    q.adv = 0;
  }
  function fill(S, side, q, setup) {
    const mine = S.units.filter(u => u.side === side && u.sq === q.id && isLine(u.cls) && !u.dead);
    if (mine.length > q.n) { const far = mine.map(u => [toLocal(side, u.x, u.z)[1], u]).sort((a, b) => b[0] - a[0]).map(a => a[1]); for (const u of far.slice(0, mine.length - q.n)) { sendBack(u, setup); mine.splice(mine.indexOf(u), 1); } }
    const fresh = [];
    if (mine.length < q.n) for (const u of reserveOf(S, side, q.cls).slice(0, q.n - mine.length)) { u.res = false; u.rec = false; u.sq = q.id; u.adv = 0; u.morale = 100; u.rout = false; fresh.push(u); }
    q.n = mine.length + fresh.length;
    let spots = along([q.path], q.n) || [];
    if (setup) spots = spots.map(p => [p[0], clampN(p[1], FIELD.deployFront, FIELD.deployBack)]);
    spots = spots.map(p => [clampN(p[0], -FIELD.maxX, FIELD.maxX), clampN(p[1], -FIELD.maxZ, FIELD.maxZ)]);
    const free = spots.slice();
    const takeNearest = (lx, ly) => { let bi = 0, bd = 1e9; for (let i = 0; i < free.length; i++) { const d = (free[i][0] - lx) ** 2 + (free[i][1] - ly) ** 2; if (d < bd) { bd = d; bi = i; } } return free.splice(bi, 1)[0]; };
    for (const u of mine.sort((a, b) => a.x - b.x)) { const l = toLocal(side, u.x, u.z), p = takeNearest(l[0], l[1]); if (p) place(u, side, p[0], p[1], setup); u.adv = 0; }
    for (const u of fresh) { const p = free.shift(); if (!p) continue; place(u, side, p[0], p[1], setup);
      if (!setup) { const w = toWorld(side, p[0], FIELD.maxZ); u.x = w[0]; u.z = w[1]; u._px = u.x; u._pz = u.z; u.face = side ? 0 : Math.PI; } }   // they run in from the camp at the back
  }
  // back to the reserve: at once while setting up, otherwise a 3 second retreat (still shooting)
  function sendBack(u, setup) { u.sq = 0; u.adv = 0; if (setup) { u.res = true; u.rec = false; u.tgt = -1; } else { u.rec = true; u.recT = RECALL_T; } }
  function dropSquad(S, side, q, setup) {
    for (const u of S.units) if (u.side === side && u.sq === q.id && !u.dead) { if (isLeader(u)) { u.sq = 0; u.adv = 0; } else sendBack(u, setup); }
    const sd = S.sides[side], i = sd.squads.indexOf(q); if (i >= 0) sd.squads.splice(i, 1); sd.map.delete(q.id);
  }
  function spreadLeaders(S, side) {
    const sd = S.sides[side], sqs = sd.squads.filter(q => q.n > 0);
    const offs = S.units.filter(u => u.side === side && u.cls === 'officer' && !u.dead), coms = S.units.filter(u => u.side === side && u.cls === 'commander' && !u.dead);
    for (const u of offs.concat(coms)) { u.sq = 0; u.adv = 0; }
    if (sqs.length) {
      const give = (list, ns) => { let k = 0; ns.forEach((n, i) => { for (let j = 0; j < n && k < list.length; j++) list[k++].sq = sqs[i].id; }); };
      give(offs, split(offs.length, sqs.map(q => q.n)));
      give(coms, split(coms.length, sqs.map(q => q.cls === 'soldier' || q.cls === 'shield' ? q.n : q.n * .5)));
      for (const q of sqs) layoutLeaders(S, side, q, true);
    }
    layoutGuards(S, side, true);
  }
  function takeLeaders(S, side, q) {
    const guard = S.units.filter(u => u.side === side && isLeader(u) && !u.sq && !u.dead && !u.rout);
    let wantO = Math.max(1, Math.round(q.n / 10)), wantC = q.n >= 20 ? 1 : 0;
    for (const u of guard) { if (u.cls === 'officer' && wantO > 0) { u.sq = q.id; wantO--; } else if (u.cls === 'commander' && wantC > 0) { u.sq = q.id; wantC--; } }
    layoutLeaders(S, side, q, false);
  }
  function layoutLeaders(S, side, q, setup) {
    const fv = faceVec(q), shift = (p, k) => p.map(a => [a[0] - fv[0] * k, a[1] - fv[1] * k]);
    const lead = S.units.filter(u => u.side === side && u.sq === q.id && isLeader(u) && !u.dead);
    for (const [cls, k] of [['officer', 2.4], ['commander', 4.8]]) {
      const us = lead.filter(u => u.cls === cls); if (!us.length) continue;
      const spots = along([shift(q.path, k)], us.length) || [];
      us.forEach((u, i) => { const p = spots[i] || q.path[0]; let ly = clampN(p[1], -FIELD.maxZ, FIELD.maxZ); if (setup) ly = clampN(ly, FIELD.deployFront, FIELD.deployBack + 2); place(u, side, clampN(p[0], -FIELD.maxX, FIELD.maxX), ly, setup); u.adv = 0; });
    }
  }
  function guardOffset(i, n) { const row = Math.floor(i / 10), k = i % 10, m = Math.min(10, n - row * 10), R = 4 + row * 2.4, a = Math.PI * (k + .5) / Math.max(1, m); return [-Math.cos(a) * R, -Math.sin(a) * R * .75]; }
  function layoutGuards(S, side, setup) {
    const g = S.units.find(u => u.side === side && u.cls === 'general'), gl = S.units.filter(u => u.side === side && isLeader(u) && !u.sq && !u.dead);
    gl.forEach((u, i) => { const o = guardOffset(i, gl.length); place(u, side, g.lx + o[0], g.ly + o[1], setup); });
  }

  function step(S, dt) {
    if (S.over) return; dt = dt || 0.1; S.started = true; S.t += dt; const ev = S.ev = [];
    const U = S.units, alive = U.filter(u => !u.dead && !u.res);
    const G = new Map(), cell = 6, key = (x, z) => ((Math.floor(x / cell) + 128) << 9) | (Math.floor(z / cell) + 128);
    for (const u of alive) { const k = key(u.x, u.z); let a = G.get(k); if (!a) G.set(k, a = []); a.push(u); }
    const near = (x, z, r, fn) => { const c0 = Math.floor((x - r) / cell), c1 = Math.floor((x + r) / cell), d0 = Math.floor((z - r) / cell), d1 = Math.floor((z + r) / cell);
      for (let cx = c0; cx <= c1; cx++) for (let cz = d0; cz <= d1; cz++) { const a = G.get(((cx + 128) << 9) | (cz + 128)); if (a) for (const v of a) if ((v.x - x) ** 2 + (v.z - z) ** 2 <= r * r) fn(v); } };
    if (!S._cg) { S._cg = new Map(); for (const c of S.cover) { const k = key(c.x, c.z); let a = S._cg.get(k); if (!a) S._cg.set(k, a = []); a.push(c); } }
    const coverNear = (x, z, fn) => { const cx = Math.floor(x / cell), cz = Math.floor(z / cell); for (let i = cx - 1; i <= cx + 1; i++) for (let j = cz - 1; j <= cz + 1; j++) { const a = S._cg.get(((i + 128) << 9) | (j + 128)); if (a) for (const c of a) fn(c); } };
    S._coverNear = coverNear;
    const enemyWithin = (u, r) => { let f = false; near(u.x, u.z, r, v => { if (!f && v.side !== u.side && !v.dead) f = true; }); return f; };

    // grenades that land now
    S.nades = S.nades.filter(n => {
      if (n.t > S.t) return true; const C = CLASSES.grenadier, src = { side: n.side, boost: 0 }; ev.push(['boom', Math.round(n.x * 10) / 10, Math.round(n.z * 10) / 10]);
      near(n.x, n.z, C.splash, v => { if (v.side === n.side || v.dead) return; const d = Math.hypot(v.x - n.x, v.z - n.z), dx = v.x - n.x || .01, dz = v.z - n.z;
        hurt(S, src, v, n.dmg * (1 - .7 * d / C.splash) * (defending(S, v) ? DEFEND : 1), dx, dz, Math.max(.5, d), near); v.morale -= 6; });
      return false; });

    // lines: how many troops are left on each one and how far it has got. Empty lines disappear.
    for (const s of [0, 1]) { const sd = S.sides[s]; sd.map = new Map(); for (const q of sd.squads) { q._n = 0; q._a = 0; sd.map.set(q.id, q); } }
    for (const u of alive) if (u.sq && !isLeader(u)) { const q = S.sides[u.side].map.get(u.sq); if (q) { q._n++; q._a += u.adv; } }
    for (const s of [0, 1]) { const sd = S.sides[s];
      for (const q of sd.squads.slice()) { if (!q._n) { dropSquad(S, s, q, false); sd.ver++; ev.push(['sqgone', s, q.id]); continue; } q.n = q._n; q.adv = q._a / q._n; } }
    const gen = [0, 1].map(s => U.find(u => u.side === s && u.cls === 'general'));
    for (const s of [0, 1]) { const gl = alive.filter(u => u.side === s && isLeader(u) && !u.sq); gl.forEach((u, i) => { u._gi = i; u._gn = gl.length; }); }

    // leaders: who is near an officer / commander / the General
    for (const u of alive) { u.boost = 0; u.led = false; u._hc = HEAL_CAP * dt; }      // nobody can be healed faster than HEAL_CAP per second
    for (const l of alive) { const C = CLASSES[l.cls]; if (!C.aura || l.rout) continue; near(l.x, l.z, C.aura, v => { if (v.side === l.side) { if (C.boost > v.boost) v.boost = C.boost; v.led = true; } }); }

    for (const u of alive) {
      if (u.dead || u.res) continue;
      const C = CLASSES[u.cls], sd = S.sides[u.side], md = modOf(sd, u.cls), q = u.sq ? sd.map.get(u.sq) : null, lead = isLeader(u);
      const fire = q ? q.fire : 'shoot';                 // (retreating troops keep shooting)
      u.fired = false; u.healing = false; if (u.eq > 0) u.eq -= dt;
      let allies = 0, foes = 0; near(u.x, u.z, 12, v => { if (v === u) return; if (v.side === u.side) allies++; else foes++; });
      if (foes > allies * 1.6 + 1) u.morale -= 6 * dt;
      u.morale += (u.led ? 5 : 1) * dt;
      if (u.rout) { let calm = true; near(u.x, u.z, 18, v => { if (v.side !== u.side) calm = false; }); if (calm) u.morale += 6 * dt; if (u.morale > 45) u.rout = false; }
      else if (u.morale < 12 && u.cls !== 'general' && !u.rec) { u.rout = true; ev.push(['rout', u.id]); }
      u.morale = Math.max(0, Math.min(100, u.morale));
      const fl = u.rout ? [0, 1] : q ? faceVec(q) : [0, -1], fw = toWorld(u.side, fl[0], fl[1]); u.fx = fw[0]; u.fz = fw[1];

      // pick a target (nearest enemy in range; snipers prefer leaders)
      u.retgt -= dt;
      let T = u.tgt >= 0 ? U[u.tgt] : null;
      if (fire !== 'shoot') { T = null; u.tgt = -1; }
      else if (!T || T.dead || T.res || u.retgt <= 0 || (T.x - u.x) ** 2 + (T.z - u.z) ** 2 > C.range * C.range) {
        u.retgt = .4 + S.rand() * .3; let best = null, bd = 1e9, bestL = null, bdL = 1e9;
        near(u.x, u.z, C.range, v => { if (v.side === u.side || v.dead) return; const d = (v.x - u.x) ** 2 + (v.z - u.z) ** 2; if (d < bd) { bd = d; best = v; } if ((v.cls === 'officer' || v.cls === 'commander' || v.cls === 'general') && d < bdL) { bdL = d; bestL = v; } });
        T = (u.cls === 'sniper' && bestL) ? bestL : best; u.tgt = T ? T.id : -1;
      }

      // where to go
      let gx = u.x, gz = u.z, spdMul = 1;
      if (u.rout) { gx = u.x; gz = u.side ? -FIELD.maxZ : FIELD.maxZ; }
      else if (u.rec) {                                // retreating to the reserve: 3 seconds, then they are back in the reserve
        u.recT -= dt;
        if (u.recT <= 0) { u.res = true; u.rec = false; u.morale = 100; u.tgt = -1; u.moving = false; u.hp = u.maxHp; const w = toWorld(u.side, 0, FIELD.maxZ + 6); u.x = w[0]; u.z = w[1]; ev.push(['home', u.id]); continue; }
        const l = toLocal(u.side, u.x, u.z), w = toWorld(u.side, l[0], Math.min(FIELD.maxZ, l[1] + 20)); gx = w[0]; gz = w[1];
      }
      else if (u.cls === 'general') {
        const w = toWorld(u.side, u.lx, u.ly); gx = w[0]; gz = w[1];
        let nx = 0, nz = 0, k = 0; near(u.x, u.z, 27, v => { if (v.side !== u.side && !v.dead) { const d = Math.hypot(u.x - v.x, u.z - v.z) || 1; nx += (u.x - v.x) / d; nz += (u.z - v.z) / d; k++; } });
        if (k) { const l = Math.hypot(nx, nz) || 1; gx = u.x + nx / l * 6; gz = u.z + nz / l * 6 - fwdZ(u.side) * 2; }
      }
      else if (!q) { const g = gen[u.side], o = guardOffset(u._gi || 0, u._gn || 1), w = toWorld(u.side, o[0], o[1]); gx = g.x + w[0]; gz = g.z + w[1]; }
      else {
        const dv = dirVec(q.dir);
        spdMul = q.fire === 'none' ? 1.3 : q.fire === 'defend' ? .85 : 1; if (q.mv === 'retreat' && q.fire !== 'none') spdMul *= .75;
        let adv = lead ? q.adv : u.adv;
        if (!lead && q.mv !== 'hold') {
          const cx = u.lx + dv[0] * u.adv, cy = u.ly + dv[1] * u.adv, cw = toWorld(u.side, clampN(cx, -FIELD.maxX, FIELD.maxX), clampN(cy, -FIELD.maxZ, FIELD.maxZ));
          let stop = (cw[0] - u.x) ** 2 + (cw[1] - u.z) ** 2 > 6.25 || Math.abs(cx + dv[0]) > FIELD.maxX || Math.abs(cy + dv[1]) > FIELD.maxZ;
          if (!stop && q.mv === 'charge') {
            if (u.cls === 'medic') stop = enemyWithin(u, 22);
            else if (q.fire === 'shoot') stop = !!(T && (T.x - u.x) ** 2 + (T.z - u.z) ** 2 <= (C.range * .85) ** 2);
            else stop = enemyWithin(u, 2.4);
          }
          if (!stop) u.adv = Math.min(u.adv + C.spd * spdMul * dt, 300);
          adv = u.adv;
        }
        const w = toWorld(u.side, clampN(u.lx + dv[0] * adv, -FIELD.maxX, FIELD.maxX), clampN(u.ly + dv[1] * adv, -FIELD.maxZ, FIELD.maxZ)); gx = w[0]; gz = w[1];
        if (q.mv === 'charge' && q.fire === 'defend' && u.cls !== 'medic' && u.cls !== 'sniper' && !u.rout) {
          let M = null, md2 = 144; near(u.x, u.z, 12, v => { if (v.side !== u.side && !v.dead) { const d = (v.x - u.x) ** 2 + (v.z - u.z) ** 2; if (d < md2) { md2 = d; M = v; } } });
          if (M) { if (md2 > 1.8 * 1.8) { gx = M.x; gz = M.z; } else { gx = u.x; gz = u.z; } }
        }
        if (u.cls === 'medic' && !u.rout) {
          let best = null, bm = 0; near(u.x, u.z, 16, v => { if (v.side === u.side && v !== u && !v.dead) { const m = v.maxHp - v.hp; if (m > bm + 5) { bm = m; best = v; } } });
          if (best && Math.hypot(best.x - u.x, best.z - u.z) > C.healR * .7 && Math.hypot(best.x - gx, best.z - gz) < 10) { gx = best.x - fwdZ(u.side) * 2; gz = best.z - fwdZ(u.side) * 2; }
        }
      }
      const dx = gx - u.x, dz = gz - u.z, dist = Math.hypot(dx, dz);
      const spd = C.spd * spdMul * (u.rout ? 1.15 : 1) * (u.morale < 30 ? .85 : 1);
      u.moving = dist > .6;
      if (u.moving) { const m = Math.min(dist, spd * dt); u.x += dx / dist * m; u.z += dz / dist * m; }

      // heal, shoot, throw or fight up close
      u.cd -= dt;
      if (u.cls === 'medic' && !u.rout && !u.rec) {
        const give = (v, a) => { a = Math.min(a, v._hc || 0, v.maxHp - v.hp); if (a > 0) { v.hp += a; v._hc -= a; } return a; };
        near(u.x, u.z, 5, v => { if (v.side === u.side && !v.dead && v !== u) give(v, C.healAura * md.heal * dt); });   // everybody right next to a medic heals a little
        let best = null, bm = 0; near(u.x, u.z, C.healR, v => { if (v.side === u.side && !v.dead && v !== u && (v._hc || 0) > .01) { const m = v.maxHp - v.hp; if (m > bm) { bm = m; best = v; } } });
        if (best && bm > 1) { give(best, C.heal * md.heal * dt); u.healing = true; u.face = Math.atan2(best.x - u.x, best.z - u.z); if (S.rand() < .25) ev.push(['heal', u.id, best.id]); continue; }
      }
      if (u.rout || fire === 'none' || u.cd > 0 || u.eq > 0) continue;
      if (fire === 'defend') {
        if (u.cls === 'medic' || u.cls === 'sniper' || u.cls === 'grenadier') continue;
        let M = null, mdd = 2.3 * 2.3; near(u.x, u.z, 2.3, v => { if (v.side !== u.side && !v.dead) { const d = (v.x - u.x) ** 2 + (v.z - u.z) ** 2; if (d < mdd) { mdd = d; M = v; } } });
        if (!M) continue;
        u.cd = (.9 + S.rand() * .2); const mx = M.x - u.x, mz = M.z - u.z, d = Math.hypot(mx, mz) || .01; u.face = Math.atan2(mx, mz);
        const hit = S.rand() < .6 * (defending(S, M) ? DEFEND : 1); ev.push(['melee', u.id, M.id, hit ? 1 : 0]);
        if (hit) hurt(S, u, M, (u.cls === 'shield' ? 14 : 10) * (1 + u.boost) * md.dmg, mx, mz, d, near);
        continue;
      }
      if (!T) continue;
      if (u.cls === 'sniper' && u.moving) continue;     // snipers must stand still to shoot
      const tx = T.x - u.x, tz = T.z - u.z, d = Math.hypot(tx, tz) || .01;
      if (u.cls === 'grenadier') {                      // throw a grenade at the thickest bunch of enemies near the target
        if (d < C.minR) continue;
        let ax = 0, az = 0, n = 0; near(T.x, T.z, 4, v => { if (v.side !== u.side && !v.dead) { ax += v.x; az += v.z; n++; } }); ax /= n; az /= n;
        const miss = (1 - Math.min(.95, C.acc + md.acc)) * 5 * (u.moving ? 1.6 : 1) * S.rand(), ma = S.rand() * Math.PI * 2; ax += Math.cos(ma) * miss; az += Math.sin(ma) * miss;
        u.cd = C.cd * (.9 + S.rand() * .2); u.face = Math.atan2(tx, tz); u.fired = true;
        S.nades.push({ x: ax, z: az, t: S.t + .5 + d / 40, side: u.side, dmg: C.dmg * (1 + u.boost) * md.dmg }); ev.push(['nade', u.id, Math.round(ax * 10) / 10, Math.round(az * 10) / 10, Math.round((.5 + d / 40) * 100) / 100]);
        continue;
      }
      u.cd = C.cd * (.9 + S.rand() * .2);
      u.face = Math.atan2(tx, tz);
      let acc = Math.min(.98, C.acc + md.acc) * (1 - d / C.range * .25) * (u.moving || u.rec ? (u.cls === 'mg' ? .4 : .7) : 1) * (u.morale < 40 ? .8 : 1);
      if (u.cls === 'sniper' && d < 10) acc *= .5;
      if (defending(S, T)) acc *= DEFEND;
      if (shielded(T, u, near)) acc *= .6;               // a shield trooper right in front of the target
      if (u.cls !== 'sniper') {
        let blocked = false; near(u.x, u.z, Math.min(d, 14), v => { if (blocked || v === u || v.side !== u.side) return; const px = v.x - u.x, pz = v.z - u.z, al = (px * tx + pz * tz) / d; if (al < 1.4 || al > d - 1) return; const perp = Math.abs(px * tz - pz * tx) / d; if (perp < .8) blocked = true; });
        if (blocked) acc *= .35;
      }
      const hit = S.rand() < acc;
      u.fired = true; ev.push(['shot', u.id, T.id, hit ? 1 : 0]);
      if (!hit) continue;
      let dmg = C.dmg * (1 + u.boost) * md.dmg;
      if (u.cls === 'sniper' && (T.cls === 'officer' || T.cls === 'commander' || T.cls === 'general')) dmg *= 1.3;
      hurt(S, u, T, dmg, tx, tz, d, near);
    }

    for (const u of alive) {
      if (u.dead || u.res) continue;
      near(u.x, u.z, 1.0, v => { if (v === u || v.dead || v.res) return; let px = u.x - v.x, pz = u.z - v.z, d = Math.hypot(px, pz); if (d < .001) { px = (u.id % 7) - 3; pz = 1; d = Math.hypot(px, pz); } const push = (1.0 - d) * .5; u.x += px / d * push; u.z += pz / d * push; });
      coverNear(u.x, u.z, c => { const px = u.x - c.x, pz = u.z - c.z, d = Math.hypot(px, pz); if (d < c.r + .5) { const k = (c.r + .5) / (d || 1); u.x = c.x + px * k; u.z = c.z + pz * k; } });
      u.x = Math.max(-FIELD.maxX, Math.min(FIELD.maxX, u.x)); u.z = Math.max(-FIELD.maxZ, Math.min(FIELD.maxZ, u.z));
      if (u.moving && !u.fired && !u.healing) u.face = Math.atan2(u.x - (u._px != null ? u._px : u.x), u.z - (u._pz != null ? u._pz : u.z)) || u.face;
      u._px = u.x; u._pz = u.z;
    }

    const fighting = [0, 1].map(s => U.filter(u => u.side === s && !u.dead && !u.rout && u.cls !== 'general').length);
    if (gen[0].dead || gen[1].dead) end(S, gen[0].dead && gen[1].dead ? -1 : gen[0].dead ? 1 : 0, 'general');
    else if (!fighting[0] || !fighting[1]) end(S, !fighting[0] && !fighting[1] ? -1 : !fighting[0] ? 1 : 0, 'army');
    else if (S.t >= S.timeLimit) { const sc = strength(S); end(S, Math.abs(sc[0] - sc[1]) < 1 ? -1 : sc[0] > sc[1] ? 0 : 1, 'time'); }
  }
  const fwdZ = side => side ? 1 : -1;
  function defending(S, T) { if (!T.sq || T.rout || T.rec) return false; const q = S.sides[T.side].map.get(T.sq); return !!(q && q.fire === 'defend'); }
  function shielded(T, shooter, near) {
    if (T.cls === 'shield') return false; let yes = false; const sx = shooter.x - T.x, sz = shooter.z - T.z, sl = Math.hypot(sx, sz) || 1;
    near(T.x, T.z, 3, v => { if (yes || v === T || v.side !== T.side || v.cls !== 'shield' || v.dead || v.rout) return; const px = v.x - T.x, pz = v.z - T.z; if ((px * sx + pz * sz) / sl > .6 && Math.abs(px * sz - pz * sx) / sl < 1.6) yes = true; });
    return yes;
  }
  function hurt(S, u, T, dmg, tx, tz, d, near) {
    if (T.cls === 'general') { let guards = 0; near(T.x, T.z, 6, v => { if (v.side === T.side && v !== T && !v.dead && !v.rout) guards++; }); if (guards >= 3) dmg *= .5; }
    const fl = Math.hypot(T.fx, T.fz) || 1, cos = ((-tx) * T.fx + (-tz) * T.fz) / (d * fl);
    dmg *= cos > .35 ? (T.cls === 'shield' ? CLASSES.shield.front : 1) : cos < -.35 ? 1.75 : 1.35;
    let cov = 1; (S._coverNear || ((x, z, fn) => S.cover.forEach(fn)))(T.x, T.z, c => { if (cov < 1) return;
      const cx = c.x - T.x, cz = c.z - T.z, cd2 = Math.hypot(cx, cz); if (cd2 > c.r + 1.6) return;
      if ((cx * -tx + cz * -tz) / (cd2 * d || 1) > .35) cov = c.kind === 'tree' ? .7 : .45; });
    dmg *= cov;
    T.hp -= dmg; T.morale -= dmg * .12;
    if (T.hp <= 0 && !T.dead) {
      T.dead = true; T.hp = 0; T.deadAt = S.t; T.rec = false; S.sides[u.side].kills++; S.sides[T.side].lost++; S.ev.push(['die', T.id]);
      const hit = T.cls === 'commander' ? [25, 22] : T.cls === 'officer' ? [14, 12] : T.cls === 'general' ? [40, 35] : [10, 8];
      near(T.x, T.z, hit[0], v => { if (v.side === T.side && !v.dead) v.morale -= hit[1]; });
    }
  }
  function end(S, w, why) { S.over = true; S.winner = w; S.reason = why; S.ev.push(['end', w, why]); }
  function strength(S) { const sc = [0, 0]; for (const u of S.units) if (!u.dead) sc[u.side] += CLASSES[u.cls].value * 10 * (u.hp / u.maxHp) * (u.rout ? .5 : 1); return sc; }

  /* ── the AI commander ── */
  const AI_LEVELS = [
    { name: 'Recruit',  hpMul: .85, think: 14, smart: 0, lv: 0, types: FREE },
    { name: 'Veteran',  hpMul: 1.0, think: 10, smart: 1, lv: 1, types: FREE.concat(['scout', 'shield']) },
    { name: 'Elite',    hpMul: 1.05, think: 7, smart: 2, lv: 2, types: FREE.concat(['scout', 'shield', 'mg']) },
    { name: 'Warlord',  hpMul: 1.1, think: 5,  smart: 3, lv: 4, types: LINE },
  ];
  function aiArmy(level, rand) {
    const L2 = AI_LEVELS[level] || AI_LEVELS[0], army = { unlock: {}, lv: {} };
    L2.types.forEach(t => { army.unlock[t] = true; army.lv[t] = L2.lv; });
    const base = { soldier: 40, medic: 12, sniper: 11, scout: 8, shield: 10, mg: 10, grenadier: 9 }, c = {};
    L2.types.forEach(t => c[t] = base[t] * (.7 + rand() * .6));
    const comp = cleanComp(c, L2.types);
    const forms = L2.smart ? ['line', 'wedge', 'wall', 'turtle', 'pincer'] : ['line', 'column', 'wedge', 'turtle'], form = forms[Math.floor(rand() * forms.length)];
    return { comp, form, army, hpMul: L2.hpMul, lines: presetLines(form, comp) };
  }
  function centre(S, side, q) { let x = 0, y = 0, n = 0; for (const u of S.units) if (u.side === side && u.sq === q.id && !u.dead && !isLeader(u)) { const l = toLocal(side, u.x, u.z); x += l[0]; y += l[1]; n++; } return n ? [x / n, y / n] : null; }
  function aimFull(S, side, q) {
    const c = centre(S, side, q); if (!c) return null; let best = null, bd = 1e9;
    for (const v of S.units) if (v.side !== side && !v.dead && !v.res) { const l = toLocal(side, v.x, v.z), d = (l[0] - c[0]) ** 2 + (l[1] - c[1]) ** 2; if (d < bd) { bd = d; best = l; } }
    if (!best) return null; let a = Math.atan2(-(best[1] - c[1]), best[0] - c[0]) * 180 / Math.PI; if (a < 0) a += 360;
    return { ang: Math.round(a), dist: Math.sqrt(bd) };
  }
  function aiThink(S, side, level, mem) {
    const L2 = AI_LEVELS[level] || AI_LEVELS[0]; mem = mem || {};
    if (S.over || S.t < (mem.next || 2)) return mem;
    mem.next = S.t + L2.think * (.8 + S.rand() * .4);
    const sd = S.sides[side], sc = strength(S), ratio = sc[side] / Math.max(1, sc[1 - side]);
    const of = (...c) => sd.squads.filter(q => c.includes(q.cls));
    const front = of('soldier', 'shield'), scouts = of('scout'), med = of('medic'), back = of('sniper', 'mg'), nades = of('grenadier');
    const set = (qs, mv, fire, dir) => { if (qs.length) command(S, side, { op: 'set', ids: qs.map(q => q.id), mv, fire, dir }); };
    const goAt = (q, fire, onlyFront) => { const a = aimFull(S, side, q); if (!a) return; const fr = a.ang <= 180;
      if (onlyFront && !fr) { if (q.mv !== 'hold') command(S, side, { op: 'set', ids: [q.id], mv: 'hold', fire }); return; }
      const mv = fr ? 'charge' : 'retreat'; if (q.mv !== mv || q.fire !== fire || Math.abs(a.ang - q.dir) > 12) command(S, side, { op: 'set', ids: [q.id], mv, fire, dir: a.ang }); };
    if (!mem.mode) {
      const go = L2.smart < 2 && S.rand() < .5; mem.mode = go ? 'attack' : 'wait';
      for (const q of front.concat(med, nades)) command(S, side, { op: 'set', ids: [q.id], mv: go ? 'charge' : 'hold', fire: 'shoot', dir: q.dir });
      set(back, 'hold', 'shoot'); set(scouts, 'hold', 'shoot');
      return mem;
    }
    const frontLeft = S.units.filter(u => u.side === side && (u.cls === 'soldier' || u.cls === 'shield' || u.cls === 'scout') && !u.dead).length;
    if (mem.mode === 'pull') { if (S.t >= mem.until) { mem.mode = 'regroup'; mem.until = S.t + 10; set(front, 'hold', 'shoot', 90); set(med.concat(nades), 'hold', 'shoot', 90); } return mem; }
    if (mem.mode === 'regroup' && S.t >= mem.until) mem.mode = 'attack';
    if (mem.mode === 'wait' && S.t > (L2.smart >= 2 ? 18 : 25)) mem.mode = 'attack';
    if (L2.smart && ratio < .8 && !mem.pulled && S.t > 30 && frontLeft >= 12) { mem.pulled = true; mem.mode = 'pull'; mem.until = S.t + 6; set(front, 'retreat', 'shoot', 270); set(med.concat(nades), 'retreat', 'none', 270); return mem; }
    if (ratio > 1.3 && mem.mode === 'attack' && S.t > (mem.rushAt || 0)) { mem.mode = 'rush'; mem.until = S.t + 12; mem.rushAt = S.t + 45; }
    if (mem.mode === 'rush' && (S.t >= mem.until || ratio < 1.1)) mem.mode = 'attack';
    if (mem.mode === 'attack' || mem.mode === 'rush') {
      for (const q of front) goAt(q, mem.mode === 'rush' ? 'defend' : 'shoot');
      for (const q of scouts) goAt(q, 'shoot');
      for (const q of med) goAt(q, 'shoot', true);
      for (const q of nades) goAt(q, 'shoot', true);
    }
    for (const q of back) { const a = aimFull(S, side, q); if (!a) continue; const R = CLASSES[q.cls].range * .85;
      if (frontLeft < 12 || (a.dist > R && S.t > 30)) goAt(q, 'shoot'); else if (q.mv !== 'hold') command(S, side, { op: 'set', ids: [q.id], mv: 'hold', fire: 'shoot' }); }
    if (frontLeft < 12) for (const q of med.concat(nades)) goAt(q, 'shoot');
    // the cleverest commanders retrain what is left in their reserve and send it out
    if (L2.smart >= 2) { const r = reserveCount(S, side).res, tot = LINE.reduce((a, k) => a + r[k], 0);
      if (tot >= 8) for (const k of LINE) if (r[k] >= 8 && sd.allowed.includes(k)) { command(S, side, { op: 'add', cls: k, path: [[-20, 40], [20, 40]], n: r[k], mv: 'charge', fire: 'shoot', dir: 90 }); } }
    return mem;
  }

  /* ── small messages for 1v1 ── */
  function roster(S) { return S.units.map(u => [u.side, ORDER.indexOf(u.cls), u.maxHp]); }
  function snapshot(S, ev) {
    const u = []; for (const v of S.units) u.push(Math.round(v.x * 10), Math.round(v.z * 10), Math.ceil(v.hp / v.maxHp * 100), (v.dead ? 1 : 0) | (v.rout ? 2 : 0) | (v.moving ? 4 : 0) | (v.fired ? 8 : 0) | (v.healing ? 16 : 0) | (v.res ? 32 : 0) | (v.rec ? 64 : 0), Math.round(((v.face % 6.2832) + 6.2832) % 6.2832 * 40), ORDER.indexOf(v.cls));
    return { t: Math.round(S.t * 10) / 10, u, ev: (ev || S.ev).filter(e => e[0] !== 'heal' || Math.random() < .5), k: S.sides.map(s => s.kills), over: S.over, w: S.winner, why: S.reason };
  }
  function squadInfo(S, side, withPaths) {
    const sd = S.sides[side], r = reserveCount(S, side);
    const o = { v: sd.ver, q: sd.squads.map(q => [q.id, q.k || 0, LINE.indexOf(q.cls), q.n, MOVES.indexOf(q.mv), FIRES.indexOf(q.fire), q.dir, Math.round(q.adv * 10) / 10]), r: r.res, b: r.back, a: sd.allowed };
    if (withPaths) { o.p = {}; for (const q of sd.squads) o.p[q.id] = q.path; }
    return o;
  }

  root.CMDSIM = { FIELD, CLASSES, ORDER, LINE, FREE, MOVES, FIRES, ARMY, UPG, PRESETS, AI_LEVELS, MAXSQ, RECALL_T, rng, cleanComp, cleanArmy, allowedOf, presetLines, cleanPath, cleanDir, flipFor, dirVec, faceVec, along, toWorld, toLocal,
    makeEnv, createBattle, command, reserveCount, step, strength, aiArmy, aiThink, roster, snapshot, squadInfo, modOf };
})(typeof window !== 'undefined' ? window : global);


/* ═══ COMMANDER 1v1 (V101): two players each command 250 troops (their own unlocked troop types and upgrades,
   from their saved account). The server runs the battle 10 times a second and sends both players what happens
   5 times a second; players send orders (new lines, changes, new troop types, retraining, back to the reserve). ═══ */
const CMD = { queue: [], rooms: new Map(), next: 1 };
function cmdArmyOf(name) { const a = accounts[name]; return global.CMDSIM.cleanArmy(a && a.save && a.save.cmdArmy); }
function cmdSend(p, m) { if (p && p.ws && p.ws.readyState === 1) send(p.ws, m); }
function cmdLeaveQueue(p) { const i = CMD.queue.indexOf(p); if (i >= 0) CMD.queue.splice(i, 1); }
function cmdEnd(room, winner, why) {
  if (room.over) return; room.over = true; clearInterval(room.timer); clearTimeout(room.setupTimer);
  const k = room.S ? room.S.sides.map(s => s.kills) : [0, 0];
  room.players.forEach(q => { cmdSend(q, { type: 'cmdEnd', winner, why, kills: k }); if (q.cmdRoom === room) q.cmdRoom = null; });
  CMD.rooms.delete(room.id);
  console.log('  [commander] ' + room.names.join(' vs ') + ' -> ' + (winner < 0 ? 'draw' : room.names[winner] + ' wins') + ' (' + why + ')');
}
function cmdStart(room) {
  if (room.S || room.over) return; clearTimeout(room.setupTimer); const C = global.CMDSIM;
  const S = room.S = C.createBattle({ seed: room.seed, comps: room.comps, armies: room.armies });
  for (const i of [0, 1]) {            // put each player's lines on the field (nothing drawn: a plain Line)
    let added = 0; for (const l of (room.lines[i] || []).slice(0, C.MAXSQ)) if (l && C.command(S, i, Object.assign({}, l, { op: 'add' }))) added++;
    if (!added) for (const l of C.presetLines('line', S.sides[i].comp)) C.command(S, i, Object.assign({}, l, { op: 'add' }));
  }
  const roster = C.roster(S); room.sentVer = [0, 0]; room.tick = 0;
  room.players.forEach((q, i) => { room.sentVer[i] = S.sides[i].ver; cmdSend(q, { type: 'cmdStart', roster, seed: room.seed, timeLimit: S.timeLimit, sq: C.squadInfo(S, i, true) }); });
  let evBuf = [];
  room.timer = setInterval(() => {
    try { C.step(S, .1); } catch (e) { console.log('  [commander] error', e.message); return cmdEnd(room, -1, 'time'); }
    room.tick++; for (const e of S.ev) evBuf.push(e);
    if (room.tick % 2 && !S.over) return;                       // 5 messages a second (the game smooths the movement in between)
    const snap = C.snapshot(S, evBuf); evBuf = [];
    room.players.forEach((q, i) => {
      if (q.ws.readyState !== 1) return; const msg = { type: 'cmdSnap', s: snap }, ch = S.sides[i].ver !== room.sentVer[i];
      if (ch || room.tick % 6 === 0) { msg.sq = C.squadInfo(S, i, ch); room.sentVer[i] = S.sides[i].ver; }      // your own lines only (paths when they changed)
      q.ws.send(JSON.stringify(msg));
    });
    if (S.over) cmdEnd(room, S.winner, S.reason);
  }, 100);
}

wss.on('connection', ws => {
  const p = { id: 'p' + (nextId++), ws, name:'player', team:0, x:0, y:0, z:0, yaw:0, hp:500, kills:0, deaths:0, room:null, lastDeath:0 }; ws.__p = p;
  ws.on('message', raw => {
    let m; try { m = JSON.parse(raw); } catch(e) { return; }
    if (!m || typeof m.type !== 'string') return;
    const room = p.room;
    switch (m.type) {
      case 'join': {
        if (room) return;
        const ts = Math.max(1, Math.min(5, parseInt(m.teamSize) || 1));
        { const v = checkLogin(m.name, m.pass); if (!v) { authFail(ws, m.name); return; } p.name = v; }
        if (m.mode === 'tg') {                                  // Training Grounds: join straight in
          const r = findTgRoom(); p.room = r; p.team = nextTgTeam++; p.kills = 0; p.deaths = 0;
          send(ws, { type:'welcome', id:p.id, team:p.team, players:roster(r), tg:true, count:r.players.size + 1 });
          bcast(r, { type:'joined', player:pub(p) }); r.players.set(p.id, p);
          send(ws, { type:'start', seed:r.seed, killTarget:1e9, scores:[0,0], players:roster(r), tg:true });
          break;
        }
        const r = findRoom(ts); p.room = r; p.team = pickTeam(r);
        send(ws, { type:'welcome', id:p.id, team:p.team, players:roster(r) });
        bcast(r, { type:'joined', player:pub(p) });
        r.players.set(p.id, p);
        if (r.state === 'voting' && r.vote) send(ws, { type:'mapVote', options:r.vote.opts, seconds:Math.max(1, Math.round((r.vote.ends - Date.now()) / 1000)), tally:voteTally(r) });
        maybeStart(r);
        break;
      }
      case 'state':
        if (!room) return;
        for (const k of ['x','y','z','yaw','hp']) if (typeof m[k] === 'number' && isFinite(m[k])) p[k] = m[k];
        { const st = { type:'state', id:p.id, x:p.x, y:p.y, z:p.z, yaw:p.yaw, hp:p.hp, weapon:m.weapon|0, moving:!!m.moving, sl:m.sl ? 1 : 0, cr:m.cr ? 1 : 0, sk:String(m.sk || '').replace(/[^a-z0-9_]/g, '').slice(0, 20) }; p.sk = st.sk;
          if (room.tg) { const out = JSON.stringify(st); for (const q of room.players.values()) if (q !== p && q.ws.readyState === 1 && Math.abs(q.x - p.x) < 320 && Math.abs(q.z - p.z) < 320) q.ws.send(out); }
          else bcast(room, st, p); }
        break;
      case 'hit': {
        if (!room || room.state !== 'playing') return;
        const t = room.players.get(m.target);
        if (!t || t === p || t.team === p.team) return; // no friendly fire
        const dmg = Math.max(0, Math.min(1000, +m.dmg || 0));
        send(t.ws, { type:'hit', from:p.id, name:p.name, dmg });
        break;
      }
      case 'died': {
        if (!room || room.state !== 'playing') return;
        const now = Date.now(); if (now - p.lastDeath < 1500) return; p.lastDeath = now;
        p.deaths++;
        const k = room.players.get(m.killer);
        if (room.tg) { if (k && k !== p) k.kills++; bcast(room, { type:'death', id:p.id, killer:k ? k.id : null, name:p.name, killerName:k ? k.name : null, scores:[0,0], players:[pub(p)].concat(k ? [pub(k)] : []), tg:true }); break; }
        if (k && k.team !== p.team) { k.kills++; room.scores[k.team]++; }
        bcast(room, { type:'death', id:p.id, killer:k ? k.id : null, scores:room.scores, players:roster(room) });
        if (k && room.scores[k.team] >= KILL_TARGET) endMatch(room, k.team);
        break;
      }
      case 'shot': if (room) bcast(room, { type:'shot', id:p.id, weapon:m.weapon|0 }, p); break;
      case 'vote': if (room && room.state === 'voting' && room.vote && room.vote.opts.includes(m.map)) { room.vote.votes.set(p.id, m.map); bcast(room, { type:'votes', tally:voteTally(room) }); } break;
      case 'door': if (room) bcast(room, { type:'door', id:(m.id | 0), open:!!m.open }, p); break;
      case 'build':
        if (!room) return;
        bcast(room, { type:'build', kind:m.kind, matId:m.matId, x:+m.x, y:+m.y, z:+m.z, alongX:!!m.alongX, rotation:m.rotation }, p);
        break;
      case 'leave': leave(p); p.room = null; break;
      case 'hubJoin': {
        if (p.hub) return;
        { const v = checkLogin(m.name, m.pass); if (!v) { authFail(ws, m.name); return; } p.name = v; }
        p.hx = 0; p.hy = 0; p.hz = 6; p.hyaw = 0;
        for (const hb of hubs) for (const q of hb.players.values()) if (q.name === p.name && q !== p) { send(q.ws, { type:'hubKicked', text:'You opened the game in another tab or window, so this one was disconnected.' }); hubLeave(q); setTimeout(() => { try { q.ws.close(); } catch (e) {} }, 100); }
        let h = null; if (m.server) h = hubs.find(x => x.num === (m.server|0) && x.players.size < HUB_MAX); if (!h) h = hubFor(); p.hub = h;
        p.role = roleOf(p.name);
        send(ws, { type:'hubWelcome', id:p.id, server:h.num, max:HUB_MAX, role:p.role, players:[...h.players.values()].map(hubPub) });
        { const ev = eventsLeft(); if (Object.keys(ev).length) send(ws, { type:'events', events:ev }); }
        if (p.role) hubAll({ type:'hubChat', id:0, name:'SYSTEM', system:true, text:(p.role === 'founder' ? 'The FOUNDER has arrived: ' : 'An ADMIN has arrived: ') + p.name });
        for (const q of h.players.values()) send(q.ws, { type:'hubJoined', player:hubPub(p) });
        h.players.set(p.id, p);
        break;
      }
      case 'matchChat': {
        if (!room || !rateOk(p)) return; const text = cleanText(m.text); if (!text) return;
        bcast(room, { type:'matchChat', name:p.name, team:p.team, text }); break;
      }
      case 'hubChat': {
        const h = p.hub; if (!h || !rateOk(p)) return; const text = cleanText(m.text); if (!text) return;
        const out = JSON.stringify({ type:'hubChat', id:p.id, name:p.name, role:p.role || null, text });
        for (const q of h.players.values()) if (q.ws.readyState === 1) q.ws.send(out);
        break;
      }
      case 'adminAnnounce': {   // world-wide: every player on every island, PvP match, Training Grounds and stage sees it at the top of the screen
        const who = p.hub || p.room ? p.name : p.sname; const role = p.role || (who ? roleOf(who) : null); if (!role) return;
        const now = Date.now(); if (now - (p.lastAnn || 0) < 2000) return; p.lastAnn = now;
        const text = cleanText(m.text); if (!text) return;
        const out = JSON.stringify({ type:'announce', id:now + '-' + p.id, name:who, role, text });
        for (const c of wss.clients) { const q = c.__p; if (c.readyState === 1 && q && (q.hub || q.room || q.sname)) c.send(out); }
        hubAll({ type:'hubChat', id:0, name:'SYSTEM', system:true, text:'[ANNOUNCEMENT from ' + who + '] ' + text });
        break; }
      case 'adminBuff': { // founders only: power up another player
        const sys = t => send(ws, { type:'hubChat', id:0, name:'SYSTEM', system:true, text:t });
        if (p.role !== 'founder') { sys('Only founders can use that command.'); return; }
        const what = String(m.what || ''); if (!['strong','givelevel','givestats','givecoins','giveweapons','healplayer','godplayer'].includes(what)) return;
        const value = Math.max(0, Math.min(1e12, +m.value || 0)); const who = alias(String(m.name || '').toLowerCase());
        for (const hb of hubs) for (const q of hb.players.values()) if (q.name.toLowerCase() === who) {
          send(q.ws, { type:'adminBuff', what, value, from:p.name }); sys('Done: ' + what + ' → ' + q.name + (value ? ' (' + value + ')' : '')); return; }
        sys('No player called "' + String(m.name || '').slice(0, 20) + '" is on the islands right now.'); break; }
      case 'adminEvent': {
        const sys = t => send(ws, { type:'hubChat', id:0, name:'SYSTEM', system:true, text:t });
        if (!p.role) { sys('Only admins and founders can start events.'); return; }
        if (m.kind === 'stop') { for (const k in EVENTS) delete EVENTS[k]; hubAll({ type:'events', events:{}, by:p.name }); hubAll({ type:'hubChat', id:0, name:'SYSTEM', system:true, text:'All events were stopped by ' + p.name }); return; }
        const kind = String(m.kind || ''); if (!EVENT_KINDS.includes(kind)) { sys('Unknown event.'); return; }
        if (m.off) { delete EVENTS[kind]; hubAll({ type:'events', events:eventsLeft(), by:p.name, stopped:kind }); hubAll({ type:'hubChat', id:0, name:'SYSTEM', system:true, text:(kind === 'abuse' ? 'ADMIN ABUSE' : kind.toUpperCase()) + ' turned off by ' + p.name }); break; }
        const mins = +m.minutes > 0 ? Math.min(1440, +m.minutes) : 0; EVENTS[kind] = mins ? Date.now() + mins * 60000 : Infinity;   // 0 = stays on until turned off
        hubAll({ type:'events', events:eventsLeft(), by:p.name, started:kind });
        hubAll({ type:'hubChat', id:0, name:'SYSTEM', system:true, text:(kind === 'abuse' ? 'ADMIN ABUSE' : kind.toUpperCase()) + ' turned on by ' + p.name + (mins ? ' for ' + mins + ' minutes!' : ' (until an admin turns it off)') }); break; }
      case 'adminAct': {
        const sys = t => send(ws, { type:'hubChat', id:0, name:'SYSTEM', system:true, text:t });
        if (!p.role) { sys('Only admins and founders can use that command.'); return; }
        const act = String(m.act || ''); if (!['freeze','unfreeze','bring','kill','fling','explode','trip','sparkle','heal','jump','giant','tiny','normal','spin','unspin','jail','unjail','ice','invisible','visible','fire','unfire','gold','ungold','god','ungod','speed','slow','normalspeed','smite','rocket','skydive','confuse','blind','coins','reset'].includes(act)) return;
        if ((act === 'coins' || act === 'god') && p.role !== 'founder') { sys('Only founders can give coins or god mode.'); return; }
        const who = alias(String(m.name || '').toLowerCase()); let n = 0;
        for (const hb of hubs) for (const q of hb.players.values()) {
          const hit = who === 'all' ? q !== p : who === 'others' ? q !== p : q.name.toLowerCase() === who; if (!hit) continue;
          if (q.role === 'founder' && p.role !== 'founder' && q !== p) continue;   // admins can't troll founders
          send(q.ws, { type:'adminAct', act, from:p.name, x:p.hx, y:p.hy, z:p.hz, value:+m.value || 0 }); n++; }
        sys(n ? act + ' → ' + n + ' player' + (n > 1 ? 's' : '') : 'No player called "' + String(m.name || '').slice(0, 20) + '" is on the islands right now.'); break; }
      case 'adminKick': { if (!p.role) return; const who = String(m.name || '').toLowerCase();
        for (const hb of hubs) for (const q of hb.players.values()) if (q.name.toLowerCase() === who && q !== p) {
          if (q.role === 'founder' && p.role !== 'founder') { send(ws, { type:'hubChat', id:0, name:'SYSTEM', system:true, text:'You cannot kick the founder.' }); return; }
          send(q.ws, { type:'hubKicked', text:'You were kicked by ' + p.name + '.' }); hubLeave(q); setTimeout(() => { try { q.ws.close(); } catch (e) {} }, 100);
          hubAll({ type:'hubChat', id:0, name:'SYSTEM', system:true, text:q.name + ' was kicked by ' + p.name }); return; }
        send(ws, { type:'hubChat', id:0, name:'SYSTEM', system:true, text:'No player called ' + who + ' is online.' }); break; }
      case 'saveProgress': {                            // the game sends your whole save here, so it lives on the server too
        const n = checkLogin(m.name, m.pass); if (!n) { authFail(ws, m.name); return; }
        const d = m.data; if (!d || typeof d !== 'object') return; const txt = JSON.stringify(d); if (txt.length > 400000) return send(ws, { type:'progressSaved', ok:false });
        const a = accounts[n]; const prev = a.save && a.save.savedAt || 0; if ((+d.savedAt || 0) >= prev) { delete d.password; delete d.tok; delete d.pwh; a.save = d; saveAccounts(); }
        send(ws, { type:'progressSaved', ok:true }); break;
      }
      case 'loadProgress': {                            // log in on any device (and after server updates) and get your stuff back
        const nn = m.create ? alias(keyOf(m.name)) : resolveName(m.name);   // signing up uses your exact spelling
        const existed = !!accounts[nn]; if (!existed && !m.create) { send(ws, { type:'progress', ok:false, exists:false }); return; }
        if (!existed && !canRegister(nn)) { send(ws, { type:'progress', ok:false, exists:false, reserved:true }); return; }
        const n = checkLogin(nn, m.pass, true);
        if (!n) { send(ws, { type:'progress', ok:false, exists:true }); return; }
        send(ws, { type:'progress', ok:true, existed, name: n, save: accounts[n].save || null, token: tokenFor(n), freshAt: accounts[n].freshAt || 0 }); break;
      }
      case 'rename': {                                  // change your username (keeps password + friends)
        const old = checkLogin(m.name, m.pass); if (!old) { authFail(ws, m.name); return; }
        const nn = alias(keyOf(m.newName));          // your new name exactly as typed (capitals kept)
        if (nn.length < 2) return send(ws, { type:'renameResult', ok:false, text:'Names need 2 to 20 letters, numbers or _' });
        if (nn === old) return send(ws, { type:'renameResult', ok:true, name:nn });
        if (accounts[nn] || !canRegister(nn)) return send(ws, { type:'renameResult', ok:false, text:'"' + nn + '" is already taken or reserved. Try another name.' });
        accounts[nn] = accounts[old]; delete accounts[old]; saveAccounts();
        if (social[old]) { social[nn] = social[old]; delete social[old]; }
        Object.values(social).forEach(s => ['friends','incoming','outgoing'].forEach(k => { s[k] = (s[k] || []).map(x => x === old ? nn : x); }));
        saveSocial(); if (online.get(old)) { online.set(nn, online.get(old)); online.delete(old); }
        send(ws, { type:'renameResult', ok:true, name:nn }); break;
      }
      case 'cmdQueue': {                                // Commander 1v1: find an opponent
        const v = checkLogin(m.name, m.pass); if (!v) { authFail(ws, m.name); return; }
        p.name = v; if (p.cmdRoom) return; cmdLeaveQueue(p);
        const oi = CMD.queue.findIndex(q => q !== p && q.name !== v && q.ws.readyState === 1);
        if (oi < 0) { CMD.queue.push(p); send(ws, { type:'cmdQueued', waiting: CMD.queue.length }); return; }
        const o = CMD.queue.splice(oi, 1)[0], C = global.CMDSIM, seed = (Math.random() * 4e9) >>> 0;
        const rm = { id: CMD.next++, players: [o, p], names: [o.name, v], seed, armies: [cmdArmyOf(o.name), cmdArmyOf(v)], comps: [null, null], lines: [null, null], ready: [false, false], S: null, over: false };
        CMD.rooms.set(rm.id, rm); o.cmdRoom = rm; p.cmdRoom = rm;
        rm.players.forEach((q, i) => cmdSend(q, { type:'cmdMatch', room: rm.id, side: i, opp: rm.names[1 - i], secs: 60, seed, army: rm.armies[i] }));
        rm.setupTimer = setTimeout(() => cmdStart(rm), 63000);
        console.log('  [commander] match: ' + rm.names.join(' vs '));
        break;
      }
      case 'cmdSetup': {                                // Commander 1v1: your troops and formation
        const rm = p.cmdRoom; if (!rm || rm.S) return; const i = rm.players.indexOf(p); if (i < 0) return; const C = global.CMDSIM;
        rm.comps[i] = C.cleanComp(m.comp, C.allowedOf(rm.armies[i])); rm.lines[i] = Array.isArray(m.lines) ? m.lines.slice(0, C.MAXSQ) : []; rm.ready[i] = !!m.ready;
        if (rm.ready[i]) cmdSend(rm.players[1 - i], { type:'cmdOppReady' });
        if (rm.ready[0] && rm.ready[1]) cmdStart(rm);
        break;
      }
      case 'cmdOrder': {                                // Commander 1v1: draw / change / send back lines during the battle
        const rm = p.cmdRoom; if (!rm || !rm.S || rm.over) return; const i = rm.players.indexOf(p); if (i < 0) return;
        const now = Date.now(); p.cmdTok = Math.min(10, (p.cmdTok == null ? 10 : p.cmdTok) + (now - (p.cmdTokAt || now)) / 125); p.cmdTokAt = now;   // up to 8 orders a second
        if (p.cmdTok < 1) return; p.cmdTok--;
        const o = m.o; if (!o || typeof o !== 'object' || !['add', 'set', 'recall', 'retype', 'retrain'].includes(o.op)) return;
        try { global.CMDSIM.command(rm.S, i, o); } catch (e) { console.log('  [commander] bad order', e.message); }
        break;
      }
      case 'cmdLeave': {
        cmdLeaveQueue(p); const rm = p.cmdRoom; if (rm) { const i = rm.players.indexOf(p); cmdEnd(rm, i < 0 ? -1 : 1 - i, 'left'); }
        break;
      }
      case 'changePass': {                              // change your password (Settings → Change your password)
        const fail = text => send(ws, { type:'passChanged', ok:false, text });
        ws._pwTries = (ws._pwTries || 0) + 1; if (ws._pwTries > 5) return fail('Too many tries. Reload the game and try again.');
        const n = cleanName(m.name), cur = String(m.pass || ''), np = String(m.newPass || '');
        if (!accounts[n]) return fail('There is no account called "' + n + '" on the server.');
        if (cur.startsWith('tok:') || checkLogin(n, cur) !== n) return fail('Your current password is wrong.');
        if (np.length < 4 || np.length > 64) return fail('The new password needs 4 to 64 characters.');
        const salt = crypto.randomBytes(16).toString('hex'); Object.assign(accounts[n], { salt, hash: hashPw(np, salt) }); saveAccounts();
        console.log('  [password] "' + n + '" changed their password');
        send(ws, { type:'passChanged', ok:true, name:n, token: tokenFor(n) }); break;
      }
      case 'hello': {                                   // social connection (friends, DMs, presence)
        const n = checkLogin(m.name, m.pass); if (!n) { authFail(ws, m.name); return; } p.sname = n; p.where = cleanText(m.where) || 'Online';
        const old = online.get(n); online.set(n, p); if (old && old !== p) { try { old.ws.close(); } catch (e) {} }
        send(ws, socialState(n)); notifyFriends(n); break;
      }
      case 'status': { if (!p.sname) return; p.where = cleanText(m.where).slice(0, 60); p.hubServer = m.server | 0; p.hx = +m.x || 0; p.hz = +m.z || 0; notifyFriends(p.sname); break; }
      case 'friendReq': {
        if (!p.sname) return; const to = cleanName(m.to); if (!to || to === p.sname) return send(ws, { type:'socialError', text:'Pick another name.' });
        if (!accounts[to] || REMOVED.includes(to)) return send(ws, { type:'socialError', text:'There is no player called "' + to + '". Check the spelling.' });
        const me = S(p.sname), them = S(to);
        if (me.friends.includes(to)) return send(ws, { type:'socialError', text:to + ' is already your friend.' });
        if (me.incoming.includes(to)) { // they already asked me -> accept
          me.incoming = me.incoming.filter(x => x !== to); them.outgoing = them.outgoing.filter(x => x !== p.sname);
          me.friends.push(to); them.friends.push(p.sname); saveSocial(); pushState(p.sname); pushState(to); break; }
        if (!me.outgoing.includes(to)) me.outgoing.push(to); if (!them.incoming.includes(p.sname)) them.incoming.push(p.sname); saveSocial();
        pushState(p.sname); pushState(to); send(ws, { type:'friendSent', to }); const t = online.get(to); if (t) send(t.ws, { type:'friendRequest', from:p.sname }); break;
      }
      case 'friendAccept': case 'friendDecline': {
        if (!p.sname) return; const from = cleanName(m.from), me = S(p.sname), them = S(from);
        if (!me.incoming.includes(from)) return;
        me.incoming = me.incoming.filter(x => x !== from); them.outgoing = them.outgoing.filter(x => x !== p.sname);
        if (m.type === 'friendAccept') { if (!me.friends.includes(from)) me.friends.push(from); if (!them.friends.includes(p.sname)) them.friends.push(p.sname);
          const t = online.get(from); if (t) send(t.ws, { type:'friendAccepted', by:p.sname }); }
        saveSocial(); pushState(p.sname); pushState(from); break;
      }
      case 'friendRemove': {
        if (!p.sname) return; const n = cleanName(m.name), me = S(p.sname), them = S(n);
        me.friends = me.friends.filter(x => x !== n); them.friends = them.friends.filter(x => x !== p.sname);
        me.outgoing = me.outgoing.filter(x => x !== n); them.incoming = them.incoming.filter(x => x !== p.sname);
        saveSocial(); pushState(p.sname); pushState(n); break;
      }
      case 'dm': {
        if (!p.sname || !rateOk(p)) return; const to = cleanName(m.to), text = cleanText(m.text); if (!text) return;
        if (!S(p.sname).friends.includes(to)) return send(ws, { type:'socialError', text:'You can only message friends.' });
        const t = online.get(to); if (!t) return send(ws, { type:'socialError', text:to + ' is offline.' });
        send(t.ws, { type:'dm', from:p.sname, text }); send(ws, { type:'dmSent', to, text }); break;
      }
      case 'joinFriend': {
        if (!p.sname) return; const n = cleanName(m.name); if (!S(p.sname).friends.includes(n)) return;
        const t = online.get(n); if (!t || !t.hubServer) return send(ws, { type:'socialError', text:n + ' is not on the islands right now.' });
        send(ws, { type:'friendLocation', name:n, server:t.hubServer, x:t.hx, z:t.hz }); break;
      }
      case 'hubState': {
        const h = p.hub; if (!h) return;
        for (const k of ['x','y','z','yaw']) if (typeof m[k] === 'number' && isFinite(m[k])) p['h'+k] = m[k];
        p.hsk = String(m.sk || '').replace(/[^a-z0-9_]/g, '').slice(0, 20);
        const out = JSON.stringify({ type:'hubState', id:p.id, x:p.hx, y:p.hy, z:p.hz, yaw:p.hyaw, hp:m.hp|0, sl:m.sl ? 1 : 0, cr:m.cr ? 1 : 0, fx:String(m.fx || '').replace(/[^a-z,]/g, '').slice(0, 60), sk:String(m.sk || '').replace(/[^a-z0-9_]/g, '').slice(0, 20) });
        for (const q of h.players.values()) if (q !== p && q.ws.readyState === 1) q.ws.send(out);
        break;
      }
    }
  });
  ws.on('close', () => { cmdLeaveQueue(p); if (p.cmdRoom) { const r = p.cmdRoom, i = r.players.indexOf(p); cmdEnd(r, i < 0 ? -1 : 1 - i, 'left'); } leave(p); hubLeave(p); if (p.sname && online.get(p.sname) === p) { online.delete(p.sname); notifyFriends(p.sname); } });
  ws.on('error', () => {});
});

// keep-alive ping so hosts don't drop idle sockets
// keep-alive: ping everyone; drop connections that stopped answering (sleeping laptop, lost Wi-Fi)
setInterval(() => { const now = Date.now(); for (const c of wss.clients) { if (c.lastSeen && now - c.lastSeen > 70000) { try { c.sock.destroy(); } catch (e) {} c._end(); continue; } try { c.ping(); } catch(e){} } }, 20000);

// Start listening. If the port is busy (another program uses 8080), try the next ones.
let port = Number(PORT), tries = 0;
server.on('error', e => {
  if (e.code === 'EADDRINUSE' && tries < 15) { console.log('  Port ' + port + ' is busy, trying ' + (port + 1) + '...'); tries++; port++; setTimeout(() => server.listen(port), 200); return; }
  console.error('\n  SERVER ERROR: ' + e.message + '\n'); process.exit(1);
});
server.on('listening', () => {
  const url = 'http://localhost:' + port;
  console.log('\n  ================================================');
  console.log('   Abyssal Clash server version 103 is RUNNING');
  console.log('   Play at:  ' + url);
  console.log('   Keep this window open while you play.');
  console.log('  ================================================\n');
  if (process.env.OPEN_BROWSER === '1') {
    const cmd = process.platform === 'win32' ? 'start "" "' + url + '"' : process.platform === 'darwin' ? 'open "' + url + '"' : 'xdg-open "' + url + '"';
    require('child_process').exec(cmd, () => {});
  }
});
server.listen(port);
