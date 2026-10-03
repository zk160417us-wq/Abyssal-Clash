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
const KILL_TARGET = 15, FILL_WAIT = 20, COUNTDOWN = 3;
const HUB_MAX = 10;               // max players per island server

/* ─── accounts: passwords are checked on the server (scrypt-hashed in accounts.json) ─── */
const crypto = require('crypto');
const ACC_FILE = path.join(__dirname, 'accounts.json');
let accounts = {}; try { accounts = JSON.parse(fs.readFileSync(ACC_FILE, 'utf8')); } catch (e) { accounts = {}; }
let accTimer = null; function saveAccounts() { clearTimeout(accTimer); accTimer = setTimeout(() => fs.writeFile(ACC_FILE, JSON.stringify(accounts), () => {}), 300); }
const hashPw = (pw, salt) => crypto.scryptSync(String(pw), salt, 32).toString('hex');
// Returns the verified username, or null. First time a name is seen, it is registered with that password.
function checkLogin(name, pass) {
  const n = String(name || '').toLowerCase().replace(/[^a-z0-9_]/g, '').slice(0, 20); const pw = String(pass || '');
  if (n.length < 3 || pw.length < 4) return null;
  const a = accounts[n];
  if (!a) { const salt = crypto.randomBytes(16).toString('hex'); accounts[n] = { salt, hash: hashPw(pw, salt), created: Date.now() }; saveAccounts(); return n; }
  const h = hashPw(pw, a.salt); return crypto.timingSafeEqual(Buffer.from(h, 'hex'), Buffer.from(a.hash, 'hex')) ? n : null;
}
function authFail(ws, name) { send(ws, { type:'authFail', name: String(name || '').slice(0, 20), text:'Wrong password for "' + String(name || '').slice(0, 20) + '" on this server. That username is already taken here — log out and use another name, or type the right password.' }); }

/* ─── friends + chat ─── */
const FRIENDS_FILE = path.join(__dirname, 'friends.json');
let social = {};                                   // name -> { friends:[], incoming:[], outgoing:[] }
try { social = JSON.parse(fs.readFileSync(FRIENDS_FILE, 'utf8')); } catch (e) { social = {}; }
let saveTimer = null;
function saveSocial() { clearTimeout(saveTimer); saveTimer = setTimeout(() => fs.writeFile(FRIENDS_FILE, JSON.stringify(social), () => {}), 500); }
const online = new Map();                          // name -> player (social socket)
function S(name) { return social[name] || (social[name] = { friends: [], incoming: [], outgoing: [] }); }
const cleanName = n => String(n || '').toLowerCase().replace(/[^a-z0-9_]/g, '').slice(0, 20);
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
const FOUNDERS = (process.env.FOUNDERS || 'auraguy').toLowerCase().split(',').map(s => s.trim()).filter(Boolean);
const ADMINS = (process.env.ADMINS || '').toLowerCase().split(',').map(s => s.trim()).filter(Boolean);
function roleOf(name) { const n = String(name || '').toLowerCase(); return FOUNDERS.includes(n) ? 'founder' : ADMINS.includes(n) ? 'admin' : null; }
function hubAll(msg) { const out = JSON.stringify(msg); for (const hb of hubs) for (const q of hb.players.values()) if (q.ws.readyState === 1) q.ws.send(out); }
function hubFor() {
  let h = hubs.find(h => h.players.size < HUB_MAX);
  if (!h) { let num = 1; while (hubs.some(x => x.num === num)) num++; h = { num, players: new Map() }; hubs.push(h); hubs.sort((a,b)=>a.num-b.num); }
  return h;
}
function hubPub(p) { return { id:p.id, name:p.name, x:p.hx, y:p.hy, z:p.hz, yaw:p.hyaw }; }
function hubLeave(p) {
  const h = p.hub; if (!h) return; p.hub = null;
  h.players.delete(p.id);
  for (const q of h.players.values()) send(q.ws, { type:'hubLeft', id:p.id });
  if (h.players.size === 0) hubs.splice(hubs.indexOf(h), 1);
}

function send(ws, m) { if (ws.readyState === 1) ws.send(JSON.stringify(m)); }
function bcast(room, m, except) { for (const p of room.players.values()) if (p !== except) send(p.ws, m); }
function pub(p) { return { id:p.id, name:p.name, team:p.team, x:p.x, y:p.y, z:p.z, yaw:p.yaw, hp:p.hp, kills:p.kills, deaths:p.deaths }; }
function roster(room) { return [...room.players.values()].map(pub); }

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
function countdown(room) {
  if (room.state !== 'waiting') return;
  clearTimeout(room.timer); room.timer = null; room.state = 'countdown';
  let s = COUNTDOWN;
  const tick = () => {
    if (room.players.size < 2) { room.state = 'waiting'; return; }
    if (s > 0) { bcast(room, { type:'countdown', seconds:s }); s--; return setTimeout(tick, 1000); }
    room.state = 'playing';
    bcast(room, { type:'start', seed:room.seed, killTarget:KILL_TARGET, scores:room.scores, players:roster(room) });
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
  if (room.players.size === 0) { clearTimeout(room.timer); rooms.delete(room.id); return; }
  if (room.state === 'playing') {
    const teams = [0,0]; for (const q of room.players.values()) teams[q.team]++;
    if (!teams[0]) endMatch(room, 1); else if (!teams[1]) endMatch(room, 0);
  }
}

wss.on('connection', ws => {
  const p = { id: 'p' + (nextId++), ws, name:'player', team:0, x:0, y:0, z:0, yaw:0, hp:500, kills:0, deaths:0, room:null, lastDeath:0 };
  ws.on('message', raw => {
    let m; try { m = JSON.parse(raw); } catch(e) { return; }
    if (!m || typeof m.type !== 'string') return;
    const room = p.room;
    switch (m.type) {
      case 'join': {
        if (room) return;
        const ts = Math.max(1, Math.min(5, parseInt(m.teamSize) || 1));
        { const v = checkLogin(m.name, m.pass); if (!v) { authFail(ws, m.name); return; } p.name = v; }
        const r = findRoom(ts); p.room = r; p.team = pickTeam(r);
        send(ws, { type:'welcome', id:p.id, team:p.team, players:roster(r) });
        bcast(r, { type:'joined', player:pub(p) });
        r.players.set(p.id, p);
        maybeStart(r);
        break;
      }
      case 'state':
        if (!room) return;
        for (const k of ['x','y','z','yaw','hp']) if (typeof m[k] === 'number' && isFinite(m[k])) p[k] = m[k];
        bcast(room, { type:'state', id:p.id, x:p.x, y:p.y, z:p.z, yaw:p.yaw, hp:p.hp, weapon:m.weapon|0, moving:!!m.moving }, p);
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
        if (k && k.team !== p.team) { k.kills++; room.scores[k.team]++; }
        bcast(room, { type:'death', id:p.id, killer:k ? k.id : null, scores:room.scores, players:roster(room) });
        if (k && room.scores[k.team] >= KILL_TARGET) endMatch(room, k.team);
        break;
      }
      case 'shot': if (room) bcast(room, { type:'shot', id:p.id, weapon:m.weapon|0 }, p); break;
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
      case 'adminAnnounce': { if (!p.role) return; const text = cleanText(m.text); if (!text) return; hubAll({ type:'hubChat', id:0, name:'SYSTEM', system:true, text:'[ANNOUNCEMENT from ' + p.name + '] ' + text }); break; }
      case 'adminKick': { if (!p.role) return; const who = String(m.name || '').toLowerCase();
        for (const hb of hubs) for (const q of hb.players.values()) if (q.name.toLowerCase() === who && q !== p) {
          if (q.role === 'founder' && p.role !== 'founder') { send(ws, { type:'hubChat', id:0, name:'SYSTEM', system:true, text:'You cannot kick the founder.' }); return; }
          send(q.ws, { type:'hubKicked', text:'You were kicked by ' + p.name + '.' }); hubLeave(q); setTimeout(() => { try { q.ws.close(); } catch (e) {} }, 100);
          hubAll({ type:'hubChat', id:0, name:'SYSTEM', system:true, text:q.name + ' was kicked by ' + p.name }); return; }
        send(ws, { type:'hubChat', id:0, name:'SYSTEM', system:true, text:'No player called ' + who + ' is online.' }); break; }
      case 'hello': {                                   // social connection (friends, DMs, presence)
        const n = checkLogin(m.name, m.pass); if (!n) { authFail(ws, m.name); return; } p.sname = n; p.where = cleanText(m.where) || 'Online';
        const old = online.get(n); online.set(n, p); if (old && old !== p) { try { old.ws.close(); } catch (e) {} }
        send(ws, socialState(n)); notifyFriends(n); break;
      }
      case 'status': { if (!p.sname) return; p.where = cleanText(m.where).slice(0, 60); p.hubServer = m.server | 0; p.hx = +m.x || 0; p.hz = +m.z || 0; notifyFriends(p.sname); break; }
      case 'friendReq': {
        if (!p.sname) return; const to = cleanName(m.to); if (!to || to === p.sname) return send(ws, { type:'socialError', text:'Pick another name.' });
        const me = S(p.sname), them = S(to);
        if (me.friends.includes(to)) return send(ws, { type:'socialError', text:to + ' is already your friend.' });
        if (me.incoming.includes(to)) { // they already asked me -> accept
          me.incoming = me.incoming.filter(x => x !== to); them.outgoing = them.outgoing.filter(x => x !== p.sname);
          me.friends.push(to); them.friends.push(p.sname); saveSocial(); pushState(p.sname); pushState(to); break; }
        if (!me.outgoing.includes(to)) me.outgoing.push(to); if (!them.incoming.includes(p.sname)) them.incoming.push(p.sname); saveSocial();
        pushState(p.sname); pushState(to); const t = online.get(to); if (t) send(t.ws, { type:'friendRequest', from:p.sname }); break;
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
        const out = JSON.stringify({ type:'hubState', id:p.id, x:p.hx, y:p.hy, z:p.hz, yaw:p.hyaw, hp:m.hp|0 });
        for (const q of h.players.values()) if (q !== p && q.ws.readyState === 1) q.ws.send(out);
        break;
      }
    }
  });
  ws.on('close', () => { leave(p); hubLeave(p); if (p.sname && online.get(p.sname) === p) { online.delete(p.sname); notifyFriends(p.sname); } });
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
  console.log('   Core Conflict server is RUNNING');
  console.log('   Play at:  ' + url);
  console.log('   Keep this window open while you play.');
  console.log('  ================================================\n');
  if (process.env.OPEN_BROWSER === '1') {
    const cmd = process.platform === 'win32' ? 'start "" "' + url + '"' : process.platform === 'darwin' ? 'open "' + url + '"' : 'xdg-open "' + url + '"';
    require('child_process').exec(cmd, () => {});
  }
});
server.listen(port);
