/* DTCL Season 4 auction server. Zero dependencies: node server.js
 *
 *  - Holds the authoritative auction state for both leagues.
 *  - Pushes every change to all open browsers over Server-Sent Events.
 *  - Only requests carrying the admin password can change anything.
 */
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const Rules = require('./public/rules.js');

const PORT = +process.env.PORT || 3000;
const RUNTIME = path.join(__dirname, 'runtime');
const STATE_FILE = path.join(RUNTIME, 'state.json');
const PUBLIC = path.join(__dirname, 'public');
const DATA = JSON.parse(fs.readFileSync(path.join(__dirname, 'data', 'players.json'), 'utf8'));
fs.mkdirSync(RUNTIME, { recursive: true });

/* ---------- admin password: env var, else a generated one kept on disk ---------- */
let ADMIN = process.env.ADMIN_PASSWORD;
let generated = false;
if (!ADMIN) {
  const f = path.join(RUNTIME, 'admin-password.txt');
  try { ADMIN = fs.readFileSync(f, 'utf8').trim(); } catch (e) {}
  if (!ADMIN) { ADMIN = crypto.randomBytes(5).toString('hex'); fs.writeFileSync(f, ADMIN + '\n'); }
  generated = true;
}
const isAdmin = pw => {
  const a = crypto.createHash('sha256').update(String(pw || '')).digest();
  const b = crypto.createHash('sha256').update(ADMIN).digest();
  return crypto.timingSafeEqual(a, b);
};

/* ---------- state ---------- */
const CAT_ORDER = Rules.CATS;
const DEFAULTS = {
  men: {
    purse: 5000000, maxSquad: 12,
    quotas: { PLATINUM: { n: 2, base: 500000 }, GOLD: { n: 2, base: 300000 }, SILVER: { n: 3, base: 200000 }, BRONZE: { n: 3, base: 100000 } },
    inc: { PLATINUM: 50000, GOLD: 50000, SILVER: 25000, BRONZE: 25000 },
  },
  women: {
    // only 5 platinum / 10 gold / 10 silver women exist, so 2-2-3-3 cannot work for 5 teams
    purse: 4000000, maxSquad: 12,
    quotas: { PLATINUM: { n: 1, base: 500000 }, GOLD: { n: 2, base: 300000 }, SILVER: { n: 2, base: 200000 }, BRONZE: { n: 5, base: 100000 } },
    inc: { PLATINUM: 50000, GOLD: 50000, SILVER: 25000, BRONZE: 25000 },
  },
};
const PLAYERS = { men: {}, women: {} };
for (const lg of ['men', 'women']) for (const p of DATA[lg].players) PLAYERS[lg][p.id] = p;

function freshLeague(lg) {
  const L = {
    config: JSON.parse(JSON.stringify(DEFAULTS[lg])),
    sales: {}, unsold: [], category: 'PLATINUM', current: null, last: null, log: [], seq: 0,
  };
  for (const pid in PLAYERS[lg]) {
    const p = PLAYERS[lg][pid];
    if (p.pre) L.sales[pid] = { teamId: p.pre, price: 0, pre: true, ts: 0 };
  }
  return L;
}
let STATE = { men: freshLeague('men'), women: freshLeague('women') };
try {
  const saved = JSON.parse(fs.readFileSync(STATE_FILE, 'utf8'));
  for (const lg of ['men', 'women']) if (saved[lg]) STATE[lg] = saved[lg];
  console.log('Resumed auction from', STATE_FILE);
} catch (e) {}

let saveTimer = null;
function persist() {
  clearTimeout(saveTimer);
  saveTimer = setTimeout(() => {
    const tmp = STATE_FILE + '.tmp';
    fs.writeFile(tmp, JSON.stringify(STATE), err => { if (!err) fs.rename(tmp, STATE_FILE, () => {}); });
  }, 150);
}

/* ---------- live connections ---------- */
const clients = new Set();
function send(res, event, data) { res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`); }
function broadcast(lg) {
  const msg = { league: lg, state: STATE[lg], now: Date.now() };
  for (const res of clients) send(res, 'update', msg);
  persist();
}
setInterval(() => { for (const res of clients) res.write(': hb\n\n'); }, 20000);

/* ---------- actions ---------- */
const SPIN_MS = 7000;
const ok = () => ({ ok: true });
const fail = error => ({ ok: false, error });

function shuffle(a) {
  for (let i = a.length - 1; i > 0; i--) { const j = crypto.randomInt(i + 1); [a[i], a[j]] = [a[j], a[i]]; }
  return a;
}
function log(L, entry) { L.log.push(Object.assign({ ts: Date.now() }, entry)); if (L.log.length > 400) L.log.shift(); }
function advanceCategory(lg) {
  const L = STATE[lg], P = PLAYERS[lg];
  if (L.category !== 'UNSOLD' && Rules.pool(L, P, L.category).length) return;
  for (const c of CAT_ORDER) if (Rules.pool(L, P, c).length) { L.category = c; return; }
  if (L.unsold.length) L.category = 'UNSOLD';
}
const bidsOpen = L => L.current && L.current.phase === 'bidding' && Date.now() >= L.current.spin.start + L.current.spin.dur;

const ACTIONS = {
  setCategory(lg, L, b) {
    if (L.current) return fail('Finish the current player first');
    if (b.category !== 'UNSOLD' && CAT_ORDER.indexOf(b.category) < 0) return fail('Unknown category');
    L.category = b.category;
    return ok();
  },

  spin(lg, L, b) {
    if (L.current) return fail('A player is already on the block');
    const cat = b.category || L.category;
    if (cat !== 'UNSOLD' && CAT_ORDER.indexOf(cat) < 0) return fail('Unknown category');
    const ids = shuffle(Rules.pool(L, PLAYERS[lg], cat));
    if (!ids.length) return fail('Nobody left in ' + Rules.CAT_LABEL[cat]);
    const idx = crypto.randomInt(ids.length);
    const pid = ids[idx];
    L.category = cat;
    if (cat === 'UNSOLD') L.unsold = L.unsold.filter(x => x !== pid);
    L.current = {
      pid, from: cat, phase: 'bidding', bids: [],
      spin: { id: ++L.seq, ids, idx, off: 0.2 + Math.random() * 0.6, start: Date.now(), dur: SPIN_MS },
    };
    return ok();
  },

  bid(lg, L, b) {
    if (!bidsOpen(L)) return fail('Wait for the wheel to stop');
    const P = PLAYERS[lg], player = P[L.current.pid];
    const e = Rules.eligibility(L, P, b.teamId, player);
    if (!e.ok) return fail(e.reason);
    const lead = Rules.currentBid(L);
    if (lead && lead.teamId === b.teamId) return fail('That team already holds the highest bid');
    const inc = Math.max(5000, Math.min(1000000, Math.round(+b.inc / 5000) * 5000 || L.config.inc[player.cat]));
    const price = lead ? lead.price + inc : e.min;
    if (price > e.max) return fail(`Over the limit — max bid is ${Rules.fmt(e.max)} for this team`);
    L.current.bids.push({ teamId: b.teamId, price, ts: Date.now() });
    return ok();
  },

  unbid(lg, L) {
    if (!bidsOpen(L) || !L.current.bids.length) return fail('Nothing to undo');
    L.current.bids.pop();
    return ok();
  },

  sold(lg, L) {
    if (!bidsOpen(L)) return fail('Wait for the wheel to stop');
    const lead = Rules.currentBid(L);
    if (!lead) return fail('No bids yet — mark unsold or wait for a bid');
    const pid = L.current.pid;
    L.sales[pid] = { teamId: lead.teamId, price: lead.price, ts: Date.now() };
    L.last = { seq: ++L.seq, type: 'sold', pid, teamId: lead.teamId, price: lead.price, ts: Date.now() };
    log(L, { type: 'sold', pid, teamId: lead.teamId, price: lead.price });
    L.current = null;
    advanceCategory(lg);
    return ok();
  },

  unsold(lg, L) {
    if (!bidsOpen(L)) return fail('Wait for the wheel to stop');
    const pid = L.current.pid;
    L.unsold.push(pid);
    L.last = { seq: ++L.seq, type: 'unsold', pid, ts: Date.now() };
    log(L, { type: 'unsold', pid });
    L.current = null;
    advanceCategory(lg);
    return ok();
  },

  /* Player not present / draw to be ignored: back into the wheel, no result. */
  withdraw(lg, L) {
    if (!L.current) return fail('Nobody on the block');
    if (L.current.from === 'UNSOLD') L.unsold.push(L.current.pid);
    L.current = null;
    return ok();
  },

  /* Undo a sale (any player, or the most recent one). Player returns to the wheel. */
  release(lg, L, b) {
    if (L.current) return fail('Finish the current player first');
    let pid = b.pid;
    if (!pid) { for (let i = L.log.length - 1; i >= 0; i--) if (L.log[i].type === 'sold' && L.sales[L.log[i].pid] && !L.sales[L.log[i].pid].pre) { pid = L.log[i].pid; break; } }
    const s = L.sales[pid];
    if (!s) return fail('No sale to undo');
    if (s.pre) return fail('Pre-assigned players cannot be released');
    delete L.sales[pid];
    log(L, { type: 'undo', pid, teamId: s.teamId, price: s.price });
    L.last = null;
    L.category = PLAYERS[lg][pid].cat;
    return ok();
  },

  settings(lg, L, b) {
    const c = b.config || {}, cfg = L.config;
    const num = (v, lo, hi) => (Number.isFinite(+v) && +v >= lo && +v <= hi) ? Math.round(+v) : null;
    const purse = num(c.purse, 0, 1e9); if (purse !== null) cfg.purse = purse;
    const sq = num(c.maxSquad, 1, 40); if (sq !== null) cfg.maxSquad = sq;
    for (const k of CAT_ORDER) {
      const q = c.quotas && c.quotas[k];
      if (q) { const n = num(q.n, 0, 20), base = num(q.base, 0, 1e8); if (n !== null) cfg.quotas[k].n = n; if (base !== null) cfg.quotas[k].base = base; }
      const i = c.inc && num(c.inc[k], 5000, 1e7); if (i) cfg.inc[k] = i;
    }
    return ok();
  },

  reset(lg, L, b) {
    if (b.confirm !== 'RESET') return fail('Type RESET to confirm');
    const cfg = L.config;
    STATE[lg] = freshLeague(lg);
    STATE[lg].config = cfg; // keep the settings, wipe the auction
    return ok();
  },
};

/* ---------- http ---------- */
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.json': 'application/json', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon' };

function body(req) {
  return new Promise(resolve => {
    let s = '';
    req.on('data', d => { s += d; if (s.length > 1e5) req.destroy(); });
    req.on('end', () => { try { resolve(JSON.parse(s || '{}')); } catch (e) { resolve({}); } });
  });
}
const json = (res, code, obj) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(obj)); };

http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');

  if (req.method === 'GET' && url.pathname === '/api/events') {
    res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache, no-transform', Connection: 'keep-alive', 'X-Accel-Buffering': 'no' });
    res.write('retry: 2000\n\n');
    send(res, 'init', { now: Date.now(), leagues: STATE });
    clients.add(res);
    req.on('close', () => clients.delete(res));
    return;
  }
  if (req.method === 'GET' && url.pathname === '/api/data') {
    res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'public, max-age=300' });
    return res.end(JSON.stringify(DATA));
  }
  if (req.method === 'POST' && url.pathname === '/api/login') {
    const b = await body(req);
    return json(res, isAdmin(b.password) ? 200 : 401, { ok: isAdmin(b.password) });
  }
  if (req.method === 'POST' && url.pathname === '/api/act') {
    if (!isAdmin(req.headers['x-admin'])) return json(res, 401, fail('Not authorised'));
    const b = await body(req);
    const lg = b.league;
    if (!STATE[lg] || !ACTIONS[b.action]) return json(res, 400, fail('Bad request'));
    const r = ACTIONS[b.action](lg, STATE[lg], b);
    if (r.ok) broadcast(lg);
    return json(res, 200, r);
  }

  if (req.method !== 'GET') { res.writeHead(405); return res.end(); }
  let rel = url.pathname === '/' || url.pathname === '/admin' ? '/index.html' : url.pathname;
  const file = path.normalize(path.join(PUBLIC, rel));
  if (!file.startsWith(PUBLIC + path.sep)) { res.writeHead(403); return res.end(); }
  fs.readFile(file, (err, buf) => {
    if (err) { res.writeHead(404); return res.end('Not found'); }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream', 'Cache-Control': 'no-cache' });
    res.end(buf);
  });
}).listen(PORT, () => {
  console.log(`\n  DTCL Season 4 auction running on http://localhost:${PORT}`);
  console.log(`  Viewers : http://localhost:${PORT}/`);
  console.log(`  Auctioneer: http://localhost:${PORT}/admin   password: ${ADMIN}${generated ? '  (generated; set ADMIN_PASSWORD to choose your own)' : ''}\n`);
});
