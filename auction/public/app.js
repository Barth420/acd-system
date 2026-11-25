(() => {
'use strict';
const { CATS, CAT_LABEL, teamInfo, eligibility, pool, poolTotal, currentBid, fmt } = Rules;
const $ = s => document.querySelector(s);
const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const catColor = c => c === 'UNSOLD' ? 'var(--UNSOLD)' : `var(--${c})`;

/* ---------- state ---------- */
let DATA = null;
const P = { men: {}, women: {} };       // players by id
const TEAMS = { men: {}, women: {} };   // teams by id (+ colour)
const S = { men: null, women: null };   // live league state from the server
let skew = 0;                           // server clock - local clock
const seenSeq = { men: 0, women: 0 };
let league = 'men', tab = 'auction';
let adminPw = null;
let poolView = null, lastCat = {};
let inc = null;                         // raise-by chosen by the auctioneer
let plFilter = { q: '', cat: 'ALL', status: 'ALL' };
const srvNow = () => Date.now() + skew;
const L = () => S[league];

/* ---------- boot ---------- */
(async function boot() {
  parseHash();
  DATA = await (await fetch('/api/data')).json();
  for (const lg of ['men', 'women']) {
    DATA[lg].teams.forEach((t, i) => {
      t.color = `hsl(${Math.round((i * 360 / DATA[lg].teams.length + 14) % 360)} 58% 62%)`;
      TEAMS[lg][t.id] = t;
    });
    for (const p of DATA[lg].players) P[lg][p.id] = p;
  }
  if (location.pathname.replace(/\/$/, '') === '/admin') await adminLogin();
  connect();
  wire();
})();

function connect() {
  const es = new EventSource('/api/events');
  const live = $('#live');
  es.onopen = () => { live.classList.add('on'); live.lastChild.textContent = 'Live'; };
  es.onerror = () => { live.classList.remove('on'); live.lastChild.textContent = 'Reconnecting'; };
  es.addEventListener('init', e => {
    const m = JSON.parse(e.data);
    skew = m.now - Date.now();
    for (const lg of ['men', 'women']) { S[lg] = m.leagues[lg]; seenSeq[lg] = S[lg].last ? S[lg].last.seq : 0; }
    renderAll();
  });
  es.addEventListener('update', e => {
    const m = JSON.parse(e.data);
    skew = m.now - Date.now();
    S[m.league] = m.state;
    const last = m.state.last;
    if (last && last.seq > seenSeq[m.league]) {
      seenSeq[m.league] = last.seq;
      if (m.league === league) showResult(last);
    } else if (last) seenSeq[m.league] = Math.max(seenSeq[m.league], last.seq);
    if (m.league === league) renderAll();
  });
}

/* ---------- routing / wiring ---------- */
function parseHash() {
  const [a, b] = location.hash.replace('#', '').split('/');
  if (a === 'men' || a === 'women') league = a; else { try { league = localStorage.getItem('league') || 'men'; } catch (e) {} }
  if (['auction', 'teams', 'players'].includes(b)) tab = b;
}
function setHash() { history.replaceState(null, '', location.pathname + '#' + league + '/' + tab); try { localStorage.setItem('league', league); } catch (e) {} }

function wire() {
  $('#tabs').addEventListener('click', e => { const b = e.target.closest('button'); if (b) { tab = b.dataset.tab; setHash(); renderAll(); } });
  $('#leagueSeg').addEventListener('click', e => {
    const b = e.target.closest('button'); if (!b || b.dataset.league === league) return;
    league = b.dataset.league; poolView = null; inc = null; setHash(); dismissOverlay(); renderAll();
  });
  $('#abCats').addEventListener('click', e => { const b = e.target.closest('button'); if (b) act('setCategory', { category: b.dataset.cat }); });
  $('#spinBtn').addEventListener('click', () => act('spin', {}));
  $('#soldBtn').addEventListener('click', () => act('sold'));
  $('#unsoldBtn').addEventListener('click', () => act('unsold'));
  $('#unbidBtn').addEventListener('click', () => act('unbid'));
  $('#withdrawBtn').addEventListener('click', () => act('withdraw'));
  $('#undoSale').addEventListener('click', () => act('release', {}));
  $('#openSettings').addEventListener('click', openSettings);
  $('#openReset').addEventListener('click', openReset);
  $('#incSeg').addEventListener('click', e => { const b = e.target.closest('button'); if (b) { inc = +b.dataset.inc; renderBidActions(); } });
  $('#tiles').addEventListener('click', e => {
    const t = e.target.closest('.tile.can'); if (t) act('bid', { teamId: t.dataset.team, inc: curInc() });
  });
  $('#poolTabs').addEventListener('click', e => { const b = e.target.closest('button'); if (b) { poolView = b.dataset.cat; renderPool(); } });
  $('#teamsGrid').addEventListener('click', e => {
    const b = e.target.closest('.rel'); if (b && confirm('Undo this sale and return the player to the wheel?')) act('release', { pid: b.dataset.pid });
  });
  $('#plSearch').addEventListener('input', e => { plFilter.q = e.target.value.trim().toLowerCase(); renderPlayerList(); });
  $('#plCats').addEventListener('click', e => { const b = e.target.closest('.chip'); if (b) { plFilter.cat = b.dataset.v; renderPlayers(); } });
  $('#plStatus').addEventListener('click', e => { const b = e.target.closest('.chip'); if (b) { plFilter.status = b.dataset.v; renderPlayers(); } });
  $('#overlay').addEventListener('click', dismissOverlay);
  window.addEventListener('hashchange', () => { parseHash(); renderAll(); });
  window.addEventListener('keydown', e => {
    if (e.code === 'Space' && adminPw && !/INPUT|TEXTAREA|BUTTON/.test(document.activeElement.tagName) && !$('#modal').childElementCount) {
      e.preventDefault(); if (!L().current) act('spin', {});
    }
  });
}

/* ---------- admin ---------- */
async function adminLogin() {
  try { adminPw = sessionStorage.getItem('pw'); } catch (e) {}
  if (adminPw && await verify(adminPw)) return enableAdmin();
  adminPw = null;
  await new Promise(resolve => {
    openModal(`<div class="dlg"><h3>Auctioneer sign-in</h3><p>Enter the auction password to control the draw and bids.</p>
      <label for="pw">Password</label><input id="pw" type="password" autocomplete="current-password">
      <div class="err" id="pwErr"></div>
      <div class="foot"><a class="btn ghost" href="/" style="text-decoration:none">Watch only</a><button class="btn primary" id="pwGo">Sign in</button></div></div>`);
    const go = async () => {
      const v = $('#pw').value;
      if (await verify(v)) { adminPw = v; try { sessionStorage.setItem('pw', v); } catch (e) {} closeModal(); enableAdmin(); resolve(); }
      else $('#pwErr').textContent = 'Wrong password.';
    };
    $('#pwGo').onclick = go; $('#pw').onkeydown = e => { if (e.key === 'Enter') go(); };
    $('#pw').focus();
  });
}
async function verify(pw) {
  try { const r = await fetch('/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ password: pw }) }); return r.ok; }
  catch (e) { return false; }
}
function enableAdmin() { document.body.classList.add('admin'); }

async function act(action, payload = {}) {
  if (!adminPw) return;
  try {
    const r = await fetch('/api/act', { method: 'POST', headers: { 'Content-Type': 'application/json', 'x-admin': adminPw }, body: JSON.stringify({ league, action, ...payload }) });
    const j = await r.json();
    if (!j.ok) toast(j.error || 'Not allowed');
    return j;
  } catch (e) { toast('Connection problem — try again'); }
}

/* ---------- rendering ---------- */
function renderAll() {
  const lg = S[league]; if (!lg) return;
  document.documentElement.dataset.league = league;
  document.querySelectorAll('#tabs button').forEach(b => b.classList.toggle('on', b.dataset.tab === tab));
  document.querySelectorAll('#leagueSeg button').forEach(b => b.classList.toggle('on', b.dataset.league === league));
  for (const t of ['auction', 'teams', 'players']) $('#view-' + t).hidden = tab !== t;
  document.title = `${league === 'men' ? "Men's" : "Women's"} Auction · DTCL Season 4`;

  if (tab === 'auction') { renderAdminBar(); renderStage(); renderPool(); renderRecent(); renderTiles(); }
  if (tab === 'teams') renderTeams();
  if (tab === 'players') renderPlayers();
}

function avatar(p, cls = '') {
  const ini = p.name.split(' ').filter(Boolean).slice(0, 2).map(w => w[0]).join('');
  return `<span class="av ${cls}"><b>${esc(ini)}</b>${p.photo ? `<img src="${esc(p.photo)}" alt="" referrerpolicy="no-referrer" loading="lazy" onerror="this.remove()">` : ''}</span>`;
}
const crest = (t, cls = '') => `<span class="crest ${cls}" style="--tc:${t.color}">${esc(t.short)}</span>`;
const base = (cat) => L().config.quotas[cat].base;
const revealed = () => { const c = L().current; return !!c && srvNow() >= c.spin.start + c.spin.dur; };
const curInc = () => inc || L().config.inc[P[league][L().current.pid].cat];

/* ----- admin bar ----- */
function renderAdminBar() {
  const l = L();
  $('#abCats').innerHTML = [...CATS, 'UNSOLD'].map(c =>
    `<button data-cat="${c}" class="${l.category === c ? 'on' : ''}" ${l.current ? 'disabled' : ''}>${CAT_LABEL[c]}<span class="n">${pool(l, P[league], c).length}</span></button>`).join('');
  $('#spinBtn').disabled = !!l.current || !pool(l, P[league], l.category).length;
  $('#undoSale').disabled = !!l.current || !l.log.some(x => x.type === 'sold' && l.sales[x.pid] && !l.sales[x.pid].pre);
}

/* ----- stage: wheel + player ----- */
const wheel = { key: '', ids: [], rest: 0, hl: -1, raf: 0, cat: 'PLATINUM' };

function renderStage() {
  const l = L();
  syncWheel();
  renderPlayerPanel();
  const n = wheel.ids.length;
  $('#wheelCap').innerHTML = l.current
    ? `<b>${n}</b> names on the wheel`
    : n ? `<b>${n}</b> ${CAT_LABEL[l.category].toLowerCase()} ${l.category === 'UNSOLD' ? 'players' : 'players left'} on the wheel` : '';
}

function syncWheel() {
  const l = L(), cur = l.current;
  if (cur) {
    const key = league + ':' + cur.spin.id;
    wheel.cat = cur.from;
    if (wheel.key !== key) startSpin(key, cur);
    return;
  }
  cancelAnimationFrame(wheel.raf);
  wheel.key = ''; wheel.hl = -1; wheel.rest = 0; wheel.cat = l.category;
  wheel.ids = pool(l, P[league], l.category);
  drawWheel(0);
}

function startSpin(key, cur) {
  cancelAnimationFrame(wheel.raf);
  wheel.key = key; wheel.ids = cur.spin.ids; wheel.hl = -1;
  const pl = P[league][cur.pid];
  if (pl.photo) { const im = new Image(); im.referrerPolicy = 'no-referrer'; im.src = pl.photo; } // warm the cache so the reveal is instant
  const a = 2 * Math.PI / wheel.ids.length;
  const target = 2 * Math.PI * 7 - (cur.spin.idx + cur.spin.off) * a;
  const ease = t => 1 - Math.pow(1 - t, 4);
  const tick = () => {
    const t = Math.min(1, Math.max(0, (srvNow() - cur.spin.start) / cur.spin.dur));
    wheel.rest = target * ease(t);
    if (t >= 1) { wheel.hl = cur.spin.idx; drawWheel(wheel.rest); if (wheel.key === key && league === key.split(':')[0]) { renderPlayerPanel(); renderTiles(); renderAdminBar(); } return; }
    drawWheel(wheel.rest);
    wheel.raf = requestAnimationFrame(tick);
  };
  tick();
}

function drawWheel(angle) {
  const cv = $('#wheel'), ctx = cv.getContext('2d');
  const dpr = Math.min(2, window.devicePixelRatio || 1), W = 640;
  if (cv.width !== W * dpr) { cv.width = cv.height = W * dpr; }
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, W, W);
  const cx = W / 2, cy = W / 2 + 6, R = 296, hub = 62;
  const ids = wheel.ids, n = ids.length, ring = getComputedStyle(document.documentElement);
  const accent = ring.getPropertyValue('--acc').trim() || '#4f8cff';
  const rim = wheel.cat === 'UNSOLD' ? '#e5604b' : ({ PLATINUM: '#7fd0e6', GOLD: '#e3b04b', SILVER: '#aab4c4', BRONZE: '#c8814f' }[wheel.cat] || '#7fd0e6');

  // outer ring
  ctx.beginPath(); ctx.arc(cx, cy, R + 12, 0, 7); ctx.fillStyle = '#0d1422'; ctx.fill();
  ctx.lineWidth = 3; ctx.strokeStyle = rim; ctx.stroke();

  if (!n) {
    ctx.beginPath(); ctx.arc(cx, cy, R, 0, 7); ctx.fillStyle = '#131c2e'; ctx.fill();
    ctx.fillStyle = '#62738d'; ctx.textAlign = 'center'; ctx.font = '500 20px Inter, sans-serif';
    ctx.fillText('No players left', cx, cy - 4); ctx.font = '14px Inter, sans-serif'; ctx.fillText('in this set', cx, cy + 20);
  } else {
    const a = 2 * Math.PI / n;
    const fs = Math.max(9, Math.min(15, a * 100));
    ctx.save(); ctx.translate(cx, cy); ctx.rotate(angle - Math.PI / 2);
    for (let i = 0; i < n; i++) {
      const on = i === wheel.hl;
      ctx.beginPath(); ctx.moveTo(0, 0); ctx.arc(0, 0, R, i * a, (i + 1) * a); ctx.closePath();
      ctx.fillStyle = on ? accent : (i % 2 ? '#1c2943' : '#15203a'); ctx.fill();
      if (n > 1) { ctx.strokeStyle = 'rgba(10,15,25,.65)'; ctx.lineWidth = 1; ctx.stroke(); }
      ctx.save(); ctx.rotate((i + .5) * a); ctx.textAlign = 'right'; ctx.textBaseline = 'middle';
      ctx.font = `${on ? 600 : 500} ${fs}px Inter, sans-serif`;
      ctx.fillStyle = on ? '#fff' : '#d5deee';
      const maxW = R - hub - 26; let txt = P[league][ids[i]].short;
      while (ctx.measureText(txt).width > maxW && txt.length > 4) txt = txt.slice(0, -2);
      ctx.fillText(txt === P[league][ids[i]].short ? txt : txt.trim() + '…', R - 14, 0);
      ctx.restore();
    }
    ctx.restore();
  }
  // hub
  ctx.beginPath(); ctx.arc(cx, cy, hub, 0, 7); ctx.fillStyle = '#0d1422'; ctx.fill();
  ctx.lineWidth = 3; ctx.strokeStyle = rim; ctx.stroke();
  ctx.fillStyle = '#e7ecf5'; ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
  ctx.font = '700 28px "Barlow Condensed", sans-serif'; ctx.fillText(String(n), cx, cy - 6);
  ctx.font = '600 10px Inter, sans-serif'; ctx.fillStyle = '#62738d'; ctx.fillText('LEFT', cx, cy + 16);
  // pointer
  ctx.beginPath(); ctx.moveTo(cx - 17, 2); ctx.lineTo(cx + 17, 2); ctx.lineTo(cx, 46); ctx.closePath();
  ctx.fillStyle = '#f3f6fb'; ctx.shadowColor = 'rgba(0,0,0,.5)'; ctx.shadowBlur = 8; ctx.fill(); ctx.shadowBlur = 0;
}

function renderPlayerPanel() {
  const l = L(), cur = l.current, empty = $('#pEmpty'), blk = $('#pBlock');
  if (cur && revealed()) {
    empty.hidden = true; blk.hidden = false;
    const p = P[league][cur.pid], c = p.cat, bid = currentBid(l);
    if ($('#pPhoto').dataset.pid !== p.id) { $('#pPhoto').dataset.pid = p.id; $('#pPhoto').innerHTML = avatar(p); }
    const cat = $('#pCat'); cat.style.setProperty('--c', catColor(c)); cat.textContent = CAT_LABEL[c];
    $('#pName').textContent = p.name;
    $('#pSub').textContent = `${p.role} · ${p.pts.toFixed(2)} pts`;
    $('#pBase').textContent = fmt(base(c));
    const price = $('#bPrice'), shown = bid ? fmt(bid.price) : fmt(base(c));
    if (price.textContent !== shown && bid) { price.classList.remove('bump'); void price.offsetWidth; price.classList.add('bump'); }
    price.textContent = shown; price.style.color = bid ? '' : 'var(--dim)';
    const t = bid && TEAMS[league][bid.teamId];
    $('#bLeader').innerHTML = t ? `${crest(t, 'sm')}<b>${esc(t.name)}</b>` : 'Awaiting the opening bid at base price';
    $('#bHist').innerHTML = cur.bids.slice(-4).reverse().map(b => `<li><span>${esc(TEAMS[league][b.teamId].name)}</span><span>${fmt(b.price)}</span></li>`).join('');
    renderBidActions();
    return;
  }
  blk.hidden = true; empty.hidden = false;
  if (cur) { // wheel is still turning
    empty.innerHTML = `<span class="eyebrow">Drawing</span><h2>Spinning<span class="dots"> <span></span><span></span><span></span></span></h2><p>The next player is about to be revealed.</p>`;
    return;
  }
  const rem = pool(l, P[league], l.category).length;
  const all = CATS.every(c => !pool(l, P[league], c).length) && !l.unsold.length;
  let html;
  if (all) html = `<span class="eyebrow">Auction complete</span><h2>That's a wrap</h2><p>Every player has been through the wheel. Check the Teams tab for the final squads.</p>`;
  else html = `<span class="eyebrow" style="color:${catColor(l.category)}">${CAT_LABEL[l.category]} set</span><h2>Ready for the next draw</h2><p>${rem ? `${rem} ${rem === 1 ? 'player' : 'players'} left in this set. The wheel decides who comes up next.` : `Nobody left in this set.`}</p>`;
  const last = l.last && P[league][l.last.pid];
  if (last) {
    const t = l.last.teamId && TEAMS[league][l.last.teamId];
    html += `<div class="last"><span class="eyebrow">Previous player</span><div class="row">${avatar(last)}<div><strong>${esc(last.name)}</strong><small>${l.last.type === 'sold' ? `Sold to ${esc(t.name)} for ${fmt(l.last.price)}` : 'Unsold'}</small></div></div></div>`;
  }
  empty.innerHTML = html;
}

function renderBidActions() {
  const l = L(); if (!l.current || !revealed()) return;
  const cat = P[league][l.current.pid].cat, cur = curInc();
  const opts = [...new Set([25000, 50000, 100000, 200000, l.config.inc[cat]])].sort((a, b) => a - b);
  $('#incSeg').innerHTML = opts.map(v => `<button data-inc="${v}" class="${v === cur ? 'on' : ''}">+${fmt(v).replace('₹', '')}</button>`).join('');
  const has = l.current.bids.length > 0;
  $('#soldBtn').disabled = !has; $('#unbidBtn').disabled = !has;
  $('#soldBtn').textContent = has ? `Sold · ${fmt(currentBid(l).price)}` : 'Sold';
  $('#unsoldBtn').disabled = has;
}

/* ----- pool (what is left) ----- */
function renderPool() {
  const l = L(), p = P[league];
  if (lastCat[league] !== l.category) { lastCat[league] = l.category; poolView = l.category; }
  const view = poolView || l.category;
  const tabs = [...CATS, 'UNSOLD'];
  $('#poolTabs').innerHTML = tabs.map(c => `<button data-cat="${c}" class="${view === c ? 'on' : ''}" style="--c:${catColor(c)}"><i></i>${CAT_LABEL[c]} <em>${pool(l, p, c).length}</em></button>`).join('');
  const ids = pool(l, p, view).sort((a, b) => p[b].pts - p[a].pts);
  $('#poolList').innerHTML = ids.length
    ? ids.map(id => `<div class="it">${avatar(p[id], 'sm')}<span title="${esc(p[id].name)}">${esc(p[id].short)}</span></div>`).join('')
    : `<div class="empty">${view === 'UNSOLD' ? 'No unsold players' : 'Everyone in this set has been drawn'}</div>`;
  let sold = 0, spent = 0;
  for (const id in l.sales) if (!l.sales[id].pre) { sold++; spent += l.sales[id].price; }
  $('#poolStats').textContent = `${sold} sold · ${l.unsold.length} unsold · ${fmt(spent)} spent`;
}

function renderRecent() {
  const l = L(), p = P[league];
  const items = l.log.filter(x => x.type !== 'undo' || false).slice(-10).reverse();
  $('#recent').innerHTML = items.length ? items.map(x => {
    const pl = p[x.pid], t = x.teamId && TEAMS[league][x.teamId];
    const live = x.type === 'sold' ? !!l.sales[x.pid] : true;
    if (x.type === 'sold') return `<li style="${live ? '' : 'opacity:.45;text-decoration:line-through'}">${avatar(pl, 'sm')}<div class="t"><b>${esc(pl.name)}</b><small>${esc(t.name)}</small></div><span class="p">${fmt(x.price)}</span></li>`;
    return `<li>${avatar(pl, 'sm')}<div class="t"><b>${esc(pl.name)}</b><small>${CAT_LABEL[pl.cat]}</small></div><span class="p u">Unsold</span></li>`;
  }).join('') : `<li class="none">Nothing yet — the first draw is coming up</li>`;
}

/* ----- team tiles ----- */
function renderTiles() {
  const l = L(), pl = P[league], cur = l.current, bidding = !!cur && revealed();
  const player = cur && pl[cur.pid], lead = bidding ? currentBid(l) : null;
  const minSquad = CATS.reduce((s, c) => s + l.config.quotas[c].n, 0);
  $('#tilesNote').textContent = bidding ? `Bidding for ${player.short} · ${CAT_LABEL[player.cat]}` : `Core squad is ${minSquad} players · up to ${l.config.maxSquad} with extra bronze`;
  $('#tiles').innerHTML = DATA[league].teams.map(t => {
    const info = teamInfo(l, pl, t.id);
    let cls = 'tile', line = `<b>${fmt(info.left)}</b> left · ${info.count}/${minSquad}`;
    if (bidding) {
      const e = eligibility(l, pl, t.id, player);
      const isLead = lead && lead.teamId === t.id;
      if (isLead) cls += ' lead';
      else if (!e.ok) cls += ' off';
      else cls += ' can';
      if (!e.ok && !isLead) line = `<span class="why">${esc(e.reason)}</span>`;
      else line = `<b>${fmt(info.left)}</b> left · max <span class="max">${fmt(e.max)}</span>`;
      if (isLead) cls = cls.replace(' can', '');
    }
    const pips = CATS.map(c => {
      const n = info.byCat[c], q = l.config.quotas[c].n;
      return `<span class="pip ${n === q ? 'full' : n > q ? 'over' : ''}" style="--c:${catColor(c)}" title="${CAT_LABEL[c]}: ${n} of ${q}">${n}/${q}</span>`;
    }).join('');
    const clickable = cls.includes(' can') && !!adminPw;
    if (!clickable) cls = cls.replace(' can', '');
    return `<${clickable ? 'button' : 'div'} class="${cls}" data-team="${t.id}">${lead && lead.teamId === t.id ? '<span class="flag">Leading</span>' : ''}
      <div class="hd">${crest(t)}<span class="nm">${esc(t.name)}</span></div><div class="sub">${line}</div><div class="pips">${pips}</div></${clickable ? 'button' : 'div'}>`;
  }).join('');
}

/* ----- teams tab ----- */
function renderTeams() {
  const l = L(), pl = P[league];
  const minSquad = CATS.reduce((s, c) => s + l.config.quotas[c].n, 0);
  $('#teamsGrid').innerHTML = DATA[league].teams.map(t => {
    const info = teamInfo(l, pl, t.id);
    const rows = info.pids.sort((a, b) => CATS.indexOf(pl[a].cat) - CATS.indexOf(pl[b].cat) || l.sales[b].price - l.sales[a].price || pl[b].pts - pl[a].pts);
    const needs = CATS.filter(c => info.needs[c]).map(c => `<b>${info.needs[c]}</b> ${CAT_LABEL[c]}`).join(' · ');
    return `<article class="card tcard" style="--tc:${t.color}">
      <div class="tcard-h">${crest(t)}<div><h3>${esc(t.name)}</h3><div class="sub">${info.count} of ${minSquad} · ${fmt(info.spent)} spent</div></div>
        <div class="purse"><b>${fmt(info.left)}</b><small>Purse left</small></div></div>
      <div class="prog"><i style="width:${Math.min(100, info.count / minSquad * 100)}%"></i></div>
      <div class="needs">${needs ? `Still needs ${needs}` : 'Core squad complete'}</div>
      <ul class="roster">${rows.map(id => {
        const p = pl[id], s = l.sales[id];
        return `<li>${`<span class="cd" style="--c:${catColor(p.cat)}"></span>`}${avatar(p, 'sm')}<div class="rn"><b>${esc(p.name)}</b><small>${CAT_LABEL[p.cat]} · ${esc(p.role)}</small></div>
          ${s.pre ? '<span class="rp ret">Retained</span>' : `<span class="rp">${fmt(s.price)}</span><button class="rel" data-pid="${id}" title="Undo this sale">×</button>`}</li>`;
      }).join('')}</ul></article>`;
  }).join('');
}

/* ----- players tab ----- */
function renderPlayers() {
  const l = L();
  const mk = (arr, cur) => arr.map(([v, t]) => `<button class="chip ${cur === v ? 'on' : ''}" data-v="${v}">${t}</button>`).join('');
  $('#plCats').innerHTML = mk([['ALL', 'All'], ...CATS.map(c => [c, CAT_LABEL[c]])], plFilter.cat);
  $('#plStatus').innerHTML = mk([['ALL', 'Any status'], ['AVAIL', 'Available'], ['SOLD', 'Sold'], ['UNSOLD', 'Unsold']], plFilter.status);
  renderPlayerList();
}
function renderPlayerList() {
  const l = L(), pl = P[league];
  const rows = Object.values(pl).filter(p => {
    if (plFilter.cat !== 'ALL' && p.cat !== plFilter.cat) return false;
    if (plFilter.q && !p.name.toLowerCase().includes(plFilter.q)) return false;
    const s = l.sales[p.id], un = l.unsold.includes(p.id), onBlock = l.current && l.current.pid === p.id;
    const st = s ? 'SOLD' : un ? 'UNSOLD' : 'AVAIL';
    return plFilter.status === 'ALL' || plFilter.status === st || (plFilter.status === 'AVAIL' && onBlock);
  }).sort((a, b) => CATS.indexOf(a.cat) - CATS.indexOf(b.cat) || b.pts - a.pts);
  $('#plList').innerHTML = rows.length ? rows.map(p => {
    const s = l.sales[p.id], t = s && TEAMS[league][s.teamId];
    let st = `<div class="st">Available</div>`;
    if (l.current && l.current.pid === p.id) st = `<div class="st live">On the block</div>`;
    else if (s) st = `<div class="st sold">${crest(t, 'sm')}<span>${esc(t.name)}</span><span class="pr">${s.pre ? '' : fmt(s.price)}</span>${s.pre ? '<span style="margin-left:auto;color:var(--dim);font-size:11px;letter-spacing:.06em;text-transform:uppercase">Retained</span>' : ''}</div>`;
    else if (l.unsold.includes(p.id)) st = `<div class="st un">Unsold</div>`;
    return `<div class="prow"><div class="who">${avatar(p, 'sm')}<span>${esc(p.name)}</span></div><span class="cat" style="--c:${catColor(p.cat)}">${CAT_LABEL[p.cat]}</span><span>${esc(p.role)}</span><span class="r">${p.pts.toFixed(2)}</span>${st}</div>`;
  }).join('') : `<div class="pl-empty">No players match.</div>`;
}

/* ---------- result overlay + confetti ---------- */
let overlayTimer = 0;
function showResult(last) {
  const p = P[league][last.pid], ov = $('#overlay');
  clearTimeout(overlayTimer);
  if (last.type === 'sold') {
    const t = TEAMS[league][last.teamId];
    ov.innerHTML = `<div class="result" style="--tc:${t.color}"><div class="verdict">Sold</div><div class="rphoto">${avatar(p)}</div><h2>${esc(p.name)}</h2>
      <div class="to">${crest(t, 'sm')}<span>to <b>${esc(t.name)}</b></span></div><div class="rprice">${fmt(last.price)}</div></div>`;
    confetti(t.color);
  } else {
    ov.innerHTML = `<div class="result u" style="--tc:var(--UNSOLD)"><div class="verdict">Unsold</div><div class="rphoto">${avatar(p)}</div><h2>${esc(p.name)}</h2><div class="to">No bids — back later in the unsold round</div></div>`;
  }
  ov.hidden = false;
  overlayTimer = setTimeout(dismissOverlay, 5200);
}
function dismissOverlay() { clearTimeout(overlayTimer); $('#overlay').hidden = true; }

function confetti(teamColor) {
  const cv = $('#confetti'), ctx = cv.getContext('2d'), dpr = window.devicePixelRatio || 1;
  cv.width = innerWidth * dpr; cv.height = innerHeight * dpr; ctx.scale(dpr, dpr);
  const cols = ['#e3b04b', '#f3f6fb', teamColor, '#37b97f'];
  const bits = Array.from({ length: 130 }, () => ({
    x: innerWidth / 2 + (Math.random() - .5) * 200, y: innerHeight * .55, vx: (Math.random() - .5) * 15, vy: -Math.random() * 15 - 5,
    w: 5 + Math.random() * 6, h: 3 + Math.random() * 5, r: Math.random() * 6, vr: (Math.random() - .5) * .4, c: cols[Math.floor(Math.random() * cols.length)],
  }));
  let f = 0;
  (function step() {
    ctx.clearRect(0, 0, innerWidth, innerHeight);
    for (const b of bits) { b.vy += .35; b.vx *= .99; b.x += b.vx; b.y += b.vy; b.r += b.vr; ctx.save(); ctx.translate(b.x, b.y); ctx.rotate(b.r); ctx.fillStyle = b.c; ctx.globalAlpha = Math.max(0, 1 - f / 150); ctx.fillRect(-b.w / 2, -b.h / 2, b.w, b.h); ctx.restore(); }
    if (++f < 150) requestAnimationFrame(step); else ctx.clearRect(0, 0, innerWidth, innerHeight);
  })();
}

/* ---------- modals ---------- */
function openModal(html) { const m = $('#modal'); m.innerHTML = html; m.hidden = false; }
function closeModal() { const m = $('#modal'); m.hidden = true; m.innerHTML = ''; }
function toast(msg) { const t = $('#toast'); t.textContent = msg; t.hidden = false; clearTimeout(toast.t); toast.t = setTimeout(() => t.hidden = true, 3200); }

function openSettings() {
  const c = L().config, lk = v => +(v / 100000).toFixed(3);
  openModal(`<div class="dlg"><h3>Rules &amp; purse · ${league === 'men' ? "Men's" : "Women's"}</h3>
    <p>Amounts are in lakh (₹). Changes apply immediately to everyone.</p>
    <div class="grid">
      <div><label>Purse per team</label><input id="s-purse" type="number" step="0.5" min="0" value="${lk(c.purse)}"></div>
      <div><label>Max squad size</label><input id="s-max" type="number" step="1" min="1" value="${c.maxSquad}"></div>
    </div>
    <div class="rows"><span class="h">Category</span><span class="h">Players / team</span><span class="h">Base (lakh)</span><span class="h">Raise by (lakh)</span>
    ${CATS.map(k => `<span class="cn" style="--c:${catColor(k)}"><i></i>${CAT_LABEL[k]}</span>
      <input data-k="${k}" data-f="n" type="number" min="0" step="1" value="${c.quotas[k].n}">
      <input data-k="${k}" data-f="base" type="number" min="0" step="0.05" value="${lk(c.quotas[k].base)}">
      <input data-k="${k}" data-f="inc" type="number" min="0.05" step="0.05" value="${lk(c.inc[k])}">`).join('')}</div>
    <p class="note">Players per team counts retained players too. A team may only bid while it can still afford the base price of every slot it has left to fill.</p>
    <div class="foot"><button class="btn ghost" id="mClose">Cancel</button><button class="btn primary" id="mSave">Save</button></div></div>`);
  $('#mClose').onclick = closeModal;
  $('#mSave').onclick = async () => {
    const cfg = { purse: +$('#s-purse').value * 100000, maxSquad: +$('#s-max').value, quotas: {}, inc: {} };
    document.querySelectorAll('#modal input[data-k]').forEach(i => {
      const k = i.dataset.k, f = i.dataset.f; cfg.quotas[k] = cfg.quotas[k] || {};
      if (f === 'inc') cfg.inc[k] = +i.value * 100000; else cfg.quotas[k][f] = f === 'n' ? +i.value : +i.value * 100000;
    });
    const r = await act('settings', { config: cfg }); if (r && r.ok) closeModal();
  };
}

function openReset() {
  openModal(`<div class="dlg"><h3>Reset ${league === 'men' ? "men's" : "women's"} auction</h3>
    <p>Every sale and unsold mark is wiped and the wheel starts again. Retained players stay with their teams. Settings are kept.</p>
    <label for="rs">Type RESET to confirm</label><input id="rs" autocomplete="off">
    <div class="err" id="rsErr"></div>
    <div class="foot"><button class="btn ghost" id="mClose">Cancel</button><button class="btn sold" id="rsGo" style="background:var(--bad);color:#fff">Reset auction</button></div></div>`);
  $('#mClose').onclick = closeModal;
  $('#rsGo').onclick = async () => { const r = await act('reset', { confirm: $('#rs').value.trim() }); if (r && r.ok) closeModal(); else if (r) $('#rsErr').textContent = r.error; };
}

/* keep clocks honest: re-render once the reveal moment passes (e.g. page opened mid-spin) */
setInterval(() => { const l = S[league]; if (l && l.current && tab === 'auction' && !$('#pBlock').hidden !== revealed()) renderAll(); }, 500);
})();
