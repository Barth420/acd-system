'use strict';
/* ACD lab console. Vanilla JS, no build, no CDN, works inside an iframe (same-origin calls to the controller).
   Every dynamic value is inserted with textContent / createTextNode through el(): scenario text and log entries can carry
   attacker-style strings, so innerHTML is never used. */

const $ = (s, r = document) => r.querySelector(s);
const MODES = ['normal', 'rate_limited', 'read_only', 'fallback', 'isolated'];
const ACTOR = { 'X-Actor': 'lab-console' };

function el(tag, props = {}, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (v == null) continue;
    if (k === 'class') n.className = v; else if (k === 'text') n.textContent = v;
    else if (k.startsWith('on')) n.addEventListener(k.slice(2), v); else n.setAttribute(k, v);
  }
  for (const c of kids.flat()) if (c != null) n.append(c.nodeType ? c : document.createTextNode(String(c)));
  return n;
}
function svgEl(tag, attrs = {}, ...kids) {
  const n = document.createElementNS('http://www.w3.org/2000/svg', tag);
  for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v);
  for (const c of kids.flat()) if (c != null) n.append(c.nodeType ? c : document.createTextNode(String(c)));
  return n;
}
const put = (n, ...kids) => { for (const c of kids.flat()) n.append(c); return n; };   // append() would stringify arrays
const clear = n => { while (n.firstChild) n.removeChild(n.firstChild); return n; };
async function api(path, opts = {}) {
  const r = await fetch(path, { ...opts, headers: { 'Content-Type': 'application/json', ...ACTOR, ...(opts.headers || {}) } });
  let j = null; try { j = await r.json(); } catch (e) { /* no body */ }
  if (!r.ok) throw new Error((j && (j.error || j.detail)) || r.statusText);
  return j;
}
const post = (p, b) => api(p, { method: 'POST', body: JSON.stringify(b || {}) });
const pct = v => (v == null ? 'n/a' : Math.round(v * 100) + '%');
function say(text, cls) { const m = $('#msg'); m.textContent = text; m.className = 'small ' + (cls || ''); }

const S = { topo: null, state: null, health: null, sel: 'auth_api', runId: null, scenarios: [] };

/* ── graph ──────────────────────────────────────────────────────────────── */
function drawGraph() {
  const svg = clear($('#graph')); if (!S.topo || !S.state) return;
  const W = 760, H = 340, NW = 122, NH = 44;
  const tiers = {}; S.topo.services.forEach(s => (tiers[s.tier] = tiers[s.tier] || []).push(s.name));
  const keys = Object.keys(tiers).map(Number).sort((a, b) => a - b), pos = {};
  keys.forEach((t, row) => tiers[t].forEach((n, i) => { pos[n] = { x: ((i + 1) * W) / (tiers[t].length + 1), y: 48 + row * ((H - 96) / Math.max(1, keys.length - 1)), tier: t }; }));
  svg.append(svgEl('defs', {}, svgEl('marker', { id: 'arr', viewBox: '0 0 10 10', refX: 9, refY: 5, markerWidth: 7, markerHeight: 7, orient: 'auto-start-reverse' }, svgEl('path', { d: 'M0,0 L10,5 L0,10 z', fill: 'var(--muted)' }))));
  const cut = new Set(S.state.cut_edges.map(e => e.from + '->' + e.to));
  const path = (a, b) => {
    const p = pos[a], q = pos[b];
    if (p.tier === q.tier) { const y = p.y - NH / 2; return `M${p.x},${y} Q${(p.x + q.x) / 2},${y - 55} ${q.x},${q.y - NH / 2 - 2}`; }
    const d = q.y > p.y ? 1 : -1; return `M${p.x},${p.y + d * NH / 2} L${q.x},${q.y - d * (NH / 2 + 3)}`;
  };
  const edges = [...S.topo.edges];
  for (const e of S.state.cut_edges) if (!edges.find(x => x.from === e.from && x.to === e.to)) edges.push(e);   // cuts on undeclared (lateral) edges
  for (const e of edges) svg.append(svgEl('path', { d: path(e.from, e.to), class: 'edge' + (cut.has(e.from + '->' + e.to) ? ' cut' : ''), 'marker-end': 'url(#arr)' },
    svgEl('title', {}, `${e.from} -> ${e.to}` + (cut.has(e.from + '->' + e.to) ? ' (CUT)' : ''))));
  for (const s of S.topo.services) {
    const st = S.state.services[s.name], p = pos[s.name], col = `var(--m-${st.mode})`;
    svg.append(svgEl('g', { class: 'node' + (S.sel === s.name ? ' sel' : '') + (st.isolated ? ' detached' : ''), transform: `translate(${p.x - NW / 2},${p.y - NH / 2})` },
      svgEl('rect', { width: NW, height: NH, rx: 8, style: `stroke:${col}` }),
      svgEl('text', { x: NW / 2, y: 18 }, s.name),
      svgEl('text', { x: NW / 2, y: 35, class: 'mode', style: `fill:${col}` }, st.mode.replace('_', ' ') + (st.up ? '' : ' · down')),
      svgEl('title', {}, `${s.name}: tier ${s.tier}, ${s.sensitivity}, ${s.exposure}, port ${s.port}`)));
    svg.lastChild.addEventListener('click', () => { S.sel = s.name; $('#svc').value = s.name; render(); });
  }
}

/* ── panels ─────────────────────────────────────────────────────────────── */
function renderHealth() {
  const h = S.health; if (!h) return;
  $('#overall').textContent = pct(h.overall_availability);
  const t = clear($('#journeys'));
  put(t, el('tr', {}, ['journey', 'ok (30 s)', 'last', 'path'].map(x => el('th', { text: x }))),
    h.journeys.map(j => el('tr', {}, el('td', { text: j.name }), el('td', { class: j.ok_rate_30s >= 0.95 ? 'ok' : (j.ok_rate_30s > 0 ? 'warn' : 'bad'), text: pct(j.ok_rate_30s) }), el('td', { text: j.last_status }), el('td', { class: 'small mono', text: j.path }))));
  const c = clear($('#services'));
  for (const [n, v] of Object.entries(h.services)) c.append(el('span', { class: 'chip ' + (v.ok ? 'ok' : 'bad'), text: `${n} ${pct(v.ok_rate_30s)}` }));
}
function renderControls() {
  if (!S.state) return;
  const st = S.state.services[S.sel];
  $('#svc-now').textContent = `now: ${st.mode}${st.isolated ? ' (detached from networks)' : ''}${st.up ? '' : ' · down'}`;
  const m = clear($('#modes'));
  MODES.forEach(x => m.append(el('button', { class: x === st.mode ? 'on' : '', text: x.replace('_', ' '), onclick: async () => { try { const r = await post(`/services/${S.sel}/mode`, { mode: x }); say(`${S.sel} -> ${x} (${r.network_isolation})`, 'ok'); } catch (e) { say(e.message, 'bad'); } refresh(); } })));
  $('#cuts').textContent = S.state.cut_edges.length ? 'cut: ' + S.state.cut_edges.map(e => `${e.from}->${e.to}`).join(', ') : 'no edges cut';
}
function renderActions(list) {
  const t = clear($('#actions'));
  put(t, el('tr', {}, ['time', 'actor', 'action', 'args', 'result'].map(x => el('th', { text: x }))),
    [...list].reverse().slice(0, 40).map(a => el('tr', {}, el('td', { class: 'mono', text: a.ts.slice(11, 23) }), el('td', { text: a.actor }), el('td', { text: a.action }), el('td', { class: 'mono', text: JSON.stringify(a.args) }), el('td', { class: a.result === 'ok' ? 'ok' : 'bad', text: a.result }))));
}
function render() { drawGraph(); renderHealth(); renderControls(); }

/* ── scenarios / live run ───────────────────────────────────────────────── */
async function loadScenarios() {
  try {
    S.scenarios = await api('/scenarios');
    const sel = clear($('#scenario'));
    S.scenarios.forEach(s => sel.append(el('option', { value: s.id, text: `${s.id} · ${s.name}` })));
    const d = () => { const s = S.scenarios.find(x => x.id === sel.value); $('#scn-desc').textContent = s ? s.description : ''; };
    sel.addEventListener('change', d); d();
  } catch (e) { $('#scn-desc').textContent = 'scenarios unavailable: ' + e.message; }
}
function outcomeClass(o) { return { succeeded: 'bad', blocked_by_containment: 'ok', failed: 'warn' }[o] || ''; }
async function renderRun() {
  if (!S.runId) return;
  try {
    const [run, gt] = await Promise.all([api('/runs/' + S.runId), api(`/runs/${S.runId}/ground-truth`)]);
    $('#run-info').textContent = `${run.scenario_id} · ${run.status} · ${S.runId}`;
    const t = clear($('#steps'));
    put(t, el('tr', {}, ['#', 't+s', 'source', 'target', 'technique', 'capability', 'expected type', 'outcome', 'blocked by', 'inj'].map(x => el('th', { text: x }))),
      gt.steps.map(s => el('tr', {}, el('td', { text: s.step }), el('td', { text: s.t_offset_s }), el('td', { text: s.source }), el('td', { text: s.target_service }), el('td', { text: s.technique }),
        el('td', { text: s.requires_capability }), el('td', { text: s.expected_attack_type }), el('td', { class: outcomeClass(s.outcome), text: s.outcome }),
        el('td', { class: 'mono', text: s.blocked_by ? `${s.blocked_by.service} (${s.blocked_by.mode})` : '' }), el('td', { text: s.injection_payload ? 'yes' : '' }))));
    $('#gt-summary').textContent = `compromised: ${gt.compromised_services.map(c => c.service).join(', ') || 'none'}   ·   attack path: ${gt.attack_path.join(' → ') || '(empty)'}`;
  } catch (e) { $('#run-info').textContent = e.message; }
}
$('#run').addEventListener('click', async () => {
  const seed = $('#seed').value === '' ? null : Number($('#seed').value);
  try { const r = await post(`/scenarios/${$('#scenario').value}/run`, { seed }); S.runId = r.run_id; say('run started ' + r.run_id, 'ok'); renderRun(); }
  catch (e) { say(e.message, 'bad'); }
});
$('#stop').addEventListener('click', async () => { if (S.runId) { try { await post(`/runs/${S.runId}/stop`); } catch (e) { say(e.message, 'bad'); } } });

/* ── buttons ────────────────────────────────────────────────────────────── */
$('#traffic-on').addEventListener('click', async () => { try { await post('/traffic/start', { rate_per_s: Number($('#rate').value) || 5 }); say('traffic started', 'ok'); } catch (e) { say(e.message, 'bad'); } refresh(); });
$('#traffic-off').addEventListener('click', async () => { try { await post('/traffic/stop'); say('traffic stopped', 'ok'); } catch (e) { say(e.message, 'bad'); } refresh(); });
$('#reset').addEventListener('click', async () => { if (confirm('Reset all modes, edges and credentials?')) { try { await post('/reset'); say('lab reset', 'ok'); } catch (e) { say(e.message, 'bad'); } refresh(); } });
$('#rotate').addEventListener('click', async () => { try { const r = await post(`/services/${S.sel}/rotate-credentials`); say(`${S.sel}: credentials rotated (generation ${r.generation})`, 'ok'); } catch (e) { say(e.message, 'bad'); } refresh(); });
for (const [id, cut] of [['#cut', true], ['#restore', false]]) $(id).addEventListener('click', async () => {
  try { await post(cut ? '/edges/cut' : '/edges/restore', { from: $('#e-from').value, to: $('#e-to').value }); say(`${cut ? 'cut' : 'restored'} ${$('#e-from').value} -> ${$('#e-to').value}`, 'ok'); }
  catch (e) { say(e.message, 'bad'); } refresh();
});
$('#svc').addEventListener('change', e => { S.sel = e.target.value; render(); });

/* ── refresh loop ───────────────────────────────────────────────────────── */
async function init() {
  S.topo = await api('/topology');
  for (const id of ['#svc', '#e-from', '#e-to']) { const s = clear($(id)); S.topo.services.forEach(x => s.append(el('option', { value: x.name, text: x.name }))); }
  $('#svc').value = S.sel; $('#e-from').value = 'order_api'; $('#e-to').value = 'queue';
  const lg = clear($('#legend')); MODES.forEach(m => lg.append(el('span', { style: `--c:var(--m-${m})`, text: m.replace('_', ' ') }))); lg.append(el('span', { style: '--c:var(--bad)', text: 'cut edge (dashed red)' }));
  loadScenarios();
}
async function refresh() {
  try {
    [S.state, S.health] = await Promise.all([api('/state'), api('/health')]);
    const p = $('#status'); p.textContent = 'controller up'; p.className = 'pill ok';
    render(); renderActions(await api('/actions')); renderRun();
  } catch (e) { const p = $('#status'); p.textContent = 'controller unreachable'; p.className = 'pill bad'; }
}
init().then(refresh).catch(e => { $('#status').textContent = 'init failed: ' + e.message; });
setInterval(refresh, 2000);
