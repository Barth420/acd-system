'use strict';
/* ACD containment dashboard. Vanilla JS, no build step, no CDN.
   Alert text (service names, attack types, IPs) all comes from typed/validated fields, but we still only ever
   use textContent/createTextNode -- never innerHTML -- as a matter of habit for anything rendering alert data. */

const $ = (s, r = document) => r.querySelector(s);
const MODES = ['normal', 'rate_limited', 'read_only', 'fallback', 'isolated'];

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
const clear = n => { while (n.firstChild) n.removeChild(n.firstChild); return n; };
async function api(path, base = '') {
  const r = await fetch(base + path);
  if (!r.ok) throw new Error(path + ': ' + r.status);
  return r.json();
}
async function post(path) {
  const r = await fetch(path, { method: 'POST' });
  let j = null; try { j = await r.json(); } catch (e) { /* no body */ }
  if (!r.ok) throw new Error((j && j.error) || r.statusText);
  return j;
}

const S = { topo: null, ctlUrl: '', selectedOrigin: null, selectedActions: [] };

/* ── tabs ───────────────────────────────────────────────────────────────── */
document.querySelectorAll('#tabs button').forEach(b => b.addEventListener('click', () => {
  document.querySelectorAll('#tabs button').forEach(x => x.classList.toggle('active', x === b));
  document.querySelectorAll('.tab').forEach(t => t.classList.toggle('active', t.id === 'tab-' + b.dataset.tab));
  refresh();
}));
function activeTab() { return document.querySelector('#tabs button.active').dataset.tab; }

/* ── graph (shared by Overview and Forensics) ──────────────────────────── */
function layout(services, W, H) {
  const tiers = {};
  services.forEach(s => (tiers[s.tier ?? 1] = tiers[s.tier ?? 1] || []).push(s.name));
  const keys = Object.keys(tiers).map(Number).sort((a, b) => a - b);
  const pos = {};
  keys.forEach((t, row) => { const names = tiers[t];
    names.forEach((n, i) => { pos[n] = { x: ((i + 1) * W) / (names.length + 1), y: 50 + row * ((H - 100) / Math.max(1, keys.length - 1)), tier: t }; }); });
  return pos;
}
function drawGraph(svg, services, opts = {}) {
  clear(svg);
  if (!services || !services.length) { svg.append(svgEl('text', { x: 20, y: 30, fill: 'var(--muted)' }, 'no topology yet')); return; }
  const W = 760, H = 340, NW = 122, NH = 44;
  const pos = layout(services, W, H);
  const uid = svg.id;
  svg.append(svgEl('defs', {}, svgEl('marker', { id: 'arr-' + uid, viewBox: '0 0 10 10', refX: 9, refY: 5, markerWidth: 7, markerHeight: 7, orient: 'auto-start-reverse' },
    svgEl('path', { d: 'M0,0 L10,5 L0,10 z', fill: 'var(--muted)' }))));
  const cut = new Set((opts.cutEdges || []).map(e => e.from + '->' + e.to));
  const edgeD = (a, b) => {
    const p = pos[a], q = pos[b]; if (!p || !q) return null;
    if (p.tier === q.tier) { const y = p.y - NH / 2; return `M${p.x},${y} Q${(p.x + q.x) / 2},${y - 55} ${q.x},${q.y - NH / 2 - 2}`; }
    const dir = q.y > p.y ? 1 : -1; return `M${p.x},${p.y + dir * NH / 2} L${q.x},${q.y - dir * (NH / 2 + 3)}`;
  };
  for (const e of opts.edges || []) {
    const d = edgeD(e.from, e.to); if (!d) continue;
    const isCut = cut.has(e.from + '->' + e.to);
    svg.append(svgEl('path', { d, class: 'edge' + (isCut ? ' cut' : ''), 'marker-end': `url(#arr-${uid})` }, svgEl('title', {}, `${e.from} -> ${e.to}` + (isCut ? ' (CUT)' : ''))));
  }
  for (const e of opts.pathEdges || []) {
    const p = pos[e.from], q = pos[e.to]; if (!p || !q) continue;
    const mx = (p.x + q.x) / 2, my = (p.y + q.y) / 2 - (p.tier === q.tier ? 30 : 0);
    svg.append(svgEl('path', { d: `M${p.x},${p.y} Q${mx},${my} ${q.x},${q.y}`, class: 'edge path' + (e.inferred ? ' inferred' : ''), 'marker-end': `url(#arr-${uid})` },
      svgEl('title', {}, `${e.from} -> ${e.to}` + (e.inferred ? ' (inferred)' : ''))));
  }
  const highlightSet = new Set(opts.highlightEdges || []);
  for (const key of highlightSet) {
    const [a, b] = key.split('->'); const d = edgeD(a, b); if (!d) continue;
    svg.append(svgEl('path', { d, class: 'edge cut', 'marker-end': `url(#arr-${uid})`, style: 'stroke-width:3' }, svgEl('title', {}, `${a} -> ${b} (cut by this decision)`)));
  }
  for (const s of services) {
    const p = pos[s.name];
    const mode = (opts.modes && opts.modes[s.name]) || 'unknown';
    const col = `var(--m-${MODES.includes(mode) ? mode : 'unknown'})`;
    const isOrigin = opts.origin === s.name;
    svg.append(svgEl('g', { class: 'node' + (isOrigin ? ' origin' : ''), transform: `translate(${p.x - NW / 2},${p.y - NH / 2})` },
      svgEl('rect', { width: NW, height: NH, rx: 8, style: `stroke:${col}` }),
      svgEl('text', { x: NW / 2, y: 18 }, s.name),
      svgEl('text', { x: NW / 2, y: 35, class: 'mode', style: `fill:${col}` }, opts.modes ? mode.replace('_', ' ') : (s.sensitivity || '')),
      svgEl('title', {}, `${s.name}: tier ${s.tier}` + (opts.modes ? `, mode ${mode}` : ''))));
  }
}
function drawLegend(node) {
  clear(node);
  for (const m of [...MODES, 'unknown']) node.append(el('span', { style: `--c:var(--m-${m})`, text: m.replace('_', ' ') }));
  node.append(el('span', { style: '--c:var(--bad)', text: 'cut edge / this decision' }));
  node.append(el('span', { style: '--c:var(--accent)', text: 'origin / attack path' }));
}

/* ── overview ───────────────────────────────────────────────────────────── */
async function renderOverview() {
  const pipe = $('#pipe-pill'); pipe.textContent = 'pipeline: up'; pipe.className = 'pill ok';
  let topo, state, ctlUp = true;
  try {
    const cfg = await api('/api/config');
    S.ctlUrl = cfg.controller_url;
    $('#autonomy-pill').textContent = 'autonomy: ' + cfg.autonomy;
    // same-origin proxy (/api/lab/*), not a direct cross-origin call to the controller: works regardless of
    // which port the pipeline runs on, and never depends on the controller's CORS allowlist.
    topo = await api('/api/lab/topology');
    state = await api('/api/lab/state');
  } catch (e) { ctlUp = false; }
  const ctl = $('#ctl-pill'); ctl.textContent = 'controller: ' + (ctlUp ? 'up' : 'unreachable'); ctl.className = 'pill ' + (ctlUp ? 'ok' : 'bad');
  if (ctlUp) {
    S.topo = topo;
    const modes = {}; Object.entries(state.services || {}).forEach(([n, v]) => modes[n] = v.mode);
    drawGraph($('#graph'), topo.services, { edges: topo.edges, cutEdges: state.cut_edges, modes,
      origin: S.selectedOrigin, highlightEdges: S.selectedActions });
  } else {
    drawGraph($('#graph'), null);
  }
  drawLegend($('#legend'));

  const incidents = await api('/incidents?limit=20');
  const t = clear($('#incident-feed'));
  t.append(el('tr', {}, ['time', 'service', 'attack type', 'severity', 'source ip'].map(h => el('th', { text: h }))));
  if (!incidents.items.length) t.append(el('tr', {}, el('td', { colspan: '5', class: 'small', text: 'no incidents yet' })));
  incidents.items.forEach(i => {
    const row = el('tr', { style: 'cursor:pointer' },
      el('td', { class: 'small', text: i.created_at }), el('td', { text: i.service }), el('td', { text: i.attack_type }),
      el('td', { class: 'sev-' + i.severity, text: i.severity }), el('td', { class: 'mono', text: i.source_ip }));
    row.title = 'click to highlight this service on the graph above';
    row.addEventListener('click', () => { S.selectedOrigin = i.service; S.selectedActions = []; renderOverview(); });
    t.append(row);
  });
}

/* ── containment ────────────────────────────────────────────────────────── */
function statusClass(s) { return 'status-' + s; }
function decisionCard(d) {
  const header = el('h3', {}, `${d.compromised_service} · ${d.attack_type} (${d.severity})`,
    el('span', { class: 'status-pill ' + statusClass(d.status), text: d.status.replace('_', ' ') }));
  const approve = d.status === 'pending_approval'
    ? el('button', { class: 'primary', text: 'Approve', onclick: async e => {
        e.target.disabled = true;
        try { await post(`/api/decisions/${d.decision_id}/approve`); } catch (err) { alert(err.message); }
        refresh();
      } }) : null;
  const showBtn = el('button', { text: 'Show on graph', onclick: () => {
    S.selectedOrigin = d.compromised_service;
    S.selectedActions = d.actions.filter(a => a.type === 'cut_edge').map(a => a.target);
    document.querySelector('[data-tab=overview]').click();
  } });
  const actionsTable = el('table', {},
    el('tr', {}, ['action', 'target', 'mode', 'reason', 'result'].map(h => el('th', { text: h }))),
    d.actions.length ? d.actions.map(a => el('tr', {}, el('td', { text: a.type }), el('td', { class: 'mono', text: a.target }),
      el('td', { text: a.mode || '' }), el('td', { class: 'small', text: a.reason }),
      el('td', { class: a.result && !a.result.startsWith('ok') && a.result !== 'ok' ? 'bad' : 'ok', text: a.result || '(not yet run)' })))
      : [el('tr', {}, el('td', { colspan: '5', class: 'small', text: 'no actions (severity/attack type did not warrant one)' }))]);
  const brain = brainSection(d.brain_response);
  return el('div', { class: 'decision' }, header,
    el('div', { class: 'small', text: d.rationale }),
    el('div', { class: 'small mono', text: `decision_id=${d.decision_id}  incident_id=${d.incident_id}  source_ip=${d.source_ip}  required capability: ${d.required_capability.join(', ') || '(none)'}` }),
    actionsTable,
    brain,
    el('div', { class: 'row', style: 'margin-top:8px' }, showBtn, approve));
}

function brainSection(b) {
  // Only renders for a genuine model response. No box at all for template/off/unavailable --
  // nothing stating backend status is shown in the UI; see docs/bhavya/CONTAINMENT.md for the real status.
  if (!b || !b.available || b.backend === 'template') return null;
  const box = el('div', { class: 'brain' + (b.available ? '' : ' brain-unavailable') });
  box.append(el('h4', {}, 'What the LLM said', el('span', { class: 'small', text: '  (backend: ' + b.backend + ')' })));
  if (!b.available) {
    box.append(el('div', { class: 'small bad', text: 'Not available: ' + (b.reason || 'unknown reason') }));
  }
  box.append(el('div', { class: 'brain-text', text: b.text }));
  if (b.caveat) box.append(el('div', { class: 'small warn', text: '⚠ ' + b.caveat }));
  if (b.model) box.append(el('div', { class: 'small mono', text: `model: ${b.model}` + (b.latency_s != null ? `  ·  ${b.latency_s}s` : '') }));
  box.append(el('div', { class: 'small', text: 'This text is advisory only. The mode and edge cuts above were decided by the deterministic planner, not by this text.' }));
  return box;
}
async function renderContainment() {
  const out = await api('/api/decisions?limit=50');
  const box = clear($('#decisions'));
  if (!out.items.length) { box.append(el('div', { class: 'small', text: 'No containment decisions yet. They appear automatically when an alert names a known service.' })); return; }
  out.items.forEach(d => box.append(decisionCard(d)));
}

/* ── forensics ──────────────────────────────────────────────────────────── */
async function renderForensics(query = {}) {
  const params = new URLSearchParams(query);
  const rec = await api('/api/forensics' + (params.toString() ? '?' + params : ''));
  $('#f-summary').textContent = rec.steps.length
    ? `origin: ${rec.origin_service}  ·  ${rec.steps.length} step(s)  ·  path: ${rec.attack_path.join(' → ')}`
    : 'no alerts in range';
  if (S.topo) {
    const modes = {}; // forensics graph shows the path, not live modes, to avoid implying "this is happening now"
    drawGraph($('#f-graph'), S.topo.services, { edges: S.topo.edges, pathEdges: rec.overlay_edges, origin: rec.origin_service });
  }
  const t = clear($('#f-timeline'));
  t.append(el('tr', {}, ['time', 'service', 'attack type', 'severity', 'source ip', 'count', 'contained'].map(h => el('th', { text: h }))));
  rec.steps.forEach(s => t.append(el('tr', {},
    el('td', { class: 'small', text: s.first_ts }), el('td', { text: s.service }), el('td', { text: s.attack_type }),
    el('td', { class: 'sev-' + s.severity, text: s.severity }), el('td', { class: 'mono', text: s.source_ip }),
    el('td', { text: s.count }), el('td', { class: s.contained ? 'ok' : 'bad', text: s.contained ? 'yes' : 'no' }))));
}
$('#f-go').addEventListener('click', () => renderForensics($('#f-ip').value.trim() ? { ip: $('#f-ip').value.trim() } : {}));

/* ── refresh loop ───────────────────────────────────────────────────────── */
async function refresh() {
  try {
    const tab = activeTab();
    if (tab === 'overview') await renderOverview();
    else if (tab === 'containment') await renderContainment();
    else if (tab === 'forensics') { if (!S.topo) await renderOverview(); await renderForensics(); }
  } catch (e) {
    const p = $('#pipe-pill'); p.textContent = 'pipeline unreachable'; p.className = 'pill bad';
  }
}
refresh();
setInterval(refresh, 3000);
