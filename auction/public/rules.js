/* Auction rules shared by the server (authoritative) and the browser (to grey
 * out teams that cannot bid). All money is stored in whole rupees. */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.Rules = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  const CATS = ['PLATINUM', 'GOLD', 'SILVER', 'BRONZE'];
  const CAT_LABEL = { PLATINUM: 'Platinum', GOLD: 'Gold', SILVER: 'Silver', BRONZE: 'Bronze', UNSOLD: 'Unsold' };

  /* Everything a team currently holds, pre-assigned players included. */
  function teamInfo(L, P, teamId) {
    const pids = [];
    let spent = 0;
    const byCat = { PLATINUM: 0, GOLD: 0, SILVER: 0, BRONZE: 0 };
    for (const pid in L.sales) {
      const s = L.sales[pid];
      if (s.teamId !== teamId) continue;
      pids.push(pid);
      spent += s.price;
      byCat[P[pid].cat]++;
    }
    const needs = {};
    let needTotal = 0, reserve = 0;
    for (const c of CATS) {
      const q = L.config.quotas[c];
      needs[c] = Math.max(0, q.n - byCat[c]);
      needTotal += needs[c];
      reserve += needs[c] * q.base;
    }
    return { pids, spent, left: L.config.purse - spent, count: pids.length, byCat, needs, needTotal, reserve };
  }

  /* Can this team bid on this player, and what is the most it may pay?
   * A team must always keep enough purse to fill its remaining mandatory
   * slots at base price, so the ceiling is purse - reserve for the others. */
  function eligibility(L, P, teamId, player) {
    const t = teamInfo(L, P, teamId);
    const cfg = L.config, cat = player.cat, q = cfg.quotas[cat];
    const base = q.base;
    const out = { teamId, min: base, max: 0, ok: false, reason: '', info: t };
    if (t.count >= cfg.maxSquad) { out.reason = 'Squad full'; return out; }
    let reserve = t.reserve;
    if (t.byCat[cat] < q.n) reserve -= base; // this purchase fills one mandatory slot
    else if (cat !== 'BRONZE') { out.reason = CAT_LABEL[cat] + ' quota full'; return out; }
    out.max = t.left - reserve;
    if (out.max < base) { out.reason = 'Purse too low'; return out; }
    out.ok = true;
    return out;
  }

  const inCurrent = (L, pid) => !!(L.current && L.current.pid === pid);

  /* Players still waiting to be drawn in a category (or the unsold re-run). */
  function pool(L, P, cat) {
    if (cat === 'UNSOLD') return L.unsold.filter(pid => !inCurrent(L, pid));
    const out = [];
    for (const pid in P) {
      const p = P[pid];
      if (p.cat === cat && !L.sales[pid] && !inCurrent(L, pid) && L.unsold.indexOf(pid) < 0) out.push(pid);
    }
    return out;
  }

  /* How many auctionable (non pre-assigned) players the category started with. */
  function poolTotal(P, cat) {
    let n = 0;
    for (const pid in P) if (P[pid].cat === cat && !P[pid].pre) n++;
    return n;
  }

  function currentBid(L) {
    const c = L.current;
    return c && c.bids.length ? c.bids[c.bids.length - 1] : null;
  }

  function fmt(n) {
    if (!n) return '₹0';
    if (n < 100000) return '₹' + +(n / 1000).toFixed(1) + 'K';
    return '₹' + +(n / 100000).toFixed(2) + 'L';
  }

  return { CATS, CAT_LABEL, teamInfo, eligibility, pool, poolTotal, currentBid, fmt };
});
