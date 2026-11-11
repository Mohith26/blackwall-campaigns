// Campaigns core: find distributed bot campaigns that rotate IPs, and turn each into a
// Blackwall Custom Rule with measured collateral on verified humans. Pure functions; used by
// the build script (node), the tests and the app (browser).
//
// Sessions are rows of categorical attributes (TLS/HTTP2 fingerprints, header order, headers,
// path, domain, ASN, behaviour). Detection = contrast-set mining against a randomized
// verification holdout, with exact binomial bounds and family-wise multiple-testing control.

export const FIELDS = ['ja4', 'h2', 'hdr', 'chua', 'al', 'ua', 'path', 'asn', 'cc', 'dom', 'cookie', 'js', 'cadence'];
// Fields a Blackwall Custom Rule can express today (docs: Custom Rules editor).
export const RULE_FIELDS = {
  ua: { label: 'User-Agent', op: 'Is any of' },
  chua: { label: 'HTTP Header · sec-ch-ua', op: 'Is' },
  al: { label: 'HTTP Header · Accept-Language', op: 'Is' },
  path: { label: 'URI Path', op: 'Matches to expression' },
  dom: { label: 'Domain', op: 'Is any of' },
  asn: { label: 'Autonomous System Number', op: 'Is any of' },
  cc: { label: 'Country Code', op: 'Is any of' },
  // Signals GateKeeper sees but the rule editor cannot express yet (proposed fields).
  ja4: { label: 'TLS fingerprint (JA4)', op: 'Is', proposed: true },
  h2: { label: 'HTTP/2 fingerprint', op: 'Is', proposed: true },
  hdr: { label: 'Header order', op: 'Is', proposed: true },
};

export function mulberry32(seed) {
  let a = seed >>> 0;
  return function () {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

// ---------------------------------------------------------------------------------------
// Contrast-set mining against a randomized verification holdout.
// A random share of sessions is challenged (invisible JS / CAPTCHA). Among challenged sessions,
// humans pass and bots almost never do, so for any attribute combination X the pass rate among
// its challenged sessions estimates the human share of X, with an exact binomial bound.
// A campaign is a combination that (a) spans many IPs and (b) is provably bot-dominated.
// ---------------------------------------------------------------------------------------

export const MINE_FIELDS = ['ja4', 'h2', 'hdr', 'chua', 'al', 'ua', 'path', 'dom', 'asn'];

// Level-wise enumeration of conjunctions (up to maxLen conditions on distinct fields) with
// support >= minSup among `eligible` sessions. Returns [{conds:[[field,val],...], n, h, p, ipCount}].
export function mineItemsets(table, { fields = MINE_FIELDS, minSup = 60, maxLen = 3, eligible = null } = {}) {
  const n = table.n;
  const elig = eligible || new Uint8Array(n).fill(1);
  const F = fields.length;
  // level 1 counts
  const c1 = fields.map(() => new Map());
  for (let i = 0; i < n; i++) if (elig[i]) fields.forEach((f, fi) => { const v = table.cols[f][i]; c1[fi].set(v, (c1[fi].get(v) || 0) + 1); });
  const freq1 = fields.map((f, fi) => new Set([...c1[fi].entries()].filter(([, c]) => c >= minSup).map(([v]) => v)));
  const stats = new Map(); // key -> {conds, n, h, p, ips:Set}
  const bump = (key, conds, i) => {
    let st = stats.get(key);
    if (!st) { st = { conds, n: 0, h: [0, 0], p: [0, 0], ips: new Set() }; stats.set(key, st); }
    const sp = table.cols.split[i];
    st.n++; st.h[sp] += table.cols.holdout[i]; st.p[sp] += table.cols.verified[i]; st.ips.add(table.cols.ip[i]);
  };
  // count all itemsets up to maxLen whose singletons are frequent (exact counts, then filter)
  const items = new Array(F);
  const cnt2 = new Map();
  for (let i = 0; i < n; i++) {
    if (!elig[i]) continue;
    let k = 0;
    for (let fi = 0; fi < F; fi++) { const v = table.cols[fields[fi]][i]; if (freq1[fi].has(v)) items[k++] = fi * 100000 + v; }
    for (let a = 0; a < k; a++) {
      bump('' + items[a], [items[a]], i);
      if (maxLen < 2) continue;
      for (let b = a + 1; b < k; b++) {
        const kb = items[a] + '|' + items[b];
        cnt2.set(kb, (cnt2.get(kb) || 0) + 1);
      }
    }
  }
  if (maxLen >= 2) {
    const freq2 = new Set([...cnt2.entries()].filter(([, c]) => c >= minSup).map(([k]) => k));
    for (let i = 0; i < n; i++) {
      if (!elig[i]) continue;
      let k = 0;
      for (let fi = 0; fi < F; fi++) { const v = table.cols[fields[fi]][i]; if (freq1[fi].has(v)) items[k++] = fi * 100000 + v; }
      for (let a = 0; a < k; a++) for (let b = a + 1; b < k; b++) {
        const kab = items[a] + '|' + items[b];
        if (!freq2.has(kab)) continue;
        bump(kab, [items[a], items[b]], i);
        if (maxLen < 3) continue;
        for (let c = b + 1; c < k; c++) {
          if (!freq2.has(items[a] + '|' + items[c]) || !freq2.has(items[b] + '|' + items[c])) continue;
          bump(kab + '|' + items[c], [items[a], items[b], items[c]], i);
        }
      }
    }
  }
  const out = [];
  for (const st of stats.values()) if (st.n >= minSup) out.push({ conds: st.conds.map((x) => [fields[Math.floor(x / 100000)], x % 100000]), n: st.n, h: st.h, p: st.p, ipCount: st.ips.size });
  return out;
}

// Upper confidence bound on the human share of a set of sessions from its challenged sessions:
// Clopper-Pearson bound on the pass rate, divided by the human pass rate.
export function humanShareUpper(p, h, alphaEach, humanPass = 0.985) {
  return Math.min(1, cpUpper(p, h, alphaEach) / humanPass);
}
// Smallest number of additional challenged sessions (all failing) after which the bound would
// drop to theta: used to tell the operator how much targeted challenging a suspect needs.
export function challengesNeeded(p, h, alphaEach, theta, humanPass = 0.985) {
  if (humanShareUpper(p, h, alphaEach, humanPass) <= theta) return 0;
  let lo = 0, hi = 1;
  while (humanShareUpper(p, h + hi, alphaEach, humanPass) > theta) { hi *= 2; if (hi > 1e7) return Infinity; }
  while (hi - lo > 1) { const mid = (lo + hi) >> 1; if (humanShareUpper(p, h + mid, alphaEach, humanPass) > theta) lo = mid; else hi = mid; }
  return hi;
}

export function itemsetMatch(table, conds, i) {
  for (const [f, v] of conds) if (table.cols[f][i] !== v) return false;
  return true;
}

// Greedy maximum coverage over significant itemsets: repeatedly take the itemset that covers the
// most not-yet-covered eligible sessions (classic (1 - 1/e) guarantee for max coverage).
export function selectCampaigns(table, significant, { eligible, maxCampaigns = 8, minGain = 100 } = {}) {
  const covered = new Uint8Array(table.n);
  const lists = significant.map((it) => { const l = []; for (let i = 0; i < table.n; i++) if (eligible[i] && itemsetMatch(table, it.conds, i)) l.push(i); return l; });
  const chosen = [];
  for (let k = 0; k < maxCampaigns; k++) {
    let best = -1, bestGain = 0;
    lists.forEach((l, j) => { let gnew = 0; for (const i of l) if (!covered[i]) gnew++; if (gnew < 0.5 * l.length) return; if (gnew > bestGain || (gnew === bestGain && best >= 0 && significant[j].conds.length < significant[best].conds.length)) { bestGain = gnew; best = j; } });
    if (best < 0 || bestGain < minGain) break;
    const sessions = lists[best].filter((i) => !covered[i]);
    for (const i of lists[best]) covered[i] = 1;
    chosen.push({ itemset: significant[best], sessions, all: lists[best] });
  }
  return { chosen, covered };
}

// Full pipeline (selective inference by sample splitting):
// 1) explore half: mine itemsets, keep those spanning >= minIps IPs whose explore pass rate is
//    low, and pick campaigns by greedy coverage; 2) confirm half: test only the k chosen
//    campaigns, Bonferroni alpha/k, so every confirmed campaign is <= theta human with
//    family-wise probability >= 1 - alpha.
export function detect(table, { alpha = 0.05, theta = 0.10, minSup = 60, minIps = 20, eligible, maxCampaigns = 8 } = {}) {
  const its = mineItemsets(table, { minSup, eligible });
  const cand = its.filter((it) => it.ipCount >= minIps && it.h[0] >= 10 && it.p[0] / it.h[0] <= theta / 2);
  const sel = selectCampaigns(table, cand, { eligible, maxCampaigns });
  const k = Math.max(sel.chosen.length, 1);
  for (const c of sel.chosen) {
    let h = 0, p = 0; for (const i of c.all) if (table.cols.split[i] === 1) { h += table.cols.holdout[i]; p += table.cols.verified[i]; }
    c.confirm = { h, p, upper: humanShareUpper(p, h, alpha / k), need: challengesNeeded(p, h, alpha / k, theta) };
    c.confirmed = c.confirm.upper <= theta;
  }
  return { itemsets: its.length, candidates: cand.length, k, alpha, theta, ...sel };
}

// Clopper-Pearson upper bound for a binomial proportion (one-sided, level 1 - alpha).
export function cpUpper(x, n, alpha = 0.05) {
  if (n === 0) return 1;
  if (x >= n) return 1;
  // bisection on the binomial CDF: P(X <= x | p) = alpha
  let lo = x / n, hi = 1;
  for (let it = 0; it < 80; it++) { const mid = (lo + hi) / 2; if (binomCdf(x, n, mid) > alpha) lo = mid; else hi = mid; }
  return hi;
}
export function binomCdf(x, n, p) {
  if (p <= 0) return 1; if (p >= 1) return x >= n ? 1 : 0;
  // sum in log space
  let s = 0; const lp = Math.log(p), lq = Math.log1p(-p);
  let lc = 0; // log C(n,0)
  for (let k = 0; k <= x; k++) { if (k > 0) lc += Math.log(n - k + 1) - Math.log(k); s += Math.exp(lc + k * lp + (n - k) * lq); }
  return Math.min(1, s);
}

// A condition: { field, values: Set of value codes }. A rule = AND of conditions.
export function matches(table, rule, i) {
  for (const c of rule) if (!c.values.has(table.cols[c.field][i])) return false;
  return true;
}

// Evaluate a rule against the table. Returns coverage of the block (share of sessions, and of requests),
// matches among verified humans, and matches overall.
export function evalRule(table, rule, blockSet, { split = null, alphaEach = 0.05 } = {}) {
  let blockS = 0, blockR = 0, blockRtot = 0, vh = 0, vhTot = 0, all = 0, allR = 0;
  const { verified, req } = table.cols;
  for (let i = 0; i < table.n; i++) {
    const m = rule.length ? matches(table, rule, i) : false;
    if (blockSet.has(i)) { blockRtot += req[i]; if (m) { blockS++; blockR += req[i]; } }
    if (verified[i] && (split === null || table.cols.split[i] === split)) { vhTot++; if (m) vh++; }
    if (m) { all++; allR += req[i]; }
  }
  return { blockS, blockN: blockSet.size, blockR, blockRtot, coverage: blockSet.size ? blockS / blockSet.size : 0, reqCoverage: blockRtot ? blockR / blockRtot : 0, vh, vhTot, vhRate: vhTot ? vh / vhTot : 0, vhUpper: cpUpper(vh, vhTot, alphaEach), all, allR };
}

// Candidate conditions for a block: for each rule-expressible field, the smallest set of
// values that covers >= 95% of the block's sessions (values sorted by block share), as long
// as that set is small (<= maxVals).
export function candidateConditions(table, sessions, { maxVals = 8, includeProposed = true } = {}) {
  const out = [];
  for (const f of Object.keys(RULE_FIELDS)) {
    if (!includeProposed && RULE_FIELDS[f].proposed) continue;
    const cnt = new Map();
    for (const i of sessions) { const v = table.cols[f][i]; cnt.set(v, (cnt.get(v) || 0) + 1); }
    const vals = [...cnt.entries()].sort((a, b) => b[1] - a[1]);
    let cum = 0; const chosen = [];
    for (const [v, c] of vals) { chosen.push(v); cum += c; if (cum >= 0.95 * sessions.length) break; }
    if (chosen.length <= maxVals && cum >= 0.95 * sessions.length) out.push({ field: f, values: new Set(chosen), share: cum / sessions.length, proposed: !!RULE_FIELDS[f].proposed });
  }
  return out;
}

// Exact search over conjunctions of up to `maxConds` (<= 4) candidate conditions. Objective: maximize
// covered block requests subject to the 95% Clopper-Pearson upper bound of the verified-human
// match rate (explore half) being <= humanBudget.
export function synthesizeRule(table, cands, blockSet, { maxConds = 4, humanBudget = 0.005, allowProposed = true, split = 0, covTol = 0.03 } = {}) {
  const pool = cands.filter((c) => allowProposed || !c.proposed);
  const feasible = [];
  const consider = (combo) => {
    const ev = evalRule(table, combo, blockSet, { split });
    if (ev.vhUpper > humanBudget) return;
    feasible.push({ rule: combo, ev, np: combo.filter((c) => c.proposed).length });
  };
  const m = pool.length;
  for (let a = 0; a < m; a++) {
    consider([pool[a]]);
    if (maxConds < 2) continue;
    for (let b = a + 1; b < m; b++) {
      consider([pool[a], pool[b]]);
      if (maxConds < 3) continue;
      for (let c = b + 1; c < m; c++) {
        consider([pool[a], pool[b], pool[c]]);
        if (maxConds < 4) continue;
        for (let d = c + 1; d < m; d++) consider([pool[a], pool[b], pool[c], pool[d]]);
      }
    }
  }
  if (!feasible.length) return null;
  // Among rules within `covTol` of the best coverage, prefer the fewest human matches, then
  // fewer proposed fields, then fewer conditions (simpler rules generalise better).
  const maxCov = Math.max(...feasible.map((f) => f.ev.coverage));
  const near = feasible.filter((f) => f.ev.coverage >= maxCov - covTol);
  near.sort((x, y) => x.ev.vh - y.ev.vh || x.np - y.np || x.rule.length - y.rule.length || y.ev.coverage - x.ev.coverage);
  return near[0];
}

// Per-IP rate limit baseline: an IP is caught if its peak rate exceeds `perMin` requests/minute
// or its daily total exceeds `perDay`.
export function rateLimitCatch(table, { perMin = 30, perDay = 1000 } = {}) {
  const byIp = new Map();
  const { ip, req, dur } = table.cols;
  for (let i = 0; i < table.n; i++) {
    const r = byIp.get(ip[i]) || { req: 0, peak: 0 };
    r.req += req[i]; r.peak = Math.max(r.peak, req[i] / Math.max(dur[i], 1));
    byIp.set(ip[i], r);
  }
  const caught = new Uint8Array(table.n);
  for (let i = 0; i < table.n; i++) { const r = byIp.get(ip[i]); if (r.peak > perMin || r.req > perDay) caught[i] = 1; }
  return caught;
}

