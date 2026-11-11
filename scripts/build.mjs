// Runs detection + rule synthesis on one seeded day and writes data/day.json for the app.
// Run: node scripts/build.mjs
import { writeFileSync } from 'node:fs';
import { generateDay, encode } from './gen.mjs';
import { detect, candidateConditions, synthesizeRule, evalRule, rateLimitCatch, itemsetMatch, RULE_FIELDS } from '../src/campaigns.js';

export const SEED = 20261110;

export function eligibility(tab) {
  const rl = rateLimitCatch(tab);
  const good = new Set(tab.vocab.ua.map((u, i) => (/Googlebot|bingbot/.test(u) ? i : -1)).filter((i) => i >= 0));
  const elig = new Uint8Array(tab.n);
  for (let i = 0; i < tab.n; i++) elig[i] = !rl[i] && !good.has(tab.cols.ua[i]) ? 1 : 0;
  return { rl, elig };
}

export function analyzeDay(tab, opts = {}) {
  const { rl, elig } = eligibility(tab);
  const d = detect(tab, { eligible: elig, ...opts });
  const campaigns = d.chosen.map((c, idx) => {
    const set = new Set(c.all);
    const cands = candidateConditions(tab, c.all);
    const deploy = synthesizeRule(tab, cands, set, { allowProposed: false });
    const best = synthesizeRule(tab, cands, set, { allowProposed: true });
    const conf = (r) => r && evalRule(tab, r.rule, set, { split: 1, alphaEach: 0.05 / d.k });
    let ips = new Set(), asns = new Set(), ccs = new Set(), doms = new Set(), reqs = 0, rlReq = 0;
    for (const i of c.all) { ips.add(tab.cols.ip[i]); asns.add(tab.cols.asn[i]); ccs.add(tab.cols.cc[i]); doms.add(tab.cols.dom[i]); reqs += tab.cols.req[i]; if (rl[i]) rlReq += tab.cols.req[i]; }
    // per-IP rate limits on everything matching the campaign signature (incl. sessions already blocked)
    let sigReq = 0, sigRl = 0; for (let i = 0; i < tab.n; i++) if (itemsetMatch(tab, c.itemset.conds, i)) { sigReq += tab.cols.req[i]; if (rl[i]) sigRl += tab.cols.req[i]; }
    const ruleOut = (r) => r && { conds: r.rule.map((x) => ({ field: x.field, label: RULE_FIELDS[x.field].label, op: RULE_FIELDS[x.field].op, proposed: !!RULE_FIELDS[x.field].proposed, values: [...x.values] })), explore: r.ev, confirm: conf(r) };
    return { id: 'CMP-' + String(idx + 1).padStart(2, '0'), itemset: c.itemset.conds, sessions: c.all, n: c.all.length, ips: ips.size, asns: asns.size, countries: ccs.size, domains: doms.size, requests: reqs,
      confirm: c.confirm, confirmed: c.confirmed, deploy: ruleOut(deploy), best: ruleOut(best), rateLimit: { sigReq, sigRl } };
  });
  return { k: d.k, alpha: d.alpha, theta: d.theta, itemsets: d.itemsets, candidates: d.candidates, campaigns, eligible: [...elig].reduce((a, b) => a + b, 0) };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const tab = encode(generateDay(SEED));
  const t0 = Date.now();
  const an = analyzeDay(tab);
  // Ship a compact table: fixed-width base-36 columns; IP strings only for campaign top sources.
  const SHIP = ['asn', 'cc', 'ja4', 'h2', 'hdr', 'chua', 'al', 'ua', 'path', 'dom', 'req', 'hour', 'verified', 'holdout', 'split'];
  const packed = {};
  for (const c of SHIP) { const col = tab.cols[c]; const w = Math.max(1, Math.max(...col).toString(36).length); packed[c] = { w, s: col.map((v) => v.toString(36).padStart(w, '0')).join('') }; }
  for (const cmp of an.campaigns) {
    const byIp = new Map(); for (const i of cmp.sessions) { const ip = tab.cols.ip[i]; const r = byIp.get(ip) || { ip: tab.vocab.ip[ip], asn: tab.vocab.asn[tab.cols.asn[i]], cc: tab.vocab.cc[tab.cols.cc[i]], req: 0 }; r.req += tab.cols.req[i]; byIp.set(ip, r); }
    cmp.topIps = [...byIp.values()].sort((a, b) => b.req - a.req).slice(0, 10);
    cmp.ipReqs = [...byIp.values()].map((r) => r.req).sort((a, b) => a - b);
  }
  const vocab = { ...tab.vocab }; delete vocab.ip; delete vocab.cookie; delete vocab.js; delete vocab.cadence;
  const pub = { n: tab.n, packed, vocab, asnName: tab.asnName, ipCount: tab.vocab.ip.length };
  const truth = tab.truth; // ground truth is not shipped to the app
  writeFileSync(new URL('../data/day.json', import.meta.url), JSON.stringify({ seed: SEED, node: 'gk-fra-03', date: '2026-11-10', table: pub, analysis: an, ms: Date.now() - t0 }));
  writeFileSync(new URL('../data/truth.json', import.meta.url), JSON.stringify({ seed: SEED, truth }));
  console.log('sessions', tab.n, 'campaigns', an.campaigns.map((c) => `${c.id} n=${c.n} ips=${c.ips} confirmed=${c.confirmed} up=${c.confirm.upper.toFixed(3)} deploy=${c.deploy ? c.deploy.conds.map((x) => x.field).join('+') + ' cov ' + c.deploy.explore.coverage.toFixed(3) : 'none'}`).join('\n'), Date.now() - t0, 'ms');
}
