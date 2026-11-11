// Evaluation against ground truth over many simulated days. Writes data/results.json.
// Run: node scripts/results.mjs [days]   (default 20, ~1 min)
import { readFileSync, writeFileSync } from 'node:fs';
import { generateDay, encode } from './gen.mjs';
import { analyzeDay, eligibility, SEED } from './build.mjs';

const BIG = ['C1', 'C2', 'C3'];
const ALLC = ['C1', 'C2', 'C3', 'C4'];

// Evaluate one day: which true campaigns were confirmed, rule coverage of campaign requests,
// human collateral, and the per-IP rate-limit and ASN-block baselines.
export function evaluateDay(seed) {
  const tab = encode(generateDay(seed));
  const an = analyzeDay(tab);
  const { rl } = eligibility(tab);
  const T = tab.truth;
  const isCamp = (i) => ALLC.includes(T[i]);
  let campReq = 0, humanN = 0; const reqBy = {};
  for (let i = 0; i < tab.n; i++) { if (isCamp(i)) { campReq += tab.cols.req[i]; reqBy[T[i]] = (reqBy[T[i]] || 0) + tab.cols.req[i]; } if (T[i] === 'human') humanN++; }
  // which true campaign does each detected campaign correspond to (majority) and its true human share
  const det = an.campaigns.map((c) => { const k = {}; for (const i of c.sessions) k[T[i]] = (k[T[i]] || 0) + 1; const major = Object.entries(k).sort((a, b) => b[1] - a[1])[0][0]; return { id: c.id, major, humanShare: (k.human || 0) / c.n, confirmed: c.confirmed, deploy: c.deploy, best: c.best }; });
  const confirmedBig = new Set(det.filter((d) => d.confirmed && BIG.includes(d.major)).map((d) => d.major));
  const falseConfirm = det.filter((d) => d.confirmed && d.humanShare > an.theta).length;
  // rules: union of deployable rules of confirmed campaigns
  const match = (rule, i) => rule.conds.every((c) => c.values.includes(tab.cols[c.field][i]));
  const rules = det.filter((d) => d.confirmed && d.deploy).map((d) => d.deploy);
  const rulesBest = det.filter((d) => d.confirmed && d.best).map((d) => d.best);
  let ruleCampReq = 0, ruleHuman = 0, bestCampReq = 0, bestHuman = 0, rlCampReq = 0, rlHuman = 0, asnCampReq = 0, asnHuman = 0;
  // ASN baseline: block every ASN that sent >= 1 campaign session (what an analyst blocking "proxy ASNs" would do)
  const campAsn = new Set(); for (let i = 0; i < tab.n; i++) if (BIG.includes(T[i])) campAsn.add(tab.cols.asn[i]);
  for (let i = 0; i < tab.n; i++) {
    const r = rules.some((x) => match(x, i)), b = rulesBest.some((x) => match(x, i)), a = campAsn.has(tab.cols.asn[i]);
    if (isCamp(i)) { if (r) ruleCampReq += tab.cols.req[i]; if (b) bestCampReq += tab.cols.req[i]; if (rl[i]) rlCampReq += tab.cols.req[i]; if (a) asnCampReq += tab.cols.req[i]; }
    if (T[i] === 'human') { if (r) ruleHuman++; if (b) bestHuman++; if (rl[i]) rlHuman++; if (a) asnHuman++; }
  }
  const campIps = new Set(); for (let i = 0; i < tab.n; i++) if (isCamp(i)) campIps.add(tab.cols.ip[i]);
  return { seed, confirmedBig: confirmedBig.size, c4Confirmed: det.some((d) => d.confirmed && d.major === 'C4'), falseConfirm, campReq, campIps: campIps.size, humanN,
    rules: { campReqShare: ruleCampReq / campReq, humanShare: ruleHuman / humanN }, rulesWithProposed: { campReqShare: bestCampReq / campReq, humanShare: bestHuman / humanN },
    rateLimit: { campReqShare: rlCampReq / campReq, humanShare: rlHuman / humanN }, asnBlock: { campReqShare: asnCampReq / campReq, humanShare: asnHuman / humanN } };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const D = Number(process.argv[2] || 20);
  const t0 = Date.now();
  const days = []; for (let d = 0; d < D; d++) days.push(evaluateDay(SEED + 1 + d));
  const mean = (f) => days.reduce((s, x) => s + f(x), 0) / D;
  const min = (f) => Math.min(...days.map(f)), max = (f) => Math.max(...days.map(f));
  const day = JSON.parse(readFileSync(new URL('../data/day.json', import.meta.url)));
  const demo = evaluateDay(SEED);
  const summary = {
    days: D,
    allThreeBigConfirmed: days.filter((x) => x.confirmedBig === 3).length,
    c4ConfirmedDays: days.filter((x) => x.c4Confirmed).length,
    falseConfirmations: days.reduce((s, x) => s + x.falseConfirm, 0),
    rules: { campReqShare: mean((x) => x.rules.campReqShare), minCampReqShare: min((x) => x.rules.campReqShare), humanShare: mean((x) => x.rules.humanShare), maxHumanShare: max((x) => x.rules.humanShare) },
    rulesWithProposed: { campReqShare: mean((x) => x.rulesWithProposed.campReqShare), humanShare: mean((x) => x.rulesWithProposed.humanShare) },
    rateLimit: { campReqShare: mean((x) => x.rateLimit.campReqShare), humanShare: mean((x) => x.rateLimit.humanShare) },
    asnBlock: { campReqShare: mean((x) => x.asnBlock.campReqShare), humanShare: mean((x) => x.asnBlock.humanShare) },
    campIps: mean((x) => x.campIps),
  };
  writeFileSync(new URL('../data/results.json', import.meta.url), JSON.stringify({ generated: 'node scripts/results.mjs ' + D, demoDay: demo, summary, days, seconds: (Date.now() - t0) / 1000, demoAnalysisMs: day.ms }, null, 2));
  console.log(JSON.stringify({ demo, summary }, null, 2));
}
