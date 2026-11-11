import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  mulberry32, mineItemsets, humanShareUpper, challengesNeeded, cpUpper, binomCdf, evalRule, synthesizeRule,
  candidateConditions, selectCampaigns, rateLimitCatch, detect, itemsetMatch,
} from '../src/campaigns.js';
import { generateDay, encode } from '../scripts/gen.mjs';
import { analyzeDay, eligibility, SEED } from '../scripts/build.mjs';
import { evaluateDay } from '../scripts/results.mjs';

const day = JSON.parse(readFileSync(new URL('../data/day.json', import.meta.url)));
const results = JSON.parse(readFileSync(new URL('../data/results.json', import.meta.url)));
const TAB = encode(generateDay(SEED));

// tiny hand-made table helper
function table(rows) {
  const fields = Object.keys(rows[0]);
  const cols = {}; for (const f of fields) cols[f] = rows.map((r) => r[f]);
  return { n: rows.length, cols };
}

test('binomial CDF and Clopper-Pearson bound agree with closed forms', () => {
  // P(X <= 0 | n, p) = (1-p)^n, so the 95% upper bound with 0 successes is 1 - 0.05^(1/n)
  assert.ok(Math.abs(binomCdf(0, 50, 0.1) - Math.pow(0.9, 50)) < 1e-12);
  for (const n of [10, 100, 1500]) assert.ok(Math.abs(cpUpper(0, n, 0.05) - (1 - Math.pow(0.05, 1 / n))) < 1e-6);
  assert.equal(cpUpper(5, 5), 1);
});

test('Clopper-Pearson upper bound covers the true rate at least 95% of the time (randomized)', () => {
  const rng = mulberry32(11); let miss = 0; const R = 2000;
  for (let r = 0; r < R; r++) {
    const p = rng() * 0.2, n = 20 + Math.floor(rng() * 300);
    let x = 0; for (let i = 0; i < n; i++) if (rng() < p) x++;
    if (cpUpper(x, n, 0.05) < p) miss++;
  }
  assert.ok(miss / R <= 0.05, `miscoverage ${miss / R}`);
});

test('itemset mining counts support, holdout and passes exactly (brute force check)', () => {
  const rng = mulberry32(3); const rows = [];
  for (let i = 0; i < 400; i++) rows.push({ ja4: Math.floor(rng() * 3), hdr: Math.floor(rng() * 2), path: Math.floor(rng() * 4), ip: i, holdout: rng() < 0.3 ? 1 : 0, verified: 0, split: rng() < 0.5 ? 0 : 1 });
  rows.forEach((r) => { r.verified = r.holdout && rng() < 0.5 ? 1 : 0; });
  const t = table(rows);
  const its = mineItemsets(t, { fields: ['ja4', 'hdr', 'path'], minSup: 20 });
  for (const it of its) {
    let n = 0, h = 0, p = 0;
    for (let i = 0; i < t.n; i++) if (itemsetMatch(t, it.conds, i)) { n++; h += t.cols.holdout[i]; p += t.cols.verified[i]; }
    assert.equal(it.n, n); assert.equal(it.h[0] + it.h[1], h); assert.equal(it.p[0] + it.p[1], p);
    assert.ok(n >= 20);
  }
  assert.ok(its.some((it) => it.conds.length === 3));
});

test('challengesNeeded is the smallest count that brings the bound under theta', () => {
  const a = 0.0125, th = 0.10;
  const k = challengesNeeded(0, 20, a, th);
  assert.ok(humanShareUpper(0, 20 + k, a) <= th);
  assert.ok(humanShareUpper(0, 20 + k - 1, a) > th);
  assert.equal(challengesNeeded(0, 400, a, th), 0);
});

test('greedy coverage picks disjoint-majority itemsets in order of gain', () => {
  const rows = [];
  for (let i = 0; i < 300; i++) rows.push({ a: i < 200 ? 1 : 0, b: i >= 150 ? 1 : 0 });
  const t = table(rows); const elig = new Uint8Array(300).fill(1);
  const its = [{ conds: [['a', 1]] }, { conds: [['b', 1]] }];
  const sel = selectCampaigns(t, its, { eligible: elig, minGain: 10 });
  assert.equal(sel.chosen[0].itemset.conds[0][0], 'a');
  assert.equal(sel.chosen[1].sessions.length, 100); // only the not-yet-covered part of b
});

test('rule synthesis respects the human-collateral budget and prefers fewer human matches', () => {
  const rows = [];
  for (let i = 0; i < 2000; i++) rows.push({ ua: 0, chua: i < 300 ? 1 : 0, al: i < 300 ? 1 : (i % 7 === 0 ? 1 : 0), req: 1, verified: i >= 300 && i % 2 === 0 ? 1 : 0, split: 0 });
  const t = table(rows); const block = Array.from({ length: 300 }, (_, i) => i); const set = new Set(block);
  const cands = candidateConditions({ ...t, cols: { ...t.cols, path: t.cols.ua, dom: t.cols.ua, asn: t.cols.ua, cc: t.cols.ua, ja4: t.cols.ua, h2: t.cols.ua, hdr: t.cols.ua } }, block, { includeProposed: false });
  const best = synthesizeRule({ ...t, cols: { ...t.cols, path: t.cols.ua, dom: t.cols.ua, asn: t.cols.ua, cc: t.cols.ua } }, cands, set, { humanBudget: 0.005, allowProposed: false });
  assert.ok(best);
  assert.ok(best.ev.vhUpper <= 0.005);
  assert.equal(best.ev.coverage, 1);
  assert.ok(best.rule.some((c) => c.field === 'chua'));
});

test('per-IP rate limit catches fast single IPs and misses slow rotating ones', () => {
  const rows = [{ ip: 1, req: 900, dur: 10 }, { ip: 2, req: 3, dur: 2 }, { ip: 3, req: 4, dur: 1 }];
  const caught = rateLimitCatch(table(rows), { perMin: 30, perDay: 1000 });
  assert.deepEqual([...caught], [1, 0, 0]);
});

test('the generator is deterministic and the committed day matches it', () => {
  const again = encode(generateDay(SEED));
  assert.equal(again.n, TAB.n);
  assert.equal(day.table.n, TAB.n);
  const w = day.table.packed.req.w; const s = day.table.packed.req.s;
  for (const i of [0, 17, 999, TAB.n - 1]) assert.equal(parseInt(s.substr(i * w, w), 36), TAB.cols.req[i]);
});

test('campaign sessions never trip the per-IP limit (they are mined from traffic that passed it)', () => {
  const { rl } = eligibility(TAB);
  for (const c of day.analysis.campaigns) for (const i of c.sessions) assert.equal(rl[i], 0);
});

test('detection on the demo day confirms exactly the three large campaigns, each nearly pure', () => {
  const truth = JSON.parse(readFileSync(new URL('../data/truth.json', import.meta.url))).truth;
  const conf = day.analysis.campaigns.filter((c) => c.confirmed);
  assert.equal(conf.length, 3);
  const majors = conf.map((c) => { const k = {}; for (const i of c.sessions) k[truth[i]] = (k[truth[i]] || 0) + 1; const top = Object.entries(k).sort((a, b) => b[1] - a[1])[0]; return [top[0], top[1] / c.n, (k.human || 0) / c.n]; });
  assert.deepEqual(majors.map((m) => m[0]).sort(), ['C1', 'C2', 'C3']);
  for (const m of majors) { assert.ok(m[1] > 0.97); assert.ok(m[2] <= day.analysis.theta); }
});

test('the shipped analysis is reproducible from the generator and the core', () => {
  const an = analyzeDay(TAB);
  assert.deepEqual(an.campaigns.map((c) => [c.id, c.n, c.ips, c.confirmed]), day.analysis.campaigns.map((c) => [c.id, c.n, c.ips, c.confirmed]));
  const c1 = an.campaigns[0], d1 = day.analysis.campaigns[0];
  assert.ok(Math.abs(c1.confirm.upper - d1.confirm.upper) < 1e-12);
  assert.equal(c1.deploy.explore.blockS, d1.deploy.explore.blockS);
});

test('family-wise guarantee: across random null days no human-majority group is ever confirmed (randomized)', () => {
  // Days with no campaigns at all: anything confirmed would be a false campaign.
  let falseConf = 0;
  for (let s = 0; s < 3; s++) {
    const S = generateDay(500 + s, { scale: 0.5 }).filter((x) => x.kind === 'human' || x.kind === 'goodbot' || x.kind === 'badbot');
    const t = encode(S); const { elig } = eligibility(t);
    const d = detect(t, { eligible: elig });
    falseConf += d.chosen.filter((c) => c.confirmed).length;
  }
  assert.equal(falseConf, 0);
});

test('headline numbers in data/results.json reproduce (one day re-run + committed 20-day summary)', () => {
  const s = results.summary;
  assert.equal(s.days, 20);
  assert.equal(s.allThreeBigConfirmed, 20);
  assert.equal(s.falseConfirmations, 0);
  assert.ok(s.rules.campReqShare > 0.94);
  assert.ok(s.rules.humanShare < 0.001);
  assert.ok(s.rateLimit.campReqShare < 0.001);
  const d = evaluateDay(SEED + 1);
  const c = results.days[0];
  assert.equal(d.confirmedBig, c.confirmedBig);
  assert.ok(Math.abs(d.rules.campReqShare - c.rules.campReqShare) < 1e-12);
  assert.ok(Math.abs(d.rules.humanShare - c.rules.humanShare) < 1e-12);
});
