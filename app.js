// Campaigns page in the Blackwall Dashboard shell. Detection results come from
// scripts/build.mjs (data/day.json); everything shown is computed from that file, and the
// rule editor re-evaluates coverage and collateral live in the browser with src/campaigns.js.
import { evalRule, RULE_FIELDS } from './src/campaigns.js';

const $ = (s, el = document) => el.querySelector(s);
const view = $('#view');
const LS = 'bw-campaigns-v1';
let DATA = null, TAB = null, LOADERR = null, AN = null;
const store = (() => { try { return Object.assign({ rules: [], challenge: {}, period: 'today' }, JSON.parse(localStorage.getItem(LS) || '{}')); } catch { return { rules: [], challenge: {}, period: 'today' }; } })();
const save = () => localStorage.setItem(LS, JSON.stringify(store));
let sel = 0;
const edit = {}; // per-campaign editor state

const nf = new Intl.NumberFormat('en-US');
const N = (x) => nf.format(Math.round(x));
const pct = (x, d = 1) => (x * 100).toFixed(d) + '%';
const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const FIELD_SHORT = { ja4: 'JA4', h2: 'HTTP/2', hdr: 'Header order', chua: 'sec-ch-ua', al: 'Accept-Language', ua: 'User-Agent', path: 'Path', dom: 'Domain', asn: 'ASN', cc: 'Country' };
const COLORS = ['#eb2450', '#992deb', '#1e2035', '#4682b4', '#cf116f', '#2e8b57'];

// ---------- data
function unpack(pub) {
  const cols = {};
  for (const [c, { w, s }] of Object.entries(pub.packed)) { const n = s.length / w; const a = new Int32Array(n); for (let i = 0; i < n; i++) a[i] = parseInt(s.substr(i * w, w), 36); cols[c] = a; }
  return { n: pub.n, cols, vocab: pub.vocab, asnName: pub.asnName };
}
async function load() {
  try { const r = await fetch('data/day.json', { cache: 'no-cache' }); if (!r.ok) throw new Error('HTTP ' + r.status); DATA = await r.json(); TAB = unpack(DATA.table); AN = DATA.analysis; LOADERR = null; }
  catch (e) { LOADERR = e; DATA = null; }
}
const valLabel = (field, v) => { const raw = TAB.vocab[field][v]; if (field === 'asn') return `AS${raw} ${TAB.asnName[raw] || ''}`.trim(); if (field === 'chua' && raw === 'absent') return '(absent)'; if (field === 'al' && raw === 'none') return '(absent)'; return raw; };
const shortVal = (field, v) => { const s = valLabel(field, v); if (field === 'ua') { const m = s.match(/(Chrome|CriOS|Firefox|Version|Edg)\/(\d+)/); const os = /Windows/.test(s) ? 'Win' : /Macintosh/.test(s) ? 'Mac' : /Android/.test(s) ? 'Android' : /iPhone/.test(s) ? 'iOS' : ''; return m ? `${m[1] === 'Version' ? 'Safari' : m[1]} ${m[2]} ${os}` : s.slice(0, 28); } if (field === 'hdr') return s.split(',').slice(0, 4).join(',') + '…'; if (field === 'h2') return s.slice(0, 22) + '…'; if (field === 'ja4') return s; return s; };

// ---------- routing
function parseHash() { const h = location.hash.replace(/^#/, '') || '/campaigns'; const [p, q = ''] = h.split('?'); const parts = p.split('/').filter(Boolean); return { page: parts[0] || 'campaigns', id: parts[1] || null, params: Object.fromEntries(new URLSearchParams(q)) }; }
function setNav(page) { document.querySelectorAll('.mainnav a[data-route]').forEach((a) => a.classList.toggle('active', a.dataset.route === page)); }

// ---------- helpers
function campaignStats(c) {
  const hours = new Array(24).fill(0); let verifiedAll = 0;
  for (const i of c.sessions) { hours[TAB.cols.hour[i]] += TAB.cols.req[i]; verifiedAll += TAB.cols.verified[i]; }
  return { hours, verifiedAll };
}
function signatureHTML(c) { return `<div class="sig">${c.itemset.map(([f, v]) => `<span class="tok ${RULE_FIELDS[f]?.proposed ? 'p' : ''}" title="${esc(FIELD_SHORT[f] + ': ' + valLabel(f, v))}">${FIELD_SHORT[f]}: ${esc(shortVal(f, v))}</span>`).join('')}</div>`; }
function ruleFor(c) { return store.rules.find((r) => r.campaign === c.id); }
function statusBadge(c) {
  const r = ruleFor(c);
  if (r) return `<span class="badge ${r.on ? 'rule' : 'off'}">${r.on ? 'Rule active' : 'Rule off'}</span>`;
  if (c.confirmed) return '<span class="badge conf">Confirmed</span>';
  return `<span class="badge susp">${store.challenge[c.id] ? 'Challenging' : 'Suspected'}</span>`;
}
// Median requests per IP address across confirmed campaigns (exact, from per-IP counts in day.json).
function perIpMedian(cs) { const all = cs.flatMap((c) => c.ipReqs).sort((a, b) => a - b); return all.length ? all[Math.floor(all.length / 2)] : 0; }
// ---------- list view
function renderList() {
  setNav('campaigns');
  const cs = AN.campaigns, conf = cs.filter((c) => c.confirmed);
  const ips = conf.reduce((s, c) => s + c.ips, 0), reqs = conf.reduce((s, c) => s + c.requests, 0);
  const totalReq = TAB.cols.req.reduce((a, b) => a + b, 0);
  let html = `<h1 class="page">Campaigns</h1><p class="lead">Bot operations that spread their traffic over thousands of IP addresses so that no single address ever trips a rate limit. Blackwall groups sessions by what they share (TLS and HTTP/2 fingerprints, header order, headers, paths) and confirms each group with the verification holdout before suggesting a Custom Rule.</p>`;
  html += `<div class="subhead"><h2>Overview</h2><div class="seg" role="tablist" aria-label="Time frame">${['today', 'yesterday', 'week', 'month'].map((p) => `<button role="tab" data-p="${p}" class="${store.period === p ? 'on' : ''}" aria-selected="${store.period === p}">${{ today: 'Today', yesterday: 'Yesterday', week: 'This week', month: 'This month' }[p]}</button>`).join('')}</div></div>`;
  if (store.period !== 'today') {
    html += `<div class="empty"><h3>No campaign analysis for this period</h3><p>Campaign mining runs on a rolling 24-hour window of node <b>${esc(DATA.node)}</b>. Historical runs are kept in the Data Warehouse; this demo ships one day (${esc(DATA.date)}).</p><button class="btn purple" id="toToday" type="button">Show today</button></div>`;
    view.innerHTML = html; bindSeg(); $('#toToday').onclick = () => { store.period = 'today'; save(); route(); }; return;
  }
  html += `<div class="kpis">
    <div class="kpi k1"><div class="k">Campaigns<br>confirmed</div><div class="v">${conf.length}</div><div class="s">${cs.length - conf.length} more suspected</div></div>
    <div class="kpi k2"><div class="k">Rotating<br>IP addresses</div><div class="v">${N(ips)}</div><div class="s">across ${N(conf.reduce((s, c) => s + c.asns, 0))} networks in ${N(new Set(conf.flatMap((c) => c.sessions.map((i) => TAB.cols.cc[i]))).size)} countries</div></div>
    <div class="kpi k3"><div class="k">Requests in<br>campaigns</div><div class="v">${N(reqs)}</div><div class="s">${pct(reqs / totalReq)} of all requests today</div></div>
    <div class="kpi k4"><div class="k">Median requests<br>per IP, 24 h</div><div class="v">${N(perIpMedian(conf))}</div><div class="s">busiest IP: ${N(Math.max(...conf.map((c) => c.topIps[0]?.req || 0)))} requests in 24 h</div></div>
  </div>`;
  html += `<h2 class="sec">Detected campaigns</h2><div class="table-wrap"><table class="t" aria-label="Detected campaigns"><thead><tr><th>ID</th><th>Shared signature</th><th class="num">IPs</th><th class="num">Networks</th><th class="num">Requests</th><th class="num" title="Upper bound on the share of humans in the campaign (verification holdout, 95% family-wise)">Human share ≤</th><th class="num" title="Share of the campaign's sessions the suggested rule matches">Rule covers</th><th>Status</th></tr></thead><tbody>`;
  cs.forEach((c, i) => {
    const d = c.deploy;
    html += `<tr class="row ${i === sel ? 'sel' : ''}" tabindex="0" data-id="${c.id}" data-i="${i}"><td><b>${c.id}</b></td><td>${signatureHTML(c)}</td><td class="num">${N(c.ips)}</td><td class="num">${N(c.asns)}</td><td class="num">${N(c.requests)}</td><td class="num">${pct(c.confirm.upper)}</td><td class="num">${d ? pct(d.explore.coverage) : '—'}</td><td>${statusBadge(c)}</td></tr>`;
  });
  html += `</tbody></table></div>`;
  html += `<div class="panel" style="margin-top:28px"><h3>Campaign activity</h3><div class="legend">${cs.map((c, i) => `<span><i style="background:${COLORS[i]}"></i>${c.id}</span>`).join('')}</div><div id="act"></div></div>`;
  html += `<p class="note">Mined ${N(DATA.analysis.itemsets)} attribute combinations over ${N(AN.eligible)} sessions that passed existing rules on ${esc(DATA.node)}, ${esc(DATA.date)}; ${N(AN.candidates)} looked bot-dominated on the exploration half and ${cs.length} were kept by greedy coverage. Confirmation uses the other half of the holdout with a ${pct(AN.alpha / AN.k, 2)} error budget per campaign (${pct(AN.alpha, 0)} family-wise). Keys: <kbd>j</kbd>/<kbd>k</kbd>, <kbd>Enter</kbd>, <kbd>Esc</kbd>, <kbd>e</kbd> export, <kbd>?</kbd>. <a href="#/rules">Custom rules created here (${store.rules.length})</a></p>`;
  view.innerHTML = html;
  bindSeg();
  view.querySelectorAll('tr.row').forEach((tr) => { tr.onclick = () => (location.hash = '#/campaigns/' + tr.dataset.id); tr.onkeydown = (e) => { if (e.key === 'Enter') location.hash = '#/campaigns/' + tr.dataset.id; }; });
  activityChart($('#act'), cs.map((c, i) => ({ name: c.id, color: COLORS[i], v: campaignStats(c).hours })));
}
function bindSeg() { view.querySelectorAll('.seg button').forEach((b) => (b.onclick = () => { store.period = b.dataset.p; save(); route(); })); }

function activityChart(el, series, H = 260) {
  const W = Math.max(600, el.clientWidth || 1200), L = 52, R = 10, T = 10, B = 50;
  const max = Math.max(1, ...series.flatMap((s) => s.v)); const step = nice(max / 6); const top = Math.ceil(max / step) * step;
  const x = (i) => L + (W - L - R) * (i / 23), y = (v) => T + (H - T - B) * (1 - v / top);
  let s = `<svg class="chart" viewBox="0 0 ${W} ${H}" role="img" aria-label="Requests per hour by campaign">`;
  for (let v = 0; v <= top + 1e-9; v += step) s += `<line class="grid" x1="${L}" x2="${W - R}" y1="${y(v)}" y2="${y(v)}"/><text x="${L - 6}" y="${y(v) + 4}" text-anchor="end">${N(v)}</text>`;
  for (let i = 0; i < 24; i++) s += `<line class="grid" x1="${x(i)}" x2="${x(i)}" y1="${T}" y2="${H - B}"/><text x="${x(i)}" y="${H - B + 14}" text-anchor="end" transform="rotate(-45 ${x(i)} ${H - B + 14})">${String(i).padStart(2, '0')}:00</text>`;
  for (const sr of series) s += `<polyline fill="none" stroke="${sr.color}" stroke-width="2.2" points="${sr.v.map((v, i) => `${x(i)},${y(v)}`).join(' ')}"/>` + sr.v.map((v, i) => `<circle cx="${x(i)}" cy="${y(v)}" r="3" fill="${sr.color}"/>`).join('');
  s += '</svg>'; el.innerHTML = s;
  const svg = el.firstChild, tip = $('#tip');
  svg.onmousemove = (e) => { const b = svg.getBoundingClientRect(); const i = Math.round((((e.clientX - b.left) * (W / b.width)) - L) / ((W - L - R) / 23)); if (i < 0 || i > 23) { tip.hidden = true; return; } tip.innerHTML = `<b>${String(i).padStart(2, '0')}:00</b>` + series.map((sr) => `<div class="r"><span><i style="background:${sr.color}"></i>${sr.name}</span><span>${N(sr.v[i])}</span></div>`).join(''); tip.hidden = false; tip.style.left = e.clientX + 14 + 'px'; tip.style.top = e.clientY + 10 + 'px'; };
  svg.onmouseleave = () => (tip.hidden = true);
}
function nice(raw) { const p = Math.pow(10, Math.floor(Math.log10(raw))); const f = raw / p; return (f <= 1 ? 1 : f <= 2 ? 2 : f <= 5 ? 5 : 10) * p; }

// ---------- detail view
function renderDetail(id) {
  setNav('campaigns');
  const idx = AN.campaigns.findIndex((c) => c.id === id);
  if (idx < 0) { view.innerHTML = `<h1 class="page">Campaign not found</h1><div class="empty"><h3>No campaign “${esc(id)}”</h3><p>It may have aged out of the 24-hour window.</p><a class="btn purple" href="#/campaigns">All campaigns</a></div>`; return; }
  sel = idx;
  const c = AN.campaigns[idx], st = campaignStats(c), set = new Set(c.sessions);
  if (!edit[c.id]) { const base = (c.best && c.best.conds) || (c.deploy && c.deploy.conds) || []; edit[c.id] = { conds: (c.deploy || c.best) ? JSON.parse(JSON.stringify(((c.deploy && c.deploy.conds) || base))).map((x) => ({ ...x, on: true })) : [], proposed: false, action: c.confirmed ? 'deny' : 'captcha', rate: 4 }; }
  const ed = edit[c.id];
  let html = `<p class="crumbs"><a href="#/campaigns">Campaigns</a> / ${c.id}</p><h1 class="page">Campaign ${c.id} ${statusBadge(c)}</h1>`;
  html += `<p class="lead">${N(c.n)} sessions from <b>${N(c.ips)}</b> IP addresses in ${N(c.asns)} networks and ${N(c.countries)} countries, hitting ${N(c.domains)} of this node's domains. The busiest single IP sent only <b>${N(c.topIps[0]?.req || 0)}</b> requests all day.</p>`;
  // holdout evidence
  const conf = c.confirm;
  const ver = c.confirmed ? `Confirmed bot campaign: at most ${pct(conf.upper)} of these sessions can be human (95% family-wise).` : `Not confirmed yet: the bound is ${pct(conf.upper)}, above the ${pct(AN.theta, 0)} threshold. About ${N(conf.need)} more challenged sessions with no passes would confirm it.`;
  html += `<div class="grid2"><div class="darksec"><h3>Shared fingerprint</h3><table><thead><tr><th>Signal</th><th>Value</th><th class="num">In campaign</th><th class="num">Verified humans</th></tr></thead><tbody>${fingerprintRows(c)}</tbody></table><p class="small" style="opacity:.75;margin:12px 0 0">Purple-outlined signals are seen by GateKeeper but cannot be used in the Custom Rules editor today.</p></div>
    <div class="card"><h3>Verification holdout</h3><div class="stat"><span>Challenged sessions (confirmation half)</span><b>${N(conf.h)}</b></div><div class="stat"><span>Passed the challenge</span><b>${N(conf.p)}</b></div><div class="stat"><span>Human share, upper bound</span><b>${pct(conf.upper)}</b></div><div class="stat"><span>Confirmation threshold</span><b>${pct(AN.theta, 0)}</b></div><div class="stat"><span>Error budget for this campaign</span><b>${pct(AN.alpha / AN.k, 2)}</b></div>
    <p class="verdict">${ver}</p>${c.confirmed ? '' : `<p><button class="btn mag" id="challenge" type="button" ${store.challenge[c.id] ? 'disabled' : ''}>${store.challenge[c.id] ? 'Challenging all matching sessions' : 'Challenge all matching sessions'}</button></p><p class="small muted">${N(c.n / 24)} matching sessions an hour; at 100% challenge the bound clears in about ${Math.max(1, Math.ceil(conf.need / Math.max(c.n / 24, 1)))} hour(s) if none pass.</p>`}</div></div>`;
  // rule editor
  html += `<div class="editor" id="editor"><h3>Add a custom rule</h3><label class="cap" for="rname">Rule name</label><input class="inp" id="rname" value="${esc(ed.name || defaultName(c))}" />
    <div style="display:flex;justify-content:space-between;align-items:center;margin-top:20px"><span class="cap" style="font-size:17px;font-weight:700;text-transform:uppercase">Conditions (all must match)</span><label class="switch"><input type="checkbox" id="useProp" ${ed.proposed ? 'checked' : ''} /> Use fingerprint fields (proposed)</label></div><div id="conds">${condRows(ed)}</div>
    <div class="impact" id="impact"></div>
    <div class="actions"><div class="ttl">If all of these conditions are met, perform this action:</div>
      <label class="radio"><input type="radio" name="act" value="deny" ${ed.action === 'deny' ? 'checked' : ''}/>Deny access</label>
      <label class="radio"><input type="radio" name="act" value="captcha" ${ed.action === 'captcha' ? 'checked' : ''}/>Use CAPTCHA</label>
      <label class="radio"><input type="radio" name="act" value="rate" ${ed.action === 'rate' ? 'checked' : ''}/>Limit requests rate by: <input class="inp" style="width:90px;height:40px" type="number" min="1" id="rate" value="${ed.rate}" aria-label="Requests per minute"/> <span style="text-transform:none;font-weight:500">per minute</span></label></div>
    <div style="display:flex;gap:12px;margin-top:20px"><button class="btn" id="addRule" type="button">${ruleFor(c) ? 'Update rule' : 'Add Rule'}</button><button class="btn ghost" id="exRule" type="button">Export rule JSON</button><button class="btn ghost" id="exIps" type="button">Export sessions CSV</button></div></div>`;
  html += `<div class="grid2"><div class="panel"><h3>Requests per hour</h3><div id="hrs"></div></div><div class="darksec"><h3>Top 10 Bot Sources</h3><table><thead><tr><th>IP</th><th>Provider</th><th>Country</th><th class="num">Requests</th></tr></thead><tbody>${c.topIps.map((r) => `<tr><td>${esc(r.ip)}</td><td>${esc(TAB.asnName[r.asn] || 'AS' + r.asn)}</td><td>${esc(r.cc)}</td><td class="num">${N(r.req)}</td></tr>`).join('')}</tbody></table></div></div>`;
  view.innerHTML = html;
  activityChart($('#hrs'), [{ name: c.id, color: COLORS[idx], v: st.hours }], 220);
  const upd = () => { $('#impact').innerHTML = impactHTML(c, ed, set); };
  upd();
  $('#conds').onchange = (e) => { const k = e.target.dataset.k; if (k !== undefined) { ed.conds[+k].on = e.target.checked; $('#conds').innerHTML = condRows(ed); upd(); } };
  $('#useProp').onchange = (e) => { ed.proposed = e.target.checked; const src = ed.proposed ? c.best : c.deploy; ed.conds = src ? JSON.parse(JSON.stringify(src.conds)).map((x) => ({ ...x, on: true })) : []; $('#conds').innerHTML = condRows(ed); upd(); };
  view.querySelectorAll('input[name=act]').forEach((r) => (r.onchange = () => { ed.action = r.value; }));
  $('#rate').oninput = (e) => { ed.rate = Math.max(1, +e.target.value || 1); };
  $('#rname').oninput = (e) => { ed.name = e.target.value; };
  $('#addRule').onclick = () => confirmAdd(c, ed, set);
  $('#exRule').onclick = () => download(`${c.id}-custom-rule.json`, JSON.stringify(ruleJSON(c, ed), null, 2), 'application/json');
  $('#exIps').onclick = () => download(`${c.id}-sessions.csv`, ['ip_count,asn,country,domain,path,user_agent,requests,hour', ...c.sessions.slice(0, 20000).map((i) => ['1', TAB.vocab.asn[TAB.cols.asn[i]], TAB.vocab.cc[TAB.cols.cc[i]], TAB.vocab.dom[TAB.cols.dom[i]], TAB.vocab.path[TAB.cols.path[i]], '"' + TAB.vocab.ua[TAB.cols.ua[i]].replace(/"/g, '""') + '"', TAB.cols.req[i], TAB.cols.hour[i]].join(','))].join('\n'), 'text/csv');
  const ch = $('#challenge'); if (ch) ch.onclick = () => { store.challenge[c.id] = Date.now(); save(); toast(`Challenging every session that matches ${c.id}`); renderDetail(id); };
}
function defaultName(c) {
  const cnt = new Map(); for (const i of c.sessions) cnt.set(TAB.cols.path[i], (cnt.get(TAB.cols.path[i]) || 0) + 1);
  const top = [...cnt.entries()].sort((a, b) => b[1] - a[1])[0][0];
  return `Campaign ${c.id} · ${TAB.vocab.path[top]} · ${N(c.ips)} IPs`;
}
function fingerprintRows(c) {
  // shares of each itemset value and of the rule fields' dominant values, in the campaign vs verified humans
  const fields = ['ja4', 'h2', 'hdr', 'chua', 'al', 'ua', 'path', 'dom'];
  let vhTot = 0; for (let i = 0; i < TAB.n; i++) vhTot += TAB.cols.verified[i];
  return fields.map((f) => {
    const cnt = new Map(); for (const i of c.sessions) cnt.set(TAB.cols[f][i], (cnt.get(TAB.cols[f][i]) || 0) + 1);
    const [v, k] = [...cnt.entries()].sort((a, b) => b[1] - a[1])[0];
    let vh = 0; for (let i = 0; i < TAB.n; i++) if (TAB.cols.verified[i] && TAB.cols[f][i] === v) vh++;
    const share = k / c.n, hs = vh / vhTot;
    return `<tr><td><span class="tok ${RULE_FIELDS[f]?.proposed ? 'p' : ''}" style="background:transparent;color:#fff;border-color:${RULE_FIELDS[f]?.proposed ? '#b58cff' : '#fff'}">${FIELD_SHORT[f]}</span></td><td title="${esc(valLabel(f, v))}">${esc(shortVal(f, v))}</td><td class="num"><span class="bar" style="width:${Math.round(share * 44)}px"></span> ${pct(share, 0)}</td><td class="num"><span class="bar h" style="width:${Math.round(hs * 44)}px"></span> ${pct(hs, hs < 0.01 ? 1 : 0)}</td></tr>`;
  }).join('');
}
function condRows(ed) {
  if (!ed.conds.length) return '<p class="muted" style="margin:14px 0 0">No rule meets the collateral budget with these fields. Turn on fingerprint fields or challenge this campaign first.</p>';
  return ed.conds.map((x, k) => `<div class="cond ${x.on ? '' : 'offc'}"><input type="checkbox" data-k="${k}" ${x.on ? 'checked' : ''} aria-label="Use condition ${k + 1}"/><div><label class="cap">Field${x.proposed ? '<span class="prop">proposed</span>' : ''}</label><div class="inp" style="display:flex;align-items:center">${esc(x.label)}</div></div><div><label class="cap">Logical condition</label><div class="inp" style="display:flex;align-items:center">${esc(x.op.toLowerCase())}</div></div><div><label class="cap">Field value</label><div class="inp" style="display:flex;align-items:center;overflow:hidden;white-space:nowrap;text-overflow:ellipsis" title="${esc(x.values.map((v) => valLabel(x.field, v)).join(', '))}">${esc(fieldValue(x))}</div></div></div>`).join('');
}
function fieldValue(x) {
  const vals = x.values.map((v) => valLabel(x.field, v));
  if (x.field === 'path') return '^(' + vals.map((p) => p.replace('/*', '/').replace(/[.]/g, '\\.')).join('|') + ')';
  if (x.field === 'asn') return x.values.map((v) => TAB.vocab.asn[v]).join(', ');
  if (x.field === 'chua') return vals[0] === '(absent)' ? '"" (header not sent)' : vals[0];
  if (x.field === 'ua') return `${vals.length} values: ` + x.values.map((v) => shortVal('ua', v)).join(', ');
  return vals.join(', ');
}
function activeRule(ed) { return ed.conds.filter((x) => x.on).map((x) => ({ field: x.field, values: new Set(x.values) })); }
function impactHTML(c, ed, set) {
  const rule = activeRule(ed);
  if (!rule.length) return '<b>No conditions selected.</b> The rule would match nothing.';
  const ex = evalRule(TAB, rule, set, { split: 0 }), cf = evalRule(TAB, rule, set, { split: 1, alphaEach: AN.alpha / AN.k });
  const humansAll = (ex.vhTot + cf.vhTot) / (1 - 0); // verified humans across both halves
  const ok = cf.vhUpper <= 0.005;
  return `Matches <b>${N(ex.blockS)}</b> of ${N(ex.blockN)} campaign sessions (<b>${pct(ex.coverage)}</b>, ${pct(ex.reqCoverage)} of its ${N(ex.blockRtot)} requests).<br>Verified humans matched: <b>${ex.vh + cf.vh}</b> of ${N(humansAll)}. On the held-out half, at most <b>${pct(cf.vhUpper, 2)}</b> of human sessions would be hit (95% bound) ${ok ? '<span class="badge rule" style="margin-left:6px">within 0.5% budget</span>' : '<span class="badge conf" style="margin-left:6px">over 0.5% budget</span>'}.<br><span class="small muted">Other traffic matched today: ${N(ex.all - ex.blockS)} sessions outside the campaign.</span>`;
}
function ruleJSON(c, ed) {
  const act = ed.action === 'deny' ? { type: 'deny_access' } : ed.action === 'captcha' ? { type: 'use_captcha' } : { type: 'limit_request_rate', requests: ed.rate, per: 'minute' };
  return { rule_name: ed.name || defaultName(c), conditions: ed.conds.filter((x) => x.on).map((x) => ({ field: x.label, logical_condition: x.op.toLowerCase(), field_value: fieldValue(x), proposed_field: !!x.proposed })), action: act, source: { campaign: c.id, node: DATA.node, date: DATA.date, human_share_upper: +c.confirm.upper.toFixed(4) } };
}
function confirmAdd(c, ed, set) {
  const rule = activeRule(ed); if (!rule.length) { toast('Select at least one condition'); return; }
  const cf = evalRule(TAB, rule, set, { split: 1, alphaEach: AN.alpha / AN.k }), ex = evalRule(TAB, rule, set, { split: 0 });
  const m = $('#modal');
  m.innerHTML = `<div class="dialog" role="dialog" aria-modal="true" aria-labelledby="dt"><h3 id="dt">Add rule for ${c.id}?</h3><p>Custom Rules take priority over Core Rules and Rulesets on every website of this account.</p><table><tr><td>Action</td><td>${{ deny: 'Deny access', captcha: 'Use CAPTCHA', rate: `Limit to ${ed.rate}/min` }[ed.action]}</td></tr><tr><td>Campaign sessions matched</td><td>${pct(ex.coverage)}</td></tr><tr><td>Human sessions hit (95% bound)</td><td>≤ ${pct(cf.vhUpper, 2)}</td></tr>${ed.conds.some((x) => x.on && x.proposed) ? '<tr><td>Needs</td><td>fingerprint fields (proposed)</td></tr>' : ''}</table><div class="acts"><button class="btn ghost" id="no" type="button">Cancel</button><button class="btn purple" id="yes" type="button">Add Rule</button></div></div>`;
  m.hidden = false; $('#yes').focus();
  const close = () => { m.hidden = true; m.innerHTML = ''; };
  $('#no').onclick = close; m.onclick = (e) => { if (e.target === m) close(); };
  $('#yes').onclick = () => { store.rules = store.rules.filter((r) => r.campaign !== c.id); store.rules.push({ campaign: c.id, on: true, created: Date.now(), json: ruleJSON(c, ed) }); save(); close(); toast(`Rule added for ${c.id}`); route(); };
}

// ---------- custom rules created from campaigns
function renderRules() {
  setNav('campaigns');
  let html = `<p class="crumbs"><a href="#/campaigns">Campaigns</a> / Custom rules</p><h1 class="page">Custom rules from campaigns</h1>`;
  if (!store.rules.length) { view.innerHTML = html + `<div class="empty"><h3>No rules yet</h3><p>Open a confirmed campaign and click Add Rule. Rules created here also appear under Websites → Settings → Custom Rules.</p><a class="btn purple" href="#/campaigns">Open campaigns</a></div>`; return; }
  html += `<div class="table-wrap"><table class="t"><thead><tr><th>Rule name</th><th>Conditions</th><th>Action</th><th>Active</th><th></th></tr></thead><tbody>${store.rules.map((r, k) => `<tr><td><b>${esc(r.json.rule_name)}</b><div class="small muted">${r.campaign} · ${new Date(r.created).toLocaleString('en-GB')}</div></td><td class="small">${r.json.conditions.map((x) => `${esc(x.field)} ${esc(x.logical_condition)} <code>${esc(x.field_value.slice(0, 60))}</code>`).join('<br>')}</td><td>${esc(r.json.action.type.replace(/_/g, ' '))}</td><td><label class="switch"><input type="checkbox" data-k="${k}" ${r.on ? 'checked' : ''} aria-label="Rule active"/></label></td><td><button class="btn red" data-del="${k}" type="button">Remove</button></td></tr>`).join('')}</tbody></table></div>`;
  view.innerHTML = html;
  view.querySelectorAll('input[data-k]').forEach((i) => (i.onchange = () => { store.rules[+i.dataset.k].on = i.checked; save(); toast(i.checked ? 'Rule activated' : 'Rule deactivated'); }));
  view.querySelectorAll('[data-del]').forEach((b) => (b.onclick = () => { store.rules.splice(+b.dataset.del, 1); save(); route(); }));
}

function renderStub(page) {
  setNav(page);
  view.innerHTML = `<h1 class="page">${esc({ dashboard: 'Dashboard', events: 'Events', websites: 'Websites', support: 'Support', profile: 'Profile' }[page] || 'Not found')}</h1><div class="empty"><h3>Not part of this demo</h3><p>Only the new Campaigns page is built here. It sits next to Events because it is built from the same event stream.</p><a class="btn purple" href="#/campaigns">Open Campaigns</a></div>`;
}
function renderLoading() { view.innerHTML = '<h1 class="page">Campaigns</h1>' + '<div class="skel" style="width:50%"></div>'.repeat(1) + '<div class="kpis">' + '<div class="kpi" style="background:#eee"></div>'.repeat(4) + '</div>' + '<div class="skel"></div>'.repeat(6); }
function renderError() { view.innerHTML = `<h1 class="page">Campaigns</h1><div class="alert" role="alert">Could not load campaign analysis (${esc(LOADERR?.message || 'error')}).</div><button class="btn purple" id="retry" type="button">Retry</button>`; $('#retry').onclick = boot; }

// ---------- misc
function download(name, text, type) { const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([text], { type })); a.download = name; document.body.appendChild(a); a.click(); setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 0); toast(`Downloaded ${name}`); }
let tt; function toast(m) { const t = $('#toast'); t.textContent = m; t.hidden = false; clearTimeout(tt); tt = setTimeout(() => (t.hidden = true), 2600); }
function exportList() { download('campaigns.csv', ['id,status,sessions,ips,networks,countries,domains,requests,human_share_upper,rule_coverage,signature', ...AN.campaigns.map((c) => [c.id, c.confirmed ? 'confirmed' : 'suspected', c.n, c.ips, c.asns, c.countries, c.domains, c.requests, c.confirm.upper.toFixed(4), c.deploy ? c.deploy.explore.coverage.toFixed(4) : '', '"' + c.itemset.map(([f, v]) => FIELD_SHORT[f] + '=' + valLabel(f, v)).join(' & ').replace(/"/g, '""') + '"'].join(','))].join('\n'), 'text/csv'); }
function help() { const m = $('#modal'); m.innerHTML = `<div class="dialog" role="dialog" aria-modal="true" aria-labelledby="ht"><h3 id="ht">Keyboard shortcuts</h3><table><tr><td><kbd>j</kbd> / <kbd>k</kbd></td><td>Next / previous campaign</td></tr><tr><td><kbd>Enter</kbd></td><td>Open campaign</td></tr><tr><td><kbd>Esc</kbd></td><td>Back to campaigns</td></tr><tr><td><kbd>e</kbd></td><td>Export CSV</td></tr><tr><td><kbd>?</kbd></td><td>This help</td></tr></table><div class="acts"><button class="btn purple" id="hc" type="button">Close</button></div></div>`; m.hidden = false; $('#hc').focus(); $('#hc').onclick = () => { m.hidden = true; m.innerHTML = ''; }; }
document.addEventListener('keydown', (e) => {
  if (e.target.matches('input, select, textarea') || e.metaKey || e.ctrlKey || e.altKey) return;
  const m = $('#modal'); if (!m.hidden) { if (e.key === 'Escape') { m.hidden = true; m.innerHTML = ''; } return; }
  if (!AN) return; const { page, id } = parseHash(); if (page !== 'campaigns') return;
  const n = AN.campaigns.length;
  if (e.key === '?') help();
  else if (e.key === 'Escape' && id) location.hash = '#/campaigns';
  else if (e.key === 'e') exportList();
  else if (e.key === 'j' || e.key === 'k') { sel = (sel + (e.key === 'j' ? 1 : n - 1)) % n; if (id) location.hash = '#/campaigns/' + AN.campaigns[sel].id; else { view.querySelectorAll('tr.row').forEach((tr) => tr.classList.toggle('sel', +tr.dataset.i === sel)); view.querySelector(`tr.row[data-i="${sel}"]`)?.focus(); } }
  else if (e.key === 'Enter' && !id && document.activeElement?.tagName !== 'TR') location.hash = '#/campaigns/' + AN.campaigns[sel].id;
});
function route() {
  if (!DATA) return LOADERR ? renderError() : renderLoading();
  const { page, id } = parseHash();
  if (page === 'campaigns') id ? renderDetail(id) : renderList();
  else if (page === 'rules') renderRules();
  else renderStub(page);
  window.scrollTo(0, 0);
}
window.addEventListener('hashchange', route);
window.addEventListener('resize', () => { clearTimeout(window.__rz); window.__rz = setTimeout(route, 200); });
async function boot() { renderLoading(); await load(); route(); }
boot();
