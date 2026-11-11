// Seeded generator: one day of sessions on a hosting provider's GateKeeper node
// (40 customer domains). Ground truth is kept in `truth` and used only for evaluation.
import { mulberry32 } from '../src/campaigns.js';

// Real-looking fingerprints. Chrome/Edge/Samsung share the Chromium TLS and HTTP/2 stack.
const JA4 = { chrome: 't13d1516h2_8daaf6152771_02713d6af862', firefox: 't13d1715h2_5b57614c22b0_3d5424432f57', safari: 't13d2014h2_a09f3c656075_14788d8d241b', go: 't13d1312h2_f57a46bbacb6_ab7e3b40a677', py: 't13d1812h1_85036bcba153_375ca2c5e164' };
const H2 = { chrome: '1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p', firefox: '1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s', safari: '2:0;3:100;4:2097152;9:1|10420225|0|m,s,a,p', go: '1:65536;3:1000;4:4194304;6:10485760|1073741824|0|m,s,a,p', h1: 'HTTP/1.1' };
const HDR = { chrome: 'host,sec-ch-ua,sec-ch-ua-mobile,sec-ch-ua-platform,upgrade-insecure-requests,user-agent,accept,sec-fetch-site,sec-fetch-mode,sec-fetch-user,sec-fetch-dest,accept-encoding,accept-language,cookie', firefox: 'host,user-agent,accept,accept-language,accept-encoding,referer,connection,cookie,upgrade-insecure-requests,sec-fetch-dest,sec-fetch-mode,sec-fetch-site,sec-fetch-user', safari: 'host,accept,sec-fetch-site,cookie,sec-fetch-dest,accept-language,sec-fetch-mode,user-agent,accept-encoding', cffi: 'host,user-agent,accept,accept-language,accept-encoding,connection', go: 'host,user-agent,accept,accept-encoding', py: 'host,user-agent,accept-encoding,accept,connection' };
const UA = {
  chromeWin: (v) => `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${v}.0.0.0 Safari/537.36`,
  chromeMac: (v) => `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${v}.0.0.0 Safari/537.36`,
  chromeAnd: (v) => `Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${v}.0.0.0 Mobile Safari/537.36`,
  edge: (v) => `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${v}.0.0.0 Safari/537.36 Edg/${v}.0.0.0`,
  firefox: (v) => `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:${v}.0) Gecko/20100101 Firefox/${v}.0`,
  safariIos: (v) => `Mozilla/5.0 (iPhone; CPU iPhone OS ${v}_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/${v}.0 Mobile/15E148 Safari/604.1`,
  safariMac: (v) => `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/${v}.0 Safari/605.1.15`,
  criOS: (v) => `Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/${v}.0.0.0 Mobile/15E148 Safari/604.1`,
};
// Residential and mobile ISPs (real ASNs) in the node's markets, plus proxy-heavy markets and clouds.
const RES = [[3320, 'Deutsche Telekom AG', 'DE', 14], [3209, 'Vodafone GmbH', 'DE', 8], [6805, 'Telefonica Germany', 'DE', 5], [5617, 'Orange Polska', 'PL', 6], [12912, 'T-Mobile Polska', 'PL', 4], [1136, 'KPN B.V.', 'NL', 5], [33915, 'Vodafone Libertel (Ziggo)', 'NL', 4], [2856, 'British Telecommunications', 'GB', 6], [5607, 'Sky UK', 'GB', 4], [7922, 'Comcast Cable', 'US', 8], [20115, 'Charter Communications', 'US', 5], [701, 'Verizon Business', 'US', 4], [3215, 'Orange S.A.', 'FR', 5], [12322, 'Free SAS', 'FR', 3], [8708, 'RCS & RDS', 'RO', 3], [6830, 'Liberty Global', 'AT', 2]];
const PROXY = [[28573, 'Claro NXT', 'BR', 6], [27699, 'Telefonica Brasil', 'BR', 5], [7552, 'Viettel Group', 'VN', 5], [55836, 'Reliance Jio', 'IN', 6], [9498, 'Bharti Airtel', 'IN', 5], [9121, 'Turk Telekom', 'TR', 4], [8151, 'UNINET (Telmex)', 'MX', 4], [17974, 'Telkomnet Indonesia', 'ID', 4], [4134, 'Chinanet', 'CN', 2]];
const CLOUD = [[45102, 'Alibaba US Technology Co., Ltd.', 'HK', 6], [132203, 'Tencent Building, Kejizhongyi Avenue', 'SG', 4], [24940, 'Hetzner Online GmbH', 'DE', 3], [16276, 'OVH SAS', 'FR', 3], [14061, 'DigitalOcean, LLC', 'US', 3], [16509, 'Amazon.com, Inc.', 'US', 3]];
const GOOGLE = [15169, 'Google LLC', 'US'], MSFT = [8075, 'Microsoft Corporation', 'US'];
const SHOPS = ['plumberion.shop', 'veselba-moda.pl', 'kafence.de', 'zahradni-svet.cz', 'oranjefiets.nl', 'atelier-lumen.fr', 'northfield-outdoor.co.uk', 'brickhaus.de'];
const BLOGS = ['tech-notizen.de', 'kuchnia-ani.pl', 'reisblog.nl', 'mountainmiles.co.uk', 'petitecuisine.fr', 'gartenfreund.de', 'pixelpost.dev', 'running-diary.com', 'nordlicht-foto.de', 'stadtgeschichten.de', 'budget-travel.pl', 'woodshop-notes.com', 'fotografia-krakow.pl', 'lekker-koken.nl', 'cyclingroutes.eu', 'gamedev-log.io', 'homelab-wiki.net', 'muzyka-dzis.pl', 'leesclub.nl', 'kinderzimmer-ideen.de', 'craftbeer-review.de', 'paris-balades.fr', 'linux-tipps.de', 'zahnarzt-mueller.de', 'kanzlei-berg.de', 'yoga-studio-mila.pl', 'immobilien-nord.de', 'autohaus-krebs.de', 'hotel-seeblick.at', 'weingut-hofmann.de', 'bakery-oskar.nl', 'tierarzt-sonne.de'];
const DOMAINS = [...SHOPS, ...BLOGS];
const LANGS = { DE: 'de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7', PL: 'pl-PL,pl;q=0.9,en-US;q=0.8,en;q=0.7', NL: 'nl-NL,nl;q=0.9,en-US;q=0.8,en;q=0.7', GB: 'en-GB,en;q=0.9', US: 'en-US,en;q=0.9', FR: 'fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7', RO: 'ro-RO,ro;q=0.9,en-US;q=0.8,en;q=0.7', AT: 'de-AT,de;q=0.9,en;q=0.8' };

export function generateDay(seed = 20261110, opts = {}) {
  const rng = mulberry32(seed);
  const pick = (arr) => arr[Math.floor(rng() * arr.length)];
  const wpick = (arr, wi = 3) => { const tot = arr.reduce((s, a) => s + a[wi], 0); let u = rng() * tot; for (const a of arr) { u -= a[wi]; if (u <= 0) return a; } return arr[arr.length - 1]; };
  const ipOf = new Map(); let ipSeq = 0;
  const newIp = (asn) => { // stable fake prefixes per ASN, random host part
    if (!ipOf.has(asn)) ipOf.set(asn, [11 + (asn * 7) % 200, (asn * 13) % 250]);
    const [a, b] = ipOf.get(asn); ipSeq++;
    return `${a}.${b}.${Math.floor(rng() * 254) + 1}.${Math.floor(rng() * 254) + 1}`;
  };
  const S = [];
  const add = (s) => S.push(s);
  const hourHuman = () => { // diurnal curve, Europe
    const u = rng(); const h = Math.floor(24 * u); const wgt = [0.3, 0.2, 0.15, 0.12, 0.12, 0.2, 0.4, 0.7, 0.9, 1, 1, 1, 1, 1, 0.95, 0.95, 1, 1.05, 1.15, 1.25, 1.3, 1.2, 0.9, 0.55];
    return rng() < wgt[h] / 1.3 ? h : hourHuman();
  };
  const scale = opts.scale ?? 1;
  // ---------------- humans
  const profiles = [
    ['chromeWin', 'chrome', 0.27], ['chromeMac', 'chrome', 0.06], ['chromeAnd', 'chrome', 0.17], ['edge', 'chrome', 0.08], ['firefox', 'firefox', 0.06],
    ['safariIos', 'safari', 0.2], ['safariMac', 'safari', 0.06], ['criOS', 'safari', 0.04], ['privacyChrome', 'chrome', 0.02], ['other', 'chrome', 0.04],
  ];
  const nHuman = Math.round(20000 * scale);
  for (let k = 0; k < nHuman; k++) {
    let u = rng(), prof = profiles[0];
    for (const p of profiles) { u -= p[2]; if (u <= 0) { prof = p; break; } }
    const isp = wpick(RES);
    const cc = isp[2];
    const chromeV = 126 + Math.floor(rng() * 6), ffV = 128 + Math.floor(rng() * 5), sfV = 17 + Math.floor(rng() * 2);
    let ua, chua = 'absent', stack = prof[1];
    if (prof[0] === 'privacyChrome') { ua = UA.chromeWin(chromeV); chua = 'absent'; }
    else if (prof[0] === 'other') { ua = UA.chromeWin(110 + Math.floor(rng() * 16)); chua = 'present'; }
    else if (stack === 'chrome') { ua = UA[prof[0]](chromeV); chua = 'present'; }
    else if (stack === 'firefox') ua = UA.firefox(ffV);
    else ua = UA[prof[0]](prof[0] === 'criOS' ? chromeV : sfV);
    const shopper = rng() < 0.45;
    const dom = shopper ? pick(SHOPS) : pick(BLOGS);
    const path = shopper ? pick(['/product/*', '/product/*', '/category/*', '/', '/cart', '/search', '/my-account']) : pick(['/blog/*', '/blog/*', '/', '/about', '/contact', '/wp-login.php']);
    const reqs = 2 + Math.floor(-Math.log(1 - rng()) * 9);
    add({ kind: 'human', ip: newIp(isp[0]), asn: isp[0], asnName: isp[1], cc, ja4: JA4[stack], h2: H2[stack], hdr: HDR[stack], chua, al: rng() < 0.9 ? LANGS[cc] : LANGS.US, ua, path, dom,
      cookie: rng() < 0.97 ? 'returned' : 'none', js: rng() < 0.96 ? 'executed' : 'none', cadence: 'irregular', req: reqs, dur: 1 + Math.round(reqs * (0.5 + rng() * 2)), hour: hourHuman(), pass: 0.985 });
  }
  // ---------------- good bots (verified search engines)
  for (let k = 0; k < 1800 * scale; k++) {
    const g = rng() < 0.7 ? GOOGLE : MSFT;
    add({ kind: 'goodbot', ip: newIp(g[0]), asn: g[0], asnName: g[1], cc: g[2], ja4: g === GOOGLE ? JA4.chrome : 't13d1011h2_4b22cbed5bed_7af1ed941c26', h2: g === GOOGLE ? H2.chrome : H2.go, hdr: 'host,connection,from,user-agent,accept,accept-encoding', chua: 'absent', al: 'none',
      ua: g === GOOGLE ? 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)' : 'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)', path: pick(['/robots.txt', '/', '/blog/*', '/product/*', '/category/*']), dom: pick(DOMAINS),
      cookie: 'none', js: 'none', cadence: 'regular', req: 3 + Math.floor(rng() * 30), dur: 10 + Math.floor(rng() * 60), hour: Math.floor(rng() * 24), pass: 0, noHoldout: true });
  }
  // ---------------- simple bad bots from datacenters (already handled by per-IP limits / core rules)
  for (let k = 0; k < 120 * scale; k++) {
    const c = wpick(CLOUD); const ip = newIp(c[0]); const sessions = 1 + Math.floor(rng() * 4);
    const tool = pick([['python-requests/2.32.3', 'py', 'py'], ['Go-http-client/1.1', 'go', 'go'], ['curl/8.5.0', 'py', 'py'], ['Scrapy/2.11 (+https://scrapy.org)', 'py', 'py']]);
    for (let s = 0; s < sessions; s++) add({ kind: 'badbot', ip, asn: c[0], asnName: c[1], cc: c[2], ja4: JA4[tool[1]], h2: tool[1] === 'go' ? H2.go : H2.h1, hdr: HDR[tool[2]], chua: 'absent', al: 'none', ua: tool[0],
      path: pick(['/product/*', '/blog/*', '/wp-login.php', '/xmlrpc.php', '/.env', '/']), dom: pick(DOMAINS), cookie: 'none', js: 'none', cadence: 'regular', req: 200 + Math.floor(rng() * 1500), dur: 5 + Math.floor(rng() * 25), hour: Math.floor(rng() * 24), pass: 0 });
  }
  // ---------------- campaigns (the targets)
  // C1: price scraper on 3 shops through residential proxies; curl_cffi impersonating Chrome
  //     (same JA4 and HTTP/2 as real Chrome), but its own header order, no client hints.
  const c1Shops = SHOPS.slice(0, 3);
  const c1UA = [128, 129, 130, 131].flatMap((v) => [UA.chromeWin(v), UA.chromeMac(v)]).slice(0, 6);
  for (let k = 0; k < 2600 * scale; k++) {
    const isp = rng() < 0.55 ? wpick(PROXY) : wpick(RES);
    const ip = newIp(isp[0]); const n = 1 + Math.floor(rng() * 2);
    for (let s = 0; s < n; s++) add({ kind: 'C1', ip, asn: isp[0], asnName: isp[1], cc: isp[2], ja4: JA4.chrome, h2: H2.chrome, hdr: HDR.cffi, chua: 'absent', al: 'en-US,en;q=0.9', ua: pick(c1UA),
      path: rng() < 0.9 ? '/product/*' : '/category/*', dom: pick(c1Shops), cookie: 'none', js: 'none', cadence: 'regular', req: 2 + Math.floor(rng() * 6), dur: 1 + Math.floor(rng() * 3), hour: Math.floor(rng() * 24), pass: 0 });
  }
  // C2: AI crawler spoofing Safari from cloud pools (Go TLS stack), hits blogs at night.
  const c2UA = [UA.safariMac(17), UA.safariMac(18)];
  for (let k = 0; k < 520 * scale; k++) {
    const c = rng() < 0.7 ? CLOUD[0] : CLOUD[1]; const ip = newIp(c[0]);
    for (let s = 0; s < 1 + Math.floor(rng() * 3); s++) add({ kind: 'C2', ip, asn: c[0], asnName: c[1], cc: c[2], ja4: JA4.go, h2: H2.go, hdr: HDR.go, chua: 'absent', al: rng() < 0.5 ? 'none' : 'en-US,en;q=0.9', ua: pick(c2UA),
      path: rng() < 0.85 ? '/blog/*' : '/', dom: pick(BLOGS), cookie: 'none', js: 'none', cadence: 'regular', req: 3 + Math.floor(rng() * 12), dur: 1 + Math.floor(rng() * 4), hour: (22 + Math.floor(rng() * 8)) % 24, pass: 0 });
  }
  // C3: low-and-slow credential stuffing on WordPress/WooCommerce logins from mobile proxies.
  const c3UA = [UA.chromeAnd(129), UA.chromeAnd(130), UA.safariIos(17), UA.safariIos(18)];
  for (let k = 0; k < 900 * scale; k++) {
    const isp = wpick(PROXY.concat(RES.slice(0, 6))); const ip = newIp(isp[0]);
    add({ kind: 'C3', ip, asn: isp[0], asnName: isp[1], cc: isp[2], ja4: JA4.py, h2: H2.h1, hdr: HDR.py, chua: 'absent', al: 'en-US,en;q=0.5', ua: pick(c3UA),
      path: rng() < 0.6 ? '/wp-login.php' : '/my-account', dom: pick(DOMAINS), cookie: rng() < 0.5 ? 'returned' : 'none', js: 'none', cadence: 'regular', req: 2 + Math.floor(rng() * 3), dur: 2 + Math.floor(rng() * 6), hour: Math.floor(rng() * 24), pass: 0 });
  }
  // C4: sneaker-style scalper at a 11:00 drop on one shop, rotating residential IPs, Chrome-like TLS.
  for (let k = 0; k < 180 * scale; k++) {
    const isp = wpick(RES); const ip = newIp(isp[0]);
    add({ kind: 'C4', ip, asn: isp[0], asnName: isp[1], cc: isp[2], ja4: JA4.chrome, h2: H2.chrome, hdr: HDR.chrome, chua: 'present', al: LANGS[isp[2]] || LANGS.US, ua: UA.chromeWin(130),
      path: '/cart/add', dom: SHOPS[3], cookie: 'returned', js: 'none', cadence: 'regular', req: 4 + Math.floor(rng() * 10), dur: 1, hour: 11, pass: 0.03 });
  }
  // Verification holdout: a random 15% of sessions (excluding verified search engines) get an
  // invisible challenge; `verified` = challenged and passed. Humans pass 98.5%, bots rarely (solver farms).
  const HOLDOUT = opts.holdout ?? 0.15;
  for (const s of S) { s.holdout = !s.noHoldout && rng() < HOLDOUT ? 1 : 0; s.verified = s.holdout && rng() < s.pass ? 1 : 0; s.split = rng() < 0.5 ? 0 : 1; delete s.pass; delete s.noHoldout; }
  // shuffle rows so ids carry no information
  for (let i = S.length - 1; i > 0; i--) { const j = Math.floor(rng() * (i + 1)); [S[i], S[j]] = [S[j], S[i]]; }
  return S;
}

// Dictionary-encode into the column table used by the core and the app.
export const COLS = ['ip', 'asn', 'cc', 'ja4', 'h2', 'hdr', 'chua', 'al', 'ua', 'path', 'dom', 'cookie', 'js', 'cadence'];
export function encode(S) {
  const vocab = {}; const cols = {};
  for (const c of COLS) { vocab[c] = []; cols[c] = new Array(S.length); }
  const idx = {}; for (const c of COLS) idx[c] = new Map();
  S.forEach((s, i) => {
    for (const c of COLS) { const v = String(s[c]); let k = idx[c].get(v); if (k === undefined) { k = vocab[c].length; vocab[c].push(v); idx[c].set(v, k); } cols[c][i] = k; }
  });
  cols.req = S.map((s) => s.req); cols.dur = S.map((s) => s.dur); cols.hour = S.map((s) => s.hour); cols.verified = S.map((s) => s.verified); cols.holdout = S.map((s) => s.holdout); cols.split = S.map((s) => s.split);
  const asnName = {}; S.forEach((s) => { asnName[s.asn] = s.asnName; });
  return { n: S.length, cols, vocab, asnName, truth: S.map((s) => s.kind) };
}
