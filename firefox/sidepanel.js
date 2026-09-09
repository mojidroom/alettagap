/* AlettaGAP sidebar UI — Firefox MV2 port of the Chrome side panel. */
'use strict';

const api = (typeof browser !== 'undefined' && browser.runtime) ? browser : chrome;

let currentOrigin = null;
let currentTab = 'params';
let currentData = null;
const $ = (id) => document.getElementById(id);

const send = (msg) => Promise.resolve(api.runtime.sendMessage(msg));

async function activeTabUrl() {
  const httpRe = /^https?:/i;
  const cur = await api.tabs.query({ active: true, currentWindow: true });
  if (cur && cur[0] && httpRe.test(cur[0].url || '')) return cur[0].url;
  const norm = await api.tabs.query({ windowType: 'normal', active: true });
  for (const t of norm || []) if (httpRe.test(t.url || '')) return t.url;
  return cur && cur[0] && cur[0].url;
}

function esc(s) { return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }

function setStatus(text, cls) {
  const el = $('status');
  el.textContent = text;
  el.className = 'statusbar' + (cls ? ' ' + cls : '');
}


// ---------- random-value injection (separate from param extraction) ----------
const randInt = (n) => Math.floor(Math.random() * n);
const randDigits = (n) => Array.from({ length: n }, () => randInt(10)).join('');
const randAlnum = (n) => Array.from({ length: n }, () =>
  'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'[randInt(62)]).join('');

// traceable randoms: one numeric run-nonce + a 2-digit index per param.
// grep the response body for the nonce to see which params reflected; the
// trailing 2 digits tell you WHICH param number carried it.
let runNonce = '';
function nonce() { if (!runNonce) runNonce = randDigits(8); return runNonce; }
function reseed() { runNonce = randDigits(8); return runNonce; }
function idx2(i) { return String(i % 100).padStart(2, '0'); }
function trace(i, tail) { return nonce() + idx2(i) + randAlnum(tail || 4); }

function valueForParam(name, cat, idx) {
  const i = idx || 0;
  const lc = String(name).toLowerCase();
  // every shape still contains the numeric nonce so a single Ctrl+F finds it all
  if (/email/.test(lc)) return trace(i, 3) + '@example.com';
  if (/phone|mobile|tel/.test(lc)) return '09' + runNonce + idx2(i);
  if (/redirect|url|next|return|dest|target|callback/.test(lc)) return 'https://t' + runNonce + idx2(i) + '.invalid/x';
  if (/(id|_at|at)$/.test(lc) || /^(page|offset|limit|year|month|day|amount|price|qty|code)$/.test(lc) || lc === 'rrn') return trace(i, 4);
  if (/token|key|secret|sig|hash|otp|csrf/.test(lc)) return trace(i, 18);
  return trace(i, 4);
}

function tryLinkVal(origin, path, param, cat, idx) {
  const base = path.startsWith('http') ? path : origin + (path.startsWith('/') ? path : '/' + path);
  const u = new URL(base, origin);
  if (param) u.searchParams.set(param, valueForParam(param, cat, idx));
  return u.href;
}

async function render() {
  if (!currentData) { $('content').innerHTML = ''; return; }
  const d = currentData;
  $('c-params').textContent = d.params.length;
  $('c-endpoints').textContent = d.endpoints.length;
  $('c-secrets').textContent = d.secrets.length;
  $('c-words').textContent = d.words.length;

  const f = $('filter').value.trim().toLowerCase();
  const susByName = {};
  for (const s of (d.sus || [])) susByName[s.name] = s.sus;
  const out = [];

  if (currentTab === 'params') {
    const rank = { Firm: 0, Sus: 1, Tentative: 2 };
    const epSet = new Set(d.endpoints);
    // separation guard: never list an endpoint (with or without leading slash) as a param
    let rows = [...d.params]
      .filter(p => !p.name.includes('/') && !epSet.has(p.name) && !epSet.has('/' + p.name))
      .sort((a, b) => (rank[a.cls] - rank[b.cls]) || a.name.localeCompare(b.name));
    if (f) rows = rows.filter(p => p.name.toLowerCase().includes(f) || (susByName[p.name] || '').toLowerCase().includes(f));
    out.push('<table><tr><th>Parameter</th><th>Class</th><th>Sus</th><th>Try</th></tr>');
    rows.forEach((p, rowIdx) => {
      const cat = susByName[p.name];
      const mk = (path) => tryLinkVal(d.origin, path, p.name, cat, rowIdx);
      out.push(`<tr><td class="name" data-copy="${esc(p.name)}">${esc(p.name)}</td>` +
        `<td><span class="cls ${p.cls}">${p.cls}</span></td>` +
        `<td class="suscat">${cat ? esc(cat) : ''}</td>` +
        `<td><button class="act fuzz" data-open="${esc(mk('/'))}">/?${esc(p.name)}=…</button>` +
        `<button class="act fuzz" data-open="${esc(mk(d.endpoints[0] || '/'))}">first ep</button></td></tr>`);
    });
    out.push('</table>');
    if (!rows.length) out.push('<div class="nodata">' + (f ? 'No params match the filter.' : 'No params found for this origin yet.') + '</div>');
  } else if (currentTab === 'endpoints') {
    const pNames = new Set(d.params.map(p => p.name));
    // separation guard: endpoints must look like paths (contain '/') and not be bare param names
    let eps = [...d.endpoints].filter(e => (e.includes('/') || e.startsWith('http')) && !pNames.has(e.replace(/^\//, ''))).sort();
    if (f) eps = eps.filter(e => e.toLowerCase().includes(f) || ((d.epMethods || {})[e] || []).some(m => m.toLowerCase().includes(f)));
    const epM = d.epMethods || {};
    out.push('<table><tr><th>Endpoint</th><th>Methods</th><th></th></tr>');
    for (const e of eps) {
      const meths = (epM[e] || []);
      out.push(`<tr><td class="name" data-copy="${esc(e)}">${esc(e)}</td>` +
        `<td class="meths">${meths.map(m => `<span class="mchip ${m.toLowerCase()}">${m}</span>`).join('')}</td>` +
        `<td><button class="act" data-open="${esc(new URL(e, d.origin).href)}">open</button></td></tr>`);
    }
    out.push('</table>');
    if (!eps.length) out.push('<div class="nodata">' + (f ? 'No endpoints match the filter.' : 'No endpoints found for this origin — this page does not expose API paths in HTML/JS. Scan an interactive/logged-in page.') + '</div>');
  } else if (currentTab === 'secrets') {
    let sec = d.secrets;
    if (f) sec = sec.filter(s => (s.name + s.match).toLowerCase().includes(f));
    out.push('<table><tr><th>Pattern</th><th>Match (truncated)</th><th>Source</th></tr>');
    for (const s of sec.slice(0, 300)) {
      out.push(`<tr><td class="name">${esc(s.name)}</td><td class="secret-match" data-copy="${esc(s.match)}">${esc(s.match)}</td>` +
        `<td class="secret-page">${esc(s.page)}</td></tr>`);
    }
    out.push('</table>');
  } else {
    let w = d.words.sort();
    if (f) w = w.filter(x => x.includes(f));
    out.push('<table><tr><th>#</th><th>Word</th></tr>');
    w.slice(0, 1500).forEach((x, i) => out.push(`<tr><td style="color:var(--dim)">${i + 1}</td><td class="name" data-copy="${esc(x)}">${esc(x)}</td></tr>`));
    out.push('</table>');
  }
  $('content').innerHTML = out.join('');
  $('empty').style.display = (d.params.length || d.endpoints.length) ? 'none' : 'block';
  buildJoin(d);
}

function showNoData(msg) {
  currentData = null;
  $('joinbox').style.display = 'none';
  $('content').innerHTML = '<div class="nodata">' + esc(msg) + '</div>';
  $('empty').style.display = 'none';
  $('c-params').textContent = '0';
  $('c-endpoints').textContent = '0';
  $('c-secrets').textContent = '0';
  $('c-words').textContent = '0';
}


// ---------- bottom join box: ALL params &-joined with random values ----------
function xssQuery(d, filter) {
  const susByName = {};
  for (const s of (d.sus || [])) susByName[s.name] = s.sus;
  const seen = new Set();
  const pairs = [];
  for (const p of [...d.params].sort((a, b) => a.name.localeCompare(b.name))) {
    if (seen.has(p.name)) continue;
    seen.add(p.name);
    if (filter && !p.name.toLowerCase().includes(filter)) continue;
    pairs.push(encodeURIComponent(p.name) + '=' + encodeURIComponent(valueForParam(p.name, susByName[p.name], pairs.length)));
  }
  return pairs;
}

function joinUrl(origin, path, pairs) {
  const base = path.startsWith('http') ? path : origin + (path.startsWith('/') ? path : '/' + path);
  if (!pairs.length) return new URL(base, origin).href;
  return base + (base.includes('?') ? '&' : '?') + pairs.join('&');
}

let joinPairs = [];
let joinOrigin = '';

function buildJoin(d) {
  joinOrigin = d.origin;
  reseed();
  joinPairs = xssQuery(d, '');
  const box = $('joinbox');
  if (!joinPairs.length) { box.style.display = 'none'; return; }
  box.style.display = 'block';
  $('join-count').textContent = '(' + joinPairs.length + ' params · trace: ' + runNonce + ' + param#)';
  const full = joinUrl(d.origin, '/', joinPairs);
  const el = $('join-url');
  el.textContent = full;
  el.dataset.copy = full;
  $('join-open').dataset.open = full;
}

function rerollJoin() {
  if (!currentData) return;
  buildJoin(currentData);
}

$('join-copy').addEventListener('click', async () => {
  const txt = joinPairs.length ? $('join-url').dataset.copy : '';
  const b = $('join-copy'); const old = b.textContent;
  if (!txt) { b.textContent = 'nothing'; }
  else {
    window.__lastJoinCopy = txt;
    try { await navigator.clipboard.writeText(txt); } catch (e) {}
    b.textContent = '\u2713 copied ' + joinPairs.length;
  }
  setTimeout(() => { b.textContent = old; }, 900);
});

$('join-refresh').addEventListener('click', rerollJoin);
$('join-save').addEventListener('click', () => {
  if (!currentData || !joinPairs.length) return;
  const d = currentData;
  const lines = [joinUrl(d.origin, '/', joinPairs)];
  for (const ep of [...d.endpoints].sort().slice(0, 500)) lines.push(joinUrl(d.origin, ep, joinPairs));
  const blob = new Blob([lines.join('\n') + '\n'], { type: 'text/plain' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = new URL(d.origin).hostname + '_alettagap_join.txt';
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 3000);
});

// events: copy + open
$('content').addEventListener('click', async (e) => {
  const open = e.target.closest('[data-open]');
  if (open) { api.tabs.create({ url: open.dataset.open }); return; }
  const cp = e.target.closest('[data-copy]');
  if (cp) {
    window.__lastCopy = cp.dataset.copy;
    try { await navigator.clipboard.writeText(cp.dataset.copy); } catch (e2) {}
    const old = cp.textContent; cp.textContent = '✓ copied';
    setTimeout(() => cp.textContent = old, 700);
  }
});

$('tabs').addEventListener('click', (e) => {
  const b = e.target.closest('button[data-tab]');
  if (!b) return;
  document.querySelectorAll('.tabs button').forEach(x => x.classList.remove('active'));
  b.classList.add('active');
  currentTab = b.dataset.tab;
  render();
});
$('filter').addEventListener('input', render);

// GAP-style "Copy" per pane: every visible item of the current tab, one per line
$('copyall').addEventListener('click', async () => {
  const items = [...new Set([...document.querySelectorAll('#content [data-copy]')].map(e => e.dataset.copy))];
  const text = items.join('\n');
  window.__lastCopyAll = text;
  const b = $('copyall'); const old = b.textContent;
  if (!items.length) { b.textContent = 'nothing to copy'; }
  else {
    try { await navigator.clipboard.writeText(text); } catch (e) {}
    b.textContent = '✓ ' + items.length + ' copied';
  }
  setTimeout(() => b.textContent = old, 1000);
});




async function refreshOrigin() {
  const url = await activeTabUrl();
  try {
    const o = url ? new URL(url).origin : null;
    if (o && /^https?:/.test(o)) {
      $('origin').textContent = o;
      if (o !== currentOrigin) { currentOrigin = o; currentData = null; $('content').innerHTML = ''; }
      const r = await send({ type: 'get', origin: o });
      if (r && r.data && (r.data.params.length || r.data.endpoints.length || r.data.secrets.length)) {
        currentData = r.data; render();
      } else {
        $('empty').style.display = 'block';
      }
    } else $('origin').textContent = '—';
  } catch (e) {}
}

function currentModes() {
  const on = (id) => { const el = $(id); return !el || el.checked; };
  return { params: on('m-params'), links: on('m-links'), words: on('m-words') };
}

$('scan').addEventListener('click', async () => {
  $('scan').disabled = true;
  $('content').innerHTML = '';
  $('empty').style.display = 'none';
  currentData = null;
  setStatus('scanning page… (DOM + inline JS)', 'busy');
  const r = await send({ type: 'scan', modes: currentModes() });
  $('scan').disabled = false;
  if (r && r.error) { setStatus('✗ ' + r.error, 'err'); showNoData('Scan failed — ' + r.error); return; }
  currentOrigin = r.origin;
  const g = await send({ type: 'get', origin: currentOrigin });
  currentData = g.data;
  if (currentData && (currentData.params.length || currentData.endpoints.length || currentData.secrets.length)) {
    render();
    setStatus(`✓ ${r.stats.params} params · ${r.stats.endpoints} endpoints · ${r.stats.secrets} secrets`);
  } else {
    $('c-params').textContent = '0'; $('c-endpoints').textContent = '0';
    $('c-secrets').textContent = '0'; $('c-words').textContent = '0';
    $('content').innerHTML = '<div class="nodata">Nothing found on this page —<br>it may be a pure-HTML page with no JS/params/endpoints to harvest. Try a page that runs the app (logged-in / interactive).</div>';
    setStatus('✓ 0 params · 0 endpoints · 0 secrets — nothing extracted', 'err');
  }
});

api.runtime.onMessage.addListener((m) => {
  if (m.type === 'progress') setStatus(`mining ${m.phase}… ${m.done}/${m.total}`, 'busy');
  if (m.type === 'done' && m.origin === currentOrigin) {
    send({ type: 'get', origin: m.origin }).then((g) => {
      if (!g || !g.data) return;
      if (g.data.params.length || g.data.endpoints.length || g.data.secrets.length) {
        currentData = g.data; render();
        setStatus(`✓ ${g.data.params.length} params · ${g.data.endpoints.length} endpoints · ${g.data.secrets.length} secrets (deep-mined)`);
      }
    });
  }
});

$('exp-params').addEventListener('click', () => currentOrigin && send({ type: 'export', origin: currentOrigin, what: 'params' }));
$('exp-endpoints').addEventListener('click', () => currentOrigin && send({ type: 'export', origin: currentOrigin, what: 'endpoints' }));
$('exp-wordlist').addEventListener('click', () => currentOrigin && send({ type: 'export', origin: currentOrigin, what: 'words' }));
$('clear').addEventListener('click', async () => {
  if (!currentOrigin) return;
  await send({ type: 'clear', origin: currentOrigin });
  currentData = null; $('content').innerHTML = ''; render();
  setStatus('cleared ' + currentOrigin);
});

api.tabs.onActivated.addListener(refreshOrigin);
api.tabs.onUpdated.addListener((id, info) => { if (info.status === 'complete') refreshOrigin(); });
refreshOrigin();
