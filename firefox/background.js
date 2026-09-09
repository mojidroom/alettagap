/* AlettaGAP background — Firefox MV2 port of the Chrome service worker.
 * Same pipeline: inject page scanner, deep-mine same-origin JS + sourcemaps,
 * persist per-origin results, serve the sidebar. Uses the combined-code
 * injection strategy so the lib and scanner always share one content scope. */
'use strict';

const api = (typeof browser !== 'undefined' && browser.runtime) ? browser : window.chrome;
const G = window.AlettaGAP; // loaded first via manifest background.scripts

let SECRET_PATTERNS = [];
let SUS_MAP = {};
let STOP_WORDS = new Set();
let loaded = false;
let LIB_SRC = '';
let SCAN_SRC = '';

async function ensureData() {
  if (loaded) return;
  const u = (p) => api.runtime.getURL(p);
  const [sec, params, lib, scan] = await Promise.all([
    fetch(u('secrets_patterns.json')).then(r => r.json()).catch(() => []),
    fetch(u('params_data.json')).then(r => r.json()).catch(() => ({})),
    fetch(u('alettgap_lib.js')).then(r => r.text()),
    fetch(u('page_scan.js')).then(r => r.text()),
  ]);
  SECRET_PATTERNS = sec;
  SUS_MAP = params;
  STOP_WORDS = new Set((params.STOP_WORDS || []).map(w => String(w).toLowerCase()));
  LIB_SRC = lib;
  SCAN_SRC = scan;
  loaded = true;
}

function splitP(enc) {
  const i = enc.indexOf('\u0000');
  return { name: enc.slice(0, i), cls: enc.slice(i + 1) || 'Tentative' };
}

function classifySus(encList) {
  const lower = {};
  for (const cat of Object.keys(SUS_MAP)) {
    if (cat === 'STOP_WORDS') continue;
    for (const p of SUS_MAP[cat]) lower[String(p).toLowerCase()] = cat;
  }
  const out = [];
  for (const enc of encList) {
    const { name } = splitP(enc);
    const cat = lower[name.toLowerCase()];
    if (cat) out.push({ name, sus: cat });
  }
  return out;
}

// find the tab to scan: explicit id → sender window's active http tab →
// any normal window's active http tab (covers sidebar, popup windows, dev E2E)
const httpRe = /^https?:/i;
async function resolveTargetTab(explicitId) {
  if (explicitId) {
    const t = await api.tabs.get(explicitId).catch(() => null);
    if (t && httpRe.test(t.url || '')) return t;
  }
  const cur = await api.tabs.query({ active: true, currentWindow: true });
  if (cur && cur[0] && httpRe.test(cur[0].url || '')) return cur[0];
  const norm = await api.tabs.query({ windowType: 'normal', active: true });
  for (const t of norm || []) if (httpRe.test(t.url || '')) return t;
  return null;
}

const keyFor = (origin) => 'scan:' + origin;
async function getScan(origin) { return (await api.storage.local.get(keyFor(origin)))[keyFor(origin)] || null; }
async function setScan(origin, data) { await api.storage.local.set({ [keyFor(origin)]: data }); }

function mergeScan(oldScan, nw) {
  const uniqBy = (arr, f) => [...new Map((arr || []).map(x => [f(x), x])).values()];
  const params = uniqBy([...(oldScan && oldScan.params || []), ...(nw.params || [])], p => p.name + '|' + p.cls)
    .sort((a, b) => a.name.localeCompare(b.name));
  const epMeta = Object.assign({}, (oldScan && oldScan.epMethods) || {}, nw.epMethods || {});
  const epAll = new Set([...(oldScan && oldScan.endpoints || []), ...(nw.endpoints || [])]);
  const endpoints = [...epAll].sort();
  // separation guard: a param name (bare, no slash) is never an endpoint,
  // and an endpoint path is never kept as a param
  const epSet = new Set(endpoints);
  const cleanParams = params.filter(p => !p.name.includes('/') && !epSet.has(p.name) && !epSet.has('/' + p.name));
  const pNameSet = new Set(cleanParams.map(p => p.name));
  const cleanEndpoints = endpoints.filter(e => !pNameSet.has(e.replace(/^\//, '')) && !pNameSet.has(e));
  const secrets = uniqBy([...(oldScan && oldScan.secrets || []), ...(nw.secrets || [])], s => s.name + '|' + s.match);
  const words = [...new Set([...(oldScan && oldScan.words || []), ...(nw.words || [])])].filter(w => !STOP_WORDS.has(String(w).toLowerCase())).sort();
  const sus = uniqBy([...(oldScan && oldScan.sus || []), ...(nw.sus || [])], s => s.name);
  return {
    origin: nw.origin, url: nw.url, title: nw.title,
    updated: Date.now(), pages: ((oldScan && oldScan.pages) || 0) + 1,
    params: cleanParams, endpoints: cleanEndpoints,
    epMethods: Object.fromEntries(Object.entries(epMeta).filter(([k]) => cleanEndpoints.includes(k))),
    secrets, words, sus,
  };
}

async function broadcast(msg) {
  try { await api.runtime.sendMessage(msg); } catch (e) { /* sidebar not open */ }
}

// one combined injection: config + engine + scanner, then read the result back
async function injectScan(tabId, modes) {
  const cfg = JSON.stringify({ secrets: SECRET_PATTERNS, modes: modes || {} });
  const code = 'window.__ALETTAGAP_CFG=' + cfg + ';\n' + LIB_SRC + '\n' + SCAN_SRC + '\n;window.__ALETTAGAP_RESULT || null;';
  const out = await api.tabs.executeScript(tabId, { code });
  if (Array.isArray(out)) return out[out.length - 1];
  return out;
}

// ---- the actual scan pipeline for one tab ----
async function scanTab(tabId, modes) {
  await ensureData();
  const tab = await api.tabs.get(tabId);
  const tabUrl = tab.url || '';
  const origin = new URL(tabUrl).origin;

  const page = await injectScan(tabId, modes);
  if (!page) throw new Error('Scanner did not run on this page.');
  if (page.error) throw new Error(page.error);

  const acc = {
    params: [...page.params],
    endpoints: [...page.endpoints],
    epMethods: {},
    secrets: [...page.secrets],
    words: [...page.words],
  };
  for (const [ep, meths] of Object.entries(page.epMethods || {})) acc.epMethods[ep] = meths;

  // deep-mine scripts + sourcemaps (background page fetch ignores page CORS/CSP)
  const toFetch = [...new Set([...(page.scripts || []), ...(page.sourcemaps || [])])].slice(0, 120);
  for (let i = 0; i < toFetch.length; i++) {
    const url = toFetch[i];
    await broadcast({ type: 'progress', origin, phase: /\.map($|\?)/.test(url) ? 'sourcemaps' : 'scripts', done: i + 1, total: toFetch.length });
    let text = null;
    try {
      const res = await fetch(url, { credentials: 'include' });
      if (!res.ok) continue;
      const ctype = res.headers.get('content-type') || '';
      if (/image|video|audio|font/.test(ctype)) continue;
      text = await res.text();
    } catch (e) { continue; }
    if (!text) continue;
    if (text.length > 2500000) text = text.slice(0, 2500000);
    if (/\.map($|\?)/.test(url)) {
      try {
        const map = JSON.parse(text);
        text = JSON.stringify(map.sources || []) + JSON.stringify(map.names || []) + (map.sourcesContent || []).join('\n');
      } catch (e) { continue; }
    }
    const a = G.newAcc();
    G.scanBlob(text, url, a, { secrets: SECRET_PATTERNS, modes: modes || {} });
    a.params.forEach(p => acc.params.push(p));
    a.endpoints.forEach(e2 => acc.endpoints.push(e2));
    a.secrets.forEach(s => acc.secrets.push(s));
    for (const [ep, set] of Object.entries(a.epMethods || {})) {
      acc.epMethods[ep] = [...new Set([...(acc.epMethods[ep] || []), ...set])];
    }
  }

  const epList = [...new Set(acc.endpoints)];
  const qSet = new Set();
  G.extractQueryParams(epList, qSet); // fallparams: query keys of endpoints become real params
  qSet.forEach(p => acc.params.push(p));
  const encSet = [...new Set(acc.params)];
  const nw = {
    origin, url: page.url, title: page.title,
    params: encSet.map(splitP),
    endpoints: [...new Set(acc.endpoints)].sort(),
    epMethods: acc.epMethods,
    secrets: acc.secrets,
    words: acc.words,
    sus: classifySus(encSet),
  };
  const prev = await getScan(origin);
  const merged = mergeScan(prev, nw);
  await setScan(origin, merged);
  return merged;
}

// ---- message router (callback style; kept open for async) ----
api.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    try {
      await ensureData();
      if (msg.type === 'scan') {
        const tab = await resolveTargetTab(msg.tabId);
        if (!tab) { sendResponse({ error: 'Open a normal http(s) page first.' }); return; }
        const data = await scanTab(tab.id, msg.modes);
        try {
          await api.browserAction.setBadgeBackgroundColor({ color: '#3fb950' });
          await api.browserAction.setBadgeText({ text: String(data.params.length), tabId: tab.id });
        } catch (e) {}
        sendResponse({ ok: true, origin: data.origin, stats: { params: data.params.length, endpoints: data.endpoints.length, secrets: data.secrets.length, words: data.words.length } });
      } else if (msg.type === 'get') {
        sendResponse({ ok: true, data: await getScan(msg.origin) });
      } else if (msg.type === 'clear') {
        await api.storage.local.remove(keyFor(msg.origin));
        sendResponse({ ok: true });
      } else if (msg.type === 'export') {
        const d = await getScan(msg.origin);
        if (!d) { sendResponse({ error: 'no scan data for ' + msg.origin }); return; }
        let lines, fname;
        if (msg.what === 'params') { lines = [...new Set(d.params.map(p => p.name))].sort(); }
        else if (msg.what === 'endpoints') { lines = [...new Set(d.endpoints)].sort(); }
        else { lines = [...new Set(d.words.filter(w => !STOP_WORDS.has(w)))].sort(); }
        fname = msg.origin.replace(/^https?:\/\//, '').replace(/[^a-z0-9]+/gi, '_') + '_' + msg.what + '.txt';
        const dataUrl = 'data:text/plain;charset=utf-8,' + encodeURIComponent(lines.join('\n'));
        await api.downloads.download({ url: dataUrl, filename: 'AlettaGAP/' + fname, saveAs: false, conflictAction: 'overwrite' });
        sendResponse({ ok: true, count: lines.length });
      } else {
        sendResponse({ error: 'unknown message' });
      }
    } catch (e) {
      sendResponse({ error: String((e && e.message) || e) });
    }
  })();
  return true;
});

// clicking the toolbar icon opens the native sidebar
api.browserAction.onClicked.addListener(() => {
  try { api.sidebarAction.open(); } catch (e) {}
});

// E2E/debug helper: open the panel as a real popup window (moz-extension pages
// cannot be window.open'd from web content; the extension itself can).
api.runtime.onMessage.addListener((msg) => {
  if (msg.type === 'openPanelPopup') {
    const url = api.runtime.getURL('sidepanel.html');
    Promise.resolve(api.windows.create({ url, type: 'popup', width: 480, height: 780 }))
      .then(() => {}).catch(() => {});
  }
});

api.tabs.onUpdated.addListener((tabId, info) => {
  if (info.status === 'loading') api.browserAction.setBadgeText({ text: '', tabId }).catch(() => {});
});
