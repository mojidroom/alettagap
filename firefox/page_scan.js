/* AlettaGAP page scanner — injected into MAIN world via chrome.scripting.
 * Requires alettgap_lib.js + window.__ALETTAGAP_CFG preset.
 * Result is stored on window.__ALETTAGAP_RESULT (read back by the service worker). */
window.__ALETTAGAP_RESULT = (function () {
  const G = window.AlettaGAP;
  if (!G) return { error: 'lib missing' };
  const cfg = window.__ALETTAGAP_CFG || { secrets: [] };
  const MODES = Object.assign({ params: true, links: true, words: true }, cfg.modes || {});
  const acc = G.newAcc();
  const loc = location.href;

  // 1) full DOM HTML (cap 4 MB)
  let html = '';
  try { html = document.documentElement.outerHTML.slice(0, 4000000); } catch (e) { return { error: 'dom unreadable' }; }
  G.scanBlob(html, loc, acc, cfg);

  // 2) inline <script> bodies (secrets + endpoints often live only here)
  let inline = 0;
  document.querySelectorAll('script:not([src])').forEach(s => {
    if (inline++ < 300 && s.textContent) G.scanBlob(s.textContent, loc, acc, cfg);
  });

  // 3) live URL + DOM structure params
  if (MODES.params) { try { for (const [k] of (new URL(loc)).searchParams) G.addParam(acc.params, k, 'Firm'); } catch (e) {} }
  document.querySelectorAll('a[href]').forEach(a => {
    try {
      const u = new URL(a.href, loc);
      if (MODES.params) for (const [k] of u.searchParams) G.addParam(acc.params, k, 'Firm');
      if (MODES.links && u.origin === location.origin && u.pathname.length > 1) acc.endpoints.add(u.pathname);
    } catch (e) {}
  });
  document.querySelectorAll('form').forEach(f => {
    if (f.action && MODES.links) { try { acc.endpoints.add(new URL(f.action, loc).pathname); } catch (e) {} }
  });
  document.querySelectorAll('input,textarea,select,button').forEach(el => {
    if (!MODES.params) return;
    if (el.name) G.addParam(acc.params, el.name, 'Firm');
    if (el.id) G.addParam(acc.params, el.id, 'Sus');
  });

  // 4) external scripts for the worker to mine (same-origin + CDN)
  document.querySelectorAll('script[src]').forEach(s => {
    try { acc.scripts.add(new URL(s.src, loc).href); } catch (e) {}
  });

  // 5) target-specific wordlist: endpoint segments + identifiers
  if (MODES.words) {
  for (const ep of acc.endpoints) {
    ep.split(/[/?&=,\-_.{}[\]()]/).forEach(w => {
      if (w && /^[A-Za-z][A-Za-z0-9_]{2,30}$/.test(w)) acc.words.add(w.toLowerCase());
    });
  }
  const RE_WORDS = /(?<!\/)\b\w{3,}\b(?!\/)/g;
  let wm, wn = 0;
  while ((wm = RE_WORDS.exec(html)) && wn++ < 6000) acc.words.add(wm[0].toLowerCase());
  }

  return {
    ok: true,
    origin: location.origin,
    url: loc,
    title: document.title || '',
    params: [...acc.params],
    endpoints: [...acc.endpoints],
    epMethods: Object.fromEntries([...acc.endpoints].map(e => [e, [...(acc.epMethods[e] || [])]]).filter(x => x[1].length)),
    secrets: acc.secrets,
    scripts: [...acc.scripts].slice(0, 80),
    sourcemaps: [...acc.sourcemapUrls].slice(0, 40),
    words: [...acc.words],
  };
})();
