/* AlettaGAP extraction library — shared by side panel page scan and service worker fetch mining.
 * Engine ports: PortSwigger get-all-parameters (GAP v6) parameter regexes
 *                + SharokhAtaie/extractify endpoint & secret regexes.
 */
(function (global) {
  'use strict';
  const VALID_PARAM = /^[A-Za-z0-9_.~\-\[\]]+$/;
  const BT = String.fromCharCode(96); // backtick

  // ---------- GAP-ported parameter regexes ----------
  const RE_JSONKEYS = /"([a-zA-Z0-9$_.\-]{1,1000}?)":/g;
  const RE_SOURCEMAP = /(?:sourceMappingURL\s*=\s*|SourceMap:\s*)(\S+)/gi;
  const RE_PARAMKEYS = /[?&]([^=&\s"']{2,100})(?==)/g;
  const RE_PARAMSPOSSIBLE = /(?:\?|%3f|\\u003f|&|%26|\\u0026|%3d|\\u003d|=)["']?([a-z0-9_\-]{3,})["']?(?:=|%3d|\\u003d)(?!=)/gi;
  const RE_JSDECL = /(?:let|var|const)\s+([a-zA-Z$_][a-zA-Z0-9$_]{2,200}?)\s*(?:=|,|;|\n)/g;
  const RE_JSNESTED = /(?:JSON\.stringify\(|dataLayer\.push\(|(?:var|let|const)\s+[$A-Za-z0-9_\[\]]{1,1000}\s*=\s*)\s*\{/g;
  const RE_JSNESTEDPARAM = /(?:['"]([A-Za-z0-9_.\-]{1,100})['"]|^\s*([A-Za-z_$][A-Za-z0-9_]{1,100}))\s*:/gm;
  const RE_WORDS = /(?<!\/)\b\w{3,}\b(?!\/)/g;
  const RE_HTML_NAME = /\bname\s*=\s*["']([^"'\s]{1,100})["']/gi;
  // URLSearchParams-style JS-built params: sp.append("userId", v) / .set("page", 1)
  const RE_JS_PARAM_CALL = /(?:searchParams|params|qs|query|urlSearchParams|sp|q)\s*\.\s*(?:append|set|get|has|delete)\s*\(\s*["']([A-Za-z0-9_\-.$~]{2,60})["']/g;

  // ---------- Extractify-ported endpoint regex (quote after =, :, (, ,, [, {, > or return) ----------
  const OPEN = "(?:[=:>(,\\[{]\\s*['" + BT + "\"]|\\breturn\\s*['" + BT + "])";
  const NQ = '[^' + BT + '"\'\\s<>]';
  const EP_PARTS = [
    '[a-zA-Z][a-zA-Z0-9+.-]*:\\/\\/' + NQ + '+',                       // 1) full URLs
    '\\/(?:\\$\\{[^}]+\\}|[a-zA-Z0-9_.-])' + NQ + '*',                  // 2) absolute paths
    '\\.\\.?\\/' + NQ + '+',                                            // 3) relative paths
    '[a-zA-Z0-9_-]+(?:\\/[a-zA-Z0-9_$.' + BT + '{\\}()\\[\\]?&=%,-]+)+', // 4) api-like word/word
    '[a-zA-Z0-9_-]+\\.(?:php|asp|aspx|cfm|pl|jsp|json|js|action|html?|bak|do|txt|xml|xlsx?|key|env|pem|git|ovpn|log|secrets?|access|dat|db|sql|pwd|passwd|properties|dtd|conf|cfg|configs|apk|cgi|sh|py|java|rb|rs|go|ya?ml|toml|php4|zip|tars?|gz|rar|7z|docx?|csv|odt|ts|phtml|php5|pdf|vue|svelte|jsx?|tsx?|s?css|less|styl|wasm|dll|exe|bin|iso|pkg|deb|rpm|msi)\\b', // 5) interesting files
    '\\$\\{[^}]+\\}\\/' + NQ + '+',                                     // 6) template paths
  ];
  const RE_ENDPOINTS = new RegExp(OPEN + '(' + EP_PARTS.join('|') + ')', 'g');
  // also catch "/multi/segment/path" style endpoints as bare quoted/template strings
  const RE_ABS_ENDPOINTS = new RegExp('["\'`]' + '(\\/[a-zA-Z0-9_.$' + BT + '{}/\\}()\\[\\]?&=%,:<>@+~-]{2,400})["\'`]', 'g');

  const EXCLUDE_MIME = new RegExp(
    '^(?:text/javascript|application/javascript|application/x-www-form-urlencoded|' +
    'multipart/form-data|text/css|text/plain|text/html|text/xml|text/csv|image/[a-z+.\\-]+|' +
    'audio/[a-z.\\-]+|video/[a-z.\\-]+|font/[a-z0-9.\\-]+|application/[a-z+.\\-]+)$', 'i');

  function addParam(set, name, cls) {
    if (!name) return;
    name = String(name).trim().replace(/^['"]|['"]$/g, '');
    if (name.length < 1 || name.length > 100) return;
    if (!VALID_PARAM.test(name)) return;
    set.add(name + '\u0000' + cls);
  }

  function extractParamsFromBlob(text, out) {
    let m;
    RE_JSONKEYS.lastIndex = 0;
    while ((m = RE_JSONKEYS.exec(text))) addParam(out, m[1], 'Firm');
    RE_PARAMSPOSSIBLE.lastIndex = 0;
    while ((m = RE_PARAMSPOSSIBLE.exec(text))) addParam(out, m[1], 'Tentative');
    RE_JSDECL.lastIndex = 0;
    while ((m = RE_JSDECL.exec(text))) addParam(out, m[1], 'Sus');
    RE_HTML_NAME.lastIndex = 0;
    while ((m = RE_HTML_NAME.exec(text))) addParam(out, m[1], 'Sus');
    RE_JS_PARAM_CALL.lastIndex = 0;
    while ((m = RE_JS_PARAM_CALL.exec(text))) addParam(out, m[1], 'Firm');
  }

  function extractJsNested(text, out) {
    RE_JSNESTED.lastIndex = 0;
    let m, count = 0;
    while ((m = RE_JSNESTED.exec(text)) && count++ < 300) {
      let i = text.indexOf('{', m.index), depth = 0, start = i, end = -1;
      if (i < 0) continue;
      for (; i < text.length && i - start < 60000; i++) {
        if (text[i] === '{') depth++;
        else if (text[i] === '}') { depth--; if (depth === 0) { end = i; break; } }
      }
      if (end > 0) {
        const obj = text.slice(start + 1, end);
        RE_JSNESTEDPARAM.lastIndex = 0;
        let p, n = 0;
        while ((p = RE_JSNESTEDPARAM.exec(obj)) && n++ < 400) addParam(out, p[1] || p[2], 'Sus');
      }
    }
  }

  const RE_NOISE_EXT = /\.(?:png|jpe?g|gif|webp|avif|ico|bmp|tiff?|heic|woff2?|ttf|eot|otf|mp3|mp4|m4a|webm|ogg|wav|avi|mov|flv|css|map|zip|rar|7z|tar|gz|tgz|bz2)$/i;
  const RE_BAD_SCHEME = /^(?:data|blob|mailto|javascript|vbscript|tel|sms|callto|about|chrome):/i;

  function cleanEp(ep) {
    if (!ep) return null;
    ep = ep.split('#')[0].replace(/[);,]+$/, '').replace(/["'`]+$/, '');
    if (!ep || ep.length < 2 || ep.length > 300) return null;
    if (EXCLUDE_MIME.test(ep)) return null;
    if (RE_BAD_SCHEME.test(ep)) return null;
    if (/\s/.test(ep)) return null;
    if (ep.endsWith('.') || ep.endsWith(',')) return null;
    if (ep.startsWith('/') && RE_NOISE_EXT.test(ep)) return null; // pure static asset, not API surface
    if (ep.endsWith('/') && ep.length > 1) ep = ep.slice(0, -1); // normalize trailing slash
    return ep;
  }

  // JSRecon-Buddy ported call-site patterns -> endpoint + HTTP method
  const RE_CALL_FETCH = /fetch\s*\(\s*["'`]([^"'`\s]+)["'`]\s*,\s*\{(?:[^{}]|\{[^{}]*\}|\[[^\[\]]*\]){0,300}?["'`]?(?:method|METHOD)["'`]?\s*[:=]\s*["'`]?(\w+)/gi;
  const RE_CALL_AXIOS = /(?:axios|\$http|request)\s*\.\s*(get|post|put|patch|delete|head|options)\s*\(\s*["'`]([^"'`\s]+)["'`]/gi;
  const RE_CALL_HTTP = /\b(?:client|api|http|httpClient|apiClient|restClient|service|rpc)\s*\.\s*(get|post|put|patch|delete|head|options)\s*\(\s*["'`]([^"'`\s]+)["'`]/gi;
  const RE_CALL_XHR = /\.open\s*\(\s*["'`](\w+)["'`]\s*,\s*["'`]([^"'`\s]+)["'`]/gi;

  function noteMethod(acc, ep, method) {
    if (!acc || !acc.epMethods) return;
    const k = ep;
    acc.epMethods[k] = acc.epMethods[k] || new Set();
    if (method) acc.epMethods[k].add(String(method).toUpperCase());
  }

  function extractEndpoints(text, out, acc) {
    let m, n = 0;
    RE_ENDPOINTS.lastIndex = 0;
    while ((m = RE_ENDPOINTS.exec(text)) && n++ < 4000) {
      const ep = cleanEp(m[1]);
      if (ep) out.add(ep);
    }
    RE_ABS_ENDPOINTS.lastIndex = 0;
    while ((m = RE_ABS_ENDPOINTS.exec(text)) && n++ < 8000) {
      const ep = cleanEp(m[1]);
      if (ep) out.add(ep);
    }
    if (!acc) return;
    const calls = [[RE_CALL_FETCH, 1, 2], [RE_CALL_AXIOS, 2, 1], [RE_CALL_HTTP, 2, 1], [RE_CALL_XHR, 2, 1]];
    for (const [re, epG, mG] of calls) {
      re.lastIndex = 0; let k = 0;
      while ((m = re.exec(text)) && k++ < 2000) {
        const ep = cleanEp(m[epG]);
        if (ep) { out.add(ep); noteMethod(acc, ep, m[mG]); }
      }
    }
  }

  function extractSecrets(text, pageUrl, out, patterns) {
    for (const s of patterns) {
      try {
        const re = new RegExp(s.regex, 'gi');
        let m, n = 0;
        while ((m = re.exec(text)) && n++ < 30) {
          out.push({ name: s.name, match: (m[1] || m[0] || '').slice(0, 80), page: pageUrl });
        }
      } catch (e) { /* Go-only regex flavor — skip silently */ }
    }
  }

  function scanBlob(text, pageUrl, acc, cfg) {
    if (!text || text.length > 4000000) text = (text || '').slice(0, 4000000);
    cfg = cfg || {};
    const modes = Object.assign({ params: true, links: true }, cfg.modes || {});
    if (modes.params) {
      extractParamsFromBlob(text, acc.params);
      extractJsNested(text, acc.params);
      let m1;
      RE_PARAMKEYS.lastIndex = 0;
      while ((m1 = RE_PARAMKEYS.exec(text))) addParam(acc.params, m1[1], 'Tentative');
    }
    if (modes.links) {
      extractEndpoints(text, acc.endpoints, acc);
      let m2;
      RE_SOURCEMAP.lastIndex = 0;
      while ((m2 = RE_SOURCEMAP.exec(text))) {
        try { acc.sourcemapUrls.add(new URL(m2[1], pageUrl).href); } catch (e) {}
      }
    }
    extractSecrets(text, pageUrl, acc.secrets, cfg.secrets || []);
  }

  // fallparams-style: mine query keys out of discovered endpoints/URLs
  function extractQueryParams(endpoints, out) {
    for (const ep of endpoints) {
      const qi = ep.indexOf('?');
      if (qi < 0) continue;
      let qs = ep.slice(qi + 1);
      try { qs = decodeURIComponent(qs); } catch (e) {}
      let m, n = 0;
      const re = /(^|[&;])([A-Za-z0-9_.~\-]{1,100})(?==|&|$)/g;
      while ((m = re.exec(qs)) && n++ < 200) addParam(out, m[2], 'Firm');
    }
  }

  function newAcc() {
    return { params: new Set(), endpoints: new Set(), epMethods: {}, secrets: [], scripts: new Set(), sourcemapUrls: new Set(), words: new Set() };
  }

  global.AlettaGAP = { scanBlob, extractEndpoints, cleanEp, extractParamsFromBlob, extractQueryParams, newAcc, addParam, VALID_PARAM };
})(typeof window !== 'undefined' ? window : globalThis);
