// Phishing Link Unwrapper: peels safe-link and redirect wrappers off a URL offline, then checks the real destination
// (brand lookalikes, punycode, shorteners, IP hosts, credential tricks). Nothing is fetched: links are decoded, never visited.
(function () {
  'use strict';
  var OV = window.OV, I = window.VSIoc, A = window.VSAnalyzer, C = window.OVCharts;
  var $ = function (id) { return document.getElementById(id); };
  var last = null;

  var SAMPLE = [
    'From the reported email:',
    'https://nam12.safelinks.protection.outlook.com/?url=https%3A%2F%2Furldefense.com%2Fv3%2F__https%3A%2F%2Fmicrosoft-365-verify.support%2Flogin%3Fid%3D7741__%3B!!Q2Kp!x1Z%24&data=05%7C02%7Cfinance%40contoso.com&reserved=0',
    'https://urldefense.proofpoint.com/v2/url?u=https-3A__www.paypa1-2Daccount.com_signin_verify&d=DwMFaQ&c=abc&r=def',
    'https://www.google.com/url?q=https://xn--micrsoft-qbh.com/owa/&sa=D',
    'https://bit.ly/3InvoiceQ4',
    'https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=4765445b&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback',
    'hxxps://secure-docs[.]pages[.]dev/view?file=Invoice_8841.html'
  ].join('\n');

  // ---------------------------------------------------------------- unwrapping
  var RUN = {};
  'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'.split('').forEach(function (c, i) { RUN[c] = i + 2; });

  function b64urlDecode(s) {
    s = s.replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    try {
      var bin = atob(s), bytes = new Uint8Array(bin.length);
      for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
      return new TextDecoder('utf-8').decode(bytes);
    } catch (e) { return ''; }
  }

  // Proofpoint URL Defense v3: https://urldefense.com/v3/__<url>__;<base64url bytes>!!<customer>
  // '*' in the URL stands for the next decoded character; '**X' for a run of characters (X gives the length).
  function proofpointV3(href) {
    var m = href.match(/\/v3\/__(.+?)__;([^!]*)!/);
    if (!m) { var m2 = href.match(/\/v3\/__(.+?)__/); return m2 ? m2[1] : null; }
    var url = m[1], chars = Array.from(b64urlDecode(m[2])), at = 0;
    return url.replace(/\*(\*.)?/g, function (tok) {
      if (tok === '*') return chars[at++] || '';
      var n = RUN[tok.charAt(2)] || 0, run = chars.slice(at, at + n).join('');
      at += n;
      return run;
    });
  }

  var REDIRECT_PARAMS = ['url', 'u', 'q', 'target', 'dest', 'destination', 'redirect', 'redirect_url', 'redirectUrl', 'redir', 'link', 'to', 'goto', 'out', 'continue', 'next', 'r'];
  var SHORTENERS = /^(bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|buff\.ly|is\.gd|cutt\.ly|rebrand\.ly|rb\.gy|shorturl\.at|tiny\.cc|t\.ly|s\.id|lnkd\.in|bl\.ink|qrco\.de|shorturl\.gg|v\.gd|x\.co)$/i;

  /** One hop: returns {next, via, note} or null when this URL is the end of the chain. */
  function peel(u) {
    var h = u.hostname.toLowerCase(), p = u.searchParams, path = u.pathname;
    var get = function (k) { var v = p.get(k); return v && /^(https?:)?\/\//i.test(v.trim()) ? v.trim() : null; };
    if (/safelinks\.protection\.outlook\.com$/.test(h) && get('url')) return { next: get('url'), via: 'Microsoft Defender Safe Links' };
    if (/(^|\.)urldefense\.com$/.test(h) && /^\/v3\//.test(path)) { var v3 = proofpointV3(u.href); if (v3) return { next: v3, via: 'Proofpoint URL Defense (v3)' }; }
    if (h === 'urldefense.proofpoint.com' && p.get('u')) {
      // v2 writes %XX as -XX and / as _ (a literal hyphen is -2D).
      var raw = p.get('u'), dec = path.indexOf('/v1/') === 0 ? raw : raw.replace(/-([0-9A-Fa-f]{2})/g, '%$1').replace(/_/g, '/');
      try { dec = decodeURIComponent(dec); } catch (e) { /* keep */ }
      return { next: dec, via: 'Proofpoint URL Defense (' + (path.indexOf('/v1/') === 0 ? 'v1' : 'v2') + ')' };
    }
    if (/(^|\.)linkprotect\.cudasvc\.com$/.test(h) && get('a')) return { next: get('a'), via: 'Barracuda Link Protection' };
    if (/(^|\.)clicktime\.symantec\.com$/.test(h) && get('u')) return { next: get('u'), via: 'Symantec Click-time URL Protection' };
    if (/(^|\.)google\.[a-z.]+$/.test(h) && path === '/url' && (get('q') || get('url'))) return { next: get('q') || get('url'), via: 'Google redirect' };
    if (h === 'l.facebook.com' && get('u')) return { next: get('u'), via: 'Facebook link shim' };
    if (/(^|\.)linkedin\.com$/.test(h) && path.indexOf('/redir/') === 0 && get('url')) return { next: get('url'), via: 'LinkedIn redirect' };
    if (h === 'slack-redir.net' && get('url')) return { next: get('url'), via: 'Slack redirect' };
    if (/(mimecastprotect\.com|protect-[a-z]+\.mimecast\.com)$/.test(h)) return { stop: 'Mimecast keeps the destination on its own servers, so it can\'t be decoded offline. Look it up on urlscan instead of clicking.' };
    if (/(^|\.)secure-web\.cisco\.com$/.test(h)) return { stop: 'Cisco Secure Email rewrites links with an encrypted token; the destination can\'t be decoded offline.' };
    if (SHORTENERS.test(h)) return { stop: 'Link shortener: the destination is only revealed by visiting it. Expand it with urlscan rather than clicking.' };
    // Generic open-redirect pattern: a parameter that is itself a full URL (OAuth redirect_uri is not followed).
    for (var i = 0; i < REDIRECT_PARAMS.length; i++) {
      var g = get(REDIRECT_PARAMS[i]);
      if (g) return { next: g, via: 'Redirect parameter "' + REDIRECT_PARAMS[i] + '" on ' + h, generic: true };
    }
    // Base64-encoded URL in a parameter (aHR0c = "http").
    var b64 = null;
    p.forEach(function (v) { if (!b64 && /^aHR0c[A-Za-z0-9+/_=-]{8,}$/.test(v)) b64 = b64urlDecode(v); });
    if (b64 && /^https?:\/\//.test(b64)) return { next: b64, via: 'Base64-encoded URL in a parameter' };
    return null;
  }

  function unwrap(input) {
    var chain = [], cur = I ? I.refang(input) : input, stop = null;
    for (var d = 0; d < 8; d++) {
      var u;
      try { u = new URL(cur); } catch (e) { break; }
      var step = peel(u);
      chain.push({ url: u.href, host: u.hostname.toLowerCase(), via: step && step.via, generic: step && step.generic });
      if (!step || step.stop) { stop = step && step.stop; break; }
      cur = /^\/\//.test(step.next) ? 'https:' + step.next : step.next;
    }
    return { chain: chain, final: chain.length ? chain[chain.length - 1].url : input, stop: stop };
  }

  // ---------------------------------------------------------------- checks on the destination
  function inspect(href) {
    var u;
    try { u = new URL(href); } catch (e) { return null; }
    var host = u.hostname.toLowerCase(), shown = A ? A.decodeHost(host) : host;
    var v = A ? A.analyzeUrl(u.href, {}) : { reasons: [], level: 'safe', score: 0 };
    var flags = v.reasons.slice();
    var add = function (t) { if (flags.indexOf(t) < 0) flags.push(t); };
    if (u.username || u.password) add('The address contains "' + (u.username || '') + '@" before the host: browsers ignore it, so the real site is ' + host);
    if (shown !== host) add('Punycode host: it displays as "' + shown + '"');
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(host) || host.charAt(0) === '[') add('The host is a bare IP address');
    if (u.port && u.port !== '443' && u.port !== '80') add('Non-standard port ' + u.port);
    if (u.protocol === 'http:') add('Plain HTTP: anything typed on the page travels unencrypted');
    if (host.split('.').length >= 5) add('Long chain of subdomains, often used to hide the real domain');
    if (/(login|signin|sign-in|verify|account|password|secure|update|wallet|invoice|payment)/i.test(u.pathname + u.search) && v.level !== 'safe') add('Login or payment words in the path');
    if (/\.(html?|svg|zip|iso|exe|scr|js|hta|lnk)(\?|$)/i.test(u.pathname)) add('Links straight to a file (' + u.pathname.split('.').pop().split('?')[0] + ')');
    var params = [];
    u.searchParams.forEach(function (val, key) { params.push([key, val]); });
    return { u: u, host: host, shown: shown, domain: A ? A.registrableDomain(host) : host, level: v.level === 'safe' && flags.length ? 'caution' : v.level, score: v.score, brand: v.brand, flags: flags, params: params };
  }

  // ---------------------------------------------------------------- render
  var LEVEL = { block: ['bad', 'Dangerous'], warn: ['warn', 'Suspicious'], caution: ['warn', 'Be careful'], safe: ['good', 'No red flags'] };

  function analyze() {
    var text = $('input').value;
    var urls = [];
    if (I) I.unique(text).forEach(function (x) { if (x.type === 'url') urls.push(x.value); });
    if (!urls.length && text.trim()) { var t = text.trim(); if (/^[\w.-]+\.[a-z]{2,}(\/|$)/i.test(t)) urls.push('https://' + t); }
    if (!urls.length) { $('out').innerHTML = '<p class="empty">' + (text.trim() ? 'No links found. Paste a full URL, defanged or not.' : 'Paste one or more links and press Unwrap.') + '</p>'; $('note').disabled = true; last = null; return; }
    var results = urls.slice(0, 25).map(function (raw) {
      var w = unwrap(raw); w.raw = raw; w.info = inspect(w.final);
      if (w.stop && w.info && w.info.level === 'safe') w.info.level = 'caution'; // destination unknown
      return w;
    });
    last = results;
    var worst = results.reduce(function (a, r) { var o = { block: 3, warn: 2, caution: 1, safe: 0 }; return r.info && o[r.info.level] > o[a] ? r.info.level : a; }, 'safe');
    var nWrapped = results.filter(function (r) { return r.chain.length > 1; }).length;
    var html = '<div class="stats"><div class="stat"><b>' + results.length + '</b><span>link' + (results.length === 1 ? '' : 's') + '</span></div>' +
      '<div class="stat"><b>' + nWrapped + '</b><span>unwrapped</span></div>' +
      '<div class="stat"><b style="color:var(--bad)">' + results.filter(function (r) { return r.info && (r.info.level === 'block' || r.info.level === 'warn'); }).length + '</b><span>suspicious</span></div></div>';
    html += OV.nextSteps(worst === 'block' || worst === 'warn' ? [
      'Don\'t open the flagged links. Block the destination domains at your web proxy or DNS filter.',
      'Search mail logs for the same domain to find everyone who received it, and pull the messages.',
      { t: 'If anyone clicked and typed a password, reset it and revoke their sessions.', href: '/guides/phishing-triage-checklist/', link: 'Checklist' }
    ] : [
      'The destinations show none of the built-in red flags. That does not prove they are safe.',
      'For anything still doubtful, use the urlscan button to see the page without visiting it yourself.'
    ], worst === 'block' || worst === 'warn' ? 'bad' : '');
    html += results.map(card).join('');
    $('out').innerHTML = html;
    $('note').disabled = false;
  }

  function card(r) {
    var i = r.info, L = i ? LEVEL[i.level] : ['', 'Not a valid URL'];
    var h = '<div class="finding"><div class="finding-h"><span class="sev ' + (L[0] === 'bad' ? 'high' : L[0] === 'warn' ? 'med' : 'info') + '">' + L[1] + '</span><b class="mono" style="word-break:break-all">' + OV.esc(I.defang(r.final, 'url')) + '</b></div>';
    if (r.chain.length > 1) {
      h += '<div class="path" role="list" aria-label="Redirect chain">' + r.chain.map(function (c, k) {
        var last = k === r.chain.length - 1;
        return (k ? '<div class="hop-link" aria-hidden="true"><span>' + OV.esc(r.chain[k - 1].via ? 'unwrap' : '→') + '</span></div>' : '') +
          '<div class="hop' + (last ? (i && (i.level === 'block' || i.level === 'warn') ? ' origin' : ' me') : '') + '" role="listitem"><div class="hop-k">' + (last ? 'Real destination' : OV.esc(c.via || 'Link')) + '</div><b>' + OV.esc(c.host) + '</b></div>';
      }).join('') + '</div>';
    }
    if (r.stop) h += '<p class="sub" style="color:var(--amber);max-width:none">' + OV.esc(r.stop) + '</p>';
    if (i) {
      if (i.flags.length) h += '<ul class="reasons">' + i.flags.map(function (f) { return '<li class="bad">' + OV.esc(f) + '</li>'; }).join('') + '</ul>';
      var rows = [['Scheme', i.u.protocol.replace(':', '')], ['Host', i.host + (i.shown !== i.host ? '  (shows as ' + i.shown + ')' : '')], ['Registered domain', i.domain], ['Path', i.u.pathname]];
      if (i.u.port) rows.push(['Port', i.u.port]);
      i.params.slice(0, 12).forEach(function (pr) { rows.push(['?' + pr[0], pr[1].length > 160 ? pr[1].slice(0, 160) + '…' : pr[1]]); });
      if (i.u.hash) rows.push(['Fragment', i.u.hash]);
      h += '<details><summary>URL breakdown</summary><dl class="kv">' + rows.map(function (x) { return '<dt>' + OV.esc(x[0]) + '</dt><dd class="mono" style="word-break:break-all">' + OV.esc(x[1]) + '</dd>'; }).join('') + '</dl></details>';
      h += '<div style="margin-top:8px">' + OV.pivots('url', r.final) + '</div><div style="margin-top:4px">' + OV.pivots('domain', i.domain) + '</div>';
    }
    return h + '</div>';
  }

  function ticketNote() {
    var lines = ['Link analysis (OpsVantage Phishing Link Unwrapper)', ''];
    last.forEach(function (r) {
      lines.push('Link: ' + I.defang(r.raw, 'url'));
      if (r.chain.length > 1) lines.push('  Unwrapped via: ' + r.chain.slice(0, -1).map(function (c) { return c.via; }).join(' > '));
      lines.push('  Real destination: ' + I.defang(r.final, 'url') + (r.info ? ' [' + LEVEL[r.info.level][1] + ']' : ''));
      if (r.info) r.info.flags.forEach(function (f) { lines.push('  - ' + f); });
      if (r.stop) lines.push('  Note: ' + r.stop);
      lines.push('');
    });
    lines.push('(Links defanged and decoded offline; none were visited.)');
    return lines.join('\n');
  }

  $('analyze').addEventListener('click', analyze);
  $('sample').addEventListener('click', function () { $('input').value = SAMPLE; analyze(); });
  $('clear').addEventListener('click', function () { $('input').value = ''; analyze(); $('input').focus(); });
  $('note').addEventListener('click', function () { if (last) OV.copy(ticketNote(), 'Ticket note copied'); });
  $('input').addEventListener('paste', function () { setTimeout(analyze, 0); });
  OV.ctrlEnter($('input'), analyze);
  var handed = OV.takeHandoff();
  if (handed) { $('input').value = handed; analyze(); }
  window.OVLinkUnwrap = { unwrap: unwrap, inspect: inspect, proofpointV3: proofpointV3 };
})();
