// Shared by every page: theme toggle (same storage key as opsvantage.net) and small helpers for tool pages.
(function () {
  var root = document.documentElement;
  function current() {
    return root.getAttribute('data-theme') ||
      (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark');
  }
  document.addEventListener('click', function (e) {
    var btn = e.target.closest('.theme-toggle');
    if (!btn) return;
    var next = current() === 'light' ? 'dark' : 'light';
    root.setAttribute('data-theme', next);
    try { localStorage.setItem('ov-theme', next); } catch (err) { /* storage blocked: theme still applies for this visit */ }
  });
  // Demo videos load only when scrolled near, play muted while visible and pause off-screen.
  // With reduced motion they get controls and never start on their own.
  var vids = document.querySelectorAll('video.demo-video[data-src]');
  if (vids.length) {
    var still = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    var load = function (v) { if (!v.src) { v.src = v.dataset.src; v.load(); } };
    // preload="none" keeps the file from downloading until the viewer presses play.
    if (still || !('IntersectionObserver' in window)) vids.forEach(function (v) { v.controls = true; v.preload = 'none'; v.src = v.dataset.src; });
    else {
      var io = new IntersectionObserver(function (es) {
        es.forEach(function (e) {
          var v = e.target;
          if (e.isIntersecting) { load(v); var p = v.play(); if (p && p.catch) p.catch(function () { v.controls = true; }); }
          else if (!v.paused) v.pause();
        });
      }, { rootMargin: '200px 0px', threshold: 0.25 });
      vids.forEach(function (v) { io.observe(v); v.addEventListener('click', function () { if (v.paused) v.play(); else v.pause(); }); });
    }
  }

  // Keyboard users can scroll wide code blocks (WCAG: scrollable regions must be focusable).
  var focusPre = function (root) { (root.querySelectorAll ? root : document).querySelectorAll('pre').forEach(function (p) { if (!p.hasAttribute('tabindex')) { p.tabIndex = 0; p.setAttribute('aria-label', 'Code block'); } }); };
  focusPre(document);
  if ('MutationObserver' in window && document.querySelector('main')) {
    new MutationObserver(function (ms) { ms.forEach(function (m) { m.addedNodes.forEach(function (n) { if (n.nodeType === 1) { if (n.tagName === 'PRE') focusPre(n.parentNode); else focusPre(n); } }); }); })
      .observe(document.querySelector('main'), { childList: true, subtree: true });
  }
  // "Skip to content" link for keyboard and screen-reader users.
  var main = document.querySelector('main');
  if (main && !document.querySelector('.skip')) {
    if (!main.id) main.id = 'main';
    var sk = document.createElement('a');
    sk.className = 'skip'; sk.href = '#' + main.id; sk.textContent = 'Skip to content';
    document.body.insertBefore(sk, document.body.firstChild);
  }

  var y = document.getElementById('year');
  if (y) y.textContent = new Date().getFullYear();

  var toastEl;
  function toast(msg) {
    if (!toastEl) {
      toastEl = document.createElement('div');
      toastEl.className = 'toast';
      toastEl.setAttribute('role', 'status');
      document.body.appendChild(toastEl);
    }
    toastEl.textContent = msg;
    toastEl.classList.add('show');
    clearTimeout(toastEl._t);
    toastEl._t = setTimeout(function () { toastEl.classList.remove('show'); }, 1600);
  }

  function copy(text, label) {
    var done = function () { toast((label || 'Copied') + ' to clipboard'); };
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(done, function () { fallback(text); done(); });
    } else { fallback(text); done(); }
  }
  function fallback(text) {
    var ta = document.createElement('textarea');
    ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
    document.body.appendChild(ta); ta.select();
    try { document.execCommand('copy'); } catch (err) { /* nothing else to try */ }
    ta.remove();
  }

  function download(name, text, type) {
    var url = URL.createObjectURL(new Blob([text], { type: type || 'text/plain' }));
    var a = document.createElement('a');
    a.href = url; a.download = name;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  }

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }

  function csvCell(v) {
    var s = String(v == null ? '' : v);
    if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; // keep spreadsheets from treating a value as a formula
    return /[",\n\r]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
  }

  // Minimal RFC 4180 CSV parser (quoted fields, embedded commas/newlines, BOM).
  function parseCsv(text) {
    text = String(text || '').replace(/^﻿/, '');
    var rows = [], row = [], field = '', q = false;
    for (var i = 0; i < text.length; i++) {
      var c = text[i];
      if (q) {
        if (c === '"') { if (text[i + 1] === '"') { field += '"'; i++; } else q = false; }
        else field += c;
      } else if (c === '"') q = true;
      else if (c === ',') { row.push(field); field = ''; }
      else if (c === '\n' || c === '\r') {
        if (c === '\r' && text[i + 1] === '\n') i++;
        row.push(field); field = '';
        if (row.length > 1 || row[0] !== '') rows.push(row);
        row = [];
      } else field += c;
    }
    if (field !== '' || row.length) { row.push(field); rows.push(row); }
    return rows;
  }

  // One-click lookups. Nothing is sent until the analyst clicks; each link opens the source in a new tab.
  var E = encodeURIComponent;
  var PIVOTS = {
    ip: [['VirusTotal', function (v) { return 'https://www.virustotal.com/gui/ip-address/' + E(v); }],
      ['AbuseIPDB', function (v) { return 'https://www.abuseipdb.com/check/' + E(v); }],
      ['GreyNoise', function (v) { return 'https://viz.greynoise.io/ip/' + E(v); }],
      ['Shodan', function (v) { return 'https://www.shodan.io/host/' + E(v); }],
      ['urlscan', function (v) { return 'https://urlscan.io/search/#ip:' + E('"' + v + '"'); }]],
    domain: [['VirusTotal', function (v) { return 'https://www.virustotal.com/gui/domain/' + E(v); }],
      ['urlscan', function (v) { return 'https://urlscan.io/domain/' + E(v); }],
      ['WHOIS', function (v) { return 'https://who.is/whois/' + E(v); }],
      ['crt.sh', function (v) { return 'https://crt.sh/?q=' + E(v); }]],
    url: [['VirusTotal', function (v) { return 'https://www.virustotal.com/gui/search/' + E(E(v)); }],
      ['urlscan', function (v) { return 'https://urlscan.io/search/#page.url:' + E('"' + v + '"'); }]],
    hash: [['VirusTotal', function (v) { return 'https://www.virustotal.com/gui/file/' + E(v); }],
      ['MalwareBazaar', function (v) { return 'https://bazaar.abuse.ch/browse.php?search=' + E((v.length === 32 ? 'md5:' : v.length === 40 ? 'sha1:' : 'sha256:') + v); }],
      ['Hybrid Analysis', function (v) { return 'https://www.hybrid-analysis.com/search?query=' + E(v); }]],
    cve: [['NVD', function (v) { return 'https://nvd.nist.gov/vuln/detail/' + E(v); }],
      ['CISA KEV', function (v) { return 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=' + E(v); }],
      ['CVE.org', function (v) { return 'https://www.cve.org/CVERecord?id=' + E(v); }]],
    asn: [['BGP.he.net', function (v) { return 'https://bgp.he.net/' + E(v); }],
      ['ipinfo', function (v) { return 'https://ipinfo.io/' + E(v); }]],
    crypto: [['mempool.space', function (v) { return 'https://mempool.space/address/' + E(v); }]]
  };
  var GROUP_OF = { ipv4: 'ip', ipv6: 'ip', ip: 'ip', domain: 'domain', url: 'url', md5: 'hash', sha1: 'hash', sha256: 'hash', hash: 'hash', cve: 'cve', asn: 'asn', btc: 'crypto' };
  /** Small "open in" links for an indicator (refanged value). Empty string when there is nothing useful to open. */
  function pivots(type, value) {
    var list = PIVOTS[GROUP_OF[type]];
    if (!list || !value) return '';
    if (GROUP_OF[type] === 'ip' && window.VSIoc && window.VSIoc.isPrivateIp(value)) return '';
    return '<span class="pivots">' + list.map(function (p) {
      return '<a href="' + esc(p[1](value)) + '" target="_blank" rel="noopener noreferrer" title="Open in ' + esc(p[0]) + ' (sends this value to ' + esc(p[0]) + ')">' + esc(p[0]) + '</a>';
    }).join('') + '</span>';
  }

  // ---------------------------------------------------------------- hand-off between tools
  // Data moves through sessionStorage in this tab only (never the URL), and is read once.
  var HKEY = 'ov-handoff';
  function sendTo(path, text) {
    try { sessionStorage.setItem(HKEY, JSON.stringify({ to: path, text: String(text || ''), t: Date.now() })); }
    catch (err) { copy(text, 'Storage is blocked here, so the data was copied instead. Paste it'); }
    location.href = path;
  }
  function takeHandoff() {
    try {
      var raw = sessionStorage.getItem(HKEY);
      if (!raw) return '';
      var h = JSON.parse(raw);
      if (location.pathname.indexOf(h.to) < 0 || Date.now() - h.t > 5 * 60 * 1000) return '';
      sessionStorage.removeItem(HKEY);
      return h.text || '';
    } catch (err) { return ''; }
  }
  /** Ctrl+Enter (Cmd+Enter on a Mac) in a field runs fn. */
  function ctrlEnter(el, fn) {
    if (el) el.addEventListener('keydown', function (e) { if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) { e.preventDefault(); fn(); } });
  }
  /** "What to do now" box. steps: [text or {t, href}] (plain text; links open guides on this site). */
  function nextSteps(steps, tone) {
    steps = (steps || []).filter(Boolean);
    if (!steps.length) return '';
    return '<div class="next-steps' + (tone ? ' ' + tone : '') + '"><b>What to do now</b><ol>' + steps.map(function (s) {
      if (typeof s === 'string') return '<li>' + esc(s) + '</li>';
      return '<li>' + esc(s.t) + (s.href ? ' <a href="' + esc(s.href) + '">' + esc(s.link || 'How') + ' →</a>' : '') + '</li>';
    }).join('') + '</ol></div>';
  }

  // ---------------------------------------------------------------- what was pasted?
  var TOOLS = {
    email: { path: '/email-headers/', name: 'Email Header Analyzer', what: 'email headers or an .eml message' },
    signins: { path: '/m365-signins/', name: 'M365 Sign-in Review', what: 'an Entra ID sign-in log export' },
    events: { path: '/event-triage/', name: 'Windows Event Triage', what: 'exported Windows events' },
    dmarc: { path: '/dmarc-checker/', name: 'SPF, DKIM & DMARC Checker', what: 'a domain' },
    ioc: { path: '/ioc-extractor/', name: 'IOC Extractor', what: 'text with indicators' },
    links: { path: '/link-unwrapper/', name: 'Phishing Link Unwrapper', what: 'links to unwrap and check' },
    cve: { path: '/cve-prioritizer/', name: 'CVE Prioritizer', what: 'a list of CVEs' },
    payload: { path: '/payload-decoder/', name: 'Payload Decoder', what: 'an encoded payload' },
    jwt: { path: '/jwt-decoder/', name: 'JWT Token Decoder', what: 'a JWT token' },
    hunt: { path: '/hunt-queries/', name: 'Hunting Query Generator', what: 'indicators to hunt for' }
  };
  function detect(text) {
    var t = String(text || '').trim();
    if (!t) return null;
    var head = t.slice(0, 4000), first = head.split(/\r?\n/)[0];
    var hdrLines = (head.match(/^(Received|Return-Path|Authentication-Results|DKIM-Signature|ARC-Seal|Delivered-To|X-MS-Exchange-[\w-]+|Message-ID|Received-SPF|X-Originating-IP):/gim) || []).length;
    if (hdrLines >= 2 || (/^From:/im.test(head) && /^Subject:/im.test(head) && /^(Date|To|Message-ID):/im.test(head))) return TOOLS.email;
    if ((/username/i.test(first) && /ip ?address/i.test(first)) || (/"userPrincipalName"/.test(head) && /"(ipAddress|createdDateTime)"/.test(head))) return TOOLS.signins;
    if (/<Event[\s>]/.test(head) || /(^|,|")\s*(event ?id|eventcode|event code|timecreated|providername)\s*("|,|$)/i.test(first) || /"(EventID|EventCode|event_id)"\s*:/.test(head)) return TOOLS.events;
    // A token, an encoded payload, a CVE list or a list of links each have their own tool.
    if (/^(bearer\s+)?eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*$/i.test(t)) return TOOLS.jwt;
    if (/(?:^|\s)-(?:e|ec|en|enc|encodedcommand)\s+[A-Za-z0-9+/=]{40,}/i.test(t) || /FromBase64String\(/i.test(t) || (!/\s/.test(t) && t.length >= 60 && /^[A-Za-z0-9+/]+={0,2}$/.test(t))) return TOOLS.payload;
    var cves = t.match(/CVE-\d{4}-\d{4,7}/gi) || [];
    var lines = t.split(/\r?\n/).filter(function (l) { return l.trim(); });
    if (cves.length >= 2 && cves.length >= lines.length * 0.6) return Object.assign({ alt: TOOLS.ioc }, TOOLS.cve);
    if (lines.length <= 25 && lines.every(function (l) { return /^\s*(h(xx|tt)ps?)(:\/\/|\[:\]\/\/)\S+\s*$/i.test(l); })) return Object.assign({ alt: TOOLS.ioc }, TOOLS.links);
    // A bare domain: is it spoofable? (A full URL is a link to check, so it goes to the IOC Extractor.)
    if (!/\s/.test(t) && /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$/i.test(t)) return Object.assign({ alt: TOOLS.ioc }, TOOLS.dmarc, { value: t.toLowerCase() });
    return TOOLS.ioc;
  }

  // ---------------------------------------------------------------- PDF report (browser print)
  // Adds a "Save PDF report" button next to each tool's main copy button. It enables with that button,
  // stamps a report header, names the file, and opens the browser's print dialog (Save as PDF).
  function printReport() {
    var h1 = document.querySelector('.tool-head h1');
    var tool = h1 ? h1.textContent.trim() : document.title;
    var now = new Date();
    var stamp = now.getFullYear() + '-' + String(now.getMonth() + 1).padStart(2, '0') + '-' + String(now.getDate()).padStart(2, '0');
    var head = document.getElementById('print-head');
    if (!head) { head = document.createElement('div'); head.id = 'print-head'; var m = document.querySelector('main'); m.insertBefore(head, m.firstChild); }
    var by = '';
    try { by = localStorage.getItem('ov.m365.brand') || ''; } catch (e) { /* storage blocked */ }
    head.innerHTML = '<b>' + esc(tool) + ' report</b>' + esc(now.toLocaleString()) + (by ? ' · Prepared by ' + esc(by) : '') +
      ' · Generated in the browser with tools.opsvantage.net. Nothing was uploaded.';
    var old = document.title;
    document.title = tool.replace(/[^\w &-]+/g, '').trim() + ' report ' + stamp;
    var restore = function () { document.title = old; window.removeEventListener('afterprint', restore); };
    window.addEventListener('afterprint', restore);
    window.print();
    setTimeout(restore, 1500);
  }
  function addPdfButton() {
    if (document.getElementById('pdf-report')) return;
    var anchor = document.getElementById('note') || document.getElementById('copy-all') || document.getElementById('copy-report');
    if (!anchor) return;
    var b = document.createElement('button');
    b.type = 'button'; b.id = 'pdf-report'; b.className = 'btn btn-ghost btn-sm'; b.textContent = 'Save PDF report';
    b.disabled = anchor.disabled;
    anchor.parentNode.insertBefore(b, anchor.nextSibling);
    b.addEventListener('click', printReport);
    if ('MutationObserver' in window) new MutationObserver(function () { b.disabled = anchor.disabled; }).observe(anchor, { attributes: true, attributeFilter: ['disabled'] });
  }
  addPdfButton();
  // The DMARC checker draws its copy button with the result, so look again when results change.
  var res = document.getElementById('result');
  if (res && 'MutationObserver' in window) new MutationObserver(addPdfButton).observe(res, { childList: true });

  // ---------------------------------------------------------------- first-visit tour
  // Three short tips on a tool page the first time it is opened (remembered per page in this browser).
  // Skipped when data was handed over from another tool, or with ?tour=0.
  var TOUR = [
    { sel: '#input, #domain', t: 'Paste your data here, or drop a file on the box. It stays in this browser tab.' },
    { sel: '#sample, #demo', t: 'Not sure what to paste? Load the sample to see a complete result first.' },
    { sel: '#out, #result, #report, #connect', t: 'Results show up here: a verdict, what to do now, charts and one-click lookups. When you are done, save a PDF report.' }
  ];
  function startTour(force) {
    var key = 'ov-tour:' + location.pathname;
    var seen = false;
    try { seen = !!localStorage.getItem(key); } catch (e) { return; }
    if (!force && (seen || /[?&]tour=0/.test(location.search) || !document.querySelector('.tool-head'))) return;
    var steps = TOUR.map(function (s) { return { el: document.querySelector(s.sel), t: s.t }; }).filter(function (s) { return s.el; });
    if (steps.length < 2) return;
    var i = 0, pop = document.createElement('div'), prevFocus = document.activeElement;
    pop.style.top = (window.scrollY + 80) + 'px';
    pop.className = 'tour'; pop.setAttribute('role', 'dialog'); pop.setAttribute('aria-label', 'Quick tour'); pop.tabIndex = -1;
    document.body.appendChild(pop);
    var done = function () {
      try { localStorage.setItem(key, '1'); } catch (e) { /* not remembered */ }
      document.querySelectorAll('.tour-on').forEach(function (e) { e.classList.remove('tour-on'); });
      pop.remove(); document.removeEventListener('keydown', onKey); window.removeEventListener('resize', place);
      if (prevFocus && prevFocus.focus) prevFocus.focus();
    };
    function place() {
      var r = steps[i].el.getBoundingClientRect(), w = Math.min(320, window.innerWidth - 24);
      pop.style.width = w + 'px';
      var top = r.bottom + window.scrollY + 10;
      if (r.bottom + 170 > window.innerHeight && r.top > 190) top = r.top + window.scrollY - pop.offsetHeight - 10;
      pop.style.top = Math.max(8, top) + 'px';
      pop.style.left = Math.max(12, Math.min(r.left + window.scrollX, window.scrollX + window.innerWidth - w - 12)) + 'px';
    }
    function show() {
      document.querySelectorAll('.tour-on').forEach(function (e) { e.classList.remove('tour-on'); });
      var s = steps[i];
      s.el.classList.add('tour-on');
      pop.innerHTML = '<div class="tour-n">Tip ' + (i + 1) + ' of ' + steps.length + '</div><p>' + esc(s.t) + '</p><div class="tour-b">' +
        '<button type="button" class="btn btn-ghost btn-sm" data-t="skip">Skip</button>' +
        '<button type="button" class="btn btn-primary btn-sm" data-t="next">' + (i === steps.length - 1 ? 'Got it' : 'Next') + '</button></div>';
      var r = s.el.getBoundingClientRect(), off = r.top < 70 || r.bottom > window.innerHeight - 40;
      if (off) s.el.scrollIntoView({ block: 'center' });
      place();
      pop.querySelector('[data-t="next"]').focus({ preventScroll: true });
    }
    function onKey(e) { if (e.key === 'Escape') done(); }
    pop.addEventListener('click', function (e) {
      var b = e.target.closest('button[data-t]');
      if (!b) return;
      if (b.dataset.t === 'skip' || i === steps.length - 1) done(); else { i++; show(); }
    });
    document.addEventListener('keydown', onKey);
    window.addEventListener('resize', place);
    show();
  }
  var handedOver = false;
  try { var hh = sessionStorage.getItem(HKEY); handedOver = !!hh && location.pathname.indexOf(JSON.parse(hh).to) >= 0; } catch (e) { /* ignore */ }
  if (!handedOver) setTimeout(function () { startTour(false); }, 900);

  window.OV = { startTour: startTour, toast: toast, copy: copy, download: download, esc: esc, csvCell: csvCell, parseCsv: parseCsv, pivots: pivots,
    sendTo: sendTo, takeHandoff: takeHandoff, ctrlEnter: ctrlEnter, nextSteps: nextSteps, detect: detect, TOOLS: TOOLS };
})();
