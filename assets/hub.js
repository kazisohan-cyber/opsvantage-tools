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

  window.OV = { toast: toast, copy: copy, download: download, esc: esc, csvCell: csvCell, parseCsv: parseCsv, pivots: pivots };
})();
