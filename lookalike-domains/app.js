// Lookalike Domain Checker: generates typo, homoglyph, punycode, keyword and TLD variants of a domain (in the spirit
// of dnstwist) and checks each one over DNS-over-HTTPS (Cloudflare, Google fallback) straight from the browser.
// Registered variants get A, MX, SPF and DMARC lookups. Nothing is sent to an OpsVantage server.
(function () {
  'use strict';
  var OV = window.OV;
  var $ = function (id) { return document.getElementById(id); };
  var MAX = 400, CONC = 8;
  var last = null, runId = 0;

  var RESOLVERS = [
    function (n, t) { return 'https://cloudflare-dns.com/dns-query?name=' + encodeURIComponent(n) + '&type=' + t; },
    function (n, t) { return 'https://dns.google/resolve?name=' + encodeURIComponent(n) + '&type=' + t; }
  ];
  var TYPE = { A: 1, MX: 15, TXT: 16, NS: 2 };
  async function dns(name, type) {
    var err;
    for (var i = 0; i < RESOLVERS.length; i++) {
      try {
        var ctl = new AbortController(), to = setTimeout(function () { ctl.abort(); }, 8000);
        var r = await fetch(RESOLVERS[i](name, type), { headers: { accept: 'application/dns-json' }, signal: ctl.signal });
        clearTimeout(to);
        if (!r.ok) throw new Error('HTTP ' + r.status);
        var j = await r.json();
        return { status: j.Status, data: (j.Answer || []).filter(function (a) { return a.type === TYPE[type]; }).map(function (a) { return String(a.data); }) };
      } catch (e) { err = e; }
    }
    throw err || new Error('DNS lookup failed');
  }

  // Two-level public suffixes that matter most; anything else uses the last label as the TLD.
  var SLD = /\.(co|com|net|org|gov|edu|ac|or|ne)\.(uk|au|nz|in|bd|my|sg|jp|kr|za|br|mx|ar|tr|id|ph|th|pk|ng|ke|eg|hk|tw|cn|il|sa|ae)$/;
  function split(d) {
    var m = d.match(SLD);
    var suffix = m ? m[0].slice(1) : d.split('.').pop();
    var rest = d.slice(0, d.length - suffix.length - 1).split('.');
    return { name: rest.pop(), sub: rest.join('.'), tld: suffix };
  }
  function norm(s) {
    s = String(s || '').trim().toLowerCase().split(/\s/)[0];
    if (s.indexOf('@') >= 0) s = s.split('@').pop();
    s = s.replace(/^[a-z][a-z0-9+.-]*:\/\//, '').split(/[\/?#]/)[0].split(':')[0].replace(/\.$/, '').replace(/^www\./, '');
    try { s = new URL('http://' + s).hostname; } catch (e) { return ''; }
    return /^([a-z0-9-]+\.)+[a-z0-9-]{2,}$/.test(s) ? s : '';
  }

  var KEYS = ['1234567890-', 'qwertyuiop', 'asdfghjkl', 'zxcvbnm'];
  function near(c) {
    var out = [];
    KEYS.forEach(function (row, r) {
      var i = row.indexOf(c);
      if (i < 0) return;
      [row[i - 1], row[i + 1], (KEYS[r - 1] || '')[i], (KEYS[r + 1] || '')[i]].forEach(function (x) { if (x && x !== '-') out.push(x); });
    });
    return out;
  }
  var GLYPH = { o: ['0'], 0: ['o'], l: ['1', 'i'], i: ['1', 'l'], 1: ['l', 'i'], m: ['rn', 'nn'], w: ['vv'], d: ['cl'], g: ['q'], q: ['g'], e: ['3'], a: ['4'], s: ['5'], b: ['8'], u: ['v'], v: ['u'], n: ['m'], h: ['b'] };
  var MULTI = [['rn', 'm'], ['vv', 'w'], ['cl', 'd'], ['nn', 'm']];
  var IDN = { a: 'а', c: 'с', e: 'е', o: 'о', p: 'р', x: 'х', y: 'у', i: 'і', j: 'ј', s: 'ѕ', h: 'һ', k: 'κ', n: 'ո', d: 'ԁ' };
  var KW = ['login', 'secure', 'support', 'verify', 'account', 'mail', 'portal', 'online', 'billing', 'invoice', 'pay', 'hr', 'it', 'helpdesk', 'sso', 'auth', 'docs', 'app'];
  var TLDS = ['com', 'net', 'org', 'co', 'io', 'info', 'biz', 'us', 'app', 'online', 'site', 'xyz', 'shop', 'top', 'live', 'store', 'tech', 'cloud', 'services', 'support', 'email', 'group', 'cc', 'me', 'ai', 'uk', 'co.uk', 'de', 'in', 'ca', 'au', 'eu', 'click', 'link', 'help'];

  function variants(d, opt) {
    var p = split(d), n = p.name, tld = p.tld, seen = {}, out = [];
    function add(name, kind, t) {
      t = t || tld;
      if (!name || name === n && t === tld || name.length > 63 || /^-|-$/.test(name)) return;
      var host = name + '.' + t, ascii;
      try { ascii = new URL('http://' + host).hostname; } catch (e) { return; }
      if (seen[ascii]) return;
      seen[ascii] = 1;
      out.push({ host: ascii, show: host, kind: kind });
    }
    var i, c;
    for (i = 0; i < n.length; i++) {
      c = n[i];
      add(n.slice(0, i) + n.slice(i + 1), 'Missing letter');
      add(n.slice(0, i) + c + n.slice(i), 'Doubled letter');
      if (i < n.length - 1 && n[i] !== n[i + 1]) add(n.slice(0, i) + n[i + 1] + n[i] + n.slice(i + 2), 'Swapped letters');
      near(c).forEach(function (k) { add(n.slice(0, i) + k + n.slice(i + 1), 'Neighbouring key'); add(n.slice(0, i) + k + n.slice(i), 'Extra key'); });
      (GLYPH[c] || []).forEach(function (g) { add(n.slice(0, i) + g + n.slice(i + 1), 'Look-alike character'); });
      if (i > 0) { add(n.slice(0, i) + '-' + n.slice(i), 'Added hyphen'); add(n.slice(0, i) + '.' + n.slice(i), 'Added dot'); }
      if ('aeiou'.indexOf(c) >= 0) 'aeiou'.split('').forEach(function (v) { if (v !== c) add(n.slice(0, i) + v + n.slice(i + 1), 'Vowel swap'); });
      if (opt.idn && IDN[c]) add(n.slice(0, i) + IDN[c] + n.slice(i + 1), 'Homoglyph (punycode)');
    }
    MULTI.forEach(function (m) { var j = n.indexOf(m[0]); if (j >= 0) add(n.slice(0, j) + m[1] + n.slice(j + m[0].length), 'Look-alike character'); });
    if (n.indexOf('-') >= 0) add(n.replace(/-/g, ''), 'Removed hyphen');
    add(n + 's', 'Plural');
    if (opt.kw) KW.forEach(function (k) { add(n + '-' + k, 'Keyword'); add(k + '-' + n, 'Keyword'); add(n + k, 'Keyword'); });
    if (opt.tld) TLDS.forEach(function (t) { if (t !== tld) add(n, 'Other TLD', t); });
    if (opt.tld && tld.indexOf('.') < 0) add(n + tld, 'Missing dot', 'com');
    // Most likely to be abused first, so the cap cuts the least useful ones.
    var order = ['Other TLD', 'Homoglyph (punycode)', 'Look-alike character', 'Keyword', 'Missing letter', 'Swapped letters', 'Doubled letter', 'Added hyphen', 'Plural', 'Vowel swap', 'Neighbouring key', 'Removed hyphen', 'Missing dot', 'Added dot', 'Extra key'];
    out.sort(function (a, b) { return order.indexOf(a.kind) - order.indexOf(b.kind); });
    return out.slice(0, MAX);
  }

  async function inspect(v) {
    var a = await dns(v.host, 'A');
    if (a.status === 3) return null;           // NXDOMAIN: not registered
    if (a.status !== 0) { v.err = true; return v; }
    v.a = a.data.filter(function (x) { return /^\d+\.\d+\.\d+\.\d+$/.test(x); });
    var res = await Promise.all([dns(v.host, 'MX').catch(function () { return { data: [] }; }), dns(v.host, 'TXT').catch(function () { return { data: [] }; }), dns('_dmarc.' + v.host, 'TXT').catch(function () { return { data: [] }; })]);
    v.mx = res[0].data.map(function (x) { return x.split(' ').pop().replace(/\.$/, ''); }).filter(function (x) { return x && x !== '.'; });
    v.spf = res[1].data.some(function (t) { return /v=spf1/i.test(t); });
    v.dmarc = res[2].data.some(function (t) { return /v=DMARC1/i.test(t); });
    v.nullmx = res[0].data.some(function (x) { return /^0 \.$/.test(x.trim()); });
    v.risk = v.mx.length ? 'high' : v.a.length ? 'med' : 'low';
    if (v.nullmx && !v.a.length) v.risk = 'low';
    return v;
  }

  async function analyze() {
    var d = norm($('input').value), my = ++runId;
    if (!d) { $('out').innerHTML = '<p class="empty">' + ($('input').value.trim() ? 'That does not look like a domain. Try something like contoso.com.' : 'Enter a domain and press Check.') + '</p>'; $('note').disabled = true; return; }
    var list = variants(d, { tld: $('opt-tld').checked, kw: $('opt-kw').checked, idn: $('opt-idn').checked });
    var found = [], done = 0, errs = 0, idx = 0;
    $('analyze').disabled = true;
    $('note').disabled = true;
    function progress() {
      $('out').innerHTML = '<p class="empty"><span class="spin"></span>Checking ' + done + ' of ' + list.length + ' variants of ' + OV.esc(d) + ' … ' + found.length + ' registered so far</p>';
    }
    progress();
    async function worker() {
      while (idx < list.length && my === runId) {
        var v = list[idx++];
        try { var r = await inspect(v); if (r && !r.err) found.push(r); else if (r && r.err) errs++; } catch (e) { errs++; }
        done++;
        if (done % 10 === 0) progress();
      }
    }
    var ws = [];
    for (var k = 0; k < CONC; k++) ws.push(worker());
    await Promise.all(ws);
    $('analyze').disabled = false;
    if (my !== runId) return;
    last = { d: d, total: list.length, found: found, errs: errs };
    render();
  }

  function render() {
    var L = last, f = L.found.slice().sort(function (a, b) { var r = { high: 0, med: 1, low: 2 }; return r[a.risk] - r[b.risk] || a.host.localeCompare(b.host); });
    var hi = f.filter(function (x) { return x.risk === 'high'; }).length;
    if (L.errs > L.total / 2) { $('out').innerHTML = '<p class="empty">Most DNS lookups failed. Your network may block DNS-over-HTTPS; try again or from another network.</p>'; return; }
    var html = '<div class="verdict ' + (hi ? 'bad' : f.length ? 'warn' : 'good') + '"><div><div class="v">' + f.length + ' registered lookalike' + (f.length === 1 ? '' : 's') + '</div><div class="sub" style="margin:2px 0 0">' +
      OV.esc(L.total + ' variants of ' + L.d + ' checked. ' + hi + ' with mail servers (MX).' + (L.errs ? ' ' + L.errs + ' lookups failed.' : '')) + '</div></div></div>';
    html += OV.nextSteps(f.length ? [
      'Start with the ones that have mail servers: they can receive replies to a phishing email and usually send as well. Check their owner (WHOIS or RDAP) and registration date.',
      'If one is new and not yours, block it on your mail gateway and web proxy, and warn finance and the helpdesk, the usual targets of invoice and password-reset lures.',
      'Lookalikes you own should not have MX records unless they send mail; give them a null MX, SPF -all and DMARC p=reject so nobody can spoof them either.'
    ] : ['No registered lookalikes among the variants checked. Run it again every few weeks, or after a phishing campaign against your sector.'], hi ? 'bad' : f.length ? 'warn' : '');
    if (f.length) {
      html += '<div class="table-wrap" style="margin-top:12px"><table class="data" style="min-width:680px"><thead><tr><th>Domain</th><th>Type</th><th>Web (A)</th><th>Mail (MX)</th><th>SPF / DMARC</th></tr></thead><tbody>' + f.map(function (x) {
        return '<tr><td class="mono" style="word-break:break-all"><span aria-hidden="true" style="display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px;background:' + (x.risk === 'high' ? 'var(--bad)' : x.risk === 'med' ? 'var(--amber)' : 'var(--muted-2)') + '"></span>' + OV.esc(x.show) + (x.show !== x.host ? '<br><span class="sub" style="font-size:.75rem">' + OV.esc(x.host) + '</span>' : '') +
          '</td><td>' + OV.esc(x.kind) + '</td><td class="mono">' + OV.esc(x.a.slice(0, 2).join(', ') || '-') + '</td><td class="mono" style="word-break:break-all">' + (x.nullmx ? 'null MX (no mail)' : OV.esc(x.mx.slice(0, 2).join(', ') || '-')) +
          '</td><td>' + (x.spf ? 'SPF' : '-') + ' / ' + (x.dmarc ? 'DMARC' : '-') + '</td></tr>';
      }).join('') + '</tbody></table></div>';
      html += '<p class="sub" style="font-size:.8rem;max-width:none">Red: has mail servers. Amber: has a web address. Others exist in DNS but point nowhere yet (often parked or held). Pivot on a domain: ' + OV.pivots('domain', f[0].host) + '</p>';
    }
    $('out').innerHTML = html;
    $('note').disabled = !f.length;
  }

  function note() {
    var t = ['Lookalike domains for ' + last.d + ' (OpsVantage Lookalike Domain Checker), ' + last.found.length + ' registered of ' + last.total + ' checked:'];
    last.found.forEach(function (x) { t.push('- ' + x.host + (x.show !== x.host ? ' (' + x.show + ')' : '') + ' [' + x.kind + '] A: ' + (x.a.join(', ') || '-') + ' MX: ' + (x.nullmx ? 'null' : x.mx.join(', ') || '-')); });
    return t.join('\n');
  }

  $('input').setAttribute('data-tour', 'Type your domain here. Its variants are looked up in public DNS from your browser; nothing goes to us.');
  $('analyze').addEventListener('click', analyze);
  $('sample').addEventListener('click', function () { $('input').value = 'contoso.com'; analyze(); });
  $('clear').addEventListener('click', function () { runId++; $('analyze').disabled = false; $('input').value = ''; $('out').innerHTML = '<p class="empty">Enter a domain and press Check.</p>'; $('note').disabled = true; $('input').focus(); });
  $('note').addEventListener('click', function () { if (last) OV.copy(note(), 'List copied'); });
  OV.ctrlEnter($('input'), analyze);
  $('input').addEventListener('keydown', function (e) { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); analyze(); } });
  var handed = OV.takeHandoff();
  if (handed) { $('input').value = handed; analyze(); }
})();
