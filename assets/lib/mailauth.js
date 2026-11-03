// Mail authentication DNS checks (MX, SPF, DMARC, DKIM, MTA-STS, TLS-RPT, BIMI) over DNS-over-HTTPS.
// Shared by the SPF / DKIM / DMARC Checker and the M365 Posture Scanner. No OpsVantage backend.
(function () {
  'use strict';

  var RESOLVERS = [
    function (n, t) { return 'https://cloudflare-dns.com/dns-query?name=' + encodeURIComponent(n) + '&type=' + t; },
    function (n, t) { return 'https://dns.google/resolve?name=' + encodeURIComponent(n) + '&type=' + t; }
  ];
  var TYPE = { TXT: 16, MX: 15 };
  var SELECTORS = ['selector1', 'selector2', 'google', 'default', 'k1', 'k2', 'k3', 's1', 's2', 'dkim', 'mail', 'smtp',
    'mandrill', 'mxvault', 'zoho', 'zmail', 'fm1', 'fm2', 'fm3', 'protonmail', 'protonmail2', 'protonmail3',
    'everlytickey1', 'everlytickey2', 'sig1', 'pm', 'mailjet', 'cm', 'mte1', 'amazonses'];
  var PROVIDERS = [
    [/\.mail\.protection\.outlook\.com$|\.outlook\.com$/, 'Microsoft 365', 'include:spf.protection.outlook.com'],
    [/google(mail)?\.com$|\.smtp\.goog$/, 'Google Workspace', 'include:_spf.google.com'],
    [/zoho\.(com|eu|in)$/, 'Zoho Mail', 'include:zohomail.com'],
    [/pphosted\.com$/, 'Proofpoint', ''],
    [/mimecast\.com$/, 'Mimecast', ''],
    [/barracudanetworks\.com$/, 'Barracuda', ''],
    [/messagelabs\.com$/, 'Broadcom Email Security', ''],
    [/protonmail\.ch$/, 'Proton Mail', 'include:_spf.protonmail.ch'],
    [/secureserver\.net$/, 'GoDaddy', 'include:secureserver.net'],
    [/amazonaws\.com$/, 'Amazon SES', 'include:amazonses.com'],
    [/messagingengine\.com$/, 'Fastmail', 'include:spf.messagingengine.com']
  ];

  var cache = {};
  function query(name, type) {
    var key = name + '|' + type;
    if (!cache[key]) cache[key] = (async function () {
      var lastErr;
      for (var i = 0; i < RESOLVERS.length; i++) {
        try {
          var ctl = new AbortController();
          var to = setTimeout(function () { ctl.abort(); }, 8000);
          var r = await fetch(RESOLVERS[i](name, type), { headers: { accept: 'application/dns-json' }, signal: ctl.signal });
          clearTimeout(to);
          if (!r.ok) throw new Error('HTTP ' + r.status);
          var j = await r.json();
          return { status: j.Status, answers: (j.Answer || []).filter(function (a) { return a.type === TYPE[type]; }).map(function (a) { return a.data; }) };
        } catch (e) { lastErr = e; }
      }
      delete cache[key];
      throw lastErr || new Error('DNS lookup failed');
    })();
    return cache[key];
  }
  function joinTxt(d) { return String(d).replace(/^"|"$/g, '').replace(/"\s*"/g, '').replace(/\\"/g, '"'); }
  async function txt(name) { var r = await query(name, 'TXT'); return { status: r.status, records: r.answers.map(joinTxt) }; }
  function isSpf(r) { return /^v=spf1(\s|$)/i.test(r); }

  function normDomain(s) {
    s = String(s || '').trim().toLowerCase();
    if (s.indexOf('@') >= 0) s = s.split('@').pop();
    s = s.replace(/^[a-z][a-z0-9+.-]*:\/\//, '').split(/[\/?#\s]/)[0].split(':')[0].replace(/\.$/, '').replace(/^www\./, '');
    try { s = new URL('http://' + s).hostname; } catch (e) { return ''; }
    return /^([a-z0-9_-]+\.)+[a-z0-9-]{2,}$/.test(s) ? s : '';
  }

  // ---------------------------------------------------------------- checks ---

  async function countLookups(rec, depth, seen) {
    if (depth > 8) return 0;
    var n = 0, nested = [];
    rec.split(/\s+/).slice(1).forEach(function (term) {
      var t = term.replace(/^[+\-~?]/, '').toLowerCase();
      var m = t.match(/^include:(.+)$/) || t.match(/^redirect=(.+)$/);
      if (m) {
        n++;
        var target = m[1];
        if (target.indexOf('%{') >= 0 || seen.has(target)) return;
        seen.add(target);
        nested.push(txt(target).then(function (r) {
          var sub = r.records.find(isSpf);
          return sub ? countLookups(sub, depth + 1, seen) : 0;
        }).catch(function () { return 0; }));
      } else if (/^(a|mx|ptr|exists)([:/]|$)/.test(t)) n++;
    });
    var subs = await Promise.all(nested);
    return subs.reduce(function (a, b) { return a + b; }, n);
  }

  async function checkSpf(d) {
    var t = await txt(d);
    var recs = t.records.filter(isSpf);
    var res = { records: recs, issues: [], score: 0, state: 'fail' };
    if (!recs.length) { res.issues.push(['bad', 'No SPF record. Receivers cannot tell which servers may send mail for this domain.']); return res; }
    var rec = recs[0];
    var allm = rec.match(/(?:^|\s)([+\-~?]?)all(?:\s|$)/i);
    var q = allm ? (allm[1] || '+') : null;
    var redirect = /(?:^|\s)redirect=/i.test(rec);
    res.lookups = await countLookups(rec, 0, new Set([d]));
    res.score = q === '-' ? 25 : q === '~' ? 20 : q === '?' ? 5 : q === '+' ? 0 : redirect ? 20 : 5;
    if (q === '-') res.issues.push(['good', 'Ends with -all: mail from unlisted servers fails SPF.']);
    else if (q === '~') res.issues.push(['warn', 'Ends with ~all (softfail). Fine while DMARC enforces; switch to -all once every sender is listed.']);
    else if (q === '?') res.issues.push(['bad', 'Ends with ?all (neutral): SPF gives no protection.']);
    else if (q === '+') res.issues.push(['bad', 'Ends with +all: ANY server in the world is allowed to send as this domain.']);
    else if (redirect) res.issues.push(['info', 'Uses redirect= to another domain\'s SPF policy.']);
    else res.issues.push(['bad', 'No "all" mechanism at the end, so unlisted servers get a neutral result.']);
    if (recs.length > 1) { res.score = Math.min(res.score, 5); res.issues.push(['bad', recs.length + ' SPF records found. More than one is a permanent error (permerror): merge them into one record.']); }
    if (res.lookups > 10) { res.score = Math.min(res.score, 5); res.issues.push(['bad', res.lookups + ' DNS lookups: over the limit of 10, so receivers return permerror and SPF fails.']); }
    else if (res.lookups >= 8) res.issues.push(['warn', res.lookups + ' of 10 allowed DNS lookups used. One more include could break SPF.']);
    else res.issues.push(['good', res.lookups + ' of 10 allowed DNS lookups used.']);
    if (/(?:^|\s)[+\-~?]?ptr(?:[:\s]|$)/i.test(rec)) res.issues.push(['warn', 'Uses the deprecated ptr mechanism (slow, and ignored by some receivers).']);
    res.state = res.score >= 20 ? 'pass' : res.score >= 5 ? 'warn' : 'fail';
    return res;
  }

  function parseTags(rec) {
    var tags = {};
    rec.split(';').forEach(function (kv) {
      var i = kv.indexOf('=');
      if (i > 0) tags[kv.slice(0, i).trim().toLowerCase()] = kv.slice(i + 1).trim();
    });
    return tags;
  }

  async function checkDmarc(d) {
    var at = d, t = await txt('_dmarc.' + d);
    var recs = t.records.filter(function (r) { return /^v=DMARC1/i.test(r); });
    var inherited = false;
    if (!recs.length && d.split('.').length > 2) {
      var parent = d.split('.').slice(-2).join('.');
      var pt = await txt('_dmarc.' + parent);
      var precs = pt.records.filter(function (r) { return /^v=DMARC1/i.test(r); });
      if (precs.length) { recs = precs; inherited = true; at = parent; }
    }
    var res = { records: recs, issues: [], score: 0, state: 'fail', at: at };
    if (!recs.length) { res.issues.push(['bad', 'No DMARC record. Nothing tells receivers to block mail that fakes this domain.']); return res; }
    var tags = parseTags(recs[0]);
    var p = (inherited ? (tags.sp || tags.p) : tags.p || '').toLowerCase();
    var pct = tags.pct == null ? 100 : Number(tags.pct);
    res.tags = tags; res.policy = p; res.pct = pct;
    if (inherited) res.issues.push(['info', 'No record on ' + d + '; the organisational domain ' + at + ' applies' + (tags.sp ? ' its subdomain policy (sp=' + tags.sp + ').' : '.')]);
    if (recs.length > 1) res.issues.push(['bad', 'More than one DMARC record: receivers ignore DMARC entirely. Keep only one.']);
    if (p === 'reject') { res.score = 40; res.issues.push(['good', 'Policy p=reject: spoofed mail is refused.']); }
    else if (p === 'quarantine') { res.score = 32; res.issues.push(['good', 'Policy p=quarantine: spoofed mail goes to spam. Move to p=reject when reports look clean.']); }
    else if (p === 'none') { res.score = 10; res.issues.push(['bad', 'Policy p=none: monitoring only. Spoofed mail is still delivered.']); }
    else { res.issues.push(['bad', 'Missing or invalid p= tag, so the record is not valid.']); }
    if ((p === 'reject' || p === 'quarantine') && pct < 100) { res.score -= 6; res.issues.push(['warn', 'pct=' + pct + ': the policy applies to only ' + pct + '% of failing mail.']); }
    if (!inherited && tags.sp && tags.sp.toLowerCase() === 'none' && p !== 'none') res.issues.push(['warn', 'sp=none: subdomains (anything.' + d + ') can still be spoofed.']);
    if (tags.rua) res.issues.push(['good', 'Aggregate reports go to ' + tags.rua + '.']);
    else res.issues.push(['warn', 'No rua= address, so you get no reports showing who sends mail as this domain.']);
    if (recs.length > 1) res.score = Math.min(res.score, 5);
    res.state = res.score >= 30 ? 'pass' : res.score >= 10 ? 'warn' : 'fail';
    return res;
  }

  function keyInfo(rec) {
    var tags = parseTags(rec);
    var p = (tags.p || '').replace(/\s+/g, '');
    if (!p) return { revoked: true, label: 'revoked (empty p=)' };
    if ((tags.k || 'rsa').toLowerCase() === 'ed25519') return { bits: 256, label: 'Ed25519' };
    var bytes = Math.floor(p.length * 3 / 4);
    var bits = bytes <= 170 ? 1024 : bytes <= 300 ? 2048 : bytes <= 560 ? 4096 : 8192;
    if (bytes < 100) bits = 512;
    return { bits: bits, label: 'RSA ~' + bits + '-bit' };
  }

  async function checkDkim(d, extra) {
    var sels = SELECTORS.slice();
    if (extra && sels.indexOf(extra) < 0) sels.unshift(extra);
    var found = [];
    await Promise.all(sels.map(function (s) {
      return txt(s + '._domainkey.' + d).then(function (r) {
        var rec = r.records.find(function (x) { return /(^|;)\s*(v=DKIM1|k=|p=)/i.test(x); });
        if (rec) found.push({ selector: s, record: rec, key: keyInfo(rec) });
      }).catch(function () {});
    }));
    found.sort(function (a, b) { return sels.indexOf(a.selector) - sels.indexOf(b.selector); });
    var live = found.filter(function (f) { return !f.key.revoked; });
    var res = { found: found, issues: [], score: 0, state: 'fail' };
    if (!live.length) {
      res.state = 'warn';
      res.issues.push(['warn', found.length ? 'Only revoked DKIM keys found.' : 'No DKIM key found on ' + sels.length + ' common selectors. If you use a custom selector, enter it above; otherwise DKIM signing is probably off.']);
      return res;
    }
    var weak = live.filter(function (f) { return f.key.bits && f.key.bits < 2048 && f.key.label.indexOf('RSA') === 0; });
    res.score = weak.length === live.length ? 15 : 20;
    res.state = 'pass';
    res.issues.push(['good', live.length + ' DKIM key' + (live.length > 1 ? 's' : '') + ' found.']);
    if (weak.length) res.issues.push(['warn', 'Weak key on ' + weak.map(function (f) { return f.selector; }).join(', ') + ': rotate to 2048-bit RSA.']);
    return res;
  }

  async function checkMx(d) {
    var r = await query(d, 'MX');
    var mx = r.answers.map(function (a) { var p = String(a).split(/\s+/); return { pref: Number(p[0]), host: (p[1] || '').replace(/\.$/, '').toLowerCase() }; })
      .sort(function (a, b) { return a.pref - b.pref; });
    var nullMx = mx.length === 1 && (mx[0].host === '' || mx[0].host === '.');
    var provider = null;
    mx.some(function (m) { return PROVIDERS.some(function (p) { if (p[0].test(m.host)) { provider = { name: p[1], spf: p[2] }; return true; } return false; }); });
    return { mx: nullMx ? [] : mx, nullMx: nullMx, provider: provider, exists: r.status !== 3 };
  }

  async function checkExtra(name, re) {
    try { var r = await txt(name); return r.records.find(function (x) { return re.test(x); }) || ''; } catch (e) { return ''; }
  }

  window.OVMail = { normDomain: normDomain, checkMx: checkMx, checkSpf: checkSpf, checkDmarc: checkDmarc, checkDkim: checkDkim, checkExtra: checkExtra, SELECTORS: SELECTORS };
})();
