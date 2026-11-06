// SPF / DKIM / DMARC checker. DNS goes from the browser to public DNS-over-HTTPS resolvers; there is no OpsVantage backend.
(function () {
  'use strict';
  var OV = window.OV;
  var $ = function (id) { return document.getElementById(id); };

  var M = window.OVMail;
  var normDomain = M.normDomain, checkMx = M.checkMx, checkSpf = M.checkSpf, checkDmarc = M.checkDmarc, checkDkim = M.checkDkim, checkExtra = M.checkExtra;

  // ---------------------------------------------------------------- render ---

  var last = null;

  function issueList(issues) {
    return '<ul class="reasons">' + issues.map(function (x) { return '<li class="' + (x[0] === 'info' ? '' : x[0]) + '">' + OV.esc(x[1]) + '</li>'; }).join('') + '</ul>';
  }
  function statePill(s, text) { return '<span class="pill ' + (s === 'pass' ? 'pass' : s === 'warn' ? 'warn' : 'fail') + '">' + text + '</span>'; }
  function recordBox(r) { return '<div class="record">' + OV.esc(r) + '</div>'; }
  function fixBox(title, host, value) {
    return '<div class="fix"><b>' + OV.esc(title) + '</b>' +
      '<div class="sub" style="margin:6px 0 0;font-size:.8rem">TXT record · Name: <span class="mono">' + OV.esc(host) + '</span></div>' +
      recordBox(value) + '<button class="copy" type="button" data-value="' + OV.esc(value) + '">Copy record</button></div>';
  }

  function grade(score) { return score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : 'F'; }

  function render(d, R) {
    var spf = R.spf, dm = R.dmarc, dk = R.dkim, mx = R.mx;
    var noMail = mx.nullMx || !mx.mx.length;
    var score = spf.score + Math.max(0, dm.score) + dk.score + (dm.tags && dm.tags.rua ? 5 : 0) + (R.mtasts ? 5 : 0) + (R.tlsrpt ? 5 : 0);
    var g = grade(score);
    var enforcing = (dm.policy === 'reject' || dm.policy === 'quarantine') && dm.pct === 100;
    var spoof = enforcing && (spf.records.length || dk.found.length)
      ? ['good', 'Hard to spoof', 'Receivers are told to ' + dm.policy + ' mail that fakes ' + d + '.']
      : (dm.policy === 'reject' || dm.policy === 'quarantine')
        ? ['warn', 'Partly protected', 'DMARC enforces on only part of the mail, so some spoofed messages can still land.']
        : ['bad', 'Can be spoofed', 'Anyone can send email that appears to come from @' + d + ', and most inboxes will deliver it.'];

    var html = '<section class="panel" style="margin-bottom:18px"><div style="display:flex;gap:18px;align-items:center;flex-wrap:wrap">' +
      '<div class="grade ' + g + '" aria-label="Grade ' + g + '">' + g + '</div><div style="flex:1;min-width:220px">' +
      '<div class="mono" style="color:var(--muted)">' + OV.esc(d) + ' · ' + score + '/100</div>' +
      '<div class="verdict ' + spoof[0] + '" style="margin:8px 0 0;padding:10px 14px"><div><div class="v">' + spoof[1] + '</div><div class="sub" style="margin:2px 0 0">' + OV.esc(spoof[2]) + '</div></div></div></div>' +
      '<button class="btn btn-ghost btn-sm" type="button" id="copy-report">Copy report</button></div>' +
      '<div class="stats" style="margin:16px 0 0">' +
      '<div class="stat"><b>' + statePill(spf.state, spf.records.length ? 'SPF' : 'none') + '</b><span>SPF ' + spf.score + '/25</span></div>' +
      '<div class="stat"><b>' + statePill(dm.state, dm.policy ? 'p=' + dm.policy : 'none') + '</b><span>DMARC ' + Math.max(0, dm.score) + '/40</span></div>' +
      '<div class="stat"><b>' + statePill(dk.state, dk.found.length ? dk.found.length + ' key' + (dk.found.length > 1 ? 's' : '') : 'not found') + '</b><span>DKIM ' + dk.score + '/20</span></div>' +
      '<div class="stat"><b>' + statePill(R.mtasts ? 'pass' : 'warn', R.mtasts ? 'on' : 'off') + '</b><span>MTA-STS</span></div>' +
      '<div class="stat"><b>' + statePill(R.tlsrpt ? 'pass' : 'warn', R.tlsrpt ? 'on' : 'off') + '</b><span>TLS-RPT</span></div>' +
      '</div></section>';

    html += '<section class="panel">';
    // MX
    html += '<div class="check"><div class="check-h"><b>Mail servers (MX)</b>' + (mx.provider ? '<span class="pill">' + OV.esc(mx.provider.name) + '</span>' : '') + '</div>';
    if (mx.nullMx) html += '<p class="sub" style="margin:0">Null MX: this domain declares it does not receive email.</p>';
    else if (!mx.mx.length) html += '<p class="sub" style="margin:0">No MX records: this domain does not receive email. If it also never sends, lock it down with the records below so it can\'t be spoofed.</p>';
    else html += mx.mx.map(function (m) { return recordBox(m.pref + '  ' + m.host); }).join('');
    html += '</div>';

    // SPF
    html += '<div class="check"><div class="check-h"><b>SPF</b>' + statePill(spf.state, spf.score + '/25') + '</div>' + spf.records.map(recordBox).join('') + issueList(spf.issues);
    if (!spf.records.length) {
      var inc = noMail ? '' : (mx.provider && mx.provider.spf) || 'include:YOUR-MAIL-PROVIDER';
      html += fixBox(noMail ? 'This domain sends no mail: publish a deny-all SPF record' : 'Add an SPF record (list every service that sends as ' + d + ')', d, ('v=spf1 ' + inc + ' -all').replace('  ', ' '));
    } else if (spf.records.length === 1 && /(?:^|\s)[~?+]all/i.test(spf.records[0]) && spf.lookups <= 10) {
      html += fixBox('Stricter ending (once all senders are listed)', d, spf.records[0].replace(/(^|\s)[~?+]all(\s|$)/i, '$1-all$2'));
    }
    html += '</div>';

    // DMARC
    html += '<div class="check"><div class="check-h"><b>DMARC</b>' + statePill(dm.state, Math.max(0, dm.score) + '/40') + '</div>' + dm.records.map(recordBox).join('') + issueList(dm.issues);
    var rua = 'mailto:dmarc-reports@' + d;
    if (!dm.records.length) {
      html += noMail
        ? fixBox('This domain sends no mail: reject everything that claims to be from it', '_dmarc.' + d, 'v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s')
        : fixBox('Step 1: start monitoring (change the report address to a mailbox you own)', '_dmarc.' + d, 'v=DMARC1; p=none; rua=' + rua + '; fo=1') +
          '<p class="sub" style="font-size:.84rem">Step 2 after 2 to 4 weeks of clean reports: <span class="mono">p=quarantine</span>. Step 3: <span class="mono">p=reject</span>.</p>';
    } else if (dm.policy === 'none' && dm.at === d) {
      var next = dm.records[0].replace(/p=none/i, 'p=quarantine');
      if (!dm.tags.rua) next += '; rua=' + rua;
      html += fixBox('Next step: enforce (check your reports first)', '_dmarc.' + d, next);
    } else if (dm.at === d && !dm.tags.rua) {
      html += fixBox('Add reporting so you can see who sends as ' + d, '_dmarc.' + d, dm.records[0].replace(/;?\s*$/, '') + '; rua=' + rua);
    }
    html += '</div>';

    // DKIM
    html += '<div class="check"><div class="check-h"><b>DKIM</b>' + statePill(dk.state, dk.score + '/20') + '</div>';
    if (dk.found.length) {
      html += '<div class="table-wrap"><table class="data"><thead><tr><th>Selector</th><th>Key</th><th>Record</th></tr></thead><tbody>' +
        dk.found.map(function (f) {
          return '<tr><td class="mono">' + OV.esc(f.selector) + '</td><td>' + statePill(f.key.revoked ? 'warn' : (f.key.bits < 2048 && f.key.label.indexOf('RSA') === 0 ? 'warn' : 'pass'), OV.esc(f.key.label)) +
            '</td><td class="mono" style="max-width:420px">' + OV.esc(f.record.length > 90 ? f.record.slice(0, 90) + '…' : f.record) + '</td></tr>';
        }).join('') + '</tbody></table></div>';
    }
    html += issueList(dk.issues);
    if (!dk.found.length && !noMail) {
      var how = mx.provider && mx.provider.name === 'Microsoft 365' ? 'Microsoft 365: Defender portal > Email & collaboration > Policies > Email authentication settings > DKIM > enable for ' + d + '.'
        : mx.provider && mx.provider.name === 'Google Workspace' ? 'Google Workspace: Admin console > Apps > Google Workspace > Gmail > Authenticate email > Generate new record, publish it, then Start authentication.'
          : 'Turn on DKIM signing in your mail provider\'s admin console; it gives you a selector and a TXT or CNAME record to publish.';
      html += '<div class="fix"><b>Enable DKIM signing</b><p class="sub" style="margin:6px 0 0;font-size:.86rem">' + OV.esc(how) + '</p></div>';
    }
    html += '</div>';

    // Extras
    html += '<div class="check"><div class="check-h"><b>Transport security &amp; branding</b></div><ul class="reasons">' +
      '<li class="' + (R.mtasts ? 'good' : 'warn') + '">MTA-STS: ' + (R.mtasts ? OV.esc(R.mtasts) : 'not set. Senders may deliver to you over unencrypted or downgraded connections.') + '</li>' +
      '<li class="' + (R.tlsrpt ? 'good' : 'warn') + '">TLS-RPT: ' + (R.tlsrpt ? OV.esc(R.tlsrpt) : 'not set. You get no reports when encrypted delivery to you fails.') + '</li>' +
      '<li class="' + (R.bimi ? 'good' : '') + '">BIMI: ' + (R.bimi ? OV.esc(R.bimi) : 'not set (optional: shows your logo in Gmail and Apple Mail, needs DMARC enforcement).') + '</li></ul>';
    if (!R.tlsrpt && !noMail) html += fixBox('Add TLS reporting', '_smtp._tls.' + d, 'v=TLSRPTv1; rua=mailto:tls-reports@' + d);
    html += '</div></section>';

    html += '<p class="sub" style="margin-top:16px;font-size:.86rem">Managing many client domains? Daily monitoring with alerts when a record breaks is coming to OpsVantage. <a href="https://github.com/kazisohan-cyber/soclens" style="color:var(--pink)">Follow for updates</a>.</p>';
    $('result').innerHTML = html;
    last = { d: d, R: R, score: score, grade: g, spoof: spoof };
  }

  function report() {
    var L = last, R = L.R;
    var lines = ['Email security report for ' + L.d + ' (OpsVantage SPF/DKIM/DMARC Checker)', 'Grade: ' + L.grade + ' (' + L.score + '/100). ' + L.spoof[1] + ': ' + L.spoof[2], ''];
    lines.push('SPF (' + R.spf.score + '/25): ' + (R.spf.records[0] || 'missing'));
    R.spf.issues.forEach(function (x) { lines.push('  - ' + x[1]); });
    lines.push('DMARC (' + Math.max(0, R.dmarc.score) + '/40): ' + (R.dmarc.records[0] || 'missing'));
    R.dmarc.issues.forEach(function (x) { lines.push('  - ' + x[1]); });
    lines.push('DKIM (' + R.dkim.score + '/20): ' + (R.dkim.found.length ? R.dkim.found.map(function (f) { return f.selector + ' (' + f.key.label + ')'; }).join(', ') : 'no key on common selectors'));
    lines.push('MTA-STS: ' + (R.mtasts ? 'on' : 'off') + ' | TLS-RPT: ' + (R.tlsrpt ? 'on' : 'off') + ' | BIMI: ' + (R.bimi ? 'on' : 'off'));
    lines.push('', 'Checked ' + new Date().toISOString().slice(0, 16).replace('T', ' ') + ' UTC');
    return lines.join('\n');
  }

  async function run(d) {
    $('go').disabled = true;
    $('result').innerHTML = '<section class="panel"><p class="empty"><span class="spin"></span>Checking ' + OV.esc(d) + '…</p></section>';
    try {
      var sel = $('selector').value.trim().toLowerCase().replace(/\._domainkey.*$/, '');
      if (sel && !/^[a-z0-9._-]{1,63}$/.test(sel)) sel = '';
      var mx = await checkMx(d);
      if (!mx.exists) {
        $('result').innerHTML = '<section class="panel"><p class="empty">' + OV.esc(d) + ' does not exist in DNS (NXDOMAIN). Check the spelling.</p></section>';
        return;
      }
      var out = await Promise.all([checkSpf(d), checkDmarc(d), checkDkim(d, sel),
        checkExtra('_mta-sts.' + d, /^v=STSv1/i), checkExtra('_smtp._tls.' + d, /^v=TLSRPTv1/i), checkExtra('default._bimi.' + d, /^v=BIMI1/i)]);
      render(d, { mx: mx, spf: out[0], dmarc: out[1], dkim: out[2], mtasts: out[3], tlsrpt: out[4], bimi: out[5] });
    } catch (e) {
      $('result').innerHTML = '<section class="panel"><p class="empty">DNS lookup failed (' + OV.esc(e.message || e) + '). Your network may block DNS-over-HTTPS; try again or from another network.</p></section>';
    } finally {
      $('go').disabled = false;
    }
  }

  $('form').addEventListener('submit', function (e) {
    e.preventDefault();
    var d = normDomain($('domain').value);
    if (!d) { OV.toast('Enter a valid domain, like example.com'); return; }
    $('domain').value = d;
    try { history.replaceState(null, '', '?domain=' + encodeURIComponent(d)); } catch (err) { /* sandboxed: URL just won't update */ }
    run(d);
  });
  $('result').addEventListener('click', function (e) {
    var b = e.target.closest('.copy');
    if (b) OV.copy(b.dataset.value, 'Record copied');
    if (e.target.id === 'copy-report' && last) OV.copy(report(), 'Report copied');
  });

  var initial = normDomain(OV.takeHandoff() || new URLSearchParams(location.search).get('domain'));
  if (initial) { $('domain').value = initial; run(initial); }
})();
