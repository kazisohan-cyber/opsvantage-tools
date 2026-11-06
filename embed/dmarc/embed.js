// Embeddable SPF / DKIM / DMARC checker (iframe on other sites). Same checks as /dmarc-checker/: DNS goes from the
// visitor's browser to public DNS-over-HTTPS resolvers, nothing reaches OpsVantage. ?theme=light|dark sets the look.
(function () {
  'use strict';
  var M = window.OVMail, C = window.OVCharts;
  var $ = function (id) { return document.getElementById(id); };
  var esc = function (s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); };
  var th = new URLSearchParams(location.search).get('theme');
  if (th === 'light' || th === 'dark') document.documentElement.setAttribute('data-theme', th);

  function grade(score) { return score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : 'F'; }
  function pill(state, text) { return '<span class="pill ' + (state === 'pass' ? 'pass' : state === 'warn' ? 'warn' : 'fail') + '">' + esc(text) + '</span>'; }

  async function run(d) {
    $('go').disabled = true;
    $('res').innerHTML = '<p class="empty">Checking ' + esc(d) + '…</p>';
    try {
      var mx = await M.checkMx(d);
      if (!mx.exists) { $('res').innerHTML = '<p class="empty">' + esc(d) + ' does not exist in DNS. Check the spelling.</p>'; return; }
      var o = await Promise.all([M.checkSpf(d), M.checkDmarc(d), M.checkDkim(d, ''), M.checkExtra('_mta-sts.' + d, /^v=STSv1/i), M.checkExtra('_smtp._tls.' + d, /^v=TLSRPTv1/i)]);
      var spf = o[0], dm = o[1], dk = o[2];
      var score = spf.score + Math.max(0, dm.score) + dk.score + (dm.tags && dm.tags.rua ? 5 : 0) + (o[3] ? 5 : 0) + (o[4] ? 5 : 0);
      var enforcing = (dm.policy === 'reject' || dm.policy === 'quarantine') && dm.pct === 100;
      var verdict = enforcing && (spf.records.length || dk.found.length) ? ['good', 'Hard to spoof'] : (dm.policy === 'reject' || dm.policy === 'quarantine') ? ['warn', 'Partly protected'] : ['bad', 'Can be spoofed'];
      var issues = spf.issues.concat(dm.issues).filter(function (x) { return x[0] === 'bad' || x[0] === 'warn'; }).slice(0, 3);
      $('res').innerHTML = '<div class="e-top">' + (C ? C.gauge(score, grade(score), null, 104) : '') + '<div><div class="mono e-d">' + esc(d) + '</div>' +
        '<div class="verdict ' + verdict[0] + '" style="margin:6px 0 0;padding:8px 12px"><div class="v">' + verdict[1] + '</div></div></div></div>' +
        '<div class="stats" style="margin:12px 0 0">' +
        '<div class="stat"><b>' + pill(spf.state, spf.records.length ? 'SPF' : 'none') + '</b><span>SPF ' + spf.score + '/25</span></div>' +
        '<div class="stat"><b>' + pill(dm.state, dm.policy ? 'p=' + dm.policy : 'none') + '</b><span>DMARC ' + Math.max(0, dm.score) + '/40</span></div>' +
        '<div class="stat"><b>' + pill(dk.state, dk.found.length ? dk.found.length + ' key' + (dk.found.length > 1 ? 's' : '') : 'not found') + '</b><span>DKIM ' + dk.score + '/20</span></div></div>' +
        (issues.length ? '<ul class="reasons" style="margin-top:10px">' + issues.map(function (x) { return '<li class="' + x[0] + '">' + esc(x[1]) + '</li>'; }).join('') + '</ul>' : '') +
        '<p class="e-more"><a href="https://tools.opsvantage.net/dmarc-checker/?domain=' + encodeURIComponent(d) + '" target="_blank" rel="noopener">Full report with the exact DNS records to fix →</a></p>';
    } catch (e) {
      $('res').innerHTML = '<p class="empty">DNS lookup failed. The network may block DNS-over-HTTPS.</p>';
    } finally { $('go').disabled = false; }
  }

  $('f').addEventListener('submit', function (e) {
    e.preventDefault();
    var d = M.normDomain($('d').value);
    if (!d) { $('res').innerHTML = '<p class="empty">Enter a domain such as example.com</p>'; return; }
    $('d').value = d;
    run(d);
  });
})();
