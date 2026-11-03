// Email Header Analyzer: renders VSHeaders.analyze() output. Nothing leaves the page.
(function () {
  'use strict';
  var H = window.VSHeaders, I = window.VSIoc, OV = window.OV;
  var $ = function (id) { return document.getElementById(id); };
  var last = null;

  var SAMPLE = [
    'Received: from AM9PR02MB7012.eurprd02.prod.outlook.com (2603:10a6:20b:3e1::18) by DB9PR02MB7300.eurprd02.prod.outlook.com with HTTPS; Mon, 2 Nov 2026 08:14:09 +0000',
    'Received: from mail.payments-update-secure.top (91.215.85.142) by AM9PR02MB7012.mail.protection.outlook.com (10.167.242.64) with Microsoft SMTP Server id 15.20.7633.10; Mon, 2 Nov 2026 08:14:05 +0000',
    'Received: from DESKTOP-7H2K (unknown [45.88.97.11]) by mail.payments-update-secure.top (Postfix) with ESMTPA id 4XkQ2r6TzbzJ; Mon, 2 Nov 2026 08:13:58 +0000',
    'Authentication-Results: spf=fail (sender IP is 91.215.85.142) smtp.mailfrom=payments-update-secure.top; dkim=none (message not signed) header.d=none; dmarc=fail action=quarantine header.from=contoso-finance.com; compauth=fail reason=000',
    'Received-SPF: Fail (protection.outlook.com: domain of payments-update-secure.top does not designate 91.215.85.142 as permitted sender)',
    'From: "Microsoft 365 Billing" <billing@contoso-finance.com>',
    'Reply-To: accounts.payable@payments-update-secure.top',
    'Return-Path: bounce@payments-update-secure.top',
    'To: finance@example.com',
    'Subject: URGENT: Updated bank details for outstanding invoice INV-20931',
    'Date: Mon, 2 Nov 2026 08:13:55 +0000',
    'Message-ID: <20261102081355.4XkQ2r6TzbzJ@mail.payments-update-secure.top>',
    'X-Mailer: PHPMailer 6.8.1',
    'X-MS-Exchange-Organization-SCL: 5',
    'MIME-Version: 1.0',
    'Content-Type: text/html; charset=UTF-8'
  ].join('\n');

  var VCLASS = { malicious: 'bad', suspicious: 'warn', benign: 'good', unknown: '' };
  var VTEXT = {
    malicious: 'Strong signs of spoofing or phishing. Do not reply or click; treat as an incident.',
    suspicious: 'Some red flags. Verify the sender through a known channel before acting.',
    benign: 'Authentication passes and no red flags were found.',
    unknown: 'Not enough signals for a verdict. Review the details below.'
  };

  function pill(label, val, dom) {
    var v = (val || 'none').toLowerCase();
    var cls = v === 'pass' ? 'pass' : (v === 'fail' || v === 'permerror') ? 'fail' : v === 'none' ? '' : 'warn';
    return '<div class="stat"><b><span class="pill ' + cls + '">' + OV.esc(v) + '</span></b><span>' + label + (dom ? ' · ' + OV.esc(dom) : '') + '</span></div>';
  }

  function analyze() {
    var raw = $('input').value;
    if (!raw.trim()) { $('out').innerHTML = '<p class="empty">Paste headers and press Analyze.</p>'; $('details').hidden = true; $('note').disabled = true; return; }
    var r = H.analyze(raw);
    last = r;
    if (!r.ok) {
      $('out').innerHTML = '<p class="empty">' + OV.esc(r.error) + '</p>';
      $('details').hidden = true; $('note').disabled = true;
      return;
    }
    $('note').disabled = false;
    var a = r.auth;
    var html = '<div class="verdict ' + VCLASS[r.verdict] + '"><div><div class="v">' + r.verdict + '</div><div class="sub" style="margin:2px 0 0">' +
      VTEXT[r.verdict] + '</div></div></div>';
    html += '<div class="stats">' + pill('SPF', a.spf, a.spfDomain) + pill('DKIM', a.dkim || (a.dkimDomain ? '' : 'none'), a.dkimDomain) +
      pill('DMARC', a.dmarc, a.dmarcFrom) + (a.compauth ? pill('CompAuth', a.compauth) : '') + '</div>';
    html += '<h3 style="font-family:var(--display);font-size:.95rem;margin:4px 0 8px">Findings</h3><ul class="reasons">' +
      r.reasons.map(function (x) { return '<li class="' + (x.kind === 'bad' ? 'bad' : x.kind === 'good' ? 'good' : '') + '">' + OV.esc(x.t) + '</li>'; }).join('') + '</ul>';
    if (r.iocs.length) {
      html += '<h3 style="font-family:var(--display);font-size:.95rem;margin:16px 0 8px">Indicators to check</h3><ul class="ioc-list">' +
        r.iocs.map(function (x) {
          var d = I.defang(x.value, x.type);
          return '<li><span>' + OV.esc(d) + ' <span class="sub">' + OV.esc(x.why) + '</span></span><button class="copy" type="button" data-value="' + OV.esc(x.value) + '">Copy</button></li>';
        }).join('') + '</ul>';
    }
    $('out').innerHTML = html;

    $('hop-count').textContent = r.hops.length;
    $('hops').innerHTML = '<thead><tr><th>#</th><th>From</th><th>By</th><th>Protocol</th><th>IP</th><th>Delay</th></tr></thead><tbody>' +
      (r.hops.length ? r.hops.map(function (h, i) {
        var priv = h.ip && I.isPrivateIp(h.ip);
        return '<tr><td>' + (i + 1) + '</td><td class="mono">' + OV.esc(h.from || '-') + '</td><td class="mono">' + OV.esc(h.by || '-') + '</td><td>' + OV.esc(h.with || '-') +
          '</td><td class="mono">' + OV.esc(h.ip || '-') + (h.ip ? ' <span class="pill' + (priv ? '' : ' warn') + '">' + (priv ? 'private' : 'public') + '</span>' : '') +
          (h.ip && h.ip === r.origin ? ' <span class="pill fail">origin</span>' : '') +
          '</td><td>' + (h.delay == null ? '-' : fmtDelay(h.delay)) + '</td></tr>';
      }).join('') : '<tr><td colspan="6" class="sub">No Received headers found.</td></tr>') + '</tbody>';

    var s = r.summary;
    var rows = [['From', s.from], ['Reply-To', s.replyTo], ['Return-Path', s.returnPath], ['To', s.to], ['Subject', s.subject], ['Date', s.date], ['Message-ID', s.messageId], ['Mailer', s.mailer], ['Originating IP', r.origin]];
    $('summary').innerHTML = rows.filter(function (x) { return x[1]; }).map(function (x) { return '<dt>' + x[0] + '</dt><dd class="' + (x[0] === 'Message-ID' || x[0] === 'Originating IP' ? 'mono' : '') + '">' + OV.esc(x[1]) + '</dd>'; }).join('');
    $('details').hidden = false;
  }

  function fmtDelay(sec) {
    if (sec < 0) return '<span class="pill warn">' + sec + 's</span>';
    if (sec < 60) return sec + 's';
    if (sec < 3600) return Math.round(sec / 60) + ' min';
    return '<span class="pill warn">' + Math.round(sec / 3600) + ' h</span>';
  }

  function ticketNote() {
    var r = last, s = r.summary, a = r.auth;
    var lines = [
      'Email header analysis (OpsVantage Email Header Analyzer)',
      'Verdict: ' + r.verdict.toUpperCase() + ' (score ' + r.score + ')',
      'From: ' + (s.from || '-'),
      'Subject: ' + (s.subject || '-'),
      'Date: ' + (s.date || '-'),
      'Auth: SPF=' + (a.spf || 'none') + ', DKIM=' + (a.dkim || 'none') + ', DMARC=' + (a.dmarc || 'none') + (a.compauth ? ', CompAuth=' + a.compauth : ''),
      'Originating IP: ' + (r.origin ? I.defang(r.origin, r.origin.indexOf(':') >= 0 ? 'ipv6' : 'ipv4') : '-'),
      '',
      'Findings:'
    ].concat(r.reasons.map(function (x) { return '- ' + x.t; }));
    if (r.iocs.length) lines = lines.concat(['', 'Indicators (defanged):'], r.iocs.map(function (x) { return '- ' + I.defang(x.value, x.type) + ' (' + x.why + ')'; }));
    return lines.join('\n');
  }

  function loadFile(f) {
    if (!f) return;
    if (f.size > 25 * 1024 * 1024) { OV.toast('File is over 25 MB'); return; }
    var rd = new FileReader();
    rd.onload = function () { $('input').value = String(rd.result); analyze(); };
    rd.readAsText(f);
  }

  $('analyze').addEventListener('click', analyze);
  $('sample').addEventListener('click', function () { $('input').value = SAMPLE; analyze(); });
  $('clear').addEventListener('click', function () { $('input').value = ''; analyze(); $('input').focus(); });
  $('file').addEventListener('change', function () { loadFile(this.files[0]); this.value = ''; });
  $('input').addEventListener('dragover', function (e) { e.preventDefault(); });
  $('input').addEventListener('drop', function (e) {
    if (e.dataTransfer.files && e.dataTransfer.files[0]) { e.preventDefault(); loadFile(e.dataTransfer.files[0]); }
  });
  $('input').addEventListener('paste', function () { setTimeout(analyze, 0); });
  $('note').addEventListener('click', function () { if (last && last.ok) OV.copy(ticketNote(), 'Ticket note copied'); });
  $('out').addEventListener('click', function (e) {
    var b = e.target.closest('.copy');
    if (b) OV.copy(b.dataset.value, 'Copied');
  });
})();
