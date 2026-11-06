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

  // A full message (headers + body) also gets its links and attachments read. The HTML is parsed in an inert
  // document only to collect links: nothing in the email is rendered, run or fetched.
  var fileBytes = null, fileText = null, seq = 0;
  function hasBody(raw) {
    var i = raw.replace(/\r\n/g, '\n').search(/\n[ \t]*\n/);
    return i > 0 && raw.slice(i).trim().length > 0;
  }

  async function analyze() {
    var raw = $('input').value;
    var mine = ++seq;
    if (!raw.trim()) { $('out').innerHTML = '<p class="empty">Paste headers and press Analyze.</p>'; $('details').hidden = true; $('note').disabled = true; return; }
    var r = H.analyze(raw);
    r.body = null;
    if (r.ok && window.VSEml && hasBody(raw)) {
      try {
        var bytes = fileBytes && raw === fileText ? fileBytes : new TextEncoder().encode(raw);
        var e = await window.VSEml.analyze(bytes);
        if (mine !== seq) return;
        if (e.ok) {
          r.body = { urls: e.urls, attachments: e.attachments };
          r.reasons = r.reasons.concat(e.reasons);
          r.verdict = e.verdict;
        }
      } catch (err) { /* body unreadable: keep the header result */ }
    }
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
    html += emailSteps(r);
    html += '<h3 style="font-family:var(--display);font-size:.95rem;margin:4px 0 8px">Findings</h3><ul class="reasons">' +
      r.reasons.map(function (x) { return '<li class="' + (x.kind === 'bad' ? 'bad' : x.kind === 'good' ? 'good' : '') + '">' + OV.esc(x.t) + '</li>'; }).join('') + '</ul>';
    if (r.iocs.length) {
      html += '<h3 style="font-family:var(--display);font-size:.95rem;margin:16px 0 8px">Indicators to check</h3><ul class="ioc-list">' +
        r.iocs.map(function (x) {
          var d = I.defang(x.value, x.type);
          return '<li><span class="ioc-v"><span>' + OV.esc(d) + ' <span class="sub">' + OV.esc(x.why) + '</span></span>' +
            OV.pivots(x.type === 'email' ? 'domain' : x.type, x.type === 'email' ? x.value.split('@')[1] : x.value) + '</span><button class="copy" type="button" data-value="' + OV.esc(x.value) + '">Copy</button></li>';
        }).join('') + '</ul>';
    }
    if (r.body) html += bodyHtml(r.body);
    var fromDom = (r.summary.fromAddr || '').split('@')[1] || '';
    html += '<div class="send-row"><button class="btn btn-ghost btn-sm" type="button" id="to-ioc">Send all indicators to IOC Extractor</button>' +
      (fromDom ? '<button class="btn btn-ghost btn-sm" type="button" id="to-dmarc" data-domain="' + OV.esc(fromDom) + '">Can ' + OV.esc(fromDom) + ' be spoofed?</button>' : '') + '</div>';
    $('out').innerHTML = html;

    $('hop-count').textContent = r.hops.length;
    $('path-viz').innerHTML = pathViz(r);
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

  // The route as boxes: sender → each relay → recipient, with the time spent on every hop.
  function pathViz(r) {
    if (!r.hops.length) return '<p class="sub">No Received headers, so the route can\'t be drawn.</p>';
    var C = window.OVCharts;
    var nodes = [];
    var first = r.hops[0];
    nodes.push({ k: 'Sender', host: first.from || 'unknown', ip: first.ip, origin: first.ip && first.ip === r.origin });
    r.hops.forEach(function (h, i) {
      var next = r.hops[i + 1];
      nodes.push({ k: i === r.hops.length - 1 ? 'Delivered by' : 'Relay', host: h.by || '?', ip: next ? next.ip : '', origin: next && next.ip && next.ip === r.origin, last: i === r.hops.length - 1, delay: h.delay, proto: h.with });
    });
    var html = '<div class="path" role="list" aria-label="Delivery route, oldest first">';
    nodes.forEach(function (n, i) {
      if (i) {
        var d = n.delay;
        html += '<div class="hop-link' + (d != null && d > 600 ? ' slow' : '') + '" aria-hidden="true"><span>' + (d == null ? (n.proto ? OV.esc(n.proto) : '→') : fmtDelay(d).replace(/<[^>]+>/g, '')) + '</span></div>';
      }
      var priv = n.ip && I.isPrivateIp(n.ip);
      html += '<div class="hop' + (n.origin ? ' origin' : '') + (n.last ? ' me' : '') + '" role="listitem"><div class="hop-k">' + n.k + (n.origin ? ' · origin' : '') + '</div><b>' + OV.esc(n.host) + '</b>' +
        (n.ip ? '<div class="ip">' + OV.esc(n.ip) + ' <span class="pill' + (priv ? '' : ' warn') + '">' + (priv ? 'private' : 'public') + '</span></div>' : '') + '</div>';
    });
    html += '</div>';
    var withDelay = r.hops.filter(function (h) { return h.delay != null; });
    if (C && withDelay.length) {
      var total = withDelay.reduce(function (a, h) { return a + Math.max(0, h.delay); }, 0);
      html += '<div class="viz" style="margin-top:6px"><h3>Time spent on each hop · total ' + fmtDelay(total).replace(/<[^>]+>/g, '') + '</h3>' +
        C.bars(withDelay.map(function (h) { return { label: h.by || '?', value: Math.max(0, h.delay), note: fmtDelay(h.delay).replace(/<[^>]+>/g, ''), color: h.delay > 600 ? 'var(--amber)' : h.delay < 0 ? '#ef4444' : 'var(--pink)' }; })) + '</div>';
    }
    return html;
  }

  function emailSteps(r) {
    var s = r.summary, origin = r.origin, fromDom = (s.fromAddr || '').split('@')[1] || '';
    var subj = s.subject ? '"' + s.subject.slice(0, 60) + '"' : 'this subject';
    // When DMARC fails the From domain was forged (it may belong to a real partner): block the attacker's own
    // reply / bounce domain instead.
    var forged = r.auth.dmarc === 'fail' || r.auth.dmarc === 'none' && r.auth.spf === 'fail';
    var dom = function (a) { return (a || '').split('@')[1] || ''; };
    var blockDom = forged ? (dom(s.replyTo) !== fromDom && dom(s.replyTo)) || (dom(s.returnPath) !== fromDom && dom(s.returnPath)) || '' : fromDom;
    var block = [blockDom ? 'the sender domain ' + blockDom : '', origin ? 'the originating IP ' + origin : ''].filter(Boolean).join(' and ');
    if (r.verdict === 'malicious') return OV.nextSteps([
      'Don\'t reply, click or open attachments.' + (block ? ' Block ' + block + ' at your mail gateway.' : '') +
        (forged && fromDom ? ' The From address on ' + fromDom + ' was forged, so don\'t block that domain.' : ''),
      { t: 'Find every copy: search all mailboxes for ' + subj + ' from the same sender and remove them (Microsoft 365: Threat Explorer or Content search).', href: '/guides/phishing-triage-checklist/', link: 'Checklist' },
      { t: 'If anyone clicked or typed a password: reset it, revoke their sessions and check their mailbox for new inbox rules.', href: '/guides/m365-inbox-rules-forwarding/', link: 'Inbox rules' }
    ], 'bad');
    if (r.verdict === 'suspicious') return OV.nextSteps([
      'Confirm with the sender through a channel you already trust (a known phone number), not by replying.',
      'Look up the links, attachment hashes and originating IP with the buttons below before anyone acts on the email.',
      r.body ? '' : 'Drop the whole .eml file here to also check the links and attachments inside it.'
    ], 'warn');
    return OV.nextSteps([
      r.body ? 'No strong red flags. If the email asks for money, a password or new bank details, still confirm by phone.' : 'Only the headers were checked. Drop the whole .eml file to also check the links and attachments inside it.',
      fromDom ? 'Check whether ' + fromDom + ' could be spoofed with the button at the end.' : ''
    ]);
  }

  function fmtSize(n) { return n < 1024 ? n + ' B' : n < 1048576 ? Math.round(n / 1024) + ' KB' : (n / 1048576).toFixed(1) + ' MB'; }

  function bodyHtml(b) {
    var h = '';
    var H3 = function (t, n) { return '<h3 style="font-family:var(--display);font-size:.95rem;margin:16px 0 8px">' + t + ' <span class="count">' + n + '</span></h3>'; };
    if (b.attachments.length) {
      h += H3('Attachments', b.attachments.length) + '<ul class="ioc-list">' + b.attachments.map(function (a) {
        return '<li><span class="ioc-v"><span>' + OV.esc(a.name) + ' <span class="sub">' + OV.esc(a.type || '') + ' · ' + fmtSize(a.size) + '</span></span>' +
          (a.flags.length ? '<span class="sub" style="color:#ef4444;white-space:normal">' + OV.esc(a.flags.join('; ')) + '</span>' : '') +
          '<span class="sub" style="white-space:normal;word-break:break-all">SHA-256 ' + OV.esc(a.sha256) + '</span>' + OV.pivots('sha256', a.sha256) +
          '</span><button class="copy" type="button" data-value="' + OV.esc(a.sha256) + '">Copy hash</button></li>';
      }).join('') + '</ul>';
    }
    if (b.urls.length) {
      var urls = b.urls.slice().sort(function (x, y) { return (y.mismatch + (y.level === 'block') * 2 + (y.level === 'warn')) - (x.mismatch + (x.level === 'block') * 2 + (x.level === 'warn')); });
      h += H3('Links in the email', urls.length) + '<ul class="ioc-list">' + urls.slice(0, 40).map(function (u) {
        var warn = [];
        if (u.mismatch) warn.push('Text shows "' + u.text.slice(0, 80) + '" but goes to ' + u.host);
        if (u.real !== u.url) warn.push('Unwrapped from a safe-link redirect');
        if (u.reasons.length) warn.push(u.reasons.join('; '));
        var bad = u.mismatch || u.level === 'block' || u.level === 'warn';
        return '<li><span class="ioc-v"><span>' + OV.esc(I.defang(u.real, 'url')) + '</span>' +
          (warn.length ? '<span class="sub" style="white-space:normal;' + (bad ? 'color:#ef4444' : '') + '">' + OV.esc(warn.join(' · ')) + '</span>' : '') +
          OV.pivots('url', u.real) + '</span><button class="copy" type="button" data-value="' + OV.esc(u.real) + '">Copy</button></li>';
      }).join('') + '</ul>' + (urls.length > 40 ? '<p class="sub">…and ' + (urls.length - 40) + ' more.</p>' : '');
    }
    if (!b.attachments.length && !b.urls.length) h += '<p class="sub" style="margin-top:12px">The message body has no links or attachments.</p>';
    return h;
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
    if (r.body && r.body.attachments.length) lines = lines.concat(['', 'Attachments:'], r.body.attachments.map(function (a) { return '- ' + a.name + ' (' + fmtSize(a.size) + ') SHA-256 ' + a.sha256 + (a.flags.length ? ' [' + a.flags.join('; ') + ']' : ''); }));
    if (r.body && r.body.urls.length) lines = lines.concat(['', 'Links (defanged):'], r.body.urls.slice(0, 20).map(function (u) { return '- ' + I.defang(u.real, 'url') + (u.mismatch ? ' [text shows ' + u.text.slice(0, 60) + ']' : ''); }));
    return lines.join('\n');
  }

  function loadFile(f) {
    if (!f) return;
    if (f.size > 25 * 1024 * 1024) { OV.toast('File is over 25 MB'); return; }
    var rd = new FileReader();
    rd.onload = function () {
      fileBytes = new Uint8Array(rd.result);
      fileText = new TextDecoder('utf-8').decode(fileBytes);
      $('input').value = fileText;
      fileText = $('input').value; // the textarea normalises line endings
      analyze();
    };
    rd.readAsArrayBuffer(f);
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
    if (b) { OV.copy(b.dataset.value, 'Copied'); return; }
    if (e.target.closest('#to-dmarc')) { OV.sendTo('/dmarc-checker/', e.target.closest('#to-dmarc').dataset.domain); return; }
    if (e.target.closest('#to-ioc') && last && last.ok) {
      var lines = last.iocs.map(function (x) { return x.value; });
      if (last.body) {
        last.body.attachments.forEach(function (x) { lines.push(x.sha256 + ' ' + x.name); });
        last.body.urls.forEach(function (u) { lines.push(u.real); });
      }
      OV.sendTo('/ioc-extractor/', lines.join('\n'));
    }
  });
  OV.ctrlEnter($('input'), analyze);
  var handed = OV.takeHandoff();
  if (handed) { $('input').value = handed; analyze(); }
})();
