// Hunting Query Generator: turns a list of indicators into ready-to-run hunting queries for Microsoft Sentinel /
// Defender XDR (KQL), Splunk (SPL), CrowdStrike Falcon LogScale and Elastic (KQL). Everything is built in the page.
(function () {
  'use strict';
  var OV = window.OV, I = window.VSIoc;
  var $ = function (id) { return document.getElementById(id); };
  var last = null;

  var SAMPLE = [
    'IOCs from the incident report:',
    'C2: 185.220.101[.]45, 45.137.21.9 and update-cdn-sync[.]xyz',
    'Phishing: hxxps://login-micros0ft-support[.]com/owa/auth.php, sender billing@micros0ft-support[.]com',
    'Payload SHA256 4f5d3c2b1a0e9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c',
    'Dropper MD5 44d88612fea8a8f36de82e1278abb02f'
  ].join('\n');

  var q = function (v) { return '"' + String(v).replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"'; };
  var list = function (vals) { return vals.map(q).join(', '); };
  var orList = function (vals) { return vals.map(q).join(' or '); };

  function collect(text) {
    var g = { ip: [], domain: [], url: [], sha256: [], sha1: [], md5: [], email: [] };
    var keepPrivate = $('opt-private').checked;
    I.unique(text, { max: 5000 }).forEach(function (x) {
      if (x.type === 'ipv4' || x.type === 'ipv6') { if (keepPrivate || !I.isPrivateIp(x.value)) g.ip.push(x.value); }
      else if (x.type === 'domain') g.domain.push(x.value);
      else if (x.type === 'url') { g.url.push(x.value); var h = I.domainOf('url', x.value); if (h && !/^[\d.]+$/.test(h) && g.domain.indexOf(h) < 0) g.domain.push(h); }
      else if (g[x.type]) g[x.type].push(x.value);
    });
    Object.keys(g).forEach(function (k) { g[k] = g[k].filter(function (v, i, a) { return a.indexOf(v) === i; }); });
    return g;
  }

  // ---------------------------------------------------------------- query builders
  function kql(g, days) {
    var out = [], lb = 'let lookback = ' + days + 'd;\n';
    if (g.ip.length) out.push(['IP addresses', lb + 'let ips = dynamic([' + list(g.ip) + ']);\nunion isfuzzy=true\n' +
      '  (DeviceNetworkEvents | where Timestamp > ago(lookback) | where RemoteIP in (ips)\n     | project Timestamp, Source="DeviceNetworkEvents", DeviceName, Indicator=RemoteIP, RemoteUrl, InitiatingProcessFileName),\n' +
      '  (CommonSecurityLog | where TimeGenerated > ago(lookback) | where DestinationIP in (ips) or SourceIP in (ips)\n     | project Timestamp=TimeGenerated, Source="CommonSecurityLog", DeviceName=Computer, Indicator=iff(DestinationIP in (ips), DestinationIP, SourceIP), DeviceAction),\n' +
      '  (SigninLogs | where TimeGenerated > ago(lookback) | where IPAddress in (ips)\n     | project Timestamp=TimeGenerated, Source="SigninLogs", UserPrincipalName, Indicator=IPAddress, ResultType)\n| sort by Timestamp desc']);
    if (g.domain.length) out.push(['Domains', lb + 'let domains = dynamic([' + list(g.domain) + ']);\nunion isfuzzy=true\n' +
      '  (DeviceNetworkEvents | where Timestamp > ago(lookback) | where RemoteUrl has_any (domains)\n     | project Timestamp, Source="DeviceNetworkEvents", DeviceName, Indicator=RemoteUrl, InitiatingProcessFileName),\n' +
      '  (DeviceEvents | where Timestamp > ago(lookback) | where ActionType == "DnsQueryResponse"\n     | extend Query = tostring(parse_json(AdditionalFields).DnsQueryString) | where Query has_any (domains)\n     | project Timestamp, Source="DeviceEvents (DNS)", DeviceName, Indicator=Query, InitiatingProcessFileName),\n' +
      '  (EmailUrlInfo | where Timestamp > ago(lookback) | where UrlDomain in~ (domains)\n     | project Timestamp, Source="EmailUrlInfo", NetworkMessageId, Indicator=Url),\n' +
      '  (UrlClickEvents | where Timestamp > ago(lookback) | where Url has_any (domains)\n     | project Timestamp, Source="UrlClickEvents", AccountUpn, Indicator=Url, ActionType),\n' +
      '  (DnsEvents | where TimeGenerated > ago(lookback) | where Name has_any (domains)\n     | project Timestamp=TimeGenerated, Source="DnsEvents", DeviceName=Computer, Indicator=Name)\n| sort by Timestamp desc']);
    if (g.url.length) out.push(['URLs', lb + 'let urls = dynamic([' + list(g.url) + ']);\nunion isfuzzy=true\n' +
      '  (EmailUrlInfo | where Timestamp > ago(lookback) | where Url in~ (urls)\n     | project Timestamp, Source="EmailUrlInfo", NetworkMessageId, Indicator=Url),\n' +
      '  (UrlClickEvents | where Timestamp > ago(lookback) | where Url in~ (urls)\n     | project Timestamp, Source="UrlClickEvents", AccountUpn, Indicator=Url, ActionType, IsClickedThrough)\n| sort by Timestamp desc']);
    if (g.sha256.length || g.sha1.length || g.md5.length) out.push(['File hashes', lb +
      'let sha256s = dynamic([' + list(g.sha256) + ']);\nlet sha1s = dynamic([' + list(g.sha1) + ']);\nlet md5s = dynamic([' + list(g.md5) + ']);\nunion isfuzzy=true\n' +
      '  (DeviceFileEvents | where Timestamp > ago(lookback) | where SHA256 in (sha256s) or SHA1 in (sha1s) or MD5 in (md5s)\n     | project Timestamp, Source="DeviceFileEvents", DeviceName, FileName, FolderPath, SHA256, ActionType),\n' +
      '  (DeviceProcessEvents | where Timestamp > ago(lookback) | where SHA256 in (sha256s) or SHA1 in (sha1s) or MD5 in (md5s)\n     | project Timestamp, Source="DeviceProcessEvents", DeviceName, FileName, FolderPath, SHA256, ProcessCommandLine),\n' +
      '  (EmailAttachmentInfo | where Timestamp > ago(lookback) | where SHA256 in (sha256s)\n     | project Timestamp, Source="EmailAttachmentInfo", RecipientEmailAddress, FileName, SHA256)\n| sort by Timestamp desc']);
    if (g.email.length) out.push(['Email senders', lb + 'let senders = dynamic([' + list(g.email) + ']);\nEmailEvents\n| where Timestamp > ago(lookback)\n' +
      '| where SenderFromAddress in~ (senders) or SenderMailFromAddress in~ (senders)\n| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject, DeliveryAction, NetworkMessageId\n| sort by Timestamp desc']);
    return out;
  }

  function spl(g, days) {
    var out = [], e = 'index=* earliest=-' + days + 'd ';
    var stats = '\n| stats count min(_time) as first_seen max(_time) as last_seen by index, sourcetype, host\n| convert ctime(first_seen) ctime(last_seen)';
    if (g.ip.length) {
      var L = list(g.ip);
      out.push(['IP addresses (raw search)', e + '(src_ip IN (' + L + ') OR dest_ip IN (' + L + ') OR src IN (' + L + ') OR dest IN (' + L + ') OR clientip IN (' + L + '))' + stats]);
      out.push(['IP addresses (CIM Network_Traffic, faster)', '| tstats summariesonly=false count min(_time) as first_seen max(_time) as last_seen from datamodel=Network_Traffic\n  where earliest=-' + days + 'd (' +
        g.ip.map(function (v) { return 'All_Traffic.src_ip=' + q(v) + ' OR All_Traffic.dest_ip=' + q(v); }).join(' OR ') + ')\n  by All_Traffic.src_ip All_Traffic.dest_ip All_Traffic.dest_port\n| convert ctime(first_seen) ctime(last_seen)']);
    }
    if (g.domain.length) {
      var D = list(g.domain), W = g.domain.map(function (d) { return q('*' + d + '*'); }).join(', ');
      out.push(['Domains', e + '(query IN (' + D + ') OR domain IN (' + D + ') OR dest IN (' + D + ') OR url IN (' + W + '))' + stats]);
    }
    if (g.url.length) out.push(['URLs', e + 'url IN (' + list(g.url) + ')' + stats]);
    var H = g.sha256.concat(g.sha1, g.md5);
    if (H.length) { var HL = list(H); out.push(['File hashes', e + '(file_hash IN (' + HL + ') OR sha256 IN (' + HL + ') OR sha1 IN (' + HL + ') OR md5 IN (' + HL + ') OR hash IN (' + HL + '))' + stats]); }
    if (g.email.length) { var EL = list(g.email); out.push(['Email senders', e + '(src_user IN (' + EL + ') OR sender IN (' + EL + ') OR from IN (' + EL + '))' + stats]); }
    return out;
  }

  function logscale(g) {
    var out = [];
    var v = function (vals) { return '[' + list(vals) + ']'; };
    var v4 = g.ip.filter(function (x) { return x.indexOf(':') < 0; }), v6 = g.ip.filter(function (x) { return x.indexOf(':') >= 0; });
    if (v4.length) out.push(['IPv4 connections', '#event_simpleName=NetworkConnectIP4\n| in(field="RemoteAddressIP4", values=' + v(v4) + ')\n| groupBy([aid, RemoteAddressIP4, RemotePort], function=[count(), min(@timestamp, as=first_seen), max(@timestamp, as=last_seen)])']);
    if (v6.length) out.push(['IPv6 connections', '#event_simpleName=NetworkConnectIP6\n| in(field="RemoteAddressIP6", values=' + v(v6) + ')\n| groupBy([aid, RemoteAddressIP6, RemotePort], function=count())']);
    if (g.domain.length) out.push(['DNS requests', '#event_simpleName=DnsRequest\n| in(field="DomainName", values=' + v(g.domain) + ', ignoreCase=true)\n| groupBy([aid, DomainName], function=[count(), min(@timestamp, as=first_seen), max(@timestamp, as=last_seen)])']);
    if (g.sha256.length) out.push(['Processes by SHA-256', '#event_simpleName=ProcessRollup2\n| in(field="SHA256HashData", values=' + v(g.sha256) + ')\n| groupBy([aid, FileName, SHA256HashData], function=count())']);
    if (g.md5.length) out.push(['Processes by MD5', '#event_simpleName=ProcessRollup2\n| in(field="MD5HashData", values=' + v(g.md5) + ')\n| groupBy([aid, FileName, MD5HashData], function=count())']);
    return out;
  }

  function elastic(g) {
    var out = [];
    var p = function (vals) { return '(' + orList(vals) + ')'; };
    if (g.ip.length) out.push(['IP addresses', 'source.ip : ' + p(g.ip) + ' or destination.ip : ' + p(g.ip)]);
    if (g.domain.length) out.push(['Domains', 'dns.question.name : ' + p(g.domain) + ' or url.domain : ' + p(g.domain) + ' or destination.domain : ' + p(g.domain)]);
    if (g.url.length) out.push(['URLs', 'url.full : ' + p(g.url)]);
    var H = g.sha256.concat(g.sha1, g.md5);
    if (H.length) out.push(['File hashes', 'file.hash.sha256 : ' + p(H) + ' or file.hash.sha1 : ' + p(H) + ' or file.hash.md5 : ' + p(H) + ' or process.hash.sha256 : ' + p(H)]);
    if (g.email.length) out.push(['Email senders', 'email.from.address : ' + p(g.email)]);
    return out;
  }

  var PLATFORMS = [
    ['kql', 'Microsoft Sentinel / Defender XDR (KQL)', 'Advanced hunting or a Log Analytics workspace. Tables you don\'t have are skipped (isfuzzy=true).'],
    ['spl', 'Splunk (SPL)', 'Field names follow the Splunk CIM; adjust the index if you don\'t search index=*.'],
    ['logscale', 'CrowdStrike Falcon (LogScale / Next-Gen SIEM)', 'Event search over Falcon sensor telemetry.'],
    ['elastic', 'Elastic / Kibana (KQL, ECS fields)', 'Paste into the Discover or Security search bar.']
  ];

  function analyze() {
    var text = $('input').value, days = Number($('opt-days').value) || 30;
    var g = collect(text);
    var total = Object.keys(g).reduce(function (a, k) { return a + g[k].length; }, 0);
    if (!total) { $('out').innerHTML = '<p class="empty">' + (text.trim() ? 'No indicators found. Paste IPs, domains, URLs, hashes or email addresses.' : 'Paste indicators and press Generate.') + '</p>'; $('note').disabled = true; last = null; return; }
    var built = { kql: kql(g, days), spl: spl(g, days), logscale: logscale(g), elastic: elastic(g) };
    last = { g: g, built: built, days: days };
    var C = window.OVCharts;
    var html = '<div class="stats">' + [['ip', 'IPs'], ['domain', 'domains'], ['url', 'URLs'], ['sha256', 'SHA-256'], ['sha1', 'SHA-1'], ['md5', 'MD5'], ['email', 'emails']]
      .filter(function (k) { return g[k[0]].length; }).map(function (k) { return '<div class="stat"><b>' + g[k[0]].length + '</b><span>' + k[1] + '</span></div>'; }).join('') + '</div>';
    html += OV.nextSteps([
      'Run the query for your platform over the last ' + days + ' days. No rows is a good result, not an error.',
      'Any hit: note the device or account, then widen the search around that time on the same host.',
      total > 300 ? 'Long lists slow queries down. In Sentinel, put them in a watchlist and join on it instead.' : 'For a verdict on each indicator, use the lookup buttons in the IOC Extractor.'
    ]);
    html += PLATFORMS.map(function (pf) {
      var qs = built[pf[0]];
      if (!qs.length) return '';
      return '<div class="viz"><h3>' + OV.esc(pf[1]) + '</h3><p class="sub" style="margin:-4px 0 10px;font-size:.8rem;max-width:none">' + OV.esc(pf[2]) + '</p>' +
        qs.map(function (x, k) {
          return '<div class="q-block"><div class="q-h"><b>' + OV.esc(x[0]) + '</b><button class="copy" type="button" data-p="' + pf[0] + '" data-i="' + k + '">Copy query</button></div><pre class="q">' + OV.esc(x[1]) + '</pre></div>';
        }).join('') + '</div>';
    }).join('');
    $('out').innerHTML = html;
    $('note').disabled = false;
  }

  function allText() {
    var t = ['Hunting queries (OpsVantage Hunting Query Generator), lookback ' + last.days + ' days', ''];
    PLATFORMS.forEach(function (pf) {
      if (!last.built[pf[0]].length) return;
      t.push('===== ' + pf[1] + ' =====');
      last.built[pf[0]].forEach(function (x) { t.push('-- ' + x[0], x[1], ''); });
    });
    return t.join('\n');
  }

  $('analyze').addEventListener('click', analyze);
  $('sample').addEventListener('click', function () { $('input').value = SAMPLE; analyze(); });
  $('clear').addEventListener('click', function () { $('input').value = ''; analyze(); $('input').focus(); });
  $('opt-days').addEventListener('change', function () { if (last) analyze(); });
  $('opt-private').addEventListener('change', function () { if (last) analyze(); });
  $('note').addEventListener('click', function () { if (last) OV.copy(allText(), 'All queries copied'); });
  $('out').addEventListener('click', function (e) {
    var b = e.target.closest('.copy[data-p]');
    if (b && last) OV.copy(last.built[b.dataset.p][Number(b.dataset.i)][1], 'Query copied');
  });
  $('input').addEventListener('paste', function () { setTimeout(analyze, 0); });
  OV.ctrlEnter($('input'), analyze);
  var handed = OV.takeHandoff();
  if (handed) { $('input').value = handed; analyze(); }
})();
