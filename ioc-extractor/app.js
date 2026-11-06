// IOC Extractor: groups VSIoc.extract() results and renders them. Everything stays in the page.
(function () {
  'use strict';
  var I = window.VSIoc, OV = window.OV;
  var $ = function (id) { return document.getElementById(id); };

  var GROUPS = [
    { key: 'url', label: 'URLs', types: ['url'] },
    { key: 'domain', label: 'Domains', types: ['domain'] },
    { key: 'ip', label: 'IP addresses', types: ['ipv4', 'ipv6'] },
    { key: 'email', label: 'Email addresses', types: ['email'] },
    { key: 'hash', label: 'File hashes', types: ['sha256', 'sha1', 'md5'] },
    { key: 'cve', label: 'CVEs', types: ['cve'] },
    { key: 'file', label: 'File names', types: ['filename'] },
    { key: 'registry', label: 'Registry keys', types: ['registry'] },
    { key: 'asn', label: 'ASNs', types: ['asn'] },
    { key: 'crypto', label: 'Bitcoin addresses', types: ['btc'] }
  ];

  var SAMPLE = [
    'Incident summary: user reported a phishing email from billing@micros0ft-support[.]com.',
    'The link pointed to hxxps://login-micros0ft-support[.]com/owa/auth.php?id=8842 which served a fake Microsoft 365 page.',
    'Payload dropped from http://185.220.101[.]45:8080/inv.exe',
    'SHA256: 4f5d3c2b1a0e9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c',
    'MD5: 44d88612fea8a8f36de82e1278abb02f',
    'C2 beacons seen to 45.137.21.9 and update-cdn-sync.xyz every 60s.',
    'Internal host 10.20.4.17 (FIN-LT-042) contacted the C2. Exploited CVE-2024-21412.',
    'Persistence: C:\\Users\\Public\\svchost.exe added under HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater.',
    'Ransom note asks for payment to bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq. C2 hosting is in AS9009.',
    'Log field event.type=network is not an indicator.'
  ].join('\n');

  var state = { fmt: 'defang', items: [] };

  function scan() {
    var text = $('input').value;
    var opts = { strict: $('opt-strict').checked, max: 5000 };
    var found = I.extract(text, opts);
    var seen = new Set(), items = [];
    function push(type, value, from) {
      var k = type + '|' + value;
      if (seen.has(k)) return;
      seen.add(k);
      items.push({ type: type, group: I.GROUP[type], value: value, from: from || '' });
    }
    found.forEach(function (x) {
      if ((x.type === 'ipv4' || x.type === 'ipv6') && !$('opt-private').checked && I.isPrivateIp(x.value)) return;
      push(x.type, x.value);
      if ($('opt-urldomains').checked && x.type === 'url') {
        var host = I.domainOf('url', x.value);
        if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) {
          if ($('opt-private').checked || !I.isPrivateIp(host)) push('ipv4', host, 'from URL');
        } else if (host && host.indexOf(':') < 0 && host.charAt(0) !== '[') push('domain', host, 'from URL');
      }
    });
    state.items = items;
    render();
  }

  function shown(item) {
    return state.fmt === 'defang' ? I.defang(item.value, item.type) : item.value;
  }

  function render() {
    var items = state.items, out = $('out');
    var has = items.length > 0;
    ['copy-all', 'csv', 'defang-text'].forEach(function (id) { $(id).disabled = !has; });
    $('stats').innerHTML = has ? GROUPS.map(function (g) {
      var n = items.filter(function (x) { return x.group === g.key; }).length;
      return n ? '<div class="stat"><b>' + n + '</b><span>' + g.label + '</span></div>' : '';
    }).join('') : '';
    if (!has) {
      out.innerHTML = '<p class="empty">' + ($('input').value.trim() ? 'No indicators found in this text.' : 'Indicators will appear here as you paste.') + '</p>';
      return;
    }
    out.innerHTML = GROUPS.map(function (g) {
      var list = items.filter(function (x) { return x.group === g.key; });
      if (!list.length) return '';
      return '<div class="group"><div class="group-h"><span><b>' + g.label + '</b><span class="count">' + list.length +
        '</span></span><button class="copy" type="button" data-group="' + g.key + '">Copy ' + g.label.toLowerCase() + '</button></div>' +
        '<ul class="ioc-list">' + list.map(function (x) {
          var note = x.type !== 'url' && x.group === 'hash' ? I.LABEL_OF[x.type] : x.type === 'ipv6' ? 'IPv6' : x.from;
          return '<li><span class="ioc-v"><span>' + OV.esc(shown(x)) + (note ? ' <span class="sub">' + OV.esc(note) + '</span>' : '') +
            '</span>' + OV.pivots(x.type, x.value) + '</span><button class="copy" type="button" data-value="' + OV.esc(shown(x)) + '">Copy</button></li>';
        }).join('') + '</ul></div>';
    }).join('');
  }

  function groupText(key) {
    return state.items.filter(function (x) { return x.group === key; }).map(shown).join('\n');
  }

  function allText() {
    return GROUPS.map(function (g) {
      var t = groupText(g.key);
      return t ? '# ' + g.label + '\n' + t : '';
    }).filter(Boolean).join('\n\n');
  }

  function defangedText() {
    var text = $('input').value;
    var found = I.extract(text, { strict: $('opt-strict').checked, max: 5000 });
    var out = '', pos = 0;
    found.forEach(function (x) {
      out += text.slice(pos, x.start) + I.defang(x.value, x.type);
      pos = x.end;
    });
    return out + text.slice(pos);
  }

  var timer;
  $('input').addEventListener('input', function () { clearTimeout(timer); timer = setTimeout(scan, 150); });
  ['opt-private', 'opt-urldomains', 'opt-strict'].forEach(function (id) { $(id).addEventListener('change', scan); });
  $('sample').addEventListener('click', function () { $('input').value = SAMPLE; scan(); });
  $('clear').addEventListener('click', function () { $('input').value = ''; scan(); $('input').focus(); });

  document.querySelector('.seg').addEventListener('click', function (e) {
    var b = e.target.closest('button[data-fmt]');
    if (!b) return;
    state.fmt = b.dataset.fmt;
    this.querySelectorAll('button').forEach(function (x) { x.setAttribute('aria-pressed', String(x === b)); });
    render();
  });

  $('out').addEventListener('click', function (e) {
    var b = e.target.closest('.copy');
    if (!b) return;
    if (b.dataset.group) OV.copy(groupText(b.dataset.group), 'List copied');
    else OV.copy(b.dataset.value, 'Copied');
  });
  $('copy-all').addEventListener('click', function () { OV.copy(allText(), 'All indicators copied'); });
  $('defang-text').addEventListener('click', function () { OV.copy(defangedText(), 'Defanged text copied'); });
  $('csv').addEventListener('click', function () {
    var rows = [['type', 'value', 'defanged', 'note']].concat(state.items.map(function (x) {
      return [I.LABEL_OF[x.type] || x.type, x.value, I.defang(x.value, x.type), x.from];
    }));
    OV.download('iocs.csv', rows.map(function (r) { return r.map(OV.csvCell).join(','); }).join('\r\n'), 'text/csv');
  });
})();
