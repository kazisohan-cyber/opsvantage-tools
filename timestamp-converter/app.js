// Timestamp Converter: detects and converts the timestamp formats analysts meet in logs and forensics (Unix epoch in
// s/ms/us/ns, Windows FILETIME and LDAP/AD 18-digit values, hex FILETIME, Chrome/WebKit, Mac absolute, Excel/OLE,
// date strings). BigInt keeps 18- and 19-digit values exact. Everything runs in the page.
(function () {
  'use strict';
  var OV = window.OV;
  var $ = function (id) { return document.getElementById(id); };
  var last = [];

  var EPOCH_1601_MS = 11644473600000n;      // ms between 1601-01-01 and 1970-01-01
  var EPOCH_2001_MS = 978307200000n;         // Mac absolute time starts 2001-01-01
  var EXCEL_EPOCH_MS = -2209161600000;       // 1899-12-30, the OLE / Excel day 0
  var MIN = Date.UTC(1980, 0, 1), MAX = Date.UTC(2100, 0, 1);
  var AD_NEVER = 9223372036854775807n;

  // Every way to read a BigInt as a time; each returns ms since 1970 as a BigInt.
  var INT_FORMATS = [
    ['Unix epoch, seconds', function (n) { return n * 1000n; }],
    ['Unix epoch, milliseconds', function (n) { return n; }],
    ['Unix epoch, microseconds', function (n) { return n / 1000n; }],
    ['Unix epoch, nanoseconds', function (n) { return n / 1000000n; }],
    ['Windows FILETIME / LDAP (100 ns since 1601)', function (n) { return n / 10000n - EPOCH_1601_MS; }],
    ['Chrome / WebKit (microseconds since 1601)', function (n) { return n / 1000n - EPOCH_1601_MS; }],
    ['Mac absolute time (seconds since 2001)', function (n) { return n * 1000n + EPOCH_2001_MS; }]
  ];

  function fromBig(n, label) {
    if (n === 0n) return [{ fmt: 'Zero', special: 'Not set. In Active Directory, lastLogon 0 means never logged on; accountExpires 0 means the account never expires.' }];
    if (n === AD_NEVER) return [{ fmt: 'Active Directory "never"', special: '9223372036854775807 (0x7FFFFFFFFFFFFFFF) is how accountExpires says the account never expires.' }];
    var out = [];
    INT_FORMATS.forEach(function (f) {
      var ms = f[1](n);
      if (ms >= BigInt(MIN) && ms <= BigInt(MAX)) out.push({ fmt: f[0] + (label || ''), ms: Number(ms) });
    });
    return out;
  }

  function hexReadings(h) {
    var out = [];
    var be = BigInt('0x' + h);
    var le = BigInt('0x' + (h.match(/../g) || []).reverse().join(''));
    if (h.length === 16) {
      fromBig(be).forEach(function (r) { if (/FILETIME/.test(r.fmt)) out.push({ fmt: 'Windows FILETIME, hex', ms: r.ms }); });
      if (le !== be) fromBig(le).forEach(function (r) { if (/FILETIME/.test(r.fmt)) out.push({ fmt: 'Windows FILETIME, hex bytes in little-endian order (registry, raw disk)', ms: r.ms }); });
    } else if (h.length <= 8) {
      [[be, 'Unix epoch seconds, hex'], [le, 'Unix epoch seconds, hex bytes little-endian']].forEach(function (x, i) {
        if (i && le === be) return;
        var ms = Number(x[0]) * 1000;
        if (ms >= MIN && ms <= MAX) out.push({ fmt: x[1], ms: ms });
      });
    } else {
      fromBig(be).forEach(function (r) { out.push({ fmt: r.fmt + ', from hex', ms: r.ms }); });
    }
    return out;
  }

  function parse(raw) {
    var s = raw.trim().replace(/^["']|["']$/g, '');
    var m;
    if (!s) return null;
    // FILETIME written as two 32-bit halves: 0x01DB5A2F:0x3C8E4000 or 01DB5A2F 3C8E4000
    if ((m = s.match(/^(?:0x)?([0-9a-f]{1,8})\s*[:\s]\s*(?:0x)?([0-9a-f]{1,8})$/i))) return { raw: s, r: hexReadings(m[1].padStart(8, '0') + m[2].padStart(8, '0')) };
    if ((m = s.match(/^0x([0-9a-f]{1,16})$/i)) || (/[a-f]/i.test(s) && (m = s.match(/^([0-9a-f]{16}|[0-9a-f]{8})$/i)))) return { raw: s, r: hexReadings(m[1].length > 8 ? m[1].padStart(16, '0') : m[1]) };
    if ((m = s.replace(/[\s,_]/g, '').match(/^(?:[0-9a-f]{2}[-\s]?){8}$/i)) && /[\s-]/.test(s)) return { raw: s, r: hexReadings(s.replace(/[^0-9a-f]/gi, '')) };
    if (/^-?\d{1,19}$/.test(s.replace(/[,_]/g, ''))) {
      var n = BigInt(s.replace(/[,_]/g, ''));
      return { raw: s, r: n < 0n ? [] : fromBig(n) };
    }
    if (/^\d+\.\d+$/.test(s)) {
      var f = parseFloat(s), r = [];
      [['Unix epoch, seconds with fraction', f * 1000], ['Mac absolute time (seconds since 2001)', f * 1000 + Number(EPOCH_2001_MS)], ['Excel / OLE date (days since 1899-12-30)', EXCEL_EPOCH_MS + f * 86400000]].forEach(function (x) {
        if (x[1] >= MIN && x[1] <= MAX) r.push({ fmt: x[0], ms: Math.round(x[1]) });
      });
      return { raw: s, r: r };
    }
    // Date strings. A bare "2026-11-16 08:30:00" has no zone: treat it as UTC, which is what most logs mean.
    var iso = s.replace(/^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?)$/, '$1T$2Z');
    var t = Date.parse(iso);
    if (!isNaN(t)) return { raw: s, r: [{ fmt: 'Date string' + (iso !== s ? ' (no time zone given, read as UTC)' : ''), ms: t, fromText: true }] };
    return { raw: s, r: [] };
  }

  // Rank: closest to now first, so the most plausible reading of an ambiguous number comes first.
  function rank(r) { var now = Date.now(); return r.slice().sort(function (a, b) { return (a.special ? 0 : Math.abs(a.ms - now)) - (b.special ? 0 : Math.abs(b.ms - now)); }); }

  function isoUtc(ms) { return new Date(ms).toISOString().replace('.000Z', 'Z'); }
  function inZone(ms, tz) {
    try { return new Intl.DateTimeFormat('en-GB', { timeZone: tz, year: 'numeric', month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false, timeZoneName: 'short' }).format(new Date(ms)); }
    catch (e) { return ''; }
  }
  function rel(ms) {
    var d = (ms - Date.now()) / 1000, a = Math.abs(d), u;
    u = a < 90 ? [Math.round(a), 'second'] : a < 5400 ? [Math.round(a / 60), 'minute'] : a < 129600 ? [Math.round(a / 3600), 'hour'] : a < 5184000 ? [Math.round(a / 86400), 'day'] : a < 63072000 ? [Math.round(a / 2592000), 'month'] : [Math.round(a / 31557600), 'year'];
    var s = u[0] + ' ' + u[1] + (u[0] === 1 ? '' : 's');
    return d < 0 ? s + ' ago' : 'in ' + s;
  }
  function allFormats(ms) {
    var b = BigInt(ms), ft = (b + EPOCH_1601_MS) * 10000n;
    return [
      ['ISO 8601 (UTC)', new Date(ms).toISOString()],
      ['Unix seconds', String(Math.floor(ms / 1000))],
      ['Unix milliseconds', String(ms)],
      ['LDAP / FILETIME', ft.toString()],
      ['FILETIME hex', '0x' + ft.toString(16).toUpperCase().padStart(16, '0')],
      ['Chrome / WebKit', ((b + EPOCH_1601_MS) * 1000n).toString()],
      ['Mac absolute', String((ms - Number(EPOCH_2001_MS)) / 1000)],
      ['Excel / OLE date', ((ms - EXCEL_EPOCH_MS) / 86400000).toFixed(6)]
    ];
  }

  function analyze() {
    var lines = $('input').value.split(/\r?\n/).map(function (l) { return l.trim(); }).filter(Boolean).slice(0, 50);
    var tz = $('opt-tz').value, local = Intl.DateTimeFormat().resolvedOptions().timeZone;
    last = [];
    if (!lines.length) { $('out').innerHTML = '<p class="empty">Paste one or more timestamps and press Convert.</p>'; $('note').disabled = true; return; }
    var html = '';
    lines.forEach(function (line) {
      var p = parse(line);
      if (!p) return;
      p.r = rank(p.r);
      last.push(p);
      html += '<div class="finding" style="margin-top:12px"><h3 style="font-family:var(--display);font-size:1rem;margin:0 0 6px;word-break:break-all"><span class="mono">' + OV.esc(p.raw) + '</span></h3>';
      if (!p.r.length) { html += '<p class="sub" style="margin:0">Not a timestamp this tool recognises, or it falls outside 1980 to 2100.</p></div>'; return; }
      p.r.forEach(function (r, i) {
        if (r.special) { html += '<p style="margin:4px 0"><b>' + OV.esc(r.fmt) + '</b></p><ul class="reasons"><li>' + OV.esc(r.special) + '</li></ul>'; return; }
        if (i === 0) {
          html += '<p style="margin:4px 0"><b>' + OV.esc(isoUtc(r.ms)) + '</b> <span class="sub" style="font-size:.85rem">' + OV.esc(rel(r.ms)) + '</span></p>';
          html += '<p class="sub" style="margin:2px 0 8px;font-size:.85rem">' + (r.fromText ? '' : 'Read as ' + OV.esc(r.fmt) + (p.r.length > 1 ? ' (most likely)' : '') + '. ') + 'Your time: ' + OV.esc(inZone(r.ms, local)) + (tz && tz !== local ? ' · ' + OV.esc(inZone(r.ms, tz)) : '') + '</p>';
          html += '<div class="table-wrap"><table class="data"><tbody>' + allFormats(r.ms).map(function (f) { return '<tr><td>' + OV.esc(f[0]) + '</td><td class="mono" style="word-break:break-all">' + OV.esc(f[1]) + '</td></tr>'; }).join('') + '</tbody></table></div>';
        } else {
          if (i === 1) html += '<p class="sub" style="margin:10px 0 4px;font-size:.85rem">Other possible readings:</p><ul class="reasons">';
          html += '<li>' + OV.esc(r.fmt) + ': <span class="mono">' + OV.esc(isoUtc(r.ms)) + '</span></li>';
          if (i === p.r.length - 1) html += '</ul>';
        }
      });
      html += '</div>';
    });
    var ok = last.filter(function (p) { return p.r.length; }).length;
    $('out').innerHTML = '<div class="verdict ' + (ok === last.length ? 'good' : 'warn') + '"><div><div class="v">' + ok + '/' + last.length + ' converted</div><div class="sub" style="margin:2px 0 0">Times are shown in UTC first. Ambiguous numbers list every plausible reading.</div></div></div>' + html;
    $('note').disabled = !ok;
  }

  function note() {
    var t = ['Timestamps (OpsVantage Timestamp Converter)'];
    last.forEach(function (p) {
      if (!p.r.length) { t.push(p.raw + ': not recognised'); return; }
      var r = p.r[0];
      t.push(p.raw + ' = ' + (r.special ? r.fmt : isoUtc(r.ms) + ' (' + r.fmt + ')'));
    });
    return t.join('\n');
  }

  // Time zone list: the browser's own list when it has one.
  (function () {
    var sel = $('opt-tz'), zones = ['UTC', 'America/New_York', 'America/Chicago', 'America/Los_Angeles', 'Europe/London', 'Europe/Berlin', 'Asia/Dubai', 'Asia/Kolkata', 'Asia/Dhaka', 'Asia/Singapore', 'Asia/Kuala_Lumpur', 'Asia/Tokyo', 'Australia/Sydney'];
    try { if (Intl.supportedValuesOf) zones = Intl.supportedValuesOf('timeZone'); } catch (e) {}
    sel.innerHTML = '<option value="">No other zone</option>' + zones.map(function (z) { return '<option>' + OV.esc(z) + '</option>'; }).join('');
    sel.addEventListener('change', function () { if (last.length) analyze(); });
  })();

  function sample() {
    var now = Date.now() - 3 * 3600000, b = BigInt(now);
    var ft = (b + EPOCH_1601_MS) * 10000n;
    return [String(Math.floor(now / 1000)), ft.toString(), '0x' + ((b - 86400000n * 30n + EPOCH_1601_MS) * 10000n).toString(16).toUpperCase().padStart(16, '0'),
      ((b - 86400000n * 2n + EPOCH_1601_MS) * 1000n).toString(), '9223372036854775807', '2026-11-16 08:30:00'].join('\n');
  }

  $('analyze').addEventListener('click', analyze);
  $('sample').addEventListener('click', function () { $('input').value = sample(); analyze(); });
  $('clear').addEventListener('click', function () { $('input').value = ''; analyze(); $('input').focus(); });
  $('note').addEventListener('click', function () { if (last.length) OV.copy(note(), 'Results copied'); });
  $('input').addEventListener('paste', function () { setTimeout(analyze, 0); });
  OV.ctrlEnter($('input'), analyze);
  var handed = OV.takeHandoff();
  if (handed) { $('input').value = handed; analyze(); }
})();
