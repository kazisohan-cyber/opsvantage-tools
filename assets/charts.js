// Small dependency-free SVG charts for the tool pages. Every chart returns an HTML string and uses
// CSS variables, so it follows the light and dark theme. No external scripts, nothing leaves the page.
(function () {
  'use strict';
  var esc = function (s) { return window.OV ? window.OV.esc(s) : String(s); };
  var SEV_COLOR = { crit: '#ef4444', high: '#f97316', med: '#E9A94A', low: '#60a5fa', info: '#94a3b8' };
  var round = function (n) { return Math.round(n * 10) / 10; };

  /** Ring gauge: value 0-100, big label in the middle (e.g. grade letter). */
  function gauge(value, label, color, size) {
    size = size || 132;
    var r = size / 2 - 10, c = 2 * Math.PI * r, v = Math.max(0, Math.min(100, value || 0));
    var col = color || (v >= 90 ? 'var(--live)' : v >= 60 ? 'var(--amber)' : '#ef4444');
    return '<svg class="ch-gauge" width="' + size + '" height="' + size + '" viewBox="0 0 ' + size + ' ' + size + '" role="img" aria-label="' + esc(label) + ' ' + v + ' out of 100">' +
      '<circle cx="' + size / 2 + '" cy="' + size / 2 + '" r="' + r + '" fill="none" stroke="var(--line-2)" stroke-width="10"/>' +
      '<circle cx="' + size / 2 + '" cy="' + size / 2 + '" r="' + r + '" fill="none" stroke="' + col + '" stroke-width="10" stroke-linecap="round" ' +
      'stroke-dasharray="' + round(c * v / 100) + ' ' + round(c) + '" transform="rotate(-90 ' + size / 2 + ' ' + size / 2 + ')"><animate attributeName="stroke-dasharray" from="0 ' + round(c) + '" to="' + round(c * v / 100) + ' ' + round(c) + '" dur=".8s" fill="freeze"/></circle>' +
      '<text x="50%" y="47%" text-anchor="middle" dominant-baseline="middle" class="ch-gauge-big" fill="' + col + '">' + esc(label) + '</text>' +
      '<text x="50%" y="70%" text-anchor="middle" class="ch-gauge-small">' + v + '/100</text></svg>';
  }

  /** Horizontal bars: [{label, value, color?, note?}] scaled to max. */
  function bars(items, opts) {
    opts = opts || {};
    var max = Math.max.apply(null, items.map(function (x) { return x.value; }).concat([opts.max || 0, 1]));
    return '<div class="ch-bars">' + items.map(function (x) {
      var w = Math.max(x.value ? 2 : 0, x.value / max * 100);
      return '<div class="ch-bar" title="' + esc(x.label + ': ' + (x.note || x.value)) + '"><span class="ch-bar-l">' + esc(x.label) + '</span>' +
        '<span class="ch-bar-t"><span class="ch-bar-f" style="width:' + round(w) + '%;background:' + (x.color || 'var(--pink)') + '"></span></span>' +
        '<span class="ch-bar-v">' + esc(x.note || x.value) + '</span></div>';
    }).join('') + '</div>';
  }

  /** Donut: [{label, value, color}], centre text. */
  function donut(items, centre, size) {
    size = size || 120;
    var total = items.reduce(function (a, x) { return a + x.value; }, 0) || 1;
    var r = size / 2 - 12, c = 2 * Math.PI * r, off = 0;
    var arcs = items.filter(function (x) { return x.value; }).map(function (x) {
      var len = c * x.value / total;
      var s = '<circle cx="' + size / 2 + '" cy="' + size / 2 + '" r="' + r + '" fill="none" stroke="' + x.color + '" stroke-width="14" stroke-dasharray="' + round(len) + ' ' + round(c - len) + '" stroke-dashoffset="' + round(-off) + '" transform="rotate(-90 ' + size / 2 + ' ' + size / 2 + ')"><title>' + esc(x.label + ': ' + x.value) + '</title></circle>';
      off += len;
      return s;
    }).join('');
    var legend = '<ul class="ch-legend">' + items.filter(function (x) { return x.value; }).map(function (x) {
      return '<li><i style="background:' + x.color + '"></i>' + esc(x.label) + ' <b>' + x.value + '</b></li>';
    }).join('') + '</ul>';
    return '<div class="ch-donut"><svg width="' + size + '" height="' + size + '" viewBox="0 0 ' + size + ' ' + size + '" role="img" aria-label="' + esc(centre) + '">' +
      '<circle cx="' + size / 2 + '" cy="' + size / 2 + '" r="' + r + '" fill="none" stroke="var(--line)" stroke-width="14"/>' + arcs +
      '<text x="50%" y="50%" text-anchor="middle" dominant-baseline="middle" class="ch-gauge-big" style="font-size:' + Math.round(size / 5) + 'px" fill="var(--text)">' + esc(centre) + '</text></svg>' + legend + '</div>';
  }

  /**
   * Activity timeline: points [{t (ms), sev, label}] bucketed into columns, stacked by severity,
   * plus optional markers [{t, sev, label}] drawn as flags above the bars.
   */
  function timeline(points, markers, opts) {
    opts = opts || {};
    var ts = points.map(function (p) { return p.t; }).filter(function (t) { return t != null; });
    if (ts.length < 2) return '';
    var t0 = Math.min.apply(null, ts), t1 = Math.max.apply(null, ts);
    if (t1 === t0) t1 = t0 + 60000;
    var W = 720, H = 150, pad = 26, cols = Math.min(60, Math.max(12, Math.round(ts.length / 2))), bw = (W - pad * 2) / cols;
    var order = ['info', 'low', 'med', 'high', 'crit'];
    var buckets = [];
    for (var i = 0; i < cols; i++) buckets.push({ info: 0, low: 0, med: 0, high: 0, crit: 0, n: 0 });
    var col = function (t) { return Math.min(cols - 1, Math.floor((t - t0) / (t1 - t0) * cols)); };
    points.forEach(function (p) { if (p.t == null) return; var b = buckets[col(p.t)]; b[p.sev || 'info']++; b.n++; });
    var max = Math.max.apply(null, buckets.map(function (b) { return b.n; }).concat([1]));
    var bh = H - pad - 30;
    var rects = buckets.map(function (b, i) {
      var y = H - pad, out = '';
      order.forEach(function (s) {
        if (!b[s]) return;
        var h = b[s] / max * bh;
        y -= h;
        out += '<rect x="' + round(pad + i * bw + 1) + '" y="' + round(y) + '" width="' + round(Math.max(1, bw - 2)) + '" height="' + round(h) + '" rx="1.5" fill="' + SEV_COLOR[s] + '"><title>' + b[s] + ' ' + s + '</title></rect>';
      });
      return out;
    }).join('');
    var fmt = opts.fmt || function (t) { return new Date(t).toLocaleString(); };
    var flags = (markers || []).filter(function (m) { return m.t != null; }).slice(0, 12).map(function (m) {
      var x = round(pad + (col(m.t) + 0.5) * bw);
      return '<g class="ch-flag"><line x1="' + x + '" x2="' + x + '" y1="14" y2="' + (H - pad) + '" stroke="' + SEV_COLOR[m.sev] + '" stroke-dasharray="3 3" stroke-width="1.2"/>' +
        '<circle cx="' + x + '" cy="12" r="5" fill="' + SEV_COLOR[m.sev] + '"><title>' + esc(fmt(m.t) + ' · ' + m.label) + '</title></circle></g>';
    }).join('');
    return '<div class="ch-wrap"><svg class="ch-timeline" viewBox="0 0 ' + W + ' ' + H + '" preserveAspectRatio="none" role="img" aria-label="Activity over time">' +
      '<line x1="' + pad + '" x2="' + (W - pad) + '" y1="' + (H - pad) + '" y2="' + (H - pad) + '" stroke="var(--line-2)"/>' + rects + flags + '</svg>' +
      '<div class="ch-axis"><span>' + esc(fmt(t0)) + '</span><span>' + esc(fmt(t1)) + '</span></div>' +
      '<div class="ch-legend-row">' + ['crit', 'high', 'med', 'low', 'info'].map(function (s) { return '<span><i style="background:' + SEV_COLOR[s] + '"></i>' + { crit: 'Critical', high: 'High', med: 'Medium', low: 'Low', info: 'Other' }[s] + '</span>'; }).join('') +
      (markers && markers.length ? '<span><i class="dot" style="background:var(--muted)"></i>Finding</span>' : '') + '</div></div>';
  }

  /** 7 x 24 heatmap: cells[day][hour] = {n, bad}. Days Mon..Sun. */
  function heatmap(cells, opts) {
    opts = opts || {};
    var max = 1;
    cells.forEach(function (row) { row.forEach(function (c) { if (c.n > max) max = c.n; }); });
    var days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
    var html = '<div class="ch-heat" role="img" aria-label="' + esc(opts.label || 'Activity by day and hour') + '"><div class="ch-heat-h"><span></span>';
    for (var h = 0; h < 24; h++) html += '<span>' + (h % 6 === 0 ? h : '') + '</span>';
    html += '</div>';
    cells.forEach(function (row, d) {
      html += '<div class="ch-heat-r"><span>' + days[d] + '</span>' + row.map(function (c, hr) {
        var a = c.n ? 0.18 + 0.82 * c.n / max : 0;
        var colr = c.bad && c.bad >= c.n / 2 ? '239,68,68' : '228,43,161';
        return '<i style="background:' + (c.n ? 'rgba(' + colr + ',' + round(a) + ')' : 'var(--line)') + '" title="' + days[d] + ' ' + hr + ':00 · ' + c.n + ' sign-in' + (c.n === 1 ? '' : 's') + (c.bad ? ', ' + c.bad + ' failed' : '') + '"></i>';
      }).join('') + '</div>';
    });
    return html + '<div class="ch-legend-row"><span><i style="background:rgba(228,43,161,.8)"></i>Mostly successful</span><span><i style="background:rgba(239,68,68,.8)"></i>Mostly failed</span><span>' + esc(opts.tz || 'UTC') + '</span></div></div>';
  }

  // MITRE ATT&CK tactics in kill-chain order, and the tactic each technique the rules emit belongs to.
  var TACTICS = [['TA0001', 'Initial Access'], ['TA0002', 'Execution'], ['TA0003', 'Persistence'], ['TA0004', 'Privilege Escalation'], ['TA0005', 'Defense Evasion'],
    ['TA0006', 'Credential Access'], ['TA0007', 'Discovery'], ['TA0008', 'Lateral Movement'], ['TA0011', 'Command and Control'], ['TA0040', 'Impact']];
  var TECH = {
    'T1078.004': ['TA0001', 'Cloud accounts'], 'T1078': ['TA0001', 'Valid accounts'],
    'T1059.001': ['TA0002', 'PowerShell'], 'T1053.005': ['TA0002', 'Scheduled task'], 'T1569.002': ['TA0002', 'Service execution'],
    'T1098': ['TA0003', 'Account manipulation'], 'T1136': ['TA0003', 'Create account'], 'T1136.001': ['TA0003', 'Local account'], 'T1543.003': ['TA0003', 'Windows service'],
    'T1134.005': ['TA0004', 'SID-History injection'],
    'T1070.001': ['TA0005', 'Clear Windows logs'], 'T1218': ['TA0005', 'Signed binary proxy'], 'T1562.001': ['TA0005', 'Disable tools'], 'T1562.002': ['TA0005', 'Disable event logging'], 'T1562.010': ['TA0005', 'Downgrade attack'],
    'T1003': ['TA0006', 'Credential dumping'], 'T1003.001': ['TA0006', 'LSASS memory'], 'T1003.006': ['TA0006', 'DCSync'], 'T1110': ['TA0006', 'Brute force'], 'T1110.001': ['TA0006', 'Password guessing'],
    'T1110.003': ['TA0006', 'Password spraying'], 'T1558.003': ['TA0006', 'Kerberoasting'], 'T1621': ['TA0006', 'MFA request flooding'], 'T1528': ['TA0006', 'Steal app token'],
    'T1021.001': ['TA0008', 'RDP'], 'T1021.002': ['TA0008', 'SMB admin shares'],
    'T1105': ['TA0011', 'Ingress tool transfer'],
    'T1490': ['TA0040', 'Inhibit system recovery']
  };
  /** Kill-chain strip: which tactics the findings touch, coloured by the worst severity in each. */
  function attackGrid(findings) {
    var by = {};
    var rank = { crit: 0, high: 1, med: 2, low: 3, info: 4 };
    findings.forEach(function (f) {
      var t = TECH[f.mitre] || TECH[String(f.mitre || '').split('.')[0]];
      if (!t) return;
      var b = by[t[0]] || (by[t[0]] = { sev: 'info', items: [] });
      if (rank[f.sev] < rank[b.sev]) b.sev = f.sev;
      if (b.items.indexOf(t[1]) < 0) b.items.push(t[1]);
    });
    var hit = Object.keys(by).length;
    if (!hit) return '';
    return '<div class="attack" role="list" aria-label="MITRE ATT&CK tactics seen">' + TACTICS.map(function (t) {
      var b = by[t[0]];
      return '<div class="att' + (b ? ' hit' : '') + '" role="listitem" style="' + (b ? '--c:' + SEV_COLOR[b.sev] : '') + '"><b>' + t[1] + '</b>' +
        (b ? '<span>' + b.items.map(esc).join('<br>') + '</span>' : '<span class="none">-</span>') + '</div>';
    }).join('') + '</div><p class="sub" style="font-size:.76rem;margin-top:6px">' + hit + ' of ' + TACTICS.length + ' attack stages seen, left to right in the order an intrusion usually unfolds.</p>';
  }

  /**
   * Dot world map (needs assets/lib/world-dots.js). points: [{lat, lon, n, bad, label}], arcs: [{a:[lat,lon], b:[lat,lon], label}].
   * Equirectangular, so x = longitude + 180 and y = top latitude - latitude.
   */
  function worldMap(points, arcs) {
    var W = window.OV_WORLD;
    if (!W) return '';
    var H = W.rows.length * W.step;
    var dots = '';
    W.rows.forEach(function (row, r) {
      for (var i = 0; i < row.length; i += 2) {
        var c = parseInt(row.substr(i, 2), 36);
        dots += 'M' + round((c + 0.5) * W.step) + ' ' + round((r + 0.5) * W.step) + 'h0';
      }
    });
    var xy = function (lat, lon) { return [round(lon + 180), round(W.latTop - lat + W.step / 2)]; };
    var max = Math.max.apply(null, points.map(function (p) { return p.n; }).concat([1]));
    var arcSvg = (arcs || []).map(function (a) {
      var p = xy(a.a[0], a.a[1]), q = xy(a.b[0], a.b[1]);
      var mx = (p[0] + q[0]) / 2, my = Math.min(p[1], q[1]) - Math.max(8, Math.abs(p[0] - q[0]) / 4);
      return '<path d="M' + p[0] + ' ' + p[1] + ' Q' + round(mx) + ' ' + round(my) + ' ' + q[0] + ' ' + q[1] + '" fill="none" stroke="#ef4444" stroke-width="1" stroke-dasharray="3 2" class="ch-arc"><title>' + esc(a.label) + '</title></path>';
    }).join('');
    var pts = points.map(function (p) {
      var c = xy(p.lat, p.lon), r = round(1.6 + 4.5 * Math.sqrt(p.n / max));
      var col = p.bad && p.bad >= p.n / 2 ? '#ef4444' : 'var(--pink)';
      return '<g><circle cx="' + c[0] + '" cy="' + c[1] + '" r="' + round(r * 1.9) + '" fill="' + col + '" opacity=".18"/><circle cx="' + c[0] + '" cy="' + c[1] + '" r="' + r + '" fill="' + col + '" stroke="var(--bg)" stroke-width=".5"><title>' + esc(p.label) + '</title></circle></g>';
    }).join('');
    return '<div class="ch-map"><svg viewBox="0 0 360 ' + H + '" role="img" aria-label="Sign-in locations on a world map">' +
      '<path d="' + dots + '" stroke="var(--muted-2)" stroke-opacity=".45" stroke-width="1.25" stroke-linecap="round"/>' + arcSvg + pts + '</svg>' +
      '<div class="ch-legend-row"><span><i class="dot" style="background:var(--pink)"></i>Mostly successful</span><span><i class="dot" style="background:#ef4444"></i>Mostly failed</span>' +
      (arcs && arcs.length ? '<span><i style="background:#ef4444;height:2px;width:14px;vertical-align:3px"></i>Impossible travel</span>' : '') + '<span>Circle size = number of sign-ins</span></div></div>';
  }

  /**
   * Scatter: points [{x, y, label, color}] with x 0..xMax and y 0..1 (shown as %). Optional quadrant lines.
   * Used for CVSS (x) against exploit probability (y).
   */
  function scatter(points, opts) {
    opts = opts || {};
    var W = 640, H = 300, L = 46, B = 34, T = 12, R = 14, xMax = opts.xMax || 10;
    var px = function (x) { return round(L + (W - L - R) * Math.max(0, Math.min(xMax, x)) / xMax); };
    var py = function (y) { return round(T + (H - T - B) * (1 - Math.max(0, Math.min(1, y)))); };
    var grid = '';
    for (var gx = 0; gx <= xMax; gx += 2) grid += '<line x1="' + px(gx) + '" x2="' + px(gx) + '" y1="' + T + '" y2="' + (H - B) + '" stroke="var(--line)"/><text x="' + px(gx) + '" y="' + (H - B + 16) + '" text-anchor="middle" class="ch-ax">' + gx + '</text>';
    [0, .25, .5, .75, 1].forEach(function (gy) { grid += '<line x1="' + L + '" x2="' + (W - R) + '" y1="' + py(gy) + '" y2="' + py(gy) + '" stroke="var(--line)"/><text x="' + (L - 6) + '" y="' + (py(gy) + 4) + '" text-anchor="end" class="ch-ax">' + Math.round(gy * 100) + '%</text>'; });
    var q = '';
    if (opts.qx != null) q += '<line x1="' + px(opts.qx) + '" x2="' + px(opts.qx) + '" y1="' + T + '" y2="' + (H - B) + '" stroke="var(--muted-2)" stroke-dasharray="4 4"/>';
    if (opts.qy != null) q += '<line x1="' + L + '" x2="' + (W - R) + '" y1="' + py(opts.qy) + '" y2="' + py(opts.qy) + '" stroke="var(--muted-2)" stroke-dasharray="4 4"/>';
    var dots = points.map(function (p) {
      return '<circle cx="' + px(p.x) + '" cy="' + py(p.y) + '" r="' + (p.r || 6) + '" fill="' + (p.color || 'var(--pink)') + '" fill-opacity=".85" stroke="var(--bg)" stroke-width="1.5"><title>' + esc(p.label) + '</title></circle>';
    }).join('');
    return '<div class="ch-wrap"><svg viewBox="0 0 ' + W + ' ' + H + '" style="width:100%;height:auto" role="img" aria-label="' + esc(opts.label || 'Scatter chart') + '">' + grid + q + dots +
      '<text x="' + ((L + W - R) / 2) + '" y="' + (H - 2) + '" text-anchor="middle" class="ch-ax">' + esc(opts.xLabel || '') + '</text>' +
      '<text x="12" y="' + ((T + H - B) / 2) + '" text-anchor="middle" class="ch-ax" transform="rotate(-90 12 ' + ((T + H - B) / 2) + ')">' + esc(opts.yLabel || '') + '</text></svg></div>';
  }

  window.OVCharts = { scatter: scatter, gauge: gauge, bars: bars, donut: donut, timeline: timeline, heatmap: heatmap, attackGrid: attackGrid, worldMap: worldMap, SEV_COLOR: SEV_COLOR };
})();
