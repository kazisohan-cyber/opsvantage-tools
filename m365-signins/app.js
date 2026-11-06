// M365 / Entra ID sign-in log analyzer. Parses CSV or JSON exports and applies account-takeover rules, all in the page.
(function () {
  'use strict';
  var OV = window.OV, I = window.VSIoc;
  var $ = function (id) { return document.getElementById(id); };
  var SEV_ORDER = { crit: 0, high: 1, med: 2, low: 3, info: 4 };
  var SEV_LABEL = { crit: 'Critical', high: 'High', med: 'Medium', low: 'Low', info: 'Info' };

  // Rough country positions (major population centre) for travel-speed estimates.
  var GEO = {
    US: [39.8, -98.6], CA: [45.4, -75.7], MX: [19.4, -99.1], BR: [-23.5, -46.6], AR: [-34.6, -58.4], CL: [-33.4, -70.6], CO: [4.7, -74.1], PE: [-12, -77],
    VE: [10.5, -66.9], GB: [51.5, -0.1], IE: [53.3, -6.3], FR: [48.9, 2.4], DE: [50.1, 8.7], NL: [52.4, 4.9], BE: [50.8, 4.4], LU: [49.6, 6.1], CH: [47.4, 8.5],
    AT: [48.2, 16.4], IT: [41.9, 12.5], ES: [40.4, -3.7], PT: [38.7, -9.1], SE: [59.3, 18.1], NO: [59.9, 10.8], FI: [60.2, 24.9], DK: [55.7, 12.6], PL: [52.2, 21],
    CZ: [50.1, 14.4], HU: [47.5, 19], RO: [44.4, 26.1], BG: [42.7, 23.3], GR: [38, 23.7], TR: [41, 29], UA: [50.5, 30.5], RU: [55.8, 37.6], BY: [53.9, 27.6],
    IL: [32.1, 34.8], AE: [25.2, 55.3], SA: [24.7, 46.7], QA: [25.3, 51.5], KW: [29.4, 48], BH: [26.2, 50.6], OM: [23.6, 58.4], IR: [35.7, 51.4], IQ: [33.3, 44.4],
    EG: [30, 31.2], NG: [6.5, 3.4], ZA: [-26.2, 28], KE: [-1.3, 36.8], MA: [33.6, -7.6], GH: [5.6, -0.2], IN: [19.1, 72.9], PK: [24.9, 67], BD: [23.8, 90.4],
    LK: [6.9, 79.9], NP: [27.7, 85.3], CN: [31.2, 121.5], HK: [22.3, 114.2], MO: [22.2, 113.5], TW: [25, 121.5], JP: [35.7, 139.7], KR: [37.6, 127], KP: [39, 125.8],
    SG: [1.35, 103.8], MY: [3.1, 101.7], ID: [-6.2, 106.8], TH: [13.8, 100.5], VN: [10.8, 106.7], PH: [14.6, 121], KH: [11.6, 104.9], MM: [16.9, 96.2], LA: [18, 102.6],
    BN: [4.9, 114.9], AU: [-33.9, 151.2], NZ: [-36.8, 174.8], KZ: [43.2, 76.9], UZ: [41.3, 69.2], GE: [41.7, 44.8], AM: [40.2, 44.5], AZ: [40.4, 49.9],
    RS: [44.8, 20.5], HR: [45.8, 16], SI: [46.1, 14.5], SK: [48.1, 17.1], LT: [54.7, 25.3], LV: [56.9, 24.1], EE: [59.4, 24.8], IS: [64.1, -21.9], CY: [35.2, 33.4],
    MT: [35.9, 14.5], JO: [31.9, 35.9], LB: [33.9, 35.5], PA: [9, -79.5], CR: [9.9, -84.1], DO: [18.5, -69.9], PR: [18.5, -66.1], EC: [-0.2, -78.5], UY: [-34.9, -56.2]
  };
  var ERRORS = {
    0: 'Success', 50126: 'Invalid username or password', 50053: 'Account locked (smart lockout) or blocked IP', 50057: 'Account disabled', 50055: 'Password expired',
    50034: 'User does not exist', 50074: 'MFA required (interrupt)', 50076: 'MFA required by policy (interrupt)', 500121: 'MFA failed or denied', 53003: 'Blocked by Conditional Access',
    50140: 'Keep me signed in prompt', 50158: 'External security challenge', 50097: 'Device authentication required', 50089: 'Flow token expired', 70044: 'Session expired',
    70043: 'Session expired (CA sign-in frequency)', 16000: 'Account selection required', 16001: 'Account selection required', 50199: 'User confirmation required',
    81010: 'Seamless SSO failed', 65001: 'Consent required', 90094: 'Admin consent required', 530032: 'Blocked by security defaults', 50173: 'Fresh token required'
  };
  var INTERRUPT = [50074, 50076, 50140, 50072, 50079, 50125, 50133, 50199, 81010, 16000, 16001, 50158, 50097, 50089, 70044, 70043, 50173];
  var LEGACY = /exchange activesync|imap|pop3?\b|authenticated smtp|\bsmtp\b|exchange web services|mapi over http|other clients|autodiscover|exchange online powershell|offline address book|outlook anywhere|reporting web services|universal outlook|outlook service/i;
  var MODERN = /^(browser|mobile apps and desktop clients)$/i;
  var SCRIPTED = /python-requests|python-urllib|aiohttp|axios|go-http-client|\bcurl\/|\bwget|okhttp|^java\/|node-fetch|fasthttp|libwww|windowspowershell|bav2ropc|postman|ruby|httpclient/i;

  // ------------------------------------------------------------- parsing ---

  function norm(o) {
    var code = Number(o.code) || 0;
    var st = String(o.status || '').toLowerCase();
    var status = /success/.test(st) ? 'success' : /interrupt/.test(st) ? 'interrupted' : /fail/.test(st) ? 'failure'
      : code === 0 ? 'success' : INTERRUPT.indexOf(code) >= 0 ? 'interrupted' : 'failure';
    var loc = String(o.location || '');
    var country = String(o.country || (loc.split(',').pop() || '')).trim().toUpperCase();
    if (country.length !== 2) country = '';
    var t = Date.parse(o.time);
    return {
      time: isNaN(t) ? null : t, user: String(o.user || '').trim().toLowerCase(), app: String(o.app || '').trim(), ip: String(o.ip || '').trim(),
      country: country, city: String(o.city || loc.split(',')[0] || '').trim(), lat: o.lat == null ? null : Number(o.lat), lon: o.lon == null ? null : Number(o.lon),
      status: status, code: code, reason: String(o.reason || '').trim(), client: String(o.client || '').trim(), mfa: String(o.mfa || '').trim(),
      authReq: String(o.authReq || '').trim(), ca: String(o.ca || '').trim(), risk: String(o.risk || '').trim().toLowerCase(), ua: String(o.ua || '').trim(),
      proto: String(o.proto || '').trim(), os: String(o.os || '').trim()
    };
  }

  function parseCsvLog(text) {
    var rows = OV.parseCsv(text);
    if (rows.length < 2) throw new Error('Not enough rows.');
    var head = rows[0].map(function (h) { return h.trim().toLowerCase(); });
    var col = function (names) { for (var i = 0; i < names.length; i++) { var k = head.indexOf(names[i]); if (k >= 0) return k; } return -1; };
    var C = {
      time: col(['date (utc)', 'date', 'createddatetime', 'time', 'timestamp']), user: col(['username', 'user principal name', 'userprincipalname', 'upn', 'user']),
      app: col(['application', 'appdisplayname', 'app']), ip: col(['ip address', 'ipaddress', 'ip']), location: col(['location']), country: col(['country', 'countryorregion', 'country or region']),
      city: col(['city']), status: col(['status']), code: col(['sign-in error code', 'error code', 'errorcode']), reason: col(['failure reason', 'failurereason']),
      client: col(['client app', 'clientappused', 'client app used']), mfa: col(['multifactor authentication result', 'mfa result']),
      authReq: col(['authentication requirement', 'authenticationrequirement']), ca: col(['conditional access', 'conditionalaccessstatus']),
      risk: col(['risk level during sign-in', 'risk level (during sign-in)', 'riskleveldurningsignin', 'riskleveldurringsignin', 'risk level']),
      ua: col(['user agent', 'useragent']), proto: col(['authentication protocol', 'authenticationprotocol']), os: col(['operating system', 'os'])
    };
    if (C.user < 0 || (C.ip < 0 && C.status < 0)) throw new Error('This does not look like an Entra ID sign-in export (no Username / IP address / Status columns).');
    return rows.slice(1).map(function (r) {
      var o = {};
      Object.keys(C).forEach(function (k) { o[k] = C[k] >= 0 ? r[C[k]] : ''; });
      return norm(o);
    }).filter(function (x) { return x.user; });
  }

  function parseJsonLog(text) {
    var data;
    try { data = JSON.parse(text); } catch (e) {
      data = text.split(/\r?\n/).filter(function (l) { return l.trim(); }).map(function (l) { return JSON.parse(l); });
    }
    if (data && !Array.isArray(data)) data = data.value || data.signIns || [data];
    return data.map(function (s) {
      var loc = s.location || s.Location || {}, geo = loc.geoCoordinates || {}, st = s.status || s.Status || {}, dev = s.deviceDetail || {};
      return norm({
        time: s.createdDateTime || s.CreatedDateTime, user: s.userPrincipalName || s.UserPrincipalName, app: s.appDisplayName || s.AppDisplayName,
        ip: s.ipAddress || s.IpAddress, country: loc.countryOrRegion || loc.CountryOrRegion, city: loc.city || loc.City, lat: geo.latitude, lon: geo.longitude,
        code: st.errorCode != null ? st.errorCode : st.ErrorCode, reason: st.failureReason || st.FailureReason, client: s.clientAppUsed || s.ClientAppUsed,
        mfa: (s.mfaDetail && s.mfaDetail.authMethod) || '', authReq: s.authenticationRequirement || s.AuthenticationRequirement,
        ca: s.conditionalAccessStatus || s.ConditionalAccessStatus, risk: s.riskLevelDuringSignIn || s.RiskLevelDuringSignIn, ua: s.userAgent || s.UserAgent,
        proto: s.authenticationProtocol || s.AuthenticationProtocol, os: dev.operatingSystem || ''
      });
    }).filter(function (x) { return x.user; });
  }

  function parse(text) {
    var t = text.trim().replace(/^﻿/, '');
    if (!t) return [];
    return (t.charAt(0) === '[' || t.charAt(0) === '{') ? parseJsonLog(t) : parseCsvLog(t);
  }

  // ------------------------------------------------------------- rules ---

  function km(a, b) {
    var R = 6371, r = Math.PI / 180;
    var dLat = (b[0] - a[0]) * r, dLon = (b[1] - a[1]) * r;
    var h = Math.sin(dLat / 2) * Math.sin(dLat / 2) + Math.cos(a[0] * r) * Math.cos(b[0] * r) * Math.sin(dLon / 2) * Math.sin(dLon / 2);
    return 2 * R * Math.asin(Math.sqrt(h));
  }
  function pos(s) { return s.lat != null && !isNaN(s.lat) && s.lon != null && !isNaN(s.lon) && (s.lat || s.lon) ? [s.lat, s.lon] : GEO[s.country] || null; }
  function isFailCred(s) { return s.code === 50126 || /invalid username or password/i.test(s.reason); }
  function isMfaFail(s) { return s.code === 500121 || /strong authentication|mfa denied|denied the authentication/i.test(s.reason); }
  function legacy(s) { return s.client && !MODERN.test(s.client) && LEGACY.test(s.client); }
  function singleFactor(s) { return /single\s*factor/i.test(s.authReq); }

  function detect(L, home) {
    var out = [];
    var add = function (sev, title, detail, rows, mitre) { out.push({ sev: sev, title: title, detail: detail, rows: rows || [], mitre: mitre || '' }); };
    var ok = L.filter(function (s) { return s.status === 'success'; });

    // Entra ID Protection risk
    var hi = L.filter(function (s) { return s.risk === 'high'; }), mid = L.filter(function (s) { return s.risk === 'medium'; });
    if (hi.length) add('high', 'High-risk sign-ins (Entra ID Protection)', hi.length + ' sign-in(s) for ' + uniq(hi.map(us)).join(', ') + '.', hi, 'T1078.004');
    if (mid.length) add('med', 'Medium-risk sign-ins', mid.length + ' sign-in(s) for ' + uniq(mid.map(us)).join(', ') + '.', mid, 'T1078.004');

    // Impossible travel (password accepted: success or MFA interrupt)
    var travel = [];
    groupBy(L.filter(function (s) { return (s.status === 'success' || s.status === 'interrupted') && s.country && s.time; }), us).forEach(function (list, user) {
      list.sort(function (a, b) { return a.time - b.time; });
      for (var i = 1; i < list.length; i++) {
        var a = list[i - 1], b = list[i];
        if (a.country === b.country) continue;
        var pa = pos(a), pb = pos(b), hours = Math.max((b.time - a.time) / 3600e3, 1 / 60);
        if (pa && pb) {
          var d = km(pa, pb);
          if (d >= 500 && d / hours >= 1000) travel.push({ user: user, a: a, b: b, d: d, hours: hours });
        } else if (hours < 1) travel.push({ user: user, a: a, b: b, d: null, hours: hours });
      }
    });
    groupBy(travel, function (t) { return t.user; }).forEach(function (list, user) {
      var t = list[0];
      add('high', 'Impossible travel for ' + user, list.length + ' jump(s). Example: ' + t.a.country + ' → ' + t.b.country + ' in ' + dur(t.hours) + (t.d ? ' (~' + Math.round(t.d).toLocaleString() + ' km, ' + Math.round(t.d / t.hours).toLocaleString() + ' km/h)' : '') +
        ', IPs ' + t.a.ip + ' → ' + t.b.ip + '. A VPN can cause this; confirm with the user.', [].concat.apply([], list.map(function (x) { return [x.a, x.b]; })), 'T1078.004');
    });

    // Successful sign-ins from outside the home country
    if (home) {
      var away = ok.filter(function (s) { return s.country && s.country !== home; });
      groupBy(away, us).forEach(function (list, user) {
        var cs = uniq(list.map(function (s) { return s.country; }));
        var noMfa = list.filter(singleFactor).length;
        add(noMfa ? 'high' : 'med', 'Sign-ins from outside ' + home + ' for ' + user, list.length + ' successful sign-in(s) from ' + cs.join(', ') + (noMfa ? ', ' + noMfa + ' of them without MFA' : '') + '.', list, 'T1078.004');
      });
    }

    // Password spraying and brute force
    var bad = L.filter(isFailCred);
    groupBy(bad, function (s) { return s.ip; }).forEach(function (list, ip) {
      var users = uniq(list.map(us));
      if (ip && users.length >= 5) add('high', 'Password spraying from ' + ip + (list[0].country ? ' (' + list[0].country + ')' : ''), list.length + ' bad-password attempts against ' + users.length + ' accounts' + span(list) + ' via ' + uniq(list.map(function (s) { return s.client || s.app; })).join(', ') + '.', list, 'T1110.003');
    });
    groupBy(bad, us).forEach(function (list, user) {
      if (list.length >= 10) add('high', 'Brute force against ' + user, list.length + ' bad-password attempts' + span(list) + ' from ' + uniq(list.map(function (s) { return s.ip; })).slice(0, 5).join(', ') + '.', list, 'T1110.001');
    });
    var locked = L.filter(function (s) { return s.code === 50053; });
    if (locked.length) add('med', 'Smart lockout triggered', locked.length + ' attempt(s) blocked for ' + uniq(locked.map(us)).join(', ') + '. Someone is guessing passwords.', locked, 'T1110');

    // MFA fatigue: password correct, MFA repeatedly failing
    groupBy(L.filter(isMfaFail), us).forEach(function (list, user) {
      list.sort(function (a, b) { return a.time - b.time; });
      var lastFail = list[list.length - 1];
      var after = ok.filter(function (s) { return us(s) === user && s.time && lastFail.time && s.time > lastFail.time && s.time - lastFail.time < 3600e3; });
      if (list.length >= 3 && after.length) add('crit', 'MFA fatigue then success for ' + user, list.length + ' MFA failures' + span(list) + ', then a successful sign-in from ' + after[0].ip + (after[0].country ? ' (' + after[0].country + ')' : '') + '. The password is known and the user may have approved a push.', list.concat(after.slice(0, 1)), 'T1621');
      else if (list.length >= 3) add('high', 'Repeated MFA failures for ' + user, list.length + ' MFA failures' + span(list) + '. The password is correct; someone may be push-bombing this user.', list, 'T1621');
      else add('low', 'MFA failure for ' + user, 'The password was accepted but MFA failed (' + list.length + 'x). Confirm it was the user.', list, 'T1621');
    });

    // Legacy authentication
    var leg = L.filter(legacy);
    var legOk = leg.filter(function (s) { return s.status === 'success'; });
    if (legOk.length) add('high', 'Successful legacy authentication', legOk.length + ' sign-in(s) with ' + uniq(legOk.map(function (s) { return s.client; })).join(', ') + ' for ' + uniq(legOk.map(us)).join(', ') + '. Legacy protocols skip MFA; block them with Conditional Access.', legOk, 'T1078.004');
    var legBad = leg.filter(function (s) { return s.status !== 'success'; });
    if (legBad.length >= 3) add('med', 'Legacy authentication attempts', legBad.length + ' failed attempt(s) over ' + uniq(legBad.map(function (s) { return s.client; })).join(', ') + '. Password spraying usually uses these.', legBad, 'T1110.003');

    // Scripted clients, device code, ROPC
    var bot = L.filter(function (s) { return SCRIPTED.test(s.ua); });
    var botOk = bot.filter(function (s) { return s.status === 'success'; });
    if (botOk.length) add('high', 'Successful sign-in from a script or tool', uniq(botOk.map(function (s) { return s.ua; })).slice(0, 3).join(' | ') + ' for ' + uniq(botOk.map(us)).join(', ') + '.', botOk, 'T1078.004');
    else if (bot.length) add('med', 'Sign-in attempts from scripts or tools', bot.length + ' attempt(s), e.g. ' + bot[0].ua + '.', bot, 'T1110');
    var dc = L.filter(function (s) { return /device\s*code/i.test(s.proto) && s.status === 'success'; });
    if (dc.length) add('med', 'Device code flow sign-ins', dc.length + ' for ' + uniq(dc.map(us)).join(', ') + '. Device code phishing abuses this flow; block it with Conditional Access if unused.', dc, 'T1528');
    var ropc = L.filter(function (s) { return /ropc/i.test(s.proto) && s.status === 'success'; });
    if (ropc.length) add('med', 'ROPC (password-only) sign-ins', ropc.length + ' for ' + uniq(ropc.map(us)).join(', ') + '. ROPC cannot do MFA.', ropc, 'T1078.004');

    // Single-factor modern sign-ins
    var sf = ok.filter(function (s) { return singleFactor(s) && !legacy(s); });
    if (sf.length) {
      var sfUsers = uniq(sf.map(us));
      add('low', 'Successful sign-ins without MFA', sf.length + ' sign-in(s) by ' + sfUsers.length + ' user(s): ' + sfUsers.slice(0, 8).join(', ') + (sfUsers.length > 8 ? '…' : '') + '. Fine from trusted devices or locations; otherwise require MFA.', sf, 'T1078.004');
    }
    var ca = L.filter(function (s) { return s.code === 53003 || s.code === 530032; });
    if (ca.length) add('info', 'Blocked by Conditional Access', ca.length + ' attempt(s) blocked, from ' + uniq(ca.map(function (s) { return s.country || s.ip; })).slice(0, 8).join(', ') + '. Policies are working; the attempts still show interest in these accounts.', ca, '');

    return out.sort(function (a, b) { return SEV_ORDER[a.sev] - SEV_ORDER[b.sev]; });
  }

  function us(s) { return s.user; }
  function groupBy(list, keyFn) { var m = new Map(); list.forEach(function (x) { var k = keyFn(x) || ''; if (!m.has(k)) m.set(k, []); m.get(k).push(x); }); return m; }
  function uniq(arr) { var s = new Set(); return arr.map(function (x) { return String(x || '').trim(); }).filter(function (x) { if (!x || s.has(x)) return false; s.add(x); return true; }); }
  function dur(h) { return h < 1 ? Math.round(h * 60) + ' min' : h < 48 ? (Math.round(h * 10) / 10) + ' h' : Math.round(h / 24) + ' days'; }
  function span(list) {
    var t = list.map(function (s) { return s.time; }).filter(Boolean);
    if (t.length < 2) return '';
    return ' in ' + dur((Math.max.apply(null, t) - Math.min.apply(null, t)) / 3600e3);
  }
  function fmt(t) { return t ? new Date(t).toISOString().replace('T', ' ').slice(0, 16) + ' UTC' : ''; }
  function line(s) {
    return fmt(s.time) + ' · ' + s.user + ' · ' + (s.app || '?') + '\n' + (s.ip || '?') + (s.country ? ' (' + (s.city ? s.city + ', ' : '') + s.country + ')' : '') +
      ' · ' + s.status + (s.code ? ' ' + s.code + ' ' + (ERRORS[s.code] || s.reason) : '') + (s.client ? ' · ' + s.client : '') + (s.authReq ? ' · ' + s.authReq : '') + (s.ua ? '\nUA: ' + s.ua : '');
  }

  // ------------------------------------------------------------- render ---

  var last = null;

  function analyze() {
    var raw = $('input').value, L;
    var fail = function (msg) { $('out').innerHTML = '<p class="empty">' + OV.esc(msg) + '</p>'; $('users-panel').hidden = $('geo-panel').hidden = true; $('note').disabled = true; };
    try { L = parse(raw); } catch (e) { return fail((e.message || 'Could not read the file.') + ' Use the CSV or JSON download from Entra ID sign-in logs.'); }
    if (!L.length) return fail(raw.trim() ? 'No sign-ins recognised.' : 'Load a sign-in export and press Analyze.');

    var counts = {};
    L.filter(function (s) { return s.status === 'success' && s.country; }).forEach(function (s) { counts[s.country] = (counts[s.country] || 0) + 1; });
    var auto = Object.keys(counts).sort(function (a, b) { return counts[b] - counts[a]; })[0] || '';
    var homeIn = $('home').value.trim().toUpperCase();
    var home = /^[A-Z]{2}$/.test(homeIn) ? homeIn : auto;
    var findings = detect(L, home);
    var okN = L.filter(function (s) { return s.status === 'success'; }).length;
    var times = L.map(function (s) { return s.time; }).filter(Boolean);
    last = { L: L, findings: findings, home: home, from: Math.min.apply(null, times), to: Math.max.apply(null, times) };

    var cnt = function (s) { return findings.filter(function (f) { return f.sev === s; }).length; };
    var html = '<div class="stats">' +
      '<div class="stat"><b>' + L.length + '</b><span>sign-ins</span></div>' +
      '<div class="stat"><b>' + uniq(L.map(us)).length + '</b><span>users</span></div>' +
      '<div class="stat"><b>' + Math.round(okN / L.length * 100) + '%</b><span>successful</span></div>' +
      '<div class="stat"><b style="color:#ef4444">' + (cnt('crit') + cnt('high')) + '</b><span>critical / high</span></div></div>';
    if (times.length) html += '<p class="sub" style="margin:-4px 0 12px;font-size:.82rem">' + fmt(last.from) + ' → ' + fmt(last.to) + (home ? ' · home country ' + home + (homeIn ? '' : ' (auto)') : '') + '</p>';
    html += findings.length ? findings.map(function (f) {
      return '<div class="finding"><div class="finding-h"><span class="sev ' + f.sev + '">' + SEV_LABEL[f.sev] + '</span><b>' + OV.esc(f.title) + '</b>' +
        (f.mitre ? '<span class="pill">' + OV.esc(f.mitre) + '</span>' : '') + '</div><p>' + OV.esc(f.detail) + '</p>' +
        '<details><summary>Evidence (' + f.rows.length + ')</summary>' + f.rows.slice(0, 6).map(function (s) { return '<pre>' + OV.esc(line(s)) + '</pre>'; }).join('') +
        (f.rows.length > 6 ? '<p>…and ' + (f.rows.length - 6) + ' more.</p>' : '') + '</details></div>';
    }).join('') : '<div class="verdict good"><div><div class="v">No findings</div><div class="sub" style="margin:2px 0 0">None of the built-in rules matched this export.</div></div></div>';
    // IPs that appear in findings first, then the rest with failures, each with one-click lookups.
    var flagged = new Set();
    findings.forEach(function (f) { if (f.sev !== 'info') f.rows.forEach(function (s) { if (s.ip) flagged.add(s.ip); }); });
    var ipStats = {};
    L.forEach(function (s) { if (!s.ip || window.VSIoc.isPrivateIp(s.ip)) return; var o = ipStats[s.ip] || (ipStats[s.ip] = { ip: s.ip, n: 0, bad: 0, users: new Set(), country: s.country }); o.n++; if (s.status !== 'success') o.bad++; o.users.add(s.user); });
    var ipList = Object.keys(ipStats).map(function (k) { return ipStats[k]; }).filter(function (o) { return flagged.has(o.ip) || o.bad; })
      .sort(function (a, b) { return (flagged.has(b.ip) - flagged.has(a.ip)) || (b.bad - a.bad); }).slice(0, 25);
    if (ipList.length) html += '<h3 style="font-family:var(--display);font-size:.95rem;margin:14px 0 8px">IPs worth checking <button class="copy" type="button" data-value="' + OV.esc(ipList.map(function (o) { return o.ip; }).join('\n')) + '">Copy all</button></h3><ul class="ioc-list">' +
      ipList.map(function (o) {
        return '<li><span class="ioc-v"><span>' + OV.esc(o.ip) + ' <span class="sub">' + (o.country ? OV.esc(o.country) + ' · ' : '') + o.n + ' sign-in' + (o.n === 1 ? '' : 's') + (o.bad ? ', ' + o.bad + ' failed' : '') + ', ' + o.users.size + ' user' + (o.users.size === 1 ? '' : 's') + '</span></span>' +
          OV.pivots('ip', o.ip) + '</span><button class="copy" type="button" data-value="' + OV.esc(o.ip) + '">Copy</button></li>';
      }).join('') + '</ul>';
    $('out').innerHTML = html;
    $('note').disabled = false;

    var flagged = new Map();
    findings.forEach(function (f) { uniq(f.rows.map(us)).forEach(function (u) { flagged.set(u, (flagged.get(u) || 0) + (SEV_ORDER[f.sev] <= 1 ? 3 : 1)); }); });
    var users = [];
    groupBy(L, us).forEach(function (list, u) {
      users.push({ u: u, n: list.length, fail: list.filter(function (s) { return s.status === 'failure'; }).length, cs: uniq(list.map(function (s) { return s.country; })),
        leg: list.filter(legacy).length, sf: list.filter(function (s) { return s.status === 'success' && singleFactor(s); }).length, score: flagged.get(u) || 0 });
    });
    users.sort(function (a, b) { return b.score - a.score || b.fail - a.fail; });
    $('users').innerHTML = '<thead><tr><th>User</th><th>Sign-ins</th><th>Failed</th><th>Countries</th><th>Legacy</th><th>No MFA</th><th>Flags</th></tr></thead><tbody>' +
      users.slice(0, 200).map(function (r) {
        return '<tr><td class="mono">' + OV.esc(r.u) + '</td><td>' + r.n + '</td><td>' + r.fail + '</td><td>' + r.cs.map(function (c) { return '<span class="pill' + (home && c !== home ? ' warn' : '') + '">' + OV.esc(c) + '</span>'; }).join(' ') +
          '</td><td>' + (r.leg ? '<span class="pill warn">' + r.leg + '</span>' : '0') + '</td><td>' + r.sf + '</td><td>' + (r.score ? '<span class="pill ' + (r.score >= 3 ? 'fail' : 'warn') + '">' + r.score + '</span>' : '') + '</td></tr>';
      }).join('') + '</tbody>';
    var geo = [];
    groupBy(L.filter(function (s) { return s.country; }), function (s) { return s.country; }).forEach(function (list, c) {
      geo.push({ c: c, n: list.length, ok: list.filter(function (s) { return s.status === 'success'; }).length, users: uniq(list.map(us)).length });
    });
    geo.sort(function (a, b) { return b.n - a.n; });
    $('geo').innerHTML = '<thead><tr><th>Country</th><th>Sign-ins</th><th>Successful</th><th>Users</th></tr></thead><tbody>' + geo.map(function (g) {
      return '<tr><td><span class="pill' + (home && g.c !== home ? ' warn' : ' pass') + '">' + OV.esc(g.c) + '</span></td><td>' + g.n + '</td><td>' + g.ok + '</td><td>' + g.users + '</td></tr>';
    }).join('') + '</tbody>';
    $('users-panel').hidden = false;
    $('geo-panel').hidden = !geo.length;
  }

  function ticketNote() {
    var L = last;
    var lines = ['M365 sign-in review (OpsVantage M365 Sign-in Review)', L.L.length + ' sign-ins, ' + fmt(L.from) + ' to ' + fmt(L.to) + (L.home ? ', home country ' + L.home : ''), ''];
    if (!L.findings.length) lines.push('No rule matched.');
    L.findings.forEach(function (f) { lines.push('[' + SEV_LABEL[f.sev].toUpperCase() + '] ' + f.title + (f.mitre ? ' (' + f.mitre + ')' : ''), '  ' + f.detail.replace(/\b(\d{1,3}(?:\.\d{1,3}){3})\b/g, function (ip) { return I.defang(ip, 'ipv4'); })); });
    return lines.join('\n');
  }

  // ------------------------------------------------------------- sample ---

  function sample() {
    var head = ['Date (UTC)', 'Username', 'Application', 'IP address', 'Location', 'Status', 'Sign-in error code', 'Failure reason', 'Client app', 'Authentication requirement', 'Conditional Access', 'User agent', 'Authentication Protocol', 'Risk level during sign-in'];
    var rows = [head];
    var base = Date.UTC(2026, 10, 2, 0, 0, 0);
    var at = function (min) { return new Date(base + min * 60000).toISOString().replace('.000', ''); };
    var EDGE = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36 Edg/130.0';
    var r = function (min, user, app, ip, loc, status, code, reason, client, auth, ca, ua, proto, risk) {
      rows.push([at(min), user + '@contoso.com', app, ip, loc, status, code || '0', reason || '', client || 'Browser', auth || 'multiFactorAuthentication', ca || 'success', ua || EDGE, proto || 'none', risk || 'none']);
    };
    var SG = 'Singapore, Singapore, SG';
    ['alice', 'bob', 'carol', 'dave', 'erin', 'frank', 'grace', 'henry'].forEach(function (u, i) { r(30 + i * 7, u, 'Office 365 Exchange Online', '203.116.' + (10 + i) + '.' + (20 + i), SG, 'Success'); });
    r(480, 'bob', 'Office 365 SharePoint Online', '203.116.11.21', SG, 'Success');
    r(552, 'bob', 'Office 365 Exchange Online', '102.89.34.17', 'Lagos, Lagos, NG', 'Success', '0', '', 'Browser', 'singleFactorAuthentication', 'notApplied', EDGE, 'none', 'medium');
    ['alice', 'carol', 'dave', 'grace', 'henry', 'ivan', 'judy'].forEach(function (u, i) { r(600 + i, u, 'Office 365 Exchange Online', '185.220.101.45', 'Frankfurt am Main, Hessen, DE', 'Failure', '50126', 'Invalid username or password or Invalid on-premise username or password.', 'IMAP4', 'singleFactorAuthentication', 'notApplied', 'python-requests/2.31.0'); });
    r(640, 'carol', 'Office 365 Exchange Online', '91.240.118.52', 'Moscow, Moscow, RU', 'Success', '0', '', 'IMAP4', 'singleFactorAuthentication', 'notApplied', 'BAV2ROPC', 'ropc');
    for (var i = 0; i < 6; i++) r(700 + i, 'dave', 'Microsoft Office', '45.137.21.9', 'Amsterdam, Noord-Holland, NL', 'Failure', '500121', 'Authentication failed during strong authentication request.', 'Mobile Apps and Desktop clients', 'multiFactorAuthentication', 'notApplied');
    r(712, 'dave', 'Microsoft Office', '45.137.21.9', 'Amsterdam, Noord-Holland, NL', 'Success', '0', '', 'Mobile Apps and Desktop clients');
    r(760, 'frank', 'Microsoft Authentication Broker', '154.47.20.8', 'Singapore, Singapore, SG', 'Success', '0', '', 'Mobile Apps and Desktop clients', 'multiFactorAuthentication', 'success', EDGE, 'deviceCode');
    r(800, 'erin', 'Office 365 Exchange Online', '198.51.100.23', 'Ashburn, Virginia, US', 'Failure', '53003', 'Access has been blocked by Conditional Access policies.', 'Browser', 'singleFactorAuthentication', 'failure');
    return rows.map(function (row) { return row.map(OV.csvCell).join(','); }).join('\r\n');
  }

  function loadFile(f) {
    if (!f) return;
    if (f.size > 100 * 1024 * 1024) { OV.toast('File is over 100 MB; export a shorter period'); return; }
    var rd = new FileReader();
    rd.onload = function () { $('input').value = String(rd.result); analyze(); };
    rd.readAsText(f);
  }

  $('analyze').addEventListener('click', analyze);
  $('sample').addEventListener('click', function () { $('input').value = sample(); analyze(); });
  $('clear').addEventListener('click', function () { $('input').value = ''; analyze(); $('input').focus(); });
  $('file').addEventListener('change', function () { loadFile(this.files[0]); this.value = ''; });
  $('home').addEventListener('change', function () { if ($('input').value.trim()) analyze(); });
  $('input').addEventListener('dragover', function (e) { e.preventDefault(); });
  $('input').addEventListener('drop', function (e) { if (e.dataTransfer.files && e.dataTransfer.files[0]) { e.preventDefault(); loadFile(e.dataTransfer.files[0]); } });
  $('note').addEventListener('click', function () { if (last) OV.copy(ticketNote(), 'Ticket note copied'); });
  $('out').addEventListener('click', function (e) { var b = e.target.closest('.copy'); if (b) OV.copy(b.dataset.value, 'Copied'); });
})();
