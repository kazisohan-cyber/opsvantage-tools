// JWT Token Decoder: decodes a JSON Web Token in the page and explains it, with extra detail for Microsoft Entra ID
// tokens (tenant, client app, MFA, admin roles, scopes, issuing IP). The signature is not verified and the token is
// never sent anywhere; it is cleared when the page closes.
(function () {
  'use strict';
  var OV = window.OV;
  var $ = function (id) { return document.getElementById(id); };
  var last = null;

  // Well-known Microsoft first-party client and resource IDs.
  var APPS = {
    '04b07795-8ddb-461a-bbee-02f9e1bf7b46': ['Azure CLI', true], '1950a258-227b-4e31-a9cf-717495945fc2': ['Azure PowerShell', true],
    '14d82eec-204b-4c2f-b7e8-296a70dab67e': ['Microsoft Graph Command Line Tools (Graph PowerShell)', true], '1b730954-1685-4b74-9bfd-dac224a7b894': ['Azure AD PowerShell', true],
    'd3590ed6-52b3-4102-aeff-aad2292ab01c': ['Microsoft Office', true], '1fec8e78-bce4-4aaf-ab1b-5451cc387264': ['Microsoft Teams', false],
    '29d9ed98-a469-4536-ade2-f981bc1d605e': ['Microsoft Authentication Broker', true], '9bc3ab49-b65d-410a-85ad-de819febfddc': ['SharePoint Online Management Shell', true],
    '27922004-5251-4030-b22d-91ecd9a37ea4': ['Outlook Mobile', false], '4813382a-8fa7-425e-ab75-3b753aab3abb': ['Microsoft Authenticator', false],
    'ab9b8c07-8f02-4f72-87fa-80105867a763': ['OneDrive Sync Engine', false], '89bee1f7-5e6e-4d8a-9f3d-ecd601259da7': ['Office 365 web (Office.com)', false],
    '00000003-0000-0000-c000-000000000000': ['Microsoft Graph', false], '00000002-0000-0ff1-ce00-000000000000': ['Exchange Online', false],
    '00000003-0000-0ff1-ce00-000000000000': ['SharePoint Online', false], '797f4846-ba00-4fd7-ba43-dac1f8f63013': ['Azure Resource Manager', false],
    'https://graph.microsoft.com': ['Microsoft Graph', false], 'https://management.azure.com/': ['Azure Resource Manager', false], 'https://outlook.office365.com': ['Exchange Online', false]
  };
  // Directory role template IDs (wids claim).
  var ROLES = {
    '62e90394-69f5-4237-9190-012177145e10': ['Global Administrator', 3], 'e8611ab8-c189-46e8-94e1-60213ab1f814': ['Privileged Role Administrator', 3],
    '7be44c8a-adaf-4e2a-84d6-ab2649e08a13': ['Privileged Authentication Administrator', 3], '194ae4cb-b126-40b2-bd5b-6091b380977d': ['Security Administrator', 2],
    '29232cdf-9323-42fd-ade2-1d097af3e4de': ['Exchange Administrator', 2], 'f28a1f50-f6e7-4571-818b-6a12f2af6b6c': ['SharePoint Administrator', 2],
    '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3': ['Application Administrator', 2], '158c047a-c907-4556-b7ef-446551a6b5f7': ['Cloud Application Administrator', 2],
    'fe930be7-5e62-47db-91af-98c3a49a38b1': ['User Administrator', 2], 'c4e39bd9-1100-46d3-8c65-fb160da0071f': ['Authentication Administrator', 2],
    'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9': ['Conditional Access Administrator', 2], '3a2c62db-5318-420d-8d74-23affee5d9d5': ['Intune Administrator', 2],
    '729827e3-9c14-49f7-bb1b-9608f156bbb8': ['Helpdesk Administrator', 1], 'f2ef992c-3afb-46b9-b7cf-a126ee74c451': ['Global Reader', 1],
    '5d6b6bb7-de71-4623-b4af-96380a352509': ['Security Reader', 1], 'b79fbf4d-3ef9-4689-8143-76b194e85509': ['Default user role', 0]
  };
  var AMR = { pwd: 'password', mfa: 'multi-factor', rsa: 'RSA key or token', otp: 'one-time code', sms: 'SMS code', ngcmfa: 'Windows Hello / passwordless (counts as MFA)', fido: 'FIDO2 security key',
    wia: 'Windows integrated auth', phr: 'phone sign-in', kba: 'security questions', face: 'face recognition', fpt: 'fingerprint', hwk: 'hardware key', swk: 'software key', pop: 'proof of possession', mca: 'multiple channels', tel: 'phone call', user: 'user presence', pin: 'PIN' };
  var MFA_AMR = /^(mfa|ngcmfa|fido|rsa|otp|sms|hwk|mca|tel|face|fpt)$/;
  var RISKY_SCOPES = /^(Mail\.(ReadWrite|Send)(\.All|\.Shared)?|Files\.ReadWrite\.All|Sites\.(ReadWrite|FullControl)\.All|Directory\.ReadWrite\.All|User\.ReadWrite\.All|Application\.ReadWrite\.All|AppRoleAssignment\.ReadWrite\.All|RoleManagement\.ReadWrite\.Directory|full_access_as_user|EWS\.AccessAsUser\.All|Mail\.ReadWrite|MailboxSettings\.ReadWrite|user_impersonation)$/i;

  function b64json(part) {
    var s = part.replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    var bin = atob(s), bytes = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return JSON.parse(new TextDecoder().decode(bytes));
  }
  function b64enc(obj) { return btoa(unescape(encodeURIComponent(JSON.stringify(obj)))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }

  // A made-up Entra token: valid structure, fake tenant and signature.
  function sample() {
    var now = Math.floor(Date.now() / 1000) - 600;
    var h = { typ: 'JWT', alg: 'RS256', kid: 'example-key-id' };
    var p = { aud: '00000003-0000-0000-c000-000000000000', iss: 'https://sts.windows.net/9c1c4f1e-5a7b-4c6e-9d0a-1a2b3c4d5e6f/', iat: now, nbf: now, exp: now + 4500,
      acct: 0, amr: ['pwd'], app_displayname: 'Microsoft Azure CLI', appid: '04b07795-8ddb-461a-bbee-02f9e1bf7b46', appidacr: '0', idtyp: 'user', ipaddr: '185.220.101.45',
      name: 'Dave Lee', oid: '3f8b2c1d-7e6a-4b5c-9d8e-0f1a2b3c4d5e', scp: 'AuditLog.Read.All Directory.AccessAsUser.All Mail.ReadWrite Mail.Send User.Read offline_access',
      tid: '9c1c4f1e-5a7b-4c6e-9d0a-1a2b3c4d5e6f', unique_name: 'dave@contoso.com', upn: 'dave@contoso.com', ver: '1.0',
      wids: ['62e90394-69f5-4237-9190-012177145e10', 'b79fbf4d-3ef9-4689-8143-76b194e85509'] };
    return 'Bearer ' + b64enc(h) + '.' + b64enc(p) + '.not-a-real-signature';
  }

  var fmtT = function (s) { return s ? new Date(s * 1000).toISOString().replace('T', ' ').slice(0, 19) + ' UTC' : ''; };
  var dur = function (sec) { sec = Math.abs(sec); return sec < 3600 ? Math.round(sec / 60) + ' min' : sec < 172800 ? (sec / 3600).toFixed(1) + ' h' : Math.round(sec / 86400) + ' days'; };

  function analyze() {
    var raw = $('input').value.trim().replace(/^(bearer|authorization:\s*bearer)\s+/i, '').replace(/^["']|["']$/g, '');
    var m = raw.match(/eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/);
    if (!m) { $('out').innerHTML = '<p class="empty">' + (raw ? 'No JWT found. A token has three parts separated by dots and starts with eyJ.' : 'Paste a token and press Decode.') + '</p>'; $('note').disabled = true; last = null; return; }
    var parts = m[0].split('.'), h, p;
    try { h = b64json(parts[0]); p = b64json(parts[1]); } catch (e) { $('out').innerHTML = '<p class="empty">The token parts are not valid Base64 JSON.</p>'; $('note').disabled = true; return; }
    var now = Date.now() / 1000, f = [];
    var add = function (sev, t) { f.push({ sev: sev, t: t }); };
    var entra = /sts\.windows\.net|login\.microsoftonline\.com|login\.windows\.net/.test(p.iss || '') || !!p.tid;
    if (String(h.alg).toLowerCase() === 'none') add('high', 'alg is "none": the token is unsigned. No service should accept it.');
    if (p.exp && p.exp < now) add('info', 'Expired ' + dur(now - p.exp) + ' ago.');
    else if (p.exp) add('info', 'Valid for another ' + dur(p.exp - now) + '.');
    if (p.exp && p.iat && p.exp - p.iat > 86400 * 2) add('med', 'Lifetime of ' + dur(p.exp - p.iat) + ', far longer than the usual 1 to 1.5 hours for access tokens.');
    var amr = Array.isArray(p.amr) ? p.amr : [];
    if (entra && amr.length && !amr.some(function (a) { return MFA_AMR.test(a); })) add('med', 'Sign-in used ' + amr.map(function (a) { return AMR[a] || a; }).join(' + ') + ' only, with no MFA claim. Check whether Conditional Access should have required MFA.');
    if (entra && amr.some(function (a) { return MFA_AMR.test(a); })) add('good', 'MFA was satisfied (' + amr.map(function (a) { return AMR[a] || a; }).join(', ') + ').');
    var app = APPS[p.appid || p.azp];
    if (app && app[1]) add('med', 'Issued to ' + app[0] + '. Attackers favour this public client in device-code phishing and token theft because it needs no app registration.');
    var roles = (p.wids || []).map(function (w) { return ROLES[w] ? ROLES[w].concat([w]) : ['Directory role ' + w, 1, w]; }).filter(function (r) { return r[1] > 0; });
    var top = roles.reduce(function (a, r) { return Math.max(a, r[1]); }, 0);
    if (roles.length) add(top >= 3 ? 'high' : 'med', 'The account holds ' + roles.map(function (r) { return r[0]; }).join(', ') + '. A stolen token for it carries those rights.');
    var scopes = String(p.scp || '').split(/\s+/).filter(Boolean), appRoles = Array.isArray(p.roles) ? p.roles : [];
    var risky = scopes.concat(appRoles).filter(function (s) { return RISKY_SCOPES.test(s); });
    if (risky.length) add('med', 'Can ' + (appRoles.length ? 'act as the application across the tenant with ' : 'act as the user with ') + risky.join(', ') + '.');
    if (scopes.indexOf('offline_access') >= 0) add('info', 'offline_access was granted, so the app also holds a refresh token that outlives this access token.');
    if (p.idtyp === 'app' || (!p.upn && !p.unique_name && appRoles.length)) add('info', 'App-only token: no user signed in; it acts as the application itself.');
    last = { h: h, p: p, f: f, entra: entra, app: app, roles: roles, sig: parts[2] };
    render();
  }

  var CLAIMS = {
    iss: 'Issuer (who created the token)', aud: 'Audience (the API it is for)', sub: 'Subject', oid: 'Object ID of the user or app', tid: 'Tenant ID', upn: 'User principal name',
    unique_name: 'User name', preferred_username: 'User name', name: 'Display name', appid: 'Client app ID', azp: 'Client app ID', app_displayname: 'Client app name', ipaddr: 'IP address at sign-in',
    amr: 'Authentication methods', acr: 'Authentication context', iat: 'Issued at', nbf: 'Not before', exp: 'Expires', scp: 'Delegated permissions', roles: 'Application permissions or app roles',
    wids: 'Directory roles', idtyp: 'Token type', deviceid: 'Device ID', ver: 'Token version', sid: 'Session ID', uti: 'Token identifier (unique per token)', auth_time: 'Time of sign-in',
    email: 'Email', groups: 'Groups', appidacr: 'Client authentication (0 = public client, 1 = secret, 2 = certificate)', acct: 'Account type (0 = member, 1 = guest)', xms_cc: 'Client capabilities', family_name: 'Surname', given_name: 'Given name'
  };

  function explain(k, v) {
    if (/^(iat|nbf|exp|auth_time)$/.test(k) && typeof v === 'number') return fmtT(v);
    if ((k === 'appid' || k === 'azp' || k === 'aud') && APPS[v]) return v + '  (' + APPS[v][0] + ')';
    if (k === 'amr' && Array.isArray(v)) return v.map(function (a) { return a + (AMR[a] ? ' (' + AMR[a] + ')' : ''); }).join(', ');
    if (k === 'wids' && Array.isArray(v)) return v.map(function (w) { return ROLES[w] ? ROLES[w][0] : w; }).join(', ');
    return typeof v === 'object' ? JSON.stringify(v) : String(v);
  }

  function render() {
    var L = last, p = L.p;
    var sevCls = { high: 'high', med: 'med', info: 'info', good: 'low' };
    var bad = L.f.some(function (x) { return x.sev === 'high'; }), med = L.f.some(function (x) { return x.sev === 'med'; });
    var html = '<div class="verdict ' + (bad ? 'bad' : med ? 'warn' : 'good') + '"><div><div class="v">' + (L.entra ? 'Microsoft Entra ID token' : 'JSON Web Token') + '</div><div class="sub" style="margin:2px 0 0">' +
      OV.esc([p.upn || p.unique_name || p.preferred_username || p.sub || '', L.app ? 'via ' + L.app[0] : p.app_displayname ? 'via ' + p.app_displayname : '', p.aud && APPS[p.aud] ? 'for ' + APPS[p.aud][0] : ''].filter(Boolean).join(' · ')) + '</div></div></div>';
    html += OV.nextSteps(bad || med ? [
      'If this token was found where it should not be (a phishing kit, a log, a paste site), treat it as stolen: revoke the user\'s sessions so its refresh token stops working.',
      p.ipaddr ? 'Check the sign-in from ' + p.ipaddr + ' in the Entra sign-in logs (filter by the uti or session ID) and confirm it was the user.' : 'Find the matching sign-in in the Entra sign-in logs and confirm it was the user.',
      L.roles.length ? 'Admin accounts should sign in with phishing-resistant MFA and short sessions; review this one\'s Conditional Access.' : 'Review the app\'s permissions under Enterprise applications if they look broader than it needs.'
    ] : ['Nothing stands out. Remember the signature was not checked here, so the claims are only as trustworthy as where the token came from.'], bad ? 'bad' : med ? 'warn' : '');
    html += '<ul class="reasons">' + L.f.map(function (x) { return '<li class="' + (x.sev === 'high' || x.sev === 'med' ? 'bad' : x.sev === 'good' ? 'good' : '') + '">' + OV.esc(x.t) + '</li>'; }).join('') + '</ul>';
    if (p.iat && p.exp) {
      var now = Date.now() / 1000, span = p.exp - p.iat, pos = Math.max(0, Math.min(1, (now - p.iat) / span));
      html += '<div class="viz"><h3>Lifetime</h3><div class="ch-bar"><span class="ch-bar-l">' + OV.esc(fmtT(p.iat).slice(11, 16)) + ' issued</span><span class="ch-bar-t"><span class="ch-bar-f" style="width:' + Math.round(pos * 100) + '%;background:' + (now > p.exp ? 'var(--muted-2)' : 'var(--live)') + '"></span></span><span class="ch-bar-v">' + (now > p.exp ? 'expired' : dur(p.exp - now) + ' left') + '</span></div></div>';
    }
    var rows = Object.keys(p).map(function (k) { return '<tr><td class="mono">' + OV.esc(k) + '</td><td>' + OV.esc(CLAIMS[k] || '') + '</td><td class="mono" style="word-break:break-all">' + OV.esc(explain(k, p[k])) + '</td></tr>'; }).join('');
    html += '<h3 style="font-family:var(--display);font-size:.95rem;margin:14px 0 8px">Claims</h3><div class="table-wrap"><table class="data"><thead><tr><th>Claim</th><th>Meaning</th><th>Value</th></tr></thead><tbody>' + rows + '</tbody></table></div>';
    if (p.ipaddr) html += '<div style="margin-top:8px">' + OV.pivots('ip', p.ipaddr) + '</div>';
    html += '<details style="margin-top:10px"><summary>Header and raw payload</summary><pre class="q">' + OV.esc(JSON.stringify(L.h, null, 2)) + '</pre><pre class="q">' + OV.esc(JSON.stringify(p, null, 2)) + '</pre></details>';
    html += '<p class="sub" style="font-size:.78rem;max-width:none">The signature (' + (L.sig ? L.sig.length + ' characters' : 'missing') + ') is not verified: that needs the issuer\'s public keys. Decoding only reads what the token claims.</p>';
    $('out').innerHTML = html;
    $('note').disabled = false;
  }

  function note() {
    var p = last.p, t = ['Token review (OpsVantage JWT Decoder)'];
    ['upn', 'unique_name', 'oid', 'tid', 'appid', 'app_displayname', 'aud', 'ipaddr', 'amr', 'scp', 'roles', 'wids', 'iat', 'exp', 'uti'].forEach(function (k) { if (p[k] != null) t.push(k + ': ' + explain(k, p[k])); });
    t.push('', 'Findings:');
    last.f.forEach(function (x) { t.push('- ' + x.t); });
    t.push('', '(Signature not verified; decoded in the browser.)');
    return t.join('\n');
  }

  $('analyze').addEventListener('click', analyze);
  $('sample').addEventListener('click', function () { $('input').value = sample(); analyze(); });
  $('clear').addEventListener('click', function () { $('input').value = ''; analyze(); $('input').focus(); });
  $('note').addEventListener('click', function () { if (last) OV.copy(note(), 'Ticket note copied'); });
  $('input').addEventListener('paste', function () { setTimeout(analyze, 0); });
  OV.ctrlEnter($('input'), analyze);
  window.addEventListener('pagehide', function () { $('input').value = ''; });
  var handed = OV.takeHandoff();
  if (handed) { $('input').value = handed; analyze(); }
})();
