// Microsoft identity platform sign-in: authorization code flow with PKCE, no library.
// The access token is kept in memory only; nothing about the session is written to storage except the
// one-time PKCE verifier, which lives in sessionStorage for the duration of the redirect.
(function () {
  'use strict';
  var CFG = window.OV_M365_CONFIG || {};
  var AUTHORITY = 'https://login.microsoftonline.com/organizations/oauth2/v2.0/';
  var GRAPH = 'https://graph.microsoft.com/';
  var SCOPES = ['openid', 'profile'].concat([
    'User.Read', 'Directory.Read.All', 'Policy.Read.All', 'AuditLog.Read.All', 'UserAuthenticationMethod.Read.All',
    'SecurityEvents.Read.All', 'IdentityRiskyUser.Read.All'
  ].map(function (s) { return GRAPH + s; }));
  var KEY = 'ov.m365.pkce';

  function b64url(buf) {
    var bytes = new Uint8Array(buf), s = '';
    for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  function random(n) { var a = new Uint8Array(n); crypto.getRandomValues(a); return b64url(a); }
  async function challenge(verifier) { return b64url(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))); }
  function redirectUri() { return location.origin + location.pathname; }
  function claims(jwt) {
    try {
      var p = jwt.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
      return JSON.parse(decodeURIComponent(atob(p).split('').map(function (c) { return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2); }).join('')));
    } catch (e) { return {}; }
  }

  function friendly(code, desc) {
    var d = String(desc || '');
    var aad = (d.match(/AADSTS\d+/) || [])[0] || '';
    var map = {
      AADSTS65001: 'This tenant has not consented to the scanner yet. A Global Administrator needs to grant admin consent once (use the admin consent link below).',
      AADSTS90094: 'Admin consent is required. Ask a Global Administrator to grant consent with the admin consent link below.',
      AADSTS90008: 'Admin consent is required for this tenant.',
      AADSTS50105: 'Your account is not assigned to the scanner app in this tenant.',
      AADSTS700016: 'The scanner app is not available in this tenant. Check the client ID in config.js.',
      AADSTS50011: 'The redirect URI is not registered on the app. Add this page\'s URL as a Single-page application redirect URI.',
      AADSTS9002326: 'The redirect URI must be registered as a Single-page application (not Web) platform.',
      AADSTS50020: 'Personal Microsoft accounts are not supported. Sign in with a work account.'
    };
    var e = new Error(map[aad] || (code === 'access_denied' ? 'Sign-in was cancelled or consent was declined.' : (d.split('\r\n')[0] || code || 'Sign-in failed.')));
    e.code = aad || code;
    e.needsConsent = /AADSTS(65001|90094|90008)/.test(aad) || code === 'consent_required';
    return e;
  }

  async function signIn(hint) {
    if (!CFG.clientId) throw new Error('Sign-in is not configured yet. Use the demo tenant, or set the client ID in config.js.');
    var verifier = random(48), state = random(16);
    sessionStorage.setItem(KEY, JSON.stringify({ v: verifier, s: state, t: Date.now() }));
    var q = new URLSearchParams({
      client_id: CFG.clientId, response_type: 'code', redirect_uri: redirectUri(), response_mode: 'fragment',
      scope: SCOPES.join(' '), state: state, code_challenge: await challenge(verifier), code_challenge_method: 'S256', prompt: 'select_account'
    });
    if (hint) q.set('login_hint', hint);
    location.assign(AUTHORITY + 'authorize?' + q.toString());
  }

  // Returns a session after the redirect back from Microsoft, or null when the page was opened normally.
  async function completeSignIn() {
    var h = new URLSearchParams(location.hash.replace(/^#/, ''));
    if (!h.get('code') && !h.get('error')) return null;
    history.replaceState(null, '', location.pathname + location.search);
    var saved = null;
    try { saved = JSON.parse(sessionStorage.getItem(KEY) || 'null'); } catch (e) { /* treated as missing */ }
    sessionStorage.removeItem(KEY);
    if (h.get('error')) throw friendly(h.get('error'), h.get('error_description'));
    if (!saved || saved.s !== h.get('state') || Date.now() - saved.t > 15 * 60e3) throw new Error('The sign-in response did not match this browser session. Please sign in again.');
    var r = await fetch(AUTHORITY + 'token', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ client_id: CFG.clientId, grant_type: 'authorization_code', code: h.get('code'), redirect_uri: redirectUri(), code_verifier: saved.v, scope: SCOPES.join(' ') })
    });
    var j = await r.json().catch(function () { return {}; });
    if (!r.ok || !j.access_token) throw friendly(j.error, j.error_description);
    var c = claims(j.id_token || '');
    return { token: j.access_token, expires: Date.now() + (Number(j.expires_in) || 3600) * 1000, tenantId: c.tid || '', user: c.preferred_username || c.upn || '', name: c.name || '' };
  }

  function adminConsentUrl(tenant) {
    var t = String(tenant || 'organizations').trim() || 'organizations';
    return 'https://login.microsoftonline.com/' + encodeURIComponent(t) + '/v2.0/adminconsent?' + new URLSearchParams({
      client_id: CFG.clientId, scope: GRAPH + '.default', redirect_uri: redirectUri(), state: 'adminconsent'
    }).toString();
  }

  window.OVAuth = { signIn: signIn, completeSignIn: completeSignIn, adminConsentUrl: adminConsentUrl, configured: !!CFG.clientId, SCOPES: SCOPES };
})();
