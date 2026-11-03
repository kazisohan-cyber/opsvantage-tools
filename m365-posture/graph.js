// Read-only Microsoft Graph client: paging, $batch, throttling retries. In demo mode it answers from OV_M365_DEMO.
(function () {
  'use strict';
  var BASE = 'https://graph.microsoft.com/';

  function GraphError(status, code, message, path) {
    var e = new Error(message || ('Graph request failed (' + status + ')'));
    e.status = status; e.code = code || ''; e.path = path;
    // Premium-only APIs answer 403 with a licensing message; surface that clearly.
    e.license = /premium|license|P1|P2|not have.*licen|Authentication_RequestFromNonPremiumTenantOrB2CTenant/i.test(String(code) + ' ' + String(message));
    return e;
  }

  function sleep(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }

  function Client(session, demo) {
    this.session = session; this.demo = demo; this.calls = 0;
  }

  Client.prototype.req = async function (method, path, body) {
    var url = /^https:/.test(path) ? path : BASE + (path.charAt(0) === '/' ? 'v1.0' + path : path);
    if (url.indexOf(BASE) !== 0) throw GraphError(0, 'BadUrl', 'Refusing to call a non-Graph URL', path);
    if (this.demo) {
      await sleep(40);
      var d = window.OV_M365_DEMO.answer(method, url.slice(BASE.length), body);
      if (d && d.__error) throw GraphError(d.__error, d.code, d.message, path);
      return d;
    }
    if (Date.now() > this.session.expires - 30e3) throw GraphError(401, 'TokenExpired', 'Your sign-in expired. Sign in again to rescan.', path);
    for (var attempt = 0; attempt < 5; attempt++) {
      this.calls++;
      var r = await fetch(url, {
        method: method,
        headers: Object.assign({ authorization: 'Bearer ' + this.session.token, accept: 'application/json' }, body ? { 'content-type': 'application/json' } : {}),
        body: body ? JSON.stringify(body) : undefined
      });
      if (r.status === 429 || r.status === 503 || r.status === 504) {
        var wait = Math.min(Number(r.headers.get('retry-after')) || Math.pow(2, attempt), 30);
        await sleep(wait * 1000);
        continue;
      }
      var j = await r.json().catch(function () { return {}; });
      if (!r.ok) throw GraphError(r.status, j.error && j.error.code, j.error && j.error.message, path);
      return j;
    }
    throw GraphError(429, 'Throttled', 'Microsoft Graph kept throttling the scan. Wait a minute and rescan.', path);
  };

  Client.prototype.get = function (path) { return this.req('GET', path); };

  Client.prototype.all = async function (path, cap) {
    var out = [], next = path, max = cap || 20000;
    while (next && out.length < max) {
      var j = await this.get(next);
      out = out.concat(j.value || []);
      next = j['@odata.nextLink'];
    }
    return out.slice(0, max);
  };

  // Runs GETs through /$batch, 20 at a time. Returns results in input order: { status, body }.
  Client.prototype.batch = async function (paths, onProgress) {
    var results = new Array(paths.length);
    for (var i = 0; i < paths.length; i += 20) {
      var chunk = paths.slice(i, i + 20);
      var pending = chunk.map(function (p, k) { return { id: String(i + k), method: 'GET', url: p }; });
      for (var attempt = 0; attempt < 4 && pending.length; attempt++) {
        var res = await this.req('POST', 'v1.0/$batch', { requests: pending });
        var retry = [], wait = 0;
        (res.responses || []).forEach(function (x) {
          if (x.status === 429 || x.status === 503) {
            retry.push(pending.find(function (p) { return p.id === x.id; }));
            wait = Math.max(wait, Number((x.headers || {})['Retry-After']) || 2);
          } else results[Number(x.id)] = { status: x.status, body: x.body };
        });
        pending = retry.filter(Boolean);
        if (pending.length) await sleep(Math.min(wait, 30) * 1000);
      }
      pending.forEach(function (p) { results[Number(p.id)] = { status: 429, body: null }; });
      if (onProgress) onProgress(Math.min(i + 20, paths.length), paths.length);
    }
    return results;
  };

  window.OVGraph = { Client: Client };
})();
