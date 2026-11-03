// Reads tenant configuration through Microsoft Graph (read-only). Each step records what it could not read and why,
// so the report can say "needs Entra ID P1" instead of silently passing a check.
(function () {
  'use strict';
  var GRAPH_APP = '00000003-0000-0000-c000-000000000000';
  var EXO_APP = '00000002-0000-0ff1-ce00-000000000000';
  var MICROSOFT_TENANTS = ['f8cdef31-a31e-4b4a-93e4-5f571e91255a', '72f988bf-86f1-41af-91ab-2d7cd011db47', '33e01921-4d64-4f8c-a055-5bdaffd5e33d'];
  var USER_FIELDS = 'id,displayName,userPrincipalName,userType,accountEnabled,createdDateTime,assignedLicenses,onPremisesSyncEnabled,externalUserState';

  async function collect(g, onStep, opts) {
    var T = { errors: {}, steps: [], scannedAt: new Date().toISOString(), demo: !!g.demo };
    async function step(key, label, fn) {
      onStep && onStep(key, label, 'run');
      try { await fn(); T.steps.push({ key: key, label: label, ok: true }); onStep && onStep(key, label, 'ok'); }
      catch (e) {
        T.errors[key] = { status: e.status || 0, code: e.code || '', message: e.message || String(e), license: !!e.license };
        T.steps.push({ key: key, label: label, ok: false, error: T.errors[key] });
        onStep && onStep(key, label, e.license || e.status === 403 ? 'warn' : 'fail', T.errors[key]);
        if (e.status === 401) throw e;
      }
    }

    await step('org', 'Organisation and licences', async function () {
      T.org = ((await g.get('/organization?$select=id,displayName,verifiedDomains,onPremisesSyncEnabled,onPremisesLastSyncDateTime,createdDateTime')).value || [])[0] || {};
      T.skus = await g.all('/subscribedSkus?$select=skuId,skuPartNumber,capabilityStatus,consumedUnits,prepaidUnits,servicePlans');
      var plans = new Set();
      T.skus.filter(function (s) { return s.capabilityStatus === 'Enabled'; }).forEach(function (s) { (s.servicePlans || []).forEach(function (p) { if (p.provisioningStatus !== 'Disabled') plans.add(p.servicePlanName); }); });
      T.p1 = plans.has('AAD_PREMIUM') || plans.has('AAD_PREMIUM_P2');
      T.p2 = plans.has('AAD_PREMIUM_P2');
    });
    await step('domains', 'Domains', async function () {
      T.domains = await g.all('/domains?$select=id,isVerified,isDefault,authenticationType,passwordValidityPeriodInDays,supportedServices');
    });
    await step('secdef', 'Security defaults', async function () {
      T.securityDefaults = !!(await g.get('/policies/identitySecurityDefaultsEnforcementPolicy')).isEnabled;
    });
    await step('ca', 'Conditional Access policies', async function () {
      T.ca = await g.all('/identity/conditionalAccess/policies');
    });
    await step('authz', 'Authorization and consent policy', async function () {
      var a = await g.get('/policies/authorizationPolicy');
      T.authz = a.value ? a.value[0] : a;
    });
    await step('methods', 'Authentication methods policy', async function () {
      T.methodsPolicy = await g.get('/policies/authenticationMethodsPolicy');
    });
    await step('roles', 'Admin roles', async function () {
      // $expand=members stops at 20 objects, so members are read per role.
      T.roles = await g.all('/directoryRoles?$select=id,displayName,roleTemplateId');
      var sel = '?$select=id,displayName,userPrincipalName,userType,accountEnabled,onPremisesSyncEnabled,assignedLicenses';
      var res = await g.batch(T.roles.map(function (r) { return '/directoryRoles/' + r.id + '/members/microsoft.graph.user' + sel; }));
      for (var i = 0; i < T.roles.length; i++) {
        var r = T.roles[i], x = res[i];
        if (!x || x.status !== 200) throw Object.assign(new Error('Could not read members of ' + r.displayName), { status: x ? x.status : 0 });
        r.members = x.body.value || [];
        if (x.body['@odata.nextLink']) r.members = r.members.concat(await g.all(x.body['@odata.nextLink']));
      }
    });
    await step('users', 'Users and last sign-in', async function () {
      try {
        // Graph caps the page size at 120 when signInActivity is selected.
        T.users = await g.all('/users?$top=120&$select=' + USER_FIELDS + ',signInActivity', 50000);
        T.signInActivity = true;
      } catch (e) {
        if (e.status !== 403 && e.status !== 400) throw e;
        T.users = await g.all('/users?$top=999&$select=' + USER_FIELDS, 50000);
        T.signInActivity = false;
        T.errors.signin = { status: e.status, message: 'Last sign-in dates need Entra ID P1 and AuditLog.Read.All; stale-account checks are limited.', license: true };
      }
    });
    await step('mfa', 'MFA registration', async function () {
      try {
        T.mfa = (await g.all('/reports/authenticationMethods/userRegistrationDetails?$top=999', 50000)).map(function (r) {
          return { id: r.id, upn: r.userPrincipalName, isAdmin: !!r.isAdmin, mfa: !!r.isMfaRegistered, capable: !!r.isMfaCapable, passwordless: !!r.isPasswordlessCapable, methods: r.methodsRegistered || [], userType: r.userType };
        });
        T.mfaSource = 'report';
      } catch (e) {
        if (e.status !== 403 && e.status !== 400) throw e;
        // No P1: read each enabled member's methods directly (capped for very large tenants).
        var targets = (T.users || []).filter(function (u) { return u.accountEnabled && u.userType !== 'Guest'; }).slice(0, opts && opts.maxUsers || 1500);
        var res = await g.batch(targets.map(function (u) { return '/users/' + u.id + '/authentication/methods'; }), function (d, n) { onStep && onStep('mfa', 'MFA registration (' + d + '/' + n + ' users)', 'run'); });
        T.mfa = targets.map(function (u, i) {
          var r = res[i] || {};
          if (r.status !== 200) return { id: u.id, upn: u.userPrincipalName, unknown: true, methods: [] };
          var types = (r.body.value || []).map(function (m) { return String(m['@odata.type'] || '').replace('#microsoft.graph.', '').replace('AuthenticationMethod', ''); });
          var strong = types.filter(function (t) { return t !== 'password' && t !== 'email'; });
          return { id: u.id, upn: u.userPrincipalName, mfa: strong.length > 0, capable: strong.length > 0, passwordless: types.some(function (t) { return /fido2|windowsHelloForBusiness|passkey|platformCredential/i.test(t); }), methods: types, userType: 'member' };
        });
        T.mfaSource = 'methods';
        T.mfaTruncated = (T.users || []).filter(function (u) { return u.accountEnabled && u.userType !== 'Guest'; }).length > targets.length;
      }
    });
    await step('grants', 'Delegated app consents', async function () {
      T.grants = await g.all('/oauth2PermissionGrants', 20000);
      var ids = Array.from(new Set(T.grants.map(function (x) { return x.clientId; })));
      T.sps = {};
      var res = await g.batch(ids.map(function (id) { return '/servicePrincipals/' + id + '?$select=id,appId,displayName,appOwnerOrganizationId,verifiedPublisher,publisherName,servicePrincipalType,accountEnabled,createdDateTime'; }));
      ids.forEach(function (id, i) { if (res[i] && res[i].status === 200) T.sps[id] = res[i].body; });
    });
    await step('appperms', 'Application permissions', async function () {
      T.appPerms = [];
      for (var k = 0; k < 2; k++) {
        var appId = k ? EXO_APP : GRAPH_APP;
        var sp = ((await g.get("/servicePrincipals?$filter=appId eq '" + appId + "'&$select=id,displayName,appRoles")).value || [])[0];
        if (!sp) continue;
        var roles = {};
        (sp.appRoles || []).forEach(function (r) { roles[r.id] = r.value; });
        (await g.all('/servicePrincipals/' + sp.id + '/appRoleAssignedTo?$top=999')).forEach(function (a) {
          T.appPerms.push({ principalId: a.principalId, principalName: a.principalDisplayName, principalType: a.principalType, permission: roles[a.appRoleId] || a.appRoleId, resource: sp.displayName, created: a.createdDateTime });
        });
      }
      var missing = Array.from(new Set(T.appPerms.map(function (a) { return a.principalId; }))).filter(function (id) { return !(T.sps || {})[id]; });
      var res = await g.batch(missing.map(function (id) { return '/servicePrincipals/' + id + '?$select=id,appId,displayName,appOwnerOrganizationId,verifiedPublisher,publisherName,servicePrincipalType'; }));
      T.sps = T.sps || {};
      missing.forEach(function (id, i) { if (res[i] && res[i].status === 200) T.sps[id] = res[i].body; });
    });
    await step('score', 'Microsoft Secure Score', async function () {
      T.secureScore = ((await g.get('/security/secureScores?$top=1')).value || [])[0] || null;
      // Titles are a nice-to-have: keep the score even if the profiles call fails.
      if (T.secureScore) {
        try { T.scoreProfiles = await g.all('/security/secureScoreControlProfiles', 2000); } catch (e) { T.scoreProfiles = []; }
      }
    });
    await step('risky', 'Risky users', async function () {
      T.riskyUsers = await g.all("/identityProtection/riskyUsers?$filter=riskState eq 'atRisk'&$select=id,userPrincipalName,riskLevel,riskState,riskLastUpdatedDateTime", 5000);
    });
    await step('dns', 'Email authentication (SPF, DKIM, DMARC)', async function () {
      var list = (T.domains || []).filter(function (d) { return d.isVerified && !/\.onmicrosoft\.com$/i.test(d.id) && (d.supportedServices || []).indexOf('Email') >= 0; }).slice(0, 10);
      if (g.demo) { T.mail = window.OV_M365_DEMO.mail(list); return; }
      var M = window.OVMail;
      T.mail = await Promise.all(list.map(async function (d) {
        try {
          var r = await Promise.all([M.checkSpf(d.id), M.checkDmarc(d.id), M.checkDkim(d.id, 'selector1')]);
          return { domain: d.id, spf: r[0], dmarc: r[1], dkim: r[2] };
        } catch (e) { return { domain: d.id, error: e.message }; }
      }));
    });
    T.microsoftTenants = MICROSOFT_TENANTS;
    return T;
  }

  window.OVCollect = { collect: collect };
})();
