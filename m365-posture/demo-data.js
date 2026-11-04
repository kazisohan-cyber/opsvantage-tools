// Fictional demo tenant ("Contoso Dental Group") answering the same Graph calls the scanner makes.
// Lets people see a full report without signing in. All names, IDs and domains are made up.
(function () {
  'use strict';
  var NOW = Date.now(), DAY = 86400e3;
  var iso = function (daysAgo) { return new Date(NOW - daysAgo * DAY).toISOString(); };
  var GA = '62e90394-69f5-4237-9190-012177145e10';
  var SPB = { skuId: 'cbdc14ab-d96c-4c30-b9f4-6ada7cdc1d46' };

  var people = ['amelia.tan', 'ben.okafor', 'chloe.ng', 'daniel.lim', 'emma.wong', 'farah.aziz', 'george.lee', 'hana.kim', 'ivan.petrov', 'jia.chen',
    'kevin.raj', 'lina.ho', 'marcus.teo', 'nora.ali', 'oscar.diaz', 'priya.nair', 'quinn.foo', 'rachel.goh', 'sam.chua', 'tara.singh',
    'umar.khan', 'vera.lim', 'will.tan', 'xin.yi', 'yusuf.osman', 'zoe.koh', 'reception', 'billing', 'clinic.east', 'clinic.west',
    'dr.patel', 'dr.morgan', 'it.admin', 'practice.manager', 'hr', 'scanner', 'old.locum', 'intern2024'];
  var users = people.map(function (p, i) {
    var stale = p === 'old.locum' || p === 'intern2024' || p === 'clinic.west';
    return {
      id: 'u' + i, displayName: p.replace('.', ' '), userPrincipalName: p + '@contosodental.com', userType: 'Member', accountEnabled: true,
      createdDateTime: iso(400 + i), assignedLicenses: p === 'scanner' || p === 'billing' || p === 'clinic.west' ? [] : [SPB], onPremisesSyncEnabled: i % 3 === 0,
      signInActivity: { lastSignInDateTime: p === 'intern2024' ? null : iso(stale ? 140 + i : i % 9) }
    };
  });
  users.push({ id: 'u90', displayName: 'Former Hygienist', userPrincipalName: 'f.hygienist@contosodental.com', userType: 'Member', accountEnabled: false, createdDateTime: iso(900), assignedLicenses: [SPB], signInActivity: { lastSignInDateTime: iso(200) } });
  users.push({ id: 'u91', displayName: 'Former Nurse', userPrincipalName: 'f.nurse@contosodental.com', userType: 'Member', accountEnabled: false, createdDateTime: iso(800), assignedLicenses: [SPB], signInActivity: { lastSignInDateTime: iso(160) } });
  users.push({ id: 'g1', displayName: 'IT Partner', userPrincipalName: 'support_itpartner.example#EXT#@contosodental.onmicrosoft.com', userType: 'Guest', accountEnabled: true, createdDateTime: iso(700), assignedLicenses: [], signInActivity: { lastSignInDateTime: iso(12) } });
  users.push({ id: 'g2', displayName: 'Lab Supplier', userPrincipalName: 'orders_dentallab.example#EXT#@contosodental.onmicrosoft.com', userType: 'Guest', accountEnabled: true, createdDateTime: iso(500), assignedLicenses: [], signInActivity: { lastSignInDateTime: iso(210) } });
  users.push({ id: 'g3', displayName: 'Auditor', userPrincipalName: 'jane_audit.example#EXT#@contosodental.onmicrosoft.com', userType: 'Guest', accountEnabled: true, createdDateTime: iso(300), assignedLicenses: [], signInActivity: { lastSignInDateTime: null } });
  var byUpn = {};
  users.forEach(function (u) { byUpn[u.userPrincipalName.split('@')[0]] = u; });

  var noMfa = ['dr.patel', 'reception', 'billing', 'clinic.east', 'clinic.west', 'old.locum', 'intern2024', 'hr', 'quinn.foo', 'scanner', 'umar.khan'];
  var smsOnly = ['practice.manager', 'tara.singh'];
  var registration = users.filter(function (u) { return u.userType === 'Member' && u.accountEnabled; }).map(function (u) {
    var k = u.userPrincipalName.split('@')[0];
    var methods = noMfa.indexOf(k) >= 0 ? [] : smsOnly.indexOf(k) >= 0 ? ['mobilePhone'] : k === 'it.admin' ? ['microsoftAuthenticatorPush', 'fido2SecurityKey'] : ['microsoftAuthenticatorPush'];
    return { id: u.id, userPrincipalName: u.userPrincipalName, isAdmin: ['dr.patel', 'it.admin', 'practice.manager', 'dr.morgan'].indexOf(k) >= 0, isMfaRegistered: methods.length > 0, isMfaCapable: methods.length > 0, isPasswordlessCapable: k === 'it.admin', methodsRegistered: methods, userType: 'member' };
  });

  var roles = [
    { id: 'r1', displayName: 'Global Administrator', roleTemplateId: GA, members: ['dr.patel', 'it.admin', 'practice.manager', 'dr.morgan', 'support_itpartner.example#EXT#'] },
    { id: 'r2', displayName: 'Exchange Administrator', roleTemplateId: '29232cdf-9323-42fd-ade2-1d097af3e4de', members: ['it.admin'] },
    { id: 'r3', displayName: 'Helpdesk Administrator', roleTemplateId: '729827e3-9c14-49f7-bb1b-9608f156bbb8', members: ['amelia.tan'] }
  ];

  var sps = {
    'sp-mailsync': { id: 'sp-mailsync', appId: 'a1', displayName: 'Mail Sync Pro', appOwnerOrganizationId: '0f1e2d3c-0000-4000-8000-000000000001', verifiedPublisher: {}, publisherName: 'MailSyncPro Ltd' },
    'sp-signflow': { id: 'sp-signflow', appId: 'a2', displayName: 'SignFlow', appOwnerOrganizationId: '0f1e2d3c-0000-4000-8000-000000000002', verifiedPublisher: { displayName: 'SignFlow Inc.' } },
    'sp-backup': { id: 'sp-backup', appId: 'a3', displayName: 'BackupVault Cloud', appOwnerOrganizationId: '0f1e2d3c-0000-4000-8000-000000000003', verifiedPublisher: { displayName: 'BackupVault' } },
    'sp-relay': { id: 'sp-relay', appId: 'a4', displayName: 'Legacy Scanner Relay', appOwnerOrganizationId: 'demo-tenant', verifiedPublisher: {} },
    'sp-teams': { id: 'sp-teams', appId: 'a5', displayName: 'Microsoft Teams', appOwnerOrganizationId: 'f8cdef31-a31e-4b4a-93e4-5f571e91255a', verifiedPublisher: { displayName: 'Microsoft Corporation' } }
  };

  var profiles = [
    ['MFARegistrationV2', 'Ensure all users can complete multifactor authentication', 9], ['BlockLegacyAuthentication', 'Enable policy to block legacy authentication', 8],
    ['AdminMFAV2', 'Require MFA for administrative roles', 10], ['OneAdmin', 'Designate more than one global admin', 1], ['IntegratedApps', 'Do not allow users to grant consent to unreliable applications', 4],
    ['SelfServicePasswordReset', 'Enable self-service password reset', 1], ['PWAgePolicyNew', 'Set the password expiration policy to never expire', 8], ['RoleOverlap', 'Use least privileged administrative roles', 1],
    ['mdo_safelinksforemail', 'Ensure Safe Links for email is enabled', 9], ['mdo_atpprotection', 'Turn on Safe Attachments in block mode', 8]
  ].map(function (p, i) { return { id: p[0], title: p[1], maxScore: p[2], rank: i + 1, userImpact: 'Low', implementationCost: 'Low', service: /^mdo/.test(p[0]) ? 'MDO' : 'AzureAD' }; });
  var controlScores = { MFARegistrationV2: 6.4, BlockLegacyAuthentication: 0, AdminMFAV2: 7.5, OneAdmin: 1, IntegratedApps: 0, SelfServicePasswordReset: 1, PWAgePolicyNew: 0, RoleOverlap: 0, mdo_safelinksforemail: 0, mdo_atpprotection: 9 };

  function member(k) {
    var u = byUpn[k];
    return { id: u.id, displayName: u.displayName, userPrincipalName: u.userPrincipalName, userType: u.userType, accountEnabled: u.accountEnabled, onPremisesSyncEnabled: !!u.onPremisesSyncEnabled, assignedLicenses: u.assignedLicenses };
  }
  var err = function (status, code, message) { return { __error: status, code: code, message: message }; };

  function answer(method, path, body) {
    var p = path.replace(/^v1\.0\//, ''), base = decodeURIComponent(p.split('?')[0]);
    if (base === '$batch') return { responses: body.requests.map(function (r) { var a = answer('GET', 'v1.0' + r.url); return a && a.__error ? { id: r.id, status: a.__error, body: { error: { code: a.code, message: a.message } } } : { id: r.id, status: 200, body: a }; }) };
    var m;
    if (base === 'organization') return { value: [{ id: 'demo-tenant', displayName: 'Contoso Dental Group', verifiedDomains: [{ name: 'contosodental.com', isDefault: true }], onPremisesSyncEnabled: true, onPremisesLastSyncDateTime: iso(5), createdDateTime: iso(1500) }] };
    if (base === 'subscribedSkus') return { value: [
      { skuId: SPB.skuId, skuPartNumber: 'SPB', capabilityStatus: 'Enabled', consumedUnits: 39, prepaidUnits: { enabled: 45 }, servicePlans: [{ servicePlanName: 'AAD_PREMIUM', provisioningStatus: 'Success' }, { servicePlanName: 'EXCHANGE_S_STANDARD', provisioningStatus: 'Success' }] },
      { skuId: 'x2', skuPartNumber: 'EXCHANGESTANDARD', capabilityStatus: 'Enabled', consumedUnits: 2, prepaidUnits: { enabled: 5 }, servicePlans: [] },
      { skuId: 'x3', skuPartNumber: 'FLOW_FREE', capabilityStatus: 'Enabled', consumedUnits: 6, prepaidUnits: { enabled: 10000 }, servicePlans: [] }] };
    if (base === 'domains') return { value: [
      { id: 'contosodental.com', isVerified: true, isDefault: true, authenticationType: 'Managed', passwordValidityPeriodInDays: 90, supportedServices: ['Email', 'OfficeCommunicationsOnline'] },
      { id: 'contoso-dental.co', isVerified: true, isDefault: false, authenticationType: 'Managed', passwordValidityPeriodInDays: 90, supportedServices: ['Email'] },
      { id: 'contosodental.onmicrosoft.com', isVerified: true, isDefault: false, authenticationType: 'Managed', passwordValidityPeriodInDays: 90, supportedServices: ['Email'] }] };
    if (base === 'policies/identitySecurityDefaultsEnforcementPolicy') return { isEnabled: false };
    if (base === 'identity/conditionalAccess/policies') return { value: [
      { id: 'ca1', displayName: 'Require MFA - all users', state: 'enabledForReportingButNotEnforced', conditions: { users: { includeUsers: ['All'], excludeUsers: ['u26', 'u27', 'u28', 'u29', 'u34', 'u35', 'u30', 'u36'] }, applications: { includeApplications: ['All'] }, clientAppTypes: ['all'] }, grantControls: { builtInControls: ['mfa'] } },
      { id: 'ca2', displayName: 'Require MFA for admins', state: 'enabled', conditions: { users: { includeRoles: [GA], includeUsers: [] }, applications: { includeApplications: ['All'] }, clientAppTypes: ['all'] }, grantControls: { builtInControls: ['mfa'] } }] };
    if (base === 'policies/authorizationPolicy') return { allowInvitesFrom: 'everyone', guestUserRoleId: '10dae51f-b6af-4016-8d66-8c2a99b929b3', defaultUserRolePermissions: { allowedToCreateApps: true, permissionGrantPoliciesAssigned: ['ManagePermissionGrantsForSelf.microsoft-user-default-legacy'] } };
    if (base === 'policies/authenticationMethodsPolicy') return { authenticationMethodConfigurations: [{ id: 'Sms', state: 'enabled' }, { id: 'Voice', state: 'disabled' }, { id: 'Fido2', state: 'disabled' }, { id: 'MicrosoftAuthenticator', state: 'enabled' }, { id: 'Email', state: 'enabled' }] };
    if (base === 'directoryRoles') return { value: roles.map(function (r) { return { id: r.id, displayName: r.displayName, roleTemplateId: r.roleTemplateId }; }) };
    if ((m = base.match(/^directoryRoles\/(\w+)\/members/))) { var role = roles.find(function (r) { return r.id === m[1]; }); return { value: role.members.map(member) }; }
    if (base === 'users') return { value: users };
    if (base === 'reports/authenticationMethods/userRegistrationDetails') return { value: registration };
    if ((m = base.match(/^users\/(\w+)\/authentication\/methods$/))) {
      var reg = registration.find(function (r) { return r.id === m[1]; }) || { methodsRegistered: [] };
      var type = { microsoftAuthenticatorPush: 'microsoftAuthenticator', mobilePhone: 'phone', fido2SecurityKey: 'fido2' };
      return { value: [{ '@odata.type': '#microsoft.graph.passwordAuthenticationMethod' }].concat(reg.methodsRegistered.map(function (x) { return { '@odata.type': '#microsoft.graph.' + (type[x] || x) + 'AuthenticationMethod' }; })) };
    }
    if (base === 'oauth2PermissionGrants') return { value: [
      { clientId: 'sp-mailsync', consentType: 'Principal', principalId: 'u4', scope: 'openid offline_access Mail.ReadWrite Mail.Send' },
      { clientId: 'sp-mailsync', consentType: 'Principal', principalId: 'u11', scope: 'openid offline_access Mail.ReadWrite Mail.Send' },
      { clientId: 'sp-mailsync', consentType: 'Principal', principalId: 'u19', scope: 'openid offline_access Mail.ReadWrite' },
      { clientId: 'sp-signflow', consentType: 'AllPrincipals', principalId: null, scope: 'User.Read Files.ReadWrite.All' },
      { clientId: 'sp-teams', consentType: 'AllPrincipals', principalId: null, scope: 'Files.ReadWrite.All Sites.ReadWrite.All' }] };
    if ((m = base.match(/^servicePrincipals\/([\w-]+)$/))) return sps[m[1]] || err(404, 'Request_ResourceNotFound', 'Not found');
    if (base === 'servicePrincipals') {
      return /00000003-0000-0000-c000-000000000000/.test(p)
        ? { value: [{ id: 'sp-graph', displayName: 'Microsoft Graph', appRoles: [{ id: 'r-mailrw', value: 'Mail.ReadWrite' }, { id: 'r-files', value: 'Files.ReadWrite.All' }, { id: 'r-userread', value: 'User.Read.All' }] }] }
        : { value: [{ id: 'sp-exo', displayName: 'Office 365 Exchange Online', appRoles: [{ id: 'r-fullapp', value: 'full_access_as_app' }] }] };
    }
    if (base === 'servicePrincipals/sp-graph/appRoleAssignedTo') return { value: [
      { principalId: 'sp-backup', principalDisplayName: 'BackupVault Cloud', principalType: 'ServicePrincipal', appRoleId: 'r-mailrw', createdDateTime: iso(300) },
      { principalId: 'sp-backup', principalDisplayName: 'BackupVault Cloud', principalType: 'ServicePrincipal', appRoleId: 'r-files', createdDateTime: iso(300) },
      { principalId: 'sp-teams', principalDisplayName: 'Microsoft Teams', principalType: 'ServicePrincipal', appRoleId: 'r-userread', createdDateTime: iso(900) }] };
    if (base === 'servicePrincipals/sp-exo/appRoleAssignedTo') return { value: [{ principalId: 'sp-relay', principalDisplayName: 'Legacy Scanner Relay', principalType: 'ServicePrincipal', appRoleId: 'r-fullapp', createdDateTime: iso(600) }] };
    if (base === 'security/secureScores') return { value: [{ currentScore: 24.9, maxScore: 59, createdDateTime: iso(0), averageComparativeScores: [{ basis: 'AllTenants', averageScore: 41.2 }], controlScores: Object.keys(controlScores).map(function (k) { return { controlName: k, score: controlScores[k] }; }) }] };
    if (base === 'security/secureScoreControlProfiles') return { value: profiles };
    if (base === 'identityProtection/riskyUsers') return err(403, 'Forbidden', 'Your tenant is not licensed for this feature (Microsoft Entra ID P2 required).');
    return err(404, 'NotFound', 'Demo tenant has no data for ' + base);
  }

  // DNS results for the demo domains, in the same shape as OVMail.
  function mail(list) {
    return list.map(function (d) {
      if (d.id === 'contosodental.com') return { domain: d.id,
        spf: { records: ['v=spf1 include:spf.protection.outlook.com include:servers.mcsv.net ~all'], state: 'pass', score: 20, lookups: 4 },
        dmarc: { records: ['v=DMARC1; p=none; rua=mailto:dmarc@contosodental.com'], policy: 'none', pct: 100 },
        dkim: { found: [{ selector: 'selector1', key: { label: 'RSA ~2048-bit', bits: 2048 } }] } };
      return { domain: d.id, spf: { records: [], state: 'fail', score: 0 }, dmarc: { records: [], policy: '', pct: 100 }, dkim: { found: [] } };
    });
  }

  window.OV_M365_DEMO = { answer: answer, mail: mail };
})();
