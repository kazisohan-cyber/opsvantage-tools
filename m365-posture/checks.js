// Posture checks over the collected tenant data. Each check returns pass / warn / fail / na with evidence and a fix.
(function () {
  'use strict';
  var GA = '62e90394-69f5-4237-9190-012177145e10';
  var PRIV_ROLES = {
    '62e90394-69f5-4237-9190-012177145e10': 'Global Administrator', 'e8611ab8-c189-46e8-94e1-60213ab1f814': 'Privileged Role Administrator',
    '7be44c8a-adaf-4e2a-84d6-ab2649e08a13': 'Privileged Authentication Administrator', '194ae4cb-b126-40b2-bd5b-6091b380977d': 'Security Administrator',
    '29232cdf-9323-42fd-ade2-1d097af3e4de': 'Exchange Administrator', 'f28a1f50-f6e7-4571-818b-6a12f2af6b6c': 'SharePoint Administrator',
    'fe930be7-5e62-47db-91af-98c3a49a38b1': 'User Administrator', 'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9': 'Conditional Access Administrator',
    '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3': 'Application Administrator', '158c047a-c907-4556-b7ef-446551a6b5f7': 'Cloud Application Administrator',
    'c4e39bd9-1100-46d3-8c65-fb160da0071f': 'Authentication Administrator', '729827e3-9c14-49f7-bb1b-9608f156bbb8': 'Helpdesk Administrator',
    '8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2': 'Hybrid Identity Administrator', '3a2c62db-5318-420d-8d74-23affee5d9d5': 'Intune Administrator',
    '69091246-20e8-4a56-aa4d-066075b2a7a8': 'Teams Administrator', 'b0f54661-2d74-4c50-afa3-1ec803f12efe': 'Billing Administrator'
  };
  var RISKY_SCOPES = new Set(['Mail.Read', 'Mail.ReadWrite', 'Mail.Send', 'Mail.Read.Shared', 'Mail.ReadWrite.Shared', 'Mail.Send.Shared', 'MailboxSettings.ReadWrite',
    'Files.Read.All', 'Files.ReadWrite.All', 'Sites.Read.All', 'Sites.ReadWrite.All', 'Sites.FullControl.All', 'Directory.ReadWrite.All', 'Directory.AccessAsUser.All',
    'User.ReadWrite.All', 'Group.ReadWrite.All', 'RoleManagement.ReadWrite.Directory', 'Application.ReadWrite.All', 'AppRoleAssignment.ReadWrite.All',
    'full_access_as_user', 'full_access_as_app', 'EWS.AccessAsUser.All', 'Notes.ReadWrite.All', 'Chat.Read.All', 'ChannelMessage.Read.All',
    'Policy.ReadWrite.ConditionalAccess', 'UserAuthenticationMethod.ReadWrite.All', 'Mail.ReadBasic.All']);
  var GUEST_ROLE = { 'a0b1b346-4d3e-4e8b-98f8-753987be4970': 'same as members', '10dae51f-b6af-4016-8d66-8c2a99b929b3': 'limited (default)', '2af84b1e-32c8-42b7-82bc-daa82404023b': 'restricted' };
  var WEIGHT = { crit: 10, high: 6, med: 3, low: 1 };
  var DAY = 86400e3;

  function enabled(p) { return p.state === 'enabled'; }
  function users(p) { return (p.conditions && p.conditions.users) || {}; }
  function allUsers(p) { return (users(p).includeUsers || []).indexOf('All') >= 0; }
  function grants(p) { return (p.grantControls && p.grantControls.builtInControls) || []; }
  function mfaGrant(p) { return grants(p).indexOf('mfa') >= 0 || !!(p.grantControls && p.grantControls.authenticationStrength); }
  function allApps(p) { var a = (p.conditions && p.conditions.applications) || {}; return (a.includeApplications || []).indexOf('All') >= 0; }
  function clientTypes(p) { return (p.conditions && p.conditions.clientAppTypes) || []; }
  function excluded(p) { var u = users(p); return (u.excludeUsers || []).length + (u.excludeGroups || []).length; }
  function daysAgo(iso) { var t = Date.parse(iso); return isNaN(t) ? null : Math.floor((Date.now() - t) / DAY); }
  function pct(a, b) { return b ? Math.round(a / b * 100) : 100; }

  function run(T) {
    var out = [];
    var add = function (f) { out.push(f); };
    var na = function (id, cat, sev, title, why) { add({ id: id, cat: cat, sev: sev, title: title, status: 'na', summary: why }); };
    var err = function (k) { return T.errors[k]; };
    var ca = T.ca || [];
    var caOk = !err('ca');
    var userById = {};
    (T.users || []).forEach(function (u) { userById[u.id] = u; });
    var members = (T.users || []).filter(function (u) { return u.accountEnabled && u.userType !== 'Guest'; });
    // Enabled members without a licence are mostly shared mailboxes, room and equipment accounts and service accounts.
    // Counting them as people distorts MFA and stale-account numbers, so person checks use licensed members only.
    var licensed = function (u) { return (u.assignedLicenses || []).length > 0; };
    var people = members.filter(licensed);
    var unlicensed = members.filter(function (u) { return !licensed(u); });
    if (!people.length) people = members;
    var mfaById = {};
    (T.mfa || []).forEach(function (m) { mfaById[m.id] = m; });

    // Admin role holders
    var admins = {};
    (T.roles || []).forEach(function (r) {
      (r.members || []).forEach(function (m) {
        if (!m.userPrincipalName && m['@odata.type'] && !/user/i.test(m['@odata.type'])) return;
        var a = admins[m.id] = admins[m.id] || { id: m.id, upn: m.userPrincipalName || m.displayName, name: m.displayName, userType: m.userType, enabled: m.accountEnabled !== false, synced: !!m.onPremisesSyncEnabled, licensed: (m.assignedLicenses || []).length > 0, roles: [], priv: false, ga: false };
        a.roles.push(r.displayName);
        if (PRIV_ROLES[r.roleTemplateId]) a.priv = true;
        if (r.roleTemplateId === GA) a.ga = true;
      });
    });
    var adminList = Object.keys(admins).map(function (k) { return admins[k]; }).filter(function (a) { return a.enabled; });
    var privAdmins = adminList.filter(function (a) { return a.priv; });
    var gas = adminList.filter(function (a) { return a.ga; });

    // ---------------------------------------------------------- Identity & MFA
    var mfaAll = ca.filter(function (p) { return enabled(p) && allUsers(p) && allApps(p) && mfaGrant(p); });
    if (T.securityDefaults == null && !caOk) na('mfa-baseline', 'identity', 'crit', 'MFA is enforced for every user', 'Could not read security defaults or Conditional Access.');
    else add({
      id: 'mfa-baseline', cat: 'identity', sev: 'crit', title: 'MFA is enforced for every user',
      status: T.securityDefaults || mfaAll.length ? 'pass' : 'fail',
      summary: T.securityDefaults ? 'Security defaults are on: every user must register and use MFA.'
        : mfaAll.length ? 'Conditional Access policy "' + mfaAll[0].displayName + '" requires MFA for all users and apps.'
          : 'Neither security defaults nor an enabled Conditional Access policy requires MFA for all users. One stolen password is enough to get in.',
      fix: T.p1 ? { where: 'Entra admin center > Protection > Conditional Access > Create new policy from templates > "Require multifactor authentication for all users"', steps: ['Exclude one or two break-glass accounts', 'Start in report-only for a few days, then turn it on'] }
        : { where: 'Entra admin center > Identity > Overview > Properties > Manage security defaults', steps: ['Set Security defaults to Enabled'], ps: 'Update-MgPolicyIdentitySecurityDefaultEnforcementPolicy -IsEnabled:$true' }
    });

    if (err('mfa') || !T.mfa) na('mfa-admins', 'identity', 'crit', 'Every admin has MFA registered', 'MFA registration could not be read.');
    else {
      var noMfaAdmins = privAdmins.filter(function (a) { var m = mfaById[a.id]; return m && !m.unknown && !m.mfa; });
      add({
        id: 'mfa-admins', cat: 'identity', sev: 'crit', title: 'Every admin has MFA registered',
        status: noMfaAdmins.length ? 'fail' : 'pass',
        summary: noMfaAdmins.length ? noMfaAdmins.length + ' privileged admin(s) have no MFA method registered.' : 'All ' + privAdmins.length + ' privileged admins have an MFA method registered.',
        evidence: noMfaAdmins.length ? { cols: ['Admin', 'Roles'], rows: noMfaAdmins.map(function (a) { return [a.upn, a.roles.join(', ')]; }) } : null,
        fix: { where: 'Entra admin center > Identity > Users > [admin] > Authentication methods', steps: ['Have each admin register Microsoft Authenticator or a passkey now', 'Block sign-in for admin accounts that are not in use'] }
      });
    }

    if (err('mfa') || !T.mfa) na('mfa-users', 'identity', 'high', 'Users have MFA registered', 'MFA registration could not be read.');
    else {
      var known = people.filter(function (u) { var m = mfaById[u.id]; return m && !m.unknown; });
      var missing = known.filter(function (u) { return !mfaById[u.id].mfa; });
      var p = pct(known.length - missing.length, known.length);
      add({
        id: 'mfa-users', cat: 'identity', sev: 'high', title: 'Users have MFA registered',
        status: p >= 95 ? 'pass' : p >= 80 ? 'warn' : 'fail',
        summary: p + '% of ' + known.length + ' licensed users have an MFA method (' + missing.length + ' without).' + (unlicensed.length && people !== members ? ' ' + unlicensed.length + ' unlicensed accounts (shared mailboxes, rooms, service accounts) are checked separately under Accounts & licensing.' : '') + (T.mfaTruncated ? ' Large tenant: the first 1,500 users were checked.' : ''),
        evidence: missing.length ? { cols: ['User', 'Methods'], rows: missing.slice(0, 500).map(function (u) { return [u.userPrincipalName, (mfaById[u.id].methods || []).join(', ') || 'none']; }), csv: 'users-without-mfa' } : null,
        fix: { where: 'Entra admin center > Protection > Authentication methods > Registration campaign', steps: ['Enable the registration campaign for Microsoft Authenticator', 'Follow up with the listed users'] }
      });
    }

    if (!T.methodsPolicy) na('weak-methods', 'identity', 'med', 'Phishable MFA methods are limited', 'Authentication methods policy could not be read.');
    else {
      var cfg = {};
      (T.methodsPolicy.authenticationMethodConfigurations || []).forEach(function (c) { cfg[String(c.id).toLowerCase()] = c.state; });
      var weak = ['sms', 'voice'].filter(function (k) { return cfg[k] === 'enabled'; });
      var smsOnlyAdmins = privAdmins.filter(function (a) { var m = mfaById[a.id]; return m && m.mfa && (m.methods || []).every(function (x) { return /mobilePhone|sms|voice|phone|email|password/i.test(x); }); });
      add({
        id: 'weak-methods', cat: 'identity', sev: 'med', title: 'Phishable MFA methods are limited',
        status: smsOnlyAdmins.length ? 'fail' : weak.length ? 'warn' : 'pass',
        summary: (smsOnlyAdmins.length ? smsOnlyAdmins.length + ' admin(s) rely only on SMS or phone calls. ' : '') + (weak.length ? weak.join(' and ').toUpperCase() + ' sign-in methods are enabled; they are easy to phish or SIM-swap.' : 'SMS and voice are disabled.'),
        evidence: smsOnlyAdmins.length ? { cols: ['Admin', 'Methods'], rows: smsOnlyAdmins.map(function (a) { return [a.upn, mfaById[a.id].methods.join(', ')]; }) } : null,
        fix: { where: 'Entra admin center > Protection > Authentication methods > Policies', steps: ['Move users to Microsoft Authenticator or passkeys', 'Then disable SMS and Voice call'] }
      });
      add({
        id: 'phish-resistant', cat: 'identity', sev: 'low', title: 'Phishing-resistant sign-in is available',
        status: cfg.fido2 === 'enabled' || cfg.passkey === 'enabled' ? 'pass' : 'warn',
        summary: cfg.fido2 === 'enabled' ? 'Passkeys (FIDO2) are enabled. Require them for admins with an authentication strength policy.' : 'Passkeys (FIDO2) are not enabled. They stop adversary-in-the-middle phishing that defeats push MFA.',
        fix: { where: 'Entra admin center > Protection > Authentication methods > Policies > Passkey (FIDO2)', steps: ['Enable for admins first', 'Add a Conditional Access authentication strength of "Phishing-resistant MFA" for admin roles'] }
      });
    }

    var legacyBlock = ca.filter(function (p) { var t = clientTypes(p); return enabled(p) && allUsers(p) && grants(p).indexOf('block') >= 0 && t.indexOf('exchangeActiveSync') >= 0 && t.indexOf('other') >= 0; });
    if (T.securityDefaults == null && !caOk) na('legacy-auth', 'identity', 'high', 'Legacy authentication is blocked', 'Could not read security defaults or Conditional Access.');
    else add({
      id: 'legacy-auth', cat: 'identity', sev: 'high', title: 'Legacy authentication is blocked',
      status: T.securityDefaults || legacyBlock.length ? 'pass' : 'fail',
      summary: T.securityDefaults ? 'Security defaults block legacy protocols.' : legacyBlock.length ? 'Blocked by "' + legacyBlock[0].displayName + '".' : 'Nothing blocks IMAP, POP, SMTP AUTH and other legacy protocols. They skip MFA and are the main path for password spraying.',
      fix: { where: 'Entra admin center > Protection > Conditional Access > Create new policy from templates > "Block legacy authentication"', steps: ['Check sign-in logs for legacy clients first (scanners, printers using SMTP)', 'Exclude only a dedicated service account if a device truly needs it'] }
    });

    if (!T.p2) na('risk-policies', 'identity', 'med', 'Risk-based Conditional Access', 'Needs Entra ID P2 (Microsoft 365 E5 or Entra ID P2 add-on).');
    else {
      var risk = ca.filter(function (p) { var c = p.conditions || {}; return enabled(p) && ((c.signInRiskLevels || []).length || (c.userRiskLevels || []).length); });
      add({ id: 'risk-policies', cat: 'identity', sev: 'med', title: 'Risk-based Conditional Access', status: risk.length ? 'pass' : 'warn',
        summary: risk.length ? risk.length + ' risk-based policies are enabled.' : 'The tenant has P2 but no sign-in or user risk policy. Risky sign-ins are detected but not acted on.',
        fix: { where: 'Entra admin center > Protection > Conditional Access > templates "Require MFA for risky sign-ins" and "Require password change for high-risk users"', steps: [] } });
    }

    if (err('risky')) na('risky-users', 'identity', 'high', 'No users flagged at risk', err('risky').license ? 'Needs Entra ID P2.' : 'Could not read risky users.');
    else {
      var ru = T.riskyUsers || [];
      add({ id: 'risky-users', cat: 'identity', sev: 'high', title: 'No users flagged at risk', status: ru.length ? 'fail' : 'pass',
        summary: ru.length ? ru.length + ' user(s) are flagged at risk by Entra ID Protection and not yet remediated.' : 'No users are currently at risk.',
        evidence: ru.length ? { cols: ['User', 'Risk', 'Updated'], rows: ru.map(function (r) { return [r.userPrincipalName, r.riskLevel, (r.riskLastUpdatedDateTime || '').slice(0, 10)]; }) } : null,
        fix: { where: 'Entra admin center > Protection > Identity Protection > Risky users', steps: ['Investigate each user\'s risky sign-ins', 'Reset password and revoke sessions, then confirm or dismiss the risk'] } });
    }

    // ---------------------------------------------------------- Privileged access
    if (err('roles')) na('ga-count', 'admins', 'high', '2 to 4 Global Administrators', 'Roles could not be read.');
    else {
      add({ id: 'ga-count', cat: 'admins', sev: 'high', title: '2 to 4 Global Administrators',
        status: gas.length > 4 ? 'fail' : gas.length < 2 ? 'warn' : 'pass',
        summary: gas.length + ' active Global Administrator(s).' + (gas.length > 4 ? ' Every extra Global Admin is another account that can take over the whole tenant.' : gas.length < 2 ? ' With one Global Admin there is no break-glass path if that account is locked out.' : ''),
        evidence: { cols: ['Global Administrator', 'Type', 'Synced from AD'], rows: gas.map(function (a) { return [a.upn, a.userType || 'Member', a.synced ? 'yes' : 'no']; }) },
        fix: { where: 'Entra admin center > Identity > Roles & admins > Global Administrator', steps: ['Move day-to-day admins to least-privilege roles (Exchange, User, Helpdesk Administrator)', 'Keep two cloud-only break-glass accounts'] } });
      var guestAdmins = adminList.filter(function (a) { return a.userType === 'Guest' || /#EXT#/i.test(a.upn || ''); });
      add({ id: 'admin-guests', cat: 'admins', sev: 'crit', title: 'No guest accounts hold admin roles', status: guestAdmins.length ? 'fail' : 'pass',
        summary: guestAdmins.length ? guestAdmins.length + ' guest account(s) hold admin roles. Their security depends on another organisation.' : 'No guests hold admin roles.',
        evidence: guestAdmins.length ? { cols: ['Guest', 'Roles'], rows: guestAdmins.map(function (a) { return [a.upn, a.roles.join(', ')]; }) } : null,
        fix: { where: 'Entra admin center > Identity > Roles & admins', steps: ['Remove the role, or replace with a member account or GDAP for partners'] } });
      var synced = privAdmins.filter(function (a) { return a.synced; });
      add({ id: 'admin-synced', cat: 'admins', sev: 'med', title: 'Admins are cloud-only accounts', status: synced.length ? 'warn' : 'pass',
        summary: synced.length ? synced.length + ' privileged admin(s) are synced from on-premises AD. A domain compromise would hand over the cloud too.' : 'Privileged admins are cloud-only.',
        evidence: synced.length ? { cols: ['Admin', 'Roles'], rows: synced.map(function (a) { return [a.upn, a.roles.join(', ')]; }) } : null,
        fix: { where: 'Microsoft 365 admin center > Users > Add a user', steps: ['Create cloud-only admin accounts (admin-name@tenant.onmicrosoft.com)', 'Remove roles from the synced accounts'] } });
      var licensedGa = gas.filter(function (a) { return a.licensed; });
      add({ id: 'admin-licensed', cat: 'admins', sev: 'low', title: 'Global Admins are separate from daily-use accounts', status: licensedGa.length ? 'warn' : 'pass',
        summary: licensedGa.length ? licensedGa.length + ' Global Admin(s) have licences, so they probably read email and browse with full admin rights.' : 'Global Admin accounts carry no licences.',
        evidence: licensedGa.length ? { cols: ['Global Administrator'], rows: licensedGa.map(function (a) { return [a.upn]; }) } : null,
        fix: { where: 'Microsoft 365 admin center > Users', steps: ['Give each admin a separate, unlicensed admin account', 'Keep the licensed mailbox account as a normal user'] } });
    }

    // ---------------------------------------------------------- Apps & consent
    var az = T.authz;
    if (!az) na('user-consent', 'apps', 'high', 'Users cannot consent to risky apps', 'Authorization policy could not be read.');
    else {
      var pol = ((az.defaultUserRolePermissions || {}).permissionGrantPoliciesAssigned || []).join(' ');
      var legacy = /microsoft-user-default-legacy/.test(pol), low = /microsoft-user-default-low/.test(pol);
      add({ id: 'user-consent', cat: 'apps', sev: 'high', title: 'Users cannot consent to risky apps', status: legacy ? 'fail' : 'pass',
        summary: legacy ? 'Any user can grant any third-party app access to their mail and files. This is how consent-phishing attacks take over mailboxes without a password.' : low ? 'Users can consent only to low-risk permissions from verified publishers.' : 'User consent is disabled; admins approve apps.',
        fix: { where: 'Entra admin center > Identity > Applications > Enterprise applications > Consent and permissions > User consent settings', steps: ['Choose "Allow user consent for apps from verified publishers, for selected permissions" or "Do not allow user consent"', 'Turn on the admin consent workflow so users can request apps'] } });
      var canCreate = (az.defaultUserRolePermissions || {}).allowedToCreateApps;
      add({ id: 'users-create-apps', cat: 'apps', sev: 'low', title: 'Users cannot register applications', status: canCreate ? 'warn' : 'pass',
        summary: canCreate ? 'Any user can register app registrations, which can be abused for persistence.' : 'Only admins can register apps.',
        fix: { where: 'Entra admin center > Identity > Users > User settings', steps: ['Set "Users can register applications" to No'], ps: 'Update-MgPolicyAuthorizationPolicy -DefaultUserRolePermissions @{ AllowedToCreateApps = $false }' } });
    }

    // First-party apps live in several Microsoft tenants; a verified "Microsoft Corporation" publisher cannot be faked.
    function isMs(sp) { return !!sp && (T.microsoftTenants.indexOf(sp.appOwnerOrganizationId) >= 0 || (sp.verifiedPublisher && sp.verifiedPublisher.displayName === 'Microsoft Corporation')); }
    function verified(sp) { return !!(sp && sp.verifiedPublisher && sp.verifiedPublisher.displayName); }
    if (err('grants')) na('risky-delegated', 'apps', 'high', 'Third-party apps with access to mail and files', 'App consents could not be read.');
    else {
      var byApp = {};
      (T.grants || []).forEach(function (gr) {
        var sp = T.sps[gr.clientId];
        if (isMs(sp)) return;
        var risky = String(gr.scope || '').split(/\s+/).filter(function (s) { return RISKY_SCOPES.has(s); });
        if (!risky.length) return;
        var a = byApp[gr.clientId] = byApp[gr.clientId] || { sp: sp, scopes: new Set(), users: 0, all: false };
        risky.forEach(function (s) { a.scopes.add(s); });
        if (gr.consentType === 'AllPrincipals') a.all = true; else a.users++;
      });
      var apps = Object.keys(byApp).map(function (k) { return byApp[k]; });
      var unverified = apps.filter(function (a) { return !verified(a.sp); });
      add({ id: 'risky-delegated', cat: 'apps', sev: 'high', title: 'Third-party apps with access to mail and files', status: unverified.length ? 'fail' : apps.length ? 'warn' : 'pass',
        summary: apps.length ? apps.length + ' non-Microsoft app(s) hold delegated access to mail, files or the directory' + (unverified.length ? ', ' + unverified.length + ' from unverified publishers.' : '. All have verified publishers; confirm each is still needed.') : 'No third-party app holds high-risk delegated permissions.',
        evidence: apps.length ? { cols: ['App', 'Publisher', 'Permissions', 'Granted to'], rows: apps.map(function (a) { return [(a.sp && a.sp.displayName) || 'Unknown app', verified(a.sp) ? a.sp.verifiedPublisher.displayName + ' (verified)' : ((a.sp && a.sp.publisherName) || '?') + ' (unverified)', Array.from(a.scopes).join(', '), a.all ? 'All users (admin consent)' : a.users + ' user(s)']; }) } : null,
        fix: { where: 'Entra admin center > Enterprise applications > [app] > Permissions', steps: ['Revoke apps nobody recognises; check sign-in logs for the app first', 'For consent phishing, also reset the affected users\' sessions'] } });
    }
    if (err('appperms')) na('risky-app-perms', 'apps', 'high', 'Apps with tenant-wide application permissions', 'Application permissions could not be read.');
    else {
      var byPrincipal = {};
      (T.appPerms || []).forEach(function (a) {
        var sp = T.sps[a.principalId];
        if (isMs(sp) || !RISKY_SCOPES.has(a.permission)) return;
        var x = byPrincipal[a.principalId] = byPrincipal[a.principalId] || { name: a.principalName, sp: sp, perms: new Set() };
        x.perms.add(a.permission);
      });
      var list = Object.keys(byPrincipal).map(function (k) { return byPrincipal[k]; });
      add({ id: 'risky-app-perms', cat: 'apps', sev: 'high', title: 'Apps with tenant-wide application permissions', status: list.some(function (x) { return !verified(x.sp); }) ? 'fail' : list.length ? 'warn' : 'pass',
        summary: list.length ? list.length + ' app(s) can read or change data across the whole tenant without any user signed in. A leaked app secret here is a full breach.' : 'No third-party app holds high-risk application permissions.',
        evidence: list.length ? { cols: ['App', 'Publisher', 'Application permissions'], rows: list.map(function (x) { return [x.name, verified(x.sp) ? x.sp.verifiedPublisher.displayName + ' (verified)' : 'unverified', Array.from(x.perms).join(', ')]; }) } : null,
        fix: { where: 'Entra admin center > Enterprise applications > [app] > Permissions', steps: ['Confirm the vendor and owner of each app', 'Scope Exchange access with RBAC for Applications instead of tenant-wide Mail permissions', 'Rotate secrets and prefer certificates'] } });
    }

    // ---------------------------------------------------------- External access
    if (az) {
      var gr2 = az.guestUserRoleId;
      add({ id: 'guest-access', cat: 'external', sev: 'med', title: 'Guest directory access is limited', status: gr2 === 'a0b1b346-4d3e-4e8b-98f8-753987be4970' ? 'fail' : 'pass',
        summary: 'Guest access level: ' + (GUEST_ROLE[gr2] || 'unknown') + '.' + (gr2 === 'a0b1b346-4d3e-4e8b-98f8-753987be4970' ? ' Guests can enumerate every user, group and app.' : ''),
        fix: { where: 'Entra admin center > Identity > External Identities > External collaboration settings', steps: ['Set Guest user access to "restricted to properties and memberships of their own directory objects"'] } });
      add({ id: 'guest-invites', cat: 'external', sev: 'low', title: 'Only admins and inviters can invite guests', status: az.allowInvitesFrom === 'everyone' ? 'warn' : 'pass',
        summary: 'Guest invitations allowed from: ' + (az.allowInvitesFrom || 'unknown') + '.',
        fix: { where: 'Entra admin center > Identity > External Identities > External collaboration settings', steps: ['Set "Guest invite settings" to "Only users assigned to specific admin roles can invite guest users"'] } });
    }
    if (T.signInActivity) {
      var staleGuests = (T.users || []).filter(function (u) { if (u.userType !== 'Guest' || !u.accountEnabled) return false; var d = daysAgo((u.signInActivity || {}).lastSignInDateTime); return d == null ? daysAgo(u.createdDateTime) > 90 : d > 90; });
      add({ id: 'stale-guests', cat: 'external', sev: 'low', title: 'No stale guest accounts', status: staleGuests.length ? 'warn' : 'pass',
        summary: staleGuests.length ? staleGuests.length + ' guest(s) have not signed in for 90+ days.' : 'Every enabled guest signed in within 90 days.',
        evidence: staleGuests.length ? { cols: ['Guest', 'Last sign-in'], rows: staleGuests.slice(0, 300).map(function (u) { return [u.userPrincipalName, ((u.signInActivity || {}).lastSignInDateTime || 'never').slice(0, 10)]; }) } : null,
        fix: { where: 'Entra admin center > Identity Governance > Access reviews', steps: ['Remove guests who no longer need access, or set up a quarterly access review'] } });
    }

    // ---------------------------------------------------------- Conditional Access hygiene
    if (caOk && ca.length) {
      var reportOnly = ca.filter(function (p) { return p.state === 'enabledForReportingButNotEnforced'; });
      add({ id: 'ca-report-only', cat: 'ca', sev: 'low', title: 'No policies stuck in report-only', status: reportOnly.length ? 'warn' : 'pass',
        summary: reportOnly.length ? reportOnly.length + ' policy(ies) are report-only and protect nothing yet.' : 'All policies are enforced or deliberately off.',
        evidence: reportOnly.length ? { cols: ['Policy'], rows: reportOnly.map(function (p) { return [p.displayName]; }) } : null,
        fix: { where: 'Entra admin center > Protection > Conditional Access > Policies', steps: ['Review the report-only results, then switch each policy to On'] } });
      var bigExcl = mfaAll.filter(function (p) { return excluded(p) > 5; });
      var noBreakGlass = mfaAll.length && mfaAll.every(function (p) { return excluded(p) === 0; });
      if (!mfaAll.length) na('ca-exclusions', 'ca', 'med', 'MFA policy exclusions are minimal', 'No enforced all-user MFA policy to review yet.');
      else add({ id: 'ca-exclusions', cat: 'ca', sev: 'med', title: 'MFA policy exclusions are minimal', status: bigExcl.length ? 'warn' : noBreakGlass ? 'warn' : 'pass',
        summary: bigExcl.length ? '"' + bigExcl[0].displayName + '" excludes ' + excluded(bigExcl[0]) + ' users or groups. Attackers look for exactly these accounts.' : noBreakGlass ? 'The MFA policy excludes nobody, so there is no break-glass account if MFA or Conditional Access breaks.' : 'Exclusions look minimal.',
        fix: { where: 'Entra admin center > Protection > Conditional Access > [policy] > Users > Exclude', steps: ['Keep only break-glass accounts excluded', 'Monitor break-glass sign-ins with an alert'] } });
    }

    // ---------------------------------------------------------- Accounts & licensing
    if (T.signInActivity) {
      var stale = people.filter(function (u) { var d = daysAgo((u.signInActivity || {}).lastSignInDateTime); return d == null ? daysAgo(u.createdDateTime) > 30 : d > 90; });
      add({ id: 'stale-users', cat: 'hygiene', sev: 'med', title: 'No stale enabled accounts', status: stale.length > Math.max(2, people.length * 0.05) ? 'warn' : 'pass',
        summary: stale.length ? stale.length + ' licensed user account(s) have not signed in for 90+ days (or never). Leavers\' accounts are easy targets.' : 'All licensed users signed in within 90 days.',
        evidence: stale.length ? { cols: ['User', 'Last sign-in', 'Licensed'], rows: stale.slice(0, 500).map(function (u) { return [u.userPrincipalName, ((u.signInActivity || {}).lastSignInDateTime || 'never').slice(0, 10), (u.assignedLicenses || []).length ? 'yes' : 'no']; }), csv: 'stale-accounts' } : null,
        fix: { where: 'Microsoft 365 admin center > Users > Active users', steps: ['Block sign-in for leavers, convert their mailboxes to shared if needed, then remove licences'] } });
    } else na('stale-users', 'hygiene', 'med', 'No stale enabled accounts', 'Last sign-in dates need Entra ID P1.');
    if (people !== members) {
      var lastIn = function (u) { return ((u.signInActivity || {}).lastSignInDateTime || '').slice(0, 10); };
      var unlicSorted = unlicensed.slice().sort(function (a, b) { return lastIn(b).localeCompare(lastIn(a)); });
      var recent = T.signInActivity ? unlicensed.filter(function (u) { var d = daysAgo((u.signInActivity || {}).lastSignInDateTime); return d != null && d <= 90; }) : [];
      add({ id: 'unlicensed-signin', cat: 'hygiene', sev: 'med', title: 'Shared mailboxes and resource accounts cannot sign in', status: unlicensed.length ? 'warn' : 'pass',
        summary: unlicensed.length ? unlicensed.length + ' enabled account(s) have no licence. These are usually shared mailboxes, rooms and service accounts, and each one has a password that works until sign-in is blocked.' + (T.signInActivity ? ' ' + recent.length + ' of them signed in during the last 90 days.' : '') : 'Every enabled member account has a licence.',
        evidence: unlicensed.length ? { cols: ['Account', 'Last sign-in', 'MFA registered', 'Synced from AD'], rows: unlicSorted.slice(0, 500).map(function (u) { var m = mfaById[u.id]; return [u.userPrincipalName, T.signInActivity ? (lastIn(u) || 'never') : 'unknown', m ? (m.unknown ? 'unknown' : m.mfa ? 'yes' : 'no') : 'not checked', u.onPremisesSyncEnabled ? 'yes' : 'no']; }), csv: 'unlicensed-enabled-accounts' } : null,
        fix: { where: 'Microsoft 365 admin center > Users > Active users > [account] > Block sign-in (for synced accounts, disable them in on-premises AD)', steps: ['Block sign-in for shared mailboxes, rooms and equipment; people with delegated access keep using the mailbox', 'Keep sign-in only for service accounts that need it', 'For accounts that signed in recently, find out who uses them before blocking'] } });
    }
    var disabledLicensed = (T.users || []).filter(function (u) { return !u.accountEnabled && (u.assignedLicenses || []).length; });
    add({ id: 'disabled-licensed', cat: 'hygiene', sev: 'low', title: 'Disabled accounts do not hold licences', status: disabledLicensed.length ? 'warn' : 'pass',
      summary: disabledLicensed.length ? disabledLicensed.length + ' disabled account(s) still hold licences you are paying for.' : 'No disabled accounts hold licences.',
      evidence: disabledLicensed.length ? { cols: ['User', 'Licences'], rows: disabledLicensed.slice(0, 300).map(function (u) { return [u.userPrincipalName, String(u.assignedLicenses.length)]; }) } : null,
      fix: { where: 'Microsoft 365 admin center > Users > [user] > Licenses and apps', steps: ['Remove licences (convert to a shared mailbox first if the mail must stay)'] } });
    if (T.org && T.org.onPremisesSyncEnabled) {
      var age = T.org.onPremisesLastSyncDateTime ? Math.round((Date.now() - Date.parse(T.org.onPremisesLastSyncDateTime)) / 3600e3) : null;
      add({ id: 'dir-sync', cat: 'hygiene', sev: 'med', title: 'Directory sync is healthy', status: age == null || age > 72 ? 'fail' : age > 3 ? 'warn' : 'pass',
        summary: age == null ? 'Sync is enabled but has never reported.' : 'Last sync ' + age + ' hour(s) ago.' + (age > 3 ? ' Leavers disabled on-premises stay active in the cloud until sync runs.' : ''),
        fix: { where: 'Entra admin center > Identity > Hybrid management > Microsoft Entra Connect', steps: ['Check the Entra Connect server and the ADSync service'] } });
    }
    var expiring = (T.domains || []).filter(function (d) { return d.isVerified && d.passwordValidityPeriodInDays && d.passwordValidityPeriodInDays < 2147483647; });
    if (T.domains) add({ id: 'password-expiry', cat: 'hygiene', sev: 'low', title: 'Passwords do not expire (with MFA in place)', status: expiring.length ? 'warn' : 'pass',
      summary: expiring.length ? 'Password expiry is ' + expiring[0].passwordValidityPeriodInDays + ' days. Forced rotation leads to weaker passwords; Microsoft and NIST recommend no expiry once MFA is enforced.' : 'Passwords are set to never expire.',
      fix: { where: 'Microsoft 365 admin center > Settings > Org settings > Security & privacy > Password expiration policy', steps: ['Set passwords to never expire after MFA is enforced for everyone'] } });

    // ---------------------------------------------------------- Email domains
    if (T.mail && T.mail.length) {
      var rows = [], worst = 'pass';
      T.mail.forEach(function (m) {
        if (m.error) { rows.push([m.domain, 'error', 'error', 'error']); return; }
        var dm = m.dmarc.policy || 'none', enforcing = (dm === 'reject' || dm === 'quarantine') && m.dmarc.pct === 100;
        var spf = m.spf.records.length ? (m.spf.state === 'pass' ? 'ok' : 'weak') : 'missing';
        var dk = m.dkim.found.some(function (f) { return !f.key.revoked; }) ? 'ok' : 'not found';
        if (!m.dmarc.records.length || !m.spf.records.length) worst = 'fail'; else if (!enforcing || spf !== 'ok' || dk !== 'ok') worst = worst === 'fail' ? 'fail' : 'warn';
        rows.push([m.domain, spf, m.dmarc.records.length ? 'p=' + dm + (m.dmarc.pct < 100 ? ' pct=' + m.dmarc.pct : '') : 'missing', dk]);
      });
      add({ id: 'mail-auth', cat: 'mail', sev: 'high', title: 'Email domains cannot be spoofed', status: worst,
        summary: worst === 'pass' ? 'Every email domain has SPF, DKIM and an enforcing DMARC policy.' : worst === 'fail' ? 'At least one email domain is missing SPF or DMARC, so anyone can send mail as it.' : 'Some domains are not fully enforced (DMARC p=none, weak SPF or no DKIM).',
        evidence: { cols: ['Domain', 'SPF', 'DMARC', 'DKIM'], rows: rows },
        fix: { where: 'tools.opsvantage.net/dmarc-checker for exact records; DKIM: Defender portal > Email & collaboration > Policies > Email authentication settings > DKIM', steps: ['Publish SPF ending in -all', 'Enable DKIM for each domain', 'Move DMARC from p=none to quarantine, then reject'] } });
    }

    return out;
  }

  function score(findings) {
    var total = 0, earned = 0, cats = {};
    findings.forEach(function (f) {
      if (f.status === 'na') return;
      var w = WEIGHT[f.sev] || 1, e = f.status === 'pass' ? w : f.status === 'warn' ? w / 2 : 0;
      total += w; earned += e;
      var c = cats[f.cat] = cats[f.cat] || { total: 0, earned: 0 };
      c.total += w; c.earned += e;
    });
    var s = total ? Math.round(earned / total * 100) : 0;
    Object.keys(cats).forEach(function (k) { cats[k].pct = Math.round(cats[k].earned / cats[k].total * 100); });
    return { score: s, grade: s >= 90 ? 'A' : s >= 75 ? 'B' : s >= 60 ? 'C' : s >= 40 ? 'D' : 'F', cats: cats };
  }

  window.OVChecks = { run: run, score: score, PRIV_ROLES: PRIV_ROLES };
})();
