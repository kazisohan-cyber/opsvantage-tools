// M365 Posture Scanner page: sign-in or demo, run the collection, render the report and exports.
(function () {
  'use strict';
  var OV = window.OV, A = window.OVAuth, C = window.OVChecks;
  var $ = function (id) { return document.getElementById(id); };
  var esc = OV.esc;
  var BRAND_KEY = 'ov.m365.brand';
  var CATS = { identity: 'Identity & MFA', admins: 'Privileged access', apps: 'Apps & consent', external: 'Guests & external access', ca: 'Conditional Access hygiene', hygiene: 'Accounts & licensing', mail: 'Email domains' };
  var SEV = { crit: 'Critical', high: 'High', med: 'Medium', low: 'Low' };
  var STATUS = { fail: 'Fail', warn: 'Warning', pass: 'Pass', na: 'Not checked' };
  var SKU = {
    SPB: 'Microsoft 365 Business Premium', O365_BUSINESS_PREMIUM: 'Microsoft 365 Business Standard', O365_BUSINESS_ESSENTIALS: 'Microsoft 365 Business Basic',
    O365_BUSINESS: 'Microsoft 365 Apps for business', SPE_E3: 'Microsoft 365 E3', SPE_E5: 'Microsoft 365 E5', ENTERPRISEPACK: 'Office 365 E3', ENTERPRISEPREMIUM: 'Office 365 E5',
    STANDARDPACK: 'Office 365 E1', SPE_F1: 'Microsoft 365 F3', DESKLESSPACK: 'Office 365 F3', EXCHANGESTANDARD: 'Exchange Online (Plan 1)', EXCHANGEENTERPRISE: 'Exchange Online (Plan 2)',
    AAD_PREMIUM: 'Microsoft Entra ID P1', AAD_PREMIUM_P2: 'Microsoft Entra ID P2', EMS: 'Enterprise Mobility + Security E3', EMSPREMIUM: 'Enterprise Mobility + Security E5',
    DEVELOPERPACK_E5: 'Microsoft 365 E5 Developer', POWER_BI_STANDARD: 'Power BI (free)', FLOW_FREE: 'Power Automate (free)', TEAMS_EXPLORATORY: 'Teams Exploratory',
    MICROSOFT_BUSINESS_CENTER: 'Microsoft Business Center', WINDOWS_STORE: 'Windows Store for Business', Microsoft_Teams_Exploratory_Dept: 'Teams Exploratory',
    Microsoft_365_E3: 'Microsoft 365 E3 (no Teams)', Microsoft_365_E5: 'Microsoft 365 E5 (no Teams)', O365_w_o_Teams_Bundle_E3: 'Office 365 E3 (no Teams)',
    SPE_E3_USGOV_GCCHIGH: 'Microsoft 365 E3 (GCC High)', SPE_F5_SECCOMP: 'Microsoft 365 F5 Security + Compliance', IDENTITY_THREAT_PROTECTION: 'Microsoft 365 E5 Security',
    Microsoft_Teams_Premium: 'Teams Premium', MCOEV: 'Teams Phone Standard', MCOMEETADV: 'Microsoft 365 Audio Conferencing', MCOPSTN1: 'Teams Domestic Calling Plan',
    Microsoft_Teams_Rooms_Pro: 'Teams Rooms Pro', Microsoft_Teams_Rooms_Basic: 'Teams Rooms Basic', PHONESYSTEM_VIRTUALUSER: 'Teams Phone Resource Account (free)',
    PROJECTPROFESSIONAL: 'Project Plan 3', PROJECTPREMIUM: 'Project Plan 5', PROJECT_P1: 'Project Plan 1', VISIOCLIENT: 'Visio Plan 2', VISIOONLINE_PLAN1: 'Visio Plan 1',
    POWER_BI_PRO: 'Power BI Pro', PBI_PREMIUM_PER_USER: 'Power BI Premium Per User', POWERAPPS_PER_USER: 'Power Apps Premium', FLOW_PER_USER: 'Power Automate Premium',
    POWERAPPS_DEV: 'Power Apps Developer (free)', POWERAPPS_VIRAL: 'Power Apps trial (free)', POWER_PAGES_VTRIAL_FOR_MAKERS: 'Power Pages trial (free)',
    CCIBOTS_PRIVPREV_VIRAL: 'Copilot Studio trial (free)', STREAM: 'Microsoft Stream trial', FORMS_PRO: 'Dynamics 365 Customer Voice trial', RIGHTSMANAGEMENT_ADHOC: 'Rights Management ad hoc (free)',
    DYN365_ENTERPRISE_SALES: 'Dynamics 365 Sales Enterprise', DYN365_ENTERPRISE_CUSTOMER_SERVICE: 'Dynamics 365 Customer Service Enterprise', DYN365_TEAM_MEMBERS: 'Dynamics 365 Team Members',
    INTUNE_A: 'Microsoft Intune Plan 1', ATP_ENTERPRISE: 'Defender for Office 365 (Plan 1)', THREAT_INTELLIGENCE: 'Defender for Office 365 (Plan 2)',
    WIN_DEF_ATP: 'Defender for Endpoint P2', MDATP_XPLAT: 'Defender for Endpoint P2', DEFENDER_ENDPOINT_P1: 'Defender for Endpoint P1', Win10_VDA_E3: 'Windows Enterprise E3', WIN10_VDA_E5: 'Windows Enterprise E5',
    EXCHANGEDESKLESS: 'Exchange Online Kiosk', EXCHANGEARCHIVE_ADDON: 'Exchange Online Archiving', Microsoft_365_Copilot: 'Microsoft 365 Copilot'
  };
  // Free, trial and self-service ("viral") SKUs come with huge or arbitrary seat counts. Their unused seats are not money spent,
  // so the licence table shows them last and without an unused figure.
  var FREE_SKU = /^(POWER_BI_STANDARD|FLOW_FREE|TEAMS_EXPLORATORY|Microsoft_Teams_Exploratory_Dept|POWERAPPS_DEV|POWERAPPS_VIRAL|POWER_PAGES_VTRIAL_FOR_MAKERS|CCIBOTS_PRIVPREV_VIRAL|STREAM|FORMS_PRO|RIGHTSMANAGEMENT_ADHOC|MICROSOFT_BUSINESS_CENTER|WINDOWS_STORE|PHONESYSTEM_VIRTUALUSER|DEVELOPERPACK_E5)$|_VIRAL$|TRIAL|_FREE$/i;
  function freeSku(s) { return FREE_SKU.test(s.skuPartNumber || '') || ((s.prepaidUnits || {}).enabled || 0) >= 10000; }
  var EXO_SCRIPT = [
    '# OpsVantage: read-only Exchange Online checks Graph cannot see.',
    '# Install-Module ExchangeOnlineManagement -Scope CurrentUser ; Connect-ExchangeOnline',
    '"== Mailboxes forwarding mail outside =="',
    'Get-Mailbox -ResultSize Unlimited | Where-Object { $_.ForwardingSmtpAddress -or $_.ForwardingAddress } |',
    '  Select-Object UserPrincipalName, ForwardingSmtpAddress, ForwardingAddress, DeliverToMailboxAndForward | Format-Table -AutoSize',
    '"== Inbox rules that forward, redirect or delete =="',
    'Get-Mailbox -ResultSize Unlimited -RecipientTypeDetails UserMailbox,SharedMailbox | ForEach-Object {',
    '  Get-InboxRule -Mailbox $_.UserPrincipalName -ErrorAction SilentlyContinue |',
    '    Where-Object { $_.ForwardTo -or $_.ForwardAsAttachmentTo -or $_.RedirectTo -or $_.DeleteMessage -or $_.MoveToFolder -match "RSS|Archive|Conversation History" } |',
    '    Select-Object MailboxOwnerId, Name, Enabled, ForwardTo, RedirectTo, DeleteMessage, MoveToFolder',
    '} | Format-Table -AutoSize',
    '"== Automatic external forwarding (should be Off) =="',
    'Get-HostedOutboundSpamFilterPolicy | Select-Object Name, AutoForwardingMode | Format-Table -AutoSize',
    '"== SMTP AUTH (should be disabled tenant-wide) =="',
    'Get-TransportConfig | Select-Object SmtpClientAuthenticationDisabled',
    '"== Audit logging (should be on) =="',
    'Get-AdminAuditLogConfig | Select-Object UnifiedAuditLogIngestionEnabled',
    'Get-OrganizationConfig | Select-Object AuditDisabled',
    '"== Shared mailboxes that can sign in (should be blocked) =="',
    'Get-User -RecipientTypeDetails SharedMailbox -ResultSize Unlimited | Where-Object { -not $_.AccountDisabled } | Select-Object UserPrincipalName',
    '"== External sender tag in Outlook =="',
    'Get-ExternalInOutlook | Select-Object Enabled',
    '"== DKIM signing per domain =="',
    'Get-DkimSigningConfig | Select-Object Domain, Enabled | Format-Table -AutoSize'
  ].join('\n');

  var state = { T: null, findings: null, score: null, session: null };

  // ---------------------------------------------------------------- scan ---

  function stepUi(key, label, status, error) {
    var li = document.querySelector('#steps [data-k="' + key + '"]');
    if (!li) { li = document.createElement('li'); li.dataset.k = key; $('steps').appendChild(li); }
    var icon = { run: '<span class="spin"></span>', ok: '<span class="pill pass">done</span>', warn: '<span class="pill warn">limited</span>', fail: '<span class="pill fail">error</span>' }[status];
    li.innerHTML = icon + ' <span>' + esc(label) + '</span>' + (error ? '<span class="sub" style="margin:0 0 0 6px;font-size:.78rem">' + esc(error.license ? 'needs a higher licence' : (error.status === 403 ? 'no permission' : error.message)) + '</span>' : '');
  }

  async function scan(client, who) {
    $('connect').hidden = true; $('report').hidden = true; $('progress').hidden = false;
    $('steps').innerHTML = '';
    $('scan-who').textContent = who;
    try {
      var T = await window.OVCollect.collect(client, stepUi, {});
      state.T = T;
      state.findings = C.run(T);
      state.score = C.score(state.findings);
      render();
      $('progress').hidden = true; $('report').hidden = false;
      $('report').scrollIntoView({ behavior: 'smooth', block: 'start' });
    } catch (e) {
      $('steps').insertAdjacentHTML('beforeend', '<li><span class="pill fail">stopped</span> ' + esc(e.message) + '</li>');
      $('progress').insertAdjacentHTML('beforeend', '<div class="row-actions"><button class="btn btn-ghost btn-sm" type="button" data-act="restart">Back</button></div>');
    }
  }

  // ---------------------------------------------------------------- render ---

  function brand() { try { return localStorage.getItem(BRAND_KEY) || ''; } catch (e) { return ''; } }

  function table(ev) {
    if (!ev || !ev.rows || !ev.rows.length) return '';
    var more = ev.rows.length > 25;
    return '<div class="table-wrap"><table class="data"><thead><tr>' + ev.cols.map(function (c) { return '<th>' + esc(c) + '</th>'; }).join('') + '</tr></thead><tbody>' +
      ev.rows.slice(0, 25).map(function (r) { return '<tr>' + r.map(function (c, i) { return '<td' + (i === 0 ? ' class="mono"' : '') + '>' + esc(c) + '</td>'; }).join('') + '</tr>'; }).join('') +
      '</tbody></table></div>' + (more ? '<p class="sub" style="font-size:.8rem">Showing 25 of ' + ev.rows.length + '. Download the CSV for the full list.</p>' : '');
  }

  function findingHtml(f) {
    var cls = f.status === 'fail' ? 'fail' : f.status === 'warn' ? 'warn' : f.status === 'pass' ? 'pass' : '';
    var body = '<p>' + esc(f.summary) + '</p>';
    if (f.evidence || f.fix) {
      body += '<details' + (f.status === 'fail' && f.sev === 'crit' ? ' open' : '') + '><summary>' + (f.status === 'pass' ? 'Details' : 'Evidence and fix') + '</summary>' + table(f.evidence);
      if (f.fix && f.status !== 'pass') {
        body += '<div class="fix"><b>How to fix</b><p class="sub" style="margin:6px 0 0;font-size:.86rem">' + esc(f.fix.where) + '</p>' +
          (f.fix.steps && f.fix.steps.length ? '<ul class="fix-steps">' + f.fix.steps.map(function (s) { return '<li>' + esc(s) + '</li>'; }).join('') + '</ul>' : '') +
          (f.fix.ps ? '<div class="record">' + esc(f.fix.ps) + '</div><button class="copy" type="button" data-value="' + esc(f.fix.ps) + '">Copy PowerShell</button>' : '') + '</div>';
      }
      body += '</details>';
    }
    return '<div class="finding status-' + f.status + '" data-id="' + f.id + '"><div class="finding-h"><span class="pill ' + cls + '">' + STATUS[f.status] + '</span>' +
      '<span class="sev ' + f.sev + '">' + SEV[f.sev] + '</span><b>' + esc(f.title) + '</b></div>' + body + '</div>';
  }

  function render() {
    var T = state.T, F = state.findings, S = state.score;
    var org = T.org || {};
    var defDomain = ((T.domains || []).find(function (d) { return d.isDefault; }) || {}).id || ((org.verifiedDomains || []).find(function (d) { return d.isDefault; }) || {}).name || '';
    var count = function (s) { return F.filter(function (f) { return f.status === s; }).length; };
    var by = brand();
    var date = new Date(T.scannedAt).toLocaleString();

    var html = '<section class="panel report-head">' +
      '<div class="rh-top"><div><div class="eyebrow" style="margin-bottom:8px">Microsoft 365 security posture' + (T.demo ? ' · demo tenant' : '') + '</div>' +
      '<h2 style="font-size:1.6rem">' + esc(org.displayName || 'Tenant') + '</h2>' +
      '<p class="sub" style="margin-top:4px">' + esc(defDomain) + ' · scanned ' + esc(date) + (state.session && state.session.user ? ' by ' + esc(state.session.user) : '') + '</p>' +
      (by ? '<p class="sub" style="margin-top:2px">Prepared by <b style="color:var(--text)">' + esc(by) + '</b></p>' : '') + '</div>' +
      '<div class="grade-box"><div class="grade ' + S.grade + '">' + S.grade + '</div><div class="mono" style="text-align:center;margin-top:6px">' + S.score + '/100</div></div></div>' +
      '<div class="stats" style="margin-top:16px">' +
      '<div class="stat"><b style="color:var(--bad)">' + count('fail') + '</b><span>failed</span></div>' +
      '<div class="stat"><b style="color:var(--amber)">' + count('warn') + '</b><span>warnings</span></div>' +
      '<div class="stat"><b style="color:var(--live)">' + count('pass') + '</b><span>passed</span></div>' +
      '<div class="stat"><b>' + count('na') + '</b><span>not checked</span></div>' +
      '<div class="stat"><b>' + (T.users || []).filter(function (u) { return u.accountEnabled && u.userType !== 'Guest'; }).length + '</b><span>active users</span></div>' +
      '<div class="stat"><b>' + (T.p2 ? 'P2' : T.p1 ? 'P1' : 'None') + '</b><span>Entra ID licence</span></div></div>' +
      '<div class="posture-viz">' + (window.OVCharts ? '<div class="posture-radar">' + window.OVCharts.radar(Object.keys(CATS).filter(function (k) { return S.cats[k]; }).map(function (k) {
        return { label: ({ identity: 'Identity & MFA', admins: 'Admins', apps: 'Apps', external: 'Guests', ca: 'Cond. Access', hygiene: 'Accounts', mail: 'Email' })[k] || CATS[k], value: S.cats[k].pct };
      }), { label: 'Security posture by category' }) + '<p class="sub" style="font-size:.74rem;text-align:center;margin:2px 0 0;max-width:none">Dashed ring: 80%, a reasonable target for each area</p></div>' : '') +
      '<div class="cats">' + Object.keys(CATS).filter(function (k) { return S.cats[k]; }).map(function (k) {
        var p = S.cats[k].pct, col = p >= 80 ? 'var(--live)' : p >= 50 ? 'var(--amber)' : '#ef4444';
        return '<div class="cat"><div class="cat-h"><span>' + CATS[k] + '</span><span class="mono">' + p + '%</span></div><div class="bar"><i style="width:' + p + '%;background:' + col + '"></i></div></div>';
      }).join('') + '</div></div>' +
      '<div class="row-actions no-print">' +
      '<button class="btn btn-primary btn-sm" type="button" data-act="print">Print / save PDF</button>' +
      '<button class="btn btn-ghost btn-sm" type="button" data-act="summary">Copy summary</button>' +
      '<button class="btn btn-ghost btn-sm" type="button" data-act="csv">Download CSV</button>' +
      '<button class="btn btn-ghost btn-sm" type="button" data-act="json">Download JSON</button>' +
      '<button class="btn btn-ghost btn-sm" type="button" data-act="restart">New scan</button></div></section>';

    var top = F.filter(function (f) { return f.status === 'fail' && (f.sev === 'crit' || f.sev === 'high'); });
    if (top.length) html += '<section class="panel"><h2 style="font-size:1.1rem;margin-bottom:10px">Fix these first</h2><ol class="priorities">' +
      top.map(function (f) { return '<li><span class="sev ' + f.sev + '">' + SEV[f.sev] + '</span> <a href="#f-' + f.id + '">' + esc(f.title) + '</a><span class="sub" style="display:block;margin:2px 0 0;font-size:.84rem">' + esc(f.summary) + '</span></li>'; }).join('') + '</ol></section>';

    var order = { fail: 0, warn: 1, na: 2, pass: 3 }, sevOrder = { crit: 0, high: 1, med: 2, low: 3 };
    Object.keys(CATS).forEach(function (k) {
      var list = F.filter(function (f) { return f.cat === k; }).sort(function (a, b) { return order[a.status] - order[b.status] || sevOrder[a.sev] - sevOrder[b.sev]; });
      if (!list.length) return;
      html += '<section class="panel"><div class="panel-h"><h2>' + CATS[k] + '</h2>' + (S.cats[k] ? '<span class="mono" style="color:var(--muted)">' + S.cats[k].pct + '%</span>' : '') + '</div>' +
        list.map(function (f) { return findingHtml(f).replace('data-id="' + f.id + '"', 'data-id="' + f.id + '" id="f-' + f.id + '"'); }).join('') + '</section>';
    });

    var ss = T.secureScore;
    if (ss) {
      var prof = {};
      (T.scoreProfiles || []).forEach(function (p) { prof[p.id] = p; });
      var gaps = (ss.controlScores || []).map(function (c) { var p = prof[c.controlName]; return p ? { title: p.title, gap: (p.maxScore || 0) - (c.score || 0), max: p.maxScore, url: p.actionUrl, service: p.service } : null; })
        .filter(function (x) { return x && x.gap > 0.5; }).sort(function (a, b) { return b.gap - a.gap; }).slice(0, 8);
      var avg = (ss.averageComparativeScores || []).find(function (a) { return a.basis === 'AllTenants'; });
      var sp = Math.round(ss.currentScore / ss.maxScore * 100);
      html += '<section class="panel"><div class="panel-h"><h2>Microsoft Secure Score</h2><span class="mono">' + sp + '% (' + Math.round(ss.currentScore) + ' / ' + Math.round(ss.maxScore) + ')</span></div>' +
        '<div class="bar" style="height:10px"><i style="width:' + sp + '%;background:' + (sp >= 70 ? 'var(--live)' : sp >= 45 ? 'var(--amber)' : '#ef4444') + '"></i></div>' +
        (avg ? '<p class="sub" style="font-size:.84rem">Average across all tenants: ' + Math.round(avg.averageScore / ss.maxScore * 100) + '%.</p>' : '') +
        (gaps.length ? '<h3 style="font-family:var(--display);font-size:.95rem;margin:14px 0 8px">Biggest point gains</h3>' + table({ cols: ['Improvement action', 'Points available', 'Area'], rows: gaps.map(function (g) { return [g.title, '+' + (Math.round(g.gap * 10) / 10), g.service || '']; }) }) : '') + '</section>';
    }

    if ((T.skus || []).length) {
      var skus = T.skus.filter(function (s) { return (s.prepaidUnits || {}).enabled; })
        .sort(function (a, b) { return (freeSku(a) ? 1 : 0) - (freeSku(b) ? 1 : 0) || (b.consumedUnits || 0) - (a.consumedUnits || 0); });
      html += '<section class="panel"><div class="panel-h"><h2>Licences</h2></div>' + table({ cols: ['Licence', 'Assigned', 'Purchased', 'Unused'], rows: skus.map(function (s) {
        var tot = s.prepaidUnits.enabled, free = freeSku(s), name = SKU[s.skuPartNumber] || s.skuPartNumber;
        if (free && !/free|trial/i.test(name)) name += ' (free or trial)';
        return [name, String(s.consumedUnits), free ? '-' : String(tot), free ? '-' : String(Math.max(0, tot - s.consumedUnits))];
      }) }) + (skus.some(freeSku) ? '<p class="sub" style="font-size:.84rem;margin-top:8px">Free and trial licences are listed last; their seat counts are not purchases, so no unused figure is shown.</p>' : '') + '</section>';
    }

    html += '<section class="panel no-print"><div class="panel-h"><h2>Exchange Online checks</h2><button class="copy" type="button" data-value="' + esc(EXO_SCRIPT) + '">Copy script</button></div>' +
      '<p class="sub" style="margin:0 0 10px">Mailbox forwarding, inbox rules, SMTP AUTH and audit settings are not exposed in Microsoft Graph. Run this read-only script in Exchange Online PowerShell to finish the review.</p>' +
      '<pre class="script">' + esc(EXO_SCRIPT) + '</pre></section>';

    html += '<section class="panel"><details><summary style="font-family:var(--display);font-weight:600">Scan log (' + T.steps.filter(function (s) { return s.ok; }).length + '/' + T.steps.length + ' data sources read)</summary><ul class="reasons" style="margin-top:10px">' +
      T.steps.map(function (s) { return '<li class="' + (s.ok ? 'good' : s.error.license ? 'warn' : 'bad') + '">' + esc(s.label) + (s.ok ? '' : ': ' + esc(s.error.license ? 'not available with this tenant\'s licences' : s.error.message)) + '</li>'; }).join('') +
      (T.errors.signin ? '<li class="warn">' + esc(T.errors.signin.message) + '</li>' : '') +
      '<li>MFA data source: ' + (T.mfaSource === 'report' ? 'authentication methods registration report' : 'per-user authentication methods') + '</li></ul></details></section>';

    $('report').innerHTML = html;
  }

  // ---------------------------------------------------------------- exports ---

  function summaryText() {
    var T = state.T, S = state.score, F = state.findings;
    var lines = ['Microsoft 365 security posture: ' + ((T.org || {}).displayName || 'tenant'), 'Grade ' + S.grade + ' (' + S.score + '/100), scanned ' + new Date(T.scannedAt).toISOString().slice(0, 10) + (brand() ? ', prepared by ' + brand() : ''), ''];
    ['fail', 'warn'].forEach(function (st) {
      var list = F.filter(function (f) { return f.status === st; });
      if (!list.length) return;
      lines.push(st === 'fail' ? 'FAILED' : 'WARNINGS');
      list.forEach(function (f) { lines.push('- [' + SEV[f.sev] + '] ' + f.title + ': ' + f.summary); });
      lines.push('');
    });
    lines.push('Passed: ' + F.filter(function (f) { return f.status === 'pass'; }).map(function (f) { return f.title; }).join('; '));
    return lines.join('\n');
  }

  function csvText() {
    var rows = [['category', 'check', 'severity', 'status', 'item', 'details']];
    state.findings.forEach(function (f) {
      if (f.evidence && f.evidence.rows && f.evidence.rows.length && f.status !== 'pass') f.evidence.rows.forEach(function (r) { rows.push([CATS[f.cat], f.title, SEV[f.sev], STATUS[f.status], r[0], r.slice(1).join(' | ')]); });
      else rows.push([CATS[f.cat], f.title, SEV[f.sev], STATUS[f.status], '', f.summary]);
    });
    return rows.map(function (r) { return r.map(OV.csvCell).join(','); }).join('\r\n');
  }

  function fileBase() { return ((state.T.org || {}).displayName || 'tenant').replace(/[^\w-]+/g, '-').toLowerCase() + '-m365-posture-' + state.T.scannedAt.slice(0, 10); }

  function act(name) {
    if (name === 'print') {
      var opened = [];
      document.querySelectorAll('#report details:not([open])').forEach(function (d) { d.open = true; opened.push(d); });
      window.print();
      opened.forEach(function (d) { d.open = false; });
    } else if (name === 'summary') OV.copy(summaryText(), 'Summary copied');
    else if (name === 'csv') OV.download(fileBase() + '.csv', csvText(), 'text/csv');
    else if (name === 'json') OV.download(fileBase() + '.json', JSON.stringify({ tenant: (state.T.org || {}).displayName, tenantId: (state.T.org || {}).id, scannedAt: state.T.scannedAt, preparedBy: brand(), score: state.score, findings: state.findings, scanLog: state.T.steps }, null, 2), 'application/json');
    else if (name === 'restart') { state.session = null; $('report').hidden = true; $('progress').hidden = true; $('connect').hidden = false; window.scrollTo({ top: 0 }); }
  }

  // ---------------------------------------------------------------- wiring ---

  function showAuthError(e) {
    var box = $('auth-error');
    box.hidden = false;
    box.innerHTML = '<b>Sign-in problem.</b> ' + esc(e.message) + (e.needsConsent && A.configured ? '<div class="row-actions"><input class="input" id="consent-tenant" placeholder="tenant domain, e.g. contoso.onmicrosoft.com" style="flex:1;min-width:220px;padding:7px 10px;font-size:13px"><a class="btn btn-ghost btn-sm" id="consent-link" href="' + esc(A.adminConsentUrl()) + '">Open admin consent</a></div>' : '');
    var t = $('consent-tenant');
    if (t) t.addEventListener('input', function () { $('consent-link').href = A.adminConsentUrl(t.value); });
  }

  document.addEventListener('click', function (e) {
    var b = e.target.closest('[data-act]');
    if (b) { act(b.dataset.act); return; }
    var c = e.target.closest('#report .copy');
    if (c) OV.copy(c.dataset.value, 'Copied');
  });
  $('signin').addEventListener('click', function () { A.signIn().catch(showAuthError); });
  $('demo').addEventListener('click', function () { state.session = null; scan(new window.OVGraph.Client(null, true), 'Contoso Dental Group (demo)'); });
  $('brand').value = brand();
  $('brand').addEventListener('input', function () { try { localStorage.setItem(BRAND_KEY, $('brand').value.trim()); } catch (err) { /* not saved; still used for this report */ } });

  if (!A.configured) {
    $('signin').disabled = true;
    $('signin-note').hidden = false;
  }
  if (new URLSearchParams(location.search).get('state') === 'adminconsent') {
    var q = new URLSearchParams(location.search);
    history.replaceState(null, '', location.pathname);
    if (q.get('admin_consent') === 'True') { $('auth-error').hidden = false; $('auth-error').innerHTML = '<b>Admin consent granted.</b> You can sign in and scan this tenant now.'; }
    else if (q.get('error')) showAuthError(new Error(q.get('error_description') || q.get('error')));
  }
  A.completeSignIn().then(function (s) {
    if (!s) return;
    state.session = s;
    scan(new window.OVGraph.Client(s, false), s.user);
  }).catch(showAuthError);
})();
