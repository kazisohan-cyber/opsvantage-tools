// Windows Error Code Decoder: explains logon status codes (NTSTATUS, Event ID 4625 / 4776), Kerberos result codes
// (4768 / 4769 / 4771), Kerberos ticket options and Sysmon Event ID 10 process access masks. Everything runs in the page.
(function () {
  'use strict';
  var OV = window.OV;
  var $ = function (id) { return document.getElementById(id); };
  var last = [];

  // NTSTATUS: [name, meaning, what it usually means for an investigation, severity 0 info / 1 watch / 2 suspicious pattern]
  var NT = {
    0xC000006D: ['STATUS_LOGON_FAILURE', 'Bad user name or authentication information.', 'Generic: read the Sub Status for the real reason.', 1],
    0xC000006A: ['STATUS_WRONG_PASSWORD', 'The user name exists but the password is wrong.', 'One or two are typos. Many for one account is guessing; one try each for many accounts is password spraying.', 1],
    0xC0000064: ['STATUS_NO_SUCH_USER', 'The user name does not exist.', 'Often a typo or an old account in a script. Many different unknown names from one source is user enumeration or spraying with a username list.', 2],
    0xC0000234: ['STATUS_ACCOUNT_LOCKED_OUT', 'The account is locked out.', 'Find the source of the earlier failures (4740 on the domain controller names the caller computer). A stale password on a phone or mapped drive is the usual cause.', 1],
    0xC0000072: ['STATUS_ACCOUNT_DISABLED', 'The account is disabled.', 'Attempts against disabled accounts (leavers, old service accounts) are worth a look, especially from outside.', 2],
    0xC0000193: ['STATUS_ACCOUNT_EXPIRED', 'The account has expired.', 'Same as disabled: someone is still using, or trying, an account that should be gone.', 1],
    0xC0000071: ['STATUS_PASSWORD_EXPIRED', 'The password has expired.', 'Usually a user or service that missed a password change.', 0],
    0xC0000224: ['STATUS_PASSWORD_MUST_CHANGE', 'The user must change the password at next logon.', 'Normal after a reset. Repeated failures from a non-interactive source mean a script is using the account.', 0],
    0xC000006F: ['STATUS_INVALID_LOGON_HOURS', 'Logon outside the allowed hours.', 'The account has logon hour restrictions; check who tries it at night.', 1],
    0xC0000070: ['STATUS_INVALID_WORKSTATION', 'Logon from a computer the account is not allowed to use.', 'The account is restricted to certain workstations. Attempts from other hosts can be lateral movement.', 2],
    0xC000006E: ['STATUS_ACCOUNT_RESTRICTION', 'An account restriction blocked the logon, for example a blank password.', 'Check the account options and policy.', 1],
    0xC000015B: ['STATUS_LOGON_TYPE_NOT_GRANTED', 'The user is not allowed this logon type on this machine.', 'For example network or RDP logon denied by user rights. Expected for tiered admin accounts; unexpected attempts are worth a look.', 1],
    0xC0000133: ['STATUS_TIME_DIFFERENCE_AT_DC', 'The clock on the client and the domain controller are too far apart.', 'A time sync problem, not an attack. Kerberos allows 5 minutes by default.', 0],
    0xC000005E: ['STATUS_NO_LOGON_SERVERS', 'No logon servers are available.', 'The client could not reach a domain controller.', 0],
    0xC0000192: ['STATUS_NETLOGON_NOT_STARTED', 'The Netlogon service is not running.', 'A service problem on the machine.', 0],
    0xC000018C: ['STATUS_TRUSTED_DOMAIN_FAILURE', 'The trust relationship with the domain failed.', 'Usually a broken computer account or trust.', 0],
    0xC0000413: ['STATUS_AUTHENTICATION_FIREWALL_FAILED', 'The machine is not allowed to authenticate (selective authentication or an authentication policy).', 'A cross-forest or authentication policy block. Expected only if you set one up.', 1],
    0xC0000062: ['STATUS_INVALID_ACCOUNT_NAME', 'The account name is not valid.', 'Malformed user names often come from scanners and scripts.', 1],
    0xC0000371: ['STATUS_NO_SECRETS', 'The local account store does not hold secret material for the account.', 'Seen with some local and virtual accounts.', 0],
    0xC0000225: ['STATUS_NOT_FOUND', 'An error occurred while logging on.', 'Microsoft documents this one for 4625 as a Windows bug, not a security risk.', 0],
    0xC00002EE: ['STATUS_UNFINISHED_CONTEXT_DELETED', 'An error occurred during logon.', 'A failed security context, often seen with Kerberos or NTLM problems.', 0],
    0xC000009A: ['STATUS_INSUFFICIENT_RESOURCES', 'Not enough system resources.', 'The machine was overloaded. A flood of logon attempts can cause it.', 1],
    0xC0000022: ['STATUS_ACCESS_DENIED', 'Access denied.', 'Read it together with the event that reported it.', 0],
    0xC0000005: ['STATUS_ACCESS_VIOLATION', 'An application tried to read or write memory it may not access.', 'A crash code, not a logon code. Repeated crashes of one process can follow exploitation attempts.', 0],
    0x00000000: ['STATUS_SUCCESS', 'Success.', 'Nothing failed.', 0]
  };
  // Kerberos result codes (RFC 4120 and Microsoft): [name, meaning, investigation note, severity]
  var KRB = {
    0x0: ['KDC_ERR_NONE', 'No error.', 'The request succeeded.', 0],
    0x6: ['KDC_ERR_C_PRINCIPAL_UNKNOWN', 'Client not found in the Kerberos database: the user name does not exist.', 'In 4768 from one source for many names: user enumeration (tools such as Kerbrute test names this way).', 2],
    0x7: ['KDC_ERR_S_PRINCIPAL_UNKNOWN', 'Server not found: the service (SPN) does not exist.', 'Usually a misconfigured SPN or an old server name.', 0],
    0x9: ['KDC_ERR_NULL_KEY', 'The client or server has a null key.', 'The account has no usable key, for example no password set.', 0],
    0xC: ['KDC_ERR_POLICY', 'Rejected by policy, such as logon hours or workstation restrictions.', 'Check the account restrictions and any authentication policy.', 1],
    0xD: ['KDC_ERR_BADOPTION', 'The KDC cannot accommodate the requested option.', 'Often seen with delegation; repeated failures from one host can be delegation abuse attempts.', 1],
    0xE: ['KDC_ERR_ETYPE_NOSUPP', 'The encryption type is not supported.', 'Common after disabling RC4 or DES: a client or account still asks for an old encryption type.', 0],
    0x10: ['KDC_ERR_PADATA_TYPE_NOSUPP', 'The pre-authentication type is not supported.', 'Usually smart card logon problems.', 0],
    0x12: ['KDC_ERR_CLIENT_REVOKED', 'Client credentials revoked: the account is disabled, expired, locked out or outside logon hours.', 'Attempts on locked or disabled accounts. Watch for many from one source.', 1],
    0x17: ['KDC_ERR_KEY_EXPIRED', 'The password has expired.', 'The user must change the password.', 0],
    0x18: ['KDC_ERR_PREAUTH_FAILED', 'Pre-authentication failed: wrong password.', 'The Kerberos equivalent of a bad password. Many in 4771 across accounts from one IP is password spraying.', 1],
    0x19: ['KDC_ERR_PREAUTH_REQUIRED', 'Pre-authentication is required.', 'Normal: the client first asks without it and then retries. Not a failure you need to chase.', 0],
    0x1F: ['KRB_AP_ERR_BAD_INTEGRITY', 'Integrity check on a decrypted field failed.', 'Often a password changed while an old ticket was cached.', 0],
    0x20: ['KRB_AP_ERR_TKT_EXPIRED', 'The ticket has expired.', 'Normal; the client gets a new one.', 0],
    0x25: ['KRB_AP_ERR_SKEW', 'The clock skew is too great.', 'Time sync problem between client and domain controller.', 0],
    0x29: ['KRB_AP_ERR_MODIFIED', 'The message was modified, or the service key does not match.', 'Often duplicate SPNs or a service account password mismatch.', 0],
    0x3C: ['KRB_ERR_GENERIC', 'Generic error.', 'Read the rest of the event for context.', 0],
    0x44: ['KDC_ERR_WRONG_REALM', 'Wrong realm.', 'The request went to the wrong domain, typical of cross-forest referrals.', 0]
  };
  // Kerberos ticket options: bit 0 is the most significant bit.
  var TOPT = [[0x40000000, 'forwardable'], [0x20000000, 'forwarded'], [0x10000000, 'proxiable'], [0x08000000, 'proxy'], [0x04000000, 'allow-postdate'], [0x02000000, 'postdated'],
    [0x01000000, 'invalid'], [0x00800000, 'renewable'], [0x00400000, 'initial'], [0x00200000, 'pre-authent'], [0x00100000, 'opt-hardware-auth'], [0x00040000, 'request-anonymous'],
    [0x00020000, 'cname-in-addl-tkt (constrained delegation, S4U2proxy)'], [0x00010000, 'canonicalize'], [0x00000020, 'disable-transited-check'], [0x00000010, 'renewable-ok'],
    [0x00000008, 'enc-tkt-in-skey'], [0x00000002, 'renew'], [0x00000001, 'validate']];
  // Process access rights (Sysmon Event ID 10 GrantedAccess).
  var PACC = [[0x1, 'PROCESS_TERMINATE'], [0x2, 'PROCESS_CREATE_THREAD'], [0x4, 'PROCESS_SET_SESSIONID'], [0x8, 'PROCESS_VM_OPERATION'], [0x10, 'PROCESS_VM_READ'],
    [0x20, 'PROCESS_VM_WRITE'], [0x40, 'PROCESS_DUP_HANDLE'], [0x80, 'PROCESS_CREATE_PROCESS'], [0x100, 'PROCESS_SET_QUOTA'], [0x200, 'PROCESS_SET_INFORMATION'],
    [0x400, 'PROCESS_QUERY_INFORMATION'], [0x800, 'PROCESS_SUSPEND_RESUME'], [0x1000, 'PROCESS_QUERY_LIMITED_INFORMATION'], [0x2000, 'PROCESS_SET_LIMITED_INFORMATION'],
    [0x10000, 'DELETE'], [0x20000, 'READ_CONTROL'], [0x40000, 'WRITE_DAC'], [0x80000, 'WRITE_OWNER'], [0x100000, 'SYNCHRONIZE']];

  var hex = function (n, w) { return '0x' + (n >>> 0).toString(16).toUpperCase().padStart(w || 1, '0'); };
  function bits(v, table) {
    var names = [], rest = v >>> 0;
    table.forEach(function (b) { if ((v & b[0]) >>> 0) { names.push(b[1]); rest = (rest & ~b[0]) >>> 0; } });
    return { names: names, rest: rest };
  }

  // Find codes in the text, remembering the label in front of each one (Sub Status, Failure Code, GrantedAccess ...).
  function extract(text) {
    var out = [], seen = {}, re = /(?:^|[^\w])((?:0x)?[0-9a-f]{1,8})(?![\w.:-])/gi, m;
    text.split(/\r?\n/).forEach(function (line) {
      var label = (line.match(/^\s*([A-Za-z][A-Za-z ._-]{1,40}?)\s*[:=]/) || [])[1] || '';
      re.lastIndex = 0;
      while ((m = re.exec(line))) {
        var tok = m[1], isHex = /^0x/i.test(tok) || /[a-f]/i.test(tok);
        // Plain decimals only as short Kerberos-style codes, on their own line or after a code label ("Failure Code: 24").
        if (!isHex && !(/^\d{1,3}$/.test(tok) && (line.trim() === tok || /fail|result|error|code|status/i.test(label)))) continue;
        if (!/^0x/i.test(tok) && /[a-f]/i.test(tok) && tok.length < 8) continue; // skip words like "dead" or "face"
        var key = label.toLowerCase() + '|' + tok.toLowerCase();
        if (seen[key]) continue;
        seen[key] = 1;
        out.push({ raw: tok, value: parseInt(tok.replace(/^0x/i, ''), isHex ? 16 : 10) >>> 0, decimal: !isHex, label: label.trim() });
      }
    });
    return out.slice(0, 60);
  }

  function readings(c) {
    var v = c.value, l = c.label.toLowerCase(), r = [];
    var ctxKrb = /fail|result|kerberos|krb|error code/.test(l) && !/status/.test(l);
    var ctxTopt = /ticket ?options?/.test(l), ctxAcc = /access|mask/.test(l);
    if (NT[v] && !ctxTopt && !ctxAcc && (v !== 0 || /status/.test(l))) r.push({ kind: 'NTSTATUS (logon status)', code: hex(v, 8), d: NT[v] });
    if (KRB[v] !== undefined && !ctxTopt && !ctxAcc && (c.decimal || v <= 0x50) && (!NT[v] || ctxKrb)) r.push({ kind: 'Kerberos result code', code: hex(v, 2) + (c.decimal ? ' (decimal ' + v + ')' : ''), d: KRB[v] });
    if (!c.decimal && v >= 0x10000 && (ctxTopt || (!ctxAcc && !NT[v] && (v & 0x40000000)))) {
      var b = bits(v, TOPT);
      if (!b.rest) r.push({ kind: 'Kerberos ticket options', code: hex(v, 8), flags: b.names, d: ticketNote(v, b.names) });
    }
    if (!c.decimal && v > 0 && v <= 0x1FFFFF && (ctxAcc || (!NT[v] && !r.length && v > 0x50))) {
      var a = bits(v, PACC);
      if (!a.rest || v === 0x1FFFFF) r.push({ kind: 'Process access mask (Sysmon 10)', code: hex(v, 4), flags: v === 0x1FFFFF ? ['PROCESS_ALL_ACCESS'] : a.names, d: accessNote(v) });
    }
    return r;
  }

  function ticketNote(v, names) {
    var s = names.indexOf('forwardable') >= 0 && names.indexOf('renewable') >= 0 ? 'Typical of a normal Windows ticket request.' : 'Less common combination.';
    var sev = 0, n = s;
    if (v & 0x00020000) { n = 'Constrained delegation (S4U2proxy): a service asked for a ticket on behalf of a user. Expected for configured delegation; unexpected from a workstation or user account it can be delegation abuse.'; sev = 1; }
    else if (v & 0x00000008) { n = 'enc-tkt-in-skey (user-to-user). Rare in normal traffic; some attack tools request it.'; sev = 1; }
    if (v === 0x40810010 || v === 0x40810000 || v === 0x60810010) n = 'Very common in normal 4769 events. When hunting Kerberoasting, the encryption type (0x17, RC4) matters more than these options.';
    return ['', n, '', sev];
  }
  function accessNote(v) {
    var read = v & 0x10, write = v & 0x20, thread = v & 0x2;
    if (v === 0x1FFFFF) return ['', 'Full access to the process.', 'Common for system and security tools. Full access to lsass.exe from anything unusual is a strong credential theft signal.', 2];
    if (read) return ['', 'Includes PROCESS_VM_READ: the caller can read the target\'s memory.', 'If the target is lsass.exe and the caller is not your EDR, backup or Windows itself, treat it as credential dumping (0x1010 and 0x1410 are the classic Mimikatz values).', 2];
    if (write || thread) return ['', 'Can ' + (write ? 'write memory' : '') + (write && thread ? ' and ' : '') + (thread ? 'create threads' : '') + ' in the target.', 'The rights needed for process injection. Check who opened which process.', 2];
    return ['', 'Query or limited access only.', 'Usually harmless: many programs query other processes this way.', 0];
  }

  function analyze() {
    var codes = extract($('input').value);
    last = [];
    if (!codes.length) { $('out').innerHTML = '<p class="empty">' + ($('input').value.trim() ? 'No codes found. Paste values such as 0xC000006A, 0x18 or 0x1410.' : 'Paste one or more codes and press Decode.') + '</p>'; $('note').disabled = true; return; }
    var html = '', worst = 0;
    codes.forEach(function (c) {
      var r = readings(c);
      last.push({ c: c, r: r });
      r.forEach(function (x) { worst = Math.max(worst, x.d[3]); });
    });
    var found = last.filter(function (x) { return x.r.length; }).length;
    html += '<div class="verdict ' + (worst === 2 ? 'bad' : worst === 1 ? 'warn' : 'good') + '"><div><div class="v">' + found + '/' + codes.length + ' code' + (codes.length === 1 ? '' : 's') + ' recognised</div><div class="sub" style="margin:2px 0 0">' +
      (worst === 2 ? 'At least one points to a pattern worth investigating.' : worst === 1 ? 'Worth a look in context.' : 'Nothing here suggests an attack on its own.') + '</div></div></div>';
    var steps = [];
    last.forEach(function (x) { x.r.forEach(function (y) {
      if (y.code === '0xC0000064' || y.code === '0x06') steps.push('Count distinct user names per source IP: unknown names from one source in a short time is enumeration or password spraying.');
      if (y.code === '0xC000006A' || y.code === '0x18') steps.push('Group the failures by source IP and by account. One account, many tries: brute force. Many accounts, one try each: spraying. Then check for a success from the same source.');
      if (y.code === '0xC0000234' || y.code === '0x12') steps.push('Find what is locking the account: Event ID 4740 on the domain controller names the caller computer.');
      if (/access mask/i.test(y.kind) && y.d[3] === 2) steps.push('Check the TargetImage and SourceImage in the Sysmon 10 event. Memory access to lsass.exe from an unknown tool: isolate the host and reset the credentials used on it.');
    }); });
    steps = steps.filter(function (s, i) { return steps.indexOf(s) === i; });
    if (steps.length) html += OV.nextSteps(steps, worst === 2 ? 'bad' : 'warn');
    last.forEach(function (x) {
      var c = x.c;
      html += '<div class="finding" style="margin-top:12px"><h3 style="font-family:var(--display);font-size:1rem;margin:0 0 6px"><span class="mono">' + OV.esc(c.raw) + '</span>' + (c.label ? ' <span class="sub" style="font-size:.8rem">' + OV.esc(c.label) + '</span>' : '') + '</h3>';
      if (!x.r.length) html += '<p class="sub" style="margin:0">Not a code this tool knows. Check the event documentation for the field it came from.</p>';
      x.r.forEach(function (y) {
        html += '<p style="margin:4px 0"><b>' + OV.esc(y.kind) + '</b>' + (y.d[0] ? ' · <span class="mono">' + OV.esc(y.d[0]) + '</span>' : '') + '</p>';
        if (y.flags) html += '<p class="mono" style="margin:4px 0;font-size:.85rem">' + OV.esc(y.flags.join(' | ')) + '</p>';
        html += '<ul class="reasons"><li>' + OV.esc(y.d[1]) + '</li>' + (y.d[2] ? '<li class="' + (y.d[3] === 2 ? 'bad' : '') + '">' + OV.esc(y.d[2]) + '</li>' : '') + '</ul>';
      });
      html += '</div>';
    });
    $('out').innerHTML = html;
    $('note').disabled = false;
  }

  function note() {
    var t = ['Code lookup (OpsVantage Windows Error Code Decoder)'];
    last.forEach(function (x) {
      if (!x.r.length) { t.push(x.c.raw + ': not recognised'); return; }
      x.r.forEach(function (y) { t.push(x.c.raw + (x.c.label ? ' (' + x.c.label + ')' : '') + ' = ' + y.kind + (y.d[0] ? ' ' + y.d[0] : '') + (y.flags ? ' [' + y.flags.join(', ') + ']' : '') + ': ' + y.d[1] + (y.d[2] ? ' ' + y.d[2] : '')); });
    });
    return t.join('\n');
  }

  var SAMPLE = 'Event ID 4625\nStatus: 0xC000006D\nSub Status: 0xC0000064\n\nEvent ID 4771\nFailure Code: 0x18\n\nEvent ID 4769\nTicket Options: 0x40810010\n\nSysmon Event ID 10 (TargetImage lsass.exe)\nGrantedAccess: 0x1410';
  $('analyze').addEventListener('click', analyze);
  $('sample').addEventListener('click', function () { $('input').value = SAMPLE; analyze(); });
  $('clear').addEventListener('click', function () { $('input').value = ''; analyze(); $('input').focus(); });
  $('note').addEventListener('click', function () { if (last.length) OV.copy(note(), 'Ticket note copied'); });
  $('input').addEventListener('paste', function () { setTimeout(analyze, 0); });
  OV.ctrlEnter($('input'), analyze);
  var handed = OV.takeHandoff();
  if (handed) { $('input').value = handed; analyze(); }
  // Support links such as /error-codes/#0xC000006A from event and guide pages (the hash never leaves the browser).
  var h = decodeURIComponent(location.hash.slice(1));
  if (!handed && /^(0x)?[0-9a-f]{1,8}$/i.test(h)) { $('input').value = h; analyze(); }
})();
