// Windows Event Triage: event ID lookup plus rule-based analysis of exported CSV / XML events. Runs in the page only.
(function () {
  'use strict';
  var OV = window.OV, I = window.VSIoc, DB = window.OV_EVENTS;
  var $ = function (id) { return document.getElementById(id); };
  var SEV_ORDER = { crit: 0, high: 1, med: 2, low: 3, info: 4 };
  var SEV_LABEL = { crit: 'Critical', high: 'High', med: 'Medium', low: 'Low', info: 'Info' };

  // ------------------------------------------------------------- lookup ---

  function logOf(provider) {
    var p = String(provider || '');
    if (/sysmon/i.test(p)) return 'Sysmon';
    if (/defender|antimalware/i.test(p)) return 'Defender';
    if (/powershell/i.test(p)) return 'PowerShell';
    if (/terminalservices/i.test(p)) return 'RDP';
    if (/service control manager|eventlog/i.test(p) && !/security/i.test(p)) return 'System';
    if (/security-auditing/i.test(p)) return 'Security';
    return '';
  }
  function info(id, provider) {
    var log = logOf(provider);
    var all = DB.filter(function (e) { return e.id === id; });
    return all.find(function (e) { return log && e.log === log; }) || (log === 'Sysmon' || !log && id < 30 ? all.find(function (e) { return e.log === 'Sysmon'; }) : null) || all.find(function (e) { return e.log !== 'Sysmon'; }) || all[0] || null;
  }

  function card(e) {
    return '<div class="ev"><div class="ev-h"><b>' + e.id + ' · ' + OV.esc(e.name) + '</b><span class="sev ' + e.sev + '">' + SEV_LABEL[e.sev] + '</span></div>' +
      '<div class="sub" style="margin:0;font-size:.76rem;font-family:var(--mono)">' + OV.esc(e.log) + (e.mitre ? ' · MITRE ' + e.mitre : '') + '</div>' +
      '<p><strong>Why it matters:</strong> ' + OV.esc(e.why) + '</p><p><strong>Check:</strong> ' + OV.esc(e.check) + '</p></div>';
  }

  function lookup() {
    var q = $('lookup').value.trim().toLowerCase();
    if (!q) { $('cards').innerHTML = ''; return; }
    var hits = /^\d+$/.test(q)
      ? DB.filter(function (e) { return String(e.id) === q; })
      : DB.filter(function (e) { return (e.name + ' ' + e.why + ' ' + e.check + ' ' + e.log + ' ' + e.mitre).toLowerCase().indexOf(q) >= 0; });
    $('cards').innerHTML = hits.length ? hits.slice(0, 12).map(card).join('') : '<p class="empty" style="grid-column:1/-1">No match in the built-in list of ' + DB.length + ' security-relevant events.</p>';
  }

  // ------------------------------------------------------------- parsing ---

  function parseXml(text) {
    var t = text.replace(/<\?xml[^>]*\?>/g, '').trim();
    if (!/^<Events[\s>]/i.test(t)) t = '<Events>' + t + '</Events>';
    var doc = new DOMParser().parseFromString(t, 'application/xml');
    if (doc.getElementsByTagName('parsererror').length) throw new Error('The XML could not be parsed.');
    var out = [];
    Array.prototype.forEach.call(doc.getElementsByTagName('Event'), function (ev) {
      var first = function (tag) { return ev.getElementsByTagName(tag)[0]; };
      var idEl = first('EventID');
      if (!idEl) return;
      var data = {};
      Array.prototype.forEach.call(ev.getElementsByTagName('Data'), function (d) {
        var n = d.getAttribute('Name');
        if (n) data[n] = d.textContent.trim();
      });
      var ud = first('UserData');
      if (ud) Array.prototype.forEach.call(ud.getElementsByTagName('*'), function (n) { if (!n.children.length) data[n.localName] = n.textContent.trim(); });
      var msgEl = first('Message');
      var prov = first('Provider'), tc = first('TimeCreated'), comp = first('Computer');
      var msg = msgEl ? msgEl.textContent : Object.keys(data).map(function (k) { return k + ': ' + data[k]; }).join('\n');
      out.push(mk(Number(idEl.textContent), prov ? prov.getAttribute('Name') : '', tc ? tc.getAttribute('SystemTime') : '', comp ? comp.textContent : '', msg, data));
    });
    return out;
  }

  function parseCsvEvents(text) {
    var rows = OV.parseCsv(text);
    if (rows.length < 2) throw new Error('Not enough rows.');
    var head = rows[0].map(function (h) { return h.trim().toLowerCase().replace(/\s*\[[^\]]*\]$/, ''); }); // "TimeGenerated [UTC]" (Sentinel CSV)
    var col = function (names) { for (var i = 0; i < names.length; i++) { var k = head.indexOf(names[i]); if (k >= 0) return k; } return -1; };
    var cId = col(['event id', 'id', 'eventid', 'eventcode', 'event code']);
    if (cId < 0) throw new Error('No "Event ID" or "Id" column found.');
    var cTime = col(['date and time', 'timecreated', 'timegenerated', 'time', 'date']);
    var cProv = col(['source', 'providername', 'provider', 'provider name']);
    var cComp = col(['machinename', 'computer', 'computername']);
    var cMsg = col(['message', 'description']);
    var orig = rows[0].map(function (h) { return h.trim(); });
    var out = [];
    rows.slice(1).forEach(function (r) {
      var id = parseInt(r[cId], 10);
      if (isNaN(id)) return;
      var msg = cMsg >= 0 ? r[cMsg] : r.slice(head.length).join(',');
      // SIEM CSV exports (Sentinel, Splunk) carry the event fields as columns: keep them as named data.
      var data = {};
      orig.forEach(function (h, i) { if (h && r[i] != null && r[i] !== '') setField(data, h, r[i]); });
      out.push(mk(id, cProv >= 0 ? r[cProv] : '', cTime >= 0 ? r[cTime] : '', cComp >= 0 ? r[cComp] : '', msg || '', data));
    });
    return out;
  }

  // Splunk's WinEventLog field names and ECS / winlogbeat names, mapped to the Windows XML names the rules read.
  var ALIAS = {
    source_network_address: 'IpAddress', src_ip: 'IpAddress', client_address: 'IpAddress', ipaddress: 'IpAddress',
    logon_type: 'LogonType', process_command_line: 'CommandLine', commandline: 'CommandLine', command_line: 'CommandLine',
    service_name: 'ServiceName', service_file_name: 'ImagePath', ticket_encryption_type: 'TicketEncryptionType',
    task_name: 'TaskName', targetusername: 'TargetUserName', target_user_name: 'TargetUserName', subjectusername: 'SubjectUserName',
    subject_user_name: 'SubjectUserName', membername: 'MemberName', member_name: 'MemberName', scriptblocktext: 'ScriptBlockText',
    script_block_text: 'ScriptBlockText', account_name: 'TargetUserName'
  };
  function setField(data, key, value) {
    if (value == null || typeof value === 'object') return;
    var k = String(key).split('.').pop();
    var v = String(value);
    if (!(k in data)) data[k] = v;
    var a = ALIAS[k.toLowerCase()];
    if (a && !data[a]) data[a] = v;
  }
  function flatten(o, data, depth) {
    if (!o || typeof o !== 'object' || depth > 6) return;
    Object.keys(o).forEach(function (k) {
      var v = o[k];
      if (v && typeof v === 'object' && !Array.isArray(v)) flatten(v, data, depth + 1);
      else if (Array.isArray(v)) { if (v.length && typeof v[0] !== 'object') setField(data, k, v.join(', ')); }
      else setField(data, k, v);
    });
  }
  var pick = function (data, names) { for (var i = 0; i < names.length; i++) if (data[names[i]] != null && data[names[i]] !== '') return data[names[i]]; return ''; };

  /** One SIEM record (Sentinel, Splunk, Elastic / winlogbeat, Defender advanced hunting) as an event. */
  function fromRecord(rec) {
    if (!rec || typeof rec !== 'object') return null;
    var o = rec.result || rec._source || rec.fields || rec;
    var data = {};
    flatten(o, data, 0);
    // Sentinel SecurityEvent keeps the raw <EventData> as a string column.
    var xml = pick(data, ['EventData']);
    if (/<Data\s/i.test(xml)) xml.replace(/<Data Name="([^"]+)">([^<]*)<\/Data>/g, function (m, n, v) { if (!data[n]) data[n] = v; return m; });
    var winlog = o.winlog || {};
    // ECS: user.name / source.ip are only meaningful with their parent, so read them before the flat names.
    if (o.user && o.user.name && !data.TargetUserName) data.TargetUserName = String(o.user.name);
    if (o.source && o.source.ip && !data.IpAddress) data.IpAddress = String(o.source.ip);
    if (o.process && o.process.command_line && !data.CommandLine) data.CommandLine = String(o.process.command_line);
    var id = parseInt(winlog.event_id || (o.event && o.event.code) || pick(data, ['EventID', 'EventId', 'EventCode', 'event_id', 'Id']), 10);
    if (isNaN(id)) return null;
    var time = o['@timestamp'] || pick(data, ['TimeGenerated', 'TimeCreated', 'Timestamp', '_time', 'timestamp', 'SystemTime', 'created']);
    var comp = (o.host && (o.host.name || o.host.hostname)) || winlog.computer_name || pick(data, ['Computer', 'ComputerName', 'DeviceName', 'host', 'computer_name']);
    var prov = winlog.provider_name || pick(data, ['ProviderName', 'Provider', 'provider_name', 'SourceName', 'source', 'EventSourceName', 'Channel', 'channel']);
    var msg = pick(data, ['Message', 'message', 'RenderedDescription', 'Activity']) || Object.keys(data).slice(0, 40).map(function (k) { return k + ': ' + data[k]; }).join('\n');
    return mk(id, prov, time, comp, msg, data);
  }

  function parseJson(text) {
    var recs;
    try {
      var j = JSON.parse(text);
      recs = Array.isArray(j) ? j : (j.hits && j.hits.hits) || j.results || j.value || j.rows || j.data || j.Results || [j];
      // Log Analytics API shape: { tables: [{ columns, rows }] }
      if (j.tables && j.tables[0] && j.tables[0].columns) {
        var cols = j.tables[0].columns.map(function (c) { return c.name; });
        recs = j.tables[0].rows.map(function (r) { var o = {}; cols.forEach(function (c, i) { o[c] = r[i]; }); return o; });
      }
    } catch (err) {
      // NDJSON: one JSON object per line (Splunk export, Elastic, Defender)
      recs = text.split(/\r?\n/).filter(function (l) { return l.trim(); }).map(function (l) { try { return JSON.parse(l); } catch (e) { return null; } }).filter(Boolean);
      if (!recs.length) throw new Error('The JSON could not be parsed.');
    }
    var out = recs.map(fromRecord).filter(Boolean);
    if (!out.length) throw new Error('No Windows event IDs found in this JSON (looked for EventID, EventCode or winlog.event_id).');
    return out;
  }

  function mk(id, provider, time, computer, msg, data) {
    var t = Date.parse(time);
    return { id: id, provider: provider || '', time: isNaN(t) ? null : t, computer: computer || '', msg: String(msg || ''), data: data };
  }

  function parse(text) {
    var t = text.trim();
    if (!t) return [];
    if (t.charAt(0) === '<') return parseXml(t);
    if (t.charAt(0) === '[' || t.charAt(0) === '{') return parseJson(t);
    return parseCsvEvents(t);
  }

  // ------------------------------------------------------------- fields ---

  function clean(v) { v = String(v == null ? '' : v).trim(); return v === '-' || v === '%%1843' ? '' : v; }
  function grab(msg, label, which) {
    var re = new RegExp('^[ \\t]*' + label.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + ':[ \\t]*(.*)$', 'gim');
    var m, vals = [];
    while ((m = re.exec(msg))) vals.push(m[1].trim());
    return clean(which === 'first' ? vals[0] : vals[vals.length - 1]);
  }
  function field(ev, xmlNames, label, which) {
    for (var i = 0; i < xmlNames.length; i++) { var v = clean(ev.data[xmlNames[i]]); if (v) return v; }
    return label ? grab(ev.msg, label, which) : '';
  }
  var F = {
    user: function (e) { return field(e, ['TargetUserName'], 'Account Name'); },
    actor: function (e) { return field(e, ['SubjectUserName'], 'Account Name', 'first'); },
    ip: function (e) { return field(e, ['IpAddress', 'SourceNetworkAddress', 'ClientAddress', 'Address'], 'Source Network Address') || grab(e.msg, 'Client Address') || grab(e.msg, 'Source Address'); },
    logonType: function (e) { return field(e, ['LogonType'], 'Logon Type'); },
    cmd: function (e) {
      return field(e, ['CommandLine', 'ScriptBlockText', 'ImagePath', 'HostApplication'], 'Process Command Line') ||
        grab(e.msg, 'CommandLine') || grab(e.msg, 'Service File Name') || grab(e.msg, 'HostApplication') ||
        (e.id === 4104 ? e.msg : '');
    },
    service: function (e) { return field(e, ['ServiceName'], 'Service Name'); },
    group: function (e) { return clean(e.data.Group_Name) || (e.data.TargetUserName && /^47(28|32|56)$/.test(String(e.id)) ? e.data.TargetUserName : grab(e.msg, 'Group Name')); },
    member: function (e) { return field(e, ['MemberName', 'MemberSid']) || grab(e.msg, 'Account Name') || grab(e.msg, 'Security ID'); },
    enc: function (e) { return field(e, ['TicketEncryptionType'], 'Ticket Encryption Type'); },
    task: function (e) { return field(e, ['TaskName'], 'Task Name'); }
  };
  function cleanIp(ip) { return String(ip || '').replace(/^::ffff:/i, '').replace(/^\[|\]$/g, ''); }
  function isPublicIp(ip) { ip = cleanIp(ip); return /^\d+\.\d+\.\d+\.\d+$/.test(ip) ? !I.isPrivateIp(ip) : (ip.indexOf(':') > 0 && !I.isPrivateIp(ip)); }
  function short(s, n) { s = String(s || '').replace(/\s+/g, ' ').trim(); return s.length > (n || 220) ? s.slice(0, n || 220) + '…' : s; }

  // ------------------------------------------------------------- rules ---

  var CMD_RULES = [
    ['crit', 'Credential dumping tool or command', /mimikatz|sekurlsa|lsadump::|kerberos::(golden|ptt)|invoke-mimikatz|procdump.{0,40}lsass|comsvcs(\.dll)?.{0,20}minidump/i, 'T1003'],
    ['crit', 'Shadow copies or backups destroyed (ransomware precursor)', /vssadmin(\.exe)?\s+delete\s+shadows|wmic(\.exe)?\s+shadowcopy\s+delete|wbadmin(\.exe)?\s+delete|bcdedit.{0,40}recoveryenabled\s+no|delete\s+catalog\s+-quiet/i, 'T1490'],
    ['crit', 'AMSI bypass attempt', /amsiutils|amsiinitfailed|amsiscanbuffer|amsicontext/i, 'T1562.001'],
    ['high', 'Encoded PowerShell command', /(powershell|pwsh)[^\n]{0,80}\s-(e|ec|en|enc|enco|encodedcommand)\s+[A-Za-z0-9+/=]{16,}/i, 'T1059.001'],
    ['high', 'Download cradle (script pulls code from the internet)', /downloadstring|downloadfile|downloaddata|net\.webclient|invoke-webrequest|\biwr\s+http|start-bitstransfer|invoke-restmethod\s+http/i, 'T1105'],
    ['high', 'LOLBin used to fetch or run remote code', /certutil(\.exe)?.{0,40}(-urlcache|-decode|-verifyctl)|mshta(\.exe)?\s+(https?:|javascript:|vbscript:)|regsvr32(\.exe)?.{0,60}\/i:https?|rundll32(\.exe)?.{0,60}javascript:|bitsadmin(\.exe)?.{0,40}\/transfer/i, 'T1218'],
    ['high', 'Microsoft Defender tampered with', /set-mppreference.{0,80}-disable\w*\s+(\$true|1)|add-mppreference.{0,40}-exclusion|disableantispyware|disablerealtimemonitoring/i, 'T1562.001'],
    ['high', 'Event log cleared from the command line', /wevtutil(\.exe)?\s+cl\b|clear-eventlog|remove-eventlog/i, 'T1070.001'],
    ['med', 'Invoke-Expression (runs a string as code)', /\biex\b|invoke-expression/i, 'T1059.001'],
    ['med', 'Account or group change from the command line', /net1?(\.exe)?\s+(user|localgroup|group)\s+.{0,80}\/add/i, 'T1136'],
    ['med', 'PowerShell version 2 downgrade (bypasses logging)', /powershell(\.exe)?\s+.{0,20}-version\s+2/i, 'T1562.010']
  ];
  var PRIV_GROUP = /administrators|domain admins|enterprise admins|schema admins|account operators|backup operators|server operators|remote desktop users|dnsadmins|group policy creator/i;
  var BAD_SERVICE = /\\(temp|tmp|appdata|users\\public|programdata|perflogs)\\|cmd(\.exe)?\s+\/[ck]|powershell|%comspec%|\\\\127\.0\.0\.1\\|\\\\localhost\\|rundll32|mshta|\.(bat|ps1|vbs|js)\b/i;
  var DCSYNC = /1131f6aa-9c07-11d1-f79f-00c04fc2dcd2|1131f6ad-9c07-11d1-f79f-00c04fc2dcd2|89e95b76-444d-4c62-991a-0facbeda640c/i;

  function detect(events) {
    var out = [];
    var add = function (sev, title, detail, evs, mitre) { out.push({ sev: sev, title: title, detail: detail, evs: evs || [], mitre: mitre || '' }); };
    var by = function (ids) { return events.filter(function (e) { return ids.indexOf(e.id) >= 0; }); };

    // Log clearing and audit tampering
    var cleared = by([1102]);
    if (cleared.length) add('crit', 'Security log cleared', cleared.length + ' time(s), by ' + uniq(cleared.map(F.actor)).join(', ') + '. Attackers do this to hide activity.', cleared, 'T1070.001');
    var syscleared = events.filter(function (e) { return e.id === 104 && logOf(e.provider) !== 'Defender'; });
    if (syscleared.length) add('high', 'Event log cleared', syscleared.length + ' System/Application log clear event(s).', syscleared, 'T1070.001');
    var audit = by([4719]);
    if (audit.length) add('high', 'Audit policy changed', audit.length + ' change(s). Disabling auditing blinds the SOC.', audit, 'T1562.002');

    // Brute force / spraying
    var fails = events.filter(function (e) { return e.id === 4625 || e.id === 4771 || (e.id === 4776 && /0xc000006a|0xc0000064/i.test(e.msg + JSON.stringify(e.data))); });
    var byUser = group(fails, F.user);
    Object.keys(byUser).forEach(function (u) {
      var list = byUser[u];
      if (u && list.length >= 10) add(list.length >= 50 ? 'crit' : 'high', 'Brute force against "' + u + '"', list.length + ' failed logons' + span(list) + ' from ' + uniq(list.map(function (e) { return cleanIp(F.ip(e)); })).slice(0, 5).join(', ') + '.', list, 'T1110.001');
    });
    var byIp = group(fails, function (e) { return cleanIp(F.ip(e)); });
    Object.keys(byIp).forEach(function (ip) {
      var users = uniq(byIp[ip].map(F.user));
      if (ip && users.length >= 5) add('high', 'Password spraying from ' + ip, byIp[ip].length + ' failures across ' + users.length + ' different accounts' + span(byIp[ip]) + ': ' + users.slice(0, 8).join(', ') + (users.length > 8 ? '…' : '') + '.', byIp[ip], 'T1110.003');
    });

    // Success after failures
    by([4624]).forEach(function (s) {
      var u = F.user(s);
      if (!u || /\$$/.test(u)) return;
      var before = (byUser[u] || []).filter(function (f) { return !s.time || !f.time || (f.time <= s.time && s.time - f.time < 3600e3); });
      if (before.length >= 5) add('crit', 'Successful logon right after failures for "' + u + '"', before.length + ' failures then a success (logon type ' + (F.logonType(s) || '?') + ', from ' + (cleanIp(F.ip(s)) || 'unknown') + '). Possible guessed password.', before.slice(-3).concat([s]), 'T1110');
    });

    // RDP / network logons from public IPs
    var pubRdp = events.filter(function (e) { return ((e.id === 4624 && F.logonType(e) === '10') || e.id === 1149 || (e.id === 21 && logOf(e.provider) === 'RDP')) && isPublicIp(F.ip(e)); });
    if (pubRdp.length) add('high', 'RDP logon from a public IP', pubRdp.length + ' logon(s) from ' + uniq(pubRdp.map(function (e) { return cleanIp(F.ip(e)); })).join(', ') + ' as ' + uniq(pubRdp.map(F.user)).join(', ') + '. RDP should not be reachable from the internet.', pubRdp, 'T1021.001');
    var locks = by([4740]);
    if (locks.length) add(locks.length >= 5 ? 'med' : 'low', 'Account lockouts', locks.length + ' lockout(s): ' + uniq(locks.map(F.user)).slice(0, 8).join(', ') + '.', locks, 'T1110');

    // Accounts and groups
    var created = by([4720]);
    if (created.length) add('med', 'New user account(s) created', uniq(created.map(F.user)).join(', ') + ' created by ' + uniq(created.map(F.actor)).join(', ') + '. Confirm there is a change ticket.', created, 'T1136.001');
    var grp = by([4728, 4732, 4756]);
    var priv = grp.filter(function (e) { return PRIV_GROUP.test(F.group(e)); });
    if (priv.length) add('high', 'Member added to a privileged group', priv.map(function (e) { return (F.member(e) || '?') + ' → ' + F.group(e); }).filter(uniqF()).join('; ') + '.', priv, 'T1098');
    var resets = by([4724]);
    if (resets.length >= 3) add('med', 'Several passwords reset by another account', resets.length + ' resets of ' + uniq(resets.map(F.user)).slice(0, 8).join(', ') + ' by ' + uniq(resets.map(F.actor)).join(', ') + '.', resets, 'T1098');
    var sid = by([4765, 4766, 4794]);
    if (sid.length) add('high', 'SID History or DSRM change', sid.length + ' event(s). Common domain backdoors.', sid, 'T1134.005');

    // Services and tasks
    var svc = by([7045, 4697]);
    var badSvc = svc.filter(function (e) { return BAD_SERVICE.test(F.cmd(e)); });
    var psexec = svc.filter(function (e) { return /psexe(c|svc)|paexec|remcom/i.test(F.service(e) + ' ' + F.cmd(e)) && badSvc.indexOf(e) < 0; });
    if (badSvc.length) add('high', 'Service installed from a suspicious path or command', badSvc.map(function (e) { return (F.service(e) || '?') + ': ' + short(F.cmd(e), 120); }).join('; '), badSvc, 'T1543.003');
    if (psexec.length) add('med', 'PsExec-style remote service', psexec.length + ' install(s). Normal for some admins, also used for lateral movement.', psexec, 'T1569.002');
    var otherSvc = svc.filter(function (e) { return badSvc.indexOf(e) < 0 && psexec.indexOf(e) < 0; });
    if (otherSvc.length) add('low', 'New services installed', otherSvc.map(function (e) { return F.service(e) || '?'; }).filter(uniqF()).slice(0, 10).join(', ') + '. Review any you don\'t recognise.', otherSvc, 'T1543.003');
    var tasks = by([4698]);
    if (tasks.length) add(tasks.some(function (e) { return BAD_SERVICE.test(e.msg); }) ? 'high' : 'med', 'Scheduled task(s) created', uniq(tasks.map(F.task)).slice(0, 8).join(', ') + '.', tasks, 'T1053.005');

    // Command lines and scripts
    var cmdEvents = events.filter(function (e) { return e.id === 4688 || e.id === 4104 || e.id === 4103 || e.id === 400 || e.id === 800 || (e.id === 1 && logOf(e.provider) !== 'RDP'); });
    CMD_RULES.forEach(function (r) {
      var hits = cmdEvents.filter(function (e) { return r[2].test(F.cmd(e) || e.msg); });
      if (hits.length) add(r[0], r[1], hits.length + ' event(s) on ' + uniq(hits.map(function (e) { return e.computer; })).join(', ') + '. Example: ' + short(F.cmd(hits[0]) || hits[0].msg, 200), hits, r[3]);
    });

    // Kerberos and AD
    var rc4 = by([4769]).filter(function (e) { return /^0x(17|18)$/i.test(F.enc(e)); });
    var rc4By = group(rc4, function (e) { return field(e, ['TargetUserName'], 'Account Name', 'first'); });
    Object.keys(rc4By).forEach(function (u) {
      var svcs = uniq(rc4By[u].map(F.service));
      if (svcs.length >= 5) add('high', 'Possible Kerberoasting by "' + u + '"', svcs.length + ' RC4 service tickets for different services' + span(rc4By[u]) + '.', rc4By[u], 'T1558.003');
    });
    var dcs = by([4662]).filter(function (e) { return DCSYNC.test(e.msg + JSON.stringify(e.data)) && !/\$$/.test(F.actor(e)); });
    if (dcs.length) add('crit', 'Possible DCSync (directory replication by a non-DC account)', 'Replication rights used by ' + uniq(dcs.map(F.actor)).join(', ') + '.', dcs, 'T1003.006');
    var lsass = events.filter(function (e) { return e.id === 10 && logOf(e.provider) === 'Sysmon' && /lsass\.exe/i.test(e.data.TargetImage || e.msg) && !/msmpeng|csrss|wininit|svchost|lsm\.exe|wmiprvse|mrt\.exe|sensecncproxy|vmtoolsd/i.test(e.data.SourceImage || grab(e.msg, 'SourceImage')); });
    if (lsass.length) add('high', 'LSASS memory accessed', 'By ' + uniq(lsass.map(function (e) { return e.data.SourceImage || grab(e.msg, 'SourceImage'); })).join(', ') + '. Typical of credential dumping.', lsass, 'T1003.001');

    // Defender
    var det = events.filter(function (e) { return e.id === 1116 && (logOf(e.provider) === 'Defender' || !e.provider); });
    if (det.length) add('high', 'Defender detected malware', det.length + ' detection(s). Example: ' + short(grab(det[0].msg, 'Name') || det[0].msg, 160), det, '');
    var off = events.filter(function (e) { return (e.id === 5001 || (e.id === 5007 && /exclusion/i.test(e.msg))) && (logOf(e.provider) === 'Defender' || !e.provider); });
    if (off.length) add('high', 'Defender protection disabled or exclusions added', off.length + ' event(s).', off, 'T1562.001');

    // Lateral movement
    var adminShare = by([5140, 5145]).filter(function (e) { return /\\\\\*\\(admin|c|ipc)\$|share name:\s*\\\\\*\\(admin|c)\$/i.test(e.msg + ' ' + (e.data.ShareName || '')) && !/ipc\$/i.test(e.data.ShareName || ''); });
    if (adminShare.length) add('med', 'Admin share access (ADMIN$ / C$)', adminShare.length + ' access(es) from ' + uniq(adminShare.map(function (e) { return cleanIp(F.ip(e)); })).join(', ') + '. Normal for some admin tools, also a lateral movement sign.', adminShare, 'T1021.002');

    return out.sort(function (a, b) { return SEV_ORDER[a.sev] - SEV_ORDER[b.sev]; });
  }

  function group(list, keyFn) { var g = {}; list.forEach(function (e) { var k = keyFn(e) || ''; (g[k] = g[k] || []).push(e); }); return g; }
  function uniq(arr) { return arr.map(function (x) { return String(x || '').trim(); }).filter(Boolean).filter(uniqF()); }
  function uniqF() { var s = new Set(); return function (x) { if (s.has(x)) return false; s.add(x); return true; }; }
  function span(list) {
    var t = list.map(function (e) { return e.time; }).filter(Boolean);
    if (t.length < 2) return '';
    var s = (Math.max.apply(null, t) - Math.min.apply(null, t)) / 1000;
    return ' in ' + (s < 120 ? Math.round(s) + ' seconds' : s < 7200 ? Math.round(s / 60) + ' minutes' : Math.round(s / 3600) + ' hours');
  }
  function fmtTime(t) { return t ? new Date(t).toLocaleString() : ''; }

  // ------------------------------------------------------------- render ---

  var last = null;

  // One concrete next action per technique, most severe finding first; the top three distinct ones are shown.
  var ACTIONS = {
    'T1490': { t: 'Isolate the host now: deleting shadow copies is the step right before ransomware encrypts.' },
    'T1070.001': { t: 'Treat it as an incident: find who cleared the log and pull the same period from your SIEM or log forwarder, which still has the events.' },
    'T1110': { t: 'A logon succeeded right after many failures: reset that password, end its sessions and check what the account did next (4624, 4688).' },
    'T1110.001': { t: 'Block the source IP and confirm none of its attempts succeeded; turn on account lockout if it is off.' },
    'T1110.003': { t: 'Block the spraying IP and check every targeted account for a later successful logon.' },
    'T1558.003': { t: 'Reset the targeted service account passwords to 25+ random characters and move them to AES or gMSA.', href: '/guides/kerberoasting-event-4769/', link: 'Guide' },
    'T1003.006': { t: 'DCSync from a non-DC: disable the account, reset krbtgt twice and treat the domain as compromised.' },
    'T1003.001': { t: 'LSASS was read: isolate the host and reset passwords of everyone who logged on to it.' },
    'T1003': { t: 'Credential dumping signs: isolate the host and reset passwords of accounts that used it.' },
    'T1098': { t: 'Check for a change ticket for the group change; if there is none, remove the member and disable the account.', href: '/guides/new-admin-account-detection/', link: 'Guide' },
    'T1136.001': { t: 'Confirm the new account was requested; if not, disable it and find who created it.', href: '/guides/new-admin-account-detection/', link: 'Guide' },
    'T1136': { t: 'Confirm the new account was requested; if not, disable it and find who created it.' },
    'T1543.003': { t: 'Get the service binary\'s hash and check it; stop and remove the service if it is not a known install.' },
    'T1569.002': { t: 'PsExec-style remote service: confirm an admin ran it, otherwise check the source host.' },
    'T1059.001': { t: 'Decode the PowerShell command and see what it downloads or runs.', href: '/guides/decode-encoded-powershell/', link: 'Decode' },
    'T1105': { t: 'Find the downloaded file and its hash, and block the download URL.' },
    'T1021.001': { t: 'Close RDP to the internet (VPN or gateway only) and review what that session did.' },
    'T1562.001': { t: 'Turn the protection back on and find out who turned it off: attackers do this before running tools.' },
    'T1053.005': { t: 'Open the scheduled task, check its command and remove it if nobody can explain it.' }
  };
  // Timeline of every event (coloured by how much the event ID matters) with a flag where each finding starts,
  // plus the ATT&CK stages the findings cover.
  function eventViz(events, findings) {
    var C = window.OVCharts;
    if (!C) return '';
    var pts = events.map(function (e) { var i = info(e.id, e.provider); return { t: e.time, sev: i ? i.sev : 'info' }; });
    var marks = findings.filter(function (f) { return f.sev !== 'info'; }).map(function (f) {
      var ts = f.evs.map(function (e) { return e.time; }).filter(Boolean);
      return { t: ts.length ? Math.min.apply(null, ts) : null, sev: f.sev, label: f.title };
    });
    var tl = C.timeline(pts, marks, { fmt: fmtTime });
    var grid = C.attackGrid(findings);
    if (!tl && !grid) return '';
    return '<div class="viz">' + (tl ? '<h3>Timeline</h3>' + tl : '') + (grid ? '<h3 style="margin-top:' + (tl ? '6px' : '0') + '">Attack stages (MITRE ATT&amp;CK)</h3>' + grid : '') + '</div>';
  }

  function eventSteps(findings) {
    var seen = {}, steps = [];
    // Within the same severity, the actions that stop damage spreading come first.
    var URGENT = { 'T1490': 0, 'T1003.006': 1, 'T1003.001': 2 };
    var rank = function (f) { return SEV_ORDER[f.sev] * 10 + (f.mitre in URGENT ? URGENT[f.mitre] : 5); };
    findings.slice().sort(function (a, b) { return rank(a) - rank(b); }).forEach(function (f) {
      var a = ACTIONS[f.mitre] || ACTIONS[String(f.mitre).split('.')[0]];
      if (a && !seen[a.t] && steps.length < 3 && f.sev !== 'info' && f.sev !== 'low') { seen[a.t] = 1; steps.push(a); }
    });
    if (!findings.length) return OV.nextSteps(['No rule matched. Widen the time range or add Sysmon and PowerShell (4104) logs, which most attacks show up in.']);
    if (!steps.length) steps.push({ t: 'Read each finding below and confirm with the account owner or a change ticket.' });
    var top = findings[0].sev;
    return OV.nextSteps(steps, top === 'crit' || top === 'high' ? 'bad' : top === 'med' ? 'warn' : '');
  }

  function analyze() {
    var raw = $('input').value;
    var events;
    try { events = parse(raw); } catch (e) {
      $('out').innerHTML = '<p class="empty">' + OV.esc(e.message) + ' Paste CSV (Event Viewer, Export-Csv or a SIEM export), XML (Event Viewer or wevtutil /f:xml) or JSON (Sentinel, Splunk, Elastic).</p>';
      $('breakdown').hidden = true; $('note').disabled = true; return;
    }
    if (!events.length) {
      $('out').innerHTML = '<p class="empty">' + (raw.trim() ? 'No events recognised. Check the format.' : 'Paste exported events and press Analyze.') + '</p>';
      $('breakdown').hidden = true; $('note').disabled = true; return;
    }
    var findings = detect(events);
    var times = events.map(function (e) { return e.time; }).filter(Boolean);
    var ips = uniq(events.map(function (e) { return cleanIp(F.ip(e)); }).filter(isPublicIp));
    last = { events: events, findings: findings, ips: ips, from: times.length ? Math.min.apply(null, times) : null, to: times.length ? Math.max.apply(null, times) : null };

    var count = function (s) { return findings.filter(function (f) { return f.sev === s; }).length; };
    var html = '<div class="stats">' +
      '<div class="stat"><b>' + events.length + '</b><span>events</span></div>' +
      '<div class="stat"><b>' + uniq(events.map(function (e) { return e.computer; })).length + '</b><span>hosts</span></div>' +
      '<div class="stat"><b style="color:var(--bad)">' + (count('crit') + count('high')) + '</b><span>critical / high</span></div>' +
      '<div class="stat"><b style="color:var(--amber)">' + count('med') + '</b><span>medium</span></div></div>';
    if (last.from) html += '<p class="sub" style="margin:-4px 0 12px;font-size:.82rem">' + fmtTime(last.from) + ' → ' + fmtTime(last.to) + '</p>';
    html += eventSteps(findings);
    html += eventViz(events, findings);
    html += findings.length ? findings.map(function (f, i) {
      return '<div class="finding"><div class="finding-h"><span class="sev ' + f.sev + '">' + SEV_LABEL[f.sev] + '</span><b>' + OV.esc(f.title) + '</b>' +
        (f.mitre ? '<span class="pill">' + OV.esc(f.mitre) + '</span>' : '') + '</div><p>' + OV.esc(f.detail) + '</p>' +
        '<details><summary>Evidence (' + f.evs.length + ' event' + (f.evs.length === 1 ? '' : 's') + ')</summary>' +
        f.evs.slice(0, 5).map(function (e) { return '<pre>' + OV.esc((fmtTime(e.time) ? fmtTime(e.time) + ' · ' : '') + e.id + (e.computer ? ' · ' + e.computer : '') + '\n' + short(e.msg, 900)) + '</pre>'; }).join('') +
        (f.evs.length > 5 ? '<p>…and ' + (f.evs.length - 5) + ' more.</p>' : '') + '</details></div>';
    }).join('') : '<div class="verdict good"><div><div class="v">No findings</div><div class="sub" style="margin:2px 0 0">None of the built-in rules matched. That is not proof of a clean system, only that these patterns are absent.</div></div></div>';
    if (ips.length) html += '<h3 style="font-family:var(--display);font-size:.95rem;margin:14px 0 8px">Public IPs seen <button class="copy" type="button" data-value="' + OV.esc(ips.join('\n')) + '">Copy all</button></h3><ul class="ioc-list">' +
      ips.slice(0, 30).map(function (ip) { return '<li><span class="ioc-v"><span>' + OV.esc(ip) + '</span>' + OV.pivots('ip', ip) + '</span><button class="copy" type="button" data-value="' + OV.esc(ip) + '">Copy</button></li>'; }).join('') + '</ul>';
    if (ips.length) html += '<div class="send-row"><button class="btn btn-ghost btn-sm" type="button" id="to-ioc">Send IPs to IOC Extractor (CSV, defang)</button></div>';
    $('out').innerHTML = html;
    $('note').disabled = false;

    var counts = group(events, function (e) { return e.id + '|' + logOf(e.provider); });
    var rows = Object.keys(counts).map(function (k) { var e = counts[k][0]; return { id: e.id, prov: e.provider, n: counts[k].length, info: info(e.id, e.provider) }; })
      .sort(function (a, b) { return b.n - a.n; });
    $('ids').innerHTML = '<thead><tr><th>Event ID</th><th>Count</th><th>Meaning</th><th>Severity</th></tr></thead><tbody>' + rows.map(function (r) {
      return '<tr><td class="mono">' + r.id + '</td><td>' + r.n + '</td><td>' + (r.info ? OV.esc(r.info.name) + ' <span class="sub" style="font-size:.74rem">' + OV.esc(r.info.log) + '</span>' : '<span class="sub">' + OV.esc(r.prov || 'Not in the built-in list') + '</span>') +
        '</td><td>' + (r.info ? '<span class="sev ' + r.info.sev + '">' + SEV_LABEL[r.info.sev] + '</span>' : '') + '</td></tr>';
    }).join('') + '</tbody>';
    $('breakdown').hidden = false;
  }

  function ticketNote() {
    var L = last;
    var lines = ['Windows event triage (OpsVantage Windows Event Triage)', L.events.length + ' events' + (L.from ? ', ' + fmtTime(L.from) + ' to ' + fmtTime(L.to) : ''), ''];
    if (!L.findings.length) lines.push('No rule matched.');
    L.findings.forEach(function (f) { lines.push('[' + SEV_LABEL[f.sev].toUpperCase() + '] ' + f.title + (f.mitre ? ' (' + f.mitre + ')' : ''), '  ' + f.detail); });
    if (L.ips.length) lines.push('', 'Public IPs (defanged): ' + L.ips.map(function (ip) { return I.defang(ip, ip.indexOf(':') >= 0 ? 'ipv6' : 'ipv4'); }).join(', '));
    return lines.join('\n');
  }

  // ------------------------------------------------------------- sample ---

  function sample() {
    var rows = [['TimeCreated', 'Id', 'ProviderName', 'MachineName', 'Message']];
    var base = Date.UTC(2026, 10, 2, 1, 50, 0), t = 0;
    var at = function (sec) { t = sec; return new Date(base + sec * 1000).toISOString(); };
    var host = 'FIN-SRV-01.corp.local', sec = 'Microsoft-Windows-Security-Auditing';
    var fail = function (user, ip) { return 'An account failed to log on.\n\nSubject:\n\tSecurity ID:\t\tNULL SID\n\tAccount Name:\t\t-\n\nLogon Type:\t\t\t3\n\nAccount For Which Logon Failed:\n\tSecurity ID:\t\tNULL SID\n\tAccount Name:\t\t' + user + '\n\tAccount Domain:\t\tCORP\n\nFailure Information:\n\tFailure Reason:\t\tUnknown user name or bad password.\n\tStatus:\t\t\t0xC000006D\n\tSub Status:\t\t0xC000006A\n\nNetwork Information:\n\tWorkstation Name:\t-\n\tSource Network Address:\t' + ip + '\n\tSource Port:\t\t0'; };
    for (var i = 0; i < 14; i++) rows.push([at(i * 11), '4625', sec, host, fail('administrator', '185.220.101.45')]);
    ['jsmith', 'mlee', 'akhan', 'finance', 'backup', 'svc_sql'].forEach(function (u, k) { rows.push([at(200 + k * 4), '4625', sec, host, fail(u, '45.137.21.9')]); });
    rows.push([at(260), '4624', sec, host, 'An account was successfully logged on.\n\nSubject:\n\tSecurity ID:\t\tSYSTEM\n\tAccount Name:\t\tFIN-SRV-01$\n\nLogon Information:\n\tLogon Type:\t\t10\n\nNew Logon:\n\tSecurity ID:\t\tCORP\\administrator\n\tAccount Name:\t\tadministrator\n\tAccount Domain:\t\tCORP\n\nNetwork Information:\n\tWorkstation Name:\tWIN-K3J9\n\tSource Network Address:\t185.220.101.45\n\tSource Port:\t\t51522']);
    rows.push([at(320), '4720', sec, host, 'A user account was created.\n\nSubject:\n\tSecurity ID:\t\tCORP\\administrator\n\tAccount Name:\t\tadministrator\n\nNew Account:\n\tSecurity ID:\t\tFIN-SRV-01\\support_adm\n\tAccount Name:\t\tsupport_adm']);
    rows.push([at(335), '4732', sec, host, 'A member was added to a security-enabled local group.\n\nSubject:\n\tSecurity ID:\t\tCORP\\administrator\n\tAccount Name:\t\tadministrator\n\nMember:\n\tSecurity ID:\t\tFIN-SRV-01\\support_adm\n\tAccount Name:\t\tsupport_adm\n\nGroup:\n\tGroup Name:\t\tAdministrators\n\tGroup Domain:\t\tBuiltin']);
    rows.push([at(410), '7045', 'Service Control Manager', host, 'A service was installed in the system.\n\nService Name:  WinUpdateSvc\nService File Name:  C:\\Users\\Public\\svchost.exe\nService Type:  user mode service\nService Start Type:  auto start\nService Account:  LocalSystem']);
    rows.push([at(470), '4688', sec, host, 'A new process has been created.\n\nCreator Subject:\n\tAccount Name:\t\tadministrator\n\nProcess Information:\n\tNew Process Name:\tC:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\n\tProcess Command Line:\tpowershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA']);
    rows.push([at(530), '4688', sec, host, 'A new process has been created.\n\nCreator Subject:\n\tAccount Name:\t\tsupport_adm\n\nProcess Information:\n\tNew Process Name:\tC:\\Windows\\System32\\vssadmin.exe\n\tProcess Command Line:\tvssadmin.exe delete shadows /all /quiet']);
    rows.push([at(600), '1102', 'Microsoft-Windows-Eventlog', host, 'The audit log was cleared.\nSubject:\n\tSecurity ID:\tCORP\\support_adm\n\tAccount Name:\tsupport_adm\n\tDomain Name:\tCORP']);
    return rows.map(function (r) { return r.map(function (c) { return '"' + String(c).replace(/"/g, '""') + '"'; }).join(','); }).join('\r\n');
  }

  function loadFile(f) {
    if (!f) return;
    if (/\.evtx$/i.test(f.name)) { OV.toast('.evtx is binary: export to CSV, XML or JSON first'); return; }
    if (f.size > 50 * 1024 * 1024) { OV.toast('File is over 50 MB; export fewer events'); return; }
    var rd = new FileReader();
    rd.onload = function () { $('input').value = String(rd.result); analyze(); };
    rd.readAsText(f);
  }

  var lt;
  $('lookup').addEventListener('input', function () { clearTimeout(lt); lt = setTimeout(lookup, 120); });
  $('analyze').addEventListener('click', analyze);
  $('sample').addEventListener('click', function () { $('input').value = sample(); analyze(); });
  $('clear').addEventListener('click', function () { $('input').value = ''; analyze(); $('input').focus(); });
  $('file').addEventListener('change', function () { loadFile(this.files[0]); this.value = ''; });
  $('input').addEventListener('dragover', function (e) { e.preventDefault(); });
  $('input').addEventListener('drop', function (e) { if (e.dataTransfer.files && e.dataTransfer.files[0]) { e.preventDefault(); loadFile(e.dataTransfer.files[0]); } });
  $('note').addEventListener('click', function () { if (last) OV.copy(ticketNote(), 'Ticket note copied'); });
  $('out').addEventListener('click', function (e) {
    var b = e.target.closest('.copy');
    if (b) { OV.copy(b.dataset.value, 'Copied'); return; }
    if (e.target.closest('#to-ioc') && last) OV.sendTo('/ioc-extractor/', last.ips.join('\n'));
  });
  OV.ctrlEnter($('input'), analyze);
  var handed = OV.takeHandoff();
  if (handed) { $('input').value = handed; analyze(); }
})();
