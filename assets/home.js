// Homepage "paste anything" box: guesses what was pasted and hands it to the right tool in this tab.
(function () {
  'use strict';
  var OV = window.OV;
  var $ = function (id) { return document.getElementById(id); };
  var input = $('quick-in'), go = $('quick-go'), alt = $('quick-alt'), hint = $('quick-hint');
  if (!input) return;
  var DEFAULT_HINT = hint.textContent;
  var current = null;

  function update() {
    current = OV.detect(input.value);
    go.disabled = !current;
    alt.hidden = !(current && current.alt);
    if (!current) { hint.textContent = DEFAULT_HINT; go.textContent = 'Analyze'; return; }
    hint.innerHTML = 'Looks like <b>' + OV.esc(current.what) + '</b>';
    go.textContent = 'Open in ' + current.name;
    if (current.alt) alt.textContent = 'Look it up instead';
  }

  function open(tool) {
    var text = tool === current && current.value ? current.value : input.value;
    OV.sendTo(tool.path, text);
  }

  input.addEventListener('input', update);
  input.addEventListener('paste', function () { setTimeout(update, 0); });
  OV.ctrlEnter(input, function () { if (current) open(current); });
  $('quick').addEventListener('submit', function (e) { e.preventDefault(); if (current) open(current); });
  alt.addEventListener('click', function () { if (current && current.alt) OV.sendTo(current.alt.path, input.value.trim()); });
  input.addEventListener('dragover', function (e) { e.preventDefault(); });
  input.addEventListener('drop', function (e) {
    var f = e.dataTransfer.files && e.dataTransfer.files[0];
    if (!f) return;
    e.preventDefault();
    if (f.size > 25 * 1024 * 1024) { OV.toast('File is over 25 MB'); return; }
    var rd = new FileReader();
    rd.onload = function () { input.value = String(rd.result); update(); };
    rd.readAsText(f);
  });
  update();
})();
