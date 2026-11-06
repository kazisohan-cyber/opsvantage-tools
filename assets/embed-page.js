// /embed/ page: live preview and copy-paste snippet for the embeddable DMARC checker.
(function () {
  'use strict';
  var $ = function (id) { return document.getElementById(id); };
  function snippet() {
    var t = $('emb-theme').value, h = $('emb-height').value;
    return '<iframe src="https://tools.opsvantage.net/embed/dmarc/?theme=' + t + '" title="SPF, DKIM and DMARC checker" width="100%" height="' + h +
      '" style="border:0;max-width:640px" loading="lazy"></iframe>\n<p style="font-size:12px">Free <a href="https://tools.opsvantage.net/dmarc-checker/">DMARC checker</a> by OpsVantage Tools</p>';
  }
  function update() {
    $('emb-code').textContent = snippet();
    $('emb-preview').src = 'dmarc/?theme=' + $('emb-theme').value;
    $('emb-preview').style.height = $('emb-height').value + 'px';
  }
  document.addEventListener('DOMContentLoaded', function () {
    if (!$('emb-code')) return;
    $('emb-theme').addEventListener('change', update);
    $('emb-height').addEventListener('change', update);
    $('emb-copy').addEventListener('click', function () { window.OV.copy(snippet(), 'Snippet copied'); });
    $('emb-code').textContent = snippet();
  });
})();
