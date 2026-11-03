// Applies the saved light/dark choice before first paint. External file so pages with a strict CSP can use it.
(function () { try { var t = localStorage.getItem('ov-theme'); if (t) document.documentElement.setAttribute('data-theme', t); } catch (e) { /* storage blocked */ } })();
