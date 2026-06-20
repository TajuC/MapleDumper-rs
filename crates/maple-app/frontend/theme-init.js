// The design ships a fixed "Aurora" accent at comfortable density, so we apply it
// before first paint and ignore (and clear) any stale accent/density the earlier
// build's picker may have persisted — otherwise an old "Ember" choice would re-tint
// the whole UI orange.
(function () {
  try {
    localStorage.removeItem("accent");
    localStorage.removeItem("density");
  } catch (e) {}
  var ac = "#6e8bff"; // Aurora
  var r = parseInt(ac.slice(1, 3), 16),
    g = parseInt(ac.slice(3, 5), 16),
    b = parseInt(ac.slice(5, 7), 16);
  var s = document.documentElement.style;
  s.setProperty("--ac", ac);
  s.setProperty("--ac-deep", "rgb(" + Math.round(r * 0.74) + "," + Math.round(g * 0.74) + "," + Math.round(b * 0.74) + ")");
  s.setProperty("--ac-soft", "rgba(" + r + "," + g + "," + b + ",0.16)");
  s.setProperty("--ac-softer", "rgba(" + r + "," + g + "," + b + ",0.08)");
  s.setProperty("--ac-glow", "rgba(" + r + "," + g + "," + b + ",0.5)");
  s.setProperty("--ac-line", "rgba(" + r + "," + g + "," + b + ",0.4)");
  s.setProperty("--rowpad", "13px");
})();
