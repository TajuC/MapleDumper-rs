// Redesign runtime: accent + density theming, the memory-I/O monitor, the scan
// radar, and the title-bar quick search. Self-contained and defensive — it reads
// existing hooks (#ring state, #w-body rows, showView) and never mutates the
// contracts the other modules own.
(function () {
  "use strict";

  var byId = function (id) {
    return document.getElementById(id);
  };

  // ---- accent palette ----------------------------------------------------
  var ACCENTS = { Aurora: "#6e8bff", Ember: "#f2683c", Cyan: "#3fc9e0", Violet: "#b98cff" };

  function applyAccent(name) {
    var ac = ACCENTS[name] || ACCENTS.Aurora;
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
    accentRgb = [r, g, b];
  }

  function applyDensity(name) {
    document.documentElement.style.setProperty("--rowpad", name === "Compact" ? "9px" : "13px");
  }

  var savedAccent = "Aurora";
  try {
    if (ACCENTS[localStorage.getItem("accent")]) savedAccent = localStorage.getItem("accent");
  } catch (e) {}
  var savedDensity = "Comfortable";
  try {
    if (localStorage.getItem("density") === "Compact") savedDensity = "Compact";
  } catch (e) {}

  var accentRgb = [110, 139, 255];
  applyAccent(savedAccent);
  applyDensity(savedDensity);

  var accentSel = byId("accent-select");
  if (accentSel) {
    accentSel.value = savedAccent;
    accentSel.addEventListener("change", function () {
      applyAccent(accentSel.value);
      try {
        localStorage.setItem("accent", accentSel.value);
      } catch (e) {}
    });
  }
  var densitySel = byId("density-select");
  if (densitySel) {
    densitySel.value = savedDensity;
    densitySel.addEventListener("change", function () {
      applyDensity(densitySel.value);
      try {
        localStorage.setItem("density", densitySel.value);
      } catch (e) {}
    });
  }

  // ---- shared scan state -------------------------------------------------
  function isScanning() {
    var ring = byId("ring");
    if (ring && ring.classList.contains("run")) return true;
    var pill = byId("conn-pill");
    return !!(pill && (pill.classList.contains("run") || pill.classList.contains("wait")));
  }
  function scanProgress() {
    var rt = byId("ring-text");
    if (!rt) return 0;
    var m = /(\d+)/.exec(rt.textContent || "");
    return m ? Math.min(100, parseInt(m[1], 10)) : 0;
  }
  function hasResults() {
    var body = byId("w-body");
    return !!(body && body.querySelector("tr[data-name]"));
  }
  function tr(key, fallback) {
    return typeof t === "function" ? t(key) : fallback;
  }

  // ---- scan radar --------------------------------------------------------
  var radar = byId("w-radar");
  var radarPct = byId("w-radar-pct");
  var radarTitle = byId("w-radar-title");
  var radarSub = byId("w-radar-sub");
  var lastRadarKey = "";
  var everScanned = false;

  function setCaption(el, key, fallback) {
    if (!el) return;
    if (el.getAttribute("data-i18n") !== key) {
      el.setAttribute("data-i18n", key);
      el.textContent = tr(key, fallback);
    }
  }

  function syncRadar() {
    if (!radar) return;
    var scanning = isScanning();
    if (scanning) everScanned = true;
    var results = hasResults();
    // Radar owns the panel only while scanning, or before the first scan has run.
    // After a scan that found nothing, the table's own empty row tells the story.
    var show = scanning || (!everScanned && !results);
    var table = document.querySelector("#view-workspace .results-panel .table-scroll");
    var pct = scanning ? scanProgress() : 0;
    var key = (show ? 1 : 0) + "|" + (scanning ? 1 : 0) + "|" + pct;
    if (key === lastRadarKey) return;
    lastRadarKey = key;

    radar.hidden = !show;
    if (table) table.style.display = show ? "none" : "";
    radar.classList.toggle("scanning", scanning);
    if (scanning) {
      radar.style.setProperty("--radar-pct", String(pct));
      if (radarPct) radarPct.textContent = pct + "%";
      setCaption(radarTitle, "ws.scanning", "Scanning memory");
      setCaption(radarSub, "ws.scanningSub", "resolving patterns across loaded modules");
    } else {
      if (radarPct) radarPct.textContent = "";
      setCaption(radarTitle, "ws.awaiting", "Awaiting target");
      setCaption(radarSub, "ws.awaitingSub", "Press Start Scan to resolve patterns");
    }
  }

  // ---- memory I/O monitor ------------------------------------------------
  var wave = byId("md-wave");
  var rate = byId("md-iorate");
  var phase = 0;
  var lastRate = "";

  function draw() {
    if (wave) {
      var w = Math.max(40, wave.clientWidth || 0);
      if (w > 0) {
        var h = 36;
        if (wave.width !== w) wave.width = w;
        if (wave.height !== h) wave.height = h;
        var ctx = wave.getContext("2d");
        ctx.clearRect(0, 0, w, h);
        var scanning = isScanning();
        var amp = scanning ? 11 : 5;
        phase += scanning ? 0.085 : 0.035;
        var ac = "rgb(" + accentRgb[0] + "," + accentRgb[1] + "," + accentRgb[2] + ")";
        ctx.strokeStyle = "rgba(255,255,255,0.05)";
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.moveTo(0, h / 2);
        ctx.lineTo(w, h / 2);
        ctx.stroke();
        ctx.beginPath();
        for (var x = 0; x <= w; x += 2) {
          var n =
            Math.sin(x * 0.045 + phase) * amp +
            Math.sin(x * 0.12 + phase * 1.7) * amp * 0.4 +
            (Math.random() - 0.5) * (scanning ? 5 : 1.4);
          var y = h / 2 - n;
          if (x === 0) ctx.moveTo(x, y);
          else ctx.lineTo(x, y);
        }
        ctx.strokeStyle = ac;
        ctx.lineWidth = 1.6;
        ctx.shadowColor = ac;
        ctx.shadowBlur = 6;
        ctx.stroke();
        ctx.shadowBlur = 0;
      }
    }
    if (rate) {
      var label = isScanning() ? tr("conn.scanning", "Scanning") : tr("conn.idle", "Idle");
      if (label !== lastRate) {
        rate.textContent = label;
        lastRate = label;
      }
    }
    syncRadar();
    requestAnimationFrame(draw);
  }
  requestAnimationFrame(draw);

  // re-localize the dynamic readouts when the language flips
  var prevOnLang = typeof onLangChange === "function" ? onLangChange : null;
  if (typeof onLangChange !== "undefined") {
    onLangChange = function () {
      if (prevOnLang) prevOnLang();
      lastRate = "";
      lastRadarKey = "";
    };
  }

  // ---- title-bar quick search -------------------------------------------
  var search = byId("tb-search-input");
  function navItems() {
    return Array.prototype.map.call(document.querySelectorAll("#nav .nav-item"), function (b) {
      return { view: b.getAttribute("data-view"), label: (b.textContent || "").trim().toLowerCase() };
    });
  }
  if (search) {
    search.addEventListener("keydown", function (e) {
      var k = (e.key || "").toLowerCase();
      if (k === "escape") {
        search.value = "";
        search.blur();
        return;
      }
      if (k === "enter") {
        var q = search.value.trim().toLowerCase();
        if (!q) return;
        var hit = navItems().filter(function (it) {
          return it.view && (it.view.indexOf(q) === 0 || it.label.indexOf(q) >= 0);
        })[0];
        if (hit && typeof showView === "function") {
          showView(hit.view);
          search.value = "";
          search.blur();
        }
      }
    });
  }
  document.addEventListener("keydown", function (e) {
    var k = (e.key || "").toLowerCase();
    if ((e.ctrlKey || e.metaKey) && k === "k") {
      e.preventDefault();
      if (search) search.focus();
    }
  });
})();
