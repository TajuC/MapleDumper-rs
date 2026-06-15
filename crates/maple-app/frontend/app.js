const invoke = window.__TAURI__.core.invoke;
const $ = (id) => document.getElementById(id);

// Returns the localized string with {param} placeholders substituted RAW (not HTML-escaped), so it
// is safe to assign to textContent. A caller that puts a t(...) result with interpolated params into
// innerHTML must wrap it in esc() first; backend/user values rendered into innerHTML are escaped at
// the render site (see the workspace/history/sigmaker render paths), not here.
function t(key, params) {
  const table = I18N[LANG] || I18N.en;
  let s = table[key] != null ? table[key] : I18N.en[key] != null ? I18N.en[key] : key;
  if (params) s = s.replace(/\{(\w+)\}/g, (m, k) => (params[k] != null ? params[k] : m));
  return s;
}
function applyStatic() {
  document.querySelectorAll("[data-i18n]").forEach((el) => (el.textContent = t(el.getAttribute("data-i18n"))));
  document.querySelectorAll("[data-i18n-ph]").forEach((el) => el.setAttribute("placeholder", t(el.getAttribute("data-i18n-ph"))));
  document.querySelectorAll("[data-i18n-title]").forEach((el) => el.setAttribute("title", t(el.getAttribute("data-i18n-title"))));
}
function setLang(lang) {
  if (!I18N[lang]) lang = "en";
  LANG = lang;
  try {
    localStorage.setItem("lang", lang);
  } catch {
  }
  document.documentElement.setAttribute("lang", lang);
  document.documentElement.setAttribute("dir", RTL.has(lang) ? "rtl" : "ltr");
  applyStatic();
  if (onLangChange) onLangChange();
}
setLang(LANG);

const SEED = `# MapleDumper pattern list
# name = AOB   ; trailing note is optional
# suffixes pick a resolver: _PTR rip-relative, _OFF displacement, _HDR immediate, _CALL two-hop

[functions]
SendPacket_PTR = 48 8B ?? ?? ?? ?? ?? E8   ; outgoing packet sender
Recv_CALL = E8 ?? ?? ?? ?? 84 C0           ; inbound dispatch

[globals]
GameState = A1 ?? ?? ?? ?? 8B

[offsets]
Player_Hp_OFF = 8B 8E ?? ?? ?? ??          ; hp field on the character struct

[packets]
Login_HDR = C7 45 ?? ?? ?? ?? ??           ; login opcode immediate
`;


const state = {
  patternText: SEED,
  mask: loadMaskSettings(),
  maskMode: loadMaskMode(),
  addrMode: loadAddrMode(),
  patterns: [],
  editingIndex: -1,
  arch: "x64",
  wait: true,
  byClass: false,
  codeOnly: true,
  rows: [],
  report: null,
  activeCat: "all",
  selected: null,
  connKey: "idle",
  connCls: "",
  foot: { titleKey: "foot.idle", subKey: "foot.idleSub" },
  engineVer: null,
  sourceFile: null,
  output: null,
  outputGenerated: false,
};

let monacoEditor = null;
let monacoLoading = false;
const RING_C = 169.6;

function toast(message, isError) {
  const el = $("toast");
  el.textContent = message;
  el.classList.toggle("err", !!isError);
  el.hidden = false;
  clearTimeout(toast._t);
  toast._t = setTimeout(() => (el.hidden = true), 2600);
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text == null ? "" : String(text));
    toast(t("toast.copied"));
  } catch (e) {
    toast(String(e), true);
  }
}

function hideCtxMenu() {
  const m = $("ctx-menu");
  if (m) m.hidden = true;
}

function showCtxMenu(x, y, items) {
  const m = $("ctx-menu");
  if (!m) return;
  m.innerHTML = items
    .map((it) => (it.sep ? `<div class="ctx-sep"></div>` : `<button type="button">${esc(it.label)}</button>`))
    .join("");
  let bi = 0;
  const btns = m.querySelectorAll("button");
  items.forEach((it) => {
    if (it.sep) return;
    const b = btns[bi++];
    b.addEventListener("click", () => {
      hideCtxMenu();
      it.action();
    });
  });
  m.hidden = false;
  const mw = m.offsetWidth;
  const mh = m.offsetHeight;
  m.style.left = Math.max(8, Math.min(x, window.innerWidth - mw - 8)) + "px";
  m.style.top = Math.max(8, Math.min(y, window.innerHeight - mh - 8)) + "px";
}

document.addEventListener("click", (e) => {
  if (!(e.target.closest && e.target.closest("#ctx-menu"))) hideCtxMenu();
});
document.addEventListener("keydown", (e) => {
  if ((e.key || "") === "Escape") hideCtxMenu();
});
document.addEventListener("scroll", hideCtxMenu, true);
window.addEventListener("blur", hideCtxMenu);

function esc(s) {
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
// For values placed inside double-quoted HTML attributes (paths, AOBs, titles): also escape quotes.
function escAttr(s) {
  return esc(s).replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

function hueOf(str) {
  let h = 0;
  for (let i = 0; i < str.length; i++) h = (h * 31 + str.charCodeAt(i)) >>> 0;
  return h % 360;
}
function catChip(category) {
  return `<span class="cat-chip" style="--ch:${hueOf(category)}">${esc(category)}</span>`;
}
function smartName(ext) {
  const r = state.report;
  const mod = ((r && r.module_name) || "offsets").replace(/\.exe$/i, "");
  const ver = r && r.build_version ? `-${r.build_version}` : "";
  const date = new Date().toISOString().slice(0, 10);
  return `${mod}${ver}-${date}.${ext}`;
}

let currentView = "workspace";
function showView(name) {
  currentView = name;
  document.querySelectorAll(".nav-item").forEach((b) => b.classList.toggle("active", b.dataset.view === name));
  document.querySelectorAll(".view").forEach((v) => v.classList.toggle("active", v.id === `view-${name}`));
  if (name === "patterns") refreshPatterns();
  if (name === "editor") ensureEditor();
  if (name === "history") loadHistory();
  if (name === "asmscan") asmSyncTarget();
  if (name === "sigmaker") renderSigFiles();
}
document.querySelectorAll(".nav-item").forEach((b) => b.addEventListener("click", () => showView(b.dataset.view)));
$("open-editor").addEventListener("click", () => showView("editor"));
document.addEventListener("keydown", (e) => {
  if ((e.ctrlKey || e.metaKey) && (e.key === "f" || e.key === "F")) {
    if (currentView === "editor") return;
    const inp = $({ workspace: "w-search", patterns: "pattern-search", history: "hist-search", asmscan: "asm-search" }[currentView]);
    if (inp) {
      e.preventDefault();
      inp.focus();
      inp.select();
    }
  }
});

function currentWindow() {
  const tauri = window.__TAURI__ || {};
  if (tauri.window && tauri.window.getCurrentWindow) return tauri.window.getCurrentWindow();
  if (tauri.webviewWindow && tauri.webviewWindow.getCurrentWebviewWindow) return tauri.webviewWindow.getCurrentWebviewWindow();
  return null;
}
try {
  const appWindow = currentWindow();
  if (appWindow) {
    $("win-min").addEventListener("click", () => appWindow.minimize());
    $("win-max").addEventListener("click", () => appWindow.toggleMaximize());
    $("win-close").addEventListener("click", () => appWindow.close());
  }
} catch {
}

document.addEventListener("contextmenu", (e) => {
  if (!(e.target.closest && e.target.closest(".monaco-editor"))) e.preventDefault();
});
document.addEventListener("keydown", (e) => {
  const k = (e.key || "").toLowerCase();
  if (k === "f5" || ((e.ctrlKey || e.metaKey) && (k === "r" || k === "p"))) e.preventDefault();
});


$("mask-toggle").addEventListener("click", () => {
  masked = !masked;
  const btn = $("mask-toggle");
  btn.classList.toggle("active", masked);
  btn.querySelector(".ico").innerHTML = ICONS[masked ? "eye-off" : "eye"];
  btn.title = t(masked ? "mask.on" : "mask.off");
  applyMask();
});

document.querySelectorAll("[data-mask]").forEach((cb) => {
  cb.checked = !!state.mask[cb.dataset.mask];
  cb.addEventListener("change", () => {
    state.mask[cb.dataset.mask] = cb.checked;
    saveMaskSettings();
    applyMask();
  });
});

const modeCb = $("mask-mode");
if (modeCb) {
  modeCb.checked = state.maskMode === "randomize";
  modeCb.addEventListener("change", () => {
    state.maskMode = modeCb.checked ? "randomize" : "blur";
    saveMaskMode();
    applyMask();
  });
}

const addrSel = $("addr-mode-select");
if (addrSel) {
  addrSel.value = state.addrMode;
  addrSel.addEventListener("change", () => {
    state.addrMode = addrSel.value;
    saveAddrMode(state.addrMode);
    // Live re-render so existing results pick up the new format without re-generating.
    if (typeof renderSigResults === "function") renderSigResults();
    if (typeof refreshInspectorAddr === "function") refreshInspectorAddr();
  });
}

applyMask();

$("t-arch").addEventListener("click", () => {
  state.arch = state.arch === "x64" ? "x86" : "x64";
  const on = state.arch === "x64";
  $("t-arch").classList.toggle("active", on);
  $("t-arch-label").textContent = on ? t("ws.arch64") : t("ws.arch32");
});
$("t-wait").addEventListener("click", () => {
  state.wait = !state.wait;
  $("t-wait").classList.toggle("active", state.wait);
});
$("t-class").addEventListener("click", () => {
  state.byClass = !state.byClass;
  $("t-class").classList.toggle("active", state.byClass);
  $("target-label").textContent = state.byClass ? t("ws.windowClass") : t("ws.targetProcess");
  $("w-target").placeholder = state.byClass ? t("ws.windowClassPh") : "MapleStory.exe";
});
$("t-code").addEventListener("click", () => {
  state.codeOnly = !state.codeOnly;
  $("t-code").classList.toggle("active", state.codeOnly);
});

function setConn(key, cls) {
  state.connKey = key;
  state.connCls = cls || "";
  $("conn-text").textContent = t(`conn.${key}`);
  $("conn-pill").className = `conn-pill ${cls || ""}`;
}

function setRing(mode, pct) {
  const ring = $("ring");
  if (mode === "run") {
    ring.classList.add("run");
    $("ring-text").textContent = "···";
    $("ring-fg").style.strokeDashoffset = RING_C * 0.25;
    return;
  }
  ring.classList.remove("run");
  const p = Math.max(0, Math.min(100, pct || 0));
  $("ring-fg").style.strokeDashoffset = RING_C * (1 - p / 100);
  $("ring-text").textContent = `${Math.round(p)}%`;
}

function setFoot(titleKey, subKey, params, rawSub) {
  state.foot = { titleKey, subKey, params, rawSub };
  $("foot-title").textContent = t(titleKey);
  $("foot-sub").textContent = subKey ? t(subKey, params) : rawSub || "";
}

function fmtMs(ms) {
  return ms < 1000 ? `${ms} ms` : `${(ms / 1000).toFixed(2)} s`;
}

async function runScan() {
  const req = {
    locator: state.byClass ? "class" : "name",
    target: $("w-target").value.trim(),
    module: $("w-module").value.trim(),
    arch: state.arch,
    wait: state.wait,
    timeout_secs: $("w-timeout").value ? Number($("w-timeout").value) : null,
    code_only: state.codeOnly,
    patterns: state.patternText,
  };
  if (!req.target) {
    toast(t("toast.enterTarget"), true);
    return;
  }

  $("w-scan").disabled = true;
  $("w-stop").disabled = false;
  setConn(state.wait ? "waiting" : "scanning", state.wait ? "wait" : "run");
  setRing("run");
  setFoot(state.wait ? "foot.waiting" : "foot.scanning", state.wait ? "foot.waitingSub" : "foot.scanningSub");

  try {
    const report = await invoke("attach_and_scan", { req });
    state.report = report;
    state.rows = report.rows;
    state.activeCat = "all";
    state.selected = null;
    buildTabs();
    renderResults();
    autoSelect();

    const total = report.found + report.unresolved + report.not_found;
    $("s-found").textContent = report.found;
    $("s-unresolved").textContent = report.unresolved;
    $("s-time").textContent = fmtMs(report.elapsed_ms);
    $("s-module").textContent = report.module_name;
    setConn("attached", "ok");
    setRing("done", total ? (report.found / total) * 100 : 0);
    const mb = (report.bytes_scanned / 1048576).toFixed(0);
    const gbs = (report.scan_ms > 0 ? report.bytes_scanned / (report.scan_ms / 1000) / 1073741824 : 0).toFixed(2);
    setFoot("foot.complete", "foot.completeSub", { found: report.found, total, mb, gbs, attach: report.attach_ms });
    renderScanDiag(report);
    if (Array.isArray(report.warnings)) {
      for (const w of report.warnings) toast(w, true);
    }
  } catch (err) {
    if (String(err) === "scan cancelled") {
      // The user hit Stop and the backend now genuinely aborts the scan. The stop handler already set
      // the cancelled state, so keep it rather than overwriting it with a failure.
      setConn("cancelled", "");
      setRing("done", 0);
      setFoot("foot.cancelled", "foot.cancelledSub");
    } else {
      setConn("error", "err");
      setRing("done", 0);
      setFoot("foot.failed", null, null, String(err));
      toast(String(err), true);
    }
  } finally {
    $("w-scan").disabled = false;
    $("w-stop").disabled = true;
  }
}

$("w-scan").addEventListener("click", runScan);
$("w-stop").addEventListener("click", () => {
  invoke("cancel_scan");
  setConn("cancelled", "");
  setRing("done", 0);
  setFoot("foot.cancelled", "foot.cancelledSub");
});


$("asm-scan").addEventListener("click", runAsmScan);
$("asm-stop").addEventListener("click", () => invoke("cancel_scan"));
$("asm-search").addEventListener("input", () => {
  if (asmState.report) renderAsmResults(asmState.report);
});


$("sig-pick").addEventListener("click", sigPickFiles);
$("sig-pick-neg").addEventListener("click", sigPickNegatives);
$("sig-gen").addEventListener("click", runSigGen);
$("sig-stop").addEventListener("click", () => invoke("cancel_scan"));
$("sig-json").addEventListener("click", () => {
  sigState.showJson = !sigState.showJson;
  renderSigResults();
});
$("sig-mode-tabs")
  .querySelectorAll(".tab")
  .forEach((b) => b.addEventListener("click", () => sigSetMode(b.dataset.mode)));
$("sig-cross-toggle")
  .querySelectorAll(".seg-btn")
  .forEach((b) => b.addEventListener("click", () => sigSetCross(b.dataset.cross)));
["sig-aob", "sig-rva"].forEach((id) => {
  const ta = $(id);
  ta.addEventListener("input", sigUpdateValidity);
  ta.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
      e.preventDefault();
      if (!$("sig-gen").disabled) runSigGen();
    }
  });
});
document.querySelectorAll(".sig-load").forEach((b) => b.addEventListener("click", () => sigLoadFile(b.dataset.target)));
$("sig-file-input").addEventListener("change", (e) => {
  const file = e.target.files && e.target.files[0];
  if (!file || !sigLoadTarget) {
    e.target.value = "";
    return;
  }
  const target = sigLoadTarget;
  const reader = new FileReader();
  reader.onload = () => {
    const ta = $(target);
    const incoming = String(reader.result || "")
      .split(/\r?\n/)
      .map((s) => s.trim())
      .filter(Boolean);
    const existing = ta.value
      .split("\n")
      .map((s) => s.trim())
      .filter(Boolean);
    ta.value = existing.concat(incoming).join("\n");
    sigUpdateValidity();
    toast(t("sig.loadedLines", { n: incoming.length }));
  };
  reader.readAsText(file);
  e.target.value = "";
});
sigUpdateValidity();


$("w-search").addEventListener("input", renderResults);
$("w-source-btn").addEventListener("click", async () => {
  const path = await invoke("pick_open_file");
  if (!path) return;
  try {
    state.patternText = await invoke("read_text_file", { path });
    syncEditor();
    await reparse();
    state.sourceFile = path.split(/[\\/]/).pop();
    $("w-source").value = state.sourceFile;
    toast(t("toast.loadedN", { n: state.patterns.length }));
  } catch (err) {
    toast(String(err), true);
  }
});

const EXPORT_KEY = { header: "ws.exportHeader", ce: "ws.exportCe", txt: "ws.exportTxt" };

$("w-export").addEventListener("click", (e) => {
  e.stopPropagation();
  $("export-menu").hidden = !$("export-menu").hidden;
});
document.addEventListener("click", () => ($("export-menu").hidden = true));
document.querySelectorAll("#export-menu button").forEach((b) =>
  b.addEventListener("click", async () => {
    try {
      const text = await invoke("export_text", { format: b.dataset.export });
      $("output-text").textContent = text;
      state.outputGenerated = true;
      state.output = { typeKey: EXPORT_KEY[b.dataset.export], n: text.split("\n").length };
      $("output-label").textContent = t("out.label", { name: t(state.output.typeKey), n: state.output.n });
      $("output-text").dataset.suggest = smartName(
        b.dataset.export === "header" ? "h" : b.dataset.export === "ce" ? "CT" : "txt",
      );
      showView("output");
    } catch (err) {
      toast(String(err), true);
    }
  })
);

$("out-copy").addEventListener("click", async () => {
  await navigator.clipboard.writeText($("output-text").textContent);
  toast(t("toast.copied"));
});
$("out-save").addEventListener("click", async () => {
  const path = await invoke("pick_save_file", { defaultName: $("output-text").dataset.suggest || "output.txt" });
  if (!path) return;
  try {
    await invoke("write_text_file", { path, contents: $("output-text").textContent });
    toast(t("toast.saved", { path }));
  } catch (err) {
    toast(String(err), true);
  }
});


$("pattern-search").addEventListener("input", renderPatterns);
$("pattern-cat").addEventListener("change", renderPatterns);
$("pat-add").addEventListener("click", () => openModal(-1));
$("pat-load").addEventListener("click", async () => {
  const path = await invoke("pick_open_file");
  if (!path) return;
  try {
    state.patternText = await invoke("read_text_file", { path });
    state.sourceFile = path.split(/[\\/]/).pop();
    $("w-source").value = state.sourceFile;
    syncEditor();
    await reparse();
    renderPatterns();
    toast(t("toast.loadedN", { n: state.patterns.length }));
  } catch (err) {
    toast(String(err), true);
  }
});
$("pat-save").addEventListener("click", async () => {
  const path = await invoke("pick_save_file", { defaultName: "patterns.txt" });
  if (!path) return;
  try {
    const body = path.toLowerCase().endsWith(".json")
      ? JSON.stringify({ arch: state.arch, patterns: state.patterns }, null, 2)
      : state.patternText;
    await invoke("write_text_file", { path, contents: body });
    toast(t("toast.saved", { path }));
  } catch (err) {
    toast(String(err), true);
  }
});

function openModal(index) {
  state.editingIndex = index;
  const p = index >= 0 ? state.patterns[index] : null;
  $("modal-title").textContent = p ? t("modal.edit") : t("modal.add");
  $("f-name").value = p ? p.name : "";
  $("f-cat").value = p ? p.category : "";
  $("f-aob").value = p ? p.aob : "";
  $("f-note").value = p ? p.note : "";
  $("modal").hidden = false;
  $("f-name").focus();
}
function closeModal() {
  $("modal").hidden = true;
}
$("modal-cancel").addEventListener("click", closeModal);
$("modal").addEventListener("click", (e) => {
  if (e.target.id === "modal") closeModal();
});
$("modal-ok").addEventListener("click", async () => {
  const name = $("f-name").value.trim();
  const aob = $("f-aob").value.trim();
  if (!name || !aob) {
    toast(t("toast.nameAobRequired"), true);
    return;
  }
  const entry = { name, category: $("f-cat").value.trim() || "globals", aob, note: $("f-note").value.trim() };
  const next = state.patterns.slice();
  if (state.editingIndex >= 0) next[state.editingIndex] = entry;
  else next.push(entry);
  const wasEdit = state.editingIndex >= 0;
  closeModal();
  await commitPatterns(next);
  toast(wasEdit ? t("toast.updated") : t("toast.added"));
});

window.MonacoEnvironment = {
  getWorkerUrl() {
    return "vs/base/worker/workerMain.js";
  },
};


$("ed-load").addEventListener("click", async () => {
  const path = await invoke("pick_open_file");
  if (!path) return;
  try {
    state.patternText = await invoke("read_text_file", { path });
    state.sourceFile = path.split(/[\\/]/).pop();
    $("w-source").value = state.sourceFile;
    syncEditor();
    toast(t("toast.loaded"));
  } catch (err) {
    toast(String(err), true);
  }
});
$("ed-save").addEventListener("click", async () => {
  const path = await invoke("pick_save_file", { defaultName: "patterns.txt" });
  if (!path) return;
  try {
    await invoke("write_text_file", { path, contents: state.patternText });
    toast(t("toast.saved", { path }));
  } catch (err) {
    toast(String(err), true);
  }
});
$("ed-apply").addEventListener("click", async () => {
  if (monacoEditor) state.patternText = monacoEditor.getValue();
  await reparse();
  renderPatterns();
  toast(t("toast.appliedN", { n: state.patterns.length }));
});

(function initLang() {
  const sel = $("lang-select");
  sel.innerHTML = LANGS.map((l) => `<option value="${l.code}">${esc(l.label)}</option>`).join("");
  sel.value = LANG;
  sel.addEventListener("change", () => setLang(sel.value));
})();

$("hist-refresh").addEventListener("click", loadHistory);
$("hist-compare").addEventListener("click", compareHist);
$("hist-matrix").addEventListener("click", openMatrix);
$("hist-difffiles").addEventListener("click", () => $("diff-file-input").click());
$("diff-file-input").addEventListener("change", async (e) => {
  const files = Array.from(e.target.files || []);
  e.target.value = "";
  if (files.length < 2) {
    toast(t("hist.diffPickTwo"), true);
    return;
  }
  try {
    const [a, b] = files;
    const [oldText, newText] = await Promise.all([a.text(), b.text()]);
    openTab({
      type: "difffiles",
      key: `df:${a.name}|${b.name}`,
      title: `${a.name} ↔ ${b.name}`,
      old: oldText,
      new: newText,
    });
  } catch (err) {
    toast(String(err), true);
  }
});
$("hist-clear").addEventListener("click", clearHistory);
$("hist-tab-content").addEventListener("click", (e) => {
  const tr = e.target.closest && e.target.closest("tr.sym-row");
  if (tr) toggleSymDetail(tr);
});

function relocalize() {
  $("mask-toggle").title = t(masked ? "mask.on" : "mask.off");
  $("t-arch-label").textContent = state.arch === "x64" ? t("ws.arch64") : t("ws.arch32");
  $("target-label").textContent = state.byClass ? t("ws.windowClass") : t("ws.targetProcess");
  $("w-target").placeholder = state.byClass ? t("ws.windowClassPh") : "MapleStory.exe";
  $("engine-badge").textContent = state.engineVer ? `${t("engine.label")} ${state.engineVer}` : t("engine.offline");
  const av = $("about-version");
  if (av) av.textContent = state.engineVer || "";
  $("w-source").value = state.sourceFile || t("ws.builtinSamples");
  setConn(state.connKey, state.connCls);
  setFoot(state.foot.titleKey, state.foot.subKey, state.foot.params, state.foot.rawSub);
  $("output-label").textContent = state.output ? t("out.label", { name: t(state.output.typeKey), n: state.output.n }) : t("out.nothing");
  if (!state.outputGenerated) $("output-text").textContent = t("out.default");
  buildTabs();
  renderResults();
  renderPatterns();
  asmSyncTarget();
  if (asmState.report) renderAsmResults(asmState.report);
  renderSigFiles();
  if (sigState.response) renderSigResults();
  if (histState.groups.length) {
    renderHistory();
    renderTabs();
    renderActiveTab();
  }
  if (state.selected) selectRow(state.selected);
  else {
    $("insp-name").textContent = t("insp.noSelection");
    $("insp-desc").textContent = t("insp.selectRow");
  }
  const sel = $("lang-select");
  if (sel) sel.value = LANG;
}
onLangChange = relocalize;

(async function boot() {
  injectIcons();
  $("t-arch-label").textContent = t("ws.arch64");
  $("target-label").textContent = t("ws.targetProcess");
  $("w-source").value = t("ws.builtinSamples");
  $("output-label").textContent = t("out.nothing");
  $("output-text").textContent = t("out.default");
  $("insp-name").textContent = t("insp.noSelection");
  $("insp-desc").textContent = t("insp.selectRow");
  $("mask-toggle").title = t("mask.off");
  setConn("idle", "");
  setFoot("foot.idle", "foot.idleSub");
  try {
    state.engineVer = await invoke("engine_version");
    $("engine-badge").textContent = `${t("engine.label")} ${state.engineVer}`;
  } catch {
    $("engine-badge").textContent = t("engine.offline");
  }
  const av = $("about-version");
  if (av) av.textContent = state.engineVer || "";
  const repo = $("about-repo");
  if (repo) repo.addEventListener("click", () => copyText(repo.textContent.trim()));
  await reparse();
  renderResults();
  renderPatterns();
})();
