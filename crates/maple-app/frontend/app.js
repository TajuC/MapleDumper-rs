const invoke = window.__TAURI__.core.invoke;
const $ = (id) => document.getElementById(id);

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

function loadMaskSettings() {
  const def = { sig: true, name: false, addr: false, cat: false, note: false, editor: true, output: true };
  try {
    return Object.assign(def, JSON.parse(localStorage.getItem("maskSettings") || "{}"));
  } catch {
    return def;
  }
}
function saveMaskSettings() {
  try {
    localStorage.setItem("maskSettings", JSON.stringify(state.mask));
  } catch {
  }
}
function loadMaskMode() {
  try {
    return localStorage.getItem("maskMode") || "blur";
  } catch {
    return "blur";
  }
}
function saveMaskMode() {
  try {
    localStorage.setItem("maskMode", state.maskMode);
  } catch {
  }
}

const state = {
  patternText: SEED,
  mask: loadMaskSettings(),
  maskMode: loadMaskMode(),
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

let masked = false;

const FAKE_WORDS = ["Get", "Set", "Send", "Recv", "Make", "Init", "Update", "Player", "Skill", "Packet", "Mob", "Quest", "Field", "Stat", "Buff", "Item", "Inven", "Login", "Channel", "Hook", "Base", "Ctx", "Mgr", "Pool", "Node", "Data", "Calc", "Apply", "Reset", "Find"];
const FAKE_CATS = ["functions", "packets", "globals", "offsets", "structs", "hooks"];
const FAKE_NOTES = ["entry point", "inbound handler", "struct field", "opcode", "cached pointer", ""];
const MASK_KEYS = { "d-sig": "sig", "d-name": "name", "d-addr": "addr", "d-cat": "cat", "d-note": "note" };
const FIELD_CLASSES = ".d-sig, .d-name, .d-addr, .d-cat, .d-note";

function seedHash(s) {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) {
    h = (h ^ s.charCodeAt(i)) >>> 0;
    h = Math.imul(h, 16777619) >>> 0;
  }
  return h >>> 0 || 1;
}
function rngFrom(seed) {
  let x = seed >>> 0 || 1;
  return () => {
    x ^= x << 13;
    x >>>= 0;
    x ^= x >>> 17;
    x ^= x << 5;
    x >>>= 0;
    return x;
  };
}
function fakeFor(kind, real) {
  if (kind === "d-addr" && !/0x/i.test(real)) return real;
  const rng = rngFrom(seedHash(real));
  const hex = "0123456789ABCDEF";
  if (kind === "d-name") {
    let s = "";
    for (let i = 0, n = 2 + (rng() % 2); i < n; i++) s += FAKE_WORDS[rng() % FAKE_WORDS.length];
    return s;
  }
  if (kind === "d-addr") {
    const m = real.match(/0x([0-9a-fA-F]+)/i);
    const len = m ? m[1].length : 6;
    let out = "";
    for (let i = 0; i < len; i++) out += hex[rng() % 16];
    return "0x" + out;
  }
  if (kind === "d-sig") {
    return real
      .trim()
      .split(/\s+/)
      .map((tok) => (tok.includes("?") ? "??" : hex[rng() % 16] + hex[rng() % 16]))
      .join(" ");
  }
  if (kind === "d-cat") return FAKE_CATS[rng() % FAKE_CATS.length];
  if (kind === "d-note") return real.trim() ? FAKE_NOTES[rng() % FAKE_NOTES.length] : "";
  return real;
}
function fieldKind(el) {
  return ["d-sig", "d-name", "d-addr", "d-cat", "d-note"].find((k) => el.classList.contains(k));
}
function randomizeActive() {
  return masked && state.maskMode === "randomize";
}
const maskObserver = new MutationObserver(() => applyRandomizeTo(document));
function applyRandomizeTo(root) {
  maskObserver.disconnect();
  root.querySelectorAll(FIELD_CLASSES).forEach((el) => {
    const kind = fieldKind(el);
    if (randomizeActive() && state.mask[MASK_KEYS[kind]]) {
      if (el.dataset.real == null) el.dataset.real = el.textContent;
      el.textContent = fakeFor(kind, el.dataset.real);
    } else if (el.dataset.real != null) {
      el.textContent = el.dataset.real;
      delete el.dataset.real;
    }
  });
  if (randomizeActive()) maskObserver.observe(document.body, { childList: true, subtree: true });
}

function applyMask() {
  const c = document.body.classList;
  c.toggle("masked", masked);
  c.toggle("mask-rand", randomizeActive());
  c.toggle("m-sig", state.mask.sig);
  c.toggle("m-name", state.mask.name);
  c.toggle("m-addr", state.mask.addr);
  c.toggle("m-cat", state.mask.cat);
  c.toggle("m-note", state.mask.note);
  c.toggle("m-editor", state.mask.editor);
  c.toggle("m-output", state.mask.output);
  applyRandomizeTo(document);
}

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
  } catch (err) {
    setConn("error", "err");
    setRing("done", 0);
    setFoot("foot.failed", null, null, String(err));
    toast(String(err), true);
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

const asmState = { report: null };

function asmSyncTarget() {
  const target = $("w-target").value.trim();
  const el = $("asm-target");
  if (!el) return;
  if (!target) {
    el.textContent = t("asm.noTarget");
    return;
  }
  const arch = state.arch === "x64" ? t("ws.arch64") : t("ws.arch32");
  el.textContent = t("asm.targetSummary", { target, module: $("w-module").value.trim() || target, arch });
}

async function runAsmScan() {
  const target = $("w-target").value.trim();
  if (!target) {
    toast(t("toast.enterTarget"), true);
    return;
  }
  const lines = $("asm-input").value;
  if (!lines.trim()) {
    toast(t("asm.needLines"), true);
    return;
  }
  const req = {
    locator: state.byClass ? "class" : "name",
    target,
    module: $("w-module").value.trim(),
    arch: state.arch,
    wait: state.wait,
    timeout_secs: $("w-timeout").value ? Number($("w-timeout").value) : null,
    code_only: state.codeOnly,
    from: $("asm-from").value.trim() || null,
    to: $("asm-to").value.trim() || null,
    lines,
  };
  $("asm-scan").disabled = true;
  $("asm-stop").disabled = false;
  $("asm-count").textContent = t("asm.running");
  try {
    const report = await invoke("assembly_scan", { req });
    asmState.report = report;
    renderAsmResults(report);
  } catch (err) {
    asmState.report = null;
    $("asm-count").textContent = "";
    $("asm-results").innerHTML = `<div class="insp-hint">${esc(String(err))}</div>`;
    toast(String(err), true);
  } finally {
    $("asm-scan").disabled = false;
    $("asm-stop").disabled = true;
  }
}

function renderAsmResults(report) {
  $("asm-count").textContent =
    (report.total === 1 ? t("asm.matchOne") : t("asm.match", { n: report.total })) +
    (report.truncated ? " · " + t("asm.truncated", { shown: report.hits.length, total: report.total }) : "");
  const host = $("asm-results");
  if (!report.hits.length) {
    host.innerHTML = `<div class="insp-hint">${t("asm.none")}</div>`;
    return;
  }
  const term = ($("asm-search").value || "").trim().toLowerCase();
  const hits = term
    ? report.hits.filter((h) => h.address.toLowerCase().includes(term) || h.lines.join(" ").toLowerCase().includes(term))
    : report.hits;
  host.innerHTML = hits
    .map(
      (h) =>
        `<div class="asm-hit"><div class="asm-hit-head"><span class="mono d-addr">${esc(h.address)}</span><span class="asm-rva muted">+${esc(h.rva)}</span><button class="icon-btn asm-save" data-bytes="${esc(h.bytes)}">${esc(t("asm.save"))}</button></div><pre class="asm-lines mono">${h.lines.map(esc).join("\n")}</pre></div>`,
    )
    .join("");
  host.querySelectorAll(".asm-save").forEach((b) => b.addEventListener("click", () => asmSaveAsPattern(b.dataset.bytes)));
}

function asmSaveAsPattern(bytes) {
  openModal(-1);
  $("f-aob").value = bytes;
  $("f-name").focus();
}

$("asm-scan").addEventListener("click", runAsmScan);
$("asm-stop").addEventListener("click", () => invoke("cancel_scan"));
$("asm-search").addEventListener("input", () => {
  if (asmState.report) renderAsmResults(asmState.report);
});

const sigState = { files: [], negatives: [], response: null, mode: "aob", cross: "separate", showJson: false, alertDismissed: false };

function renderSigFiles() {
  const host = $("sig-files");
  if (!host) return;
  if (!sigState.files.length) {
    host.innerHTML = `<span class="muted">${esc(t("sig.noFiles"))}</span>`;
  } else {
    host.innerHTML = sigState.files
      .map((f) => {
        const tip = escAttr(
          `entropy ${(f.max_entropy || 0).toFixed(2)}${f.reasons.length ? " · " + f.reasons.join("; ") : ""}`,
        );
        const badge = f.packed
          ? `<span class="sig-badge packed" title="${tip}">${t("sig.packed")}</span>`
          : `<span class="sig-badge ok" title="${tip}">${t("sig.unpacked")}</span>`;
        return `<span class="sig-chip"><span class="d-name">${esc(f.name)}</span><span class="muted">${esc(f.arch)}</span>${badge}<button class="sig-chip-x" data-rm="${escAttr(f.path)}" title="remove">✕</button></span>`;
      })
      .join("");
    host.querySelectorAll("[data-rm]").forEach((b) => b.addEventListener("click", () => sigRemoveFile(b.dataset.rm)));
  }
  const sel = $("sig-ref");
  if (sel) sel.innerHTML = sigState.files.map((f) => `<option value="${escAttr(f.path)}">${esc(f.name)}</option>`).join("");
  const anyPacked = sigState.files.some((f) => f.packed);
  const alert = $("sig-alert");
  if (anyPacked && !sigState.alertDismissed) {
    alert.hidden = false;
    alert.innerHTML = `<span>⚠ ${esc(t("sig.packedAlert"))}</span><button class="sig-alert-x" title="${escAttr(t("sig.dismiss"))}">✕</button>`;
    const x = alert.querySelector(".sig-alert-x");
    if (x)
      x.addEventListener("click", () => {
        sigState.alertDismissed = true;
        alert.hidden = true;
      });
  } else {
    alert.hidden = true;
  }
}

async function sigPickFiles() {
  let paths;
  try {
    paths = await invoke("pick_open_files");
  } catch {
    return;
  }
  for (const p of paths) {
    if (sigState.files.some((f) => f.path === p)) continue;
    try {
      const info = await invoke("inspect_pe", { path: p });
      sigState.files.push({
        path: p,
        name: info.name,
        arch: info.arch,
        packed: info.packed,
        reasons: info.reasons,
        max_entropy: info.max_entropy,
      });
    } catch (e) {
      toast(String(e), true);
    }
  }
  sigState.alertDismissed = false;
  renderSigFiles();
  sigUpdateValidity();
}

function sigRemoveFile(path) {
  sigState.files = sigState.files.filter((f) => f.path !== path);
  sigState.alertDismissed = false;
  renderSigFiles();
  sigUpdateValidity();
}

function renderSigNegatives() {
  const host = $("sig-negatives");
  if (!host) return;
  if (!sigState.negatives.length) {
    host.innerHTML = "";
    return;
  }
  host.innerHTML = `<span class="muted">${esc(t("sig.negatives"))}:</span> ` +
    sigState.negatives
      .map((n) => `<span class="sig-chip"><span class="d-name">${esc(n.name)}</span><button class="sig-chip-x" data-rmneg="${escAttr(n.path)}" title="remove">✕</button></span>`)
      .join("");
  host.querySelectorAll("[data-rmneg]").forEach((b) => b.addEventListener("click", () => sigRemoveNegative(b.dataset.rmneg)));
}

async function sigPickNegatives() {
  let paths;
  try {
    paths = await invoke("pick_open_files");
  } catch {
    return;
  }
  for (const p of paths) {
    if (sigState.negatives.some((n) => n.path === p)) continue;
    sigState.negatives.push({ path: p, name: p.split(/[\\/]/).pop() || p });
  }
  renderSigNegatives();
}

function sigRemoveNegative(path) {
  sigState.negatives = sigState.negatives.filter((n) => n.path !== path);
  renderSigNegatives();
}

function sigSetMode(mode) {
  sigState.mode = mode;
  $("sig-mode-tabs")
    .querySelectorAll(".tab")
    .forEach((b) => b.classList.toggle("active", b.dataset.mode === mode));
  $("sig-aob-row").hidden = !(mode === "aob" || mode === "both");
  $("sig-ref-row").hidden = !(mode === "ref" || mode === "both");
  $("sig-both-opts").hidden = mode !== "both";
  sigUpdateValidity();
}

function sigSetCross(mode) {
  sigState.cross = mode;
  $("sig-cross-toggle")
    .querySelectorAll(".seg-btn")
    .forEach((b) => b.classList.toggle("active", b.dataset.cross === mode));
  const hint = $("sig-cross-hint");
  const key = mode === "cross" ? "sig.crossHint" : "sig.separateHint";
  hint.setAttribute("data-i18n", key);
  hint.textContent = t(key);
  sigUpdateValidity();
}

function sigLines(id) {
  return $(id)
    .value.split("\n")
    .map((s) => s.trim())
    .filter(Boolean);
}

const SIG_RVA_RE = /^(0x)?[0-9a-fA-F]+$/;
function sigRvaValidity() {
  const lines = sigLines("sig-rva");
  const bad = lines.length > 0 && lines.some((l) => !SIG_RVA_RE.test(l));
  $("sig-rva").classList.toggle("invalid", bad);
  return lines.length > 0 && !bad;
}

function sigUpdateValidity() {
  const m = sigState.mode;
  const hasFiles = sigState.files.length > 0;
  const aobOk = sigLines("sig-aob").length > 0;
  const rvaOk = sigRvaValidity();
  let ok = hasFiles;
  if (m === "aob") ok = ok && aobOk;
  else if (m === "ref") ok = ok && rvaOk;
  else if (sigState.cross === "cross") ok = ok && aobOk && rvaOk;
  else ok = ok && (aobOk || rvaOk);
  $("sig-gen").disabled = !ok;
}

function buildSigJobs() {
  const m = sigState.mode;
  const refPath = $("sig-ref").value;
  const aobs = sigLines("sig-aob");
  const rvas = sigLines("sig-rva");
  const jobs = [];
  if (m === "aob") {
    for (const sig of aobs) jobs.push({ type: "aob", sig });
  } else if (m === "ref") {
    for (const rva of rvas) jobs.push({ type: "ref", ref_path: refPath, rva });
  } else if (sigState.cross === "cross") {
    const n = Math.min(aobs.length, rvas.length);
    for (let i = 0; i < n; i++) jobs.push({ type: "cross", sig: aobs[i], ref_path: refPath, rva: rvas[i] });
  } else {
    for (const sig of aobs) jobs.push({ type: "aob", sig });
    for (const rva of rvas) jobs.push({ type: "ref", ref_path: refPath, rva });
  }
  return jobs;
}

let sigLoadTarget = null;
function sigLoadFile(targetId) {
  sigLoadTarget = targetId;
  $("sig-file-input").click();
}

function sigPhaseText(p) {
  const key = p && SIG_STAGE_KEY[p.phase];
  const base = key ? t(key, { label: p.label || "", index: p.index || 0, total: p.total || 0 }) : t("sig.generating");
  if (p && p.jobs > 1 && p.job > 0) return t("sig.jobProgress", { job: p.job, jobs: p.jobs }) + " " + base;
  return base;
}

async function runSigGen() {
  if (!sigState.files.length) {
    toast(t("sig.noFiles"), true);
    return;
  }
  const jobs = buildSigJobs();
  if (!jobs.length) {
    toast(sigState.mode === "ref" ? t("sig.needRva") : t("sig.needAob"), true);
    return;
  }
  if (sigState.mode === "both" && sigState.cross === "cross") {
    const a = sigLines("sig-aob").length;
    const r = sigLines("sig-rva").length;
    if (a !== r) toast(t("sig.crossUneven", { sigs: a, rvas: r }));
  }
  const req = { clients: sigState.files.map((f) => f.path), jobs, negatives: sigState.negatives.map((n) => n.path) };
  $("sig-gen").disabled = true;
  const setStatus = (msg) => {
    $("sig-results").innerHTML = `<div class="insp-hint">${esc(msg)}</div>`;
  };
  setStatus(t("sig.generating"));
  let unlisten = null;
  const ev = (window.__TAURI__ || {}).event;
  if (ev && ev.listen) {
    try {
      unlisten = await ev.listen("sig-progress", (e) => setStatus(sigPhaseText(e.payload)));
    } catch (_) {
      unlisten = null;
    }
  }
  try {
    sigState.response = await invoke("generate_signature", { req });
    if (unlisten) {
      unlisten();
      unlisten = null;
    }
    sigState.showJson = false;
    $("sig-json").hidden = false;
    renderSigResults();
  } catch (e) {
    sigState.response = null;
    $("sig-json").hidden = true;
    setStatus(String(e));
    toast(String(e), true);
  } finally {
    if (unlisten) unlisten();
    sigUpdateValidity();
  }
}

function gradeDesc(letter) {
  return t("sig.grade" + String(letter).toUpperCase());
}

function sigCandCard(c, tag, primary) {
  const grade = c.grade.toLowerCase();
  const rows = c.per_version
    .map(
      (p) =>
        `<tr><td class="d-name">${esc(p.label)}</td><td class="mono d-addr">${esc(p.match_rva || "-")}</td><td class="mono d-addr">${esc(p.resolved_target_rva || "-")}</td><td>${esc(p.target_type || "-")}</td></tr>`,
    )
    .join("");
  const diags = c.diags.length
    ? `<ul class="sig-diags">${c.diags.map((d) => `<li>${esc(d)}</li>`).join("")}</ul>`
    : "";
  return `<div class="sig-cand${primary ? " primary" : ""}">
    <div class="sig-cand-head">
      <span class="sig-grade g-${grade}" title="${escAttr(gradeDesc(c.grade))}">${esc(c.grade)}</span>
      ${tag ? `<span class="sig-tag">${esc(tag)}</span>` : ""}
      <span class="sig-aob mono d-sig">${esc(c.aob)}${esc(c.suffix)}</span>
      <span class="sig-actions">
        <button class="icon-btn sig-copy" data-aob="${escAttr(c.aob)}">${esc(t("sig.copy"))}</button>
        <button class="icon-btn sig-save" data-aob="${escAttr(c.aob)}" data-suffix="${escAttr(c.suffix)}">${esc(t("sig.save"))}</button>
      </span>
    </div>
    <div class="sig-stats muted">${t("sig.bytesFixed", { bytes: c.bytes, fixed: c.fixed, wild: c.wildcards, ratio: c.fixed_ratio.toFixed(2) })}${c.reloc_safe ? "" : " · ⚠ reloc"}</div>
    <table class="grid-table sig-pv"><thead><tr><th>${esc(t("sig.colVersion"))}</th><th>${esc(t("sig.colMatch"))}</th><th>${esc(t("sig.colTarget"))}</th><th>${esc(t("col.type"))}</th></tr></thead><tbody>${rows}</tbody></table>
    ${diags}
  </div>`;
}

function reportInnerHtml(r) {
  const anyPacked = r.inputs.some((i) => i.packed);
  let html = `<div class="sig-summary">${esc(t("sig.summary", { arch: r.arch, files: r.inputs.length, builds: r.unique_builds }))}${anyPacked ? ` · ⚠ ${esc(t("sig.packed"))}` : ""}</div>`;
  const dups = r.duplicate_groups.filter((g) => g[1].length > 1);
  if (dups.length) {
    html += `<div class="sig-section-h">${t("sig.dupBuilds")}</div>`;
    html += dups
      .map(
        (g) =>
          `<div class="sig-dup"><span class="sig-dup-hash mono">${esc(g[0])}</span><span class="muted">${esc(g[1].join(", "))}</span></div>`,
      )
      .join("");
  }
  html += r.chosen ? sigCandCard(r.chosen, t("sig.chosen"), true) : `<div class="insp-hint">${t("sig.none")}</div>`;
  if (r.alternates.length) {
    html += `<div class="sig-section-h">${t("sig.alternates")}</div>` + r.alternates.map((c) => sigCandCard(c, "", false)).join("");
  }
  if (r.rejected.length) {
    html += `<div class="sig-section-h">${t("sig.rejected")}</div>` + r.rejected.map((c) => sigCandCard(c, "", false)).join("");
  }
  if (r.diagnostics.length) {
    html += `<div class="sig-section-h">${t("sig.diagnostics")}</div><ul class="sig-diags">` + r.diagnostics.map((d) => `<li>${esc(d)}</li>`).join("") + "</ul>";
  }
  if (r.holdout && r.holdout.length) {
    const passed = r.holdout.filter((h) => h.matched).length;
    html += `<div class="sig-section-h">${t("sig.holdout")} (${passed}/${r.holdout.length})</div><ul class="sig-diags">` +
      r.holdout
        .map((h) => {
          const verdict = h.matched ? t("sig.holdoutOk") : h.generated ? t("sig.holdoutMiss") : t("sig.holdoutNone");
          return `<li class="sig-holdout ${h.matched ? "ok" : "bad"}"><span class="mono">${esc(h.held_out)}</span> ${esc(verdict)}</li>`;
        })
        .join("") +
      "</ul>";
  }
  if (r.string_anchor) {
    html += `<div class="sig-section-h">${t("sig.stringAnchor")}</div>` +
      `<div class="sig-anchor"><code class="mono">${esc(r.string_anchor)}</code><button class="icon-btn sig-copy" data-aob="${escAttr(r.string_anchor)}" title="${escAttr(t("sig.copy"))}">⧉</button></div>` +
      `<div class="insp-hint">${esc(t("sig.stringAnchorHint"))}</div>`;
  }
  if (r.negative_hits && r.negative_hits.length) {
    html += `<div class="sig-section-h">${t("sig.negHits")} (${r.negative_hits.length})</div><ul class="sig-diags">` +
      r.negative_hits
        .map((h) => `<li class="sig-holdout bad"><span class="mono">${esc(h.label)}</span> ${esc(t("sig.negHitCount", { n: h.count }))}</li>`)
        .join("") +
      "</ul>";
  }
  return html;
}

function gradeLegendHtml() {
  return (
    `<div class="sig-section-h">${t("sig.gradeLegend")}</div><ul class="sig-legend">` +
    ["A", "B", "C", "D", "F"].map((g) => `<li><span class="sig-grade g-${g.toLowerCase()}">${g}</span><span>${esc(gradeDesc(g))}</span></li>`).join("") +
    "</ul>"
  );
}

function crossVerdictHtml(c) {
  if (c.agrees) {
    return `<div class="sig-cross-verdict ok">✓ ${esc(t("sig.crossOk", { rva: c.expected_rva }))}</div>`;
  }
  return `<div class="sig-cross-verdict bad">✗ ${esc(t("sig.crossMismatch", { got: c.matched_rva || t("sig.crossNoMatch"), expected: c.expected_rva }))}</div>`;
}

function wireSigButtons(host) {
  host.querySelectorAll(".sig-copy").forEach((b) =>
    b.addEventListener("click", async () => {
      await navigator.clipboard.writeText(b.dataset.aob);
      toast(t("toast.copied"));
    }),
  );
  host.querySelectorAll(".sig-save").forEach((b) => b.addEventListener("click", () => sigSaveAsPattern(b.dataset.aob, b.dataset.suffix)));
}

function renderSigResults() {
  const host = $("sig-results");
  const resp = sigState.response;
  if (!resp) return;
  if (sigState.showJson) {
    host.innerHTML = `<pre class="sig-jsonview mono">${esc(JSON.stringify(resp, null, 2))}</pre>`;
    return;
  }
  const jobs = resp.jobs || [];
  if (!jobs.length) {
    host.innerHTML = `<div class="insp-hint">${t("sig.none")}</div>`;
    return;
  }
  const multi = jobs.length > 1;
  let html = "";
  jobs.forEach((job, i) => {
    const framed = multi || !!job.cross;
    html += `<div class="sig-job${framed ? " framed" : ""}">`;
    if (framed) {
      const chosen = job.report && job.report.chosen;
      const gradeChip = chosen ? `<span class="sig-grade g-${chosen.grade.toLowerCase()}" title="${escAttr(gradeDesc(chosen.grade))}">${esc(chosen.grade)}</span>` : "";
      html += `<div class="sig-job-head">${multi ? `<span class="sig-job-n">#${i + 1}</span>` : ""}<span class="sig-job-label mono">${esc(job.label)}</span>${gradeChip}</div>`;
    }
    if (job.error) {
      html += `<div class="sig-job-err">${esc(job.error)}</div>`;
    } else {
      if (job.cross) html += crossVerdictHtml(job.cross);
      if (job.report) html += reportInnerHtml(job.report);
    }
    html += `</div>`;
  });
  html += gradeLegendHtml();
  host.innerHTML = html;
  wireSigButtons(host);
}

function sigSaveAsPattern(aob, suffix) {
  // The resolver keys off the pattern-name suffix (_PTR/_CALL/_OFF/_HDR). Kind::Call follows both
  // call and jmp rel32, so a _JMP anchor is saved as _CALL so the scanner resolves it to its target.
  const nameSuffix = suffix === "_JMP" ? "_CALL" : suffix;
  openModal(-1);
  $("f-aob").value = aob;
  $("f-name").value = "NewSig" + nameSuffix;
  $("f-name").focus();
}

$("sig-pick").addEventListener("click", sigPickFiles);
$("sig-pick-neg").addEventListener("click", sigPickNegatives);
$("sig-gen").addEventListener("click", runSigGen);
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

function buildTabs() {
  const cats = [...new Set(state.rows.map((r) => r.category))].sort();
  const host = $("w-tabs");
  host.innerHTML =
    `<button class="tab ${state.activeCat === "all" ? "active" : ""}" data-cat="all">${esc(t("ws.tabAll"))}</button>` +
    cats
      .map((c) => `<button class="tab ${state.activeCat === c ? "active" : ""}" data-cat="${esc(c)}">${esc(c)}</button>`)
      .join("");
  host.querySelectorAll(".tab").forEach((tabEl) =>
    tabEl.addEventListener("click", () => {
      state.activeCat = tabEl.dataset.cat;
      buildTabs();
      renderResults();
    })
  );
}

function accentClass(row) {
  if (row.status !== "found") return "dot-muted";
  return row.type === "call" || row.type === "header" ? "dot-violet" : "dot-blue";
}

function typeKey(kind) {
  return { pointer: "type.pointer", call: "type.function", offset: "type.offset", header: "type.header", direct: "type.address" }[kind];
}
function typeLabel(kind) {
  const key = typeKey(kind);
  return key ? t(key) : kind;
}

function statusClass(status) {
  return status === "not found" ? "notfound" : status;
}
function statusText(status) {
  return status === "found" ? t("status.found") : status === "unresolved" ? t("status.unresolved") : t("status.notFound");
}
function statusBadge(status) {
  return `<span class="badge ${statusClass(status)}">${esc(statusText(status))}</span>`;
}

function renderResults() {
  const term = $("w-search").value.trim().toLowerCase();
  const body = $("w-body");
  const maxHits = Math.max(1, ...state.rows.map((r) => r.matches));
  const n = state.rows.length;
  $("w-count").textContent = t(n === 1 ? "res.countOne" : "res.count", { n });

  const rows = state.rows.filter((r) => {
    if (state.activeCat !== "all" && r.category !== state.activeCat) return false;
    if (!term) return true;
    return (
      r.name.toLowerCase().includes(term) ||
      (r.value || "").toLowerCase().includes(term) ||
      r.category.toLowerCase().includes(term)
    );
  });

  if (rows.length === 0) {
    body.innerHTML = `<tr class="empty"><td colspan="6">${esc(state.rows.length ? t("ws.emptyFilter") : t("ws.empty"))}</td></tr>`;
    return;
  }

  body.innerHTML = rows
    .map((r) => {
      const pct = (r.matches / maxHits) * 100;
      const value = r.value ? `<span class="mono d-addr">${r.value}</span>` : '<span class="muted"></span>';
      return `<tr data-name="${esc(r.name)}" class="${state.selected === r.name ? "selected" : ""}">
        <td><div class="name-cell"><span class="dot-acc ${accentClass(r)}"></span>
          <div><div class="name-main d-name">${esc(r.name)}</div><div class="name-sub d-cat">${esc(r.category)}</div></div></div></td>
        <td>${value}</td>
        <td><span class="sig d-sig" title="${esc(r.pattern)}">${esc(r.pattern)}</span></td>
        <td>${statusBadge(r.status)}</td>
        <td><span class="tag">${esc(typeLabel(r.type))}</span></td>
        <td><div class="hits"><div class="bar"><span style="width:${pct}%"></span></div><span class="num">${r.matches}</span></div></td>
      </tr>`;
    })
    .join("");

  body.querySelectorAll("tr[data-name]").forEach((tr) => tr.addEventListener("click", () => selectRow(tr.dataset.name)));
}

function autoSelect() {
  const first = state.rows.find((r) => r.status === "found") || state.rows[0];
  if (first) selectRow(first.name);
}

function absAddress(row) {
  if (!row.value || row.is_offset || !state.report) return null;
  try {
    return "0x" + (BigInt(state.report.module_base) + BigInt(row.value)).toString(16).toUpperCase();
  } catch {
    return null;
  }
}

function selectRow(name) {
  const row = state.rows.find((r) => r.name === name);
  if (!row) return;
  state.selected = name;
  document.querySelectorAll("#w-body tr").forEach((tr) => tr.classList.toggle("selected", tr.dataset.name === name));

  $("insp-name").textContent = row.name;
  const sb = $("insp-status");
  sb.className = `badge ${statusClass(row.status)}`;
  sb.textContent = statusText(row.status);
  $("insp-desc").textContent = `${typeLabel(row.type)} · ${row.category}`;
  $("insp-hint").hidden = true;
  $("insp-body").hidden = false;

  const abs = absAddress(row);
  $("insp-rva").textContent = row.value || "";
  $("insp-abs").textContent = abs || (row.is_offset ? t("insp.displacement") : "");
  $("insp-aob").textContent = row.pattern;
  $("insp-type").textContent = typeLabel(row.type);
  $("insp-cat").textContent = row.category;
  $("insp-mod").textContent = state.report ? state.report.module_name : "";

  const maxHits = Math.max(1, ...state.rows.map((r) => r.matches));
  $("insp-bar").style.width = `${(row.matches / maxHits) * 100}%`;
  $("insp-hits").textContent = `${row.matches}`;
  $("insp-note").textContent = row.note || t("insp.noNotes");

  $("insp-diag").innerHTML = diagnosticsHtml({
    confidence: row.confidence,
    trace: row.trace || "",
    candidates: row.candidates && row.candidates.length > 1 ? row.candidates.join(",") : "",
  });

  const copy = $("insp-copy");
  copy.disabled = !row.value;
  copy.onclick = async () => {
    await navigator.clipboard.writeText(abs || row.value || "");
    toast(t("toast.addressCopied"));
  };
}

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

async function reparse() {
  state.patterns = await invoke("parse_patterns_text", { text: state.patternText, arch: state.arch });
  $("s-loaded").textContent = state.patterns.length;
}

function refreshPatterns() {
  reparse().then(renderPatterns);
}

function patternMatches(p, term, cat) {
  if (cat !== "all" && p.category !== cat) return false;
  if (!term) return true;
  return (
    p.name.toLowerCase().includes(term) ||
    p.aob.toLowerCase().includes(term) ||
    (p.note || "").toLowerCase().includes(term)
  );
}

function filteredPatterns() {
  const term = $("pattern-search").value.trim().toLowerCase();
  const cat = $("pattern-cat").value || "all";
  return state.patterns.filter((p) => patternMatches(p, term, cat));
}

function patternRecord(p) {
  return { name: p.name, type: typeLabel(p.type), category: p.category, signature: p.aob, note: p.note || "" };
}

function patternLine(p) {
  return `${p.name} = ${p.aob}${p.note ? ` ; ${p.note}` : ""}`;
}

function patternCtxItems(p) {
  return [
    { label: t("ctx.copyName"), action: () => copyText(p.name) },
    { label: t("ctx.copyType"), action: () => copyText(typeLabel(p.type)) },
    { label: t("ctx.copyCategory"), action: () => copyText(p.category) },
    { label: t("ctx.copySignature"), action: () => copyText(p.aob) },
    { label: t("ctx.copyNote"), action: () => copyText(p.note || "") },
    { sep: true },
    { label: t("ctx.copyJson"), action: () => copyText(JSON.stringify(patternRecord(p), null, 2)) },
    { label: t("ctx.copyText"), action: () => copyText(patternLine(p)) },
    { sep: true },
    { label: t("ctx.copyAllJson"), action: () => copyText(JSON.stringify(filteredPatterns().map(patternRecord), null, 2)) },
    { label: t("ctx.copyAllText"), action: () => copyText(filteredPatterns().map(patternLine).join("\n")) },
  ];
}

function renderPatterns() {
  const n = state.patterns.length;
  $("pattern-count").textContent = t(n === 1 ? "pat.countOne" : "pat.count", { n });
  const sel = $("pattern-cat");
  const current = sel.value || "all";
  const cats = [...new Set(state.patterns.map((p) => p.category))].sort();
  sel.innerHTML =
    `<option value="all">${esc(t("pat.allCategories"))}</option>` +
    cats.map((c) => `<option value="${esc(c)}">${esc(c)}</option>`).join("");
  sel.value = [...sel.options].some((o) => o.value === current) ? current : "all";

  const term = $("pattern-search").value.trim().toLowerCase();
  const cat = sel.value;
  const body = $("pattern-body");
  const rows = state.patterns.map((p, i) => ({ p, i })).filter(({ p }) => patternMatches(p, term, cat));

  if (rows.length === 0) {
    body.innerHTML = `<tr class="empty"><td colspan="6">${esc(t("pat.empty"))}</td></tr>`;
    return;
  }

  body.innerHTML = rows
    .map(
      ({ p, i }) => `<tr data-pi="${i}">
      <td class="mono d-name">${esc(p.name)}</td>
      <td><span class="tag">${esc(typeLabel(p.type))}</span></td>
      <td class="d-cat">${esc(p.category)}</td>
      <td><span class="sig d-sig copyable" title="${escAttr(p.aob)}" data-aob="${escAttr(p.aob)}">${esc(p.aob)}</span></td>
      <td class="note-cell d-note">${esc(p.note || "")}</td>
      <td><div class="row-actions">
        <button class="icon-btn" data-edit="${i}">${esc(t("pat.edit"))}</button>
        <button class="icon-btn danger" data-del="${i}">${esc(t("pat.del"))}</button>
      </div></td></tr>`
    )
    .join("");
  body.querySelectorAll("[data-edit]").forEach((b) => b.addEventListener("click", () => openModal(Number(b.dataset.edit))));
  body.querySelectorAll("[data-del]").forEach((b) => b.addEventListener("click", () => deletePattern(Number(b.dataset.del))));
  body.querySelectorAll(".sig.copyable").forEach((el) => el.addEventListener("click", () => copyText(el.dataset.aob)));
  body.querySelectorAll("tr[data-pi]").forEach((tr) =>
    tr.addEventListener("contextmenu", (e) => {
      e.preventDefault();
      const p = state.patterns[Number(tr.dataset.pi)];
      if (p) showCtxMenu(e.clientX, e.clientY, patternCtxItems(p));
    })
  );
}

function regenerate(patterns) {
  const groups = new Map();
  for (const p of patterns) {
    const cat = (p.category || "globals").trim() || "globals";
    if (!groups.has(cat)) groups.set(cat, []);
    groups.get(cat).push(p);
  }
  const lines = [];
  for (const [cat, items] of groups) {
    lines.push(`[${cat}]`);
    for (const p of items) lines.push(`${p.name} = ${p.aob}${p.note && p.note.trim() ? `   ; ${p.note.trim()}` : ""}`);
    lines.push("");
  }
  return lines.join("\n").trimEnd() + "\n";
}

async function commitPatterns(patterns) {
  state.patternText = regenerate(patterns);
  syncEditor();
  await reparse();
  renderPatterns();
}

function deletePattern(index) {
  commitPatterns(state.patterns.filter((_, i) => i !== index));
  toast(t("toast.deleted"));
}

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

function ensureEditor() {
  if (monacoEditor) {
    monacoEditor.layout();
    return;
  }
  if (monacoLoading) return;
  monacoLoading = true;
  $("editor-host").innerHTML = `<div style="padding:18px;color:#64748b">${esc(t("ed.loading"))}</div>`;
  require.config({ paths: { vs: "vs" } });
  require(["vs/editor/editor.main"], () => {
    monaco.languages.register({ id: "maplepat" });
    monaco.languages.setMonarchTokensProvider("maplepat", {
      tokenizer: {
        root: [
          [/\[[^\]]*\]/, "type"],
          [/[;#].*$/, "comment"],
          [/\b([A-Za-z_]\w*?)(_PTR|_CALL|_OFF|_HDR)(?=\s*[:=])/, ["identifier", "tag"]],
          [/\b[A-Za-z_]\w*(?=\s*[:=])/, "identifier"],
          [/\?\?|\?/, "keyword"],
          [/\b0x[0-9A-Fa-f]{1,2}\b/, "number"],
          [/\b[0-9A-Fa-f]{2}\b/, "number"],
          [/[:=,]/, "operator"],
        ],
      },
    });
    monaco.editor.defineTheme("mapledumper", {
      base: "vs-dark",
      inherit: true,
      rules: [
        { token: "comment", foreground: "6e7681", fontStyle: "italic" },
        { token: "type", foreground: "ffa657", fontStyle: "bold" },
        { token: "identifier", foreground: "79c0ff" },
        { token: "tag", foreground: "d2a8ff", fontStyle: "bold" },
        { token: "number", foreground: "7ee787" },
        { token: "keyword", foreground: "f778ba" },
        { token: "operator", foreground: "8b949e" },
      ],
      colors: {
        "editor.background": "#0d121b",
        "editor.foreground": "#e6edf3",
        "editorLineNumber.foreground": "#39414f",
        "editorLineNumber.activeForeground": "#9aa6b6",
        "editor.lineHighlightBackground": "#161d2a",
        "editor.lineHighlightBorder": "#00000000",
        "editor.selectionBackground": "#2d4f7c80",
        "editor.inactiveSelectionBackground": "#2d4f7c40",
        "editorCursor.foreground": "#6cb6ff",
        "editorIndentGuide.background": "#1b2330",
        "editorIndentGuide.activeBackground": "#2d3748",
        "editorBracketMatch.background": "#3b82f633",
        "editorBracketMatch.border": "#3b82f6",
        "editorGutter.background": "#0d121b",
        "editorWidget.background": "#11161f",
        "editorWidget.border": "#232c39",
        "scrollbarSlider.background": "#232c3988",
        "scrollbarSlider.hoverBackground": "#2e3a4a",
        "scrollbarSlider.activeBackground": "#3a4658",
      },
    });
    $("editor-host").innerHTML = "";
    monacoEditor = monaco.editor.create($("editor-host"), {
      value: state.patternText,
      language: "maplepat",
      theme: "mapledumper",
      fontFamily: "Cascadia Code, JetBrains Mono, Consolas, monospace",
      fontLigatures: true,
      fontSize: 14,
      lineHeight: 22,
      letterSpacing: 0.3,
      minimap: { enabled: false },
      automaticLayout: true,
      scrollBeyondLastLine: false,
      padding: { top: 16, bottom: 16 },
      renderLineHighlight: "all",
      cursorBlinking: "smooth",
      cursorSmoothCaretAnimation: "on",
      smoothScrolling: true,
      roundedSelection: true,
      bracketPairColorization: { enabled: true },
      scrollbar: { verticalScrollbarSize: 11, horizontalScrollbarSize: 11 },
    });
    monacoEditor.onDidChangeModelContent(() => (state.patternText = monacoEditor.getValue()));
    monacoLoading = false;
  });
}

function syncEditor() {
  if (monacoEditor && monacoEditor.getValue() !== state.patternText) monacoEditor.setValue(state.patternText);
}

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

const histState = { groups: [], pinA: null, pinB: null, selected: null, tabs: [], activeTab: null, tabSeq: 0 };

function fmtDate(unix) {
  return new Date(unix * 1000).toLocaleString();
}
function scanInfo(id) {
  for (const g of histState.groups) for (const s of g.scans) if (s.id === id) return { scan: s, group: g };
  return null;
}
function verLabel(g) {
  if (!g) return "?";
  return g.build_version ? `v${g.build_version}` : g.build_hash.slice(0, 8);
}
function pinLabel(id) {
  const info = scanInfo(id);
  return info ? `${esc(verLabel(info.group))} · ${esc(fmtDate(info.scan.created_at))}` : "";
}
function renderHistPins() {
  const el = $("hist-pins");
  if (!histState.pinA && !histState.pinB) {
    el.innerHTML = `<span class="pins-hint">${t("hist.pinHint")}</span>`;
  } else {
    const base = histState.pinA ? pinLabel(histState.pinA) : `<span class="pins-empty">${t("hist.unset")}</span>`;
    const target = histState.pinB ? pinLabel(histState.pinB) : `<span class="pins-empty">${t("hist.unset")}</span>`;
    el.innerHTML = `<span class="pins-slot"><span class="pins-tag">${t("hist.base")}</span>${base}</span><span class="pins-arrow">→</span><span class="pins-slot"><span class="pins-tag">${t("hist.target")}</span>${target}</span>`;
  }
  $("hist-compare").disabled = !(histState.pinA && histState.pinB);
}
function renderHistory() {
  const list = $("hist-list");
  if (!histState.groups.length) {
    list.innerHTML = `<div class="empty-pad">${t("hist.empty")}</div>`;
    renderHistPins();
    return;
  }
  list.innerHTML = histState.groups
    .map((g) => {
      const ver = g.build_version ? `v${esc(g.build_version)}` : t("hist.unknownVer");
      const scans = g.scans
        .map(
          (s) =>
            `<div class="hist-scan${s.id === histState.selected ? " active" : ""}" data-id="${s.id}"><div class="hist-scan-main"><span class="hist-scan-time d-addr">${esc(fmtDate(s.created_at))}</span><span class="hist-scan-meta">${esc(s.arch)} · ${t("hist.found")} ${s.found}/${s.total_matches}</span></div><div class="hist-scan-actions"><button class="pin${histState.pinA === s.id ? " pinned" : ""}" data-pin="a" data-id="${s.id}" title="${t("hist.setBase")}">${t("hist.base")}</button><button class="pin${histState.pinB === s.id ? " pinned" : ""}" data-pin="b" data-id="${s.id}" title="${t("hist.setTarget")}">${t("hist.target")}</button><button class="hist-del" data-del="${s.id}" title="${t("hist.delete")}">✕</button></div></div>`,
        )
        .join("");
      return `<div class="hist-group"><div class="hist-group-head" style="--vh:${hueOf(g.build_hash)}"><span class="hist-ver d-name">${ver}</span><span class="hist-hash d-addr">${esc(g.build_hash)}</span><span class="hist-count">${g.scans.length}</span></div>${scans}</div>`;
    })
    .join("");
  list.querySelectorAll(".hist-scan-main").forEach((el) =>
    el.addEventListener("click", () => selectHistScan(Number(el.parentElement.dataset.id))),
  );
  list.querySelectorAll("[data-pin]").forEach((b) =>
    b.addEventListener("click", (e) => {
      e.stopPropagation();
      if (b.dataset.pin === "a") histState.pinA = Number(b.dataset.id);
      else histState.pinB = Number(b.dataset.id);
      renderHistory();
    }),
  );
  list.querySelectorAll("[data-del]").forEach((b) =>
    b.addEventListener("click", (e) => {
      e.stopPropagation();
      deleteHistScan(Number(b.dataset.del));
    }),
  );
  renderHistPins();
}
async function loadHistory() {
  try {
    histState.groups = await invoke("history_builds");
    renderHistory();
    renderTabs();
  } catch (e) {
    toast(String(e), true);
  }
}
function wireDetailSearch() {
  const inp = $("hist-search");
  if (!inp) return;
  const tbody = $("hist-tab-content").querySelector("tbody");
  if (!tbody) return;
  inp.addEventListener("input", () => {
    const term = inp.value.trim().toLowerCase();
    tbody.querySelectorAll("tr").forEach((tr) => {
      tr.style.display = !term || tr.textContent.toLowerCase().includes(term) ? "" : "none";
    });
  });
}

function activateTab(id) {
  histState.activeTab = id;
  const tab = histState.tabs.find((tb) => tb.id === id);
  histState.selected = tab && tab.type === "scan" ? tab.scanId : null;
  renderHistory();
  renderTabs();
  renderActiveTab();
}
function openTab(spec) {
  let tab = histState.tabs.find((tb) => tb.key === spec.key);
  if (!tab) {
    tab = { id: ++histState.tabSeq, ...spec };
    histState.tabs.push(tab);
  }
  activateTab(tab.id);
}
function closeTab(id) {
  const i = histState.tabs.findIndex((tb) => tb.id === id);
  if (i < 0) return;
  histState.tabs.splice(i, 1);
  if (histState.activeTab === id) {
    const next = histState.tabs[i] || histState.tabs[i - 1] || null;
    activateTab(next ? next.id : null);
  } else {
    renderTabs();
  }
}
function startRename(el, id) {
  el.contentEditable = "true";
  el.focus();
  el.addEventListener(
    "blur",
    () => {
      el.contentEditable = "false";
      const tab = histState.tabs.find((tb) => tb.id === id);
      if (tab) tab.title = el.textContent.trim() || tab.title;
      renderTabs();
    },
    { once: true },
  );
  el.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      el.blur();
    }
  });
}
function renderTabs() {
  const bar = $("hist-tabs");
  bar.hidden = histState.tabs.length === 0;
  bar.innerHTML = histState.tabs
    .map(
      (tb) =>
        `<div class="hist-tab${tb.id === histState.activeTab ? " active" : ""}" data-tab="${tb.id}"><span class="hist-tab-title" data-tab="${tb.id}" title="${t("hist.rename")}">${esc(tb.title)}</span><button class="hist-tab-close" data-close="${tb.id}">✕</button></div>`,
    )
    .join("");
  bar.querySelectorAll(".hist-tab-title").forEach((el) => {
    el.addEventListener("click", () => activateTab(Number(el.dataset.tab)));
    el.addEventListener("dblclick", () => startRename(el, Number(el.dataset.tab)));
  });
  bar.querySelectorAll(".hist-tab-close").forEach((b) =>
    b.addEventListener("click", (e) => {
      e.stopPropagation();
      closeTab(Number(b.dataset.close));
    }),
  );
}
async function asmFor(hex, bits, base) {
  if (!hex) return `<div class="sym-empty">${t("hist.noBytes")}</div>`;
  const lines = await invoke("disassemble", { hex, bits, base: base || "0" });
  const hexFmt = hex.replace(/(..)/g, "$1 ").trim();
  const asm = lines.length ? lines.map((l) => esc(l)).join("\n") : esc(hexFmt);
  return `<div class="sym-hex mono">${esc(hexFmt)}</div><pre class="sym-asm">${asm}</pre>`;
}
async function toggleSymDetail(tr) {
  const next = tr.nextElementSibling;
  if (next && next.classList.contains("sym-detail")) {
    next.remove();
    return;
  }
  tr.closest("tbody")
    .querySelectorAll(".sym-detail")
    .forEach((e) => e.remove());
  const bits = Number(tr.dataset.bits) || 64;
  const det = document.createElement("tr");
  det.className = "sym-detail";
  det.innerHTML = `<td colspan="${tr.children.length}"><div class="sym-body">${t("hist.loading")}</div></td>`;
  tr.after(det);
  const body = det.querySelector(".sym-body");
  try {
    if (tr.dataset.kind === "diff") {
      const oldAsm = await asmFor(tr.dataset.oldBytes, bits, tr.dataset.old);
      const newAsm = await asmFor(tr.dataset.newBytes, bits, tr.dataset.new);
      body.innerHTML = `<div class="sym-cols"><div class="sym-col"><div class="sym-h">${t("diff.colOld")} <span class="mono">${esc(tr.dataset.old || "-")}</span></div>${oldAsm}</div><div class="sym-col"><div class="sym-h">${t("diff.colNew")} <span class="mono">${esc(tr.dataset.new || "-")}</span></div>${newAsm}</div></div>`;
    } else {
      const diag = diagnosticsHtml(tr.dataset);
      body.innerHTML = diag + (await asmFor(tr.dataset.bytes, bits, tr.dataset.addr));
    }
  } catch (e) {
    body.textContent = String(e);
  }
}
async function renderActiveTab() {
  const c = $("hist-tab-content");
  const tab = histState.tabs.find((tb) => tb.id === histState.activeTab);
  if (!tab) {
    c.innerHTML = `<div class="insp-hint">${t("hist.selectHint")}</div>`;
    return;
  }
  try {
    if (tab.type === "scan") c.innerHTML = await scanTabHtml(tab);
    else if (tab.type === "diff") c.innerHTML = await diffTabHtml(tab);
    else if (tab.type === "difffiles") c.innerHTML = await diffFilesTabHtml(tab);
    else if (tab.type === "matrix") c.innerHTML = await matrixTabHtml(tab);
    const exp = $("hist-exp");
    if (exp && tab.type === "scan") exp.addEventListener("click", () => exportHistScan(tab.scanId));
    wireDetailSearch();
  } catch (e) {
    toast(String(e), true);
  }
}
function confChip(c) {
  if (c == null || c === "") return "";
  const n = Number(c);
  const cls = n >= 80 ? "hi" : n >= 40 ? "mid" : "lo";
  return ` <span class="conf-chip ${cls}" title="${t("diag.confidence")}">${n}</span>`;
}
function diagnosticsHtml(ds) {
  const parts = [];
  if (ds.confidence != null && ds.confidence !== "") {
    const c = Number(ds.confidence);
    parts.push(
      `<div class="diag-row"><span class="diag-k">${t("diag.confidence")}</span><span class="diag-bar"><span style="width:${c}%"></span></span><span class="diag-v">${c}/100</span></div>`,
    );
  }
  if (ds.trace)
    parts.push(`<div class="diag-row"><span class="diag-k">${t("diag.trace")}</span><span class="diag-v mono d-addr">${esc(ds.trace)}</span></div>`);
  if (ds.candidates)
    parts.push(
      `<div class="diag-row"><span class="diag-k">${t("diag.candidates")}</span><span class="diag-v mono d-addr">${esc(ds.candidates.split(",").join("   "))}</span></div>`,
    );
  return parts.length ? `<div class="sym-diag">${parts.join("")}</div>` : "";
}
async function scanTabHtml(tab) {
  const findings = await invoke("history_findings", { id: tab.scanId });
  if (!findings.length) return `<div class="insp-hint">${t("hist.noFindings")}</div>`;
  const info = scanInfo(tab.scanId);
  const g = info && info.group;
  const bits = info && info.scan.arch === "x86" ? 32 : 64;
  const ver = g && g.build_version ? `v${esc(g.build_version)}` : t("hist.unknownVer");
  const hue = g ? hueOf(g.build_hash) : 210;
  const rows = findings
    .map(
      (f) =>
        `<tr class="sym-row" data-kind="scan" data-bits="${bits}" data-addr="${esc(f.value || "")}" data-bytes="${esc(f.bytes || "")}" data-trace="${esc(f.trace || "")}" data-candidates="${esc(f.candidates || "")}" data-confidence="${f.confidence ?? ""}"><td class="d-name">${esc(f.name)}</td><td class="mono d-addr">${f.value ? esc(f.value) : "-"}</td><td>${catChip(f.category)}</td><td>${statusBadge(f.status)}${confChip(f.confidence)}</td></tr>`,
    )
    .join("");
  return `<div class="hist-banner" style="--vh:${hue}"><span class="hist-banner-ver">${ver}</span><span class="hist-banner-hash">${g ? esc(g.build_hash) : ""}</span><input id="hist-search" class="hist-search" type="text" placeholder="${t("hist.search")}" spellcheck="false" /><button id="hist-exp" class="btn btn-soft">${t("out.copy")}</button></div><div class="table-scroll"><table class="grid-table"><thead><tr><th>${t("col.name")}</th><th>${t("col.address")}</th><th>${t("col.category")}</th><th>${t("col.status")}</th></tr></thead><tbody>${rows}</tbody></table></div>`;
}
async function diffTabHtml(tab) {
  const view = await invoke("history_diff", { a: tab.a, b: tab.b });
  const info = scanInfo(tab.a);
  const bits = info && info.scan.arch === "x86" ? 32 : 64;
  return diffViewHtml(view, bits);
}
async function diffFilesTabHtml(tab) {
  const view = await invoke("diff_dumps", { old: tab.old, new: tab.new });
  return diffViewHtml(view, 64);
}
function diffViewHtml(view, bits) {
  const label = { moved: t("diff.moved"), new: t("diff.new"), removed: t("diff.removed") };
  const cls = { moved: "moved", new: "new", removed: "removed" };
  const tail = view.changed === true ? ` (${t("diff.changed")})` : view.changed === false ? ` (${t("diff.same")})` : "";
  const head = `${view.old_build || "?"} → ${view.new_build || "?"}${tail}`;
  const summary = `${t("diff.unchanged")} ${view.unchanged} · ${t("diff.new")} ${view.added} · ${t("diff.moved")} ${view.moved} · ${t("diff.removed")} ${view.removed}`;
  const rows = view.rows.length
    ? view.rows
        .map(
          (r) =>
            `<tr class="sym-row" data-kind="diff" data-bits="${bits}" data-old="${esc(r.old || "")}" data-new="${esc(r.new || "")}" data-old-bytes="${esc(r.old_bytes || "")}" data-new-bytes="${esc(r.new_bytes || "")}"><td class="d-name">${esc(r.name)}</td><td><span class="diff-tag ${cls[r.state]}">${label[r.state]}</span></td><td class="mono d-addr">${esc(r.old || "-")}</td><td class="mono d-addr">${esc(r.new || "-")}</td><td class="d-cat">${esc(r.category)}</td></tr>`,
        )
        .join("")
    : `<tr class="empty"><td colspan="5">${t("diff.noChanges")}</td></tr>`;
  return `<div class="diff-builds">${esc(head)}</div><div class="diff-summary">${summary}</div><div class="hist-toolbar"><input id="hist-search" class="hist-search" type="text" placeholder="${t("hist.search")}" spellcheck="false" /></div><div class="table-scroll"><table class="grid-table"><thead><tr><th>${t("col.name")}</th><th>${t("diff.colChange")}</th><th>${t("diff.colOld")}</th><th>${t("diff.colNew")}</th><th>${t("col.category")}</th></tr></thead><tbody>${rows}</tbody></table></div>`;
}
async function matrixTabHtml(tab) {
  const view = await invoke("history_matrix", { ids: tab.ids });
  const cols = view.columns.map((c) => `<th class="mx-col">${esc(c.label)}</th>`).join("");
  const rows = view.rows
    .map((r) => {
      let prev = null;
      const cells = r.cells
        .map((v) => {
          const changed = v != null && prev != null && v !== prev;
          if (v != null) prev = v;
          return `<td class="mono d-addr${changed ? " mx-changed" : ""}">${v ? esc(v) : "-"}</td>`;
        })
        .join("");
      return `<tr><td class="d-name mx-name">${esc(r.name)}</td><td>${catChip(r.category)}</td>${cells}</tr>`;
    })
    .join("");
  return `<div class="hist-toolbar"><input id="hist-search" class="hist-search" type="text" placeholder="${t("hist.search")}" spellcheck="false" /></div><div class="table-scroll mx-scroll"><table class="grid-table mx-table"><thead><tr><th class="mx-name">${t("col.name")}</th><th>${t("col.category")}</th>${cols}</tr></thead><tbody>${rows}</tbody></table></div>`;
}
function selectHistScan(id) {
  const info = scanInfo(id);
  openTab({ type: "scan", key: "s" + id, scanId: id, title: info ? verLabel(info.group) : `#${id}` });
}
async function exportHistScan(id) {
  try {
    const text = await invoke("history_export", { id, format: "txt" });
    await navigator.clipboard.writeText(text);
    toast(t("toast.copied"));
  } catch (e) {
    toast(String(e), true);
  }
}
async function deleteHistScan(id) {
  try {
    await invoke("history_delete", { id });
    if (histState.pinA === id) histState.pinA = null;
    if (histState.pinB === id) histState.pinB = null;
    histState.tabs = histState.tabs.filter((tb) => !(tb.type === "scan" && tb.scanId === id));
    if (!histState.tabs.some((tb) => tb.id === histState.activeTab)) {
      histState.activeTab = histState.tabs.length ? histState.tabs[histState.tabs.length - 1].id : null;
    }
    await loadHistory();
    renderActiveTab();
  } catch (e) {
    toast(String(e), true);
  }
}
async function clearHistory() {
  try {
    await invoke("history_clear");
    histState.pinA = null;
    histState.pinB = null;
    histState.tabs = [];
    histState.activeTab = null;
    histState.selected = null;
    await loadHistory();
    renderActiveTab();
  } catch (e) {
    toast(String(e), true);
  }
}
function compareHist() {
  if (!histState.pinA || !histState.pinB) return;
  const a = histState.pinA;
  const b = histState.pinB;
  const ga = (scanInfo(a) || {}).group;
  const gb = (scanInfo(b) || {}).group;
  openTab({ type: "diff", key: `d${a}-${b}`, a, b, title: `${verLabel(ga)} → ${verLabel(gb)}` });
}
function openMatrix() {
  const picks = histState.groups
    .filter((g) => g.scans.length)
    .map((g) => ({ id: g.scans[0].id, at: g.scans[0].created_at }));
  if (picks.length < 2) {
    toast(t("hist.needTwo"), true);
    return;
  }
  picks.sort((x, y) => x.at - y.at);
  const ids = picks.map((p) => p.id);
  openTab({ type: "matrix", key: "m" + ids.join(","), ids, title: t("hist.matrixTitle", { n: ids.length }) });
}
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
