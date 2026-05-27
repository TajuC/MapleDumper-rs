const invoke = window.__TAURI__.core.invoke;
const $ = (id) => document.getElementById(id);

/* ---------- icons ---------- */

const SVG = (inner) =>
  `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${inner}</svg>`;

const ICONS = {
  grid: SVG('<rect x="3" y="3" width="18" height="18" rx="2"/><path d="M3 12h18M12 3v18"/>'),
  "file-code": SVG('<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><path d="m10 13-2 2 2 2"/><path d="m14 17 2-2-2-2"/>'),
  terminal: SVG('<polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/>'),
  database: SVG('<ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M3 5v14a9 3 0 0 0 18 0V5"/><path d="M3 12a9 3 0 0 0 18 0"/>'),
  shield: SVG('<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/><path d="m9 12 2 2 4-4"/>'),
  activity: SVG('<polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>'),
  boxes: SVG('<path d="M21 8 12 3 3 8l9 5 9-5z"/><path d="M3 8v8l9 5 9-5V8"/><path d="M12 13v8"/>'),
  play: SVG('<polygon points="6 3 20 12 6 21 6 3"/>'),
  square: SVG('<rect x="5" y="5" width="14" height="14" rx="2"/>'),
  cpu: SVG('<rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/><path d="M9 2v2M15 2v2M9 20v2M15 20v2M2 9h2M2 15h2M20 9h2M20 15h2"/>'),
  download: SVG('<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>'),
  chevron: SVG('<polyline points="6 9 12 15 18 9"/>'),
  folder: SVG('<path d="M4 20h16a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.93a2 2 0 0 1-1.66-.9l-.82-1.2A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13a2 2 0 0 0 2 2z"/>'),
  search: SVG('<circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/>'),
  copy: SVG('<rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>'),
  layers: SVG('<polygon points="12 2 2 7 12 12 22 7 12 2"/><polyline points="2 17 12 22 22 17"/><polyline points="2 12 12 17 22 12"/>'),
  eye: SVG('<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7z"/><circle cx="12" cy="12" r="3"/>'),
  "eye-off": SVG('<path d="M9.88 9.88a3 3 0 1 0 4.24 4.24"/><path d="M10.73 5.08A10.4 10.4 0 0 1 12 5c6.5 0 10 7 10 7a13.5 13.5 0 0 1-1.67 2.68"/><path d="M6.61 6.61A13.5 13.5 0 0 0 2 12s3.5 7 10 7a9.7 9.7 0 0 0 5.39-1.61"/><path d="m2 2 20 20"/>'),
};

function injectIcons(root = document) {
  root.querySelectorAll("[data-icon]").forEach((el) => {
    const target = el.querySelector(".ico") || el;
    if (ICONS[el.dataset.icon]) target.innerHTML = ICONS[el.dataset.icon];
  });
}

/* ---------- state ---------- */

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

function esc(s) {
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

/* ---------- routing ---------- */

function showView(name) {
  document.querySelectorAll(".nav-item").forEach((b) => b.classList.toggle("active", b.dataset.view === name));
  document.querySelectorAll(".view").forEach((v) => v.classList.toggle("active", v.id === `view-${name}`));
  if (name === "patterns") refreshPatterns();
  if (name === "editor") ensureEditor();
}
document.querySelectorAll(".nav-item").forEach((b) => b.addEventListener("click", () => showView(b.dataset.view)));
$("open-editor").addEventListener("click", () => showView("editor"));

/* ---------- window controls ---------- */

function currentWindow() {
  const t = window.__TAURI__ || {};
  if (t.window && t.window.getCurrentWindow) return t.window.getCurrentWindow();
  if (t.webviewWindow && t.webviewWindow.getCurrentWebviewWindow) return t.webviewWindow.getCurrentWebviewWindow();
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
  /* window controls unavailable outside the desktop shell */
}

/* ---------- privacy mask ---------- */

let masked = false;
$("mask-toggle").addEventListener("click", () => {
  masked = !masked;
  document.body.classList.toggle("masked", masked);
  const btn = $("mask-toggle");
  btn.classList.toggle("active", masked);
  btn.querySelector(".ico").innerHTML = ICONS[masked ? "eye-off" : "eye"];
  btn.title = masked ? "Show signatures" : "Mask signatures for screenshots";
});

/* ---------- toggles ---------- */

$("t-arch").addEventListener("click", () => {
  state.arch = state.arch === "x64" ? "x86" : "x64";
  const on = state.arch === "x64";
  $("t-arch").classList.toggle("active", on);
  $("t-arch-label").textContent = on ? "64-bit" : "32-bit";
});
$("t-wait").addEventListener("click", () => {
  state.wait = !state.wait;
  $("t-wait").classList.toggle("active", state.wait);
});
$("t-class").addEventListener("click", () => {
  state.byClass = !state.byClass;
  $("t-class").classList.toggle("active", state.byClass);
  $("target-label").textContent = state.byClass ? "Window class" : "Target process";
  $("w-target").placeholder = state.byClass ? "Window class name" : "MapleStory.exe";
});
$("t-code").addEventListener("click", () => {
  state.codeOnly = !state.codeOnly;
  $("t-code").classList.toggle("active", state.codeOnly);
});

/* ---------- connection + footer ---------- */

function setConn(text, cls) {
  $("conn-text").textContent = text;
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

function setFoot(title, sub) {
  $("foot-title").textContent = title;
  $("foot-sub").textContent = sub;
}

function fmtMs(ms) {
  return ms < 1000 ? `${ms} ms` : `${(ms / 1000).toFixed(2)} s`;
}

/* ---------- scan ---------- */

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
    toast("Enter a target process or window class.", true);
    return;
  }

  $("w-scan").disabled = true;
  $("w-stop").disabled = false;
  setConn(state.wait ? "Waiting" : "Scanning", state.wait ? "wait" : "run");
  setRing("run");
  setFoot(state.wait ? "Waiting for target…" : "Scanning patterns…", state.wait ? "Will attach the moment it appears." : "Reading committed memory regions.");

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
    setConn("Attached", "ok");
    setRing("done", total ? (report.found / total) * 100 : 0);
    const mb = report.bytes_scanned / 1048576;
    const gbs = report.scan_ms > 0 ? report.bytes_scanned / (report.scan_ms / 1000) / 1073741824 : 0;
    setFoot(
      "Scan complete",
      `${report.found} of ${total} resolved · ${mb.toFixed(0)} MB @ ${gbs.toFixed(2)} GB/s · attach ${report.attach_ms} ms`
    );
  } catch (err) {
    setConn("Error", "err");
    setRing("done", 0);
    setFoot("Scan failed", String(err));
    toast(String(err), true);
  } finally {
    $("w-scan").disabled = false;
    $("w-stop").disabled = true;
  }
}

$("w-scan").addEventListener("click", runScan);
$("w-stop").addEventListener("click", () => {
  invoke("cancel_scan");
  setConn("Cancelled", "");
  setRing("done", 0);
  setFoot("Cancelled", "The scan was stopped.");
});

/* ---------- results table ---------- */

function buildTabs() {
  const cats = [...new Set(state.rows.map((r) => r.category))].sort();
  const host = $("w-tabs");
  host.innerHTML =
    `<button class="tab ${state.activeCat === "all" ? "active" : ""}" data-cat="all">All</button>` +
    cats
      .map((c) => `<button class="tab ${state.activeCat === c ? "active" : ""}" data-cat="${esc(c)}">${esc(c)}</button>`)
      .join("");
  host.querySelectorAll(".tab").forEach((t) =>
    t.addEventListener("click", () => {
      state.activeCat = t.dataset.cat;
      buildTabs();
      renderResults();
    })
  );
}

function accentClass(row) {
  if (row.status !== "found") return "dot-muted";
  return row.kind === "call" || row.kind === "header" ? "dot-violet" : "dot-blue";
}

function typeLabel(kind) {
  return { pointer: "Pointer", call: "Function", offset: "Offset", header: "Header", direct: "Address" }[kind] || kind;
}

function statusBadge(status) {
  const cls = status === "not found" ? "notfound" : status;
  return `<span class="badge ${cls}">${status === "not found" ? "Not Found" : status[0].toUpperCase() + status.slice(1)}</span>`;
}

function renderResults() {
  const term = $("w-search").value.trim().toLowerCase();
  const body = $("w-body");
  const maxHits = Math.max(1, ...state.rows.map((r) => r.matches));
  $("w-count").textContent = state.rows.length;

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
    body.innerHTML = `<tr class="empty"><td colspan="6">${
      state.rows.length ? "No rows match this filter." : "No scan yet. Set a target and click Start Scan."
    }</td></tr>`;
    return;
  }

  body.innerHTML = rows
    .map((r) => {
      const pct = (r.matches / maxHits) * 100;
      const value = r.value
        ? `<span class="mono">${r.value}</span>`
        : '<span class="muted"></span>';
      return `<tr data-name="${esc(r.name)}" class="${state.selected === r.name ? "selected" : ""}">
        <td><div class="name-cell"><span class="dot-acc ${accentClass(r)}"></span>
          <div><div class="name-main">${esc(r.name)}</div><div class="name-sub">${esc(r.category)}</div></div></div></td>
        <td>${value}</td>
        <td><span class="sig" title="${esc(r.pattern)}">${esc(r.pattern)}</span></td>
        <td>${statusBadge(r.status)}</td>
        <td><span class="tag">${typeLabel(r.kind)}</span></td>
        <td><div class="hits"><div class="bar"><span style="width:${pct}%"></span></div><span class="num">${r.matches}</span></div></td>
      </tr>`;
    })
    .join("");

  body.querySelectorAll("tr[data-name]").forEach((tr) =>
    tr.addEventListener("click", () => selectRow(tr.dataset.name))
  );
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
  sb.className = `badge ${row.status === "not found" ? "notfound" : row.status}`;
  sb.textContent = row.status === "not found" ? "Not Found" : row.status[0].toUpperCase() + row.status.slice(1);
  $("insp-desc").textContent = `${typeLabel(row.kind)} · ${row.category}`;
  $("insp-hint").hidden = true;
  $("insp-body").hidden = false;

  const abs = absAddress(row);
  $("insp-rva").textContent = row.value || "";
  $("insp-abs").textContent = abs || (row.is_offset ? "displacement" : "");
  $("insp-aob").textContent = row.pattern;
  $("insp-type").textContent = typeLabel(row.kind);
  $("insp-cat").textContent = row.category;
  $("insp-mod").textContent = state.report ? state.report.module_name : "";

  const maxHits = Math.max(1, ...state.rows.map((r) => r.matches));
  $("insp-bar").style.width = `${(row.matches / maxHits) * 100}%`;
  $("insp-hits").textContent = `${row.matches}`;
  $("insp-note").textContent = row.note || "No notes";

  const copy = $("insp-copy");
  copy.disabled = !row.value;
  copy.onclick = async () => {
    await navigator.clipboard.writeText(abs || row.value || "");
    toast("Address copied");
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
    $("w-source").value = path.split(/[\\/]/).pop();
    $("s-loaded").textContent = state.patterns.length;
    toast(`Loaded ${state.patterns.length} patterns`);
  } catch (err) {
    toast(String(err), true);
  }
});

/* ---------- export ---------- */

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
      $("output-label").textContent = `${b.textContent} · ${text.split("\n").length} lines`;
      $("output-text").dataset.suggest =
        b.dataset.export === "header" ? "offsets.h" : b.dataset.export === "ce" ? "table.CT" : "offsets.txt";
      showView("output");
    } catch (err) {
      toast(String(err), true);
    }
  })
);

$("out-copy").addEventListener("click", async () => {
  await navigator.clipboard.writeText($("output-text").textContent);
  toast("Copied to clipboard");
});
$("out-save").addEventListener("click", async () => {
  const path = await invoke("pick_save_file", { defaultName: $("output-text").dataset.suggest || "output.txt" });
  if (!path) return;
  try {
    await invoke("write_text_file", { path, contents: $("output-text").textContent });
    toast(`Saved to ${path}`);
  } catch (err) {
    toast(String(err), true);
  }
});

/* ---------- patterns ---------- */

async function reparse() {
  state.patterns = await invoke("parse_patterns_text", { text: state.patternText, arch: state.arch });
  $("s-loaded").textContent = state.patterns.length;
}

function refreshPatterns() {
  reparse().then(renderPatterns);
}

function renderPatterns() {
  $("pattern-count").textContent = `${state.patterns.length} pattern${state.patterns.length === 1 ? "" : "s"}`;
  const sel = $("pattern-cat");
  const current = sel.value || "all";
  const cats = [...new Set(state.patterns.map((p) => p.category))].sort();
  sel.innerHTML = '<option value="all">All categories</option>' + cats.map((c) => `<option value="${esc(c)}">${esc(c)}</option>`).join("");
  sel.value = [...sel.options].some((o) => o.value === current) ? current : "all";

  const term = $("pattern-search").value.trim().toLowerCase();
  const cat = sel.value;
  const body = $("pattern-body");
  const rows = state.patterns
    .map((p, i) => ({ p, i }))
    .filter(({ p }) => {
      if (cat !== "all" && p.category !== cat) return false;
      if (!term) return true;
      return p.name.toLowerCase().includes(term) || p.aob.toLowerCase().includes(term) || (p.note || "").toLowerCase().includes(term);
    });

  if (rows.length === 0) {
    body.innerHTML = `<tr class="empty"><td colspan="6">No patterns. Use + Add or load a file.</td></tr>`;
    return;
  }

  body.innerHTML = rows
    .map(
      ({ p, i }) => `<tr>
      <td class="mono">${esc(p.name)}</td>
      <td><span class="tag">${p.kind}</span></td>
      <td>${esc(p.category)}</td>
      <td><span class="sig" title="${esc(p.aob)}">${esc(p.aob)}</span></td>
      <td class="note-cell">${esc(p.note || "")}</td>
      <td><div class="row-actions">
        <button class="icon-btn" data-edit="${i}">edit</button>
        <button class="icon-btn danger" data-del="${i}">del</button>
      </div></td></tr>`
    )
    .join("");
  body.querySelectorAll("[data-edit]").forEach((b) => b.addEventListener("click", () => openModal(Number(b.dataset.edit))));
  body.querySelectorAll("[data-del]").forEach((b) => b.addEventListener("click", () => deletePattern(Number(b.dataset.del))));
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
  toast("Pattern deleted");
}

$("pattern-search").addEventListener("input", renderPatterns);
$("pattern-cat").addEventListener("change", renderPatterns);
$("pat-add").addEventListener("click", () => openModal(-1));
$("pat-load").addEventListener("click", async () => {
  const path = await invoke("pick_open_file");
  if (!path) return;
  try {
    state.patternText = await invoke("read_text_file", { path });
    $("w-source").value = path.split(/[\\/]/).pop();
    syncEditor();
    await reparse();
    renderPatterns();
    toast(`Loaded ${state.patterns.length} patterns`);
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
    toast(`Saved to ${path}`);
  } catch (err) {
    toast(String(err), true);
  }
});

/* ---------- modal ---------- */

function openModal(index) {
  state.editingIndex = index;
  const p = index >= 0 ? state.patterns[index] : null;
  $("modal-title").textContent = p ? "Edit pattern" : "Add pattern";
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
    toast("Name and signature are required.", true);
    return;
  }
  const entry = { name, category: $("f-cat").value.trim() || "globals", aob, note: $("f-note").value.trim() };
  const next = state.patterns.slice();
  if (state.editingIndex >= 0) next[state.editingIndex] = entry;
  else next.push(entry);
  const wasEdit = state.editingIndex >= 0;
  closeModal();
  await commitPatterns(next);
  toast(wasEdit ? "Pattern updated" : "Pattern added");
});

/* ---------- editor (monaco) ---------- */

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
  $("editor-host").innerHTML = '<div style="padding:18px;color:#64748b">loading editor…</div>';
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
    $("w-source").value = path.split(/[\\/]/).pop();
    syncEditor();
    toast("Loaded");
  } catch (err) {
    toast(String(err), true);
  }
});
$("ed-save").addEventListener("click", async () => {
  const path = await invoke("pick_save_file", { defaultName: "patterns.txt" });
  if (!path) return;
  try {
    await invoke("write_text_file", { path, contents: state.patternText });
    toast(`Saved to ${path}`);
  } catch (err) {
    toast(String(err), true);
  }
});
$("ed-apply").addEventListener("click", async () => {
  if (monacoEditor) state.patternText = monacoEditor.getValue();
  await reparse();
  renderPatterns();
  toast(`Applied ${state.patterns.length} patterns`);
});

/* ---------- boot ---------- */

(async function boot() {
  injectIcons();
  try {
    $("engine-badge").textContent = `Engine ${await invoke("engine_version")}`;
  } catch {
    $("engine-badge").textContent = "Engine offline";
  }
  await reparse();
})();
