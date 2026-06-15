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
  let traceShown = false;
  if (ds.resolverTrace) {
    try {
      const rt = JSON.parse(ds.resolverTrace);
      const seg = [];
      if (rt.resolver) seg.push(esc(rt.resolver));
      if (rt.mnemonic) seg.push(esc(rt.mnemonic));
      if (rt.operand_kind) seg.push(esc(rt.operand_kind));
      if (rt.target_rva != null) seg.push("&rarr; 0x" + Number(rt.target_rva).toString(16).toUpperCase());
      if (rt.target_section) seg.push(esc(rt.target_section));
      if (Array.isArray(rt.checks) && rt.checks.length) seg.push("&check; " + rt.checks.map(esc).join(" "));
      if (rt.failure) seg.push("&cross; " + esc(rt.failure));
      if (seg.length) {
        // The structured trace is richer than the human one-liner (operand, target, checks), so when
        // it round-tripped from history we show it in preference to the plain string.
        parts.push(`<div class="diag-row"><span class="diag-k">${t("diag.trace")}</span><span class="diag-v mono d-addr">${seg.join("  &middot;  ")}</span></div>`);
        traceShown = true;
      }
    } catch {
      /* malformed JSON: fall back to the human string below */
    }
  }
  if (!traceShown && ds.trace)
    parts.push(`<div class="diag-row"><span class="diag-k">${t("diag.trace")}</span><span class="diag-v mono d-addr">${esc(ds.trace)}</span></div>`);
  if (ds.candidates)
    parts.push(
      `<div class="diag-row"><span class="diag-k">${t("diag.candidates")}</span><span class="diag-v mono d-addr">${esc(ds.candidates.split(",").join("   "))}</span></div>`,
    );
  return parts.length ? `<div class="sym-diag">${parts.join("")}</div>` : "";
}
// Bound how many rows a history view materializes at once (DESK-2). A large saved scan, comparison
// matrix, or diff otherwise builds thousands of DOM nodes; the hist-search box narrows the set, and
// this caps the initial render, appending a notice for the remainder.
const MAX_HIST_ROWS = 800;
function capRows(items) {
  return items.length > MAX_HIST_ROWS
    ? { items: items.slice(0, MAX_HIST_ROWS), hidden: items.length - MAX_HIST_ROWS }
    : { items, hidden: 0 };
}
function moreRow(hidden, cols) {
  return hidden > 0
    ? `<tr class="more-row"><td colspan="${cols}">${t("hist.more", { n: hidden })}</td></tr>`
    : "";
}
async function scanTabHtml(tab) {
  const findings = await invoke("history_findings", { id: tab.scanId });
  if (!findings.length) return `<div class="insp-hint">${t("hist.noFindings")}</div>`;
  const info = scanInfo(tab.scanId);
  const g = info && info.group;
  const bits = info && info.scan.arch === "x86" ? 32 : 64;
  const ver = g && g.build_version ? `v${esc(g.build_version)}` : t("hist.unknownVer");
  const hue = g ? hueOf(g.build_hash) : 210;
  const capped = capRows(findings);
  const rows =
    capped.items
      .map(
        (f) =>
          `<tr class="sym-row" data-kind="scan" data-bits="${bits}" data-addr="${esc(f.value || "")}" data-bytes="${esc(f.bytes || "")}" data-trace="${esc(f.trace || "")}" data-candidates="${esc(f.candidates || "")}" data-confidence="${f.confidence ?? ""}" data-resolver-trace="${escAttr(f.resolver_trace || "")}"><td class="d-name">${esc(f.name)}</td><td class="mono d-addr">${f.value ? esc(f.value) : "-"}</td><td>${catChip(f.category)}</td><td>${statusBadge(f.status)}${confChip(f.confidence)}</td></tr>`,
      )
      .join("") + moreRow(capped.hidden, 4);
  let coverage = "";
  try {
    const gapsJson = await invoke("history_read_gaps", { id: tab.scanId });
    if (typeof gapsJson === "string" && gapsJson) {
      const unread = JSON.parse(gapsJson).reduce((a, x) => a + Math.max(0, (x.requested || 0) - (x.got || 0)), 0);
      if (unread > 0) coverage = `<span class="hist-banner-cov" title="${t("diag.coverage")}">&#9888; ${t("diag.coverage")}: ${unread} B</span>`;
    }
  } catch {
    /* a malformed or absent gaps blob just shows no coverage note */
  }
  return `<div class="hist-banner" style="--vh:${hue}"><span class="hist-banner-ver">${ver}</span><span class="hist-banner-hash">${g ? esc(g.build_hash) : ""}</span>${coverage}<input id="hist-search" class="hist-search" type="text" placeholder="${t("hist.search")}" spellcheck="false" /><button id="hist-exp" class="btn btn-soft">${t("out.copy")}</button></div><div class="table-scroll"><table class="grid-table"><thead><tr><th>${t("col.name")}</th><th>${t("col.address")}</th><th>${t("col.category")}</th><th>${t("col.status")}</th></tr></thead><tbody>${rows}</tbody></table></div>`;
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
  const capped = capRows(view.rows);
  const rows = capped.items.length
    ? capped.items
        .map(
          (r) =>
            `<tr class="sym-row" data-kind="diff" data-bits="${bits}" data-old="${esc(r.old || "")}" data-new="${esc(r.new || "")}" data-old-bytes="${esc(r.old_bytes || "")}" data-new-bytes="${esc(r.new_bytes || "")}"><td class="d-name">${esc(r.name)}</td><td><span class="diff-tag ${cls[r.state]}">${label[r.state]}</span></td><td class="mono d-addr">${esc(r.old || "-")}</td><td class="mono d-addr">${esc(r.new || "-")}</td><td class="d-cat">${esc(r.category)}</td></tr>`,
        )
        .join("") + moreRow(capped.hidden, 5)
    : `<tr class="empty"><td colspan="5">${t("diff.noChanges")}</td></tr>`;
  const warn =
    Array.isArray(view.warnings) && view.warnings.length
      ? `<div class="diff-warn">${view.warnings.map((w) => esc(w)).join("<br>")}</div>`
      : "";
  return `${warn}<div class="diff-builds">${esc(head)}</div><div class="diff-summary">${summary}</div><div class="hist-toolbar"><input id="hist-search" class="hist-search" type="text" placeholder="${t("hist.search")}" spellcheck="false" /></div><div class="table-scroll"><table class="grid-table"><thead><tr><th>${t("col.name")}</th><th>${t("diff.colChange")}</th><th>${t("diff.colOld")}</th><th>${t("diff.colNew")}</th><th>${t("col.category")}</th></tr></thead><tbody>${rows}</tbody></table></div>`;
}
async function matrixTabHtml(tab) {
  const view = await invoke("history_matrix", { ids: tab.ids });
  const cols = view.columns.map((c) => `<th class="mx-col">${esc(c.label)}</th>`).join("");
  const capped = capRows(view.rows);
  const rows =
    capped.items
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
      .join("") + moreRow(capped.hidden, view.columns.length + 2);
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
