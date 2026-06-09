// The "Investigate" panel: deep per-function analysis of one address (disassembly, cross-references,
// callers/callees, imported APIs, referenced strings and constants, vtable/RTTI), shown in a modal. Opened
// by clicking an address in the signature maker; caller/callee chips re-open the panel for that function.

let inspCurrent = null; // { path, label }

// Address formatter for the inspector, honoring the global address-display setting and the image base the
// inspect command returned.
function inspAddrFmt(view) {
  const mode = (typeof state !== "undefined" && state.addrMode) || "rva";
  return function (rvaHex) {
    if (!rvaHex) return "-";
    if (mode === "rva" || !view.base) return rvaHex;
    let abs;
    try {
      abs = "0x" + (BigInt(view.base) + BigInt(rvaHex)).toString(16).toUpperCase();
    } catch {
      return rvaHex;
    }
    return mode === "abs" ? abs : `${rvaHex} → ${abs}`;
  };
}

async function openInspector(path, rva, label) {
  const modal = document.getElementById("insp-modal");
  const body = document.getElementById("insp-modal-body");
  if (!modal || !body) return;
  inspCurrent = { path, label };
  modal.hidden = false;
  document.getElementById("insp-modal-title").textContent = t("insp.investigate") + (label ? " · " + label : "");
  body.innerHTML = `<div class="insp-hint">${esc(t("insp.loading"))}</div>`;
  try {
    const view = await invoke("inspect_address", { path, rva });
    body.innerHTML = renderInsight(view);
    if (typeof injectIcons === "function") injectIcons(body);
    wireInspector(body);
  } catch (e) {
    body.innerHTML = `<div class="sig-job-err">${esc(String((e && e.message) || e))}</div>`;
  }
}

function inspStat(label, val) {
  return `<div class="insp-stat"><span class="insp-stat-l">${esc(label)}</span><b class="mono">${esc(val)}</b></div>`;
}

function inspAddrChips(list, fmt) {
  if (!list || !list.length) return `<span class="muted">${esc(t("insp.none"))}</span>`;
  return list.map((a) => `<button class="insp-addr-chip mono" data-rva="${escAttr(a)}" title="${escAttr(t("insp.investigate"))}">${esc(fmt(a))}</button>`).join("");
}

function renderInsight(v) {
  const fmt = inspAddrFmt(v);
  let h = `<div class="insp-head-row">
    <div class="insp-kv"><span>${esc(t("insp.function"))}</span><b class="mono d-addr">${esc(fmt(v.entry_rva))}</b></div>
    <div class="insp-kv"><span>${esc(t("insp.queried"))}</span><b class="mono d-addr">${esc(fmt(v.query_rva))}</b></div>
    ${v.string_anchor ? `<div class="insp-kv wide"><span>${esc(t("insp.anchor"))}</span><code class="mono d-sig">${esc(v.string_anchor)}</code><button class="icon-btn sig-copy" data-aob="${escAttr(v.string_anchor)}">⧉</button></div>` : ""}
  </div>`;
  if (v.vtable) {
    const cls = v.vtable.class_name ? ` · <b>${esc(v.vtable.class_name)}</b>` : ` · <span class="muted">${esc(t("insp.noRtti"))}</span>`;
    h += `<div class="insp-vtable"><span class="ico" data-icon="layers"></span> ${esc(t("insp.vtable"))}: ${esc(t("insp.slot"))} ${v.vtable.slot}/${v.vtable.slot_count} @ <span class="mono">${esc(fmt(v.vtable.table_rva))}</span>${cls}</div>`;
  }
  h += `<div class="insp-stats">` +
    inspStat(t("insp.instrs"), v.instr_count) + inspStat(t("insp.blocks"), v.blocks) +
    inspStat(t("insp.calls"), v.calls) + inspStat(t("insp.branches"), v.branches) +
    inspStat(t("insp.returns"), v.returns) + inspStat(t("insp.xrefs"), v.xref_count) +
    `</div>`;
  h += `<div class="insp-section-h">${esc(t("insp.callers"))} (${v.callers.length})</div><div class="insp-chips">${inspAddrChips(v.callers, fmt)}</div>`;
  h += `<div class="insp-section-h">${esc(t("insp.callees"))} (${v.callees.length})</div><div class="insp-chips">${inspAddrChips(v.callees, fmt)}</div>`;
  if (v.imports && v.imports.length) {
    h += `<div class="insp-section-h">${esc(t("insp.imports"))} (${v.imports.length})</div><div class="insp-chips">${v.imports.map((i) => `<span class="insp-tag mono">${esc(i)}</span>`).join("")}</div>`;
  }
  if (v.strings && v.strings.length) {
    h += `<div class="insp-section-h">${esc(t("insp.strings"))} (${v.strings.length})</div><ul class="insp-strings">${v.strings.map((s) => `<li class="mono d-sig">${esc(s)}</li>`).join("")}</ul>`;
  }
  if (v.constants && v.constants.length) {
    h += `<div class="insp-section-h">${esc(t("insp.constants"))} (${v.constants.length})</div><div class="insp-chips">${v.constants.map((c) => `<span class="insp-tag mono">${esc(c)}</span>`).join("")}</div>`;
  }
  h += `<div class="insp-section-h">${esc(t("insp.disasm"))} (${v.disasm.length})</div>`;
  h += `<div class="insp-disasm mono">` +
    v.disasm.map((d) => `<div class="insp-disrow"><span class="insp-disaddr">${esc(fmt(d.rva))}</span><span class="insp-disbytes">${esc(d.bytes)}</span><span class="insp-distext">${esc(d.text)}</span></div>`).join("") +
    `</div>`;
  return h;
}

function wireInspector(host) {
  host.querySelectorAll(".insp-addr-chip").forEach((b) =>
    b.addEventListener("click", () => {
      if (inspCurrent) openInspector(inspCurrent.path, b.dataset.rva, inspCurrent.label);
    }),
  );
  host.querySelectorAll(".sig-copy").forEach((b) =>
    b.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(b.dataset.aob);
        if (typeof toast === "function") toast(t("toast.copied"));
      } catch {}
    }),
  );
}

function closeInspector() {
  const m = document.getElementById("insp-modal");
  if (m) m.hidden = true;
}

if (typeof document !== "undefined" && document.addEventListener) {
  document.addEventListener("DOMContentLoaded", () => {
    const c = document.getElementById("insp-modal-close");
    if (c) c.addEventListener("click", closeInspector);
    const m = document.getElementById("insp-modal");
    if (m) m.addEventListener("click", (e) => { if (e.target === m) closeInspector(); });
    document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeInspector(); });
  });
}
