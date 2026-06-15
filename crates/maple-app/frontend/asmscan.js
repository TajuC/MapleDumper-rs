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
    if (Array.isArray(report.warnings)) {
      for (const w of report.warnings) toast(w, true);
    }
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
