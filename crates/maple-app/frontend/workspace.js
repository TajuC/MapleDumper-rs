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
      const value = r.value ? `<span class="mono d-addr">${esc(r.value)}</span>` : '<span class="muted"></span>';
      return `<tr data-name="${esc(r.name)}" tabindex="0" aria-selected="${state.selected === r.name}" class="${state.selected === r.name ? "selected" : ""}">
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

  body.querySelectorAll("tr[data-name]").forEach((tr) => {
    tr.addEventListener("click", () => selectRow(tr.dataset.name));
    tr.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        selectRow(tr.dataset.name);
      }
    });
  });
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
  document.querySelectorAll("#w-body tr").forEach((tr) => {
    const sel = tr.dataset.name === name;
    tr.classList.toggle("selected", sel);
    if (tr.dataset.name) tr.setAttribute("aria-selected", String(sel));
  });

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

function renderScanDiag(report) {
  const host = $("scan-diag");
  if (!report) {
    host.hidden = true;
    return;
  }
  host.hidden = false;
  const total = Math.max(1, report.elapsed_ms);
  const seg = (cls, ms) => `<span class="tl-seg ${cls}" style="width:${(ms / total) * 100}%"></span>`;
  const timeline = `<div class="diag-head">${t("diag.timeline")}</div><div class="timeline">${seg("tl-attach", report.attach_ms)}${seg("tl-scan", report.scan_ms)}</div><div class="tl-legend"><span><i class="tl-dot tl-attach"></i>${t("diag.attach")} ${fmtMs(report.attach_ms)}</span><span><i class="tl-dot tl-scan"></i>${t("diag.scanPhase")} ${fmtMs(report.scan_ms)}</span></div>`;
  const regions = report.regions_detail || [];
  const maxF = Math.max(1, ...regions.map((r) => r.findings));
  const sect = regions
    .map(
      (r) =>
        `<div class="sect-row"><span class="mono d-addr">${esc(r.base)}</span><span class="sect-bar"><span style="width:${(r.findings / maxF) * 100}%"></span></span><span class="sect-n">${r.findings}</span></div>`,
    )
    .join("");
  const sectionMap = `<div class="diag-head">${t("diag.sectionMap")}</div><div class="sect-list">${sect || `<div class="muted">${t("diag.noRegions")}</div>`}</div>`;
  host.innerHTML = `<div class="diag-col">${timeline}</div><div class="diag-col">${sectionMap}</div>`;
}
