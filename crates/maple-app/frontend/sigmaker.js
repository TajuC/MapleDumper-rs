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
    html += `<div class="sig-section-h">${t("sig.negHits")} (${r.negative_hits.length})</div>`;
    const ns = r.negative_summary;
    if (ns) {
      html += `<div class="insp-hint">${esc(t("sig.negSummary", { hit: ns.modules_hit, scanned: ns.modules_scanned, total: ns.total_hits, max: ns.max_hits_per_module }))}</div>`;
    }
    html += `<ul class="sig-diags">` +
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
