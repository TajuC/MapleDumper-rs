const unpackState = { mode: "full", input: "", output: "", packed: "", unlicense: "", report: null, running: false };

function unpackSetMode(mode) {
  unpackState.mode = mode;
  const tabs = $("unpack-mode-tabs");
  if (tabs) tabs.querySelectorAll(".tab").forEach((b) => b.classList.toggle("active", b.dataset.umode === mode));
  const packedRow = $("unpack-packed-row");
  if (packedRow) packedRow.hidden = mode !== "clean";
  const ulRow = $("unpack-unlicense-row");
  if (ulRow) ulRow.hidden = mode !== "full";
  const dumpPill = document.querySelector('#unpack-progress .ustage[data-stage="dump"]');
  if (dumpPill) dumpPill.hidden = mode !== "full";
  const hint = $("unpack-input-hint");
  if (hint) {
    const key = mode === "full" ? "unpack.inputHintFull" : "unpack.inputHintClean";
    hint.setAttribute("data-i18n", key);
    hint.textContent = t(key);
  }
  unpackUpdateValidity();
}

async function unpackPick(target) {
  let paths;
  try {
    paths = await invoke("pick_open_files");
  } catch {
    return;
  }
  if (!paths || !paths.length) return;
  unpackState[target] = paths[0];
  const field = $("unpack-" + target);
  if (field) field.value = paths[0];
  unpackUpdateValidity();
}

async function unpackPickOutput() {
  const base = unpackState.input ? unpackState.input.split(/[\\/]/).pop() || "client.exe" : "client.exe";
  const suggested = "unpacked_" + base.replace(/\.exe$/i, "") + ".min.exe";
  let path;
  try {
    path = await invoke("pick_save_file", { defaultName: suggested });
  } catch {
    return;
  }
  if (!path) return;
  unpackState.output = path;
  const field = $("unpack-output");
  if (field) field.value = path;
  unpackUpdateValidity();
}

function unpackUpdateValidity() {
  const btn = $("unpack-run");
  if (btn) btn.disabled = unpackState.running || !unpackState.input || !unpackState.output;
}

function unpackSync() {
  unpackSetMode(unpackState.mode);
  for (const f of ["input", "output", "packed", "unlicense"]) {
    const el = $("unpack-" + f);
    if (el) el.value = unpackState[f];
  }
  unpackUpdateValidity();
}

const UNPACK_STAGE_ORDER = ["dump", "clean", "verify"];
function setUnpackStage(stage) {
  const active = stage === "locate" ? "dump" : stage;
  const idx = UNPACK_STAGE_ORDER.indexOf(active);
  const host = $("unpack-progress");
  if (!host) return;
  host.querySelectorAll(".ustage").forEach((el) => {
    const i = UNPACK_STAGE_ORDER.indexOf(el.dataset.stage);
    const done = stage === "done" || (idx >= 0 && i >= 0 && i < idx);
    el.classList.toggle("active", stage !== "done" && i === idx);
    el.classList.toggle("done", done);
  });
}

function appendUnpackLog(line) {
  const log = $("unpack-log");
  if (!log) return;
  log.textContent += line + "\n";
  log.scrollTop = log.scrollHeight;
}

async function runUnpack() {
  if (!unpackState.input || !unpackState.output) {
    toast(t("unpack.needPaths"), true);
    return;
  }
  unpackState.running = true;
  unpackState.report = null;
  unpackUpdateValidity();
  const prog = $("unpack-progress");
  if (prog) prog.hidden = false;
  const log = $("unpack-log");
  if (log) log.textContent = "";
  setUnpackStage(unpackState.mode === "full" ? "dump" : "clean");
  const host = $("unpack-results");
  if (host) host.innerHTML = `<div class="insp-hint">${esc(t("unpack.working"))}</div>`;

  let unlisten = null;
  const ev = (window.__TAURI__ || {}).event;
  if (ev && ev.listen) {
    try {
      unlisten = await ev.listen("unpack-progress", (e) => {
        const p = e.payload || {};
        if (p.kind === "stage") setUnpackStage(p.stage);
        else if (p.kind === "line") appendUnpackLog(p.line);
      });
    } catch (_) {
      unlisten = null;
    }
  }

  const cleanOnly = unpackState.mode === "clean";
  const args = {
    input: unpackState.input,
    output: unpackState.output,
    cleanOnly,
    packed: cleanOnly && unpackState.packed ? unpackState.packed : null,
    unlicense: !cleanOnly && unpackState.unlicense ? unpackState.unlicense : null,
    unbindIat: $("unpack-unbind") ? $("unpack-unbind").checked : true,
    zeroTimestamp: $("unpack-zerots") ? $("unpack-zerots").checked : true,
  };

  try {
    const report = await invoke("unpack_binary", args);
    unpackState.report = report;
    setUnpackStage("done");
    renderUnpackReport(report);
    if (report.gates_pass) toast(t("unpack.done"));
    else toast(t("unpack.gatesFailed"), true);
  } catch (e) {
    renderUnpackError(String(e));
    toast(String(e), true);
  } finally {
    if (unlisten) unlisten();
    unpackState.running = false;
    unpackUpdateValidity();
  }
}

function uHex(n) {
  return "0x" + (n >>> 0).toString(16);
}

function unpackRefLabel(ref) {
  if (ref === "packed original") return t("unpack.refPacked");
  if (ref === "input dump") return t("unpack.refDump");
  return ref;
}

function uChip(state) {
  if (state === true) return `<span class="u-chip pass">PASS</span>`;
  if (state === false) return `<span class="u-chip fail">FAIL</span>`;
  return `<span class="u-chip na">n/a</span>`;
}

function uGateRow(label, valueHtml, mark) {
  return `<tr><td class="u-gk">${esc(label)}</td><td class="u-gv">${valueHtml}</td><td class="u-gm">${mark === undefined ? "" : uChip(mark)}</td></tr>`;
}

function renderUnpackError(msg) {
  const host = $("unpack-results");
  if (!host) return;
  host.innerHTML = `<div class="u-banner bad">${esc(t("unpack.error"))}</div><div class="u-error">${esc(msg)}</div>`;
}

function renderUnpackReport(r) {
  const host = $("unpack-results");
  if (!host) return;
  const v = r.verify;
  const c = r.clean;
  const pass = !!r.gates_pass;

  let html = `<div class="u-banner ${pass ? "ok" : "bad"}">${esc(pass ? t("unpack.gatesPass") : t("unpack.gatesFail"))}</div>`;

  html += `<div class="u-meta">`;
  html += `<div><span class="muted">${esc(t("unpack.rInput"))}</span> <span class="mono">${esc(r.input)}</span></div>`;
  if (r.dump_path) html += `<div><span class="muted">${esc(t("unpack.rDump"))}</span> <span class="mono">${esc(r.dump_path)}</span></div>`;
  if (r.output) html += `<div><span class="muted">${esc(t("unpack.rOutput"))}</span> <span class="mono">${esc(r.output)}</span></div>`;
  else html += `<div class="u-warn">${esc(t("unpack.notWritten"))}</div>`;
  html += `<div><span class="muted">${esc(t("unpack.rSize"))}</span> <span class="mono">${esc(Number(v.output_size).toLocaleString())}</span></div>`;
  html += `</div>`;

  html += `<div class="sig-section-h">${esc(t("unpack.verifyH"))}</div>`;
  html += `<table class="grid-table u-gates"><tbody>`;
  const oepNote = v.oep_is_msvc ? t("unpack.oepMsvc") : t("unpack.oepOther");
  html += uGateRow("OEP", `<span class="mono">${esc(uHex(v.oep_rva))}</span> <span class="muted">${esc(oepNote)}</span>`, undefined);
  html += uGateRow(t("unpack.rImports"), esc(t("unpack.importsVal", { dlls: v.import_dlls, fns: v.import_functions })), v.imports_ok);
  html += uGateRow(".pdata", esc(t("unpack.pdataVal", { n: v.pdata_entries, valid: v.pdata_valid_pct.toFixed(2), asc: v.pdata_ascending_pct.toFixed(2) })), v.pdata_ok);
  html += uGateRow(t("unpack.rVirt"), esc(t("unpack.virtVal", { pct: v.virtualization_pct.toFixed(4), n: v.virtualization_sampled })), undefined);
  const textVal = v.text_ref ? `<span class="muted">${esc(t("unpack.textVs", { ref: unpackRefLabel(v.text_ref) }))}</span>` : `<span class="muted">${esc(t("unpack.textNa"))}</span>`;
  html += uGateRow(".text identity", textVal, v.text_identity === null ? null : v.text_identity);
  if (v.text_sha256) html += uGateRow(".text SHA-256", `<span class="mono u-sha">${esc(v.text_sha256)}</span>`, undefined);
  html += `</tbody></table>`;

  if (v.oep_disasm && v.oep_disasm.length) {
    html += `<div class="sig-section-h">${esc(t("unpack.disasm"))}</div>`;
    html += `<pre class="mono u-disasm">${v.oep_disasm.map((l) => esc(l)).join("\n")}</pre>`;
  }

  if (v.warnings && v.warnings.length) {
    html += `<div class="sig-section-h">${esc(t("unpack.rWarnings"))}</div><ul class="u-warns">${v.warnings.map((w) => `<li>${esc(w)}</li>`).join("")}</ul>`;
  }

  const summary = [];
  if (c.exception_repointed) summary.push(t("unpack.cExc"));
  if (c.cert_cleared) summary.push(t("unpack.cCert"));
  if (c.iat_dir) summary.push(t("unpack.cIat", { rva: uHex(c.iat_dir[0]), size: uHex(c.iat_dir[1]) }));
  if (c.unbound_thunks) summary.push(t("unpack.cUnbound", { n: c.unbound_thunks }));
  if (c.renamed && c.renamed.length) summary.push(t("unpack.cRenamed", { names: c.renamed.join(", ") }));
  if (c.stripped_bytes) summary.push(t("unpack.cStripped", { bytes: Number(c.stripped_bytes).toLocaleString() }));
  if (c.timestamp_zeroed) summary.push(t("unpack.cTs"));
  if (summary.length) {
    html += `<div class="sig-section-h">${esc(t("unpack.cleanH"))}</div><ul class="u-summary">${summary.map((s) => `<li>${esc(s)}</li>`).join("")}</ul>`;
  }

  host.innerHTML = html;
  if (typeof injectIcons === "function") injectIcons(host);
}
