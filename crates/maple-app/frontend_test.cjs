// Headless smoke test for the desktop frontend (run: `node crates/maple-app/frontend_test.cjs`).
// Stubs a DOM, loads app.js, drives the Signature Maker render path, and asserts the HTML.
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const noop = () => {};
function clStub() {
  return { toggle: noop, add: noop, remove: noop, contains: () => false };
}
function makeEl() {
  const store = { value: "", dataset: {}, style: {}, classList: clStub() };
  return new Proxy(function () {}, {
    get(_t, p) {
      if (p === "classList") return store.classList;
      if (p === "dataset") return store.dataset;
      if (p === "style") return store.style;
      if (p === "querySelectorAll") return () => [];
      if (p === "querySelector" || p === "closest") return () => null;
      if (p === "options" || p === "children") return [];
      if (p === "parentElement" || p === "nextElementSibling") return null;
      if (p in store) return store[p];
      return noop;
    },
    set(_t, p, v) {
      store[p] = v;
      return true;
    },
    apply() {},
  });
}

const els = {};
const byId = (id) => (els[id] ||= makeEl());
const invoke = (cmd) => (cmd === "engine_version" ? Promise.resolve("test") : Promise.resolve([]));
const localStorage = { getItem: () => null, setItem: noop, removeItem: noop };
const MutationObserver = class {
  observe() {}
  disconnect() {}
};
const sandbox = {
  window: {
    __TAURI__: { core: { invoke }, event: { listen: () => Promise.resolve(() => {}) }, window: {}, webviewWindow: {} },
    localStorage,
    MutationObserver,
    addEventListener: noop,
  },
  document: {
    getElementById: byId,
    querySelectorAll: () => [],
    querySelector: () => null,
    createElement: () => makeEl(),
    addEventListener: noop,
    documentElement: makeEl(),
    body: makeEl(),
  },
  navigator: { clipboard: { writeText: () => Promise.resolve() } },
  localStorage,
  MutationObserver,
  requestAnimationFrame: (cb) => setTimeout(cb, 0),
  console,
  setTimeout,
  clearTimeout,
};
sandbox.window.document = sandbox.document;
process.on("unhandledRejection", noop);

const driver = `
;try {
  sigState.files = [
    { path: "C:/a.exe", name: "a.exe", arch: "x64", packed: false, reasons: [], max_entropy: 6.1 },
    { path: "C:/b.exe", name: "b.exe", arch: "x64", packed: true, reasons: ["high entropy 7.90 in .text"], max_entropy: 7.9 },
  ];
  renderSigFiles();
  globalThis.__filesHtml = document.getElementById("sig-files").innerHTML;
  globalThis.__alertHidden = document.getElementById("sig-alert").hidden;
  const fakeReport = {
    arch: "x64", unique_builds: 2,
    inputs: [ { label: "a.exe", packed: false, reasons: [] }, { label: "b.exe", packed: true, reasons: ["x"] } ],
    duplicate_groups: [ ["DEADBEEFCAFE0001", ["a.exe", "c.exe"]] ],
    chosen: { aob: "E8 ?? ?? ?? ?? 48 83 C4 ??", suffix: "_CALL", grade: "A", score: 88, bytes: 14, fixed: 5, wildcards: 9, fixed_ratio: 0.36, reloc_safe: true, scores: { uniqueness: 91, stability: 80, entropy: 74, semantic: 85, resolver_confidence: 90, cross_build: 77, final_score: 88 }, reasons: ["validated branch to code", "callee fingerprint stable across builds"], per_version: [ { label: "a.exe", match_rva: "0x23B64", resolved_target_rva: "0x24190", target_type: "code", fingerprint_similarity: 0.97 } ], diags: [] },
    alternates: [ { aob: "48 89 5C 24 ??", suffix: "", grade: "B", score: 70, bytes: 5, fixed: 4, wildcards: 1, fixed_ratio: 0.8, reloc_safe: true, scores: { uniqueness: 72, stability: 88, entropy: 60, semantic: 40, resolver_confidence: 55, cross_build: 50, final_score: 70 }, reasons: ["reloc-safe, not content-validated"], per_version: [ { label: "a.exe", match_rva: "0x24190", resolved_target_rva: null, target_type: null, fingerprint_similarity: null } ], diags: [] } ],
    rejected: [ { aob: "90", suffix: "", grade: "F", score: 0, bytes: 1, fixed: 1, wildcards: 0, fixed_ratio: 1, reloc_safe: true, scores: { uniqueness: 0, stability: 0, entropy: 0, semantic: 0, resolver_confidence: 0, cross_build: 0, final_score: 0 }, reasons: [], per_version: [], diags: ["too few fixed bytes (1)"] } ],
    diagnostics: ["packed input b.exe: high entropy 7.90 in .text"],
    holdout: [
      { held_out: "a.exe", generated: true, matched: true },
      { held_out: "b.exe", generated: true, matched: false },
    ],
    string_anchor: "@string=UI/UIWindow2.img/Stat",
    negative_hits: [{ label: "other.dll", count: 2 }],
    negative_summary: { modules_scanned: 4, modules_hit: 1, total_hits: 2, max_hits_per_module: 2 },
  };
  sigState.response = { jobs: [
    { label: "E8 ?? ?? ?? ?? 48 83 C4 ??", report: fakeReport, cross: null, error: null },
    { label: "0x24190", report: fakeReport, cross: { expected_rva: "0x24190", matched_rva: "0x24190", agrees: true }, error: null },
    { label: "zz zz", report: null, cross: null, error: "invalid signature: bad hex byte 'zz'" },
  ] };
  renderSigResults();
  globalThis.__reportHtml = document.getElementById("sig-results").innerHTML;
  // A declined 3-target run (template-clone target): no chosen signature, but a structural family and
  // partial byte matches are surfaced, and absolute addressing (base + rva) is exercised via "both" mode.
  state.addrMode = "both";
  const declined = {
    arch: "x86", unique_builds: 3,
    inputs: [ { label: "v83", packed: false, reasons: [] }, { label: "v84", packed: false, reasons: [] }, { label: "v88", packed: false, reasons: [] } ],
    duplicate_groups: [], chosen: null, alternates: [], rejected: [],
    shortlists: [ { label: "v84", candidates: [ { rva: "0x31799C", similarity: 0.974, aob: "89 45 ?? E8 ?? ?? ?? ??" }, { rva: "0x448A6E", similarity: 0.974, aob: null } ] } ],
    diagnostics: ["found in v83 at 0x4D6D95", "found in v84 at 0x4DE0BA", "not found in v88"],
    holdout: [], string_anchor: null, negative_hits: [], negative_summary: null,
    bases: [ { label: "v83", base: "0x400000" }, { label: "v84", base: "0x400000" }, { label: "v88", base: "0x400000" } ],
  };
  sigState.response = { jobs: [ { label: "B3 ?? 83 EC", report: declined, cross: null, error: null } ] };
  renderSigResults();
  globalThis.__declinedHtml = document.getElementById("sig-results").innerHTML;
  state.addrMode = "rva";
  globalThis.__diagHtml = diagnosticsHtml({ confidence: "50", trace: "memory pointer resolved to 0x10", candidates: "0x10,0x20" });
  globalThis.__diagStructured = diagnosticsHtml({ resolverTrace: JSON.stringify({ resolver: "nested call", mnemonic: "call", operand_kind: "nearbranch64", target_rva: 0x24190, target_section: "code", checks: ["range", "section"], failure: null }) });
  globalThis.__confHi = confChip(95);
  globalThis.__confLo = confChip(10);
  globalThis.__confNone = confChip(null);
  state.rows = [
    { name: "Amb", category: "globals", type: "pointer", value: "0x300", is_offset: false, matches: 2, status: "found (ambiguous)", note: "", pattern: "CA FE", confidence: 50, trace: "match address resolved to 0x300", candidates: ["0x300", "0x400"] },
  ];
  state.report = { module_name: "MapleStory.exe", module_base: "0x140000000" };
  selectRow("Amb");
  globalThis.__inspDiag = document.getElementById("insp-diag").innerHTML;
  globalThis.__fake = fakeFor("name", "SendPacket");
  applyMask();
  globalThis.__maskOk = true;
  renderScanDiag({ elapsed_ms: 100, attach_ms: 30, scan_ms: 70, regions_detail: [
    { base: "0x1000", size: 4096, findings: 3 }, { base: "0x5000", size: 2048, findings: 1 },
  ] });
  globalThis.__scanDiag = document.getElementById("scan-diag").innerHTML;
  state.rows = [
    { name: "EscRow", category: "globals", type: "pointer", value: "0x10<script>", is_offset: false, matches: 1, status: "found", note: "", pattern: "AA BB", confidence: null, trace: "", candidates: [] },
  ];
  renderResults();
  globalThis.__wsBody = document.getElementById("w-body").innerHTML;
  globalThis.__cap = capRows(new Array(900).fill(0));
  globalThis.__more = moreRow(100, 4);
  // Unpack report card: the verification gates must render (a silent drop here once shipped a broken UI).
  const fakeUnpack = {
    input: "C:/x/269.1.exe", output: "C:/x/unpacked_269.1.min.exe", dump_path: "C:/x/unpacked_269.1.exe", gates_pass: true,
    clean: { exception_repointed: true, cert_cleared: true, iat_dir: [0x7251000, 0x13c8], unbound_thunks: 591, deexec: [".themida", ".boot", ".SCY"], renamed: [".themida", ".boot"], timestamp_zeroed: true, stripped_bytes: 35555840, size_before: 193601536, size_after: 150477312 },
    verify: { oep_rva: 0x6a2c61c, oep_bytes: "48895c2420", oep_is_msvc: true, oep_disasm: ["0x146a2c61c: mov [rsp+20h],rbx", "0x146a2c621: push rbp"], import_dlls: 39, import_functions: 591, imports_ok: true, pdata_entries: 361813, pdata_valid_pct: 99.99, pdata_ascending_pct: 100.0, pdata_ok: true, virtualization_pct: 0.0, virtualization_sampled: 2010, text_identity: true, text_ref: "packed original", text_sha256: "481e121e10f10028b8e180b9c6d17c54", output_size: 150477312, gates_pass: true, warnings: [] },
  };
  unpackState.report = fakeUnpack;
  renderUnpackReport(fakeUnpack);
  globalThis.__unpackHtml = document.getElementById("unpack-results").innerHTML;
  const failUnpack = JSON.parse(JSON.stringify(fakeUnpack));
  failUnpack.gates_pass = false; failUnpack.output = null; failUnpack.verify.text_identity = false; failUnpack.verify.gates_pass = false;
  renderUnpackReport(failUnpack);
  globalThis.__unpackFailHtml = document.getElementById("unpack-results").innerHTML;
} catch (e) { globalThis.__renderError = String((e && e.stack) || e); }
`;

const i18nCode = fs.readFileSync(path.join(__dirname, "frontend", "i18n.js"), "utf8");
const iconsCode = fs.readFileSync(path.join(__dirname, "frontend", "icons.js"), "utf8");
const maskingCode = fs.readFileSync(path.join(__dirname, "frontend", "masking.js"), "utf8");
const inspectorCode = fs.readFileSync(path.join(__dirname, "frontend", "inspector.js"), "utf8");
const sigCode = fs.readFileSync(path.join(__dirname, "frontend", "sigmaker.js"), "utf8");
const histCode = fs.readFileSync(path.join(__dirname, "frontend", "history.js"), "utf8");
const readFront = (f) => fs.readFileSync(path.join(__dirname, "frontend", f), "utf8");
const code =
  i18nCode + iconsCode + maskingCode + inspectorCode + sigCode + readFront("unpack.js") + histCode +
  readFront("asmscan.js") + readFront("workspace.js") + readFront("patterns.js") + readFront("editor.js") +
  readFront("app.js") + driver;
try {
  vm.runInNewContext(code, sandbox, { filename: "app.js" });
} catch (e) {
  console.error("LOAD THREW:", e);
  process.exit(1);
}

const fails = [];
const check = (cond, msg) => {
  if (!cond) fails.push(msg);
};
check(!sandbox.__renderError, `render threw: ${sandbox.__renderError}`);
const files = sandbox.__filesHtml || "";
check(files.includes("a.exe") && files.includes("b.exe"), "file chips missing names");
check(files.includes("Unpacked") && files.includes("Packed"), "file chips missing packed/unpacked badges");
check(files.includes("entropy 7.90"), "packed chip tooltip missing entropy");
check(sandbox.__alertHidden === false, "packed alert should be visible when a file is packed");
const rep = sandbox.__reportHtml || "";
check(rep.includes("E8 ?? ?? ?? ??") && rep.includes("_CALL"), "chosen AOB/suffix missing");
check(rep.includes(">A<"), "chosen grade badge missing");
check(rep.includes("0x24190"), "resolved target RVA missing from per-version table");
check(rep.includes("Score breakdown") && rep.includes("sig-sc-fill"), "score breakdown bars missing");
check(rep.includes("Unique") && rep.includes(">91<") && rep.includes("Final") && rep.includes(">88<"), "sub-score values missing");
check(rep.includes("Why this grade") && rep.includes("callee fingerprint stable across builds"), "candidate reasons missing");
check(rep.includes("Fingerprint") && rep.includes("97%"), "fingerprint-similarity column/value missing");
check(rep.includes(">-<"), "null fingerprint similarity should render as -");
check(rep.includes("Alternates") && rep.includes("Rejected"), "alternates/rejected sections missing");
check(rep.includes("Duplicate builds") && rep.includes("DEADBEEFCAFE0001"), "duplicate-build section missing");
check(rep.includes("Diagnostics"), "diagnostics section missing");
check(rep.includes("Holdout validation") && rep.includes("(1/2)"), "holdout section/summary missing");
check(rep.includes("matched the held-out build"), "holdout pass verdict missing");
check(rep.includes("did not match the held-out build"), "holdout miss verdict missing");
check(rep.includes("String anchor") && rep.includes("@string=UI/UIWindow2.img/Stat"), "string anchor suggestion missing");
check(rep.includes("Negative corpus matches") && rep.includes("other.dll"), "negative corpus hits missing");
check(rep.includes("1 of 4 module(s) matched") && rep.includes("2 total"), "negative corpus summary line missing");
check(rep.includes("2 file(s)") && rep.includes("2 unique build(s)"), "input summary missing");
check(rep.includes("sig-job-n") && rep.includes("#1") && rep.includes("#2"), "per-job framing/numbers missing");
check(rep.includes("sig-cross-verdict ok") && rep.includes("Resolves to 0x24190 as expected"), "cross verdict missing");
check(rep.includes("sig-job-err") && rep.includes("bad hex byte"), "job error card missing");
check(rep.includes("Grade legend"), "grade legend missing");
// Declined run: the structural family, partial coverage, and absolute addressing must all surface.
const dec = sandbox.__declinedHtml || "";
check(dec.includes("Structural family"), "structural family section missing on declined run");
check(dec.includes("0x31799C"), "shortlist candidate rva missing");
check(dec.includes("89 45 ?? E8"), "shortlist minted AOB missing");
check(dec.includes("No unique cross-build signature"), "declined explanation title missing");
check(dec.includes("found in v83 at 0x4D6D95"), "partial-coverage (found-in-build) diagnostics missing");
check(dec.includes("0x71799C"), "absolute address (base + rva) missing in 'both' mode");
const diag = sandbox.__diagHtml || "";
check(diag.includes("Resolver trace") && diag.includes("memory pointer resolved to 0x10"), "diagnostics trace missing");
check(diag.includes("Candidates") && diag.includes("0x10") && diag.includes("0x20"), "diagnostics candidates missing");
check(diag.includes("50/100"), "diagnostics confidence value missing");
const diagS = sandbox.__diagStructured || "";
check(
  diagS.includes("nested call") && diagS.includes("nearbranch64") && diagS.includes("0x24190") && diagS.includes("code"),
  "structured ResolveTrace fields must render in history diagnostics (#17)",
);
check((sandbox.__confHi || "").includes("conf-chip hi"), "high-confidence chip missing");
check((sandbox.__confLo || "").includes("conf-chip lo"), "low-confidence chip missing");
check(sandbox.__confNone === "", "null confidence should yield no chip");
const inspDiag = sandbox.__inspDiag || "";
check(inspDiag.includes("match address resolved to 0x300"), "inspector trace missing");
check(inspDiag.includes("0x300") && inspDiag.includes("0x400"), "inspector candidate list missing");
check(inspDiag.includes("50/100"), "inspector confidence value missing");
check(typeof sandbox.__fake === "string" && sandbox.__fake.length > 0, "fakeFor (masking) should produce a string");
check(sandbox.__maskOk === true, "applyMask (masking) should run without throwing");
const scanDiag = sandbox.__scanDiag || "";
check(scanDiag.includes("Job timeline") && scanDiag.includes("Section map"), "scan diagnostics panels missing");
check(scanDiag.includes("0x1000") && scanDiag.includes("0x5000"), "section map regions missing");
check(scanDiag.includes("tl-attach") && scanDiag.includes("tl-scan"), "job timeline segments missing");
const wsBody = sandbox.__wsBody || "";
check(wsBody.includes("0x10&lt;script&gt;"), "workspace value must be HTML-escaped (SEC-4)");
check(!wsBody.includes("0x10<script>"), "workspace value must not render a raw unescaped tag (SEC-4)");
check(wsBody.includes('tabindex="0"'), "result rows must be keyboard-focusable (a11y DESK-1)");
check(wsBody.includes("aria-selected"), "result rows must expose selection state (a11y DESK-1)");

// Static accessibility gate over the markup (DESK-1). A focused structural check rather than a full
// axe/jsdom run, which would pull a large npm tree into a deliberately zero-dependency frontend; it
// covers the high-impact rules (text alternatives, header semantics, landmark/dialog roles, and an
// accessible name on every icon-only control) so a regression in those fails CI.
const indexHtml = fs.readFileSync(path.join(__dirname, "frontend", "index.html"), "utf8");
const imgsMissingAlt = indexHtml.match(/<img\b(?![^>]*\balt=)[^>]*>/g) || [];
check(imgsMissingAlt.length === 0, `every <img> needs an alt (a11y): ${imgsMissingAlt.join(" ")}`);
check(indexHtml.includes('scope="col"'), "results table headers need scope=col (a11y)");
check(
  indexHtml.includes('role="region"') && indexHtml.includes('aria-labelledby="insp-name"'),
  "inspector needs role=region + aria-labelledby (a11y)",
);
check(
  indexHtml.includes('role="dialog"') && indexHtml.includes('aria-labelledby="modal-title"'),
  "modal needs role=dialog + aria-labelledby (a11y)",
);
for (const id of ["win-min", "win-max", "win-close", "mask-toggle", "w-source-btn"]) {
  const tag = (indexHtml.match(new RegExp(`<button[^>]*\\bid="${id}"[^>]*>`)) || [""])[0];
  check(
    /\baria-label=|\btitle=|\bdata-i18n-title=/.test(tag),
    `icon-only button #${id} needs an accessible name (aria-label/title) (a11y)`,
  );
}
// Large-result-set rendering: history views cap how many rows they materialize (DESK-2).
const cap = sandbox.__cap;
check(cap && cap.items.length === 800 && cap.hidden === 100, "history views must cap rendered rows (DESK-2)");
check((sandbox.__more || "").includes("more"), "a capped history view must render a more-rows notice (DESK-2)");

// Unpack report card: the verification report must surface, never silently drop (mirrors the engine-output regression).
const up = sandbox.__unpackHtml || "";
check(up.includes("Gates pass"), "unpack report must show the gates-pass banner");
check(up.includes("0x6a2c61c"), "unpack report must show the OEP rva");
check(up.includes("39 DLLs / 591 functions"), "unpack report must show the import count");
check(up.includes("361813"), "unpack report must show the .pdata entry count");
check(up.includes(".text identity") && up.includes("packed original"), "unpack report must show the .text-identity reference");
check(up.includes("PASS"), "unpack report must show a PASS chip on a passing gate");
check(up.includes("OEP disassembly") && up.includes("mov [rsp+20h],rbx"), "unpack report must show the OEP disassembly");
check(up.includes("IAT directory set"), "unpack report must show the clean summary");
const upf = sandbox.__unpackFailHtml || "";
check(upf.includes("Gates failed") && upf.includes("No binary written"), "a failed unpack must explain itself and not claim an output");
check(upf.includes("FAIL"), "a failed gate must show a FAIL chip");

if (fails.length) {
  console.error("FRONTEND RENDER TEST FAILED:");
  for (const f of fails) console.error("  - " + f);
  process.exit(1);
}
console.log("FRONTEND RENDER TEST OK");
