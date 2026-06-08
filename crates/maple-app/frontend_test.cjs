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
} catch (e) { globalThis.__renderError = String((e && e.stack) || e); }
`;

const i18nCode = fs.readFileSync(path.join(__dirname, "frontend", "i18n.js"), "utf8");
const iconsCode = fs.readFileSync(path.join(__dirname, "frontend", "icons.js"), "utf8");
const maskingCode = fs.readFileSync(path.join(__dirname, "frontend", "masking.js"), "utf8");
const sigCode = fs.readFileSync(path.join(__dirname, "frontend", "sigmaker.js"), "utf8");
const histCode = fs.readFileSync(path.join(__dirname, "frontend", "history.js"), "utf8");
const readFront = (f) => fs.readFileSync(path.join(__dirname, "frontend", f), "utf8");
const code =
  i18nCode + iconsCode + maskingCode + sigCode + histCode +
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

if (fails.length) {
  console.error("FRONTEND RENDER TEST FAILED:");
  for (const f of fails) console.error("  - " + f);
  process.exit(1);
}
console.log("FRONTEND RENDER TEST OK");
