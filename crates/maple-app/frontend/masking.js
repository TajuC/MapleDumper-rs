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
// Address display mode: "rva" (section-relative, default), "abs" (image base + RVA), or "both".
function loadAddrMode() {
  try {
    const v = localStorage.getItem("addrMode");
    return v === "abs" || v === "both" ? v : "rva";
  } catch {
    return "rva";
  }
}
function saveAddrMode(v) {
  try {
    localStorage.setItem("addrMode", v);
  } catch {
  }
}

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
