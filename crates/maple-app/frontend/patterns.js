async function reparse() {
  const res = await invoke("parse_patterns_text", { text: state.patternText, arch: state.arch });
  // The command returns { patterns, warnings }; tolerate a bare array too so an older shape or a stub
  // does not break the view.
  state.patterns = Array.isArray(res) ? res : (res && res.patterns) || [];
  $("s-loaded").textContent = state.patterns.length;
  const warnings = (res && res.warnings) || [];
  for (const w of warnings) toast(w, true);
}

function refreshPatterns() {
  reparse().then(renderPatterns);
}

function patternMatches(p, term, cat) {
  if (cat !== "all" && p.category !== cat) return false;
  if (!term) return true;
  return (
    p.name.toLowerCase().includes(term) ||
    p.aob.toLowerCase().includes(term) ||
    (p.note || "").toLowerCase().includes(term)
  );
}

function filteredPatterns() {
  const term = $("pattern-search").value.trim().toLowerCase();
  const cat = $("pattern-cat").value || "all";
  return state.patterns.filter((p) => patternMatches(p, term, cat));
}

function patternRecord(p) {
  return { name: p.name, type: typeLabel(p.type), category: p.category, signature: p.aob, note: p.note || "" };
}

function patternLine(p) {
  return `${p.name} = ${p.aob}${p.note ? ` ; ${p.note}` : ""}`;
}

function patternCtxItems(p) {
  return [
    { label: t("ctx.copyName"), action: () => copyText(p.name) },
    { label: t("ctx.copyType"), action: () => copyText(typeLabel(p.type)) },
    { label: t("ctx.copyCategory"), action: () => copyText(p.category) },
    { label: t("ctx.copySignature"), action: () => copyText(p.aob) },
    { label: t("ctx.copyNote"), action: () => copyText(p.note || "") },
    { sep: true },
    { label: t("ctx.copyJson"), action: () => copyText(JSON.stringify(patternRecord(p), null, 2)) },
    { label: t("ctx.copyText"), action: () => copyText(patternLine(p)) },
    { sep: true },
    { label: t("ctx.copyAllJson"), action: () => copyText(JSON.stringify(filteredPatterns().map(patternRecord), null, 2)) },
    { label: t("ctx.copyAllText"), action: () => copyText(filteredPatterns().map(patternLine).join("\n")) },
  ];
}

function renderPatterns() {
  const n = state.patterns.length;
  $("pattern-count").textContent = t(n === 1 ? "pat.countOne" : "pat.count", { n });
  const sel = $("pattern-cat");
  const current = sel.value || "all";
  const cats = [...new Set(state.patterns.map((p) => p.category))].sort();
  sel.innerHTML =
    `<option value="all">${esc(t("pat.allCategories"))}</option>` +
    cats.map((c) => `<option value="${esc(c)}">${esc(c)}</option>`).join("");
  sel.value = [...sel.options].some((o) => o.value === current) ? current : "all";

  const term = $("pattern-search").value.trim().toLowerCase();
  const cat = sel.value;
  const body = $("pattern-body");
  const rows = state.patterns.map((p, i) => ({ p, i })).filter(({ p }) => patternMatches(p, term, cat));

  if (rows.length === 0) {
    body.innerHTML = `<tr class="empty"><td colspan="6">${esc(t("pat.empty"))}</td></tr>`;
    return;
  }

  body.innerHTML = rows
    .map(
      ({ p, i }) => `<tr data-pi="${i}">
      <td><div class="name-cell"><span class="pat-dot" style="--ch:${hueOf(p.category)}"></span><span class="mono d-name">${esc(p.name)}</span></div></td>
      <td><span class="tag">${esc(typeLabel(p.type))}</span></td>
      <td class="d-cat">${esc(p.category)}</td>
      <td><span class="sig d-sig copyable" title="${escAttr(p.aob)}" data-aob="${escAttr(p.aob)}">${esc(p.aob)}</span></td>
      <td class="note-cell d-note">${esc(p.note || "")}</td>
      <td><div class="row-actions">
        <button class="icon-btn" data-edit="${i}">${esc(t("pat.edit"))}</button>
        <button class="icon-btn danger" data-del="${i}">${esc(t("pat.del"))}</button>
      </div></td></tr>`
    )
    .join("");
  body.querySelectorAll("[data-edit]").forEach((b) => b.addEventListener("click", () => openModal(Number(b.dataset.edit))));
  body.querySelectorAll("[data-del]").forEach((b) => b.addEventListener("click", () => deletePattern(Number(b.dataset.del))));
  body.querySelectorAll(".sig.copyable").forEach((el) => el.addEventListener("click", () => copyText(el.dataset.aob)));
  body.querySelectorAll("tr[data-pi]").forEach((tr) =>
    tr.addEventListener("contextmenu", (e) => {
      e.preventDefault();
      const p = state.patterns[Number(tr.dataset.pi)];
      if (p) showCtxMenu(e.clientX, e.clientY, patternCtxItems(p));
    })
  );
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
  toast(t("toast.deleted"));
}
