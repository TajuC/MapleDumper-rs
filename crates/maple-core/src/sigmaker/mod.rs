use crate::fileimage::{RelocKind, RelocLookup};
use crate::memory::MemorySource;
use crate::pattern::{Arch, Signature, try_signature_from_aob};
use crate::resolver::decode_rel_target;
use crate::scanner::{CompiledPattern, find_all};
use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, OpKind, Register};

mod scoring;
mod types;
pub use scoring::{NegativeEvidence, apply_negative_corpus, apply_negatives};
pub use types::*;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Anchor {
    Direct,
    Branch,
    Ptr { rip: bool },
}

pub(super) fn bitness(arch: Arch) -> u32 {
    if matches!(arch, Arch::X64) { 64 } else { 32 }
}

// Truncate to the bytes actually read so an unreadable tail is never handed back as real zeros: a
// short read at a region boundary or an unmapped page must shrink the slice, not fabricate data the
// signature logic would then anchor on.
pub(super) fn read_region(src: &dyn MemorySource, base: usize, size: usize) -> Vec<u8> {
    let mut buf = vec![0u8; size];
    let mut off = 0;
    while off < size {
        match src.read_into(base + off, &mut buf[off..]) {
            Ok(0) | Err(_) => break,
            Ok(n) => off += n,
        }
    }
    buf.truncate(off);
    buf
}

pub(super) fn read_at(src: &dyn MemorySource, base: usize, rva: usize, len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    let mut off = 0;
    while off < len {
        match src.read_into(base + rva + off, &mut buf[off..]) {
            Ok(0) | Err(_) => break,
            Ok(n) => off += n,
        }
    }
    buf.truncate(off);
    buf
}

pub(super) struct CodeCache {
    image_base: usize,
    regions: Vec<(usize, Vec<u8>)>,
}

impl CodeCache {
    pub(super) fn build(img: &ImageInput) -> Self {
        let regions = img
            .code_regions
            .iter()
            .map(|r| (r.base, read_region(img.source, r.base, r.size)))
            .collect();
        Self {
            image_base: img.base,
            regions,
        }
    }

    pub(super) fn locate(&self, pat: &CompiledPattern) -> (usize, Option<u64>) {
        let mut count = 0;
        let mut first: Option<u64> = None;
        for (base, bytes) in &self.regions {
            for off in find_all(bytes, pat) {
                count += 1;
                let rva = (base + off - self.image_base) as u64;
                first = Some(first.map_or(rva, |f| f.min(rva)));
            }
        }
        (count, first)
    }
}

struct InstrMask {
    len: usize,
    fixed: Vec<bool>,
    operand: Vec<bool>,
    unsupported: Option<(usize, u8)>,
}

fn set_range(v: &mut [bool], start: usize, size: usize) {
    for b in v.iter_mut().skip(start).take(size) {
        *b = true;
    }
}

fn decode_masked(
    bytes: &[u8],
    arch: Arch,
    base: usize,
    rva: usize,
    reloc: Option<&dyn RelocLookup>,
    max_instrs: usize,
) -> Vec<InstrMask> {
    let ip = (base + rva) as u64;
    let mut decoder = Decoder::with_ip(bitness(arch), bytes, ip, DecoderOptions::NONE);
    let mut instr = Instruction::default();
    let mut out = Vec::new();
    while decoder.can_decode() && out.len() < max_instrs {
        decoder.decode_out(&mut instr);
        if instr.is_invalid() {
            break;
        }
        let len = instr.len();
        if len == 0 {
            break;
        }
        let co = decoder.get_constant_offsets(&instr);
        let mut operand = vec![false; len];
        if co.has_displacement() {
            set_range(
                &mut operand,
                co.displacement_offset(),
                co.displacement_size(),
            );
        }
        if co.has_immediate() {
            set_range(&mut operand, co.immediate_offset(), co.immediate_size());
        }
        if co.has_immediate2() {
            set_range(&mut operand, co.immediate_offset2(), co.immediate_size2());
        }
        let mut fixed: Vec<bool> = operand.iter().map(|&o| !o).collect();
        let mut unsupported: Option<(usize, u8)> = None;
        if let Some(reloc) = reloc {
            let instr_rva = (instr.ip() as usize) - base;
            for (k, f) in fixed.iter_mut().enumerate() {
                let rva = instr_rva + k;
                if let Some(kind) = reloc.reloc_kind_at(rva) {
                    *f = false; // a relocated byte is patched at load, so it can't stay fixed
                    if let RelocKind::Unsupported(t) = kind {
                        unsupported.get_or_insert((rva, t));
                    }
                }
            }
        }
        out.push(InstrMask {
            len,
            fixed,
            operand,
            unsupported,
        });
    }
    out
}

fn compile(bytes: &[u8], mask: &[bool]) -> Option<CompiledPattern> {
    CompiledPattern::new(&Signature {
        bytes: bytes.to_vec(),
        mask: mask.to_vec(),
    })
}

fn aob_of(bytes: &[u8], mask: &[bool]) -> String {
    Signature {
        bytes: bytes.to_vec(),
        mask: mask.to_vec(),
    }
    .to_aob()
}

struct Located {
    ref_idx: usize,
    anchors: Vec<(usize, u64)>, // (image index, rva) for each required, located build
}

pub(super) fn mem_target(instr: &Instruction, arch: Arch) -> Option<usize> {
    if !(0..instr.op_count()).any(|i| instr.op_kind(i) == OpKind::Memory) {
        return None;
    }
    if instr.is_ip_rel_memory_operand() {
        return Some(instr.ip_rel_memory_address() as usize);
    }
    if matches!(arch, Arch::X86)
        && instr.memory_base() == Register::None
        && instr.memory_index() == Register::None
    {
        return Some(instr.memory_displacement64() as usize);
    }
    None
}

fn resolve_anchor(anchor: Anchor, img: &ImageInput, site: usize) -> Option<usize> {
    match anchor {
        Anchor::Direct => None,
        Anchor::Branch => {
            let bytes = read_at(img.source, img.base, site, 8);
            decode_rel_target(&bytes, img.base + site)
        }
        Anchor::Ptr { .. } => {
            let bytes = read_at(img.source, img.base, site, 16);
            let mut decoder = Decoder::with_ip(
                bitness(img.arch),
                &bytes,
                (img.base + site) as u64,
                DecoderOptions::NONE,
            );
            let mut instr = Instruction::default();
            decoder.decode_out(&mut instr);
            (!instr.is_invalid())
                .then(|| mem_target(&instr, img.arch))
                .flatten()
        }
    }
}

mod aob;
mod callers;
mod chain;
mod constants;
mod encoding;
mod ensemble;
mod graph;
mod identity;
mod imports;
mod model;
mod relocate;
mod validate;
mod vtable;
use aob::collapse_aob_ranges;
use chain::relocate_path;
use ensemble::{anchor_landing, ensemble_decide};
pub use identity::*;
use relocate::{
    caller_relocate, constant_relocate, encoding_relocate, fingerprint_relocate, graph_relocate,
    import_relocate, relocation_shortlists, string_anchor_candidate, vtable_relocate,
};
// The relocation anchors' tuned constants live in `relocate` now; the corpus harnesses assert against
// them, so re-export everything there for the test modules (test-only, so nothing is dead in the library).
#[cfg(test)]
use relocate::*;
pub use validate::{holdout_validate, negative_corpus_hits};

/// Mint a byte signature unique within a SINGLE build at `rva`, masking operand and relocated bytes
/// the same way the cross-build generator does, and growing the window instruction by instruction
/// until the pattern matches exactly once in that build. This is how a relocation fallback hands back
/// a usable AOB for a recompiled build: the original cross-build AOB no longer matches there, but once
/// the function has been relocated, its own bytes in that build still yield a fresh unique pattern.
/// `None` if no operand-masked window up to `opts.max_len` is unique (a function whose bytes recur, or
/// an unreadable site).
fn single_build_aob(img: &ImageInput, rva: usize, opts: &SigOptions) -> Option<String> {
    let cache = CodeCache::build(img);
    let max_instrs = opts.max_len / 2 + 8;
    let window = read_at(img.source, img.base, rva, opts.max_len + 16);
    if window.is_empty() {
        return None;
    }
    let instrs = decode_masked(&window, img.arch, img.base, rva, img.reloc, max_instrs);

    let mut acc = 0usize;
    let mut lens: Vec<usize> = Vec::new();
    for im in &instrs {
        acc += im.len;
        if acc > opts.max_len || acc > window.len() {
            break;
        }
        lens.push(acc);
    }

    for &len in &lens {
        let mut fixed = vec![true; len];
        let mut operand = vec![false; len];
        let mut pos = 0usize;
        for im in &instrs {
            if pos >= len {
                break;
            }
            for k in 0..im.len {
                if pos + k < len {
                    fixed[pos + k] = im.fixed[k];
                    operand[pos + k] = im.operand[k];
                }
            }
            pos += im.len;
        }
        let fixed_n = fixed.iter().filter(|&&f| f).count();
        let meaningful = (0..len).filter(|&k| fixed[k] && !operand[k]).count();
        if fixed_n < opts.min_fixed
            || meaningful == 0
            || (fixed_n as f64 / len as f64) < opts.min_fixed_ratio
        {
            continue;
        }
        let Some(pat) = compile(&window[..len], &fixed) else {
            continue;
        };
        if cache.locate(&pat).0 == 1 {
            return Some(aob_of(&window[..len], &fixed));
        }
    }
    None
}

/// #13: whether a string-anchored cross-version relocation is corroborated enough to be reported as a
/// confident (A/B) match. Across a major recompile a lone string can resolve to a *migrated* string in
/// a different function, and the cross-build structural identity is the tell: the corpus sweep found
/// single-string landings under ~0.30 identity to the origin could not be confirmed as the same
/// function. Confidence therefore requires either a second corroborating string (`paired`) or that the
/// worst build's landing stays structurally close to the reference. A single build (`None`) carries no
/// cross-build evidence and is governed by the separate single-build cap, not this gate. Within a
/// lineage the landings stay highly similar, so this never downgrades there.
fn string_relocation_confirmed(paired: bool, min_landing_similarity: Option<f64>) -> bool {
    const MAJOR_GAP_SIM: f64 = 0.30;
    paired || min_landing_similarity.is_none_or(|s| s >= MAJOR_GAP_SIM)
}

#[allow(clippy::too_many_arguments)]
fn finalize(
    images: &[ImageInput],
    caches: &[(usize, CodeCache)],
    located: &Located,
    ref_bytes: &[u8],
    base_fixed: &[bool],
    operand: &[bool],
    suffix: Suffix,
    anchor: Anchor,
    unsupported: Option<(usize, u8)>,
    any_packed: bool,
    opts: &SigOptions,
    diags_in: &[Diag],
) -> Option<SigCandidate> {
    let len = ref_bytes.len();
    let mut bytes = ref_bytes.to_vec();
    let mut fixed = base_fixed.to_vec();
    let cache_of = |idx: usize| &caches.iter().find(|(i, _)| *i == idx).unwrap().1;

    for &(idx, rva) in &located.anchors {
        if idx == located.ref_idx {
            continue;
        }
        let other = read_at(images[idx].source, images[idx].base, rva as usize, len);
        for k in 0..len {
            if fixed[k] && other.get(k) != Some(&bytes[k]) {
                fixed[k] = false;
            }
        }
    }

    let fixed_n = fixed.iter().filter(|&&f| f).count();
    let wild_n = len - fixed_n;
    let ratio = if len == 0 {
        0.0
    } else {
        fixed_n as f64 / len as f64
    };
    let meaningful = (0..len)
        .filter(|&k| fixed[k] && !operand.get(k).copied().unwrap_or(false))
        .count();

    let pat = compile(&bytes, &fixed)?;
    let is_anchor = !matches!(anchor, Anchor::Direct);
    let mut per_version = Vec::new();
    let mut unique_all = true;
    let mut anchor_diags: Vec<Diag> = Vec::new();
    let mut all_code = true;
    let mut any_unresolved = false;
    let mut kinds: Vec<TargetKind> = Vec::new();
    // Callee identities for code targets, with the per_version row each belongs to, so cross-build
    // fingerprint similarity can be filled in after the per-build pass.
    let mut idents: Vec<FnIdentity> = Vec::new();
    let mut ident_pv: Vec<usize> = Vec::new();
    for &(idx, _) in &located.anchors {
        let img = &images[idx];
        let (count, rva) = cache_of(idx).locate(&pat);
        if count != 1 {
            unique_all = false;
        }
        let mut resolved_target_rva = None;
        let mut target_kind = None;
        if is_anchor && let Some(site) = rva {
            match resolve_anchor(anchor, img, site as usize) {
                Some(target_abs) => {
                    match crate::domain::checked_rva(target_abs, img.base, img.size) {
                        Ok(rva_u64) => {
                            let target_rva = rva_u64 as usize;
                            let kind = img.classify(target_abs);
                            resolved_target_rva = Some(rva_u64);
                            target_kind = Some(kind);
                            kinds.push(kind);
                            if kind == TargetKind::Code {
                                idents.push(fn_identity(img, target_rva));
                                ident_pv.push(per_version.len());
                            } else {
                                all_code = false;
                                if matches!(anchor, Anchor::Branch) {
                                    anchor_diags.push(Diag::TargetNotCode {
                                        label: img.label.clone(),
                                        rva: target_rva,
                                    });
                                }
                            }
                        }
                        Err(_) => {
                            // the target resolved outside the image; treat it as unresolvable rather
                            // than recording a bounded numeric RVA that could look like a valid target.
                            any_unresolved = true;
                            anchor_diags.push(Diag::UnresolvableTarget {
                                label: img.label.clone(),
                            });
                        }
                    }
                }
                None => {
                    any_unresolved = true;
                    anchor_diags.push(Diag::UnresolvableTarget {
                        label: img.label.clone(),
                    });
                }
            }
        }
        per_version.push(PerVersion {
            label: img.label.clone(),
            match_rva: rva,
            resolved_target_rva,
            target_kind,
            fingerprint_similarity: None,
            // The byte path's own `aob` already matches every build, so no per-build AOB is needed.
            aob: None,
        });
    }

    if !unique_all {
        return None; // not unique here; the caller will grow the window
    }

    // Fill in each code target's callee similarity to the first build's, as per-build evidence.
    for (k, ident) in idents.iter().enumerate() {
        if k > 0 {
            per_version[ident_pv[k]].fingerprint_similarity = Some(idents[0].similarity(ident));
        }
    }

    let mut diags: Vec<Diag> = diags_in.to_vec();
    diags.extend(anchor_diags);
    let mut gated = false;
    if fixed_n < opts.min_fixed {
        diags.push(Diag::TooFewFixedBytes { fixed: fixed_n });
        gated = true;
    }
    if ratio < opts.min_fixed_ratio {
        diags.push(Diag::LowFixedRatio { ratio });
        gated = true;
    }
    if meaningful == 0 {
        diags.push(Diag::NoOpcodeBytes);
        gated = true;
    }
    if let Some((rva, reloc_type)) = unsupported {
        // An unsupported relocation could still patch a byte we kept fixed, so reject it rather
        // than ship a signature that breaks at load time.
        diags.push(Diag::UnsupportedReloc { rva, reloc_type });
        gated = true;
    }
    let reloc_safe = unsupported.is_none();

    // Cross-build callee agreement as a graceful numeric similarity, not fingerprint equality: a
    // callee that gained or shifted an instruction across a recompile stays high. The hard mismatch
    // diagnostic only fires on a genuine divergence (the Low band), not on that small drift.
    let callee_similarity = scoring::callee_similarity(&idents);
    let kinds_consistent = kinds.windows(2).all(|w| w[0] == w[1]);
    if is_anchor && !any_unresolved && callee_similarity.is_some_and(scoring::is_callee_divergence)
    {
        diags.push(Diag::CalleeMismatch);
    }

    // The grade is derived from the independent sub-scores (see `scoring`), not the other way round.
    // A content-validated anchor (branch / RIP-relative ref to code with a consistent callee) scores
    // into the A band; a stable data ref is B; an absolute, unresolved, or kind-inconsistent ref is
    // weaker. Hard gates force F and a packed input caps at D regardless of score.
    let anchor_kind = match anchor {
        Anchor::Direct => scoring::AnchorKind::Direct,
        Anchor::Branch => scoring::AnchorKind::Branch,
        Anchor::Ptr { rip: true } => scoring::AnchorKind::RipPtr,
        Anchor::Ptr { rip: false } => scoring::AnchorKind::AbsPtr,
    };
    let fixed_bytes: Vec<u8> = (0..len).filter(|&k| fixed[k]).map(|k| bytes[k]).collect();
    let operand_masked = (0..len)
        .filter(|&k| operand.get(k).copied().unwrap_or(false) && !fixed[k])
        .count();
    let initial_fixed = base_fixed.iter().filter(|&&f| f).count();
    let byte_survival = if initial_fixed == 0 {
        1.0
    } else {
        fixed_n as f64 / initial_fixed as f64
    };
    let ev = scoring::Evidence {
        anchor: anchor_kind,
        is_anchor,
        all_code,
        any_unresolved,
        callee_similarity,
        kinds_consistent,
        first_kind: kinds.first().copied(),
        reloc_safe,
        packed: any_packed,
        fixed_bytes,
        fixed_n,
        len,
        meaningful,
        operand_masked,
        builds: located.anchors.len(),
        ref_ident: idents.first(),
        byte_survival,
    };
    let (scores, reasons) = scoring::score(&ev);
    let grade = scoring::grade_from(scores.final_score, gated, any_packed);
    let score = scores.final_score;

    let aob = aob_of(&bytes, &fixed);
    bytes.truncate(len);
    Some(SigCandidate {
        aob,
        suffix,
        grade,
        score,
        bytes_len: len,
        fixed: fixed_n,
        wildcards: wild_n,
        fixed_ratio: ratio,
        reloc_safe,
        gated,
        packed: any_packed,
        scores,
        reasons,
        per_version,
        diags,
        relocation: None,
    })
}

fn ptr_sites(
    image_base: usize,
    ref_cache: &CodeCache,
    target_abs: usize,
    arch: Arch,
    cap: usize,
) -> Vec<(u64, bool)> {
    let bits = bitness(arch);
    let mut sites = Vec::new();
    let mut instr = Instruction::default();
    for (rbase, bytes) in &ref_cache.regions {
        let mut decoder = Decoder::with_ip(bits, bytes, *rbase as u64, DecoderOptions::NONE);
        while decoder.can_decode() {
            decoder.decode_out(&mut instr);
            if instr.is_invalid() {
                continue;
            }
            if mem_target(&instr, arch) == Some(target_abs) {
                let rip = instr.is_ip_rel_memory_operand();
                sites.push(((instr.ip() as usize - image_base) as u64, rip));
                if sites.len() >= cap {
                    return sites;
                }
            }
        }
    }
    sites
}

#[allow(clippy::too_many_arguments)]
fn candidate_at(
    images: &[ImageInput],
    caches: &[(usize, CodeCache)],
    required: &[usize],
    ref_idx: usize,
    site_rva: u64,
    suffix: Suffix,
    seed_mask: Option<&[bool]>,
    anchor: Anchor,
    any_packed: bool,
    opts: &SigOptions,
) -> (Option<SigCandidate>, Vec<SigCandidate>) {
    let arch = images[ref_idx].arch;
    let cache_of = |idx: usize| &caches.iter().find(|(i, _)| *i == idx).unwrap().1;
    let max_instrs = opts.max_len / 2 + 8;
    let ref_img = &images[ref_idx];
    let window = read_at(
        ref_img.source,
        ref_img.base,
        site_rva as usize,
        opts.max_len + 16,
    );
    let instrs = decode_masked(
        &window,
        arch,
        ref_img.base,
        site_rva as usize,
        ref_img.reloc,
        max_instrs,
    );

    let mut try_lens: Vec<usize> = Vec::new();
    if let Some(sm) = seed_mask {
        try_lens.push(sm.len().min(window.len()));
    }
    let mut acc = 0;
    for im in &instrs {
        acc += im.len;
        if acc > opts.max_len {
            break;
        }
        if !try_lens.contains(&acc) {
            try_lens.push(acc);
        }
    }

    let mut rejected: Vec<SigCandidate> = Vec::new();
    for &len in &try_lens {
        if len == 0 || len > window.len() {
            continue;
        }
        let mut fixed = vec![true; len];
        let mut operand = vec![false; len];
        let mut unsupported: Option<(usize, u8)> = None;
        let mut pos = 0;
        for im in &instrs {
            if pos >= len {
                break;
            }
            for k in 0..im.len {
                if pos + k < len {
                    fixed[pos + k] = im.fixed[k];
                    operand[pos + k] = im.operand[k];
                }
            }
            if unsupported.is_none()
                && let Some((rva, t)) = im.unsupported
                && rva.saturating_sub(site_rva as usize) < len
            {
                unsupported = Some((rva, t));
            }
            pos += im.len;
        }
        if let Some(sm) = seed_mask {
            for k in 0..len.min(sm.len()) {
                if !sm[k] {
                    fixed[k] = false;
                }
            }
        }

        let Some(pat) = compile(&window[..len], &fixed) else {
            continue;
        };
        let mut anchors = Vec::new();
        let mut all_unique = true;
        let mut diags_loc: Vec<Diag> = Vec::new();
        for &idx in required {
            let (count, rva) = cache_of(idx).locate(&pat);
            match (count, rva) {
                (1, Some(r)) => anchors.push((idx, r)),
                (0, _) => {
                    all_unique = false;
                    diags_loc.push(Diag::MissingInImage {
                        label: images[idx].label.clone(),
                    });
                }
                (n, _) => {
                    all_unique = false;
                    diags_loc.push(Diag::AmbiguousInImage {
                        label: images[idx].label.clone(),
                        count: n,
                    });
                }
            }
        }
        if !all_unique {
            continue;
        }
        let located = Located { ref_idx, anchors };
        if let Some(cand) = finalize(
            images,
            caches,
            &located,
            &window[..len],
            &fixed,
            &operand,
            suffix,
            anchor,
            unsupported,
            any_packed,
            opts,
            &diags_loc,
        ) {
            if cand.grade == Grade::F {
                rejected.push(cand);
            } else {
                return (Some(cand), rejected);
            }
        }
    }
    (None, rejected)
}

// Disassemble linearly so an E8/E9 inside another instruction's operand is never mistaken for a
// branch. Accept only a real 5-byte CALL/JMP whose rel32 resolves to target_abs.
fn branch_sites(
    image_base: usize,
    ref_cache: &CodeCache,
    target_abs: usize,
    arch: Arch,
    want_call: bool,
    cap: usize,
) -> Vec<u64> {
    let bits = bitness(arch);
    let target = target_abs as u64;
    let mut sites: Vec<u64> = Vec::new();
    let mut instr = Instruction::default();
    for (rbase, bytes) in &ref_cache.regions {
        let mut decoder = Decoder::with_ip(bits, bytes, *rbase as u64, DecoderOptions::NONE);
        while decoder.can_decode() {
            decoder.decode_out(&mut instr);
            if instr.is_invalid() {
                continue;
            }
            let kind_ok = if want_call {
                instr.flow_control() == FlowControl::Call
            } else {
                instr.flow_control() == FlowControl::UnconditionalBranch
            };
            if instr.len() == 5 && kind_ok && instr.near_branch_target() == target {
                let off = instr.ip() as usize - rbase;
                if decode_rel_target(&bytes[off..], instr.ip() as usize) == Some(target_abs) {
                    sites.push(((instr.ip() as usize) - image_base) as u64);
                    if sites.len() >= cap {
                        return sites;
                    }
                }
            }
        }
    }
    sites
}

/// The relocation anchor that produced a candidate, for ordering ties by channel strength (string is the
/// most precise, the mnemonic fingerprint the fuzziest) and for naming corroborators in the report.
#[derive(Clone, Copy, PartialEq, Eq)]
enum AnchorKind {
    String,
    Import,
    Constant,
    Caller,
    Graph,
    Vtable,
    Encoding,
    Fingerprint,
}

impl AnchorKind {
    fn label(self) -> &'static str {
        match self {
            AnchorKind::String => "string",
            AnchorKind::Import => "import",
            AnchorKind::Constant => "constant",
            AnchorKind::Caller => "caller",
            AnchorKind::Graph => "graph",
            AnchorKind::Vtable => "vtable",
            AnchorKind::Encoding => "encoding",
            AnchorKind::Fingerprint => "fingerprint",
        }
    }
}

/// Relocate the target by every applicable anchor and decide by cross-anchor agreement, instead of taking
/// the first anchor that fires. Independent channels that land on the same function corroborate the
/// address; a channel that lands on a different function and is not outvoted caps the result to a
/// candidate, because a disagreement between independent methods is the strongest wrong-address signal
/// there is. The chosen landing is always one an anchor actually produced (each of which the corpus sweep
/// records at zero confirmed false positives), so the ensemble only declines confidence or chooses among
/// agreeing results; it never invents a new address. Running every applicable anchor costs more than the
/// old first-success chain, which the shared analysis model offsets in a later phase.
fn ensemble_relocate(
    images: &[ImageInput],
    required: &[usize],
    ref_idx: usize,
    ref_rva: u64,
    opts: &SigOptions,
) -> Option<SigCandidate> {
    type AnchorFn = fn(&[ImageInput], &[usize], usize, u64, &SigOptions) -> Option<SigCandidate>;
    // Descending channel strength, so a tie in support and grade breaks toward the more precise anchor.
    let anchors: [(AnchorKind, AnchorFn); 8] = [
        (AnchorKind::String, string_anchor_candidate),
        (AnchorKind::Import, import_relocate),
        (AnchorKind::Constant, constant_relocate),
        (AnchorKind::Caller, caller_relocate),
        (AnchorKind::Graph, graph_relocate),
        (AnchorKind::Vtable, vtable_relocate),
        (AnchorKind::Encoding, encoding_relocate),
        (AnchorKind::Fingerprint, fingerprint_relocate),
    ];
    let mut found: Vec<(AnchorKind, SigCandidate)> = Vec::new();
    for (kind, f) in anchors {
        if let Some(c) = f(images, required, ref_idx, ref_rva, opts) {
            found.push((kind, c));
        }
    }
    if found.is_empty() {
        return None;
    }
    if found.len() == 1 {
        let (kind, mut cand) = found.pop().unwrap();
        cand.relocation = Some(RelocationLedger {
            anchor: kind.label().to_string(),
            support: 1,
            corroborators: Vec::new(),
            conflict: false,
        });
        return Some(cand);
    }
    let landings: Vec<_> = found
        .iter()
        .map(|(_, c)| anchor_landing(images, c))
        .collect();
    let ranks: Vec<u8> = found.iter().map(|(_, c)| c.grade.rank()).collect();
    let v = ensemble_decide(&landings, &ranks);
    let corroborators: Vec<String> = v
        .corroborators
        .iter()
        .map(|&j| found[j].0.label().to_string())
        .collect();
    let mut cand = found[v.winner].1.clone();
    cand.relocation = Some(RelocationLedger {
        anchor: found[v.winner].0.label().to_string(),
        support: v.support,
        corroborators: corroborators.clone(),
        conflict: v.conflict,
    });
    if v.support >= 2 {
        cand.reasons.push(format!(
            "corroborated by {} independent anchor(s): {}",
            v.support - 1,
            corroborators.join(", ")
        ));
    }
    if v.conflict && v.support < 2 {
        // A lone channel that another independent channel contradicts: report it as a candidate, never a
        // confirmed relocation, however high it scored on its own.
        cand.grade = cand.grade.max_rank(Grade::C);
        cand.reasons.push(
            "another independent anchor resolves a different address and nothing corroborates this one, \
             so it is reported as a candidate, not a confirmed relocation"
                .to_string(),
        );
    } else if v.conflict {
        cand.reasons.push(
            "an independent anchor disagreed but was outvoted by the corroborating channels"
                .to_string(),
        );
    }
    Some(cand)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SigStage {
    Deduplicating,
    ReadingCode { build: usize, total: usize },
    LocatingTarget,
    ScanningDirect,
    ScanningCallJmp,
    ScanningPtr,
    Scoring,
}

pub fn generate_with_progress(
    images: &[ImageInput],
    spec: &TargetSpec,
    opts: &SigOptions,
    progress: &mut dyn FnMut(SigStage),
) -> SigReport {
    let arch = images.first().map_or(Arch::X64, |i| i.arch);
    let inputs: Vec<InputInfo> = images
        .iter()
        .map(|i| InputInfo {
            label: i.label.clone(),
            packed: i.packed,
            reasons: i.pack_reasons.clone(),
        })
        .collect();
    let mut diagnostics: Vec<Diag> = images
        .iter()
        .filter(|i| i.packed)
        .map(|i| Diag::PackedInput {
            label: i.label.clone(),
            reasons: i.pack_reasons.clone(),
        })
        .collect();

    let fail = |diagnostics: Vec<Diag>, unique_builds, dups| SigReport {
        arch,
        inputs: inputs.clone(),
        unique_builds,
        duplicate_groups: dups,
        chosen: None,
        alternates: Vec::new(),
        rejected: Vec::new(),
        shortlists: Vec::new(),
        aob_ranges: Vec::new(),
        diagnostics,
    };

    if images.is_empty() {
        diagnostics.push(Diag::NoInputs);
        return fail(diagnostics, 0, Vec::new());
    }
    if images.iter().any(|i| i.arch != arch) {
        diagnostics.push(Diag::MixedArch);
        return fail(diagnostics, 0, Vec::new());
    }

    progress(SigStage::Deduplicating);
    // group identical builds by code hash; the first occurrence represents the group
    let mut dup_groups: Vec<DupGroup> = Vec::new();
    let mut required: Vec<usize> = Vec::new();
    for (idx, img) in images.iter().enumerate() {
        if let Some(g) = dup_groups.iter_mut().find(|g| g.code_hash == img.code_hash) {
            g.labels.push(img.label.clone());
        } else {
            dup_groups.push(DupGroup {
                code_hash: img.code_hash,
                labels: vec![img.label.clone()],
            });
            required.push(idx);
        }
    }
    let unique_builds = required.len();
    let any_packed = images.iter().any(|i| i.packed);
    let mut caches: Vec<(usize, CodeCache)> = Vec::with_capacity(required.len());
    for (n, &i) in required.iter().enumerate() {
        progress(SigStage::ReadingCode {
            build: n + 1,
            total: required.len(),
        });
        caches.push((i, CodeCache::build(&images[i])));
    }
    let cache_of = |idx: usize| &caches.iter().find(|(i, _)| *i == idx).unwrap().1;

    progress(SigStage::LocatingTarget);
    let mut aob_found: Vec<(usize, u64)> = Vec::new();
    let (ref_idx, ref_rva, _seed_len, seed_mask): (usize, u64, usize, Option<Vec<bool>>) =
        match spec {
            TargetSpec::Aob(aob) => {
                let sig = match try_signature_from_aob(aob) {
                    Ok(s) => s,
                    Err(reason) => {
                        diagnostics.push(Diag::InvalidAob { reason });
                        return fail(diagnostics, unique_builds, dup_groups);
                    }
                };
                let Some(pat) = CompiledPattern::new(&sig) else {
                    diagnostics.push(Diag::InvalidAob {
                        reason: "signature is empty".to_string(),
                    });
                    return fail(diagnostics, unique_builds, dup_groups);
                };
                for &idx in &required {
                    let (count, rva) = cache_of(idx).locate(&pat);
                    match (count, rva) {
                        (1, Some(r)) => aob_found.push((idx, r)),
                        (0, _) => diagnostics.push(Diag::MissingInImage {
                            label: images[idx].label.clone(),
                        }),
                        (n, _) if n > 1 => diagnostics.push(Diag::AmbiguousInImage {
                            label: images[idx].label.clone(),
                            count: n,
                        }),
                        _ => {}
                    }
                }
                let Some(&(idx, r)) = aob_found.first() else {
                    return fail(diagnostics, unique_builds, dup_groups);
                };
                (idx, r, sig.bytes.len(), Some(sig.mask))
            }
            TargetSpec::Ref { image, rva } => {
                if *image >= images.len() {
                    diagnostics.push(Diag::BuildFailed);
                    return fail(diagnostics, unique_builds, dup_groups);
                }
                // map to the representative of its dup group
                let ref_idx = required
                    .iter()
                    .copied()
                    .find(|&r| images[r].code_hash == images[*image].code_hash)
                    .unwrap_or(*image);
                (ref_idx, *rva, 1, None)
            }
        };

    let target_abs = images[ref_idx].base + ref_rva as usize;
    let mut pool: Vec<SigCandidate> = Vec::new();
    let mut rejected: Vec<SigCandidate> = Vec::new();

    progress(SigStage::ScanningDirect);
    let (cand, rej) = candidate_at(
        images,
        &caches,
        &required,
        ref_idx,
        ref_rva,
        Suffix::None,
        seed_mask.as_deref(),
        Anchor::Direct,
        any_packed,
        opts,
    );
    pool.extend(cand);
    rejected.extend(rej);

    progress(SigStage::ScanningCallJmp);
    for (want_call, suffix) in [(true, Suffix::Call), (false, Suffix::Jmp)] {
        for site in branch_sites(
            images[ref_idx].base,
            cache_of(ref_idx),
            target_abs,
            arch,
            want_call,
            24,
        ) {
            let (cand, rej) = candidate_at(
                images,
                &caches,
                &required,
                ref_idx,
                site,
                suffix,
                None,
                Anchor::Branch,
                any_packed,
                opts,
            );
            pool.extend(cand);
            rejected.extend(rej);
        }
    }

    progress(SigStage::ScanningPtr);
    for (site, rip) in ptr_sites(
        images[ref_idx].base,
        cache_of(ref_idx),
        target_abs,
        arch,
        24,
    ) {
        let (cand, rej) = candidate_at(
            images,
            &caches,
            &required,
            ref_idx,
            site,
            Suffix::Ptr,
            None,
            Anchor::Ptr { rip },
            any_packed,
            opts,
        );
        pool.extend(cand);
        rejected.extend(rej);
    }

    progress(SigStage::Scoring);
    if pool.is_empty() {
        // No byte signature could be hardened across the builds, so relocate the target by its recompile-
        // stable anchors. Rather than take the first anchor that fires, the ensemble runs every applicable
        // one (string, import-set, string-anchored caller, C++ vtable structure, encoding fingerprint, and
        // the fuzzier mnemonic fingerprint) and decides by agreement: independent channels that land on the
        // same function corroborate it, and a channel that lands elsewhere without being outvoted caps the
        // result to a candidate. Each relocated build is still handed a freshly minted per-build AOB; none
        // emit a byte/string the resolver can re-scan for as a cross-build pattern, so all stay capped
        // below the byte anchors.
        if let Some(cand) = ensemble_relocate(images, &required, ref_idx, ref_rva, opts) {
            pool.push(cand);
        }
    }
    // confidence first, then fewest wildcards / shortest / kind / AOB text, so the same inputs
    // always pick the same winner
    pool.sort_by(|a, b| {
        (
            a.grade.rank(),
            a.wildcards,
            a.bytes_len,
            a.suffix.order(),
            a.aob.as_str(),
        )
            .cmp(&(
                b.grade.rank(),
                b.wildcards,
                b.bytes_len,
                b.suffix.order(),
                b.aob.as_str(),
            ))
    });
    let chosen = (!pool.is_empty()).then(|| pool.remove(0));
    // Collapse the chosen signature's per-build coverage into contiguous version ranges: a single
    // re-scannable byte pattern is one range over every build it matches, while a relocated signature
    // (whose bytes a recompile moves) becomes one range per minted AOB, reporting exactly where the old
    // bytes break and which fresh AOB takes over for the next span.
    let aob_ranges = match &chosen {
        Some(c) if try_signature_from_aob(&c.aob).is_ok() => {
            let labels: Vec<String> = c
                .per_version
                .iter()
                .filter(|p| p.match_rva.is_some())
                .map(|p| p.label.clone())
                .collect();
            if labels.is_empty() {
                Vec::new()
            } else {
                vec![AobRange {
                    aob: c.aob.clone(),
                    minted_in: labels[0].clone(),
                    first_label: labels[0].clone(),
                    last_label: labels[labels.len() - 1].clone(),
                    labels,
                }]
            }
        }
        Some(c) => collapse_aob_ranges(images, &c.per_version),
        None => Vec::new(),
    };
    let alternates = pool;
    // When nothing could be pinned, fall back to a per-build shortlist of the structural family so the
    // user gets candidates to disambiguate instead of an empty result.
    let shortlists = if chosen.is_none() {
        for &(idx, rva) in &aob_found {
            diagnostics.push(Diag::FoundInBuild {
                label: images[idx].label.clone(),
                rva,
            });
        }
        diagnostics.push(Diag::NotUnique);
        relocation_shortlists(images, &required, ref_idx, ref_rva, opts)
    } else {
        Vec::new()
    };

    SigReport {
        arch,
        inputs,
        unique_builds,
        duplicate_groups: dup_groups,
        chosen,
        alternates,
        rejected,
        shortlists,
        aob_ranges,
        diagnostics,
    }
}

pub fn generate(images: &[ImageInput], spec: &TargetSpec, opts: &SigOptions) -> SigReport {
    generate_with_progress(images, spec, opts, &mut |_| {})
}

/// Generates a signature, then checks it lands on `expected_rva` in the reference build.
#[derive(Clone, Debug)]
pub struct CrossReport {
    pub report: SigReport,
    pub expected_rva: u64,
    pub matched_rva: Option<u64>,
    pub agrees: bool,
}

pub fn generate_cross_with_progress(
    images: &[ImageInput],
    aob: &str,
    ref_image: usize,
    expected_rva: u64,
    opts: &SigOptions,
    progress: &mut dyn FnMut(SigStage),
) -> CrossReport {
    let report = generate_with_progress(images, &TargetSpec::Aob(aob.to_string()), opts, progress);
    let ref_label = images.get(ref_image).map(|i| i.label.as_str());
    // where it points: the resolved target for an anchored sig, or its own match for a direct one
    let matched_rva = report.chosen.as_ref().and_then(|c| {
        c.per_version
            .iter()
            .find(|p| Some(p.label.as_str()) == ref_label)
            .and_then(|p| p.resolved_target_rva.or(p.match_rva))
    });
    let agrees = matched_rva == Some(expected_rva);
    CrossReport {
        report,
        expected_rva,
        matched_rva,
        agrees,
    }
}

pub fn generate_cross(
    images: &[ImageInput],
    aob: &str,
    ref_image: usize,
    expected_rva: u64,
    opts: &SigOptions,
) -> CrossReport {
    generate_cross_with_progress(images, aob, ref_image, expected_rva, opts, &mut |_| {})
}

#[cfg(test)]
mod corpus_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::{BufferSource, Region};

    #[test]
    fn single_string_relocation_across_a_major_gap_is_not_confirmed() {
        // Within a lineage the landings stay structurally close, so a lone string is confident.
        assert!(string_relocation_confirmed(false, Some(0.85)));
        assert!(
            string_relocation_confirmed(false, Some(0.30)),
            "at the floor still confirms"
        );
        // Across a major recompile the worst landing diverges; a lone string is NOT confident,
        // because the string may have migrated to a different function.
        assert!(!string_relocation_confirmed(false, Some(0.18)));
        // ...unless a second corroborating string pins it.
        assert!(string_relocation_confirmed(true, Some(0.18)));
        // A single build carries no cross-build evidence; the separate single-build cap governs it.
        assert!(string_relocation_confirmed(false, None));
    }

    #[test]
    fn ensemble_vote_prefers_corroboration_and_flags_conflict() {
        use std::collections::HashMap;
        let m = |pairs: &[(&str, usize)]| -> HashMap<String, usize> {
            pairs.iter().map(|(l, f)| ((*l).to_string(), *f)).collect()
        };
        // Two channels land the target at function 0x100 in v95; one lands at 0x200 (a wrong address) and
        // is graded best (rank 0) to prove corroboration beats a better lone grade.
        let dissent = m(&[("v83", 0x10), ("v95", 0x200)]);
        let agree_a = m(&[("v83", 0x10), ("v95", 0x100)]);
        let agree_b = m(&[("v83", 0x10), ("v95", 0x100)]);
        let v = ensemble_decide(
            &[dissent.clone(), agree_a.clone(), agree_b.clone()],
            &[0, 1, 1],
        );
        assert_eq!(
            v.winner, 1,
            "the corroborated pair wins over the better-graded loner"
        );
        assert_eq!(v.support, 2);
        assert!(v.conflict, "the dissenter conflicts with the winner on v95");

        // A lone pair that disagrees: support 1 each, conflict, winner by grade (the dissenter, rank 0).
        let lone = ensemble_decide(&[agree_a.clone(), dissent.clone()], &[1, 0]);
        assert_eq!(v.support, 2);
        assert!(lone.conflict);
        assert_eq!(lone.support, 1);
        assert_eq!(lone.winner, 1);

        // No build in common: neither corroborates nor conflicts.
        let none = ensemble_decide(&[m(&[("v83", 0x10)]), m(&[("v95", 0x100)])], &[1, 1]);
        assert!(!none.conflict);
        assert_eq!(none.support, 1);
    }

    #[test]
    fn ensemble_attaches_a_ledger_to_a_string_relocation() {
        // Two x86 builds whose target references one unique string but is recompiled so no cross-build
        // byte signature survives: the string anchor relocates it and the ensemble must attach a
        // structured ledger naming the channel (FP-neutral reporting).
        fn mk(src: &BufferSource, base: usize, hash: u64) -> ImageInput<'_> {
            ImageInput {
                label: format!("h{hash}"),
                source: src,
                base,
                size: 0x800,
                code_regions: vec![Region { base, size: 0x600 }],
                regions: vec![Region { base, size: 0x800 }],
                import: None,
                arch: Arch::X86,
                code_hash: hash,
                packed: false,
                pack_reasons: Vec::new(),
                reloc: None,
            }
        }
        const B: usize = 0x40_0000;
        let s = b"EnsembleLedgerUniqueAnchorString\0";
        let build = |body: &[u8]| -> Vec<u8> {
            let mut buf = vec![0u8; 0x800];
            let s_off = 0x600;
            buf[s_off..s_off + s.len()].copy_from_slice(s);
            let s_abs = (B + s_off) as u32;
            let mut f = vec![0x55u8, 0x8B, 0xEC, 0x68];
            f.extend_from_slice(&s_abs.to_le_bytes());
            f.extend_from_slice(body);
            f.extend_from_slice(&[0x5D, 0xC3]);
            buf[0x100..0x100 + f.len()].copy_from_slice(&f);
            buf
        };
        let a = BufferSource::new(B, build(&[0x33, 0xC0, 0x40]));
        let bb = BufferSource::new(B, build(&[0x8B, 0x45, 0x08, 0x48, 0x48]));
        let images = [mk(&a, B, 1), mk(&bb, B, 2)];
        let report = generate(
            &images,
            &TargetSpec::Ref {
                image: 0,
                rva: 0x100,
            },
            &SigOptions::default(),
        );
        let cand = report.chosen.expect("a relocation candidate");
        let led = cand
            .relocation
            .expect("a relocated candidate carries a ledger");
        assert_eq!(led.anchor, "string");
        assert!(led.support >= 1);
    }

    #[test]
    fn relocation_anchors_fabricate_nothing_on_a_degenerate_x64_image() {
        // #12: all five anchors now operate on x64. The safety property is that a degenerate image
        // (nothing but padding, no real vtable / import / string / call structure) yields no anchor at
        // all, never a fabricated relocation. Each anchor's positive x64 behaviour is validated in its
        // own module; this locks the negative side on x64.
        let mem = BufferSource::new(0x1000, vec![0x90u8; 0x200]);
        let region = Region {
            base: 0x1000,
            size: 0x200,
        };
        let img = ImageInput {
            label: "x64".to_string(),
            source: &mem,
            base: 0x1000,
            size: 0x200,
            code_regions: vec![region],
            regions: vec![region],
            import: Some((0x1000, 0x1100)),
            arch: Arch::X64,
            code_hash: 0,
            packed: false,
            pack_reasons: Vec::new(),
            reloc: None,
        };
        assert!(vtable::make_vtable_anchor(&img, 0x1000).is_none());
        assert!(imports::make_import_anchor(&img, 0x1000).is_none());
        assert!(callers::make_caller_anchor(&img, 0x1000).is_none());
        assert!(encoding::best_encoding_match(&img, &[1, 2, 3]).is_none());
        assert!(make_string_anchor(&img, 0x1000).is_none());
    }

    #[test]
    fn relocate_path_bridges_a_hop_through_an_intermediate_build() {
        // #14: the generic chainer must route through an intermediate build when the direct edge is
        // gated out. Three builds; the direct reference->last edge declines, but reference->mid and
        // mid->last are open, so the widest-path walk reaches the last build via the chain. Synthetic
        // make/edge closures exercise the walk independently of any real anchor: the anchor minted at a
        // build is that build's base, so `edge` can tell which build the hop starts from.
        let m0 = BufferSource::new(0x1000, vec![0u8; 1]);
        let m1 = BufferSource::new(0x2000, vec![0u8; 1]);
        let m2 = BufferSource::new(0x3000, vec![0u8; 1]);
        fn mk(base: usize, src: &BufferSource) -> ImageInput<'_> {
            ImageInput {
                label: String::new(),
                source: src,
                base,
                size: 1,
                code_regions: Vec::new(),
                regions: Vec::new(),
                import: None,
                arch: Arch::X86,
                code_hash: 0,
                packed: false,
                pack_reasons: Vec::new(),
                reloc: None,
            }
        }
        let images = vec![mk(0x1000, &m0), mk(0x2000, &m1), mk(0x3000, &m2)];
        let required = [1usize, 2];
        let make = |i: &ImageInput, _rva: usize| Some(i.base);
        let edge = |i: &ImageInput, anchor: &usize| match (*anchor, i.base) {
            (0x1000, 0x2000) => Some((0x10, 0.90)), // ref -> mid
            (0x2000, 0x3000) => Some((0x20, 0.80)), // mid -> last
            (0x1000, 0x3000) => None, // ref -> last is gated; only the chain reaches it
            _ => None,
        };
        let located = relocate_path(&images, &required, 0, 0, make, edge);
        assert_eq!(
            located[1].map(|(rva, _)| rva),
            Some(0x10),
            "mid reached directly"
        );
        assert!(
            located[2].is_some(),
            "last build reached via the ref->mid->last chain"
        );
        // A path's confidence is its weakest hop: min(0.90, 0.80) = 0.80.
        assert!((located[2].unwrap().1 - 0.80).abs() < 1e-9);
    }

    #[test]
    fn score_and_grade_agree_on_a_validated_candidate() {
        // A validated _CALL to code: its grade is read off final_score, the sub-scores are exposed,
        // and the backward-compatible `score` field mirrors final_score.
        let mut data = vec![0x48, 0x89, 0xE5, 0xC3];
        data.resize(0x20, 0x90);
        data.extend_from_slice(&[0xE8, 0xDB, 0xFF, 0xFF, 0xFF]);
        data.extend_from_slice(&[0x0F, 0xB6, 0xC0, 0x33, 0xC9]);
        data.resize(0x40, 0x90);
        let src = BufferSource::new(0x1000, data);
        let report = generate(
            &[img("a", &src, 0x1000, 0x40)],
            &TargetSpec::Ref { image: 0, rva: 0 },
            &SigOptions::default(),
        );
        let cand = report.chosen.expect("a candidate");
        assert_eq!(cand.grade, Grade::A);
        assert_eq!(cand.score, cand.scores.final_score);
        assert!(cand.scores.final_score >= 82);
        assert_eq!(
            Grade::from_final_score(cand.scores.final_score),
            Grade::A,
            "grade must be the band of final_score"
        );
        assert!(cand.scores.resolver_confidence >= 90);
        assert!(!cand.reasons.is_empty());
        // A cross-build byte signature is not a relocation, so it carries no ensemble ledger.
        assert!(cand.relocation.is_none());
    }

    struct ShortSource {
        base: usize,
        readable: usize,
    }

    impl MemorySource for ShortSource {
        fn read_into(&self, address: usize, buf: &mut [u8]) -> std::io::Result<usize> {
            let off = address - self.base;
            if off >= self.readable {
                return Ok(0);
            }
            let n = buf.len().min(self.readable - off);
            buf[..n].fill(0xCC);
            Ok(n)
        }
    }

    #[test]
    fn reads_drop_the_unreadable_tail_instead_of_zero_filling() {
        let src = ShortSource {
            base: 0x4000,
            readable: 7,
        };
        let region = read_region(&src, 0x4000, 64);
        assert_eq!(
            region.len(),
            7,
            "tail past the readable range must be dropped"
        );
        assert!(region.iter().all(|&b| b == 0xCC));

        let at = read_at(&src, 0x4000, 0, 64);
        assert_eq!(at.len(), 7);
        assert!(at.iter().all(|&b| b == 0xCC));

        let none = read_at(&src, 0x4000, 7, 16);
        assert!(none.is_empty(), "a read starting past the range is empty");
    }

    #[test]
    fn callee_fingerprint_is_register_invariant_but_mnemonic_sensitive() {
        let base = 0x2000;
        let a = BufferSource::new(base, vec![0x48, 0x89, 0xD8, 0xC3]); // mov rax, rbx ; ret
        let b = BufferSource::new(base, vec![0x48, 0x89, 0xD1, 0xC3]); // mov rcx, rdx ; ret
        let c = BufferSource::new(base, vec![0x48, 0x01, 0xD8, 0xC3]); // add rax, rbx ; ret
        let fa = fn_identity(&img("a", &a, base, 4), 0).fingerprint();
        let fb = fn_identity(&img("b", &b, base, 4), 0).fingerprint();
        let fc = fn_identity(&img("c", &c, base, 4), 0).fingerprint();
        assert_eq!(fa, fb, "register allocation must not change the identity");
        assert_ne!(
            fa, fc,
            "a different mnemonic stream must change the identity"
        );
    }

    fn img<'a>(label: &str, src: &'a BufferSource, base: usize, size: usize) -> ImageInput<'a> {
        ImageInput {
            label: label.to_string(),
            source: src,
            base,
            size,
            code_regions: vec![Region { base, size }],
            regions: vec![Region { base, size }],
            import: None,
            arch: Arch::X64,
            code_hash: super::super::stamp::BuildStamp::capture(
                src,
                base,
                &[Region { base, size }],
            )
            .hash,
            packed: false,
            pack_reasons: Vec::new(),
            reloc: None,
        }
    }

    #[test]
    fn collapse_aob_ranges_groups_builds_until_the_bytes_break() {
        // A and B carry the same bytes at the relocated address, C diverges: the first AOB must cover
        // A and B as one range, then a fresh AOB opens a new range at C.
        fn buf_with(pat: &[u8], at: usize) -> Vec<u8> {
            let mut b = vec![0u8; 0x100];
            b[at..at + pat.len()].copy_from_slice(pat);
            b
        }
        let dead = [0xDE, 0xAD, 0xBE, 0xEF];
        let cafe = [0xCA, 0xFE, 0xBA, 0xBE];
        let sa = BufferSource::new(0x1000, buf_with(&dead, 0x10));
        let sb = BufferSource::new(0x1000, buf_with(&dead, 0x20));
        let sc = BufferSource::new(0x1000, buf_with(&cafe, 0x30));
        let images = [
            img("A", &sa, 0x1000, 0x100),
            img("B", &sb, 0x1000, 0x100),
            img("C", &sc, 0x1000, 0x100),
        ];
        let pv = |label: &str, rva: u64, aob: &str| PerVersion {
            label: label.into(),
            match_rva: Some(rva),
            resolved_target_rva: Some(rva),
            target_kind: Some(TargetKind::Code),
            fingerprint_similarity: None,
            aob: Some(aob.into()),
        };
        let per_version = vec![
            pv("A", 0x10, "DE AD BE EF"),
            pv("B", 0x20, "DE AD BE EF"),
            pv("C", 0x30, "CA FE BA BE"),
        ];
        let ranges = collapse_aob_ranges(&images, &per_version);
        assert_eq!(ranges.len(), 2, "two ranges: A..B then C");
        assert_eq!(ranges[0].labels, ["A", "B"]);
        assert_eq!(ranges[0].aob, "DE AD BE EF");
        assert_eq!(ranges[1].labels, ["C"]);
        assert_eq!(ranges[1].aob, "CA FE BA BE");
    }

    #[test]
    fn collapse_aob_ranges_breaks_on_an_unreached_build() {
        // A build with no relocated address breaks contiguity even if the bytes would have matched.
        let dead = [0xDEu8, 0xAD, 0xBE, 0xEF];
        let mut bytes = vec![0u8; 0x100];
        bytes[0x10..0x14].copy_from_slice(&dead);
        let s = BufferSource::new(0x1000, bytes);
        let images = [img("A", &s, 0x1000, 0x100), img("B", &s, 0x1000, 0x100)];
        let per_version = vec![
            PerVersion {
                label: "A".into(),
                match_rva: Some(0x10),
                resolved_target_rva: Some(0x10),
                target_kind: Some(TargetKind::Code),
                fingerprint_similarity: None,
                aob: Some("DE AD BE EF".into()),
            },
            PerVersion {
                label: "B".into(),
                match_rva: None,
                resolved_target_rva: None,
                target_kind: None,
                fingerprint_similarity: None,
                aob: None,
            },
        ];
        let ranges = collapse_aob_ranges(&images, &per_version);
        assert_eq!(ranges.len(), 1, "only the reached build forms a range");
        assert_eq!(ranges[0].labels, ["A"]);
    }

    // A small x64 blob with a rip-relative lea, a call rel32, then padding to make it unique.
    fn blob(call_target: u32, tail: u8) -> Vec<u8> {
        let mut v = vec![
            0x48, 0x8D, 0x05, 0x11, 0x22, 0x33, 0x44, // lea rax,[rip+disp32]
            0xE8, 0x00, 0x00, 0x00, 0x00, // call rel32 (patched below)
            0x33, 0xC0, // xor eax,eax
            0xC3, // ret
        ];
        v[8..12].copy_from_slice(&call_target.to_le_bytes());
        v.push(tail);
        // pad so the region is long enough and the pattern stays unique
        v.extend_from_slice(&[0x90; 32]);
        v
    }

    #[test]
    fn direct_generate_masks_operands_and_is_unique() {
        let a = BufferSource::new(0x1000, blob(0x10, 0xAA));
        let b = BufferSource::new(0x1000, blob(0x999, 0xAA)); // different call target only
        let ia = img("a", &a, 0x1000, 49);
        let ib = img("b", &b, 0x1000, 49);
        let report = generate(
            &[ia, ib],
            &TargetSpec::Ref { image: 0, rva: 0 },
            &SigOptions::default(),
        );
        let cand = report.chosen.expect("a candidate");
        assert_eq!(cand.suffix, Suffix::None);
        assert_eq!(cand.grade, Grade::B); // clean, reloc-safe, direct
        // the call rel32 (4 bytes) must be wildcarded
        assert!(cand.wildcards >= 4);
        assert!(cand.aob.contains("??"));
        assert!(cand.per_version.iter().all(|p| p.match_rva.is_some()));
        assert_eq!(cand.per_version.len(), 2);
    }

    #[test]
    fn negative_corpus_flags_a_module_that_contains_the_signature() {
        let aob = "48 8D 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 C3";
        let contains = BufferSource::new(0x5000, blob(0x77, 0xCC));
        let clean = BufferSource::new(0x5000, vec![0x90u8; 64]);
        let negs = [
            img("contains", &contains, 0x5000, 49),
            img("clean", &clean, 0x5000, 64),
        ];
        let hits = negative_corpus_hits(aob, &negs);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].label, "contains");
        assert!(hits[0].count >= 1);
    }

    #[test]
    fn negative_corpus_is_empty_for_an_unrelated_module() {
        let aob = "48 8D 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 C3";
        let clean = BufferSource::new(0x5000, vec![0xCCu8; 128]);
        let negs = [img("clean", &clean, 0x5000, 128)];
        assert!(negative_corpus_hits(aob, &negs).is_empty());
    }

    #[test]
    fn negative_corpus_ignores_an_unparseable_signature() {
        let clean = BufferSource::new(0x5000, vec![0x90u8; 64]);
        let negs = [img("clean", &clean, 0x5000, 64)];
        assert!(negative_corpus_hits("not a signature", &negs).is_empty());
    }

    #[test]
    fn holdout_passes_when_the_signature_generalizes() {
        // Three builds of the same function, differing only in the masked call target. A signature
        // generated from any two must still uniquely match the third.
        let a = BufferSource::new(0x1000, blob(0x10, 0xAA));
        let b = BufferSource::new(0x1000, blob(0x20, 0xBB));
        let c = BufferSource::new(0x1000, blob(0x30, 0xCC));
        let images = [
            img("a", &a, 0x1000, 49),
            img("b", &b, 0x1000, 49),
            img("c", &c, 0x1000, 49),
        ];
        let aob = "48 8D 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 C3";
        let results = holdout_validate(
            &images,
            &TargetSpec::Aob(aob.to_string()),
            &SigOptions::default(),
        );
        assert_eq!(results.len(), 3);
        assert!(results.iter().all(|r| r.generated && r.matched_holdout));
    }

    #[test]
    fn holdout_is_skipped_below_three_builds() {
        let a = BufferSource::new(0x1000, blob(0x10, 0xAA));
        let b = BufferSource::new(0x1000, blob(0x20, 0xBB));
        let images = [img("a", &a, 0x1000, 49), img("b", &b, 0x1000, 49)];
        let aob = "48 8D 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 C3";
        assert!(
            holdout_validate(
                &images,
                &TargetSpec::Aob(aob.to_string()),
                &SigOptions::default()
            )
            .is_empty()
        );
    }

    #[test]
    fn fn_identity_captures_distinctive_constants() {
        let base = 0x4000;
        // mov eax, 0xDEADBEEF ; ret
        let src = BufferSource::new(base, vec![0xB8, 0xEF, 0xBE, 0xAD, 0xDE, 0xC3]);
        let id = fn_identity(&img("c", &src, base, 6), 0);
        assert!(
            id.constants.contains(&0xDEAD_BEEF),
            "got {:?}",
            id.constants
        );
        assert_eq!(id.returns, 1);
        // a small struct offset is not distinctive
        let small = BufferSource::new(base, vec![0x83, 0xC0, 0x08, 0xC3]); // add eax, 8 ; ret
        assert!(
            fn_identity(&img("s", &small, base, 4), 0)
                .constants
                .is_empty()
        );
    }

    #[test]
    fn fn_identity_captures_string_references() {
        let base = 0x6000;
        // lea rax, [rip+9] ; ret ; pad ; "Hello\0" at rva 16
        let mut code = vec![0x48, 0x8D, 0x05, 0x09, 0x00, 0x00, 0x00, 0xC3];
        code.resize(16, 0x00);
        code.extend_from_slice(b"Hello\0");
        let src = BufferSource::new(base, code);
        let id = fn_identity(&img("str", &src, base, 22), 0);
        assert!(
            id.strings.iter().any(|s| s == "Hello"),
            "got {:?}",
            id.strings
        );
    }

    #[test]
    fn build_profile_separates_arch_and_pack_lanes() {
        let src = BufferSource::new(0x1000, blob(0x10, 0xAA));
        let mut a = img("a", &src, 0x1000, 49);
        let mut b = img("b", &src, 0x1000, 49);
        assert!(BuildProfile::of(&a).same_variant(&BuildProfile::of(&b)));
        b.arch = Arch::X86;
        assert!(!BuildProfile::of(&a).same_variant(&BuildProfile::of(&b)));
        b.arch = Arch::X64;
        a.packed = true;
        assert!(!BuildProfile::of(&a).same_variant(&BuildProfile::of(&b)));
    }

    #[test]
    fn xref_count_finds_rel32_calls() {
        let base = 0x10000;
        let mut code = vec![0x90u8; 0x80];
        for site in [0x10usize, 0x20] {
            code[site] = 0xE8;
            let rel = 0x40i32 - (site as i32 + 5);
            code[site + 1..site + 5].copy_from_slice(&rel.to_le_bytes());
        }
        let src = BufferSource::new(base, code);
        assert_eq!(xref_count(&img("x", &src, base, 0x80), 0x40), 2);
    }

    #[test]
    fn string_anchor_locates_a_function_by_its_string() {
        let base = 0x1000;
        let mut mem = vec![0u8; 0x200];
        mem[0x10..0x1B].copy_from_slice(b"MapleStory\0");
        mem[0x100] = 0x68; // push imm32 of the string address
        mem[0x101..0x105].copy_from_slice(&0x1010u32.to_le_bytes());
        let src = BufferSource::new(base, mem);
        let input = ImageInput {
            label: "t".to_string(),
            source: &src,
            base,
            size: 0x200,
            code_regions: vec![Region {
                base: base + 0x100,
                size: 0x100,
            }],
            regions: vec![
                Region { base, size: 0x100 },
                Region {
                    base: base + 0x100,
                    size: 0x100,
                },
            ],
            import: None,
            arch: Arch::X86,
            code_hash: 0,
            packed: false,
            pack_reasons: Vec::new(),
            reloc: None,
        };
        let anchor = make_string_anchor(&input, 0x100).expect("a string anchor");
        assert_eq!(anchor.text, "MapleStory");
        assert_eq!(resolve_string_anchor(&input, &anchor), Some(0x101));
        assert!(
            resolve_string_anchor(
                &input,
                &StringAnchor {
                    text: "absent".to_string(),
                    also: None,
                }
            )
            .is_none()
        );
    }

    #[test]
    fn string_anchor_collapses_repeats_to_the_x86_entry() {
        let base = 0x2000;
        let mut mem = vec![0u8; 0x300];
        mem[0x10..0x1B].copy_from_slice(b"DistinctStr");
        mem[0x100..0x103].copy_from_slice(&[0x55, 0x8B, 0xEC]); // push ebp ; mov ebp, esp
        for site in [0x110usize, 0x120] {
            mem[site] = 0x68; // push the same string address twice in one function
            mem[site + 1..site + 5].copy_from_slice(&0x2010u32.to_le_bytes());
        }
        let src = BufferSource::new(base, mem);
        let input = ImageInput {
            label: "t".to_string(),
            source: &src,
            base,
            size: 0x300,
            code_regions: vec![Region {
                base: base + 0x100,
                size: 0x200,
            }],
            regions: vec![
                Region { base, size: 0x100 },
                Region {
                    base: base + 0x100,
                    size: 0x200,
                },
            ],
            import: None,
            arch: Arch::X86,
            code_hash: 0,
            packed: false,
            pack_reasons: Vec::new(),
            reloc: None,
        };
        let anchor = make_string_anchor(&input, 0x110).expect("a string anchor");
        assert_eq!(resolve_string_anchor(&input, &anchor), Some(0x100));
    }

    #[test]
    fn string_anchor_uses_a_pair_when_each_string_is_shared() {
        let base = 0x3000;
        let mut mem = vec![0u8; 0x200];
        mem[0x10..0x16].copy_from_slice(b"alpha\0");
        mem[0x20..0x25].copy_from_slice(b"beta\0");
        let push = |mem: &mut [u8], at: usize, addr: u32| {
            mem[at] = 0x68;
            mem[at + 1..at + 5].copy_from_slice(&addr.to_le_bytes());
        };
        for entry in [0x100usize, 0x140, 0x180] {
            mem[entry..entry + 3].copy_from_slice(&[0x55, 0x8B, 0xEC]);
        }
        push(&mut mem, 0x103, 0x3010); // F1 references alpha
        push(&mut mem, 0x108, 0x3020); // F1 references beta
        push(&mut mem, 0x143, 0x3010); // F2 references alpha
        push(&mut mem, 0x183, 0x3020); // F3 references beta
        let src = BufferSource::new(base, mem);
        let input = ImageInput {
            label: "t".to_string(),
            source: &src,
            base,
            size: 0x200,
            code_regions: vec![Region {
                base: base + 0x100,
                size: 0x100,
            }],
            regions: vec![
                Region { base, size: 0x100 },
                Region {
                    base: base + 0x100,
                    size: 0x100,
                },
            ],
            import: None,
            arch: Arch::X86,
            code_hash: 0,
            packed: false,
            pack_reasons: Vec::new(),
            reloc: None,
        };
        // neither string alone is unique, but only F1 references both
        let anchor = make_string_anchor(&input, 0x103).expect("a paired anchor");
        assert!(anchor.also.is_some());
        assert_eq!(resolve_string_anchor(&input, &anchor), Some(0x100));
    }

    #[test]
    fn string_anchor_fallback_when_byte_aob_only_matches_one_build() {
        // Both builds hold the same function: an x86 prologue that pushes the address of a shared,
        // distinctive string. Their tails differ, so a byte AOB taken from the first build cannot be
        // made unique across both, and generation must fall back to the recompile-stable string
        // anchor instead of giving up.
        let build = |hash: u64, tail: [u8; 5]| {
            let mut mem = vec![0u8; 0x200];
            mem[0x10..0x1B].copy_from_slice(b"MapleStory\0");
            mem[0x100..0x103].copy_from_slice(&[0x55, 0x8B, 0xEC]); // push ebp ; mov ebp, esp
            mem[0x103] = 0x68; // push imm32 of the string address
            mem[0x104..0x108].copy_from_slice(&0x1010u32.to_le_bytes());
            mem[0x108..0x10D].copy_from_slice(&tail);
            (BufferSource::new(0x1000, mem), hash)
        };
        // the tails differ in the opcode byte, not just an immediate, so operand-masking the seed
        // AOB cannot reconcile the two builds and the byte path is forced to give up.
        let (a_src, a_hash) = build(1, [0xB8, 0xEF, 0xBE, 0xAD, 0xDE]); // mov eax, 0xDEADBEEF
        let (b_src, b_hash) = build(2, [0xB9, 0x11, 0x22, 0x33, 0x44]); // mov ecx, 0x44332211
        fn make_input<'a>(label: &str, src: &'a BufferSource, hash: u64) -> ImageInput<'a> {
            ImageInput {
                label: label.to_string(),
                source: src,
                base: 0x1000,
                size: 0x200,
                code_regions: vec![Region {
                    base: 0x1100,
                    size: 0x100,
                }],
                regions: vec![
                    Region {
                        base: 0x1000,
                        size: 0x100,
                    },
                    Region {
                        base: 0x1100,
                        size: 0x100,
                    },
                ],
                import: None,
                arch: Arch::X86,
                code_hash: hash,
                packed: false,
                pack_reasons: Vec::new(),
                reloc: None,
            }
        }
        let images = [
            make_input("a", &a_src, a_hash),
            make_input("b", &b_src, b_hash),
        ];
        // matches only build a: the DEADBEEF tail does not exist in build b
        let aob = "55 8B EC 68 10 10 00 00 B8 EF BE AD DE";
        let report = generate(
            &images,
            &TargetSpec::Aob(aob.to_string()),
            &SigOptions::default(),
        );
        let cand = report.chosen.expect("a string-anchor fallback candidate");
        assert!(
            cand.aob.starts_with("@string="),
            "expected a string anchor, got {}",
            cand.aob
        );
        assert_eq!(cand.aob, "@string=MapleStory");
        assert_eq!(cand.per_version.len(), 2);
        assert!(
            cand.per_version
                .iter()
                .all(|p| p.resolved_target_rva == Some(0x100))
        );
    }

    // A single x86 build holding "MapleStory" and a function that references it.
    fn string_build() -> BufferSource {
        let mut mem = vec![0u8; 0x200];
        mem[0x10..0x1B].copy_from_slice(b"MapleStory\0");
        mem[0x100..0x103].copy_from_slice(&[0x55, 0x8B, 0xEC]); // push ebp ; mov ebp,esp
        mem[0x103] = 0x68; // push imm32 of the string address
        mem[0x104..0x108].copy_from_slice(&0x1010u32.to_le_bytes());
        mem[0x108] = 0xC3; // ret
        BufferSource::new(0x1000, mem)
    }

    fn string_img(src: &BufferSource, hash: u64) -> ImageInput<'_> {
        ImageInput {
            label: "a".to_string(),
            source: src,
            base: 0x1000,
            size: 0x200,
            code_regions: vec![Region {
                base: 0x1100,
                size: 0x100,
            }],
            regions: vec![
                Region {
                    base: 0x1000,
                    size: 0x100,
                },
                Region {
                    base: 0x1100,
                    size: 0x100,
                },
            ],
            import: None,
            arch: Arch::X86,
            code_hash: hash,
            packed: false,
            pack_reasons: Vec::new(),
            reloc: None,
        }
    }

    #[test]
    fn string_anchor_single_build_is_capped_below_a() {
        // Validated against only one build, a string anchor cannot earn A: there is no cross-version
        // evidence, so it is capped and the reason is recorded.
        let src = string_build();
        let img = string_img(&src, 1);
        let cand = string_anchor_candidate(&[img], &[0], 0, 0x100, &SigOptions::default())
            .expect("a string anchor");
        assert!(cand.aob.starts_with("@string="));
        assert_ne!(cand.grade, Grade::A);
        assert!(cand.reasons.iter().any(|r| r.contains("one build")));
    }

    #[test]
    fn string_anchor_consistent_across_builds_earns_a() {
        // Two builds whose referenced function is byte-identical: the anchor resolves consistently in
        // both, so it earns A and carries per-build similarity evidence.
        let a = string_build();
        let b = string_build();
        let cand = string_anchor_candidate(
            &[string_img(&a, 1), string_img(&b, 2)],
            &[0, 1],
            0,
            0x100,
            &SigOptions::default(),
        )
        .expect("a string anchor");
        assert_eq!(cand.grade, Grade::A);
        assert_eq!(cand.per_version.len(), 2);
        assert_eq!(cand.per_version[1].fingerprint_similarity, Some(1.0));
        assert!(cand.scores.cross_build >= 95);
    }

    #[test]
    fn single_build_aob_mints_a_unique_operand_masked_pattern() {
        // A function with a volatile call/lea operand: the minted AOB masks the operand bytes and still
        // matches exactly once in the build.
        let src = BufferSource::new(0x1000, blob(0x1234, 0xAB));
        let image = img("x", &src, 0x1000, 49);
        let aob = single_build_aob(&image, 0, &SigOptions::default()).expect("an aob");
        assert!(
            aob.contains("??"),
            "the volatile operand should be wildcarded: {aob}"
        );
        let sig = crate::pattern::try_signature_from_aob(&aob).unwrap();
        let pat = CompiledPattern::new(&sig).unwrap();
        assert_eq!(
            CodeCache::build(&image).locate(&pat).0,
            1,
            "the minted AOB must be unique in the build"
        );
    }

    #[test]
    fn string_anchor_mints_a_fresh_per_build_aob_when_bytes_differ() {
        // Two builds: the same function references the same unique string, but its bytes differ (a
        // recompile inserts `xor eax,eax`). A single cross-build byte AOB cannot match both, but the
        // string anchor relocates the function in each build and mints a build-specific AOB that
        // uniquely matches there. This is the "new AOB for the recompiled build" path.
        let mut a = vec![0u8; 0x200];
        a[0x10..0x1B].copy_from_slice(b"MapleStory\0");
        a[0x100..0x103].copy_from_slice(&[0x55, 0x8B, 0xEC]); // push ebp ; mov ebp,esp
        a[0x103] = 0x68; // push imm32 (string address)
        a[0x104..0x108].copy_from_slice(&0x1010u32.to_le_bytes());
        a[0x108] = 0xC3; // ret
        let mut b = vec![0u8; 0x200];
        b[0x10..0x1B].copy_from_slice(b"MapleStory\0");
        b[0x100..0x105].copy_from_slice(&[0x55, 0x8B, 0xEC, 0x33, 0xC0]); // + xor eax,eax
        b[0x105] = 0x68;
        b[0x106..0x10A].copy_from_slice(&0x1010u32.to_le_bytes());
        b[0x10A] = 0xC3;
        let sa = BufferSource::new(0x1000, a);
        let sb = BufferSource::new(0x1000, b);
        let cand = string_anchor_candidate(
            &[string_img(&sa, 1), string_img(&sb, 2)],
            &[0, 1],
            0,
            0x100,
            &SigOptions::default(),
        )
        .expect("a string anchor");
        let aob_a = cand.per_version[0]
            .aob
            .clone()
            .expect("per-build AOB for build A");
        let aob_b = cand.per_version[1]
            .aob
            .clone()
            .expect("per-build AOB for build B");
        assert_ne!(aob_a, aob_b, "a recompiled build must get its own AOB");
        let unique_in = |aob: &str, src: &BufferSource| {
            let sig = crate::pattern::try_signature_from_aob(aob).unwrap();
            let pat = CompiledPattern::new(&sig).unwrap();
            CodeCache::build(&string_img(src, 9)).locate(&pat).0
        };
        assert_eq!(unique_in(&aob_a, &sa), 1, "A's AOB matches A uniquely");
        assert_eq!(unique_in(&aob_b, &sb), 1, "B's AOB matches B uniquely");
        assert_eq!(
            unique_in(&aob_a, &sb),
            0,
            "A's AOB must NOT match the recompiled build B"
        );
    }

    // An x86 ImageInput over a raw buffer, for the shortlist test.
    fn x86_img<'a>(
        label: &str,
        src: &'a BufferSource,
        base: usize,
        size: usize,
        hash: u64,
    ) -> ImageInput<'a> {
        ImageInput {
            label: label.to_string(),
            source: src,
            base,
            size,
            code_regions: vec![Region { base, size }],
            regions: vec![Region { base, size }],
            import: None,
            arch: Arch::X86,
            code_hash: hash,
            packed: false,
            pack_reasons: Vec::new(),
            reloc: None,
        }
    }

    #[test]
    fn a_degenerate_repeated_function_yields_a_per_build_shortlist() {
        // A distinctive function repeated three times in each build: no unique byte AOB, no string or
        // import anchor, and the encoding/fingerprint paths tie three ways, so every confident path
        // declines. Instead of nothing, the engine returns a shortlist of the family for the other
        // build, the honest fallback for an anchor-less, structurally-degenerate target.
        let body = [
            0xB8, 0x11, 0x22, 0x33, 0x44, // mov eax, imm32
            0xBB, 0x55, 0x66, 0x77, 0x88, // mov ebx, imm32
            0x01, 0xD8, // add eax, ebx
            0x31, 0xC9, // xor ecx, ecx
            0x83, 0xC0, 0x10, // add eax, 0x10
            0xC3, // ret
        ];
        let image = |pad: u8| {
            let mut v = vec![0x90u8; 0x300];
            for &at in &[0x40usize, 0x120, 0x200] {
                v[at..at + body.len()].copy_from_slice(&body);
            }
            v[0x2F0] = pad; // differ so the two builds are distinct required inputs
            v
        };
        let a = BufferSource::new(0x1000, image(0xAA));
        let b = BufferSource::new(0x1000, image(0xBB));
        let report = generate(
            &[
                x86_img("a", &a, 0x1000, 0x300, 1),
                x86_img("b", &b, 0x1000, 0x300, 2),
            ],
            &TargetSpec::Ref {
                image: 0,
                rva: 0x40,
            },
            &SigOptions::default(),
        );
        assert!(
            report.chosen.is_none(),
            "an ambiguous repeated function cannot be pinned"
        );
        let sl = report
            .shortlists
            .iter()
            .find(|s| s.label == "b")
            .expect("a shortlist for build b");
        assert!(
            sl.entries.len() >= 2,
            "the degenerate family should list multiple candidates, got {}",
            sl.entries.len()
        );
        assert!(sl.entries.iter().all(|e| e.similarity >= 0.65));
    }

    #[test]
    fn fingerprint_similarity_survives_a_volatile_immediate() {
        // The same function differing only in a non-distinctive immediate keeps identity 1.0 (the kind
        // of operand byte a signature masks must not perturb the fingerprint); a changed mnemonic
        // stream drops it below 1.
        let a = BufferSource::new(
            0x2000,
            vec![0x48, 0x89, 0xE5, 0xB8, 0x10, 0x00, 0x00, 0x00, 0xC3],
        );
        let b = BufferSource::new(
            0x2000,
            vec![0x48, 0x89, 0xE5, 0xB8, 0x20, 0x00, 0x00, 0x00, 0xC3],
        );
        let ia = fn_identity(&img("a", &a, 0x2000, 9), 0);
        let ib = fn_identity(&img("b", &b, 0x2000, 9), 0);
        assert!((ia.similarity(&ib) - 1.0).abs() < 1e-9);
        let c = BufferSource::new(
            0x2000,
            vec![0x48, 0x01, 0xE5, 0xB8, 0x10, 0x00, 0x00, 0x00, 0xC3],
        );
        let ic = fn_identity(&img("c", &c, 0x2000, 9), 0);
        assert!(ia.similarity(&ic) < 1.0);
    }

    #[test]
    fn cross_validate_agrees_only_on_matching_rva() {
        let a = BufferSource::new(0x1000, blob(0x10, 0xAA));
        let b = BufferSource::new(0x1000, blob(0x999, 0xBB));
        let images = [img("a", &a, 0x1000, 49), img("b", &b, 0x1000, 49)];
        let aob = "48 8D 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 C3";

        let hit = generate_cross(&images, aob, 0, 0, &SigOptions::default());
        assert!(hit.report.chosen.is_some());
        assert_eq!(hit.matched_rva, Some(0));
        assert!(hit.agrees);

        let miss = generate_cross(&images, aob, 0, 0x40, &SigOptions::default());
        assert_eq!(miss.matched_rva, Some(0));
        assert!(!miss.agrees);
    }

    #[test]
    fn duplicate_builds_collapse() {
        let a = BufferSource::new(0x1000, blob(0x10, 0xAA));
        let b = BufferSource::new(0x1000, blob(0x10, 0xAA)); // identical
        let c = BufferSource::new(0x1000, blob(0x55, 0xBB)); // different
        let report = generate(
            &[
                img("a", &a, 0x1000, 49),
                img("b", &b, 0x1000, 49),
                img("c", &c, 0x1000, 49),
            ],
            &TargetSpec::Ref { image: 0, rva: 0 },
            &SigOptions::default(),
        );
        assert_eq!(report.unique_builds, 2);
        assert_eq!(report.duplicate_groups.len(), 2);
    }

    #[test]
    fn mixed_arch_is_rejected() {
        let a = BufferSource::new(0x1000, blob(0x10, 0xAA));
        let b = BufferSource::new(0x1000, blob(0x10, 0xAA));
        let mut ib = img("b", &b, 0x1000, 49);
        ib.arch = Arch::X86;
        let report = generate(
            &[img("a", &a, 0x1000, 49), ib],
            &TargetSpec::Ref { image: 0, rva: 0 },
            &SigOptions::default(),
        );
        assert!(report.chosen.is_none());
        assert!(
            report
                .diagnostics
                .iter()
                .any(|d| matches!(d, Diag::MixedArch))
        );
    }

    #[test]
    fn packed_input_caps_grade_at_d() {
        let a = BufferSource::new(0x1000, blob(0x10, 0xAA));
        let b = BufferSource::new(0x1000, blob(0x999, 0xAA));
        let mut ia = img("a", &a, 0x1000, 49);
        ia.packed = true;
        ia.pack_reasons = vec!["test".into()];
        let report = generate(
            &[ia, img("b", &b, 0x1000, 49)],
            &TargetSpec::Ref { image: 0, rva: 0 },
            &SigOptions::default(),
        );
        assert_eq!(report.chosen.unwrap().grade, Grade::D);
        assert!(
            report
                .diagnostics
                .iter()
                .any(|d| matches!(d, Diag::PackedInput { .. }))
        );
    }

    #[test]
    fn entry_a_hardens_an_existing_aob() {
        let a = BufferSource::new(0x1000, blob(0x10, 0xAA));
        let b = BufferSource::new(0x1000, blob(0x999, 0xAA));
        // the lea + call with the rel32 already wildcarded by the user
        let aob = "48 8D 05 11 22 33 44 E8 ?? ?? ?? ?? 33 C0 C3";
        let report = generate(
            &[img("a", &a, 0x1000, 49), img("b", &b, 0x1000, 49)],
            &TargetSpec::Aob(aob.to_string()),
            &SigOptions::default(),
        );
        let cand = report.chosen.expect("hardened candidate");
        assert_eq!(cand.per_version.len(), 2);
        assert!(cand.aob.contains("??"));
    }

    #[test]
    fn deterministic_across_runs() {
        let a = BufferSource::new(0x1000, blob(0x10, 0xAA));
        let b = BufferSource::new(0x1000, blob(0x999, 0xAA));
        let run = || {
            generate(
                &[img("a", &a, 0x1000, 49), img("b", &b, 0x1000, 49)],
                &TargetSpec::Ref { image: 0, rva: 0 },
                &SigOptions::default(),
            )
            .chosen
            .unwrap()
            .aob
        };
        assert_eq!(run(), run());
    }

    struct FakeReloc {
        rva: usize,
        kind: RelocKind,
    }
    impl RelocLookup for FakeReloc {
        fn is_relocated(&self, rva: usize) -> bool {
            self.reloc_kind_at(rva).is_some()
        }
        fn reloc_kind_at(&self, rva: usize) -> Option<RelocKind> {
            let width = if matches!(self.kind, RelocKind::Dir64) {
                8
            } else {
                4
            };
            (rva >= self.rva && rva < self.rva + width).then_some(self.kind)
        }
    }

    #[test]
    fn unsupported_reloc_in_window_is_rejected_with_real_rva() {
        let a = BufferSource::new(0x1000, blob(0x10, 0xAA));
        let fake = FakeReloc {
            rva: 0x1,
            kind: RelocKind::Unsupported(7),
        };
        let mut ia = img("a", &a, 0x1000, 49);
        ia.reloc = Some(&fake);
        let report = generate(
            &[ia],
            &TargetSpec::Ref { image: 0, rva: 0 },
            &SigOptions::default(),
        );
        assert!(report.chosen.is_none());
        let found = report.rejected.iter().flat_map(|c| &c.diags).any(|d| {
            matches!(
                d,
                Diag::UnsupportedReloc {
                    rva: 0x1,
                    reloc_type: 7
                }
            )
        });
        assert!(
            found,
            "expected an UnsupportedReloc diag carrying rva 0x1 and type 7"
        );
    }

    #[test]
    fn call_anchor_is_discovered_and_validated() {
        // function at rva 0; a `call rva 0` at rva 0x20; sigmaker should prefer the validated _CALL.
        let mut data = vec![0x48, 0x89, 0xE5, 0xC3]; // mov rbp,rsp ; ret
        data.resize(0x20, 0x90);
        data.extend_from_slice(&[0xE8, 0xDB, 0xFF, 0xFF, 0xFF]); // call rva 0 (-0x25 from rva 0x25)
        data.extend_from_slice(&[0x0F, 0xB6, 0xC0, 0x33, 0xC9]); // movzx eax,al ; xor ecx,ecx
        data.resize(0x40, 0x90);
        let src = BufferSource::new(0x1000, data);
        let report = generate(
            &[img("a", &src, 0x1000, 0x40)],
            &TargetSpec::Ref { image: 0, rva: 0 },
            &SigOptions::default(),
        );
        let cand = report.chosen.expect("a candidate");
        assert_eq!(cand.suffix, Suffix::Call);
        assert_eq!(cand.grade, Grade::A);
        assert_eq!(cand.per_version[0].resolved_target_rva, Some(0));
        assert_eq!(cand.per_version[0].target_kind, Some(TargetKind::Code));
        assert!(cand.aob.starts_with("E8 ?? ?? ?? ??"));
    }

    #[test]
    fn jmp_anchor_is_discovered() {
        let mut data = vec![0x48, 0x89, 0xE5, 0xC3]; // func at rva 0
        data.resize(0x20, 0x90);
        data.extend_from_slice(&[0xE9, 0xDB, 0xFF, 0xFF, 0xFF]); // jmp rva 0
        data.extend_from_slice(&[0x0F, 0xB6, 0xC0, 0x33, 0xC9]);
        data.resize(0x40, 0x90);
        let src = BufferSource::new(0x1000, data);
        let report = generate(
            &[img("a", &src, 0x1000, 0x40)],
            &TargetSpec::Ref { image: 0, rva: 0 },
            &SigOptions::default(),
        );
        let cand = report.chosen.expect("a candidate");
        assert_eq!(cand.suffix, Suffix::Jmp);
        assert_eq!(cand.grade, Grade::A);
        assert_eq!(cand.per_version[0].resolved_target_rva, Some(0));
        assert!(cand.aob.starts_with("E9 ?? ?? ?? ??"));
    }

    #[test]
    fn branch_target_outside_code_is_downgraded() {
        // call at rva 0 (in code) targets rva 0x200, which is outside the declared code region.
        let mut data = vec![0xE8, 0xFB, 0x01, 0x00, 0x00, 0x0F, 0xB6, 0xC0, 0x33, 0xC9]; // call 0x200
        data.resize(0x210, 0x90);
        let src = BufferSource::new(0x1000, data);
        let regions = vec![Region {
            base: 0x1000,
            size: 0x40,
        }];
        let input = ImageInput {
            label: "a".to_string(),
            source: &src,
            base: 0x1000,
            size: 0x210,
            code_hash: super::super::stamp::BuildStamp::capture(&src, 0x1000, &regions).hash,
            regions: regions.clone(),
            code_regions: regions,
            import: None,
            arch: Arch::X64,
            packed: false,
            pack_reasons: Vec::new(),
            reloc: None,
        };
        let report = generate(
            &[input],
            &TargetSpec::Ref {
                image: 0,
                rva: 0x200,
            },
            &SigOptions::default(),
        );
        let cand = report.chosen.expect("a candidate");
        assert_eq!(cand.suffix, Suffix::Call);
        assert_eq!(cand.grade, Grade::C);
        assert_eq!(cand.per_version[0].target_kind, Some(TargetKind::Unknown));
        assert!(
            cand.diags
                .iter()
                .any(|d| matches!(d, Diag::TargetNotCode { .. }))
        );
    }

    #[test]
    fn ptr_anchor_rip_relative_is_discovered() {
        // a `lea rax, [rip+func]` referencing the function at rva 0 should win as a validated _PTR.
        let mut data = vec![0x48, 0x89, 0xE5, 0xC3]; // func at rva 0
        data.resize(0x20, 0x90);
        data.extend_from_slice(&[0x48, 0x8D, 0x05, 0xD9, 0xFF, 0xFF, 0xFF]); // lea rax,[rip+rva 0]
        data.extend_from_slice(&[0x0F, 0xB6, 0xC0, 0x33, 0xC9]);
        data.resize(0x40, 0x90);
        let src = BufferSource::new(0x1000, data);
        let report = generate(
            &[img("a", &src, 0x1000, 0x40)],
            &TargetSpec::Ref { image: 0, rva: 0 },
            &SigOptions::default(),
        );
        let cand = report.chosen.expect("a candidate");
        assert_eq!(cand.suffix, Suffix::Ptr);
        assert_eq!(cand.grade, Grade::A);
        assert_eq!(cand.per_version[0].resolved_target_rva, Some(0));
        assert_eq!(cand.per_version[0].target_kind, Some(TargetKind::Code));
        assert!(cand.aob.starts_with("48 8D 05 ?? ?? ?? ??"));
    }

    fn custom_img<'a>(
        src: &'a BufferSource,
        base: usize,
        code: Vec<Region>,
        regions: Vec<Region>,
        arch: Arch,
    ) -> ImageInput<'a> {
        ImageInput {
            label: "a".to_string(),
            source: src,
            base,
            size: 0x10000,
            code_hash: super::super::stamp::BuildStamp::capture(src, base, &code).hash,
            code_regions: code,
            regions,
            import: None,
            arch,
            packed: false,
            pack_reasons: Vec::new(),
            reloc: None,
        }
    }

    #[test]
    fn ptr_to_data_is_not_grade_a() {
        // RIP-relative `mov rax,[rip+data]` into a data region: resolved + kind-stable, but its
        // content is not validated, so it must be graded B (not A) on kind-consistency alone.
        let mut data = vec![0x48, 0x89, 0xE5, 0xC3];
        data.resize(0x20, 0x90);
        // mov rax,[rip+0x3000] at abs 0x1020: disp = 0x3000 - 0x1027 = 0x1FD9
        data.extend_from_slice(&[0x48, 0x8B, 0x05, 0xD9, 0x1F, 0x00, 0x00]);
        data.extend_from_slice(&[0x0F, 0xB6, 0xC0, 0x33, 0xC9]);
        data.resize(0x40, 0x90);
        let src = BufferSource::new(0x1000, data);
        let input = custom_img(
            &src,
            0x1000,
            vec![Region {
                base: 0x1000,
                size: 0x100,
            }],
            vec![
                Region {
                    base: 0x1000,
                    size: 0x100,
                },
                Region {
                    base: 0x3000,
                    size: 0x100,
                },
            ],
            Arch::X64,
        );
        let report = generate(
            &[input],
            &TargetSpec::Ref {
                image: 0,
                rva: 0x2000,
            },
            &SigOptions::default(),
        );
        let cand = report.chosen.expect("a candidate");
        assert_eq!(cand.suffix, Suffix::Ptr);
        assert_eq!(cand.grade, Grade::B);
        assert_eq!(cand.per_version[0].target_kind, Some(TargetKind::Data));
        assert_eq!(cand.per_version[0].resolved_target_rva, Some(0x2000));
    }

    #[test]
    fn ptr_to_unknown_is_grade_c() {
        let mut data = vec![0x48, 0x89, 0xE5, 0xC3];
        data.resize(0x20, 0x90);
        // mov rax,[rip+0x6000]: target outside every region -> Unknown
        data.extend_from_slice(&[0x48, 0x8B, 0x05, 0xD9, 0x4F, 0x00, 0x00]);
        data.extend_from_slice(&[0x0F, 0xB6, 0xC0, 0x33, 0xC9]);
        data.resize(0x40, 0x90);
        let src = BufferSource::new(0x1000, data);
        let code = vec![Region {
            base: 0x1000,
            size: 0x100,
        }];
        let input = custom_img(&src, 0x1000, code.clone(), code, Arch::X64);
        let report = generate(
            &[input],
            &TargetSpec::Ref {
                image: 0,
                rva: 0x5000,
            },
            &SigOptions::default(),
        );
        let cand = report.chosen.expect("a candidate");
        assert_eq!(cand.suffix, Suffix::Ptr);
        assert_eq!(cand.grade, Grade::C);
        assert_eq!(cand.per_version[0].target_kind, Some(TargetKind::Unknown));
    }

    #[test]
    fn x86_absolute_ptr_is_capped_below_a() {
        // 32-bit absolute `mov eax,[0x400000]` referencing the function at rva 0; absolute is never A.
        let mut data = vec![0x55, 0x8B, 0xEC, 0xC3]; // push ebp ; mov ebp,esp ; ret
        data.resize(0x20, 0x90);
        data.extend_from_slice(&[0x8B, 0x05, 0x00, 0x00, 0x40, 0x00]); // mov eax,[0x400000]
        data.extend_from_slice(&[0x0F, 0xB6, 0xC0, 0x33, 0xC9]);
        data.resize(0x40, 0x90);
        let src = BufferSource::new(0x40_0000, data);
        let code = vec![Region {
            base: 0x40_0000,
            size: 0x40,
        }];
        let input = custom_img(&src, 0x40_0000, code.clone(), code, Arch::X86);
        let report = generate(
            &[input],
            &TargetSpec::Ref { image: 0, rva: 0 },
            &SigOptions::default(),
        );
        let ptr = report
            .chosen
            .iter()
            .chain(&report.alternates)
            .chain(&report.rejected)
            .find(|c| c.suffix == Suffix::Ptr)
            .expect("a ptr candidate");
        assert_ne!(ptr.grade, Grade::A);
        assert_eq!(ptr.grade, Grade::C);
    }

    #[test]
    fn ptr_across_two_nonduplicate_builds() {
        let make = |imm: u32| {
            let mut d = vec![0x48, 0x89, 0xE5, 0xC3]; // func at rva 0
            d.resize(0x10, 0x90);
            d.push(0xB8);
            d.extend_from_slice(&imm.to_le_bytes());
            d.resize(0x20, 0x90);
            d.extend_from_slice(&[0x48, 0x8D, 0x05, 0xD9, 0xFF, 0xFF, 0xFF]); // lea rax,[rip+rva 0]
            d.extend_from_slice(&[0x0F, 0xB6, 0xC0, 0x33, 0xC9]);
            d.resize(0x40, 0x90);
            d
        };
        let a = BufferSource::new(0x1000, make(0x1111_1111));
        let b = BufferSource::new(0x1000, make(0x2222_2222));
        let report = generate(
            &[img("a", &a, 0x1000, 0x40), img("b", &b, 0x1000, 0x40)],
            &TargetSpec::Ref { image: 0, rva: 0 },
            &SigOptions::default(),
        );
        assert_eq!(report.unique_builds, 2);
        let cand = report.chosen.expect("a candidate");
        assert_eq!(cand.suffix, Suffix::Ptr);
        assert_eq!(cand.grade, Grade::A);
        assert_eq!(cand.per_version.len(), 2);
        assert!(
            cand.per_version.iter().all(
                |p| p.resolved_target_rva == Some(0) && p.target_kind == Some(TargetKind::Code)
            )
        );
    }

    #[test]
    fn e8_inside_an_immediate_is_not_a_branch_site() {
        // `mov rax, 0x0000_00FF_FFFF_E9E8`, whose immediate (E8 E9 FF FF FF ...) decodes as
        // `call rva 0` if scanned from the middle, but the E8 is not an instruction boundary, so
        // linear disassembly must never treat it as a call site.
        let mut data = vec![0x48, 0x89, 0xE5, 0xC3]; // func at rva 0
        data.resize(0x10, 0x90);
        data.extend_from_slice(&[0x48, 0xB8, 0xE8, 0xE9, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00]);
        data.resize(0x40, 0x90);
        let src = BufferSource::new(0x1000, data);
        // sanity: the embedded bytes really would decode as `call rva 0` mid-stream
        assert_eq!(
            decode_rel_target(&[0xE8, 0xE9, 0xFF, 0xFF, 0xFF], 0x1012),
            Some(0x1000)
        );
        let report = generate(
            &[img("a", &src, 0x1000, 0x40)],
            &TargetSpec::Ref { image: 0, rva: 0 },
            &SigOptions::default(),
        );
        let any_branch = report
            .chosen
            .iter()
            .chain(report.alternates.iter())
            .chain(report.rejected.iter())
            .any(|c| c.suffix != Suffix::None);
        assert!(
            !any_branch,
            "a mid-instruction E8 must not be accepted as a branch site"
        );
        assert_eq!(
            report.chosen.expect("direct candidate").suffix,
            Suffix::None
        );
    }

    #[test]
    fn call_anchor_across_two_nonduplicate_builds() {
        // identical call + callee, but a differing `mov eax, imm` makes the two builds non-duplicate.
        let make = |imm: u32| {
            let mut d = vec![0x48, 0x89, 0xE5, 0xC3];
            d.resize(0x10, 0x90);
            d.push(0xB8);
            d.extend_from_slice(&imm.to_le_bytes());
            d.resize(0x20, 0x90);
            d.extend_from_slice(&[0xE8, 0xDB, 0xFF, 0xFF, 0xFF]); // call rva 0
            d.extend_from_slice(&[0x0F, 0xB6, 0xC0, 0x33, 0xC9]);
            d.resize(0x40, 0x90);
            d
        };
        let a = BufferSource::new(0x1000, make(0x1111_1111));
        let b = BufferSource::new(0x1000, make(0x2222_2222));
        let report = generate(
            &[img("a", &a, 0x1000, 0x40), img("b", &b, 0x1000, 0x40)],
            &TargetSpec::Ref { image: 0, rva: 0 },
            &SigOptions::default(),
        );
        assert_eq!(report.unique_builds, 2);
        let cand = report.chosen.expect("a candidate");
        assert_eq!(cand.suffix, Suffix::Call);
        assert_eq!(cand.grade, Grade::A);
        assert_eq!(cand.per_version.len(), 2);
        assert!(
            cand.per_version
                .iter()
                .all(|p| p.resolved_target_rva == Some(0))
        );
    }

    #[test]
    fn deterministic_when_direct_and_call_both_pass() {
        let mut data = vec![0x48, 0x89, 0xE5, 0xC3];
        data.resize(0x20, 0x90);
        data.extend_from_slice(&[0xE8, 0xDB, 0xFF, 0xFF, 0xFF]);
        data.extend_from_slice(&[0x0F, 0xB6, 0xC0, 0x33, 0xC9]);
        data.resize(0x40, 0x90);
        let src = BufferSource::new(0x1000, data);
        let run = || {
            let r = generate(
                &[img("a", &src, 0x1000, 0x40)],
                &TargetSpec::Ref { image: 0, rva: 0 },
                &SigOptions::default(),
            );
            (r.chosen.unwrap().aob, r.alternates.len())
        };
        let first = run();
        assert_eq!(first, run());
        assert!(
            first.1 >= 1,
            "the direct candidate should remain as an alternate"
        );
    }

    #[test]
    fn invalid_aob_is_reported_not_silently_dropped() {
        let a = BufferSource::new(0x1000, blob(0x10, 0xAA));
        let report = generate(
            &[img("a", &a, 0x1000, 49)],
            &TargetSpec::Aob("48 ZZ C3".to_string()),
            &SigOptions::default(),
        );
        assert!(report.chosen.is_none());
        assert!(
            report
                .diagnostics
                .iter()
                .any(|d| matches!(d, Diag::InvalidAob { .. }))
        );
    }

    // An x86 image (0x400 bytes) modelling a recompile: the target function is placed at `entry`,
    // reached by a `call` from a per-build offset, surrounded by per-build filler. The two builds use
    // DIFFERENT instruction encodings of the SAME mnemonic stream (`recompiled` picks the alternate
    // encoding of mov/add/xor reg,reg), exactly as a recompiler does, so the opcode bytes differ and no
    // byte AOB (direct, branch, or pointer) can stay fixed across both, while the mnemonic-level
    // identity is preserved. With no string to anchor on either, this forces the fingerprint fallback.
    fn fp_image(entry: usize, seed: u8, call_from: usize, recompiled: bool) -> Vec<u8> {
        // Distinct filler per build so direct/branch/ptr byte windows cannot reconcile across builds.
        let mut mem: Vec<u8> = (0..0x400u32).map(|i| (i as u8) ^ seed).collect();
        // A frame prologue appearing in the filler by accident would add a competing candidate; scrub
        // any 55 8B EC / 55 89 E5 the xor pattern happens to produce.
        for i in 0..mem.len().saturating_sub(2) {
            let w = &mem[i..i + 3];
            if w[0] == 0x55 && ((w[1] == 0x8B && w[2] == 0xEC) || (w[1] == 0x89 && w[2] == 0xE5)) {
                mem[i] = 0x90;
            }
        }
        // call rel32 -> entry, so the entry is an enumerated candidate.
        mem[call_from] = 0xE8;
        let rel = entry as i32 - (call_from as i32 + 5);
        mem[call_from + 1..call_from + 5].copy_from_slice(&rel.to_le_bytes());
        // push ebp ; mov ebp,esp ; mov eax,imm32 ; add eax,ecx ; xor edx,edx ; imul eax,ebx
        //          ; pop ebp ; ret  -- build B uses the alternate encoding of the reg,reg ops.
        let (mov_ee, add, xor): ([u8; 2], [u8; 2], [u8; 2]) = if recompiled {
            ([0x89, 0xE5], [0x03, 0xC1], [0x33, 0xD2]) // mov/add/xor, alternate encodings
        } else {
            ([0x8B, 0xEC], [0x01, 0xC8], [0x31, 0xD2])
        };
        let body = &mut mem[entry..];
        body[0] = 0x55; // push ebp
        body[1..3].copy_from_slice(&mov_ee); // mov ebp, esp
        body[3] = 0xB8; // mov eax, imm32 -- a genuine magic constant the recompile preserves
        body[4..8].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        body[8..10].copy_from_slice(&add); // add eax, ecx
        body[10..12].copy_from_slice(&xor); // xor edx, edx
        body[12..15].copy_from_slice(&[0x0F, 0xAF, 0xC3]); // imul eax, ebx
        body[15] = 0x5D; // pop ebp
        body[16] = 0xC3; // ret
        mem
    }

    fn fp_input<'a>(label: &str, src: &'a BufferSource, hash: u64) -> ImageInput<'a> {
        ImageInput {
            label: label.to_string(),
            source: src,
            base: 0x1000,
            size: 0x400,
            code_regions: vec![Region {
                base: 0x1000,
                size: 0x400,
            }],
            regions: vec![Region {
                base: 0x1000,
                size: 0x400,
            }],
            import: None,
            arch: Arch::X86,
            code_hash: hash,
            packed: false,
            pack_reasons: Vec::new(),
            reloc: None,
        }
    }

    #[test]
    fn fingerprint_relocates_a_recompiled_function_when_bytes_and_strings_fail() {
        // Two builds of the same function differing only in operand bytes (a different immediate, here
        // also a different opcode tail so the byte AOB genuinely cannot be hardened), with no string to
        // anchor on. The byte and string paths must fail and the fingerprint fallback must relocate the
        // function in both builds and emit a candidate.
        let a = BufferSource::new(0x1000, fp_image(0x40, 0x11, 0x10, false));
        let b = BufferSource::new(0x1000, fp_image(0x120, 0x22, 0x90, true));
        let images = [fp_input("a", &a, 1), fp_input("b", &b, 2)];
        // This synthetic carries a rare constant, so the end-to-end ensemble relocates it via the more
        // precise constant anchor; assert that holds, then exercise the fingerprint path (this test's
        // subject) by calling it directly, since the ensemble would otherwise hide it behind the constant.
        assert!(
            generate(
                &images,
                &TargetSpec::Ref {
                    image: 0,
                    rva: 0x40
                },
                &SigOptions::default(),
            )
            .chosen
            .is_some(),
            "the ensemble must relocate the recompiled function"
        );
        let cand = fingerprint_relocate(&images, &[0usize, 1], 0, 0x40, &SigOptions::default())
            .expect("the fingerprint anchor relocates the recompiled function");
        assert!(
            cand.aob.starts_with("@fingerprint="),
            "expected a fingerprint anchor, got {}",
            cand.aob
        );
        assert_eq!(cand.per_version.len(), 2);
        // Each build relocates into its own copy of the function (the recompile moved it). A
        // sliding-window relocation lands on the best-scoring boundary, which may be an instruction or
        // two inside the entry, so assert membership in the function extent rather than the exact byte.
        let in_fn_a =
            (0x40..0x40 + 17).contains(&(cand.per_version[0].match_rva.unwrap() as usize));
        let in_fn_b =
            (0x120..0x120 + 17).contains(&(cand.per_version[1].match_rva.unwrap() as usize));
        assert!(
            in_fn_a && in_fn_b,
            "both builds should relocate into the function body, got {:?} and {:?}",
            cand.per_version[0].match_rva,
            cand.per_version[1].match_rva
        );
        // The second build carries the cross-build similarity to the reference.
        assert!(
            cand.per_version[1]
                .fingerprint_similarity
                .is_some_and(|s| s >= FP_MIN_MUTUAL),
            "cross-build similarity should be high, got {:?}",
            cand.per_version[1].fingerprint_similarity
        );
        // Semantic-only: never better than B, and clearly weaker than a byte/string anchor.
        assert!(
            cand.grade.rank() >= Grade::B.rank(),
            "a fingerprint-only relocation must not grade A, got {:?}",
            cand.grade
        );
        assert!(cand.reasons.iter().any(|r| r.contains("fingerprint")));
    }

    // An x86 image whose only function (entry 0x120, reached by a call) is unrelated to the reference:
    // a different mnemonic stream and a different magic constant, so nothing in it should fingerprint
    // as the reference function.
    fn fp_unrelated_image(seed: u8) -> Vec<u8> {
        let mut mem: Vec<u8> = (0..0x400u32).map(|i| (i as u8) ^ seed).collect();
        for i in 0..mem.len().saturating_sub(2) {
            let w = &mem[i..i + 3];
            if w[0] == 0x55 && ((w[1] == 0x8B && w[2] == 0xEC) || (w[1] == 0x89 && w[2] == 0xE5)) {
                mem[i] = 0x90;
            }
        }
        mem[0x90] = 0xE8;
        let rel = 0x120i32 - (0x90 + 5);
        mem[0x91..0x95].copy_from_slice(&rel.to_le_bytes());
        // push ebp ; mov ebp,esp ; cmp eax, imm32 ; jne $+2 ; inc ecx ; not edx ; leave ; ret
        let body = &mut mem[0x120..];
        body[0..3].copy_from_slice(&[0x55, 0x8B, 0xEC]);
        body[3] = 0x3D; // cmp eax, imm32
        body[4..8].copy_from_slice(&0x0BAD_F00Du32.to_le_bytes()); // a different magic constant
        body[8..10].copy_from_slice(&[0x75, 0x00]); // jne $+2
        body[10] = 0x41; // inc ecx
        body[11..13].copy_from_slice(&[0xF7, 0xD2]); // not edx
        body[13] = 0xC9; // leave
        body[14] = 0xC3; // ret
        mem
    }

    #[test]
    fn fingerprint_relocate_declines_when_the_function_is_absent_in_a_build() {
        // The reference function exists in build A but build B holds only an unrelated function (a
        // different mnemonic stream and a different magic constant). No confident, consistent
        // relocation exists, so the fallback must decline rather than emit a wrong RVA, and generation
        // reports no signature.
        let a = BufferSource::new(0x1000, fp_image(0x40, 0x11, 0x10, false));
        let b = BufferSource::new(0x1000, fp_unrelated_image(0x22));
        let report = generate(
            &[fp_input("a", &a, 1), fp_input("b", &b, 2)],
            &TargetSpec::Ref {
                image: 0,
                rva: 0x40,
            },
            &SigOptions::default(),
        );
        assert!(
            report.chosen.is_none(),
            "an inconsistent relocation must not be emitted, got {:?}",
            report.chosen.map(|c| c.aob)
        );
    }

    #[test]
    fn fingerprint_relocate_declines_for_a_too_thin_function() {
        // A 1-instruction function (just `ret`) carries no distinguishing shape, so the fallback must
        // refuse to fingerprint it rather than relocate on a single mnemonic that matches everywhere.
        let mut bytes_a = vec![0u8; 0x80];
        bytes_a[0x10] = 0xE8;
        let rel = 0x40i32 - (0x10 + 5);
        bytes_a[0x11..0x15].copy_from_slice(&rel.to_le_bytes());
        bytes_a[0x40] = 0xC3; // ret
        let mut bytes_b = bytes_a.clone();
        bytes_b[0x20] = 0x90;
        let a = BufferSource::new(0x1000, bytes_a);
        let b = BufferSource::new(0x1000, bytes_b);
        let ia = fp_input("a", &a, 1);
        let ib = fp_input("b", &b, 2);
        assert!(
            fingerprint_relocate(&[ia, ib], &[0, 1], 0, 0x40, &SigOptions::default()).is_none(),
            "a 1-instruction function is too thin to relocate by fingerprint"
        );
    }

    #[test]
    fn best_fingerprint_match_is_x86_only() {
        // The candidate enumeration relies on x86 prologue/call shape; on x64 it must report nothing
        // rather than scan with the wrong assumptions.
        let src = BufferSource::new(0x1000, blob(0x10, 0xAA));
        let mut x64 = img("x", &src, 0x1000, 49);
        x64.arch = Arch::X64;
        let reference = fn_identity(&x64, 0);
        assert!(best_fingerprint_match(&x64, &reference).is_none());
    }

    #[test]
    fn fingerprint_relocate_is_not_tried_when_a_byte_signature_succeeds() {
        // When the byte path already produces a candidate, the fingerprint fallback must not run: the
        // chosen signature is a real AOB, not an @fingerprint anchor.
        let a = BufferSource::new(0x1000, blob(0x10, 0xAA));
        let b = BufferSource::new(0x1000, blob(0x999, 0xBB));
        let report = generate(
            &[img("a", &a, 0x1000, 49), img("b", &b, 0x1000, 49)],
            &TargetSpec::Ref { image: 0, rva: 0 },
            &SigOptions::default(),
        );
        let cand = report.chosen.expect("a byte candidate");
        assert!(!cand.aob.starts_with("@fingerprint="));
    }
}
