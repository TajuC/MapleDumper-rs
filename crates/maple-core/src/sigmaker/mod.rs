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
mod tests;
