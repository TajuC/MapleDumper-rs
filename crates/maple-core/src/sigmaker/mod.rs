use crate::fileimage::{RelocKind, RelocLookup};
use crate::memory::MemorySource;
use crate::pattern::{Arch, Signature, try_signature_from_aob};
use crate::resolver::decode_rel_target;
use crate::scanner::{CompiledPattern, find_all};
use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, OpKind, Register};

mod scoring;
mod types;
pub use scoring::{NegativeEvidence, apply_negative_corpus};
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

struct CodeCache {
    image_base: usize,
    regions: Vec<(usize, Vec<u8>)>,
}

impl CodeCache {
    fn build(img: &ImageInput) -> Self {
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

    fn locate(&self, pat: &CompiledPattern) -> (usize, Option<u64>) {
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

/// Scan a corpus of unrelated modules for `aob` and report any that contain it. Generation only
/// proves a signature is unique among the supplied builds, so a short or low-entropy pattern can
/// still collide inside some other module; a hit here means the signature is not specific enough to
/// trust as an identity. Returns one entry per negative image that matched, with the match count.
#[must_use]
pub fn negative_corpus_hits(aob: &str, negatives: &[ImageInput]) -> Vec<NegativeHit> {
    let Some(pat) = crate::pattern::try_signature_from_aob(aob)
        .ok()
        .and_then(|sig| CompiledPattern::new(&sig))
    else {
        return Vec::new();
    };
    negatives
        .iter()
        .filter_map(|img| {
            let (count, _) = CodeCache::build(img).locate(&pat);
            (count > 0).then_some(NegativeHit {
                label: img.label.clone(),
                count,
            })
        })
        .collect()
}

/// Leave-one-out validation: for each build, regenerate the signature from the others and check it
/// still uniquely matches the held-out build. Generation only proves a signature fits the builds it
/// was trained on; a signature that fits those but fails a build it never saw is overfit to the
/// corpus. Needs at least three builds (two to train on, one to hold out) and returns one result per
/// eligible held-out build. A reference build that defines the target cannot itself be held out.
#[must_use]
pub fn holdout_validate(
    images: &[ImageInput],
    spec: &TargetSpec,
    opts: &SigOptions,
) -> Vec<HoldoutResult> {
    if images.len() < 3 {
        return Vec::new();
    }
    let mut out = Vec::new();
    for i in 0..images.len() {
        let adjusted = match spec {
            TargetSpec::Aob(s) => TargetSpec::Aob(s.clone()),
            TargetSpec::Ref { image, rva } => {
                if i == *image {
                    continue; // the reference defines the target, so it cannot be held out
                }
                let image = if i < *image { image - 1 } else { *image };
                TargetSpec::Ref { image, rva: *rva }
            }
        };
        let train: Vec<ImageInput> = images
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, img)| img.clone())
            .collect();
        let report = generate(&train, &adjusted, opts);
        let matched = report.chosen.as_ref().is_some_and(|c| {
            crate::pattern::try_signature_from_aob(&c.aob)
                .ok()
                .and_then(|sig| CompiledPattern::new(&sig))
                .is_some_and(|pat| CodeCache::build(&images[i]).locate(&pat).0 == 1)
        });
        out.push(HoldoutResult {
            held_out: images[i].label.clone(),
            generated: report.chosen.is_some(),
            matched_holdout: matched,
        });
    }
    out
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

mod identity;
pub use identity::*;

fn string_anchor_candidate(
    images: &[ImageInput],
    required: &[usize],
    ref_idx: usize,
    ref_rva: u64,
) -> Option<SigCandidate> {
    let entry = identity::enclosing_function(&images[ref_idx], ref_rva as usize);
    let anchor = make_string_anchor(&images[ref_idx], entry)?;
    // Validate: the string must exist and resolve to exactly one enclosing function in every required
    // build (resolve_string_anchor returns None otherwise), and we capture each resolved function's
    // identity so cross-build consistency becomes evidence, not an assumption.
    let mut per_version = Vec::with_capacity(required.len());
    let mut idents: Vec<FnIdentity> = Vec::new();
    for &idx in required {
        let resolved = resolve_string_anchor(&images[idx], &anchor)? as u64;
        idents.push(fn_identity(&images[idx], resolved as usize));
        per_version.push(PerVersion {
            label: images[idx].label.clone(),
            match_rva: Some(resolved),
            resolved_target_rva: Some(resolved),
            target_kind: Some(TargetKind::Code),
            fingerprint_similarity: None,
        });
    }
    for k in 1..idents.len() {
        per_version[k].fingerprint_similarity = Some(idents[0].similarity(&idents[k]));
    }

    let aob = match &anchor.also {
        Some(also) => format!("@string={} @also={also}", anchor.text),
        None => format!("@string={}", anchor.text),
    };
    // Score from string-anchor evidence, not from the string's bytes as code-byte entropy: presence
    // and unique resolution in every build, how specifically the string pins the function, cross-build
    // callee similarity, and a reference xref count. The string text is never fed in as fixed code
    // bytes, so its characters cannot be mistaken for opcode entropy or fixed-byte density.
    let ref_entry = resolve_string_anchor(&images[ref_idx], &anchor).unwrap_or(entry);
    let ev = scoring::StringEvidence {
        builds: required.len(),
        text_len: anchor.text.chars().count(),
        paired: anchor.also.is_some(),
        xrefs: identity::xref_count(&images[ref_idx], ref_entry),
        callee_similarity: scoring::callee_similarity(&idents),
        ref_ident: idents.first().cloned(),
    };
    let (scores, mut reasons) = scoring::score_string_anchor(&ev);
    let mut grade = scoring::grade_from(scores.final_score, false, false);
    // A string anchor only earns A when it is validated across more than one build; a single build
    // gives no cross-version evidence, so cap it at B and say so.
    if required.len() < 2 && grade == Grade::A {
        grade = Grade::B;
        reasons.push("string anchor validated against only one build; capped below A".to_string());
    }
    Some(SigCandidate {
        aob,
        suffix: Suffix::None,
        grade,
        score: scores.final_score,
        bytes_len: anchor.text.len(),
        fixed: anchor.text.len(),
        wildcards: 0,
        fixed_ratio: 1.0,
        reloc_safe: true,
        scores,
        reasons,
        per_version,
        diags: Vec::new(),
    })
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
        scores,
        reasons,
        per_version,
        diags,
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
    if pool.is_empty()
        && let Some(anchor_cand) = string_anchor_candidate(images, &required, ref_idx, ref_rva)
    {
        pool.push(anchor_cand);
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
    let alternates = pool;
    if chosen.is_none() {
        for &(idx, rva) in &aob_found {
            diagnostics.push(Diag::FoundInBuild {
                label: images[idx].label.clone(),
                rva,
            });
        }
        diagnostics.push(Diag::NotUnique);
    }

    SigReport {
        arch,
        inputs,
        unique_builds,
        duplicate_groups: dup_groups,
        chosen,
        alternates,
        rejected,
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
mod tests {
    use super::*;
    use crate::memory::{BufferSource, Region};

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
        let cand = string_anchor_candidate(&[img], &[0], 0, 0x100).expect("a string anchor");
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
        let cand =
            string_anchor_candidate(&[string_img(&a, 1), string_img(&b, 2)], &[0, 1], 0, 0x100)
                .expect("a string anchor");
        assert_eq!(cand.grade, Grade::A);
        assert_eq!(cand.per_version.len(), 2);
        assert_eq!(cand.per_version[1].fingerprint_similarity, Some(1.0));
        assert!(cand.scores.cross_build >= 95);
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
}
