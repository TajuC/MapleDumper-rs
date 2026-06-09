//! The cross-version relocation anchors: each tries to relocate a target function across builds by a
//! different recompile-stable handle (referenced string, import set, rare constant, call-graph position,
//! vtable structure, encoding/mnemonic fingerprint), capped below the byte path since none proves the
//! target by its own bytes. Extracted from the generation core to keep mod.rs a thin orchestrator (Phase
//! 9); each anchor reads its helpers from the parent module via `use super::*`.

use super::*;

pub(super) fn string_anchor_candidate(
    images: &[ImageInput],
    required: &[usize],
    ref_idx: usize,
    ref_rva: u64,
    opts: &SigOptions,
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
            // The string survives recompiles that move the bytes, so each build needs its own AOB,
            // minted at the function the string resolves to there.
            aob: single_build_aob(&images[idx], resolved as usize, opts),
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
    // #13: a single string across a major recompile may have migrated to a different function. When the
    // worst build's landing is structurally far from the reference and no second string corroborates
    // it, report a candidate (cap below the confident A/B bands), never a confirmed relocation.
    if !string_relocation_confirmed(ev.paired, ev.callee_similarity) {
        let capped = grade.max_rank(Grade::C);
        if capped != grade {
            reasons.push(format!(
                "single-string relocation across a major recompile: the worst build's landing is only \
                 {:.0}% structurally similar to the reference and no second signal corroborates it, so \
                 it is a candidate, not a confirmed relocation",
                ev.callee_similarity.unwrap_or(0.0) * 100.0
            ));
            grade = capped;
        }
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
        gated: false,
        packed: false,
        scores,
        reasons,
        per_version,
        diags: Vec::new(),
        relocation: None,
    })
}

// A function relocated by its import set could in principle resolve to a different function across
// builds; require the resolved functions to look alike (minimum cross-build mnemonic similarity) so a
// coincidental import-set collision is rejected rather than shipped.
pub(super) const IMPORT_MIN_CONSISTENCY: f64 = 0.50;

/// Cross-version relocation by the distinctive SET of imported APIs a function calls. Imported names
/// are recompile-stable, so a function calling, say, the twelve `ws2_32` socket APIs is identifiable
/// in any build even after its bytes are rewritten; the same function in a recompiled build is then
/// handed back with a freshly minted per-build AOB. Emits only when the import set pins exactly one
/// function in every required build (an ambiguous or absent set declines) and the relocated functions
/// agree across builds. x86 / PE32 only. See [`imports`].
pub(super) fn import_relocate(
    images: &[ImageInput],
    required: &[usize],
    ref_idx: usize,
    ref_rva: u64,
    opts: &SigOptions,
) -> Option<SigCandidate> {
    if !matches!(images[ref_idx].arch, Arch::X86) {
        return None;
    }
    let entry = identity::enclosing_function(&images[ref_idx], ref_rva as usize);
    let anchor = imports::make_import_anchor(&images[ref_idx], entry)?;
    let src_ident = fn_identity(&images[ref_idx], entry);
    // Reach builds over the maximum-confidence chain (#14), so an import set that drifted past direct
    // ref->target resolution is still bridged through an intermediate build. Each hop is validated
    // against the IMMUTABLE source identity, so the chain cannot drift onto a neighbouring function, and
    // coverage is partial by design: report every build a confident path reaches.
    let located = relocate_path(
        images,
        required,
        ref_idx,
        entry,
        imports::make_import_anchor,
        |img, a| {
            let rva = imports::resolve_import_anchor(img, a)?;
            let sim = fn_identity(img, rva).similarity(&src_ident);
            (sim >= IMPORT_MIN_CONSISTENCY).then_some((rva as u64, sim))
        },
    );

    let mut per_version = Vec::with_capacity(required.len());
    let mut idents: Vec<Option<FnIdentity>> = Vec::with_capacity(required.len());
    let mut diags: Vec<Diag> = Vec::new();
    let mut min_conf = 1.0f64;
    let mut reached = 0usize;
    for &idx in required {
        match located[idx] {
            Some((rva, conf)) => {
                reached += 1;
                if idx != ref_idx {
                    min_conf = min_conf.min(conf);
                }
                idents.push(Some(fn_identity(&images[idx], rva as usize)));
                per_version.push(PerVersion {
                    label: images[idx].label.clone(),
                    match_rva: Some(rva),
                    resolved_target_rva: Some(rva),
                    target_kind: Some(TargetKind::Code),
                    fingerprint_similarity: None,
                    aob: single_build_aob(&images[idx], rva as usize, opts),
                });
            }
            None => {
                diags.push(Diag::MissingInImage {
                    label: images[idx].label.clone(),
                });
                idents.push(None);
                per_version.push(PerVersion {
                    label: images[idx].label.clone(),
                    match_rva: None,
                    resolved_target_rva: None,
                    target_kind: None,
                    fingerprint_similarity: None,
                    aob: None,
                });
            }
        }
    }
    // The reference plus at least one other build are needed to claim a cross-version relocation.
    if reached < 2 {
        return None;
    }
    let ref_ident = required
        .iter()
        .position(|&i| i == ref_idx)
        .and_then(|p| idents[p].clone());
    for (pv, id) in per_version.iter_mut().zip(&idents) {
        if let (Some(id), Some(rid)) = (id, &ref_ident) {
            pv.fingerprint_similarity = Some(rid.similarity(id));
        }
    }
    // The same import set must resolve to the SAME function across the builds it reached, not merely to
    // some function in each: the conservative minimum cross-build similarity must clear the bar.
    let reached_idents: Vec<FnIdentity> = idents.iter().flatten().cloned().collect();
    let mutual = scoring::callee_similarity(&reached_idents).unwrap_or(1.0);
    if mutual < IMPORT_MIN_CONSISTENCY {
        return None;
    }

    let aob = format!("@imports={}", anchor.names.join(","));
    let ev = scoring::FingerprintEvidence {
        builds: reached,
        min_similarity: min_conf,
        mutual_similarity: mutual,
        ref_ident: ref_ident.clone(),
    };
    let (scores, mut reasons) = scoring::score_fingerprint(&ev);
    reasons.insert(
        0,
        format!(
            "relocated to {reached} of {} builds by a distinctive set of {} imported APIs",
            required.len(),
            anchor.names.len()
        ),
    );
    let grade = scoring::grade_from(scores.final_score, false, false).max_rank(Grade::B);
    Some(SigCandidate {
        aob,
        suffix: Suffix::None,
        grade,
        score: scores.final_score,
        bytes_len: 0,
        fixed: 0,
        wildcards: 0,
        fixed_ratio: 0.0,
        reloc_safe: true,
        gated: false,
        packed: false,
        scores,
        reasons,
        per_version,
        diags,
        relocation: None,
    })
}

// Vtable-relocation gates. The structural agreement of the whole table is strong evidence, so the
// agreement floor is high; the margin rejects two sibling classes that share enough base-class slots to
// tie (which must decline, not be guessed between).
pub(super) const VT_MIN_AGREEMENT: f64 = 0.72;
pub(super) const VT_MIN_MARGIN: f64 = 0.10;
// A relocated method whose identity drifted further than this from the reference is treated as a wrong
// landing (a coincidental table match), even though the table agreed. The floor is low on purpose: the
// whole point is to relocate methods whose own bytes churned, so only a gross mismatch is rejected.
pub(super) const VT_MIN_CONSISTENCY: f64 = 0.30;

/// Relocate a vtable method across builds via [`relocate_path`], gating each hop on per-slot agreement,
/// a uniqueness margin, and cross-build identity so a coincidental match cannot extend the chain.
/// x86 vtable methods only. Behaviour is identical to the earlier hand-rolled walk.
pub(super) fn vtable_relocate_path(
    images: &[ImageInput],
    required: &[usize],
    ref_idx: usize,
    ref_rva: u64,
) -> Vec<Option<(u64, f64)>> {
    let entry = identity::enclosing_function(&images[ref_idx], ref_rva as usize);
    let src_ident = fn_identity(&images[ref_idx], entry);
    relocate_path(
        images,
        required,
        ref_idx,
        entry,
        vtable::make_vtable_anchor,
        |img, anchor| {
            let (rva, agree, runner) = vtable::resolve_vtable_anchor(img, anchor)?;
            (agree >= VT_MIN_AGREEMENT
                && agree - runner >= VT_MIN_MARGIN
                && fn_identity(img, rva).similarity(&src_ident) >= VT_MIN_CONSISTENCY)
                .then_some((rva as u64, agree))
        },
    )
}

/// Cross-version relocation by C++ vtable structure, for a virtual method with no distinctive string or
/// import set of its own. The vtable the method is dispatched from is matched across builds under a
/// semi-global affine alignment of its per-slot fingerprints (so methods inserted or removed across
/// versions shift the match instead of breaking it), weighted toward the class-specific methods so a
/// sibling sharing only the inherited backbone cannot tie. The target slot is then read, any adjustor
/// thunk followed, and a fresh per-build AOB minted. Builds are reached over the maximum-confidence
/// chain through intermediate versions, and coverage is PARTIAL by design: the method is pinned in
/// every build a confident path reaches and reported unreached in the rest, instead of the whole
/// relocation failing because one late build diverged. Emits when the reference plus at least one other
/// build are pinned and the relocated methods agree. x86 / PE32 only. See [`vtable`].
pub(super) fn vtable_relocate(
    images: &[ImageInput],
    required: &[usize],
    ref_idx: usize,
    ref_rva: u64,
    opts: &SigOptions,
) -> Option<SigCandidate> {
    if !matches!(images[ref_idx].arch, Arch::X86) {
        return None;
    }
    let entry = identity::enclosing_function(&images[ref_idx], ref_rva as usize);
    let anchor = vtable::make_vtable_anchor(&images[ref_idx], entry)?;
    let located = vtable_relocate_path(images, required, ref_idx, ref_rva);

    let mut per_version = Vec::with_capacity(required.len());
    let mut idents: Vec<Option<FnIdentity>> = Vec::with_capacity(required.len());
    let mut diags: Vec<Diag> = Vec::new();
    let mut min_conf = 1.0f64;
    let mut reached = 0usize;
    for &idx in required {
        match located[idx] {
            Some((rva, conf)) => {
                reached += 1;
                if idx != ref_idx {
                    min_conf = min_conf.min(conf);
                }
                idents.push(Some(fn_identity(&images[idx], rva as usize)));
                per_version.push(PerVersion {
                    label: images[idx].label.clone(),
                    match_rva: Some(rva),
                    resolved_target_rva: Some(rva),
                    target_kind: Some(TargetKind::Code),
                    fingerprint_similarity: None,
                    aob: single_build_aob(&images[idx], rva as usize, opts),
                });
            }
            None => {
                diags.push(Diag::MissingInImage {
                    label: images[idx].label.clone(),
                });
                idents.push(None);
                per_version.push(PerVersion {
                    label: images[idx].label.clone(),
                    match_rva: None,
                    resolved_target_rva: None,
                    target_kind: None,
                    fingerprint_similarity: None,
                    aob: None,
                });
            }
        }
    }
    // The reference plus at least one other build are needed to claim a cross-version relocation.
    if reached < 2 {
        return None;
    }
    // Per-build similarity to the reference's own relocated identity, and the mutual-consistency gate
    // over the builds that were reached (a coincidental table collision on a different method is cut).
    let ref_ident = required
        .iter()
        .position(|&i| i == ref_idx)
        .and_then(|p| idents[p].clone());
    for (pv, id) in per_version.iter_mut().zip(&idents) {
        if let (Some(id), Some(rid)) = (id, &ref_ident) {
            pv.fingerprint_similarity = Some(rid.similarity(id));
        }
    }
    let reached_idents: Vec<FnIdentity> = idents.iter().flatten().cloned().collect();
    let mutual = scoring::callee_similarity(&reached_idents).unwrap_or(1.0);
    if mutual < VT_MIN_CONSISTENCY {
        return None;
    }

    // A compact, stable identity label (not a re-scannable byte pattern): slot count, target slot, and a
    // fold of the reference table's per-slot fingerprint.
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    for slot in &anchor.fingerprint {
        for &m in slot {
            h ^= u64::from(m);
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
    let aob = format!(
        "@vtable={}:{}:{:016X}",
        anchor.fingerprint.len(),
        anchor.slot,
        h
    );

    let ev = scoring::FingerprintEvidence {
        builds: reached,
        min_similarity: min_conf,
        mutual_similarity: mutual,
        ref_ident: ref_ident.clone(),
    };
    let (scores, mut reasons) = scoring::score_fingerprint(&ev);
    reasons.insert(
        0,
        format!(
            "relocated to {reached} of {} builds by matching its C++ vtable structure ({} slots), reading slot {}{}",
            required.len(),
            anchor.fingerprint.len(),
            anchor.slot,
            if anchor.via_thunk {
                " through an adjustor thunk"
            } else {
                ""
            }
        ),
    );
    if reached < required.len() {
        reasons.push(format!(
            "{} build(s) could not be reached by a confident chain and are left unpinned",
            required.len() - reached
        ));
    }
    // Structural match located in the other builds by table shape, backed by the reference build's
    // bytes but not by a re-scannable cross-build byte/string, so capped at B however high it scores.
    let grade = scoring::grade_from(scores.final_score, false, false).max_rank(Grade::B);
    Some(SigCandidate {
        aob,
        suffix: Suffix::None,
        grade,
        score: scores.final_score,
        bytes_len: 0,
        fixed: 0,
        wildcards: 0,
        fixed_ratio: 0.0,
        reloc_safe: true,
        gated: false,
        packed: false,
        scores,
        reasons,
        per_version,
        diags,
        relocation: None,
    })
}

/// Cross-version relocation by a string-anchored CALLER, for a function with no recompile-stable handle
/// of its own. A caller that references a build-stable string is located in each build, and the target
/// is re-found as the caller's callee whose identity matches the reference target's (matching by
/// identity, not by call index, survives the call being reordered). Coverage is partial: a build where
/// the caller resolves and the target is its distinctive callee is pinned, the rest reported unreached.
/// Emits when the reference plus one other build are pinned and the relocated functions agree. x86 only.
/// See [`callers`].
pub(super) fn caller_relocate(
    images: &[ImageInput],
    required: &[usize],
    ref_idx: usize,
    ref_rva: u64,
    opts: &SigOptions,
) -> Option<SigCandidate> {
    if !matches!(images[ref_idx].arch, Arch::X86) {
        return None;
    }
    let entry = identity::enclosing_function(&images[ref_idx], ref_rva as usize);
    let anchor = callers::make_caller_anchor(&images[ref_idx], entry)?;

    let mut per_version = Vec::with_capacity(required.len());
    let mut idents: Vec<Option<FnIdentity>> = Vec::with_capacity(required.len());
    let mut diags: Vec<Diag> = Vec::new();
    let mut reached = 0usize;
    for &idx in required {
        match callers::resolve_caller_anchor(&images[idx], &anchor) {
            Some(rva) => {
                reached += 1;
                idents.push(Some(fn_identity(&images[idx], rva)));
                per_version.push(PerVersion {
                    label: images[idx].label.clone(),
                    match_rva: Some(rva as u64),
                    resolved_target_rva: Some(rva as u64),
                    target_kind: Some(TargetKind::Code),
                    fingerprint_similarity: None,
                    aob: single_build_aob(&images[idx], rva, opts),
                });
            }
            None => {
                diags.push(Diag::MissingInImage {
                    label: images[idx].label.clone(),
                });
                idents.push(None);
                per_version.push(PerVersion {
                    label: images[idx].label.clone(),
                    match_rva: None,
                    resolved_target_rva: None,
                    target_kind: None,
                    fingerprint_similarity: None,
                    aob: None,
                });
            }
        }
    }
    if reached < 2 {
        return None;
    }
    let ref_ident = required
        .iter()
        .position(|&i| i == ref_idx)
        .and_then(|p| idents[p].clone());
    for (pv, id) in per_version.iter_mut().zip(&idents) {
        if let (Some(id), Some(rid)) = (id, &ref_ident) {
            pv.fingerprint_similarity = Some(rid.similarity(id));
        }
    }
    let reached_idents: Vec<FnIdentity> = idents.iter().flatten().cloned().collect();
    let mutual = scoring::callee_similarity(&reached_idents).unwrap_or(1.0);
    if mutual < VT_MIN_CONSISTENCY {
        return None;
    }

    let aob = format!("@caller={}", anchor.caller.text);
    let ev = scoring::FingerprintEvidence {
        builds: reached,
        min_similarity: mutual,
        mutual_similarity: mutual,
        ref_ident,
    };
    let (scores, mut reasons) = scoring::score_fingerprint(&ev);
    reasons.insert(
        0,
        format!(
            "relocated to {reached} of {} builds via a string-anchored caller ({:?}), matched as its distinctive callee",
            required.len(),
            anchor.caller.text
        ),
    );
    if reached < required.len() {
        reasons.push(format!(
            "{} build(s) could not be reached and are left unpinned",
            required.len() - reached
        ));
    }
    let grade = scoring::grade_from(scores.final_score, false, false).max_rank(Grade::B);
    Some(SigCandidate {
        aob,
        suffix: Suffix::None,
        grade,
        score: scores.final_score,
        bytes_len: 0,
        fixed: 0,
        wildcards: 0,
        fixed_ratio: 0.0,
        reloc_safe: true,
        gated: false,
        packed: false,
        scores,
        reasons,
        per_version,
        diags,
        relocation: None,
    })
}

// Graph-alignment bounds. The relocation is positional (it carries no content of the target itself), so
// it rests entirely on the consensus discipline inside `graph::align` (>= 2 independent matched neighbours
// agree, strict-unique maximum, mutual-best). These two bound the per-relocation seeding to the target's
// call-graph neighbourhood instead of the whole image: depth-2 reaches the neighbours' neighbours so the
// alignment has room to propagate, and the cap keeps a densely connected hub from blowing up the seed set.
pub(super) const GRAPH_DEPTH: usize = 2;
pub(super) const GRAPH_CAP: usize = 256;

/// Relocate a function across builds by its POSITION in the matched call graph (Phase 7), for a target no
/// content anchor pins, typically a method the v95 class refactor moved past the vtable matcher. The
/// target's call-graph neighbourhood is seeded with the 1:1 string anchors among it (made once in the
/// reference, re-resolved per build), then [`graph::align`] propagates the correspondence by neighbour
/// consensus. align commits the target only on >= 2 agreeing neighbours, a strict-unique maximum, and
/// mutual-best, so a positional match cannot be a coincidence; this driver adds no looser gate. Capped at
/// grade B: there is no byte or string proof of the target itself, only of its neighbours. x86 / PE32 only.
pub(super) fn graph_relocate(
    images: &[ImageInput],
    required: &[usize],
    ref_idx: usize,
    ref_rva: u64,
    opts: &SigOptions,
) -> Option<SigCandidate> {
    if !matches!(images[ref_idx].arch, Arch::X86) {
        return None;
    }
    let entry = identity::enclosing_function(&images[ref_idx], ref_rva as usize);
    let ref_model = model::AnalysisModel::build(&images[ref_idx]);
    let ref_graph = graph::CallGraph::build(&images[ref_idx], &ref_model);
    let candidates = ref_graph.neighbourhood(entry, GRAPH_DEPTH, GRAPH_CAP);
    // Make the seed anchors once in the reference; each build re-resolves them. Need at least two, since
    // a single neighbour cannot reach the consensus floor.
    let anchors = graph::anchor_candidates(&images[ref_idx], &candidates);
    if anchors.len() < 2 {
        return None;
    }

    let mut per_version = Vec::with_capacity(required.len());
    let mut idents: Vec<Option<FnIdentity>> = Vec::with_capacity(required.len());
    let mut diags: Vec<Diag> = Vec::new();
    let mut reached = 0usize;
    for &idx in required {
        let located = if idx == ref_idx {
            Some(entry)
        } else {
            let b_model = model::AnalysisModel::build(&images[idx]);
            let b_graph = graph::CallGraph::build(&images[idx], &b_model);
            let seeds = graph::resolve_seeds(&images[idx], &anchors);
            if seeds.len() < 2 {
                None
            } else {
                graph::align(&ref_graph, &b_graph, &seeds)
                    .get(&entry)
                    .copied()
            }
        };
        match located {
            Some(rva) => {
                reached += 1;
                idents.push(Some(fn_identity(&images[idx], rva)));
                per_version.push(PerVersion {
                    label: images[idx].label.clone(),
                    match_rva: Some(rva as u64),
                    resolved_target_rva: Some(rva as u64),
                    target_kind: Some(TargetKind::Code),
                    fingerprint_similarity: None,
                    aob: single_build_aob(&images[idx], rva, opts),
                });
            }
            None => {
                diags.push(Diag::MissingInImage {
                    label: images[idx].label.clone(),
                });
                idents.push(None);
                per_version.push(PerVersion {
                    label: images[idx].label.clone(),
                    match_rva: None,
                    resolved_target_rva: None,
                    target_kind: None,
                    fingerprint_similarity: None,
                    aob: None,
                });
            }
        }
    }
    // The reference plus at least one other build are needed to claim a cross-version relocation.
    if reached < 2 {
        return None;
    }
    let reached_ref = required
        .iter()
        .position(|&i| i == ref_idx)
        .and_then(|p| idents[p].clone());
    for (pv, id) in per_version.iter_mut().zip(&idents) {
        if let (Some(id), Some(rid)) = (id, &reached_ref) {
            pv.fingerprint_similarity = Some(rid.similarity(id));
        }
    }
    // Positional evidence: content-free, so the grade is held at B even though the consensus is strict.
    // Confidence rises with the share of builds a confident graph path reached; entropy is zero (no fixed
    // code bytes back the target itself).
    let cross_build = ((reached as f64 / required.len() as f64) * 100.0).round() as u32;
    let final_score = (55.0 + 0.25 * f64::from(cross_build)).round() as u32;
    let scores = SubScores {
        uniqueness: 60,
        stability: 80,
        entropy: 0,
        semantic: 55,
        resolver_confidence: 62,
        cross_build,
        final_score,
    };
    let reasons = vec![format!(
        "relocated to {reached} of {} build(s) by call-graph consensus: at least two independent \
         string-anchored neighbours agree on the landing and it is mutual-best, with no content anchor on \
         the target itself",
        required.len()
    )];
    let grade = scoring::grade_from(final_score, false, false).max_rank(Grade::B);
    Some(SigCandidate {
        aob: "@graph".to_string(),
        suffix: Suffix::None,
        grade,
        score: final_score,
        bytes_len: 0,
        fixed: 0,
        wildcards: 0,
        fixed_ratio: 0.0,
        reloc_safe: true,
        gated: false,
        packed: false,
        scores,
        reasons,
        per_version,
        diags,
        relocation: None,
    })
}

// Thresholds for the fingerprint-relocation fallback, tuned against the real GMS corpus (see the
// `--ignored` test `fingerprint_relocation_on_real_gms_v83_to_v84_is_measured_and_honest`). A
// distinctive function relocates near 1.0 with a clear margin; a structurally-thin or recompiled
// function ties across many windows, so the fallback must DECLINE rather than emit a guess. These
// gates encode that: a build must have a single best window comfortably above chance AND clearly ahead
// of its nearest rival, and every build's window must agree with the reference's.
pub(super) const FP_MIN_SIMILARITY: f64 = 0.82;
pub(super) const FP_MIN_MARGIN: f64 = 0.06;
pub(super) const FP_MIN_MUTUAL: f64 = 0.82;

/// Last-resort cross-version relocation by semantic fingerprint, for when the byte AOB matches too few
/// builds to harden and no string anchor isolates the function either. The reference function's
/// `FnIdentity` (mnemonic stream, CFG-lite shape, distinctive constants, referenced strings) is matched
/// against every instruction-boundary code window in each build (see [`best_fingerprint_match`]); a
/// build contributes only if its single best window clears [`FP_MIN_SIMILARITY`] and leads the
/// runner-up by [`FP_MIN_MARGIN`] (so an ambiguous tie is rejected, not guessed). The fallback then
/// requires every build's window to agree with the reference at no less than [`FP_MIN_MUTUAL`] before
/// emitting a candidate, so one build that relocated to a different function cannot slip through.
/// Returns `None` (declines) whenever the evidence is ambiguous or inconsistent. x86 only.
pub(super) fn fingerprint_relocate(
    images: &[ImageInput],
    required: &[usize],
    ref_idx: usize,
    ref_rva: u64,
    opts: &SigOptions,
) -> Option<SigCandidate> {
    if !matches!(images[ref_idx].arch, Arch::X86) {
        return None;
    }
    let ref_entry = identity::enclosing_function(&images[ref_idx], ref_rva as usize);
    let reference = fn_identity(&images[ref_idx], ref_entry);
    // Too thin to fingerprint at all: nothing to distinguish it from boilerplate, so do not even try.
    if reference.instr_count < 6 {
        return None;
    }

    let mut per_version = Vec::with_capacity(required.len());
    let mut idents: Vec<FnIdentity> = Vec::new();
    let mut min_sim = 1.0f64;
    for &idx in required {
        let img = &images[idx];
        let (rva, sim, runner_up, id) = best_fingerprint_match(img, &reference)?;
        // A build whose best match is weak or ambiguous (tied with the runner-up) is not a confident
        // relocation; decline the whole fallback rather than emit a guessed RVA for it.
        if sim < FP_MIN_SIMILARITY || sim - runner_up < FP_MIN_MARGIN {
            return None;
        }
        min_sim = min_sim.min(sim);
        idents.push(id);
        per_version.push(PerVersion {
            label: img.label.clone(),
            match_rva: Some(rva as u64),
            resolved_target_rva: Some(rva as u64),
            target_kind: Some(TargetKind::Code),
            fingerprint_similarity: None,
            aob: single_build_aob(img, rva, opts),
        });
    }
    // Mutual consistency: every build's chosen function must look like the reference's. The minimum
    // pairwise similarity (conservative) must clear the bar, so one diverging build sinks the result.
    let mutual = scoring::callee_similarity(&idents).unwrap_or(1.0);
    if mutual < FP_MIN_MUTUAL {
        return None;
    }
    for k in 1..idents.len() {
        per_version[k].fingerprint_similarity = Some(idents[0].similarity(&idents[k]));
    }

    let aob = format!("@fingerprint={}", reference.fingerprint());
    let ev = scoring::FingerprintEvidence {
        builds: required.len(),
        min_similarity: min_sim,
        mutual_similarity: mutual,
        ref_ident: idents.first().cloned(),
    };
    let (scores, reasons) = scoring::score_fingerprint(&ev);
    // A fingerprint relocation is semantic-only: no byte or string proof backs it, so it is capped
    // below the byte/string anchors (never better than B) however high the similarity runs.
    let grade = scoring::grade_from(scores.final_score, false, false).max_rank(Grade::B);
    Some(SigCandidate {
        aob,
        suffix: Suffix::None,
        grade,
        score: scores.final_score,
        bytes_len: 0,
        fixed: 0,
        wildcards: 0,
        fixed_ratio: 0.0,
        reloc_safe: true,
        gated: false,
        packed: false,
        scores,
        reasons,
        per_version,
        diags: Vec::new(),
        relocation: None,
    })
}

// Last-resort shortlist: how similar a window must be to make the list, and how many to list. The
// floor is deliberately loose (this only runs once every confident path has already declined), and the
// cap keeps the list short enough to disambiguate by hand.
pub(super) const SHORTLIST_FLOOR: f64 = 0.65;
pub(super) const SHORTLIST_K: usize = 10;

/// When no anchor pinned the function uniquely, build a per-build shortlist of the structural
/// near-duplicates it belongs to, each with a freshly minted AOB. This is the honest fallback for a
/// degenerate, anchor-less target: it cannot say which window is THE function, but it can hand back the
/// small family to disambiguate manually or at runtime, instead of returning nothing. x86 only; heavy
/// (a full instruction-boundary scan per build), so it runs only after every confident path declined.
pub(super) fn relocation_shortlists(
    images: &[ImageInput],
    required: &[usize],
    ref_idx: usize,
    ref_rva: u64,
    opts: &SigOptions,
) -> Vec<Shortlist> {
    if !matches!(images[ref_idx].arch, Arch::X86) {
        return Vec::new();
    }
    let ref_entry = identity::enclosing_function(&images[ref_idx], ref_rva as usize);
    let reference = fn_identity(&images[ref_idx], ref_entry);
    // Too thin to even shortlist: a handful of generic instructions would match half the image.
    if reference.instr_count < 6 {
        return Vec::new();
    }
    // Family members share a long template body, so the default window cannot tell them apart; allow a
    // longer signature here so the minted AOB can reach the divergent tail that disambiguates each one.
    let aob_opts = SigOptions {
        max_len: opts.max_len.max(256),
        min_fixed: opts.min_fixed,
        min_fixed_ratio: opts.min_fixed_ratio,
    };
    let mut out = Vec::new();
    for &idx in required {
        if idx == ref_idx {
            continue; // the reference build already has the function at the known site
        }
        let top =
            identity::fingerprint_topk(&images[idx], &reference, SHORTLIST_K, SHORTLIST_FLOOR);
        if top.is_empty() {
            continue;
        }
        let entries = top
            .into_iter()
            .map(|(rva, similarity)| ShortlistEntry {
                rva: rva as u64,
                similarity,
                aob: single_build_aob(&images[idx], rva, &aob_opts),
            })
            .collect();
        out.push(Shortlist {
            label: images[idx].label.clone(),
            entries,
        });
    }
    out
}

// Thresholds for the encoding-fingerprint relocation. The signal is a near-exact encoding match (it
// keeps registers and operand sizes and masks only the relocatable values), so the bar is high: the
// best window must clear ENC_MIN_SIMILARITY, be the SOLE window at the top score (no tie), and lead
// the runner-up by ENC_MIN_MARGIN, with every build's relocated window mutually consistent. A true
// recompile shifts register allocation, the leading-signature prefilter then matches nothing, and the
// fallback declines rather than guess.
pub(super) const ENC_MIN_SIMILARITY: f64 = 0.95;
pub(super) const ENC_MIN_MARGIN: f64 = 0.02;
pub(super) const ENC_MIN_MUTUAL: f64 = 0.92;
// Below this many decoded encoding tokens the reference is too short to be a distinctive identity.
pub(super) const ENC_MIN_STREAM: usize = 10;

/// Cross-version relocation by *instruction-encoding* fingerprint, for a function whose mnemonic
/// stream ties across template-instanced siblings (so [`fingerprint_relocate`] declines) but whose
/// per-instance register and operand-size signature is unique. The reference window is taken at the
/// match site itself (not walked back to a prologue: the real target is a vtable-reached mid-function
/// site with no standard prologue), its encoding stream is matched against every build, and a
/// candidate is emitted only when each build has a single unambiguous high match and the relocated
/// windows agree across builds. Declines (returns `None`) on any ambiguity or on a true recompile.
/// x86 only. See [`encoding`] for why register + operand size, with values masked, is the right
/// granularity.
pub(super) fn encoding_relocate(
    images: &[ImageInput],
    required: &[usize],
    ref_idx: usize,
    ref_rva: u64,
    opts: &SigOptions,
) -> Option<SigCandidate> {
    // Arch-agnostic (#12): the encoding fingerprint decodes at the image's bitness and masks operand
    // values, and its similarity/uniqueness/mutual gates are arch-neutral, so it relocates x64 targets
    // as soon as a confident, unique match exists. This is the one anchor that crosses to x64 today; the
    // string/import/caller/vtable anchors are still x86-only (their addressing assumptions differ on
    // x64) and decline cleanly there.
    let reference = encoding::encoding_stream(&images[ref_idx], ref_rva as usize);
    if reference.len() < ENC_MIN_STREAM {
        return None;
    }

    let mut per_version = Vec::with_capacity(required.len());
    let mut streams: Vec<Vec<u64>> = Vec::new();
    let mut min_sim = 1.0f64;
    for &idx in required {
        let img = &images[idx];
        let (rva, sim, runner, ties) = encoding::best_encoding_match(img, &reference)?;
        // A weak, tied, or non-unique best is not a confident relocation: decline the whole fallback
        // rather than emit a guessed RVA for this build.
        if sim < ENC_MIN_SIMILARITY || ties != 1 || sim - runner < ENC_MIN_MARGIN {
            return None;
        }
        min_sim = min_sim.min(sim);
        streams.push(encoding::encoding_stream(img, rva));
        per_version.push(PerVersion {
            label: img.label.clone(),
            match_rva: Some(rva as u64),
            resolved_target_rva: Some(rva as u64),
            target_kind: Some(TargetKind::Code),
            fingerprint_similarity: None,
            aob: single_build_aob(img, rva, opts),
        });
    }
    // Mutual consistency: every build's relocated window must look like the reference build's, so one
    // build that locked onto a different instance sinks the result. Conservative minimum, not average.
    let mutual = streams
        .iter()
        .skip(1)
        .map(|s| encoding::encoding_similarity(&streams[0], s))
        .fold(1.0f64, f64::min);
    if streams.len() >= 2 && mutual < ENC_MIN_MUTUAL {
        return None;
    }
    for k in 1..streams.len() {
        per_version[k].fingerprint_similarity =
            Some(encoding::encoding_similarity(&streams[0], &streams[k]));
    }

    // A compact, stable label for the encoding identity (not a re-scannable byte pattern, like
    // `@fingerprint=`): the token count and a fold of the reference encoding stream.
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    for &t in &reference {
        h ^= t;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    let aob = format!("@encoding={}:{:016X}", reference.len(), h);

    let ev = scoring::FingerprintEvidence {
        builds: required.len(),
        min_similarity: min_sim,
        mutual_similarity: if streams.len() >= 2 { mutual } else { min_sim },
        ref_ident: Some(fn_identity(&images[ref_idx], ref_rva as usize)),
    };
    let (scores, mut reasons) = scoring::score_fingerprint(&ev);
    reasons.insert(
        0,
        "relocated across builds by instruction-encoding fingerprint (registers and operand sizes, immediate/displacement values masked)".to_string(),
    );
    // Encoding-only match: backed by the reference build's bytes but located in the others by shape,
    // so capped below the byte/string anchors at B however high the similarity runs.
    let grade = scoring::grade_from(scores.final_score, false, false).max_rank(Grade::B);
    Some(SigCandidate {
        aob,
        suffix: Suffix::None,
        grade,
        score: scores.final_score,
        bytes_len: 0,
        fixed: 0,
        wildcards: 0,
        fixed_ratio: 0.0,
        reloc_safe: true,
        gated: false,
        packed: false,
        scores,
        reasons,
        per_version,
        diags: Vec::new(),
        relocation: None,
    })
}

// A constant-relocated landing whose identity drifted further than this from the reference is a
// coincidental collision (the same rare value reused by an unrelated function), not the same function;
// reject it. The floor is low because the whole point is to relocate functions whose bodies churned.
pub(super) const CONST_MIN_CONSISTENCY: f64 = 0.30;

/// Relocate the function at `ref_rva` by a rare immediate constant it uses (see [`constants`]): mint the
/// anchor from a value unique to the function in the reference build, then find the single function in each
/// other build that uses the same value. Declines on any ambiguity or when the resolved functions look
/// nothing alike (a coincidental constant collision). Backed by the reference build's bytes but located in
/// the others by a single value, so capped below the byte/string anchors at B.
pub(super) fn constant_relocate(
    images: &[ImageInput],
    required: &[usize],
    ref_idx: usize,
    ref_rva: u64,
    opts: &SigOptions,
) -> Option<SigCandidate> {
    let entry = identity::enclosing_function(&images[ref_idx], ref_rva as usize);
    let anchor = constants::make_constant_anchor(&images[ref_idx], entry)?;
    let mut per_version = Vec::with_capacity(required.len());
    let mut idents: Vec<FnIdentity> = Vec::new();
    for &idx in required {
        let img = &images[idx];
        let r = constants::resolve_constant_anchor(img, &anchor)?;
        let re = identity::enclosing_function(img, r);
        idents.push(fn_identity(img, re));
        per_version.push(PerVersion {
            label: img.label.clone(),
            match_rva: Some(re as u64),
            resolved_target_rva: Some(re as u64),
            target_kind: Some(TargetKind::Code),
            fingerprint_similarity: None,
            aob: single_build_aob(img, re, opts),
        });
    }
    let mut min_sim = 1.0f64;
    for k in 1..idents.len() {
        let sim = idents[0].similarity(&idents[k]);
        per_version[k].fingerprint_similarity = Some(sim);
        min_sim = min_sim.min(sim);
    }
    if idents.len() >= 2 && min_sim < CONST_MIN_CONSISTENCY {
        return None;
    }
    let ev = scoring::FingerprintEvidence {
        builds: required.len(),
        min_similarity: min_sim,
        mutual_similarity: min_sim,
        ref_ident: idents.first().cloned(),
    };
    let (scores, mut reasons) = scoring::score_fingerprint(&ev);
    reasons.insert(
        0,
        format!(
            "relocated across builds by a rare constant (0x{:X}) used by exactly one function per build",
            anchor.value
        ),
    );
    let grade = scoring::grade_from(scores.final_score, false, false).max_rank(Grade::B);
    Some(SigCandidate {
        aob: format!("@constant=0x{:X}", anchor.value),
        suffix: Suffix::None,
        grade,
        score: scores.final_score,
        bytes_len: 0,
        fixed: 0,
        wildcards: 0,
        fixed_ratio: 0.0,
        reloc_safe: true,
        gated: false,
        packed: false,
        scores,
        reasons,
        per_version,
        diags: Vec::new(),
        relocation: None,
    })
}
