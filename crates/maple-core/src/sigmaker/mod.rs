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

mod aob;
mod bytepath;
mod callers;
mod chain;
mod constants;
mod encoding;
mod ensemble;
mod graph;
mod identity;
mod imports;
mod inspect;
mod model;
mod relocate;
mod strands;
mod validate;
mod vtable;
use aob::collapse_aob_ranges;
pub use inspect::{DisasmLine, FunctionInsight, VtableInsight, inspect_function};
// The byte-path minting and AOB machinery; imported back so the relocation anchors, identity, and the test
// harnesses reach `single_build_aob`/`mem_target` through `use super::*` (as when these lived here), and the
// generator calls the site builders directly.
use bytepath::{branch_sites, candidate_at, mem_target, ptr_sites, single_build_aob};
use chain::relocate_path;
use ensemble::{anchor_landing, ensemble_decide};
pub use identity::*;
use relocate::{
    caller_relocate, constant_relocate, encoding_relocate, fingerprint_relocate, graph_relocate,
    import_relocate, relocation_shortlists, strand_relocate, string_anchor_candidate,
    vtable_relocate,
};
// The relocation anchors' tuned constants live in `relocate` now; the corpus harnesses assert against
// them, so re-export everything there for the test modules (test-only, so nothing is dead in the library).
#[cfg(test)]
use relocate::*;
pub use validate::{holdout_validate, negative_corpus_hits};

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
    Strand,
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
            AnchorKind::Strand => "strand",
        }
    }
}

/// The data-flow strand channel (Phase 8) is opt-in: it adds no coverage the cheaper channels do not already
/// carry within a lineage and declines across the v95 break, so it stays out of the default decision path and
/// joins the ensemble only when `MAPLE_STRAND_CHANNEL` is set to `1`, `on`, or `true`. Keeping it behind a
/// flag preserves the byte-stable golden snapshot and the measured false-positive floor on the default path.
fn strand_channel_enabled() -> bool {
    std::env::var_os("MAPLE_STRAND_CHANNEL").is_some_and(|v| {
        let v = v.to_string_lossy();
        v == "1" || v.eq_ignore_ascii_case("on") || v.eq_ignore_ascii_case("true")
    })
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
    let mut anchors: Vec<(AnchorKind, AnchorFn)> = vec![
        (AnchorKind::String, string_anchor_candidate),
        (AnchorKind::Import, import_relocate),
        (AnchorKind::Constant, constant_relocate),
        (AnchorKind::Caller, caller_relocate),
        (AnchorKind::Graph, graph_relocate),
        (AnchorKind::Vtable, vtable_relocate),
        (AnchorKind::Encoding, encoding_relocate),
        (AnchorKind::Fingerprint, fingerprint_relocate),
    ];
    // The strand channel is fuzziest (content-free, semantic), so it joins last where a tie breaks away from
    // it, and only when explicitly opted in.
    if strand_channel_enabled() {
        anchors.push((AnchorKind::Strand, strand_relocate));
    }
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
