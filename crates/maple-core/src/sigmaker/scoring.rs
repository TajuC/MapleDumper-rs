//! Independent sub-scores for a signature candidate, and the grade derived from them.
//!
//! Each sub-score is computed from raw, measurable evidence (uniqueness in the corpus, recompile
//! stability, byte entropy, validated semantic content, resolver confidence, cross-build agreement),
//! blended into a `final_score`, and the A-F letter is read off `final_score`. This inverts the old
//! model, where the score was derived from a letter the decision tree had already chosen.

use super::identity::FnIdentity;
use super::types::{Grade, SubScores, TargetKind};

/// How closely a candidate's resolved callee agrees across builds, banded from the numeric
/// cross-build similarity (not from fingerprint equality). A callee that gained or shifted an
/// instruction across a recompile lands in `High`, where strict fingerprint equality would have
/// called it a mismatch; only a genuine divergence falls to `Low`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum SimilarityBand {
    High,
    Medium,
    Low,
}

const SIMILARITY_HIGH: f64 = 0.85;
const SIMILARITY_MEDIUM: f64 = 0.60;

impl SimilarityBand {
    fn of(similarity: f64) -> Self {
        if similarity >= SIMILARITY_HIGH {
            SimilarityBand::High
        } else if similarity >= SIMILARITY_MEDIUM {
            SimilarityBand::Medium
        } else {
            SimilarityBand::Low
        }
    }
}

/// Whether a cross-build callee similarity is a genuine divergence (the `Low` band), as opposed to
/// the small drift a recompile produces. Used to gate the hard "callee differs across builds"
/// diagnostic so a graceful shift no longer trips it.
pub(super) fn is_callee_divergence(similarity: f64) -> bool {
    SimilarityBand::of(similarity) == SimilarityBand::Low
}

/// The conservative cross-build callee agreement: the *minimum* similarity of any build's callee to
/// the reference build's, so one diverging build cannot be averaged away. `None` when there are fewer
/// than two code callees to compare (a single build is trivially self-consistent, which is not
/// cross-build evidence either way).
pub(super) fn callee_similarity(idents: &[FnIdentity]) -> Option<f64> {
    let (first, rest) = idents.split_first()?;
    if rest.is_empty() {
        return None;
    }
    Some(
        rest.iter()
            .map(|i| first.similarity(i))
            .fold(1.0_f64, f64::min),
    )
}

/// The resolver class a candidate lowered to, the strongest input to confidence and semantics.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum AnchorKind {
    /// The match bytes themselves.
    Direct,
    /// A `call`/`jmp rel` to the target.
    Branch,
    /// A RIP-relative memory reference (x64) to the target.
    RipPtr,
    /// An absolute memory reference (x86); never relocation-stable.
    AbsPtr,
}

/// Everything `finalize` observed about a candidate, handed to the scorer.
pub(super) struct Evidence<'a> {
    pub anchor: AnchorKind,
    pub is_anchor: bool,
    pub all_code: bool,
    pub any_unresolved: bool,
    /// Minimum cross-build callee similarity (0.0..=1.0), or `None` when fewer than two code callees
    /// were resolved. This is a graceful numeric agreement, not fingerprint equality: the scorer
    /// bands it rather than treating any deviation as a hard mismatch.
    pub callee_similarity: Option<f64>,
    /// Whether the resolved target kind is the same in every build (code in all, not code-then-data).
    pub kinds_consistent: bool,
    pub first_kind: Option<TargetKind>,
    pub reloc_safe: bool,
    pub packed: bool,
    /// The fixed (non-wildcard) byte values, for entropy.
    pub fixed_bytes: Vec<u8>,
    pub fixed_n: usize,
    pub len: usize,
    /// Fixed bytes that are opcode (non-operand) bytes.
    pub meaningful: usize,
    /// Operand bytes that ended up wildcarded (volatile bytes correctly masked out).
    pub operand_masked: usize,
    /// How many distinct builds the candidate was validated against.
    pub builds: usize,
    /// The reference build's callee identity, when the target is code.
    pub ref_ident: Option<&'a FnIdentity>,
    /// Fraction of initially-fixed bytes that survived cross-build masking (a direct-match signal).
    pub byte_survival: f64,
}

impl Evidence<'_> {
    /// The cross-build callee agreement banded for scoring, or `None` when there is nothing to
    /// compare (fewer than two code callees). A single build that resolved to code is self-consistent
    /// but carries no cross-build evidence, so it bands as `None`, not `High`.
    fn similarity_band(&self) -> Option<SimilarityBand> {
        self.callee_similarity.map(SimilarityBand::of)
    }

    /// Whether the callee agreement is good enough to treat the anchor as content-validated: either a
    /// `High` band, or a single resolved code build (nothing to disagree with yet). A `Medium`/`Low`
    /// band is an actual cross-build divergence and is not treated as validated.
    fn callee_validated(&self) -> bool {
        matches!(self.similarity_band(), None | Some(SimilarityBand::High))
    }
}

fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let n = bytes.len() as f64;
    -counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = f64::from(c) / n;
            p * p.log2()
        })
        .sum::<f64>()
}

fn entropy_score(ev: &Evidence) -> u32 {
    // 0..8 bits of entropy in the fixed bytes, scaled to 0..100, then damped when there are very few
    // fixed bytes (a 3-byte pattern cannot be as distinctive as a 16-byte one however random).
    let bits = shannon_entropy(&ev.fixed_bytes);
    let damp = (ev.fixed_n as f64 / 6.0).min(1.0);
    ((bits / 8.0) * 100.0 * damp).round().clamp(0.0, 100.0) as u32
}

fn resolver_confidence(ev: &Evidence) -> u32 {
    match ev.anchor {
        AnchorKind::Direct => 70,
        AnchorKind::Branch => {
            if ev.all_code && !ev.any_unresolved && ev.callee_validated() {
                100
            } else if ev.all_code && !ev.any_unresolved {
                65
            } else {
                45
            }
        }
        AnchorKind::RipPtr => match ev.first_kind {
            _ if ev.any_unresolved || !ev.kinds_consistent => 40,
            Some(TargetKind::Code) if ev.callee_validated() => 100,
            Some(TargetKind::Code) => 55,
            Some(TargetKind::Data | TargetKind::Import) => 75,
            _ => 45,
        },
        // Absolute addressing does not survive a rebase/relocation regardless of the target.
        AnchorKind::AbsPtr => 45,
    }
}

fn semantic_score(ev: &Evidence) -> u32 {
    let is_code_target = matches!(ev.first_kind, Some(TargetKind::Code));
    if ev.is_anchor && is_code_target && ev.anchor != AnchorKind::AbsPtr {
        // A validated code target carries real semantic content; richer callees score higher.
        let mut s = 78.0;
        if let Some(id) = ev.ref_ident {
            s += (id.instr_count as f64).min(12.0);
            s += ((id.blocks.saturating_sub(1)) as f64 * 4.0).min(8.0);
            s += (id.strings.len() as f64 * 3.0).min(6.0);
            s += (id.calls as f64 * 2.0).min(4.0);
        }
        s -= match ev.similarity_band() {
            Some(SimilarityBand::Low) => 25.0,
            Some(SimilarityBand::Medium) => 12.0,
            None | Some(SimilarityBand::High) => 0.0,
        };
        return s.round().clamp(0.0, 100.0) as u32;
    }
    if ev.is_anchor && matches!(ev.first_kind, Some(TargetKind::Data | TargetKind::Import)) {
        return 55;
    }
    if !ev.is_anchor {
        return 55; // a direct match is the function's own bytes: moderate semantic value
    }
    25 // unresolved or unknown target
}

fn stability_score(ev: &Evidence) -> u32 {
    let mut s = 0.0;
    if ev.reloc_safe {
        s += 50.0;
    }
    if ev.len > 0 {
        s += (ev.meaningful as f64 / ev.len as f64) * 30.0;
        s += (ev.operand_masked as f64 / ev.len as f64) * 20.0;
    }
    if ev.packed {
        s -= 30.0;
    }
    s.round().clamp(0.0, 100.0) as u32
}

fn cross_build_score(ev: &Evidence) -> u32 {
    if ev.is_anchor {
        // A target that is code in one build and not in another is not a stable cross-build anchor.
        if !ev.kinds_consistent {
            return 50;
        }
        // The conservative minimum callee similarity to the reference build: one diverging build
        // pulls this down even if the others agree. A single resolved build has no peer to compare
        // (None), so it scores as a self-consistent anchor rather than a perfect agreement.
        if let Some(sim) = ev.callee_similarity {
            return (sim * 100.0).round().clamp(0.0, 100.0) as u32;
        }
        // An anchor with no second code target: no cross-build callee evidence, but the bytes are
        // still consistent.
        return 65;
    }
    // Direct match: how many fixed bytes stayed fixed across builds.
    (ev.byte_survival * 100.0).round().clamp(0.0, 100.0) as u32
}

fn uniqueness_score(ev: &Evidence) -> u32 {
    // Unique in every build (finalize guarantees this), reduced when there are very few fixed bytes,
    // which makes an accidental collision in some unrelated module likelier. Negative-corpus hits are
    // folded in later by `apply_negative_corpus`.
    let mut s = 100i32;
    if ev.fixed_n < 6 {
        s -= ((6 - ev.fixed_n) * 5) as i32;
    }
    s.clamp(0, 100) as u32
}

/// What `string_anchor_candidate` measured about a string-anchored target. A string anchor matches on
/// a read-only string the function references, not on its code bytes, so it is scored from this
/// evidence (presence in every build, how specifically the string pins one function, cross-build
/// target stability, callee similarity) rather than from byte entropy or fixed-byte density. String
/// length is only a supporting specificity hint here, never code-byte entropy.
pub(super) struct StringEvidence {
    /// Distinct builds the string was found and resolved to a single function in.
    pub builds: usize,
    /// Length of the anchoring string in characters: a longer string is less likely to recur by
    /// accident, so it lifts specificity, but only as a supporting factor.
    pub text_len: usize,
    /// A second corroborating string was needed to pin the function (a single string was not unique
    /// on its own), which is weaker than a lone uniquely-resolving string.
    pub paired: bool,
    /// References to the resolved function in the reference build (a "hot function" signal; a target
    /// nothing references is harder to trust as a stable identity).
    pub xrefs: usize,
    /// Minimum cross-build callee similarity of the resolved function, or `None` for a single build.
    pub callee_similarity: Option<f64>,
    /// Callee identity of the resolved function in the reference build, for semantic richness.
    pub ref_ident: Option<FnIdentity>,
}

impl StringEvidence {
    fn band(&self) -> Option<SimilarityBand> {
        self.callee_similarity.map(SimilarityBand::of)
    }
    fn cross_build_consistent(&self) -> bool {
        matches!(self.band(), None | Some(SimilarityBand::High))
    }
}

/// Score a string-anchored candidate from its evidence. The byte-oriented sub-scores are
/// reinterpreted for an anchor that does not match on code bytes: `entropy` is zero (there are no
/// fixed code bytes to measure), `uniqueness` is string specificity, and `stability` reflects the
/// inherent recompile-stability of a read-only string reference.
pub(super) fn score_string_anchor(ev: &StringEvidence) -> (SubScores, Vec<String>) {
    // Specificity from how hard the string is to hit by accident: a longer, lone string that already
    // pins one function is the strongest; a short or paired one is weaker.
    let mut uniqueness = 55i32;
    uniqueness += ((ev.text_len.min(24) as i32) - 4) * 3; // +0 at 4 chars, +60 at >=24
    if ev.paired {
        uniqueness -= 15;
    }
    if ev.xrefs == 0 {
        uniqueness -= 10;
    }
    let uniqueness = uniqueness.clamp(0, 100) as u32;

    // A read-only string reference survives recompiles that shift surrounding code, so stability is
    // high by construction; a single-build anchor has not proven that across versions yet.
    let stability = if ev.builds >= 2 { 92 } else { 80 };

    // The string pins a validated code function; richer callees carry more semantic weight, and a
    // cross-build divergence in that function pulls it back.
    let mut semantic = 70.0;
    if let Some(id) = &ev.ref_ident {
        semantic += (id.instr_count as f64).min(12.0);
        semantic += ((id.blocks.saturating_sub(1)) as f64 * 4.0).min(8.0);
        semantic += (id.strings.len() as f64 * 2.0).min(6.0);
        semantic += (id.calls as f64 * 2.0).min(4.0);
    }
    semantic -= match ev.band() {
        Some(SimilarityBand::Low) => 30.0,
        Some(SimilarityBand::Medium) => 14.0,
        None | Some(SimilarityBand::High) => 0.0,
    };
    let semantic = semantic.round().clamp(0.0, 100.0) as u32;

    // Confidence the anchor re-resolves: a string that resolves to one consistent function in every
    // build is the strongest; a single build, a paired string, or a divergent callee weaken it.
    let resolver_confidence = match (ev.builds >= 2, ev.cross_build_consistent(), ev.band()) {
        (true, true, _) => {
            if ev.paired {
                85
            } else {
                92
            }
        }
        (true, false, Some(SimilarityBand::Medium)) => 72,
        (true, false, _) => 58,
        (false, _, _) => 70,
    };

    // Cross-build agreement: the resolved function's similarity across builds, or a single-build
    // baseline that carries no cross-version proof.
    let cross_build = match ev.callee_similarity {
        Some(sim) => (sim * 100.0).round().clamp(0.0, 100.0) as u32,
        None => 65,
    };

    let mut s = SubScores {
        uniqueness,
        stability,
        entropy: 0,
        semantic,
        resolver_confidence,
        cross_build,
        final_score: 0,
    };
    s.final_score = weighted_final(&s);

    let mut reasons = Vec::new();
    reasons.push(if ev.paired {
        "anchored on a pair of strings that together pin one function".into()
    } else {
        "anchored on a string that uniquely pins one function".into()
    });
    if ev.builds >= 2 {
        match (ev.band(), ev.callee_similarity) {
            (None | Some(SimilarityBand::High), _) => reasons.push(format!(
                "resolves to a consistent function across {} builds",
                ev.builds
            )),
            (Some(SimilarityBand::Medium), Some(sim)) => reasons.push(format!(
                "resolved function differs slightly across builds (similarity {:.0}%)",
                sim * 100.0
            )),
            (Some(SimilarityBand::Low), Some(sim)) => reasons.push(format!(
                "resolved function diverges across builds (similarity {:.0}%)",
                sim * 100.0
            )),
            _ => {}
        }
    } else {
        reasons
            .push("validated against only one build; cross-version stability unconfirmed".into());
    }
    if ev.text_len < 6 {
        reasons.push(format!(
            "the anchoring string is short ({} chars); it may recur in other modules",
            ev.text_len
        ));
    }
    if ev.xrefs == 0 {
        reasons.push("nothing references the resolved function in the reference build".into());
    }
    (s, reasons)
}

/// What `fingerprint_relocate` measured about a semantic cross-version relocation. The function was
/// located by matching its `FnIdentity` (mnemonic stream, CFG-lite shape, constants, strings), not by
/// any byte or string the signature can re-scan for, so it is scored from the strength and consistency
/// of that match rather than from byte entropy or fixed-byte density.
pub(super) struct FingerprintEvidence {
    /// Distinct builds the function was relocated in (all required builds; the fallback declines if
    /// any build is missing a confident match).
    pub builds: usize,
    /// The weakest single-build best-match similarity to the reference (the conservative floor).
    pub min_similarity: f64,
    /// The minimum pairwise similarity among the relocated functions across builds (mutual agreement).
    pub mutual_similarity: f64,
    /// Reference build's identity, for semantic richness.
    pub ref_ident: Option<FnIdentity>,
}

/// Score a fingerprint-relocated candidate from its evidence. Entropy is zero (there are no fixed code
/// bytes), and the other sub-scores are reinterpreted for a semantic match: `cross_build` is the
/// mutual similarity, `resolver_confidence`/`uniqueness` reflect how strong and unambiguous the match
/// was, and `semantic` reflects the richness of the relocated function. The caller additionally caps
/// the grade at B, since no byte or string evidence backs the relocation.
pub(super) fn score_fingerprint(ev: &FingerprintEvidence) -> (SubScores, Vec<String>) {
    let pct = |x: f64| (x * 100.0).round().clamp(0.0, 100.0) as u32;
    // How confidently each build matched (the floor) drives both uniqueness and resolver confidence:
    // a relocation that only just cleared the bar is less trustworthy than one matching near-exactly.
    let uniqueness = pct(ev.min_similarity);
    let cross_build = pct(ev.mutual_similarity);
    let resolver_confidence = if ev.builds >= 2 {
        pct((ev.min_similarity + ev.mutual_similarity) / 2.0)
    } else {
        // A single build proves no cross-version stability, so confidence is held down regardless.
        70.min(pct(ev.min_similarity))
    };
    let stability = if ev.builds >= 2 { 88 } else { 72 };
    let mut semantic = 64.0;
    if let Some(id) = &ev.ref_ident {
        semantic += (id.instr_count as f64).min(12.0);
        semantic += ((id.blocks.saturating_sub(1)) as f64 * 4.0).min(8.0);
        semantic += (id.strings.len() as f64 * 2.0).min(6.0);
        semantic += (id.calls as f64 * 2.0).min(4.0);
    }
    let semantic = semantic.round().clamp(0.0, 100.0) as u32;

    let mut s = SubScores {
        uniqueness,
        stability,
        entropy: 0,
        semantic,
        resolver_confidence,
        cross_build,
        final_score: 0,
    };
    s.final_score = weighted_final(&s);

    let mut reasons = vec![
        "relocated across builds by semantic fingerprint (no byte/string anchor available)"
            .to_string(),
    ];
    if ev.builds >= 2 {
        reasons.push(format!(
            "matched a consistent function in {} builds (min similarity {:.0}%, mutual {:.0}%)",
            ev.builds,
            ev.min_similarity * 100.0,
            ev.mutual_similarity * 100.0
        ));
    } else {
        reasons
            .push("validated against only one build; cross-version stability unconfirmed".into());
    }
    reasons.push("fingerprint-only match: no byte or string evidence, capped below A/B".into());
    (s, reasons)
}

fn weighted_final(s: &SubScores) -> u32 {
    // Content-validation signals dominate, so a sparse-but-validated branch/ptr anchor still grades
    // well; byte-level signals (entropy, density) refine within a tier.
    let f = 0.35 * f64::from(s.resolver_confidence)
        + 0.30 * f64::from(s.semantic)
        + 0.20 * f64::from(s.cross_build)
        + 0.08 * f64::from(s.stability)
        + 0.04 * f64::from(s.uniqueness)
        + 0.03 * f64::from(s.entropy);
    f.round().clamp(0.0, 100.0) as u32
}

/// Compute the sub-scores and the explanation reasons for a candidate.
pub(super) fn score(ev: &Evidence) -> (SubScores, Vec<String>) {
    let mut s = SubScores {
        uniqueness: uniqueness_score(ev),
        stability: stability_score(ev),
        entropy: entropy_score(ev),
        semantic: semantic_score(ev),
        resolver_confidence: resolver_confidence(ev),
        cross_build: cross_build_score(ev),
        final_score: 0,
    };
    s.final_score = weighted_final(&s);

    let mut reasons = Vec::new();
    let code_anchor = matches!(ev.anchor, AnchorKind::Branch | AnchorKind::RipPtr)
        && ev.all_code
        && !ev.any_unresolved;
    match ev.anchor {
        _ if code_anchor => match (ev.similarity_band(), ev.callee_similarity) {
            (None | Some(SimilarityBand::High), _) => {
                reasons
                    .push("target validated as code with a consistent callee across builds".into());
            }
            (Some(SimilarityBand::Medium), Some(sim)) => {
                reasons.push(format!(
                    "callee differs slightly across builds (similarity {:.0}%); still likely the same function",
                    sim * 100.0
                ));
            }
            (Some(SimilarityBand::Low), Some(sim)) => {
                reasons.push(format!(
                    "callee diverges across builds (similarity {:.0}%): likely not the same function",
                    sim * 100.0
                ));
            }
            _ => {}
        },
        AnchorKind::AbsPtr => reasons.push("absolute reference is not relocation-stable".into()),
        _ => {}
    }
    if ev.is_anchor && ev.any_unresolved {
        reasons.push("the branch/pointer target could not be resolved in some build".into());
    }
    if !ev.reloc_safe {
        reasons.push("an unsupported relocation overlaps a fixed byte".into());
    }
    if ev.packed {
        reasons.push("an input looks packed; bytes may not reflect the running image".into());
    }
    if ev.fixed_n < 6 {
        reasons.push(format!(
            "only {} fixed byte(s); may collide in unrelated modules",
            ev.fixed_n
        ));
    }
    if ev.builds < 2 {
        reasons
            .push("validated against only one build; cross-version stability unconfirmed".into());
    } else {
        reasons.push(format!("consistent across {} builds", ev.builds));
    }
    (s, reasons)
}

/// Derive the letter grade from the final score, then apply the hard caps: a gated candidate is
/// always F (rejected), and a packed input can never grade better than D.
pub(super) fn grade_from(final_score: u32, gated: bool, packed: bool) -> Grade {
    if gated {
        return Grade::F;
    }
    let band = Grade::from_final_score(final_score);
    if packed && band.rank() < Grade::D.rank() {
        Grade::D
    } else {
        band
    }
}

/// How a signature fared against the negative corpus of unrelated modules. The number of distinct
/// modules it matched is the headline specificity signal (a pattern that recurs in several unrelated
/// binaries is generic), with the match counts kept so the report can be specific rather than just
/// "N modules".
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NegativeEvidence {
    /// Unrelated modules actually scanned.
    pub modules_scanned: usize,
    /// Of those, how many contained the signature at least once.
    pub modules_hit: usize,
    /// Total matches summed across every module that hit.
    pub total_hits: usize,
    /// The most matches the signature had in any single module.
    pub max_hits_per_module: usize,
}

impl NegativeEvidence {
    /// Summarise per-module hit counts against the number of modules scanned.
    #[must_use]
    pub fn from_hits(modules_scanned: usize, hit_counts: &[usize]) -> Self {
        Self {
            modules_scanned,
            modules_hit: hit_counts.iter().filter(|&&c| c > 0).count(),
            total_hits: hit_counts.iter().sum(),
            max_hits_per_module: hit_counts.iter().copied().max().unwrap_or(0),
        }
    }
}

/// Fold a negative-corpus result into an already-scored candidate: a signature that also matches
/// unrelated modules is not specific, so its uniqueness and final score drop, and the grade is
/// re-derived (and can fall a band or two). The penalty scales with the number of distinct modules
/// hit (the real generality signal), nudged up when any one module matched it many times.
pub fn apply_negative_corpus(cand: &mut super::types::SigCandidate, neg: NegativeEvidence) {
    if neg.modules_hit == 0 {
        return;
    }
    // Each distinct unrelated module that matches is strong evidence the pattern is too generic; a
    // single module that matches it many times adds a smaller extra nudge.
    let module_penalty = (neg.modules_hit as u32 * 35).min(90);
    let volume_penalty = u32::from(neg.max_hits_per_module > 1) * 5;
    let penalty = (module_penalty + volume_penalty).min(95);
    cand.scores.uniqueness = cand.scores.uniqueness.saturating_sub(penalty);
    cand.scores.final_score = weighted_final(&cand.scores);
    cand.score = cand.scores.final_score;
    // Re-apply the original hard-gate / packed caps from the typed flags, not by re-reading the grade
    // or substring-matching the human-readable reasons (which would silently break if reworded).
    cand.grade = grade_from(cand.scores.final_score, cand.gated, cand.packed);
    // Matching any unrelated module means the pattern is not a unique identity, so it cannot grade A
    // however strong the bytes are; more distinct modules cap it harder.
    let neg_cap = if neg.modules_hit >= 2 {
        Grade::C
    } else {
        Grade::B
    };
    if cand.grade.rank() < neg_cap.rank() {
        cand.grade = neg_cap;
    }
    let scope = if neg.modules_scanned > 0 {
        format!(" of {} scanned", neg.modules_scanned)
    } else {
        String::new()
    };
    cand.reasons.push(format!(
        "matches {} unrelated module(s){scope} ({} total match(es), up to {} in one): too generic to trust as an identity",
        neg.modules_hit, neg.total_hits, neg.max_hits_per_module
    ));
}

/// Build the negative-corpus evidence from per-module hit counts, fold it into `chosen`, and return
/// it. The single entry point so a front-end computes the evidence once (to adjust the grade) and
/// reuses the returned value for its summary, instead of building it twice.
pub fn apply_negatives(
    chosen: &mut super::types::SigCandidate,
    modules_scanned: usize,
    hit_counts: &[usize],
) -> NegativeEvidence {
    let evidence = NegativeEvidence::from_hits(modules_scanned, hit_counts);
    apply_negative_corpus(chosen, evidence);
    evidence
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_evidence() -> Evidence<'static> {
        Evidence {
            anchor: AnchorKind::Direct,
            is_anchor: false,
            all_code: false,
            any_unresolved: false,
            callee_similarity: None,
            kinds_consistent: true,
            first_kind: None,
            reloc_safe: true,
            packed: false,
            fixed_bytes: vec![0x48, 0x8B, 0xEC, 0xC3, 0x55, 0x56, 0x57, 0x53],
            fixed_n: 8,
            len: 8,
            meaningful: 8,
            operand_masked: 0,
            builds: 2,
            ref_ident: None,
            byte_survival: 1.0,
        }
    }

    // A mnemonic-only identity, for driving callee_similarity in scorer tests.
    fn ident_with(mnemonics: &[u32]) -> FnIdentity {
        FnIdentity {
            instr_count: mnemonics.len(),
            mnemonics: mnemonics.to_vec(),
            ..Default::default()
        }
    }

    #[test]
    fn grade_is_derived_from_final_score() {
        assert_eq!(Grade::from_final_score(90), Grade::A);
        assert_eq!(Grade::from_final_score(70), Grade::B);
        assert_eq!(Grade::from_final_score(50), Grade::C);
        assert_eq!(Grade::from_final_score(30), Grade::D);
        assert_eq!(Grade::from_final_score(10), Grade::F);
    }

    #[test]
    fn gates_and_packed_cap_the_grade() {
        assert_eq!(grade_from(99, true, false), Grade::F); // gated overrides a high score
        assert_eq!(grade_from(99, false, true), Grade::D); // packed caps at D
        assert_eq!(grade_from(99, false, false), Grade::A);
    }

    #[test]
    fn final_score_is_the_weighted_blend_of_the_raw_sub_scores() {
        // The model runs one way only: raw sub-scores -> weighted final_score -> grade band. This locks
        // that final_score is exactly the documented blend of the independent sub-scores, so the grade
        // can never be chosen first and the score back-filled to match it.
        let mut ev = base_evidence();
        ev.anchor = AnchorKind::Branch;
        ev.is_anchor = true;
        ev.all_code = true;
        ev.first_kind = Some(TargetKind::Code);
        let (s, _) = score(&ev);
        let expected = (0.35 * f64::from(s.resolver_confidence)
            + 0.30 * f64::from(s.semantic)
            + 0.20 * f64::from(s.cross_build)
            + 0.08 * f64::from(s.stability)
            + 0.04 * f64::from(s.uniqueness)
            + 0.03 * f64::from(s.entropy))
        .round() as u32;
        assert_eq!(s.final_score, expected, "final_score must be the raw blend");
        assert_eq!(
            grade_from(s.final_score, false, false),
            Grade::from_final_score(s.final_score),
            "an ungated, unpacked grade is exactly the band of final_score"
        );
    }

    #[test]
    fn grade_bands_are_monotonic_and_total() {
        // Every possible final_score maps to a band (total), and a higher score never yields a worse
        // grade (monotonic, no inversion or gap). This is the property the on-corpus calibration
        // confirmed empirically: across adjacent builds, grade A signatures re-resolved 15/15 (100%)
        // and grade B 9/12 (75%), so the letter genuinely tracks cross-version survival. Guarded here
        // so a future edit to the bands cannot silently break that ordering.
        let mut prev_rank = Grade::from_final_score(0).rank();
        for s in 0..=100u32 {
            let rank = Grade::from_final_score(s).rank();
            assert!(
                rank <= prev_rank,
                "grade must not get worse as the score rises (score {s}: rank {rank} > {prev_rank})"
            );
            prev_rank = rank;
            // An ungated, unpacked candidate grades exactly at the band.
            assert_eq!(grade_from(s, false, false), Grade::from_final_score(s));
        }
        assert_eq!(Grade::from_final_score(100), Grade::A);
        assert_eq!(Grade::from_final_score(0), Grade::F);
    }

    #[test]
    fn weighted_final_is_monotonic_in_every_subscore() {
        // weighted_final is a positive-weighted blend, so raising any single sub-score must never
        // lower the final score: more evidence is never worse. Guards against a future weight change
        // that breaks the monotonicity the grade ordering (and the calibration above) depends on.
        let mid = SubScores {
            uniqueness: 50,
            stability: 50,
            entropy: 50,
            semantic: 50,
            resolver_confidence: 50,
            cross_build: 50,
            final_score: 0,
        };
        let setters: [fn(&mut SubScores, u32); 6] = [
            |s, v| s.uniqueness = v,
            |s, v| s.stability = v,
            |s, v| s.entropy = v,
            |s, v| s.semantic = v,
            |s, v| s.resolver_confidence = v,
            |s, v| s.cross_build = v,
        ];
        for set in setters {
            let mut prev = 0u32;
            for v in 0..=100u32 {
                let mut s = mid;
                set(&mut s, v);
                let f = weighted_final(&s);
                assert!(
                    f >= prev,
                    "raising a sub-score lowered final_score ({prev} -> {f} at value {v})"
                );
                prev = f;
            }
        }
    }

    #[test]
    fn high_entropy_scores_above_low_entropy() {
        let mut hi = base_evidence();
        hi.fixed_bytes = vec![0x1F, 0xA3, 0x4C, 0xD8, 0x57, 0x9E, 0x21, 0xBC];
        let mut lo = base_evidence();
        lo.fixed_bytes = vec![0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90];
        assert!(entropy_score(&hi) > entropy_score(&lo));
        assert_eq!(entropy_score(&lo), 0); // all identical bytes carry no entropy
    }

    #[test]
    fn validated_code_branch_scores_into_grade_a() {
        // A single resolved code build: callee_similarity is None (nothing to disagree with), which
        // counts as validated, and the branch reaches the A band.
        let id = FnIdentity {
            instr_count: 6,
            blocks: 2,
            calls: 1,
            ..Default::default()
        };
        let mut ev = base_evidence();
        ev.anchor = AnchorKind::Branch;
        ev.is_anchor = true;
        ev.all_code = true;
        ev.first_kind = Some(TargetKind::Code);
        ev.ref_ident = Some(&id);
        ev.callee_similarity = None;
        ev.fixed_bytes = vec![0xE8];
        ev.fixed_n = 1;
        ev.len = 5;
        ev.meaningful = 1;
        ev.operand_masked = 4;
        let (s, _) = score(&ev);
        assert!(
            s.final_score >= 82,
            "validated code branch should reach A band, got {}",
            s.final_score
        );
    }

    #[test]
    fn high_similarity_does_not_emit_a_mismatch_reason() {
        // A callee that gained one prologue instruction across a build: a High band. The old exact
        // fingerprint check would have flagged a mismatch; the numeric band must keep it validated and
        // emit the positive reason, not a hard mismatch.
        let id = ident_with(&[10, 11, 12, 13, 14, 15]);
        let mut shifted = ident_with(&[99, 10, 11, 12, 13, 14, 15]);
        shifted.instr_count = 7;
        let idents = [id.clone(), shifted];
        let sim = callee_similarity(&idents).unwrap();
        assert!(sim >= 0.85, "expected a High band, got {sim}");
        let mut ev = base_evidence();
        ev.anchor = AnchorKind::Branch;
        ev.is_anchor = true;
        ev.all_code = true;
        ev.callee_similarity = Some(sim);
        ev.first_kind = Some(TargetKind::Code);
        ev.ref_ident = Some(&id);
        let (s, reasons) = score(&ev);
        assert!(s.final_score >= 82, "a High-band callee should stay in A");
        assert!(
            reasons.iter().any(|r| r.contains("consistent callee")),
            "expected the validated-callee reason, got {reasons:?}"
        );
        assert!(
            !reasons.iter().any(|r| r.contains("diverges")),
            "a High band must not emit a divergence reason, got {reasons:?}"
        );
    }

    #[test]
    fn low_similarity_drops_below_a_with_a_divergence_reason() {
        // Genuinely different callees: a Low band. It must fall out of A and say the callee diverges,
        // driven by the numeric similarity rather than fingerprint inequality.
        let id = ident_with(&[1, 2, 3, 4, 5, 6]);
        let other = ident_with(&[60, 61, 62, 63, 64, 65]);
        let idents = [id.clone(), other];
        let sim = callee_similarity(&idents).unwrap();
        assert!(sim < 0.60, "expected a Low band, got {sim}");
        let mut ev = base_evidence();
        ev.anchor = AnchorKind::Branch;
        ev.is_anchor = true;
        ev.all_code = true;
        ev.callee_similarity = Some(sim);
        ev.first_kind = Some(TargetKind::Code);
        ev.ref_ident = Some(&id);
        let (s, reasons) = score(&ev);
        assert!(s.final_score < 82, "a Low-band callee must fall out of A");
        assert!(
            reasons.iter().any(|r| r.contains("diverges")),
            "expected a divergence reason, got {reasons:?}"
        );
    }

    #[test]
    fn medium_similarity_is_a_soft_downgrade_not_a_hard_mismatch() {
        // A Medium band: still likely the same function, downgraded but not declared a mismatch.
        let id = ident_with(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        let drifted = ident_with(&[1, 2, 3, 40, 41, 42, 43, 8, 9, 10]);
        let idents = [id.clone(), drifted];
        let sim = callee_similarity(&idents).unwrap();
        assert!(
            (SIMILARITY_MEDIUM..SIMILARITY_HIGH).contains(&sim),
            "expected a Medium band, got {sim}"
        );
        let mut ev = base_evidence();
        ev.anchor = AnchorKind::Branch;
        ev.is_anchor = true;
        ev.all_code = true;
        ev.callee_similarity = Some(sim);
        ev.first_kind = Some(TargetKind::Code);
        ev.ref_ident = Some(&id);
        let (_, reasons) = score(&ev);
        assert!(
            reasons.iter().any(|r| r.contains("differs slightly")),
            "expected a soft downgrade reason, got {reasons:?}"
        );
        assert!(
            !reasons.iter().any(|r| r.contains("not the same function")),
            "a Medium band must not be called a mismatch, got {reasons:?}"
        );
    }

    #[test]
    fn callee_similarity_takes_the_minimum_across_builds() {
        // One agreeing build and one diverging build: the conservative minimum must reflect the
        // divergence, not average it away.
        let r = ident_with(&[1, 2, 3, 4, 5, 6]);
        let same = ident_with(&[1, 2, 3, 4, 5, 6]);
        let diff = ident_with(&[60, 61, 62, 63, 64, 65]);
        let sim = callee_similarity(&[r, same, diff]).unwrap();
        assert!(
            sim < 0.60,
            "min similarity must catch the diverging build, got {sim}"
        );
        assert_eq!(callee_similarity(&[ident_with(&[1, 2, 3])]), None);
    }

    fn string_evidence() -> StringEvidence {
        StringEvidence {
            builds: 2,
            text_len: 16,
            paired: false,
            xrefs: 3,
            callee_similarity: Some(1.0),
            ref_ident: Some(ident_with(&[1, 2, 3, 4, 5, 6])),
        }
    }

    #[test]
    fn string_anchor_score_is_not_code_byte_entropy() {
        // The string text is not scored as fixed code bytes: entropy is zero, and the score is driven
        // by the evidence sub-scores instead. A long high-entropy string and a short one differ only
        // through specificity, never through a byte-entropy term.
        let ev = string_evidence();
        let (s, _) = score_string_anchor(&ev);
        assert_eq!(s.entropy, 0, "a string anchor has no code-byte entropy");
        assert!(s.resolver_confidence > 0 && s.cross_build > 0);
    }

    #[test]
    fn multi_build_consistent_string_anchor_can_reach_a() {
        let ev = string_evidence();
        let (s, _) = score_string_anchor(&ev);
        assert!(
            Grade::from_final_score(s.final_score) == Grade::A,
            "a consistent multi-build unique anchor should reach A, got {}",
            s.final_score
        );
    }

    #[test]
    fn single_build_string_anchor_scores_below_a() {
        // With no cross-build evidence the raw score itself must stay out of the A band, independent of
        // the explicit single-build grade cap applied by the caller.
        let mut ev = string_evidence();
        ev.builds = 1;
        ev.callee_similarity = None;
        let (s, reasons) = score_string_anchor(&ev);
        assert!(
            Grade::from_final_score(s.final_score).rank() > Grade::A.rank(),
            "a single-build anchor must not score into A, got {}",
            s.final_score
        );
        assert!(reasons.iter().any(|r| r.contains("one build")));
    }

    #[test]
    fn generic_short_string_anchor_is_downgraded() {
        let strong = score_string_anchor(&string_evidence()).0.final_score;
        let mut weak_ev = string_evidence();
        weak_ev.text_len = 4; // a 4-char string is far likelier to recur by accident
        weak_ev.paired = true;
        weak_ev.xrefs = 0;
        let (weak, reasons) = score_string_anchor(&weak_ev);
        assert!(
            weak.final_score < strong,
            "a short, paired, unreferenced anchor must score below a strong one ({} !< {strong})",
            weak.final_score
        );
        assert!(reasons.iter().any(|r| r.contains("short")));
    }

    #[test]
    fn divergent_string_anchor_target_is_downgraded() {
        let strong = score_string_anchor(&string_evidence()).0.final_score;
        let mut div = string_evidence();
        div.callee_similarity = Some(0.40); // resolves to a different function across builds
        let (weak, reasons) = score_string_anchor(&div);
        assert!(
            weak.final_score < strong,
            "an inconsistent target must downgrade ({} !< {strong})",
            weak.final_score
        );
        assert!(reasons.iter().any(|r| r.contains("diverges")));
    }

    fn graded_candidate() -> super::super::types::SigCandidate {
        use super::super::types::{SigCandidate, Suffix};
        SigCandidate {
            aob: "AA BB CC DD".into(),
            suffix: Suffix::None,
            grade: Grade::A,
            score: 90,
            bytes_len: 4,
            fixed: 4,
            wildcards: 0,
            fixed_ratio: 1.0,
            reloc_safe: true,
            gated: false,
            packed: false,
            scores: SubScores {
                uniqueness: 100,
                stability: 80,
                entropy: 70,
                semantic: 80,
                resolver_confidence: 95,
                cross_build: 100,
                final_score: 90,
            },
            reasons: Vec::new(),
            per_version: Vec::new(),
            diags: Vec::new(),
            relocation: None,
        }
    }

    #[test]
    fn negative_corpus_represerves_the_packed_cap_from_the_typed_flag() {
        // PSE-7: a packed candidate keeps its D cap after a negative-corpus re-grade even though its
        // `reasons` never contain the word "packed" (the cap is read from the typed flag, not text).
        let mut cand = graded_candidate();
        cand.packed = true;
        cand.grade = grade_from(cand.scores.final_score, false, true);
        assert_eq!(
            cand.grade,
            Grade::D,
            "packed input caps at D before the corpus"
        );
        apply_negative_corpus(
            &mut cand,
            NegativeEvidence {
                modules_scanned: 5,
                modules_hit: 1,
                total_hits: 1,
                max_hits_per_module: 1,
            },
        );
        assert_eq!(
            cand.grade,
            Grade::D,
            "the packed D cap must survive the re-grade via the typed flag, not a reason substring"
        );
    }

    fn fingerprint_evidence() -> FingerprintEvidence {
        FingerprintEvidence {
            builds: 2,
            min_similarity: 1.0,
            mutual_similarity: 1.0,
            ref_ident: Some(ident_with(&[1, 2, 3, 4, 5, 6])),
        }
    }

    #[test]
    fn fingerprint_score_has_no_code_byte_entropy_and_tracks_similarity() {
        let strong = score_fingerprint(&fingerprint_evidence()).0;
        assert_eq!(
            strong.entropy, 0,
            "a fingerprint match has no code-byte entropy"
        );
        assert_eq!(strong.cross_build, 100);
        let mut weak_ev = fingerprint_evidence();
        weak_ev.min_similarity = 0.84;
        weak_ev.mutual_similarity = 0.84;
        let weak = score_fingerprint(&weak_ev).0;
        assert!(
            weak.final_score < strong.final_score,
            "a weaker match must score lower ({} !< {})",
            weak.final_score,
            strong.final_score
        );
    }

    #[test]
    fn single_build_fingerprint_holds_confidence_down() {
        // With no second build there is no cross-version proof, so resolver confidence is held down and
        // the reasons say so.
        let mut ev = fingerprint_evidence();
        ev.builds = 1;
        let (s, reasons) = score_fingerprint(&ev);
        assert!(s.resolver_confidence <= 70);
        assert!(reasons.iter().any(|r| r.contains("one build")));
    }

    #[test]
    fn grade_max_rank_caps_but_never_promotes() {
        assert_eq!(Grade::A.max_rank(Grade::B), Grade::B); // capped down
        assert_eq!(Grade::C.max_rank(Grade::B), Grade::C); // already weaker, left alone
        assert_eq!(Grade::B.max_rank(Grade::B), Grade::B);
    }

    #[test]
    fn negative_evidence_summarises_per_module_counts() {
        let ev = NegativeEvidence::from_hits(5, &[0, 3, 0, 1]);
        assert_eq!(ev.modules_scanned, 5);
        assert_eq!(ev.modules_hit, 2);
        assert_eq!(ev.total_hits, 4);
        assert_eq!(ev.max_hits_per_module, 3);
    }

    #[test]
    fn no_negative_hits_does_not_downgrade() {
        let mut cand = graded_candidate();
        apply_negative_corpus(&mut cand, NegativeEvidence::from_hits(4, &[0, 0, 0, 0]));
        assert_eq!(cand.scores.uniqueness, 100);
        assert_eq!(cand.scores.final_score, 90);
        assert_eq!(cand.grade, Grade::A);
        assert!(cand.reasons.is_empty());
    }

    #[test]
    fn one_negative_module_downgrades() {
        let mut cand = graded_candidate();
        apply_negative_corpus(&mut cand, NegativeEvidence::from_hits(3, &[0, 1, 0]));
        assert!(cand.scores.uniqueness < 100);
        assert!(cand.scores.final_score < 90);
        let reason = cand.reasons.last().unwrap();
        assert!(reason.contains("1 unrelated module"));
        assert!(reason.contains("of 3 scanned"));
    }

    #[test]
    fn more_negative_modules_downgrade_harder() {
        let mut one = graded_candidate();
        apply_negative_corpus(&mut one, NegativeEvidence::from_hits(4, &[1, 0, 0, 0]));
        let mut many = graded_candidate();
        apply_negative_corpus(&mut many, NegativeEvidence::from_hits(4, &[1, 2, 1, 0]));
        assert!(
            many.scores.uniqueness < one.scores.uniqueness,
            "three hit modules ({}) must penalise more than one ({})",
            many.scores.uniqueness,
            one.scores.uniqueness
        );
        assert!(many.scores.final_score < one.scores.final_score);
        assert!(many.reasons.last().unwrap().contains("3 unrelated module"));
    }

    #[test]
    fn negative_corpus_hit_caps_grade_below_a() {
        let mut one = graded_candidate();
        assert_eq!(one.grade, Grade::A);
        apply_negative_corpus(&mut one, NegativeEvidence::from_hits(4, &[1, 0, 0, 0]));
        assert_ne!(
            one.grade,
            Grade::A,
            "matching an unrelated module cannot grade A"
        );
        assert!(one.grade.rank() >= Grade::B.rank());

        let mut many = graded_candidate();
        apply_negative_corpus(&mut many, NegativeEvidence::from_hits(4, &[1, 2, 1, 0]));
        assert_ne!(many.grade, Grade::A);
        assert!(
            many.grade.rank() >= one.grade.rank(),
            "more hit modules cap at least as hard as one"
        );
    }
}
