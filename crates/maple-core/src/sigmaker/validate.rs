//! Post-generation validation: confirm a minted signature is not only unique among the supplied builds
//! but trustworthy as an identity. The negative-corpus scan catches a pattern that collides inside an
//! unrelated module, and leave-one-out hold-out catches a signature overfit to the builds it was trained
//! on. Extracted from the generation core to keep the orchestrator thin (Phase 9).

use super::types::{HoldoutResult, ImageInput, NegativeHit, SigOptions, TargetSpec};
use super::{CodeCache, generate};
use crate::scanner::CompiledPattern;

/// Scan a corpus of unrelated modules for `aob` and report any that contain it. Generation only proves a
/// signature is unique among the supplied builds, so a short or low-entropy pattern can still collide
/// inside some other module; a hit here means the signature is not specific enough to trust as an
/// identity. Returns one entry per negative image that matched, with the match count.
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

/// Leave-one-out validation: for each build, regenerate the signature from the others and check it still
/// uniquely matches the held-out build. Generation only proves a signature fits the builds it was trained
/// on; a signature that fits those but fails a build it never saw is overfit to the corpus. Needs at least
/// three builds (two to train on, one to hold out) and returns one result per eligible held-out build. A
/// reference build that defines the target cannot itself be held out.
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
