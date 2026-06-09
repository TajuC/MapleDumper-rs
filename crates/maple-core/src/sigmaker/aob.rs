//! Per-build AOB version-range reporting: once a relocation has minted a byte signature at the function's
//! address in each build, collapse those into the contiguous version runs each signature covers ("AOB X
//! works v83..v88, AOB Y works v91..v95"), verifying every extension matches uniquely at the relocated
//! address so a coincidental hit elsewhere cannot bridge a run. Extracted from the generation core to keep
//! the orchestrator thin (Phase 9).

use super::CodeCache;
use super::types::{AobRange, ImageInput, PerVersion};
use crate::pattern::try_signature_from_aob;
use crate::scanner::CompiledPattern;

/// Whether `aob` matches build `img` exactly once and that one match is at `rva`. The match-at-RVA
/// requirement is essential: a pattern that happens to be unique elsewhere is a different function that
/// coincidentally shares the bytes, and extending a version range onto it would report a wrong address.
pub(super) fn aob_unique_at(img: &ImageInput, aob: &str, rva: usize) -> bool {
    let Ok(sig) = try_signature_from_aob(aob) else {
        return false;
    };
    let Some(pat) = CompiledPattern::new(&sig) else {
        return false;
    };
    let (count, first) = CodeCache::build(img).locate(&pat);
    count == 1 && first == Some(rva as u64)
}

/// Collapse a relocation's per-build minted AOBs into contiguous version ranges. Walking builds in
/// order, the current range's AOB is carried forward as long as it still matches the next build at that
/// build's relocated address; when it stops (a recompile moved the bytes) or a build was not reached,
/// the run closes and the next reached build's freshly minted AOB starts a new run. The result is the
/// "AOB X works v83..v88, AOB Y works v91..v95" story, derived purely from `resolved_target_rva`, so it
/// works for any anchor type, not just vtables.
pub(super) fn collapse_aob_ranges(
    images: &[ImageInput],
    per_version: &[PerVersion],
) -> Vec<AobRange> {
    let mut ranges: Vec<AobRange> = Vec::new();
    let mut cur: Option<(String, String, Vec<String>)> = None; // (aob, minted_in, labels)
    let close = |cur: Option<(String, String, Vec<String>)>, ranges: &mut Vec<AobRange>| {
        if let Some((aob, minted_in, labels)) = cur {
            ranges.push(AobRange {
                aob,
                minted_in,
                first_label: labels.first().cloned().unwrap_or_default(),
                last_label: labels.last().cloned().unwrap_or_default(),
                labels,
            });
        }
    };
    for pv in per_version {
        let (Some(rva), Some(aob)) = (pv.resolved_target_rva, pv.aob.as_ref()) else {
            close(cur.take(), &mut ranges);
            continue;
        };
        let Some(im) = images.iter().find(|i| i.label == pv.label) else {
            // An unresolvable label breaks contiguity rather than silently bridging the two sides.
            close(cur.take(), &mut ranges);
            continue;
        };
        let extend = cur
            .as_ref()
            .is_some_and(|(a, _, _)| aob_unique_at(im, a, rva as usize));
        if extend {
            cur.as_mut().unwrap().2.push(pv.label.clone());
        } else {
            close(cur.take(), &mut ranges);
            cur = Some((aob.clone(), pv.label.clone(), vec![pv.label.clone()]));
        }
    }
    close(cur.take(), &mut ranges);
    ranges
}
