//! The cross-anchor consensus vote (Phase 4): decide which relocation anchor's landing to commit, purely
//! from the per-build landing maps and grade ranks, so a disagreement between independent methods caps the
//! result rather than shipping a guess. Kept pure (over landing maps, not whole images) so the vote is
//! unit-tested directly. Extracted from the generation core to keep the orchestrator thin (Phase 9).

use super::identity;
use super::types::{ImageInput, SigCandidate};

/// The function (its enclosing entry) each build's resolved target maps to, keyed by build label. Two
/// candidates are compared only on the builds they both resolve, so a build one anchor declined is not
/// counted as a disagreement.
pub(super) fn anchor_landing(
    images: &[ImageInput],
    cand: &SigCandidate,
) -> std::collections::HashMap<String, usize> {
    let mut m = std::collections::HashMap::new();
    for pv in &cand.per_version {
        if let Some(rva) = pv.resolved_target_rva
            && let Some(img) = images.iter().find(|i| i.label == pv.label)
        {
            m.insert(
                pv.label.clone(),
                identity::enclosing_function(img, rva as usize),
            );
        }
    }
    m
}

/// The outcome of the cross-anchor vote: which candidate wins, how many independent channels corroborate
/// it (including itself), whether any channel conflicts with it, and the indices of its corroborators.
pub(super) struct Consensus {
    pub(super) winner: usize,
    pub(super) support: usize,
    pub(super) conflict: bool,
    pub(super) corroborators: Vec<usize>,
}

/// Decide among several anchors' landings purely from their per-build landing maps and grade ranks (a
/// lower rank is a better grade). The winner is the landing with the most corroboration (other channels
/// that agree on every shared build), ties broken toward the better grade and then the earlier (stronger)
/// channel. Two channels with no build in common neither corroborate nor conflict. Kept pure so the vote
/// is unit-tested without constructing whole images.
pub(super) fn ensemble_decide(
    landings: &[std::collections::HashMap<String, usize>],
    ranks: &[u8],
) -> Consensus {
    let n = landings.len();
    // Some(true) = agree on every shared build; Some(false) = a shared build lands differently; None = no
    // build in common.
    let verdict = |a: &std::collections::HashMap<String, usize>,
                   b: &std::collections::HashMap<String, usize>|
     -> Option<bool> {
        let mut shared = 0usize;
        let mut conflict = false;
        for (lbl, fa) in a {
            if let Some(fb) = b.get(lbl) {
                shared += 1;
                if fa != fb {
                    conflict = true;
                }
            }
        }
        (shared > 0).then_some(!conflict)
    };
    let mut support = vec![1usize; n];
    let mut conflicted = vec![false; n];
    let mut corroborators: Vec<Vec<usize>> = vec![Vec::new(); n];
    for i in 0..n {
        for j in 0..n {
            if i == j {
                continue;
            }
            match verdict(&landings[i], &landings[j]) {
                Some(true) => {
                    support[i] += 1;
                    corroborators[i].push(j);
                }
                Some(false) => conflicted[i] = true,
                None => {}
            }
        }
    }
    let mut winner = 0usize;
    for i in 1..n {
        let better = support[i] > support[winner]
            || (support[i] == support[winner] && ranks[i] < ranks[winner]);
        if better {
            winner = i;
        }
    }
    Consensus {
        winner,
        support: support[winner],
        conflict: conflicted[winner],
        corroborators: std::mem::take(&mut corroborators[winner]),
    }
}
