//! The cross-version relocation chainer: relocate a function from a reference build to every other
//! required build over the maximum-bottleneck (widest) path through the build graph, re-anchoring at each
//! hop. Generic over the anchor, so every make/resolve anchor pair gets stepwise chaining from one walk
//! (#14). Extracted from the generation core so the orchestrator stays a thin coordinator (Phase 9).

use super::types::ImageInput;

/// Relocate the function at `ref_entry` from build `ref_idx` to every other required build by the
/// maximum-bottleneck (widest) path through the build graph. Starting from the reference (confidence
/// 1.0), each newly located build re-anchors and offers edges to the rest; a build is then taken by the
/// highest-confidence path that reaches it, so a long version jump is crossed as a chain of short,
/// high-confidence hops rather than one low-confidence leap. A path's confidence is its weakest hop (a
/// chain is only as sure as its worst link). Returns, per build, the located RVA and the path's
/// bottleneck confidence, or `None` for a build no gated path reaches. This is the data-driven
/// generalisation of "diff v83->v84, then v84->v88, ...": the chain follows measured similarity, not an
/// assumed version order, so it routes around a hop that a refactor made unexpectedly hard.
///
/// Generic over the anchor (#14): `make_anchor` mints an anchor at a located function in a build, and
/// `edge` resolves that anchor in a candidate build, returning the located RVA and the hop confidence
/// already gated, or `None` to decline the hop. Any anchor with a make/resolve pair gets stepwise
/// chaining from this single walk, not just the vtable.
pub(super) fn relocate_path<A>(
    images: &[ImageInput],
    required: &[usize],
    ref_idx: usize,
    ref_entry: usize,
    make_anchor: impl Fn(&ImageInput, usize) -> Option<A>,
    edge: impl Fn(&ImageInput, &A) -> Option<(u64, f64)>,
) -> Vec<Option<(u64, f64)>> {
    let mut located: Vec<Option<(u64, f64)>> = vec![None; images.len()];
    let Some(ref_anchor) = make_anchor(&images[ref_idx], ref_entry) else {
        return located;
    };
    located[ref_idx] = Some((ref_entry as u64, 1.0));
    let mut frontier: Vec<(usize, u64, f64)> = Vec::new();
    // Offer every still-open build an edge from the just-located function `anchor` was minted at.
    let offer = |anchor: &A,
                 lconf: f64,
                 located: &[Option<(u64, f64)>],
                 frontier: &mut Vec<(usize, u64, f64)>| {
        for &v in required {
            if located[v].is_some() {
                continue;
            }
            if let Some((rva, conf)) = edge(&images[v], anchor) {
                frontier.push((v, rva, lconf.min(conf)));
            }
        }
    };
    offer(&ref_anchor, 1.0, &located, &mut frontier);
    loop {
        // The widest still-open edge: the highest-confidence frontier edge to a build not yet located.
        let mut pick: Option<usize> = None;
        let mut pick_conf = -1.0;
        for (k, &(v, _, c)) in frontier.iter().enumerate() {
            if located[v].is_none() && c > pick_conf {
                pick_conf = c;
                pick = Some(k);
            }
        }
        let Some(k) = pick else { break };
        let (v, rva, conf) = frontier[k];
        located[v] = Some((rva, conf));
        // Re-anchor in the newly located build to carry the chain forward, then offer its edges.
        if let Some(anchor) = make_anchor(&images[v], rva as usize) {
            offer(&anchor, conf, &located, &mut frontier);
        }
    }
    located
}
