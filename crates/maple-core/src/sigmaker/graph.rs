//! Global call-graph alignment (Phase 7): relocate a function across builds by its POSITION in the
//! matched call graph, for the functions no single content anchor can pin, especially across the v95
//! class refactor where the structural vtable matcher and the bytes both collapse.
//!
//! The idea, following BinDiff's seed-and-propagate (Dullien & Rolles 2005): a recompile rewrites
//! function bodies but largely preserves *who calls whom*. So if a handful of functions are pinned with
//! certainty (here: the ones a build-stable string anchors, which resolve 1:1 across builds), their
//! neighbours can be matched by agreement: a function called by several already-matched functions in the
//! old build is the function called by the images of those same callers in the new build. Committing
//! those matches turns them into new seeds and the correspondence grows outward through the graph to a
//! fixpoint.
//!
//! The discipline is the project's: decline rather than guess. A function is committed ONLY when at least
//! [`MIN_SUPPORT`] independent matched neighbours (callers and/or callees) agree on the SAME candidate,
//! that candidate is the strict unique maximum (no tie), the candidate is not already taken, and the match
//! is mutual-best (aligning the candidate back across the inverse correspondence returns the original).
//! Everything else stays undecided. This is a relational generalisation of the existing single-hop caller
//! anchor ([`super::callers`]) to the whole graph, both directions, to convergence.
//!
//! The alignment core ([`align`], [`consensus`]) is pure over [`CallGraph`]s and a seed correspondence, so
//! it is exercised on hand-built graphs without decoding a real image; [`CallGraph::build`] is the only
//! part that touches an [`ImageInput`]. x86 / PE32, like the other anchors.

use std::collections::{BTreeMap, BTreeSet};

use super::identity::{enclosing_function, make_string_anchor, resolve_string_anchor};
use super::model::AnalysisModel;
use super::types::ImageInput;
use crate::domain::StringAnchor;

/// At least this many independent matched neighbours must agree on a candidate before it is committed.
/// Two is the floor at which agreement is meaningful: a lone matched neighbour is the single-hop caller
/// anchor, which already exists and is weaker; requiring a second, independent neighbour to corroborate
/// the same landing is what makes a graph match trustworthy without content evidence.
const MIN_SUPPORT: usize = 2;

/// The function-level direct-call graph of one image: per function, the multiset of functions it calls
/// (in call-site rva order, the call-site rank) and the set of functions that call it. Built from the
/// decode-verified call edges of an [`AnalysisModel`] by mapping each call site to its enclosing function.
pub(super) struct CallGraph {
    callees: BTreeMap<usize, Vec<usize>>,
    callers: BTreeMap<usize, BTreeSet<usize>>,
}

impl CallGraph {
    #[must_use]
    pub(super) fn build(img: &ImageInput, model: &AnalysisModel) -> Self {
        // (caller function, call-site rva, callee function) for every decode-verified edge.
        let mut raw: Vec<(usize, usize, usize)> = model
            .call_sites()
            .map(|(site, callee)| (enclosing_function(img, site), site, callee))
            .collect();
        raw.sort_unstable();
        let mut callees: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
        let mut callers: BTreeMap<usize, BTreeSet<usize>> = BTreeMap::new();
        for (caller, _site, callee) in raw {
            // A self-recursive edge carries no cross-function relational information and would let a
            // function vote for itself; drop it.
            if caller == callee {
                continue;
            }
            callees.entry(caller).or_default().push(callee);
            callers.entry(callee).or_default().insert(caller);
        }
        Self { callees, callers }
    }

    fn callees_of(&self, f: usize) -> &[usize] {
        self.callees.get(&f).map_or(&[], Vec::as_slice)
    }

    fn callers_of(&self, f: usize) -> impl Iterator<Item = usize> + '_ {
        self.callers.get(&f).into_iter().flatten().copied()
    }

    /// Every function that appears in the graph (as a caller or a callee), ascending and de-duplicated.
    fn functions(&self) -> Vec<usize> {
        let mut s: BTreeSet<usize> = BTreeSet::new();
        s.extend(self.callees.keys().copied());
        s.extend(self.callers.keys().copied());
        s.into_iter().collect()
    }

    /// The functions within `depth` call-graph hops of `target`, both directions, capped at `cap`. The
    /// seed search only string-anchors these, so seeding cost is local to the target's neighbourhood
    /// rather than the whole image; the cap bounds it on a densely connected hub.
    pub(super) fn neighbourhood(&self, target: usize, depth: usize, cap: usize) -> Vec<usize> {
        let mut seen: BTreeSet<usize> = BTreeSet::from([target]);
        let mut frontier = vec![target];
        for _ in 0..depth {
            if seen.len() >= cap {
                break;
            }
            let mut next = Vec::new();
            for &f in &frontier {
                for c in self.callers_of(f) {
                    if seen.insert(c) {
                        next.push(c);
                    }
                }
                for &d in self.callees_of(f) {
                    if seen.insert(d) {
                        next.push(d);
                    }
                }
            }
            frontier = next;
        }
        seen.into_iter().take(cap).collect()
    }

    /// How many of `f`'s graph neighbours (callers and callees, counted once each) are already matched.
    fn matched_neighbours(&self, f: usize, m: &BTreeMap<usize, usize>) -> usize {
        let mut seen: BTreeSet<usize> = BTreeSet::new();
        for c in self.callers_of(f) {
            if m.contains_key(&c) {
                seen.insert(c);
            }
        }
        for &d in self.callees_of(f) {
            if m.contains_key(&d) {
                seen.insert(d);
            }
        }
        seen.len()
    }
}

/// The consensus candidate in graph `gb` for function `t` of graph `ga`, given the correspondence `m`
/// (`ga` -> `gb`): the function each of `t`'s already-matched neighbours points at, in the matching
/// direction. Returns `(candidate, support, runner_up_support)` where support is the number of distinct
/// matched neighbours of `t` that are graph-adjacent to the candidate in `gb`. `None` when `t` has no
/// matched neighbour at all. Pure: no image access, so it is unit-tested on hand-built graphs.
///
/// A matched caller `c -> m[c]` votes for every callee of `m[c]` in `gb` (the image of `t` is one of them,
/// since `c` calls `t`); a matched callee `d -> m[d]` votes for every caller of `m[d]`. Each neighbour is
/// counted once per candidate (a neighbour that calls the candidate twice still votes once), so support
/// is the count of *independent* corroborating neighbours, and the true image is the candidate every
/// matched neighbour agrees on.
fn consensus(
    t: usize,
    ga: &CallGraph,
    gb: &CallGraph,
    m: &BTreeMap<usize, usize>,
) -> Option<(usize, usize, usize)> {
    let mut support: BTreeMap<usize, usize> = BTreeMap::new();
    // Each matched neighbour votes once per distinct candidate it is graph-adjacent to (a neighbour that
    // calls the same candidate twice still counts once), so support is the count of independent neighbours.
    let vote = |candidates: BTreeSet<usize>, support: &mut BTreeMap<usize, usize>| {
        for g in candidates {
            *support.entry(g).or_default() += 1;
        }
    };
    for c in ga.callers_of(t) {
        if let Some(&cb) = m.get(&c) {
            vote(gb.callees_of(cb).iter().copied().collect(), &mut support);
        }
    }
    for &d in ga.callees_of(t) {
        if let Some(&db) = m.get(&d) {
            vote(gb.callers_of(db).collect(), &mut support);
        }
    }
    if support.is_empty() {
        return None;
    }
    // Most support wins; ties broken by lowest rva so the choice is deterministic (and a real tie is
    // rejected by the strict-margin gate in `align`, never silently resolved here).
    let mut ranked: Vec<(usize, usize)> = support.into_iter().collect();
    ranked.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    let (best_g, best_s) = ranked[0];
    let runner = ranked.get(1).map_or(0, |&(_, s)| s);
    Some((best_g, best_s, runner))
}

/// Whether `t -> g` is mutual-best: the consensus for `g` back in `ga` (across the inverse correspondence
/// `m_inv`) is `t`, with the same support floor and a strict margin. A one-directional coincidence (g is
/// t's best, but t is not g's best) fails this and is not committed.
fn mutual_best(
    t: usize,
    g: usize,
    ga: &CallGraph,
    gb: &CallGraph,
    m_inv: &BTreeMap<usize, usize>,
) -> bool {
    match consensus(g, gb, ga, m_inv) {
        Some((back, sup, run)) => back == t && sup >= MIN_SUPPORT && sup > run,
        None => false,
    }
}

/// Seed-and-propagate the correspondence `ga -> gb` from `seeds` to a fixpoint, committing only matches
/// that clear every gate (>= [`MIN_SUPPORT`] agreeing neighbours, strict unique maximum, candidate not
/// already taken, mutual-best). Returns the full correspondence including the seeds. Deterministic:
/// functions are visited in ascending order and a candidate claimed by more than one source in a round is
/// committed for none of them, so the result does not depend on iteration nondeterminism.
#[must_use]
pub(super) fn align(
    ga: &CallGraph,
    gb: &CallGraph,
    seeds: &[(usize, usize)],
) -> BTreeMap<usize, usize> {
    let mut m: BTreeMap<usize, usize> = seeds.iter().copied().collect();
    let mut m_inv: BTreeMap<usize, usize> = seeds.iter().map(|&(a, b)| (b, a)).collect();
    let functions = ga.functions();
    loop {
        // Propose every confident new match this round, then commit the conflict-free ones together, so a
        // candidate two different functions both want is taken by neither (ambiguity declines).
        let mut proposals: Vec<(usize, usize)> = Vec::new();
        for &t in &functions {
            if m.contains_key(&t) || ga.matched_neighbours(t, &m) < MIN_SUPPORT {
                continue;
            }
            let Some((g, sup, run)) = consensus(t, ga, gb, &m) else {
                continue;
            };
            if sup >= MIN_SUPPORT
                && sup > run
                && !m_inv.contains_key(&g)
                && mutual_best(t, g, ga, gb, &m_inv)
            {
                proposals.push((t, g));
            }
        }
        if proposals.is_empty() {
            break;
        }
        let mut g_claims: BTreeMap<usize, usize> = BTreeMap::new();
        for &(_, g) in &proposals {
            *g_claims.entry(g).or_default() += 1;
        }
        let mut committed = 0usize;
        for (t, g) in proposals {
            if g_claims[&g] == 1 && !m.contains_key(&t) && !m_inv.contains_key(&g) {
                m.insert(t, g);
                m_inv.insert(g, t);
                committed += 1;
            }
        }
        if committed == 0 {
            break;
        }
    }
    m
}

/// Make the certain-seed string anchors among `candidates` (function entries in build `a`): a candidate
/// whose own string anchor pins exactly it in `a` is kept with its anchor. Done once in the reference;
/// each build then re-resolves these via [`resolve_seeds`], so the image-scanning anchor construction is
/// not repeated per build. The string anchor is the project's most precise, build-stable channel, so a
/// resolved seed is ~1.0 confidence.
#[must_use]
pub(super) fn anchor_candidates(
    a: &ImageInput,
    candidates: &[usize],
) -> Vec<(usize, StringAnchor)> {
    candidates
        .iter()
        .filter_map(|&fa| {
            let sa = make_string_anchor(a, fa)?;
            (resolve_string_anchor(a, &sa) == Some(fa)).then_some((fa, sa))
        })
        .collect()
}

/// Resolve the reference's seed anchors in build `b`, yielding the 1:1 correspondence `(ref_fn, b_fn)` for
/// every anchor that pins exactly one function in `b`. An anchor that is absent or ambiguous in `b` simply
/// drops out of the seed set for that build.
#[must_use]
pub(super) fn resolve_seeds(
    b: &ImageInput,
    anchors: &[(usize, StringAnchor)],
) -> Vec<(usize, usize)> {
    anchors
        .iter()
        .filter_map(|(fa, sa)| resolve_string_anchor(b, sa).map(|fb| (*fa, fb)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a [`CallGraph`] from explicit `(caller, callee)` edges, for testing the pure alignment over
    /// hand-drawn graphs without decoding an image.
    fn graph(edges: &[(usize, usize)]) -> CallGraph {
        let mut callees: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
        let mut callers: BTreeMap<usize, BTreeSet<usize>> = BTreeMap::new();
        for &(c, d) in edges {
            if c == d {
                continue;
            }
            callees.entry(c).or_default().push(d);
            callers.entry(d).or_default().insert(c);
        }
        CallGraph { callees, callers }
    }

    #[test]
    fn two_matched_callers_relocate_their_common_callee() {
        // A: callers 10, 11 both call target 12. B: their images 110, 111 both call 112. Seeds pin the
        // callers; the target is the function both matched callers point at, so it relocates to 112.
        let ga = graph(&[(10, 12), (11, 12)]);
        let gb = graph(&[(110, 112), (111, 112)]);
        let m = align(&ga, &gb, &[(10, 110), (11, 111)]);
        assert_eq!(
            m.get(&12),
            Some(&112),
            "the common callee relocates by consensus"
        );
    }

    #[test]
    fn a_single_matched_neighbour_is_not_enough() {
        // Only one matched caller: below MIN_SUPPORT, so the target stays undecided (that is the weaker
        // single-hop case, which graph alignment deliberately does not commit on its own).
        let ga = graph(&[(10, 12), (11, 12)]);
        let gb = graph(&[(110, 112), (111, 112)]);
        let m = align(&ga, &gb, &[(10, 110)]);
        assert_eq!(
            m.get(&12),
            None,
            "one neighbour does not commit a graph match"
        );
    }

    #[test]
    fn an_ambiguous_tie_declines() {
        // Two matched callers, but in B they share TWO common callees (112 and 113): the target ties, so
        // the strict-maximum gate refuses to guess between them.
        let ga = graph(&[(10, 12), (11, 12)]);
        let gb = graph(&[(110, 112), (110, 113), (111, 112), (111, 113)]);
        let m = align(&ga, &gb, &[(10, 110), (11, 111)]);
        assert_eq!(m.get(&12), None, "a tie between two candidates declines");
    }

    #[test]
    fn mutual_best_rejects_a_one_directional_bind() {
        // t=12 is called by matched 10,11 whose images 110,111 both call 112, so 12->112 looks good one
        // way. But 112 in B is ALSO called by 120,121 (unmatched) and its consensus back to A is dominated
        // by a different function 12b that 10,11 also call... constructed so 112's back-consensus is not
        // 12. The bind must be refused.
        // A: 10->12, 11->12, 10->13, 11->13 (10,11 call both 12 and 13).
        let ga = graph(&[(10, 12), (11, 12), (10, 13), (11, 13)]);
        // B: 110->112, 111->112, 110->113, 111->113. Symmetric: 112 and 113 are indistinguishable.
        let gb = graph(&[(110, 112), (111, 112), (110, 113), (111, 113)]);
        let m = align(&ga, &gb, &[(10, 110), (11, 111)]);
        // Both 12 and 13 tie on support for both 112 and 113, so nothing commits (ambiguous), which also
        // means no one-directional mis-bind slips through.
        assert_eq!(m.get(&12), None);
        assert_eq!(m.get(&13), None);
    }

    #[test]
    fn propagation_grows_outward_from_seeds() {
        // 1-hop: 12 relocates from seeds 10,11. 2-hop: 14 is called by 12 and 13; 13 also relocates from
        // the seeds, so after 12 and 13 are committed, 14 has two matched callers and relocates too.
        let ga = graph(&[(10, 12), (11, 12), (10, 13), (20, 13), (12, 14), (13, 14)]);
        let gb = graph(&[
            (110, 112),
            (111, 112),
            (110, 113),
            (120, 113),
            (112, 114),
            (113, 114),
        ]);
        let m = align(&ga, &gb, &[(10, 110), (11, 111), (20, 120)]);
        assert_eq!(m.get(&12), Some(&112), "12 relocates at the first hop");
        assert_eq!(m.get(&13), Some(&113), "13 relocates at the first hop");
        assert_eq!(
            m.get(&14),
            Some(&114),
            "14 relocates at the second hop once its callers are matched"
        );
    }

    #[test]
    fn a_callee_direction_neighbour_also_corroborates() {
        // Direction test: t calls two matched callees; their images are called by the same g in B.
        let ga = graph(&[(12, 20), (12, 21)]);
        let gb = graph(&[(112, 120), (112, 121)]);
        let m = align(&ga, &gb, &[(20, 120), (21, 121)]);
        assert_eq!(
            m.get(&12),
            Some(&112),
            "a function relocates from two matched callees too"
        );
    }
}
