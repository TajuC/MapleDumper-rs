//! Real-corpus cross-version validation harnesses (run with `--ignored`; they need the GMS clients
//! in X:\Client_Unpacked). Kept out of the inline unit-test module so mod.rs stays a thin orchestrator
//! (Phase 9).

use super::*;

// Phase 7: measure the global call-graph alignment on the real lineage. It seeds with the 1:1 string
// anchors between two builds and propagates the correspondence by neighbour consensus; a function it
// commits BEYOND the seeds is one relocated by graph position alone (the coverage no content anchor
// reaches). The honesty check is an INDEPENDENT reverse alignment (seed-and-propagate the other way):
// a forward match `a -> b` whose target relocates back to a DIFFERENT function under the reverse
// alignment is a confirmed wrong address, and that count must be zero. Measured on a dense
// within-lineage hop (v83 -> v84, where seeds are plentiful and propagation should reach widely) and
// the hard major break (v83 -> v95.1, where the vtable chain collapses to zero).
#[test]
#[ignore = "needs the real GMS clients in X:\\Client_Unpacked; run with --ignored"]
fn graph_alignment_propagates_beyond_seeds_and_is_reverse_consistent() {
    use crate::fileimage::FileImage;
    use std::collections::BTreeSet;
    use std::path::Path;

    let dir = Path::new(r"X:\Client_Unpacked");
    let names = [
        "GMS_v83.1_U_DEVM.exe",
        "GMS_v84.1_U_DEVM.exe",
        "GMS_v88.1_U_DEVM.exe",
        "GMS_v91.1_U_DEVM.exe",
        "GMS_v95.1_U_DEVM.exe",
    ];
    if names.iter().any(|n| !dir.join(n).exists()) {
        eprintln!("real GMS clients not present; skipping");
        return;
    }
    fn mk<'a>(label: &str, img: &'a FileImage) -> ImageInput<'a> {
        let pack = img.pack_report();
        ImageInput {
            label: label.to_string(),
            source: img,
            base: img.base(),
            size: img.size(),
            code_regions: img.code_regions(),
            regions: img.regions(),
            import: img.import_range(),
            arch: img.arch(),
            code_hash: img.code_hash(),
            packed: pack.likely_packed,
            pack_reasons: pack.reasons,
            reloc: None,
        }
    }
    let i83 = FileImage::open(&dir.join(names[0])).expect("open v83");
    let i84 = FileImage::open(&dir.join(names[1])).expect("open v84");
    let i88 = FileImage::open(&dir.join(names[2])).expect("open v88");
    let i91 = FileImage::open(&dir.join(names[3])).expect("open v91");
    let i95 = FileImage::open(&dir.join(names[4])).expect("open v95.1");
    let v83 = mk("v83", &i83);
    let v84 = mk("v84", &i84);
    let v88 = mk("v88", &i88);
    let v91 = mk("v91", &i91);
    let v95 = mk("v95.1", &i95);

    let m83 = model::AnalysisModel::build(&v83);
    let g83 = graph::CallGraph::build(&v83, &m83);
    // The candidate universe for seeding is v83's call-graph functions; make their string anchors once
    // (the expensive image-scanning step) and re-resolve per target build.
    let v83_fns: Vec<usize> = m83.entries().to_vec();
    let anchors = graph::anchor_candidates(&v83, &v83_fns);
    eprintln!(
        "=== Phase 7 graph alignment (v83 anchorable functions: {} of {} entries) ===",
        anchors.len(),
        v83_fns.len()
    );

    let mut total_inconsistent = 0usize;
    for (label, tgt) in [("v84", &v84), ("v88", &v88), ("v91", &v91), ("v95.1", &v95)] {
        let mt = model::AnalysisModel::build(tgt);
        let gt = graph::CallGraph::build(tgt, &mt);
        let seeds = graph::resolve_seeds(tgt, &anchors);
        let rev_seeds: Vec<(usize, usize)> = seeds.iter().map(|&(a, b)| (b, a)).collect();
        let fwd = graph::align(&g83, &gt, &seeds);
        let rev = graph::align(&gt, &g83, &rev_seeds);
        let seed_a: BTreeSet<usize> = seeds.iter().map(|&(a, _)| a).collect();

        let (mut propagated, mut consistent, mut inconsistent, mut unverifiable) =
            (0usize, 0usize, 0usize, 0usize);
        for (&a, &b) in &fwd {
            if seed_a.contains(&a) {
                continue; // a seed, not a graph-propagated match
            }
            propagated += 1;
            match rev.get(&b) {
                Some(&back) if back == a => consistent += 1,
                Some(_) => inconsistent += 1,
                None => unverifiable += 1,
            }
        }
        total_inconsistent += inconsistent;
        eprintln!(
            "v83 -> {label}: seeds {} | propagated beyond seeds {propagated} | reverse-consistent \
                 {consistent} / INCONSISTENT {inconsistent} / unverifiable {unverifiable}",
            seeds.len()
        );
    }

    // The false-positive gate: the independent reverse alignment must never contradict a forward
    // propagated match. Inconsistency is a confirmed wrong address; it must be zero on every hop.
    assert_eq!(
        total_inconsistent, 0,
        "graph alignment produced a reverse-inconsistent (confirmed wrong) match"
    );
}
