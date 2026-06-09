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

// Broad cross-version validation sweep (run with `--ignored`): on the real GMS lineage, how many
// functions each relocation anchor actually carries from v83 to v95.1, and at what false-positive
// (wrong-address) rate. This turns "validated on a handful of cases" into corpus-wide numbers.
//
// COVERAGE is counted per anchor over a stride-sampled population of real function entries (every E8
// rel32 call target in v83): for each anchor, how many it can ANCHOR (make), RESOLVE into v95.1, and
// pin with a unique, re-scannable per-build AOB (VALIDATE). The vtable and constructor-grounding
// anchors are measured over the population they serve, the vtable-slot methods, and the grounded path
// is separated from the structural one by its sentinel score.
//
// FALSE POSITIVES are judged against an INDEPENDENT oracle, never the anchor under test. A referenced
// literal string is a semantic name, so for any function that also has an isolating string the string
// anchor names the true v95.1 function; an import, caller, or vtable relocation that lands in a
// different enclosing function than that oracle is a confirmed wrong-address hit. Two further
// anchor-independent signals corroborate: cross-anchor agreement (two independent anchors that both
// resolve a function must agree) and post-recompile identity similarity (a landing on an unrelated
// function scores far below a genuine recompiled twin). The string anchor, which cannot grade itself,
// is held to those two signals.
//
// Functions legitimately absent in v95.1 (deleted over twelve versions) make the anchors DECLINE, not
// misfire, so they lower coverage without inflating the false-positive count: declining is correct.

#[test]
#[ignore = "needs the real GMS clients in X:\\Client_Unpacked; run with --ignored"]
#[allow(clippy::too_many_lines)]
fn cross_version_relocation_coverage_and_false_positive_sweep() {
    use crate::fileimage::FileImage;
    use std::collections::{BTreeSet, HashMap};
    use std::path::Path;

    let dir = Path::new(r"X:\Client_Unpacked");
    // The full GMS unprotected lineage (v61.1 -> v111.1), spanning several real major refactors, not
    // just the single v95 structural break. Themida/VMProtect builds (v116/v117/v126/v131) are
    // statically unanalyzable and excluded. The reference is v83 and the headline round-trip target is
    // v95.1 (the known class refactor), so the per-anchor FP figures stay comparable to earlier runs
    // while the reach tables now chart coverage decay across the whole lineage on both sides of v83.
    let chain_names = [
        "GMS_v61.1_U_DEVM.exe",
        "GMS_v62.1_U_DEVM.exe",
        "GMS_v68.1_U_DEVM.exe",
        "GMS_v72.1_U_DEVM.exe",
        "GMS_v83.1_U_DEVM.exe",
        "GMS_v84.1_U_DEVM.exe",
        "GMS_v88.1_U_DEVM.exe",
        "GMS_v91.1_U_DEVM.exe",
        "GMS_v95.1_U_DEVM.exe",
        "GMS_v95.5_U_DEVM.exe",
        "GMS_v100.1_U_DEVM.exe",
        "GMS_v111.1_U_DEVM.exe",
    ];
    if chain_names.iter().any(|n| !dir.join(n).exists()) {
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
    let imgs: Vec<FileImage> = chain_names
        .iter()
        .map(|n| FileImage::open(&dir.join(n)).unwrap())
        .collect();
    let labels = [
        "v61", "v62", "v68", "v72", "v83", "v84", "v88", "v91", "v95.1", "v95.5", "v100", "v111",
    ];
    let chain: Vec<ImageInput> = labels.iter().zip(&imgs).map(|(l, i)| mk(l, i)).collect();
    let opts = SigOptions::default();
    // v83 is the reference (index 4), v95.1 the headline round-trip target (index 8).
    let (refi, tgti) = (4usize, 8usize);
    let rf = &chain[refi];
    let tg = &chain[tgti];

    let enc = |img: &ImageInput, rva: usize| identity::enclosing_function(img, rva);
    let validate = |img: &ImageInput, r: usize| {
        single_build_aob(img, r, &opts).is_some_and(|aob| aob::aob_unique_at(img, &aob, r))
    };

    // The population: distinct v83 function entries (every E8 rel32 call target landing in code), and
    // how many call sites reach each one (fan-in), used to skip generic high-fan-in helpers in the
    // caller pass.
    let mut call_freq: HashMap<usize, u32> = HashMap::new();
    for r in &rf.code_regions {
        let bytes = read_region(rf.source, r.base, r.size);
        for (i, w) in bytes.windows(5).enumerate() {
            if w[0] == 0xE8 {
                let rel = i32::from_le_bytes([w[1], w[2], w[3], w[4]]) as i64;
                let t = (r.base + i + 5) as i64 + rel - rf.base as i64;
                if t > 0x1000 && (t as usize) < rf.size {
                    *call_freq.entry(t as usize).or_default() += 1;
                }
            }
        }
    }
    let all_entries: Vec<usize> = call_freq.keys().copied().collect();
    let all_entries = {
        let mut v = all_entries;
        v.sort_unstable();
        v
    };
    const N_GENERAL: usize = 800;
    let step = (all_entries.len() / N_GENERAL).max(1);
    let sample: Vec<usize> = all_entries
        .iter()
        .copied()
        .step_by(step)
        .take(N_GENERAL)
        .collect();
    assert!(!sample.is_empty(), "v83 must yield function entries");
    eprintln!(
        "v83 function entries: {} total (string swept over all; import/caller over a {}-entry stride sample, stride {})",
        all_entries.len(),
        sample.len(),
        step
    );

    #[derive(Default)]
    struct Stats {
        made: usize,
        resolved: usize,
        validated: usize,
        id_sum: f64,
        id_n: usize,
        id_below: usize,
        rt_pass: usize,
        rt_fail: usize,
        rt_inc: usize,
    }
    impl Stats {
        fn note_id(&mut self, sim: f64) {
            self.id_sum += sim;
            self.id_n += 1;
            if sim < 0.30 {
                self.id_below += 1;
            }
        }
        fn note_rt(&mut self, rt: i8) {
            match rt {
                1 => self.rt_pass += 1,
                -1 => self.rt_fail += 1,
                _ => self.rt_inc += 1,
            }
        }
    }

    // Round-trip is the primary INDEPENDENT wrong-address check: re-anchor the relocated function in
    // v95.1 with the same anchor kind and resolve it BACK in v83. A correct landing returns to the
    // origin (1 = pass); a wrong-address landing re-anchors a different function and returns elsewhere
    // (-1 = fail); a benign decline of the reverse anchor is inconclusive (0). The STRING round-trip
    // re-uses the same string and so is near-tautological; for the string anchor, identity similarity
    // and the 1:1 uniqueness, not round-trip, are the wrong-address guard.
    fn rt_string(from: &ImageInput, r: usize, back: &ImageInput, want: usize) -> i8 {
        let Some(sa) = make_string_anchor(from, r) else {
            return 0;
        };
        match resolve_string_anchor(back, &sa) {
            Some(x) if identity::enclosing_function(back, x) == want => 1,
            Some(_) => -1,
            None => 0,
        }
    }
    fn rt_import(from: &ImageInput, r: usize, back: &ImageInput, want: usize) -> i8 {
        let Some(a) = imports::make_import_anchor(from, r) else {
            return 0;
        };
        match imports::resolve_import_anchor(back, &a) {
            Some(x) if identity::enclosing_function(back, x) == want => 1,
            Some(_) => -1,
            None => 0,
        }
    }
    fn rt_constant(from: &ImageInput, r: usize, back: &ImageInput, want: usize) -> i8 {
        let Some(a) = constants::make_constant_anchor(from, r) else {
            return 0;
        };
        match constants::resolve_constant_anchor(back, &a) {
            Some(x) if identity::enclosing_function(back, x) == want => 1,
            Some(_) => -1,
            None => 0,
        }
    }
    fn rt_caller(from: &ImageInput, r: usize, back: &ImageInput, want: usize) -> i8 {
        let Some(a) = callers::make_caller_anchor(from, r) else {
            return 0;
        };
        match callers::resolve_caller_anchor(back, &a) {
            Some(x) if identity::enclosing_function(back, x) == want => 1,
            Some(_) => -1,
            None => 0,
        }
    }
    fn rt_vtable(from: &ImageInput, r: usize, back: &ImageInput, want: usize) -> i8 {
        let Some(a) = vtable::make_vtable_anchor(from, r) else {
            return 0;
        };
        let Some((x, ag, run)) = vtable::resolve_vtable_anchor(back, &a) else {
            return 0;
        };
        let grounded = a.installer.is_some()
            && (ag - vtable::VT_GROUNDED_SCORE).abs() < 1e-9
            && run.abs() < 1e-9;
        let accepted = grounded
            || (ag >= vtable::VT_STRUCT_MIN_AGREEMENT && ag - run >= vtable::VT_STRUCT_MIN_MARGIN);
        if !accepted {
            return 0; // below the production gate: the reverse anchor declined, not a wrong address
        }
        if identity::enclosing_function(back, x) == want {
            1
        } else {
            -1
        }
    }

    // The E8 rel32 callees of a function, used to enumerate the non-string callees the caller anchor
    // serves. Mirrors the engine's own bounded callee scan.
    fn callee_entries(img: &ImageInput, rva: usize) -> Vec<usize> {
        let bytes = read_at(img.source, img.base, rva, 400 * 8);
        let mut dec = Decoder::with_ip(32, &bytes, (img.base + rva) as u64, DecoderOptions::NONE);
        let mut instr = Instruction::default();
        let mut out = Vec::new();
        let mut n = 0;
        while dec.can_decode() && n < 400 {
            dec.decode_out(&mut instr);
            if instr.is_invalid() || instr.len() == 0 {
                break;
            }
            n += 1;
            if instr.flow_control() == FlowControl::Call && instr.len() == 5 {
                let t = instr.near_branch_target() as usize;
                if t > img.base + 0x1000 && t < img.base + img.size {
                    out.push(t - img.base);
                }
            }
            if instr.flow_control() == FlowControl::Return {
                break;
            }
        }
        out
    }

    let idsim = |a_img: &ImageInput, a_rva: usize, b_img: &ImageInput, b_rva: usize| {
        fn_identity(a_img, a_rva).similarity(&fn_identity(b_img, b_rva))
    };

    // STRING over its FULL population: it serves a small, distinctive set (functions referencing an
    // isolating literal string), so the whole v83 entry list is swept to find every one. Each anchor is
    // then resolved into EVERY build to chart how coverage decays with version distance; v95.1 is the
    // headline, and the functions that resolve there are the bridging callers driving the caller pass.
    let t = std::time::Instant::now();
    let mut s_str = Stats::default();
    let mut str_anchors: Vec<(usize, crate::domain::StringAnchor)> = Vec::new();
    for &e in &all_entries {
        let Some(sa) = make_string_anchor(rf, e) else {
            continue;
        };
        if resolve_string_anchor(rf, &sa) == Some(enc(rf, e)) {
            s_str.made += 1;
            str_anchors.push((e, sa));
        }
    }
    let mut str_reach: Vec<(usize, usize)> = vec![(0, 0); chain.len()];
    let mut bridging: Vec<usize> = Vec::new();
    // Second-string corroboration: an INDEPENDENT same-function check for the string anchor (whose own
    // round-trip is near-tautological). Two distinct string literals co-occurring in one function in
    // both builds is not a coincidence, so a v95.1 landing sharing >= 2 referenced strings with the v83
    // origin is a confirmed match; one sharing only the single anchor string AND whose body diverged
    // (identity < 0.30) is the genuine wrong-address suspect (the string may have migrated).
    let (mut str_corrob, mut str_single, mut str_single_lowid) = (0usize, 0usize, 0usize);
    for (e, sa) in &str_anchors {
        let mut tgt = None;
        for (bi, img) in chain.iter().enumerate() {
            if let Some(r) = resolve_string_anchor(img, sa) {
                let v = validate(img, r);
                str_reach[bi].0 += 1;
                if v {
                    str_reach[bi].1 += 1;
                }
                if bi == tgti {
                    tgt = Some((r, v));
                }
            }
        }
        if let Some((r, v)) = tgt {
            s_str.resolved += 1;
            bridging.push(*e);
            let re = enc(tg, r);
            if v {
                s_str.validated += 1;
            }
            let id_ref = fn_identity(rf, enc(rf, *e));
            let id_tgt = fn_identity(tg, re);
            let sim = id_ref.similarity(&id_tgt);
            s_str.note_id(sim);
            s_str.note_rt(rt_string(tg, r, rf, enc(rf, *e)));
            let v83s: BTreeSet<&str> = id_ref.strings.iter().map(String::as_str).collect();
            let v95s: BTreeSet<&str> = id_tgt.strings.iter().map(String::as_str).collect();
            if v83s.intersection(&v95s).count() >= 2 {
                str_corrob += 1;
            } else {
                str_single += 1;
                if sim < 0.30 {
                    str_single_lowid += 1;
                }
            }
        }
    }
    eprintln!(
        "string pass: {} made over {} entries, resolved per build, in {:.0}s",
        s_str.made,
        all_entries.len(),
        t.elapsed().as_secs_f64()
    );

    // IMPORT over a stride sample (its population is large, so a sample gives a sound rate). The
    // forward resolve scans every v95.1 function and the reverse resolve every v83 function, so both
    // are hard-capped.
    let t = std::time::Instant::now();
    let mut s_imp = Stats::default();
    const IMPORT_RESOLVE_CAP: usize = 50;
    let mut imp_applicable = 0usize;
    for &e in &sample {
        let Some(ia) = imports::make_import_anchor(rf, e) else {
            continue;
        };
        imp_applicable += 1;
        if s_imp.made >= IMPORT_RESOLVE_CAP {
            continue;
        }
        s_imp.made += 1;
        let Some(r) = imports::resolve_import_anchor(tg, &ia) else {
            continue;
        };
        s_imp.resolved += 1;
        let re = enc(tg, r);
        if validate(tg, r) {
            s_imp.validated += 1;
        }
        s_imp.note_id(idsim(rf, enc(rf, e), tg, re));
        s_imp.note_rt(rt_import(tg, r, rf, enc(rf, e)));
    }
    eprintln!(
        "import pass: {imp_applicable} applicable of {} sampled, {} resolved (cap {IMPORT_RESOLVE_CAP}) in {:.0}s",
        sample.len(),
        s_imp.resolved,
        t.elapsed().as_secs_f64()
    );

    // CONSTANT over the sample (capped): a function with a rare immediate that occurs exactly once in
    // the code. Forward resolve and the reverse round-trip each scan a build's code by byte search.
    let t = std::time::Instant::now();
    let mut s_const = Stats::default();
    const CONST_CAP: usize = 300;
    for &e in sample.iter().take(CONST_CAP) {
        let Some(ca) = constants::make_constant_anchor(rf, e) else {
            continue;
        };
        s_const.made += 1;
        let Some(r) = constants::resolve_constant_anchor(tg, &ca) else {
            continue;
        };
        s_const.resolved += 1;
        let re = enc(tg, r);
        if validate(tg, r) {
            s_const.validated += 1;
        }
        s_const.note_id(idsim(rf, enc(rf, e), tg, re));
        s_const.note_rt(rt_constant(tg, r, rf, enc(rf, e)));
    }
    eprintln!(
        "constant pass: {} made / {} resolved of {} sampled (cap {CONST_CAP}) in {:.0}s",
        s_const.made,
        s_const.resolved,
        sample.len().min(CONST_CAP),
        t.elapsed().as_secs_f64()
    );

    // CALLER over its true population: the non-string callees of the string-bridging functions. This
    // is exactly who caller-relative anchoring serves (a function with no handle of its own, reachable
    // through a caller that has one). Only a callee reached by more than CALLER_MAX_FANIN call sites is
    // skipped: that is a generic shared helper whose huge caller set makes anchoring slow and which is
    // a poor caller-anchor target anyway. Attempts and wall time are capped so the pass stays bounded.
    let t = std::time::Instant::now();
    let mut s_cal = Stats::default();
    let mut seen_callee: BTreeSet<usize> = BTreeSet::new();
    let mut cal_attempts = 0usize;
    const CALLER_MAX_FANIN: u32 = 200;
    const CALLER_ATTEMPT_CAP: usize = 150;
    'callers: for &g in &bridging {
        for c in callee_entries(rf, g) {
            if !seen_callee.insert(c)
                || call_freq.get(&c).copied().unwrap_or(0) > CALLER_MAX_FANIN
                || make_string_anchor(rf, c).is_some()
            {
                continue; // already tested, too widely shared, or it has its own string
            }
            if cal_attempts >= CALLER_ATTEMPT_CAP || t.elapsed().as_secs() >= 150 {
                break 'callers;
            }
            cal_attempts += 1;
            let Some(ca) = callers::make_caller_anchor(rf, c) else {
                continue;
            };
            s_cal.made += 1;
            let Some(r) = callers::resolve_caller_anchor(tg, &ca) else {
                continue;
            };
            s_cal.resolved += 1;
            let re = enc(tg, r);
            if validate(tg, r) {
                s_cal.validated += 1;
            }
            s_cal.note_id(idsim(rf, enc(rf, c), tg, re));
            s_cal.note_rt(rt_caller(tg, r, rf, enc(rf, c)));
        }
    }
    eprintln!(
        "caller pass: {} made / {} resolved from {cal_attempts} attempts ({} bridging callers) in {:.0}s",
        s_cal.made,
        s_cal.resolved,
        bridging.len(),
        t.elapsed().as_secs_f64()
    );

    // VTABLE / constructor-grounding over the slot-method population (sampled): methods that sit in a
    // vtable, a run of at least eight consecutive pointers into code (the engine's MIN_SLOTS). The
    // grounded path is separated from the structural one by its sentinel score.
    let t = std::time::Instant::now();
    let buf83 = read_region(rf.source, rf.base, rf.size);
    let in_code = |abs: usize| {
        rf.code_regions
            .iter()
            .any(|r| abs >= r.base && abs < r.base + r.size)
    };
    let mut vt_methods: BTreeSet<usize> = BTreeSet::new();
    {
        let end = buf83.len() & !3;
        let mut i = 0usize;
        while i + 4 <= end {
            let v =
                u32::from_le_bytes([buf83[i], buf83[i + 1], buf83[i + 2], buf83[i + 3]]) as usize;
            if in_code(v) {
                let mut run: Vec<usize> = Vec::new();
                while i + 4 <= end {
                    let v = u32::from_le_bytes([buf83[i], buf83[i + 1], buf83[i + 2], buf83[i + 3]])
                        as usize;
                    if !in_code(v) {
                        break;
                    }
                    run.push(v - rf.base);
                    i += 4;
                }
                if run.len() >= 8 {
                    vt_methods.extend(run);
                }
            } else {
                i += 4;
            }
        }
    }
    let vt_methods: Vec<usize> = vt_methods.into_iter().collect();
    const N_VT: usize = 200;
    let vstep = (vt_methods.len() / N_VT).max(1);
    let vt_sample: Vec<usize> = vt_methods
        .iter()
        .copied()
        .step_by(vstep)
        .take(N_VT)
        .collect();

    #[derive(Default)]
    struct VtStats {
        made: usize,
        installer_present: usize,
        structural: usize,
        grounded: usize,
        declined: usize,
        validated: usize,
        id_sum: f64,
        id_n: usize,
        id_below: usize,
        rt_pass: usize,
        rt_fail: usize,
        rt_inc: usize,
    }
    let mut vt = VtStats::default();
    const VT_RT_CAP: usize = 120;
    let mut vt_rt_done = 0usize;
    for &m in &vt_sample {
        let Some(anchor) = vtable::make_vtable_anchor(rf, m) else {
            continue;
        };
        vt.made += 1;
        let has_installer = anchor.installer.is_some();
        if has_installer {
            vt.installer_present += 1;
        }
        let Some((r, a, runner)) = vtable::resolve_vtable_anchor(tg, &anchor) else {
            vt.declined += 1;
            continue;
        };
        // The installer-grounded fallback returns the sentinel (0.9, 0.0); a structural match returns
        // its real weighted agreement and runner-up, gated at >= 0.72 with a >= 0.10 margin.
        let grounded =
            has_installer && (a - vtable::VT_GROUNDED_SCORE).abs() < 1e-9 && runner.abs() < 1e-9;
        if grounded {
            vt.grounded += 1;
        } else if a >= vtable::VT_STRUCT_MIN_AGREEMENT && a - runner >= vtable::VT_STRUCT_MIN_MARGIN
        {
            vt.structural += 1;
        } else {
            vt.declined += 1; // below the gate and not grounded: production would not emit this
            continue;
        }
        let re = enc(tg, r);
        if validate(tg, r) {
            vt.validated += 1;
        }
        let sim = idsim(rf, enc(rf, m), tg, re);
        vt.id_sum += sim;
        vt.id_n += 1;
        if sim < 0.30 {
            vt.id_below += 1;
        }
        if vt_rt_done < VT_RT_CAP {
            vt_rt_done += 1;
            match rt_vtable(tg, r, rf, enc(rf, m)) {
                1 => vt.rt_pass += 1,
                -1 => vt.rt_fail += 1,
                _ => vt.rt_inc += 1,
            }
        }
    }
    eprintln!(
        "vtable pass: {} made / {} pinned of {} sampled (of {} slot methods) in {:.0}s",
        vt.made,
        vt.structural + vt.grounded,
        vt_sample.len(),
        vt_methods.len(),
        t.elapsed().as_secs_f64()
    );

    // CHAIN: the shipped vtable reach is a widest-path chain through the intermediate builds. Report
    // how far it carries by counting, per build, how many subsampled methods it pins (it is expected
    // to carry within the lineage and decline at the genuine v95 class refactor).
    let t = std::time::Instant::now();
    const N_CHAIN: usize = 25;
    let cstep = (vt_sample.len() / N_CHAIN).max(1);
    let required: Vec<usize> = (0..chain.len()).collect();
    let mut chain_attempt = 0usize;
    let mut chain_reach = vec![0usize; chain.len()];
    for &m in vt_sample.iter().step_by(cstep).take(N_CHAIN) {
        chain_attempt += 1;
        let Some(cand) = vtable_relocate(&chain, &required, refi, m as u64, &opts) else {
            continue;
        };
        for (k, lbl) in labels.iter().enumerate() {
            if cand
                .per_version
                .iter()
                .any(|p| &p.label == lbl && p.match_rva.is_some())
            {
                chain_reach[k] += 1;
            }
        }
    }
    eprintln!(
        "chain pass: {chain_attempt} methods in {:.0}s",
        t.elapsed().as_secs_f64()
    );

    let pct = |n: usize, d: usize| {
        if d == 0 {
            "n/a".to_string()
        } else {
            format!("{:.0}%", 100.0 * n as f64 / d as f64)
        }
    };
    let mean = |sum: f64, n: usize| {
        if n == 0 {
            "n/a".to_string()
        } else {
            format!("{:.2}", sum / n as f64)
        }
    };
    let row = |name: &str, s: &Stats| {
        eprintln!(
            "  {name:<7} {:>5} {:>9} {:>7}   {:>6}   {:>3}/{:<3}/{:<3} {:>5}   {:>4}",
            s.made,
            s.resolved,
            s.validated,
            mean(s.id_sum, s.id_n),
            s.rt_pass,
            s.rt_fail,
            s.rt_inc,
            pct(s.rt_fail, s.rt_pass + s.rt_fail),
            s.id_below,
        );
    };
    eprintln!("\n=== cross-version relocation sweep: GMS v83 -> v95.1 ===");
    eprintln!(
        "  {:<7} {:>5} {:>9} {:>7}   {:>6}   {:>11} {:>5}   {:>4}",
        "anchor", "made", "resolved", "valid", "id-sim", "rt P/F/inc", "FP", "id<.3"
    );
    row("string", &s_str);
    row("import", &s_imp);
    row("constant", &s_const);
    row("caller", &s_cal);
    eprintln!(
        "  {:<7} {:>5} {:>9} {:>7}   {:>6}   {:>3}/{:<3}/{:<3} {:>5}   {:>4}",
        "vtable",
        vt.made,
        vt.structural + vt.grounded,
        vt.validated,
        mean(vt.id_sum, vt.id_n),
        vt.rt_pass,
        vt.rt_fail,
        vt.rt_inc,
        pct(vt.rt_fail, vt.rt_pass + vt.rt_fail),
        vt.id_below,
    );
    eprintln!(
        "    vtable detail: structural {}, constructor-grounded {}, declined {} (installer present on {} of {} made)",
        vt.structural, vt.grounded, vt.declined, vt.installer_present, vt.made
    );
    eprintln!(
        "  columns: made=anchorable, resolved/valid in v95.1, rt=round-trip back to v83 pass/fail/inconclusive, FP=fail/(pass+fail), id<.3=landings below 0.30 identity"
    );
    eprintln!(
        "  string FP note: round-trip re-uses the same string (near-tautological); its real wrong-address guard is the 2nd-string check below"
    );
    eprintln!(
        "  string corroboration (of {} resolved): {str_corrob} share a 2nd independent string (same-function confirmed); {str_single} share only the anchor string, of which {str_single_lowid} also have id<0.30 (the genuine wrong-address suspects)",
        s_str.resolved
    );
    eprintln!("chain reach (of {chain_attempt} subsampled vtable methods, pinned per build):");
    for (k, lbl) in labels.iter().enumerate() {
        eprintln!(
            "    {lbl:<6} {} ({})",
            chain_reach[k],
            pct(chain_reach[k], chain_attempt)
        );
    }
    eprintln!(
        "string reach (of {} v83 string anchors, resolved / validated per build):",
        s_str.made
    );
    for (k, lbl) in labels.iter().enumerate() {
        eprintln!(
            "    {lbl:<6} {:>3} resolved ({}), {:>3} validated",
            str_reach[k].0,
            pct(str_reach[k].0, s_str.made),
            str_reach[k].1,
        );
    }

    // Asserts guard that the harness exercised real anchors and that conclusive wrong-address rates
    // stay low; exact counts are corpus-dependent and printed above.
    assert!(
        s_str.validated > 0,
        "string anchor must validate on real GMS"
    );
    assert!(
        vt.structural + vt.grounded > 0,
        "the vtable anchor must pin some real virtual methods"
    );
    let fp_fail = s_imp.rt_fail + s_cal.rt_fail + vt.rt_fail;
    let fp_total =
        s_imp.rt_pass + s_imp.rt_fail + s_cal.rt_pass + s_cal.rt_fail + vt.rt_pass + vt.rt_fail;
    if fp_total >= 10 {
        assert!(
            fp_fail * 5 <= fp_total,
            "conclusive round-trip false positives must stay a small minority ({fp_fail}/{fp_total})"
        );
    }
}

// Grade calibration on the real corpus (run with `--ignored`): generate a cross-version signature
// for a sample of v83 functions, bucket the chosen candidate by its grade, and measure how often
// each grade's signature still uniquely matches a held-out build (leave-one-out). A well-calibrated
// grade ladder has A re-resolving more reliably than B, B than C, and so on. This is the measured
// evidence the scoring-methodology questions (PSE-5 correlated evidence, PSE-6 band cliff) need
// before any grade-changing recalibration: it quantifies whether the current grades predict
// cross-version survival, so a change can be shown to improve calibration rather than just move it.
#[test]
#[ignore = "needs the real GMS clients in X:\\Client_Unpacked; run with --ignored"]
#[allow(clippy::too_many_lines)]
fn scoring_grade_calibration_on_real_gms() {
    use crate::fileimage::FileImage;
    use std::collections::{BTreeMap, BTreeSet};
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
    let imgs: Vec<FileImage> = names
        .iter()
        .map(|n| FileImage::open(&dir.join(n)).unwrap())
        .collect();
    let labels = ["v83", "v84", "v88", "v91", "v95.1"];
    let inputs: Vec<ImageInput> = labels.iter().zip(&imgs).map(|(l, i)| mk(l, i)).collect();
    let opts = SigOptions::default();

    let rf = &inputs[0];
    let mut entries: BTreeSet<usize> = BTreeSet::new();
    for r in &rf.code_regions {
        let bytes = read_region(rf.source, r.base, r.size);
        for (i, w) in bytes.windows(5).enumerate() {
            if w[0] == 0xE8 {
                let rel = i32::from_le_bytes([w[1], w[2], w[3], w[4]]) as i64;
                let t = (r.base + i + 5) as i64 + rel - rf.base as i64;
                if t > 0x1000 && (t as usize) < rf.size {
                    entries.insert(t as usize);
                }
            }
        }
    }
    let entries: Vec<usize> = entries.into_iter().collect();
    const N: usize = 40;
    let step = (entries.len() / N).max(1);
    let sample: Vec<usize> = entries.iter().copied().step_by(step).take(N).collect();

    // Measure per-grade leave-one-out re-resolution over two spans. The full span includes the
    // v95.1 structural break, where byte signatures almost never survive, so it yields very few
    // gradeable signatures. The pre-break span (v83..v91) is the realistic relocation regime and
    // populates the grade range, which is what a recalibration needs. grade -> (signatures,
    // holdout builds generated, holdout builds re-resolved).
    let spans: [(&str, &[ImageInput]); 2] = [
        (
            "v83 -> v84/v88/v91/v95.1 (full, across the v95 break)",
            &inputs[..],
        ),
        ("v83 -> v84/v88/v91 (pre-break)", &inputs[..4]),
    ];
    let mut grand_total = 0usize;
    for (title, span) in spans {
        let mut by_grade: BTreeMap<char, (usize, usize, usize)> = BTreeMap::new();
        for &e in &sample {
            let spec = TargetSpec::Ref {
                image: 0,
                rva: e as u64,
            };
            let report = generate(span, &spec, &opts);
            let Some(chosen) = &report.chosen else {
                continue;
            };
            let hold = holdout_validate(span, &spec, &opts);
            let total = hold.iter().filter(|h| h.generated).count();
            let matched = hold.iter().filter(|h| h.matched_holdout).count();
            let entry = by_grade.entry(chosen.grade.letter()).or_default();
            entry.0 += 1;
            entry.1 += total;
            entry.2 += matched;
        }
        eprintln!(
            "\n=== grade calibration ({title}), {} sampled ===",
            sample.len()
        );
        eprintln!("  grade  sigs  holdout re-resolved");
        for (g, (n, tot, mat)) in &by_grade {
            let pct = if *tot == 0 {
                "n/a".to_string()
            } else {
                format!("{:.0}%", 100.0 * (*mat as f64) / (*tot as f64))
            };
            eprintln!("  {g}      {n:>4}  {mat}/{tot} ({pct})");
        }
        grand_total += by_grade.values().map(|v| v.0).sum::<usize>();
    }
    assert!(grand_total > 0, "expected at least one generated signature");
}
