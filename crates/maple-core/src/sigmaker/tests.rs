use super::*;
use crate::memory::{BufferSource, Region};

#[test]
fn single_string_relocation_across_a_major_gap_is_not_confirmed() {
    // Within a lineage the landings stay structurally close, so a lone string is confident.
    assert!(string_relocation_confirmed(false, Some(0.85)));
    assert!(
        string_relocation_confirmed(false, Some(0.30)),
        "at the floor still confirms"
    );
    // Across a major recompile the worst landing diverges; a lone string is NOT confident,
    // because the string may have migrated to a different function.
    assert!(!string_relocation_confirmed(false, Some(0.18)));
    // ...unless a second corroborating string pins it.
    assert!(string_relocation_confirmed(true, Some(0.18)));
    // A single build carries no cross-build evidence; the separate single-build cap governs it.
    assert!(string_relocation_confirmed(false, None));
}

#[test]
fn ensemble_vote_prefers_corroboration_and_flags_conflict() {
    use std::collections::HashMap;
    let m = |pairs: &[(&str, usize)]| -> HashMap<String, usize> {
        pairs.iter().map(|(l, f)| ((*l).to_string(), *f)).collect()
    };
    // Two channels land the target at function 0x100 in v95; one lands at 0x200 (a wrong address) and
    // is graded best (rank 0) to prove corroboration beats a better lone grade.
    let dissent = m(&[("v83", 0x10), ("v95", 0x200)]);
    let agree_a = m(&[("v83", 0x10), ("v95", 0x100)]);
    let agree_b = m(&[("v83", 0x10), ("v95", 0x100)]);
    let v = ensemble_decide(
        &[dissent.clone(), agree_a.clone(), agree_b.clone()],
        &[0, 1, 1],
    );
    assert_eq!(
        v.winner, 1,
        "the corroborated pair wins over the better-graded loner"
    );
    assert_eq!(v.support, 2);
    assert!(v.conflict, "the dissenter conflicts with the winner on v95");

    // A lone pair that disagrees: support 1 each, conflict, winner by grade (the dissenter, rank 0).
    let lone = ensemble_decide(&[agree_a.clone(), dissent.clone()], &[1, 0]);
    assert_eq!(v.support, 2);
    assert!(lone.conflict);
    assert_eq!(lone.support, 1);
    assert_eq!(lone.winner, 1);

    // No build in common: neither corroborates nor conflicts.
    let none = ensemble_decide(&[m(&[("v83", 0x10)]), m(&[("v95", 0x100)])], &[1, 1]);
    assert!(!none.conflict);
    assert_eq!(none.support, 1);
}

#[test]
fn ensemble_attaches_a_ledger_to_a_string_relocation() {
    // Two x86 builds whose target references one unique string but is recompiled so no cross-build
    // byte signature survives: the string anchor relocates it and the ensemble must attach a
    // structured ledger naming the channel (FP-neutral reporting).
    fn mk(src: &BufferSource, base: usize, hash: u64) -> ImageInput<'_> {
        ImageInput {
            label: format!("h{hash}"),
            source: src,
            base,
            size: 0x800,
            code_regions: vec![Region { base, size: 0x600 }],
            regions: vec![Region { base, size: 0x800 }],
            import: None,
            arch: Arch::X86,
            code_hash: hash,
            packed: false,
            pack_reasons: Vec::new(),
            reloc: None,
        }
    }
    const B: usize = 0x40_0000;
    let s = b"EnsembleLedgerUniqueAnchorString\0";
    let build = |body: &[u8]| -> Vec<u8> {
        let mut buf = vec![0u8; 0x800];
        let s_off = 0x600;
        buf[s_off..s_off + s.len()].copy_from_slice(s);
        let s_abs = (B + s_off) as u32;
        let mut f = vec![0x55u8, 0x8B, 0xEC, 0x68];
        f.extend_from_slice(&s_abs.to_le_bytes());
        f.extend_from_slice(body);
        f.extend_from_slice(&[0x5D, 0xC3]);
        buf[0x100..0x100 + f.len()].copy_from_slice(&f);
        buf
    };
    let a = BufferSource::new(B, build(&[0x33, 0xC0, 0x40]));
    let bb = BufferSource::new(B, build(&[0x8B, 0x45, 0x08, 0x48, 0x48]));
    let images = [mk(&a, B, 1), mk(&bb, B, 2)];
    let report = generate(
        &images,
        &TargetSpec::Ref {
            image: 0,
            rva: 0x100,
        },
        &SigOptions::default(),
    );
    let cand = report.chosen.expect("a relocation candidate");
    let led = cand
        .relocation
        .expect("a relocated candidate carries a ledger");
    assert_eq!(led.anchor, "string");
    assert!(led.support >= 1);
}

#[test]
fn relocation_anchors_fabricate_nothing_on_a_degenerate_x64_image() {
    // #12: all five anchors now operate on x64. The safety property is that a degenerate image
    // (nothing but padding, no real vtable / import / string / call structure) yields no anchor at
    // all, never a fabricated relocation. Each anchor's positive x64 behaviour is validated in its
    // own module; this locks the negative side on x64.
    let mem = BufferSource::new(0x1000, vec![0x90u8; 0x200]);
    let region = Region {
        base: 0x1000,
        size: 0x200,
    };
    let img = ImageInput {
        label: "x64".to_string(),
        source: &mem,
        base: 0x1000,
        size: 0x200,
        code_regions: vec![region],
        regions: vec![region],
        import: Some((0x1000, 0x1100)),
        arch: Arch::X64,
        code_hash: 0,
        packed: false,
        pack_reasons: Vec::new(),
        reloc: None,
    };
    assert!(vtable::make_vtable_anchor(&img, 0x1000).is_none());
    assert!(imports::make_import_anchor(&img, 0x1000).is_none());
    assert!(callers::make_caller_anchor(&img, 0x1000).is_none());
    assert!(encoding::best_encoding_match(&img, &[1, 2, 3]).is_none());
    assert!(make_string_anchor(&img, 0x1000).is_none());
}

#[test]
fn relocate_path_bridges_a_hop_through_an_intermediate_build() {
    // #14: the generic chainer must route through an intermediate build when the direct edge is
    // gated out. Three builds; the direct reference->last edge declines, but reference->mid and
    // mid->last are open, so the widest-path walk reaches the last build via the chain. Synthetic
    // make/edge closures exercise the walk independently of any real anchor: the anchor minted at a
    // build is that build's base, so `edge` can tell which build the hop starts from.
    let m0 = BufferSource::new(0x1000, vec![0u8; 1]);
    let m1 = BufferSource::new(0x2000, vec![0u8; 1]);
    let m2 = BufferSource::new(0x3000, vec![0u8; 1]);
    fn mk(base: usize, src: &BufferSource) -> ImageInput<'_> {
        ImageInput {
            label: String::new(),
            source: src,
            base,
            size: 1,
            code_regions: Vec::new(),
            regions: Vec::new(),
            import: None,
            arch: Arch::X86,
            code_hash: 0,
            packed: false,
            pack_reasons: Vec::new(),
            reloc: None,
        }
    }
    let images = vec![mk(0x1000, &m0), mk(0x2000, &m1), mk(0x3000, &m2)];
    let required = [1usize, 2];
    let make = |i: &ImageInput, _rva: usize| Some(i.base);
    let edge = |i: &ImageInput, anchor: &usize| match (*anchor, i.base) {
        (0x1000, 0x2000) => Some((0x10, 0.90)), // ref -> mid
        (0x2000, 0x3000) => Some((0x20, 0.80)), // mid -> last
        (0x1000, 0x3000) => None,               // ref -> last is gated; only the chain reaches it
        _ => None,
    };
    let located = relocate_path(&images, &required, 0, 0, make, edge);
    assert_eq!(
        located[1].map(|(rva, _)| rva),
        Some(0x10),
        "mid reached directly"
    );
    assert!(
        located[2].is_some(),
        "last build reached via the ref->mid->last chain"
    );
    // A path's confidence is its weakest hop: min(0.90, 0.80) = 0.80.
    assert!((located[2].unwrap().1 - 0.80).abs() < 1e-9);
}

#[test]
fn score_and_grade_agree_on_a_validated_candidate() {
    // A validated _CALL to code: its grade is read off final_score, the sub-scores are exposed,
    // and the backward-compatible `score` field mirrors final_score.
    let mut data = vec![0x48, 0x89, 0xE5, 0xC3];
    data.resize(0x20, 0x90);
    data.extend_from_slice(&[0xE8, 0xDB, 0xFF, 0xFF, 0xFF]);
    data.extend_from_slice(&[0x0F, 0xB6, 0xC0, 0x33, 0xC9]);
    data.resize(0x40, 0x90);
    let src = BufferSource::new(0x1000, data);
    let report = generate(
        &[img("a", &src, 0x1000, 0x40)],
        &TargetSpec::Ref { image: 0, rva: 0 },
        &SigOptions::default(),
    );
    let cand = report.chosen.expect("a candidate");
    assert_eq!(cand.grade, Grade::A);
    assert_eq!(cand.score, cand.scores.final_score);
    assert!(cand.scores.final_score >= 82);
    assert_eq!(
        Grade::from_final_score(cand.scores.final_score),
        Grade::A,
        "grade must be the band of final_score"
    );
    assert!(cand.scores.resolver_confidence >= 90);
    assert!(!cand.reasons.is_empty());
    // A cross-build byte signature is not a relocation, so it carries no ensemble ledger.
    assert!(cand.relocation.is_none());
}

struct ShortSource {
    base: usize,
    readable: usize,
}

impl MemorySource for ShortSource {
    fn read_into(&self, address: usize, buf: &mut [u8]) -> std::io::Result<usize> {
        let off = address - self.base;
        if off >= self.readable {
            return Ok(0);
        }
        let n = buf.len().min(self.readable - off);
        buf[..n].fill(0xCC);
        Ok(n)
    }
}

#[test]
fn reads_drop_the_unreadable_tail_instead_of_zero_filling() {
    let src = ShortSource {
        base: 0x4000,
        readable: 7,
    };
    let region = read_region(&src, 0x4000, 64);
    assert_eq!(
        region.len(),
        7,
        "tail past the readable range must be dropped"
    );
    assert!(region.iter().all(|&b| b == 0xCC));

    let at = read_at(&src, 0x4000, 0, 64);
    assert_eq!(at.len(), 7);
    assert!(at.iter().all(|&b| b == 0xCC));

    let none = read_at(&src, 0x4000, 7, 16);
    assert!(none.is_empty(), "a read starting past the range is empty");
}

#[test]
fn callee_fingerprint_is_register_invariant_but_mnemonic_sensitive() {
    let base = 0x2000;
    let a = BufferSource::new(base, vec![0x48, 0x89, 0xD8, 0xC3]); // mov rax, rbx ; ret
    let b = BufferSource::new(base, vec![0x48, 0x89, 0xD1, 0xC3]); // mov rcx, rdx ; ret
    let c = BufferSource::new(base, vec![0x48, 0x01, 0xD8, 0xC3]); // add rax, rbx ; ret
    let fa = fn_identity(&img("a", &a, base, 4), 0).fingerprint();
    let fb = fn_identity(&img("b", &b, base, 4), 0).fingerprint();
    let fc = fn_identity(&img("c", &c, base, 4), 0).fingerprint();
    assert_eq!(fa, fb, "register allocation must not change the identity");
    assert_ne!(
        fa, fc,
        "a different mnemonic stream must change the identity"
    );
}

fn img<'a>(label: &str, src: &'a BufferSource, base: usize, size: usize) -> ImageInput<'a> {
    ImageInput {
        label: label.to_string(),
        source: src,
        base,
        size,
        code_regions: vec![Region { base, size }],
        regions: vec![Region { base, size }],
        import: None,
        arch: Arch::X64,
        code_hash: super::super::stamp::BuildStamp::capture(src, base, &[Region { base, size }])
            .hash,
        packed: false,
        pack_reasons: Vec::new(),
        reloc: None,
    }
}

#[test]
fn collapse_aob_ranges_groups_builds_until_the_bytes_break() {
    // A and B carry the same bytes at the relocated address, C diverges: the first AOB must cover
    // A and B as one range, then a fresh AOB opens a new range at C.
    fn buf_with(pat: &[u8], at: usize) -> Vec<u8> {
        let mut b = vec![0u8; 0x100];
        b[at..at + pat.len()].copy_from_slice(pat);
        b
    }
    let dead = [0xDE, 0xAD, 0xBE, 0xEF];
    let cafe = [0xCA, 0xFE, 0xBA, 0xBE];
    let sa = BufferSource::new(0x1000, buf_with(&dead, 0x10));
    let sb = BufferSource::new(0x1000, buf_with(&dead, 0x20));
    let sc = BufferSource::new(0x1000, buf_with(&cafe, 0x30));
    let images = [
        img("A", &sa, 0x1000, 0x100),
        img("B", &sb, 0x1000, 0x100),
        img("C", &sc, 0x1000, 0x100),
    ];
    let pv = |label: &str, rva: u64, aob: &str| PerVersion {
        label: label.into(),
        match_rva: Some(rva),
        resolved_target_rva: Some(rva),
        target_kind: Some(TargetKind::Code),
        fingerprint_similarity: None,
        aob: Some(aob.into()),
    };
    let per_version = vec![
        pv("A", 0x10, "DE AD BE EF"),
        pv("B", 0x20, "DE AD BE EF"),
        pv("C", 0x30, "CA FE BA BE"),
    ];
    let ranges = collapse_aob_ranges(&images, &per_version, &[]);
    assert_eq!(ranges.len(), 2, "two ranges: A..B then C");
    assert_eq!(ranges[0].labels, ["A", "B"]);
    assert_eq!(ranges[0].aob, "DE AD BE EF");
    assert_eq!(ranges[1].labels, ["C"]);
    assert_eq!(ranges[1].aob, "CA FE BA BE");
}

#[test]
fn collapse_aob_ranges_breaks_on_an_unreached_build() {
    // A build with no relocated address breaks contiguity even if the bytes would have matched.
    let dead = [0xDEu8, 0xAD, 0xBE, 0xEF];
    let mut bytes = vec![0u8; 0x100];
    bytes[0x10..0x14].copy_from_slice(&dead);
    let s = BufferSource::new(0x1000, bytes);
    let images = [img("A", &s, 0x1000, 0x100), img("B", &s, 0x1000, 0x100)];
    let per_version = vec![
        PerVersion {
            label: "A".into(),
            match_rva: Some(0x10),
            resolved_target_rva: Some(0x10),
            target_kind: Some(TargetKind::Code),
            fingerprint_similarity: None,
            aob: Some("DE AD BE EF".into()),
        },
        PerVersion {
            label: "B".into(),
            match_rva: None,
            resolved_target_rva: None,
            target_kind: None,
            fingerprint_similarity: None,
            aob: None,
        },
    ];
    let ranges = collapse_aob_ranges(&images, &per_version, &[]);
    assert_eq!(ranges.len(), 1, "only the reached build forms a range");
    assert_eq!(ranges[0].labels, ["A"]);
}

// A small x64 blob with a rip-relative lea, a call rel32, then padding to make it unique.
fn blob(call_target: u32, tail: u8) -> Vec<u8> {
    let mut v = vec![
        0x48, 0x8D, 0x05, 0x11, 0x22, 0x33, 0x44, // lea rax,[rip+disp32]
        0xE8, 0x00, 0x00, 0x00, 0x00, // call rel32 (patched below)
        0x33, 0xC0, // xor eax,eax
        0xC3, // ret
    ];
    v[8..12].copy_from_slice(&call_target.to_le_bytes());
    v.push(tail);
    // pad so the region is long enough and the pattern stays unique
    v.extend_from_slice(&[0x90; 32]);
    v
}

#[test]
fn direct_generate_masks_operands_and_is_unique() {
    let a = BufferSource::new(0x1000, blob(0x10, 0xAA));
    let b = BufferSource::new(0x1000, blob(0x999, 0xAA)); // different call target only
    let ia = img("a", &a, 0x1000, 49);
    let ib = img("b", &b, 0x1000, 49);
    let report = generate(
        &[ia, ib],
        &TargetSpec::Ref { image: 0, rva: 0 },
        &SigOptions::default(),
    );
    let cand = report.chosen.expect("a candidate");
    assert_eq!(cand.suffix, Suffix::None);
    assert_eq!(cand.grade, Grade::B); // clean, reloc-safe, direct
    // the call rel32 (4 bytes) must be wildcarded
    assert!(cand.wildcards >= 4);
    assert!(cand.aob.contains("??"));
    assert!(cand.per_version.iter().all(|p| p.match_rva.is_some()));
    assert_eq!(cand.per_version.len(), 2);
}

#[test]
fn negative_corpus_flags_a_module_that_contains_the_signature() {
    let aob = "48 8D 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 C3";
    let contains = BufferSource::new(0x5000, blob(0x77, 0xCC));
    let clean = BufferSource::new(0x5000, vec![0x90u8; 64]);
    let negs = [
        img("contains", &contains, 0x5000, 49),
        img("clean", &clean, 0x5000, 64),
    ];
    let hits = negative_corpus_hits(aob, &negs);
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].label, "contains");
    assert!(hits[0].count >= 1);
}

#[test]
fn negative_corpus_is_empty_for_an_unrelated_module() {
    let aob = "48 8D 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 C3";
    let clean = BufferSource::new(0x5000, vec![0xCCu8; 128]);
    let negs = [img("clean", &clean, 0x5000, 128)];
    assert!(negative_corpus_hits(aob, &negs).is_empty());
}

#[test]
fn negative_corpus_ignores_an_unparseable_signature() {
    let clean = BufferSource::new(0x5000, vec![0x90u8; 64]);
    let negs = [img("clean", &clean, 0x5000, 64)];
    assert!(negative_corpus_hits("not a signature", &negs).is_empty());
}

#[test]
fn holdout_passes_when_the_signature_generalizes() {
    // Three builds of the same function, differing only in the masked call target. A signature
    // generated from any two must still uniquely match the third.
    let a = BufferSource::new(0x1000, blob(0x10, 0xAA));
    let b = BufferSource::new(0x1000, blob(0x20, 0xBB));
    let c = BufferSource::new(0x1000, blob(0x30, 0xCC));
    let images = [
        img("a", &a, 0x1000, 49),
        img("b", &b, 0x1000, 49),
        img("c", &c, 0x1000, 49),
    ];
    let aob = "48 8D 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 C3";
    let results = holdout_validate(
        &images,
        &TargetSpec::Aob(aob.to_string()),
        &SigOptions::default(),
    );
    assert_eq!(results.len(), 3);
    assert!(results.iter().all(|r| r.generated && r.matched_holdout));
}

#[test]
fn holdout_is_skipped_below_three_builds() {
    let a = BufferSource::new(0x1000, blob(0x10, 0xAA));
    let b = BufferSource::new(0x1000, blob(0x20, 0xBB));
    let images = [img("a", &a, 0x1000, 49), img("b", &b, 0x1000, 49)];
    let aob = "48 8D 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 C3";
    assert!(
        holdout_validate(
            &images,
            &TargetSpec::Aob(aob.to_string()),
            &SigOptions::default()
        )
        .is_empty()
    );
}

#[test]
fn fn_identity_captures_distinctive_constants() {
    let base = 0x4000;
    // mov eax, 0xDEADBEEF ; ret
    let src = BufferSource::new(base, vec![0xB8, 0xEF, 0xBE, 0xAD, 0xDE, 0xC3]);
    let id = fn_identity(&img("c", &src, base, 6), 0);
    assert!(
        id.constants.contains(&0xDEAD_BEEF),
        "got {:?}",
        id.constants
    );
    assert_eq!(id.returns, 1);
    // a small struct offset is not distinctive
    let small = BufferSource::new(base, vec![0x83, 0xC0, 0x08, 0xC3]); // add eax, 8 ; ret
    assert!(
        fn_identity(&img("s", &small, base, 4), 0)
            .constants
            .is_empty()
    );
}

#[test]
fn fn_identity_captures_string_references() {
    let base = 0x6000;
    // lea rax, [rip+9] ; ret ; pad ; "Hello\0" at rva 16
    let mut code = vec![0x48, 0x8D, 0x05, 0x09, 0x00, 0x00, 0x00, 0xC3];
    code.resize(16, 0x00);
    code.extend_from_slice(b"Hello\0");
    let src = BufferSource::new(base, code);
    let id = fn_identity(&img("str", &src, base, 22), 0);
    assert!(
        id.strings.iter().any(|s| s == "Hello"),
        "got {:?}",
        id.strings
    );
}

#[test]
fn build_profile_separates_arch_and_pack_lanes() {
    let src = BufferSource::new(0x1000, blob(0x10, 0xAA));
    let mut a = img("a", &src, 0x1000, 49);
    let mut b = img("b", &src, 0x1000, 49);
    assert!(BuildProfile::of(&a).same_variant(&BuildProfile::of(&b)));
    b.arch = Arch::X86;
    assert!(!BuildProfile::of(&a).same_variant(&BuildProfile::of(&b)));
    b.arch = Arch::X64;
    a.packed = true;
    assert!(!BuildProfile::of(&a).same_variant(&BuildProfile::of(&b)));
}

#[test]
fn xref_count_finds_rel32_calls() {
    let base = 0x10000;
    let mut code = vec![0x90u8; 0x80];
    for site in [0x10usize, 0x20] {
        code[site] = 0xE8;
        let rel = 0x40i32 - (site as i32 + 5);
        code[site + 1..site + 5].copy_from_slice(&rel.to_le_bytes());
    }
    let src = BufferSource::new(base, code);
    assert_eq!(xref_count(&img("x", &src, base, 0x80), 0x40), 2);
}

#[test]
fn string_anchor_locates_a_function_by_its_string() {
    let base = 0x1000;
    let mut mem = vec![0u8; 0x200];
    mem[0x10..0x1B].copy_from_slice(b"MapleStory\0");
    mem[0x100] = 0x68; // push imm32 of the string address
    mem[0x101..0x105].copy_from_slice(&0x1010u32.to_le_bytes());
    let src = BufferSource::new(base, mem);
    let input = ImageInput {
        label: "t".to_string(),
        source: &src,
        base,
        size: 0x200,
        code_regions: vec![Region {
            base: base + 0x100,
            size: 0x100,
        }],
        regions: vec![
            Region { base, size: 0x100 },
            Region {
                base: base + 0x100,
                size: 0x100,
            },
        ],
        import: None,
        arch: Arch::X86,
        code_hash: 0,
        packed: false,
        pack_reasons: Vec::new(),
        reloc: None,
    };
    let anchor = make_string_anchor(&input, 0x100).expect("a string anchor");
    assert_eq!(anchor.text, "MapleStory");
    assert_eq!(resolve_string_anchor(&input, &anchor), Some(0x101));
    assert!(
        resolve_string_anchor(
            &input,
            &StringAnchor {
                text: "absent".to_string(),
                also: None,
            }
        )
        .is_none()
    );
}

#[test]
fn string_anchor_collapses_repeats_to_the_x86_entry() {
    let base = 0x2000;
    let mut mem = vec![0u8; 0x300];
    mem[0x10..0x1B].copy_from_slice(b"DistinctStr");
    mem[0x100..0x103].copy_from_slice(&[0x55, 0x8B, 0xEC]); // push ebp ; mov ebp, esp
    for site in [0x110usize, 0x120] {
        mem[site] = 0x68; // push the same string address twice in one function
        mem[site + 1..site + 5].copy_from_slice(&0x2010u32.to_le_bytes());
    }
    let src = BufferSource::new(base, mem);
    let input = ImageInput {
        label: "t".to_string(),
        source: &src,
        base,
        size: 0x300,
        code_regions: vec![Region {
            base: base + 0x100,
            size: 0x200,
        }],
        regions: vec![
            Region { base, size: 0x100 },
            Region {
                base: base + 0x100,
                size: 0x200,
            },
        ],
        import: None,
        arch: Arch::X86,
        code_hash: 0,
        packed: false,
        pack_reasons: Vec::new(),
        reloc: None,
    };
    let anchor = make_string_anchor(&input, 0x110).expect("a string anchor");
    assert_eq!(resolve_string_anchor(&input, &anchor), Some(0x100));
}

#[test]
fn string_anchor_uses_a_pair_when_each_string_is_shared() {
    let base = 0x3000;
    let mut mem = vec![0u8; 0x200];
    mem[0x10..0x16].copy_from_slice(b"alpha\0");
    mem[0x20..0x25].copy_from_slice(b"beta\0");
    let push = |mem: &mut [u8], at: usize, addr: u32| {
        mem[at] = 0x68;
        mem[at + 1..at + 5].copy_from_slice(&addr.to_le_bytes());
    };
    for entry in [0x100usize, 0x140, 0x180] {
        mem[entry..entry + 3].copy_from_slice(&[0x55, 0x8B, 0xEC]);
    }
    push(&mut mem, 0x103, 0x3010); // F1 references alpha
    push(&mut mem, 0x108, 0x3020); // F1 references beta
    push(&mut mem, 0x143, 0x3010); // F2 references alpha
    push(&mut mem, 0x183, 0x3020); // F3 references beta
    let src = BufferSource::new(base, mem);
    let input = ImageInput {
        label: "t".to_string(),
        source: &src,
        base,
        size: 0x200,
        code_regions: vec![Region {
            base: base + 0x100,
            size: 0x100,
        }],
        regions: vec![
            Region { base, size: 0x100 },
            Region {
                base: base + 0x100,
                size: 0x100,
            },
        ],
        import: None,
        arch: Arch::X86,
        code_hash: 0,
        packed: false,
        pack_reasons: Vec::new(),
        reloc: None,
    };
    // neither string alone is unique, but only F1 references both
    let anchor = make_string_anchor(&input, 0x103).expect("a paired anchor");
    assert!(anchor.also.is_some());
    assert_eq!(resolve_string_anchor(&input, &anchor), Some(0x100));
}

#[test]
fn string_anchor_fallback_when_byte_aob_only_matches_one_build() {
    // Both builds hold the same function: an x86 prologue that pushes the address of a shared,
    // distinctive string. Their tails differ, so a byte AOB taken from the first build cannot be
    // made unique across both, and generation must fall back to the recompile-stable string
    // anchor instead of giving up.
    let build = |hash: u64, tail: [u8; 5]| {
        let mut mem = vec![0u8; 0x200];
        mem[0x10..0x1B].copy_from_slice(b"MapleStory\0");
        mem[0x100..0x103].copy_from_slice(&[0x55, 0x8B, 0xEC]); // push ebp ; mov ebp, esp
        mem[0x103] = 0x68; // push imm32 of the string address
        mem[0x104..0x108].copy_from_slice(&0x1010u32.to_le_bytes());
        mem[0x108..0x10D].copy_from_slice(&tail);
        (BufferSource::new(0x1000, mem), hash)
    };
    // the tails differ in the opcode byte, not just an immediate, so operand-masking the seed
    // AOB cannot reconcile the two builds and the byte path is forced to give up.
    let (a_src, a_hash) = build(1, [0xB8, 0xEF, 0xBE, 0xAD, 0xDE]); // mov eax, 0xDEADBEEF
    let (b_src, b_hash) = build(2, [0xB9, 0x11, 0x22, 0x33, 0x44]); // mov ecx, 0x44332211
    fn make_input<'a>(label: &str, src: &'a BufferSource, hash: u64) -> ImageInput<'a> {
        ImageInput {
            label: label.to_string(),
            source: src,
            base: 0x1000,
            size: 0x200,
            code_regions: vec![Region {
                base: 0x1100,
                size: 0x100,
            }],
            regions: vec![
                Region {
                    base: 0x1000,
                    size: 0x100,
                },
                Region {
                    base: 0x1100,
                    size: 0x100,
                },
            ],
            import: None,
            arch: Arch::X86,
            code_hash: hash,
            packed: false,
            pack_reasons: Vec::new(),
            reloc: None,
        }
    }
    let images = [
        make_input("a", &a_src, a_hash),
        make_input("b", &b_src, b_hash),
    ];
    // matches only build a: the DEADBEEF tail does not exist in build b
    let aob = "55 8B EC 68 10 10 00 00 B8 EF BE AD DE";
    let report = generate(
        &images,
        &TargetSpec::Aob(aob.to_string()),
        &SigOptions::default(),
    );
    let cand = report.chosen.expect("a string-anchor fallback candidate");
    assert!(
        cand.aob.starts_with("@string="),
        "expected a string anchor, got {}",
        cand.aob
    );
    assert_eq!(cand.aob, "@string=MapleStory");
    assert_eq!(cand.per_version.len(), 2);
    assert!(
        cand.per_version
            .iter()
            .all(|p| p.resolved_target_rva == Some(0x100))
    );
}

// A single x86 build holding "MapleStory" and a function that references it.
fn string_build() -> BufferSource {
    let mut mem = vec![0u8; 0x200];
    mem[0x10..0x1B].copy_from_slice(b"MapleStory\0");
    mem[0x100..0x103].copy_from_slice(&[0x55, 0x8B, 0xEC]); // push ebp ; mov ebp,esp
    mem[0x103] = 0x68; // push imm32 of the string address
    mem[0x104..0x108].copy_from_slice(&0x1010u32.to_le_bytes());
    mem[0x108] = 0xC3; // ret
    BufferSource::new(0x1000, mem)
}

fn string_img(src: &BufferSource, hash: u64) -> ImageInput<'_> {
    ImageInput {
        label: "a".to_string(),
        source: src,
        base: 0x1000,
        size: 0x200,
        code_regions: vec![Region {
            base: 0x1100,
            size: 0x100,
        }],
        regions: vec![
            Region {
                base: 0x1000,
                size: 0x100,
            },
            Region {
                base: 0x1100,
                size: 0x100,
            },
        ],
        import: None,
        arch: Arch::X86,
        code_hash: hash,
        packed: false,
        pack_reasons: Vec::new(),
        reloc: None,
    }
}

#[test]
fn string_anchor_single_build_is_capped_below_a() {
    // Validated against only one build, a string anchor cannot earn A: there is no cross-version
    // evidence, so it is capped and the reason is recorded.
    let src = string_build();
    let img = string_img(&src, 1);
    let cand = string_anchor_candidate(&[img], &[0], 0, 0x100, &SigOptions::default())
        .expect("a string anchor");
    assert!(cand.aob.starts_with("@string="));
    assert_ne!(cand.grade, Grade::A);
    assert!(cand.reasons.iter().any(|r| r.contains("one build")));
}

#[test]
fn string_anchor_consistent_across_builds_earns_a() {
    // Two builds whose referenced function is byte-identical: the anchor resolves consistently in
    // both, so it earns A and carries per-build similarity evidence.
    let a = string_build();
    let b = string_build();
    let cand = string_anchor_candidate(
        &[string_img(&a, 1), string_img(&b, 2)],
        &[0, 1],
        0,
        0x100,
        &SigOptions::default(),
    )
    .expect("a string anchor");
    assert_eq!(cand.grade, Grade::A);
    assert_eq!(cand.per_version.len(), 2);
    assert_eq!(cand.per_version[1].fingerprint_similarity, Some(1.0));
    assert!(cand.scores.cross_build >= 95);
}

#[test]
fn single_build_aob_mints_a_unique_operand_masked_pattern() {
    // A function with a volatile call/lea operand: the minted AOB masks the operand bytes and still
    // matches exactly once in the build.
    let src = BufferSource::new(0x1000, blob(0x1234, 0xAB));
    let image = img("x", &src, 0x1000, 49);
    let aob = single_build_aob(&image, 0, &SigOptions::default()).expect("an aob");
    assert!(
        aob.contains("??"),
        "the volatile operand should be wildcarded: {aob}"
    );
    let sig = crate::pattern::try_signature_from_aob(&aob).unwrap();
    let pat = CompiledPattern::new(&sig).unwrap();
    assert_eq!(
        CodeCache::build(&image).locate(&pat).0,
        1,
        "the minted AOB must be unique in the build"
    );
}

#[test]
fn string_anchor_mints_a_fresh_per_build_aob_when_bytes_differ() {
    // Two builds: the same function references the same unique string, but its bytes differ (a
    // recompile inserts `xor eax,eax`). A single cross-build byte AOB cannot match both, but the
    // string anchor relocates the function in each build and mints a build-specific AOB that
    // uniquely matches there. This is the "new AOB for the recompiled build" path.
    let mut a = vec![0u8; 0x200];
    a[0x10..0x1B].copy_from_slice(b"MapleStory\0");
    a[0x100..0x103].copy_from_slice(&[0x55, 0x8B, 0xEC]); // push ebp ; mov ebp,esp
    a[0x103] = 0x68; // push imm32 (string address)
    a[0x104..0x108].copy_from_slice(&0x1010u32.to_le_bytes());
    a[0x108] = 0xC3; // ret
    let mut b = vec![0u8; 0x200];
    b[0x10..0x1B].copy_from_slice(b"MapleStory\0");
    b[0x100..0x105].copy_from_slice(&[0x55, 0x8B, 0xEC, 0x33, 0xC0]); // + xor eax,eax
    b[0x105] = 0x68;
    b[0x106..0x10A].copy_from_slice(&0x1010u32.to_le_bytes());
    b[0x10A] = 0xC3;
    let sa = BufferSource::new(0x1000, a);
    let sb = BufferSource::new(0x1000, b);
    let cand = string_anchor_candidate(
        &[string_img(&sa, 1), string_img(&sb, 2)],
        &[0, 1],
        0,
        0x100,
        &SigOptions::default(),
    )
    .expect("a string anchor");
    let aob_a = cand.per_version[0]
        .aob
        .clone()
        .expect("per-build AOB for build A");
    let aob_b = cand.per_version[1]
        .aob
        .clone()
        .expect("per-build AOB for build B");
    assert_ne!(aob_a, aob_b, "a recompiled build must get its own AOB");
    let unique_in = |aob: &str, src: &BufferSource| {
        let sig = crate::pattern::try_signature_from_aob(aob).unwrap();
        let pat = CompiledPattern::new(&sig).unwrap();
        CodeCache::build(&string_img(src, 9)).locate(&pat).0
    };
    assert_eq!(unique_in(&aob_a, &sa), 1, "A's AOB matches A uniquely");
    assert_eq!(unique_in(&aob_b, &sb), 1, "B's AOB matches B uniquely");
    assert_eq!(
        unique_in(&aob_a, &sb),
        0,
        "A's AOB must NOT match the recompiled build B"
    );
}

// An x86 ImageInput over a raw buffer, for the shortlist test.
fn x86_img<'a>(
    label: &str,
    src: &'a BufferSource,
    base: usize,
    size: usize,
    hash: u64,
) -> ImageInput<'a> {
    ImageInput {
        label: label.to_string(),
        source: src,
        base,
        size,
        code_regions: vec![Region { base, size }],
        regions: vec![Region { base, size }],
        import: None,
        arch: Arch::X86,
        code_hash: hash,
        packed: false,
        pack_reasons: Vec::new(),
        reloc: None,
    }
}

#[test]
fn a_degenerate_repeated_function_yields_a_per_build_shortlist() {
    // A distinctive function repeated three times in each build: no unique byte AOB, no string or
    // import anchor, and the encoding/fingerprint paths tie three ways, so every confident path
    // declines. Instead of nothing, the engine returns a shortlist of the family for the other
    // build, the honest fallback for an anchor-less, structurally-degenerate target.
    let body = [
        0xB8, 0x11, 0x22, 0x33, 0x44, // mov eax, imm32
        0xBB, 0x55, 0x66, 0x77, 0x88, // mov ebx, imm32
        0x01, 0xD8, // add eax, ebx
        0x31, 0xC9, // xor ecx, ecx
        0x83, 0xC0, 0x10, // add eax, 0x10
        0xC3, // ret
    ];
    let image = |pad: u8| {
        let mut v = vec![0x90u8; 0x300];
        for &at in &[0x40usize, 0x120, 0x200] {
            v[at..at + body.len()].copy_from_slice(&body);
        }
        v[0x2F0] = pad; // differ so the two builds are distinct required inputs
        v
    };
    let a = BufferSource::new(0x1000, image(0xAA));
    let b = BufferSource::new(0x1000, image(0xBB));
    let report = generate(
        &[
            x86_img("a", &a, 0x1000, 0x300, 1),
            x86_img("b", &b, 0x1000, 0x300, 2),
        ],
        &TargetSpec::Ref {
            image: 0,
            rva: 0x40,
        },
        &SigOptions::default(),
    );
    assert!(
        report.chosen.is_none(),
        "an ambiguous repeated function cannot be pinned"
    );
    let sl = report
        .shortlists
        .iter()
        .find(|s| s.label == "b")
        .expect("a shortlist for build b");
    assert!(
        sl.entries.len() >= 2,
        "the degenerate family should list multiple candidates, got {}",
        sl.entries.len()
    );
    assert!(sl.entries.iter().all(|e| e.similarity >= 0.65));
}

#[test]
fn fingerprint_similarity_survives_a_volatile_immediate() {
    // The same function differing only in a non-distinctive immediate keeps identity 1.0 (the kind
    // of operand byte a signature masks must not perturb the fingerprint); a changed mnemonic
    // stream drops it below 1.
    let a = BufferSource::new(
        0x2000,
        vec![0x48, 0x89, 0xE5, 0xB8, 0x10, 0x00, 0x00, 0x00, 0xC3],
    );
    let b = BufferSource::new(
        0x2000,
        vec![0x48, 0x89, 0xE5, 0xB8, 0x20, 0x00, 0x00, 0x00, 0xC3],
    );
    let ia = fn_identity(&img("a", &a, 0x2000, 9), 0);
    let ib = fn_identity(&img("b", &b, 0x2000, 9), 0);
    assert!((ia.similarity(&ib) - 1.0).abs() < 1e-9);
    let c = BufferSource::new(
        0x2000,
        vec![0x48, 0x01, 0xE5, 0xB8, 0x10, 0x00, 0x00, 0x00, 0xC3],
    );
    let ic = fn_identity(&img("c", &c, 0x2000, 9), 0);
    assert!(ia.similarity(&ic) < 1.0);
}

#[test]
fn cross_validate_agrees_only_on_matching_rva() {
    let a = BufferSource::new(0x1000, blob(0x10, 0xAA));
    let b = BufferSource::new(0x1000, blob(0x999, 0xBB));
    let images = [img("a", &a, 0x1000, 49), img("b", &b, 0x1000, 49)];
    let aob = "48 8D 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 C3";

    let hit = generate_cross(&images, aob, 0, 0, &SigOptions::default());
    assert!(hit.report.chosen.is_some());
    assert_eq!(hit.matched_rva, Some(0));
    assert!(hit.agrees);

    let miss = generate_cross(&images, aob, 0, 0x40, &SigOptions::default());
    assert_eq!(miss.matched_rva, Some(0));
    assert!(!miss.agrees);
}

#[test]
fn duplicate_builds_collapse() {
    let a = BufferSource::new(0x1000, blob(0x10, 0xAA));
    let b = BufferSource::new(0x1000, blob(0x10, 0xAA)); // identical
    let c = BufferSource::new(0x1000, blob(0x55, 0xBB)); // different
    let report = generate(
        &[
            img("a", &a, 0x1000, 49),
            img("b", &b, 0x1000, 49),
            img("c", &c, 0x1000, 49),
        ],
        &TargetSpec::Ref { image: 0, rva: 0 },
        &SigOptions::default(),
    );
    assert_eq!(report.unique_builds, 2);
    assert_eq!(report.duplicate_groups.len(), 2);
}

#[test]
fn mixed_arch_is_rejected() {
    let a = BufferSource::new(0x1000, blob(0x10, 0xAA));
    let b = BufferSource::new(0x1000, blob(0x10, 0xAA));
    let mut ib = img("b", &b, 0x1000, 49);
    ib.arch = Arch::X86;
    let report = generate(
        &[img("a", &a, 0x1000, 49), ib],
        &TargetSpec::Ref { image: 0, rva: 0 },
        &SigOptions::default(),
    );
    assert!(report.chosen.is_none());
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| matches!(d, Diag::MixedArch))
    );
}

#[test]
fn packed_input_caps_grade_at_d() {
    let a = BufferSource::new(0x1000, blob(0x10, 0xAA));
    let b = BufferSource::new(0x1000, blob(0x999, 0xAA));
    let mut ia = img("a", &a, 0x1000, 49);
    ia.packed = true;
    ia.pack_reasons = vec!["test".into()];
    let report = generate(
        &[ia, img("b", &b, 0x1000, 49)],
        &TargetSpec::Ref { image: 0, rva: 0 },
        &SigOptions::default(),
    );
    assert_eq!(report.chosen.unwrap().grade, Grade::D);
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| matches!(d, Diag::PackedInput { .. }))
    );
}

#[test]
fn entry_a_hardens_an_existing_aob() {
    let a = BufferSource::new(0x1000, blob(0x10, 0xAA));
    let b = BufferSource::new(0x1000, blob(0x999, 0xAA));
    // the lea + call with the rel32 already wildcarded by the user
    let aob = "48 8D 05 11 22 33 44 E8 ?? ?? ?? ?? 33 C0 C3";
    let report = generate(
        &[img("a", &a, 0x1000, 49), img("b", &b, 0x1000, 49)],
        &TargetSpec::Aob(aob.to_string()),
        &SigOptions::default(),
    );
    let cand = report.chosen.expect("hardened candidate");
    assert_eq!(cand.per_version.len(), 2);
    assert!(cand.aob.contains("??"));
}

#[test]
fn deterministic_across_runs() {
    let a = BufferSource::new(0x1000, blob(0x10, 0xAA));
    let b = BufferSource::new(0x1000, blob(0x999, 0xAA));
    let run = || {
        generate(
            &[img("a", &a, 0x1000, 49), img("b", &b, 0x1000, 49)],
            &TargetSpec::Ref { image: 0, rva: 0 },
            &SigOptions::default(),
        )
        .chosen
        .unwrap()
        .aob
    };
    assert_eq!(run(), run());
}

struct FakeReloc {
    rva: usize,
    kind: RelocKind,
}
impl RelocLookup for FakeReloc {
    fn is_relocated(&self, rva: usize) -> bool {
        self.reloc_kind_at(rva).is_some()
    }
    fn reloc_kind_at(&self, rva: usize) -> Option<RelocKind> {
        let width = if matches!(self.kind, RelocKind::Dir64) {
            8
        } else {
            4
        };
        (rva >= self.rva && rva < self.rva + width).then_some(self.kind)
    }
}

#[test]
fn unsupported_reloc_in_window_is_rejected_with_real_rva() {
    let a = BufferSource::new(0x1000, blob(0x10, 0xAA));
    let fake = FakeReloc {
        rva: 0x1,
        kind: RelocKind::Unsupported(7),
    };
    let mut ia = img("a", &a, 0x1000, 49);
    ia.reloc = Some(&fake);
    let report = generate(
        &[ia],
        &TargetSpec::Ref { image: 0, rva: 0 },
        &SigOptions::default(),
    );
    assert!(report.chosen.is_none());
    let found = report.rejected.iter().flat_map(|c| &c.diags).any(|d| {
        matches!(
            d,
            Diag::UnsupportedReloc {
                rva: 0x1,
                reloc_type: 7
            }
        )
    });
    assert!(
        found,
        "expected an UnsupportedReloc diag carrying rva 0x1 and type 7"
    );
}

#[test]
fn call_anchor_is_discovered_and_validated() {
    // function at rva 0; a `call rva 0` at rva 0x20; sigmaker should prefer the validated _CALL.
    let mut data = vec![0x48, 0x89, 0xE5, 0xC3]; // mov rbp,rsp ; ret
    data.resize(0x20, 0x90);
    data.extend_from_slice(&[0xE8, 0xDB, 0xFF, 0xFF, 0xFF]); // call rva 0 (-0x25 from rva 0x25)
    data.extend_from_slice(&[0x0F, 0xB6, 0xC0, 0x33, 0xC9]); // movzx eax,al ; xor ecx,ecx
    data.resize(0x40, 0x90);
    let src = BufferSource::new(0x1000, data);
    let report = generate(
        &[img("a", &src, 0x1000, 0x40)],
        &TargetSpec::Ref { image: 0, rva: 0 },
        &SigOptions::default(),
    );
    let cand = report.chosen.expect("a candidate");
    assert_eq!(cand.suffix, Suffix::Call);
    assert_eq!(cand.grade, Grade::A);
    assert_eq!(cand.per_version[0].resolved_target_rva, Some(0));
    assert_eq!(cand.per_version[0].target_kind, Some(TargetKind::Code));
    assert!(cand.aob.starts_with("E8 ?? ?? ?? ??"));
}

#[test]
fn jmp_anchor_is_discovered() {
    let mut data = vec![0x48, 0x89, 0xE5, 0xC3]; // func at rva 0
    data.resize(0x20, 0x90);
    data.extend_from_slice(&[0xE9, 0xDB, 0xFF, 0xFF, 0xFF]); // jmp rva 0
    data.extend_from_slice(&[0x0F, 0xB6, 0xC0, 0x33, 0xC9]);
    data.resize(0x40, 0x90);
    let src = BufferSource::new(0x1000, data);
    let report = generate(
        &[img("a", &src, 0x1000, 0x40)],
        &TargetSpec::Ref { image: 0, rva: 0 },
        &SigOptions::default(),
    );
    let cand = report.chosen.expect("a candidate");
    assert_eq!(cand.suffix, Suffix::Jmp);
    assert_eq!(cand.grade, Grade::A);
    assert_eq!(cand.per_version[0].resolved_target_rva, Some(0));
    assert!(cand.aob.starts_with("E9 ?? ?? ?? ??"));
}

#[test]
fn branch_target_outside_code_is_downgraded() {
    // call at rva 0 (in code) targets rva 0x200, which is outside the declared code region.
    let mut data = vec![0xE8, 0xFB, 0x01, 0x00, 0x00, 0x0F, 0xB6, 0xC0, 0x33, 0xC9]; // call 0x200
    data.resize(0x210, 0x90);
    let src = BufferSource::new(0x1000, data);
    let regions = vec![Region {
        base: 0x1000,
        size: 0x40,
    }];
    let input = ImageInput {
        label: "a".to_string(),
        source: &src,
        base: 0x1000,
        size: 0x210,
        code_hash: super::super::stamp::BuildStamp::capture(&src, 0x1000, &regions).hash,
        regions: regions.clone(),
        code_regions: regions,
        import: None,
        arch: Arch::X64,
        packed: false,
        pack_reasons: Vec::new(),
        reloc: None,
    };
    let report = generate(
        &[input],
        &TargetSpec::Ref {
            image: 0,
            rva: 0x200,
        },
        &SigOptions::default(),
    );
    let cand = report.chosen.expect("a candidate");
    assert_eq!(cand.suffix, Suffix::Call);
    assert_eq!(cand.grade, Grade::C);
    assert_eq!(cand.per_version[0].target_kind, Some(TargetKind::Unknown));
    assert!(
        cand.diags
            .iter()
            .any(|d| matches!(d, Diag::TargetNotCode { .. }))
    );
}

#[test]
fn ptr_anchor_rip_relative_is_discovered() {
    // a `lea rax, [rip+func]` referencing the function at rva 0 should win as a validated _PTR.
    let mut data = vec![0x48, 0x89, 0xE5, 0xC3]; // func at rva 0
    data.resize(0x20, 0x90);
    data.extend_from_slice(&[0x48, 0x8D, 0x05, 0xD9, 0xFF, 0xFF, 0xFF]); // lea rax,[rip+rva 0]
    data.extend_from_slice(&[0x0F, 0xB6, 0xC0, 0x33, 0xC9]);
    data.resize(0x40, 0x90);
    let src = BufferSource::new(0x1000, data);
    let report = generate(
        &[img("a", &src, 0x1000, 0x40)],
        &TargetSpec::Ref { image: 0, rva: 0 },
        &SigOptions::default(),
    );
    let cand = report.chosen.expect("a candidate");
    assert_eq!(cand.suffix, Suffix::Ptr);
    assert_eq!(cand.grade, Grade::A);
    assert_eq!(cand.per_version[0].resolved_target_rva, Some(0));
    assert_eq!(cand.per_version[0].target_kind, Some(TargetKind::Code));
    assert!(cand.aob.starts_with("48 8D 05 ?? ?? ?? ??"));
}

fn custom_img<'a>(
    src: &'a BufferSource,
    base: usize,
    code: Vec<Region>,
    regions: Vec<Region>,
    arch: Arch,
) -> ImageInput<'a> {
    ImageInput {
        label: "a".to_string(),
        source: src,
        base,
        size: 0x10000,
        code_hash: super::super::stamp::BuildStamp::capture(src, base, &code).hash,
        code_regions: code,
        regions,
        import: None,
        arch,
        packed: false,
        pack_reasons: Vec::new(),
        reloc: None,
    }
}

#[test]
fn ptr_to_data_is_not_grade_a() {
    // RIP-relative `mov rax,[rip+data]` into a data region: resolved + kind-stable, but its
    // content is not validated, so it must be graded B (not A) on kind-consistency alone.
    let mut data = vec![0x48, 0x89, 0xE5, 0xC3];
    data.resize(0x20, 0x90);
    // mov rax,[rip+0x3000] at abs 0x1020: disp = 0x3000 - 0x1027 = 0x1FD9
    data.extend_from_slice(&[0x48, 0x8B, 0x05, 0xD9, 0x1F, 0x00, 0x00]);
    data.extend_from_slice(&[0x0F, 0xB6, 0xC0, 0x33, 0xC9]);
    data.resize(0x40, 0x90);
    let src = BufferSource::new(0x1000, data);
    let input = custom_img(
        &src,
        0x1000,
        vec![Region {
            base: 0x1000,
            size: 0x100,
        }],
        vec![
            Region {
                base: 0x1000,
                size: 0x100,
            },
            Region {
                base: 0x3000,
                size: 0x100,
            },
        ],
        Arch::X64,
    );
    let report = generate(
        &[input],
        &TargetSpec::Ref {
            image: 0,
            rva: 0x2000,
        },
        &SigOptions::default(),
    );
    let cand = report.chosen.expect("a candidate");
    assert_eq!(cand.suffix, Suffix::Ptr);
    assert_eq!(cand.grade, Grade::B);
    assert_eq!(cand.per_version[0].target_kind, Some(TargetKind::Data));
    assert_eq!(cand.per_version[0].resolved_target_rva, Some(0x2000));
}

#[test]
fn ptr_to_unknown_is_grade_c() {
    let mut data = vec![0x48, 0x89, 0xE5, 0xC3];
    data.resize(0x20, 0x90);
    // mov rax,[rip+0x6000]: target outside every region -> Unknown
    data.extend_from_slice(&[0x48, 0x8B, 0x05, 0xD9, 0x4F, 0x00, 0x00]);
    data.extend_from_slice(&[0x0F, 0xB6, 0xC0, 0x33, 0xC9]);
    data.resize(0x40, 0x90);
    let src = BufferSource::new(0x1000, data);
    let code = vec![Region {
        base: 0x1000,
        size: 0x100,
    }];
    let input = custom_img(&src, 0x1000, code.clone(), code, Arch::X64);
    let report = generate(
        &[input],
        &TargetSpec::Ref {
            image: 0,
            rva: 0x5000,
        },
        &SigOptions::default(),
    );
    let cand = report.chosen.expect("a candidate");
    assert_eq!(cand.suffix, Suffix::Ptr);
    assert_eq!(cand.grade, Grade::C);
    assert_eq!(cand.per_version[0].target_kind, Some(TargetKind::Unknown));
}

#[test]
fn x86_absolute_ptr_is_capped_below_a() {
    // 32-bit absolute `mov eax,[0x400000]` referencing the function at rva 0; absolute is never A.
    let mut data = vec![0x55, 0x8B, 0xEC, 0xC3]; // push ebp ; mov ebp,esp ; ret
    data.resize(0x20, 0x90);
    data.extend_from_slice(&[0x8B, 0x05, 0x00, 0x00, 0x40, 0x00]); // mov eax,[0x400000]
    data.extend_from_slice(&[0x0F, 0xB6, 0xC0, 0x33, 0xC9]);
    data.resize(0x40, 0x90);
    let src = BufferSource::new(0x40_0000, data);
    let code = vec![Region {
        base: 0x40_0000,
        size: 0x40,
    }];
    let input = custom_img(&src, 0x40_0000, code.clone(), code, Arch::X86);
    let report = generate(
        &[input],
        &TargetSpec::Ref { image: 0, rva: 0 },
        &SigOptions::default(),
    );
    let ptr = report
        .chosen
        .iter()
        .chain(&report.alternates)
        .chain(&report.rejected)
        .find(|c| c.suffix == Suffix::Ptr)
        .expect("a ptr candidate");
    assert_ne!(ptr.grade, Grade::A);
    assert_eq!(ptr.grade, Grade::C);
}

#[test]
fn ptr_across_two_nonduplicate_builds() {
    let make = |imm: u32| {
        let mut d = vec![0x48, 0x89, 0xE5, 0xC3]; // func at rva 0
        d.resize(0x10, 0x90);
        d.push(0xB8);
        d.extend_from_slice(&imm.to_le_bytes());
        d.resize(0x20, 0x90);
        d.extend_from_slice(&[0x48, 0x8D, 0x05, 0xD9, 0xFF, 0xFF, 0xFF]); // lea rax,[rip+rva 0]
        d.extend_from_slice(&[0x0F, 0xB6, 0xC0, 0x33, 0xC9]);
        d.resize(0x40, 0x90);
        d
    };
    let a = BufferSource::new(0x1000, make(0x1111_1111));
    let b = BufferSource::new(0x1000, make(0x2222_2222));
    let report = generate(
        &[img("a", &a, 0x1000, 0x40), img("b", &b, 0x1000, 0x40)],
        &TargetSpec::Ref { image: 0, rva: 0 },
        &SigOptions::default(),
    );
    assert_eq!(report.unique_builds, 2);
    let cand = report.chosen.expect("a candidate");
    assert_eq!(cand.suffix, Suffix::Ptr);
    assert_eq!(cand.grade, Grade::A);
    assert_eq!(cand.per_version.len(), 2);
    assert!(
        cand.per_version
            .iter()
            .all(|p| p.resolved_target_rva == Some(0) && p.target_kind == Some(TargetKind::Code))
    );
}

#[test]
fn e8_inside_an_immediate_is_not_a_branch_site() {
    // `mov rax, 0x0000_00FF_FFFF_E9E8`, whose immediate (E8 E9 FF FF FF ...) decodes as
    // `call rva 0` if scanned from the middle, but the E8 is not an instruction boundary, so
    // linear disassembly must never treat it as a call site.
    let mut data = vec![0x48, 0x89, 0xE5, 0xC3]; // func at rva 0
    data.resize(0x10, 0x90);
    data.extend_from_slice(&[0x48, 0xB8, 0xE8, 0xE9, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00]);
    data.resize(0x40, 0x90);
    let src = BufferSource::new(0x1000, data);
    // sanity: the embedded bytes really would decode as `call rva 0` mid-stream
    assert_eq!(
        decode_rel_target(&[0xE8, 0xE9, 0xFF, 0xFF, 0xFF], 0x1012),
        Some(0x1000)
    );
    let report = generate(
        &[img("a", &src, 0x1000, 0x40)],
        &TargetSpec::Ref { image: 0, rva: 0 },
        &SigOptions::default(),
    );
    let any_branch = report
        .chosen
        .iter()
        .chain(report.alternates.iter())
        .chain(report.rejected.iter())
        .any(|c| c.suffix != Suffix::None);
    assert!(
        !any_branch,
        "a mid-instruction E8 must not be accepted as a branch site"
    );
    assert_eq!(
        report.chosen.expect("direct candidate").suffix,
        Suffix::None
    );
}

#[test]
fn call_anchor_across_two_nonduplicate_builds() {
    // identical call + callee, but a differing `mov eax, imm` makes the two builds non-duplicate.
    let make = |imm: u32| {
        let mut d = vec![0x48, 0x89, 0xE5, 0xC3];
        d.resize(0x10, 0x90);
        d.push(0xB8);
        d.extend_from_slice(&imm.to_le_bytes());
        d.resize(0x20, 0x90);
        d.extend_from_slice(&[0xE8, 0xDB, 0xFF, 0xFF, 0xFF]); // call rva 0
        d.extend_from_slice(&[0x0F, 0xB6, 0xC0, 0x33, 0xC9]);
        d.resize(0x40, 0x90);
        d
    };
    let a = BufferSource::new(0x1000, make(0x1111_1111));
    let b = BufferSource::new(0x1000, make(0x2222_2222));
    let report = generate(
        &[img("a", &a, 0x1000, 0x40), img("b", &b, 0x1000, 0x40)],
        &TargetSpec::Ref { image: 0, rva: 0 },
        &SigOptions::default(),
    );
    assert_eq!(report.unique_builds, 2);
    let cand = report.chosen.expect("a candidate");
    assert_eq!(cand.suffix, Suffix::Call);
    assert_eq!(cand.grade, Grade::A);
    assert_eq!(cand.per_version.len(), 2);
    assert!(
        cand.per_version
            .iter()
            .all(|p| p.resolved_target_rva == Some(0))
    );
}

#[test]
fn deterministic_when_direct_and_call_both_pass() {
    let mut data = vec![0x48, 0x89, 0xE5, 0xC3];
    data.resize(0x20, 0x90);
    data.extend_from_slice(&[0xE8, 0xDB, 0xFF, 0xFF, 0xFF]);
    data.extend_from_slice(&[0x0F, 0xB6, 0xC0, 0x33, 0xC9]);
    data.resize(0x40, 0x90);
    let src = BufferSource::new(0x1000, data);
    let run = || {
        let r = generate(
            &[img("a", &src, 0x1000, 0x40)],
            &TargetSpec::Ref { image: 0, rva: 0 },
            &SigOptions::default(),
        );
        (r.chosen.unwrap().aob, r.alternates.len())
    };
    let first = run();
    assert_eq!(first, run());
    assert!(
        first.1 >= 1,
        "the direct candidate should remain as an alternate"
    );
}

#[test]
fn invalid_aob_is_reported_not_silently_dropped() {
    let a = BufferSource::new(0x1000, blob(0x10, 0xAA));
    let report = generate(
        &[img("a", &a, 0x1000, 49)],
        &TargetSpec::Aob("48 ZZ C3".to_string()),
        &SigOptions::default(),
    );
    assert!(report.chosen.is_none());
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| matches!(d, Diag::InvalidAob { .. }))
    );
}

// An x86 image (0x400 bytes) modelling a recompile: the target function is placed at `entry`,
// reached by a `call` from a per-build offset, surrounded by per-build filler. The two builds use
// DIFFERENT instruction encodings of the SAME mnemonic stream (`recompiled` picks the alternate
// encoding of mov/add/xor reg,reg), exactly as a recompiler does, so the opcode bytes differ and no
// byte AOB (direct, branch, or pointer) can stay fixed across both, while the mnemonic-level
// identity is preserved. With no string to anchor on either, this forces the fingerprint fallback.
fn fp_image(entry: usize, seed: u8, call_from: usize, recompiled: bool) -> Vec<u8> {
    // Distinct filler per build so direct/branch/ptr byte windows cannot reconcile across builds.
    let mut mem: Vec<u8> = (0..0x400u32).map(|i| (i as u8) ^ seed).collect();
    // A frame prologue appearing in the filler by accident would add a competing candidate; scrub
    // any 55 8B EC / 55 89 E5 the xor pattern happens to produce.
    for i in 0..mem.len().saturating_sub(2) {
        let w = &mem[i..i + 3];
        if w[0] == 0x55 && ((w[1] == 0x8B && w[2] == 0xEC) || (w[1] == 0x89 && w[2] == 0xE5)) {
            mem[i] = 0x90;
        }
    }
    // call rel32 -> entry, so the entry is an enumerated candidate.
    mem[call_from] = 0xE8;
    let rel = entry as i32 - (call_from as i32 + 5);
    mem[call_from + 1..call_from + 5].copy_from_slice(&rel.to_le_bytes());
    // push ebp ; mov ebp,esp ; mov eax,imm32 ; add eax,ecx ; xor edx,edx ; imul eax,ebx
    //          ; pop ebp ; ret  -- build B uses the alternate encoding of the reg,reg ops.
    let (mov_ee, add, xor): ([u8; 2], [u8; 2], [u8; 2]) = if recompiled {
        ([0x89, 0xE5], [0x03, 0xC1], [0x33, 0xD2]) // mov/add/xor, alternate encodings
    } else {
        ([0x8B, 0xEC], [0x01, 0xC8], [0x31, 0xD2])
    };
    let body = &mut mem[entry..];
    body[0] = 0x55; // push ebp
    body[1..3].copy_from_slice(&mov_ee); // mov ebp, esp
    body[3] = 0xB8; // mov eax, imm32 -- a genuine magic constant the recompile preserves
    body[4..8].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
    body[8..10].copy_from_slice(&add); // add eax, ecx
    body[10..12].copy_from_slice(&xor); // xor edx, edx
    body[12..15].copy_from_slice(&[0x0F, 0xAF, 0xC3]); // imul eax, ebx
    body[15] = 0x5D; // pop ebp
    body[16] = 0xC3; // ret
    mem
}

fn fp_input<'a>(label: &str, src: &'a BufferSource, hash: u64) -> ImageInput<'a> {
    ImageInput {
        label: label.to_string(),
        source: src,
        base: 0x1000,
        size: 0x400,
        code_regions: vec![Region {
            base: 0x1000,
            size: 0x400,
        }],
        regions: vec![Region {
            base: 0x1000,
            size: 0x400,
        }],
        import: None,
        arch: Arch::X86,
        code_hash: hash,
        packed: false,
        pack_reasons: Vec::new(),
        reloc: None,
    }
}

#[test]
fn fingerprint_relocates_a_recompiled_function_when_bytes_and_strings_fail() {
    // Two builds of the same function differing only in operand bytes (a different immediate, here
    // also a different opcode tail so the byte AOB genuinely cannot be hardened), with no string to
    // anchor on. The byte and string paths must fail and the fingerprint fallback must relocate the
    // function in both builds and emit a candidate.
    let a = BufferSource::new(0x1000, fp_image(0x40, 0x11, 0x10, false));
    let b = BufferSource::new(0x1000, fp_image(0x120, 0x22, 0x90, true));
    let images = [fp_input("a", &a, 1), fp_input("b", &b, 2)];
    // This synthetic carries a rare constant, so the end-to-end ensemble relocates it via the more
    // precise constant anchor; assert that holds, then exercise the fingerprint path (this test's
    // subject) by calling it directly, since the ensemble would otherwise hide it behind the constant.
    assert!(
        generate(
            &images,
            &TargetSpec::Ref {
                image: 0,
                rva: 0x40
            },
            &SigOptions::default(),
        )
        .chosen
        .is_some(),
        "the ensemble must relocate the recompiled function"
    );
    let cand = fingerprint_relocate(&images, &[0usize, 1], 0, 0x40, &SigOptions::default())
        .expect("the fingerprint anchor relocates the recompiled function");
    assert!(
        cand.aob.starts_with("@fingerprint="),
        "expected a fingerprint anchor, got {}",
        cand.aob
    );
    assert_eq!(cand.per_version.len(), 2);
    // Each build relocates into its own copy of the function (the recompile moved it). A
    // sliding-window relocation lands on the best-scoring boundary, which may be an instruction or
    // two inside the entry, so assert membership in the function extent rather than the exact byte.
    let in_fn_a = (0x40..0x40 + 17).contains(&(cand.per_version[0].match_rva.unwrap() as usize));
    let in_fn_b = (0x120..0x120 + 17).contains(&(cand.per_version[1].match_rva.unwrap() as usize));
    assert!(
        in_fn_a && in_fn_b,
        "both builds should relocate into the function body, got {:?} and {:?}",
        cand.per_version[0].match_rva,
        cand.per_version[1].match_rva
    );
    // The second build carries the cross-build similarity to the reference.
    assert!(
        cand.per_version[1]
            .fingerprint_similarity
            .is_some_and(|s| s >= FP_MIN_MUTUAL),
        "cross-build similarity should be high, got {:?}",
        cand.per_version[1].fingerprint_similarity
    );
    // Semantic-only: never better than B, and clearly weaker than a byte/string anchor.
    assert!(
        cand.grade.rank() >= Grade::B.rank(),
        "a fingerprint-only relocation must not grade A, got {:?}",
        cand.grade
    );
    assert!(cand.reasons.iter().any(|r| r.contains("fingerprint")));
}

// An x86 image whose only function (entry 0x120, reached by a call) is unrelated to the reference:
// a different mnemonic stream and a different magic constant, so nothing in it should fingerprint
// as the reference function.
fn fp_unrelated_image(seed: u8) -> Vec<u8> {
    let mut mem: Vec<u8> = (0..0x400u32).map(|i| (i as u8) ^ seed).collect();
    for i in 0..mem.len().saturating_sub(2) {
        let w = &mem[i..i + 3];
        if w[0] == 0x55 && ((w[1] == 0x8B && w[2] == 0xEC) || (w[1] == 0x89 && w[2] == 0xE5)) {
            mem[i] = 0x90;
        }
    }
    mem[0x90] = 0xE8;
    let rel = 0x120i32 - (0x90 + 5);
    mem[0x91..0x95].copy_from_slice(&rel.to_le_bytes());
    // push ebp ; mov ebp,esp ; cmp eax, imm32 ; jne $+2 ; inc ecx ; not edx ; leave ; ret
    let body = &mut mem[0x120..];
    body[0..3].copy_from_slice(&[0x55, 0x8B, 0xEC]);
    body[3] = 0x3D; // cmp eax, imm32
    body[4..8].copy_from_slice(&0x0BAD_F00Du32.to_le_bytes()); // a different magic constant
    body[8..10].copy_from_slice(&[0x75, 0x00]); // jne $+2
    body[10] = 0x41; // inc ecx
    body[11..13].copy_from_slice(&[0xF7, 0xD2]); // not edx
    body[13] = 0xC9; // leave
    body[14] = 0xC3; // ret
    mem
}

#[test]
fn fingerprint_relocate_declines_when_the_function_is_absent_in_a_build() {
    // The reference function exists in build A but build B holds only an unrelated function (a
    // different mnemonic stream and a different magic constant). No confident, consistent
    // relocation exists, so the fallback must decline rather than emit a wrong RVA, and generation
    // reports no signature.
    let a = BufferSource::new(0x1000, fp_image(0x40, 0x11, 0x10, false));
    let b = BufferSource::new(0x1000, fp_unrelated_image(0x22));
    let report = generate(
        &[fp_input("a", &a, 1), fp_input("b", &b, 2)],
        &TargetSpec::Ref {
            image: 0,
            rva: 0x40,
        },
        &SigOptions::default(),
    );
    assert!(
        report.chosen.is_none(),
        "an inconsistent relocation must not be emitted, got {:?}",
        report.chosen.map(|c| c.aob)
    );
}

#[test]
fn fingerprint_relocate_declines_for_a_too_thin_function() {
    // A 1-instruction function (just `ret`) carries no distinguishing shape, so the fallback must
    // refuse to fingerprint it rather than relocate on a single mnemonic that matches everywhere.
    let mut bytes_a = vec![0u8; 0x80];
    bytes_a[0x10] = 0xE8;
    let rel = 0x40i32 - (0x10 + 5);
    bytes_a[0x11..0x15].copy_from_slice(&rel.to_le_bytes());
    bytes_a[0x40] = 0xC3; // ret
    let mut bytes_b = bytes_a.clone();
    bytes_b[0x20] = 0x90;
    let a = BufferSource::new(0x1000, bytes_a);
    let b = BufferSource::new(0x1000, bytes_b);
    let ia = fp_input("a", &a, 1);
    let ib = fp_input("b", &b, 2);
    assert!(
        fingerprint_relocate(&[ia, ib], &[0, 1], 0, 0x40, &SigOptions::default()).is_none(),
        "a 1-instruction function is too thin to relocate by fingerprint"
    );
}

#[test]
fn best_fingerprint_match_is_x86_only() {
    // The candidate enumeration relies on x86 prologue/call shape; on x64 it must report nothing
    // rather than scan with the wrong assumptions.
    let src = BufferSource::new(0x1000, blob(0x10, 0xAA));
    let mut x64 = img("x", &src, 0x1000, 49);
    x64.arch = Arch::X64;
    let reference = fn_identity(&x64, 0);
    assert!(best_fingerprint_match(&x64, &reference).is_none());
}

#[test]
fn fingerprint_relocate_is_not_tried_when_a_byte_signature_succeeds() {
    // When the byte path already produces a candidate, the fingerprint fallback must not run: the
    // chosen signature is a real AOB, not an @fingerprint anchor.
    let a = BufferSource::new(0x1000, blob(0x10, 0xAA));
    let b = BufferSource::new(0x1000, blob(0x999, 0xBB));
    let report = generate(
        &[img("a", &a, 0x1000, 49), img("b", &b, 0x1000, 49)],
        &TargetSpec::Ref { image: 0, rva: 0 },
        &SigOptions::default(),
    );
    let cand = report.chosen.expect("a byte candidate");
    assert!(!cand.aob.starts_with("@fingerprint="));
}
