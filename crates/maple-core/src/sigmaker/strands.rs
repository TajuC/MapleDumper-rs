//! Static data-flow "strand" similarity (Phase 8): match two functions by WHAT they compute, not how the
//! bytes or registers happen to be laid out. This is the static, execution-free core of the Esh idea
//! (David, Partush, Yahav, *Statistical Similarity of Binaries*, PLDI 2016): a recompile reorders blocks,
//! reallocates registers, and rewrites instruction encodings, but the *computation* a function performs is
//! source-determined and survives. So each output value (a memory store, a call, the return value) is
//! hashed by the data-flow that produced it: an instruction's value-hash folds its mnemonic with the
//! value-hashes of the inputs feeding it, recursively, so the register names and the instruction order
//! drop out and only the shape of the computation remains. Two functions that compute the same outputs
//! through different register allocations or block orderings share strand hashes; different computations
//! do not.
//!
//! This is the most order/encoding-robust channel: where the byte AOB, the encoding fingerprint, and even
//! the mnemonic stream all desynchronise at a true recompile, the data-flow shape does not. It is gated
//! and measured before it would join the default decision path; this module is the algorithm plus its
//! synthetic correctness tests, exercised without a real image.

use std::collections::{BTreeSet, HashMap};

use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Instruction, InstructionInfoFactory, OpAccess, Register,
};

use super::types::ImageInput;
use super::{bitness, read_at};

const STRAND_MAX_INSTRS: usize = 80;
const STRAND_WINDOW: usize = STRAND_MAX_INSTRS * 8;
const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;

/// A function with fewer than this many observable output values is too thin to identify by its data
/// flow: a couple of generic outputs match half the image, so the strand channel declines rather than
/// guess. The relocation driver and the corpus sweep both gate on this.
pub(super) const STRAND_MIN_OUTPUTS: usize = 4;

fn reads(a: OpAccess) -> bool {
    matches!(
        a,
        OpAccess::Read | OpAccess::CondRead | OpAccess::ReadWrite | OpAccess::ReadCondWrite
    )
}

fn writes(a: OpAccess) -> bool {
    matches!(
        a,
        OpAccess::Write | OpAccess::CondWrite | OpAccess::ReadWrite | OpAccess::ReadCondWrite
    )
}

fn fold(h: u64, x: u64) -> u64 {
    (h ^ x).wrapping_mul(0x0000_0100_0000_01b3)
}

/// The set of data-flow strand hashes of the function at `rva`: each output value (memory store, call, or
/// return value) hashed by how it is computed. Register names and instruction order are absorbed, so the
/// hash is invariant to the register allocation and block layout a recompile rewrites. `x86`/`x64`.
#[must_use]
pub(super) fn strand_set(img: &ImageInput, rva: usize) -> BTreeSet<u64> {
    let bytes = read_at(img.source, img.base, rva, STRAND_WINDOW);
    let mut dec = Decoder::with_ip(
        bitness(img.arch),
        &bytes,
        (img.base + rva) as u64,
        DecoderOptions::NONE,
    );
    let mut instr = Instruction::default();
    let mut factory = InstructionInfoFactory::new();
    // The current value-hash defining each full register; an absent register is a function input.
    let mut defs: HashMap<Register, u64> = HashMap::new();
    let mut outputs: BTreeSet<u64> = BTreeSet::new();
    let mut n = 0;
    while dec.can_decode() && n < STRAND_MAX_INSTRS {
        dec.decode_out(&mut instr);
        if instr.is_invalid() || instr.len() == 0 {
            break;
        }
        n += 1;
        let info = factory.info(&instr);
        // The value-hashes this instruction reads. An undefined register is a function input, bottomed out
        // by its own identity so distinct inputs stay distinct (but the same input in either build agrees).
        let mut inputs: Vec<u64> = Vec::new();
        for ur in info.used_registers() {
            if reads(ur.access()) {
                let r = ur.register().full_register();
                inputs.push(
                    defs.get(&r)
                        .copied()
                        .unwrap_or_else(|| fold(FNV_OFFSET, r as u64)),
                );
            }
        }
        // Order-normalise the inputs so a commutative reordering does not change the value-hash.
        inputs.sort_unstable();
        let mut h = fold(FNV_OFFSET, instr.mnemonic() as u64);
        for &i in &inputs {
            h = fold(h, i);
        }
        // Propagate the computed value to every register this instruction defines.
        for ur in info.used_registers() {
            if writes(ur.access()) {
                defs.insert(ur.register().full_register(), h);
            }
        }
        // A store to memory is an observable output; a call's effect also leaves the function.
        if info.used_memory().iter().any(|um| writes(um.access())) {
            outputs.insert(fold(h, 1));
        }
        match instr.flow_control() {
            FlowControl::Call | FlowControl::IndirectCall => {
                outputs.insert(fold(h, 2));
            }
            FlowControl::Return => {
                // The return value lives in (r/e)ax; full_register folds eax into rax above.
                if let Some(&r) = defs.get(&Register::RAX) {
                    outputs.insert(fold(r, 3));
                }
                break;
            }
            _ => {}
        }
    }
    outputs
}

/// Sorensen-Dice over two strand sets: `2|a ∩ b| / (|a| + |b|)`. 1.0 only when the two functions compute
/// the same set of output values; 0.0 when they share none or either side is effect-free.
#[must_use]
pub(super) fn strand_similarity(a: &BTreeSet<u64>, b: &BTreeSet<u64>) -> f64 {
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    let inter = a.intersection(b).count();
    (2.0 * inter as f64) / (a.len() + b.len()) as f64
}

/// The candidate (by index into `cand_strands`) whose strand set is most similar to `reference`, together
/// with that similarity and the best similarity of any *other* candidate (the runner-up), so the caller can
/// demand a uniqueness margin. Candidates whose entry is within `GAP` bytes of the winner are treated as the
/// same site shifted by an instruction, not a distinct rival, mirroring `identity::best_fingerprint_match`.
/// `None` only when the candidate list is empty.
#[must_use]
pub(super) fn best_strand_match(
    reference: &BTreeSet<u64>,
    cand_rvas: &[usize],
    cand_strands: &[BTreeSet<u64>],
) -> Option<(usize, f64, f64)> {
    const GAP: usize = 16;
    let mut best: Option<(usize, f64)> = None;
    let mut runner = 0.0f64;
    for (i, s) in cand_strands.iter().enumerate() {
        let sim = strand_similarity(reference, s);
        match best {
            Some((bi, bsim)) if sim > bsim => {
                if cand_rvas[bi].abs_diff(cand_rvas[i]) >= GAP {
                    runner = runner.max(bsim);
                }
                best = Some((i, sim));
            }
            Some((bi, _)) => {
                if cand_rvas[bi].abs_diff(cand_rvas[i]) >= GAP {
                    runner = runner.max(sim);
                }
            }
            None => best = Some((i, sim)),
        }
    }
    best.map(|(i, sim)| (i, sim, runner))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::{BufferSource, Region};
    use crate::pattern::Arch;

    fn img<'a>(src: &'a BufferSource, base: usize, size: usize) -> ImageInput<'a> {
        ImageInput {
            label: "t".into(),
            source: src,
            base,
            size,
            code_regions: vec![Region { base, size }],
            regions: vec![Region { base, size }],
            import: None,
            arch: Arch::X86,
            code_hash: 0,
            packed: false,
            pack_reasons: Vec::new(),
            reloc: None,
        }
    }

    fn strands(bytes: Vec<u8>) -> BTreeSet<u64> {
        let src = BufferSource::new(0x1000, bytes);
        strand_set(&img(&src, 0x1000, 0x40), 0)
    }

    #[test]
    fn same_computation_through_different_registers_matches() {
        // Both: load [edi], add 5, move the value into eax, store to [esi], return. They differ only in
        // the intermediate register (ecx vs edx), which a recompile's register allocator routinely changes.
        // The data-flow shape is identical, so the strand sets are identical.
        // A: mov ecx,[edi]; add ecx,5; mov eax,ecx; mov [esi],eax; ret
        let a = strands(vec![
            0x8B, 0x0F, 0x83, 0xC1, 0x05, 0x89, 0xC8, 0x89, 0x06, 0xC3,
        ]);
        // B: mov edx,[edi]; add edx,5; mov eax,edx; mov [esi],eax; ret
        let b = strands(vec![
            0x8B, 0x17, 0x83, 0xC2, 0x05, 0x89, 0xD0, 0x89, 0x06, 0xC3,
        ]);
        assert!(!a.is_empty(), "the function has observable outputs");
        assert!(
            (strand_similarity(&a, &b) - 1.0).abs() < 1e-9,
            "register renaming must not change the data-flow strands (got {})",
            strand_similarity(&a, &b)
        );
    }

    #[test]
    fn a_different_computation_does_not_match() {
        // A multiplies the loaded value (shl by 2) where the reference adds 5: a different computation, so
        // the store strand hashes differently and the sets do not fully agree.
        let a = strands(vec![
            0x8B, 0x0F, 0x83, 0xC1, 0x05, 0x89, 0xC8, 0x89, 0x06, 0xC3,
        ]);
        // C: mov eax,[edi]; shl eax,2; mov [esi],eax; ret
        let c = strands(vec![0x8B, 0x07, 0xC1, 0xE0, 0x02, 0x89, 0x06, 0xC3]);
        assert!(
            strand_similarity(&a, &c) < 1.0,
            "a different computation must not be a perfect strand match"
        );
    }

    #[test]
    fn best_strand_match_picks_the_winner_and_reports_a_distinct_runner_up() {
        let reference: BTreeSet<u64> = [1, 2, 3, 4].into_iter().collect();
        // Candidate 1 (rva 0x400) is the perfect match; candidate 2 (rva 0x800, far enough to count as a
        // distinct rival) overlaps half; candidate 0 (rva 0x100) shares nothing.
        let cand_rvas = [0x100usize, 0x400, 0x800];
        let cand_strands: Vec<BTreeSet<u64>> = vec![
            [9, 8, 7].into_iter().collect(),
            [1, 2, 3, 4].into_iter().collect(),
            [1, 2, 5, 6].into_iter().collect(),
        ];
        let (idx, sim, runner) =
            best_strand_match(&reference, &cand_rvas, &cand_strands).expect("a winner");
        assert_eq!(idx, 1, "the identical strand set wins");
        assert!((sim - 1.0).abs() < 1e-9, "the winner is a perfect match");
        assert!(
            (runner - 0.5).abs() < 1e-9,
            "the runner-up is the half-overlapping rival, not the winner itself (got {runner})"
        );
    }

    #[test]
    fn best_strand_match_ignores_a_near_duplicate_window_as_its_own_runner_up() {
        // Two entries a few bytes apart are the same site shifted by an instruction; the second must not be
        // reported as a distinct runner-up, so a lone true match keeps a zero runner-up (full margin).
        let reference: BTreeSet<u64> = [1, 2, 3, 4].into_iter().collect();
        let cand_rvas = [0x400usize, 0x404];
        let cand_strands: Vec<BTreeSet<u64>> = vec![
            [1, 2, 3, 4].into_iter().collect(),
            [1, 2, 3, 4].into_iter().collect(),
        ];
        let (_, _, runner) =
            best_strand_match(&reference, &cand_rvas, &cand_strands).expect("a winner");
        assert!(
            runner.abs() < 1e-9,
            "a within-gap near-duplicate is not a distinct rival (got {runner})"
        );
    }
}
