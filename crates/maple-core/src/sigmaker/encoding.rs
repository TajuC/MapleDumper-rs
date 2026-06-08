//! Encoding-fingerprint relocation: find the same function across builds by the instruction
//! *encoding shape* with relocatable operand values masked.
//!
//! The mnemonic-stream fingerprint ([`super::identity`]) ties on template-instanced code: many
//! sibling instantiations share an identical mnemonic stream, so it finds the right *shape* but
//! cannot pick the right *instance* (measured on the real GMS corpus: the true v84 site and an
//! impostor sibling both score 1.0 mnemonic similarity). The byte AOB disambiguates them only
//! because it keeps the exact operand bytes.
//!
//! This module captures exactly what the byte AOB keeps and the mnemonic stream drops: per
//! instruction, the mnemonic plus its operand *registers* and operand/displacement *sizes*, while
//! masking the immediate and displacement *values* (which are frame offsets and relocated addresses
//! that drift even between same-source builds). It is the AOB's wildcard discipline generalised: `mov
//! bl` vs `mov al` (register) and `lea esi,[ebp+disp8]` vs `lea esi,[ebp+disp32]` (displacement size)
//! separate two siblings, while the wildcarded disp/imm values do not pollute the comparison. Two
//! template siblings differ here on exactly the bytes the AOB fixes; the true cross-build twin does
//! not, so the true site is the unique high match where the mnemonic stream only tied.
//!
//! The signal is precise but local: it bridges same-codegen hops (a minor version bump that shifts
//! operands but not register allocation), and it correctly DECLINES across a true recompile, where
//! register allocation itself changes and no window matches uniquely.

use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, OpKind};

use super::types::ImageInput;
use super::{bitness, read_at, read_region};

// How many instructions of encoding to fingerprint. Long enough to span a template instance's body
// past its shared prologue, short enough not to spill into the self-similar neighbour that follows it
// (measured: past ~48 instructions a sibling out-scores the true twin as the window runs into a clone
// of the next instance). The stream also stops early at a `ret`.
const ENC_MAX_INSTRS: usize = 48;
const ENC_WINDOW_BYTES: usize = ENC_MAX_INSTRS * 8 + 16;

// The size class of an immediate operand: the width it is *encoded* at, never its value. The size
// (imm8 vs imm32) is a stable codegen choice that survives same-source rebuilds; the value is a
// constant or frame offset that may not. The memory-displacement size comes straight from iced's
// `memory_displ_size`, which is the encoded width, so no value-based heuristic is needed there.
fn imm_size_class(k: OpKind) -> u8 {
    match k {
        OpKind::Immediate8
        | OpKind::Immediate8_2nd
        | OpKind::Immediate8to16
        | OpKind::Immediate8to32
        | OpKind::Immediate8to64 => 1,
        OpKind::Immediate16 => 2,
        OpKind::Immediate32 | OpKind::Immediate32to64 => 4,
        OpKind::Immediate64 => 8,
        _ => 0,
    }
}

/// A 64-bit hash of one instruction's encoding shape: its mnemonic, each operand's register and the
/// memory addressing form, and the operand/displacement *sizes*, with immediate and displacement
/// *values* deliberately excluded. Register allocation and operand sizes are kept (they are the
/// per-instance discriminator the byte AOB relies on); the volatile values are dropped.
fn enc_hash(instr: &Instruction) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    let mut fold = |x: u64| {
        h ^= x;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    };
    fold(instr.mnemonic() as u64);
    for i in 0..instr.op_count() {
        let k = instr.op_kind(i);
        match k {
            OpKind::Register => {
                fold(1);
                fold(instr.op_register(i) as u64);
            }
            OpKind::Memory => {
                // Registers and scale plus the *encoded displacement width* (disp8 vs disp32), never
                // the displacement value: `[ebp-0x3C]` (disp8) and `[ebp-0x210]` (disp32) differ here
                // exactly as the byte AOB's fixed bytes do, while two disp8 frame offsets do not.
                fold(2);
                fold(instr.memory_base() as u64);
                fold(instr.memory_index() as u64);
                fold(instr.memory_index_scale() as u64);
                fold(u64::from(instr.memory_displ_size()));
            }
            OpKind::Immediate8
            | OpKind::Immediate8_2nd
            | OpKind::Immediate16
            | OpKind::Immediate32
            | OpKind::Immediate64
            | OpKind::Immediate8to16
            | OpKind::Immediate8to32
            | OpKind::Immediate8to64
            | OpKind::Immediate32to64 => {
                fold(4);
                fold(imm_size_class(k) as u64);
            }
            _ => fold(5),
        }
    }
    h
}

/// The encoding-shape stream of up to [`ENC_MAX_INSTRS`] instructions from `rva`, stopping early at a
/// `ret` (the function's tail) or the first undecodable byte. Each element is an [`enc_hash`].
#[must_use]
pub(super) fn encoding_stream(img: &ImageInput, rva: usize) -> Vec<u64> {
    let bytes = read_at(img.source, img.base, rva, ENC_WINDOW_BYTES);
    let ip0 = (img.base + rva) as u64;
    let mut decoder = Decoder::with_ip(bitness(img.arch), &bytes, ip0, DecoderOptions::NONE);
    let mut instr = Instruction::default();
    let mut out = Vec::with_capacity(ENC_MAX_INSTRS);
    while decoder.can_decode() && out.len() < ENC_MAX_INSTRS {
        decoder.decode_out(&mut instr);
        if instr.is_invalid() || instr.len() == 0 {
            break;
        }
        out.push(enc_hash(&instr));
        if instr.flow_control() == FlowControl::Return {
            break;
        }
    }
    out
}

// Length of the longest common subsequence of two encoding streams. Order-preserving and
// insertion-tolerant, so one extra or dropped instruction across a build costs one position rather
// than desynchronising the rest.
fn lcs_len(a: &[u64], b: &[u64]) -> usize {
    if a.is_empty() || b.is_empty() {
        return 0;
    }
    let mut prev = vec![0usize; b.len() + 1];
    let mut cur = vec![0usize; b.len() + 1];
    for &x in a {
        for (j, &y) in b.iter().enumerate() {
            cur[j + 1] = if x == y {
                prev[j] + 1
            } else {
                prev[j + 1].max(cur[j])
            };
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    prev[b.len()]
}

/// Dice similarity of two encoding streams: `2*LCS / (|a| + |b|)`. 1.0 only when the two streams are
/// identical. Either stream empty (an undecodable window) scores 0.0: an absence of evidence is not a
/// match. A single inserted or removed instruction stays high instead of collapsing.
#[must_use]
pub(super) fn encoding_similarity(a: &[u64], b: &[u64]) -> f64 {
    let total = a.len() + b.len();
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    (2.0 * lcs_len(a, b) as f64) / total as f64
}

/// How many leading encoding tokens of the reference to require an exact match on before a candidate
/// window is scored in full. The reference's first few instructions are its per-instance signature
/// (the registers and operand sizes the AOB fixes); requiring them prunes the superset scan from every
/// code byte to the handful of windows that share that signature, and excludes the siblings that
/// differ in the prologue (`mov al` where the true site has `mov bl`). Capped at the stream length.
const PREFIX_GATE: usize = 4;

/// The best encoding match for `reference` among the candidate code windows of `img`, found by a
/// prefix-prefiltered superset scan. Returns the winning RVA, its similarity, the best similarity of
/// any other window at least [`MIN_DISTINCT_GAP`] bytes away (the runner-up, for a uniqueness margin),
/// and how many distinct windows tie at the top score (1 = unique, >1 = ambiguous).
///
/// The candidate set is *every* code byte offset, not the single-phase instruction lattice: a
/// vtable-reached mid-function target is frequently off that lattice (an upstream data island shifts
/// the global phase), so the lattice silently excludes the true site. The first-instruction prefilter
/// keeps the superset scan cheap by decoding one instruction per offset and only fully scoring the few
/// whose leading encoding matches the reference's. `None` when the image is not x86 or has no code.
#[must_use]
pub(super) fn best_encoding_match(
    img: &ImageInput,
    reference: &[u64],
) -> Option<(usize, f64, f64, usize)> {
    // Arch-agnostic: the stream is decoded at the image's own bitness and operand VALUES are masked,
    // so it fingerprints x86 and x64 the same way (a RIP-relative displacement is masked out, not a
    // false difference). The mis-resolution gates the caller applies (similarity, uniqueness margin,
    // mutual consistency) are arch-neutral too, so enabling x64 cannot produce a confident wrong match.
    if reference.is_empty() {
        return None;
    }
    const MIN_DISTINCT_GAP: usize = 16;
    let prefix_len = PREFIX_GATE.min(reference.len());
    let bits = bitness(img.arch);

    // Prefilter: collect the code offsets whose first decoded instruction's encoding equals the
    // reference's first. One decode per byte, one u64 compare; the surviving set is small.
    let mut prefix_hits: Vec<usize> = Vec::new();
    let mut instr = Instruction::default();
    for region in &img.code_regions {
        let bytes = read_region(img.source, region.base, region.size);
        for off in 0..bytes.len() {
            let mut dec = Decoder::with_ip(
                bits,
                &bytes[off..],
                (region.base + off) as u64,
                DecoderOptions::NONE,
            );
            if !dec.can_decode() {
                continue;
            }
            dec.decode_out(&mut instr);
            if instr.is_invalid() || instr.len() == 0 {
                continue;
            }
            if enc_hash(&instr) == reference[0] {
                prefix_hits.push(region.base + off - img.base);
            }
        }
    }

    let mut best: Option<(usize, f64)> = None;
    let mut runner_up = 0.0f64;
    let mut top_ties = 0usize;
    for rva in prefix_hits {
        let stream = encoding_stream(img, rva);
        // Require the whole leading signature, not just the first token, to score this window.
        if stream.len() < prefix_len || stream[..prefix_len] != reference[..prefix_len] {
            continue;
        }
        let sim = encoding_similarity(reference, &stream);
        match best {
            Some((brva, bsim)) if sim > bsim => {
                if brva.abs_diff(rva) >= MIN_DISTINCT_GAP {
                    runner_up = runner_up.max(bsim);
                }
                best = Some((rva, sim));
                top_ties = 1;
            }
            Some((brva, bsim)) => {
                if brva.abs_diff(rva) >= MIN_DISTINCT_GAP {
                    runner_up = runner_up.max(sim);
                    if (sim - bsim).abs() < 1e-9 {
                        top_ties += 1;
                    }
                }
            }
            None => {
                best = Some((rva, sim));
                top_ties = 1;
            }
        }
    }
    best.map(|(rva, sim)| (rva, sim, runner_up, top_ties))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::{BufferSource, Region};
    use crate::pattern::Arch;
    use crate::sigmaker::types::ImageInput;

    fn img_arch<'a>(src: &'a BufferSource, base: usize, size: usize, arch: Arch) -> ImageInput<'a> {
        ImageInput {
            label: "t".into(),
            source: src,
            base,
            size,
            code_regions: vec![Region { base, size }],
            regions: vec![Region { base, size }],
            import: None,
            arch,
            code_hash: 0,
            packed: false,
            pack_reasons: Vec::new(),
            reloc: None,
        }
    }
    fn img<'a>(src: &'a BufferSource, base: usize, size: usize) -> ImageInput<'a> {
        img_arch(src, base, size, Arch::X86)
    }

    #[test]
    fn register_and_disp_size_separate_two_siblings() {
        // Same mnemonic stream, differing only as the real siblings do: `mov bl,imm8` vs `mov al,imm8`
        // (register) and `lea esi,[ebp+disp8]` vs `lea esi,[ebp+disp32]` (displacement size).
        let truth = vec![
            0xB3, 0xFF, // mov bl, 0xFF
            0x8D, 0x75, 0xC4, // lea esi, [ebp-0x3C]   (disp8)
            0xC3, // ret
        ];
        let sibling = vec![
            0xB0, 0xFF, // mov al, 0xFF            (different register)
            0x8D, 0xB5, 0xF0, 0xFD, 0xFF, 0xFF, // lea esi, [ebp-0x210] (disp32)
            0xC3, // ret
        ];
        let bt = BufferSource::new(0x1000, truth);
        let bs = BufferSource::new(0x1000, sibling);
        let st = encoding_stream(&img(&bt, 0x1000, 6), 0);
        let ss = encoding_stream(&img(&bs, 0x1000, 9), 0);
        assert_ne!(
            st[0], ss[0],
            "register difference must change the first token"
        );
        assert_ne!(
            st[1], ss[1],
            "displacement-size difference must change the lea token"
        );
        assert!(
            encoding_similarity(&st, &ss) < 1.0,
            "two siblings must not be a perfect encoding match"
        );
    }

    #[test]
    fn masked_values_do_not_affect_the_encoding() {
        // Identical encoding shape, different immediate and displacement VALUES: the masked values
        // must not change the stream, so these score a perfect match (the volatile bytes the AOB
        // wildcards do not pollute the comparison).
        let a = vec![0xB3, 0x01, 0x8D, 0x75, 0x10, 0xC3]; // mov bl,1 ; lea esi,[ebp+0x10] ; ret
        let b = vec![0xB3, 0x7F, 0x8D, 0x75, 0x20, 0xC3]; // mov bl,0x7f ; lea esi,[ebp+0x20] ; ret
        let ba = BufferSource::new(0x2000, a);
        let bb = BufferSource::new(0x2000, b);
        let sa = encoding_stream(&img(&ba, 0x2000, 6), 0);
        let sb = encoding_stream(&img(&bb, 0x2000, 6), 0);
        assert_eq!(
            sa, sb,
            "masked imm/disp values must not change the encoding stream"
        );
        assert!((encoding_similarity(&sa, &sb) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn best_match_is_unique_when_only_one_window_shares_the_signature() {
        // A buffer with one copy of the reference signature and a sibling that differs in the first
        // token: the prefix prefilter excludes the sibling, so the match is unique.
        let mut data = vec![
            0xB3, 0xFF, 0x83, 0xEC, 0x10, 0x8B, 0xFC, 0x8D, 0x75, 0xC4, 0xC3, // reference
        ];
        data.resize(0x40, 0x90);
        // a sibling: mov al instead of mov bl, same rest
        data.extend_from_slice(&[
            0xB0, 0xFF, 0x83, 0xEC, 0x10, 0x8B, 0xFC, 0x8D, 0x75, 0xC4, 0xC3,
        ]);
        data.resize(0x80, 0x90);
        let src = BufferSource::new(0x1000, data);
        let image = img(&src, 0x1000, 0x80);
        let reference = encoding_stream(&image, 0);
        let (rva, sim, _runner, ties) = best_encoding_match(&image, &reference).expect("a match");
        assert_eq!(rva, 0, "the reference window itself is the best match");
        assert!((sim - 1.0).abs() < 1e-9);
        assert_eq!(ties, 1, "only one window shares the leading signature");
    }

    #[test]
    fn matches_an_x64_function_by_encoding_fingerprint() {
        // #12: the encoding-fingerprint anchor is arch-agnostic, so it relocates x64 targets too. A
        // buffer holding one copy of an x64 reference signature plus a sibling that differs only in the
        // first instruction's source register: the prefix prefilter drops the sibling, so the x64 match
        // is unique. Validated synthetically because no x64 MapleStory client exists to measure against;
        // the value-masking means the RIP-relative displacement (the `05 10 00 00 00` below) does not
        // perturb the fingerprint.
        let mut data = vec![
            0x48, 0x89, 0xE5, // mov rbp, rsp
            0x48, 0x83, 0xEC, 0x20, // sub rsp, 0x20
            0x8B, 0x45, 0x08, // mov eax, [rbp+8]
            0x48, 0x8B, 0x05, 0x10, 0x00, 0x00,
            0x00, // mov rax, [rip+0x10]  (masked displacement)
            0xC3, // ret
        ];
        data.resize(0x40, 0x90);
        data.extend_from_slice(&[
            0x48, 0x89, 0xD5, // mov rbp, rdx  (different source register: prefilter drops it)
            0x48, 0x83, 0xEC, 0x20, 0x8B, 0x45, 0x08, 0x48, 0x8B, 0x05, 0x10, 0x00, 0x00, 0x00,
            0xC3,
        ]);
        data.resize(0x80, 0x90);
        let src = BufferSource::new(0x1000, data);
        let image = img_arch(&src, 0x1000, 0x80, Arch::X64);
        let reference = encoding_stream(&image, 0);
        assert!(
            reference.len() >= 4,
            "x64 reference should decode to several tokens"
        );
        let (rva, sim, _runner, ties) =
            best_encoding_match(&image, &reference).expect("an x64 encoding match");
        assert_eq!(rva, 0, "the reference window itself is the best x64 match");
        assert!((sim - 1.0).abs() < 1e-9);
        assert_eq!(ties, 1, "only one window shares the leading x64 signature");
    }
}
