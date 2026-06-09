//! A shared per-image analysis the relocation anchors query instead of each re-deriving the call graph
//! from the raw bytes. The graph is recovered by a single linear decode of each code region rather than
//! a bare `0xE8` byte scan: opcode `0xE8` is unconditionally `call rel32`, so a scan that trusts the
//! byte (or decodes starting *on* it) counts every `0xE8` as a call, including one that is really part
//! of another instruction's operand, and mints a phantom function entry (audit F9 / 21 section 2.2).
//! Decoding the region as a stream and recording a near call only where one falls on a genuine
//! instruction boundary rejects those operand bytes: the `0xE8` inside `mov eax, 0x000000E8` is consumed
//! by the `mov` and never seen as a call.
//!
//! Limitation, stated honestly: a single linear sweep can desynchronise on data embedded in `.text`
//! (a jump table, alignment padding), after which it may mis-decode until it resynchronises on the next
//! valid boundary. iced returns a one-byte invalid instruction on undecodable input, which resynchronises
//! the stream, but a desync window can still both miss a real call and admit a stray one. The robust form
//! seeds the sweep from known function starts (prologues, vtable slots, exports) and is deferred to the
//! phase that needs the full graph. The model is rebuilt per call for now; hoisting it to once per image
//! is the next increment.

use std::collections::BTreeSet;

use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction};

use super::identity::enclosing_function;
use super::types::ImageInput;
use super::{bitness, read_region};

/// One decode-verified direct call: the call site and the function entry it targets, both image RVAs.
#[derive(Clone, Copy)]
struct CallEdge {
    site: usize,
    target: usize,
}

/// The decode-verified direct-call graph of one image, built once and queried by the relocation anchors.
pub(super) struct AnalysisModel {
    edges: Vec<CallEdge>,
    entries: Vec<usize>,
}

impl AnalysisModel {
    /// Recover the call graph: linearly decode each code region once, advancing by each instruction's
    /// length, and record a near call (`E8 rel32`, the only five-byte `FlowControl::Call`) whose target
    /// lands in executable code. Recording only at real instruction boundaries is what rejects an `0xE8`
    /// that is an operand byte rather than an opcode. Every loop is bounded by the region length, so a
    /// malformed image cannot spin.
    #[must_use]
    pub(super) fn build(img: &ImageInput) -> Self {
        let bits = bitness(img.arch);
        let in_code = |abs: usize| {
            img.code_regions
                .iter()
                .any(|r| abs >= r.base && abs < r.base + r.size)
        };
        let mut edges: Vec<CallEdge> = Vec::new();
        let mut instr = Instruction::default();
        for region in &img.code_regions {
            let bytes = read_region(img.source, region.base, region.size);
            let mut dec = Decoder::with_ip(bits, &bytes, region.base as u64, DecoderOptions::NONE);
            while dec.can_decode() {
                dec.decode_out(&mut instr);
                // iced yields a one-byte invalid instruction on undecodable input and advances past it,
                // resynchronising the stream; skip it and keep sweeping.
                if instr.is_invalid() {
                    continue;
                }
                if instr.flow_control() == FlowControl::Call && instr.len() == 5 {
                    let target = instr.near_branch_target() as usize;
                    if in_code(target) {
                        let site = instr.ip() as usize;
                        debug_assert!(site >= img.base && target >= img.base);
                        edges.push(CallEdge {
                            site: site - img.base,
                            target: target - img.base,
                        });
                    }
                }
            }
        }
        let entries: Vec<usize> = edges
            .iter()
            .map(|e| e.target)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        Self { edges, entries }
    }

    /// The decode-verified function-entry set: every distinct direct-call target, ascending.
    pub(super) fn entries(&self) -> &[usize] {
        &self.entries
    }

    /// Every decode-verified direct call as `(call-site rva, callee-entry rva)`. The graph aligner maps
    /// each site to its enclosing function to build the function-level call graph; the site order within
    /// a function (ascending rva) is its call-site rank.
    pub(super) fn call_sites(&self) -> impl Iterator<Item = (usize, usize)> + '_ {
        self.edges.iter().map(|e| (e.site, e.target))
    }

    /// The enclosing functions of every decode-verified call site that targets `target_rva`, ascending
    /// and de-duplicated (several call sites can sit in one function).
    pub(super) fn callers_of(&self, img: &ImageInput, target_rva: usize) -> Vec<usize> {
        self.edges
            .iter()
            .filter(|e| e.target == target_rva)
            .map(|e| enclosing_function(img, e.site))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }
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

    #[test]
    fn recovers_a_direct_call_target_as_an_entry() {
        // call C ; ret, with C a small function later in the buffer. The call target must be recovered
        // as a function entry and the call site attributed to its enclosing function.
        const BASE: usize = 0x40_0000;
        let mut buf = vec![0x90u8; 0x200];
        // G @ 0x00: push ebp ; mov ebp, esp ; call C(@0x100) ; pop ebp ; ret
        buf[0x00..0x03].copy_from_slice(&[0x55, 0x8B, 0xEC]);
        buf[0x03] = 0xE8;
        let rel = 0x100i32 - (0x03 + 5);
        buf[0x04..0x08].copy_from_slice(&rel.to_le_bytes());
        buf[0x08..0x0A].copy_from_slice(&[0x5D, 0xC3]);
        // C @ 0x100: a tiny function.
        buf[0x100..0x107].copy_from_slice(&[0x55, 0x8B, 0xEC, 0x33, 0xC0, 0x5D, 0xC3]);

        let src = BufferSource::new(BASE, buf);
        let image = img(&src, BASE, 0x200);
        let model = AnalysisModel::build(&image);
        assert!(model.entries().contains(&0x100), "C is a call target");
        assert_eq!(
            model.callers_of(&image, 0x100),
            vec![0x00],
            "the call to C is attributed to G's entry"
        );
    }

    #[test]
    fn an_operand_byte_e8_with_an_in_code_target_is_not_an_entry() {
        // The regression the feature exists to prevent (the review probe). `mov eax, 0x000000E8` is
        // `B8 E8 00 00 00`: the 0xE8 is the immediate's low byte at offset 1, and the following byte is
        // 0x00, so a scan that decoded *starting at* that 0xE8 would read `E8 00 00 00 00` = call rel32 0,
        // a target of base+6 that IS in code, and mint a phantom entry there. The linear sweep consumes
        // the 0xE8 inside the `mov`, so it is never a call boundary and no entry is minted.
        const BASE: usize = 0x40_0000;
        let mut buf = vec![0x90u8; 0x80];
        buf[0x00..0x05].copy_from_slice(&[0xB8, 0xE8, 0x00, 0x00, 0x00]);
        buf[0x05] = 0x00;
        let src = BufferSource::new(BASE, buf);
        let image = img(&src, BASE, 0x80);
        let model = AnalysisModel::build(&image);
        assert!(
            !model.entries().contains(&0x06),
            "an operand-byte 0xE8 must not mint a phantom entry at its misaligned target"
        );
        assert!(
            model.entries().is_empty(),
            "the buffer holds no real call, so the graph is empty"
        );
    }

    #[test]
    fn ignores_a_call_whose_target_is_outside_code() {
        // A real call (on a boundary) whose target leaves the code region is not a function entry.
        const BASE: usize = 0x40_0000;
        let mut buf = vec![0x90u8; 0x80];
        buf[0x00] = 0xE8;
        // call at offset 0 (so the next ip is +5); aim the target well past the region end at 0x80.
        let rel = 0x1000i32 - 5;
        buf[0x01..0x05].copy_from_slice(&rel.to_le_bytes());
        buf[0x05] = 0xC3;
        let src = BufferSource::new(BASE, buf);
        let image = img(&src, BASE, 0x80);
        let model = AnalysisModel::build(&image);
        assert!(
            model.entries().is_empty(),
            "a call leaving the code region is not an entry"
        );
    }

    #[test]
    fn an_e8_in_the_last_bytes_of_a_region_does_not_decode_to_a_call() {
        // An 0xE8 with fewer than five bytes after it cannot be a complete near call; the sweep must not
        // read past the region to invent one.
        const BASE: usize = 0x40_0000;
        // push ebp ; mov ebp, esp ; ret ; then a trailing 0xE8 with only two bytes behind it.
        let buf = vec![0x55u8, 0x8B, 0xEC, 0xC3, 0xE8, 0x00, 0x00];
        let src = BufferSource::new(BASE, buf);
        let image = img(&src, BASE, 0x7);
        let model = AnalysisModel::build(&image);
        assert!(
            model.entries().is_empty(),
            "a truncated 0xE8 at the region tail is not a call"
        );
    }
}
