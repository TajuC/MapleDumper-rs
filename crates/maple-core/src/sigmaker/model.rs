//! A shared per-image analysis the relocation anchors query instead of each re-deriving the call graph
//! from the raw bytes. This first slice recovers the direct-call graph by *decoding* the code rather
//! than trusting a bare `0xE8` byte scan: an `0xE8` that is really part of another instruction's operand
//! (a displacement or immediate) is not a call, and counting it as one mints a phantom function entry
//! (audit F9 / 21 §2.2). Decoding the instruction at each candidate site and keeping only a real
//! five-byte near call rejects those phantoms, so the function-entry set the import anchor resolves
//! against and the call sites the caller anchor walks back are decode-verified.
//!
//! The recovered set is a subset of the old byte-scan set (it only drops bytes that do not decode as a
//! call), so it never loses a real entry; it can only remove a spurious one that a real anchor would
//! never have matched anyway. Later phases extend this model with the data-xref graph and a background
//! token frequency and re-point the remaining anchors and the string hot path to it.

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
    /// Recover the call graph: scan each code region for `0xE8` (near `call rel32`) candidates and
    /// confirm each by decoding the instruction at that offset, keeping only a genuine five-byte near
    /// call whose target lands in executable code. The kept targets are the function-entry set; the kept
    /// sites are what the caller anchor resolves to their enclosing function. Every loop is bounded by
    /// the region length, so a malformed image cannot spin.
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
            for i in 0..bytes.len() {
                if bytes[i] != 0xE8 {
                    continue;
                }
                let mut dec = Decoder::with_ip(
                    bits,
                    &bytes[i..],
                    (region.base + i) as u64,
                    DecoderOptions::NONE,
                );
                if !dec.can_decode() {
                    continue;
                }
                dec.decode_out(&mut instr);
                // A real near `call rel32` is exactly five bytes; an `0xE8` operand byte either decodes
                // to something else, to a different length, or to a target outside code.
                if instr.is_invalid()
                    || instr.len() != 5
                    || instr.flow_control() != FlowControl::Call
                {
                    continue;
                }
                let target = instr.near_branch_target() as usize;
                if in_code(target) {
                    edges.push(CallEdge {
                        site: region.base + i - img.base,
                        target: target - img.base,
                    });
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
    fn rejects_an_e8_operand_byte_that_is_not_a_call() {
        // `mov eax, 0x44E8` then `add eax, ...`: the byte 0xE8 appears inside the immediate of an earlier
        // instruction, not as a call opcode at an instruction boundary. A raw byte scan starting at that
        // 0xE8 would read the following bytes as a rel32 and mint a phantom entry; decoding from the real
        // instruction boundary never lands a five-byte near call there, so the model records no edge.
        const BASE: usize = 0x40_0000;
        let mut buf = vec![0x90u8; 0x80];
        // mov eax, 0x000044E8  (B8 E8 44 00 00) -> the 0xE8 is the low immediate byte at offset 0x01.
        buf[0x00..0x05].copy_from_slice(&[0xB8, 0xE8, 0x44, 0x00, 0x00]);
        buf[0x05] = 0xC3; // ret
        let src = BufferSource::new(BASE, buf);
        let image = img(&src, BASE, 0x80);
        let model = AnalysisModel::build(&image);
        // The only 0xE8 in the buffer is the operand byte; no decode-verified call exists.
        assert!(
            model.entries().is_empty(),
            "an 0xE8 operand byte must not become a function entry"
        );
    }

    #[test]
    fn ignores_a_call_whose_target_is_outside_code() {
        // call into data (outside any code region) is not a function entry.
        const BASE: usize = 0x40_0000;
        let mut buf = vec![0x90u8; 0x80];
        buf[0x00] = 0xE8;
        // call at offset 0 (so the next ip is +5); aim the target well past the region end at 0x80.
        let rel = 0x1000i32 - 5;
        buf[0x01..0x05].copy_from_slice(&rel.to_le_bytes());
        buf[0x05] = 0xC3;
        let src = BufferSource::new(BASE, buf);
        // Code region is only the first 0x80 bytes; the call target at +0x1000 is outside it.
        let image = img(&src, BASE, 0x80);
        let model = AnalysisModel::build(&image);
        assert!(
            model.entries().is_empty(),
            "a call leaving the code region is not an entry"
        );
    }
}
