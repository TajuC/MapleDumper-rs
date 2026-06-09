//! Rare-constant anchored relocation: a function that uses a globally rare immediate (a packet opcode, a
//! damage-formula multiplier, a crypto constant) is anchorable by that constant. The value is fixed by the
//! source, so a recompile that rewrites the surrounding code preserves it, and a value that occurs exactly
//! once in the code pins its function without a referenced string or a distinctive import set. This is
//! Diaphora's strongest non-string heuristic, made cheap and safe here by using the constant's raw
//! byte-occurrence count in the code as the rarity measure (the same rarest-anchor philosophy the byte AOB
//! uses) rather than a per-function decode sweep, and by declining when the value lands in more than one
//! function. Arch-neutral: it reads immediates, not addresses.

use std::collections::BTreeSet;

use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, OpKind};

use super::identity::enclosing_function;
use super::types::ImageInput;
use super::{bitness, read_at, read_region};

// Instruction cap when scanning a single function for its constants (bounds untrusted input).
const SCAN_INSTRS: usize = 400;
// Below this an immediate is a one-byte flag or tiny offset whose 4-byte LE pattern (value followed by
// zero bytes) collides with ordinary zero padding. Above it, the exactly-once occurrence test, not the
// magnitude, is what enforces distinctiveness, so the floor is kept low enough to admit packet opcodes
// and similar small-but-rare game constants rather than only large literals.
const MIN_CONSTANT: u64 = 0x100;

pub(super) struct ConstantAnchor {
    pub value: u64,
}

fn in_image(img: &ImageInput, v: usize) -> bool {
    v >= img.base && v < img.base + img.size
}

// The little-endian byte width to match a value on: 4 bytes for anything that fits in a u32 (the common
// imm32 case), 8 otherwise.
fn width_of(value: u64) -> usize {
    if value <= u64::from(u32::MAX) { 4 } else { 8 }
}

/// The distinctive immediate constants the function at `rva` uses: 32/64-bit immediates large enough to be
/// real literals and not addresses into this image (an in-image value is a pointer a recompile moves,
/// which the address-based anchors handle, not a stable constant). Decoded to the first `ret` or the cap.
/// Only this one function is decoded, so it is cheap.
pub(super) fn function_constants(img: &ImageInput, rva: usize) -> BTreeSet<u64> {
    let bytes = read_at(img.source, img.base, rva, SCAN_INSTRS * 8);
    let mut dec = Decoder::with_ip(
        bitness(img.arch),
        &bytes,
        (img.base + rva) as u64,
        DecoderOptions::NONE,
    );
    let mut instr = Instruction::default();
    let mut out = BTreeSet::new();
    let mut n = 0;
    while dec.can_decode() && n < SCAN_INSTRS {
        dec.decode_out(&mut instr);
        if instr.is_invalid() || instr.len() == 0 {
            break;
        }
        n += 1;
        for i in 0..instr.op_count() {
            let v = match instr.op_kind(i) {
                OpKind::Immediate32 => u64::from(instr.immediate32()),
                OpKind::Immediate32to64 | OpKind::Immediate64 => instr.immediate64(),
                _ => continue,
            };
            if v >= MIN_CONSTANT && !in_image(img, v as usize) {
                out.insert(v);
            }
        }
        if instr.flow_control() == FlowControl::Return {
            break;
        }
    }
    out
}

/// How many times the little-endian bytes of `value` occur across the code regions: a fast rarity proxy
/// that needs no per-function decode. A coincidental byte run that is not an immediate only inflates the
/// count, which makes the rarity test conservative (a value is trusted only when it is genuinely rare).
fn code_byte_count(img: &ImageInput, value: u64) -> usize {
    let width = width_of(value);
    let bytes = value.to_le_bytes();
    let needle = &bytes[..width];
    let mut count = 0usize;
    for r in &img.code_regions {
        let region = read_region(img.source, r.base, r.size);
        if region.len() >= width {
            count += region.windows(width).filter(|w| *w == needle).count();
        }
    }
    count
}

/// Build a constant anchor for the function at `rva`: a constant it uses whose bytes occur exactly once in
/// the whole code, so that one occurrence is its immediate and resolve can pin the function uniquely.
/// `None` if the function has no such uniquely-occurring constant.
#[must_use]
pub(super) fn make_constant_anchor(img: &ImageInput, rva: usize) -> Option<ConstantAnchor> {
    function_constants(img, rva)
        .into_iter()
        .find(|&v| code_byte_count(img, v) == 1)
        .map(|value| ConstantAnchor { value })
}

/// Resolve a constant anchor to the single function in `img` whose code contains its value's bytes. `None`
/// if the bytes occur in zero functions or in more than one (an ambiguous anchor declines rather than
/// guess). enclosing_function maps each occurrence back to its function start.
#[must_use]
pub(super) fn resolve_constant_anchor(img: &ImageInput, anchor: &ConstantAnchor) -> Option<usize> {
    let width = width_of(anchor.value);
    let bytes = anchor.value.to_le_bytes();
    let needle = &bytes[..width];
    let mut found: Option<usize> = None;
    for r in &img.code_regions {
        let region = read_region(img.source, r.base, r.size);
        if region.len() < width {
            continue;
        }
        for (i, w) in region.windows(width).enumerate() {
            if w == needle {
                let f = enclosing_function(img, r.base + i - img.base);
                match found {
                    Some(p) if p != f => return None, // two distinct functions: ambiguous
                    _ => found = Some(f),
                }
            }
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::{BufferSource, Region};
    use crate::pattern::Arch;

    const BASE: usize = 0x40_0000;

    // Two prologued functions (so enclosing_function can find their starts): f0 uses a rare constant, f1
    // a different one.
    fn image_with_constant() -> Vec<u8> {
        let mut buf = vec![0u8; 0x400];
        // f0 @ 0x100: push ebp ; mov ebp,esp ; mov eax, 0xDEADBEEF ; pop ebp ; ret
        buf[0x100..0x10A]
            .copy_from_slice(&[0x55, 0x8B, 0xEC, 0xB8, 0xEF, 0xBE, 0xAD, 0xDE, 0x5D, 0xC3]);
        // f1 @ 0x140: push ebp ; mov ebp,esp ; mov eax, 0x11223344 ; pop ebp ; ret
        buf[0x140..0x14A]
            .copy_from_slice(&[0x55, 0x8B, 0xEC, 0xB8, 0x44, 0x33, 0x22, 0x11, 0x5D, 0xC3]);
        buf
    }

    fn image(src: &BufferSource) -> ImageInput<'_> {
        ImageInput {
            label: "t".into(),
            source: src,
            base: BASE,
            size: 0x400,
            code_regions: vec![Region {
                base: BASE,
                size: 0x400,
            }],
            regions: vec![Region {
                base: BASE,
                size: 0x400,
            }],
            import: None,
            arch: Arch::X86,
            code_hash: 0,
            packed: false,
            pack_reasons: Vec::new(),
            reloc: None,
        }
    }

    #[test]
    fn anchors_and_resolves_a_unique_constant() {
        let src = BufferSource::new(BASE, image_with_constant());
        let img = image(&src);
        let anchor =
            make_constant_anchor(&img, 0x100).expect("f0 has a uniquely-occurring constant");
        assert_eq!(anchor.value, 0xDEAD_BEEF);
        assert_eq!(resolve_constant_anchor(&img, &anchor), Some(0x100));
    }

    #[test]
    fn declines_when_the_constant_is_not_unique() {
        // Both functions use the same constant, so its bytes occur twice: not anchorable, and an anchor
        // for that value resolves ambiguously.
        let mut buf = vec![0u8; 0x400];
        buf[0x100..0x10A]
            .copy_from_slice(&[0x55, 0x8B, 0xEC, 0xB8, 0xEF, 0xBE, 0xAD, 0xDE, 0x5D, 0xC3]);
        buf[0x140..0x14A]
            .copy_from_slice(&[0x55, 0x8B, 0xEC, 0xB8, 0xEF, 0xBE, 0xAD, 0xDE, 0x5D, 0xC3]);
        let src = BufferSource::new(BASE, buf);
        let img = image(&src);
        assert!(make_constant_anchor(&img, 0x100).is_none());
        assert!(resolve_constant_anchor(&img, &ConstantAnchor { value: 0xDEAD_BEEF }).is_none());
    }

    #[test]
    fn ignores_small_immediates() {
        // push ebp ; mov ebp,esp ; mov eax, 0x40 (a small imm32, below the literal floor) ; pop ebp ; ret
        let mut buf = vec![0u8; 0x400];
        buf[0x100..0x10A]
            .copy_from_slice(&[0x55, 0x8B, 0xEC, 0xB8, 0x40, 0x00, 0x00, 0x00, 0x5D, 0xC3]);
        let src = BufferSource::new(BASE, buf);
        let img = image(&src);
        assert!(make_constant_anchor(&img, 0x100).is_none());
    }
}
