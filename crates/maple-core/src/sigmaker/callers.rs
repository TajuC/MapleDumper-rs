//! Caller-relative anchoring: relocate a function that has no recompile-stable handle of its own by
//! anchoring a CALLER that does, then re-finding the target among that caller's callees by identity.
//!
//! A function with no referenced string, no distinctive import set, and only a vtable that a major
//! version refactors away can still be CALLED by a function that does reference a stable string. That
//! caller is locatable in any build by its string ([`super::identity::resolve_string_anchor`]), and the
//! target is the callee of it whose identity matches the reference target's. Matching by identity (not
//! by raw call index) survives the call being reordered across a recompile, and a uniqueness margin
//! rejects a caller whose callees are too alike to tell apart. x86 / PE32 only.

use std::collections::BTreeSet;

use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction};

use super::identity::{
    FnIdentity, enclosing_function, fn_identity, make_string_anchor, resolve_string_anchor,
};
use super::types::ImageInput;
use super::{bitness, read_at, read_region};
use crate::domain::StringAnchor;

// Instruction cap when scanning a caller for its callees (bounds untrusted input).
const SCAN_INSTRS: usize = 400;
// The target must match one of a caller's callees this well, and clearly ahead of the runner-up, before
// a relocation is accepted. A recompile drifts a function's identity, so the floor is moderate, but the
// margin is what actually guards against picking the wrong callee.
const CALLER_MIN_SIM: f64 = 0.50;
const CALLER_MIN_MARGIN: f64 = 0.12;

/// A string-anchorable caller of the target plus the target's own identity: enough to re-find the
/// target as that caller's matching callee in another build.
pub(super) struct CallerAnchor {
    pub caller: StringAnchor,
    pub target: FnIdentity,
}

fn in_code(img: &ImageInput, abs: usize) -> bool {
    img.code_regions
        .iter()
        .any(|r| abs >= r.base && abs < r.base + r.size)
}

/// The E8 rel32 call targets of the function at `rva`, decoded to its first `ret` or [`SCAN_INSTRS`].
fn callees(img: &ImageInput, rva: usize) -> Vec<usize> {
    let bytes = read_at(img.source, img.base, rva, SCAN_INSTRS * 8);
    let mut dec = Decoder::with_ip(
        bitness(img.arch),
        &bytes,
        (img.base + rva) as u64,
        DecoderOptions::NONE,
    );
    let mut instr = Instruction::default();
    let mut out = Vec::new();
    let mut n = 0;
    while dec.can_decode() && n < SCAN_INSTRS {
        dec.decode_out(&mut instr);
        if instr.is_invalid() || instr.len() == 0 {
            break;
        }
        n += 1;
        if instr.flow_control() == FlowControl::Call && instr.len() == 5 {
            let t = instr.near_branch_target() as usize;
            if in_code(img, t) {
                out.push(t - img.base);
            }
        }
        if instr.flow_control() == FlowControl::Return {
            break;
        }
    }
    out
}

/// Every function that contains an E8 rel32 call to `target_rva`.
fn callers_of(img: &ImageInput, target_rva: usize) -> Vec<usize> {
    let mut out = BTreeSet::new();
    let target_abs = (img.base + target_rva) as i64;
    for region in &img.code_regions {
        let bytes = read_region(img.source, region.base, region.size);
        for (i, w) in bytes.windows(5).enumerate() {
            if w[0] == 0xE8 {
                let rel = i32::from_le_bytes([w[1], w[2], w[3], w[4]]) as i64;
                if (region.base + i + 5) as i64 + rel == target_abs {
                    out.insert(enclosing_function(img, region.base + i - img.base));
                }
            }
        }
    }
    out.into_iter().collect()
}

/// The callee of `caller_rva` whose identity best matches `target`, with the runner-up's score, so the
/// caller can require a uniqueness margin. `None` when the caller calls nothing in code.
fn best_callee(
    img: &ImageInput,
    caller_rva: usize,
    target: &FnIdentity,
) -> Option<(usize, f64, f64)> {
    let mut best = (0usize, 0.0f64);
    let mut second = 0.0f64;
    let mut found = false;
    for c in callees(img, caller_rva) {
        let s = target.similarity(&fn_identity(img, c));
        if s > best.1 {
            second = best.1;
            best = (c, s);
            found = true;
        } else if s > second {
            second = s;
        }
    }
    found.then_some((best.0, best.1, second))
}

/// Build a caller-relative anchor for `target_rva`: a string-anchorable caller that calls the target as
/// its single best-matching callee, so the resolve step can re-find it among that caller's callees.
/// Returns `None` if no caller string-anchors or the target is not the caller's distinctive callee.
#[must_use]
pub(super) fn make_caller_anchor(img: &ImageInput, target_rva: usize) -> Option<CallerAnchor> {
    let target = fn_identity(img, target_rva);
    for caller in callers_of(img, target_rva) {
        let Some(sa) = make_string_anchor(img, caller) else {
            continue;
        };
        // The caller's string must already pin the caller here, and the target must stand out among the
        // caller's callees, or the resolve step could not single it out in another build.
        if resolve_string_anchor(img, &sa) != Some(caller) {
            continue;
        }
        let Some((best, sim, runner)) = best_callee(img, caller, &target) else {
            continue;
        };
        if best == target_rva && sim - runner >= CALLER_MIN_MARGIN {
            return Some(CallerAnchor { caller: sa, target });
        }
    }
    None
}

/// Resolve a caller-relative anchor in `img`: locate the caller by its string, then pick the caller's
/// callee whose identity matches the target, requiring a confident, unambiguous match.
#[must_use]
pub(super) fn resolve_caller_anchor(img: &ImageInput, anchor: &CallerAnchor) -> Option<usize> {
    let caller = resolve_string_anchor(img, &anchor.caller)?;
    let (best, sim, runner) = best_callee(img, caller, &anchor.target)?;
    (sim >= CALLER_MIN_SIM && sim - runner >= CALLER_MIN_MARGIN).then_some(best)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::{BufferSource, Region};
    use crate::pattern::Arch;

    #[test]
    fn caller_anchor_round_trips_through_a_string_anchored_caller() {
        // A caller G (standard prologue) references a unique string and calls the target C; the target
        // has no string of its own. make_caller_anchor must pin C through G's string, and resolving the
        // anchor on the same image must read C back.
        const BASE: usize = 0x40_0000;
        let mut buf = vec![0u8; 0x400];
        // G @ 0x100: push ebp ; mov ebp, esp ; push offset 0x400300 ; call C ; pop ebp ; ret
        buf[0x100..0x103].copy_from_slice(&[0x55, 0x8B, 0xEC]);
        buf[0x103..0x108].copy_from_slice(&[0x68, 0x00, 0x03, 0x40, 0x00]);
        buf[0x108] = 0xE8;
        let rel = 0x180i32 - (0x108 + 5);
        buf[0x109..0x10D].copy_from_slice(&rel.to_le_bytes());
        buf[0x10D..0x10F].copy_from_slice(&[0x5D, 0xC3]);
        // C @ 0x180: a small distinctive function, referenced by no string.
        buf[0x180..0x187].copy_from_slice(&[0x55, 0x8B, 0xEC, 0x33, 0xC0, 0x5D, 0xC3]);
        // The unique string in data.
        let s = b"UniqueAnchorString\0";
        buf[0x300..0x300 + s.len()].copy_from_slice(s);

        let src = BufferSource::new(BASE, buf);
        let img = ImageInput {
            label: "t".into(),
            source: &src,
            base: BASE,
            size: 0x400,
            code_regions: vec![Region {
                base: BASE + 0x100,
                size: 0x100,
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
        };

        let anchor = make_caller_anchor(&img, 0x180).expect("a caller anchor for C via G's string");
        assert_eq!(anchor.caller.text, "UniqueAnchorString");
        assert_eq!(resolve_caller_anchor(&img, &anchor), Some(0x180));
    }

    #[test]
    fn a_function_with_no_string_anchored_caller_declines() {
        // The caller references no string, so there is no stable handle to anchor on.
        const BASE: usize = 0x40_0000;
        let mut buf = vec![0u8; 0x400];
        // G @ 0x100: push ebp ; mov ebp, esp ; call C ; pop ebp ; ret  (no string reference)
        buf[0x100..0x103].copy_from_slice(&[0x55, 0x8B, 0xEC]);
        buf[0x103] = 0xE8;
        let rel = 0x180i32 - (0x103 + 5);
        buf[0x104..0x108].copy_from_slice(&rel.to_le_bytes());
        buf[0x108..0x10A].copy_from_slice(&[0x5D, 0xC3]);
        buf[0x180..0x187].copy_from_slice(&[0x55, 0x8B, 0xEC, 0x33, 0xC0, 0x5D, 0xC3]);
        let src = BufferSource::new(BASE, buf);
        let img = ImageInput {
            label: "t".into(),
            source: &src,
            base: BASE,
            size: 0x400,
            code_regions: vec![Region {
                base: BASE + 0x100,
                size: 0x100,
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
        };
        assert!(make_caller_anchor(&img, 0x180).is_none());
    }

    #[test]
    fn caller_anchor_round_trips_on_x64() {
        // #12: the caller anchor is arch-neutral once entry detection is, its E8 rel32 scan and the
        // string anchor already are, and enclosing_function now matches the x64 framed prologue. A
        // caller G references a unique string by a RIP-relative lea and calls the target C; the anchor
        // pins C through G's string and re-resolves to C on a 64-bit image. Validated synthetically (no
        // x64 MapleStory client exists to measure against).
        const BASE: usize = 0x40_0000;
        let mut buf = vec![0u8; 0x400];
        // G @ 0x100: push rbp ; mov rbp,rsp ; lea rcx,[rip+0x1F5] (-> str @ 0x300) ; call C ; pop rbp ; ret
        buf[0x100..0x104].copy_from_slice(&[0x55, 0x48, 0x8B, 0xEC]);
        buf[0x104..0x10B].copy_from_slice(&[0x48, 0x8D, 0x0D, 0xF5, 0x01, 0x00, 0x00]);
        buf[0x10B] = 0xE8;
        let rel = 0x180i32 - (0x10B + 5);
        buf[0x10C..0x110].copy_from_slice(&rel.to_le_bytes());
        buf[0x110..0x112].copy_from_slice(&[0x5D, 0xC3]);
        // C @ 0x180: a small distinctive x64 function, referenced by no string.
        buf[0x180..0x188].copy_from_slice(&[0x55, 0x48, 0x8B, 0xEC, 0x33, 0xC0, 0x5D, 0xC3]);
        let s = b"UniqueAnchorString\0";
        buf[0x300..0x300 + s.len()].copy_from_slice(s);

        let src = BufferSource::new(BASE, buf);
        let img = ImageInput {
            label: "t".into(),
            source: &src,
            base: BASE,
            size: 0x400,
            code_regions: vec![Region {
                base: BASE + 0x100,
                size: 0x100,
            }],
            regions: vec![Region {
                base: BASE,
                size: 0x400,
            }],
            import: None,
            arch: Arch::X64,
            code_hash: 0,
            packed: false,
            pack_reasons: Vec::new(),
            reloc: None,
        };

        let anchor =
            make_caller_anchor(&img, 0x180).expect("an x64 caller anchor for C via G's string");
        assert_eq!(anchor.caller.text, "UniqueAnchorString");
        assert_eq!(resolve_caller_anchor(&img, &anchor), Some(0x180));
    }
}
