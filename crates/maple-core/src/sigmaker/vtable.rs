//! Vtable-fingerprint anchored relocation: relocate a C++ virtual method across builds by matching the
//! structure of the vtable it is dispatched from.
//!
//! A virtual method is installed in its class's vtable, a run of consecutive code pointers. A recompile
//! rewrites individual method bodies, but the vtable's *shape*, the ordered set of methods it dispatches,
//! is fixed by the class layout and survives: the same class keeps the same methods in the same slots
//! build to build even when every method body changed. So a vtable is identifiable across builds by
//! fingerprinting each slot's function with a short mnemonic window and matching the table whose per-slot
//! fingerprints agree best under a Needleman-Wunsch alignment (so methods inserted or removed across
//! versions shift the match rather than breaking it); once the table is relocated, the target's aligned
//! slot is read back to recover the method's new address.
//!
//! This is the complement of the other anchors: where [`super::identity`]'s string anchor pins a function
//! by a read-only string it references and [`super::imports`] by the API set it calls, this pins it by the
//! class it belongs to, which is exactly the handle a virtual method with neither a distinctive string nor
//! a distinctive import set still has. A slot can dispatch through an MSVC adjustor thunk
//! (`add ecx, imm ; jmp`) under multiple inheritance; the thunk is followed so the real method, not the
//! thunk, is what relocates.
//!
//! Per-slot agreement is a distinctiveness-weighted mean Dice over the alignment (a method inherited
//! into many classes weighs little, a class-specific override weighs ~1), so a sibling that shares only
//! the inherited backbone cannot tie the real class. Measured on the real GMS v84 vtable at .text RVA
//! 0x78F16C (101 slots): a clean slot relocates to v88 at weighted agreement 0.993 (margin 0.31) and to
//! v83 at 1.000; chained through intermediate builds it carries v83 -> v84 -> v88 -> v91, and at a v95
//! class refactor the agreement falls below the gate, where the matcher declines rather than guess. The
//! caller ([`super::vtable_relocate`]) reaches builds over the highest-confidence chain and reports the
//! version ranges each minted AOB covers. x86 / PE32 only.

use std::collections::{HashMap, HashSet};

use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic, OpKind};

use super::identity::{enclosing_function, make_string_anchor, resolve_string_anchor};
use super::types::ImageInput;
use super::{bitness, read_at, read_region};
use crate::domain::StringAnchor;
use crate::pattern::Arch;

// A vtable shorter than this carries too little structure to identify uniquely (a handful of common
// base-class slots recurs across many classes); only tables at least this long are used as anchors.
const MIN_SLOTS: usize = 8;
// A run shorter than this is not even enumerated as a candidate vtable.
const MIN_RUN: usize = 4;
// Mnemonics decoded per slot to fingerprint its function. Sixteen characterises a slot without spilling
// far into the next function for short methods.
const SLOT_WINDOW: usize = 16;
// Base of the candidate-size window (the resolver widens it by a quarter of the reference length): a
// table whose slot count is within the window is aligned and scored, one wildly different in size is a
// different class and skipped before the more expensive alignment runs.
const COUNT_TOLERANCE: usize = 8;
// Instructions decoded when following a dispatch thunk (an adjustor thunk is two instructions).
const THUNK_INSTRS: usize = 2;

// The structural match is accepted only at this weighted-agreement floor and runner-up margin; below
// them the class has refactored past the per-slot fingerprint and the constructor-string grounding is
// tried instead. Measured basis: on the GMS lineage the structural chain holds within v83-v91 and
// declines to zero at the v95 class refactor (see CROSS_VERSION_BASELINE.md), and the round-trip sweep
// records zero conclusive wrong addresses under these gates. An installer-grounded match cannot report a
// real weighted agreement (it is located by string, not by alignment), so it returns the sentinel score
// below to mark itself grounded rather than structural. These are `pub(super)` so the production gate and
// the corpus harness that mirrors it share one source and cannot drift apart.
pub(super) const VT_STRUCT_MIN_AGREEMENT: f64 = 0.72;
pub(super) const VT_STRUCT_MIN_MARGIN: f64 = 0.10;
pub(super) const VT_GROUNDED_SCORE: f64 = 0.9;

/// The recompile-stable identity of a virtual method: the per-slot mnemonic fingerprint of the vtable it
/// is dispatched from, the index of its slot, and whether that slot dispatches through an adjustor thunk.
pub(super) struct VtableAnchor {
    pub slot: usize,
    pub via_thunk: bool,
    pub fingerprint: Vec<Vec<u16>>,
    /// Per-slot distinctiveness weight, the inverse of how many tables share that method: a
    /// class-specific override weighs ~1, a method inherited into many classes weighs little, so the
    /// shared base backbone cannot let a sibling class masquerade as the target's own table.
    pub weights: Vec<f64>,
    /// A string anchor for a constructor that installs this vtable, when one exists. It grounds the
    /// table across a major refactor the per-slot matcher cannot bridge: resolve the constructor by its
    /// build-stable string, read the vtable address it writes, and the table is found without matching
    /// its drifted internal structure.
    pub installer: Option<StringAnchor>,
}

fn in_code(img: &ImageInput, abs: usize) -> bool {
    img.code_regions
        .iter()
        .any(|r| abs >= r.base && abs < r.base + r.size)
}

fn whole_image(img: &ImageInput) -> Vec<u8> {
    read_region(img.source, img.base, img.size)
}

// Code-pointer width: 4 bytes on x86, 8 on x64. Vtable slots, and the pointer runs that identify a
// vtable, are this wide.
fn ptr_size(arch: Arch) -> usize {
    if matches!(arch, Arch::X64) { 8 } else { 4 }
}

// Read a `psize`-wide little-endian pointer at `i`, or `None` if it runs past `buf`.
fn read_ptr(buf: &[u8], i: usize, psize: usize) -> Option<usize> {
    let b = buf.get(i..i + psize)?;
    Some(if psize == 8 {
        u64::from_le_bytes(b.try_into().ok()?) as usize
    } else {
        u32::from_le_bytes(b.try_into().ok()?) as usize
    })
}

/// Every vtable in the image: a run of at least [`MIN_RUN`] consecutive pointer-wide (4 bytes on x86,
/// 8 on x64) values into executable code. Returns each run's start RVA and the slot target RVAs. Vtables
/// sit in `.rdata` or, in this corpus, in `.text`; scanning the whole image by pointer-into-code finds
/// them wherever they live. Every loop is bounded by the buffer length so a malformed image cannot spin.
fn vtables(img: &ImageInput, buf: &[u8]) -> Vec<(usize, Vec<usize>)> {
    let base = img.base;
    let psize = ptr_size(img.arch);
    let mut out = Vec::new();
    let mut i = 0usize;
    let end = buf.len() & !(psize - 1);
    while i + psize <= end {
        let v = read_ptr(buf, i, psize).unwrap_or(0);
        if in_code(img, v) {
            let start = i;
            let mut slots = Vec::new();
            while i + psize <= end {
                let v = read_ptr(buf, i, psize).unwrap_or(0);
                if !in_code(img, v) {
                    break;
                }
                slots.push(v - base);
                i += psize;
            }
            if slots.len() >= MIN_RUN {
                out.push((start, slots));
            }
        } else {
            i += psize;
        }
    }
    out
}

/// For the desktop inspector: is the function at `rva` a virtual method (a slot in some vtable)? Returns
/// the table's RVA, the slot index, the table's slot count, and the class name from MSVC RTTI when the
/// chain is present and navigable. RTTI is sparse and exception/framework-only on this corpus (see the
/// `rtti_is_sparse...` finding), so the class name is usually `None`; the structural membership always
/// resolves. x86 / PE32.
#[must_use]
pub(super) fn membership(
    img: &ImageInput,
    rva: usize,
) -> Option<(usize, usize, usize, Option<String>)> {
    let buf = whole_image(img);
    let psize = ptr_size(img.arch);
    for (start, slots) in vtables(img, &buf) {
        if let Some(slot) = slots.iter().position(|&s| s == rva) {
            return Some((
                start,
                slot,
                slots.len(),
                rtti_class_name(img, &buf, start, psize),
            ));
        }
    }
    None
}

// Best-effort MSVC RTTI class-name read (x86): vtable[-1] -> CompleteObjectLocator; COL+0x0C ->
// TypeDescriptor; TD+0x08 -> the mangled name (".?AVClassName@@"), de-mangled to "ClassName". These dumps
// are fixed-base (the locators hold absolute VAs, not image-base-relative offsets). `None` when any link
// is absent or out of range.
fn rtti_class_name(img: &ImageInput, buf: &[u8], table_rva: usize, psize: usize) -> Option<String> {
    if !matches!(img.arch, Arch::X86) {
        return None;
    }
    let base = img.base;
    let col_va = read_ptr(buf, table_rva.checked_sub(psize)?, psize)?;
    let col_rva = col_va.checked_sub(base)?;
    let td_va = read_ptr(buf, col_rva.checked_add(0x0C)?, psize)?;
    let name_off = td_va.checked_sub(base)?.checked_add(0x08)?;
    if name_off >= buf.len() {
        return None;
    }
    let rel_end = buf[name_off..].iter().take(160).position(|&b| b == 0)?;
    let raw = std::str::from_utf8(&buf[name_off..name_off + rel_end]).ok()?;
    demangle_rtti_name(raw)
}

// ".?AVCWvsContext@@" -> "CWvsContext"; ".?AUSomeStruct@@" -> "SomeStruct". `None` when it is not a
// class/struct type-descriptor name.
fn demangle_rtti_name(raw: &str) -> Option<String> {
    let s = raw
        .strip_prefix(".?AV")
        .or_else(|| raw.strip_prefix(".?AU"))?;
    let body = s.strip_suffix("@@").unwrap_or(s);
    let leaf = body.split('@').next().unwrap_or(body);
    (!leaf.is_empty() && leaf.chars().all(|c| c.is_ascii_graphic())).then(|| leaf.to_string())
}

/// The first `n` instruction mnemonics of the function at `rva`, the multiset fingerprint of one slot.
fn slot_mnemonics(img: &ImageInput, rva: usize, n: usize) -> Vec<u16> {
    let bytes = read_at(img.source, img.base, rva, n * 8);
    let mut dec = Decoder::with_ip(
        bitness(img.arch),
        &bytes,
        (img.base + rva) as u64,
        DecoderOptions::NONE,
    );
    let mut instr = Instruction::default();
    let mut out = Vec::with_capacity(n);
    while dec.can_decode() && out.len() < n {
        dec.decode_out(&mut instr);
        if instr.is_invalid() || instr.len() == 0 {
            break;
        }
        out.push(instr.mnemonic() as u16);
        if instr.flow_control() == FlowControl::Return {
            break;
        }
    }
    out
}

/// A per-slot fingerprint sorted ascending, so [`dice_sorted`] can intersect two of them by a linear
/// merge with no per-call allocation (the alignment scores every slot pair, so this is the hot path).
fn sorted(v: &[u16]) -> Vec<u16> {
    let mut s = v.to_vec();
    s.sort_unstable();
    s
}

/// Sorensen-Dice over two pre-sorted mnemonic multisets, counting repeats: `2*inter / (|a| + |b|)`.
fn dice_sorted(a: &[u16], b: &[u16]) -> f64 {
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    let (mut i, mut j, mut inter) = (0usize, 0usize, 0usize);
    while i < a.len() && j < b.len() {
        match a[i].cmp(&b[j]) {
            std::cmp::Ordering::Less => i += 1,
            std::cmp::Ordering::Greater => j += 1,
            std::cmp::Ordering::Equal => {
                inter += 1;
                i += 1;
                j += 1;
            }
        }
    }
    2.0 * inter as f64 / (a.len() + b.len()) as f64
}

// Affine-gap alignment constants, integer-scaled so the dynamic program is exact and deterministic. A
// matched pair scores round((2*dice - 1) * SCALE): +SCALE for an identical slot, 0 at Dice 0.5, -SCALE
// for a disjoint pair. Opening a gap costs just past a single fully mismatched slot, so the alignment
// never gaps a pair that shares any mnemonics; extending a gap is cheap, so a contiguous block of
// inserted or removed methods is one event, not many.
const SCALE: i64 = 100;
const GAP_OPEN: i64 = -120;
const GAP_EXTEND: i64 = -28;
// A sentinel for an unreachable cell, kept far from the i64 bounds so `saturating_add` never wraps.
const NEG: i64 = i64::MIN / 4;

/// Gotoh global alignment with affine gaps and free end-gaps, over two pre-sorted slot-fingerprint
/// sequences. Free end-gaps let a block of methods prepended or appended in a newer build (the usual
/// cross-major change) align at no cost instead of dragging the agreement down; affine gaps coalesce a
/// contiguous inserted or removed block into one penalty. Returns the mapping from each reference slot
/// to its aligned candidate slot (`None` where a method has no counterpart), which lets the target slot
/// follow methods inserted or removed before it. Match quality is then scored by [`weighted_agreement`].
fn align(ref_fp: &[Vec<u16>], cand_fp: &[Vec<u16>]) -> Vec<Option<usize>> {
    let m = ref_fp.len();
    let n = cand_fp.len();
    if m == 0 || n == 0 {
        return vec![None; m];
    }
    let w = n + 1;
    let sc = |i: usize, j: usize| -> i64 {
        ((2.0 * dice_sorted(&ref_fp[i], &cand_fp[j]) - 1.0) * SCALE as f64).round() as i64
    };
    let mut mm = vec![NEG; (m + 1) * w]; // best alignment ending by pairing ref[i-1] with cand[j-1]
    let mut gx = vec![NEG; (m + 1) * w]; // ending with ref[i-1] over a gap (cand not consumed)
    let mut gy = vec![NEG; (m + 1) * w]; // ending with cand[j-1] over a gap (ref not consumed)
    let mut mp = vec![0u8; (m + 1) * w]; // mm predecessor: 0 = mm, 1 = gx, 2 = gy at (i-1, j-1)
    let mut xp = vec![0u8; (m + 1) * w]; // gx predecessor: 0 = mm, 1 = gx at (i-1, j)
    let mut yp = vec![0u8; (m + 1) * w]; // gy predecessor: 0 = mm, 2 = gy at (i, j-1)
    mm[0] = 0;
    for i in 1..=m {
        gx[i * w] = 0; // free leading gap: a reference prefix with no counterpart costs nothing
    }
    gy[1..=n].fill(0); // free leading gap: a candidate prefix with no counterpart costs nothing
    for i in 1..=m {
        for j in 1..=n {
            let (mut bp, mut bv) = (0u8, mm[(i - 1) * w + (j - 1)]);
            if gx[(i - 1) * w + (j - 1)] > bv {
                bv = gx[(i - 1) * w + (j - 1)];
                bp = 1;
            }
            if gy[(i - 1) * w + (j - 1)] > bv {
                bv = gy[(i - 1) * w + (j - 1)];
                bp = 2;
            }
            mm[i * w + j] = sc(i - 1, j - 1).saturating_add(bv);
            mp[i * w + j] = bp;

            let open = mm[(i - 1) * w + j].saturating_add(GAP_OPEN);
            let ext = gx[(i - 1) * w + j].saturating_add(GAP_EXTEND);
            (gx[i * w + j], xp[i * w + j]) = if open >= ext { (open, 0) } else { (ext, 1) };

            let open = mm[i * w + (j - 1)].saturating_add(GAP_OPEN);
            let ext = gy[i * w + (j - 1)].saturating_add(GAP_EXTEND);
            (gy[i * w + j], yp[i * w + j]) = if open >= ext { (open, 0) } else { (ext, 2) };
        }
    }
    // Free trailing gaps: the alignment may end anywhere in the last row or last column.
    let (mut bi, mut bj, mut bs, mut bm) = (0usize, 0usize, NEG, 0u8);
    for j in 0..=n {
        for (mat, v) in [(0u8, mm[m * w + j]), (1, gx[m * w + j]), (2, gy[m * w + j])] {
            if v > bs {
                (bs, bi, bj, bm) = (v, m, j, mat);
            }
        }
    }
    for i in 0..=m {
        for (mat, v) in [(0u8, mm[i * w + n]), (1, gx[i * w + n]), (2, gy[i * w + n])] {
            if v > bs {
                (bs, bi, bj, bm) = (v, i, n, mat);
            }
        }
    }

    let mut mapping = vec![None; m];
    let (mut i, mut j, mut mat) = (bi, bj, bm);
    while i > 0 && j > 0 {
        match mat {
            0 => {
                mapping[i - 1] = Some(j - 1);
                mat = mp[i * w + j];
                i -= 1;
                j -= 1;
            }
            1 => {
                mat = xp[i * w + j];
                i -= 1;
            }
            _ => {
                mat = yp[i * w + j];
                j -= 1;
            }
        }
    }
    mapping
}

/// Distinctiveness-weighted mean matched Dice of a reference table against a candidate over an alignment
/// `mapping`. A reference slot aligned to a candidate slot contributes `weight * dice`; a gapped slot
/// contributes nothing but still counts in the denominator, so a missing class-specific override (high
/// weight) sharply lowers the score while a missing shared base method (low weight) barely moves it.
/// This is what separates the target's own table from a sibling class that shares only the backbone.
fn weighted_agreement(
    ref_fp: &[Vec<u16>],
    cand_fp: &[Vec<u16>],
    mapping: &[Option<usize>],
    weights: &[f64],
) -> f64 {
    let mut num = 0.0;
    let mut den = 0.0;
    for (i, slot) in mapping.iter().enumerate() {
        let weight = weights.get(i).copied().unwrap_or(1.0);
        den += weight;
        if let Some(j) = slot {
            num += weight * dice_sorted(&ref_fp[i], &cand_fp[*j]);
        }
    }
    if den > 0.0 { num / den } else { 0.0 }
}

// An MSVC adjustor thunk's first instruction adjusts the `this` pointer by a constant before the jump.
fn is_adjustor(instr: &Instruction) -> bool {
    matches!(instr.mnemonic(), Mnemonic::Add | Mnemonic::Sub)
        && instr.op0_kind() == OpKind::Register
        && matches!(
            instr.op1_kind(),
            OpKind::Immediate8
                | OpKind::Immediate8to16
                | OpKind::Immediate8to32
                | OpKind::Immediate16
                | OpKind::Immediate32
        )
}

/// Resolve a slot to the real method it dispatches, following one adjustor or plain-jump thunk. A direct
/// slot is returned unchanged; a thunk (`jmp fn`, or `add ecx, imm ; jmp fn` under multiple inheritance)
/// is followed to `fn`. The boolean reports whether a thunk was traversed.
fn follow_thunk(img: &ImageInput, slot_rva: usize) -> (usize, bool) {
    let bytes = read_at(img.source, img.base, slot_rva, THUNK_INSTRS * 8);
    let mut dec = Decoder::with_ip(
        bitness(img.arch),
        &bytes,
        (img.base + slot_rva) as u64,
        DecoderOptions::NONE,
    );
    let mut instr = Instruction::default();
    if !dec.can_decode() {
        return (slot_rva, false);
    }
    dec.decode_out(&mut instr);
    if instr.is_invalid() || instr.len() == 0 {
        return (slot_rva, false);
    }
    if instr.flow_control() == FlowControl::UnconditionalBranch {
        let t = instr.near_branch_target() as usize;
        if in_code(img, t) {
            return (t - img.base, true);
        }
        return (slot_rva, false);
    }
    if is_adjustor(&instr) && dec.can_decode() {
        dec.decode_out(&mut instr);
        if !instr.is_invalid() && instr.flow_control() == FlowControl::UnconditionalBranch {
            let t = instr.near_branch_target() as usize;
            if in_code(img, t) {
                return (t - img.base, true);
            }
        }
    }
    (slot_rva, false)
}

/// The code-pointer run starting exactly at `vt_rva`, or `None` if there is no run of at least
/// [`MIN_RUN`] pointers there. Used to read a vtable at an address recovered from its constructor.
fn vtable_at(img: &ImageInput, buf: &[u8], vt_rva: usize) -> Option<Vec<usize>> {
    let mut slots = Vec::new();
    let mut i = vt_rva;
    while i + 4 <= buf.len() {
        let v = u32::from_le_bytes([buf[i], buf[i + 1], buf[i + 2], buf[i + 3]]) as usize;
        if !in_code(img, v) {
            break;
        }
        slots.push(v - img.base);
        i += 4;
    }
    (slots.len() >= MIN_RUN).then_some(slots)
}

// Bytes scanned on each side of a string-anchored function for the vtable address it installs: a
// constructor's `mov [obj], offset vtable` sits within this of its string load, even when a prologue
// split puts them in adjacent enclosing-function pieces.
const INSTALL_WINDOW: usize = 2048;

/// Whether the vtable address `vt_abs` appears as a 4-byte value within [`INSTALL_WINDOW`] of `f`.
fn window_has_vtable(buf: &[u8], f: usize, vt_abs: u32) -> bool {
    let lo = f.saturating_sub(INSTALL_WINDOW);
    let hi = (f + INSTALL_WINDOW).min(buf.len().saturating_sub(4));
    (lo..=hi).any(|i| u32::from_le_bytes([buf[i], buf[i + 1], buf[i + 2], buf[i + 3]]) == vt_abs)
}

/// Find a string-anchorable function next to a site that installs the vtable at `vt_abs`. The function
/// that loads the class string and the instruction that writes the vtable can land in adjacent
/// prologue-split pieces, so the test is not "the install site IS the string function" but "the string
/// function's window contains the install", which the resolve step mirrors. Returns that string anchor.
fn find_installer(img: &ImageInput, buf: &[u8], vt_abs: u32) -> Option<StringAnchor> {
    let mut seen = std::collections::BTreeSet::new();
    let mut i = 0usize;
    while i + 4 <= buf.len() {
        if u32::from_le_bytes([buf[i], buf[i + 1], buf[i + 2], buf[i + 3]]) == vt_abs
            && in_code(img, img.base + i)
        {
            let ctor = enclosing_function(img, i);
            if seen.insert(ctor)
                && let Some(sa) = make_string_anchor(img, ctor)
                && let Some(f) = resolve_string_anchor(img, &sa)
                && window_has_vtable(buf, f, vt_abs)
            {
                return Some(sa);
            }
        }
        i += 1;
    }
    None
}

/// The vtable a string-anchored function installs: scan within [`INSTALL_WINDOW`] of `anchor_fn` for a
/// 4-byte value that starts a code-pointer run, returning the run whose fingerprint best matches `ref_fp`
/// (when several vtables sit nearby, the target's own wins).
fn installed_vtable(
    img: &ImageInput,
    buf: &[u8],
    anchor_fn: usize,
    ref_fp: &[Vec<u16>],
    weights: &[f64],
    slot_idx: usize,
) -> Option<(Vec<usize>, usize)> {
    let lo = anchor_fn.saturating_sub(INSTALL_WINDOW);
    let hi = (anchor_fn + INSTALL_WINDOW).min(buf.len().saturating_sub(4));
    let mut best: Option<(Vec<usize>, usize, f64)> = None;
    let mut seen = std::collections::BTreeSet::new();
    for i in lo..=hi {
        let v = u32::from_le_bytes([buf[i], buf[i + 1], buf[i + 2], buf[i + 3]]) as usize;
        let Some(rva) = v.checked_sub(img.base) else {
            continue;
        };
        let Some(slots) = vtable_at(img, buf, rva) else {
            continue;
        };
        if !seen.insert(rva) {
            continue;
        }
        let cand_fp: Vec<Vec<u16>> = slots
            .iter()
            .map(|&sv| sorted(&slot_mnemonics(img, sv, SLOT_WINDOW)))
            .collect();
        let mapping = align(ref_fp, &cand_fp);
        // The target's own slot must relocate into this table, not merely some slots match overall: a
        // neighbour table can share the backbone yet lack the target method.
        let Some(cs) = mapping.get(slot_idx).copied().flatten() else {
            continue;
        };
        let d = dice_sorted(&ref_fp[slot_idx], &cand_fp[cs]);
        if d < 0.15 {
            continue;
        }
        let score = d + weighted_agreement(ref_fp, &cand_fp, &mapping, weights);
        if best.as_ref().is_none_or(|(_, _, s)| score > *s) {
            best = Some((slots, cs, score));
        }
    }
    best.map(|(slots, cs, _)| (slots, cs))
}

/// Relocate the target through its constructor: resolve the installer's string to the constructor here,
/// read the vtable address it writes, then align and read the target slot. This grounds the table by a
/// build-stable string and so survives a major refactor the per-slot structural matcher declines on.
fn resolve_via_installer(img: &ImageInput, anchor: &VtableAnchor) -> Option<usize> {
    let inst = anchor.installer.as_ref()?;
    let f = resolve_string_anchor(img, inst)?;
    let buf = whole_image(img);
    let ref_fp: Vec<Vec<u16>> = anchor.fingerprint.iter().map(|v| sorted(v)).collect();
    let (slots, cand_slot) = installed_vtable(img, &buf, f, &ref_fp, &anchor.weights, anchor.slot)?;
    let (real, _) = follow_thunk(img, slots[cand_slot]);
    Some(real)
}

/// Build a vtable anchor for the method whose entry is `target_entry`: find the vtable that dispatches it
/// (directly or through a thunk) and capture that table's per-slot fingerprint and the target's slot.
/// Among several tables that contain the method, the largest is chosen (most structure to match on),
/// preferring a direct slot over a thunked one. Returns `None` if no table of at least [`MIN_SLOTS`]
/// dispatches the method. x86 only.
#[must_use]
pub(super) fn make_vtable_anchor(img: &ImageInput, target_entry: usize) -> Option<VtableAnchor> {
    let buf = whole_image(img);
    let vts = vtables(img, &buf);
    // How many distinct tables share each method: an inherited base method recurs across many vtables, a
    // class-specific override appears in one. This drives the per-slot distinctiveness weight below.
    let mut table_count: HashMap<usize, u32> = HashMap::new();
    for (_s, slots) in &vts {
        for rva in slots.iter().copied().collect::<HashSet<_>>() {
            *table_count.entry(rva).or_default() += 1;
        }
    }
    // Every table that dispatches the method (>= MIN_SLOTS): (slot count, start RVA, slot index, via).
    let mut candidates: Vec<(usize, usize, usize, bool)> = Vec::new();
    for (start, slots) in &vts {
        if slots.len() < MIN_SLOTS {
            continue;
        }
        for (i, &sv) in slots.iter().enumerate() {
            let (real, via) = follow_thunk(img, sv);
            if real == target_entry {
                candidates.push((slots.len(), *start, i, via));
                break; // a method rarely appears twice in one table; the first slot is enough
            }
        }
    }
    // Largest table first (most structure to match on), a direct slot before a thunked one, lowest
    // address to break ties.
    candidates.sort_by(|a, b| b.0.cmp(&a.0).then(a.3.cmp(&b.3)).then(a.1.cmp(&b.1)));
    // Prefer a table whose constructor pins itself by a string, since that grounds it across a refactor
    // the per-slot matcher cannot bridge (a shared method like a destructor sits in many sibling tables;
    // only the one with an anchorable installer can be relocated when the structure drifts). Otherwise
    // take the largest. Probe in priority order, bounded so a widely shared method does not explode.
    let mut choice: Option<(usize, usize, bool, Option<StringAnchor>)> = None;
    for &(_, start, slot, via) in candidates.iter().take(32) {
        // Constructor grounding scans for an absolute 4-byte reference to the table, an x86/PE32 form.
        // x64 references the table RIP-relatively and its address exceeds u32, so x64 relies on the
        // structural per-slot match alone rather than a truncated, potentially wrong scan.
        let inst = if matches!(img.arch, Arch::X86) {
            find_installer(img, &buf, (img.base + start) as u32)
        } else {
            None
        };
        let grounded = inst.is_some();
        if choice.is_none() || grounded {
            choice = Some((start, slot, via, inst));
        }
        if grounded {
            break;
        }
    }
    let (start, slot, via_thunk, installer) = choice?;
    let slots = vts.iter().find(|(s, _)| *s == start).map(|(_, sl)| sl)?;
    let fingerprint = slots
        .iter()
        .map(|&sv| slot_mnemonics(img, sv, SLOT_WINDOW))
        .collect();
    let weights = slots
        .iter()
        .map(|sv| 1.0 / f64::from(table_count.get(sv).copied().unwrap_or(1).max(1)))
        .collect();
    Some(VtableAnchor {
        slot,
        via_thunk,
        fingerprint,
        weights,
        installer,
    })
}

/// Relocate a vtable anchor into `img`: find the table whose slot fingerprints best align to the
/// anchor's (by Needleman-Wunsch, so methods inserted or removed across versions shift the match rather
/// than breaking it), then read the aligned target slot and follow any thunk to the method's address
/// here. Returns the relocated method RVA, the best table's agreement, and the runner-up's, so the
/// caller can reject an ambiguous (low-margin) match. x86 only.
#[must_use]
pub(super) fn resolve_vtable_anchor(
    img: &ImageInput,
    anchor: &VtableAnchor,
) -> Option<(usize, f64, f64)> {
    let buf = whole_image(img);
    let vts = vtables(img, &buf);
    let rl = anchor.fingerprint.len();
    // Alignment absorbs inserted and removed methods, so the size window can be generous; the agreement
    // and margin gates, not this filter, are what reject an unrelated table.
    let drift = rl / 4 + COUNT_TOLERANCE;
    let ref_fp: Vec<Vec<u16>> = anchor.fingerprint.iter().map(|v| sorted(v)).collect();
    let mut best_score = 0.0f64;
    let mut second = 0.0f64;
    let mut best: Option<(Vec<usize>, Vec<Option<usize>>)> = None;
    for (_start, slots) in &vts {
        if slots.is_empty() || slots.len() + drift < rl || slots.len() > rl + drift {
            continue;
        }
        let cand_fp: Vec<Vec<u16>> = slots
            .iter()
            .map(|&sv| sorted(&slot_mnemonics(img, sv, SLOT_WINDOW)))
            .collect();
        let mapping = align(&ref_fp, &cand_fp);
        let score = weighted_agreement(&ref_fp, &cand_fp, &mapping, &anchor.weights);
        if score > best_score {
            second = best_score;
            best_score = score;
            best = Some((slots.clone(), mapping));
        } else if score > second {
            second = score;
        }
    }
    // The structural match: the target method's counterpart in the best-aligned table.
    let structural = best.and_then(|(slots, mapping)| {
        let cs = mapping.get(anchor.slot).copied().flatten()?;
        let &slot_rva = slots.get(cs)?;
        Some((follow_thunk(img, slot_rva).0, best_score, second))
    });
    // A confident, unambiguous structural match wins and is exact (these are the gates the caller
    // applies). When it is weak or ambiguous, the class refactored past the per-slot matcher: ground the
    // table through its constructor's build-stable string instead, which names the exact table.
    if let Some((r, a, runner)) = structural
        && a >= VT_STRUCT_MIN_AGREEMENT
        && a - runner >= VT_STRUCT_MIN_MARGIN
    {
        return Some((r, a, runner));
    }
    if let Some(real) = resolve_via_installer(img, anchor) {
        return Some((real, VT_GROUNDED_SCORE, 0.0));
    }
    structural
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::{BufferSource, Region};

    const BASE: usize = 0x40_0000;

    // An x86 image whose code region holds ten tiny functions and whose data tail holds a vtable of
    // pointers to them. Functions use distinct one-byte instructions so per-slot fingerprints differ.
    fn synthetic() -> (Vec<u8>, Vec<usize>, usize) {
        let mut buf = vec![0u8; 0x400];
        let mut fn_rvas = Vec::new();
        for j in 0..10usize {
            let rva = 0x100 + j * 0x20;
            fn_rvas.push(rva);
            let opcode = 0x40 + (j as u8 % 8); // inc/dec eax..edi: a distinct one-byte instruction
            for k in 0..(j + 2) {
                buf[rva + k] = opcode;
            }
            buf[rva + j + 2] = 0xC3; // ret
        }
        // The vtable: ten absolute pointers to the functions, then a zero terminator.
        let table = 0x300usize;
        for (k, &rva) in fn_rvas.iter().enumerate() {
            let abs = (BASE + rva) as u32;
            buf[table + k * 4..table + k * 4 + 4].copy_from_slice(&abs.to_le_bytes());
        }
        (buf, fn_rvas, table)
    }

    fn image<'a>(src: &'a BufferSource, code: Region) -> ImageInput<'a> {
        ImageInput {
            label: "t".into(),
            source: src,
            base: BASE,
            size: 0x400,
            code_regions: vec![code],
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

    // An x64 image: ten tiny functions (distinct single-byte instructions, since 0x40..0x47 are REX
    // prefixes on x64) and a data-tail vtable of 8-byte pointers into them.
    fn synthetic_x64() -> (Vec<u8>, Vec<usize>, usize) {
        const OPS: [u8; 10] = [0x90, 0x99, 0x98, 0x9C, 0x9D, 0xF5, 0xF8, 0xF9, 0xFC, 0xFD];
        let mut buf = vec![0u8; 0x400];
        let mut fn_rvas = Vec::new();
        for j in 0..10usize {
            let rva = 0x100 + j * 0x20;
            fn_rvas.push(rva);
            for k in 0..(j + 2) {
                buf[rva + k] = OPS[j];
            }
            buf[rva + j + 2] = 0xC3; // ret
        }
        let table = 0x300usize;
        for (k, &rva) in fn_rvas.iter().enumerate() {
            let abs = (BASE + rva) as u64;
            buf[table + k * 8..table + k * 8 + 8].copy_from_slice(&abs.to_le_bytes());
        }
        (buf, fn_rvas, table)
    }

    fn image_x64<'a>(src: &'a BufferSource, code: Region) -> ImageInput<'a> {
        ImageInput {
            arch: Arch::X64,
            ..image(src, code)
        }
    }

    #[test]
    #[ignore = "needs the real GMS clients in X:\\Client_Unpacked; run with --ignored"]
    fn rtti_is_sparse_and_exception_only_not_a_general_anchor() {
        // Phase 3 premise check: real classes carry navigable RTTI, and the mangled class names persist
        // across the v95 refactor that drives the structural chain reach to 0% (CROSS_VERSION_BASELINE).
        // If this holds, RTTI class-name grounding bridges exactly where the per-slot matcher declines.
        use crate::fileimage::FileImage;
        use std::path::Path;

        let dir = Path::new(r"X:\Client_Unpacked");
        let names = ["GMS_v83.1_U_DEVM.exe", "GMS_v95.1_U_DEVM.exe"];
        if names.iter().any(|n| !dir.join(n).exists()) {
            eprintln!("real GMS clients not present; skipping");
            return;
        }
        fn mk(img: &FileImage) -> ImageInput<'_> {
            let pack = img.pack_report();
            ImageInput {
                label: String::new(),
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
        let i83 = FileImage::open(&dir.join(names[0])).unwrap();
        let img = mk(&i83);
        let base = img.base;
        let buf = whole_image(&img);
        // A: are the TypeDescriptor name strings even present in the mapped image (as opposed to only in
        // the raw file)? Scan for the mangled-name marker and report where.
        let mut td_name_rvas: Vec<usize> = Vec::new();
        let mut w = 0usize;
        while w + 4 <= buf.len() {
            if &buf[w..w + 4] == b".?AV" || &buf[w..w + 4] == b".?AU" {
                td_name_rvas.push(w);
            }
            w += 1;
        }
        eprintln!(
            "v83 base=0x{base:X} size=0x{:X}; '.?AV/.?AU' RTTI name occurrences in mapped image: {}",
            img.size,
            td_name_rvas.len()
        );
        for &r in td_name_rvas.iter().take(6) {
            let end = buf[r..].iter().take(96).position(|&b| b == 0).unwrap_or(0);
            eprintln!(
                "  name@rva 0x{r:X}: {}",
                String::from_utf8_lossy(&buf[r..r + end])
            );
        }
        // C/D: reverse-walk from the first few names. td = name-8, td_va = base+td_rva. Find a COL whose
        // +0x0C points at td_va (and whose +0 signature is 0), then a pointer equal to that COL's VA (a
        // vtable[-1]). This reveals whether the COL/locator chain exists and at what offsets, independent
        // of any assumption the forward reader makes.
        for &name_rva in td_name_rvas.iter().take(5) {
            let td_va = base + name_rva - 8;
            let mut col_rva = None;
            let mut c = 0usize;
            while c + 0x10 <= buf.len() {
                if read_ptr(&buf, c + 0x0C, 4) == Some(td_va) && read_ptr(&buf, c, 4) == Some(0) {
                    col_rva = Some(c);
                    break;
                }
                c += 4;
            }
            match col_rva {
                None => eprintln!("  td_va 0x{td_va:X}: no COL (sig0 + +0xC->td) found"),
                Some(cr) => {
                    let col_va = base + cr;
                    let mut vtm1 = None;
                    let mut p = 0usize;
                    while p + 4 <= buf.len() {
                        if read_ptr(&buf, p, 4) == Some(col_va) {
                            vtm1 = Some(p);
                            break;
                        }
                        p += 4;
                    }
                    eprintln!(
                        "  td_va 0x{td_va:X}: COL@rva 0x{cr:X} (va 0x{col_va:X}); vtable[-1]@rva {vtm1:X?} (vtable starts at +4)"
                    );
                }
            }
        }
        // Finding (Phase 3): RTTI is present but sparse and exception/framework-only. v83 carries ~16
        // type descriptors, every one an exception/error/security type (the C++ classes whose exception
        // handling forces RTTI); the gameplay classes a user actually relocates (CWvsContext, CUser,
        // packet handlers) carry none, because the client is built /GR- everywhere else. The reverse-walk
        // above confirms the locator chain is real where it exists, so this is not a reader bug. The
        // consequence: RTTI class-name grounding cannot bridge the v95 break for the targets that matter,
        // so the audit's "RTTI is the highest-value vtable anchor" does not hold for this corpus. The real
        // cross-v95 bridge is the ensemble plus graph alignment (Phases 4/7), not RTTI. This test pins the
        // finding so a future, RTTI-rich corpus would re-open the question.
        assert!(
            !td_name_rvas.is_empty(),
            "RTTI name strings are present (sparse) on real GMS"
        );
        assert!(
            td_name_rvas.len() < 64,
            "RTTI is expected to be sparse/exception-only here; {} names would suggest a richer corpus worth re-evaluating",
            td_name_rvas.len()
        );
    }

    #[test]
    fn vtable_round_trips_on_x64() {
        // #12: the structural per-slot matcher is arch-neutral, and vtables now reads 8-byte x64
        // pointers. A synthetic x64 image with one 10-slot table of 8-byte function pointers: vtables
        // enumerates it, and an anchor for one slot relocates back onto itself. Constructor grounding
        // stays x86-only, so x64 uses the structural match alone (installer is None). Validated
        // synthetically because no x64 MapleStory client exists to measure against.
        let (buf, fn_rvas, table) = synthetic_x64();
        let src = BufferSource::new(BASE, buf.clone());
        let img = image_x64(
            &src,
            Region {
                base: BASE + 0x100,
                size: 0x200,
            },
        );
        let found = vtables(&img, &buf);
        let vt = found
            .iter()
            .find(|(start, _)| *start == table)
            .expect("the x64 8-byte-pointer table is enumerated as a vtable");
        assert_eq!(
            vt.1, fn_rvas,
            "all ten 8-byte slots resolve to the function RVAs"
        );

        let target = fn_rvas[3];
        let anchor = make_vtable_anchor(&img, target).expect("the x64 method is a vtable slot");
        assert_eq!(anchor.slot, 3);
        assert!(
            anchor.installer.is_none(),
            "x64 grounds structurally, with no installer fallback"
        );
        let (rva, agreement, _runner) =
            resolve_vtable_anchor(&img, &anchor).expect("the x64 table relocates onto itself");
        assert_eq!(rva, target, "the slot reads back to the same method");
        assert!(agreement > 0.99);
    }

    #[test]
    fn vtables_enumerates_a_run_of_code_pointers() {
        let (buf, fn_rvas, table) = synthetic();
        let src = BufferSource::new(BASE, buf.clone());
        // Code region covers only the functions, so the table's bytes are data that point into it.
        let img = image(
            &src,
            Region {
                base: BASE + 0x100,
                size: 0x200,
            },
        );
        let found = vtables(&img, &buf);
        let vt = found
            .iter()
            .find(|(start, _)| *start == table)
            .expect("the function-pointer table is enumerated as a vtable");
        assert_eq!(vt.1, fn_rvas, "all ten slots resolve to the function RVAs");
    }

    #[test]
    fn make_and_resolve_round_trip_on_one_image() {
        let (buf, fn_rvas, _) = synthetic();
        let src = BufferSource::new(BASE, buf);
        let img = image(
            &src,
            Region {
                base: BASE + 0x100,
                size: 0x200,
            },
        );
        let target = fn_rvas[3];
        let anchor = make_vtable_anchor(&img, target).expect("the method is a vtable slot");
        assert_eq!(anchor.slot, 3);
        assert!(!anchor.via_thunk);
        let (rva, agreement, _runner) =
            resolve_vtable_anchor(&img, &anchor).expect("the table relocates onto itself");
        assert_eq!(rva, target, "the slot reads back to the same method");
        assert!(agreement > 0.99, "an image matches itself at agreement 1.0");
    }

    #[test]
    fn follow_thunk_follows_a_plain_jump() {
        // jmp rel32 at rva 0x10 to a `ret` at rva 0x40; whole image is code.
        let mut buf = vec![0u8; 0x100];
        buf[0x40] = 0xC3;
        let rel = 0x40i32 - (0x10 + 5);
        buf[0x10] = 0xE9;
        buf[0x11..0x15].copy_from_slice(&rel.to_le_bytes());
        let src = BufferSource::new(BASE, buf);
        let img = image(
            &src,
            Region {
                base: BASE,
                size: 0x100,
            },
        );
        assert_eq!(follow_thunk(&img, 0x10), (0x40, true));
    }

    #[test]
    fn follow_thunk_follows_an_adjustor_thunk() {
        // add ecx, 8 ; jmp rel32 -> ret at 0x40.
        let mut buf = vec![0u8; 0x100];
        buf[0x40] = 0xC3;
        buf[0x10] = 0x83; // add ecx, 8
        buf[0x11] = 0xC1;
        buf[0x12] = 0x08;
        let rel = 0x40i32 - (0x13 + 5);
        buf[0x13] = 0xE9; // jmp rel32
        buf[0x14..0x18].copy_from_slice(&rel.to_le_bytes());
        let src = BufferSource::new(BASE, buf);
        let img = image(
            &src,
            Region {
                base: BASE,
                size: 0x100,
            },
        );
        assert_eq!(follow_thunk(&img, 0x10), (0x40, true));
    }

    #[test]
    fn follow_thunk_leaves_a_direct_function_unchanged() {
        // A real function entry (not a thunk) is returned as-is.
        let mut buf = vec![0u8; 0x100];
        buf[0x10] = 0x55; // push ebp
        buf[0x11] = 0x8B; // mov ebp, esp
        buf[0x12] = 0xEC;
        let src = BufferSource::new(BASE, buf);
        let img = image(
            &src,
            Region {
                base: BASE,
                size: 0x100,
            },
        );
        assert_eq!(follow_thunk(&img, 0x10), (0x10, false));
    }

    #[test]
    fn align_absorbs_a_front_insertion() {
        // The candidate prepends two methods with no counterpart in the reference; free end-gaps must
        // let the shared tail still align 1:1 at full agreement (the cross-major front-block case).
        let (a, b, c, d) = (vec![1u16, 2], vec![3u16, 4], vec![5u16, 6], vec![7u16, 8]);
        let ref_fp = vec![a.clone(), b.clone(), c.clone(), d.clone()];
        let cand_fp = vec![vec![20u16, 21], vec![22u16, 23], a, b, c, d];
        let mapping = align(&ref_fp, &cand_fp);
        assert_eq!(mapping, vec![Some(2), Some(3), Some(4), Some(5)]);
        let agree = weighted_agreement(&ref_fp, &cand_fp, &mapping, &[1.0; 4]);
        assert!(agree > 0.99, "shared tail must align fully, got {agree}");
    }

    #[test]
    fn align_absorbs_a_middle_block_insertion() {
        // Two methods inserted between B and C; affine gaps coalesce them and the rest aligns 1:1.
        let (a, b, c, d) = (vec![1u16, 2], vec![3u16, 4], vec![5u16, 6], vec![7u16, 8]);
        let ref_fp = vec![a.clone(), b.clone(), c.clone(), d.clone()];
        let cand_fp = vec![a, b, vec![30u16, 31], vec![32u16, 33], c, d];
        let mapping = align(&ref_fp, &cand_fp);
        assert_eq!(mapping, vec![Some(0), Some(1), Some(4), Some(5)]);
    }

    // Build an ImageInput over a real on-disk client. Returns None when the corpus is absent so the
    // ignored tests below can skip cleanly off the build machine.
    #[cfg(test)]
    fn open_real<'a>(img: &'a crate::fileimage::FileImage, label: &str) -> ImageInput<'a> {
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

    // The headline claim, through the production resolver (run with `--ignored`): the 101-slot vtable at
    // v84 .text RVA 0x78F16C maps onto its counterpart in a real recompile (v88) and an adjacent build
    // (v83) with a high, unambiguous per-slot agreement, so a virtual method in it relocates by table
    // structure alone. Measured previously at v88 0.949 (margin 0.415) and v83 1.000 (margin 0.46).
    #[test]
    #[ignore = "needs the real GMS clients in X:\\Client_Unpacked; run with --ignored"]
    fn vtable_matching_relocates_the_real_gms_table_across_builds() {
        use crate::fileimage::FileImage;
        use std::path::Path;

        let dir = Path::new(r"X:\Client_Unpacked");
        let paths = [
            dir.join("GMS_v83.1_U_DEVM.exe"),
            dir.join("GMS_v84.1_U_DEVM.exe"),
            dir.join("GMS_v88.1_U_DEVM.exe"),
        ];
        if paths.iter().any(|p| !p.exists()) {
            eprintln!("real GMS clients not present; skipping");
            return;
        }
        let v83i = FileImage::open(&paths[0]).expect("open v83");
        let v84i = FileImage::open(&paths[1]).expect("open v84");
        let v88i = FileImage::open(&paths[2]).expect("open v88");
        let v83 = open_real(&v83i, "v83");
        let v84 = open_real(&v84i, "v84");
        let v88 = open_real(&v88i, "v88");

        // Locate the run that contains the known table start through the production enumerator.
        let buf84 = whole_image(&v84);
        let vts84 = vtables(&v84, &buf84);
        let (start, slots) = vts84
            .iter()
            .find(|(s, sl)| *s <= 0x78F16C && 0x78F16C < *s + sl.len() * 4)
            .expect("the target vtable is enumerated in v84");
        eprintln!("v84 target vtable @0x{start:X}: {} slots", slots.len());
        assert!(
            (90..=112).contains(&slots.len()),
            "target table slot count {} outside the expected window",
            slots.len()
        );

        // A direct (non-thunk) slot's method, anchored through the production path (weights and all).
        let slot_idx = slots
            .iter()
            .position(|&sv| !follow_thunk(&v84, sv).1)
            .expect("a direct slot in the table");
        let anchor =
            make_vtable_anchor(&v84, slots[slot_idx]).expect("anchor the clean slot method");

        // Self-match on v84: agreement 1.0, reads the same method back.
        let (r84, a84, run84) = resolve_vtable_anchor(&v84, &anchor).expect("v84 self-match");
        eprintln!(
            "v84 self: rva 0x{r84:X} agreement {a84:.3} margin {:.3}",
            a84 - run84
        );
        assert_eq!(r84, slots[slot_idx], "self-resolve reads the same slot");
        assert!(a84 > 0.99, "an image matches itself near 1.0");

        // v84 -> v88 (a real recompile) and v84 -> v83: the table maps with a clear margin. Bounds are
        // the production gates (VT_MIN_AGREEMENT 0.72 / VT_MIN_MARGIN 0.10); the actual values printed
        // here are far higher.
        for (img, name) in [(&v88, "v88"), (&v83, "v83")] {
            let (rva, agree, runner) =
                resolve_vtable_anchor(img, &anchor).unwrap_or_else(|| panic!("{name} match"));
            eprintln!(
                "{name}: rva 0x{rva:X} agreement {agree:.3} margin {:.3}",
                agree - runner
            );
            assert!(
                in_code(img, img.base + rva),
                "the relocated {name} method is in executable code"
            );
            assert!(agree >= 0.72, "{name} agreement {agree:.3} below the gate");
            assert!(
                agree - runner >= 0.10,
                "{name} margin {:.3} below the gate (ambiguous match)",
                agree - runner
            );
        }
    }

    // How far the vtable anchor actually carries (run with `--ignored`): anchor a clean direct method in
    // the v84 @0x78F16C table and resolve it across the full six-build span from the GUI screenshot,
    // including the major-version jumps to v95.x where the class layout may shift slots.
    #[test]
    #[ignore = "needs the real GMS clients in X:\\Client_Unpacked; run with --ignored"]
    fn clean_virtual_method_relocates_across_six_builds() {
        use crate::fileimage::FileImage;
        use std::path::Path;

        let dir = Path::new(r"X:\Client_Unpacked");
        let names = [
            "GMS_v83.1_U_DEVM.exe",
            "GMS_v84.1_U_DEVM.exe",
            "GMS_v88.1_U_DEVM.exe",
            "GMS_v91.1_U_DEVM.exe",
            "GMS_v95.1_U_DEVM.exe",
            "GMS_v95.5_U_DEVM.exe",
        ];
        let paths: Vec<_> = names.iter().map(|n| dir.join(n)).collect();
        if paths.iter().any(|p| !p.exists()) {
            eprintln!("real GMS clients not present; skipping");
            return;
        }
        let imgs: Vec<FileImage> = paths.iter().map(|p| FileImage::open(p).unwrap()).collect();
        let labels = ["v83", "v84", "v88", "v91", "v95.1", "v95.5"];
        let inputs: Vec<ImageInput> = labels
            .iter()
            .zip(&imgs)
            .map(|(l, i)| open_real(i, l))
            .collect();

        let v84 = &inputs[1];
        let buf = whole_image(v84);
        let vts = vtables(v84, &buf);
        let (_, slots) = vts
            .iter()
            .find(|(s, sl)| *s <= 0x78F16C && 0x78F16C < *s + sl.len() * 4)
            .expect("target table");
        let slot_idx = slots
            .iter()
            .position(|&sv| !follow_thunk(v84, sv).1)
            .expect("a direct slot");
        let anchor = make_vtable_anchor(v84, slots[slot_idx]).expect("anchor the method");
        eprintln!(
            "anchoring clean method 0x{:X} (slot {} of {}):",
            slots[slot_idx],
            anchor.slot,
            anchor.fingerprint.len()
        );
        for inp in &inputs {
            match resolve_vtable_anchor(inp, &anchor) {
                Some((rva, a, r)) if a >= 0.72 && a - r >= 0.10 => eprintln!(
                    "  {:>5}: 0x{rva:X}  agreement {a:.3} margin {:.3}  PIN",
                    inp.label,
                    a - r
                ),
                Some((rva, a, r)) => eprintln!(
                    "  {:>5}: 0x{rva:X}  agreement {a:.3} margin {:.3}  (below gate -> declines)",
                    inp.label,
                    a - r
                ),
                None => eprintln!("  {:>5}: no table match", inp.label),
            }
        }
    }

    // Validate the chaining hypothesis (run with `--ignored`): is stepwise relocation through adjacent
    // builds (v84->v88->v91->v95.1->v95.5, re-anchoring at each hop) more robust than a single direct
    // jump (v84->v95.x)? Prints both so the difference is measured, not assumed.
    #[test]
    #[ignore = "needs the real GMS clients in X:\\Client_Unpacked; run with --ignored"]
    fn chained_relocation_vs_direct_across_majors() {
        use crate::fileimage::FileImage;
        use std::path::Path;

        let dir = Path::new(r"X:\Client_Unpacked");
        let names = [
            "GMS_v83.1_U_DEVM.exe",
            "GMS_v84.1_U_DEVM.exe",
            "GMS_v88.1_U_DEVM.exe",
            "GMS_v91.1_U_DEVM.exe",
            "GMS_v95.1_U_DEVM.exe",
            "GMS_v95.5_U_DEVM.exe",
        ];
        let paths: Vec<_> = names.iter().map(|n| dir.join(n)).collect();
        if paths.iter().any(|p| !p.exists()) {
            eprintln!("real GMS clients not present; skipping");
            return;
        }
        let imgs: Vec<FileImage> = paths.iter().map(|p| FileImage::open(p).unwrap()).collect();
        let labels = ["v83", "v84", "v88", "v91", "v95.1", "v95.5"];
        let inputs: Vec<ImageInput> = labels
            .iter()
            .zip(&imgs)
            .map(|(l, i)| open_real(i, l))
            .collect();

        // Anchor a clean method in v84 (index 1): slot 0 of the 0x78F16C table.
        let v84 = &inputs[1];
        let buf = whole_image(v84);
        let vts = vtables(v84, &buf);
        let (_, slots) = vts
            .iter()
            .find(|(s, sl)| *s <= 0x78F16C && 0x78F16C < *s + sl.len() * 4)
            .expect("target table");
        let slot0 = slots[0];

        eprintln!("DIRECT v84 -> each build (one big jump):");
        let v84_anchor = make_vtable_anchor(v84, slot0).expect("anchor in v84");
        for (i, inp) in inputs.iter().enumerate() {
            if let Some((rva, a, r)) = resolve_vtable_anchor(inp, &v84_anchor) {
                eprintln!(
                    "  v84 -> {:>5}: 0x{rva:X}  agree {a:.3} margin {:.3} {}",
                    labels[i],
                    a - r,
                    if a >= 0.72 && a - r >= 0.10 {
                        "PIN"
                    } else {
                        "decline"
                    }
                );
            }
        }

        eprintln!("CHAINED from v84, re-anchoring each hop (1->2->3->4->5):");
        // Walk forward through indices 2..=5, re-anchoring in the located build each hop.
        let mut cur_idx = 1usize;
        let mut cur_rva = slot0;
        for next in 2..inputs.len() {
            let anchor = match make_vtable_anchor(&inputs[cur_idx], cur_rva) {
                Some(a) => a,
                None => {
                    eprintln!("  re-anchor in {} FAILED at 0x{cur_rva:X}", labels[cur_idx]);
                    break;
                }
            };
            match resolve_vtable_anchor(&inputs[next], &anchor) {
                Some((rva, a, r)) => {
                    eprintln!(
                        "  {:>5} -> {:>5}: 0x{rva:X}  agree {a:.3} margin {:.3} {}",
                        labels[cur_idx],
                        labels[next],
                        a - r,
                        if a >= 0.72 && a - r >= 0.10 {
                            "PIN"
                        } else {
                            "decline"
                        }
                    );
                    cur_idx = next;
                    cur_rva = rva;
                }
                None => {
                    eprintln!("  {} -> {}: no match", labels[cur_idx], labels[next]);
                    break;
                }
            }
        }
        eprintln!(
            "chained final: {} at 0x{cur_rva:X} (direct v84->v95.5 was 0.630, below gate)",
            labels[cur_idx]
        );
    }

    // Probe (run with `--ignored`): does the target's vtable have string-anchorable SIBLING methods that
    // resolve into v95, so the table (and the target's slot) can be grounded across the v95 break by a
    // build-stable string even though the target method itself references none.
    #[test]
    #[ignore = "needs the real GMS clients in X:\\Client_Unpacked; run with --ignored"]
    fn probe_string_anchorable_vtable_siblings_v91_to_v95() {
        use crate::fileimage::FileImage;
        use std::path::Path;

        let dir = Path::new(r"X:\Client_Unpacked");
        if !dir.join("GMS_v91.1_U_DEVM.exe").exists() || !dir.join("GMS_v95.1_U_DEVM.exe").exists()
        {
            eprintln!("real GMS clients not present; skipping");
            return;
        }
        let i91 = FileImage::open(&dir.join("GMS_v91.1_U_DEVM.exe")).unwrap();
        let i951 = FileImage::open(&dir.join("GMS_v95.1_U_DEVM.exe")).unwrap();
        let v91 = open_real(&i91, "v91");
        let v951 = open_real(&i951, "v95.1");

        let target_entry = crate::sigmaker::identity::enclosing_function(&v91, 0x5BCCEF);
        let buf = whole_image(&v91);
        let vts = vtables(&v91, &buf);
        let (_, slots) = vts
            .iter()
            .find(|(_, slots)| {
                slots
                    .iter()
                    .any(|&sv| follow_thunk(&v91, sv).0 == target_entry)
            })
            .expect("the v91 vtable holding the method");
        let target_slot = slots
            .iter()
            .position(|&sv| follow_thunk(&v91, sv).0 == target_entry)
            .unwrap();
        eprintln!(
            "v91 vtable: {} slots, target at slot {target_slot}",
            slots.len()
        );

        let mut bridged = 0;
        for (k, &sv) in slots.iter().enumerate() {
            let fnrva = follow_thunk(&v91, sv).0;
            let Some(a) = crate::sigmaker::identity::make_string_anchor(&v91, fnrva) else {
                continue;
            };
            if let Some(r) = crate::sigmaker::identity::resolve_string_anchor(&v951, &a) {
                bridged += 1;
                if bridged <= 12 {
                    eprintln!(
                        "  slot {k} (fn 0x{fnrva:X}) anchors {:?} -> v95.1 0x{r:X}",
                        a.text
                    );
                }
            }
        }
        eprintln!(
            "string-anchorable sibling slots resolving in v95.1: {bridged} of {}",
            slots.len()
        );
    }

    // The gap closer (run with `--ignored`): the v91 slot-0 method (0x5BCCEF) is a pure virtual method
    // whose class refactored at v95 past the per-slot matcher, with no string/import/caller of its own.
    // Anchored from v91, it must now relocate into v95.1 and v95.5 through its constructor's string.
    #[test]
    #[ignore = "needs the real GMS clients in X:\\Client_Unpacked; run with --ignored"]
    fn constructor_grounding_bridges_the_v95_break() {
        use crate::fileimage::FileImage;
        use std::path::Path;

        let dir = Path::new(r"X:\Client_Unpacked");
        let need = [
            "GMS_v91.1_U_DEVM.exe",
            "GMS_v95.1_U_DEVM.exe",
            "GMS_v95.5_U_DEVM.exe",
        ];
        if need.iter().any(|n| !dir.join(n).exists()) {
            eprintln!("real GMS clients not present; skipping");
            return;
        }
        let i91 = FileImage::open(&dir.join(need[0])).unwrap();
        let i951 = FileImage::open(&dir.join(need[1])).unwrap();
        let i955 = FileImage::open(&dir.join(need[2])).unwrap();
        let v91 = open_real(&i91, "v91");
        let v951 = open_real(&i951, "v95.1");
        let v955 = open_real(&i955, "v95.5");

        let entry = crate::sigmaker::identity::enclosing_function(&v91, 0x5BCCEF);
        let anchor = make_vtable_anchor(&v91, entry).expect("anchor the v91 method");
        eprintln!(
            "installer present: {} (slot {} of {})",
            anchor.installer.is_some(),
            anchor.slot,
            anchor.fingerprint.len()
        );
        let mut pinned = 0;
        for (img, name) in [(&v951, "v95.1"), (&v955, "v95.5")] {
            match resolve_vtable_anchor(img, &anchor) {
                Some((rva, a, r)) => {
                    eprintln!("  {name}: 0x{rva:X}  agreement {a:.3} margin {:.3}", a - r);
                    if a >= 0.72 && a - r >= 0.10 {
                        pinned += 1;
                    }
                }
                None => eprintln!("  {name}: declined"),
            }
        }
        assert_eq!(
            pinned, 2,
            "constructor grounding should pin the method in both v95 builds"
        );
    }

    // Probe (run with `--ignored`): can the target's vtable be GROUNDED in v95 through its installer
    // (the constructor that writes `mov [obj], offset vtable`)? If an installer has a string or import
    // anchor that resolves into v95.1, the v95 vtable address can be read from it and the table relocated
    // even though its internal slot structure drifted past the matcher.
    #[test]
    #[ignore = "needs the real GMS clients in X:\\Client_Unpacked; run with --ignored"]
    fn probe_vtable_installer_anchorability_v91_to_v95() {
        use crate::fileimage::FileImage;
        use std::path::Path;

        let dir = Path::new(r"X:\Client_Unpacked");
        if !dir.join("GMS_v91.1_U_DEVM.exe").exists() || !dir.join("GMS_v95.1_U_DEVM.exe").exists()
        {
            eprintln!("real GMS clients not present; skipping");
            return;
        }
        let i91 = FileImage::open(&dir.join("GMS_v91.1_U_DEVM.exe")).unwrap();
        let i951 = FileImage::open(&dir.join("GMS_v95.1_U_DEVM.exe")).unwrap();
        let v91 = open_real(&i91, "v91");
        let v951 = open_real(&i951, "v95.1");

        let target_entry = crate::sigmaker::identity::enclosing_function(&v91, 0x5BCCEF);
        let buf = whole_image(&v91);
        let vts = vtables(&v91, &buf);
        let (start, _) = vts
            .iter()
            .find(|(_, slots)| {
                slots
                    .iter()
                    .any(|&sv| follow_thunk(&v91, sv).0 == target_entry)
            })
            .expect("the v91 vtable");
        let vt_abs = (v91.base + start) as u32;
        eprintln!("v91 target vtable @0x{start:X} (abs 0x{vt_abs:X})");

        // Installers: code that mentions the vtable's absolute address as a 4-byte immediate/operand.
        let mut installers: std::collections::BTreeSet<usize> = std::collections::BTreeSet::new();
        for r in &v91.code_regions {
            let bytes = read_region(v91.source, r.base, r.size);
            for (i, w) in bytes.windows(4).enumerate() {
                if u32::from_le_bytes([w[0], w[1], w[2], w[3]]) == vt_abs {
                    installers.insert(crate::sigmaker::identity::enclosing_function(
                        &v91,
                        r.base + i - v91.base,
                    ));
                }
            }
        }
        eprintln!("{} installer/constructor site(s)", installers.len());
        let mut grounded = 0;
        for inst in installers {
            if let Some(sa) = crate::sigmaker::identity::make_string_anchor(&v91, inst)
                && let Some(r) = crate::sigmaker::identity::resolve_string_anchor(&v951, &sa)
            {
                grounded += 1;
                eprintln!(
                    "  installer 0x{inst:X} STRING {:?} -> v95.1 0x{r:X}",
                    sa.text
                );
                continue;
            }
            if let Some(ia) = crate::sigmaker::imports::make_import_anchor(&v91, inst)
                && let Some(r) = crate::sigmaker::imports::resolve_import_anchor(&v951, &ia)
            {
                grounded += 1;
                eprintln!(
                    "  installer 0x{inst:X} IMPORTS {:?} -> v95.1 0x{r:X}",
                    ia.names
                );
            }
        }
        eprintln!("installers that anchor into v95.1: {grounded}");
    }

    // `make_vtable_anchor` on real data (run with `--ignored`): a virtual method in the target table is
    // anchored to its own table and reads back to itself on a self-resolve.
    #[test]
    #[ignore = "needs the real GMS clients in X:\\Client_Unpacked; run with --ignored"]
    fn make_vtable_anchor_pins_a_real_virtual_method() {
        use crate::fileimage::FileImage;
        use std::path::Path;

        let path = Path::new(r"X:\Client_Unpacked").join("GMS_v84.1_U_DEVM.exe");
        if !path.exists() {
            eprintln!("real GMS client not present; skipping");
            return;
        }
        let v84i = FileImage::open(&path).expect("open v84");
        let v84 = open_real(&v84i, "v84");

        let buf = whole_image(&v84);
        let vts = vtables(&v84, &buf);
        let (_, slots) = vts
            .iter()
            .find(|(s, sl)| *s <= 0x78F16C && 0x78F16C < *s + sl.len() * 4)
            .expect("the target vtable is enumerated");

        // The first direct slot whose method anchors back to a table of the same size (i.e. this one,
        // not a larger table that merely shares a base-class method); bounded so the scan stays cheap.
        let mut pinned = false;
        for &sv in slots
            .iter()
            .filter(|&&sv| !follow_thunk(&v84, sv).1)
            .take(24)
        {
            let Some(anchor) = make_vtable_anchor(&v84, sv) else {
                continue;
            };
            if anchor.fingerprint.len() != slots.len() {
                continue; // method also lives in a larger table; not a clean single-table method
            }
            let (rva, agree, _) = resolve_vtable_anchor(&v84, &anchor).expect("self-resolve");
            assert_eq!(rva, sv, "the anchored method reads back to itself");
            assert!(agree > 0.99);
            eprintln!("anchored real method 0x{sv:X} at slot {}", anchor.slot);
            pinned = true;
            break;
        }
        assert!(
            pinned,
            "no clean single-table virtual method found to anchor"
        );
    }
}
