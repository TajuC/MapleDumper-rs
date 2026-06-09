use std::collections::BTreeSet;

use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, OpKind};

use super::types::ImageInput;
use super::{bitness, mem_target, read_at, read_region};
pub use crate::domain::StringAnchor;
use crate::pattern::Arch;

const ID_WINDOW: usize = 256;
const ID_MAX_INSTRS: usize = 24;

/// Recompile-stable identity of a function entry: mnemonic stream, CFG-lite block count, distinctive
/// constants, and referenced strings. The cross-build consistency check compares these.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FnIdentity {
    pub instr_count: usize,
    pub blocks: usize,
    pub calls: usize,
    pub branches: usize,
    pub returns: usize,
    pub constants: Vec<u64>,
    pub strings: Vec<String>,
    pub(super) mnemonics: Vec<u32>,
}

fn fnv_fold(h: &mut u64, bytes: &[u8]) {
    for &b in bytes {
        *h ^= u64::from(b);
        *h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
}

fn is_immediate_kind(k: OpKind) -> bool {
    matches!(
        k,
        OpKind::Immediate8
            | OpKind::Immediate8_2nd
            | OpKind::Immediate16
            | OpKind::Immediate32
            | OpKind::Immediate64
            | OpKind::Immediate8to16
            | OpKind::Immediate8to32
            | OpKind::Immediate8to64
            | OpKind::Immediate32to64
    )
}

fn in_image(img: &ImageInput, v: u64) -> bool {
    (img.base as u64..(img.base + img.size) as u64).contains(&v)
}

// Tuned: below this, an immediate is a stack or struct offset, not an identifying magic number.
fn is_distinctive_const(v: u64) -> bool {
    (v as i64).unsigned_abs() > 0xFFFF && v != u64::MAX
}

fn read_string_ref(img: &ImageInput, abs: usize) -> Option<String> {
    let rva = abs.checked_sub(img.base).filter(|&r| r < img.size)?;
    let bytes = read_at(img.source, img.base, rva, 64);
    let printable = |b: u8| (0x20..=0x7E).contains(&b);
    let ascii: String = bytes
        .iter()
        .copied()
        .take_while(|&b| printable(b))
        .map(char::from)
        .take(48)
        .collect();
    if ascii.len() >= 4 {
        return Some(ascii);
    }
    let wide: String = bytes
        .chunks_exact(2)
        .take_while(|c| c[1] == 0 && printable(c[0]))
        .map(|c| char::from(c[0]))
        .take(48)
        .collect();
    (wide.len() >= 4).then_some(wide)
}

#[must_use]
pub fn fn_identity(img: &ImageInput, target_rva: usize) -> FnIdentity {
    let bytes = read_at(img.source, img.base, target_rva, ID_WINDOW);
    let ip0 = (img.base + target_rva) as u64;
    let end_ip = ip0 + bytes.len() as u64;
    let mut decoder = Decoder::with_ip(bitness(img.arch), &bytes, ip0, DecoderOptions::NONE);
    let mut instr = Instruction::default();
    let mut mnemonics: Vec<u32> = Vec::new();
    let mut constants: Vec<u64> = Vec::new();
    let mut strings: Vec<String> = Vec::new();
    let mut blocks: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
    let (mut calls, mut branches, mut returns) = (0usize, 0usize, 0usize);
    blocks.insert(ip0);
    while decoder.can_decode() && mnemonics.len() < ID_MAX_INSTRS {
        decoder.decode_out(&mut instr);
        if instr.is_invalid() || instr.len() == 0 {
            break;
        }
        mnemonics.push(instr.mnemonic() as u32);
        let immediates = (0..instr.op_count())
            .filter(|&i| is_immediate_kind(instr.op_kind(i)))
            .map(|i| instr.immediate(i));
        let refs = immediates.chain(mem_target(&instr, img.arch).map(|a| a as u64));
        for v in refs {
            if let Some(s) = read_string_ref(img, v as usize) {
                strings.push(s);
            } else if !in_image(img, v) && is_distinctive_const(v) {
                constants.push(v);
            }
        }
        match instr.flow_control() {
            FlowControl::Call | FlowControl::IndirectCall => calls += 1,
            FlowControl::ConditionalBranch => {
                branches += 1;
                let t = instr.near_branch_target();
                if (ip0..end_ip).contains(&t) {
                    blocks.insert(t);
                }
                blocks.insert(instr.next_ip());
            }
            FlowControl::UnconditionalBranch => {
                branches += 1;
                let t = instr.near_branch_target();
                if (ip0..end_ip).contains(&t) {
                    blocks.insert(t);
                }
            }
            FlowControl::Return => {
                returns += 1;
                break;
            }
            _ => {}
        }
    }
    constants.sort_unstable();
    constants.dedup();
    strings.sort();
    strings.dedup();
    FnIdentity {
        instr_count: mnemonics.len(),
        blocks: blocks.len(),
        calls,
        branches,
        returns,
        constants,
        strings,
        mnemonics,
    }
}

// Per-instruction features captured in a SINGLE linear decode of a region, so the per-boundary identity
// scan does not re-decode the same instruction once per overlapping window. Everything `fn_identity` reads
// from a decoded instruction is recorded here; `identity_from_events` then reproduces `fn_identity` exactly
// by aggregating these forward, with no further decoding. See `for_each_boundary_identity`.
struct InstrFeat {
    ip: u64,
    len: u64,
    mnemonic: u32,
    flow: FlowControl,
    branch_target: u64,
    next_ip: u64,
    strings: Vec<String>,
    constants: Vec<u64>,
}

// One linear decode of a code region, mirroring `instruction_boundaries`' resync byte-for-byte: a decode
// position yields `Some(feat)` for a valid instruction and `None` for an invalid byte (after which the
// decoder advances one byte). The position list is therefore identical to `instruction_boundaries`, and
// each `Some` carries exactly what `fn_identity` extracts from that instruction (string/constant refs
// computed once here instead of at every overlapping window).
fn region_events(
    img: &ImageInput,
    region_base: usize,
    region_size: usize,
) -> Vec<(usize, Option<InstrFeat>)> {
    let bytes = read_region(img.source, region_base, region_size);
    let mut decoder = Decoder::with_ip(
        bitness(img.arch),
        &bytes,
        region_base as u64,
        DecoderOptions::NONE,
    );
    let mut instr = Instruction::default();
    let mut out: Vec<(usize, Option<InstrFeat>)> = Vec::new();
    while decoder.can_decode() {
        let pos = decoder.position();
        // iced's `set_position` (used on resync below) moves the buffer offset but NOT the IP, so after an
        // invalid byte the decoder's IP drifts from the real position. Re-anchor the IP to this position
        // every step so `instr.ip()`/`next_ip()`/`near_branch_target()` match a fresh decode from here,
        // exactly as the naive per-boundary `fn_identity` (a fresh decoder with `with_ip`) sees them.
        decoder.set_ip((region_base + pos) as u64);
        let rva = (region_base - img.base) + pos;
        decoder.decode_out(&mut instr);
        if instr.is_invalid() || instr.len() == 0 {
            out.push((rva, None));
            let _ = decoder.set_position(pos + 1);
            continue;
        }
        let mut strings: Vec<String> = Vec::new();
        let mut constants: Vec<u64> = Vec::new();
        let immediates = (0..instr.op_count())
            .filter(|&i| is_immediate_kind(instr.op_kind(i)))
            .map(|i| instr.immediate(i));
        let refs = immediates.chain(mem_target(&instr, img.arch).map(|a| a as u64));
        for v in refs {
            if let Some(s) = read_string_ref(img, v as usize) {
                strings.push(s);
            } else if !in_image(img, v) && is_distinctive_const(v) {
                constants.push(v);
            }
        }
        out.push((
            rva,
            Some(InstrFeat {
                ip: instr.ip(),
                len: instr.len() as u64,
                mnemonic: instr.mnemonic() as u32,
                flow: instr.flow_control(),
                branch_target: instr.near_branch_target(),
                next_ip: instr.next_ip(),
                strings,
                constants,
            }),
        ));
    }
    out
}

// Reproduce `fn_identity` for the boundary at `events[e]` by aggregating the precomputed features forward,
// with NO decoding. Output-identical to `fn_identity(img, events[e].0)` for every interior boundary: the
// instruction stream a fresh decode would walk from `ip0` is exactly the contiguous run of `Some` events
// here (x86 decode is stateless per instruction). The only window `fn_identity` reads that this region pass
// cannot see is one that spills past the region end into adjacent data; for those boundaries (within one
// `ID_WINDOW` of the region end) it falls back to the real `fn_identity`, so the result is exact everywhere.
fn identity_from_events(
    img: &ImageInput,
    region_end_ip: u64,
    events: &[(usize, Option<InstrFeat>)],
    e: usize,
) -> FnIdentity {
    let rva = events[e].0;
    let ip0 = (img.base + rva) as u64;
    // The window can read past the region into data; reproduce that by decoding it directly.
    if ip0 + ID_WINDOW as u64 > region_end_ip {
        return fn_identity(img, rva);
    }
    // An invalid byte yields an immediate break in fn_identity: just the entry block, nothing else.
    if events[e].1.is_none() {
        return FnIdentity {
            blocks: 1,
            ..FnIdentity::default()
        };
    }
    let end_ip = ip0 + ID_WINDOW as u64;
    let mut mnemonics: Vec<u32> = Vec::new();
    let mut constants: Vec<u64> = Vec::new();
    let mut strings: Vec<String> = Vec::new();
    let mut blocks: BTreeSet<u64> = BTreeSet::from([ip0]);
    let (mut calls, mut branches, mut returns) = (0usize, 0usize, 0usize);
    let mut expected = ip0;
    let mut j = e;
    while j < events.len() && mnemonics.len() < ID_MAX_INSTRS {
        let Some(f) = &events[j].1 else { break };
        // Non-contiguous (only across a resync) or an instruction the 256-byte window cannot hold: a fresh
        // decode would hit an invalid/short read here and break, so stop without including it.
        if f.ip != expected || f.ip + f.len > end_ip {
            break;
        }
        mnemonics.push(f.mnemonic);
        strings.extend(f.strings.iter().cloned());
        constants.extend(f.constants.iter().copied());
        match f.flow {
            FlowControl::Call | FlowControl::IndirectCall => calls += 1,
            FlowControl::ConditionalBranch => {
                branches += 1;
                if (ip0..end_ip).contains(&f.branch_target) {
                    blocks.insert(f.branch_target);
                }
                blocks.insert(f.next_ip);
            }
            FlowControl::UnconditionalBranch => {
                branches += 1;
                if (ip0..end_ip).contains(&f.branch_target) {
                    blocks.insert(f.branch_target);
                }
            }
            FlowControl::Return => {
                returns += 1;
                break;
            }
            _ => {}
        }
        expected += f.len;
        j += 1;
    }
    constants.sort_unstable();
    constants.dedup();
    strings.sort();
    strings.dedup();
    FnIdentity {
        instr_count: mnemonics.len(),
        blocks: blocks.len(),
        calls,
        branches,
        returns,
        constants,
        strings,
        mnemonics,
    }
}

// Visit every instruction-boundary window in the image's code (the same boundaries and identities as
// `instruction_boundaries` + `fn_identity` at each), decoding each region only ONCE instead of re-decoding
// every overlapping 24-instruction window. This is the hot path of the fingerprint scan: best-match and
// top-k both stream through it. x86 only, matching the windowing of `enclosing_function`.
fn for_each_boundary_identity(img: &ImageInput, mut f: impl FnMut(usize, &FnIdentity)) {
    if !matches!(img.arch, Arch::X86) {
        return;
    }
    for region in &img.code_regions {
        let region_end_ip = (region.base + region.size) as u64;
        let events = region_events(img, region.base, region.size);
        for e in 0..events.len() {
            let id = identity_from_events(img, region_end_ip, &events, e);
            f(events[e].0, &id);
        }
    }
}

// Jaccard over two evidence sets. Returns `None` when both are empty: no constants (or no strings) in
// either function is an absence of evidence, not a match, so the caller drops the component and
// reweights rather than letting two empty sets count as a perfect 1.0 and inflate the blend.
fn jaccard_opt<T: Eq + std::hash::Hash>(a: &[T], b: &[T]) -> Option<f64> {
    use std::collections::HashSet;
    if a.is_empty() && b.is_empty() {
        return None;
    }
    let sa: HashSet<&T> = a.iter().collect();
    let sb: HashSet<&T> = b.iter().collect();
    let union = sa.union(&sb).count();
    if union == 0 {
        None
    } else {
        Some(sa.intersection(&sb).count() as f64 / union as f64)
    }
}

// Length of the longest common subsequence of two mnemonic streams. A subsequence keeps order but
// tolerates gaps, so an instruction inserted or removed on one side only costs that one position
// instead of desynchronising everything after it.
fn lcs_len(a: &[u32], b: &[u32]) -> usize {
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

// Order-preserving, insertion-tolerant similarity of two mnemonic streams as the Dice ratio of their
// LCS: 2*LCS / (|a| + |b|). 1.0 when identical, and a single inserted prologue instruction stays high
// (e.g. 6 vs 7 shared-prefix mnemonics scores 12/13) instead of collapsing the way a strict
// leading-prefix match would. Two empty streams are vacuously identical.
fn mnemonic_similarity(a: &[u32], b: &[u32]) -> f64 {
    let total = a.len() + b.len();
    if total == 0 {
        return 1.0;
    }
    (2.0 * lcs_len(a, b) as f64) / total as f64
}

fn count_agreement(a: usize, b: usize) -> f64 {
    let m = a.max(b);
    if m == 0 {
        1.0
    } else {
        1.0 - (a.abs_diff(b) as f64 / m as f64)
    }
}

impl FnIdentity {
    /// A 0.0..=1.0 similarity to another function identity, blending an order-preserving mnemonic
    /// stream comparison, the CFG-lite block/call/branch/return shape, and the distinctive-constant
    /// and string-reference sets. Identical identities score 1.0. Unlike fingerprint equality this
    /// degrades gracefully, so a callee that shifted or gained one instruction across a build still
    /// scores high instead of dropping to zero, which is what a cross-build *similarity* (not
    /// equality) signal needs. Constant and string components are only weighed in when at least one
    /// side carries that evidence: two functions that simply reference no strings must not be treated
    /// as a perfect string match. When a component drops out, its weight is redistributed across the
    /// rest, so the blend stays a 0.0..=1.0 score normalised over the evidence actually present.
    #[must_use]
    pub fn similarity(&self, other: &FnIdentity) -> f64 {
        let mnem = mnemonic_similarity(&self.mnemonics, &other.mnemonics);
        let structure = (count_agreement(self.blocks, other.blocks)
            + count_agreement(self.calls, other.calls)
            + count_agreement(self.branches, other.branches)
            + count_agreement(self.returns, other.returns))
            / 4.0;
        let mut score = 0.40 * mnem + 0.25 * structure;
        let mut weight = 0.40 + 0.25;
        if let Some(consts) = jaccard_opt(&self.constants, &other.constants) {
            score += 0.20 * consts;
            weight += 0.20;
        }
        if let Some(strings) = jaccard_opt(&self.strings, &other.strings) {
            score += 0.15 * strings;
            weight += 0.15;
        }
        (score / weight).clamp(0.0, 1.0)
    }

    #[must_use]
    pub fn fingerprint(&self) -> String {
        let mut h = 0xcbf2_9ce4_8422_2325u64;
        for m in &self.mnemonics {
            fnv_fold(&mut h, &m.to_le_bytes());
        }
        for c in &self.constants {
            fnv_fold(&mut h, &c.to_le_bytes());
        }
        for s in &self.strings {
            fnv_fold(&mut h, s.as_bytes());
            fnv_fold(&mut h, &[0]);
        }
        format!(
            "{}:{:016X}:b{}c{}j{}r{}",
            self.instr_count, h, self.blocks, self.calls, self.branches, self.returns
        )
    }
}

/// Approximate references to `target_rva`: rel32 call/jmp and x64 rip-relative lea landing on the
/// entry. A byte scan, so it can miscount at a boundary; kept out of the fingerprint since the
/// referencing code shifts per build, but a useful "hot function" signal on its own.
#[must_use]
pub fn xref_count(img: &ImageInput, target_rva: usize) -> usize {
    let target = (img.base + target_rva) as i64;
    let rel32 = |w: &[u8]| i32::from_le_bytes([w[0], w[1], w[2], w[3]]) as i64;
    let x64 = matches!(img.arch, Arch::X64);
    img.code_regions
        .iter()
        .map(|region| {
            let bytes = read_region(img.source, region.base, region.size);
            let calls = bytes
                .windows(5)
                .enumerate()
                .filter(|(i, w)| {
                    matches!(w[0], 0xE8 | 0xE9)
                        && (region.base + i + 5) as i64 + rel32(&w[1..]) == target
                })
                .count();
            let leas = bytes
                .windows(7)
                .enumerate()
                .filter(|(j, w)| {
                    x64 && w[0] == 0x48
                        && w[1] == 0x8D
                        && w[2] & 0xC7 == 0x05
                        && (region.base + j + 7) as i64 + rel32(&w[3..]) == target
                })
                .count();
            calls + leas
        })
        .sum()
}

/// Every instruction-boundary RVA in an x86 image's executable regions, by linear disassembly. A
/// recompiled target is not necessarily a `call` destination or a standard-prologue function entry
/// (the real GMS v83/v84 target is a *mid-function* code site reached by neither), so the only
/// enumeration that can relocate an arbitrary code window is the set of real instruction starts. On an
/// invalid byte the sweep advances one byte and resyncs, so a data island in `.text` cannot derail it.
/// Now the test-only reference enumeration: the production fingerprint scan streams through
/// [`for_each_boundary_identity`] (one decode per region), and the corpus equivalence test checks the two
/// agree boundary-for-boundary and identity-for-identity.
#[cfg(test)]
fn instruction_boundaries(img: &ImageInput) -> Vec<usize> {
    let mut out: Vec<usize> = Vec::new();
    for region in &img.code_regions {
        let bytes = read_region(img.source, region.base, region.size);
        let mut decoder = Decoder::with_ip(
            bitness(img.arch),
            &bytes,
            region.base as u64,
            DecoderOptions::NONE,
        );
        let mut instr = Instruction::default();
        while decoder.can_decode() {
            let pos = decoder.position();
            out.push((region.base - img.base) + pos);
            decoder.decode_out(&mut instr);
            if instr.is_invalid() || instr.len() == 0 {
                let _ = decoder.set_position(pos + 1);
            }
        }
    }
    out
}

/// The best fingerprint match for `reference` among every instruction-boundary code window in an
/// image. Returns the winning RVA, its similarity, the best similarity of any *other* window more than
/// one instruction away (the runner-up, so the caller can require a uniqueness margin), and the
/// winner's identity. Adjacent boundaries overlap heavily and would otherwise be their own near-equal
/// runner-up, so the runner-up ignores windows within `MIN_DISTINCT_GAP` bytes of the winner. `None`
/// only when the image has no decodable code. x86 only: the windowing matches `enclosing_function`.
///
/// This is a linear scan of every instruction start in `.text`, so it is the heavy path; it runs only
/// as the last-resort fallback in generation, after byte and string anchors have both failed.
#[must_use]
pub fn best_fingerprint_match(
    img: &ImageInput,
    reference: &FnIdentity,
) -> Option<(usize, f64, f64, FnIdentity)> {
    if !matches!(img.arch, Arch::X86) {
        return None;
    }
    // Two windows closer than this are the same match shifted by a byte or two, not distinct rivals.
    const MIN_DISTINCT_GAP: usize = 16;
    let mut best: Option<(usize, f64, FnIdentity)> = None;
    let mut runner_up = 0.0f64;
    for_each_boundary_identity(img, |rva, id| {
        let sim = reference.similarity(id);
        match best.take() {
            // A new winner: the old winner becomes a rival only if it is far enough to be distinct.
            Some((brva, bsim, _)) if sim > bsim => {
                if brva.abs_diff(rva) >= MIN_DISTINCT_GAP {
                    runner_up = runner_up.max(bsim);
                }
                best = Some((rva, sim, id.clone()));
            }
            // Not a winner: it raises the runner-up only if far enough from the current winner.
            Some(prev) => {
                if prev.0.abs_diff(rva) >= MIN_DISTINCT_GAP {
                    runner_up = runner_up.max(sim);
                }
                best = Some(prev);
            }
            None => best = Some((rva, sim, id.clone())),
        }
    });
    best.map(|(rva, sim, id)| (rva, sim, runner_up, id))
}

/// The top `k` instruction-boundary windows by similarity to `reference`, at least `floor`, each more
/// than one instruction apart (gap-deduped). For the last-resort shortlist: when nothing pinned the
/// function uniquely, this surfaces the family of structural near-duplicates it belongs to so the
/// caller can list them for manual disambiguation. x86 only; empty on a non-x86 image.
#[must_use]
pub(super) fn fingerprint_topk(
    img: &ImageInput,
    reference: &FnIdentity,
    k: usize,
    floor: f64,
) -> Vec<(usize, f64)> {
    if !matches!(img.arch, Arch::X86) {
        return Vec::new();
    }
    const GAP: usize = 16;
    let mut scored: Vec<(usize, f64)> = Vec::new();
    for_each_boundary_identity(img, |rva, id| {
        let sim = reference.similarity(id);
        if sim >= floor {
            scored.push((rva, sim));
        }
    });
    scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
    let mut out: Vec<(usize, f64)> = Vec::new();
    for (rva, sim) in scored {
        if out.iter().any(|(r, _)| r.abs_diff(rva) < GAP) {
            continue;
        }
        out.push((rva, sim));
        if out.len() >= k {
            break;
        }
    }
    out
}

/// Test-only equivalence oracle: confirm the fast single-decode scan ([`for_each_boundary_identity`])
/// reproduces the naive per-boundary [`fn_identity`] EXACTLY for `img`. Returns `None` when every boundary
/// agrees (same rva, same identity in every field), or `Some((rva, naive, streamed))` for the first
/// divergence. Driven over the real GMS lineage by the `--ignored` corpus harness, so the optimisation is
/// proven byte-equivalent on real code, not merely argued.
#[cfg(test)]
pub(super) fn fingerprint_scan_divergence(img: &ImageInput) -> Option<(usize, String, String)> {
    let naive: Vec<(usize, FnIdentity)> = instruction_boundaries(img)
        .into_iter()
        .map(|rva| (rva, fn_identity(img, rva)))
        .collect();
    let mut streamed: Vec<(usize, FnIdentity)> = Vec::new();
    for_each_boundary_identity(img, |rva, id| streamed.push((rva, id.clone())));
    if naive.len() != streamed.len() {
        return Some((
            0,
            format!("naive {} boundaries", naive.len()),
            format!("streamed {} boundaries", streamed.len()),
        ));
    }
    naive
        .iter()
        .zip(&streamed)
        .find(|((r1, a), (r2, b))| r1 != r2 || a != b)
        .map(|((r1, a), (_, b))| (*r1, a.fingerprint(), b.fingerprint()))
}

fn find_string_in_data(img: &ImageInput, text: &str) -> Option<usize> {
    let ascii = text.as_bytes();
    let utf16: Vec<u8> = ascii.iter().flat_map(|&b| [b, 0]).collect();
    img.regions.iter().find_map(|r| {
        let bytes = read_region(img.source, r.base, r.size);
        [ascii, &utf16]
            .into_iter()
            .find_map(|needle| bytes.windows(needle.len()).position(|w| w == needle))
            .map(|pos| r.base + pos)
    })
}

fn string_ref_sites(bytes: &[u8], base: usize, data_abs: usize, arch: Arch) -> Vec<usize> {
    match arch {
        Arch::X86 => {
            let key = (data_abs as u32).to_le_bytes();
            bytes
                .windows(4)
                .enumerate()
                .filter(|(_, w)| *w == key)
                .map(|(i, _)| base + i)
                .collect()
        }
        Arch::X64 => bytes
            .windows(7)
            .enumerate()
            .filter_map(|(i, w)| {
                let lea = w[0] & 0xFB == 0x48 && w[1] == 0x8D && w[2] & 0xC7 == 0x05;
                let disp = i32::from_le_bytes([w[3], w[4], w[5], w[6]]) as i64;
                (lea && (base + i + 7) as i64 + disp == data_abs as i64).then_some(base + i)
            })
            .collect(),
    }
}

fn xref_sites(img: &ImageInput, data_abs: usize) -> Vec<usize> {
    img.code_regions
        .iter()
        .flat_map(|region| {
            let bytes = read_region(img.source, region.base, region.size);
            string_ref_sites(&bytes, region.base, data_abs, img.arch)
        })
        .collect()
}

// Walk back to the nearest standard frame prologue so an anchor resolves to the function entry, not
// the mid-body reference; this also collapses several references inside one function to a single site.
// The prologue is arch-specific: `push ebp; mov ebp, esp` on x86, `push rbp; mov rbp, rsp` on x64. A
// frameless function (common on optimized x64) has no such marker, so the reference site stands and the
// caller's uniqueness/identity gates reject any wrong landing; authoritative .pdata/RUNTIME_FUNCTION
// detection would pin the frameless ones too (tracked on #12).
pub(super) fn enclosing_function(img: &ImageInput, site_rva: usize) -> usize {
    let prologue: &[u8] = match img.arch {
        Arch::X86 => &[0x55, 0x8B, 0xEC],
        Arch::X64 => &[0x55, 0x48, 0x8B, 0xEC],
    };
    let start = site_rva.saturating_sub(1024);
    let bytes = read_at(
        img.source,
        img.base,
        start,
        site_rva - start + prologue.len(),
    );
    bytes
        .windows(prologue.len())
        .enumerate()
        .rev()
        .find(|(_, w)| *w == prologue)
        .map_or(site_rva, |(i, _)| start + i)
}

fn functions_referencing(img: &ImageInput, text: &str) -> Option<BTreeSet<usize>> {
    let data_abs = find_string_in_data(img, text)?;
    let set: BTreeSet<usize> = xref_sites(img, data_abs)
        .into_iter()
        .map(|site| enclosing_function(img, site - img.base))
        .collect();
    (!set.is_empty()).then_some(set)
}

fn only(set: BTreeSet<usize>) -> Option<usize> {
    let mut it = set.into_iter();
    it.next().filter(|_| it.next().is_none())
}

#[must_use]
pub fn resolve_string_anchor(img: &ImageInput, anchor: &StringAnchor) -> Option<usize> {
    let primary = functions_referencing(img, &anchor.text)?;
    match &anchor.also {
        None => only(primary),
        Some(second) => {
            let secondary = functions_referencing(img, second)?;
            only(primary.intersection(&secondary).copied().collect())
        }
    }
}

/// Build a string anchor for the function at `target_rva`. Prefers a single string that already pins
/// down one enclosing function (longest first); failing that, a pair whose referencing sets intersect
/// to exactly that function. Returns `None` if its strings cannot isolate it.
#[must_use]
pub fn make_string_anchor(img: &ImageInput, target_rva: usize) -> Option<StringAnchor> {
    let mut strings = fn_identity(img, target_rva).strings;
    strings.sort_by_key(|s| std::cmp::Reverse(s.len()));
    strings.truncate(6);
    let sets: Vec<(String, BTreeSet<usize>)> = strings
        .into_iter()
        .filter_map(|s| functions_referencing(img, &s).map(|f| (s, f)))
        .collect();

    if let Some((text, _)) = sets.iter().find(|(_, f)| f.len() == 1) {
        return Some(StringAnchor {
            text: text.clone(),
            also: None,
        });
    }
    for (i, (a, fa)) in sets.iter().enumerate() {
        for (b, fb) in &sets[i + 1..] {
            if fa.intersection(fb).count() == 1 {
                return Some(StringAnchor {
                    text: a.clone(),
                    also: Some(b.clone()),
                });
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    // A bare identity carrying only a mnemonic stream (and optional evidence sets), so the similarity
    // measure can be exercised on exact streams without decoding real machine code.
    fn ident(mnemonics: &[u32]) -> FnIdentity {
        FnIdentity {
            instr_count: mnemonics.len(),
            mnemonics: mnemonics.to_vec(),
            ..Default::default()
        }
    }

    #[test]
    fn string_anchor_resolves_an_x64_rip_relative_reference() {
        // #12: the string anchor is arch-neutral. fn_identity reads referenced strings through the
        // arch-aware mem_target (which resolves x64 RIP-relative operands), and the reverse xref scan
        // has a dedicated x64 `lea reg,[rip+d]` arm, so a function that references a unique string by a
        // RIP-relative lea is anchored and re-resolved on x64 exactly as on x86, with no x86-only
        // absolute-addressing assumption. Validated synthetically because no x64 MapleStory client
        // exists to measure against.
        use crate::memory::{BufferSource, Region};
        // A low base so the test also builds on a 32-bit target (a realistic x64 base would overflow
        // a 32-bit usize); RIP-relative resolution is base-independent, so this exercises it the same.
        const BASE: usize = 0x1000;
        let mut buf = vec![0u8; 0x200];
        // rva 0: `lea rcx, [rip+0xF9]` (-> the string at rva 0x100, since 0 + 7 + 0xF9 = 0x100) ; `ret`.
        buf[0..7].copy_from_slice(&[0x48, 0x8D, 0x0D, 0xF9, 0x00, 0x00, 0x00]);
        buf[7] = 0xC3;
        buf[0x100..0x109].copy_from_slice(b"MapleX64\0");
        let src = BufferSource::new(BASE, buf);
        let img = ImageInput {
            label: "x64".into(),
            source: &src,
            base: BASE,
            size: 0x200,
            code_regions: vec![Region {
                base: BASE,
                size: 0x80,
            }],
            regions: vec![Region {
                base: BASE,
                size: 0x200,
            }],
            import: None,
            arch: Arch::X64,
            code_hash: 0,
            packed: false,
            pack_reasons: Vec::new(),
            reloc: None,
        };
        let anchor = make_string_anchor(&img, 0).expect("an x64 string anchor");
        assert_eq!(anchor.text, "MapleX64");
        assert_eq!(
            resolve_string_anchor(&img, &anchor),
            Some(0),
            "the x64 RIP-relative string reference re-resolves to the function"
        );
    }

    #[test]
    fn mnemonic_similarity_is_one_for_identical_streams() {
        let a = ident(&[1, 2, 3, 4, 5, 6]);
        assert!((a.similarity(&a) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn inserted_prologue_instruction_stays_high() {
        // The same body with one extra instruction spliced in at the front: a strict leading-prefix
        // match would collapse to ~0, but the order-preserving LCS keeps it high.
        let base = ident(&[10, 11, 12, 13, 14, 15]);
        let mut with_insert = ident(&[99, 10, 11, 12, 13, 14, 15]);
        with_insert.blocks = base.blocks;
        with_insert.calls = base.calls;
        let s = base.similarity(&with_insert);
        assert!(
            s > 0.85,
            "one inserted instruction should stay highly similar, got {s}"
        );
    }

    #[test]
    fn inserted_instruction_in_the_middle_stays_high() {
        let base = ident(&[20, 21, 22, 23, 24, 25, 26, 27]);
        let middle = ident(&[20, 21, 22, 23, 99, 24, 25, 26, 27]);
        let s = base.similarity(&middle);
        assert!(s > 0.85, "a mid-body insertion should stay high, got {s}");
    }

    #[test]
    fn changed_core_mnemonics_score_clearly_lower() {
        let base = ident(&[1, 2, 3, 4, 5, 6]);
        let rewritten = ident(&[1, 90, 91, 92, 93, 6]);
        let inserted = ident(&[99, 1, 2, 3, 4, 5, 6]);
        let sim_changed = base.similarity(&rewritten);
        let sim_inserted = base.similarity(&inserted);
        assert!(
            sim_changed < 0.75,
            "a rewritten core must drop clearly, got {sim_changed}"
        );
        assert!(
            sim_changed < sim_inserted,
            "rewriting the core ({sim_changed}) must score below a mere insertion ({sim_inserted})"
        );
    }

    #[test]
    fn empty_constant_and_string_sets_do_not_inflate_unrelated_functions() {
        // Two functions with different mnemonic streams and no constants or strings: the absent
        // evidence must be neutral, not counted as a perfect constant/string match that drags the
        // blend up toward 1.0.
        let a = ident(&[1, 2, 3, 4]);
        let b = ident(&[40, 41, 42, 43]);
        let blended = a.similarity(&b);
        let mnem_only = mnemonic_similarity(&a.mnemonics, &b.mnemonics);
        let structure = 1.0; // identical (zero) block/call/branch/return counts
        let expected = (0.40 * mnem_only + 0.25 * structure) / (0.40 + 0.25);
        assert!(
            (blended - expected).abs() < 1e-9,
            "empty const/string sets must drop out, got {blended} want {expected}"
        );
        assert!(
            blended < 0.7,
            "unrelated bodies must not be inflated to a high score, got {blended}"
        );
    }

    #[test]
    fn jaccard_opt_is_none_for_two_empty_sets() {
        assert_eq!(jaccard_opt::<u64>(&[], &[]), None);
        assert_eq!(jaccard_opt(&[1u64, 2], &[1, 2]), Some(1.0));
        assert_eq!(jaccard_opt(&[1u64], &[2u64]), Some(0.0));
    }

    #[test]
    fn shared_constants_lift_an_otherwise_equal_pair() {
        // With identical mnemonics and structure, a shared distinctive constant should score 1.0 while
        // disjoint constants pull the blend down: proof the constant component is actually weighed when
        // present (the converse of the empty-set case).
        let mut a = ident(&[1, 2, 3]);
        let mut b = ident(&[1, 2, 3]);
        a.constants = vec![0xDEAD_BEEF];
        b.constants = vec![0xDEAD_BEEF];
        assert!((a.similarity(&b) - 1.0).abs() < 1e-9);
        b.constants = vec![0x1234_5678];
        assert!(a.similarity(&b) < 1.0);
    }
}
