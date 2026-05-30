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
    mnemonics: Vec<u32>,
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

impl FnIdentity {
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

pub(super) fn callee_fingerprint(img: &ImageInput, target_rva: usize) -> String {
    fn_identity(img, target_rva).fingerprint()
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

// Walk back to the nearest standard x86 frame prologue so an anchor resolves to the function entry,
// not the mid-body reference. This also collapses several references inside one function to a single
// site. x64 prologues vary too much to pin this way, so there the reference site stands.
fn enclosing_function(img: &ImageInput, site_rva: usize) -> usize {
    if !matches!(img.arch, Arch::X86) {
        return site_rva;
    }
    let start = site_rva.saturating_sub(1024);
    let bytes = read_at(img.source, img.base, start, site_rva - start + 3);
    bytes
        .windows(3)
        .enumerate()
        .rev()
        .find(|(_, w)| *w == [0x55, 0x8B, 0xEC])
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
