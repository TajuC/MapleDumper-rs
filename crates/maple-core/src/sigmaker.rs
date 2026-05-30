use std::collections::BTreeSet;

use crate::fileimage::{RelocKind, RelocLookup};
use crate::memory::{MemorySource, Region};
use crate::pattern::{Arch, Signature, try_signature_from_aob};
use crate::resolver::decode_rel_target;
use crate::scanner::{CompiledPattern, find_all};
use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, OpKind, Register};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Grade {
    A,
    B,
    C,
    D,
    F,
}

impl Grade {
    #[must_use]
    pub fn letter(self) -> char {
        match self {
            Grade::A => 'A',
            Grade::B => 'B',
            Grade::C => 'C',
            Grade::D => 'D',
            Grade::F => 'F',
        }
    }
    fn rank(self) -> u8 {
        match self {
            Grade::A => 0,
            Grade::B => 1,
            Grade::C => 2,
            Grade::D => 3,
            Grade::F => 4,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Suffix {
    None,
    Call,
    Jmp,
    Ptr,
}

impl Suffix {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Suffix::None => "",
            Suffix::Call => "_CALL",
            Suffix::Jmp => "_JMP",
            Suffix::Ptr => "_PTR",
        }
    }
    fn order(self) -> u8 {
        match self {
            Suffix::None => 0,
            Suffix::Call => 1,
            Suffix::Jmp => 2,
            Suffix::Ptr => 3,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TargetKind {
    Code,
    Data,
    Import,
    Unknown,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Anchor {
    Direct,
    Branch,
    Ptr { rip: bool },
}

#[derive(Clone, Debug)]
pub enum Diag {
    NoInputs,
    MixedArch,
    PackedInput { label: String, reasons: Vec<String> },
    MissingInImage { label: String },
    AmbiguousInImage { label: String, count: usize },
    StreamDiverges { label: String, offset: usize },
    UnsupportedReloc { rva: usize, reloc_type: u8 },
    InvalidAob { reason: String },
    TooFewFixedBytes { fixed: usize },
    LowFixedRatio { ratio: f64 },
    NoOpcodeBytes,
    TargetNotCode { label: String, rva: usize },
    UnresolvableTarget { label: String },
    CalleeMismatch,
    NotUnique,
    BuildFailed,
}

impl std::fmt::Display for Diag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Diag::NoInputs => f.write_str("no inputs"),
            Diag::MixedArch => f.write_str("inputs mix x86 and x64"),
            Diag::PackedInput { label, reasons } => {
                write!(f, "packed input {label}: {}", reasons.join("; "))
            }
            Diag::MissingInImage { label } => write!(f, "not found in {label}"),
            Diag::AmbiguousInImage { label, count } => write!(f, "{count} matches in {label}"),
            Diag::StreamDiverges { label, offset } => {
                write!(f, "instruction stream diverges in {label} at +0x{offset:X}")
            }
            Diag::UnsupportedReloc { rva, reloc_type } => {
                write!(f, "unsupported relocation (type {reloc_type}) at 0x{rva:X}")
            }
            Diag::InvalidAob { reason } => write!(f, "invalid signature: {reason}"),
            Diag::TooFewFixedBytes { fixed } => write!(f, "too few fixed bytes ({fixed})"),
            Diag::LowFixedRatio { ratio } => write!(f, "fixed ratio too low ({ratio:.2})"),
            Diag::NoOpcodeBytes => f.write_str("no meaningful fixed opcode bytes"),
            Diag::TargetNotCode { label, rva } => {
                write!(
                    f,
                    "branch target 0x{rva:X} is not in executable code in {label}"
                )
            }
            Diag::UnresolvableTarget { label } => {
                write!(f, "could not resolve the branch target in {label}")
            }
            Diag::CalleeMismatch => {
                f.write_str("branch target resolves to different code across builds")
            }
            Diag::NotUnique => f.write_str("could not make a unique signature across all builds"),
            Diag::BuildFailed => f.write_str("build failed"),
        }
    }
}

pub enum TargetSpec {
    Aob(String),
    Ref { image: usize, rva: u64 },
}

pub struct SigOptions {
    pub max_len: usize,
    pub min_fixed: usize,
    pub min_fixed_ratio: f64,
}

impl Default for SigOptions {
    fn default() -> Self {
        Self {
            max_len: 80,
            min_fixed: 5,
            min_fixed_ratio: 0.30,
        }
    }
}

#[derive(Clone)]
pub struct ImageInput<'a> {
    pub label: String,
    pub source: &'a dyn MemorySource,
    pub base: usize,
    pub size: usize,
    pub code_regions: Vec<Region>,
    pub regions: Vec<Region>,
    pub import: Option<(usize, usize)>,
    pub arch: Arch,
    pub code_hash: u64,
    pub packed: bool,
    pub pack_reasons: Vec<String>,
    pub reloc: Option<&'a dyn RelocLookup>,
}

impl ImageInput<'_> {
    fn classify(&self, abs: usize) -> TargetKind {
        let in_region = |rs: &[Region]| rs.iter().any(|r| abs >= r.base && abs < r.base + r.size);
        if in_region(&self.code_regions) {
            TargetKind::Code
        } else if self.import.is_some_and(|(s, e)| abs >= s && abs < e) {
            TargetKind::Import
        } else if in_region(&self.regions) {
            TargetKind::Data
        } else {
            TargetKind::Unknown
        }
    }
}

#[derive(Clone, Debug)]
pub struct PerVersion {
    pub label: String,
    pub match_rva: Option<u64>,
    pub resolved_target_rva: Option<u64>,
    pub target_kind: Option<TargetKind>,
}

#[derive(Clone, Debug)]
pub struct SigCandidate {
    pub aob: String,
    pub suffix: Suffix,
    pub grade: Grade,
    pub score: u32,
    pub bytes_len: usize,
    pub fixed: usize,
    pub wildcards: usize,
    pub fixed_ratio: f64,
    pub reloc_safe: bool,
    pub per_version: Vec<PerVersion>,
    pub diags: Vec<Diag>,
}

#[derive(Clone, Debug)]
pub struct DupGroup {
    pub code_hash: u64,
    pub labels: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct InputInfo {
    pub label: String,
    pub packed: bool,
    pub reasons: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct NegativeHit {
    pub label: String,
    pub count: usize,
}

#[derive(Clone, Debug)]
pub struct HoldoutResult {
    pub held_out: String,
    pub generated: bool,
    pub matched_holdout: bool,
}

/// The reliably detectable identity of a client build: arch, pack state, code size, and code hash.
/// A human variant label (GMS, KMS, a private fork) stays operator-supplied, not derived here.
#[derive(Clone, Debug)]
pub struct BuildProfile {
    pub arch: Arch,
    pub packed: bool,
    pub code_bytes: usize,
    pub code_hash: u64,
}

impl BuildProfile {
    #[must_use]
    pub fn of(img: &ImageInput) -> Self {
        Self {
            arch: img.arch,
            packed: img.packed,
            code_bytes: img.code_regions.iter().map(|r| r.size).sum(),
            code_hash: img.code_hash,
        }
    }

    /// Same lane = same arch and pack state; a cross-version comparison must not cross either.
    #[must_use]
    pub fn same_variant(&self, other: &Self) -> bool {
        matches!(
            (self.arch, other.arch),
            (Arch::X64, Arch::X64) | (Arch::X86, Arch::X86)
        ) && self.packed == other.packed
    }
}

#[derive(Clone, Debug)]
pub struct SigReport {
    pub arch: Arch,
    pub inputs: Vec<InputInfo>,
    pub unique_builds: usize,
    pub duplicate_groups: Vec<DupGroup>,
    pub chosen: Option<SigCandidate>,
    pub alternates: Vec<SigCandidate>,
    pub rejected: Vec<SigCandidate>,
    pub diagnostics: Vec<Diag>,
}

fn bitness(arch: Arch) -> u32 {
    if matches!(arch, Arch::X64) { 64 } else { 32 }
}

fn read_region(src: &dyn MemorySource, base: usize, size: usize) -> Vec<u8> {
    let mut buf = vec![0u8; size];
    let mut off = 0;
    while off < size {
        match src.read_into(base + off, &mut buf[off..]) {
            Ok(0) | Err(_) => break,
            Ok(n) => off += n,
        }
    }
    buf
}

fn read_at(src: &dyn MemorySource, base: usize, rva: usize, len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    let mut off = 0;
    while off < len {
        match src.read_into(base + rva + off, &mut buf[off..]) {
            Ok(0) | Err(_) => break,
            Ok(n) => off += n,
        }
    }
    buf
}

struct CodeCache {
    image_base: usize,
    regions: Vec<(usize, Vec<u8>)>,
}

impl CodeCache {
    fn build(img: &ImageInput) -> Self {
        let regions = img
            .code_regions
            .iter()
            .map(|r| (r.base, read_region(img.source, r.base, r.size)))
            .collect();
        Self {
            image_base: img.base,
            regions,
        }
    }

    fn locate(&self, pat: &CompiledPattern) -> (usize, Option<u64>) {
        let mut count = 0;
        let mut first: Option<u64> = None;
        for (base, bytes) in &self.regions {
            for off in find_all(bytes, pat) {
                count += 1;
                let rva = (base + off - self.image_base) as u64;
                first = Some(first.map_or(rva, |f| f.min(rva)));
            }
        }
        (count, first)
    }
}

/// Scan a corpus of unrelated modules for `aob` and report any that contain it. Generation only
/// proves a signature is unique among the supplied builds, so a short or low-entropy pattern can
/// still collide inside some other module; a hit here means the signature is not specific enough to
/// trust as an identity. Returns one entry per negative image that matched, with the match count.
#[must_use]
pub fn negative_corpus_hits(aob: &str, negatives: &[ImageInput]) -> Vec<NegativeHit> {
    let Some(pat) = crate::pattern::try_signature_from_aob(aob)
        .ok()
        .and_then(|sig| CompiledPattern::new(&sig))
    else {
        return Vec::new();
    };
    negatives
        .iter()
        .filter_map(|img| {
            let (count, _) = CodeCache::build(img).locate(&pat);
            (count > 0).then_some(NegativeHit {
                label: img.label.clone(),
                count,
            })
        })
        .collect()
}

/// Leave-one-out validation: for each build, regenerate the signature from the others and check it
/// still uniquely matches the held-out build. Generation only proves a signature fits the builds it
/// was trained on; a signature that fits those but fails a build it never saw is overfit to the
/// corpus. Needs at least three builds (two to train on, one to hold out) and returns one result per
/// eligible held-out build. A reference build that defines the target cannot itself be held out.
#[must_use]
pub fn holdout_validate(
    images: &[ImageInput],
    spec: &TargetSpec,
    opts: &SigOptions,
) -> Vec<HoldoutResult> {
    if images.len() < 3 {
        return Vec::new();
    }
    let mut out = Vec::new();
    for i in 0..images.len() {
        let adjusted = match spec {
            TargetSpec::Aob(s) => TargetSpec::Aob(s.clone()),
            TargetSpec::Ref { image, rva } => {
                if i == *image {
                    continue; // the reference defines the target, so it cannot be held out
                }
                let image = if i < *image { image - 1 } else { *image };
                TargetSpec::Ref { image, rva: *rva }
            }
        };
        let train: Vec<ImageInput> = images
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, img)| img.clone())
            .collect();
        let report = generate(&train, &adjusted, opts);
        let matched = report.chosen.as_ref().is_some_and(|c| {
            crate::pattern::try_signature_from_aob(&c.aob)
                .ok()
                .and_then(|sig| CompiledPattern::new(&sig))
                .is_some_and(|pat| CodeCache::build(&images[i]).locate(&pat).0 == 1)
        });
        out.push(HoldoutResult {
            held_out: images[i].label.clone(),
            generated: report.chosen.is_some(),
            matched_holdout: matched,
        });
    }
    out
}

struct InstrMask {
    len: usize,
    fixed: Vec<bool>,
    operand: Vec<bool>,
    unsupported: Option<(usize, u8)>,
}

fn set_range(v: &mut [bool], start: usize, size: usize) {
    for b in v.iter_mut().skip(start).take(size) {
        *b = true;
    }
}

fn decode_masked(
    bytes: &[u8],
    arch: Arch,
    base: usize,
    rva: usize,
    reloc: Option<&dyn RelocLookup>,
    max_instrs: usize,
) -> Vec<InstrMask> {
    let ip = (base + rva) as u64;
    let mut decoder = Decoder::with_ip(bitness(arch), bytes, ip, DecoderOptions::NONE);
    let mut instr = Instruction::default();
    let mut out = Vec::new();
    while decoder.can_decode() && out.len() < max_instrs {
        decoder.decode_out(&mut instr);
        if instr.is_invalid() {
            break;
        }
        let len = instr.len();
        if len == 0 {
            break;
        }
        let co = decoder.get_constant_offsets(&instr);
        let mut operand = vec![false; len];
        if co.has_displacement() {
            set_range(
                &mut operand,
                co.displacement_offset(),
                co.displacement_size(),
            );
        }
        if co.has_immediate() {
            set_range(&mut operand, co.immediate_offset(), co.immediate_size());
        }
        if co.has_immediate2() {
            set_range(&mut operand, co.immediate_offset2(), co.immediate_size2());
        }
        let mut fixed: Vec<bool> = operand.iter().map(|&o| !o).collect();
        let mut unsupported: Option<(usize, u8)> = None;
        if let Some(reloc) = reloc {
            let instr_rva = (instr.ip() as usize) - base;
            for (k, f) in fixed.iter_mut().enumerate() {
                let rva = instr_rva + k;
                if let Some(kind) = reloc.reloc_kind_at(rva) {
                    *f = false; // a relocated byte is patched at load, so it can't stay fixed
                    if let RelocKind::Unsupported(t) = kind {
                        unsupported.get_or_insert((rva, t));
                    }
                }
            }
        }
        out.push(InstrMask {
            len,
            fixed,
            operand,
            unsupported,
        });
    }
    out
}

fn compile(bytes: &[u8], mask: &[bool]) -> Option<CompiledPattern> {
    CompiledPattern::new(&Signature {
        bytes: bytes.to_vec(),
        mask: mask.to_vec(),
    })
}

fn aob_of(bytes: &[u8], mask: &[bool]) -> String {
    Signature {
        bytes: bytes.to_vec(),
        mask: mask.to_vec(),
    }
    .to_aob()
}

struct Located {
    ref_idx: usize,
    anchors: Vec<(usize, u64)>, // (image index, rva) for each required, located build
}

fn mem_target(instr: &Instruction, arch: Arch) -> Option<usize> {
    if !(0..instr.op_count()).any(|i| instr.op_kind(i) == OpKind::Memory) {
        return None;
    }
    if instr.is_ip_rel_memory_operand() {
        return Some(instr.ip_rel_memory_address() as usize);
    }
    if matches!(arch, Arch::X86)
        && instr.memory_base() == Register::None
        && instr.memory_index() == Register::None
    {
        return Some(instr.memory_displacement64() as usize);
    }
    None
}

fn resolve_anchor(anchor: Anchor, img: &ImageInput, site: usize) -> Option<usize> {
    match anchor {
        Anchor::Direct => None,
        Anchor::Branch => {
            let bytes = read_at(img.source, img.base, site, 8);
            decode_rel_target(&bytes, img.base + site)
        }
        Anchor::Ptr { .. } => {
            let bytes = read_at(img.source, img.base, site, 16);
            let mut decoder = Decoder::with_ip(
                bitness(img.arch),
                &bytes,
                (img.base + site) as u64,
                DecoderOptions::NONE,
            );
            let mut instr = Instruction::default();
            decoder.decode_out(&mut instr);
            (!instr.is_invalid())
                .then(|| mem_target(&instr, img.arch))
                .flatten()
        }
    }
}

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

fn callee_fingerprint(img: &ImageInput, target_rva: usize) -> String {
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

pub use crate::domain::StringAnchor;

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

// A 0-100 confidence derived from the grade band and refined by signature density and the
// corroborating signals, so the UI and sorting have a number, not only a letter.
fn confidence_score(grade: Grade, fixed_ratio: f64, reloc_safe: bool, fp_consistent: bool) -> u32 {
    let base = match grade {
        Grade::A => 80.0,
        Grade::B => 62.0,
        Grade::C => 42.0,
        Grade::D => 25.0,
        Grade::F => return 0,
    };
    let mut s = base + fixed_ratio.clamp(0.0, 1.0) * 12.0;
    if reloc_safe {
        s += 3.0;
    }
    if fp_consistent {
        s += 3.0;
    }
    s.round().min(100.0) as u32
}

#[allow(clippy::too_many_arguments)]
fn finalize(
    images: &[ImageInput],
    caches: &[(usize, CodeCache)],
    located: &Located,
    ref_bytes: &[u8],
    base_fixed: &[bool],
    operand: &[bool],
    suffix: Suffix,
    anchor: Anchor,
    unsupported: Option<(usize, u8)>,
    any_packed: bool,
    opts: &SigOptions,
    diags_in: &[Diag],
) -> Option<SigCandidate> {
    let len = ref_bytes.len();
    let mut bytes = ref_bytes.to_vec();
    let mut fixed = base_fixed.to_vec();
    let cache_of = |idx: usize| &caches.iter().find(|(i, _)| *i == idx).unwrap().1;

    for &(idx, rva) in &located.anchors {
        if idx == located.ref_idx {
            continue;
        }
        let other = read_at(images[idx].source, images[idx].base, rva as usize, len);
        for k in 0..len {
            if fixed[k] && other.get(k) != Some(&bytes[k]) {
                fixed[k] = false;
            }
        }
    }

    let fixed_n = fixed.iter().filter(|&&f| f).count();
    let wild_n = len - fixed_n;
    let ratio = if len == 0 {
        0.0
    } else {
        fixed_n as f64 / len as f64
    };
    let meaningful = (0..len)
        .filter(|&k| fixed[k] && !operand.get(k).copied().unwrap_or(false))
        .count();

    let pat = compile(&bytes, &fixed)?;
    let is_anchor = !matches!(anchor, Anchor::Direct);
    let mut per_version = Vec::new();
    let mut unique_all = true;
    let mut anchor_diags: Vec<Diag> = Vec::new();
    let mut all_code = true;
    let mut any_unresolved = false;
    let mut kinds: Vec<TargetKind> = Vec::new();
    let mut fingerprints: Vec<String> = Vec::new();
    for &(idx, _) in &located.anchors {
        let img = &images[idx];
        let (count, rva) = cache_of(idx).locate(&pat);
        if count != 1 {
            unique_all = false;
        }
        let mut resolved_target_rva = None;
        let mut target_kind = None;
        if is_anchor && let Some(site) = rva {
            match resolve_anchor(anchor, img, site as usize) {
                Some(target_abs) => {
                    match crate::domain::checked_rva(target_abs, img.base, img.size) {
                        Ok(rva_u64) => {
                            let target_rva = rva_u64 as usize;
                            let kind = img.classify(target_abs);
                            resolved_target_rva = Some(rva_u64);
                            target_kind = Some(kind);
                            kinds.push(kind);
                            if kind == TargetKind::Code {
                                fingerprints.push(callee_fingerprint(img, target_rva));
                            } else {
                                all_code = false;
                                if matches!(anchor, Anchor::Branch) {
                                    anchor_diags.push(Diag::TargetNotCode {
                                        label: img.label.clone(),
                                        rva: target_rva,
                                    });
                                }
                            }
                        }
                        Err(_) => {
                            // the target resolved outside the image; treat it as unresolvable rather
                            // than recording a bounded numeric RVA that could look like a valid target.
                            any_unresolved = true;
                            anchor_diags.push(Diag::UnresolvableTarget {
                                label: img.label.clone(),
                            });
                        }
                    }
                }
                None => {
                    any_unresolved = true;
                    anchor_diags.push(Diag::UnresolvableTarget {
                        label: img.label.clone(),
                    });
                }
            }
        }
        per_version.push(PerVersion {
            label: img.label.clone(),
            match_rva: rva,
            resolved_target_rva,
            target_kind,
        });
    }

    if !unique_all {
        return None; // not unique here; the caller will grow the window
    }

    let mut diags: Vec<Diag> = diags_in.to_vec();
    diags.extend(anchor_diags);
    let mut gated = false;
    if fixed_n < opts.min_fixed {
        diags.push(Diag::TooFewFixedBytes { fixed: fixed_n });
        gated = true;
    }
    if ratio < opts.min_fixed_ratio {
        diags.push(Diag::LowFixedRatio { ratio });
        gated = true;
    }
    if meaningful == 0 {
        diags.push(Diag::NoOpcodeBytes);
        gated = true;
    }
    if let Some((rva, reloc_type)) = unsupported {
        // An unsupported relocation could still patch a byte we kept fixed, so reject it rather
        // than ship a signature that breaks at load time.
        diags.push(Diag::UnsupportedReloc { rva, reloc_type });
        gated = true;
    }
    let reloc_safe = unsupported.is_none();

    let fp_consistent = fingerprints.windows(2).all(|w| w[0] == w[1]);
    let kinds_consistent = kinds.windows(2).all(|w| w[0] == w[1]);
    if is_anchor && !any_unresolved && !fp_consistent {
        diags.push(Diag::CalleeMismatch);
    }
    // Grade A needs a content-validated anchor: a branch or RIP-relative ref whose target is code
    // with matching callee fingerprints in every build. A stable data/import ref resolves but its
    // content is unchecked, so it caps at B; absolute refs and any cross-build mismatch fall to C.
    let grade = if gated {
        Grade::F
    } else if any_packed {
        Grade::D
    } else if !reloc_safe {
        Grade::C
    } else {
        match anchor {
            Anchor::Direct => Grade::B,
            Anchor::Branch => {
                if all_code && !any_unresolved && fp_consistent {
                    Grade::A
                } else {
                    Grade::C
                }
            }
            Anchor::Ptr { rip }
                if rip && !any_unresolved && kinds_consistent && !kinds.is_empty() =>
            {
                match kinds[0] {
                    TargetKind::Code if fp_consistent => Grade::A,
                    TargetKind::Data | TargetKind::Import => Grade::B,
                    _ => Grade::C, // code with mismatched callees, or unknown region
                }
            }
            Anchor::Ptr { .. } => Grade::C, // absolute, unresolved, or kind-inconsistent
        }
    };

    let score = confidence_score(grade, ratio, reloc_safe, fp_consistent);
    let aob = aob_of(&bytes, &fixed);
    bytes.truncate(len);
    Some(SigCandidate {
        aob,
        suffix,
        grade,
        score,
        bytes_len: len,
        fixed: fixed_n,
        wildcards: wild_n,
        fixed_ratio: ratio,
        reloc_safe,
        per_version,
        diags,
    })
}

fn ptr_sites(
    image_base: usize,
    ref_cache: &CodeCache,
    target_abs: usize,
    arch: Arch,
    cap: usize,
) -> Vec<(u64, bool)> {
    let bits = bitness(arch);
    let mut sites = Vec::new();
    let mut instr = Instruction::default();
    for (rbase, bytes) in &ref_cache.regions {
        let mut decoder = Decoder::with_ip(bits, bytes, *rbase as u64, DecoderOptions::NONE);
        while decoder.can_decode() {
            decoder.decode_out(&mut instr);
            if instr.is_invalid() {
                continue;
            }
            if mem_target(&instr, arch) == Some(target_abs) {
                let rip = instr.is_ip_rel_memory_operand();
                sites.push(((instr.ip() as usize - image_base) as u64, rip));
                if sites.len() >= cap {
                    return sites;
                }
            }
        }
    }
    sites
}

#[allow(clippy::too_many_arguments)]
fn candidate_at(
    images: &[ImageInput],
    caches: &[(usize, CodeCache)],
    required: &[usize],
    ref_idx: usize,
    site_rva: u64,
    suffix: Suffix,
    seed_mask: Option<&[bool]>,
    anchor: Anchor,
    any_packed: bool,
    opts: &SigOptions,
) -> (Option<SigCandidate>, Vec<SigCandidate>) {
    let arch = images[ref_idx].arch;
    let cache_of = |idx: usize| &caches.iter().find(|(i, _)| *i == idx).unwrap().1;
    let max_instrs = opts.max_len / 2 + 8;
    let ref_img = &images[ref_idx];
    let window = read_at(
        ref_img.source,
        ref_img.base,
        site_rva as usize,
        opts.max_len + 16,
    );
    let instrs = decode_masked(
        &window,
        arch,
        ref_img.base,
        site_rva as usize,
        ref_img.reloc,
        max_instrs,
    );

    let mut try_lens: Vec<usize> = Vec::new();
    if let Some(sm) = seed_mask {
        try_lens.push(sm.len().min(window.len()));
    }
    let mut acc = 0;
    for im in &instrs {
        acc += im.len;
        if acc > opts.max_len {
            break;
        }
        if !try_lens.contains(&acc) {
            try_lens.push(acc);
        }
    }

    let mut rejected: Vec<SigCandidate> = Vec::new();
    for &len in &try_lens {
        if len == 0 || len > window.len() {
            continue;
        }
        let mut fixed = vec![true; len];
        let mut operand = vec![false; len];
        let mut unsupported: Option<(usize, u8)> = None;
        let mut pos = 0;
        for im in &instrs {
            if pos >= len {
                break;
            }
            for k in 0..im.len {
                if pos + k < len {
                    fixed[pos + k] = im.fixed[k];
                    operand[pos + k] = im.operand[k];
                }
            }
            if unsupported.is_none()
                && let Some((rva, t)) = im.unsupported
                && rva.saturating_sub(site_rva as usize) < len
            {
                unsupported = Some((rva, t));
            }
            pos += im.len;
        }
        if let Some(sm) = seed_mask {
            for k in 0..len.min(sm.len()) {
                if !sm[k] {
                    fixed[k] = false;
                }
            }
        }

        let Some(pat) = compile(&window[..len], &fixed) else {
            continue;
        };
        let mut anchors = Vec::new();
        let mut all_unique = true;
        let mut diags_loc: Vec<Diag> = Vec::new();
        for &idx in required {
            let (count, rva) = cache_of(idx).locate(&pat);
            match (count, rva) {
                (1, Some(r)) => anchors.push((idx, r)),
                (0, _) => {
                    all_unique = false;
                    diags_loc.push(Diag::MissingInImage {
                        label: images[idx].label.clone(),
                    });
                }
                (n, _) => {
                    all_unique = false;
                    diags_loc.push(Diag::AmbiguousInImage {
                        label: images[idx].label.clone(),
                        count: n,
                    });
                }
            }
        }
        if !all_unique {
            continue;
        }
        let located = Located { ref_idx, anchors };
        if let Some(cand) = finalize(
            images,
            caches,
            &located,
            &window[..len],
            &fixed,
            &operand,
            suffix,
            anchor,
            unsupported,
            any_packed,
            opts,
            &diags_loc,
        ) {
            if cand.grade == Grade::F {
                rejected.push(cand);
            } else {
                return (Some(cand), rejected);
            }
        }
    }
    (None, rejected)
}

// Disassemble linearly so an E8/E9 inside another instruction's operand is never mistaken for a
// branch. Accept only a real 5-byte CALL/JMP whose rel32 resolves to target_abs.
fn branch_sites(
    image_base: usize,
    ref_cache: &CodeCache,
    target_abs: usize,
    arch: Arch,
    want_call: bool,
    cap: usize,
) -> Vec<u64> {
    let bits = bitness(arch);
    let target = target_abs as u64;
    let mut sites: Vec<u64> = Vec::new();
    let mut instr = Instruction::default();
    for (rbase, bytes) in &ref_cache.regions {
        let mut decoder = Decoder::with_ip(bits, bytes, *rbase as u64, DecoderOptions::NONE);
        while decoder.can_decode() {
            decoder.decode_out(&mut instr);
            if instr.is_invalid() {
                continue;
            }
            let kind_ok = if want_call {
                instr.flow_control() == FlowControl::Call
            } else {
                instr.flow_control() == FlowControl::UnconditionalBranch
            };
            if instr.len() == 5 && kind_ok && instr.near_branch_target() == target {
                let off = instr.ip() as usize - rbase;
                if decode_rel_target(&bytes[off..], instr.ip() as usize) == Some(target_abs) {
                    sites.push(((instr.ip() as usize) - image_base) as u64);
                    if sites.len() >= cap {
                        return sites;
                    }
                }
            }
        }
    }
    sites
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SigStage {
    Deduplicating,
    ReadingCode { build: usize, total: usize },
    LocatingTarget,
    ScanningDirect,
    ScanningCallJmp,
    ScanningPtr,
    Scoring,
}

pub fn generate_with_progress(
    images: &[ImageInput],
    spec: &TargetSpec,
    opts: &SigOptions,
    progress: &mut dyn FnMut(SigStage),
) -> SigReport {
    let arch = images.first().map_or(Arch::X64, |i| i.arch);
    let inputs: Vec<InputInfo> = images
        .iter()
        .map(|i| InputInfo {
            label: i.label.clone(),
            packed: i.packed,
            reasons: i.pack_reasons.clone(),
        })
        .collect();
    let mut diagnostics: Vec<Diag> = images
        .iter()
        .filter(|i| i.packed)
        .map(|i| Diag::PackedInput {
            label: i.label.clone(),
            reasons: i.pack_reasons.clone(),
        })
        .collect();

    let fail = |diagnostics: Vec<Diag>, unique_builds, dups| SigReport {
        arch,
        inputs: inputs.clone(),
        unique_builds,
        duplicate_groups: dups,
        chosen: None,
        alternates: Vec::new(),
        rejected: Vec::new(),
        diagnostics,
    };

    if images.is_empty() {
        diagnostics.push(Diag::NoInputs);
        return fail(diagnostics, 0, Vec::new());
    }
    if images.iter().any(|i| i.arch != arch) {
        diagnostics.push(Diag::MixedArch);
        return fail(diagnostics, 0, Vec::new());
    }

    progress(SigStage::Deduplicating);
    // group identical builds by code hash; the first occurrence represents the group
    let mut dup_groups: Vec<DupGroup> = Vec::new();
    let mut required: Vec<usize> = Vec::new();
    for (idx, img) in images.iter().enumerate() {
        if let Some(g) = dup_groups.iter_mut().find(|g| g.code_hash == img.code_hash) {
            g.labels.push(img.label.clone());
        } else {
            dup_groups.push(DupGroup {
                code_hash: img.code_hash,
                labels: vec![img.label.clone()],
            });
            required.push(idx);
        }
    }
    let unique_builds = required.len();
    let any_packed = images.iter().any(|i| i.packed);
    let mut caches: Vec<(usize, CodeCache)> = Vec::with_capacity(required.len());
    for (n, &i) in required.iter().enumerate() {
        progress(SigStage::ReadingCode {
            build: n + 1,
            total: required.len(),
        });
        caches.push((i, CodeCache::build(&images[i])));
    }
    let cache_of = |idx: usize| &caches.iter().find(|(i, _)| *i == idx).unwrap().1;

    progress(SigStage::LocatingTarget);
    let (ref_idx, ref_rva, _seed_len, seed_mask): (usize, u64, usize, Option<Vec<bool>>) =
        match spec {
            TargetSpec::Aob(aob) => {
                let sig = match try_signature_from_aob(aob) {
                    Ok(s) => s,
                    Err(reason) => {
                        diagnostics.push(Diag::InvalidAob { reason });
                        return fail(diagnostics, unique_builds, dup_groups);
                    }
                };
                let Some(pat) = CompiledPattern::new(&sig) else {
                    diagnostics.push(Diag::InvalidAob {
                        reason: "signature is empty".to_string(),
                    });
                    return fail(diagnostics, unique_builds, dup_groups);
                };
                let mut chosen_ref = None;
                for &idx in &required {
                    let (count, rva) = cache_of(idx).locate(&pat);
                    match (count, rva) {
                        (1, Some(r)) if chosen_ref.is_none() => chosen_ref = Some((idx, r)),
                        (0, _) => diagnostics.push(Diag::MissingInImage {
                            label: images[idx].label.clone(),
                        }),
                        (n, _) if n > 1 => diagnostics.push(Diag::AmbiguousInImage {
                            label: images[idx].label.clone(),
                            count: n,
                        }),
                        _ => {}
                    }
                }
                let Some((idx, r)) = chosen_ref else {
                    return fail(diagnostics, unique_builds, dup_groups);
                };
                (idx, r, sig.bytes.len(), Some(sig.mask))
            }
            TargetSpec::Ref { image, rva } => {
                if *image >= images.len() {
                    diagnostics.push(Diag::BuildFailed);
                    return fail(diagnostics, unique_builds, dup_groups);
                }
                // map to the representative of its dup group
                let ref_idx = required
                    .iter()
                    .copied()
                    .find(|&r| images[r].code_hash == images[*image].code_hash)
                    .unwrap_or(*image);
                (ref_idx, *rva, 1, None)
            }
        };

    let target_abs = images[ref_idx].base + ref_rva as usize;
    let mut pool: Vec<SigCandidate> = Vec::new();
    let mut rejected: Vec<SigCandidate> = Vec::new();

    progress(SigStage::ScanningDirect);
    let (cand, rej) = candidate_at(
        images,
        &caches,
        &required,
        ref_idx,
        ref_rva,
        Suffix::None,
        seed_mask.as_deref(),
        Anchor::Direct,
        any_packed,
        opts,
    );
    pool.extend(cand);
    rejected.extend(rej);

    progress(SigStage::ScanningCallJmp);
    for (want_call, suffix) in [(true, Suffix::Call), (false, Suffix::Jmp)] {
        for site in branch_sites(
            images[ref_idx].base,
            cache_of(ref_idx),
            target_abs,
            arch,
            want_call,
            24,
        ) {
            let (cand, rej) = candidate_at(
                images,
                &caches,
                &required,
                ref_idx,
                site,
                suffix,
                None,
                Anchor::Branch,
                any_packed,
                opts,
            );
            pool.extend(cand);
            rejected.extend(rej);
        }
    }

    progress(SigStage::ScanningPtr);
    for (site, rip) in ptr_sites(
        images[ref_idx].base,
        cache_of(ref_idx),
        target_abs,
        arch,
        24,
    ) {
        let (cand, rej) = candidate_at(
            images,
            &caches,
            &required,
            ref_idx,
            site,
            Suffix::Ptr,
            None,
            Anchor::Ptr { rip },
            any_packed,
            opts,
        );
        pool.extend(cand);
        rejected.extend(rej);
    }

    progress(SigStage::Scoring);
    // confidence first, then fewest wildcards / shortest / kind / AOB text, so the same inputs
    // always pick the same winner
    pool.sort_by(|a, b| {
        (
            a.grade.rank(),
            a.wildcards,
            a.bytes_len,
            a.suffix.order(),
            a.aob.as_str(),
        )
            .cmp(&(
                b.grade.rank(),
                b.wildcards,
                b.bytes_len,
                b.suffix.order(),
                b.aob.as_str(),
            ))
    });
    let chosen = (!pool.is_empty()).then(|| pool.remove(0));
    let alternates = pool;
    if chosen.is_none() {
        diagnostics.push(Diag::NotUnique);
    }

    SigReport {
        arch,
        inputs,
        unique_builds,
        duplicate_groups: dup_groups,
        chosen,
        alternates,
        rejected,
        diagnostics,
    }
}

pub fn generate(images: &[ImageInput], spec: &TargetSpec, opts: &SigOptions) -> SigReport {
    generate_with_progress(images, spec, opts, &mut |_| {})
}

/// Generates a signature, then checks it lands on `expected_rva` in the reference build.
#[derive(Clone, Debug)]
pub struct CrossReport {
    pub report: SigReport,
    pub expected_rva: u64,
    pub matched_rva: Option<u64>,
    pub agrees: bool,
}

pub fn generate_cross_with_progress(
    images: &[ImageInput],
    aob: &str,
    ref_image: usize,
    expected_rva: u64,
    opts: &SigOptions,
    progress: &mut dyn FnMut(SigStage),
) -> CrossReport {
    let report = generate_with_progress(images, &TargetSpec::Aob(aob.to_string()), opts, progress);
    let ref_label = images.get(ref_image).map(|i| i.label.as_str());
    // where it points: the resolved target for an anchored sig, or its own match for a direct one
    let matched_rva = report.chosen.as_ref().and_then(|c| {
        c.per_version
            .iter()
            .find(|p| Some(p.label.as_str()) == ref_label)
            .and_then(|p| p.resolved_target_rva.or(p.match_rva))
    });
    let agrees = matched_rva == Some(expected_rva);
    CrossReport {
        report,
        expected_rva,
        matched_rva,
        agrees,
    }
}

pub fn generate_cross(
    images: &[ImageInput],
    aob: &str,
    ref_image: usize,
    expected_rva: u64,
    opts: &SigOptions,
) -> CrossReport {
    generate_cross_with_progress(images, aob, ref_image, expected_rva, opts, &mut |_| {})
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::BufferSource;

    #[test]
    fn confidence_score_tracks_grade_and_signals() {
        assert_eq!(confidence_score(Grade::F, 0.9, true, true), 0);
        assert!(
            confidence_score(Grade::A, 0.5, true, true)
                > confidence_score(Grade::B, 0.5, true, true)
        );
        assert!(
            confidence_score(Grade::A, 0.5, true, true)
                > confidence_score(Grade::A, 0.5, false, false)
        );
        assert!(confidence_score(Grade::A, 1.0, true, true) <= 100);
    }

    #[test]
    fn callee_fingerprint_is_register_invariant_but_mnemonic_sensitive() {
        let base = 0x2000;
        let a = BufferSource::new(base, vec![0x48, 0x89, 0xD8, 0xC3]); // mov rax, rbx ; ret
        let b = BufferSource::new(base, vec![0x48, 0x89, 0xD1, 0xC3]); // mov rcx, rdx ; ret
        let c = BufferSource::new(base, vec![0x48, 0x01, 0xD8, 0xC3]); // add rax, rbx ; ret
        let fa = callee_fingerprint(&img("a", &a, base, 4), 0);
        let fb = callee_fingerprint(&img("b", &b, base, 4), 0);
        let fc = callee_fingerprint(&img("c", &c, base, 4), 0);
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
            code_hash: super::super::stamp::BuildStamp::capture(
                src,
                base,
                &[Region { base, size }],
            )
            .hash,
            packed: false,
            pack_reasons: Vec::new(),
            reloc: None,
        }
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
            cand.per_version.iter().all(
                |p| p.resolved_target_rva == Some(0) && p.target_kind == Some(TargetKind::Code)
            )
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
}
