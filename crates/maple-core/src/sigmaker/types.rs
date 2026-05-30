use crate::fileimage::RelocLookup;
use crate::memory::{MemorySource, Region};
use crate::pattern::Arch;

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
    pub(super) fn rank(self) -> u8 {
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
    pub(super) fn order(self) -> u8 {
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
    pub(super) fn classify(&self, abs: usize) -> TargetKind {
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
