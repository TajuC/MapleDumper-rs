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

    /// Cap this grade at `ceiling`: a grade better than the ceiling is lowered to it, a worse one is
    /// left alone. Used where an evidence class cannot earn the top bands however high it scores (a
    /// fingerprint-only relocation, with no byte or string proof, is capped at B).
    pub(super) fn max_rank(self, ceiling: Grade) -> Grade {
        if self.rank() < ceiling.rank() {
            ceiling
        } else {
            self
        }
    }

    /// The letter band for a `final_score` in 0..=100. The presentation grade is derived from the
    /// numeric score, never the other way round; callers then apply hard gates (F) and the packed cap
    /// (no better than D) on top.
    pub(super) fn from_final_score(final_score: u32) -> Grade {
        match final_score {
            82..=u32::MAX => Grade::A,
            64..=81 => Grade::B,
            42..=63 => Grade::C,
            25..=41 => Grade::D,
            _ => Grade::F,
        }
    }
}

/// Independent, measurable sub-scores for a candidate, each 0..=100. `final_score` is a weighted
/// blend of the others and is what the letter grade is derived from. These exist so the report can
/// show *why* a candidate scored as it did, instead of only a letter.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SubScores {
    /// How specific the signature is (unique in the corpus, dense enough, not hit by the negatives).
    pub uniqueness: u32,
    /// How recompile-stable it is (reloc-safe, operands masked, opcode-dense).
    pub stability: u32,
    /// Byte-distinctiveness of the fixed bytes (Shannon entropy, scaled by fixed-byte count).
    pub entropy: u32,
    /// How much validated semantic content backs it (a code target with a rich, consistent callee).
    pub semantic: u32,
    /// How confidently the resolver will re-resolve it (validated branch/ptr to code scores highest).
    pub resolver_confidence: u32,
    /// Cross-build agreement: callee fingerprint similarity, or byte survival for a direct match.
    pub cross_build: u32,
    /// The weighted blend the grade band is read from.
    pub final_score: u32,
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

impl TargetKind {
    /// The stable lowercase wire name (`code`/`data`/`import`/`unknown`). Both front-ends emit this
    /// in their serialized reports; keeping the mapping here is the single source for that vocabulary.
    #[must_use]
    pub fn wire_str(self) -> &'static str {
        match self {
            TargetKind::Code => "code",
            TargetKind::Data => "data",
            TargetKind::Import => "import",
            TargetKind::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Debug)]
pub enum Diag {
    NoInputs,
    MixedArch,
    PackedInput { label: String, reasons: Vec<String> },
    MissingInImage { label: String },
    FoundInBuild { label: String, rva: u64 },
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
            Diag::FoundInBuild { label, rva } => write!(f, "found in {label} at 0x{rva:X}"),
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
    /// Callee fingerprint similarity to the reference build's target, 0.0..=1.0, when both resolve to
    /// code. `None` for the reference build itself or a non-code/unresolved target.
    pub fingerprint_similarity: Option<f64>,
    /// A freshly generated byte signature unique to THIS build, minted at the relocated address. The
    /// relocation fallbacks (string anchor, encoding, fingerprint) locate the same function in a build
    /// the original AOB no longer matches because the build was recompiled; this is the new AOB the
    /// caller can actually scan for in that build. `None` on the cross-build byte path (the candidate's
    /// own `aob` already matches every build) or when no unique pattern could be minted here.
    pub aob: Option<String>,
}

#[derive(Clone, Debug)]
pub struct SigCandidate {
    pub aob: String,
    pub suffix: Suffix,
    pub grade: Grade,
    /// Backward-compatible 0..=100 confidence; equal to `scores.final_score`.
    pub score: u32,
    pub bytes_len: usize,
    pub fixed: usize,
    pub wildcards: usize,
    pub fixed_ratio: f64,
    pub reloc_safe: bool,
    /// Whether a hard gate forced grade F, and whether the input was packed (which caps the grade at
    /// D). Carried as typed flags so a later re-grade (negative corpus) re-applies the caps without
    /// re-deriving them from the grade or by substring-matching `reasons`.
    pub gated: bool,
    pub packed: bool,
    /// The independent sub-scores the grade was derived from.
    pub scores: SubScores,
    /// Human-readable explanations of why the candidate scored high or low.
    pub reasons: Vec<String>,
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

/// One candidate function in a build that could not be uniquely relocated. Part of a [`Shortlist`].
#[derive(Clone, Debug)]
pub struct ShortlistEntry {
    pub rva: u64,
    /// Structural similarity to the reference function, 0.0..=1.0.
    pub similarity: f64,
    /// A byte signature minted at this candidate in its build, when one could be made.
    pub aob: Option<String>,
}

/// A best-effort list of candidate functions in one build, emitted when a function could not be
/// confidently relocated (no byte/string/import/encoding anchor pinned it uniquely) but a family of
/// structurally near-equal functions exists. The caller disambiguates manually or at runtime; this is
/// never a confident result, only a starting point for a degenerate, anchor-less target.
#[derive(Clone, Debug)]
pub struct Shortlist {
    pub label: String,
    pub entries: Vec<ShortlistEntry>,
}

/// One contiguous run of builds a single byte signature stays valid across, before a recompile moves
/// the bytes and a fresh signature has to be minted for the next run. Reporting these ranges is how a
/// relocated signature answers "which versions does this AOB work for, and where does it break".
#[derive(Clone, Debug)]
pub struct AobRange {
    /// The byte signature that matches every build in this run at the function's relocated address.
    pub aob: String,
    /// The build whose bytes this signature was minted from (the first of the run).
    pub minted_in: String,
    /// First and last build labels of the run, for a compact "v83..v88" presentation.
    pub first_label: String,
    pub last_label: String,
    /// Every build in the run, in order.
    pub labels: Vec<String>,
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
    /// Per-build candidate shortlists, populated only when no confident signature could be produced
    /// and the target looks like one of a family of structural near-duplicates.
    pub shortlists: Vec<Shortlist>,
    /// For a relocated signature whose bytes do not survive every build unchanged, the contiguous
    /// version runs each minted AOB covers (so the report can say "works v83..v88, then this AOB for
    /// v91..v95"). Empty when the chosen signature is a single cross-build byte pattern or nothing was
    /// chosen.
    pub aob_ranges: Vec<AobRange>,
    pub diagnostics: Vec<Diag>,
}
