pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub mod asmscan;
pub mod categorizer;
pub mod diff;
pub mod domain;
pub mod engine;
pub mod fileimage;
pub mod health;
pub mod memory;
pub mod output;
pub mod pattern;
pub mod resolver;
pub mod scanner;
pub mod sigmaker;
pub mod stamp;

#[cfg(windows)]
pub mod process;

pub use asmscan::{AsmHit, AsmPattern, assembly_scan, parse_asm_patterns};
pub use diff::{DiffReport, Moved, diff, parse_dump};
pub use domain::{
    ExpectedHits, FailureReason, FindingStatus, ResolvePlan, ResolveTrace, ResolverSpec,
    SectionKind, checked_rva,
};
pub use engine::{
    PatternRow, ProfileReport, ScanResult, apply_string_anchors, profile, scan, scan_in,
};
pub use fileimage::{FileImage, PackReport, RelocKind};
pub use health::{Lint, lint};
pub use memory::{MemorySource, Region};
pub use output::Finding;
pub use pattern::{Arch, Pattern, Signature};
pub use pattern::{signature_from_aob, try_signature_from_aob};
pub use resolver::{Kind, ResolveDetail, ResolveFail, ResolveOp, resolve_op};
pub use scanner::{CompiledPattern, find_all};
pub use sigmaker::{
    BuildProfile, CrossReport, Diag, DupGroup, FnIdentity, Grade, HoldoutResult, ImageInput,
    InputInfo, NegativeEvidence, NegativeHit, PerVersion, SigCandidate, SigOptions, SigReport,
    SigStage, StringAnchor, SubScores, Suffix, TargetKind, TargetSpec, apply_negative_corpus,
    fn_identity, generate, generate_cross, generate_cross_with_progress, generate_with_progress,
    holdout_validate, make_string_anchor, negative_corpus_hits, resolve_string_anchor, xref_count,
};
pub use stamp::{BuildStamp, parse_stamp, pe_machine};

#[cfg(windows)]
pub use process::{AttachOptions, Locator, Target};
