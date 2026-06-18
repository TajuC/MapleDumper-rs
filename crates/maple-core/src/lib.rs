//! MapleDumper engine.
//!
//! The modules below are public and the flat re-exports at the bottom of this file are the engine's
//! intended API, consumed by the `maple-cli` and `maple-app` front-ends in this workspace. The
//! surface is deliberately wide for those first-party consumers rather than a minimal external SDK;
//! treat additions as semver-relevant for the workspace, not for outside crates.

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub mod asmscan;
pub mod categorizer;
pub mod diff;
pub mod domain;
pub mod engine;
pub mod fileimage;
pub mod health;
pub mod live;
pub mod memory;
pub mod output;
pub mod pattern;
pub mod resolver;
pub mod scanner;
pub mod sigmaker;
pub mod stamp;
pub mod unpack;

#[cfg(windows)]
pub mod process;

pub use asmscan::{AsmHit, AsmPattern, AsmScanResult, assembly_scan, parse_asm_patterns};
pub use diff::{DiffReport, Moved, diff, parse_dump};
pub use domain::{
    ExpectedHits, FailureReason, FindingStatus, ResolvePlan, ResolveTrace, ResolverSpec,
    SectionKind, checked_rva,
};
pub use engine::{
    PatternRow, ProfileReport, ReadGap, ScanResult, profile, read_gap_warning, scan, scan_in,
};
pub use fileimage::{FileImage, PackReport, RelocKind};
pub use health::{Lint, lint};
pub use live::{apply_string_anchors, scan_live};
pub use memory::{MemorySource, Region};
pub use output::Finding;
pub use pattern::{Arch, Pattern, Signature, arch_mismatch};
pub use pattern::{signature_from_aob, try_signature_from_aob};
pub use resolver::{Kind, ResolveDetail, ResolveFail, ResolveOp, resolve_op};
pub use scanner::{CompiledPattern, find_all};
pub use sigmaker::{
    BuildProfile, CrossReport, Diag, DisasmLine, DupGroup, FnIdentity, FunctionInsight, Grade,
    HoldoutResult, ImageInput, InputInfo, NegativeEvidence, NegativeHit, PerVersion,
    RelocationLedger, SigCandidate, SigOptions, SigReport, SigStage, StringAnchor, SubScores,
    Suffix, TargetKind, TargetSpec, VtableInsight, apply_negative_corpus, apply_negatives,
    best_fingerprint_match, fn_identity, generate, generate_cross, generate_cross_with_progress,
    generate_with_progress, holdout_validate, inspect_function, make_string_anchor,
    negative_corpus_hits, resolve_string_anchor, xref_count,
};
pub use stamp::{BuildStamp, parse_stamp, pe_machine};
pub use unpack::{
    CleanOptions, CleanSummary, Cleaned, Progress, Stage, UnpackReport, VerifyReport, clean_bytes,
    clean_to_path, locate_unlicense, unpack_to_path, verify_bytes,
};

#[cfg(windows)]
pub use process::{AttachOptions, Locator, Target};
