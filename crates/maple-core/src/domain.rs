//! Typed vocabulary for the scan and resolve pipeline. These types are the target the engine,
//! resolver and signature maker migrate onto so behavior stops being driven by thin enums and
//! string suffixes. They are introduced here and wired in across later phases.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SectionKind {
    Code,
    Data,
    ReadOnly,
    Import,
    Unknown,
}

impl SectionKind {
    /// Parse a section keyword used in a pattern schema (`code`, `data`, `rodata`, `import`).
    #[must_use]
    pub fn from_keyword(s: &str) -> Option<SectionKind> {
        match s.trim().to_ascii_lowercase().as_str() {
            "code" | "text" | ".text" => Some(SectionKind::Code),
            "data" | ".data" => Some(SectionKind::Data),
            "rodata" | "readonly" | ".rdata" | ".rodata" => Some(SectionKind::ReadOnly),
            "import" | "iat" => Some(SectionKind::Import),
            _ => None,
        }
    }
}

/// Why a pattern did not produce a trustworthy result. Replaces the old habit of collapsing every
/// failure into "not found" or a wrapped numeric RVA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FailureReason {
    Unresolved,
    OutOfModule,
    OutOfExpectedSection,
    SignatureTooWeak,
    SignatureMalformed,
    PartialRead,
    AccessDenied,
    ModuleNotLoaded,
    ArchMismatch,
    NoReadableRegions,
}

impl FailureReason {
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            FailureReason::Unresolved => "unresolved",
            FailureReason::OutOfModule => "out of module",
            FailureReason::OutOfExpectedSection => "out of expected section",
            FailureReason::SignatureTooWeak => "signature too weak",
            FailureReason::SignatureMalformed => "signature malformed",
            FailureReason::PartialRead => "partial read",
            FailureReason::AccessDenied => "access denied",
            FailureReason::ModuleNotLoaded => "module not loaded",
            FailureReason::ArchMismatch => "architecture mismatch",
            FailureReason::NoReadableRegions => "no readable regions",
        }
    }
}

/// Outcome of resolving one pattern, with ambiguity and failure made explicit so the UI and the
/// exporters can tell a unique hit apart from a guess.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FindingStatus {
    FoundUnique,
    FoundAmbiguous { candidates: usize },
    NotFound,
    Failed(FailureReason),
}

impl FindingStatus {
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            FindingStatus::FoundUnique => "found",
            FindingStatus::FoundAmbiguous { .. } => "found (ambiguous)",
            FindingStatus::NotFound => "not found",
            FindingStatus::Failed(reason) => reason.label(),
        }
    }

    /// True for any resolved match, including an ambiguous one. This is deliberately broad, for
    /// reporting and metrics; it is not export-safe, so use [`FindingStatus::is_exportable`] before
    /// emitting a value as an offset.
    #[must_use]
    pub fn is_found(&self) -> bool {
        matches!(
            self,
            FindingStatus::FoundUnique | FindingStatus::FoundAmbiguous { .. }
        )
    }

    /// True only for a single, unambiguous match.
    #[must_use]
    pub fn is_unique_found(&self) -> bool {
        matches!(self, FindingStatus::FoundUnique)
    }

    /// Whether this result is safe to emit as a normal offset. Only a unique match qualifies; an
    /// ambiguous match is shown for inspection but never exported.
    #[must_use]
    pub fn is_exportable(&self) -> bool {
        self.is_unique_found()
    }
}

/// Module-relative address of `addr` within `[base, base + size)`. Unlike a raw `wrapping_sub`, an
/// address before the module or past its end is rejected instead of wrapping into a plausible-looking
/// huge RVA that then flows into a header or table.
///
/// Passing `size == 0` skips only the upper-bound check, for callers that genuinely do not know the
/// module size yet; the lower-bound (before-base) check still applies. Do not use the `size == 0`
/// form on any path that can reach an exporter: an export must validate against the real module size
/// so an out-of-section or past-end address cannot become an offset.
///
/// # Errors
/// Returns [`FailureReason::OutOfModule`] when `addr < base`, or when `size != 0` and `addr` lands at
/// or past `base + size`.
pub fn checked_rva(addr: usize, base: usize, size: usize) -> Result<u64, FailureReason> {
    let rva = addr.checked_sub(base).ok_or(FailureReason::OutOfModule)?;
    if size != 0 && rva >= size {
        return Err(FailureReason::OutOfModule);
    }
    Ok(rva as u64)
}

/// How a matched site turns into a reported value. Today this is derived from a pattern's name
/// suffix via [`crate::resolver::Kind::spec`], but an explicit pattern schema sets it directly, so
/// behavior is driven by a typed value rather than a string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolverSpec {
    MatchAddress,
    MemoryPointer,
    StructOffset,
    Immediate,
    NestedCall,
}

impl ResolverSpec {
    /// Parse a resolver-kind keyword used in a pattern schema.
    #[must_use]
    pub fn from_keyword(s: &str) -> Option<ResolverSpec> {
        match s.trim().to_ascii_lowercase().as_str() {
            "direct" | "addr" | "address" | "match" => Some(ResolverSpec::MatchAddress),
            "ptr" | "pointer" => Some(ResolverSpec::MemoryPointer),
            "off" | "offset" => Some(ResolverSpec::StructOffset),
            "hdr" | "header" | "imm" | "immediate" => Some(ResolverSpec::Immediate),
            "call" => Some(ResolverSpec::NestedCall),
            _ => None,
        }
    }
}

/// How many matches a pattern is expected to produce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpectedHits {
    Any,
    Unique,
    AtLeast(usize),
}

impl ExpectedHits {
    /// Parse an expected-hits keyword: `any`, `unique`, or a count (`>=N`, `atleast:N`, or `N`).
    #[must_use]
    pub fn from_keyword(s: &str) -> Option<ExpectedHits> {
        let s = s.trim().to_ascii_lowercase();
        match s.as_str() {
            "any" => Some(ExpectedHits::Any),
            "unique" | "1" => Some(ExpectedHits::Unique),
            other => {
                let n = other
                    .strip_prefix(">=")
                    .or_else(|| other.strip_prefix("atleast:"))
                    .unwrap_or(other);
                n.parse::<usize>().ok().map(ExpectedHits::AtLeast)
            }
        }
    }

    /// Whether `count` matches satisfy this expectation.
    #[must_use]
    pub fn satisfied_by(self, count: usize) -> bool {
        match self {
            ExpectedHits::Any => true,
            ExpectedHits::Unique => count == 1,
            ExpectedHits::AtLeast(n) => count >= n,
        }
    }
}

/// The explicit, typed resolution plan for a pattern. Built from a pattern schema, this replaces
/// deriving behavior from the name suffix: `kind` selects the resolver and the rest refine where
/// and how the target is read and validated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvePlan {
    pub kind: ResolverSpec,
    pub instruction_offset: usize,
    pub operand_index: Option<usize>,
    pub expected_section: Option<SectionKind>,
    pub expected_hits: ExpectedHits,
}

impl ResolvePlan {
    /// A plan that selects a resolver kind with default refinements.
    #[must_use]
    pub fn new(kind: ResolverSpec) -> Self {
        Self {
            kind,
            instruction_offset: 0,
            operand_index: None,
            expected_section: None,
            expected_hits: ExpectedHits::Any,
        }
    }
}

/// A target located by the read-only strings a function references rather than by its bytes, so it
/// survives a recompile that shifts the surrounding code. A second string pins down a function whose
/// strings are each shared with others: the target is the one referencing both.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StringAnchor {
    pub text: String,
    pub also: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_rva_accepts_in_range() {
        assert_eq!(checked_rva(0x1040, 0x1000, 0x1000), Ok(0x40));
        assert_eq!(checked_rva(0x1000, 0x1000, 0x1000), Ok(0));
    }

    #[test]
    fn checked_rva_rejects_below_base() {
        assert_eq!(
            checked_rva(0x0FFF, 0x1000, 0x1000),
            Err(FailureReason::OutOfModule)
        );
    }

    #[test]
    fn checked_rva_rejects_past_end() {
        assert_eq!(
            checked_rva(0x2000, 0x1000, 0x1000),
            Err(FailureReason::OutOfModule)
        );
        assert_eq!(checked_rva(0x1FFF, 0x1000, 0x1000), Ok(0xFFF));
    }

    #[test]
    fn checked_rva_unbounded_when_size_zero() {
        assert_eq!(checked_rva(0x9000, 0x1000, 0), Ok(0x8000));
    }

    #[test]
    fn only_unique_is_exportable() {
        assert!(FindingStatus::FoundUnique.is_exportable());
        assert!(FindingStatus::FoundUnique.is_unique_found());
        let ambiguous = FindingStatus::FoundAmbiguous { candidates: 2 };
        assert!(!ambiguous.is_exportable());
        assert!(!ambiguous.is_unique_found());
        assert!(ambiguous.is_found()); // still "found" for reporting, just not exportable
        assert!(!FindingStatus::NotFound.is_exportable());
        assert!(!FindingStatus::Failed(FailureReason::OutOfModule).is_exportable());
    }

    #[test]
    fn status_labels_are_stable() {
        assert_eq!(FindingStatus::FoundUnique.label(), "found");
        assert_eq!(
            FindingStatus::FoundAmbiguous { candidates: 3 }.label(),
            "found (ambiguous)"
        );
        assert!(FindingStatus::FoundAmbiguous { candidates: 2 }.is_found());
        assert!(!FindingStatus::Failed(FailureReason::AccessDenied).is_found());
        assert_eq!(
            FindingStatus::Failed(FailureReason::OutOfModule).label(),
            "out of module"
        );
    }
}
