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
