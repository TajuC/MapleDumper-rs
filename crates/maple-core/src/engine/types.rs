use crate::domain::{FindingStatus, ResolveTrace};
use crate::output::Finding;

pub struct PatternRow {
    pub name: String,
    pub category: String,
    pub pattern: String,
    pub value: Option<u64>,
    pub is_offset: bool,
    pub matches: usize,
    pub status: FindingStatus,
    pub note: String,
    pub candidates: Vec<u64>,
    pub confidence: u8,
    /// One-line human-readable trace, derived from `trace_detail` when present.
    pub trace: Option<String>,
    /// The structured, serializable resolution trace (instruction offset, operand, target, checks,
    /// failure reason). `None` for a pattern that never matched.
    pub trace_detail: Option<ResolveTrace>,
}

/// A region window whose read returned fewer bytes than asked for, i.e. part of it was unreadable
/// (a decommitted or guard page, a racing unmap). Tracked so a "not found" over a partial region is
/// reported as inconclusive rather than as a confident absence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct ReadGap {
    pub base: usize,
    pub requested: usize,
    pub got: usize,
}

pub struct ScanResult {
    pub findings: Vec<Finding>,
    pub rows: Vec<PatternRow>,
    pub found: Vec<String>,
    pub matched_unresolved: Vec<String>,
    pub not_found: Vec<String>,
    pub total_matches: usize,
    /// Region windows that read short, so partial coverage is visible instead of silent.
    pub read_gaps: Vec<ReadGap>,
    /// Non-fatal advisories raised during the scan (partial reads, `@hits` expectation violations).
    pub warnings: Vec<String>,
}

impl ScanResult {
    /// Total bytes that were requested but could not be read across all region windows.
    #[must_use]
    pub fn unread_bytes(&self) -> u64 {
        self.read_gaps
            .iter()
            .map(|g| (g.requested - g.got) as u64)
            .sum()
    }
}

/// The standard advisory for region windows that read short, shared so the byte scan, the assembly
/// scan, and both front-ends word a partial-read warning identically. `None` when there were no gaps.
#[must_use]
pub fn read_gap_warning(read_gaps: &[ReadGap]) -> Option<String> {
    if read_gaps.is_empty() {
        return None;
    }
    let unread: usize = read_gaps.iter().map(|g| g.requested - g.got).sum();
    Some(format!(
        "partial reads: {} region window(s) returned short, {unread} byte(s) unreadable; a \
         \"not found\" result may be in unread memory",
        read_gaps.len()
    ))
}
