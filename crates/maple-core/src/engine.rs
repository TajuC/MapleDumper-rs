use crate::domain::{
    ExpectedHits, FailureReason, FindingStatus, ResolveTrace, SectionKind, checked_rva,
};
use crate::memory::{MemorySource, Region};
use crate::output::Finding;
use crate::pattern::{Arch, Pattern};
use crate::resolver::{self, Kind, ResolveDetail, ResolveFail, ResolveOp, ResolverSpec};
use crate::scanner::{self, CompiledPattern, ScannerIndex};
use crate::sigmaker::{ImageInput, resolve_string_anchor};
use rayon::prelude::*;
use std::hint::black_box;
use std::time::Instant;

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

// A 0-100 trust score for a row's resolved value, separate from uniqueness: matches that all resolve
// to the same target stay high even when the byte signature is not unique, while genuinely conflicting
// targets drop in proportion to how many distinct ones there are.
fn confidence_of(status: &FindingStatus, candidates: &[u64]) -> u8 {
    match status {
        FindingStatus::FoundUnique => 100,
        FindingStatus::FoundAmbiguous { .. } => {
            let mut distinct = candidates.to_vec();
            distinct.sort_unstable();
            distinct.dedup();
            let n = u32::try_from(distinct.len().max(1)).unwrap_or(u32::MAX);
            u8::try_from((100 / n).min(100)).unwrap_or(0)
        }
        FindingStatus::NotFound | FindingStatus::Failed(_) => 0,
    }
}

/// A region window whose read returned fewer bytes than asked for, i.e. part of it was unreadable
/// (a decommitted or guard page, a racing unmap). Tracked so a "not found" over a partial region is
/// reported as inconclusive rather than as a confident absence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

// One resolved value plus the section signal. `is_code` is the coarse section verdict for an address
// target (Some(true) in an executable region, Some(false) elsewhere in the module, None when no
// section info was supplied or the value is an offset/immediate, not an address). `target_address`
// is the absolute target for an address resolver, used to build the diagnostic trace.
#[derive(Clone, Copy)]
struct ResolvedValue {
    value: u64,
    is_offset: bool,
    is_code: Option<bool>,
    target_address: Option<usize>,
}

struct Hit {
    pattern_idx: usize,
    addr: usize,
    // The instruction-level facts behind the outcome, present whenever decoding succeeded (including
    // when a later range/section check then failed), so a failure trace can still be explanatory.
    detail: Option<ResolveDetail>,
    outcome: Result<ResolvedValue, FailureReason>,
}

// Extra bytes read past a chunk's accept window so a pattern starting near the end still
// matches in full and the resolver has enough trailing bytes to decode.
const RESOLVE_MARGIN: usize = 24;
// Accept-window size per parallel work unit. Smaller windows load-balance better across cores;
// profiling a 143 MB module on 16 cores put the knee at 256 KiB (~6x faster than the old 4 MiB).
const SCAN_CHUNK: usize = 1 << 18;
// Above this many patterns the per-pattern AVX2 scan (one buffer pass per pattern) is replaced by a
// single-pass multi-pattern index, so cost grows with the buffer plus matches, not buffer times
// pattern count. The crossover is benchmark-driven (examples/scan_matrix.rs): on an 8 MiB code-like
// buffer the index is roughly break-even at 10 patterns and 2x to 14x faster by 50, so 32 keeps the
// well-tested AVX2 path for small sets while switching early enough to win on large ones.
const MULTI_PATTERN_THRESHOLD: usize = 32;

pub(crate) fn read_range<S: MemorySource>(source: &S, base: usize, len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    let read = source.read_into(base, &mut buf).unwrap_or(0);
    buf.truncate(read);
    buf
}

// A streamed block: base address, accept-window length, and the accept+overlap bytes read.
type Block = (usize, usize, Vec<u8>);

// Whether `addr` lands in an executable region. `None` when no executable regions were supplied,
// so the caller cannot validate a section and must not invent a verdict.
fn target_is_code(addr: usize, code_regions: &[Region]) -> Option<bool> {
    if code_regions.is_empty() {
        return None;
    }
    Some(
        code_regions
            .iter()
            .any(|r| addr >= r.base && addr < r.end()),
    )
}

// A short stable hash of a pattern's AOB, so a trace can be tied to the exact signature without
// embedding the whole byte string. FNV-1a, matching the project's other lightweight digests.
fn pattern_hash(aob: &str) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in aob.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{h:016X}")
}

// Build the structured resolution trace from the pieces the aggregation has on hand. On success
// `resolved` is set; on a decode/range/section failure `failure` is set and `detail` may still carry
// what was decoded before the check failed.
#[allow(clippy::too_many_arguments)]
fn build_trace(
    name: &str,
    aob: &str,
    resolver_label: &str,
    match_addr: usize,
    module_base: usize,
    module_size: usize,
    detail: Option<&ResolveDetail>,
    resolved: Option<&ResolvedValue>,
    failure: Option<&FailureReason>,
) -> ResolveTrace {
    let mut checks = Vec::new();
    let (target_address, target_rva, target_section) = match resolved {
        // An address result: the value is the RVA and the section verdict applies.
        Some(r) if !r.is_offset => {
            checks.push("target in module".to_string());
            let section = match r.is_code {
                Some(true) => {
                    checks.push("section: code".to_string());
                    Some("code".to_string())
                }
                Some(false) => {
                    checks.push("section: non-code".to_string());
                    Some("non-code".to_string())
                }
                None => None,
            };
            (r.target_address.map(|t| t as u64), Some(r.value), section)
        }
        // An offset/immediate result: the value is carried in `raw`, not an RVA.
        Some(_) => (None, None, None),
        None => (None, None, None),
    };
    ResolveTrace {
        pattern: name.to_string(),
        pattern_hash: pattern_hash(aob),
        resolver: resolver_label.to_string(),
        match_address: match_addr as u64,
        match_rva: checked_rva(match_addr, module_base, module_size).ok(),
        instruction_offset: detail.map_or(0, |d| d.instruction_offset),
        operand_index: detail.and_then(|d| d.operand_index),
        mnemonic: detail.and_then(|d| d.mnemonic.clone()),
        operand_kind: detail.and_then(|d| d.operand_kind.clone()),
        raw: detail.and_then(|d| d.raw),
        target_address,
        target_rva,
        target_section,
        checks,
        failure: failure.map(|f| f.label().to_string()),
    }
}

// Map a typed-resolver failure onto the pattern-result vocabulary. A truncated/failed deref is a
// real partial read; the decode/operand failures are a plain unresolved.
fn fail_reason(f: ResolveFail) -> FailureReason {
    match f {
        ResolveFail::PartialRead => FailureReason::PartialRead,
        ResolveFail::Decode | ResolveFail::WrongMnemonic | ResolveFail::WrongOperand => {
            FailureReason::Unresolved
        }
    }
}

// Turn a match count into a status and an optional advisory, honoring the pattern's `@hits`
// expectation. A single satisfying match is the only exportable outcome; everything else is shown
// for inspection but never written as an offset. `unique` warns when the match is not unique;
// `>=N` warns when fewer than N matched; `any` (the default) is silent about multiplicity.
fn hits_status(expected: ExpectedHits, count: usize) -> (FindingStatus, Option<String>) {
    let status = if count == 1 && expected.satisfied_by(count) {
        FindingStatus::FoundUnique
    } else {
        FindingStatus::FoundAmbiguous { candidates: count }
    };
    let warning = match expected {
        ExpectedHits::Unique if count != 1 => {
            Some(format!("expected a unique match but found {count}"))
        }
        ExpectedHits::AtLeast(n) if count < n => {
            Some(format!("expected at least {n} matches but found {count}"))
        }
        _ => None,
    };
    (status, warning)
}

#[allow(clippy::too_many_arguments)]
fn resolve<S: MemorySource>(
    spec: ResolverSpec,
    expected_section: Option<SectionKind>,
    instruction_offset: usize,
    operand_index: Option<usize>,
    source: &S,
    module_base: usize,
    module_size: usize,
    code_regions: &[Region],
    addr: usize,
    bytes: &[u8],
    arch: Arch,
) -> (Option<ResolveDetail>, Result<ResolvedValue, FailureReason>) {
    // Lower the coarse kind plus the schema's explicit refinements onto a granular, decode-driven op,
    // then execute it. The op honors `@instr` / `@operand`; the legacy suffix patterns lower to the
    // same behavior they always had.
    let op = ResolveOp::from_spec(spec, instruction_offset, operand_index);
    let detail = match resolver::resolve_op(&op, bytes, addr, arch, source) {
        Ok(detail) => detail,
        Err(f) => return (None, Err(fail_reason(f))),
    };

    if detail.is_address {
        // An address target is range-checked into an RVA, then classified against the executable
        // regions and held to its expected section. The section check only fires when the caller
        // supplied executable regions (so a verdict exists) and the pattern declared an expectation,
        // so an ordinary pattern with no `@section` is unaffected. The detail is returned even on a
        // validation failure, so the trace can still explain what was decoded.
        let target = detail.target.unwrap_or(addr);
        let rva = match checked_rva(target, module_base, module_size) {
            Ok(rva) => rva,
            Err(e) => return (Some(detail), Err(e)),
        };
        let is_code = target_is_code(target, code_regions);
        if let (Some(expected), Some(code)) = (expected_section, is_code)
            && !expected.accepts_code_flag(code)
        {
            return (Some(detail), Err(FailureReason::OutOfExpectedSection));
        }
        (
            Some(detail),
            Ok(ResolvedValue {
                value: rva,
                is_offset: false,
                is_code,
                target_address: Some(target),
            }),
        )
    } else {
        let value = detail.value.unwrap_or(0);
        (
            Some(detail),
            Ok(ResolvedValue {
                value,
                is_offset: true,
                is_code: None,
                target_address: None,
            }),
        )
    }
}

/// Scan `regions` for `patterns` and resolve each match, with no section validation. Equivalent to
/// [`scan_in`] with an empty executable-region set: a pattern's `@section` expectation cannot be
/// checked because no section signal is supplied. Use [`scan_in`] on the live paths that have the
/// module's executable regions.
pub fn scan<S>(
    source: &S,
    module_base: usize,
    module_size: usize,
    regions: &[Region],
    patterns: &[Pattern],
    arch: Arch,
) -> ScanResult
where
    S: MemorySource + Sync,
{
    scan_in(
        source,
        module_base,
        module_size,
        regions,
        &[],
        patterns,
        arch,
    )
}

/// Scan and resolve like [`scan`], additionally validating each resolved address target against its
/// pattern's expected section. `code_regions` is the module's executable region set (a subset of the
/// module, regardless of which regions are being scanned); a target inside one counts as code, a
/// target elsewhere in the module as non-code. A pattern with `@section=code` whose target lands
/// outside `code_regions` is reported `Failed(OutOfExpectedSection)` rather than as a clean find.
/// Passing an empty `code_regions` disables the check, matching [`scan`].
pub fn scan_in<S>(
    source: &S,
    module_base: usize,
    module_size: usize,
    regions: &[Region],
    code_regions: &[Region],
    patterns: &[Pattern],
    arch: Arch,
) -> ScanResult
where
    S: MemorySource + Sync,
{
    scan_chunked(
        source,
        module_base,
        module_size,
        regions,
        code_regions,
        patterns,
        arch,
        SCAN_CHUNK,
    )
}

#[allow(clippy::too_many_arguments)]
fn scan_chunked<S>(
    source: &S,
    module_base: usize,
    module_size: usize,
    regions: &[Region],
    code_regions: &[Region],
    patterns: &[Pattern],
    arch: Arch,
    chunk: usize,
) -> ScanResult
where
    S: MemorySource + Sync,
{
    let compiled = compile_patterns(patterns);

    let max_len = compiled
        .iter()
        .filter_map(|c| c.cp.as_ref().map(CompiledPattern::len))
        .max()
        .unwrap_or(1);
    let overlap = max_len.max(RESOLVE_MARGIN);
    let block = chunk.max(1);

    // Above a pattern-count threshold, scan each block once with a multi-pattern index instead of
    // once per pattern; below it the tuned per-pattern AVX2 path is kept.
    let index = (patterns.len() >= MULTI_PATTERN_THRESHOLD).then(|| {
        ScannerIndex::build(
            compiled
                .iter()
                .enumerate()
                .filter_map(|(i, c)| c.cp.as_ref().map(|cp| (i, cp))),
        )
    });

    // A few reader threads stream region windows into the channel while the rayon pool scans them.
    // Each hit is kept only by the window covering its start, so a match straddling a boundary is
    // counted once no matter which reader produced it or in what order blocks arrive.
    let mut units: Vec<(usize, usize, usize)> = Vec::new();
    for region in regions {
        let mut off = 0;
        while off < region.size {
            let accept = block.min(region.size - off);
            let read_len = (accept + overlap).min(region.size - off);
            units.push((region.base + off, accept, read_len));
            off += accept;
        }
    }
    let units = &units;
    let readers = std::thread::available_parallelism()
        .map_or(1, |n| n.get())
        .clamp(1, 4);

    // A reader that gets back fewer bytes than it asked for has hit an unreadable hole; record the
    // gap so partial coverage is reported instead of silently dropped.
    let read_gaps_lock = std::sync::Mutex::new(Vec::<ReadGap>::new());
    let read_gaps_ref = &read_gaps_lock;

    let hits: Vec<Hit> = std::thread::scope(|scope| {
        let (tx, rx) = std::sync::mpsc::sync_channel::<Block>(readers * 2 + 4);
        for w in 0..readers {
            let tx = tx.clone();
            scope.spawn(move || {
                let mut i = w;
                while i < units.len() {
                    let (base, accept, read_len) = units[i];
                    let buf = read_range(source, base, read_len);
                    if buf.len() < read_len
                        && let Ok(mut gaps) = read_gaps_ref.lock()
                    {
                        gaps.push(ReadGap {
                            base,
                            requested: read_len,
                            got: buf.len(),
                        });
                    }
                    if tx.send((base, accept, buf)).is_err() {
                        return;
                    }
                    i += readers;
                }
            });
        }
        drop(tx);
        rx.into_iter()
            .par_bridge()
            .flat_map_iter(|(base, accept_len, buf)| {
                let mut local = Vec::new();
                if let Some(index) = index.as_ref() {
                    index.scan(&buf, accept_len, |idx, off| {
                        let addr = base + off;
                        let pat = &compiled[idx];
                        let (detail, outcome) = resolve(
                            pat.spec,
                            pat.expected_section,
                            pat.instruction_offset,
                            pat.operand_index,
                            source,
                            module_base,
                            module_size,
                            code_regions,
                            addr,
                            &buf[off..],
                            arch,
                        );
                        local.push(Hit {
                            pattern_idx: idx,
                            addr,
                            detail,
                            outcome,
                        });
                    });
                } else {
                    for (idx, pat) in compiled.iter().enumerate() {
                        let Some(cp) = pat.cp.as_ref() else { continue };
                        if buf.len() < cp.len() {
                            continue;
                        }
                        for off in scanner::find_all(&buf, cp) {
                            if off >= accept_len {
                                continue;
                            }
                            let addr = base + off;
                            let (detail, outcome) = resolve(
                                pat.spec,
                                pat.expected_section,
                                pat.instruction_offset,
                                pat.operand_index,
                                source,
                                module_base,
                                module_size,
                                code_regions,
                                addr,
                                &buf[off..],
                                arch,
                            );
                            local.push(Hit {
                                pattern_idx: idx,
                                addr,
                                detail,
                                outcome,
                            });
                        }
                    }
                }
                local
            })
            .collect()
    });

    let mut read_gaps = read_gaps_lock
        .into_inner()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    read_gaps.sort_by_key(|g| g.base);

    let total_matches = hits.len();
    let mut by_pattern: Vec<Vec<&Hit>> = vec![Vec::new(); patterns.len()];
    for hit in &hits {
        by_pattern[hit.pattern_idx].push(hit);
    }

    let mut findings = Vec::new();
    let mut rows = Vec::new();
    let mut found = Vec::new();
    let mut matched_unresolved = Vec::new();
    let mut not_found = Vec::new();
    let mut warnings = Vec::new();

    for (idx, pattern) in patterns.iter().enumerate() {
        let base = pattern.base.as_str();
        let category = pattern.category.clone();
        let aob = pattern.signature.to_aob();
        let note = pattern.note.clone().unwrap_or_default();
        let group = &mut by_pattern[idx];
        let match_count = group.len();

        if group.is_empty() {
            not_found.push(pattern.name.clone());
            rows.push(PatternRow {
                name: base.to_string(),
                category,
                pattern: aob,
                value: None,
                is_offset: false,
                matches: 0,
                status: FindingStatus::NotFound,
                note,
                candidates: Vec::new(),
                confidence: 0,
                trace: None,
                trace_detail: None,
            });
            continue;
        }

        // The precise resolver op (granular label) this pattern lowered to, for the trace.
        let op_label = ResolveOp::from_spec(
            compiled[idx].spec,
            compiled[idx].instruction_offset,
            compiled[idx].operand_index,
        )
        .label();

        group.sort_by_key(|h| h.addr);
        if let Some(hit) = group.iter().find(|h| h.outcome.is_ok()) {
            let resolved = hit.outcome.as_ref().ok().copied().expect("outcome is ok");
            let value = resolved.value;
            let is_offset = resolved.is_offset;
            found.push(pattern.name.clone());
            // How many matches the pattern is expected to produce, honoring an explicit `@hits`; with
            // no schema it defaults to `Any`, preserving the legacy "more than one match is ambiguous".
            let expected_hits = pattern
                .resolve
                .as_ref()
                .map_or(ExpectedHits::Any, |plan| plan.expected_hits);
            let (status, hits_warning) = hits_status(expected_hits, match_count);
            if let Some(w) = hits_warning {
                warnings.push(format!("{}: {w}", pattern.name));
            }
            // Only an unambiguous, satisfied match is exported as a normal offset. Anything else is
            // shown for inspection but kept out of findings, so it cannot silently become an entry in
            // offsets.h or a Cheat Engine table.
            if status.is_exportable() {
                findings.push(Finding {
                    name: base.to_string(),
                    category: category.clone(),
                    value,
                    is_offset,
                });
            }
            let candidates: Vec<u64> = group
                .iter()
                .filter_map(|h| h.outcome.as_ref().ok().map(|r| r.value))
                .collect();
            let confidence = confidence_of(&status, &candidates);
            let trace_detail = build_trace(
                base,
                &aob,
                op_label,
                hit.addr,
                module_base,
                module_size,
                hit.detail.as_ref(),
                Some(&resolved),
                None,
            );
            let trace = Some(trace_detail.human());
            rows.push(PatternRow {
                name: base.to_string(),
                category,
                pattern: aob,
                value: Some(value),
                is_offset,
                matches: match_count,
                status,
                note,
                candidates,
                confidence,
                trace,
                trace_detail: Some(trace_detail),
            });
        } else {
            // matched but nothing resolved: prefer a specific reason (a target out of the module, out
            // of its expected section, or a truncated deref) over a bare decode miss, since the
            // specific ones usually mean the signature landed on the wrong instruction.
            let failing = group
                .iter()
                .find(|h| {
                    matches!(
                        h.outcome,
                        Err(FailureReason::OutOfModule
                            | FailureReason::OutOfExpectedSection
                            | FailureReason::PartialRead)
                    )
                })
                .or_else(|| group.first());
            let reason = failing
                .and_then(|h| h.outcome.as_ref().err().cloned())
                .unwrap_or(FailureReason::Unresolved);
            let at = failing.map_or(0, |h| h.addr);
            let detail = failing.and_then(|h| h.detail.as_ref());
            matched_unresolved.push(pattern.name.clone());
            let trace_detail = build_trace(
                base,
                &aob,
                op_label,
                at,
                module_base,
                module_size,
                detail,
                None,
                Some(&reason),
            );
            let trace = Some(trace_detail.human());
            rows.push(PatternRow {
                name: base.to_string(),
                category,
                pattern: aob,
                value: None,
                is_offset: false,
                matches: match_count,
                status: FindingStatus::Failed(reason),
                note,
                candidates: Vec::new(),
                confidence: 0,
                trace,
                trace_detail: Some(trace_detail),
            });
        }
    }

    if !read_gaps.is_empty() {
        let unread: usize = read_gaps.iter().map(|g| g.requested - g.got).sum();
        warnings.push(format!(
            "partial reads: {} region window(s) returned short, {unread} byte(s) unreadable; a \
             \"not found\" result may be in unread memory",
            read_gaps.len()
        ));
    }

    ScanResult {
        findings,
        rows,
        found,
        matched_unresolved,
        not_found,
        total_matches,
        read_gaps,
        warnings,
    }
}

// A pattern compiled for scanning, carrying the resolver kind, expected section, and the explicit
// instruction/operand refinements pulled from its typed plan so resolution reads typed values rather
// than re-parsing the name.
struct CompiledPat {
    spec: ResolverSpec,
    expected_section: Option<SectionKind>,
    instruction_offset: usize,
    operand_index: Option<usize>,
    cp: Option<CompiledPattern>,
}

fn compile_patterns(patterns: &[Pattern]) -> Vec<CompiledPat> {
    patterns
        .iter()
        .map(|p| {
            // An explicit schema sets the resolver kind directly; otherwise it is derived from the
            // name suffix (the legacy form). The expected section, when present, comes only from the
            // explicit schema.
            let spec = p
                .resolve
                .as_ref()
                .map_or_else(|| Kind::classify(&p.name).0.spec(), |plan| plan.kind);
            let expected_section = p.resolve.as_ref().and_then(|plan| plan.expected_section);
            let (instruction_offset, operand_index) =
                p.resolve.as_ref().map_or((0, None), |plan| {
                    (plan.instruction_offset, plan.operand_index)
                });
            CompiledPat {
                spec,
                expected_section,
                instruction_offset,
                operand_index,
                cp: CompiledPattern::new(&p.signature),
            }
        })
        .collect()
}

/// Resolve string-anchored patterns against an image view, live target or file, and fold the results
/// into a [`ScanResult`] from [`scan`]. The byte scan leaves each empty-signature anchored pattern as
/// a placeholder not-found row; this rewrites that row in place by index, so the one-row-per-pattern
/// shape is preserved and a resolved anchor moves from not-found to found.
pub fn apply_string_anchors(result: &mut ScanResult, img: &ImageInput, patterns: &[Pattern]) {
    for (idx, p) in patterns.iter().enumerate() {
        let Some(anchor) = &p.string_anchor else {
            continue;
        };
        let base = p.base.as_str();
        let pattern = match &anchor.also {
            Some(also) => format!("@string={} @also={also}", anchor.text),
            None => format!("@string={}", anchor.text),
        };
        let resolved = resolve_string_anchor(img, anchor);
        if let Some(row) = result.rows.get_mut(idx) {
            row.pattern = pattern;
            if let Some(rva) = resolved {
                row.value = Some(rva as u64);
                row.is_offset = false;
                row.matches = 1;
                row.status = FindingStatus::FoundUnique;
                row.candidates = vec![rva as u64];
                row.confidence = 100;
                row.trace = Some(format!("string anchor resolved to 0x{rva:X}"));
            }
        }
        if let Some(rva) = resolved {
            let category = p.category.clone();
            result.not_found.retain(|n| n != &p.name);
            result.found.push(p.name.clone());
            result.total_matches += 1;
            result.findings.push(Finding {
                name: base.to_string(),
                category,
                value: rva as u64,
                is_offset: false,
            });
        }
    }
}

/// Scan a live target end to end: run the chunked scan over its regions, then apply any string
/// anchors. The CLI and the desktop app both call this, so the live-scan sequence (the scan plus the
/// degenerate `ImageInput` that string-anchor resolution needs) has a single definition and the two
/// front-ends cannot drift on it.
pub fn scan_live<S>(
    source: &S,
    module_base: usize,
    module_size: usize,
    regions: &[Region],
    code_regions: &[Region],
    patterns: &[Pattern],
    arch: Arch,
) -> ScanResult
where
    S: MemorySource + Sync,
{
    let mut result = scan_in(
        source,
        module_base,
        module_size,
        regions,
        code_regions,
        patterns,
        arch,
    );
    if patterns.iter().any(|p| p.string_anchor.is_some()) {
        let img = ImageInput {
            label: String::new(),
            source,
            base: module_base,
            size: module_size,
            code_regions: code_regions.to_vec(),
            regions: regions.to_vec(),
            import: None,
            arch,
            code_hash: 0,
            packed: false,
            pack_reasons: Vec::new(),
            reloc: None,
        };
        apply_string_anchors(&mut result, &img, patterns);
    }
    result
}

#[derive(Clone, Copy)]
struct Probe {
    buf: usize,
    off: usize,
    pat: usize,
}

fn read_sweep<S: MemorySource + Sync>(
    source: &S,
    regions: &[Region],
    block: usize,
    counts: &[usize],
) -> Vec<(usize, u128)> {
    let mut blocks: Vec<(usize, usize)> = Vec::new();
    for region in regions {
        let mut off = 0;
        while off < region.size {
            let len = block.min(region.size - off);
            blocks.push((region.base + off, len));
            off += len;
        }
    }
    let blocks = &blocks;
    counts
        .iter()
        .map(|&readers| {
            let t = Instant::now();
            std::thread::scope(|scope| {
                for w in 0..readers {
                    scope.spawn(move || {
                        let mut i = w;
                        while i < blocks.len() {
                            let (base, len) = blocks[i];
                            black_box(read_range(source, base, len));
                            i += readers;
                        }
                    });
                }
            });
            (readers, t.elapsed().as_millis())
        })
        .collect()
}

fn scan_serial(bufs: &[(usize, Vec<u8>)], compiled: &[CompiledPat]) -> (u128, Vec<Probe>) {
    let mut found = Vec::new();
    let t = Instant::now();
    for (buf, (_, data)) in bufs.iter().enumerate() {
        for (pat, c) in compiled.iter().enumerate() {
            let Some(cp) = c.cp.as_ref() else { continue };
            if data.len() < cp.len() {
                continue;
            }
            for off in scanner::find_all(data, cp) {
                found.push(Probe { buf, off, pat });
            }
        }
    }
    (t.elapsed().as_millis(), found)
}

fn resolve_pass<S: MemorySource>(
    source: &S,
    module_base: usize,
    module_size: usize,
    bufs: &[(usize, Vec<u8>)],
    compiled: &[CompiledPat],
    found: &[Probe],
    arch: Arch,
) -> (u128, usize) {
    let mut call_hits = 0;
    let mut acc = 0u64;
    let t = Instant::now();
    for p in found {
        let pat = &compiled[p.pat];
        if pat.spec == ResolverSpec::NestedCall {
            call_hits += 1;
        }
        let addr = bufs[p.buf].0 + p.off;
        // Section validation is a correctness check, not a timing one; profiling passes no
        // executable regions so the resolve cost it measures matches the real scan path.
        let (_, outcome) = resolve(
            pat.spec,
            pat.expected_section,
            pat.instruction_offset,
            pat.operand_index,
            source,
            module_base,
            module_size,
            &[],
            addr,
            &bufs[p.buf].1[p.off..],
            arch,
        );
        acc = acc.wrapping_add(outcome.map(|r| r.value).unwrap_or(0));
    }
    black_box(acc);
    (t.elapsed().as_millis(), call_hits)
}

fn time_scan<S: MemorySource + Sync>(
    source: &S,
    module_base: usize,
    module_size: usize,
    regions: &[Region],
    patterns: &[Pattern],
    arch: Arch,
    chunk: usize,
) -> u128 {
    let t = Instant::now();
    black_box(scan_chunked(
        source,
        module_base,
        module_size,
        regions,
        &[],
        patterns,
        arch,
        chunk,
    ));
    t.elapsed().as_millis()
}

/// Phase-separated timing of a scan against a live target, so the read / scan / resolve split
/// can be measured instead of guessed. All times are milliseconds. Runs several full reads of
/// the module, so it is a one-off diagnostic, not a hot path.
#[derive(Debug, Clone)]
pub struct ProfileReport {
    pub regions: usize,
    pub bytes: u64,
    pub cores: usize,
    pub patterns: usize,
    pub read_ms: Vec<(usize, u128)>,
    pub scan_serial_ms: u128,
    pub matches: usize,
    pub resolve_ms: u128,
    pub call_hits: usize,
    pub full_ms: u128,
    pub chunk_ms: Vec<(usize, u128)>,
}

#[must_use]
pub fn profile<S>(
    source: &S,
    module_base: usize,
    module_size: usize,
    regions: &[Region],
    patterns: &[Pattern],
    arch: Arch,
) -> ProfileReport
where
    S: MemorySource + Sync,
{
    const BLOCK: usize = 1 << 18;

    let compiled = compile_patterns(patterns);
    let bytes: u64 = regions.iter().map(|r| r.size as u64).sum();
    let cores = std::thread::available_parallelism().map_or(1, |n| n.get());

    let read_ms = read_sweep(source, regions, BLOCK, &[1, 2, 4]);

    let bufs: Vec<(usize, Vec<u8>)> = regions
        .iter()
        .map(|r| (r.base, read_range(source, r.base, r.size)))
        .collect();

    let (scan_serial_ms, found) = scan_serial(&bufs, &compiled);

    let (resolve_ms, call_hits) = resolve_pass(
        source,
        module_base,
        module_size,
        &bufs,
        &compiled,
        &found,
        arch,
    );

    let full_ms = time_scan(
        source,
        module_base,
        module_size,
        regions,
        patterns,
        arch,
        SCAN_CHUNK,
    );

    let chunk_ms = [
        64usize << 10,
        128 << 10,
        256 << 10,
        512 << 10,
        1 << 20,
        2 << 20,
    ]
    .into_iter()
    .map(|size| {
        (
            size,
            time_scan(
                source,
                module_base,
                module_size,
                regions,
                patterns,
                arch,
                size,
            ),
        )
    })
    .collect();

    ProfileReport {
        regions: regions.len(),
        bytes,
        cores,
        patterns: patterns.len(),
        read_ms,
        scan_serial_ms,
        matches: found.len(),
        resolve_ms,
        call_hits,
        full_ms,
        chunk_ms,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::BufferSource;
    use crate::pattern::Arch;
    use crate::pattern::parse_patterns;

    #[test]
    fn scans_and_resolves_against_buffer() {
        let base = 0x1000usize;
        let mut data = vec![0u8; 64];
        data[0x10..0x14].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        data[0x20..0x27].copy_from_slice(&[0x48, 0x8D, 0x0D, 0x09, 0x00, 0x00, 0x00]);
        let source = BufferSource::new(base, data);
        let regions = [Region { base, size: 64 }];
        let patterns = parse_patterns("Foo = DE AD BE EF\nBar_PTR = 48 8D 0D ? ? ? ?", Arch::X64);

        let result = scan(&source, base, 64, &regions, &patterns, Arch::X64);

        let foo = result.findings.iter().find(|f| f.name == "Foo").unwrap();
        assert_eq!(foo.value, 0x10);
        assert!(!foo.is_offset);
        let bar = result.findings.iter().find(|f| f.name == "Bar").unwrap();
        assert_eq!(bar.value, 0x30);
        assert_eq!(result.found.len(), 2);
        assert!(result.not_found.is_empty());
        assert_eq!(result.rows.len(), 2);
        assert!(
            result
                .rows
                .iter()
                .all(|r| r.status == FindingStatus::FoundUnique)
        );
    }

    #[test]
    fn profile_match_count_equals_the_real_scan() {
        // ARCH-4 / PERF-1: the profiler must measure the shipping path, so its match count has to
        // equal what scan() finds for the same input (the divergent scan_parallel micro-bench that
        // counted matches a second, different way is gone).
        let base = 0x1000usize;
        let mut data = vec![0u8; 64];
        data[0x10..0x14].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        data[0x20..0x27].copy_from_slice(&[0x48, 0x8D, 0x0D, 0x09, 0x00, 0x00, 0x00]);
        let source = BufferSource::new(base, data);
        let regions = [Region { base, size: 64 }];
        let patterns = parse_patterns("Foo = DE AD BE EF\nBar_PTR = 48 8D 0D ? ? ? ?", Arch::X64);
        let scanned: usize = scan(&source, base, 64, &regions, &patterns, Arch::X64)
            .rows
            .iter()
            .map(|r| r.matches)
            .sum();
        let profiled = profile(&source, base, 64, &regions, &patterns, Arch::X64).matches;
        assert_eq!(
            profiled, scanned,
            "profiler match count must equal the real scan"
        );
    }

    #[test]
    fn resolves_a_string_anchored_pattern() {
        let base = 0x1000usize;
        let mut mem = vec![0u8; 0x200];
        mem[0x10..0x1B].copy_from_slice(b"MapleStory\0");
        mem[0x100] = 0x68;
        mem[0x101..0x105].copy_from_slice(&0x1010u32.to_le_bytes());
        let source = BufferSource::new(base, mem);
        let img = ImageInput {
            label: String::new(),
            source: &source,
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
        let patterns = parse_patterns("Stat = @string=MapleStory", Arch::X86);
        let regions = [Region { base, size: 0x200 }];
        let mut result = scan(&source, base, 0x200, &regions, &patterns, Arch::X86);
        assert_eq!(result.not_found, vec!["Stat".to_string()]);
        apply_string_anchors(&mut result, &img, &patterns);
        assert_eq!(result.found, vec!["Stat".to_string()]);
        assert!(result.not_found.is_empty());
        assert_eq!(result.rows.len(), 1);
        assert_eq!(result.rows[0].status, FindingStatus::FoundUnique);
        let stat = result.findings.iter().find(|f| f.name == "Stat").unwrap();
        assert_eq!(stat.value, 0x101);
        assert!(!stat.is_offset);
    }

    #[test]
    fn scan_live_matches_scan_in_plus_apply_string_anchors() {
        // ARCH-1 / TEST-4: scan_live is the single live-scan path both front-ends call. It must equal
        // a manual scan_in + apply_string_anchors over the same input (covering both a byte pattern
        // and a string anchor), so the CLI and the app cannot drift on the scan sequence.
        let base = 0x1000usize;
        let mut mem = vec![0u8; 0x200];
        mem[0x10..0x1B].copy_from_slice(b"MapleStory\0");
        mem[0x100] = 0x68;
        mem[0x101..0x105].copy_from_slice(&0x1010u32.to_le_bytes());
        mem[0x150..0x154].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        let source = BufferSource::new(base, mem);
        let regions = vec![
            Region { base, size: 0x100 },
            Region {
                base: base + 0x100,
                size: 0x100,
            },
        ];
        let code_regions = vec![Region {
            base: base + 0x100,
            size: 0x100,
        }];
        let patterns = parse_patterns("Stat = @string=MapleStory\nMark = DE AD BE EF", Arch::X86);

        let mut reference = scan_in(
            &source,
            base,
            0x200,
            &regions,
            &code_regions,
            &patterns,
            Arch::X86,
        );
        let img = ImageInput {
            label: String::new(),
            source: &source,
            base,
            size: 0x200,
            code_regions: code_regions.clone(),
            regions: regions.clone(),
            import: None,
            arch: Arch::X86,
            code_hash: 0,
            packed: false,
            pack_reasons: Vec::new(),
            reloc: None,
        };
        apply_string_anchors(&mut reference, &img, &patterns);

        let live = scan_live(
            &source,
            base,
            0x200,
            &regions,
            &code_regions,
            &patterns,
            Arch::X86,
        );

        assert_eq!(live.found, reference.found);
        assert_eq!(live.not_found, reference.not_found);
        assert_eq!(live.findings, reference.findings);
        assert_eq!(live.rows.len(), reference.rows.len());
        assert!(live.found.contains(&"Stat".to_string()));
        assert!(live.findings.iter().any(|f| f.name == "Mark"));
    }

    #[test]
    fn reports_not_found_and_unresolved() {
        let base = 0x2000usize;
        let data = vec![0u8; 32];
        let source = BufferSource::new(base, data);
        let regions = [Region { base, size: 32 }];
        let patterns = parse_patterns("Missing = 11 22 33 44", Arch::X64);

        let result = scan(&source, base, 32, &regions, &patterns, Arch::X64);
        assert_eq!(result.not_found, vec!["Missing"]);
        assert!(result.findings.is_empty());
        assert_eq!(result.rows.len(), 1);
        assert_eq!(result.rows[0].status, FindingStatus::NotFound);
    }

    #[test]
    fn out_of_module_pointer_is_rejected_not_wrapped() {
        // a rip-relative lea whose target lands before the module base must not wrap into a
        // huge rva; it is reported as a failed resolve instead of a bogus finding.
        let base = 0x1_0000usize;
        let mut data = vec![0u8; 64];
        // 48 8D 0D <disp32> with a large negative displacement -> target far below base
        data[0x10..0x17].copy_from_slice(&[0x48, 0x8D, 0x0D, 0x00, 0x00, 0xFF, 0xFF]);
        let source = BufferSource::new(base, data);
        let regions = [Region { base, size: 64 }];
        let patterns = parse_patterns("Bad_PTR = 48 8D 0D ?? ?? ?? ??", Arch::X64);

        let result = scan(&source, base, 64, &regions, &patterns, Arch::X64);
        assert!(result.findings.is_empty());
        assert_eq!(result.rows.len(), 1);
        assert_eq!(
            result.rows[0].status,
            FindingStatus::Failed(FailureReason::OutOfModule)
        );
    }

    // A module [base, base+0x2000) whose first page is executable and second page is not, with a
    // rip-relative `lea rcx, [rip+disp]` at `lea_off` pointing at `target_off`. Used to exercise the
    // `@section` check: the same instruction can point into code or into data by choice of target.
    fn section_image(
        lea_off: usize,
        target_off: usize,
    ) -> (usize, Vec<u8>, [Region; 1], [Region; 1]) {
        let base = 0x1_0000usize;
        let mut data = vec![0u8; 0x2000];
        let lea_addr = base + lea_off;
        let target_addr = base + target_off;
        let disp = (target_addr as i64 - (lea_addr as i64 + 7)) as i32;
        data[lea_off] = 0x48;
        data[lea_off + 1] = 0x8D;
        data[lea_off + 2] = 0x0D;
        data[lea_off + 3..lea_off + 7].copy_from_slice(&disp.to_le_bytes());
        let regions = [Region { base, size: 0x2000 }];
        let code_regions = [Region { base, size: 0x1000 }];
        (base, data, regions, code_regions)
    }

    #[test]
    fn section_code_expectation_accepts_a_code_target() {
        // lea in the code page, target also in the code page -> @section=code is satisfied.
        let (base, data, regions, code) = section_image(0x100, 0x800);
        let source = BufferSource::new(base, data);
        let patterns = parse_patterns("P_PTR = 48 8D 0D ?? ?? ?? ?? @section=code", Arch::X64);
        let result = scan_in(&source, base, 0x2000, &regions, &code, &patterns, Arch::X64);
        assert_eq!(result.rows[0].status, FindingStatus::FoundUnique);
        assert_eq!(result.findings.len(), 1);
        assert!(result.rows[0].trace.as_deref().unwrap().contains("in code"));
    }

    #[test]
    fn section_code_expectation_rejects_a_non_code_target() {
        // lea in the code page, target in the data page -> @section=code must fail, not export.
        let (base, data, regions, code) = section_image(0x100, 0x1800);
        let source = BufferSource::new(base, data);
        let patterns = parse_patterns("P_PTR = 48 8D 0D ?? ?? ?? ?? @section=code", Arch::X64);
        let result = scan_in(&source, base, 0x2000, &regions, &code, &patterns, Arch::X64);
        assert_eq!(
            result.rows[0].status,
            FindingStatus::Failed(FailureReason::OutOfExpectedSection)
        );
        assert!(result.findings.is_empty());
        assert!(
            result.rows[0]
                .trace
                .as_deref()
                .unwrap()
                .contains("out of expected section")
        );
    }

    #[test]
    fn section_data_expectation_rejects_a_code_target() {
        // expecting data but the target is in the executable page -> failure.
        let (base, data, regions, code) = section_image(0x100, 0x800);
        let source = BufferSource::new(base, data);
        let patterns = parse_patterns("P_PTR = 48 8D 0D ?? ?? ?? ?? @section=data", Arch::X64);
        let result = scan_in(&source, base, 0x2000, &regions, &code, &patterns, Arch::X64);
        assert_eq!(
            result.rows[0].status,
            FindingStatus::Failed(FailureReason::OutOfExpectedSection)
        );
    }

    #[test]
    fn section_check_is_skipped_without_executable_regions() {
        // scan() supplies no executable regions, so a section expectation cannot be (and is not)
        // enforced: behavior is identical to having no @section directive. This keeps every existing
        // scan() caller unchanged.
        let (base, data, regions, _code) = section_image(0x100, 0x1800);
        let source = BufferSource::new(base, data);
        let patterns = parse_patterns("P_PTR = 48 8D 0D ?? ?? ?? ?? @section=code", Arch::X64);
        let result = scan(&source, base, 0x2000, &regions, &patterns, Arch::X64);
        assert_eq!(result.rows[0].status, FindingStatus::FoundUnique);
    }

    #[test]
    fn chunked_scan_finds_boundary_straddling_matches_once() {
        let base = 0x1000usize;
        let mut data = vec![0u8; 200];
        let sig = [0xDE, 0xAD, 0xBE, 0xEF, 0x11];
        // starts landing before, on, across, and in the overlap of 16-byte chunk boundaries
        let starts = [3usize, 33, 48, 64, 100, 190];
        for &s in &starts {
            data[s..s + sig.len()].copy_from_slice(&sig);
        }
        let source = BufferSource::new(base, data);
        let regions = [Region { base, size: 200 }];
        let patterns = parse_patterns("Foo = DE AD BE EF 11", Arch::X64);

        // a deliberately tiny chunk forces many boundaries; each match must appear exactly once
        let result = scan_chunked(&source, base, 200, &regions, &[], &patterns, Arch::X64, 16);
        assert_eq!(result.total_matches, starts.len());
        assert_eq!(result.rows.len(), 1);
        assert_eq!(result.rows[0].matches, starts.len());
        assert!(matches!(
            result.rows[0].status,
            FindingStatus::FoundAmbiguous { candidates: 6 }
        ));
        // an ambiguous match is reported but never exported as a normal offset
        assert!(result.findings.is_empty());
    }

    #[test]
    fn scan_uses_multi_pattern_index_above_threshold() {
        let base = 0x1000usize;
        let count = MULTI_PATTERN_THRESHOLD + 4;
        let mut data = vec![0u8; count * 8];
        let mut text = String::new();
        for i in 0..count {
            let off = i * 8;
            let b = i as u8;
            data[off..off + 4].copy_from_slice(&[b, 0xAA, 0x5A, 0xBB]);
            text.push_str(&format!("P{i} = {b:02X} AA 5A BB\n"));
        }
        let source = BufferSource::new(base, data);
        let regions = [Region {
            base,
            size: count * 8,
        }];
        let patterns = parse_patterns(&text, Arch::X64);

        let result = scan(&source, base, count * 8, &regions, &patterns, Arch::X64);
        assert_eq!(result.found.len(), count);
        assert!(result.not_found.is_empty());
    }

    // A source that can only read the first `cap` bytes of its buffer, so a window past the cap reads
    // short. Models a decommitted or guarded tail in a live module.
    struct CappedSource {
        base: usize,
        data: Vec<u8>,
        cap: usize,
    }

    impl MemorySource for CappedSource {
        fn read_into(&self, address: usize, buf: &mut [u8]) -> std::io::Result<usize> {
            if address < self.base {
                return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput));
            }
            let off = address - self.base;
            if off >= self.cap {
                return Ok(0);
            }
            let avail = (self.cap - off).min(self.data.len().saturating_sub(off));
            let n = buf.len().min(avail);
            buf[..n].copy_from_slice(&self.data[off..off + n]);
            Ok(n)
        }
    }

    #[test]
    fn scan_reports_partial_reads_and_keeps_readable_matches() {
        let base = 0x1000usize;
        let mut data = vec![0u8; 0x200];
        data[0x10..0x14].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        // the last 0x80 bytes are unreadable
        let source = CappedSource {
            base,
            data,
            cap: 0x180,
        };
        let regions = [Region { base, size: 0x200 }];
        let patterns = parse_patterns("Foo = DE AD BE EF", Arch::X64);
        let result = scan(&source, base, 0x200, &regions, &patterns, Arch::X64);

        assert!(
            !result.read_gaps.is_empty(),
            "a short read must be recorded"
        );
        assert!(result.unread_bytes() > 0);
        assert!(
            result.warnings.iter().any(|w| w.contains("partial reads")),
            "a partial-read advisory must be surfaced"
        );
        // the match in the readable region is still found
        assert_eq!(result.rows[0].status, FindingStatus::FoundUnique);
    }

    #[test]
    fn hits_unique_flags_multiple_matches_and_warns() {
        let base = 0x1000usize;
        let mut data = vec![0u8; 0x100];
        data[0x10..0x12].copy_from_slice(&[0xCA, 0xFE]);
        data[0x40..0x42].copy_from_slice(&[0xCA, 0xFE]);
        let source = BufferSource::new(base, data);
        let regions = [Region { base, size: 0x100 }];
        let patterns = parse_patterns("Amb = CA FE @hits=unique", Arch::X64);
        let result = scan(&source, base, 0x100, &regions, &patterns, Arch::X64);

        assert!(matches!(
            result.rows[0].status,
            FindingStatus::FoundAmbiguous { candidates: 2 }
        ));
        assert!(result.findings.is_empty(), "ambiguous must never export");
        assert!(
            result
                .warnings
                .iter()
                .any(|w| w.contains("expected a unique match"))
        );
    }

    #[test]
    fn hits_at_least_makes_a_single_match_nonexportable() {
        let base = 0x1000usize;
        let mut data = vec![0u8; 0x100];
        data[0x10..0x12].copy_from_slice(&[0xCA, 0xFE]);
        let source = BufferSource::new(base, data);
        let regions = [Region { base, size: 0x100 }];

        // default: a single match is a unique, exportable find
        let default = scan(
            &source,
            base,
            0x100,
            &regions,
            &parse_patterns("Solo = CA FE", Arch::X64),
            Arch::X64,
        );
        assert_eq!(default.rows[0].status, FindingStatus::FoundUnique);
        assert_eq!(default.findings.len(), 1);

        // @hits=>=2: the same single match no longer satisfies the expectation, so it is not exported
        let strict = scan(
            &source,
            base,
            0x100,
            &regions,
            &parse_patterns("Solo = CA FE @hits=>=2", Arch::X64),
            Arch::X64,
        );
        assert!(matches!(
            strict.rows[0].status,
            FindingStatus::FoundAmbiguous { .. }
        ));
        assert!(strict.findings.is_empty());
        assert!(
            strict
                .warnings
                .iter()
                .any(|w| w.contains("expected at least 2"))
        );
    }

    #[test]
    fn structured_trace_exposes_resolver_facts() {
        let base = 0x1000usize;
        let mut data = vec![0u8; 64];
        data[0x20..0x27].copy_from_slice(&[0x48, 0x8D, 0x0D, 0x09, 0x00, 0x00, 0x00]);
        let source = BufferSource::new(base, data);
        let regions = [Region { base, size: 64 }];
        let patterns = parse_patterns("Bar_PTR = 48 8D 0D ? ? ? ?", Arch::X64);
        let result = scan(&source, base, 64, &regions, &patterns, Arch::X64);

        let trace = result.rows[0]
            .trace_detail
            .as_ref()
            .expect("a found row carries a structured trace");
        assert_eq!(trace.resolver, "rip-relative memory");
        assert_eq!(trace.match_rva, Some(0x20));
        assert_eq!(trace.target_rva, Some(0x30));
        assert_eq!(trace.mnemonic.as_deref(), Some("lea"));
        assert_eq!(trace.operand_kind.as_deref(), Some("memory"));
        assert!(trace.failure.is_none());
        // the human one-liner is derived from the struct and stays compatible
        assert!(result.rows[0].trace.as_deref().unwrap().contains("0x30"));
    }

    #[test]
    fn structured_trace_records_section_failure() {
        // a rip-relative lea in the code page pointing into the data page, with @section=code
        let (base, data, regions, code) = section_image(0x100, 0x1800);
        let source = BufferSource::new(base, data);
        let patterns = parse_patterns("P_PTR = 48 8D 0D ?? ?? ?? ?? @section=code", Arch::X64);
        let result = scan_in(&source, base, 0x2000, &regions, &code, &patterns, Arch::X64);
        let trace = result.rows[0].trace_detail.as_ref().unwrap();
        assert_eq!(trace.failure.as_deref(), Some("out of expected section"));
    }
}
