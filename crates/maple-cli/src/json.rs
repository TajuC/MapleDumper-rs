use serde::Serialize;

use maple_core::{
    BuildStamp, FindingStatus, HoldoutResult, NegativeEvidence, NegativeHit, ResolveTrace,
    ScanResult, SigCandidate, SigReport,
};

use crate::exit::{CliError, ExitKind};

#[derive(Serialize)]
struct ScanFindingJson {
    name: String,
    category: String,
    status: String,
    value: Option<String>,
    is_offset: bool,
    matches: usize,
    confidence: u8,
    candidates: Vec<String>,
    trace: Option<String>,
    // The full structured resolution trace (instruction offset, operand, mnemonic, target, checks,
    // failure reason), so automation can inspect why a value resolved, not just the one-liner.
    trace_detail: Option<ResolveTrace>,
    exported: bool,
}

#[derive(Serialize)]
struct ScanJson {
    module: String,
    module_base: String,
    build_hash: String,
    build_version: Option<String>,
    found: usize,
    unresolved: usize,
    not_found: usize,
    ambiguous: usize,
    total_matches: usize,
    unread_bytes: u64,
    warnings: Vec<String>,
    findings: Vec<ScanFindingJson>,
}

/// Serialize a value as pretty JSON, turning the (practically unreachable) serialization failure into
/// a non-zero exit instead of the empty document it used to print with a success code.
pub(crate) fn to_json_pretty<T: serde::Serialize>(value: &T) -> Result<String, CliError> {
    serde_json::to_string_pretty(value).map_err(|e| {
        CliError::new(
            ExitKind::Internal,
            format!("could not serialize JSON output: {e}"),
        )
    })
}

pub(crate) fn scan_json(
    result: &ScanResult,
    module: &str,
    base: u64,
    stamp: &BuildStamp,
) -> Result<String, CliError> {
    let ambiguous = result
        .rows
        .iter()
        .filter(|r| matches!(r.status, FindingStatus::FoundAmbiguous { .. }))
        .count();
    let findings = result
        .rows
        .iter()
        .map(|r| ScanFindingJson {
            name: r.name.clone(),
            category: r.category.clone(),
            status: r.status.label().to_string(),
            value: r.value.map(|v| format!("0x{v:X}")),
            is_offset: r.is_offset,
            matches: r.matches,
            confidence: r.confidence,
            candidates: r.candidates.iter().map(|v| format!("0x{v:X}")).collect(),
            trace: r.trace.clone(),
            trace_detail: r.trace_detail.clone(),
            // An ambiguous or failed row is shown for inspection but is never written as an offset.
            exported: r.status.is_exportable(),
        })
        .collect();
    let report = ScanJson {
        module: module.to_string(),
        module_base: format!("0x{base:X}"),
        build_hash: stamp.short(),
        build_version: stamp.version.clone(),
        found: result.found.len(),
        unresolved: result.matched_unresolved.len(),
        not_found: result.not_found.len(),
        ambiguous,
        total_matches: result.total_matches,
        unread_bytes: result.unread_bytes(),
        warnings: result.warnings.clone(),
        findings,
    };
    to_json_pretty(&report)
}

#[derive(Serialize)]
pub(crate) struct LintJson {
    pub(crate) name: String,
    pub(crate) aob: String,
    pub(crate) lints: Vec<String>,
}

#[derive(Serialize)]
struct JPer {
    label: String,
    match_rva: Option<String>,
    resolved_target_rva: Option<String>,
    target_type: Option<String>,
    fingerprint_similarity: Option<f64>,
    /// A fresh byte signature minted for this build at the relocated address, when the cross-build AOB
    /// does not apply (a recompiled build located by string/encoding/fingerprint anchor).
    aob: Option<String>,
}
#[derive(Serialize)]
struct JScores {
    uniqueness: u32,
    stability: u32,
    entropy: u32,
    semantic: u32,
    resolver_confidence: u32,
    cross_build: u32,
    final_score: u32,
}
#[derive(Serialize)]
struct JCand {
    aob: String,
    suffix: String,
    grade: String,
    score: u32,
    scores: JScores,
    reasons: Vec<String>,
    bytes: usize,
    fixed: usize,
    wildcards: usize,
    fixed_ratio: f64,
    reloc_safe: bool,
    per_version: Vec<JPer>,
    diags: Vec<String>,
    relocation: Option<JRelocation>,
}
#[derive(Serialize)]
struct JRelocation {
    anchor: String,
    support: usize,
    corroborators: Vec<String>,
    conflict: bool,
}
#[derive(Serialize)]
struct JInput {
    label: String,
    packed: bool,
    reasons: Vec<String>,
}
#[derive(Serialize)]
struct JDup {
    code_hash: String,
    labels: Vec<String>,
}
#[derive(Serialize)]
struct JNeg {
    label: String,
    count: usize,
}
#[derive(Serialize)]
struct JNegSummary {
    modules_scanned: usize,
    modules_hit: usize,
    total_hits: usize,
    max_hits_per_module: usize,
}
#[derive(Serialize)]
struct JHold {
    held_out: String,
    generated: bool,
    matched: bool,
}
#[derive(Serialize)]
struct JShortEntry {
    rva: String,
    similarity: f64,
    aob: Option<String>,
}
#[derive(Serialize)]
struct JShortlist {
    label: String,
    candidates: Vec<JShortEntry>,
}
#[derive(Serialize)]
struct JAobRange {
    aob: String,
    minted_in: String,
    first: String,
    last: String,
    labels: Vec<String>,
}
#[derive(Serialize)]
struct JReport {
    arch: String,
    unique_builds: usize,
    inputs: Vec<JInput>,
    duplicate_groups: Vec<JDup>,
    chosen: Option<JCand>,
    alternates: Vec<JCand>,
    rejected: Vec<JCand>,
    negative_hits: Vec<JNeg>,
    negative_summary: JNegSummary,
    holdout: Vec<JHold>,
    string_anchor: Option<String>,
    shortlists: Vec<JShortlist>,
    aob_ranges: Vec<JAobRange>,
    diagnostics: Vec<String>,
}

fn jcand(c: &SigCandidate) -> JCand {
    JCand {
        aob: c.aob.clone(),
        suffix: c.suffix.as_str().to_string(),
        grade: c.grade.letter().to_string(),
        score: c.score,
        scores: JScores {
            uniqueness: c.scores.uniqueness,
            stability: c.scores.stability,
            entropy: c.scores.entropy,
            semantic: c.scores.semantic,
            resolver_confidence: c.scores.resolver_confidence,
            cross_build: c.scores.cross_build,
            final_score: c.scores.final_score,
        },
        reasons: c.reasons.clone(),
        bytes: c.bytes_len,
        fixed: c.fixed,
        wildcards: c.wildcards,
        fixed_ratio: c.fixed_ratio,
        reloc_safe: c.reloc_safe,
        per_version: c
            .per_version
            .iter()
            .map(|p| JPer {
                label: p.label.clone(),
                match_rva: p.match_rva.map(|v| format!("0x{v:X}")),
                resolved_target_rva: p.resolved_target_rva.map(|v| format!("0x{v:X}")),
                target_type: p.target_kind.map(|k| k.wire_str().to_string()),
                fingerprint_similarity: p.fingerprint_similarity,
                aob: p.aob.clone(),
            })
            .collect(),
        diags: c.diags.iter().map(|d| d.to_string()).collect(),
        relocation: c.relocation.as_ref().map(|r| JRelocation {
            anchor: r.anchor.clone(),
            support: r.support,
            corroborators: r.corroborators.clone(),
            conflict: r.conflict,
        }),
    }
}

pub(crate) fn json_report(
    r: &SigReport,
    negatives: &[NegativeHit],
    negatives_scanned: usize,
    holdout: &[HoldoutResult],
    string_anchor: Option<&str>,
) -> Result<String, CliError> {
    let neg_counts: Vec<usize> = negatives.iter().map(|h| h.count).collect();
    let neg_summary = NegativeEvidence::from_hits(negatives_scanned, &neg_counts);
    let report = JReport {
        arch: r.arch.label().to_string(),
        unique_builds: r.unique_builds,
        inputs: r
            .inputs
            .iter()
            .map(|i| JInput {
                label: i.label.clone(),
                packed: i.packed,
                reasons: i.reasons.clone(),
            })
            .collect(),
        duplicate_groups: r
            .duplicate_groups
            .iter()
            .map(|g| JDup {
                code_hash: format!("{:016X}", g.code_hash),
                labels: g.labels.clone(),
            })
            .collect(),
        chosen: r.chosen.as_ref().map(jcand),
        alternates: r.alternates.iter().map(jcand).collect(),
        rejected: r.rejected.iter().map(jcand).collect(),
        negative_hits: negatives
            .iter()
            .map(|h| JNeg {
                label: h.label.clone(),
                count: h.count,
            })
            .collect(),
        negative_summary: JNegSummary {
            modules_scanned: neg_summary.modules_scanned,
            modules_hit: neg_summary.modules_hit,
            total_hits: neg_summary.total_hits,
            max_hits_per_module: neg_summary.max_hits_per_module,
        },
        holdout: holdout
            .iter()
            .map(|h| JHold {
                held_out: h.held_out.clone(),
                generated: h.generated,
                matched: h.matched_holdout,
            })
            .collect(),
        string_anchor: string_anchor.map(str::to_string),
        shortlists: r
            .shortlists
            .iter()
            .map(|s| JShortlist {
                label: s.label.clone(),
                candidates: s
                    .entries
                    .iter()
                    .map(|e| JShortEntry {
                        rva: format!("0x{:X}", e.rva),
                        similarity: e.similarity,
                        aob: e.aob.clone(),
                    })
                    .collect(),
            })
            .collect(),
        aob_ranges: r
            .aob_ranges
            .iter()
            .map(|rg| JAobRange {
                aob: rg.aob.clone(),
                minted_in: rg.minted_in.clone(),
                first: rg.first_label.clone(),
                last: rg.last_label.clone(),
                labels: rg.labels.clone(),
            })
            .collect(),
        diagnostics: r.diagnostics.iter().map(|d| d.to_string()).collect(),
    };
    to_json_pretty(&report)
}
