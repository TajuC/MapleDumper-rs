//! The Signature Maker feature: inspect a PE for packing, and generate
//! cross-version byte signatures (AOB / ref-RVA / cross) over a set of client
//! binaries, with per-job progress events and holdout validation.

use serde::{Deserialize, Serialize};

use maple_core::{
    Arch, FileImage, ImageInput, NegativeEvidence, SigCandidate, SigOptions, SigReport, SigStage,
    TargetKind, TargetSpec, apply_negative_corpus, generate_cross_with_progress,
    generate_with_progress, make_string_anchor, negative_corpus_hits, try_signature_from_aob,
};
use tauri::Emitter;

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum SigJob {
    Aob {
        sig: String,
    },
    Ref {
        ref_path: String,
        rva: String,
    },
    Cross {
        sig: String,
        ref_path: String,
        rva: String,
    },
}

#[derive(Deserialize)]
pub struct SigGenRequest {
    clients: Vec<String>,
    jobs: Vec<SigJob>,
    #[serde(default)]
    negatives: Vec<String>,
}

#[derive(Serialize)]
pub struct PeInfoView {
    name: String,
    arch: String,
    packed: bool,
    reasons: Vec<String>,
    max_entropy: f64,
}

#[derive(Serialize)]
struct PerVerView {
    label: String,
    match_rva: Option<String>,
    resolved_target_rva: Option<String>,
    target_type: Option<String>,
    fingerprint_similarity: Option<f64>,
}

#[derive(Serialize)]
struct ScoreView {
    uniqueness: u32,
    stability: u32,
    entropy: u32,
    semantic: u32,
    resolver_confidence: u32,
    cross_build: u32,
    final_score: u32,
}

#[derive(Serialize)]
struct SigCandView {
    aob: String,
    suffix: String,
    grade: String,
    score: u32,
    scores: ScoreView,
    reasons: Vec<String>,
    bytes: usize,
    fixed: usize,
    wildcards: usize,
    fixed_ratio: f64,
    reloc_safe: bool,
    per_version: Vec<PerVerView>,
    diags: Vec<String>,
}

#[derive(Serialize)]
struct SigInputView {
    label: String,
    packed: bool,
    reasons: Vec<String>,
}

#[derive(Serialize)]
struct SigHoldoutView {
    held_out: String,
    generated: bool,
    matched: bool,
}

#[derive(Serialize)]
struct NegHitView {
    label: String,
    count: usize,
}

#[derive(Serialize)]
struct NegSummaryView {
    modules_scanned: usize,
    modules_hit: usize,
    total_hits: usize,
    max_hits_per_module: usize,
}

#[derive(Serialize)]
struct SigReportView {
    arch: String,
    unique_builds: usize,
    inputs: Vec<SigInputView>,
    duplicate_groups: Vec<(String, Vec<String>)>,
    chosen: Option<SigCandView>,
    alternates: Vec<SigCandView>,
    rejected: Vec<SigCandView>,
    diagnostics: Vec<String>,
    holdout: Vec<SigHoldoutView>,
    string_anchor: Option<String>,
    negative_hits: Vec<NegHitView>,
    negative_summary: Option<NegSummaryView>,
}

#[derive(Serialize)]
struct CrossView {
    expected_rva: String,
    matched_rva: Option<String>,
    agrees: bool,
}

#[derive(Serialize)]
struct SigJobResultView {
    label: String,
    report: Option<SigReportView>,
    cross: Option<CrossView>,
    error: Option<String>,
}

#[derive(Serialize)]
pub struct SigGenResponse {
    jobs: Vec<SigJobResultView>,
}

fn sig_kind_str(kind: TargetKind) -> &'static str {
    match kind {
        TargetKind::Code => "code",
        TargetKind::Data => "data",
        TargetKind::Import => "import",
        TargetKind::Unknown => "unknown",
    }
}

fn sig_cand_view(c: &SigCandidate) -> SigCandView {
    SigCandView {
        aob: c.aob.clone(),
        suffix: c.suffix.as_str().to_string(),
        grade: c.grade.letter().to_string(),
        score: c.score,
        scores: ScoreView {
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
            .map(|p| PerVerView {
                label: p.label.clone(),
                match_rva: p.match_rva.map(|v| format!("0x{v:X}")),
                resolved_target_rva: p.resolved_target_rva.map(|v| format!("0x{v:X}")),
                target_type: p.target_kind.map(|k| sig_kind_str(k).to_string()),
                fingerprint_similarity: p.fingerprint_similarity,
            })
            .collect(),
        diags: c.diags.iter().map(|d| d.to_string()).collect(),
    }
}

fn sig_report_view(r: &SigReport) -> SigReportView {
    SigReportView {
        arch: if matches!(r.arch, Arch::X64) {
            "x64"
        } else {
            "x86"
        }
        .to_string(),
        unique_builds: r.unique_builds,
        inputs: r
            .inputs
            .iter()
            .map(|i| SigInputView {
                label: i.label.clone(),
                packed: i.packed,
                reasons: i.reasons.clone(),
            })
            .collect(),
        duplicate_groups: r
            .duplicate_groups
            .iter()
            .map(|g| (format!("{:016X}", g.code_hash), g.labels.clone()))
            .collect(),
        chosen: r.chosen.as_ref().map(sig_cand_view),
        alternates: r.alternates.iter().map(sig_cand_view).collect(),
        rejected: r.rejected.iter().map(sig_cand_view).collect(),
        diagnostics: r.diagnostics.iter().map(|d| d.to_string()).collect(),
        holdout: Vec::new(),
        string_anchor: None,
        negative_hits: Vec::new(),
        negative_summary: None,
    }
}

fn holdout_views(
    inputs: &[ImageInput],
    spec: &TargetSpec,
    opts: &SigOptions,
) -> Vec<SigHoldoutView> {
    maple_core::holdout_validate(inputs, spec, opts)
        .into_iter()
        .map(|h| SigHoldoutView {
            held_out: h.held_out,
            generated: h.generated,
            matched: h.matched_holdout,
        })
        .collect()
}

// A string-anchored pattern for the chosen target: locate its matched build and rva and read the
// distinctive string the function references, so the user gets the patch-survivable form too.
fn string_anchor_line(r: &SigReport, inputs: &[ImageInput]) -> Option<String> {
    let chosen = r.chosen.as_ref()?;
    let anchor = chosen.per_version.iter().find_map(|pv| {
        let rva = pv.match_rva?;
        let img = inputs.iter().find(|i| i.label == pv.label)?;
        make_string_anchor(img, rva as usize)
    })?;
    Some(match &anchor.also {
        Some(also) => format!("@string={} @also={also}", anchor.text),
        None => format!("@string={}", anchor.text),
    })
}

fn enrich_report(
    r: &SigReport,
    inputs: &[ImageInput],
    negatives: &[ImageInput],
    spec: &TargetSpec,
    opts: &SigOptions,
) -> SigReportView {
    // Score the negative corpus once, then fold it into the chosen candidate before rendering so the
    // grade the UI shows already reflects that the signature also hits unrelated modules (the same
    // adjustment the CLI makes), rather than only listing the hits beside an unchanged grade.
    let hits = match &r.chosen {
        Some(chosen) if !negatives.is_empty() => negative_corpus_hits(&chosen.aob, negatives),
        _ => Vec::new(),
    };
    let mut adjusted = r.clone();
    if !hits.is_empty()
        && let Some(chosen) = adjusted.chosen.as_mut()
    {
        let counts: Vec<usize> = hits.iter().map(|h| h.count).collect();
        apply_negative_corpus(
            chosen,
            NegativeEvidence::from_hits(negatives.len(), &counts),
        );
    }

    let mut view = sig_report_view(&adjusted);
    view.holdout = holdout_views(inputs, spec, opts);
    view.string_anchor = string_anchor_line(&adjusted, inputs);
    if !negatives.is_empty() {
        let counts: Vec<usize> = hits.iter().map(|h| h.count).collect();
        let summary = NegativeEvidence::from_hits(negatives.len(), &counts);
        view.negative_hits = hits
            .into_iter()
            .map(|h| NegHitView {
                label: h.label,
                count: h.count,
            })
            .collect();
        view.negative_summary = Some(NegSummaryView {
            modules_scanned: summary.modules_scanned,
            modules_hit: summary.modules_hit,
            total_hits: summary.total_hits,
            max_hits_per_module: summary.max_hits_per_module,
        });
    }
    view
}

fn image_input(
    label: String,
    img: &FileImage,
    packed: bool,
    reasons: Vec<String>,
) -> ImageInput<'_> {
    ImageInput {
        label,
        source: img,
        base: img.base(),
        size: img.size(),
        code_regions: img.code_regions(),
        regions: img.regions(),
        import: img.import_range(),
        arch: img.arch(),
        code_hash: img.code_hash(),
        packed,
        pack_reasons: reasons,
        reloc: Some(img),
    }
}

#[tauri::command]
pub fn inspect_pe(path: String) -> Result<PeInfoView, String> {
    let img = FileImage::open(std::path::Path::new(&path)).map_err(|e| e.to_string())?;
    let report = img.pack_report();
    let name = std::path::Path::new(&path)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.clone());
    Ok(PeInfoView {
        name,
        arch: if matches!(img.arch(), Arch::X64) {
            "x64"
        } else {
            "x86"
        }
        .to_string(),
        packed: report.likely_packed,
        reasons: report.reasons,
        max_entropy: report.max_code_entropy,
    })
}

#[derive(Clone, Serialize)]
struct SigProgress {
    phase: &'static str,
    label: String,
    index: u32,
    total: u32,
    job: u32,
    jobs: u32,
}

fn stage_phase(stage: SigStage) -> (&'static str, u32, u32) {
    match stage {
        SigStage::Deduplicating => ("dedup", 0, 0),
        SigStage::ReadingCode { build, total } => ("read", build as u32, total as u32),
        SigStage::LocatingTarget => ("locate", 0, 0),
        SigStage::ScanningDirect => ("direct", 0, 0),
        SigStage::ScanningCallJmp => ("branch", 0, 0),
        SigStage::ScanningPtr => ("ptr", 0, 0),
        SigStage::Scoring => ("score", 0, 0),
    }
}

fn run_generate_signature(
    app: &tauri::AppHandle,
    req: SigGenRequest,
) -> Result<SigGenResponse, String> {
    if req.clients.is_empty() {
        return Err("add at least one client binary".to_string());
    }
    if req.jobs.is_empty() {
        return Err("add at least one target".to_string());
    }
    let label_of = |p: &str| {
        std::path::Path::new(p)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| p.to_string())
    };
    let jobs_total = req.jobs.len() as u32;
    let emit = |phase: &'static str, label: String, index: u32, total: u32, job: u32| {
        let _ = app.emit(
            "sig-progress",
            SigProgress {
                phase,
                label,
                index,
                total,
                job,
                jobs: jobs_total,
            },
        );
    };

    // Open and inspect every client once, then reuse the images across all jobs.
    let total = req.clients.len() as u32;
    let mut images: Vec<FileImage> = Vec::with_capacity(req.clients.len());
    for (k, p) in req.clients.iter().enumerate() {
        emit("load", label_of(p), k as u32 + 1, total, 0);
        images
            .push(FileImage::open(std::path::Path::new(p)).map_err(|e| format!("open {p}: {e}"))?);
    }
    emit("pack", String::new(), 0, 0, 0);
    let reports: Vec<_> = images.iter().map(FileImage::pack_report).collect();

    let inputs: Vec<ImageInput> = images
        .iter()
        .enumerate()
        .map(|(k, img)| {
            image_input(
                label_of(&req.clients[k]),
                img,
                reports[k].likely_packed,
                reports[k].reasons.clone(),
            )
        })
        .collect();

    let neg_images: Vec<FileImage> = req
        .negatives
        .iter()
        .map(|p| {
            FileImage::open(std::path::Path::new(p)).map_err(|e| format!("open negative {p}: {e}"))
        })
        .collect::<Result<_, _>>()?;
    let neg_inputs: Vec<ImageInput> = neg_images
        .iter()
        .zip(&req.negatives)
        .map(|(img, p)| image_input(label_of(p), img, false, Vec::new()))
        .collect();

    let ref_index = |ref_path: &str| -> Result<usize, String> {
        req.clients
            .iter()
            .position(|c| c == ref_path)
            .ok_or_else(|| "the reference must be one of the chosen clients".to_string())
    };
    let parse_rva = |raw: &str| -> Result<u64, String> {
        let hex = raw.trim().trim_start_matches("0x").trim_start_matches("0X");
        u64::from_str_radix(hex, 16).map_err(|_| format!("invalid RVA '{raw}'"))
    };

    let opts = SigOptions::default();
    let mut results: Vec<SigJobResultView> = Vec::with_capacity(req.jobs.len());
    for (ji, job) in req.jobs.iter().enumerate() {
        let job_n = ji as u32 + 1;
        let mut on_stage = |stage: SigStage| {
            let (phase, index, total) = stage_phase(stage);
            emit(phase, String::new(), index, total, job_n);
        };
        let result = match job {
            SigJob::Aob { sig } => {
                let sig = sig.trim().to_string();
                match try_signature_from_aob(&sig) {
                    Err(e) => job_error(sig.clone(), format!("invalid signature: {e}")),
                    Ok(_) => {
                        let spec = TargetSpec::Aob(sig.clone());
                        let report = generate_with_progress(&inputs, &spec, &opts, &mut on_stage);
                        SigJobResultView {
                            label: sig,
                            report: Some(enrich_report(
                                &report,
                                &inputs,
                                &neg_inputs,
                                &spec,
                                &opts,
                            )),
                            cross: None,
                            error: None,
                        }
                    }
                }
            }
            SigJob::Ref { ref_path, rva } => match (ref_index(ref_path), parse_rva(rva)) {
                (Ok(idx), Ok(rva_val)) => {
                    let spec = TargetSpec::Ref {
                        image: idx,
                        rva: rva_val,
                    };
                    let report = generate_with_progress(&inputs, &spec, &opts, &mut on_stage);
                    SigJobResultView {
                        label: format!("0x{rva_val:X}"),
                        report: Some(enrich_report(&report, &inputs, &neg_inputs, &spec, &opts)),
                        cross: None,
                        error: None,
                    }
                }
                (Err(e), _) | (_, Err(e)) => job_error(rva.clone(), e),
            },
            SigJob::Cross { sig, ref_path, rva } => {
                let sig = sig.trim().to_string();
                let aob_ok = try_signature_from_aob(&sig)
                    .map(|_| ())
                    .map_err(|e| format!("invalid signature: {e}"));
                match (aob_ok, ref_index(ref_path), parse_rva(rva)) {
                    (Ok(()), Ok(idx), Ok(rva_val)) => {
                        let cr = generate_cross_with_progress(
                            &inputs,
                            &sig,
                            idx,
                            rva_val,
                            &opts,
                            &mut on_stage,
                        );
                        SigJobResultView {
                            label: format!("0x{rva_val:X}"),
                            report: Some(enrich_report(
                                &cr.report,
                                &inputs,
                                &neg_inputs,
                                &TargetSpec::Aob(sig.clone()),
                                &opts,
                            )),
                            cross: Some(CrossView {
                                expected_rva: format!("0x{:X}", cr.expected_rva),
                                matched_rva: cr.matched_rva.map(|v| format!("0x{v:X}")),
                                agrees: cr.agrees,
                            }),
                            error: None,
                        }
                    }
                    (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => job_error(rva.clone(), e),
                }
            }
        };
        results.push(result);
    }
    Ok(SigGenResponse { jobs: results })
}

fn job_error(label: String, error: String) -> SigJobResultView {
    SigJobResultView {
        label,
        report: None,
        cross: None,
        error: Some(error),
    }
}

#[tauri::command]
pub async fn generate_signature(
    app: tauri::AppHandle,
    req: SigGenRequest,
) -> Result<SigGenResponse, String> {
    match tauri::async_runtime::spawn_blocking(move || run_generate_signature(&app, req)).await {
        Ok(result) => result,
        Err(e) => Err(e.to_string()),
    }
}
