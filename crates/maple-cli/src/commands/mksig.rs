use std::path::{Path, PathBuf};

use maple_core::{
    FileImage, ImageInput, SigOptions, TargetSpec, apply_negatives, generate, holdout_validate,
    make_string_anchor, negative_corpus_hits,
};

use crate::cli::MksigArgs;
use crate::config::parse_hex_opt;
use crate::exit::{CliError, ExitKind};
use crate::json::json_report;
use crate::report::print_sig_report;

fn file_label(path: &std::path::Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string())
}

fn collect_clients(
    clients: &[PathBuf],
    client_dir: Option<&Path>,
    ref_path: Option<&Path>,
) -> Result<Vec<PathBuf>, String> {
    let mut clients = clients.to_vec();
    if let Some(dir) = client_dir {
        let rd = std::fs::read_dir(dir).map_err(|e| format!("read dir {}: {e}", dir.display()))?;
        for entry in rd {
            let p = match entry {
                Ok(e) => e.path(),
                Err(e) => {
                    eprintln!("[warn] skipping unreadable entry in {}: {e}", dir.display());
                    continue;
                }
            };
            if p.extension().is_some_and(|x| x.eq_ignore_ascii_case("exe")) {
                clients.push(p);
            }
        }
    }
    if let Some(r) = ref_path {
        clients.push(r.to_path_buf());
    }
    clients.sort();
    clients.dedup();
    if clients.is_empty() {
        return Err("mksig needs at least one --client or --client-dir".to_string());
    }
    Ok(clients)
}

fn gather_negatives(files: &[PathBuf], dir: Option<&Path>) -> Result<Vec<PathBuf>, String> {
    let mut out = files.to_vec();
    if let Some(d) = dir {
        let rd = std::fs::read_dir(d).map_err(|e| format!("read dir {}: {e}", d.display()))?;
        for entry in rd {
            let p = match entry {
                Ok(e) => e.path(),
                Err(e) => {
                    eprintln!("[warn] skipping unreadable entry in {}: {e}", d.display());
                    continue;
                }
            };
            if p.extension().is_some_and(|x| x.eq_ignore_ascii_case("exe")) {
                out.push(p);
            }
        }
    }
    out.sort();
    out.dedup();
    Ok(out)
}

pub(crate) fn cmd_mksig(m: MksigArgs) -> Result<ExitKind, CliError> {
    let clients = collect_clients(&m.client, m.client_dir.as_deref(), m.ref_path.as_deref())?;
    let has_sig = m.sig.is_some();
    let has_ref = m.ref_path.is_some() || m.rva.is_some();
    if has_sig == has_ref {
        return Err("provide exactly one of --sig OR (--ref + --rva)".into());
    }
    if let Some(aob) = &m.sig {
        maple_core::try_signature_from_aob(aob).map_err(|e| format!("invalid --sig: {e}"))?;
    }

    let images: Vec<FileImage> = clients
        .iter()
        .map(|p| FileImage::open(p).map_err(|e| format!("open {}: {e}", p.display())))
        .collect::<Result<_, _>>()?;
    let reports: Vec<_> = images.iter().map(FileImage::pack_report).collect();

    for (p, pr) in clients.iter().zip(&reports) {
        if pr.likely_packed {
            eprintln!(
                "[!] {} looks packed ({}, entropy {:.2}) - generated signatures may be unreliable",
                p.display(),
                pr.reasons.join("; "),
                pr.max_code_entropy
            );
        }
    }

    let mut inputs = Vec::with_capacity(images.len());
    for (k, img) in images.iter().enumerate() {
        inputs.push(ImageInput {
            label: file_label(&clients[k]),
            source: img,
            base: img.base(),
            size: img.size(),
            code_regions: img.code_regions(),
            regions: img.regions(),
            import: img.import_range(),
            arch: img.arch(),
            code_hash: img.code_hash(),
            packed: reports[k].likely_packed,
            pack_reasons: reports[k].reasons.clone(),
            reloc: Some(img),
        });
    }

    let spec = if let Some(aob) = &m.sig {
        TargetSpec::Aob(aob.clone())
    } else {
        let rva = parse_hex_opt(&m.rva)?.ok_or("--rva <hex> is required with --ref")? as u64;
        let ref_path = m.ref_path.as_ref().ok_or("--ref <exe> is required")?;
        let idx = clients
            .iter()
            .position(|c| c == ref_path)
            .ok_or("the --ref file was not opened as a client")?;
        TargetSpec::Ref { image: idx, rva }
    };

    let mut opts = SigOptions::default();
    if let Some(r) = m.min_fixed_ratio {
        // Out of [0,1] this gate silently misbehaves: a negative value disables it, above 1 rejects
        // every candidate. Reject it up front with a clear message instead.
        if !(0.0..=1.0).contains(&r) {
            return Err(CliError::new(
                ExitKind::InvalidInput,
                format!("--min-fixed-ratio must be between 0.0 and 1.0, got {r}"),
            ));
        }
        opts.min_fixed_ratio = r;
    }

    let mut report = generate(&inputs, &spec, &opts);

    let anchor_line = report.chosen.as_ref().and_then(|c| {
        let anchor = c.per_version.iter().find_map(|pv| {
            let rva = pv.match_rva?;
            let img = inputs.iter().find(|i| i.label == pv.label)?;
            make_string_anchor(img, rva as usize)
        })?;
        Some(match &anchor.also {
            Some(also) => format!("@string={} @also={also}", anchor.text),
            None => format!("@string={}", anchor.text),
        })
    });

    let holdout = if m.holdout {
        holdout_validate(&inputs, &spec, &opts)
    } else {
        Vec::new()
    };

    let neg_paths = gather_negatives(&m.negative, m.negative_dir.as_deref())?;
    let neg_hits = match &report.chosen {
        Some(chosen) if !neg_paths.is_empty() => {
            let neg_images: Vec<FileImage> = neg_paths
                .iter()
                .map(|p| {
                    FileImage::open(p).map_err(|e| format!("open negative {}: {e}", p.display()))
                })
                .collect::<Result<_, _>>()?;
            let neg_inputs: Vec<ImageInput> = neg_images
                .iter()
                .enumerate()
                .map(|(k, img)| ImageInput {
                    label: file_label(&neg_paths[k]),
                    source: img,
                    base: img.base(),
                    size: img.size(),
                    code_regions: img.code_regions(),
                    regions: img.regions(),
                    import: img.import_range(),
                    arch: img.arch(),
                    code_hash: img.code_hash(),
                    packed: false,
                    pack_reasons: Vec::new(),
                    reloc: Some(img),
                })
                .collect();
            negative_corpus_hits(&chosen.aob, &neg_inputs)
        }
        _ => Vec::new(),
    };

    // A signature that also matches unrelated modules is too generic to trust as an identity, so
    // fold that into the chosen candidate's uniqueness/final score (and possibly its grade) before
    // reporting, rather than only noting it alongside. The evidence carries how many modules were
    // scanned, how many matched, and the match volume, so the downgrade is honest about its basis.
    if !neg_hits.is_empty()
        && let Some(chosen) = report.chosen.as_mut()
    {
        let hit_counts: Vec<usize> = neg_hits.iter().map(|h| h.count).collect();
        apply_negatives(chosen, neg_paths.len(), &hit_counts);
    }

    if m.json || m.json_out.is_some() {
        let json = json_report(
            &report,
            &neg_hits,
            neg_paths.len(),
            &holdout,
            anchor_line.as_deref(),
        )?;
        if let Some(path) = &m.json_out {
            std::fs::write(path, &json).map_err(|e| format!("write {}: {e}", path.display()))?;
            eprintln!("[+] wrote {}", path.display());
        }
        if m.json {
            println!("{json}");
        }
    } else {
        print_sig_report(&report, &opts);
    }

    if let Some(line) = &anchor_line {
        eprintln!("[+] string anchor (survives client patches): NewSig = {line}");
    }

    // Validation summaries go to stderr so a piped --json stdout stays pure JSON.
    if neg_hits.is_empty() {
        if report.chosen.is_some() && !neg_paths.is_empty() {
            eprintln!("[+] clean against {} negative module(s)", neg_paths.len());
        }
    } else {
        eprintln!(
            "[!] the chosen signature also matches {} unrelated module(s):",
            neg_hits.len()
        );
        for h in &neg_hits {
            let plural = if h.count == 1 { "" } else { "es" };
            eprintln!("      {} ({} match{plural})", h.label, h.count);
        }
    }

    if m.holdout {
        if holdout.is_empty() {
            eprintln!("[i] holdout needs at least 3 builds; skipped");
        } else {
            let passed = holdout.iter().filter(|r| r.matched_holdout).count();
            eprintln!(
                "[+] holdout: {passed}/{} held-out build(s) re-matched",
                holdout.len()
            );
            for r in &holdout {
                let verdict = if r.matched_holdout {
                    "ok"
                } else if r.generated {
                    "MISS, signature did not match the held-out build"
                } else {
                    "no signature from the remaining builds"
                };
                eprintln!("      hold out {}: {verdict}", r.held_out);
            }
        }
    }
    // No safe signature is an unresolved outcome; a chosen one that also hits the negative corpus is
    // a warning (too generic to trust as an identity); otherwise a clean success.
    Ok(if report.chosen.is_none() {
        ExitKind::Unresolved
    } else if !neg_hits.is_empty() {
        ExitKind::SuccessWithWarnings
    } else {
        ExitKind::Success
    })
}
