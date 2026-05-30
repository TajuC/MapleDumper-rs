// cargo run --release --example sig_validate -p maple-core --
//   --unpacked <exe> [--packed <exe> ...] [--negative <dll> ...] [--samples N]
//
// The unpacked client drives semantic identity; the packed ones only exercise pack detection, since
// their .text is encrypted at rest. Negatives confirm a generated signature stays unique elsewhere.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::Instant;

use maple_core::{
    BuildProfile, FileImage, ImageInput, Region, SigOptions, TargetSpec, fn_identity, generate,
    holdout_validate, make_string_anchor, negative_corpus_hits, resolve_string_anchor, xref_count,
};

struct Args {
    unpacked: Option<PathBuf>,
    packed: Vec<PathBuf>,
    negative: Vec<PathBuf>,
    cross: Vec<PathBuf>,
    samples: usize,
}

fn parse_args() -> Args {
    let mut a = Args {
        unpacked: None,
        packed: Vec::new(),
        negative: Vec::new(),
        cross: Vec::new(),
        samples: 200,
    };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--unpacked" => a.unpacked = it.next().map(PathBuf::from),
            "--packed" => a.packed.extend(it.next().map(PathBuf::from)),
            "--negative" => a.negative.extend(it.next().map(PathBuf::from)),
            "--cross" => a.cross.extend(it.next().map(PathBuf::from)),
            "--samples" => a.samples = it.next().and_then(|s| s.parse().ok()).unwrap_or(a.samples),
            other => eprintln!("ignoring unknown argument {other}"),
        }
    }
    a
}

fn file_name(p: &Path) -> String {
    p.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| p.display().to_string())
}

fn input_of<'a>(label: &str, img: &'a FileImage) -> ImageInput<'a> {
    let pack = img.pack_report();
    ImageInput {
        label: label.to_string(),
        source: img,
        base: img.base(),
        size: img.size(),
        code_regions: img.code_regions(),
        regions: img.regions(),
        import: img.import_range(),
        arch: img.arch(),
        code_hash: img.code_hash(),
        packed: pack.likely_packed,
        pack_reasons: pack.reasons,
        reloc: Some(img),
    }
}

fn region_bytes(input: &ImageInput, region: &Region) -> Vec<u8> {
    let mut buf = vec![0u8; region.size];
    let mut filled = 0;
    while filled < buf.len() {
        match input
            .source
            .read_into(region.base + filled, &mut buf[filled..])
        {
            Ok(0) | Err(_) => break,
            Ok(n) => filled += n,
        }
    }
    buf.truncate(filled);
    buf
}

fn call_targets(input: &ImageInput) -> Vec<usize> {
    let span = input.base..input.base + input.size;
    input
        .code_regions
        .iter()
        .flat_map(|region| {
            let bytes = region_bytes(input, region);
            let base = region.base;
            bytes
                .windows(5)
                .enumerate()
                .filter(|(_, w)| w[0] == 0xE8)
                .filter_map(move |(i, w)| {
                    let rel = i32::from_le_bytes([w[1], w[2], w[3], w[4]]) as i64;
                    usize::try_from((base + i + 5) as i64 + rel).ok()
                })
                .collect::<Vec<_>>()
        })
        .filter(|abs| span.contains(abs))
        .map(|abs| abs - input.base)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

struct Stats {
    sampled: usize,
    distinct: usize,
    blocks: f64,
    constants: f64,
    strings: f64,
    with_string: usize,
    examples: Vec<(usize, String)>,
}

fn analyze(input: &ImageInput, targets: &[usize]) -> Stats {
    let ids: Vec<_> = targets.iter().map(|&rva| fn_identity(input, rva)).collect();
    let n = ids.len().max(1) as f64;
    let examples = targets
        .iter()
        .zip(&ids)
        .filter_map(|(&rva, id)| id.strings.first().map(|s| (rva, s.clone())))
        .take(8)
        .collect();
    Stats {
        sampled: ids.len(),
        distinct: ids
            .iter()
            .map(|id| id.fingerprint())
            .collect::<BTreeSet<_>>()
            .len(),
        blocks: ids.iter().map(|id| id.blocks).sum::<usize>() as f64 / n,
        constants: ids.iter().map(|id| id.constants.len()).sum::<usize>() as f64 / n,
        strings: ids.iter().map(|id| id.strings.len()).sum::<usize>() as f64 / n,
        with_string: ids.iter().filter(|id| !id.strings.is_empty()).count(),
        examples,
    }
}

fn percentiles(mut xs: Vec<usize>) -> Option<(usize, usize, usize)> {
    xs.sort_unstable();
    Some((*xs.first()?, xs[xs.len() / 2], *xs.last()?))
}

fn report_unpacked(input: &ImageInput, img: &FileImage, targets: &[usize], samples: usize) {
    let pack = img.pack_report();
    println!(
        "  arch {:?} | code {} bytes | packed {} (entropy {:.2})",
        input.arch,
        img.size(),
        pack.likely_packed,
        pack.max_code_entropy
    );
    println!("  {} call targets", targets.len());

    let step = (targets.len() / samples.max(1)).max(1);
    let sampled: Vec<_> = targets
        .iter()
        .copied()
        .step_by(step)
        .take(samples)
        .collect();

    let t = Instant::now();
    let s = analyze(input, &sampled);
    let pct = |x: usize| 100.0 * x as f64 / s.sampled.max(1) as f64;
    println!(
        "  identity over {} functions in {} ms:",
        s.sampled,
        t.elapsed().as_millis()
    );
    println!(
        "    distinct fingerprints: {} ({:.0}% unique)",
        s.distinct,
        pct(s.distinct)
    );
    println!(
        "    avg basic blocks {:.2} | constants {:.2} | strings {:.2}",
        s.blocks, s.constants, s.strings
    );
    println!(
        "    functions referencing a string: {} ({:.0}%)",
        s.with_string,
        pct(s.with_string)
    );
    for (rva, text) in &s.examples {
        println!("    string function 0x{rva:X} -> {text:?}");
    }

    let t = Instant::now();
    let probe: Vec<_> = sampled
        .iter()
        .take(12)
        .map(|&rva| xref_count(input, rva))
        .collect();
    if let Some((lo, mid, hi)) = percentiles(probe) {
        println!(
            "    xref count over 12 probed: min {lo}, median {mid}, max {hi} ({} ms)",
            t.elapsed().as_millis()
        );
    }
}

fn report_packed(path: &Path) {
    match FileImage::open(path) {
        Ok(img) => {
            let r = img.pack_report();
            let reasons = if r.reasons.is_empty() {
                String::new()
            } else {
                format!(" [{}]", r.reasons.join("; "))
            };
            println!(
                "== packed {}: likely_packed {} (entropy {:.2}){reasons}",
                path.display(),
                r.likely_packed,
                r.max_code_entropy
            );
        }
        Err(e) => eprintln!("== packed {}: open failed: {e}", path.display()),
    }
}

fn report_negatives(input: &ImageInput, probe_rva: usize, paths: &[PathBuf]) {
    let spec = TargetSpec::Ref {
        image: 0,
        rva: probe_rva as u64,
    };
    let Some(chosen) = generate(std::slice::from_ref(input), &spec, &SigOptions::default()).chosen
    else {
        println!("== negative corpus: no signature for the probe target");
        return;
    };
    let images: Vec<_> = paths
        .iter()
        .filter_map(|p| FileImage::open(p).ok())
        .collect();
    let inputs: Vec<_> = images
        .iter()
        .zip(paths)
        .map(|(img, p)| input_of(&p.display().to_string(), img))
        .collect();
    let hits = negative_corpus_hits(&chosen.aob, &inputs);
    let verdict = match hits.as_slice() {
        [] => "clean".to_string(),
        hits => format!(
            "{} hit(s): {:?}",
            hits.len(),
            hits.iter().map(|h| &h.label).collect::<Vec<_>>()
        ),
    };
    println!(
        "== negative corpus over {} modules: {} -> {verdict}",
        inputs.len(),
        chosen.aob
    );
}

fn report_cross(paths: &[PathBuf], samples: usize) {
    let opened: Vec<_> = paths
        .iter()
        .filter_map(|p| Some((file_name(p), FileImage::open(p).ok()?)))
        .collect();
    if opened.len() < 3 {
        eprintln!("cross-version needs at least 3 openable builds");
        return;
    }
    let inputs: Vec<_> = opened
        .iter()
        .map(|(name, img)| input_of(name, img))
        .collect();
    let profiles: Vec<_> = inputs.iter().map(BuildProfile::of).collect();
    let same_lane = profiles[1..].iter().all(|p| profiles[0].same_variant(p));
    println!(
        "== cross-version over {} builds (arch {:?}, same lane {same_lane}) ==",
        inputs.len(),
        profiles[0].arch
    );
    for (input, prof) in inputs.iter().zip(&profiles) {
        println!(
            "  {} | code {} bytes | packed {}",
            input.label, prof.code_bytes, prof.packed
        );
    }
    if !same_lane {
        println!("  refusing to mix architecture or pack state");
        return;
    }

    let targets = call_targets(&inputs[0]);
    let step = (targets.len() / samples.max(1)).max(1);
    let sampled: Vec<_> = targets
        .iter()
        .copied()
        .step_by(step)
        .take(samples)
        .collect();
    let opts = SigOptions::default();

    let t = Instant::now();
    let fp_counts = |inp: &ImageInput| {
        call_targets(inp)
            .iter()
            .fold(BTreeMap::<String, usize>::new(), |mut m, &rva| {
                *m.entry(fn_identity(inp, rva).fingerprint()).or_default() += 1;
                m
            })
    };
    let maps: Vec<_> = inputs.iter().map(fp_counts).collect();
    let trackable = sampled
        .iter()
        .filter(|&&rva| {
            let fp = fn_identity(&inputs[0], rva).fingerprint();
            maps.iter().all(|m| m.get(&fp) == Some(&1))
        })
        .count();
    println!(
        "  exact-identity tracking: {trackable}/{} sampled functions identical in every build ({:.0}%) in {} ms",
        sampled.len(),
        100.0 * trackable as f64 / sampled.len().max(1) as f64,
        t.elapsed().as_millis()
    );

    let t = Instant::now();
    let string_sets = |inp: &ImageInput| {
        call_targets(inp)
            .iter()
            .filter_map(|&rva| Some(fn_identity(inp, rva).strings).filter(|s| !s.is_empty()))
            .fold(BTreeMap::<Vec<String>, usize>::new(), |mut m, s| {
                *m.entry(s).or_default() += 1;
                m
            })
    };
    let str_maps: Vec<_> = inputs.iter().map(string_sets).collect();
    let (str_tracked, str_total) = str_maps[0].iter().filter(|&(_, &c)| c == 1).fold(
        (0usize, 0usize),
        |(tracked, total), (s, _)| {
            let unique_everywhere = str_maps[1..].iter().all(|m| m.get(s) == Some(&1));
            (tracked + usize::from(unique_everywhere), total + 1)
        },
    );
    println!(
        "  string-anchored tracking: {str_tracked}/{str_total} distinctively string-referencing functions tracked uniquely across every build ({:.0}%) in {} ms",
        100.0 * str_tracked as f64 / str_total.max(1) as f64,
        t.elapsed().as_millis()
    );

    let t = Instant::now();
    let anchors: Vec<_> = targets
        .iter()
        .filter(|&&rva| !fn_identity(&inputs[0], rva).strings.is_empty())
        .take(150)
        .filter_map(|&rva| make_string_anchor(&inputs[0], rva))
        .collect();
    let survived = anchors
        .iter()
        .filter(|a| {
            inputs
                .iter()
                .all(|inp| resolve_string_anchor(inp, a).is_some())
        })
        .count();
    println!(
        "  string-anchor signatures: {survived}/{} resolve uniquely in every build ({:.0}%) in {} ms",
        anchors.len(),
        100.0 * survived as f64 / anchors.len().max(1) as f64,
        t.elapsed().as_millis()
    );

    let t = Instant::now();
    let grades = sampled
        .iter()
        .fold(BTreeMap::<String, usize>::new(), |mut acc, &rva| {
            let spec = TargetSpec::Ref {
                image: 0,
                rva: rva as u64,
            };
            if let Some(c) = generate(&inputs, &spec, &opts).chosen {
                *acc.entry(c.grade.letter().to_string()).or_default() += 1;
            }
            acc
        });
    let made: usize = grades.values().sum();
    println!(
        "  signatures for {made}/{} targets ({:.0}%) in {} ms; grades {grades:?}",
        sampled.len(),
        100.0 * made as f64 / sampled.len().max(1) as f64,
        t.elapsed().as_millis()
    );

    let probe: Vec<_> = sampled.iter().copied().take(16).collect();
    let t = Instant::now();
    let (pass, total) = probe.iter().fold((0usize, 0usize), |(pass, total), &rva| {
        let spec = TargetSpec::Ref {
            image: 0,
            rva: rva as u64,
        };
        holdout_validate(&inputs, &spec, &opts)
            .iter()
            .fold((pass, total), |(p, t), r| {
                (p + usize::from(r.matched_holdout), t + 1)
            })
    });
    println!(
        "  holdout over {} probed targets in {} ms: {pass}/{total} held-out builds re-matched",
        probe.len(),
        t.elapsed().as_millis()
    );
}

fn report_unpacked_client(unpacked: &Path, args: &Args) {
    println!("== unpacked client: {} ==", unpacked.display());
    let img = match FileImage::open(unpacked) {
        Ok(img) => img,
        Err(e) => return eprintln!("open failed: {e}"),
    };
    let input = input_of("unpacked", &img);
    let targets = call_targets(&input);
    report_unpacked(&input, &img, &targets, args.samples);
    args.packed
        .iter()
        .map(PathBuf::as_path)
        .for_each(report_packed);
    if let Some(&probe) = targets.first()
        && !args.negative.is_empty()
    {
        report_negatives(&input, probe, &args.negative);
    }
}

fn main() {
    let args = parse_args();
    if args.unpacked.is_none() && args.cross.is_empty() {
        eprintln!("error: pass --unpacked <exe> and/or --cross <exe> ...");
        std::process::exit(2);
    }
    if let Some(unpacked) = &args.unpacked {
        report_unpacked_client(unpacked, &args);
    }
    if !args.cross.is_empty() {
        report_cross(&args.cross, args.samples);
    }
}
