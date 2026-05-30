// cargo run --release --example sig_validate -p maple-core --
//   --unpacked <exe> [--packed <exe> ...] [--negative <dll> ...] [--samples N]
//
// The unpacked client drives semantic identity; the packed ones only exercise pack detection, since
// their .text is encrypted at rest. Negatives confirm a generated signature stays unique elsewhere.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::Instant;

use maple_core::{
    FileImage, ImageInput, Region, SigOptions, TargetSpec, fn_identity, generate,
    negative_corpus_hits, xref_count,
};

struct Args {
    unpacked: Option<PathBuf>,
    packed: Vec<PathBuf>,
    negative: Vec<PathBuf>,
    samples: usize,
}

fn parse_args() -> Args {
    let mut a = Args {
        unpacked: None,
        packed: Vec::new(),
        negative: Vec::new(),
        samples: 200,
    };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--unpacked" => a.unpacked = it.next().map(PathBuf::from),
            "--packed" => a.packed.extend(it.next().map(PathBuf::from)),
            "--negative" => a.negative.extend(it.next().map(PathBuf::from)),
            "--samples" => a.samples = it.next().and_then(|s| s.parse().ok()).unwrap_or(a.samples),
            other => eprintln!("ignoring unknown argument {other}"),
        }
    }
    a
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
    examples: Vec<String>,
}

fn analyze(input: &ImageInput, targets: &[usize]) -> Stats {
    let ids: Vec<_> = targets.iter().map(|&rva| fn_identity(input, rva)).collect();
    let n = ids.len().max(1) as f64;
    let examples = ids
        .iter()
        .filter_map(|id| id.strings.first().cloned())
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
    if !s.examples.is_empty() {
        println!("    example strings: {:?}", s.examples);
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

fn main() {
    let args = parse_args();
    let Some(unpacked) = args.unpacked else {
        eprintln!("error: --unpacked <exe> is required");
        std::process::exit(2);
    };

    println!("== unpacked client: {} ==", unpacked.display());
    let img = match FileImage::open(&unpacked) {
        Ok(img) => img,
        Err(e) => {
            eprintln!("open failed: {e}");
            std::process::exit(1);
        }
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
