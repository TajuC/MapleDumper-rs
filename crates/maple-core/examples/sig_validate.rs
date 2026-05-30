// Validate the signature pipeline against real client binaries.
//
// Usage:
//   cargo run --release --example sig_validate -p maple-core -- \
//     --unpacked <exe> [--packed <exe> ...] [--negative <dll> ...] [--samples N]
//
// The unpacked client drives semantic-identity extraction (the packed ones have an encrypted .text
// and would only decode to noise). Packed clients exercise pack detection. The negatives confirm a
// generated signature does not collide in unrelated modules.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::time::Instant;

use maple_core::{
    FileImage, ImageInput, SigOptions, TargetSpec, fn_identity, generate, negative_corpus_hits,
    xref_count,
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
            "--packed" => {
                if let Some(p) = it.next() {
                    a.packed.push(PathBuf::from(p));
                }
            }
            "--negative" => {
                if let Some(p) = it.next() {
                    a.negative.push(PathBuf::from(p));
                }
            }
            "--samples" => {
                if let Some(n) = it.next().and_then(|s| s.parse().ok()) {
                    a.samples = n;
                }
            }
            other => eprintln!("ignoring unknown argument {other}"),
        }
    }
    a
}

fn make_input<'a>(label: &str, img: &'a FileImage) -> ImageInput<'a> {
    let pr = img.pack_report();
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
        packed: pr.likely_packed,
        pack_reasons: pr.reasons.clone(),
        reloc: Some(img),
    }
}

// Collect distinct rel32 call targets that land inside the image: an approximation of the set of
// called function entries, good enough to sample real functions for identity extraction.
fn call_targets(input: &ImageInput) -> Vec<usize> {
    let mut targets = BTreeSet::new();
    let lo = input.base;
    let hi = input.base + input.size;
    for r in &input.code_regions {
        let mut bytes = vec![0u8; r.size];
        let mut off = 0;
        while off < r.size {
            match input.source.read_into(r.base + off, &mut bytes[off..]) {
                Ok(0) | Err(_) => break,
                Ok(n) => off += n,
            }
        }
        let n = bytes.len();
        let mut i = 0;
        while i + 5 <= n {
            if bytes[i] == 0xE8 {
                let rel =
                    i32::from_le_bytes([bytes[i + 1], bytes[i + 2], bytes[i + 3], bytes[i + 4]])
                        as i64;
                let target = (r.base + i + 5) as i64 + rel;
                if target >= lo as i64 && target < hi as i64 {
                    targets.insert(target as usize - input.base);
                }
            }
            i += 1;
        }
    }
    targets.into_iter().collect()
}

fn main() {
    let args = parse_args();
    let Some(unpacked) = args.unpacked.clone() else {
        eprintln!("error: --unpacked <exe> is required");
        std::process::exit(2);
    };

    println!("== unpacked client: {} ==", unpacked.display());
    let img = match FileImage::open(&unpacked) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("open failed: {e}");
            std::process::exit(1);
        }
    };
    let input = make_input("unpacked", &img);
    let pr = img.pack_report();
    println!(
        "  arch {:?} | code {} bytes | packed {} (entropy {:.2})",
        input.arch,
        img.size(),
        pr.likely_packed,
        pr.max_code_entropy
    );

    let t0 = Instant::now();
    let entries = call_targets(&input);
    println!(
        "  found {} distinct call targets in {} ms",
        entries.len(),
        t0.elapsed().as_millis()
    );

    let step = (entries.len() / args.samples.max(1)).max(1);
    let sampled: Vec<usize> = entries
        .iter()
        .copied()
        .step_by(step)
        .take(args.samples)
        .collect();

    let t1 = Instant::now();
    let mut fps = BTreeSet::new();
    let (mut blocks, mut consts, mut strings) = (0usize, 0usize, 0usize);
    let mut with_string = 0usize;
    let mut sample_strings: Vec<String> = Vec::new();
    for &rva in &sampled {
        let id = fn_identity(&input, rva);
        fps.insert(id.fingerprint());
        blocks += id.blocks;
        consts += id.constants.len();
        strings += id.strings.len();
        if !id.strings.is_empty() {
            with_string += 1;
            if sample_strings.len() < 8 {
                sample_strings.push(id.strings[0].clone());
            }
        }
    }
    let s = sampled.len().max(1);
    println!(
        "  identity over {} sampled functions in {} ms:",
        sampled.len(),
        t1.elapsed().as_millis()
    );
    println!(
        "    distinct fingerprints: {} / {} ({:.0}% unique)",
        fps.len(),
        sampled.len(),
        100.0 * fps.len() as f64 / s as f64
    );
    println!("    avg basic blocks: {:.2}", blocks as f64 / s as f64);
    println!(
        "    avg distinctive constants: {:.2}",
        consts as f64 / s as f64
    );
    println!(
        "    avg string references: {:.2}",
        strings as f64 / s as f64
    );
    println!(
        "    functions referencing a string: {with_string} / {} ({:.0}%)",
        sampled.len(),
        100.0 * with_string as f64 / s as f64
    );
    if !sample_strings.is_empty() {
        println!("    example referenced strings: {sample_strings:?}");
    }

    // xref counts are O(code) each, so probe a small sub-sample.
    let t2 = Instant::now();
    let probe: Vec<usize> = sampled.iter().copied().take(12).collect();
    let mut xrefs: Vec<usize> = probe.iter().map(|&rva| xref_count(&input, rva)).collect();
    xrefs.sort_unstable();
    if !xrefs.is_empty() {
        println!(
            "    xref count over {} probed functions: min {}, median {}, max {} ({} ms)",
            xrefs.len(),
            xrefs[0],
            xrefs[xrefs.len() / 2],
            xrefs[xrefs.len() - 1],
            t2.elapsed().as_millis()
        );
    }

    for path in &args.packed {
        match FileImage::open(path) {
            Ok(p) => {
                let r = p.pack_report();
                println!(
                    "== packed client {}: likely_packed {} (entropy {:.2}) {}",
                    path.display(),
                    r.likely_packed,
                    r.max_code_entropy,
                    if r.reasons.is_empty() {
                        String::new()
                    } else {
                        format!("[{}]", r.reasons.join("; "))
                    }
                );
            }
            Err(e) => eprintln!("== packed client {}: open failed: {e}", path.display()),
        }
    }

    if !args.negative.is_empty()
        && let Some(&rva) = sampled.first()
    {
        let spec = TargetSpec::Ref {
            image: 0,
            rva: rva as u64,
        };
        let report = generate(std::slice::from_ref(&input), &spec, &SigOptions::default());
        match report.chosen {
            Some(c) => {
                let negs: Vec<FileImage> = args
                    .negative
                    .iter()
                    .filter_map(|p| FileImage::open(p).ok())
                    .collect();
                let neg_inputs: Vec<ImageInput> = negs
                    .iter()
                    .zip(&args.negative)
                    .map(|(im, p)| make_input(&p.display().to_string(), im))
                    .collect();
                let hits = negative_corpus_hits(&c.aob, &neg_inputs);
                println!(
                    "== negative corpus over {} modules: signature {} -> {}",
                    neg_inputs.len(),
                    c.aob,
                    if hits.is_empty() {
                        "clean".to_string()
                    } else {
                        format!(
                            "{} hit(s): {:?}",
                            hits.len(),
                            hits.iter().map(|h| &h.label).collect::<Vec<_>>()
                        )
                    }
                );
            }
            None => println!("== negative corpus: no signature generated for the probe target"),
        }
    }
}
