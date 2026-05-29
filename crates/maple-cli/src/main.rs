use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use serde::Serialize;

use maple_core::output::{cheat_table, offsets_header, plain_text};
use maple_core::pattern::{Arch, ParseSeverity, parse_patterns_file_strict};
use maple_core::{
    AttachOptions, BuildStamp, DiffReport, FindingStatus, Locator, Pattern, ProfileReport,
    ScanResult, Target, assembly_scan, diff, lint, parse_asm_patterns, parse_dump, parse_stamp,
    profile, scan,
};
use maple_core::{
    FileImage, ImageInput, SigCandidate, SigOptions, SigReport, TargetKind, TargetSpec, generate,
};

struct Args {
    process: Option<String>,
    class: Option<String>,
    module: Option<String>,
    patterns: PathBuf,
    arch: Arch,
    out: PathBuf,
    ce: bool,
    offsets: bool,
    wait: bool,
    timeout: Option<Duration>,
    profile: bool,
    lint: bool,
    diff: Option<(PathBuf, PathBuf)>,
    asm: Option<PathBuf>,
    from: Option<String>,
    to: Option<String>,
    mksig: bool,
    clients: Vec<PathBuf>,
    client_dir: Option<PathBuf>,
    sig: Option<String>,
    ref_path: Option<PathBuf>,
    rva: Option<String>,
    json: bool,
    json_out: Option<PathBuf>,
    min_fixed_ratio: Option<f64>,
}

const HELP: &str = "\
mapledumper - AOB/pattern scanner and offset dumper for Windows x64 processes

USAGE:
    mapledumper (--process <name> | --class <window-class>) [options]

ATTACH:
    --process <name>   attach by process name (\".exe\" optional, case-insensitive)
    --class <class>    attach by top-level window class
    --module <name>    module to scan (default: process name)
    --no-wait          fail immediately if the target is not running
    --timeout <secs>   max seconds to wait for the target (0 = forever, default)

OUTPUT:
    --patterns <file>  pattern file (default: patterns.txt)
    --arch <32|64>     architecture section to load (default: 64)
    --out <dir>        output directory, created if missing (default: .)
    --ce               write update.txt as a Cheat Engine table
    --no-offsets       do not write offsets.h
    --profile          measure the read/scan/resolve split against the live target and exit
    --lint             check the pattern file for weak signatures and exit
    --diff <a> <b>     compare two saved dumps and report what moved, then exit
    --asm <file>       scan by assembly instructions (one per line, wildcards * ? ^ $), then exit
    --from <addr>      with --asm, only report matches at or above this address (hex)
    --to <addr>        with --asm, only report matches below this address (hex)

SIGNATURE MAKER (cross-version, reads .exe files on disk; no target needed):
    --mksig            generate a cross-version signature from client files, then exit
    --client <exe>     a client binary (repeat for each version)
    --client-dir <dir> add every .exe in a folder as a client
    --sig <aob>        target: locate this existing AOB in each client and harden it
    --ref <exe> --rva <hex>   target: an address in one reference client
    --min-fixed-ratio <f>     reject signatures below this fixed-byte ratio (default 0.30)
    --json             print the full report as JSON
    --json-out <path>  write the JSON report to a file
    (signature gate defaults: max_len 80 bytes, min_fixed 5, min_fixed_ratio 0.30)

    -h, --help         print this help
    -V, --version      print version

By default mapledumper waits for the target, so you can start it before the game.";

fn value(it: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    it.next().ok_or_else(|| format!("{flag} requires a value"))
}

fn parse_hex_opt(field: &Option<String>) -> Result<Option<usize>, String> {
    match field.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        None => Ok(None),
        Some(raw) => {
            let hex = raw.trim_start_matches("0x").trim_start_matches("0X");
            usize::from_str_radix(hex, 16)
                .map(Some)
                .map_err(|_| format!("invalid address '{raw}'"))
        }
    }
}

fn parse_arch(s: &str) -> Result<Arch, String> {
    match s.trim().to_ascii_lowercase().as_str() {
        "64" | "x64" | "amd64" | "x86_64" | "x86-64" => Ok(Arch::X64),
        "32" | "x86" | "i386" | "x86_32" => Ok(Arch::X86),
        other => Err(format!("invalid --arch '{other}' (use 32 or 64)")),
    }
}

fn parse_args() -> Result<Args, String> {
    let mut process = None;
    let mut class = None;
    let mut module = None;
    let mut patterns = PathBuf::from("patterns.txt");
    let mut arch = Arch::X64;
    let mut out = PathBuf::from(".");
    let mut ce = false;
    let mut offsets = true;
    let mut wait = true;
    let mut timeout = None;
    let mut profile = false;
    let mut lint = false;
    let mut diff = None;
    let mut asm = None;
    let mut from = None;
    let mut to = None;
    let mut mksig = false;
    let mut clients = Vec::new();
    let mut client_dir = None;
    let mut sig = None;
    let mut ref_path = None;
    let mut rva = None;
    let mut json = false;
    let mut json_out = None;
    let mut min_fixed_ratio = None;

    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--process" => process = Some(value(&mut it, "--process")?),
            "--class" => class = Some(value(&mut it, "--class")?),
            "--module" => module = Some(value(&mut it, "--module")?),
            "--patterns" => patterns = PathBuf::from(value(&mut it, "--patterns")?),
            "--arch" => arch = parse_arch(&value(&mut it, "--arch")?)?,
            "--out" => out = PathBuf::from(value(&mut it, "--out")?),
            "--ce" => ce = true,
            "--no-offsets" => offsets = false,
            "--no-wait" => wait = false,
            "--profile" => profile = true,
            "--lint" => lint = true,
            "--diff" => {
                let old = PathBuf::from(value(&mut it, "--diff")?);
                let new = PathBuf::from(value(&mut it, "--diff")?);
                diff = Some((old, new));
            }
            "--asm" => asm = Some(PathBuf::from(value(&mut it, "--asm")?)),
            "--from" => from = Some(value(&mut it, "--from")?),
            "--to" => to = Some(value(&mut it, "--to")?),
            "--mksig" => mksig = true,
            "--client" => clients.push(PathBuf::from(value(&mut it, "--client")?)),
            "--client-dir" => client_dir = Some(PathBuf::from(value(&mut it, "--client-dir")?)),
            "--sig" => sig = Some(value(&mut it, "--sig")?),
            "--ref" => ref_path = Some(PathBuf::from(value(&mut it, "--ref")?)),
            "--rva" => rva = Some(value(&mut it, "--rva")?),
            "--json" => json = true,
            "--json-out" => json_out = Some(PathBuf::from(value(&mut it, "--json-out")?)),
            "--min-fixed-ratio" => {
                let raw = value(&mut it, "--min-fixed-ratio")?;
                min_fixed_ratio = Some(
                    raw.trim()
                        .parse()
                        .map_err(|_| format!("invalid --min-fixed-ratio '{raw}'"))?,
                );
            }
            "--timeout" => {
                let raw = value(&mut it, "--timeout")?;
                let secs: u64 = raw
                    .trim()
                    .parse()
                    .map_err(|_| format!("invalid --timeout '{raw}'"))?;
                timeout = (secs > 0).then(|| Duration::from_secs(secs));
            }
            "-h" | "--help" => {
                print!("{HELP}");
                std::process::exit(0);
            }
            "-V" | "--version" => {
                println!("mapledumper {}", maple_core::VERSION);
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    if process.is_some() && class.is_some() {
        return Err("--process and --class are mutually exclusive".to_string());
    }
    Ok(Args {
        process,
        class,
        module,
        patterns,
        arch,
        out,
        ce,
        offsets,
        wait,
        timeout,
        profile,
        lint,
        diff,
        asm,
        from,
        to,
        mksig,
        clients,
        client_dir,
        sig,
        ref_path,
        rva,
        json,
        json_out,
        min_fixed_ratio,
    })
}

fn module_name(args: &Args) -> String {
    args.module
        .clone()
        .or_else(|| args.process.clone())
        .unwrap_or_else(|| "MapleStory.exe".to_string())
}

fn locator(args: &Args) -> Result<Locator, String> {
    if let Some(process) = &args.process {
        Ok(Locator::Name(process.clone()))
    } else if let Some(class) = &args.class {
        Ok(Locator::Class(class.clone()))
    } else {
        Err("specify --process <name> or --class <window-class> (see --help)".to_string())
    }
}

fn write_outputs(
    args: &Args,
    result: &ScanResult,
    module: &str,
    base: u64,
    stamp: Option<&BuildStamp>,
) -> Result<(), String> {
    std::fs::create_dir_all(&args.out)
        .map_err(|e| format!("create {}: {e}", args.out.display()))?;

    let header = stamp.map(BuildStamp::header_line);
    let update = args.out.join("update.txt");
    let contents = if args.ce {
        cheat_table(&result.findings, module)
    } else {
        plain_text(&result.findings, module, base, header.as_deref())
    };
    std::fs::write(&update, contents).map_err(|e| format!("write {}: {e}", update.display()))?;
    println!("[+] wrote {}", update.display());

    if args.offsets {
        let header = args.out.join("offsets.h");
        std::fs::write(&header, offsets_header(&result.findings, module, base))
            .map_err(|e| format!("write {}: {e}", header.display()))?;
        println!("[+] wrote {}", header.display());
    }
    Ok(())
}

fn run() -> Result<(), String> {
    let args = parse_args()?;

    if args.mksig {
        return run_mksig(&args);
    }

    if let Some((old, new)) = &args.diff {
        let old_text =
            std::fs::read_to_string(old).map_err(|e| format!("read {}: {e}", old.display()))?;
        let new_text =
            std::fs::read_to_string(new).map_err(|e| format!("read {}: {e}", new.display()))?;
        print_build_compare(
            parse_stamp(&old_text).as_ref(),
            parse_stamp(&new_text).as_ref(),
        );
        print_diff(&diff(&parse_dump(&old_text), &parse_dump(&new_text)));
        return Ok(());
    }

    let patterns = if args.asm.is_none() {
        let parsed = parse_patterns_file_strict(&args.patterns, args.arch)
            .map_err(|e| format!("failed to read {}: {e}", args.patterns.display()))?;
        let parsed = match parsed {
            Ok(parsed) => parsed,
            Err(issues) => {
                for issue in &issues {
                    let tag = match issue.severity {
                        ParseSeverity::Error => "x",
                        ParseSeverity::Warning => "!",
                    };
                    eprintln!(
                        "[{tag}] {}:{} {}",
                        args.patterns.display(),
                        issue.line,
                        issue.message
                    );
                }
                let errors = issues
                    .iter()
                    .filter(|i| i.severity == ParseSeverity::Error)
                    .count();
                return Err(format!(
                    "{errors} pattern error(s) in {}",
                    args.patterns.display()
                ));
            }
        };
        for w in &parsed.warnings {
            eprintln!("[!] {}:{} {}", args.patterns.display(), w.line, w.message);
        }
        let patterns = parsed.patterns;
        if patterns.is_empty() {
            return Err(format!(
                "no patterns loaded from {}",
                args.patterns.display()
            ));
        }
        println!("[+] loaded {} patterns", patterns.len());
        if args.lint {
            print_lints(&patterns);
            return Ok(());
        }
        patterns
    } else {
        Vec::new()
    };

    let loc = locator(&args)?;
    let module = module_name(&args);
    let opts = AttachOptions {
        wait: args.wait,
        timeout: args.timeout,
        poll: Duration::from_millis(300),
    };
    if args.wait {
        let what = match &loc {
            Locator::Name(name) => format!("process {name}"),
            Locator::Class(class) => format!("window class {class}"),
        };
        println!("[*] waiting for {what} (Ctrl-C to cancel)...");
    }
    let cancel = AtomicBool::new(false);
    let target =
        Target::attach(&loc, &module, &opts, &cancel).map_err(|e| format!("attach failed: {e}"))?;
    println!(
        "[+] attached; module {} base 0x{:X} size 0x{:X}",
        module, target.module.base, target.module.size
    );

    if let Some(path) = &args.asm {
        let text =
            std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        let pat = parse_asm_patterns(&text)
            .ok_or_else(|| format!("no assembly lines in {}", path.display()))?;
        let from = parse_hex_opt(&args.from)?;
        let to = parse_hex_opt(&args.to)?;
        let regions = maple_core::memory::clip_regions(&target.code_regions(), from, to);
        println!("[+] assembly scan over {} regions", regions.len());
        let hits = assembly_scan(
            &target,
            target.module.base,
            &regions,
            args.arch,
            &pat,
            &cancel,
        );
        println!("[+] {} matches", hits.len());
        for h in &hits {
            let bytes = h
                .bytes
                .iter()
                .map(|b| format!("{b:02X} "))
                .collect::<String>();
            println!("  0x{:X} (+0x{:X})  {}", h.address, h.rva, bytes.trim_end());
            for line in &h.lines {
                println!("      {line}");
            }
        }
        return Ok(());
    }

    if args.profile {
        let regions = target.code_regions();
        println!(
            "[*] profiling {} executable regions (runs several full reads, give it a few seconds)...",
            regions.len()
        );
        let report = profile(
            &target,
            target.module.base,
            target.module.size,
            &regions,
            &patterns,
            args.arch,
        );
        print_profile(&report);
        return Ok(());
    }

    let regions = target.regions();
    println!("[+] scanning {} regions", regions.len());
    let result = scan(
        &target,
        target.module.base,
        target.module.size,
        &regions,
        &patterns,
        args.arch,
    );

    println!();
    println!("[+] found {}", result.found.len());
    if !result.matched_unresolved.is_empty() {
        println!(
            "[!] matched but unresolved: {}",
            result.matched_unresolved.len()
        );
        for name in &result.matched_unresolved {
            println!("    {name}");
        }
    }
    if !result.not_found.is_empty() {
        println!("[-] not found: {}", result.not_found.len());
        for name in &result.not_found {
            println!("    {name}");
        }
    }
    let ambiguous: Vec<_> = result
        .rows
        .iter()
        .filter(|r| matches!(r.status, FindingStatus::FoundAmbiguous { .. }))
        .collect();
    if !ambiguous.is_empty() {
        println!(
            "[!] ambiguous (multiple matches, used the first): {}",
            ambiguous.len()
        );
        for r in &ambiguous {
            println!("    {} ({} matches)", r.name, r.matches);
        }
    }
    println!("[+] total matches {}", result.total_matches);

    let mut stamp = BuildStamp::capture(&target, target.module.base, &target.code_regions());
    stamp.version = target.file_version();
    println!("[+] build {} ({} bytes)", stamp.short(), stamp.bytes);

    write_outputs(
        &args,
        &result,
        &module,
        target.module.base as u64,
        Some(&stamp),
    )
}

fn gbps(bytes: u64, ms: u128) -> f64 {
    if ms == 0 {
        return 0.0;
    }
    bytes as f64 / (ms as f64 / 1000.0) / 1_073_741_824.0
}

fn print_profile(r: &ProfileReport) {
    let mb = r.bytes as f64 / 1_048_576.0;
    println!();
    println!(
        "==== profile: {mb:.0} MB across {} executable regions | {} patterns | {} cores ====",
        r.regions, r.patterns, r.cores
    );
    println!();
    println!("read-only (cross-process copy, no scan):");
    for (readers, ms) in &r.read_ms {
        println!(
            "  {readers} reader(s): {ms:>6} ms  ({:.2} GB/s)",
            gbps(r.bytes, *ms)
        );
    }
    println!();
    println!("scan-only on a local buffer (no reads):");
    println!(
        "  serial  (1 thread)   : {:>6} ms  ({:.2} GB/s)",
        r.scan_serial_ms,
        gbps(r.bytes, r.scan_serial_ms)
    );
    println!(
        "  parallel ({:>2} cores)  : {:>6} ms  ({:.2} GB/s)",
        r.cores,
        r.scan_parallel_ms,
        gbps(r.bytes, r.scan_parallel_ms)
    );
    println!("  matches: {}", r.matches);
    println!();
    println!(
        "resolve-only           : {:>6} ms  (_CALL hits doing extra reads: {})",
        r.resolve_ms, r.call_hits
    );
    println!();
    println!("full pipeline (read + scan + resolve overlapped):");
    println!(
        "  default chunk        : {:>6} ms  ({:.2} GB/s end-to-end)",
        r.full_ms,
        gbps(r.bytes, r.full_ms)
    );
    println!("  chunk-size sweep:");
    for (size, ms) in &r.chunk_ms {
        println!("    {:>5} KiB: {ms:>6} ms", size >> 10);
    }
    println!();
    let read1 = r.read_ms.first().map_or(0, |&(_, ms)| ms);
    println!(
        "verdict: read(1) {read1} ms | scan(parallel) {} ms | resolve {} ms | full {} ms",
        r.scan_parallel_ms, r.resolve_ms, r.full_ms
    );
    if r.full_ms > 0 && read1 as f64 >= 0.80 * r.full_ms as f64 {
        println!(
            "         read-bound: the read alone is ~{:.0}% of the full pipeline; the scan hides under it.",
            100.0 * read1 as f64 / r.full_ms as f64
        );
    } else {
        println!(
            "         not purely read-bound: scan/resolve are a meaningful fraction, so matcher work may pay off."
        );
    }
}

fn print_build_compare(old: Option<&BuildStamp>, new: Option<&BuildStamp>) {
    if let (Some(a), Some(b)) = (old, new) {
        let state = if a.hash == b.hash { "same" } else { "changed" };
        println!("[i] build {} -> {} ({state})", a.short(), b.short());
        if a.version.is_some() || b.version.is_some() {
            println!(
                "    version {} -> {}",
                a.version.as_deref().unwrap_or("?"),
                b.version.as_deref().unwrap_or("?")
            );
        }
    }
}

fn print_lints(patterns: &[Pattern]) {
    let mut flagged = 0;
    for p in patterns {
        let lints = lint(&p.signature);
        if lints.is_empty() {
            continue;
        }
        flagged += 1;
        println!("[!] {}", p.name);
        for l in &lints {
            println!("      {}", l.message());
        }
    }
    println!();
    println!(
        "[+] {} patterns, {flagged} flagged, {} clean",
        patterns.len(),
        patterns.len() - flagged
    );
}

fn print_diff(report: &DiffReport) {
    println!("[=] {} unchanged", report.unchanged);
    if !report.moved.is_empty() {
        println!("[~] {} moved:", report.moved.len());
        for m in &report.moved {
            println!("      {} 0x{:X} -> 0x{:X}", m.name, m.old, m.new);
        }
    }
    if !report.added.is_empty() {
        println!("[+] {} new:", report.added.len());
        for f in &report.added {
            println!("      {} 0x{:X}", f.name, f.value);
        }
    }
    if !report.removed.is_empty() {
        println!("[-] {} removed:", report.removed.len());
        for f in &report.removed {
            println!("      {} 0x{:X}", f.name, f.value);
        }
    }
}

fn arch_str(arch: Arch) -> &'static str {
    if matches!(arch, Arch::X64) {
        "x64"
    } else {
        "x86"
    }
}

fn kind_str(kind: TargetKind) -> &'static str {
    match kind {
        TargetKind::Code => "code",
        TargetKind::Data => "data",
        TargetKind::Import => "import",
        TargetKind::Unknown => "unknown",
    }
}

fn file_label(path: &std::path::Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string())
}

fn collect_clients(args: &Args) -> Result<Vec<PathBuf>, String> {
    let mut clients = args.clients.clone();
    if let Some(dir) = &args.client_dir {
        let rd = std::fs::read_dir(dir).map_err(|e| format!("read dir {}: {e}", dir.display()))?;
        for entry in rd.flatten() {
            let p = entry.path();
            if p.extension().is_some_and(|x| x.eq_ignore_ascii_case("exe")) {
                clients.push(p);
            }
        }
    }
    if let Some(r) = &args.ref_path {
        clients.push(r.clone());
    }
    clients.sort();
    clients.dedup();
    if clients.is_empty() {
        return Err("--mksig needs at least one --client or --client-dir".to_string());
    }
    Ok(clients)
}

#[derive(Serialize)]
struct JPer {
    label: String,
    match_rva: Option<String>,
    resolved_target_rva: Option<String>,
    target_type: Option<String>,
}
#[derive(Serialize)]
struct JCand {
    aob: String,
    suffix: String,
    grade: String,
    bytes: usize,
    fixed: usize,
    wildcards: usize,
    fixed_ratio: f64,
    reloc_safe: bool,
    per_version: Vec<JPer>,
    diags: Vec<String>,
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
struct JReport {
    arch: String,
    unique_builds: usize,
    inputs: Vec<JInput>,
    duplicate_groups: Vec<JDup>,
    chosen: Option<JCand>,
    alternates: Vec<JCand>,
    rejected: Vec<JCand>,
    diagnostics: Vec<String>,
}

fn jcand(c: &SigCandidate) -> JCand {
    JCand {
        aob: c.aob.clone(),
        suffix: c.suffix.as_str().to_string(),
        grade: c.grade.letter().to_string(),
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
                target_type: p.target_kind.map(|k| kind_str(k).to_string()),
            })
            .collect(),
        diags: c.diags.iter().map(|d| d.to_string()).collect(),
    }
}

fn json_report(r: &SigReport) -> String {
    let report = JReport {
        arch: arch_str(r.arch).to_string(),
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
        diagnostics: r.diagnostics.iter().map(|d| d.to_string()).collect(),
    };
    serde_json::to_string_pretty(&report).unwrap_or_default()
}

fn print_candidate(tag: &str, c: &SigCandidate) {
    println!(
        "[{tag}] grade {} {}{}",
        c.grade.letter(),
        c.aob,
        c.suffix.as_str()
    );
    println!(
        "      {} bytes, {} fixed, {} wild, ratio {:.2}, reloc_safe {}",
        c.bytes_len, c.fixed, c.wildcards, c.fixed_ratio, c.reloc_safe
    );
    for p in &c.per_version {
        let m = p
            .match_rva
            .map_or_else(|| "-".to_string(), |v| format!("0x{v:X}"));
        let t = p
            .resolved_target_rva
            .map_or_else(String::new, |v| format!(" -> 0x{v:X}"));
        println!("        {} @ {m}{t}", p.label);
    }
    for d in &c.diags {
        println!("        ! {d}");
    }
}

fn print_sig_report(r: &SigReport, opts: &SigOptions) {
    println!(
        "[+] arch {} | {} unique build(s)",
        arch_str(r.arch),
        r.unique_builds
    );
    println!(
        "    gates: min_fixed {}, min_fixed_ratio {:.2}, max_len {}",
        opts.min_fixed, opts.min_fixed_ratio, opts.max_len
    );
    for g in &r.duplicate_groups {
        if g.labels.len() > 1 {
            println!(
                "    duplicate build {:016X}: {}",
                g.code_hash,
                g.labels.join(", ")
            );
        }
    }
    match &r.chosen {
        Some(c) => print_candidate("chosen", c),
        None => println!("[-] no safe signature found"),
    }
    for c in &r.alternates {
        print_candidate("alt", c);
    }
    for c in &r.rejected {
        print_candidate("rejected", c);
    }
    for d in &r.diagnostics {
        println!("    note: {d}");
    }
}

fn run_mksig(args: &Args) -> Result<(), String> {
    let clients = collect_clients(args)?;
    let has_sig = args.sig.is_some();
    let has_ref = args.ref_path.is_some() || args.rva.is_some();
    if has_sig == has_ref {
        return Err("provide exactly one of --sig OR (--ref + --rva)".to_string());
    }
    if let Some(aob) = &args.sig {
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

    let spec = if let Some(aob) = &args.sig {
        TargetSpec::Aob(aob.clone())
    } else {
        let rva = parse_hex_opt(&args.rva)?.ok_or("--rva <hex> is required with --ref")? as u64;
        let ref_path = args.ref_path.as_ref().ok_or("--ref <exe> is required")?;
        let idx = clients
            .iter()
            .position(|c| c == ref_path)
            .ok_or("the --ref file was not opened as a client")?;
        TargetSpec::Ref { image: idx, rva }
    };

    let mut opts = SigOptions::default();
    if let Some(r) = args.min_fixed_ratio {
        opts.min_fixed_ratio = r;
    }

    let report = generate(&inputs, &spec, &opts);

    if args.json || args.json_out.is_some() {
        let json = json_report(&report);
        if let Some(path) = &args.json_out {
            std::fs::write(path, &json).map_err(|e| format!("write {}: {e}", path.display()))?;
            println!("[+] wrote {}", path.display());
        }
        if args.json {
            println!("{json}");
        }
    } else {
        print_sig_report(&report, &opts);
    }
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("[error] {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use maple_core::{Grade, PerVersion, Suffix};

    #[test]
    fn json_includes_ptr_target_fields() {
        let cand = SigCandidate {
            aob: "48 8D 05 ?? ?? ?? ??".to_string(),
            suffix: Suffix::Ptr,
            grade: Grade::A,
            bytes_len: 7,
            fixed: 3,
            wildcards: 4,
            fixed_ratio: 0.42,
            reloc_safe: true,
            per_version: vec![PerVersion {
                label: "a.exe".to_string(),
                match_rva: Some(0x20),
                resolved_target_rva: Some(0x1000),
                target_kind: Some(TargetKind::Code),
            }],
            diags: Vec::new(),
        };
        let report = SigReport {
            arch: Arch::X64,
            inputs: Vec::new(),
            unique_builds: 1,
            duplicate_groups: Vec::new(),
            chosen: Some(cand.clone()),
            alternates: vec![cand.clone()],
            rejected: vec![cand],
            diagnostics: Vec::new(),
        };
        let json = json_report(&report);
        // present for chosen + one alternate + one rejected
        assert_eq!(
            json.matches("\"resolved_target_rva\": \"0x1000\"").count(),
            3
        );
        assert_eq!(json.matches("\"target_type\": \"code\"").count(), 3);
    }
}
