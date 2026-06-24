use maple_core::{
    BuildStamp, DiffReport, Pattern, ProfileReport, SigCandidate, SigOptions, SigReport, Stage,
    UnpackReport, lint,
};

pub(crate) fn stage_label(s: Stage) -> &'static str {
    match s {
        Stage::Locate => "locating dumper",
        Stage::Dump => "dumping (unlicense)",
        Stage::Clean => "cleaning",
        Stage::Verify => "verifying",
        Stage::Done => "done",
    }
}

fn mark(ok: bool) -> &'static str {
    if ok { "PASS" } else { "FAIL" }
}

pub(crate) fn print_unpack_report(r: &UnpackReport) {
    let v = &r.verify;
    println!("input    {}", r.input);
    if let Some(d) = &r.dump_path {
        println!("dump     {d}");
    }
    match &r.output {
        Some(o) => println!("output   {o}"),
        None => println!("output   (not written: gates failed)"),
    }
    println!("size     {} bytes", v.output_size);
    println!();
    println!(
        "  OEP            rva {:#x}  {}",
        v.oep_rva,
        if v.oep_is_msvc {
            "MSVC prologue"
        } else {
            "non-standard prologue"
        }
    );
    for line in &v.oep_disasm {
        println!("                 {line}");
    }
    println!(
        "  imports        {} DLLs / {} functions  {}",
        v.import_dlls,
        v.import_functions,
        mark(v.imports_ok)
    );
    println!(
        "  .pdata         {} entries  valid {:.2}%  ascending {:.2}%  {}",
        v.pdata_entries,
        v.pdata_valid_pct,
        v.pdata_ascending_pct,
        mark(v.pdata_ok)
    );
    println!(
        "  virtualization {:.4}% of {} sampled starts",
        v.virtualization_pct, v.virtualization_sampled
    );
    match v.text_identity {
        Some(true) => println!(
            "  .text identity PASS (vs {})",
            v.text_ref.as_deref().unwrap_or("reference")
        ),
        Some(false) => println!(
            "  .text identity FAIL (vs {})",
            v.text_ref.as_deref().unwrap_or("reference")
        ),
        None => println!("  .text identity n/a (no reference supplied)"),
    }
    if let Some(sha) = &v.text_sha256 {
        println!("  .text sha256   {sha}");
    }
    for w in &v.warnings {
        eprintln!("[!] {w}");
    }
    println!();
    println!(
        "==> {}",
        if r.gates_pass {
            "GATES PASS"
        } else {
            "GATES FAILED"
        }
    );
}

fn gbps(bytes: u64, ms: u128) -> f64 {
    if ms == 0 {
        return 0.0;
    }
    bytes as f64 / (ms as f64 / 1000.0) / 1_073_741_824.0
}

pub(crate) fn print_profile(r: &ProfileReport) {
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
        "  serial  (1 thread)   : {:>6} ms  ({:.2} GB/s)  [single-thread baseline; the real",
        r.scan_serial_ms,
        gbps(r.bytes, r.scan_serial_ms)
    );
    println!("                          parallel scan is measured in the full pipeline below]");
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
        "verdict: read(1) {read1} ms | scan(serial) {} ms | resolve {} ms | full {} ms",
        r.scan_serial_ms, r.resolve_ms, r.full_ms
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

pub(crate) fn print_build_compare(old: Option<&BuildStamp>, new: Option<&BuildStamp>) {
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

pub(crate) fn print_lints(patterns: &[Pattern]) -> usize {
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
    flagged
}

pub(crate) fn print_diff(report: &DiffReport) {
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

fn print_candidate(tag: &str, c: &SigCandidate) {
    println!(
        "[{tag}] grade {} {}{}",
        c.grade.letter(),
        c.aob,
        c.suffix.as_str()
    );
    println!(
        "      score {} (final), {} bytes, {} fixed, {} wild, ratio {:.2}, reloc_safe {}",
        c.score, c.bytes_len, c.fixed, c.wildcards, c.fixed_ratio, c.reloc_safe
    );
    let s = &c.scores;
    println!(
        "      sub-scores: uniqueness {} stability {} entropy {} semantic {} resolver {} cross-build {}",
        s.uniqueness, s.stability, s.entropy, s.semantic, s.resolver_confidence, s.cross_build
    );
    for p in &c.per_version {
        let m = p
            .match_rva
            .map_or_else(|| "-".to_string(), |v| format!("0x{v:X}"));
        let t = p
            .resolved_target_rva
            .map_or_else(String::new, |v| format!(" -> 0x{v:X}"));
        let sim = p
            .fingerprint_similarity
            .map_or_else(String::new, |v| format!(" (callee ~{:.0}%)", v * 100.0));
        println!("        {} @ {m}{t}{sim}", p.label);
    }
    for r in &c.reasons {
        println!("        - {r}");
    }
    for d in &c.diags {
        println!("        ! {d}");
    }
}

pub(crate) fn print_sig_report(r: &SigReport, opts: &SigOptions) {
    println!(
        "[+] arch {} | {} unique build(s)",
        r.arch.label(),
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
    if !r.aob_ranges.is_empty() {
        println!("    version coverage (a fresh AOB is minted where the bytes break):");
        for rg in &r.aob_ranges {
            let span = if rg.first_label == rg.last_label {
                rg.first_label.clone()
            } else {
                format!("{} .. {}", rg.first_label, rg.last_label)
            };
            println!("      {span}  ({} build(s)):  {}", rg.labels.len(), rg.aob);
        }
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
