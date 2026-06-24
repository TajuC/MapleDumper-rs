use std::sync::atomic::AtomicBool;

use maple_core::{arch_mismatch, assembly_scan, parse_asm_patterns};

use crate::attach::attach_target;
use crate::cli::AsmArgs;
use crate::config::{Config, parse_hex_opt, resolve_arch, resolve_attach};
use crate::exit::{CliError, ExitKind};

pub(crate) fn cmd_asm(a: AsmArgs, cfg: &Config) -> Result<ExitKind, CliError> {
    let arch = resolve_arch(a.arch.as_deref(), cfg)?;
    let at = resolve_attach(&a.attach, cfg);
    let cancel = AtomicBool::new(false);
    let target = attach_target(&at, &cancel, false)?;
    if let Some(msg) = arch_mismatch(arch, target.module_arch(), &at.module) {
        return Err(CliError::new(ExitKind::InvalidInput, msg));
    }

    let text =
        std::fs::read_to_string(&a.file).map_err(|e| format!("read {}: {e}", a.file.display()))?;
    let pat = parse_asm_patterns(&text)
        .ok_or_else(|| format!("no assembly lines in {}", a.file.display()))?;
    let from = parse_hex_opt(&a.from)?;
    let to = parse_hex_opt(&a.to)?;
    let regions = maple_core::memory::clip_regions(&target.code_regions(), from, to);
    println!("[+] assembly scan over {} regions", regions.len());
    let scan = assembly_scan(&target, target.module.base, &regions, arch, &pat, &cancel);
    if let Some(w) = maple_core::read_gap_warning(&scan.read_gaps) {
        eprintln!("[warn] {w}");
    }
    let hits = scan.hits;
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
    Ok(ExitKind::Success)
}
