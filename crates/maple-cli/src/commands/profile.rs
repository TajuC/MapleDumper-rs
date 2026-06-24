use std::sync::atomic::AtomicBool;

use maple_core::{arch_mismatch, profile};

use crate::attach::attach_target;
use crate::cli::ProfileArgs;
use crate::config::{Config, resolve_arch, resolve_attach, resolve_patterns, resolve_strict};
use crate::exit::{CliError, ExitKind};
use crate::patterns::require_patterns;
use crate::report::print_profile;

pub(crate) fn cmd_profile(a: ProfileArgs, cfg: &Config) -> Result<ExitKind, CliError> {
    let arch = resolve_arch(a.arch.as_deref(), cfg)?;
    let patterns_path = resolve_patterns(a.patterns.as_ref(), cfg);
    let strict = resolve_strict(a.lenient, cfg);
    let patterns = require_patterns(&patterns_path, arch, strict, false)?;

    let at = resolve_attach(&a.attach, cfg);
    let cancel = AtomicBool::new(false);
    let target = attach_target(&at, &cancel, false)?;
    if let Some(msg) = arch_mismatch(arch, target.module_arch(), &at.module) {
        return Err(CliError::new(ExitKind::InvalidInput, msg));
    }

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
        arch,
    );
    print_profile(&report);
    Ok(ExitKind::Success)
}
