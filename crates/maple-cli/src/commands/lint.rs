use maple_core::lint;

use crate::cli::LintArgs;
use crate::config::{Config, resolve_arch, resolve_patterns, resolve_strict};
use crate::exit::{CliError, ExitKind};
use crate::json::{LintJson, to_json_pretty};
use crate::patterns::require_patterns;
use crate::report::print_lints;

pub(crate) fn cmd_lint(a: LintArgs, cfg: &Config) -> Result<ExitKind, CliError> {
    let arch = resolve_arch(a.arch.as_deref(), cfg)?;
    let patterns_path = resolve_patterns(a.patterns.as_ref(), cfg);
    let strict = resolve_strict(a.lenient, cfg);
    let patterns = require_patterns(&patterns_path, arch, strict, a.json)?;
    let flagged = if a.json {
        let report: Vec<LintJson> = patterns
            .iter()
            .map(|p| LintJson {
                name: p.name.clone(),
                aob: p.signature.to_aob(),
                lints: lint(&p.signature).iter().map(|l| l.message()).collect(),
            })
            .collect();
        let flagged = report.iter().filter(|r| !r.lints.is_empty()).count();
        println!("{}", to_json_pretty(&report)?);
        flagged
    } else {
        print_lints(&patterns)
    };
    Ok(if flagged > 0 {
        ExitKind::SuccessWithWarnings
    } else {
        ExitKind::Success
    })
}
