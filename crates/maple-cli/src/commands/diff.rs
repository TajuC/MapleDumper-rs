use maple_core::{diff, parse_dump, parse_stamp};

use crate::cli::DiffArgs;
use crate::exit::{CliError, ExitKind};
use crate::report::{print_build_compare, print_diff};

pub(crate) fn cmd_diff(a: DiffArgs) -> Result<ExitKind, CliError> {
    let old_text =
        std::fs::read_to_string(&a.old).map_err(|e| format!("read {}: {e}", a.old.display()))?;
    let new_text =
        std::fs::read_to_string(&a.new).map_err(|e| format!("read {}: {e}", a.new.display()))?;
    let old = parse_dump(&old_text);
    let new = parse_dump(&new_text);
    // A file with content but no parseable lines is almost always the wrong file or format; fail
    // clearly instead of printing an empty diff and exiting success.
    if old.is_empty() && old_text.split_whitespace().next().is_some() {
        return Err(CliError::new(
            ExitKind::InvalidInput,
            format!(
                "{} has content but no parseable dump lines (expected `[category] name = 0x...`)",
                a.old.display()
            ),
        ));
    }
    if new.is_empty() && new_text.split_whitespace().next().is_some() {
        return Err(CliError::new(
            ExitKind::InvalidInput,
            format!(
                "{} has content but no parseable dump lines (expected `[category] name = 0x...`)",
                a.new.display()
            ),
        ));
    }
    print_build_compare(
        parse_stamp(&old_text).as_ref(),
        parse_stamp(&new_text).as_ref(),
    );
    let report = diff(&old, &new);
    for w in &report.warnings {
        eprintln!("[!] {w}");
    }
    print_diff(&report);
    Ok(ExitKind::Success)
}
