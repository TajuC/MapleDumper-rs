use std::path::Path;

use maple_core::{CleanOptions, Progress, clean_to_path, unpack_to_path};

use crate::cli::UnpackArgs;
use crate::exit::{CliError, ExitKind, unpack_err};
use crate::json::to_json_pretty;
use crate::report::{print_unpack_report, stage_label};

/// Drive the bundled native unpacker for the full packed-to-min flow through the engine, which runs
/// the dump, the static clean, and the verification gates and writes the output only if every gate
/// passes. Routed through `maple_core` so the CLI and GUI share one locate-spawn-parse path.
pub(crate) fn cmd_unpack_native(a: &UnpackArgs) -> Result<ExitKind, CliError> {
    let mut on = |p: Progress| match p {
        Progress::Stage(s) => eprintln!("[unpack] {}", stage_label(s)),
        Progress::Line(l) => eprintln!("    {l}"),
    };
    let report = maple_core::run_native_dumper(&a.input, &a.out, a.native_bin.as_deref(), &mut on)
        .map_err(unpack_err)?;
    if a.json {
        println!("{}", to_json_pretty(&report)?);
    } else {
        print_unpack_report(&report);
    }
    if !report.gates_pass {
        return Err(CliError::new(
            ExitKind::Unresolved,
            "verification gates failed; no binary was written",
        ));
    }
    Ok(if report.verify.warnings.is_empty() {
        ExitKind::Success
    } else {
        ExitKind::SuccessWithWarnings
    })
}

pub(crate) fn cmd_unpack(a: UnpackArgs) -> Result<ExitKind, CliError> {
    if !a.input.is_file() {
        return Err(CliError::new(
            ExitKind::InvalidInput,
            format!("input not found: {}", a.input.display()),
        ));
    }
    if a.native {
        return cmd_unpack_native(&a);
    }
    if let Some(p) = &a.packed
        && !p.is_file()
    {
        return Err(CliError::new(
            ExitKind::InvalidInput,
            format!("packed reference not found: {}", p.display()),
        ));
    }
    // Refuse a destructive --out: the engine reads the source fully before writing, so pointing
    // --out at the input, the packed reference, or the intermediate dump would silently destroy it.
    let same = |x: &Path, y: &Path| match (std::fs::canonicalize(x), std::fs::canonicalize(y)) {
        (Ok(a), Ok(b)) => a == b,
        _ => x == y,
    };
    if same(&a.out, &a.input) {
        return Err(CliError::new(
            ExitKind::InvalidInput,
            "refusing to overwrite the input with --out",
        ));
    }
    if let Some(p) = &a.packed
        && same(&a.out, p)
    {
        return Err(CliError::new(
            ExitKind::InvalidInput,
            "refusing to overwrite the packed reference with --out",
        ));
    }
    if !a.clean_only
        && let Some(name) = a.input.file_name()
    {
        let dir = a
            .input
            .parent()
            .filter(|d| !d.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let dump = dir.join(format!("unpacked_{}", name.to_string_lossy()));
        if same(&a.out, &dump) {
            return Err(CliError::new(
                ExitKind::InvalidInput,
                "refusing to overwrite the intermediate dump with --out",
            ));
        }
    }
    let opts = CleanOptions {
        unbind_iat: !a.keep_bound_iat,
        zero_timestamp: !a.keep_timestamp,
    };
    let mut on = |p: Progress| match p {
        Progress::Stage(s) => eprintln!("[unpack] {}", stage_label(s)),
        Progress::Line(l) => eprintln!("    {l}"),
    };

    let report = if a.clean_only {
        clean_to_path(&a.input, &a.out, &opts, a.packed.as_deref(), &mut on)
    } else {
        if a.packed.is_some() {
            eprintln!(
                "[!] --packed is only used with --clean-only; the input is the packed original here"
            );
        }
        unpack_to_path(&a.input, &a.out, &opts, a.unlicense.as_deref(), &mut on)
    }
    .map_err(unpack_err)?;

    if a.json {
        println!("{}", to_json_pretty(&report)?);
    } else {
        print_unpack_report(&report);
    }

    if !report.gates_pass {
        return Err(CliError::new(
            ExitKind::Unresolved,
            "verification gates failed; no binary was written",
        ));
    }
    Ok(if report.verify.warnings.is_empty() {
        ExitKind::Success
    } else {
        ExitKind::SuccessWithWarnings
    })
}
