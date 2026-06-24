mod attach;
mod cli;
mod commands;
mod config;
mod exit;
mod json;
mod patterns;
mod report;

#[cfg(test)]
mod tests;

use std::process::ExitCode;

use clap::Parser;

use crate::cli::{Cli, Command};
use crate::config::resolve_config;
use crate::exit::{CliError, ExitKind};

fn run() -> Result<ExitKind, CliError> {
    let cli = Cli::parse();
    let cfg = resolve_config(cli.config.as_deref())?;
    match cli.command {
        Command::Scan(a) => commands::scan::cmd_scan(a, &cfg),
        Command::Lint(a) => commands::lint::cmd_lint(a, &cfg),
        Command::Diff(a) => commands::diff::cmd_diff(a),
        Command::Asm(a) => commands::asm::cmd_asm(a, &cfg),
        Command::Mksig(a) => commands::mksig::cmd_mksig(a),
        Command::Profile(a) => commands::profile::cmd_profile(a, &cfg),
        Command::Unpack(a) => commands::unpack::cmd_unpack(a),
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(kind) => ExitCode::from(kind.code()),
        Err(e) => {
            eprintln!("[error] {}", e.msg);
            ExitCode::from(e.kind.code())
        }
    }
}
