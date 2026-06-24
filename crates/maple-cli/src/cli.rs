use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "mapledumper",
    version,
    about = "AOB/pattern scanner and offset dumper for Windows processes",
    subcommand_required = true,
    arg_required_else_help = true
)]
pub(crate) struct Cli {
    /// Config file of defaults (key = value); falls back to maple.conf in the working directory
    #[arg(long, global = true, value_name = "FILE")]
    pub(crate) config: Option<PathBuf>,
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Subcommand)]
pub(crate) enum Command {
    /// Attach to a process and dump offsets from a pattern file
    Scan(ScanArgs),
    /// Check a pattern file for weak signatures
    Lint(LintArgs),
    /// Compare two saved dumps and report what moved
    Diff(DiffArgs),
    /// Scan a live process by assembly instructions
    Asm(AsmArgs),
    /// Build a cross-version signature from client files on disk, no target needed
    Mksig(MksigArgs),
    /// Measure the read/scan/resolve split against a live target
    Profile(ProfileArgs),
    /// Unpack a Themida-packed client to a clean binary, or clean an existing dump
    Unpack(UnpackArgs),
}

#[derive(Args)]
pub(crate) struct AttachArgs {
    /// Attach by process name (.exe optional, case-insensitive)
    #[arg(long, value_name = "NAME")]
    pub(crate) process: Option<String>,
    /// Attach by top-level window class
    #[arg(long, value_name = "CLASS", conflicts_with = "process")]
    pub(crate) class: Option<String>,
    /// Attach by process id (use when several processes share a name)
    #[arg(long, value_name = "PID")]
    pub(crate) pid: Option<u32>,
    /// Module to scan (default: the process name)
    #[arg(long, value_name = "NAME")]
    pub(crate) module: Option<String>,
    /// Fail immediately if the target is not running
    #[arg(long)]
    pub(crate) no_wait: bool,
    /// Max seconds to wait for the target (0 = forever)
    #[arg(long, value_name = "SECS")]
    pub(crate) timeout: Option<u64>,
}

#[derive(Args)]
pub(crate) struct ScanArgs {
    #[command(flatten)]
    pub(crate) attach: AttachArgs,
    /// Pattern file (default: patterns.txt)
    #[arg(long, value_name = "FILE")]
    pub(crate) patterns: Option<PathBuf>,
    /// Architecture section to load (32 or 64)
    #[arg(long, value_name = "BITS")]
    pub(crate) arch: Option<String>,
    /// Output directory, created if missing (default: .)
    #[arg(long, value_name = "DIR")]
    pub(crate) out: Option<PathBuf>,
    /// Write update.txt as a Cheat Engine table
    #[arg(long)]
    pub(crate) ce: bool,
    /// Do not write offsets.h
    #[arg(long)]
    pub(crate) no_offsets: bool,
    /// Accept malformed pattern lines instead of failing (power-user opt-in)
    #[arg(long)]
    pub(crate) lenient: bool,
    /// Emit the scan result as JSON on stdout (progress goes to stderr)
    #[arg(long)]
    pub(crate) json: bool,
}

#[derive(Args)]
pub(crate) struct LintArgs {
    /// Pattern file (default: patterns.txt)
    #[arg(long, value_name = "FILE")]
    pub(crate) patterns: Option<PathBuf>,
    /// Architecture section to load (32 or 64)
    #[arg(long, value_name = "BITS")]
    pub(crate) arch: Option<String>,
    /// Accept malformed pattern lines instead of failing
    #[arg(long)]
    pub(crate) lenient: bool,
    /// Emit the lint result as JSON on stdout
    #[arg(long)]
    pub(crate) json: bool,
}

#[derive(Args)]
pub(crate) struct DiffArgs {
    /// The older dump file
    #[arg(value_name = "OLD")]
    pub(crate) old: PathBuf,
    /// The newer dump file
    #[arg(value_name = "NEW")]
    pub(crate) new: PathBuf,
}

#[derive(Args)]
pub(crate) struct UnpackArgs {
    /// Input binary: a packed client (full flow) or a raw dump (with --clean-only)
    #[arg(value_name = "INPUT")]
    pub(crate) input: PathBuf,
    /// Output path for the cleaned binary
    #[arg(short = 'o', long, value_name = "PATH")]
    pub(crate) out: PathBuf,
    /// Skip the dynamic dump step; INPUT is already an unlicense dump
    #[arg(long)]
    pub(crate) clean_only: bool,
    /// The packed original, for the strong .text-identity proof in --clean-only mode
    #[arg(long, value_name = "EXE")]
    pub(crate) packed: Option<PathBuf>,
    /// Path to unlicense.exe (default: beside the packed exe, then PATH)
    #[arg(long, value_name = "EXE")]
    pub(crate) unlicense: Option<PathBuf>,
    /// Use the bundled native unpacker (maple-unpack-native) for the dump step instead of unlicense
    #[arg(long)]
    pub(crate) native: bool,
    /// Path to maple-unpack-native (default: beside this exe, then PATH)
    #[arg(long, value_name = "EXE")]
    pub(crate) native_bin: Option<PathBuf>,
    /// Keep the dump host's bound import addresses instead of unbinding the IAT
    #[arg(long)]
    pub(crate) keep_bound_iat: bool,
    /// Keep the COFF TimeDateStamp instead of zeroing it
    #[arg(long)]
    pub(crate) keep_timestamp: bool,
    /// Print the full report as JSON on stdout
    #[arg(long)]
    pub(crate) json: bool,
}

#[derive(Args)]
pub(crate) struct AsmArgs {
    #[command(flatten)]
    pub(crate) attach: AttachArgs,
    /// Assembly file, one instruction per line, wildcards * ? ^ $
    #[arg(value_name = "FILE")]
    pub(crate) file: PathBuf,
    /// Architecture section to load (32 or 64)
    #[arg(long, value_name = "BITS")]
    pub(crate) arch: Option<String>,
    /// Only report matches at or above this address (hex)
    #[arg(long, value_name = "ADDR")]
    pub(crate) from: Option<String>,
    /// Only report matches below this address (hex)
    #[arg(long, value_name = "ADDR")]
    pub(crate) to: Option<String>,
}

#[derive(Args)]
pub(crate) struct MksigArgs {
    /// A client binary (repeat for each version)
    #[arg(long = "client", value_name = "EXE")]
    pub(crate) client: Vec<PathBuf>,
    /// Add every .exe in a folder as a client
    #[arg(long, value_name = "DIR")]
    pub(crate) client_dir: Option<PathBuf>,
    /// Target: locate this existing AOB in each client and harden it
    #[arg(long, value_name = "AOB")]
    pub(crate) sig: Option<String>,
    /// Target: a reference client, paired with --rva
    #[arg(long = "ref", value_name = "EXE")]
    pub(crate) ref_path: Option<PathBuf>,
    /// Target: an address in the reference client (hex)
    #[arg(long, value_name = "HEX")]
    pub(crate) rva: Option<String>,
    /// Reject signatures below this fixed-byte ratio (default 0.30)
    #[arg(long, value_name = "F")]
    pub(crate) min_fixed_ratio: Option<f64>,
    /// An unrelated module the chosen signature must NOT match (repeatable)
    #[arg(long = "negative", value_name = "EXE")]
    pub(crate) negative: Vec<PathBuf>,
    /// Add every .exe in a folder to the negative corpus
    #[arg(long, value_name = "DIR")]
    pub(crate) negative_dir: Option<PathBuf>,
    /// Leave-one-out check: regenerate from each subset and confirm the held-out build still matches
    #[arg(long)]
    pub(crate) holdout: bool,
    /// Print the full report as JSON
    #[arg(long)]
    pub(crate) json: bool,
    /// Write the JSON report to a file
    #[arg(long, value_name = "PATH")]
    pub(crate) json_out: Option<PathBuf>,
}

#[derive(Args)]
pub(crate) struct ProfileArgs {
    #[command(flatten)]
    pub(crate) attach: AttachArgs,
    /// Pattern file (default: patterns.txt)
    #[arg(long, value_name = "FILE")]
    pub(crate) patterns: Option<PathBuf>,
    /// Architecture section to load (32 or 64)
    #[arg(long, value_name = "BITS")]
    pub(crate) arch: Option<String>,
    /// Accept malformed pattern lines instead of failing
    #[arg(long)]
    pub(crate) lenient: bool,
}
