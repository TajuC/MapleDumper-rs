//! `maple-unpack-native <packed.exe> <out_clean> [timeout_secs]`: unpack a Themida 3.x x64 client
//! to a clean, verified min. It spawns and instruments the client, recovers the OEP and imports,
//! reconstructs the PE, then runs the project's static clean + verification gates and writes the
//! output only if every gate passes.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use maple_unpack_native::{StderrProgress, dump_packed};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: maple-unpack-native <packed.exe> <out_clean> [timeout_secs]");
        return ExitCode::from(5);
    }
    let packed = PathBuf::from(&args[1]);
    let out = PathBuf::from(&args[2]);
    let secs: u64 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(180);

    let mut progress = StderrProgress;
    match dump_packed(&packed, &out, Duration::from_secs(secs), &mut progress) {
        Ok(report) => {
            eprintln!(
                "[native-unpack] OEP={:#x} base={:#x} imports={} dlls={} fns={} pdata={} text_identity={:?} size={} gates={}",
                report.oep_rva,
                report.image_base,
                report.resolved_imports,
                report.import_dlls,
                report.import_functions,
                report.pdata_entries,
                report.text_identity,
                report.output_size,
                report.gates_pass,
            );
            match serde_json::to_string(&report.unpack) {
                Ok(json) => {
                    println!("{json}");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("error: could not serialize the report: {e}");
                    ExitCode::from(1)
                }
            }
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(1)
        }
    }
}
