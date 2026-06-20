//! The Unpack command: drive the maple-core pipeline (dump with unlicense, then the static
//! clean, then the gates) and stream stage and dumper-line progress to the panel as
//! `unpack-progress` events. The binary is written by the engine only when every gate passes.
//!
//! The `native` path instead drives the bundled `maple-unpack-native` dumper (a native Frida +
//! Unicorn port of unlicense). It emits the same `UnpackReport` on stdout, so the results card and
//! progress events are identical to the unlicense path with no second report shape to maintain.

use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use maple_core::{CleanOptions, Progress, Stage, UnpackReport, clean_to_path, unpack_to_path};
use tauri::Emitter;

fn stage_str(s: Stage) -> &'static str {
    match s {
        Stage::Locate => "locate",
        Stage::Dump => "dump",
        Stage::Clean => "clean",
        Stage::Verify => "verify",
        Stage::Done => "done",
    }
}

#[derive(Clone, serde::Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
enum UnpackEvent {
    Stage { stage: &'static str },
    Line { line: String },
}

/// Find `maple-unpack-native`: an explicit path first, then beside this executable, then `PATH`.
fn locate_native(explicit: Option<&str>) -> Option<PathBuf> {
    const NAMES: [&str; 2] = ["maple-unpack-native.exe", "maple-unpack-native"];
    if let Some(p) = explicit {
        let p = Path::new(p);
        if p.is_file() {
            return Some(p.to_path_buf());
        }
    }
    let mut roots: Vec<PathBuf> = Vec::new();
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        roots.push(dir.to_path_buf());
    }
    if let Some(paths) = std::env::var_os("PATH") {
        roots.extend(std::env::split_paths(&paths));
    }
    roots
        .iter()
        .flat_map(|d| NAMES.iter().map(move |n| d.join(n)))
        .find(|c| c.is_file())
}

/// Drive the bundled native dumper, mirror its stderr progress onto `unpack-progress`, and parse the
/// `UnpackReport` it prints on stdout. Returns a loud error if the tool is missing, fails to launch,
/// exits non-zero, or any gate fails (in which case it writes no binary).
fn run_native(
    app: &tauri::AppHandle,
    input: &str,
    output: &str,
    native_bin: Option<&str>,
) -> Result<UnpackReport, String> {
    let bin = locate_native(native_bin).ok_or_else(|| {
        "native dumper not found: build maple-unpack-native or set its path".to_string()
    })?;
    let emit = |event: UnpackEvent| {
        let _ = app.emit("unpack-progress", event);
    };
    emit(UnpackEvent::Stage { stage: "locate" });

    let mut child = Command::new(&bin)
        .arg(input)
        .arg(output)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("could not launch the native dumper: {e}"))?;

    emit(UnpackEvent::Stage { stage: "dump" });

    let stderr = child.stderr.take();
    if let Some(stderr) = stderr {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            if let Some(rest) = line.strip_prefix("[native-unpack] ") {
                match rest.split_whitespace().next() {
                    Some("clean") => emit(UnpackEvent::Stage { stage: "clean" }),
                    Some("verify") => emit(UnpackEvent::Stage { stage: "verify" }),
                    _ => emit(UnpackEvent::Line { line: rest.into() }),
                }
            } else {
                emit(UnpackEvent::Line {
                    line: line.trim().to_string(),
                });
            }
        }
    }

    let mut stdout = String::new();
    if let Some(mut out) = child.stdout.take() {
        let _ = out.read_to_string(&mut stdout);
    }
    let status = child
        .wait()
        .map_err(|e| format!("the native dumper did not finish: {e}"))?;
    if !status.success() {
        return Err("native unpack failed; no verified binary was produced (see the log)".into());
    }

    let report_line = stdout
        .lines()
        .rev()
        .find(|l| l.trim_start().starts_with('{'))
        .ok_or_else(|| "the native dumper produced no report".to_string())?;
    let report: UnpackReport = serde_json::from_str(report_line)
        .map_err(|e| format!("could not read the native dumper report: {e}"))?;
    emit(UnpackEvent::Stage { stage: "done" });
    Ok(report)
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub async fn unpack_binary(
    app: tauri::AppHandle,
    input: String,
    output: String,
    clean_only: bool,
    packed: Option<String>,
    unlicense: Option<String>,
    unbind_iat: bool,
    zero_timestamp: bool,
    native: bool,
    native_bin: Option<String>,
) -> Result<UnpackReport, String> {
    if !Path::new(&input).is_file() {
        return Err(format!("input not found: {input}"));
    }
    if output.trim().is_empty() {
        return Err("no output path chosen".to_string());
    }

    if native {
        let app = app.clone();
        return tauri::async_runtime::spawn_blocking(move || {
            run_native(&app, &input, &output, native_bin.as_deref())
        })
        .await
        .map_err(|e| e.to_string())?;
    }

    if let Some(p) = &packed
        && !Path::new(p).is_file()
    {
        return Err(format!("packed reference not found: {p}"));
    }

    tauri::async_runtime::spawn_blocking(move || {
        let opts = CleanOptions {
            unbind_iat,
            zero_timestamp,
        };
        let mut on = |p: Progress| {
            let event = match p {
                Progress::Stage(s) => UnpackEvent::Stage {
                    stage: stage_str(s),
                },
                Progress::Line(l) => UnpackEvent::Line {
                    line: l.to_string(),
                },
            };
            let _ = app.emit("unpack-progress", event);
        };
        let result = if clean_only {
            clean_to_path(
                Path::new(&input),
                Path::new(&output),
                &opts,
                packed.as_deref().map(Path::new),
                &mut on,
            )
        } else {
            unpack_to_path(
                Path::new(&input),
                Path::new(&output),
                &opts,
                unlicense.as_deref().map(Path::new),
                &mut on,
            )
        };
        result.map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}
