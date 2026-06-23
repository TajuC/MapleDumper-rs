//! The Unpack command: drive the maple-core pipeline (dump with unlicense, then the static
//! clean, then the gates) and stream stage and dumper-line progress to the panel as
//! `unpack-progress` events. The binary is written by the engine only when every gate passes.
//!
//! The `native` path drives the bundled `maple-unpack-native` dumper (a native Frida + Unicorn port
//! of unlicense) through the engine's `run_native_dumper`. It emits the same `UnpackReport`, so the
//! results card and progress events are identical to the unlicense path with no second report shape
//! to maintain.

use std::path::Path;

use maple_core::{
    CleanOptions, Progress, Stage, UnpackReport, clean_to_path, component_dir,
    locate_native_dumper, run_native_dumper, unpack_to_path,
};
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

fn emit_progress(app: &tauri::AppHandle, p: Progress) {
    let event = match p {
        Progress::Stage(s) => UnpackEvent::Stage {
            stage: stage_str(s),
        },
        Progress::Line(l) => UnpackEvent::Line {
            line: l.to_string(),
        },
    };
    let _ = app.emit("unpack-progress", event);
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
            let mut on = |p: Progress| emit_progress(&app, p);
            run_native_dumper(
                Path::new(&input),
                Path::new(&output),
                native_bin.as_deref().map(Path::new),
                &mut on,
            )
            .map_err(|e| e.to_string())
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
        let mut on = |p: Progress| emit_progress(&app, p);
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

const RELEASE_URL: &str = "https://github.com/TajuC/MapleDumper-rs/releases/latest";

/// Where the native dumper resolves, if at all, so the panel can guide setup before a run instead of
/// failing at dump time. Mirrors the engine's discovery (beside this exe, the per-user component dir,
/// then `PATH`).
#[tauri::command]
pub fn native_dumper_status() -> Option<String> {
    let near = std::env::current_exe()
        .ok()
        .and_then(|e| e.parent().map(Path::to_path_buf));
    locate_native_dumper(None, near.as_deref()).map(|p| p.display().to_string())
}

/// Install a native dumper the user points at into the per-user component directory, copying its
/// `unicorn.dll` alongside it so the dumper can start. Returns the install directory. This is the
/// offline path: the app never downloads, it only copies files the user already has.
#[tauri::command]
pub fn install_native_dumper(picked: String) -> Result<String, String> {
    let src = Path::new(&picked);
    if !src.is_file() {
        return Err(format!("not a file: {picked}"));
    }
    let src_dir = src
        .parent()
        .ok_or_else(|| "the chosen file has no parent directory".to_string())?;
    let dll = src_dir.join("unicorn.dll");
    if !dll.is_file() {
        return Err(
            "unicorn.dll must sit next to the dumper; download both from the release and keep them together"
                .to_string(),
        );
    }
    let dest =
        component_dir().ok_or_else(|| "could not resolve the component directory".to_string())?;
    std::fs::create_dir_all(&dest)
        .map_err(|e| format!("could not create {}: {e}", dest.display()))?;
    std::fs::copy(src, dest.join("maple-unpack-native.exe"))
        .map_err(|e| format!("could not copy the dumper: {e}"))?;
    std::fs::copy(&dll, dest.join("unicorn.dll"))
        .map_err(|e| format!("could not copy unicorn.dll: {e}"))?;
    Ok(dest.display().to_string())
}

/// Open the releases page in the default browser so the user can download the native dumper. The app
/// stays offline; this hands a fixed, trusted URL to the OS.
#[tauri::command]
pub fn open_release_page() -> Result<(), String> {
    std::process::Command::new("cmd")
        .args(["/C", "start", "", RELEASE_URL])
        .spawn()
        .map(|_| ())
        .map_err(|e| format!("could not open the browser: {e}"))
}
