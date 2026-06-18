//! The Unpack command: drive the maple-core pipeline (dump with unlicense, then the static
//! clean, then the gates) and stream stage and dumper-line progress to the panel as
//! `unpack-progress` events. The binary is written by the engine only when every gate passes.

use std::path::Path;

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
) -> Result<UnpackReport, String> {
    if !Path::new(&input).is_file() {
        return Err(format!("input not found: {input}"));
    }
    if let Some(p) = &packed
        && !Path::new(p).is_file()
    {
        return Err(format!("packed reference not found: {p}"));
    }
    if output.trim().is_empty() {
        return Err("no output path chosen".to_string());
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
