#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! MapleDumper desktop app entry point. The Tauri command surface is split into
//! feature modules; this file only wires them into the builder. Shared state
//! lives in [`state`], small helpers in [`util`].

mod asmscan;
mod diff;
mod disasm;
mod export;
mod fileio;
mod history;
mod history_cmd;
mod jobs;
mod scan;
mod sigmaker;
mod state;
mod util;

use std::sync::{Arc, Mutex};

use crate::jobs::JobManager;
use crate::state::{AppState, open_history_db};

fn main() {
    let (db, db_warning) = open_history_db();
    tauri::Builder::default()
        .manage(AppState {
            jobs: JobManager::default(),
            last: Arc::new(Mutex::new(None)),
            db: Arc::new(Mutex::new(db)),
            db_warning,
        })
        .invoke_handler(tauri::generate_handler![
            scan::engine_version,
            state::startup_warnings,
            scan::parse_patterns_text,
            scan::attach_and_scan,
            asmscan::assembly_scan,
            scan::cancel_scan,
            scan::cancel_job,
            export::export_text,
            diff::diff_dumps,
            history_cmd::history_builds,
            history_cmd::history_page,
            history_cmd::history_findings,
            history_cmd::history_read_gaps,
            history_cmd::history_diff,
            history_cmd::history_delete,
            history_cmd::history_clear,
            history_cmd::history_export,
            history_cmd::history_matrix,
            disasm::disassemble,
            sigmaker::inspect_pe,
            sigmaker::inspect_address,
            fileio::pick_open_files,
            sigmaker::generate_signature,
            fileio::pick_save_file,
            fileio::write_text_file,
            fileio::open_pattern_file,
            fileio::save_report_file,
            fileio::import_config_file
        ])
        .run(tauri::generate_context!())
        .expect("error while running MapleDumper");
}
