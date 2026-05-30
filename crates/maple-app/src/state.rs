//! Shared application state and its construction.
//!
//! [`AppState`] is the object Tauri manages; every command reads it through
//! `tauri::State`. [`LastScan`] caches the most recent scan so the export
//! commands can render it without rescanning the target.

use std::sync::{Arc, Mutex};

use rusqlite::Connection;

use maple_core::{BuildStamp, Finding};

use crate::history;
use crate::jobs::JobManager;

pub struct AppState {
    pub(crate) jobs: JobManager,
    pub(crate) last: Arc<Mutex<Option<LastScan>>>,
    pub(crate) db: Arc<Mutex<Connection>>,
}

pub(crate) struct LastScan {
    pub(crate) findings: Vec<Finding>,
    pub(crate) module_name: String,
    pub(crate) module_base: u64,
    pub(crate) stamp: BuildStamp,
}

/// Open the on-disk history database, falling back to an in-memory store if the
/// real file cannot be opened so a session still works without persistence.
pub(crate) fn open_history_db() -> Connection {
    let path = history::default_db_path();
    match history::open(&path) {
        Ok(conn) => conn,
        Err(e) => {
            eprintln!(
                "[warn] could not open history database at {}: {e}; history will not be saved this session",
                path.display()
            );
            history::open_memory()
        }
    }
}
