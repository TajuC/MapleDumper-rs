//! Shared application state and its construction.
//!
//! [`AppState`] is the object Tauri manages; every command reads it through
//! `tauri::State`. [`LastScan`] caches the most recent scan so the export
//! commands can render it without rescanning the target.

use std::sync::{Arc, Mutex, MutexGuard};

use rusqlite::Connection;

use maple_core::{BuildStamp, Finding};

use crate::history;
use crate::jobs::JobManager;

pub struct AppState {
    pub(crate) jobs: JobManager,
    pub(crate) last: Arc<Mutex<Option<LastScan>>>,
    pub(crate) db: Arc<Mutex<Connection>>,
    /// A startup advisory the UI should show once, set when the history database fell back to memory
    /// so the user knows this session will not persist instead of only seeing it on stderr.
    pub(crate) db_warning: Option<String>,
}

/// Advisories to show the user once at startup (currently a history database that could not be
/// opened and fell back to memory). Empty when everything came up cleanly.
#[tauri::command]
pub fn startup_warnings(state: tauri::State<'_, AppState>) -> Vec<String> {
    state.db_warning.iter().cloned().collect()
}

/// Lock the history connection, recovering a poisoned mutex instead of propagating the poison. A
/// panic while another command briefly held the lock must not permanently break history reads for
/// the rest of the session (rusqlite upholds the connection's own invariants, so the recovered
/// guard is safe to use). This is the single, consistent locking policy for the database: reads and
/// writes both recover, rather than reads failing while writes recover.
pub(crate) fn lock_db(db: &Mutex<Connection>) -> MutexGuard<'_, Connection> {
    db.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

pub(crate) struct LastScan {
    pub(crate) findings: Vec<Finding>,
    pub(crate) module_name: String,
    pub(crate) module_base: u64,
    pub(crate) stamp: BuildStamp,
}

/// Open the on-disk history database, falling back to an in-memory store if the
/// real file cannot be opened so a session still works without persistence.
pub(crate) fn open_history_db() -> (Connection, Option<String>) {
    let path = history::default_db_path();
    match history::open(&path) {
        Ok(conn) => (conn, None),
        Err(e) => {
            let msg = format!(
                "could not open the history database at {}: {e}. This session's scans will not be saved.",
                path.display()
            );
            eprintln!("[warn] {msg}");
            (history::open_memory(), Some(msg))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_db_recovers_from_a_poisoned_mutex() {
        // ARCH-7: a panic while the lock is held poisons the mutex. The propagate-poison policy used
        // to break every later history read; lock_db must recover so reads keep working.
        let db = Arc::new(Mutex::new(history::open_memory()));
        let poisoner = Arc::clone(&db);
        let _ = std::thread::spawn(move || {
            let _guard = poisoner.lock().unwrap();
            panic!("poison the connection mutex");
        })
        .join();
        assert!(db.lock().is_err(), "the mutex should be poisoned");

        let conn = lock_db(&db);
        let one: i64 = conn
            .query_row("SELECT 1", [], |row| row.get(0))
            .expect("the recovered connection is still usable");
        assert_eq!(one, 1);
    }
}
