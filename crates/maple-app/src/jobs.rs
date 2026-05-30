use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

pub type JobId = u64;

#[derive(Clone)]
pub struct CancelToken(Arc<AtomicBool>);

impl CancelToken {
    #[must_use]
    pub fn flag(&self) -> &AtomicBool {
        &self.0
    }
}

/// Tracks running scans so each can be cancelled on its own token. A single shared flag let a new
/// scan clear a cancellation still meant for the previous one; here every scan owns its token and
/// starting one never touches another.
#[derive(Default)]
pub struct JobManager {
    next: AtomicU64,
    active: Mutex<HashMap<JobId, Arc<AtomicBool>>>,
}

impl JobManager {
    fn active(&self) -> MutexGuard<'_, HashMap<JobId, Arc<AtomicBool>>> {
        self.active.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn start(&self) -> (JobId, CancelToken) {
        let id = self.next.fetch_add(1, Ordering::SeqCst);
        let flag = Arc::new(AtomicBool::new(false));
        self.active().insert(id, Arc::clone(&flag));
        (id, CancelToken(flag))
    }

    pub fn finish(&self, id: JobId) {
        self.active().remove(&id);
    }

    pub fn cancel(&self, id: JobId) {
        if let Some(flag) = self.active().get(&id) {
            flag.store(true, Ordering::SeqCst);
        }
    }

    pub fn cancel_all(&self) {
        for flag in self.active().values() {
            flag.store(true, Ordering::SeqCst);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cancelled(token: &CancelToken) -> bool {
        token.flag().load(Ordering::SeqCst)
    }

    #[test]
    fn cancel_targets_one_job() {
        let jm = JobManager::default();
        let (a, ta) = jm.start();
        let (_b, tb) = jm.start();
        jm.cancel(a);
        assert!(cancelled(&ta));
        assert!(!cancelled(&tb));
    }

    #[test]
    fn starting_a_job_does_not_reset_another() {
        let jm = JobManager::default();
        let (a, ta) = jm.start();
        jm.cancel(a);
        let _ = jm.start();
        assert!(cancelled(&ta));
    }

    #[test]
    fn cancel_all_then_finish_is_safe() {
        let jm = JobManager::default();
        let (a, ta) = jm.start();
        jm.cancel_all();
        assert!(cancelled(&ta));
        jm.finish(a);
        jm.cancel_all();
    }
}
