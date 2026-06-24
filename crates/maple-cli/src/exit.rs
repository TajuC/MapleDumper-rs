use maple_core::{FindingStatus, ScanResult};

/// A stable process exit code. Automation can branch on the specific outcome instead of treating
/// every nonzero result the same. These numbers are part of the tool's contract; keep them stable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExitKind {
    /// 0: ran cleanly with nothing to flag.
    Success,
    /// 2: completed with advisory issues only (lint flagged weak signatures; mksig matched a
    /// negative-corpus module).
    SuccessWithWarnings,
    /// 3: a scan ran but some patterns were not found or matched without resolving.
    Unresolved,
    /// 4: a scan ran but at least one pattern matched in several places.
    Ambiguous,
    /// 5: bad flags, bad config, bad/empty patterns, or the target could not be located.
    InvalidInput,
    /// 6: the target process could not be opened (try running as administrator).
    AccessDenied,
    /// 1: an unexpected failure.
    Internal,
}

impl ExitKind {
    pub(crate) fn code(self) -> u8 {
        match self {
            ExitKind::Success => 0,
            ExitKind::Internal => 1,
            ExitKind::SuccessWithWarnings => 2,
            ExitKind::Unresolved => 3,
            ExitKind::Ambiguous => 4,
            ExitKind::InvalidInput => 5,
            ExitKind::AccessDenied => 6,
        }
    }
}

/// A command failure carrying both a message and the exit code it should map to.
#[derive(Debug)]
pub(crate) struct CliError {
    pub(crate) kind: ExitKind,
    pub(crate) msg: String,
}

impl CliError {
    pub(crate) fn new(kind: ExitKind, msg: impl Into<String>) -> Self {
        Self {
            kind,
            msg: msg.into(),
        }
    }
}

impl From<String> for CliError {
    /// Most string errors in this tool are user-actionable input, config or pattern problems, so a
    /// bare `?` maps to [`ExitKind::InvalidInput`]. The access-denied and internal cases are
    /// constructed explicitly where they arise (see [`attach_err`]).
    fn from(msg: String) -> Self {
        CliError::new(ExitKind::InvalidInput, msg)
    }
}

impl From<&str> for CliError {
    fn from(msg: &str) -> Self {
        CliError::new(ExitKind::InvalidInput, msg)
    }
}

/// Map an attach I/O failure to its exit code: a permission failure is access-denied, a missing
/// kernel primitive is internal, and "not running / timed out / module missing" is treated as an
/// input problem (the target specification did not resolve to a usable process).
pub(crate) fn attach_err(e: std::io::Error) -> CliError {
    let kind = match e.kind() {
        std::io::ErrorKind::PermissionDenied => ExitKind::AccessDenied,
        std::io::ErrorKind::Unsupported => ExitKind::Internal,
        _ => ExitKind::InvalidInput,
    };
    CliError::new(kind, format!("attach failed: {e}"))
}

/// The exit code that summarizes a finished scan: ambiguous beats unresolved beats
/// warnings-only beats clean.
pub(crate) fn scan_exit_kind(result: &ScanResult) -> ExitKind {
    if result
        .rows
        .iter()
        .any(|r| matches!(r.status, FindingStatus::FoundAmbiguous { .. }))
    {
        ExitKind::Ambiguous
    } else if !result.matched_unresolved.is_empty() || !result.not_found.is_empty() {
        ExitKind::Unresolved
    } else if !result.warnings.is_empty() {
        ExitKind::SuccessWithWarnings
    } else {
        ExitKind::Success
    }
}

/// Map a pipeline I/O failure to an exit code: a missing file or tool is input the user can
/// fix, a permission failure is access-denied, and a dump that ran but produced nothing is
/// unresolved.
pub(crate) fn unpack_err(e: std::io::Error) -> CliError {
    let kind = match e.kind() {
        std::io::ErrorKind::NotFound
        | std::io::ErrorKind::InvalidData
        | std::io::ErrorKind::InvalidInput => ExitKind::InvalidInput,
        std::io::ErrorKind::PermissionDenied => ExitKind::AccessDenied,
        _ => ExitKind::Unresolved,
    };
    CliError::new(kind, format!("unpack failed: {e}"))
}
