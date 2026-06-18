//! The dynamic phase: orchestrate `unlicense.exe` (Frida-based) to dump a packed image.
//! Static analysis cannot do this, so it is the one place the pipeline shells out.

use std::io::{self, BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use super::{Progress, Stage};

const UL_NAMES: [&str; 2] = ["unlicense.exe", "unlicense"];
const DEFAULT_TIMEOUT_SECS: u64 = 600;

/// Backstop for a hung dump: a Frida-based tool that runs the real client can wedge on a
/// dialog or anti-tamper spin. Generous by default, overridable for slow machines or huge
/// clients via `MAPLE_UNPACK_TIMEOUT_SECS`.
fn dump_timeout() -> Duration {
    let secs = std::env::var("MAPLE_UNPACK_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|&s| s > 0)
        .unwrap_or(DEFAULT_TIMEOUT_SECS);
    Duration::from_secs(secs)
}

/// Resolve the dumper: an explicit path first, then beside the packed exe, then `PATH`.
pub fn locate_unlicense(explicit: Option<&Path>, near: Option<&Path>) -> Option<PathBuf> {
    if let Some(p) = explicit
        && p.is_file()
    {
        return Some(p.to_path_buf());
    }
    let mut roots: Vec<PathBuf> = Vec::new();
    if let Some(dir) = near {
        roots.push(dir.to_path_buf());
    }
    if let Some(paths) = std::env::var_os("PATH") {
        roots.extend(std::env::split_paths(&paths));
    }
    roots
        .iter()
        .flat_map(|dir| UL_NAMES.iter().map(move |n| dir.join(n)))
        .find(|cand| cand.is_file())
}

/// Run unlicense and return the `unpacked_<name>` it writes beside the packed exe. Fails
/// loudly when the tool is missing, exits nonzero, or produces no output file.
pub fn dump(
    packed: &Path,
    unlicense: Option<&Path>,
    on: &mut dyn FnMut(Progress),
) -> io::Result<PathBuf> {
    let base = packed
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = packed.file_name().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "packed path has no file name")
    })?;
    let ul = locate_unlicense(unlicense, Some(base)).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "unlicense.exe not found; install from github.com/ergrelet/unlicense, place it beside the packed exe, or pass its path",
        )
    })?;
    let out = base.join(format!("unpacked_{}", file_name.to_string_lossy()));

    on(Progress::Stage(Stage::Dump));
    on(Progress::Line(&format!(
        "running {} on {}",
        ul.display(),
        file_name.to_string_lossy()
    )));

    let mut child = Command::new(&ul)
        .arg(file_name)
        .current_dir(base)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| io::Error::new(e.kind(), format!("could not launch unlicense: {e}")))?;

    let stdout = child.stdout.take().expect("stdout piped");
    let stderr = child.stderr.take().expect("stderr piped");
    let (tx, rx) = mpsc::channel::<String>();
    let tx_err = tx.clone();
    let out_thread = std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            let _ = tx.send(line);
        }
    });
    let err_thread = std::thread::spawn(move || {
        let mut collected = String::new();
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            collected.push_str(&line);
            collected.push('\n');
            let _ = tx_err.send(line);
        }
        collected
    });

    let timeout = dump_timeout();
    let deadline = Instant::now() + timeout;
    let mut timed_out = false;
    loop {
        match rx.recv_timeout(Duration::from_millis(250)) {
            Ok(line) => on(Progress::Line(&line)),
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    timed_out = true;
                    break;
                }
            }
        }
    }
    let _ = out_thread.join();
    let detail = err_thread.join().unwrap_or_default();
    let status = child.wait()?;

    if timed_out {
        return Err(io::Error::other(format!(
            "unlicense timed out after {}s and was killed; set MAPLE_UNPACK_TIMEOUT_SECS to allow longer",
            timeout.as_secs()
        )));
    }
    if !status.success() {
        let code = status
            .code()
            .map(|c| c.to_string())
            .unwrap_or_else(|| "signal".into());
        return Err(io::Error::other(format!(
            "unlicense failed (exit {code}). {}",
            detail.trim()
        )));
    }
    if !out.is_file() {
        return Err(io::Error::other(format!(
            "unlicense ran but did not produce {}",
            out.display()
        )));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locate_prefers_explicit_then_near() {
        let dir = std::env::temp_dir().join(format!("mapledumper_ul_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let near = dir.join("unlicense.exe");
        std::fs::write(&near, b"stub").unwrap();
        let explicit = dir.join("custom-ul.exe");
        std::fs::write(&explicit, b"stub").unwrap();

        assert_eq!(
            locate_unlicense(Some(&explicit), Some(&dir)),
            Some(explicit.clone())
        );
        // an explicit path that does not exist falls back to the near directory
        let missing = dir.join("nope.exe");
        assert_eq!(
            locate_unlicense(Some(&missing), Some(&dir)),
            Some(near.clone())
        );
        // no explicit: found beside the input, ahead of PATH
        assert_eq!(locate_unlicense(None, Some(&dir)), Some(near));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn locate_never_returns_a_missing_explicit() {
        let dir = std::env::temp_dir().join(format!("mapledumper_ul_empty_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let bogus = dir.join("missing.exe");
        // whatever PATH holds, a non-existent explicit path is never returned as-is
        assert_ne!(locate_unlicense(Some(&bogus), Some(&dir)), Some(bogus));
        std::fs::remove_dir_all(&dir).ok();
    }
}
