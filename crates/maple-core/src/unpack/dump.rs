//! The dynamic phase: orchestrate `unlicense.exe` (Frida-based) to dump a packed image.
//! Static analysis cannot do this, so it is the one place the pipeline shells out.

use std::io::{self, BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;

use super::{Progress, Stage};

const UL_NAMES: [&str; 2] = ["unlicense.exe", "unlicense"];

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

    for line in rx {
        on(Progress::Line(&line));
    }
    let _ = out_thread.join();
    let detail = err_thread.join().unwrap_or_default();
    let status = child.wait()?;

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
