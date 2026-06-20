//! Drive the bundled `maple-unpack-native` dumper as a subprocess. The native dumper runs the whole
//! packed-to-min flow itself (dump, clean, verify) and prints an [`UnpackReport`] as one JSON line on
//! stdout, with `[native-unpack] <stage>` progress on stderr. Centralizing the locate/spawn/parse
//! here keeps the CLI and GUI on one path and one report shape; maple-core stays Frida-free because
//! the dumper is a sibling binary, not a linked dependency, the same way [`super::dump`] shells out
//! to unlicense.

use std::io::{self, BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use super::{Progress, Stage, UnpackReport};

const NATIVE_NAMES: [&str; 2] = ["maple-unpack-native.exe", "maple-unpack-native"];

/// Resolve the native dumper: an explicit path first, then beside `near`, then `PATH`.
pub fn locate_native_dumper(explicit: Option<&Path>, near: Option<&Path>) -> Option<PathBuf> {
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
        .flat_map(|dir| NATIVE_NAMES.iter().map(move |n| dir.join(n)))
        .find(|cand| cand.is_file())
}

/// Run the native dumper for the full packed-to-min flow and return its report. Locates the binary
/// (explicit, then beside this executable, then `PATH`), streams the `[native-unpack]` stages and
/// lines through `on`, and parses the JSON report from stdout. Fails loudly when the dumper is
/// missing, fails to launch, exits non-zero, or prints no report; in the failure cases it writes no
/// binary, matching the static path.
pub fn run_native_dumper(
    packed: &Path,
    out: &Path,
    native_bin: Option<&Path>,
    on: &mut dyn FnMut(Progress),
) -> io::Result<UnpackReport> {
    on(Progress::Stage(Stage::Locate));
    let near = std::env::current_exe()
        .ok()
        .and_then(|e| e.parent().map(Path::to_path_buf));
    let bin = locate_native_dumper(native_bin, near.as_deref()).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "maple-unpack-native not found; build it, place it beside this program, or pass its path",
        )
    })?;
    on(Progress::Line(&format!("native dumper: {}", bin.display())));

    let mut child = Command::new(&bin)
        .arg(packed)
        .arg(out)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            io::Error::new(e.kind(), format!("could not launch the native dumper: {e}"))
        })?;

    on(Progress::Stage(Stage::Dump));
    // The dumper writes its one stdout line only after the stderr stream ends, so draining stderr
    // first cannot deadlock on a full stdout pipe.
    if let Some(stderr) = child.stderr.take() {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            match line.strip_prefix("[native-unpack] ") {
                Some(rest) => match rest.split_whitespace().next() {
                    Some("clean") => on(Progress::Stage(Stage::Clean)),
                    Some("verify") => on(Progress::Stage(Stage::Verify)),
                    _ => on(Progress::Line(rest)),
                },
                None => on(Progress::Line(line.trim())),
            }
        }
    }

    let mut stdout = String::new();
    if let Some(mut pipe) = child.stdout.take() {
        pipe.read_to_string(&mut stdout)?;
    }
    let status = child.wait()?;
    if !status.success() {
        let code = status
            .code()
            .map(|c| c.to_string())
            .unwrap_or_else(|| "signal".into());
        return Err(io::Error::other(format!(
            "the native dumper failed (exit {code}); no verified binary was written"
        )));
    }

    let report_line = stdout
        .lines()
        .rev()
        .find(|l| l.trim_start().starts_with('{'))
        .ok_or_else(|| io::Error::other("the native dumper produced no report"))?;
    let report: UnpackReport = serde_json::from_str(report_line)
        .map_err(|e| io::Error::other(format!("could not read the native dumper report: {e}")))?;
    on(Progress::Stage(Stage::Done));
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locate_prefers_explicit_then_near() {
        let dir = std::env::temp_dir().join(format!("mapledumper_nat_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let near = dir.join("maple-unpack-native.exe");
        std::fs::write(&near, b"stub").unwrap();
        let explicit = dir.join("custom-native.exe");
        std::fs::write(&explicit, b"stub").unwrap();

        assert_eq!(
            locate_native_dumper(Some(&explicit), Some(&dir)),
            Some(explicit.clone())
        );
        // a non-existent explicit path falls back to the near directory
        let missing = dir.join("nope.exe");
        assert_eq!(
            locate_native_dumper(Some(&missing), Some(&dir)),
            Some(near.clone())
        );
        assert_eq!(locate_native_dumper(None, Some(&dir)), Some(near));

        std::fs::remove_dir_all(&dir).ok();
    }
}
