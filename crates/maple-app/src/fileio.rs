//! File-picker dialogs and the guarded text file read/write commands.
//!
//! The frontend only reads and writes pattern lists, config, and exported reports. A path that
//! reaches these commands is treated as untrusted (a compromised webview could call them), so every
//! path is held to a typed extension allowlist, screened for alternate-data-stream and traversal
//! tricks, and canonicalized before any byte is touched. The intent-specific commands
//! (`open_pattern_file`, `open_target_list`, `save_report_file`, `import_config_file`) pair the OS
//! dialog with the IO so the path is never round-tripped through the frontend at all.

use std::io::Read;
use std::path::{Component, Path, PathBuf};

use serde::Serialize;

/// A file opened through a guarded dialog command: its display name and its validated contents. The
/// name lets the frontend show which file was loaded without the read path ever round-tripping
/// through it.
#[derive(Serialize)]
pub struct OpenedFile {
    name: String,
    content: String,
}

/// What a path is allowed to be, which decides its permitted extensions.
#[derive(Clone, Copy)]
pub(crate) enum FileKind {
    /// The broad set the legacy read/write commands accept (any text-like artifact).
    Any,
    /// A pattern list.
    Pattern,
    /// An exported report / header / table.
    Report,
    /// A config file.
    Config,
}

impl FileKind {
    fn allowed(self) -> &'static [&'static str] {
        match self {
            FileKind::Any => &[
                ".txt", ".h", ".hpp", ".inc", ".json", ".ct", ".csv", ".md", ".ini", ".cfg", ".log",
            ],
            FileKind::Pattern => &[".txt", ".json", ".ini", ".cfg", ".inc"],
            FileKind::Report => &[".txt", ".h", ".hpp", ".inc", ".ct", ".csv", ".md", ".log"],
            FileKind::Config => &[".json", ".ini", ".cfg", ".conf"],
        }
    }

    fn label(self) -> &'static str {
        match self {
            FileKind::Any => "text",
            FileKind::Pattern => "pattern",
            FileKind::Report => "report",
            FileKind::Config => "config",
        }
    }

    fn extension_ok(self, path: &str) -> bool {
        let lower = path.to_ascii_lowercase();
        self.allowed().iter().any(|ext| lower.ends_with(ext))
    }
}

/// Syntactic path checks that need no filesystem access: non-empty, no embedded NUL, no
/// alternate-data-stream colon past the drive letter, no `..` traversal component, and an allowed
/// extension. Pulled out so it can be unit-tested directly.
fn check_text_path(path: &str, kind: FileKind) -> Result<(), String> {
    if path.trim().is_empty() {
        return Err("empty path".to_string());
    }
    if path.contains('\0') {
        return Err("path contains a NUL byte".to_string());
    }
    // A ':' anywhere but the drive-letter position is an alternate data stream (`file.txt:evil`) or
    // a device path; reject it so the extension check cannot be bypassed.
    if path.char_indices().any(|(i, c)| c == ':' && i != 1) {
        return Err("path contains an unexpected ':' (alternate data stream?)".to_string());
    }
    if Path::new(path)
        .components()
        .any(|c| matches!(c, Component::ParentDir))
    {
        return Err("path must not contain '..'".to_string());
    }
    if !kind.extension_ok(path) {
        return Err(format!(
            "{} files must end in one of: {}",
            kind.label(),
            kind.allowed().join(", ")
        ));
    }
    Ok(())
}

/// Validate and canonicalize a path for reading. The file must exist; the resolved (symlink- and
/// `..`-free) path must still carry an allowed extension, so a link named `x.txt` that resolves to a
/// secret cannot slip through.
fn canonical_read(path: &str, kind: FileKind) -> Result<PathBuf, String> {
    check_text_path(path, kind)?;
    let canon = std::fs::canonicalize(path).map_err(|e| format!("cannot open {path}: {e}"))?;
    if !kind.extension_ok(&canon.to_string_lossy()) {
        return Err("the resolved file is not an allowed text file".to_string());
    }
    Ok(canon)
}

/// Validate and resolve a path for writing. The parent directory must exist (and is canonicalized,
/// neutralizing `..` and symlinks); the file name keeps its checked extension.
fn canonical_write(path: &str, kind: FileKind) -> Result<PathBuf, String> {
    check_text_path(path, kind)?;
    let p = Path::new(path);
    let parent = p
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .ok_or("path must include a directory")?;
    let name = p.file_name().ok_or("path has no file name")?;
    let dir =
        std::fs::canonicalize(parent).map_err(|e| format!("directory does not exist: {e}"))?;
    Ok(dir.join(name))
}

fn read_checked(path: &str, kind: FileKind) -> Result<String, String> {
    let canon = canonical_read(path, kind)?;
    std::fs::read(&canon)
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        .map_err(|e| e.to_string())
}

fn write_checked(path: &str, kind: FileKind, contents: &str) -> Result<(), String> {
    let canon = canonical_write(path, kind)?;
    std::fs::write(&canon, contents).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn pick_save_file(default_name: String) -> Option<String> {
    tauri::async_runtime::spawn_blocking(move || {
        rfd::FileDialog::new()
            .set_file_name(default_name)
            .save_file()
            .map(|p| p.to_string_lossy().into_owned())
    })
    .await
    .ok()
    .flatten()
}

#[tauri::command]
pub async fn pick_open_files() -> Vec<String> {
    tauri::async_runtime::spawn_blocking(|| {
        rfd::FileDialog::new()
            .add_filter("Executables", &["exe", "dll", "bin"])
            .add_filter("All files", &["*"])
            .pick_files()
            .map(|v| {
                v.into_iter()
                    .map(|p| p.to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default()
    })
    .await
    .unwrap_or_default()
}

#[tauri::command]
pub fn write_text_file(path: String, contents: String) -> Result<(), String> {
    write_checked(&path, FileKind::Any, &contents)
}

/// Open a pattern file via the OS dialog and return its contents, so the path is chosen by the user
/// in the backend and never supplied by the (untrusted) frontend.
#[tauri::command]
pub async fn open_pattern_file() -> Result<Option<OpenedFile>, String> {
    let picked = tauri::async_runtime::spawn_blocking(|| {
        rfd::FileDialog::new()
            .add_filter("Pattern lists", &["txt", "json", "ini", "cfg", "inc"])
            .pick_file()
            .map(|p| p.to_string_lossy().into_owned())
    })
    .await
    .map_err(|e| e.to_string())?;
    match picked {
        Some(path) => {
            let content = read_checked(&path, FileKind::Pattern)?;
            let name = Path::new(&path)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or(path);
            Ok(Some(OpenedFile { name, content }))
        }
        None => Ok(None),
    }
}

/// Generous for a hand-made list of addresses or signatures, and small enough that a stray binary
/// is refused before it is ever decoded into a text box.
const TARGET_LIST_MAX_BYTES: usize = 4 << 20;

/// What the Signature Maker's list import found in the picked file.
#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TargetList {
    /// A text list: one address or signature per non-blank line.
    Lines { name: String, lines: Vec<String> },
    /// A PE image. A list cannot hold one, so the user meant it as a client build.
    Client { name: String, path: String },
}

fn is_pe(head: &[u8]) -> bool {
    let Some(lfanew) = head.get(0x3C..0x40) else {
        return false;
    };
    let lfanew = u32::from_le_bytes(lfanew.try_into().unwrap()) as usize;
    head.starts_with(b"MZ") && head.get(lfanew..lfanew.saturating_add(4)) == Some(b"PE\0\0")
}

fn classify_target_list(name: String, path: String, head: &[u8]) -> Result<TargetList, String> {
    if is_pe(head) {
        return Ok(TargetList::Client { name, path });
    }
    if head.len() > TARGET_LIST_MAX_BYTES {
        return Err(format!(
            "{name} is larger than {} MiB; a target list is plain text with one address or signature per line",
            TARGET_LIST_MAX_BYTES >> 20
        ));
    }
    if head.contains(&0) {
        return Err(format!(
            "{name} is a binary file, not a text list of addresses or signatures"
        ));
    }
    let text = String::from_utf8_lossy(head);
    let lines = text
        .trim_start_matches('\u{feff}')
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect();
    Ok(TargetList::Lines { name, lines })
}

/// Import a list of addresses or signatures via the OS dialog. Only the first
/// `TARGET_LIST_MAX_BYTES + 1` bytes are ever read, so picking a game client here cannot stall the
/// app the way decoding a whole executable as text did.
#[tauri::command]
pub async fn open_target_list() -> Result<Option<TargetList>, String> {
    tauri::async_runtime::spawn_blocking(|| {
        let Some(path) = rfd::FileDialog::new()
            .add_filter("Address or signature lists", &["txt", "csv", "log", "lst"])
            .add_filter("All files", &["*"])
            .pick_file()
        else {
            return Ok(None);
        };
        let shown = path.to_string_lossy().into_owned();
        let name = path
            .file_name()
            .map_or_else(|| shown.clone(), |n| n.to_string_lossy().into_owned());
        let mut head = Vec::new();
        std::fs::File::open(&path)
            .and_then(|f| {
                f.take(TARGET_LIST_MAX_BYTES as u64 + 1)
                    .read_to_end(&mut head)
            })
            .map_err(|e| format!("cannot read {shown}: {e}"))?;
        classify_target_list(name, shown, &head).map(Some)
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Save a report via the OS dialog, writing `contents` to the user-chosen path. Returns the path
/// written, or `None` if the dialog was cancelled.
#[tauri::command]
pub async fn save_report_file(
    default_name: String,
    contents: String,
) -> Result<Option<String>, String> {
    let picked = tauri::async_runtime::spawn_blocking(move || {
        rfd::FileDialog::new()
            .set_file_name(default_name)
            .save_file()
            .map(|p| p.to_string_lossy().into_owned())
    })
    .await
    .map_err(|e| e.to_string())?;
    match picked {
        Some(path) => {
            write_checked(&path, FileKind::Report, &contents)?;
            Ok(Some(path))
        }
        None => Ok(None),
    }
}

/// Import a config file via the OS dialog and return its contents.
#[tauri::command]
pub async fn import_config_file() -> Result<Option<String>, String> {
    let picked = tauri::async_runtime::spawn_blocking(|| {
        rfd::FileDialog::new()
            .add_filter("Config", &["json", "ini", "cfg", "conf"])
            .pick_file()
            .map(|p| p.to_string_lossy().into_owned())
    })
    .await
    .map_err(|e| e.to_string())?;
    match picked {
        Some(path) => read_checked(&path, FileKind::Config).map(Some),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_nul_and_ads_and_traversal() {
        assert!(check_text_path("", FileKind::Any).is_err());
        assert!(check_text_path("a\0b.txt", FileKind::Any).is_err());
        assert!(check_text_path("C:\\x.txt:evil", FileKind::Any).is_err());
        assert!(check_text_path("C:\\dir\\..\\secret.txt", FileKind::Any).is_err());
    }

    #[test]
    fn enforces_per_kind_extensions() {
        // a drive-qualified text file is fine for Any
        assert!(check_text_path("C:\\dir\\patterns.txt", FileKind::Any).is_ok());
        // a header is a report extension, not a pattern one
        assert!(check_text_path("C:\\dir\\offsets.h", FileKind::Report).is_ok());
        assert!(check_text_path("C:\\dir\\offsets.h", FileKind::Pattern).is_err());
        // an executable is never allowed
        assert!(check_text_path("C:\\dir\\evil.exe", FileKind::Any).is_err());
        // config wants config extensions
        assert!(check_text_path("C:\\dir\\maple.conf", FileKind::Config).is_ok());
        assert!(check_text_path("C:\\dir\\maple.txt", FileKind::Config).is_err());
    }

    #[test]
    fn read_write_round_trip_through_canonicalization() {
        let dir = std::env::temp_dir().join("mapledumper_fileio_test");
        let _ = std::fs::create_dir_all(&dir);
        let file = dir.join("rt.txt");
        let path = file.to_string_lossy().into_owned();

        write_checked(&path, FileKind::Any, "hello").unwrap();
        assert_eq!(read_checked(&path, FileKind::Any).unwrap(), "hello");

        // a bad extension is refused on both paths even though the bytes exist
        let bad = dir.join("rt.exe");
        let bad_path = bad.to_string_lossy().into_owned();
        assert!(write_checked(&bad_path, FileKind::Any, "x").is_err());

        let _ = std::fs::remove_file(&file);
    }

    #[test]
    fn write_into_a_missing_directory_is_refused() {
        let missing = "C:\\this_directory_should_not_exist_9f3a\\out.txt";
        assert!(write_checked(missing, FileKind::Any, "x").is_err());
    }

    #[test]
    fn read_of_a_missing_file_is_refused() {
        let missing = std::env::temp_dir().join("mapledumper_nope_4d1c.txt");
        assert!(read_checked(&missing.to_string_lossy(), FileKind::Any).is_err());
    }

    fn classify(head: &[u8]) -> Result<TargetList, String> {
        classify_target_list("in".to_string(), "C:\\in".to_string(), head)
    }

    #[test]
    fn target_list_keeps_nonblank_trimmed_lines_and_drops_the_bom() {
        let Ok(TargetList::Lines { lines, .. }) =
            classify(b"\xEF\xBB\xBF0x4D6D95\r\n\r\n  0x1000 \n")
        else {
            panic!("a text list must import as lines");
        };
        assert_eq!(lines, ["0x4D6D95", "0x1000"]);
    }

    #[test]
    fn target_list_hands_a_pe_back_as_a_client() {
        let mut pe = vec![0u8; 0x100];
        pe[..2].copy_from_slice(b"MZ");
        pe[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        pe[0x80..0x84].copy_from_slice(b"PE\0\0");
        let Ok(TargetList::Client { path, .. }) = classify(&pe) else {
            panic!("a PE must be routed to the client list");
        };
        assert_eq!(path, "C:\\in");
        assert!(matches!(
            classify(b"MZ is not a header\n"),
            Ok(TargetList::Lines { .. })
        ));
    }

    #[test]
    fn target_list_refuses_other_binaries_and_oversized_text() {
        assert!(classify(b"\x7FELF\x00\x01").is_err());
        assert!(classify(&vec![b'a'; TARGET_LIST_MAX_BYTES + 1]).is_err());
        assert!(classify(&vec![b'a'; TARGET_LIST_MAX_BYTES]).is_ok());
    }
}
