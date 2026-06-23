use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

// Unicorn is linked dynamically (see Cargo.toml) so its bundled GLib shim no longer collides with the
// GLib in Frida's static devkit. The trade-off is that unicorn.dll must sit next to whatever runs:
// cargo does not copy a dependency's output DLL beside the final exe or the test binaries. This build
// script does, into both the profile dir (the exe and `cargo run`) and its `deps` (the test
// binaries). Without it the dumper and every Unicorn-touching test fail to start with a missing-DLL
// error rather than anything diagnosable.
fn main() {
    let Ok(out_dir) = std::env::var("OUT_DIR") else {
        return;
    };
    // OUT_DIR = <target>/<profile>/build/maple-unpack-native-<hash>/out; the profile dir is three up.
    let Some(profile_dir) = Path::new(&out_dir).ancestors().nth(3).map(PathBuf::from) else {
        return;
    };
    let Some(dll) = find_unicorn_dll(&profile_dir.join("build")) else {
        println!(
            "cargo::warning=unicorn.dll not found under the build dir; the dumper will not start until it is placed beside the exe"
        );
        return;
    };
    for dst_dir in [profile_dir.clone(), profile_dir.join("deps")] {
        let _ = fs::create_dir_all(&dst_dir);
        if let Err(e) = fs::copy(&dll, dst_dir.join("unicorn.dll")) {
            println!(
                "cargo::warning=failed to copy unicorn.dll into {}: {e}",
                dst_dir.display()
            );
        }
    }
}

// Recursively find unicorn.dll among the unicorn-engine-sys build outputs. The exact subdirectory
// (out/bin, out, or a generator- and profile-specific path) varies by toolchain, so search the whole
// subtree rather than guess; pick the freshest when several hash-suffixed dirs exist.
fn find_unicorn_dll(build_dir: &Path) -> Option<PathBuf> {
    let mut best: Option<(SystemTime, PathBuf)> = None;
    for entry in fs::read_dir(build_dir).ok()?.flatten() {
        if entry
            .file_name()
            .to_string_lossy()
            .starts_with("unicorn-engine-sys-")
        {
            walk_for_dll(&entry.path(), &mut best);
        }
    }
    best.map(|(_, p)| p)
}

fn walk_for_dll(dir: &Path, best: &mut Option<(SystemTime, PathBuf)>) {
    let Ok(rd) = fs::read_dir(dir) else {
        return;
    };
    for entry in rd.flatten() {
        let path = entry.path();
        match entry.file_type() {
            Ok(ft) if ft.is_dir() => walk_for_dll(&path, best),
            Ok(_)
                if path
                    .file_name()
                    .is_some_and(|n| n.eq_ignore_ascii_case("unicorn.dll")) =>
            {
                let mtime = fs::metadata(&path)
                    .and_then(|m| m.modified())
                    .unwrap_or(UNIX_EPOCH);
                if best.as_ref().is_none_or(|(t, _)| mtime >= *t) {
                    *best = Some((mtime, path));
                }
            }
            _ => {}
        }
    }
}
