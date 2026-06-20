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

// Pick the freshest unicorn.dll among the unicorn-engine-sys build outputs (incremental builds can
// leave several hash-suffixed dirs behind; the newest one matches the current build).
fn find_unicorn_dll(build_dir: &Path) -> Option<PathBuf> {
    let mut best: Option<(SystemTime, PathBuf)> = None;
    for entry in fs::read_dir(build_dir).ok()?.flatten() {
        if !entry
            .file_name()
            .to_string_lossy()
            .starts_with("unicorn-engine-sys-")
        {
            continue;
        }
        let out = entry.path().join("out");
        for candidate in [out.join("bin").join("unicorn.dll"), out.join("unicorn.dll")] {
            let Ok(meta) = fs::metadata(&candidate) else {
                continue;
            };
            if !meta.is_file() {
                continue;
            }
            let mtime = meta.modified().unwrap_or(UNIX_EPOCH);
            if best.as_ref().is_none_or(|(t, _)| mtime >= *t) {
                best = Some((mtime, candidate));
            }
        }
    }
    best.map(|(_, p)| p)
}
