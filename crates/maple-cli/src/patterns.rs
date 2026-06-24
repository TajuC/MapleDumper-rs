use std::path::Path;

use maple_core::Pattern;
use maple_core::pattern::{
    Arch, ParseSeverity, parse_patterns_file_lenient, parse_patterns_file_strict,
};

fn load_patterns(path: &Path, arch: Arch, strict: bool) -> Result<Vec<Pattern>, String> {
    if !strict {
        let parsed = parse_patterns_file_lenient(path, arch)
            .map_err(|e| format!("failed to read {}: {e}", path.display()))?;
        // Lenient mode keeps going past malformed input; say what it dropped so a typo does not
        // silently weaken a signature with no trace.
        for w in &parsed.warnings {
            eprintln!("[!] pattern line {}: {}", w.line, w.message);
        }
        return Ok(parsed.patterns);
    }
    let parsed = parse_patterns_file_strict(path, arch)
        .map_err(|e| format!("failed to read {}: {e}", path.display()))?;
    match parsed {
        Ok(parsed) => {
            for w in &parsed.warnings {
                eprintln!("[!] {}:{} {}", path.display(), w.line, w.message);
            }
            Ok(parsed.patterns)
        }
        Err(issues) => {
            for issue in &issues {
                let tag = match issue.severity {
                    ParseSeverity::Error => "x",
                    ParseSeverity::Warning => "!",
                };
                eprintln!(
                    "[{tag}] {}:{} {}",
                    path.display(),
                    issue.line,
                    issue.message
                );
            }
            let errors = issues
                .iter()
                .filter(|i| i.severity == ParseSeverity::Error)
                .count();
            Err(format!("{errors} pattern error(s) in {}", path.display()))
        }
    }
}

pub(crate) fn require_patterns(
    path: &Path,
    arch: Arch,
    strict: bool,
    quiet: bool,
) -> Result<Vec<Pattern>, String> {
    let patterns = load_patterns(path, arch, strict)?;
    if patterns.is_empty() {
        return Err(format!("no patterns loaded from {}", path.display()));
    }
    if !quiet {
        println!("[+] loaded {} patterns", patterns.len());
    }
    Ok(patterns)
}
