use std::path::{Path, PathBuf};
use std::time::Duration;

use maple_core::pattern::Arch;

use crate::cli::AttachArgs;

#[derive(Default)]
pub(crate) struct Config {
    pub(crate) process: Option<String>,
    pub(crate) module: Option<String>,
    pub(crate) arch: Option<Arch>,
    pub(crate) patterns: Option<PathBuf>,
    pub(crate) out: Option<PathBuf>,
    pub(crate) strict: Option<bool>,
}

pub(crate) struct ResolvedAttach {
    pub(crate) process: Option<String>,
    pub(crate) class: Option<String>,
    pub(crate) pid: Option<u32>,
    pub(crate) module: String,
    pub(crate) wait: bool,
    pub(crate) timeout: Option<Duration>,
}

fn parse_bool(v: &str) -> Result<bool, String> {
    match v.trim().to_ascii_lowercase().as_str() {
        "true" | "yes" | "on" | "1" => Ok(true),
        "false" | "no" | "off" | "0" => Ok(false),
        other => Err(format!("expected a boolean, got '{other}'")),
    }
}

pub(crate) fn parse_hex_opt(field: &Option<String>) -> Result<Option<usize>, String> {
    match field.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        None => Ok(None),
        Some(raw) => {
            let hex = raw.trim_start_matches("0x").trim_start_matches("0X");
            usize::from_str_radix(hex, 16)
                .map(Some)
                .map_err(|_| format!("invalid address '{raw}'"))
        }
    }
}

fn parse_arch(s: &str) -> Result<Arch, String> {
    Arch::parse(s)
}

pub(crate) fn parse_config(text: &str, label: &str) -> Result<Config, String> {
    let mut cfg = Config::default();
    for (n, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, val) = line
            .split_once('=')
            .ok_or_else(|| format!("{label}:{} expected key = value", n + 1))?;
        let (key, val) = (key.trim(), val.trim());
        match key {
            "process" | "process_name" => cfg.process = Some(val.to_string()),
            "module" | "module_name" => cfg.module = Some(val.to_string()),
            "arch" => {
                cfg.arch = Some(parse_arch(val).map_err(|e| format!("{label}:{} {e}", n + 1))?)
            }
            "patterns" => cfg.patterns = Some(PathBuf::from(val)),
            "out" | "outputs" => cfg.out = Some(PathBuf::from(val)),
            "strict" | "strict_patterns" => {
                cfg.strict = Some(parse_bool(val).map_err(|e| format!("{label}:{} {e}", n + 1))?);
            }
            other => return Err(format!("{label}:{} unknown key '{other}'", n + 1)),
        }
    }
    Ok(cfg)
}

fn load_config(path: &Path) -> Result<Config, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("read config {}: {e}", path.display()))?;
    parse_config(&text, &path.display().to_string())
}

pub(crate) fn resolve_config(explicit: Option<&Path>) -> Result<Config, String> {
    if let Some(p) = explicit {
        return load_config(p);
    }
    let default = Path::new("maple.conf");
    if default.exists() {
        return load_config(default);
    }
    Ok(Config::default())
}

pub(crate) fn resolve_arch(cli: Option<&str>, cfg: &Config) -> Result<Arch, String> {
    match cli {
        Some(s) => parse_arch(s),
        None => Ok(cfg.arch.unwrap_or(Arch::X64)),
    }
}

pub(crate) fn resolve_strict(lenient: bool, cfg: &Config) -> bool {
    if lenient {
        return false;
    }
    cfg.strict.unwrap_or(true)
}

pub(crate) fn resolve_patterns(cli: Option<&PathBuf>, cfg: &Config) -> PathBuf {
    cli.cloned()
        .or_else(|| cfg.patterns.clone())
        .unwrap_or_else(|| PathBuf::from("patterns.txt"))
}

pub(crate) fn resolve_attach(a: &AttachArgs, cfg: &Config) -> ResolvedAttach {
    let (process, class) = if a.class.is_some() {
        (None, a.class.clone())
    } else if a.process.is_some() {
        (a.process.clone(), None)
    } else {
        (cfg.process.clone(), None)
    };
    let module = a
        .module
        .clone()
        .or_else(|| cfg.module.clone())
        .or_else(|| process.clone())
        .unwrap_or_else(|| "MapleStory.exe".to_string());
    let timeout = a
        .timeout
        .and_then(|s| (s > 0).then(|| Duration::from_secs(s)));
    ResolvedAttach {
        process,
        class,
        pid: a.pid,
        module,
        wait: !a.no_wait,
        timeout,
    }
}
