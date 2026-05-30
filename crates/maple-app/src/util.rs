//! Small pure helpers shared across the command modules: request-field parsing
//! and value formatting that several features need.

use maple_core::{Arch, Kind, MemorySource};

pub(crate) fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub(crate) fn read_window<S: MemorySource>(source: &S, addr: usize, n: usize) -> Option<String> {
    let mut buf = vec![0u8; n];
    let read = source.read_into(addr, &mut buf).ok()?;
    if read == 0 {
        return None;
    }
    Some(buf[..read].iter().map(|b| format!("{b:02X}")).collect())
}

pub(crate) fn arch_of(s: &str) -> Arch {
    if s.eq_ignore_ascii_case("x86") || s.contains("32") {
        Arch::X86
    } else {
        Arch::X64
    }
}

pub(crate) fn parse_addr(field: &Option<String>) -> Result<Option<usize>, String> {
    match field.as_ref().map(|s| s.trim()).filter(|s| !s.is_empty()) {
        None => Ok(None),
        Some(raw) => {
            let hex = raw.trim_start_matches("0x").trim_start_matches("0X");
            usize::from_str_radix(hex, 16)
                .map(Some)
                .map_err(|_| format!("invalid address: {raw}"))
        }
    }
}

pub(crate) fn kind_label(kind: Kind) -> &'static str {
    match kind {
        Kind::Direct => "direct",
        Kind::Pointer => "pointer",
        Kind::Call => "call",
        Kind::Offset => "offset",
        Kind::Header => "header",
    }
}
