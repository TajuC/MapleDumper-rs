//! Detect the Themida/WinLicense major version of a packed image. Ported from unlicense's
//! `version_detection.py`. The native dumper targets 3.x; 2.x is detected for a clear refusal.

use crate::pe_build::parse;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PackerVersion {
    V2,
    V3,
}

const V2_PATTERNS: [&[u8]; 2] = [
    &[0x56, 0x50, 0x53, 0xE8, 0x01, 0x00, 0x00, 0x00, 0xCC, 0x58],
    &[
        0x83, 0xEC, 0x04, 0x50, 0x53, 0xE8, 0x01, 0x00, 0x00, 0x00, 0xCC, 0x58,
    ],
];

/// Best-effort packer version from the packed bytes.
pub fn detect(packed: &[u8]) -> Option<PackerVersion> {
    let pe = parse(packed).ok()?;

    // 3.x ships a `.themida`/`.winlice` section.
    if pe
        .sections
        .iter()
        .any(|s| s.name == ".themida" || s.name == ".winlice")
    {
        return Some(PackerVersion::V3);
    }

    // 2.x begins certain sections with a fixed stub prologue.
    for s in &pe.sections {
        if s.rs == 0 {
            continue;
        }
        let start = s.ro as usize;
        for pat in V2_PATTERNS {
            if packed
                .get(start..start + pat.len())
                .is_some_and(|head| head == pat)
            {
                return Some(PackerVersion::V2);
            }
        }
    }

    None
}
