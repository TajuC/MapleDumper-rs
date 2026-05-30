//! Behavior lock for the end-to-end scan and resolve pipeline. Later phases rewrite the resolver
//! and the scanner; this snapshot proves those refactors keep producing the same results. When a
//! phase intentionally changes a result (for example ambiguity becoming its own status), update the
//! expected block in the same commit so the change is visible in review.

use maple_core::memory::BufferSource;
use maple_core::pattern::{Arch, parse_patterns};
use maple_core::{PatternRow, Region, ScanResult, scan};

const BASE: usize = 0x1_0000;
const SIZE: usize = 0x5_0000;
const CHUNK_BOUNDARY: usize = 1 << 18;

fn build_image() -> Vec<u8> {
    let mut data = vec![0u8; SIZE];
    let mut put = |off: usize, bytes: &[u8]| data[off..off + bytes.len()].copy_from_slice(bytes);

    put(0x40, &[0xDE, 0xAD, 0xBE, 0xEF]);
    put(0x80, &[0x48, 0x8D, 0x0D, 0x09, 0x00, 0x00, 0x00]);
    put(0x100, &[0xE8, 0x00, 0x01, 0x00, 0x00]);
    put(0x200, &[0x48, 0x8B, 0x48, 0x10]);
    put(0x280, &[0xBA, 0x23, 0x01, 0x00, 0x00]);
    put(0x300, &[0xCA, 0xFE]);
    put(0x400, &[0xCA, 0xFE]);
    put(CHUNK_BOUNDARY - 2, &[0xAB, 0xCD, 0xEF, 0x01, 0x23]);
    data
}

const PATTERNS: &str = "\
Foo = DE AD BE EF
Bar_PTR = 48 8D 0D ?? ?? ?? ??
Baz_CALL = E8 ?? ?? ?? ??
Qux_OFF = 48 8B 48 ??
Hdr_HDR = BA ?? ?? ?? ??
Amb = CA FE
Straddle = AB CD EF 01 23
Missing = 11 22 33 44 55 66";

fn canonical(result: &ScanResult) -> String {
    let mut rows: Vec<&PatternRow> = result.rows.iter().collect();
    rows.sort_by(|a, b| a.name.cmp(&b.name));
    let mut out = String::new();
    for r in rows {
        let value = r
            .value
            .map_or_else(|| "-".to_string(), |v| format!("0x{v:X}"));
        out.push_str(&format!(
            "{} [{}] {} value={value} offset={} matches={}\n",
            r.name,
            r.category,
            r.status.label(),
            r.is_offset,
            r.matches
        ));
    }
    out.push_str(&format!("total_matches={}\n", result.total_matches));
    out.push_str(&format!("findings={}\n", result.findings.len()));
    out
}

const EXPECTED: &str = "\
Amb [uncategorized] found (ambiguous) value=0x300 offset=false matches=2
Bar [uncategorized] found value=0x90 offset=false matches=1
Baz [uncategorized] found value=0x205 offset=false matches=1
Foo [uncategorized] found value=0x40 offset=false matches=1
Hdr [uncategorized] found value=0x123 offset=true matches=1
Missing [uncategorized] not found value=- offset=false matches=0
Qux [uncategorized] found value=0x10 offset=true matches=1
Straddle [uncategorized] found value=0x3FFFE offset=false matches=1
total_matches=8
findings=6
";

#[test]
fn scan_and_resolve_snapshot() {
    let source = BufferSource::new(BASE, build_image());
    let regions = [Region {
        base: BASE,
        size: SIZE,
    }];
    let patterns = parse_patterns(PATTERNS, Arch::X64);

    let result = scan(&source, BASE, SIZE, &regions, &patterns, Arch::X64);

    assert_eq!(canonical(&result), EXPECTED);
}

#[test]
fn diagnostic_fields_expose_candidates_confidence_and_trace() {
    let source = BufferSource::new(BASE, build_image());
    let regions = [Region {
        base: BASE,
        size: SIZE,
    }];
    let patterns = parse_patterns(PATTERNS, Arch::X64);
    let result = scan(&source, BASE, SIZE, &regions, &patterns, Arch::X64);
    let row = |name: &str| {
        result
            .rows
            .iter()
            .find(|r| r.name == name)
            .unwrap_or_else(|| panic!("missing row {name}"))
    };

    let foo = row("Foo");
    assert_eq!(foo.candidates, vec![0x40]);
    assert_eq!(foo.confidence, 100);
    assert!(foo.trace.as_deref().unwrap().contains("resolved to 0x40"));

    let amb = row("Amb");
    assert_eq!(amb.candidates, vec![0x300, 0x400]);
    assert_eq!(amb.confidence, 50);
    assert!(amb.trace.is_some());

    let missing = row("Missing");
    assert!(missing.candidates.is_empty());
    assert_eq!(missing.confidence, 0);
    assert!(missing.trace.is_none());
}
