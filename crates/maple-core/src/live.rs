//! Live-scan orchestration: compose the engine's byte scan with the signature maker's string-anchor
//! resolution. This layer sits *above* both, it depends on [`crate::engine`] (the byte scan) and on
//! [`crate::sigmaker`] (the image view and the string-anchor resolver), so neither of those two has to
//! depend on the other. Keeping the composition here is what lets the engine stay a pure scan/resolve
//! layer with no knowledge of signature generation.

use crate::domain::FindingStatus;
use crate::engine::{ScanResult, scan_in};
use crate::memory::{MemorySource, Region};
use crate::output::Finding;
use crate::pattern::{Arch, Pattern};
use crate::sigmaker::{ImageInput, resolve_string_anchor};

/// Resolve string-anchored patterns against an image view, live target or file, and fold the results
/// into a [`ScanResult`] from [`crate::engine::scan`]. The byte scan leaves each empty-signature
/// anchored pattern as a placeholder not-found row; this rewrites that row in place by index, so the
/// one-row-per-pattern shape is preserved and a resolved anchor moves from not-found to found.
pub fn apply_string_anchors(result: &mut ScanResult, img: &ImageInput, patterns: &[Pattern]) {
    for (idx, p) in patterns.iter().enumerate() {
        let Some(anchor) = &p.string_anchor else {
            continue;
        };
        let base = p.base.as_str();
        let pattern = match &anchor.also {
            Some(also) => format!("@string={} @also={also}", anchor.text),
            None => format!("@string={}", anchor.text),
        };
        let resolved = resolve_string_anchor(img, anchor);
        if let Some(row) = result.rows.get_mut(idx) {
            row.pattern = pattern;
            if let Some(rva) = resolved {
                row.value = Some(rva as u64);
                row.is_offset = false;
                row.matches = 1;
                row.status = FindingStatus::FoundUnique;
                row.candidates = vec![rva as u64];
                row.confidence = 100;
                row.trace = Some(format!("string anchor resolved to 0x{rva:X}"));
            }
        }
        if let Some(rva) = resolved {
            let category = p.category.clone();
            result.not_found.retain(|n| n != &p.name);
            result.found.push(p.name.clone());
            result.total_matches += 1;
            result.findings.push(Finding {
                name: base.to_string(),
                category,
                value: rva as u64,
                is_offset: false,
            });
        }
    }
}

/// Scan a live target end to end: run the chunked scan over its regions, then apply any string
/// anchors. The CLI and the desktop app both call this, so the live-scan sequence (the scan plus the
/// degenerate `ImageInput` that string-anchor resolution needs) has a single definition and the two
/// front-ends cannot drift on it.
pub fn scan_live<S>(
    source: &S,
    module_base: usize,
    module_size: usize,
    regions: &[Region],
    code_regions: &[Region],
    patterns: &[Pattern],
    arch: Arch,
) -> ScanResult
where
    S: MemorySource + Sync,
{
    let mut result = scan_in(
        source,
        module_base,
        module_size,
        regions,
        code_regions,
        patterns,
        arch,
    );
    if patterns.iter().any(|p| p.string_anchor.is_some()) {
        let img = ImageInput {
            label: String::new(),
            source,
            base: module_base,
            size: module_size,
            code_regions: code_regions.to_vec(),
            regions: regions.to_vec(),
            import: None,
            arch,
            code_hash: 0,
            packed: false,
            pack_reasons: Vec::new(),
            reloc: None,
        };
        apply_string_anchors(&mut result, &img, patterns);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::{apply_string_anchors, scan_live};
    use crate::domain::FindingStatus;
    use crate::engine::{scan, scan_in};
    use crate::memory::{BufferSource, Region};
    use crate::pattern::{Arch, parse_patterns};
    use crate::sigmaker::ImageInput;

    #[test]
    fn resolves_a_string_anchored_pattern() {
        let base = 0x1000usize;
        let mut mem = vec![0u8; 0x200];
        mem[0x10..0x1B].copy_from_slice(b"MapleStory\0");
        mem[0x100] = 0x68;
        mem[0x101..0x105].copy_from_slice(&0x1010u32.to_le_bytes());
        let source = BufferSource::new(base, mem);
        let img = ImageInput {
            label: String::new(),
            source: &source,
            base,
            size: 0x200,
            code_regions: vec![Region {
                base: base + 0x100,
                size: 0x100,
            }],
            regions: vec![
                Region { base, size: 0x100 },
                Region {
                    base: base + 0x100,
                    size: 0x100,
                },
            ],
            import: None,
            arch: Arch::X86,
            code_hash: 0,
            packed: false,
            pack_reasons: Vec::new(),
            reloc: None,
        };
        let patterns = parse_patterns("Stat = @string=MapleStory", Arch::X86);
        let regions = [Region { base, size: 0x200 }];
        let mut result = scan(&source, base, 0x200, &regions, &patterns, Arch::X86);
        assert_eq!(result.not_found, vec!["Stat".to_string()]);
        apply_string_anchors(&mut result, &img, &patterns);
        assert_eq!(result.found, vec!["Stat".to_string()]);
        assert!(result.not_found.is_empty());
        assert_eq!(result.rows.len(), 1);
        assert_eq!(result.rows[0].status, FindingStatus::FoundUnique);
        let stat = result.findings.iter().find(|f| f.name == "Stat").unwrap();
        assert_eq!(stat.value, 0x101);
        assert!(!stat.is_offset);
    }

    #[test]
    fn scan_live_matches_scan_in_plus_apply_string_anchors() {
        // ARCH-1 / TEST-4: scan_live is the single live-scan path both front-ends call. It must equal
        // a manual scan_in + apply_string_anchors over the same input (covering both a byte pattern
        // and a string anchor), so the CLI and the app cannot drift on the scan sequence.
        let base = 0x1000usize;
        let mut mem = vec![0u8; 0x200];
        mem[0x10..0x1B].copy_from_slice(b"MapleStory\0");
        mem[0x100] = 0x68;
        mem[0x101..0x105].copy_from_slice(&0x1010u32.to_le_bytes());
        mem[0x150..0x154].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        let source = BufferSource::new(base, mem);
        let regions = vec![
            Region { base, size: 0x100 },
            Region {
                base: base + 0x100,
                size: 0x100,
            },
        ];
        let code_regions = vec![Region {
            base: base + 0x100,
            size: 0x100,
        }];
        let patterns = parse_patterns("Stat = @string=MapleStory\nMark = DE AD BE EF", Arch::X86);

        let mut reference = scan_in(
            &source,
            base,
            0x200,
            &regions,
            &code_regions,
            &patterns,
            Arch::X86,
        );
        let img = ImageInput {
            label: String::new(),
            source: &source,
            base,
            size: 0x200,
            code_regions: code_regions.clone(),
            regions: regions.clone(),
            import: None,
            arch: Arch::X86,
            code_hash: 0,
            packed: false,
            pack_reasons: Vec::new(),
            reloc: None,
        };
        apply_string_anchors(&mut reference, &img, &patterns);

        let live = scan_live(
            &source,
            base,
            0x200,
            &regions,
            &code_regions,
            &patterns,
            Arch::X86,
        );

        assert_eq!(live.found, reference.found);
        assert_eq!(live.not_found, reference.not_found);
        assert_eq!(live.findings, reference.findings);
        assert_eq!(live.rows.len(), reference.rows.len());
        assert!(live.found.contains(&"Stat".to_string()));
        assert!(live.findings.iter().any(|f| f.name == "Mark"));
    }
}
