use crate::memory::{MemorySource, Region};
use crate::output::Finding;
use crate::pattern::Pattern;
use crate::resolver::{self, Kind};
use crate::scanner::{self, CompiledPattern};
use rayon::prelude::*;

pub struct ScanResult {
    pub findings: Vec<Finding>,
    pub found: Vec<String>,
    pub matched_unresolved: Vec<String>,
    pub not_found: Vec<String>,
    pub total_matches: usize,
}

struct Hit {
    pattern_idx: usize,
    addr: usize,
    value: Option<u64>,
    is_offset: bool,
}

fn rva(addr: usize, base: usize) -> u64 {
    addr.wrapping_sub(base) as u64
}

fn resolve<S: MemorySource>(
    kind: Kind,
    source: &S,
    module_base: usize,
    addr: usize,
    bytes: &[u8],
) -> (Option<u64>, bool) {
    match kind {
        Kind::Direct => (Some(rva(addr, module_base)), false),
        Kind::Pointer => (
            resolver::extract_pointer(bytes, addr).map(|t| rva(t, module_base)),
            false,
        ),
        Kind::Offset => (resolver::extract_offset(bytes, 4).map(u64::from), true),
        Kind::Call => (
            resolver::resolve_call(source, addr, bytes).map(|t| rva(t, module_base)),
            false,
        ),
    }
}

pub fn scan<S>(
    source: &S,
    module_base: usize,
    regions: &[Region],
    patterns: &[Pattern],
) -> ScanResult
where
    S: MemorySource + Sync,
{
    let compiled: Vec<(Kind, Option<CompiledPattern>)> = patterns
        .iter()
        .map(|p| {
            let (kind, _) = Kind::classify(&p.name);
            (kind, CompiledPattern::new(&p.signature))
        })
        .collect();

    let hits: Vec<Hit> = regions
        .par_iter()
        .flat_map_iter(|region| {
            let mut buf = vec![0u8; region.size];
            let read = source.read_into(region.base, &mut buf).unwrap_or(0);
            buf.truncate(read);
            let mut local = Vec::new();
            for (idx, (kind, compiled)) in compiled.iter().enumerate() {
                let Some(cp) = compiled else { continue };
                if buf.len() < cp.len() {
                    continue;
                }
                for off in scanner::find_all(&buf, cp) {
                    let addr = region.base + off;
                    let (value, is_offset) = resolve(*kind, source, module_base, addr, &buf[off..]);
                    local.push(Hit {
                        pattern_idx: idx,
                        addr,
                        value,
                        is_offset,
                    });
                }
            }
            local
        })
        .collect();

    let total_matches = hits.len();
    let mut by_pattern: Vec<Vec<&Hit>> = vec![Vec::new(); patterns.len()];
    for hit in &hits {
        by_pattern[hit.pattern_idx].push(hit);
    }

    let mut findings = Vec::new();
    let mut found = Vec::new();
    let mut matched_unresolved = Vec::new();
    let mut not_found = Vec::new();

    for (idx, pattern) in patterns.iter().enumerate() {
        let group = &mut by_pattern[idx];
        if group.is_empty() {
            not_found.push(pattern.name.clone());
            continue;
        }
        group.sort_by_key(|h| h.addr);
        if let Some((value, is_offset)) =
            group.iter().find_map(|h| h.value.map(|v| (v, h.is_offset)))
        {
            let (_, base) = Kind::classify(&pattern.name);
            findings.push(Finding {
                name: base.to_string(),
                category: pattern.category.clone(),
                value,
                is_offset,
            });
            found.push(pattern.name.clone());
        } else {
            matched_unresolved.push(pattern.name.clone());
        }
    }

    ScanResult {
        findings,
        found,
        matched_unresolved,
        not_found,
        total_matches,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::BufferSource;
    use crate::pattern::Arch;
    use crate::pattern::parse_patterns;

    #[test]
    fn scans_and_resolves_against_buffer() {
        let base = 0x1000usize;
        let mut data = vec![0u8; 64];
        data[0x10..0x14].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        data[0x20..0x27].copy_from_slice(&[0x48, 0x8D, 0x0D, 0x09, 0x00, 0x00, 0x00]);
        let source = BufferSource::new(base, data);
        let regions = [Region { base, size: 64 }];
        let patterns = parse_patterns("Foo = DE AD BE EF\nBar_PTR = 48 8D 0D ? ? ? ?", Arch::X64);

        let result = scan(&source, base, &regions, &patterns);

        let foo = result.findings.iter().find(|f| f.name == "Foo").unwrap();
        assert_eq!(foo.value, 0x10);
        assert!(!foo.is_offset);
        let bar = result.findings.iter().find(|f| f.name == "Bar").unwrap();
        assert_eq!(bar.value, 0x30);
        assert_eq!(result.found.len(), 2);
        assert!(result.not_found.is_empty());
    }

    #[test]
    fn reports_not_found_and_unresolved() {
        let base = 0x2000usize;
        let data = vec![0u8; 32];
        let source = BufferSource::new(base, data);
        let regions = [Region { base, size: 32 }];
        let patterns = parse_patterns("Missing = 11 22 33 44", Arch::X64);

        let result = scan(&source, base, &regions, &patterns);
        assert_eq!(result.not_found, vec!["Missing"]);
        assert!(result.findings.is_empty());
    }
}
