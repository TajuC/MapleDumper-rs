use crate::domain::{FailureReason, FindingStatus, checked_rva};
use crate::memory::{MemorySource, Region};
use crate::output::Finding;
use crate::pattern::{Arch, Pattern};
use crate::resolver::{self, Kind, ResolverSpec};
use crate::scanner::{self, CompiledPattern, ScannerIndex};
use rayon::prelude::*;
use std::hint::black_box;
use std::time::Instant;

pub struct PatternRow {
    pub name: String,
    pub category: String,
    pub pattern: String,
    pub value: Option<u64>,
    pub is_offset: bool,
    pub matches: usize,
    pub status: FindingStatus,
    pub note: String,
}

pub struct ScanResult {
    pub findings: Vec<Finding>,
    pub rows: Vec<PatternRow>,
    pub found: Vec<String>,
    pub matched_unresolved: Vec<String>,
    pub not_found: Vec<String>,
    pub total_matches: usize,
}

#[derive(Clone, Copy)]
enum Resolved {
    Addr(u64),
    Off(u64),
}

impl Resolved {
    fn value(self) -> u64 {
        match self {
            Resolved::Addr(v) | Resolved::Off(v) => v,
        }
    }
    fn is_offset(self) -> bool {
        matches!(self, Resolved::Off(_))
    }
}

struct Hit {
    pattern_idx: usize,
    addr: usize,
    outcome: Result<Resolved, FailureReason>,
}

// Extra bytes read past a chunk's accept window so a pattern starting near the end still
// matches in full and the resolver has enough trailing bytes to decode.
const RESOLVE_MARGIN: usize = 24;
// Accept-window size per parallel work unit. Smaller windows load-balance better across cores;
// profiling a 143 MB module on 16 cores put the knee at 256 KiB (~6x faster than the old 4 MiB).
const SCAN_CHUNK: usize = 1 << 18;
// Above this many patterns the per-pattern AVX2 scan (one buffer pass per pattern) is replaced by a
// single-pass multi-pattern index, so cost grows with the buffer plus matches, not buffer times
// pattern count. Below it the tuned AVX2 path is kept.
const MULTI_PATTERN_THRESHOLD: usize = 64;

pub(crate) fn read_range<S: MemorySource>(source: &S, base: usize, len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    let read = source.read_into(base, &mut buf).unwrap_or(0);
    buf.truncate(read);
    buf
}

// A streamed block: base address, accept-window length, and the accept+overlap bytes read.
type Block = (usize, usize, Vec<u8>);

fn resolve<S: MemorySource>(
    kind: Kind,
    source: &S,
    module_base: usize,
    module_size: usize,
    addr: usize,
    bytes: &[u8],
    arch: Arch,
) -> Result<Resolved, FailureReason> {
    let addr_rva =
        |target: usize| checked_rva(target, module_base, module_size).map(Resolved::Addr);
    match kind.spec() {
        ResolverSpec::MatchAddress => addr_rva(addr),
        ResolverSpec::MemoryPointer => resolver::extract_pointer(bytes, addr, arch)
            .ok_or(FailureReason::Unresolved)
            .and_then(addr_rva),
        ResolverSpec::StructOffset => resolver::extract_offset(bytes, 4, arch)
            .map(|v| Resolved::Off(u64::from(v)))
            .ok_or(FailureReason::Unresolved),
        ResolverSpec::Immediate => resolver::extract_immediate(bytes, 4)
            .map(|v| Resolved::Off(u64::from(v)))
            .ok_or(FailureReason::Unresolved),
        ResolverSpec::NestedCall => resolver::resolve_call(source, addr, bytes, arch)
            .ok_or(FailureReason::Unresolved)
            .and_then(addr_rva),
    }
}

pub fn scan<S>(
    source: &S,
    module_base: usize,
    module_size: usize,
    regions: &[Region],
    patterns: &[Pattern],
    arch: Arch,
) -> ScanResult
where
    S: MemorySource + Sync,
{
    scan_chunked(
        source,
        module_base,
        module_size,
        regions,
        patterns,
        arch,
        SCAN_CHUNK,
    )
}

fn scan_chunked<S>(
    source: &S,
    module_base: usize,
    module_size: usize,
    regions: &[Region],
    patterns: &[Pattern],
    arch: Arch,
    chunk: usize,
) -> ScanResult
where
    S: MemorySource + Sync,
{
    let compiled = compile_patterns(patterns);

    let max_len = compiled
        .iter()
        .filter_map(|(_, c)| c.as_ref().map(CompiledPattern::len))
        .max()
        .unwrap_or(1);
    let overlap = max_len.max(RESOLVE_MARGIN);
    let block = chunk.max(1);

    // Above a pattern-count threshold, scan each block once with a multi-pattern index instead of
    // once per pattern; below it the tuned per-pattern AVX2 path is kept.
    let index = (patterns.len() >= MULTI_PATTERN_THRESHOLD).then(|| {
        ScannerIndex::build(
            compiled
                .iter()
                .enumerate()
                .filter_map(|(i, (_, c))| c.as_ref().map(|cp| (i, cp))),
        )
    });

    // A few reader threads stream region windows into the channel while the rayon pool scans them.
    // Each hit is kept only by the window covering its start, so a match straddling a boundary is
    // counted once no matter which reader produced it or in what order blocks arrive.
    let mut units: Vec<(usize, usize, usize)> = Vec::new();
    for region in regions {
        let mut off = 0;
        while off < region.size {
            let accept = block.min(region.size - off);
            let read_len = (accept + overlap).min(region.size - off);
            units.push((region.base + off, accept, read_len));
            off += accept;
        }
    }
    let units = &units;
    let readers = std::thread::available_parallelism()
        .map_or(1, |n| n.get())
        .clamp(1, 4);

    let hits: Vec<Hit> = std::thread::scope(|scope| {
        let (tx, rx) = std::sync::mpsc::sync_channel::<Block>(readers * 2 + 4);
        for w in 0..readers {
            let tx = tx.clone();
            scope.spawn(move || {
                let mut i = w;
                while i < units.len() {
                    let (base, accept, read_len) = units[i];
                    let buf = read_range(source, base, read_len);
                    if tx.send((base, accept, buf)).is_err() {
                        return;
                    }
                    i += readers;
                }
            });
        }
        drop(tx);
        rx.into_iter()
            .par_bridge()
            .flat_map_iter(|(base, accept_len, buf)| {
                let mut local = Vec::new();
                if let Some(index) = index.as_ref() {
                    index.scan(&buf, accept_len, |idx, off| {
                        let addr = base + off;
                        let kind = compiled[idx].0;
                        let outcome = resolve(
                            kind,
                            source,
                            module_base,
                            module_size,
                            addr,
                            &buf[off..],
                            arch,
                        );
                        local.push(Hit {
                            pattern_idx: idx,
                            addr,
                            outcome,
                        });
                    });
                } else {
                    for (idx, (kind, cp)) in compiled.iter().enumerate() {
                        let Some(cp) = cp else { continue };
                        if buf.len() < cp.len() {
                            continue;
                        }
                        for off in scanner::find_all(&buf, cp) {
                            if off >= accept_len {
                                continue;
                            }
                            let addr = base + off;
                            let outcome = resolve(
                                *kind,
                                source,
                                module_base,
                                module_size,
                                addr,
                                &buf[off..],
                                arch,
                            );
                            local.push(Hit {
                                pattern_idx: idx,
                                addr,
                                outcome,
                            });
                        }
                    }
                }
                local
            })
            .collect()
    });

    let total_matches = hits.len();
    let mut by_pattern: Vec<Vec<&Hit>> = vec![Vec::new(); patterns.len()];
    for hit in &hits {
        by_pattern[hit.pattern_idx].push(hit);
    }

    let mut findings = Vec::new();
    let mut rows = Vec::new();
    let mut found = Vec::new();
    let mut matched_unresolved = Vec::new();
    let mut not_found = Vec::new();

    for (idx, pattern) in patterns.iter().enumerate() {
        let (_, base) = Kind::classify(&pattern.name);
        let category = pattern
            .category
            .clone()
            .unwrap_or_else(|| crate::categorizer::builtin_category(base).to_string());
        let aob = pattern.signature.to_aob();
        let note = pattern.note.clone().unwrap_or_default();
        let group = &mut by_pattern[idx];
        let match_count = group.len();

        if group.is_empty() {
            not_found.push(pattern.name.clone());
            rows.push(PatternRow {
                name: base.to_string(),
                category,
                pattern: aob,
                value: None,
                is_offset: false,
                matches: 0,
                status: FindingStatus::NotFound,
                note,
            });
            continue;
        }

        group.sort_by_key(|h| h.addr);
        if let Some(resolved) = group.iter().find_map(|h| h.outcome.as_ref().ok().copied()) {
            let value = resolved.value();
            let is_offset = resolved.is_offset();
            found.push(pattern.name.clone());
            // Only a unique match is exported as a normal offset. An ambiguous match is shown in the
            // results for inspection but kept out of findings, so it cannot silently become an entry
            // in offsets.h or a Cheat Engine table.
            let status = if match_count > 1 {
                FindingStatus::FoundAmbiguous {
                    candidates: match_count,
                }
            } else {
                findings.push(Finding {
                    name: base.to_string(),
                    category: category.clone(),
                    value,
                    is_offset,
                });
                FindingStatus::FoundUnique
            };
            rows.push(PatternRow {
                name: base.to_string(),
                category,
                pattern: aob,
                value: Some(value),
                is_offset,
                matches: match_count,
                status,
                note,
            });
        } else {
            // matched but nothing resolved: surface an out-of-module target distinctly from a
            // decode miss, since it usually means the signature landed on the wrong instruction.
            let reason = group
                .iter()
                .find_map(|h| match &h.outcome {
                    Err(FailureReason::OutOfModule) => Some(FailureReason::OutOfModule),
                    _ => None,
                })
                .unwrap_or(FailureReason::Unresolved);
            matched_unresolved.push(pattern.name.clone());
            rows.push(PatternRow {
                name: base.to_string(),
                category,
                pattern: aob,
                value: None,
                is_offset: false,
                matches: match_count,
                status: FindingStatus::Failed(reason),
                note,
            });
        }
    }

    ScanResult {
        findings,
        rows,
        found,
        matched_unresolved,
        not_found,
        total_matches,
    }
}

type CompiledPat = (Kind, Option<CompiledPattern>);

fn compile_patterns(patterns: &[Pattern]) -> Vec<CompiledPat> {
    patterns
        .iter()
        .map(|p| {
            let (kind, _) = Kind::classify(&p.name);
            (kind, CompiledPattern::new(&p.signature))
        })
        .collect()
}

#[derive(Clone, Copy)]
struct Probe {
    buf: usize,
    off: usize,
    pat: usize,
}

fn read_sweep<S: MemorySource + Sync>(
    source: &S,
    regions: &[Region],
    block: usize,
    counts: &[usize],
) -> Vec<(usize, u128)> {
    let mut blocks: Vec<(usize, usize)> = Vec::new();
    for region in regions {
        let mut off = 0;
        while off < region.size {
            let len = block.min(region.size - off);
            blocks.push((region.base + off, len));
            off += len;
        }
    }
    let blocks = &blocks;
    counts
        .iter()
        .map(|&readers| {
            let t = Instant::now();
            std::thread::scope(|scope| {
                for w in 0..readers {
                    scope.spawn(move || {
                        let mut i = w;
                        while i < blocks.len() {
                            let (base, len) = blocks[i];
                            black_box(read_range(source, base, len));
                            i += readers;
                        }
                    });
                }
            });
            (readers, t.elapsed().as_millis())
        })
        .collect()
}

fn scan_serial(bufs: &[(usize, Vec<u8>)], compiled: &[CompiledPat]) -> (u128, Vec<Probe>) {
    let mut found = Vec::new();
    let t = Instant::now();
    for (buf, (_, data)) in bufs.iter().enumerate() {
        for (pat, (_, cp)) in compiled.iter().enumerate() {
            let Some(cp) = cp else { continue };
            if data.len() < cp.len() {
                continue;
            }
            for off in scanner::find_all(data, cp) {
                found.push(Probe { buf, off, pat });
            }
        }
    }
    (t.elapsed().as_millis(), found)
}

fn scan_parallel(
    bufs: &[(usize, Vec<u8>)],
    compiled: &[CompiledPat],
    block: usize,
    overlap: usize,
) -> u128 {
    let mut units: Vec<(usize, usize, usize)> = Vec::new();
    for (bi, (_, data)) in bufs.iter().enumerate() {
        let mut off = 0;
        while off < data.len() {
            let accept = block.min(data.len() - off);
            units.push((bi, off, accept));
            off += accept;
        }
    }
    let t = Instant::now();
    let hits: usize = units
        .par_iter()
        .map(|&(bi, start, accept)| {
            let data = &bufs[bi].1;
            let end = (start + accept + overlap).min(data.len());
            let slice = &data[start..end];
            compiled
                .iter()
                .filter_map(|(_, cp)| cp.as_ref())
                .filter(|cp| slice.len() >= cp.len())
                .map(|cp| {
                    scanner::find_all(slice, cp)
                        .iter()
                        .filter(|&&o| o < accept)
                        .count()
                })
                .sum::<usize>()
        })
        .sum();
    black_box(hits);
    t.elapsed().as_millis()
}

fn resolve_pass<S: MemorySource>(
    source: &S,
    module_base: usize,
    module_size: usize,
    bufs: &[(usize, Vec<u8>)],
    compiled: &[CompiledPat],
    found: &[Probe],
    arch: Arch,
) -> (u128, usize) {
    let mut call_hits = 0;
    let mut acc = 0u64;
    let t = Instant::now();
    for p in found {
        let kind = compiled[p.pat].0;
        if kind == Kind::Call {
            call_hits += 1;
        }
        let addr = bufs[p.buf].0 + p.off;
        let outcome = resolve(
            kind,
            source,
            module_base,
            module_size,
            addr,
            &bufs[p.buf].1[p.off..],
            arch,
        );
        acc = acc.wrapping_add(outcome.map(Resolved::value).unwrap_or(0));
    }
    black_box(acc);
    (t.elapsed().as_millis(), call_hits)
}

fn time_scan<S: MemorySource + Sync>(
    source: &S,
    module_base: usize,
    module_size: usize,
    regions: &[Region],
    patterns: &[Pattern],
    arch: Arch,
    chunk: usize,
) -> u128 {
    let t = Instant::now();
    black_box(scan_chunked(
        source,
        module_base,
        module_size,
        regions,
        patterns,
        arch,
        chunk,
    ));
    t.elapsed().as_millis()
}

/// Phase-separated timing of a scan against a live target, so the read / scan / resolve split
/// can be measured instead of guessed. All times are milliseconds. Runs several full reads of
/// the module, so it is a one-off diagnostic, not a hot path.
#[derive(Debug, Clone)]
pub struct ProfileReport {
    pub regions: usize,
    pub bytes: u64,
    pub cores: usize,
    pub patterns: usize,
    pub read_ms: Vec<(usize, u128)>,
    pub scan_serial_ms: u128,
    pub scan_parallel_ms: u128,
    pub matches: usize,
    pub resolve_ms: u128,
    pub call_hits: usize,
    pub full_ms: u128,
    pub chunk_ms: Vec<(usize, u128)>,
}

#[must_use]
pub fn profile<S>(
    source: &S,
    module_base: usize,
    module_size: usize,
    regions: &[Region],
    patterns: &[Pattern],
    arch: Arch,
) -> ProfileReport
where
    S: MemorySource + Sync,
{
    const BLOCK: usize = 1 << 18;

    let compiled = compile_patterns(patterns);
    let max_len = compiled
        .iter()
        .filter_map(|(_, c)| c.as_ref().map(CompiledPattern::len))
        .max()
        .unwrap_or(1);
    let bytes: u64 = regions.iter().map(|r| r.size as u64).sum();
    let cores = std::thread::available_parallelism().map_or(1, |n| n.get());

    let read_ms = read_sweep(source, regions, BLOCK, &[1, 2, 4]);

    let bufs: Vec<(usize, Vec<u8>)> = regions
        .iter()
        .map(|r| (r.base, read_range(source, r.base, r.size)))
        .collect();

    let (scan_serial_ms, found) = scan_serial(&bufs, &compiled);

    let scan_parallel_ms = scan_parallel(&bufs, &compiled, BLOCK, max_len.max(1));

    let (resolve_ms, call_hits) = resolve_pass(
        source,
        module_base,
        module_size,
        &bufs,
        &compiled,
        &found,
        arch,
    );

    let full_ms = time_scan(
        source,
        module_base,
        module_size,
        regions,
        patterns,
        arch,
        SCAN_CHUNK,
    );

    let chunk_ms = [
        64usize << 10,
        128 << 10,
        256 << 10,
        512 << 10,
        1 << 20,
        2 << 20,
    ]
    .into_iter()
    .map(|size| {
        (
            size,
            time_scan(
                source,
                module_base,
                module_size,
                regions,
                patterns,
                arch,
                size,
            ),
        )
    })
    .collect();

    ProfileReport {
        regions: regions.len(),
        bytes,
        cores,
        patterns: patterns.len(),
        read_ms,
        scan_serial_ms,
        scan_parallel_ms,
        matches: found.len(),
        resolve_ms,
        call_hits,
        full_ms,
        chunk_ms,
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

        let result = scan(&source, base, 64, &regions, &patterns, Arch::X64);

        let foo = result.findings.iter().find(|f| f.name == "Foo").unwrap();
        assert_eq!(foo.value, 0x10);
        assert!(!foo.is_offset);
        let bar = result.findings.iter().find(|f| f.name == "Bar").unwrap();
        assert_eq!(bar.value, 0x30);
        assert_eq!(result.found.len(), 2);
        assert!(result.not_found.is_empty());
        assert_eq!(result.rows.len(), 2);
        assert!(
            result
                .rows
                .iter()
                .all(|r| r.status == FindingStatus::FoundUnique)
        );
    }

    #[test]
    fn reports_not_found_and_unresolved() {
        let base = 0x2000usize;
        let data = vec![0u8; 32];
        let source = BufferSource::new(base, data);
        let regions = [Region { base, size: 32 }];
        let patterns = parse_patterns("Missing = 11 22 33 44", Arch::X64);

        let result = scan(&source, base, 32, &regions, &patterns, Arch::X64);
        assert_eq!(result.not_found, vec!["Missing"]);
        assert!(result.findings.is_empty());
        assert_eq!(result.rows.len(), 1);
        assert_eq!(result.rows[0].status, FindingStatus::NotFound);
    }

    #[test]
    fn out_of_module_pointer_is_rejected_not_wrapped() {
        // a rip-relative lea whose target lands before the module base must not wrap into a
        // huge rva; it is reported as a failed resolve instead of a bogus finding.
        let base = 0x1_0000usize;
        let mut data = vec![0u8; 64];
        // 48 8D 0D <disp32> with a large negative displacement -> target far below base
        data[0x10..0x17].copy_from_slice(&[0x48, 0x8D, 0x0D, 0x00, 0x00, 0xFF, 0xFF]);
        let source = BufferSource::new(base, data);
        let regions = [Region { base, size: 64 }];
        let patterns = parse_patterns("Bad_PTR = 48 8D 0D ?? ?? ?? ??", Arch::X64);

        let result = scan(&source, base, 64, &regions, &patterns, Arch::X64);
        assert!(result.findings.is_empty());
        assert_eq!(result.rows.len(), 1);
        assert_eq!(
            result.rows[0].status,
            FindingStatus::Failed(FailureReason::OutOfModule)
        );
    }

    #[test]
    fn chunked_scan_finds_boundary_straddling_matches_once() {
        let base = 0x1000usize;
        let mut data = vec![0u8; 200];
        let sig = [0xDE, 0xAD, 0xBE, 0xEF, 0x11];
        // starts landing before, on, across, and in the overlap of 16-byte chunk boundaries
        let starts = [3usize, 33, 48, 64, 100, 190];
        for &s in &starts {
            data[s..s + sig.len()].copy_from_slice(&sig);
        }
        let source = BufferSource::new(base, data);
        let regions = [Region { base, size: 200 }];
        let patterns = parse_patterns("Foo = DE AD BE EF 11", Arch::X64);

        // a deliberately tiny chunk forces many boundaries; each match must appear exactly once
        let result = scan_chunked(&source, base, 200, &regions, &patterns, Arch::X64, 16);
        assert_eq!(result.total_matches, starts.len());
        assert_eq!(result.rows.len(), 1);
        assert_eq!(result.rows[0].matches, starts.len());
        assert!(matches!(
            result.rows[0].status,
            FindingStatus::FoundAmbiguous { candidates: 6 }
        ));
        // an ambiguous match is reported but never exported as a normal offset
        assert!(result.findings.is_empty());
    }

    #[test]
    fn scan_uses_multi_pattern_index_above_threshold() {
        let base = 0x1000usize;
        let count = MULTI_PATTERN_THRESHOLD + 4;
        let mut data = vec![0u8; count * 8];
        let mut text = String::new();
        for i in 0..count {
            let off = i * 8;
            let b = i as u8;
            data[off..off + 4].copy_from_slice(&[b, 0xAA, 0x5A, 0xBB]);
            text.push_str(&format!("P{i} = {b:02X} AA 5A BB\n"));
        }
        let source = BufferSource::new(base, data);
        let regions = [Region {
            base,
            size: count * 8,
        }];
        let patterns = parse_patterns(&text, Arch::X64);

        let result = scan(&source, base, count * 8, &regions, &patterns, Arch::X64);
        assert_eq!(result.found.len(), count);
        assert!(result.not_found.is_empty());
    }
}
