use crate::memory::{MemorySource, Region};
use crate::pattern::{Arch, Pattern};
use crate::resolver::ResolverSpec;
use crate::scanner;
use std::hint::black_box;
use std::time::Instant;

use super::scan::{CompiledPat, SCAN_CHUNK, compile_patterns, read_range, resolve, scan_chunked};

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
        for (pat, c) in compiled.iter().enumerate() {
            let Some(cp) = c.cp.as_ref() else { continue };
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
        let pat = &compiled[p.pat];
        if pat.spec == ResolverSpec::NestedCall {
            call_hits += 1;
        }
        let addr = bufs[p.buf].0 + p.off;
        // Section validation is a correctness check, not a timing one; profiling passes no
        // executable regions so the resolve cost it measures matches the real scan path.
        let (_, outcome) = resolve(
            pat.spec,
            pat.expected_section,
            pat.instruction_offset,
            pat.operand_index,
            source,
            module_base,
            module_size,
            &[],
            addr,
            &bufs[p.buf].1[p.off..],
            arch,
        );
        acc = acc.wrapping_add(outcome.map(|r| r.value).unwrap_or(0));
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
        &[],
        patterns,
        arch,
        None,
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
    let bytes: u64 = regions.iter().map(|r| r.size as u64).sum();
    let cores = std::thread::available_parallelism().map_or(1, |n| n.get());

    let read_ms = read_sweep(source, regions, BLOCK, &[1, 2, 4]);

    let bufs: Vec<(usize, Vec<u8>)> = regions
        .iter()
        .map(|r| (r.base, read_range(source, r.base, r.size)))
        .collect();

    let (scan_serial_ms, found) = scan_serial(&bufs, &compiled);

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
        matches: found.len(),
        resolve_ms,
        call_hits,
        full_ms,
        chunk_ms,
    }
}
