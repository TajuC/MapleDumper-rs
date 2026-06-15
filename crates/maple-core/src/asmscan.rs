use crate::engine::{ReadGap, read_range};
use crate::memory::{MemorySource, Region};
use crate::pattern::Arch;
use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, NasmFormatter};
use rayon::prelude::*;
use std::sync::atomic::{AtomicBool, Ordering};

const ASM_CHUNK: usize = 1 << 20;
const LEAD_OVERLAP: usize = 64;
const MAX_INSTR_BYTES: usize = 15;

#[derive(Debug, Clone)]
pub struct AsmHit {
    pub rva: u64,
    pub address: u64,
    pub bytes: Vec<u8>,
    pub lines: Vec<String>,
}

/// The matches plus any region windows that read short. Tracking the gaps is what lets a caller
/// distinguish "no match" over fully-read code from "no match" over code that was partly unreadable,
/// the same distinction the byte-scan engine already reports.
#[derive(Debug, Clone, Default)]
pub struct AsmScanResult {
    pub hits: Vec<AsmHit>,
    pub read_gaps: Vec<ReadGap>,
}

#[derive(Clone, Copy)]
enum Tok {
    Star,
    Any,
    Lit(u8),
}

struct LineMatcher {
    toks: Vec<Tok>,
}

pub struct AsmPattern {
    lines: Vec<LineMatcher>,
}

// Lowercase, collapse whitespace runs to one space, and tighten spaces around commas, so the
// pattern and the disassembled text compare the same way regardless of how the user spaced it.
fn normalize(text: &str) -> String {
    let collapsed: String = text
        .to_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    collapsed.replace(", ", ",").replace(" ,", ",")
}

fn compile_line(raw: &str) -> LineMatcher {
    let mut s = raw.trim();
    let anchored_start = s.starts_with('^');
    if anchored_start {
        s = &s[1..];
    }
    let anchored_end = s.ends_with('$');
    if anchored_end {
        s = &s[..s.len() - 1];
    }
    let body = normalize(s);

    let mut toks = Vec::new();
    if !anchored_start {
        toks.push(Tok::Star);
    }
    for &b in body.as_bytes() {
        match b {
            b'*' => {
                if !matches!(toks.last(), Some(Tok::Star)) {
                    toks.push(Tok::Star);
                }
            }
            b'?' => toks.push(Tok::Any),
            _ => toks.push(Tok::Lit(b)),
        }
    }
    if !anchored_end {
        toks.push(Tok::Star);
    }
    LineMatcher { toks }
}

impl LineMatcher {
    // Iterative glob with `*` backtracking; `hay` must already be normalized.
    fn matches(&self, hay: &[u8]) -> bool {
        let toks = &self.toks;
        let (mut ti, mut hi) = (0usize, 0usize);
        let (mut star_ti, mut star_hi): (Option<usize>, usize) = (None, 0);
        while hi < hay.len() {
            let advanced = ti < toks.len()
                && match toks[ti] {
                    Tok::Lit(c) if c == hay[hi] => {
                        ti += 1;
                        hi += 1;
                        true
                    }
                    Tok::Any => {
                        ti += 1;
                        hi += 1;
                        true
                    }
                    Tok::Star => {
                        star_ti = Some(ti);
                        star_hi = hi;
                        ti += 1;
                        true
                    }
                    _ => false,
                };
            if advanced {
                continue;
            }
            if let Some(sti) = star_ti {
                ti = sti + 1;
                star_hi += 1;
                hi = star_hi;
            } else {
                return false;
            }
        }
        while ti < toks.len() && matches!(toks[ti], Tok::Star) {
            ti += 1;
        }
        ti == toks.len()
    }
}

#[must_use]
pub fn parse_asm_patterns(text: &str) -> Option<AsmPattern> {
    let lines: Vec<LineMatcher> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(compile_line)
        .collect();
    (!lines.is_empty()).then_some(AsmPattern { lines })
}

#[must_use]
pub fn assembly_scan<S: MemorySource + Sync>(
    source: &S,
    module_base: usize,
    regions: &[Region],
    arch: Arch,
    patterns: &AsmPattern,
    cancel: &AtomicBool,
) -> AsmScanResult {
    assembly_scan_with(
        source,
        module_base,
        regions,
        arch,
        patterns,
        cancel,
        ASM_CHUNK,
        LEAD_OVERLAP,
    )
}

#[allow(clippy::too_many_arguments)]
fn assembly_scan_with<S: MemorySource + Sync>(
    source: &S,
    module_base: usize,
    regions: &[Region],
    arch: Arch,
    patterns: &AsmPattern,
    cancel: &AtomicBool,
    chunk: usize,
    lead: usize,
) -> AsmScanResult {
    let n = patterns.lines.len();
    if n == 0 {
        return AsmScanResult::default();
    }
    let bitness = if matches!(arch, Arch::X64) { 64 } else { 32 };
    let chunk = chunk.max(1);
    let module_base = module_base as u64;

    let mut units: Vec<(usize, u64, u64, usize)> = Vec::new();
    for region in regions {
        let mut off = 0;
        while off < region.size {
            let accept = chunk.min(region.size - off);
            let accept_start = region.base + off;
            let read_base = accept_start.saturating_sub(lead).max(region.base);
            let read_end = (accept_start + accept + n * MAX_INSTR_BYTES).min(region.end());
            units.push((
                read_base,
                accept_start as u64,
                (accept_start + accept) as u64,
                read_end - read_base,
            ));
            off += accept;
        }
    }

    // A window that reads short hit an unreadable hole; record it so a "no match" over partial code is
    // reported as inconclusive instead of a confident absence, matching the byte-scan engine.
    let read_gaps = std::sync::Mutex::new(Vec::<ReadGap>::new());
    let mut hits: Vec<AsmHit> = units
        .par_iter()
        .flat_map_iter(|&(read_base, accept_start, accept_end, read_len)| {
            if cancel.load(Ordering::Relaxed) {
                return Vec::new().into_iter();
            }
            let buf = read_range(source, read_base, read_len);
            if buf.len() < read_len
                && let Ok(mut gaps) = read_gaps.lock()
            {
                gaps.push(ReadGap {
                    base: read_base,
                    requested: read_len,
                    got: buf.len(),
                });
            }
            scan_unit(
                &buf,
                read_base as u64,
                accept_start,
                accept_end,
                module_base,
                bitness,
                patterns,
                n,
                cancel,
            )
            .into_iter()
        })
        .collect();
    hits.sort_by_key(|h| h.address);
    hits.dedup_by_key(|h| h.address);
    let mut read_gaps = read_gaps
        .into_inner()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    read_gaps.sort_by_key(|g| g.base);
    AsmScanResult { hits, read_gaps }
}

#[allow(clippy::too_many_arguments)]
fn scan_unit(
    buf: &[u8],
    read_base: u64,
    accept_start: u64,
    accept_end: u64,
    module_base: u64,
    bitness: u32,
    patterns: &AsmPattern,
    n: usize,
    cancel: &AtomicBool,
) -> Vec<AsmHit> {
    let mut items: Vec<(u64, usize, String)> = Vec::new();
    let mut decoder = Decoder::with_ip(bitness, buf, read_base, DecoderOptions::NONE);
    let mut formatter = NasmFormatter::new();
    let mut instr = Instruction::default();
    let mut text = String::new();
    let mut count = 0u32;
    while decoder.can_decode() {
        count = count.wrapping_add(1);
        if count.is_multiple_of(4096) && cancel.load(Ordering::Relaxed) {
            return Vec::new();
        }
        let start_pos = decoder.position();
        decoder.decode_out(&mut instr);
        if instr.is_invalid() {
            // resync one byte past the start of the bad instruction so code after a data island is
            // still scanned, instead of abandoning the rest of the chunk
            if decoder.set_position(start_pos + 1).is_err() {
                break;
            }
            decoder.set_ip(read_base + (start_pos + 1) as u64);
            continue;
        }
        text.clear();
        formatter.format(&instr, &mut text);
        items.push((instr.ip(), instr.len(), normalize(&text)));
    }

    let mut hits = Vec::new();
    for i in 0..items.len() {
        if items[i].0 < accept_start || items[i].0 >= accept_end {
            continue;
        }
        if i + n > items.len() {
            break;
        }
        let contiguous = (i..i + n - 1).all(|k| items[k].0 + items[k].1 as u64 == items[k + 1].0);
        if !contiguous {
            continue;
        }
        if !(0..n).all(|k| patterns.lines[k].matches(items[i + k].2.as_bytes())) {
            continue;
        }
        let start_off = (items[i].0 - read_base) as usize;
        let last = &items[i + n - 1];
        let end_off = (last.0 + last.1 as u64 - read_base) as usize;
        hits.push(AsmHit {
            rva: items[i].0 - module_base,
            address: items[i].0,
            bytes: buf[start_off..end_off].to_vec(),
            lines: (0..n).map(|k| items[i + k].2.clone()).collect(),
        });
    }
    hits
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::BufferSource;

    fn pat(text: &str) -> AsmPattern {
        parse_asm_patterns(text).unwrap()
    }

    #[test]
    fn line_matcher_handles_wildcards_anchors_and_case() {
        assert!(compile_line("push").matches(b"push rax"));
        assert!(!compile_line("pop").matches(b"push rax"));
        assert!(compile_line("PUSH").matches(b"push rax"));
        assert!(compile_line("eax").matches(b"test eax,eax"));
        assert!(compile_line("test ?ax,?ax").matches(b"test eax,eax"));
        assert!(compile_line("test ?ax,?ax").matches(b"test rax,rax"));
        assert!(!compile_line("test ?ax,?bx").matches(b"test eax,eax"));
        assert!(compile_line("mov*rcx").matches(b"mov rdi,rcx"));
        assert!(compile_line("^push$").matches(b"push"));
        assert!(!compile_line("^push$").matches(b"push rax"));
        assert!(compile_line("test eax, eax").matches(b"test eax,eax"));
    }

    #[test]
    fn parse_drops_blank_and_comment_lines() {
        assert!(parse_asm_patterns("   \n  \n").is_none());
        assert!(parse_asm_patterns("# just a comment").is_none());
        assert_eq!(
            parse_asm_patterns("push\n# note\ncall")
                .unwrap()
                .lines
                .len(),
            2
        );
    }

    #[test]
    fn scans_known_code() {
        let base = 0x1000usize;
        let blob = vec![
            0x50, 0x51, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x85, 0xC0, 0xC3, 0x90,
        ];
        let src = BufferSource::new(base, blob);
        let regions = [Region { base, size: 11 }];
        let cancel = AtomicBool::new(false);

        let hits = assembly_scan(&src, base, &regions, Arch::X64, &pat("push"), &cancel).hits;
        assert_eq!(
            hits.iter().map(|h| h.address).collect::<Vec<_>>(),
            vec![0x1000, 0x1001]
        );
        assert_eq!((hits[0].rva, hits[1].rva), (0, 1));

        let seq = assembly_scan(
            &src,
            base,
            &regions,
            Arch::X64,
            &pat("push rcx\ncall"),
            &cancel,
        )
        .hits;
        assert_eq!(
            seq.iter().map(|h| h.address).collect::<Vec<_>>(),
            vec![0x1001]
        );

        assert!(
            assembly_scan(&src, base, &regions, Arch::X64, &pat("^push$"), &cancel)
                .hits
                .is_empty()
        );
        assert!(
            assembly_scan(&src, base, &regions, Arch::X64, &pat("syscall"), &cancel)
                .hits
                .is_empty()
        );
    }

    #[test]
    fn nasm_format_convention_is_tight() {
        let src = BufferSource::new(0x1000, vec![0x48, 0x8B, 0xF9]);
        let regions = [Region {
            base: 0x1000,
            size: 3,
        }];
        let cancel = AtomicBool::new(false);
        let hits = assembly_scan(
            &src,
            0x1000,
            &regions,
            Arch::X64,
            &pat("mov rdi,rcx"),
            &cancel,
        )
        .hits;
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].lines, vec!["mov rdi,rcx".to_string()]);
    }

    #[test]
    fn boundary_matches_counted_once() {
        let base = 0x2000usize;
        let mut blob = Vec::new();
        for _ in 0..20 {
            blob.push(0x50);
            blob.push(0x51);
        }
        let src = BufferSource::new(base, blob.clone());
        let regions = [Region {
            base,
            size: blob.len(),
        }];
        let cancel = AtomicBool::new(false);
        let hits = assembly_scan_with(
            &src,
            base,
            &regions,
            Arch::X64,
            &pat("push rax\npush rcx"),
            &cancel,
            4,
            64,
        )
        .hits;
        assert_eq!(hits.len(), 20);
        let mut addrs: Vec<u64> = hits.iter().map(|h| h.address).collect();
        addrs.dedup();
        assert_eq!(addrs.len(), 20);
    }

    #[test]
    fn cancel_returns_empty() {
        let src = BufferSource::new(0x3000, vec![0x50; 100]);
        let regions = [Region {
            base: 0x3000,
            size: 100,
        }];
        let cancel = AtomicBool::new(true);
        assert!(
            assembly_scan(&src, 0x3000, &regions, Arch::X64, &pat("push"), &cancel)
                .hits
                .is_empty()
        );
    }

    #[test]
    fn scan_resyncs_after_invalid_byte() {
        let base = 0x1000usize;
        // push rax, a byte that does not decode in 64-bit mode, then push rcx
        let blob = vec![0x50, 0x06, 0x51];
        let src = BufferSource::new(base, blob.clone());
        let regions = [Region {
            base,
            size: blob.len(),
        }];
        let cancel = AtomicBool::new(false);
        let hits = assembly_scan(&src, base, &regions, Arch::X64, &pat("push rcx"), &cancel).hits;
        assert_eq!(
            hits.iter().map(|h| h.address).collect::<Vec<_>>(),
            vec![0x1002]
        );
    }

    // A source that can only read the first `cap` bytes, so a window past it reads short. Mirrors the
    // byte-scan engine's gap test: models a decommitted or guarded tail in a live module.
    struct CappedSource {
        base: usize,
        data: Vec<u8>,
        cap: usize,
    }

    impl MemorySource for CappedSource {
        fn read_into(&self, address: usize, buf: &mut [u8]) -> std::io::Result<usize> {
            if address < self.base {
                return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput));
            }
            let off = address - self.base;
            if off >= self.cap {
                return Ok(0);
            }
            let avail = (self.cap - off).min(self.data.len().saturating_sub(off));
            let n = buf.len().min(avail);
            buf[..n].copy_from_slice(&self.data[off..off + n]);
            Ok(n)
        }
    }

    #[test]
    fn records_a_read_gap_over_an_unreadable_tail() {
        let base = 0x4000usize;
        let mut data = vec![0x90u8; 0x400];
        data[0] = 0x50; // push rax in the readable head
        let src = CappedSource {
            base,
            data,
            cap: 0x200,
        };
        let regions = [Region { base, size: 0x400 }];
        let cancel = AtomicBool::new(false);
        let result = assembly_scan(&src, base, &regions, Arch::X64, &pat("push rax"), &cancel);
        assert!(
            !result.read_gaps.is_empty(),
            "a short read must be recorded as a gap"
        );
        // the instruction in the readable head is still found despite the unreadable tail
        assert!(result.hits.iter().any(|h| h.address == base as u64));
    }
}
