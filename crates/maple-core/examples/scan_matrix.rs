// Compares scanning many patterns the old way (one find_all pass per pattern) against the
// single-pass ScannerIndex, across pattern counts and anchor styles, and prints CSV. This is the
// evidence behind the engine's MULTI_PATTERN_THRESHOLD. Run with:
//   cargo run --release --example scan_matrix -p maple-core
use maple_core::pattern::Signature;
use maple_core::scanner::{CompiledPattern, ScannerIndex, find_all};
use std::time::Instant;

fn xorshift(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

// A code-like haystack: a mix of common x86 bytes and noise, so anchor rarity matters.
fn code_like(len: usize, seed: u64) -> Vec<u8> {
    let common = [0x00u8, 0x48, 0xFF, 0x8B, 0xCC, 0x40, 0xE8, 0x89];
    let mut s = seed;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        let r = xorshift(&mut s);
        let byte = if r.is_multiple_of(4) {
            (r >> 16) as u8
        } else {
            common[(r as usize >> 3) % common.len()]
        };
        out.push(byte);
    }
    out
}

#[derive(Clone, Copy, PartialEq)]
enum Style {
    Varied,
    SharedAnchor,
}

// `count` distinct ~12-byte patterns with ~40% wildcards. Varied: each anchors on a distinct byte
// (small buckets). SharedAnchor: every pattern's rarest byte is 0xA7 (one large bucket, the worst
// case the reviewer asked about).
fn make_patterns(count: usize, style: Style, seed: u64) -> Vec<CompiledPattern> {
    let plen = 12usize;
    let mut s = seed;
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let mut bytes = vec![0u8; plen];
        let mut mask = vec![false; plen];
        for k in 0..plen {
            let r = xorshift(&mut s);
            if r.is_multiple_of(5) {
                mask[k] = false;
            } else {
                mask[k] = true;
                bytes[k] = (r >> 8) as u8;
            }
        }
        match style {
            Style::Varied => {
                // a distinct, rare-ish first byte so each pattern anchors on its own bucket
                bytes[0] = 0x10u8.wrapping_add(i as u8);
                mask[0] = true;
            }
            Style::SharedAnchor => {
                bytes[0] = 0xA7; // shared rare anchor
                mask[0] = true;
                bytes[1] = i as u8; // distinctness
                mask[1] = true;
                for b in bytes.iter_mut().skip(2) {
                    *b = 0x48; // common bytes so 0xA7 stays the rarest anchor
                }
                for m in mask.iter_mut().skip(2) {
                    *m = true;
                }
            }
        }
        if let Some(cp) = CompiledPattern::new(&Signature { bytes, mask }) {
            out.push(cp);
        }
    }
    out
}

fn main() {
    let len = 8 * 1024 * 1024;
    let haystack = code_like(len, 0x9E37_79B9_7F4A_7C15);
    let gib = len as f64 / (1024.0 * 1024.0 * 1024.0);
    println!("patterns,style,approach,ms,gib_per_s,matches");
    for &count in &[10usize, 50, 100, 500] {
        for &(style, name) in &[
            (Style::Varied, "varied"),
            (Style::SharedAnchor, "shared_anchor"),
        ] {
            let pats = make_patterns(count, style, 0xDEAD_BEEF ^ (count as u64));

            let t = Instant::now();
            let mut hits = 0usize;
            for p in &pats {
                hits += find_all(&haystack, p).len();
            }
            let ms = t.elapsed().as_secs_f64() * 1000.0;
            println!(
                "{count},{name},per_pattern,{ms:.1},{:.2},{hits}",
                gib / (ms / 1000.0)
            );

            let index = ScannerIndex::build(pats.iter().enumerate());
            let t = Instant::now();
            let mut ihits = 0usize;
            index.scan(&haystack, haystack.len(), |_, _| ihits += 1);
            let ms = t.elapsed().as_secs_f64() * 1000.0;
            println!(
                "{count},{name},scanner_index,{ms:.1},{:.2},{ihits}",
                gib / (ms / 1000.0)
            );
        }
    }
}
