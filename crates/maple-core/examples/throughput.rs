use std::hint::black_box;
use std::time::Instant;

use maple_core::Signature;
use maple_core::scanner::{CompiledPattern, find_all};

fn code_like_haystack(len: usize) -> Vec<u8> {
    let common = [0x00u8, 0x48, 0xFF, 0x8B, 0xCC, 0x40];
    let mut rng = 0x1234_5678_9abc_def0u64;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        let byte = if rng.is_multiple_of(4) {
            (rng >> 16) as u8
        } else {
            common[(rng as usize >> 3) % common.len()]
        };
        out.push(byte);
    }
    out
}

fn bench(name: &str, haystack: &[u8], pattern: &CompiledPattern, iters: u32) {
    for _ in 0..3 {
        black_box(find_all(black_box(haystack), pattern));
    }
    let start = Instant::now();
    for _ in 0..iters {
        black_box(find_all(black_box(haystack), pattern));
    }
    let elapsed = start.elapsed();
    let mbps =
        (haystack.len() as f64 * f64::from(iters)) / elapsed.as_secs_f64() / (1024.0 * 1024.0);
    println!("{name:22} {:>10?}/scan  {mbps:8.0} MB/s", elapsed / iters);
}

fn main() {
    let haystack = code_like_haystack(8 * 1024 * 1024);
    let iters = 100;
    println!(
        "haystack: {} MiB, {iters} iterations",
        haystack.len() / (1024 * 1024)
    );

    let rare = Signature {
        bytes: vec![0x48, 0x8B, 0x0D, 0, 0, 0, 0, 0xE8, 0x90, 0x42],
        mask: vec![
            true, true, true, false, false, false, false, true, true, true,
        ],
    };
    bench(
        "rare_anchor",
        &haystack,
        &CompiledPattern::new(&rare).unwrap(),
        iters,
    );

    let common = Signature {
        bytes: vec![0x48, 0, 0, 0, 0, 0, 0, 0],
        mask: vec![true, false, false, false, false, false, false, false],
    };
    bench(
        "forced_common_anchor",
        &haystack,
        &CompiledPattern::new(&common).unwrap(),
        iters,
    );
}
