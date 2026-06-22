use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
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

fn bench(c: &mut Criterion) {
    let haystack = code_like_haystack(8 * 1024 * 1024);
    let mut group = c.benchmark_group("find_all");
    group.throughput(Throughput::Bytes(haystack.len() as u64));

    let rare = Signature {
        bytes: vec![0x48, 0x8B, 0x0D, 0, 0, 0, 0, 0xE8, 0x90, 0x42],
        mask: vec![
            true, true, true, false, false, false, false, true, true, true,
        ],
    };
    let rare = CompiledPattern::new(&rare).unwrap();
    group.bench_function("rare_anchor", |b| {
        b.iter(|| black_box(find_all(black_box(&haystack), black_box(&rare))));
    });

    let common = Signature {
        bytes: vec![0x48, 0, 0, 0, 0, 0, 0, 0],
        mask: vec![true, false, false, false, false, false, false, false],
    };
    let common = CompiledPattern::new(&common).unwrap();
    group.bench_function("forced_common_anchor", |b| {
        b.iter(|| black_box(find_all(black_box(&haystack), black_box(&common))));
    });

    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
