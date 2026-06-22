// Generation-time benchmark for the signature maker (audit F1 / PERF-3: cross-build generation was the
// one hot path never measured). Two scenarios on a synthetic, decodable code module of realistic-ish
// size: the cheap single-build byte path, and the expensive relocation path where the byte signature
// cannot be hardened across a recompile so the anchor scans (string/encoding/vtable/imports) run over
// the whole code section. Real client .text is ~7-12 MiB; cost is linear in code size, so the 256 KiB /
// 1 MiB points extrapolate. This is the control the shared-analysis-model work (Phase 2) must beat.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use maple_core::Arch;
use maple_core::memory::{BufferSource, Region};
use maple_core::sigmaker::{ImageInput, SigOptions, TargetSpec, generate};

const BASE: usize = 0x40_0000;
const TGT: usize = 0x400;
const ANCHOR_STRING: &[u8] = b"MapleDumperBenchUniqueRelocationAnchorString_2026\0";

// A synthetic module: `code_len` bytes of seeded pseudo-random (decodable) filler, a target function at
// TGT that references a unique string in the data tail, and that string. `body` varies the target
// between the reference and its recompiled sibling so no cross-build byte signature survives and the
// relocation path is exercised; the shared string still bridges the two.
fn module(seed: u64, code_len: usize, body: &[u8]) -> Vec<u8> {
    let data_off = code_len;
    let mut buf = vec![0u8; code_len + 0x200];
    let mut rng = seed | 1;
    for b in buf[..code_len].iter_mut() {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        *b = (rng >> 24) as u8;
    }
    buf[data_off..data_off + ANCHOR_STRING.len()].copy_from_slice(ANCHOR_STRING);
    // push ebp ; mov ebp,esp ; push offset <string> ; <body> ; pop ebp ; ret
    let s_abs = (BASE + data_off) as u32;
    let mut f = vec![0x55u8, 0x8B, 0xEC, 0x68];
    f.extend_from_slice(&s_abs.to_le_bytes());
    f.extend_from_slice(body);
    f.extend_from_slice(&[0x5D, 0xC3]);
    buf[TGT..TGT + f.len()].copy_from_slice(&f);
    buf
}

fn image<'a>(
    label: &str,
    src: &'a BufferSource,
    code_hash: u64,
    code_len: usize,
) -> ImageInput<'a> {
    let total = code_len + 0x200;
    ImageInput {
        label: label.to_string(),
        source: src,
        base: BASE,
        size: total,
        code_regions: vec![Region {
            base: BASE,
            size: code_len,
        }],
        regions: vec![Region {
            base: BASE,
            size: total,
        }],
        import: None,
        arch: Arch::X86,
        code_hash,
        packed: false,
        pack_reasons: Vec::new(),
        reloc: None,
    }
}

fn bench(c: &mut Criterion) {
    let opts = SigOptions::default();
    let spec = TargetSpec::Ref {
        image: 0,
        rva: TGT as u64,
    };

    for &code_len in &[256 * 1024usize, 1024 * 1024] {
        let kib = code_len / 1024;
        let ref_buf = module(0x1111_2222_3333_4444, code_len, &[0x33, 0xC0, 0x40]); // xor eax,eax ; inc eax
        let sib_buf = module(0x5555_6666_7777_8888, code_len, &[0x8B, 0x45, 0x08, 0x48]); // mov eax,[ebp+8] ; dec eax
        let ref_src = BufferSource::new(BASE, ref_buf);
        let sib_src = BufferSource::new(BASE, sib_buf);
        let one = [image("ref", &ref_src, 1, code_len)];
        let two = [
            image("ref", &ref_src, 1, code_len),
            image("sib", &sib_src, 2, code_len),
        ];

        // Characterize once so the bench cannot silently measure the wrong path.
        let byte = generate(&one, &spec, &opts);
        let reloc = generate(&two, &spec, &opts);
        eprintln!(
            "[{kib} KiB] byte-path grade={:?} ; relocation chosen={:?} per_version_aobs={}",
            byte.chosen.as_ref().map(|c| c.grade),
            reloc.chosen.as_ref().map(|c| c.grade),
            reloc.chosen.as_ref().map_or(0, |c| c
                .per_version
                .iter()
                .filter(|p| p.aob.is_some())
                .count()),
        );

        let mut group = c.benchmark_group("generate");
        group.sample_size(20);
        group.bench_function(format!("byte_path_{kib}kib"), |b| {
            b.iter(|| {
                black_box(generate(
                    black_box(&one),
                    black_box(&spec),
                    black_box(&opts),
                ))
            });
        });
        group.bench_function(format!("relocation_{kib}kib"), |b| {
            b.iter(|| {
                black_box(generate(
                    black_box(&two),
                    black_box(&spec),
                    black_box(&opts),
                ))
            });
        });
        group.finish();
    }
}

criterion_group!(benches, bench);
criterion_main!(benches);
