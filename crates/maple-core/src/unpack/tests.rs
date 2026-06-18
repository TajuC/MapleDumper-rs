use super::*;
use std::path::Path;

fn w16(d: &mut [u8], o: usize, v: u16) {
    d[o..o + 2].copy_from_slice(&v.to_le_bytes());
}
fn w32(d: &mut [u8], o: usize, v: u32) {
    d[o..o + 4].copy_from_slice(&v.to_le_bytes());
}
fn w64(d: &mut [u8], o: usize, v: u64) {
    d[o..o + 8].copy_from_slice(&v.to_le_bytes());
}

const DD: usize = 0x108; // data directory
const COFF: usize = 0x84;
const RDATA_OFF: usize = 0xA00;
const TEXT_OFF: usize = 0x400;
const PDATA_OFF: usize = 0x1000;
const PDATA_ENTRIES: usize = 1408; // 0x4200 / 12

const OFT_REL: [usize; 6] = [0x90, 0x140, 0x1F0, 0x2A0, 0x350, 0x400];
const FT_REL: [usize; 6] = [0xE8, 0x198, 0x248, 0x2F8, 0x3A8, 0x458];
const HINT_RVA: u32 = 0x24E8;

// layout = [VirtualAddress, VirtualSize, SizeOfRawData, PointerToRawData]
fn sec(d: &mut [u8], idx: usize, name: &[u8], layout: [u32; 4], ch: u32) {
    let h = 0x188 + idx * 40;
    d[h..h + name.len()].copy_from_slice(name);
    w32(d, h + 8, layout[1]);
    w32(d, h + 12, layout[0]);
    w32(d, h + 16, layout[2]);
    w32(d, h + 20, layout[3]);
    w32(d, h + 36, ch);
}

/// A coherent PE32+ that exercises every clean op: a bogus exception/cert directory, an
/// empty IAT directory, real imports, a large strictly-ascending `.pdata`, and contiguous dead
/// `.themida`/`.boot` raw to strip. With `with_stub`, function-start 0x100 jumps into `.themida`.
fn build_image(with_stub: bool) -> Vec<u8> {
    let mut d = vec![0u8; 0x6200];
    d[0..2].copy_from_slice(b"MZ");
    w32(&mut d, 0x3C, 0x80);
    d[0x80..0x84].copy_from_slice(b"PE\0\0");

    // COFF
    w16(&mut d, COFF, 0x8664);
    w16(&mut d, COFF + 2, 6);
    w32(&mut d, COFF + 4, 0xDEAD_BEEF);
    w16(&mut d, COFF + 16, 0xF0);
    w16(&mut d, COFF + 18, 0x22);

    // optional header
    let opt = 0x98;
    w16(&mut d, opt, 0x20B);
    w32(&mut d, opt + 16, 0x1000);
    w64(&mut d, opt + 0x18, 0x1_4000_0000);
    w32(&mut d, opt + 0x38, 0xB000);
    w32(&mut d, opt + 0x3C, 0x400);
    w32(&mut d, opt + 0x6C, 16);

    // data directories: import set, exception/cert bogus (Themida copies), IAT empty
    w32(&mut d, DD + 8, 0x2000);
    w32(&mut d, DD + 12, 0x8C);
    w32(&mut d, DD + 24, 0xAAAA);
    w32(&mut d, DD + 28, 0xBBBB);
    w32(&mut d, DD + 32, 0xCCCC);
    w32(&mut d, DD + 36, 0xDDDD);

    sec(
        &mut d,
        0,
        b".text",
        [0x1000, 0x600, 0x600, 0x400],
        0x6000_0020,
    );
    sec(
        &mut d,
        1,
        b".rdata",
        [0x2000, 0x600, 0x600, 0xA00],
        0x4000_0040,
    );
    sec(
        &mut d,
        2,
        b".pdata",
        [0x3000, 0x4200, 0x4200, 0x1000],
        0x4000_0040,
    );
    sec(
        &mut d,
        3,
        b".themida",
        [0x8000, 0x1000, 0x600, 0x5200],
        0xE000_0020,
    );
    sec(
        &mut d,
        4,
        b".boot",
        [0x9000, 0x1000, 0x600, 0x5800],
        0x6000_0020,
    );
    sec(
        &mut d,
        5,
        b".SCY",
        [0xA000, 0x1000, 0x400, 0x5E00],
        0x6000_0020,
    );

    // OEP prologue + the MSVC security cookie sentinel
    let oep = [
        0x48, 0x89, 0x5c, 0x24, 0x20, 0x55, 0x48, 0x8b, 0xec, 0x48, 0x83, 0xec, 0x20, 0x48, 0x8b,
        0x05, 0x00, 0x00, 0x00, 0x00, 0x48, 0xbb, 0x32, 0xa2, 0xdf, 0x2d, 0x99, 0x2b, 0x00, 0x00,
    ];
    d[TEXT_OFF..TEXT_OFF + oep.len()].copy_from_slice(&oep);
    // a virtualization stub: jmp 0x140008000 (into .themida) at rva 0x1100, i.e. function-start 0x100
    if with_stub {
        d[TEXT_OFF + 0x100..TEXT_OFF + 0x105].copy_from_slice(&[0xE9, 0xFB, 0x6E, 0x00, 0x00]);
    }

    // imports: 6 DLLs x 10 functions
    for i in 0..6 {
        let desc = RDATA_OFF + i * 20;
        w32(&mut d, desc, 0x2000 + OFT_REL[i] as u32);
        w32(&mut d, desc + 12, 0x2000 + (0x4B0 + i * 9) as u32);
        w32(&mut d, desc + 16, 0x2000 + FT_REL[i] as u32);
        for j in 0..10 {
            w64(&mut d, RDATA_OFF + OFT_REL[i] + j * 8, HINT_RVA as u64);
            w64(
                &mut d,
                RDATA_OFF + FT_REL[i] + j * 8,
                0x7FFA_0000_0000_0000 + (i * 0x100 + j) as u64,
            );
        }
        let name = format!("DLL{i}.dll\0");
        let no = RDATA_OFF + 0x4B0 + i * 9;
        d[no..no + name.len()].copy_from_slice(name.as_bytes());
    }

    // .pdata: strictly ascending, in-range function starts; index 0x100 lands on the stub rva
    for k in 0..PDATA_ENTRIES {
        let begin = 0x1000 + k as u32;
        w32(&mut d, PDATA_OFF + k * 12, begin);
        w32(&mut d, PDATA_OFF + k * 12 + 4, begin + 0x10);
    }
    d
}

fn dir(d: &[u8], idx: usize) -> (u32, u32) {
    (
        get_u32(d, DD + idx * 8).unwrap(),
        get_u32(d, DD + idx * 8 + 4).unwrap(),
    )
}

#[test]
fn clean_rewrites_directories_and_sections() {
    let raw = build_image(false);
    let cleaned = clean_bytes(&raw, &CleanOptions::oracle()).unwrap();
    let d = &cleaned.data;

    assert_eq!(dir(d, 3), (0x3000, 0x4200), "exception dir -> .pdata");
    assert_eq!(dir(d, 4), (0, 0), "certificate dir zeroed");
    assert_eq!(dir(d, 12), (0x20E8, 0x3C8), "IAT dir computed");
    assert_eq!(cleaned.summary.iat_dir, Some((0x20E8, 0x3C8)));

    let pe = Pe::parse(d).unwrap();
    let themida = pe.section(".rsrv0").expect(".themida renamed to .rsrv0");
    let boot = pe.section(".rsrv1").expect(".boot renamed to .rsrv1");
    assert_eq!((themida.rs, themida.ro), (0, 0), "stripped raw of .rsrv0");
    assert_eq!((boot.rs, boot.ro), (0, 0), "stripped raw of .rsrv1");
    assert_eq!(
        get_u32(d, themida.hdr + 36),
        Some(0x4000_0040),
        "deexec .rsrv0"
    );

    let scy = pe.section(".SCY").expect(".SCY kept");
    assert_eq!(get_u32(d, scy.hdr + 36), Some(0x4000_0040), "deexec .SCY");
    assert_eq!(
        scy.ro, 0x5200,
        ".SCY file pointer shifted down by the stripped gap"
    );

    assert_eq!(cleaned.summary.stripped_bytes, 0xC00);
    assert_eq!(cleaned.summary.size_after, 0x6200 - 0xC00);
    assert_eq!(
        get_u32(d, COFF + 4),
        Some(0xDEAD_BEEF),
        "timestamp kept with oracle opts"
    );
}

#[test]
fn clean_preserves_text_bytes() {
    let raw = build_image(false);
    let cleaned = clean_bytes(&raw, &CleanOptions::default()).unwrap();
    let rp = Pe::parse(&raw).unwrap();
    let cp = Pe::parse(&cleaned.data).unwrap();
    let rt = rp.section(".text").unwrap();
    let ct = cp.section(".text").unwrap();
    assert_eq!(
        &raw[rt.ro as usize..(rt.ro + rt.rs) as usize],
        &cleaned.data[ct.ro as usize..(ct.ro + ct.rs) as usize],
        "code bytes must be byte-identical after clean"
    );
}

#[test]
fn production_opts_unbind_and_zero_timestamp() {
    let raw = build_image(false);
    let cleaned = clean_bytes(&raw, &CleanOptions::default()).unwrap();
    let d = &cleaned.data;
    assert_eq!(get_u32(d, COFF + 4), Some(0), "timestamp zeroed");
    assert!(cleaned.summary.timestamp_zeroed);
    assert!(cleaned.summary.unbound_thunks >= 60);
    // FirstThunk[0] of DLL0 now holds the OriginalFirstThunk value, not a bound address
    let ft0 = RDATA_OFF + FT_REL[0];
    assert_eq!(
        get_u64(d, ft0),
        Some(HINT_RVA as u64),
        "IAT unbound to OFT value"
    );
}

#[test]
fn verify_passes_on_good_image() {
    let raw = build_image(false);
    let cleaned = clean_bytes(&raw, &CleanOptions::default()).unwrap();
    let report = verify_bytes(&cleaned.data, Some((&raw, "input dump"))).unwrap();
    assert!(report.gates_pass, "gates should pass: {report:?}");
    assert_eq!(report.import_dlls, 6);
    assert_eq!(report.import_functions, 60);
    assert!(report.imports_ok);
    assert_eq!(report.pdata_entries, PDATA_ENTRIES as u32);
    assert!(report.pdata_ok);
    assert!((report.pdata_valid_pct - 100.0).abs() < 1e-9);
    assert!(report.oep_is_msvc);
    assert_eq!(report.text_identity, Some(true));
    assert!(report.text_sha256.is_some());
    assert!(
        (report.virtualization_pct).abs() < 1e-9,
        "no stubs -> zero virtualization"
    );
    assert!(report.warnings.is_empty());
}

#[test]
fn verify_flags_virtualization() {
    let raw = build_image(true);
    let cleaned = clean_bytes(&raw, &CleanOptions::default()).unwrap();
    let report = verify_bytes(&cleaned.data, Some((&raw, "input dump"))).unwrap();
    assert!(
        report.virtualization_pct > 0.0,
        "stub jumps must be detected"
    );
    assert!(
        report.gates_pass,
        "virtualization is advisory, not a hard gate"
    );
}

#[test]
fn verify_fails_on_gutted_imports() {
    let raw = build_image(false);
    let mut cleaned = clean_bytes(&raw, &CleanOptions::default()).unwrap().data;
    // wipe the import descriptors
    for i in 0..7 {
        for b in 0..20 {
            cleaned[RDATA_OFF + i * 20 + b] = 0;
        }
    }
    let report = verify_bytes(&cleaned, Some((&raw, "input dump"))).unwrap();
    assert!(!report.imports_ok);
    assert!(!report.gates_pass);
}

#[test]
fn verify_fails_on_text_mismatch() {
    let raw = build_image(false);
    let cleaned = clean_bytes(&raw, &CleanOptions::default()).unwrap();
    let mut reference = raw.clone();
    reference[TEXT_OFF] ^= 0xFF; // corrupt the reference .text
    let report = verify_bytes(&cleaned.data, Some((&reference, "packed original"))).unwrap();
    assert_eq!(report.text_identity, Some(false));
    assert!(!report.gates_pass);
}

#[test]
fn parse_rejects_non_pe() {
    assert!(Pe::parse(&[0u8; 8]).is_err());
    assert!(clean_bytes(b"not a pe at all", &CleanOptions::default()).is_err());
}

#[test]
fn clean_to_path_writes_only_on_pass() {
    let dir = std::env::temp_dir().join(format!("mapledumper_unpack_test_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let raw_path = dir.join("raw.bin");
    let out_path = dir.join("clean.bin");
    std::fs::write(&raw_path, build_image(false)).unwrap();

    let mut stages = Vec::new();
    let report = clean_to_path(
        &raw_path,
        &out_path,
        &CleanOptions::default(),
        None,
        &mut |p| {
            if let Progress::Stage(s) = p {
                stages.push(s);
            }
        },
    )
    .unwrap();
    assert!(report.gates_pass);
    assert!(out_path.is_file(), "output written on pass");
    assert!(
        stages.contains(&Stage::Clean)
            && stages.contains(&Stage::Verify)
            && stages.contains(&Stage::Done)
    );

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn compute_iat_skips_zero_firstthunk() {
    let mut raw = build_image(false);
    // a single descriptor with FirstThunk == 0 must not collapse the IAT extent to 0
    w32(&mut raw, RDATA_OFF + 5 * 20 + 16, 0);
    let cleaned = clean_bytes(&raw, &CleanOptions::oracle()).unwrap();
    assert_eq!(cleaned.summary.iat_dir, Some((0x20E8, 0x318)));
}

#[test]
fn pdata_duplicate_begin_is_not_ascending() {
    let raw = build_image(false);
    let clean_ok = clean_bytes(&raw, &CleanOptions::default()).unwrap();
    let strict = verify_bytes(&clean_ok.data, None).unwrap();
    assert!(
        (strict.pdata_ascending_pct - 100.0).abs() < 1e-9,
        "strictly ascending starts"
    );

    // a duplicate consecutive BeginAddress must count as non-ascending, not ascending
    let mut dup = build_image(false);
    let prev = get_u32(&dup, PDATA_OFF + 4 * 12).unwrap();
    w32(&mut dup, PDATA_OFF + 5 * 12, prev);
    let dup_clean = clean_bytes(&dup, &CleanOptions::default()).unwrap();
    let dup_report = verify_bytes(&dup_clean.data, None).unwrap();
    assert!(
        dup_report.pdata_ascending_pct < 100.0,
        "duplicate begin must be flagged"
    );
}

#[test]
fn pdata_gate_fails_in_isolation() {
    let mut raw = build_image(false);
    // push every function start out of the .text range: pdata invalid, imports untouched
    for k in 0..PDATA_ENTRIES {
        w32(&mut raw, PDATA_OFF + k * 12, 0x9999);
        w32(&mut raw, PDATA_OFF + k * 12 + 4, 0x99A9);
    }
    let cleaned = clean_bytes(&raw, &CleanOptions::default()).unwrap();
    let report = verify_bytes(&cleaned.data, Some((&raw, "input dump"))).unwrap();
    assert!(report.imports_ok, "imports gate still passes");
    assert!(!report.pdata_ok, "pdata gate fails in isolation");
    assert!(!report.gates_pass);
}

#[test]
fn gate_failure_writes_no_output() {
    let dir = std::env::temp_dir().join(format!("mapledumper_nowrite_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let raw_path = dir.join("raw.bin");
    let ref_path = dir.join("ref.bin");
    let out_path = dir.join("out.bin");
    std::fs::write(&raw_path, build_image(false)).unwrap();
    let mut reference = build_image(false);
    reference[TEXT_OFF] ^= 0xFF; // reference .text differs -> identity FAIL
    std::fs::write(&ref_path, &reference).unwrap();

    let report = clean_to_path(
        &raw_path,
        &out_path,
        &CleanOptions::default(),
        Some(&ref_path),
        &mut |_| {},
    )
    .unwrap();
    assert_eq!(report.verify.text_identity, Some(false));
    assert!(!report.gates_pass);
    assert!(report.output.is_none());
    assert!(
        !out_path.is_file(),
        "no binary may be written when a gate fails"
    );

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
#[ignore = "requires local Nexon binaries in D:\\D-Backup\\x64_gms"]
fn real_269_golden() {
    let dir = Path::new(r"D:\D-Backup\x64_gms");
    let raw = dir.join("unpacked_269.1.exe");
    let expected = dir.join("unpacked_269.1.min.exe");
    let packed = dir.join("269.1.exe");
    if !raw.is_file() || !expected.is_file() {
        eprintln!(
            "skipping real golden: assets missing under {}",
            dir.display()
        );
        return;
    }

    let rawb = std::fs::read(&raw).unwrap();
    let cleaned = clean_bytes(&rawb, &CleanOptions::oracle()).unwrap();
    let exp = std::fs::read(&expected).unwrap();
    assert_eq!(
        sha256::hex(&cleaned.data),
        sha256::hex(&exp),
        "oracle clean must reproduce the recorded session min byte for byte"
    );
    assert_eq!(cleaned.data, exp);

    if packed.is_file() {
        let packedb = std::fs::read(&packed).unwrap();
        let report = verify_bytes(&cleaned.data, Some((&packedb, "packed original"))).unwrap();
        assert!(
            report.gates_pass,
            "real dump must pass the gates: {report:#?}"
        );
        assert_eq!(report.text_identity, Some(true));
        assert!(report.import_dlls >= 5 && report.import_functions >= 50);
        assert!(report.pdata_entries > 1000);
        eprintln!(
            "269.1 verify: OEP {:#x} imports {}/{} pdata {} valid {:.2}% asc {:.2}% virt {:.4}% size {}",
            report.oep_rva,
            report.import_dlls,
            report.import_functions,
            report.pdata_entries,
            report.pdata_valid_pct,
            report.pdata_ascending_pct,
            report.virtualization_pct,
            report.output_size,
        );
    }

    // production opts stay deterministic across runs (unbind + zero timestamp)
    let prod_a = clean_bytes(&rawb, &CleanOptions::default()).unwrap();
    let prod_b = clean_bytes(&rawb, &CleanOptions::default()).unwrap();
    assert_eq!(
        sha256::hex(&prod_a.data),
        sha256::hex(&prod_b.data),
        "production clean is reproducible"
    );
}
