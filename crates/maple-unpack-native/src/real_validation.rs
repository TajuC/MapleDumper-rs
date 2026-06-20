//! End-to-end validation of the native rebuild against the real 269.1 client, using a recorded dump
//! so the check is deterministic and needs no live capture (the live spawn + OEP trace works with
//! the pinned Frida 16 devkit, but it requires the installed game and is not reproducible in a test).
//! It derives the rebuild inputs (section content, OEP, resolved imports) from the recorded dump,
//! runs them through [`crate::pe_build::build_dump`] and the maple-core clean + verify gates, and
//! checks the expected numbers. The binaries are Nexon-copyrighted, so this is `#[ignore]`d and
//! never runs in CI.

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::imports::ResolvedImport;
    use crate::pe_build::{DumpInputs, Pe, build_dump, parse};

    fn r32(d: &[u8], o: usize) -> u32 {
        u32::from_le_bytes(d[o..o + 4].try_into().unwrap())
    }
    fn r64(d: &[u8], o: usize) -> u64 {
        u64::from_le_bytes(d[o..o + 8].try_into().unwrap())
    }
    fn cstr(d: &[u8], o: usize) -> String {
        let end = d[o..]
            .iter()
            .position(|&b| b == 0)
            .map(|p| o + p)
            .unwrap_or(d.len());
        String::from_utf8_lossy(&d[o..end]).into_owned()
    }
    fn rva2off(pe: &Pe, rva: u32) -> Option<usize> {
        for s in &pe.sections {
            if s.rs > 0 && rva >= s.va && (rva as u64) < s.va as u64 + s.rs as u64 {
                return Some((s.ro + (rva - s.va)) as usize);
            }
        }
        None
    }

    /// Recover (module, name, slot) for every import from the recorded dump's import directory.
    fn extract_imports(dump: &[u8], pe: &Pe, image_base: u64) -> Vec<ResolvedImport> {
        let mut out = Vec::new();
        let imp_rva = r32(dump, pe.dd + 8);
        let Some(ioff) = rva2off(pe, imp_rva) else {
            return out;
        };
        let mut di = 0usize;
        while di < 4096 {
            let d = ioff + di * 20;
            if d + 20 > dump.len() {
                break;
            }
            let oft = r32(dump, d);
            let name_rva = r32(dump, d + 12);
            let ft = r32(dump, d + 16);
            if oft == 0 && name_rva == 0 && ft == 0 {
                break;
            }
            let module = rva2off(pe, name_rva)
                .map(|o| cstr(dump, o))
                .unwrap_or_default();
            let arr = if oft != 0 { oft } else { ft };
            if let Some(aoff) = rva2off(pe, arr) {
                let mut i = 0usize;
                while i < 8192 {
                    let eoff = aoff + i * 8;
                    if eoff + 8 > dump.len() {
                        break;
                    }
                    let entry = r64(dump, eoff);
                    if entry == 0 {
                        break;
                    }
                    let slot_va = image_base + (ft + (i * 8) as u32) as u64;
                    let name = if entry & 0x8000_0000_0000_0000 != 0 {
                        format!("#{}", entry & 0xffff)
                    } else {
                        rva2off(pe, entry as u32)
                            .map(|o| cstr(dump, o + 2))
                            .unwrap_or_default()
                    };
                    if !module.is_empty() && !name.is_empty() {
                        out.push(ResolvedImport {
                            slot_va,
                            api_va: 0,
                            module: module.clone(),
                            name,
                        });
                    }
                    i += 1;
                }
            }
            di += 1;
        }
        out
    }

    #[test]
    #[ignore = "requires Nexon binaries in D:\\D-Backup\\x64_gms"]
    fn native_rebuild_passes_gates_on_real_269() {
        let dir = Path::new(r"D:\D-Backup\x64_gms");
        let packed_p = dir.join("269.1.exe");
        let dump_p = dir.join("unpacked_269.1.exe");
        if !packed_p.is_file() || !dump_p.is_file() {
            eprintln!("skipping: assets missing under {}", dir.display());
            return;
        }
        let packed = std::fs::read(&packed_p).unwrap();
        let dump = std::fs::read(&dump_p).unwrap();

        let dpe = parse(&dump).unwrap();
        let image_base = r64(&dump, dpe.opt + 0x18);

        // The recorded dump is the in-memory image; index its section content by RVA.
        let mut image_mem = vec![0u8; dpe.size_of_image as usize];
        for s in &dpe.sections {
            if s.rs == 0 {
                continue;
            }
            let (ro, rs, va) = (s.ro as usize, s.rs as usize, s.va as usize);
            if ro + rs <= dump.len() && va + rs <= image_mem.len() {
                image_mem[va..va + rs].copy_from_slice(&dump[ro..ro + rs]);
            }
        }

        let oep_rva = r32(&dump, dpe.opt + 16);
        let imports = extract_imports(&dump, &dpe, image_base);
        let dlls: std::collections::BTreeSet<&str> =
            imports.iter().map(|i| i.module.as_str()).collect();
        eprintln!(
            "inputs: image_base={image_base:#x} oep_rva={oep_rva:#x} imports={} dlls={}",
            imports.len(),
            dlls.len()
        );
        drop(dump); // free ~184 MB before the rebuild + clean allocate their own copies

        let out = build_dump(&DumpInputs {
            packed: &packed,
            image_mem: &image_mem,
            image_base,
            oep_rva,
            imports: &imports,
        })
        .unwrap();
        drop(image_mem); // free ~190 MB before clean copies the dump
        eprintln!("rebuilt dump size = {}", out.len());

        let cleaned = maple_core::clean_bytes(&out, &maple_core::CleanOptions::default()).unwrap();
        let report =
            maple_core::verify_bytes(&cleaned.data, Some((&packed, "packed original"))).unwrap();
        eprintln!(
            "GATES pass={} oep={:#x} dlls={} fns={} pdata={} valid={:.2}% asc={:.2}% text_id={:?} size={}",
            report.gates_pass,
            report.oep_rva,
            report.import_dlls,
            report.import_functions,
            report.pdata_entries,
            report.pdata_valid_pct,
            report.pdata_ascending_pct,
            report.text_identity,
            report.output_size,
        );

        assert_eq!(report.oep_rva, 0x6a2c61c, "OEP");
        assert!(report.import_dlls >= 39, "DLL count {}", report.import_dlls);
        assert!(
            report.import_functions >= 591,
            "fn count {}",
            report.import_functions
        );
        assert!(
            report.pdata_entries > 360_000,
            "pdata {}",
            report.pdata_entries
        );
        assert_eq!(report.text_identity, Some(true), ".text identity");
        assert!(report.gates_pass, "all gates: {report:#?}");
    }
}
