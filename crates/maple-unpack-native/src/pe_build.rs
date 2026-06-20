//! Build the reconstructed dump from the packed image, the in-memory section content, the OEP,
//! and the resolved imports. This is the native replacement for the Scylla dump+IAT-rebuild step.
//!
//! Strategy, matching what Scylla produced for the reference client but more surgically: keep the
//! packed section table, refresh each real section's bytes from the live image (so the
//! `.text`-identity gate compares memory against the packed original), append a `.SCY` section
//! holding fresh import descriptors whose `FirstThunk` points at the in-place IAT, and set the
//! entry point. Repointing the exception/certificate/IAT directories and stripping the dead
//! sections is left to the existing `maple-core::unpack` clean pass.

use std::io;

use crate::imports::ResolvedImport;

const SCY_NAME: [u8; 8] = *b".SCY\0\0\0\0";
const SCY_CHARS: u32 = 0xE000_0060;

fn bad(m: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, m.into())
}

fn u16(d: &[u8], o: usize) -> io::Result<u16> {
    d.get(o..o + 2)
        .map(|b| u16::from_le_bytes(b.try_into().unwrap()))
        .ok_or_else(|| bad("short read u16"))
}
fn u32(d: &[u8], o: usize) -> io::Result<u32> {
    d.get(o..o + 4)
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
        .ok_or_else(|| bad("short read u32"))
}
fn put_u16(d: &mut [u8], o: usize, v: u16) -> io::Result<()> {
    d.get_mut(o..o + 2)
        .ok_or_else(|| bad("short write u16"))?
        .copy_from_slice(&v.to_le_bytes());
    Ok(())
}
fn put_u32(d: &mut [u8], o: usize, v: u32) -> io::Result<()> {
    d.get_mut(o..o + 4)
        .ok_or_else(|| bad("short write u32"))?
        .copy_from_slice(&v.to_le_bytes());
    Ok(())
}

fn round_up(v: u64, a: u64) -> u64 {
    if a == 0 { v } else { v.div_ceil(a) * a }
}

pub(crate) struct Sec {
    pub name: String,
    pub vs: u32,
    pub va: u32,
    pub rs: u32,
    pub ro: u32,
    pub chars: u32,
}

pub(crate) struct Pe {
    pub coff: usize,
    pub opt: usize,
    pub is64: bool,
    pub dd: usize,
    pub size_of_image: u32,
    pub sec_table: usize,
    pub sa: u32,
    pub fa: u32,
    pub sizeof_headers: u32,
    pub sections: Vec<Sec>,
}

pub(crate) fn parse(d: &[u8]) -> io::Result<Pe> {
    if d.len() < 0x40 || &d[0..2] != b"MZ" {
        return Err(bad("not a PE (no MZ)"));
    }
    let e = u32(d, 0x3C)? as usize;
    let coff = e + 4;
    if d.get(e..coff) != Some(b"PE\0\0".as_slice()) {
        return Err(bad("no PE signature"));
    }
    let nsec = u16(d, coff + 2)? as usize;
    let optsz = u16(d, coff + 16)? as usize;
    let opt = coff + 20;
    let is64 = match u16(d, opt)? {
        0x20B => true,
        0x10B => false,
        _ => return Err(bad("bad optional magic")),
    };
    let sa = u32(d, opt + 0x20)?;
    let fa = u32(d, opt + 0x24)?;
    let size_of_image = u32(d, opt + 0x38)?;
    let sizeof_headers = u32(d, opt + 0x3C)?;
    let dd = opt + if is64 { 0x70 } else { 0x60 };
    let sec_table = opt + optsz;
    let mut sections = Vec::with_capacity(nsec);
    for i in 0..nsec {
        let h = sec_table + i * 40;
        if h + 40 > d.len() {
            return Err(bad("truncated section table"));
        }
        let end = d[h..h + 8].iter().position(|&b| b == 0).unwrap_or(8);
        sections.push(Sec {
            name: String::from_utf8_lossy(&d[h..h + end]).into_owned(),
            vs: u32(d, h + 8)?,
            va: u32(d, h + 12)?,
            rs: u32(d, h + 16)?,
            ro: u32(d, h + 20)?,
            chars: u32(d, h + 36)?,
        });
    }
    Ok(Pe {
        coff,
        opt,
        is64,
        dd,
        size_of_image,
        sec_table,
        sa,
        fa,
        sizeof_headers,
        sections,
    })
}

/// The data needed to assemble the dump.
pub struct DumpInputs<'a> {
    /// The packed client bytes, used as the header and section-table template.
    pub packed: &'a [u8],
    /// The live image content, indexed by RVA from `image_base` (length covers SizeOfImage).
    pub image_mem: &'a [u8],
    pub image_base: u64,
    pub oep_rva: u32,
    /// Resolved imports in IAT-slot order.
    pub imports: &'a [ResolvedImport],
}

/// Assemble the reconstructed dump. The result is fed to `maple-core::unpack` clean + verify.
pub fn build_dump(inp: &DumpInputs) -> io::Result<Vec<u8>> {
    let pe = parse(inp.packed)?;
    let ptr_size = if pe.is64 { 8usize } else { 4 };
    let mut out = inp.packed.to_vec();

    // Refresh each raw-backed section from the live image so the dump reflects the unpacked
    // process. `.text` then proves identity against the packed original.
    for s in &pe.sections {
        if s.rs == 0 {
            continue;
        }
        let want = s.rs as usize;
        let src_start = s.va as usize;
        let Some(src) = inp.image_mem.get(src_start..src_start + want) else {
            continue;
        };
        let dst_start = s.ro as usize;
        if let Some(dst) = out.get_mut(dst_start..dst_start + want) {
            dst.copy_from_slice(src);
        }
    }

    // Set the original entry point.
    put_u32(&mut out, pe.opt + 16, inp.oep_rva)?;

    // Lay out the new import section.
    let last_va_end = pe
        .sections
        .iter()
        .map(|s| s.va as u64 + s.vs as u64)
        .max()
        .unwrap_or(0);
    let scy_va = round_up(last_va_end, pe.sa as u64);
    let (scy_bytes, import_rva, import_size) =
        build_import_section(inp.imports, inp.image_base, scy_va, ptr_size)?;
    if scy_bytes.is_empty() {
        return Err(bad("no imports to reconstruct"));
    }

    let scy_vsize = round_up(scy_bytes.len() as u64, pe.sa as u64) as u32;
    let scy_rawsize = round_up(scy_bytes.len() as u64, pe.fa as u64) as u32;
    let scy_rawptr = round_up(out.len() as u64, pe.fa as u64);
    out.resize(scy_rawptr as usize, 0);
    let mut padded = scy_bytes;
    padded.resize(scy_rawsize as usize, 0);
    out.extend_from_slice(&padded);

    // Append the section header (verify there is room in the header region).
    let new_hdr = pe.sec_table + pe.sections.len() * 40;
    if (new_hdr + 40) as u64 > pe.sizeof_headers as u64
        || new_hdr + 40
            > pe.sections
                .iter()
                .map(|s| s.ro as usize)
                .filter(|&r| r > 0)
                .min()
                .unwrap_or(usize::MAX)
    {
        return Err(bad("no room in PE headers for the import section header"));
    }
    out.get_mut(new_hdr..new_hdr + 8)
        .ok_or_else(|| bad("header slot out of range"))?
        .copy_from_slice(&SCY_NAME);
    put_u32(&mut out, new_hdr + 8, scy_vsize)?;
    put_u32(&mut out, new_hdr + 12, scy_va as u32)?;
    put_u32(&mut out, new_hdr + 16, scy_rawsize)?;
    put_u32(&mut out, new_hdr + 20, scy_rawptr as u32)?;
    put_u32(&mut out, new_hdr + 36, SCY_CHARS)?;

    // NumberOfSections += 1, SizeOfImage grows to cover .SCY.
    let nsec = pe.sections.len() as u16 + 1;
    put_u16(&mut out, pe.coff + 2, nsec)?;
    let new_soi = scy_va + round_up(scy_vsize as u64, pe.sa as u64);
    put_u32(&mut out, pe.opt + 0x38, new_soi as u32)?;

    // Point the import directory at the new descriptors. The IAT, exception, and certificate
    // directories are intentionally left for the clean pass to set.
    put_u32(&mut out, pe.dd + 8, import_rva)?;
    put_u32(&mut out, pe.dd + 12, import_size)?;

    Ok(out)
}

/// Group resolved imports into contiguous same-module runs and emit IMAGE_IMPORT_DESCRIPTORs,
/// OriginalFirstThunk arrays, and hint/name + DLL-name blobs. FirstThunk points at the in-place
/// IAT so existing code keeps resolving through it. Returns (bytes, import_dir_rva, size).
fn build_import_section(
    imports: &[ResolvedImport],
    image_base: u64,
    scy_va: u64,
    ptr_size: usize,
) -> io::Result<(Vec<u8>, u32, u32)> {
    if imports.is_empty() {
        return Ok((Vec::new(), 0, 0));
    }

    // Contiguous runs sharing a module, in slot order.
    struct Run<'a> {
        module: &'a str,
        first_slot_rva: u32,
        funcs: Vec<&'a str>,
    }
    let mut runs: Vec<Run> = Vec::new();
    for imp in imports {
        let slot_rva = (imp.slot_va - image_base) as u32;
        match runs.last_mut() {
            Some(r) if r.module == imp.module => r.funcs.push(&imp.name),
            _ => runs.push(Run {
                module: &imp.module,
                first_slot_rva: slot_rva,
                funcs: vec![&imp.name],
            }),
        }
    }

    let desc_size = (runs.len() + 1) * 20;
    let mut oft_off = round_up(desc_size as u64, ptr_size as u64) as usize;
    let oft_region_start = oft_off;
    let oft_total: usize = runs.iter().map(|r| (r.funcs.len() + 1) * ptr_size).sum();
    let mut names_off = oft_region_start + oft_total;

    // First pass: place name blobs and dll names, recording RVAs.
    let mut name_blob: Vec<u8> = Vec::new();
    let mut func_name_rva: Vec<Vec<u32>> = Vec::with_capacity(runs.len());
    let mut dll_name_rva: Vec<u32> = Vec::with_capacity(runs.len());
    for r in &runs {
        let mut this_run = Vec::with_capacity(r.funcs.len());
        for f in &r.funcs {
            let rva = scy_va as u32 + (names_off + name_blob.len()) as u32;
            this_run.push(rva);
            name_blob.extend_from_slice(&0u16.to_le_bytes()); // hint
            name_blob.extend_from_slice(f.as_bytes());
            name_blob.push(0);
            if name_blob.len() % 2 == 1 {
                name_blob.push(0);
            }
        }
        func_name_rva.push(this_run);
        let rva = scy_va as u32 + (names_off + name_blob.len()) as u32;
        dll_name_rva.push(rva);
        name_blob.extend_from_slice(r.module.as_bytes());
        name_blob.push(0);
        if name_blob.len() % 2 == 1 {
            name_blob.push(0);
        }
    }
    let _ = &mut names_off;

    // Assemble: descriptors, then OFT arrays, then the name blob.
    let total = oft_region_start + oft_total + name_blob.len();
    let mut buf = vec![0u8; total];

    let mut cur_oft = oft_region_start;
    for (i, r) in runs.iter().enumerate() {
        let d = i * 20;
        let oft_rva = scy_va as u32 + cur_oft as u32;
        let ft_rva = r.first_slot_rva;
        put_u32(&mut buf, d, oft_rva)?; // OriginalFirstThunk
        put_u32(&mut buf, d + 4, 0)?; // TimeDateStamp
        put_u32(&mut buf, d + 8, 0)?; // ForwarderChain
        put_u32(&mut buf, d + 12, dll_name_rva[i])?; // Name
        put_u32(&mut buf, d + 16, ft_rva)?; // FirstThunk -> in-place IAT

        for (j, &rva) in func_name_rva[i].iter().enumerate() {
            let slot = cur_oft + j * ptr_size;
            if ptr_size == 8 {
                buf.get_mut(slot..slot + 8)
                    .ok_or_else(|| bad("oft slot oob"))?
                    .copy_from_slice(&(rva as u64).to_le_bytes());
            } else {
                put_u32(&mut buf, slot, rva)?;
            }
        }
        cur_oft += (r.funcs.len() + 1) * ptr_size; // null-terminated
    }

    buf[oft_region_start + oft_total..].copy_from_slice(&name_blob);

    let import_rva = scy_va as u32;
    let import_size = desc_size as u32;
    let _ = oft_off;
    oft_off = oft_region_start;
    let _ = oft_off;
    Ok((buf, import_rva, import_size))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w16(d: &mut [u8], o: usize, v: u16) {
        d[o..o + 2].copy_from_slice(&v.to_le_bytes());
    }
    fn w32(d: &mut [u8], o: usize, v: u32) {
        d[o..o + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn w64(d: &mut [u8], o: usize, v: u64) {
        d[o..o + 8].copy_from_slice(&v.to_le_bytes());
    }

    // A minimal PE32+ with .text/.rdata/.pdata and room for one more section header.
    fn build_packed() -> (Vec<u8>, u64) {
        let image_base = 0x1_4000_0000u64;
        let mut d = vec![0u8; 0x4000];
        d[0..2].copy_from_slice(b"MZ");
        w32(&mut d, 0x3C, 0x80);
        d[0x80..0x84].copy_from_slice(b"PE\0\0");
        let coff = 0x84;
        w16(&mut d, coff, 0x8664);
        w16(&mut d, coff + 2, 3);
        w16(&mut d, coff + 16, 0xF0);
        let opt = coff + 20;
        w16(&mut d, opt, 0x20B);
        w32(&mut d, opt + 16, 0x1000); // AEP (will be overwritten)
        w64(&mut d, opt + 0x18, image_base);
        w32(&mut d, opt + 0x20, 0x1000); // SectionAlignment
        w32(&mut d, opt + 0x24, 0x200); // FileAlignment
        w32(&mut d, opt + 0x38, 0x4000); // SizeOfImage
        w32(&mut d, opt + 0x3C, 0x400); // SizeOfHeaders
        w32(&mut d, opt + 0x6C, 16); // NumberOfRvaAndSizes
        let st = opt + 0xF0;
        let sec =
            |d: &mut [u8], i: usize, name: &[u8], va: u32, vs: u32, rs: u32, ro: u32, ch: u32| {
                let h = st + i * 40;
                d[h..h + name.len()].copy_from_slice(name);
                w32(d, h + 8, vs);
                w32(d, h + 12, va);
                w32(d, h + 16, rs);
                w32(d, h + 20, ro);
                w32(d, h + 36, ch);
            };
        sec(
            &mut d,
            0,
            b".text",
            0x1000,
            0x600,
            0x600,
            0x400,
            0x6000_0020,
        );
        sec(
            &mut d,
            1,
            b".rdata",
            0x2000,
            0x600,
            0x600,
            0xA00,
            0x4000_0040,
        );
        sec(
            &mut d,
            2,
            b".pdata",
            0x3000,
            0x600,
            0x600,
            0x1000,
            0x4000_0040,
        );
        (d, image_base)
    }

    #[test]
    fn builds_dump_with_imports_oep_and_scy() {
        let (packed, image_base) = build_packed();
        // Live image: distinct .text bytes at rva 0x1000 so the refresh is observable.
        let mut mem = vec![0u8; 0x4000];
        for (i, b) in mem[0x1000..0x1600].iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        let imports = vec![
            ResolvedImport {
                slot_va: image_base + 0x2000,
                api_va: 0x7ffa_0000_0000,
                module: "kernel32.dll".into(),
                name: "GetProcAddress".into(),
            },
            ResolvedImport {
                slot_va: image_base + 0x2008,
                api_va: 0x7ffa_0000_0100,
                module: "kernel32.dll".into(),
                name: "LoadLibraryA".into(),
            },
            ResolvedImport {
                slot_va: image_base + 0x2010,
                api_va: 0x7ffb_0000_0000,
                module: "user32.dll".into(),
                name: "MessageBoxW".into(),
            },
        ];
        let out = build_dump(&DumpInputs {
            packed: &packed,
            image_mem: &mem,
            image_base,
            oep_rva: 0x1234,
            imports: &imports,
        })
        .unwrap();

        let pe = parse(&out).unwrap();
        assert_eq!(pe.sections.len(), 4, "one section appended");
        assert_eq!(u32(&out, pe.opt + 16).unwrap(), 0x1234, "OEP set");

        let scy = pe.sections.iter().find(|s| s.name == ".SCY").expect(".SCY");
        // .text refreshed from memory.
        let text = pe.sections.iter().find(|s| s.name == ".text").unwrap();
        assert_eq!(
            &out[text.ro as usize..text.ro as usize + 0x100],
            &mem[0x1000..0x1100],
            ".text refreshed from the live image"
        );

        // Import directory points at .SCY and lists 2 descriptors (kernel32, user32).
        let imp_rva = u32(&out, pe.dd + 8).unwrap();
        let imp_size = u32(&out, pe.dd + 12).unwrap();
        assert_eq!(imp_rva, scy.va, "import dir at .SCY start");
        assert_eq!(imp_size, 3 * 20, "two descriptors + null terminator");

        // Walk the descriptors and recover the module + function names.
        let rva2off = |rva: u32| -> usize {
            for s in &pe.sections {
                if rva >= s.va && rva < s.va + s.rs.max(s.vs) {
                    return (s.ro + (rva - s.va)) as usize;
                }
            }
            0
        };
        let mut dlls = Vec::new();
        let mut funcs = Vec::new();
        let mut di = 0;
        loop {
            let base = rva2off(imp_rva) + di * 20;
            let oft = u32(&out, base).unwrap();
            let name_rva = u32(&out, base + 12).unwrap();
            let ft = u32(&out, base + 16).unwrap();
            if oft == 0 && name_rva == 0 && ft == 0 {
                break;
            }
            // FirstThunk points back into the in-place IAT (.rdata at 0x2000).
            assert!((0x2000..0x3000).contains(&ft), "FT in the in-place IAT");
            let no = rva2off(name_rva);
            let end = out[no..].iter().position(|&b| b == 0).unwrap();
            dlls.push(String::from_utf8_lossy(&out[no..no + end]).into_owned());
            // First OFT entry -> hint/name.
            let oo = rva2off(oft);
            let hn_rva = u64::from_le_bytes(out[oo..oo + 8].try_into().unwrap()) as u32;
            let hno = rva2off(hn_rva) + 2;
            let fend = out[hno..].iter().position(|&b| b == 0).unwrap();
            funcs.push(String::from_utf8_lossy(&out[hno..hno + fend]).into_owned());
            di += 1;
        }
        assert_eq!(dlls, vec!["kernel32.dll", "user32.dll"]);
        assert_eq!(funcs[0], "GetProcAddress");
        assert_eq!(funcs[1], "MessageBoxW");
    }
}
