//! Locate and resolve the obfuscated IAT of a Themida/WinLicense 3.x image. Ported from
//! unlicense's `winlicense3.py` (`_find_iat`, `_unwrap_iat`) and `imports.py`.
//!
//! Each slot of the obfuscated IAT either points directly at an export or at a wrapper stub in
//! the dumped module; the latter is resolved by emulation ([`crate::emulate`]). The result is a
//! per-slot list of `(module, function)` plus the fixed IAT bytes to write back so the dumped
//! image carries resolved addresses.

use crate::emulate::resolve_wrapped_api;
use crate::process::{MemoryRange, ProcessController, pack_ptr, unpack_ptr};

const IAT_MAX_SUCCESSIVE_FAILURES: u32 = 2;

/// One resolved import slot: where it lives and what it points at.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedImport {
    /// Absolute address of the IAT slot in the target.
    pub slot_va: u64,
    /// Resolved API address.
    pub api_va: u64,
    /// Owning module, e.g. "kernel32.dll".
    pub module: String,
    /// Export name.
    pub name: String,
}

/// The outcome of unwrapping the IAT.
pub struct UnwrapResult {
    pub iat_base: u64,
    pub iat_size: u64,
    /// The fixed IAT bytes (resolved addresses) to write back into the target before dumping.
    pub fixed_iat: Vec<u8>,
    /// One entry per resolved import, in slot order.
    pub imports: Vec<ResolvedImport>,
}

fn protection_is_rx(prot: &str) -> bool {
    let b = prot.as_bytes();
    b.len() >= 3 && b[0] == b'r' && b[2] == b'x'
}

/// Decide whether `data` (a snapshot at `base_va`) looks like the obfuscated IAT, returning the
/// offset of its first plausible entry. Mirrors `_find_iat_start`.
fn find_iat_start(data: &[u8], base_va: u64, pc: &dyn ProcessController) -> Option<usize> {
    let ptr_size = pc.pointer_size();
    if data.len() < ptr_size {
        return None;
    }
    let exports = pc.enumerate_exported_functions();
    let elem_count = (data.len() / ptr_size).min(100);
    let data_size = elem_count * ptr_size;

    let mut start_offset = 0usize;
    let mut i = 0usize;
    while i + ptr_size <= data.len() && i < data.len() / ptr_size {
        let ptr = unpack_ptr(ptr_size, &data[i..i + ptr_size]);
        if exports.contains_key(&ptr) {
            start_offset = i;
            break;
        }
        if pc.query_memory_protection(ptr).as_deref() == Some("rwx") {
            start_offset = i;
            break;
        }
        i += ptr_size;
    }

    let mut non_null = 0u32;
    let mut valid = 0u32;
    let mut rx_dest = 0u32;
    let mut off = start_offset;
    while off + ptr_size <= data_size {
        let ptr = unpack_ptr(ptr_size, &data[off..off + ptr_size]);
        if ptr != 0 {
            non_null += 1;
        }
        if exports.contains_key(&ptr) {
            valid += 1;
        }
        if let Some(prot) = pc.query_memory_protection(ptr)
            && protection_is_rx(&prot)
        {
            rx_dest += 1;
        }
        off += ptr_size;
    }

    let required_valid = 1 + (f64::from(non_null) * 0.02) as u32;
    let required_rx = 1 + (f64::from(non_null) * 0.75) as u32;
    if valid >= required_valid && rx_dest >= required_rx {
        let _ = base_va;
        Some(start_offset)
    } else {
        None
    }
}

/// Find the obfuscated IAT by scanning the start of the module's sections and memory ranges.
/// Mirrors `_find_iat_from_data_sections` (the primary path for 3.x).
pub fn find_iat(
    image_base: u64,
    section_rvas: &[(u64, u64)],
    pc: &dyn ProcessController,
) -> Option<MemoryRange> {
    let page_size = pc.page_size();

    for &(rva, size) in section_rvas {
        let page_addr = image_base + rva;
        let Ok(data) = pc.read_process_memory(page_addr, page_size) else {
            continue;
        };
        if let Some(off) = find_iat_start(&data, page_addr, pc) {
            return Some(MemoryRange::new(
                page_addr + off as u64,
                size - off as u64,
                "r--",
            ));
        }
    }

    for m in pc.main_module_ranges() {
        let page_count = (m.size as usize) / page_size;
        for page_index in 0..page_count.min(4) {
            let page_addr = m.base + (page_index * page_size) as u64;
            let Ok(data) = pc.read_process_memory(page_addr, page_size) else {
                continue;
            };
            if let Some(off) = find_iat_start(&data, page_addr, pc) {
                let consumed = (page_index * page_size) as u64 + off as u64;
                return Some(MemoryRange::new(
                    page_addr + off as u64,
                    m.size - consumed,
                    m.protection.clone(),
                ));
            }
        }
    }

    None
}

fn in_main_module(address: u64, ranges: &[MemoryRange]) -> bool {
    ranges.iter().any(|r| r.contains(address))
}

fn classify(api_va: u64, slot_va: u64, pc: &dyn ProcessController) -> Option<ResolvedImport> {
    let name = pc.enumerate_exported_functions().get(&api_va)?.name.clone();
    let module = pc.find_module_by_address(api_va)?;
    Some(ResolvedImport {
        slot_va,
        api_va,
        module,
        name,
    })
}

/// Walk the IAT, resolving each wrapped slot through emulation, and return the fixed IAT plus the
/// per-slot resolution. Mirrors `_unwrap_iat`. The caller writes `fixed_iat` back before dumping.
pub fn unwrap_iat(iat: &MemoryRange, pc: &dyn ProcessController) -> Option<UnwrapResult> {
    let ptr_size = pc.pointer_size();
    let page_size = pc.page_size() as u64;
    let main_ranges = pc.enumerate_module_ranges(pc.main_module_name(), false);
    let exit_process = pc.find_export_by_name("kernel32.dll", "ExitProcess");

    let mut fixed_iat: Vec<u8> = Vec::new();
    let mut imports: Vec<ResolvedImport> = Vec::new();
    let mut successive_failures = 0u32;
    let mut last_resolution_offset = 0usize;

    let mut current = iat.base;
    let end = iat.base + iat.size;
    while current < end {
        let data_size = (page_size - (current % page_size)) as usize;
        let Ok(page) = pc.read_process_memory(current, data_size) else {
            break;
        };
        let mut i = 0usize;
        while i + ptr_size <= page.len() {
            let slot_va = current + i as u64;
            let wrapper = unpack_ptr(ptr_size, &page[i..i + ptr_size]);
            let exports = pc.enumerate_exported_functions();

            if in_main_module(wrapper, &main_ranges) {
                let resolved = resolve_wrapped_api(wrapper, pc, None);
                match resolved.filter(|a| exports.contains_key(a)) {
                    Some(api) => {
                        fixed_iat.extend_from_slice(&pack_ptr(ptr_size, api));
                        if let Some(imp) = classify(api, slot_va, pc) {
                            imports.push(imp);
                        }
                        last_resolution_offset = fixed_iat.len();
                        successive_failures = 0;
                    }
                    None => {
                        successive_failures += 1;
                        if let Some(exit) = exit_process {
                            fixed_iat.extend_from_slice(&pack_ptr(ptr_size, exit));
                        } else {
                            fixed_iat.extend_from_slice(&pack_ptr(ptr_size, 0));
                        }
                        if successive_failures >= IAT_MAX_SUCCESSIVE_FAILURES {
                            fixed_iat.truncate(last_resolution_offset + 1);
                            let size = fixed_iat.len() as u64;
                            pc.set_memory_protection(iat.base, size, "rw-");
                            let _ = pc.write_process_memory(iat.base, &fixed_iat);
                            return Some(UnwrapResult {
                                iat_base: iat.base,
                                iat_size: size,
                                fixed_iat,
                                imports,
                            });
                        }
                    }
                }
            } else if exports.contains_key(&wrapper) {
                fixed_iat.extend_from_slice(&pack_ptr(ptr_size, wrapper));
                if let Some(imp) = classify(wrapper, slot_va, pc) {
                    imports.push(imp);
                }
                last_resolution_offset = fixed_iat.len();
                successive_failures = 0;
            } else {
                // Junk (most often null); keep it to preserve alignment.
                fixed_iat.extend_from_slice(&pack_ptr(ptr_size, wrapper));
            }
            i += ptr_size;
        }
        current += data_size as u64;
    }

    if fixed_iat.is_empty() {
        return None;
    }
    let size = fixed_iat.len() as u64;
    pc.set_memory_protection(iat.base, size, "rw-");
    let _ = pc.write_process_memory(iat.base, &fixed_iat);
    Some(UnwrapResult {
        iat_base: iat.base,
        iat_size: size,
        fixed_iat,
        imports,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::Architecture;
    use crate::process::mock::MockController;

    fn build_controller() -> (MockController, u64) {
        let image_base = 0x1_4000_0000u64;
        let mut pc = MockController::new(Architecture::X86_64);

        // Two real exports in kernel32.
        let getproc = 0x7ffa_1000_0000u64;
        let loadlib = 0x7ffa_1000_1000u64;
        pc.add_export(getproc, "GetProcAddress");
        pc.add_export(loadlib, "LoadLibraryA");
        pc.modules.insert(
            "kernel32.dll".to_string(),
            vec![MemoryRange::new(0x7ffa_1000_0000, 0x10000, "r-x")],
        );
        // The kernel32 export pages must be readable for emulation fetches.
        pc.map(0x7ffa_1000_0000, vec![0xC3; 0x2000], "r-x");

        // Main module IAT page at image_base+0x2000: [getproc, loadlib, 0].
        let iat_rva = 0x2000u64;
        let mut iat = Vec::new();
        iat.extend_from_slice(&getproc.to_le_bytes());
        iat.extend_from_slice(&loadlib.to_le_bytes());
        iat.extend_from_slice(&0u64.to_le_bytes());
        iat.resize(0x1000, 0);
        pc.map(image_base + iat_rva, iat, "rw-");

        pc.modules.insert(
            pc.main_module.clone(),
            vec![MemoryRange::new(image_base, 0x10_0000, "r-x")],
        );
        pc.main_ranges = vec![MemoryRange::new(image_base, 0x10_0000, "r-x")];
        (pc, image_base)
    }

    #[test]
    fn finds_iat_at_section_start() {
        let (pc, image_base) = build_controller();
        let found = find_iat(image_base, &[(0x2000, 0x1000)], &pc).expect("iat found");
        assert_eq!(found.base, image_base + 0x2000);
    }

    #[test]
    fn unwraps_direct_exports() {
        let (pc, image_base) = build_controller();
        let iat = MemoryRange::new(image_base + 0x2000, 0x18, "rw-");
        let res = unwrap_iat(&iat, &pc).expect("unwrap");
        assert_eq!(res.imports.len(), 2);
        assert_eq!(res.imports[0].name, "GetProcAddress");
        assert_eq!(res.imports[0].module, "kernel32.dll");
        assert_eq!(res.imports[1].name, "LoadLibraryA");
    }
}
