//! Import-set anchored relocation: find the same function across builds by the distinctive set of
//! imported APIs it calls.
//!
//! Imported API names are recompile-stable (they are fixed by the DLLs the program links against), so
//! a function that calls a distinctive set of them, for example the twelve `ws2_32` socket APIs of the
//! network layer or the `advapi32` token-privilege trio, is identifiable in any build by that set even
//! when its bytes, mnemonic stream, and encoding have all been rewritten by a recompile. This is the
//! complement of [`super::identity`]'s string anchor: where that pins a function by a read-only string
//! it references, this pins it by the IAT slots it calls through. Measured on the real GMS v84 to v88
//! recompile, ~100 functions have an import set unique in both builds and relocate 1:1, the great
//! majority at mnemonic similarity 1.0.
//!
//! The anchor emits only when the import set pins exactly one function in every required build (so an
//! ambiguous or absent set declines rather than guess), and the relocated functions are checked for
//! cross-build consistency. x86 / PE32 only.

use std::collections::{BTreeSet, HashMap};

use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, OpKind, Register};

use super::types::ImageInput;
use super::{bitness, read_at};
use crate::pattern::Arch;

/// The recompile-stable identity of a function as the set of imported API names it calls directly.
#[derive(Clone, Debug)]
pub(super) struct ImportAnchor {
    pub names: Vec<String>,
}

// Below this many distinct imports a set is not distinctive enough to pin one function: a lone
// `GetLastError` recurs in thousands of functions, so two or more is the floor for an anchor.
const MIN_IMPORTS: usize = 2;
// Instruction cap when scanning a function for its import calls (bounds untrusted input).
const SCAN_INSTRS: usize = 400;

fn rd32(img: &ImageInput, abs: usize) -> Option<u32> {
    let rva = abs.checked_sub(img.base)?;
    let b = read_at(img.source, img.base, rva, 4);
    (b.len() == 4).then(|| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn cstr(img: &ImageInput, abs: usize) -> String {
    let Some(rva) = abs.checked_sub(img.base) else {
        return String::new();
    };
    read_at(img.source, img.base, rva, 128)
        .iter()
        .copied()
        .take_while(|&b| b != 0 && (0x20..=0x7E).contains(&b))
        .map(char::from)
        .collect()
}

fn rd64(img: &ImageInput, abs: usize) -> Option<u64> {
    let rva = abs.checked_sub(img.base)?;
    let b = read_at(img.source, img.base, rva, 8);
    (b.len() == 8).then(|| u64::from_le_bytes(b[..8].try_into().unwrap()))
}

/// Parse the PE32 / PE32+ import directory into a map of IAT slot VA to `"dll!func"`. Every loop is
/// bounded so a malformed directory in an untrusted image cannot spin or read out of range. The
/// `IMAGE_IMPORT_DESCRIPTOR` layout is identical for both; only the thunk width (4 vs 8 bytes) and the
/// import-by-ordinal flag (bit 31 vs bit 63) differ, so x64 reads 8-byte thunks.
pub(super) fn import_map(img: &ImageInput) -> HashMap<usize, String> {
    let mut out = HashMap::new();
    let Some((start, end)) = img.import else {
        return out;
    };
    let x64 = matches!(img.arch, Arch::X64);
    let thunk = if x64 { 8 } else { 4 };
    let ordinal_flag: u64 = if x64 {
        0x8000_0000_0000_0000
    } else {
        0x8000_0000
    };
    let read_thunk = |at: usize| -> Option<u64> {
        if x64 {
            rd64(img, at)
        } else {
            rd32(img, at).map(u64::from)
        }
    };
    let mut desc = start;
    let mut guard = 0;
    while desc + 20 <= end && guard < 8192 {
        guard += 1;
        let orig = rd32(img, desc).unwrap_or(0);
        let name_rva = rd32(img, desc + 0x0C).unwrap_or(0);
        let first = rd32(img, desc + 0x10).unwrap_or(0);
        if orig == 0 && first == 0 {
            break;
        }
        let dll = cstr(img, img.base + name_rva as usize);
        let int = if orig != 0 { orig } else { first };
        let mut i = 0usize;
        while i < 8192 {
            let Some(t) = read_thunk(img.base + int as usize + i * thunk) else {
                break;
            };
            if t == 0 {
                break;
            }
            let slot = img.base + first as usize + i * thunk;
            let name = if t & ordinal_flag != 0 {
                format!("{dll}!#{}", t & 0xFFFF)
            } else {
                // The low 31 bits are the RVA of the hint/name entry; skip its 2-byte hint.
                format!(
                    "{dll}!{}",
                    cstr(img, img.base + (t & 0x7FFF_FFFF) as usize + 2)
                )
            };
            out.insert(slot, name);
            i += 1;
        }
        desc += 20;
    }
    out
}

/// The set of imported API names a function at `rva` calls directly (`call`/`jmp [IAT slot]`), decoded
/// to its first `ret` or [`SCAN_INSTRS`].
pub(super) fn import_set(
    img: &ImageInput,
    map: &HashMap<usize, String>,
    rva: usize,
) -> BTreeSet<String> {
    let bytes = read_at(img.source, img.base, rva, SCAN_INSTRS * 8);
    let mut dec = Decoder::with_ip(
        bitness(img.arch),
        &bytes,
        (img.base + rva) as u64,
        DecoderOptions::NONE,
    );
    let mut instr = Instruction::default();
    let mut out = BTreeSet::new();
    let mut n = 0;
    while dec.can_decode() && n < SCAN_INSTRS {
        dec.decode_out(&mut instr);
        if instr.is_invalid() || instr.len() == 0 {
            break;
        }
        n += 1;
        if matches!(
            instr.flow_control(),
            FlowControl::IndirectCall | FlowControl::IndirectBranch
        ) && instr.op_kinds().any(|k| k == OpKind::Memory)
        {
            // The IAT slot the call dereferences: `call [abs]` on x86 (no base/index) or the
            // `call [rip+disp]` form on x64, whose effective address iced resolves for us.
            let slot = if instr.is_ip_rel_memory_operand() {
                Some(instr.ip_rel_memory_address() as usize)
            } else if instr.memory_base() == Register::None
                && instr.memory_index() == Register::None
            {
                Some(instr.memory_displacement64() as usize)
            } else {
                None
            };
            if let Some(name) = slot.and_then(|s| map.get(&s)) {
                out.insert(name.clone());
            }
        }
        if instr.flow_control() == FlowControl::Return {
            break;
        }
    }
    out
}

/// Build an import anchor for the function at `rva`: the set of imports it calls directly, if it is
/// distinctive enough ([`MIN_IMPORTS`]). Uniqueness is validated at resolve time. x86 only.
#[must_use]
pub(super) fn make_import_anchor(img: &ImageInput, rva: usize) -> Option<ImportAnchor> {
    let map = import_map(img);
    let set = import_set(img, &map, rva);
    (set.len() >= MIN_IMPORTS).then(|| ImportAnchor {
        names: set.into_iter().collect(),
    })
}

/// Resolve an import anchor to the single function in `img` whose direct import set equals it. Returns
/// `None` if no function matches or more than one does (an ambiguous anchor declines rather than guess).
#[must_use]
pub(super) fn resolve_import_anchor(img: &ImageInput, anchor: &ImportAnchor) -> Option<usize> {
    let map = import_map(img);
    let want: BTreeSet<&str> = anchor.names.iter().map(String::as_str).collect();
    let mut found = None;
    for &rva in super::model::AnalysisModel::build(img).entries() {
        let set = import_set(img, &map, rva);
        if set.len() == want.len() && set.iter().map(String::as_str).eq(want.iter().copied()) {
            if found.is_some() {
                return None; // not unique
            }
            found = Some(rva);
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::{BufferSource, Region};

    fn img_arch<'a>(src: &'a BufferSource, base: usize, size: usize, arch: Arch) -> ImageInput<'a> {
        ImageInput {
            label: "t".into(),
            source: src,
            base,
            size,
            code_regions: vec![Region { base, size }],
            regions: vec![Region { base, size }],
            import: None,
            arch,
            code_hash: 0,
            packed: false,
            pack_reasons: Vec::new(),
            reloc: None,
        }
    }
    fn img<'a>(src: &'a BufferSource, base: usize, size: usize) -> ImageInput<'a> {
        img_arch(src, base, size, Arch::X86)
    }

    #[test]
    fn import_set_collects_indirect_call_targets() {
        // call [0x2000] ; call [0x2004] ; ret, with a map naming those two IAT slots.
        let code = vec![
            0xFF, 0x15, 0x00, 0x20, 0x00, 0x00, // call [0x2000]
            0xFF, 0x15, 0x04, 0x20, 0x00, 0x00, // call [0x2004]
            0xC3,
        ];
        let src = BufferSource::new(0x1000, code);
        let image = img(&src, 0x1000, 0x20);
        let mut map = HashMap::new();
        map.insert(0x2000usize, "ws2_32.dll!socket".to_string());
        map.insert(0x2004usize, "ws2_32.dll!closesocket".to_string());
        let set = import_set(&image, &map, 0);
        assert_eq!(set.len(), 2);
        assert!(set.contains("ws2_32.dll!socket"));
        assert!(set.contains("ws2_32.dll!closesocket"));
    }

    #[test]
    fn a_lone_import_is_below_the_anchor_floor() {
        // One import is not distinctive: make_import_anchor must decline (MIN_IMPORTS).
        let code = vec![0xFF, 0x15, 0x00, 0x20, 0x00, 0x00, 0xC3]; // call [0x2000] ; ret
        let src = BufferSource::new(0x1000, code);
        let image = img(&src, 0x1000, 0x20);
        let map = HashMap::new(); // no names -> empty set
        assert!(import_set(&image, &map, 0).is_empty());
        assert!(make_import_anchor(&image, 0).is_none());
    }

    #[test]
    fn import_set_collects_x64_rip_relative_calls() {
        // #12: x64 dereferences the IAT RIP-relatively. call [rip+0x1FFA] (6 bytes, next IP base+6 ->
        // base+0x2000) ; call [rip+0x1FFC] (next IP base+12 -> base+0x2008) ; ret.
        let code = vec![
            0xFF, 0x15, 0xFA, 0x1F, 0x00, 0x00, // call [rip+0x1FFA]
            0xFF, 0x15, 0xFC, 0x1F, 0x00, 0x00, // call [rip+0x1FFC]
            0xC3,
        ];
        let src = BufferSource::new(0x1000, code);
        let image = img_arch(&src, 0x1000, 0x20, Arch::X64);
        let mut map = HashMap::new();
        map.insert(0x1000 + 0x2000, "ws2_32.dll!socket".to_string());
        map.insert(0x1000 + 0x2008, "ws2_32.dll!closesocket".to_string());
        let set = import_set(&image, &map, 0);
        assert_eq!(set.len(), 2);
        assert!(set.contains("ws2_32.dll!socket"));
        assert!(set.contains("ws2_32.dll!closesocket"));
    }

    #[test]
    fn import_map_parses_pe32plus_thunks() {
        // #12: a minimal PE32+ import directory naming one ws2_32 import via 8-byte thunks; import_map
        // must read the 8-byte INT entry, follow it to the hint/name, and key the IAT slot by it.
        const BASE: usize = 0x1000;
        let mut buf = vec![0u8; 0x200];
        buf[0x100..0x10B].copy_from_slice(b"ws2_32.dll\0"); // DLL name @ 0x100
        buf[0x122..0x129].copy_from_slice(b"socket\0"); // name @ 0x122 (after a 2-byte hint @ 0x120)
        buf[0x140..0x148].copy_from_slice(&0x120u64.to_le_bytes()); // INT thunk[0] -> hint/name @ 0x120
        buf[0x160..0x168].copy_from_slice(&0x120u64.to_le_bytes()); // IAT thunk[0] (pre-load mirror)
        // IMAGE_IMPORT_DESCRIPTOR @ 0x180: OriginalFirstThunk, _, _, Name, FirstThunk (then a null one).
        buf[0x180..0x184].copy_from_slice(&0x140u32.to_le_bytes()); // OriginalFirstThunk = INT rva
        buf[0x18C..0x190].copy_from_slice(&0x100u32.to_le_bytes()); // Name = DLL-name rva
        buf[0x190..0x194].copy_from_slice(&0x160u32.to_le_bytes()); // FirstThunk = IAT rva
        let src = BufferSource::new(BASE, buf);
        let mut image = img_arch(&src, BASE, 0x200, Arch::X64);
        image.import = Some((BASE + 0x180, BASE + 0x180 + 40));
        let map = import_map(&image);
        assert_eq!(
            map.get(&(BASE + 0x160)).map(String::as_str),
            Some("ws2_32.dll!socket")
        );
    }
}
