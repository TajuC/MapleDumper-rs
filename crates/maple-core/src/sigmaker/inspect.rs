//! Deep per-function analysis for the desktop "Investigate" panel: assemble everything the engine already
//! computes about one address (its enclosing function's CFG-lite shape, cross-references, callers and
//! callees, the imported APIs it calls, its referenced strings and distinctive constants, vtable/RTTI
//! membership, and a disassembly listing) into one serializable bundle. This is a read-only view built
//! from the same internals the relocation anchors use, so the user can see WHY a relocation did or did not
//! work and investigate manually. x86 / PE32, like the anchors.

use iced_x86::{Decoder, DecoderOptions, FlowControl, Formatter, Instruction, NasmFormatter};

use super::types::ImageInput;
use super::{bitness, identity, imports, model, read_at, vtable};

/// One decoded instruction in the disassembly listing.
#[derive(Clone, Debug)]
pub struct DisasmLine {
    pub rva: u64,
    pub bytes: String,
    pub text: String,
}

/// Vtable/RTTI membership of a virtual method.
#[derive(Clone, Debug)]
pub struct VtableInsight {
    pub table_rva: u64,
    pub slot: usize,
    pub slot_count: usize,
    /// The MSVC RTTI class name when the chain is navigable; usually absent on this corpus.
    pub class_name: Option<String>,
}

/// The full read-only analysis of the function enclosing a queried address.
#[derive(Clone, Debug)]
pub struct FunctionInsight {
    /// The address that was queried, and the function entry it resolved to.
    pub query_rva: u64,
    pub entry_rva: u64,
    pub instr_count: usize,
    pub blocks: usize,
    pub calls: usize,
    pub branches: usize,
    pub returns: usize,
    /// Approximate inbound cross-references (rel32 call/jmp and x64 rip-relative lea) to the entry.
    pub xref_count: usize,
    /// Distinctive immediate constants the function uses.
    pub constants: Vec<u64>,
    /// ASCII/UTF-16 strings the function references.
    pub strings: Vec<String>,
    /// Enclosing functions that call this one (their entry RVAs).
    pub callers: Vec<u64>,
    /// Functions this one calls directly (their entry RVAs).
    pub callees: Vec<u64>,
    /// Imported API names this function calls directly (`dll!Func` form not preserved; bare names).
    pub imports: Vec<String>,
    /// A re-scannable string anchor for the function, when one isolates it.
    pub string_anchor: Option<String>,
    /// Vtable/RTTI membership when the function is a virtual method.
    pub vtable: Option<VtableInsight>,
    /// A disassembly listing from the entry to the first return (capped).
    pub disasm: Vec<DisasmLine>,
}

const DISASM_MAX_INSTRS: usize = 200;

/// Analyse the function enclosing `rva` in `img`. Always returns a bundle (the structural fields resolve
/// for any code address); the anchor-specific fields are populated when applicable. x86 only for the
/// graph/vtable/import channels (they decline cleanly on x64); the disassembly works at any bitness.
#[must_use]
pub fn inspect_function(img: &ImageInput, rva: usize) -> FunctionInsight {
    let entry = identity::enclosing_function(img, rva);
    let id = identity::fn_identity(img, entry);

    // Callers and callees from the decode-verified call graph.
    let m = model::AnalysisModel::build(img);
    let callers: Vec<u64> = m
        .callers_of(img, entry)
        .into_iter()
        .map(|r| r as u64)
        .collect();
    let mut callees: Vec<u64> = m
        .call_sites()
        .filter(|&(site, _)| identity::enclosing_function(img, site) == entry)
        .map(|(_, target)| target as u64)
        .collect();
    callees.sort_unstable();
    callees.dedup();

    let imports: Vec<String> = imports::import_set(img, &imports::import_map(img), entry)
        .into_iter()
        .collect();

    let string_anchor = identity::make_string_anchor(img, entry).map(|a| match &a.also {
        Some(also) => format!("@string={} @also={also}", a.text),
        None => format!("@string={}", a.text),
    });

    let vtable = vtable::membership(img, entry).map(|(table_rva, slot, slot_count, class_name)| {
        VtableInsight {
            table_rva: table_rva as u64,
            slot,
            slot_count,
            class_name,
        }
    });

    FunctionInsight {
        query_rva: rva as u64,
        entry_rva: entry as u64,
        instr_count: id.instr_count,
        blocks: id.blocks,
        calls: id.calls,
        branches: id.branches,
        returns: id.returns,
        xref_count: identity::xref_count(img, entry),
        constants: id.constants.clone(),
        strings: id.strings.clone(),
        callers,
        callees,
        imports,
        string_anchor,
        vtable,
        disasm: disassemble(img, entry),
    }
}

// Decode and format the function from `entry` to its first return, capped at DISASM_MAX_INSTRS, resyncing
// one byte on an invalid decode so a data island cannot derail the listing.
fn disassemble(img: &ImageInput, entry: usize) -> Vec<DisasmLine> {
    let bytes = read_at(img.source, img.base, entry, DISASM_MAX_INSTRS * 8);
    let ip0 = (img.base + entry) as u64;
    let mut dec = Decoder::with_ip(bitness(img.arch), &bytes, ip0, DecoderOptions::NONE);
    let mut fmt = NasmFormatter::new();
    let mut instr = Instruction::default();
    let mut out = Vec::new();
    while dec.can_decode() && out.len() < DISASM_MAX_INSTRS {
        let pos = dec.position();
        dec.set_ip((img.base + entry + pos) as u64);
        dec.decode_out(&mut instr);
        if instr.is_invalid() || instr.len() == 0 {
            let _ = dec.set_position(pos + 1);
            continue;
        }
        let raw = &bytes[pos..pos + instr.len()];
        let hex = raw
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(" ");
        let mut text = String::new();
        fmt.format(&instr, &mut text);
        out.push(DisasmLine {
            rva: (instr.ip() as usize - img.base) as u64,
            bytes: hex,
            text,
        });
        if instr.flow_control() == FlowControl::Return {
            break;
        }
    }
    out
}
