//! Completeness gates for a cleaned dump, returning a structured report. The hard gates
//! are imports, `.pdata`, and (when a reference is supplied) `.text` identity. OEP shape
//! and the virtualization sample are advisory and never block on their own.

use iced_x86::{Decoder, DecoderOptions, FlowControl, Formatter, Instruction, NasmFormatter};

use super::{Pe, get_u32, get_u64, sha256};

const MSVC_PROLOGUE: [u8; 5] = [0x48, 0x89, 0x5c, 0x24, 0x20];
const DEAD_RANGE_NAMES: [&str; 5] = [".themida", ".boot", ".SCY", ".rsrv0", ".rsrv1"];
const VIRT_SAMPLE_CAP: usize = 2000;

/// The verification report shown on the CLI and in the GUI results card.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct VerifyReport {
    pub oep_rva: u32,
    pub oep_bytes: String,
    pub oep_is_msvc: bool,
    pub oep_disasm: Vec<String>,
    pub import_dlls: u32,
    pub import_functions: u32,
    pub imports_ok: bool,
    pub pdata_entries: u32,
    pub pdata_valid_pct: f64,
    pub pdata_ascending_pct: f64,
    pub pdata_ok: bool,
    pub virtualization_pct: f64,
    pub virtualization_sampled: u32,
    pub text_identity: Option<bool>,
    pub text_ref: Option<String>,
    pub text_sha256: Option<String>,
    pub output_size: u64,
    pub gates_pass: bool,
    pub warnings: Vec<String>,
}

fn section_raw<'a>(data: &'a [u8], pe: &Pe, name: &str) -> Option<&'a [u8]> {
    let s = pe.section(name)?;
    let end = (s.ro as usize).checked_add(s.rs as usize)?;
    data.get(s.ro as usize..end)
}

/// Run every gate over `cleaned`. `reference` is `(bytes, label)` of the binary to prove
/// `.text` identity against; `None` skips that gate.
pub fn verify_bytes(
    cleaned: &[u8],
    reference: Option<(&[u8], &str)>,
) -> std::io::Result<VerifyReport> {
    let pe = Pe::parse(cleaned)?;

    let (import_dlls, import_functions) = count_imports(cleaned, &pe);
    let imports_ok = import_dlls >= 5 && import_functions >= 50;

    let (pdata_entries, pdata_valid_pct, pdata_ascending_pct) = check_pdata(cleaned, &pe);
    let pdata_ok = pdata_entries > 1000 && pdata_valid_pct > 95.0 && pdata_ascending_pct > 99.0;

    let oep_off = pe.rva2off(pe.aep);
    let oep_head = oep_off.and_then(|o| cleaned.get(o..(o + 48).min(cleaned.len())));
    let oep_is_msvc = oep_head.is_some_and(|h| h.starts_with(&MSVC_PROLOGUE));
    let oep_bytes = oep_head
        .map(|h| hex(&h[..h.len().min(8)]))
        .unwrap_or_default();
    let oep_disasm = match (oep_off, oep_head) {
        (Some(_), Some(h)) => disasm(h, pe.image_base + pe.aep as u64, pe.is64, 6),
        _ => Vec::new(),
    };

    let (virt_sampled, virt_flagged) = virtualization_sample(cleaned, &pe);
    let virtualization_pct = if virt_sampled > 0 {
        100.0 * virt_flagged as f64 / virt_sampled as f64
    } else {
        0.0
    };

    let cleaned_text = section_raw(cleaned, &pe, ".text");
    let text_sha256 = cleaned_text.map(sha256::hex);
    let mut warnings = Vec::new();
    let (text_identity, text_ref) = match reference {
        Some((ref_bytes, label)) => {
            let ref_pe = Pe::parse(ref_bytes).ok();
            let ref_text = ref_pe
                .as_ref()
                .and_then(|rpe| section_raw(ref_bytes, rpe, ".text"));
            match (cleaned_text, ref_text) {
                (Some(ct), Some(rt)) => (Some(rt == ct), Some(label.to_string())),
                // An unreadable reference is not a code mismatch; skip the check and say so
                // rather than reporting a misleading FAIL.
                _ => {
                    warnings.push(format!(
                        "could not read .text from the {label} reference; skipped the identity check"
                    ));
                    (None, Some(label.to_string()))
                }
            }
        }
        None => (None, None),
    };

    if !oep_is_msvc {
        warnings.push(format!(
            "OEP prologue at rva {:#x} is not the expected MSVC pattern",
            pe.aep
        ));
    }
    if virtualization_pct > 1.0 {
        warnings.push(format!(
            "a virtualization sample of {virtualization_pct:.2}% across {virt_sampled} function starts suggests a VM-protected build"
        ));
    }

    let gates_pass = imports_ok && pdata_ok && text_identity != Some(false);

    Ok(VerifyReport {
        oep_rva: pe.aep,
        oep_bytes,
        oep_is_msvc,
        oep_disasm,
        import_dlls,
        import_functions,
        imports_ok,
        pdata_entries,
        pdata_valid_pct,
        pdata_ascending_pct,
        pdata_ok,
        virtualization_pct,
        virtualization_sampled: virt_sampled,
        text_identity,
        text_ref,
        text_sha256,
        output_size: cleaned.len() as u64,
        gates_pass,
        warnings,
    })
}

fn count_imports(data: &[u8], pe: &Pe) -> (u32, u32) {
    let Some(imp) = get_u32(data, pe.dd + 8) else {
        return (0, 0);
    };
    let Some(ioff) = pe.rva2off(imp) else {
        return (0, 0);
    };
    let ptr = if pe.is64 { 8usize } else { 4 };
    let (mut dlls, mut fns) = (0u32, 0u32);
    let mut idx = 0usize;
    while idx < 4096 {
        let d = ioff + idx * 20;
        let Some(oft) = get_u32(data, d) else { break };
        let name = get_u32(data, d + 12).unwrap_or(0);
        let ft = get_u32(data, d + 16).unwrap_or(0);
        if oft == 0 && name == 0 && ft == 0 {
            break;
        }
        dlls += 1;
        let arr = if oft != 0 { oft } else { ft };
        if let Some(aoff) = pe.rva2off(arr) {
            let mut j = 0usize;
            while j < 8192 {
                let off = aoff + j * ptr;
                let v = if pe.is64 {
                    get_u64(data, off)
                } else {
                    get_u32(data, off).map(u64::from)
                };
                match v {
                    Some(0) | None => break,
                    Some(_) => fns += 1,
                }
                j += 1;
            }
        }
        idx += 1;
    }
    (dlls, fns)
}

fn check_pdata(data: &[u8], pe: &Pe) -> (u32, f64, f64) {
    let (Some(ps), Some(tx)) = (pe.section(".pdata"), pe.section(".text")) else {
        return (0, 0.0, 0.0);
    };
    let Some(raw) = section_raw(data, pe, ".pdata") else {
        return (0, 0.0, 0.0);
    };
    let _ = ps;
    let n = raw.len() / 12;
    if n == 0 {
        return (0, 0.0, 0.0);
    }
    let (tlo, thi) = (tx.va, tx.va as u64 + tx.vs as u64);
    let mut valid = 0u64;
    let mut ascending = 0u64;
    let mut prev = 0u32;
    for k in 0..n {
        let begin = get_u32(raw, k * 12).unwrap_or(0);
        let end = get_u32(raw, k * 12 + 4).unwrap_or(0);
        if begin >= tlo && (begin as u64) < thi && end > begin {
            valid += 1;
        }
        if k > 0 && begin > prev {
            ascending += 1;
        }
        prev = begin;
    }
    let valid_pct = 100.0 * valid as f64 / n as f64;
    let asc_pct = if n > 1 {
        100.0 * ascending as f64 / (n - 1) as f64
    } else {
        0.0
    };
    (n as u32, valid_pct, asc_pct)
}

/// Sample function starts from `.pdata` and flag any whose first two instructions jump or
/// call directly into a dead (Themida residue) section. A near-zero rate means the bulk
/// code is real; a high rate means a VM-protected build that is out of scope.
fn virtualization_sample(data: &[u8], pe: &Pe) -> (u32, u32) {
    let Some(raw) = section_raw(data, pe, ".pdata") else {
        return (0, 0);
    };
    let n = raw.len() / 12;
    if n == 0 {
        return (0, 0);
    }
    let dead: Vec<(u32, u32)> = pe
        .sections
        .iter()
        .filter(|s| DEAD_RANGE_NAMES.contains(&s.name.as_str()))
        .map(|s| (s.va, s.va.saturating_add(s.vs.max(s.rs))))
        .collect();
    if dead.is_empty() {
        return (0, 0);
    }
    let bitness = if pe.is64 { 64u32 } else { 32 };
    let step = n.div_ceil(VIRT_SAMPLE_CAP).max(1);
    let (mut sampled, mut flagged) = (0u32, 0u32);
    let mut k = 0usize;
    while k < n {
        let begin = get_u32(raw, k * 12).unwrap_or(0);
        if let Some(off) = pe.rva2off(begin)
            && let Some(buf) = data.get(off..(off + 16).min(data.len()))
        {
            sampled += 1;
            if jumps_into_dead(
                buf,
                pe.image_base + begin as u64,
                bitness,
                pe.image_base,
                &dead,
            ) {
                flagged += 1;
            }
        }
        k += step;
    }
    (sampled, flagged)
}

fn jumps_into_dead(buf: &[u8], ip: u64, bitness: u32, base: u64, dead: &[(u32, u32)]) -> bool {
    let mut decoder = Decoder::with_ip(bitness, buf, ip, DecoderOptions::NONE);
    let mut instr = Instruction::default();
    for _ in 0..2 {
        if !decoder.can_decode() {
            break;
        }
        decoder.decode_out(&mut instr);
        if instr.is_invalid() {
            break;
        }
        if matches!(
            instr.flow_control(),
            FlowControl::Call | FlowControl::UnconditionalBranch
        ) {
            let target = instr.near_branch_target();
            if target >= base {
                let rva = (target - base) as u32;
                if dead.iter().any(|&(a, b)| rva >= a && rva < b) {
                    return true;
                }
            }
        }
    }
    false
}

fn disasm(buf: &[u8], ip: u64, is64: bool, max: usize) -> Vec<String> {
    let bitness = if is64 { 64u32 } else { 32 };
    let mut decoder = Decoder::with_ip(bitness, buf, ip, DecoderOptions::NONE);
    let mut formatter = NasmFormatter::new();
    let mut instr = Instruction::default();
    let mut out = Vec::new();
    while decoder.can_decode() && out.len() < max {
        decoder.decode_out(&mut instr);
        if instr.is_invalid() {
            break;
        }
        let mut text = String::new();
        formatter.format(&instr, &mut text);
        out.push(format!("{:#x}: {text}", instr.ip()));
    }
    out
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
