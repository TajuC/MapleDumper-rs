//! Turn a Themida-packed MapleStory client into a clean, analyzable binary.
//!
//! Two phases. The DUMP phase ([`dump`]) is inherently dynamic and orchestrates
//! `unlicense.exe`. The CLEAN phase ([`clean_bytes`]) is pure static PE editing and
//! owns the novel value: six deterministic header/section operations that never touch
//! code bytes, plus the verification gates in [`verify`]. With both options off,
//! [`clean_bytes`] reproduces the `proto/unpack_clean.py` oracle byte for byte.

mod dump;
mod sha256;
mod verify;

use std::io;
use std::path::Path;

pub use dump::locate_unlicense;
pub use verify::{VerifyReport, verify_bytes};

const IDATA: u32 = 0x40;
const READ: u32 = 0x4000_0000;

const DEAD_STRIP: [&str; 2] = [".themida", ".boot"];
const DEAD_DEEXEC: [&str; 3] = [".themida", ".boot", ".SCY"];

fn rename_target(name: &str) -> Option<[u8; 8]> {
    match name {
        ".themida" => Some(*b".rsrv0\0\0"),
        ".boot" => Some(*b".rsrv1\0\0"),
        _ => None,
    }
}

fn bad<S: Into<String>>(m: S) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, m.into())
}

fn get_u16(d: &[u8], o: usize) -> Option<u16> {
    d.get(o..o + 2)
        .map(|b| u16::from_le_bytes(b.try_into().unwrap()))
}
fn get_u32(d: &[u8], o: usize) -> Option<u32> {
    d.get(o..o + 4)
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
}
fn get_u64(d: &[u8], o: usize) -> Option<u64> {
    d.get(o..o + 8)
        .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
}
fn put_u32(d: &mut [u8], o: usize, v: u32) -> io::Result<()> {
    let slot = d
        .get_mut(o..o + 4)
        .ok_or_else(|| bad("write past end of image"))?;
    slot.copy_from_slice(&v.to_le_bytes());
    Ok(())
}
fn put_u64(d: &mut [u8], o: usize, v: u64) -> io::Result<()> {
    let slot = d
        .get_mut(o..o + 8)
        .ok_or_else(|| bad("write past end of image"))?;
    slot.copy_from_slice(&v.to_le_bytes());
    Ok(())
}

fn section_name(raw: &[u8]) -> String {
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    String::from_utf8_lossy(&raw[..end]).into_owned()
}

/// A parsed section header, carrying the file offset of the header itself so the
/// clean ops can rewrite fields in place without re-deriving layout.
pub(super) struct Sec {
    pub hdr: usize,
    pub name: String,
    pub vs: u32,
    pub va: u32,
    pub rs: u32,
    pub ro: u32,
}

/// A minimal raw view over PE headers. Mirrors `proto/unpack_clean.py::parse` and is
/// deliberately separate from [`crate::FileImage`], which maps sections for scanning
/// rather than rewriting them on disk.
pub(super) struct Pe {
    pub coff: usize,
    pub is64: bool,
    pub dd: usize,
    pub image_base: u64,
    pub aep: u32,
    pub sections: Vec<Sec>,
}

impl Pe {
    pub(super) fn parse(data: &[u8]) -> io::Result<Pe> {
        if data.len() < 0x40 || &data[0..2] != b"MZ" {
            return Err(bad("not a PE image (missing MZ)"));
        }
        let e = get_u32(data, 0x3C).ok_or_else(|| bad("truncated DOS header"))? as usize;
        let coff = e
            .checked_add(4)
            .ok_or_else(|| bad("PE header offset overflows"))?;
        if data.get(e..coff) != Some(b"PE\0\0".as_slice()) {
            return Err(bad("missing PE signature"));
        }
        let num_sections =
            get_u16(data, coff + 2).ok_or_else(|| bad("truncated COFF header"))? as usize;
        let size_opt =
            get_u16(data, coff + 16).ok_or_else(|| bad("truncated COFF header"))? as usize;
        let opt = coff + 20;
        let magic = get_u16(data, opt).ok_or_else(|| bad("truncated optional header"))?;
        let is64 = match magic {
            0x20B => true,
            0x10B => false,
            _ => return Err(bad("unsupported optional header magic")),
        };
        let image_base = if is64 {
            get_u64(data, opt + 0x18).ok_or_else(|| bad("truncated PE32+ header"))?
        } else {
            get_u32(data, opt + 0x1C).ok_or_else(|| bad("truncated PE32 header"))? as u64
        };
        let aep = get_u32(data, opt + 16).ok_or_else(|| bad("truncated optional header"))?;
        let dd = opt + if is64 { 0x70 } else { 0x60 };
        let sec_table = opt
            .checked_add(size_opt)
            .ok_or_else(|| bad("section table offset overflows"))?;
        let mut sections = Vec::with_capacity(num_sections.min(96));
        for i in 0..num_sections {
            let h = sec_table + i * 40;
            if h.checked_add(40).is_none_or(|end| end > data.len()) {
                return Err(bad("truncated section table"));
            }
            sections.push(Sec {
                hdr: h,
                name: section_name(&data[h..h + 8]),
                vs: get_u32(data, h + 8).unwrap(),
                va: get_u32(data, h + 12).unwrap(),
                rs: get_u32(data, h + 16).unwrap(),
                ro: get_u32(data, h + 20).unwrap(),
            });
        }
        Ok(Pe {
            coff,
            is64,
            dd,
            image_base,
            aep,
            sections,
        })
    }

    pub(super) fn section(&self, name: &str) -> Option<&Sec> {
        self.sections.iter().find(|s| s.name == name)
    }

    pub(super) fn rva2off(&self, rva: u32) -> Option<usize> {
        for s in &self.sections {
            if s.rs == 0 {
                continue;
            }
            // Only the raw-backed span maps to a file offset; an RVA in a section's
            // virtual-only tail (past SizeOfRawData) has no bytes on disk.
            if rva >= s.va && (rva as u64) < s.va as u64 + s.rs as u64 {
                return Some(s.ro as usize + (rva - s.va) as usize);
            }
        }
        None
    }
}

/// Production enhancements over the manual session, both on by default: a reproducible,
/// machine-neutral output. Turn both off to reproduce the recorded session min exactly.
#[derive(Clone, Copy, Debug)]
pub struct CleanOptions {
    /// Copy each `OriginalFirstThunk` over its `FirstThunk` so the import table no longer
    /// carries the dump host's live module addresses.
    pub unbind_iat: bool,
    /// Zero the COFF `TimeDateStamp` for a deterministic output hash.
    pub zero_timestamp: bool,
}

impl Default for CleanOptions {
    fn default() -> Self {
        Self {
            unbind_iat: true,
            zero_timestamp: true,
        }
    }
}

impl CleanOptions {
    /// The flags that reproduce `proto/unpack_clean.py clean` with no options, i.e. the
    /// recorded 2026 session min. Used by the golden test.
    pub fn oracle() -> Self {
        Self {
            unbind_iat: false,
            zero_timestamp: false,
        }
    }
}

/// What the clean pass did, for the report card and CLI summary.
#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct CleanSummary {
    pub exception_repointed: bool,
    pub cert_cleared: bool,
    pub iat_dir: Option<(u32, u32)>,
    pub unbound_thunks: u32,
    pub deexec: Vec<String>,
    pub renamed: Vec<String>,
    pub timestamp_zeroed: bool,
    pub stripped_bytes: u32,
    pub size_before: u64,
    pub size_after: u64,
}

/// Cleaned image bytes plus a summary of the edits. `data` is intentionally not
/// serialized; it is the (large) output binary.
pub struct Cleaned {
    pub data: Vec<u8>,
    pub summary: CleanSummary,
}

/// Coarse progress through the pipeline, reported to the CLI and GUI so a long dump
/// does not look frozen.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Stage {
    Locate,
    Dump,
    Clean,
    Verify,
    Done,
}

/// A progress event. `Line` carries a raw line from the dumper for live display.
pub enum Progress<'a> {
    Stage(Stage),
    Line(&'a str),
}

/// The end-to-end result. `output` is `None` when the gates failed: in that case no
/// binary is written, so the caller can report the failure without a broken artifact.
#[derive(Clone, Debug, serde::Serialize)]
pub struct UnpackReport {
    pub input: String,
    pub output: Option<String>,
    pub dump_path: Option<String>,
    pub gates_pass: bool,
    pub clean: CleanSummary,
    pub verify: VerifyReport,
}

/// Apply the six static clean operations. Code bytes are never modified.
pub fn clean_bytes(raw: &[u8], opts: &CleanOptions) -> io::Result<Cleaned> {
    let mut data = raw.to_vec();
    let pe = Pe::parse(&data)?;
    let mut summary = CleanSummary {
        size_before: data.len() as u64,
        ..Default::default()
    };

    if let Some(pd) = pe.section(".pdata") {
        put_u32(&mut data, pe.dd + 3 * 8, pd.va)?;
        put_u32(&mut data, pe.dd + 3 * 8 + 4, pd.vs)?;
        summary.exception_repointed = true;
    }

    put_u32(&mut data, pe.dd + 4 * 8, 0)?;
    put_u32(&mut data, pe.dd + 4 * 8 + 4, 0)?;
    summary.cert_cleared = true;

    let (iat_rva, iat_size) = compute_iat(&data, &pe)?;
    if iat_rva != 0 {
        put_u32(&mut data, pe.dd + 12 * 8, iat_rva)?;
        put_u32(&mut data, pe.dd + 12 * 8 + 4, iat_size)?;
        summary.iat_dir = Some((iat_rva, iat_size));
    }

    if opts.unbind_iat {
        summary.unbound_thunks = unbind_iat(&mut data, &pe)?;
    }

    for name in DEAD_DEEXEC {
        if let Some(s) = pe.section(name) {
            put_u32(&mut data, s.hdr + 36, READ | IDATA)?;
            summary.deexec.push(name.to_string());
        }
    }

    if opts.zero_timestamp {
        put_u32(&mut data, pe.coff + 4, 0)?;
        summary.timestamp_zeroed = true;
    }

    for s in &pe.sections {
        if let Some(nn) = rename_target(&s.name) {
            let slot = data
                .get_mut(s.hdr..s.hdr + 8)
                .ok_or_else(|| bad("section name past end"))?;
            slot.copy_from_slice(&nn);
            summary.renamed.push(s.name.clone());
        }
    }

    let dead: Vec<&Sec> = DEAD_STRIP.iter().filter_map(|n| pe.section(n)).collect();
    if !dead.is_empty() {
        summary.stripped_bytes = strip_dead(&mut data, &dead, &pe)?;
    }

    summary.size_after = data.len() as u64;
    Ok(Cleaned { data, summary })
}

/// IAT directory extent: the smallest `FirstThunk` to the largest `FirstThunk` end
/// (with each array's null terminator), across all import descriptors.
fn compute_iat(data: &[u8], pe: &Pe) -> io::Result<(u32, u32)> {
    let Some(imp) = get_u32(data, pe.dd + 8) else {
        return Ok((0, 0));
    };
    let Some(ioff) = pe.rva2off(imp) else {
        return Ok((0, 0));
    };
    let ptr = if pe.is64 { 8usize } else { 4 };
    let mut fts: Vec<(u32, u64)> = Vec::new();
    let mut idx = 0usize;
    while idx < 4096 {
        let d = ioff + idx * 20;
        let Some(oft) = get_u32(data, d) else { break };
        let name = get_u32(data, d + 12).unwrap_or(0);
        let ft = get_u32(data, d + 16).unwrap_or(0);
        if oft == 0 && name == 0 && ft == 0 {
            break;
        }
        let arr = if oft != 0 { oft } else { ft };
        let mut cnt: u64 = 0;
        if let Some(aoff) = pe.rva2off(arr) {
            while cnt < 8192 {
                let off = aoff + cnt as usize * ptr;
                let v = if pe.is64 {
                    get_u64(data, off)
                } else {
                    get_u32(data, off).map(u64::from)
                };
                match v {
                    Some(0) | None => break,
                    Some(_) => cnt += 1,
                }
            }
        }
        // Only descriptors with a real FirstThunk define the IAT extent; a zero ft has no
        // thunk array on disk, so including it would collapse the min to 0 and drop the rewrite.
        if ft != 0 {
            fts.push((ft, (cnt + 1) * ptr as u64));
        }
        idx += 1;
    }
    if fts.is_empty() {
        return Ok((0, 0));
    }
    let lo = fts.iter().map(|&(ft, _)| ft).min().unwrap();
    let hi = fts.iter().map(|&(ft, sz)| ft as u64 + sz).max().unwrap();
    let size = u32::try_from(hi - lo as u64).map_err(|_| bad("IAT extent overflows"))?;
    Ok((lo, size))
}

/// Drop the dump host's bound addresses by copying `OriginalFirstThunk` to `FirstThunk`.
fn unbind_iat(data: &mut [u8], pe: &Pe) -> io::Result<u32> {
    let Some(imp) = get_u32(data, pe.dd + 8) else {
        return Ok(0);
    };
    let Some(ioff) = pe.rva2off(imp) else {
        return Ok(0);
    };
    let ptr = if pe.is64 { 8usize } else { 4 };
    let mut idx = 0usize;
    let mut touched = 0u32;
    while idx < 4096 {
        let d = ioff + idx * 20;
        let Some(oft) = get_u32(data, d) else { break };
        let name = get_u32(data, d + 12).unwrap_or(0);
        let ft = get_u32(data, d + 16).unwrap_or(0);
        if oft == 0 && name == 0 && ft == 0 {
            break;
        }
        if oft != 0
            && ft != 0
            && let (Some(ooff), Some(foff)) = (pe.rva2off(oft), pe.rva2off(ft))
        {
            let mut j = 0usize;
            while j < 8192 {
                let (so, dofs) = (ooff + j * ptr, foff + j * ptr);
                let v = if pe.is64 {
                    get_u64(data, so)
                } else {
                    get_u32(data, so).map(u64::from)
                };
                let Some(v) = v else { break };
                if pe.is64 {
                    put_u64(data, dofs, v)?;
                } else {
                    put_u32(data, dofs, v as u32)?;
                }
                touched += 1;
                if v == 0 {
                    break;
                }
                j += 1;
            }
        }
        idx += 1;
    }
    Ok(touched)
}

/// Remove the contiguous raw run of the dead sections, keep their headers (so RVAs never
/// move), shift trailing sections' file pointers down, and truncate.
fn strip_dead(data: &mut Vec<u8>, dead: &[&Sec], pe: &Pe) -> io::Result<u32> {
    let lo = dead.iter().map(|s| s.ro as usize).min().unwrap();
    let mut hi = 0usize;
    for s in dead {
        let end = (s.ro as usize)
            .checked_add(s.rs as usize)
            .ok_or_else(|| bad("dead section extent overflows"))?;
        hi = hi.max(end);
    }
    if lo >= hi {
        return Ok(0);
    }
    if hi > data.len() {
        return Err(bad("dead section raw range past end of image"));
    }
    let dead_hdrs: Vec<usize> = dead.iter().map(|s| s.hdr).collect();
    for s in &pe.sections {
        if dead_hdrs.contains(&s.hdr) || s.rs == 0 {
            continue;
        }
        let sro = s.ro as usize;
        let send = sro + s.rs as usize;
        if !(send <= lo || sro >= hi) {
            return Err(bad(format!(
                "strip overlap: kept section {} intersects [{lo:#x},{hi:#x})",
                s.name
            )));
        }
    }
    let gap = hi - lo;
    let mut new = Vec::with_capacity(data.len() - gap);
    new.extend_from_slice(&data[..lo]);
    new.extend_from_slice(&data[hi..]);
    for s in &pe.sections {
        if dead_hdrs.contains(&s.hdr) {
            put_u32(&mut new, s.hdr + 16, 0)?;
            put_u32(&mut new, s.hdr + 20, 0)?;
        } else if s.rs != 0 && s.ro as usize >= hi {
            put_u32(&mut new, s.hdr + 20, s.ro - gap as u32)?;
        }
    }
    *data = new;
    u32::try_from(gap).map_err(|_| bad("stripped run overflows"))
}

/// Clean a raw dump on disk and verify it, writing the output only if every gate passes.
/// `packed_ref`, when given, is the packed original for the strong `.text`-identity proof;
/// without it the input dump is the reference (which proves only that clean preserved code).
pub fn clean_to_path(
    raw_path: &Path,
    out: &Path,
    opts: &CleanOptions,
    packed_ref: Option<&Path>,
    on: &mut dyn FnMut(Progress),
) -> io::Result<UnpackReport> {
    let raw = std::fs::read(raw_path)?;
    on(Progress::Stage(Stage::Clean));
    let cleaned = clean_bytes(&raw, opts)?;

    on(Progress::Stage(Stage::Verify));
    let packed_bytes = match packed_ref {
        Some(p) => Some(std::fs::read(p)?),
        None => None,
    };
    let reference = match &packed_bytes {
        Some(b) => Some((b.as_slice(), "packed original")),
        None => Some((raw.as_slice(), "input dump")),
    };
    let report = verify_bytes(&cleaned.data, reference)?;

    let output = if report.gates_pass {
        std::fs::write(out, &cleaned.data)?;
        Some(out.display().to_string())
    } else {
        None
    };
    on(Progress::Stage(Stage::Done));
    Ok(UnpackReport {
        input: raw_path.display().to_string(),
        output,
        dump_path: None,
        gates_pass: report.gates_pass,
        clean: cleaned.summary,
        verify: report,
    })
}

/// Full packed-to-min flow: orchestrate the dump, clean it, verify against the packed
/// original, and write the output only if every gate passes.
pub fn unpack_to_path(
    packed: &Path,
    out: &Path,
    opts: &CleanOptions,
    unlicense: Option<&Path>,
    on: &mut dyn FnMut(Progress),
) -> io::Result<UnpackReport> {
    on(Progress::Stage(Stage::Locate));
    let dump_path = dump::dump(packed, unlicense, on)?;

    on(Progress::Stage(Stage::Clean));
    let raw = std::fs::read(&dump_path)?;
    let cleaned = clean_bytes(&raw, opts)?;

    on(Progress::Stage(Stage::Verify));
    let packed_bytes = std::fs::read(packed)?;
    let report = verify_bytes(&cleaned.data, Some((&packed_bytes, "packed original")))?;

    let output = if report.gates_pass {
        std::fs::write(out, &cleaned.data)?;
        Some(out.display().to_string())
    } else {
        None
    };
    on(Progress::Stage(Stage::Done));
    Ok(UnpackReport {
        input: packed.display().to_string(),
        output,
        dump_path: Some(dump_path.display().to_string()),
        gates_pass: report.gates_pass,
        clean: cleaned.summary,
        verify: report,
    })
}

#[cfg(test)]
mod tests;
