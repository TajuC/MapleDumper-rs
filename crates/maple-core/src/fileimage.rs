use crate::memory::{MemorySource, Region, coalesce};
use crate::pattern::Arch;
use std::io;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelocKind {
    HighLow,
    Dir64,
    Unsupported(u8),
}

/// Lets the signature generator query loader-patched bytes without depending on `FileImage`
/// concretely (so it stays testable over `BufferSource`, which has no relocations).
pub trait RelocLookup {
    fn is_relocated(&self, rva: usize) -> bool;
    fn reloc_kind_at(&self, rva: usize) -> Option<RelocKind>;
}

impl RelocLookup for FileImage {
    fn is_relocated(&self, rva: usize) -> bool {
        FileImage::is_relocated(self, rva)
    }
    fn reloc_kind_at(&self, rva: usize) -> Option<RelocKind> {
        FileImage::reloc_kind_at(self, rva)
    }
}

#[derive(Debug, Clone)]
pub struct PackReport {
    pub likely_packed: bool,
    pub reasons: Vec<String>,
    pub max_code_entropy: f64,
}

struct Section {
    name: [u8; 8],
    rva: u32,
    mapped_size: u32,
    raw_ptr: u32,
    raw_size: u32,
    executable: bool,
    writable: bool,
}

struct Reloc {
    rva: usize,
    kind: RelocKind,
}

pub struct FileImage {
    data: Vec<u8>,
    image_base: usize,
    size_of_image: usize,
    arch: Arch,
    sections: Vec<Section>,
    headers_raw_len: usize,
    relocs: Vec<Reloc>,
    import: Option<(u32, u32)>, // import directory (rva, size), if present
}

const PACKER_NAMES: &[&str] = &[
    "UPX0", "UPX1", "UPX2", ".aspack", ".adata", ".vmp0", ".vmp1", ".themida", ".enigma1",
    ".enigma2", ".nsp0", "FSG!", ".petite", ".MPRESS1", ".MPRESS2", ".y0da",
];

fn rd_u16(d: &[u8], o: usize) -> Option<u16> {
    d.get(o..o + 2)
        .map(|b| u16::from_le_bytes(b.try_into().unwrap()))
}
fn rd_u32(d: &[u8], o: usize) -> Option<u32> {
    d.get(o..o + 4)
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
}
fn rd_u64(d: &[u8], o: usize) -> Option<u64> {
    d.get(o..o + 8)
        .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
}

fn section_name(name: &[u8; 8]) -> &str {
    let end = name.iter().position(|&b| b == 0).unwrap_or(8);
    std::str::from_utf8(&name[..end]).unwrap_or("")
}

fn entropy_is_packing_signal(entropy: f64, section_len: usize, corroborated: bool) -> bool {
    entropy > 7.2 && (section_len >= 0x4000 || corroborated)
}

fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let len = bytes.len() as f64;
    let mut h = 0.0;
    for &c in &counts {
        if c == 0 {
            continue;
        }
        let p = c as f64 / len;
        h -= p * p.log2();
    }
    h
}

impl FileImage {
    pub fn open(path: &Path) -> io::Result<Self> {
        Self::parse(std::fs::read(path)?)
    }

    fn parse(data: Vec<u8>) -> io::Result<Self> {
        let bad = |m: &str| io::Error::new(io::ErrorKind::InvalidData, m.to_string());
        if data.len() < 0x40 || &data[0..2] != b"MZ" {
            return Err(bad("not a PE image (missing MZ)"));
        }
        let e_lfanew = rd_u32(&data, 0x3C).ok_or_else(|| bad("truncated DOS header"))? as usize;
        if data.get(e_lfanew..e_lfanew + 4) != Some(b"PE\0\0".as_slice()) {
            return Err(bad("missing PE signature"));
        }
        let coff = e_lfanew + 4;
        let num_sections =
            rd_u16(&data, coff + 2).ok_or_else(|| bad("truncated COFF header"))? as usize;
        let size_opt =
            rd_u16(&data, coff + 16).ok_or_else(|| bad("truncated COFF header"))? as usize;
        let opt = coff + 20;
        let magic = rd_u16(&data, opt).ok_or_else(|| bad("truncated optional header"))?;
        let (arch, image_base) = match magic {
            0x10B => (
                Arch::X86,
                rd_u32(&data, opt + 0x1C).ok_or_else(|| bad("truncated PE32"))? as usize,
            ),
            0x20B => (
                Arch::X64,
                rd_u64(&data, opt + 0x18).ok_or_else(|| bad("truncated PE32+"))? as usize,
            ),
            _ => return Err(bad("unsupported optional header magic")),
        };
        let size_of_image =
            rd_u32(&data, opt + 0x38).ok_or_else(|| bad("truncated optional header"))? as usize;
        let size_of_headers =
            rd_u32(&data, opt + 0x3C).ok_or_else(|| bad("truncated optional header"))? as usize;

        if image_base == 0 || image_base & 0xFFF != 0 {
            return Err(bad("invalid image base"));
        }
        if size_of_image < 0x1000 {
            return Err(bad("invalid SizeOfImage"));
        }

        let sec_table = opt + size_opt;
        let mut sections = Vec::with_capacity(num_sections);
        let mut prev_rva: Option<usize> = None;
        for i in 0..num_sections {
            let h = sec_table + i * 40;
            if h + 40 > data.len() {
                return Err(bad("truncated section table"));
            }
            let mut name = [0u8; 8];
            name.copy_from_slice(&data[h..h + 8]);
            let vsize = rd_u32(&data, h + 8).unwrap();
            let rva = rd_u32(&data, h + 0x0C).unwrap();
            let raw_size = rd_u32(&data, h + 0x10).unwrap();
            let raw_ptr = rd_u32(&data, h + 0x14).unwrap();
            let chars = rd_u32(&data, h + 0x24).unwrap();
            if rva as usize >= size_of_image {
                return Err(bad("section VA past image"));
            }
            if prev_rva.is_some_and(|p| rva as usize <= p) {
                return Err(bad("sections not ascending"));
            }
            prev_rva = Some(rva as usize);
            sections.push(Section {
                name,
                rva,
                mapped_size: if vsize == 0 { raw_size } else { vsize },
                raw_ptr,
                raw_size,
                executable: chars & 0x2000_0000 != 0,
                writable: chars & 0x8000_0000 != 0,
            });
        }

        // import directory = data directory entry #1, only if NumberOfRvaAndSizes says it exists
        let num_dirs = rd_u32(&data, opt + if magic == 0x10B { 0x5C } else { 0x6C }).unwrap_or(0);
        let dir_base = opt + if magic == 0x10B { 0x60 } else { 0x70 };
        let imp_rva = rd_u32(&data, dir_base + 8).unwrap_or(0);
        let imp_size = rd_u32(&data, dir_base + 12).unwrap_or(0);
        let import =
            (num_dirs >= 2 && imp_rva != 0 && imp_size != 0).then_some((imp_rva, imp_size));

        let headers_raw_len = size_of_headers.min(data.len());
        let mut image = Self {
            data,
            image_base,
            size_of_image,
            arch,
            sections,
            headers_raw_len,
            relocs: Vec::new(),
            import,
        };
        image.relocs = image.parse_relocs(opt, magic);
        Ok(image)
    }

    /// Import directory as an absolute VA range `[start, end)`, if the image has one.
    #[must_use]
    pub fn import_range(&self) -> Option<(usize, usize)> {
        self.import.map(|(rva, size)| {
            (
                self.image_base + rva as usize,
                self.image_base + (rva + size) as usize,
            )
        })
    }

    fn rva_to_file(&self, rva: usize) -> Option<usize> {
        for s in &self.sections {
            let s_rva = s.rva as usize;
            if rva >= s_rva && rva < s_rva + s.raw_size as usize {
                return Some(s.raw_ptr as usize + (rva - s_rva));
            }
        }
        None
    }

    fn parse_relocs(&self, opt: usize, magic: u16) -> Vec<Reloc> {
        // base-relocation table = data directory #5; only present if NumberOfRvaAndSizes > 5
        let num_dirs =
            rd_u32(&self.data, opt + if magic == 0x10B { 0x5C } else { 0x6C }).unwrap_or(0);
        if num_dirs < 6 {
            return Vec::new();
        }
        let dir_base = opt + if magic == 0x10B { 0x60 } else { 0x70 };
        let entry = dir_base + 5 * 8;
        let dir_rva = rd_u32(&self.data, entry).unwrap_or(0) as usize;
        let dir_size = rd_u32(&self.data, entry + 4).unwrap_or(0) as usize;
        if dir_rva == 0 || dir_size == 0 {
            return Vec::new();
        }
        let Some(start) = self.rva_to_file(dir_rva) else {
            return Vec::new();
        };
        let end = (start + dir_size).min(self.data.len());
        let mut out = Vec::new();
        let mut off = start;
        while off + 8 <= end {
            let page = rd_u32(&self.data, off).unwrap() as usize;
            let block_size = rd_u32(&self.data, off + 4).unwrap() as usize;
            if block_size < 8 {
                break;
            }
            let block_end = (off + block_size).min(end);
            let mut e = off + 8;
            while e + 2 <= block_end {
                let raw = rd_u16(&self.data, e).unwrap();
                let offset = (raw & 0xFFF) as usize;
                let kind = match raw >> 12 {
                    0 => {
                        e += 2;
                        continue;
                    }
                    3 => RelocKind::HighLow,
                    10 => RelocKind::Dir64,
                    other => RelocKind::Unsupported(other as u8),
                };
                out.push(Reloc {
                    rva: page + offset,
                    kind,
                });
                e += 2;
            }
            off += block_size;
        }
        out.sort_by_key(|r| r.rva);
        out
    }

    #[must_use]
    pub fn base(&self) -> usize {
        self.image_base
    }
    #[must_use]
    pub fn size(&self) -> usize {
        self.size_of_image
    }
    #[must_use]
    pub fn arch(&self) -> Arch {
        self.arch
    }

    #[must_use]
    pub fn regions(&self) -> Vec<Region> {
        coalesce(
            self.sections
                .iter()
                .map(|s| Region {
                    base: self.image_base + s.rva as usize,
                    size: s.mapped_size as usize,
                })
                .collect(),
        )
    }

    #[must_use]
    pub fn code_regions(&self) -> Vec<Region> {
        coalesce(
            self.sections
                .iter()
                .filter(|s| s.executable)
                .map(|s| Region {
                    base: self.image_base + s.rva as usize,
                    size: s.mapped_size as usize,
                })
                .collect(),
        )
    }

    #[must_use]
    pub fn code_hash(&self) -> u64 {
        crate::stamp::BuildStamp::capture(self, self.image_base, &self.code_regions()).hash
    }

    #[must_use]
    pub fn reloc_kind_at(&self, rva: usize) -> Option<RelocKind> {
        let idx = self.relocs.partition_point(|r| r.rva <= rva);
        if idx == 0 {
            return None;
        }
        let r = &self.relocs[idx - 1];
        let width = match r.kind {
            RelocKind::HighLow | RelocKind::Unsupported(_) => 4,
            RelocKind::Dir64 => 8,
        };
        (rva < r.rva + width).then_some(r.kind)
    }

    #[must_use]
    pub fn is_relocated(&self, rva: usize) -> bool {
        self.reloc_kind_at(rva).is_some()
    }

    #[must_use]
    pub fn pack_report(&self) -> PackReport {
        let mut reasons = Vec::new();
        let mut entropy_hits: Vec<(String, f64, usize)> = Vec::new();
        let mut max_entropy = 0.0f64;
        for s in &self.sections {
            let name = section_name(&s.name);
            if PACKER_NAMES.iter().any(|p| name.eq_ignore_ascii_case(p)) {
                reasons.push(format!("packer section name {name}"));
            }
            if !s.executable {
                continue;
            }
            if s.writable {
                reasons.push(format!("executable+writable section {name}"));
            }
            let start = s.raw_ptr as usize;
            let len = (s.raw_size as usize).min(self.data.len().saturating_sub(start));
            if len == 0 {
                continue;
            }
            let entropy = shannon_entropy(&self.data[start..start + len]);
            max_entropy = max_entropy.max(entropy);
            if entropy > 7.2 {
                entropy_hits.push((name.to_string(), entropy, len));
            }
        }
        // High entropy alone over-reports: a few hundred bytes of dense code can exceed the cutoff
        // and wrongly cap a signature at grade D. Count it only for a sizeable section, or when a
        // packer name or executable+writable section already corroborates packing.
        let corroborated = !reasons.is_empty();
        for (name, entropy, len) in entropy_hits {
            if entropy_is_packing_signal(entropy, len, corroborated) {
                reasons.push(format!("high entropy {entropy:.2} in {name}"));
            }
        }
        PackReport {
            likely_packed: !reasons.is_empty(),
            reasons,
            max_code_entropy: max_entropy,
        }
    }

    fn segment_at(&self, rva: usize) -> (usize, usize, usize) {
        let first = self.sections.first().map(|s| s.rva as usize);
        if first.is_none_or(|fs| rva < fs) {
            let seg_end = first.unwrap_or(self.size_of_image);
            let cap = self.headers_raw_len.min(self.data.len());
            let backed = if rva < cap {
                (cap - rva).min(seg_end - rva)
            } else {
                0
            };
            return (seg_end, rva, backed);
        }
        for s in &self.sections {
            let s_rva = s.rva as usize;
            if rva < s_rva {
                return (s_rva, 0, 0);
            }
            let s_end = s_rva + s.mapped_size as usize;
            if rva < s_end {
                let raw_end = s_rva + (s.raw_size as usize).min(s.mapped_size as usize);
                let file_off = s.raw_ptr as usize + (rva - s_rva);
                let backed = if rva < raw_end {
                    (raw_end - rva).min(self.data.len().saturating_sub(file_off))
                } else {
                    0
                };
                return (s_end, file_off, backed);
            }
        }
        (self.size_of_image, 0, 0)
    }
}

impl MemorySource for FileImage {
    fn read_into(&self, address: usize, buf: &mut [u8]) -> io::Result<usize> {
        if address < self.image_base {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        let start = address - self.image_base;
        let mut filled = 0;
        while filled < buf.len() {
            let rva = start + filled;
            if rva >= self.size_of_image {
                break;
            }
            let (seg_end, file_off, backed_len) = self.segment_at(rva);
            let run = (seg_end - rva).min(buf.len() - filled);
            if run == 0 {
                break;
            }
            let backed = backed_len.min(run);
            if backed > 0 {
                buf[filled..filled + backed]
                    .copy_from_slice(&self.data[file_off..file_off + backed]);
            }
            for b in &mut buf[filled + backed..filled + run] {
                *b = 0;
            }
            filled += run;
        }
        Ok(filled)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // Minimal but valid PE: DOS + PE sig + optional header + one .text section, code at file 0x400.
    fn build_pe(pe32: bool, reloc_block: Option<(u32, &[u16])>) -> Vec<u8> {
        let mut d = vec![0u8; 0x600];
        d[0..2].copy_from_slice(b"MZ");
        let e = 0x40usize;
        d[0x3C..0x40].copy_from_slice(&(e as u32).to_le_bytes());
        d[e..e + 4].copy_from_slice(b"PE\0\0");
        let coff = e + 4;
        d[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes()); // NumberOfSections
        let size_opt: u16 = if pe32 { 0xE0 } else { 0xF0 };
        d[coff + 16..coff + 18].copy_from_slice(&size_opt.to_le_bytes());
        let opt = coff + 20;
        let magic: u16 = if pe32 { 0x10B } else { 0x20B };
        d[opt..opt + 2].copy_from_slice(&magic.to_le_bytes());
        if pe32 {
            d[opt + 0x1C..opt + 0x20].copy_from_slice(&0x0040_0000u32.to_le_bytes());
        } else {
            d[opt + 0x18..opt + 0x20].copy_from_slice(&0x1_4000_0000u64.to_le_bytes());
        }
        d[opt + 0x38..opt + 0x3C].copy_from_slice(&0x4000u32.to_le_bytes()); // SizeOfImage
        d[opt + 0x3C..opt + 0x40].copy_from_slice(&0x400u32.to_le_bytes()); // SizeOfHeaders
        let nrvas = opt + if pe32 { 0x5C } else { 0x6C };
        d[nrvas..nrvas + 4].copy_from_slice(&16u32.to_le_bytes()); // NumberOfRvaAndSizes
        let dir_base = opt + if pe32 { 0x60 } else { 0x70 };

        let sec = opt + size_opt as usize;
        d[sec..sec + 5].copy_from_slice(b".text");
        d[sec + 8..sec + 12].copy_from_slice(&0x20u32.to_le_bytes()); // VirtualSize
        d[sec + 0x0C..sec + 0x10].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualAddress
        d[sec + 0x10..sec + 0x14].copy_from_slice(&0x10u32.to_le_bytes()); // SizeOfRawData
        d[sec + 0x14..sec + 0x18].copy_from_slice(&0x400u32.to_le_bytes()); // PointerToRawData
        d[sec + 0x24..sec + 0x28].copy_from_slice(&0x6000_0020u32.to_le_bytes()); // CODE|EXEC|READ

        // known code bytes at file 0x400 (rva 0x1000)
        for i in 0..0x10u8 {
            d[0x400 + i as usize] = 0xA0 + i;
        }

        if let Some((page, entries)) = reloc_block {
            // put a .reloc-style block at rva 0x2000 / file 0x420
            let rva = 0x2000u32;
            let file = 0x420usize;
            let block_size = 8 + entries.len() * 2;
            d[file..file + 4].copy_from_slice(&page.to_le_bytes());
            d[file + 4..file + 8].copy_from_slice(&(block_size as u32).to_le_bytes());
            for (i, &en) in entries.iter().enumerate() {
                d[file + 8 + i * 2..file + 10 + i * 2].copy_from_slice(&en.to_le_bytes());
            }
            d[dir_base + 5 * 8..dir_base + 5 * 8 + 4].copy_from_slice(&rva.to_le_bytes());
            d[dir_base + 5 * 8 + 4..dir_base + 5 * 8 + 8]
                .copy_from_slice(&(block_size as u32).to_le_bytes());
            // add a second section mapping rva 0x2000 so rva_to_file can resolve the reloc dir
            d[coff + 2..coff + 4].copy_from_slice(&2u16.to_le_bytes());
            let sec2 = sec + 40;
            d[sec2..sec2 + 6].copy_from_slice(b".reloc");
            d[sec2 + 8..sec2 + 12].copy_from_slice(&0x100u32.to_le_bytes());
            d[sec2 + 0x0C..sec2 + 0x10].copy_from_slice(&0x2000u32.to_le_bytes());
            d[sec2 + 0x10..sec2 + 0x14].copy_from_slice(&0x100u32.to_le_bytes());
            d[sec2 + 0x14..sec2 + 0x18].copy_from_slice(&0x420u32.to_le_bytes());
            d[sec2 + 0x24..sec2 + 0x28].copy_from_slice(&0x4200_0040u32.to_le_bytes()); // INITIALIZED|READ
        }
        d
    }

    #[test]
    fn parses_pe32plus_and_pe32() {
        let img = FileImage::parse(build_pe(false, None)).unwrap();
        assert_eq!(img.base(), 0x1_4000_0000);
        assert_eq!(img.size(), 0x4000);
        assert_eq!(img.arch(), Arch::X64);

        let img32 = FileImage::parse(build_pe(true, None)).unwrap();
        assert_eq!(img32.base(), 0x0040_0000);
        assert_eq!(img32.arch(), Arch::X86);
    }

    #[test]
    fn rejects_malformed() {
        assert!(FileImage::parse(vec![0u8; 0x80]).is_err()); // no MZ
        let mut bad_magic = build_pe(false, None);
        let opt = 0x40 + 4 + 20;
        bad_magic[opt] = 0x07; // 0x107 ROM
        bad_magic[opt + 1] = 0x01;
        assert!(FileImage::parse(bad_magic).is_err());
        let mut bad_base = build_pe(false, None);
        bad_base[opt + 0x18..opt + 0x20].copy_from_slice(&0u64.to_le_bytes());
        assert!(FileImage::parse(bad_base).is_err()); // zero image base
    }

    #[test]
    fn code_regions_at_virtual_addresses() {
        let img = FileImage::parse(build_pe(false, None)).unwrap();
        assert_eq!(
            img.code_regions(),
            vec![Region {
                base: 0x1_4000_1000,
                size: 0x20
            }]
        );
    }

    #[test]
    fn read_into_section_bytes_and_bss_tail() {
        let img = FileImage::parse(build_pe(false, None)).unwrap();
        let mut buf = [0u8; 0x20];
        let n = img.read_into(0x1_4000_1000, &mut buf).unwrap();
        assert_eq!(n, 0x20);
        let expected: Vec<u8> = (0..0x10u8).map(|i| 0xA0 + i).collect();
        assert_eq!(&buf[..0x10], expected.as_slice()); // raw-backed
        assert!(buf[0x10..].iter().all(|&b| b == 0)); // BSS tail (VirtualSize 0x20 > RawSize 0x10)
    }

    #[test]
    fn read_into_header_and_bounds() {
        let img = FileImage::parse(build_pe(false, None)).unwrap();
        let mut mz = [0u8; 2];
        img.read_into(0x1_4000_0000, &mut mz).unwrap();
        assert_eq!(&mz, b"MZ");
        let mut pe = [0u8; 4];
        img.read_into(0x1_4000_0040, &mut pe).unwrap();
        assert_eq!(&pe, b"PE\0\0");
        assert!(img.read_into(0x1_3FFF_FFFF, &mut [0u8; 4]).is_err()); // before base
        assert_eq!(
            img.read_into(0x1_4000_0000 + 0x4000, &mut [0u8; 4])
                .unwrap(),
            0
        ); // past image
    }

    #[test]
    fn build_stamp_and_code_hash_work_on_fileimage() {
        let img = FileImage::parse(build_pe(false, None)).unwrap();
        let stamp = crate::stamp::BuildStamp::capture(&img, img.base(), &img.regions());
        assert_ne!(stamp.hash, 0);
        let a = FileImage::parse(build_pe(false, None)).unwrap();
        let b = FileImage::parse(build_pe(false, None)).unwrap();
        assert_eq!(a.code_hash(), b.code_hash());
    }

    #[test]
    fn pack_report_flags_packer_name_and_clears_normal() {
        let img = FileImage::parse(build_pe(false, None)).unwrap();
        assert!(!img.pack_report().likely_packed);

        let mut packed = build_pe(false, None);
        let sec = (0x40 + 4 + 20) + 0xF0;
        packed[sec..sec + 8].copy_from_slice(b"UPX0\0\0\0\0");
        let report = FileImage::parse(packed).unwrap().pack_report();
        assert!(report.likely_packed);
        assert!(report.reasons.iter().any(|r| r.contains("UPX0")));
    }

    #[test]
    fn entropy_alone_needs_a_sizeable_section() {
        // a few hundred high-entropy bytes are not enough on their own
        assert!(!entropy_is_packing_signal(7.5, 300, false));
        // a sizeable high-entropy section is a signal
        assert!(entropy_is_packing_signal(7.5, 0x8000, false));
        // a small high-entropy section counts when another signal already fired
        assert!(entropy_is_packing_signal(7.5, 300, true));
        // below the cutoff is never a signal
        assert!(!entropy_is_packing_signal(7.0, 0x8000, false));
    }

    #[test]
    fn opens_synthetic_pe_from_disk() {
        let bytes = build_pe(false, None);
        let mut path = std::env::temp_dir();
        path.push(format!("maple_fixture_{}.bin", std::process::id()));
        std::fs::write(&path, &bytes).unwrap();
        let opened = FileImage::open(&path);
        let _ = std::fs::remove_file(&path);
        let img = opened.unwrap();
        assert_eq!(img.base(), 0x1_4000_0000);
        assert_eq!(img.arch(), Arch::X64);
        assert_eq!(
            img.code_regions(),
            vec![Region {
                base: 0x1_4000_1000,
                size: 0x20
            }]
        );
        let mut mz = [0u8; 2];
        img.read_into(img.base(), &mut mz).unwrap();
        assert_eq!(&mz, b"MZ");
    }

    #[test]
    #[ignore = "needs a real on-disk exe; run with --ignored"]
    fn opens_real_exe() {
        let path = Path::new(r"C:\Windows\System32\notepad.exe");
        if !path.exists() {
            return;
        }
        let img = FileImage::open(path).unwrap();
        assert_ne!(img.base(), 0);
        assert!(img.size() > 0);
        assert!(!img.code_regions().is_empty());
        assert_eq!(img.arch(), Arch::X64);
        let mut mz = [0u8; 2];
        img.read_into(img.base(), &mut mz).unwrap();
        assert_eq!(&mz, b"MZ");
        let stamp = crate::stamp::BuildStamp::capture(&img, img.base(), &img.code_regions());
        assert_ne!(stamp.hash, 0);
    }

    #[test]
    fn parses_and_queries_relocations() {
        // two HIGHLOW entries on page 0x1000 at offsets 4 and 8
        let img = FileImage::parse(build_pe(
            false,
            Some((0x1000, &[(3 << 12) | 4, (3 << 12) | 8])),
        ))
        .unwrap();
        assert!(img.is_relocated(0x1004));
        assert!(img.is_relocated(0x1007)); // within the 4-byte HIGHLOW at 0x1004
        assert!(!img.is_relocated(0x1000));
        assert!(img.is_relocated(0x1008));
        assert!(!img.is_relocated(0x100C));
        assert_eq!(img.reloc_kind_at(0x1004), Some(RelocKind::HighLow));
    }

    #[test]
    fn import_range_respects_num_rva_and_sizes() {
        let opt = 0x40 + 4 + 20;
        let dir1 = opt + 0x70 + 8; // PE32+ data directory entry #1 (import)
        let mut d = build_pe(false, None);
        d[dir1..dir1 + 4].copy_from_slice(&0x1000u32.to_le_bytes());
        d[dir1 + 4..dir1 + 8].copy_from_slice(&0x40u32.to_le_bytes());

        // NumberOfRvaAndSizes = 1: directory #1 does not exist, so the entry must be ignored.
        d[opt + 0x6C..opt + 0x70].copy_from_slice(&1u32.to_le_bytes());
        assert!(
            FileImage::parse(d.clone())
                .unwrap()
                .import_range()
                .is_none()
        );

        // NumberOfRvaAndSizes = 16: the import directory is honoured.
        d[opt + 0x6C..opt + 0x70].copy_from_slice(&16u32.to_le_bytes());
        assert_eq!(
            FileImage::parse(d).unwrap().import_range(),
            Some((0x1_4000_1000, 0x1_4000_1040))
        );
    }

    #[test]
    fn opens_synthetic_pe32_from_disk() {
        let bytes = build_pe(true, None);
        let mut path = std::env::temp_dir();
        path.push(format!("maple_fixture_pe32_{}.bin", std::process::id()));
        std::fs::write(&path, &bytes).unwrap();
        let opened = FileImage::open(&path);
        let _ = std::fs::remove_file(&path);
        let img = opened.unwrap();
        assert_eq!(img.base(), 0x0040_0000);
        assert_eq!(img.arch(), Arch::X86);
        assert_eq!(
            img.code_regions(),
            vec![Region {
                base: 0x0040_1000,
                size: 0x20
            }]
        );
    }

    #[test]
    fn read_into_clamps_when_raw_size_lies_past_eof() {
        // A hostile image can claim a SizeOfRawData far larger than the file. The reader must
        // back what the file actually holds and zero-fill the rest, never indexing past the buffer.
        let mut d = build_pe(false, None);
        let sec = (0x40 + 4 + 20) + 0xF0;
        d[sec + 8..sec + 12].copy_from_slice(&0x4000u32.to_le_bytes()); // VirtualSize
        d[sec + 0x10..sec + 0x14].copy_from_slice(&0x4000u32.to_le_bytes()); // SizeOfRawData past EOF
        let img = FileImage::parse(d).unwrap();
        let mut buf = [0xFFu8; 0x300];
        let n = img.read_into(0x1_4000_1000, &mut buf).unwrap();
        assert_eq!(n, 0x300);
        let expected: Vec<u8> = (0..0x10u8).map(|i| 0xA0 + i).collect();
        assert_eq!(&buf[..0x10], expected.as_slice());
        assert!(buf[0x10..].iter().all(|&b| b == 0));
    }

    #[test]
    fn rejects_section_table_past_eof() {
        let mut d = build_pe(false, None);
        let coff = 0x40 + 4;
        d[coff + 2..coff + 4].copy_from_slice(&64u16.to_le_bytes()); // 64 sections, table runs off EOF
        assert!(FileImage::parse(d).is_err());
    }

    proptest! {
        #[test]
        fn parse_never_panics_on_arbitrary_bytes(
            bytes in proptest::collection::vec(any::<u8>(), 0..1500),
        ) {
            let _ = FileImage::parse(bytes);
        }

        #[test]
        fn parse_never_panics_on_corrupted_pe(
            muts in proptest::collection::vec((0usize..0x600, any::<u8>()), 0..40),
            pe32 in any::<bool>(),
        ) {
            let mut d = build_pe(pe32, None);
            for (i, v) in muts {
                d[i] = v;
            }
            if let Ok(img) = FileImage::parse(d) {
                let mut buf = [0u8; 0x80];
                let _ = img.read_into(img.base(), &mut buf);
                let _ = img.read_into(img.base() + img.size().saturating_sub(0x10), &mut buf);
                let _ = img.regions();
                let _ = img.pack_report();
            }
        }
    }
}
