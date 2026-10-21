//! A point-in-time copy of a module mapped in another process. The signature generator re-reads the
//! same code thousands of times, so it runs against this local copy instead of paying a
//! cross-process read per access, and the image cannot shift under it mid-analysis.

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::memory::{BufferSource, MemorySource, Region};
use crate::pattern::Arch;
use crate::sigmaker::ImageInput;
use crate::stamp::{BuildStamp, arch_from_machine, pe_machine};

/// Larger than any real game module, and a guard against a corrupt module size turning into a
/// multi-gigabyte allocation.
pub const SNAPSHOT_MAX_BYTES: usize = 1 << 30;

const READ_CHUNK: usize = 1 << 20;

pub struct ModuleSnapshot {
    bytes: BufferSource,
    base: usize,
    size: usize,
    regions: Vec<Region>,
    code_regions: Vec<Region>,
    import: Option<(usize, usize)>,
    arch: Arch,
    code_hash: u64,
    unread: usize,
}

fn clip(regions: &[Region], base: usize, end: usize) -> Vec<Region> {
    regions
        .iter()
        .filter_map(|r| {
            let lo = r.base.max(base);
            let hi = r.end().min(end);
            (lo < hi).then(|| Region {
                base: lo,
                size: hi - lo,
            })
        })
        .collect()
}

fn rd_u16(d: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        d.get(o..o.checked_add(2)?)?.try_into().ok()?,
    ))
}

fn rd_u32(d: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        d.get(o..o.checked_add(4)?)?.try_into().ok()?,
    ))
}

/// The import directory as an absolute `[start, end)` range, read from the mapped headers.
fn import_range(data: &[u8], base: usize) -> Option<(usize, usize)> {
    let opt = (rd_u32(data, 0x3C)? as usize).checked_add(0x18)?;
    let (count_at, dirs_at) = match rd_u16(data, opt)? {
        0x10B => (opt + 0x5C, opt + 0x60),
        0x20B => (opt + 0x6C, opt + 0x70),
        _ => return None,
    };
    if rd_u32(data, count_at)? < 2 {
        return None;
    }
    let rva = rd_u32(data, dirs_at + 8)? as usize;
    let size = rd_u32(data, dirs_at + 12)? as usize;
    if rva == 0 || size == 0 || rva.checked_add(size)? > data.len() {
        return None;
    }
    Some((base + rva, base + rva + size))
}

impl ModuleSnapshot {
    /// Copy the module `[base, base + size)` out of `src`. Only `regions` are read (bytes outside
    /// them stay zero and are never analyzed); `code_regions` mark where code signatures may live.
    /// Pages that refuse a read are zero-filled and counted in [`ModuleSnapshot::unread_bytes`].
    pub fn capture<S: MemorySource + ?Sized>(
        src: &S,
        base: usize,
        size: usize,
        regions: &[Region],
        code_regions: &[Region],
        cancel: Option<&AtomicBool>,
    ) -> io::Result<Self> {
        if size == 0 || size > SNAPSHOT_MAX_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("module size 0x{size:X} is not a plausible image size"),
            ));
        }
        let end = base
            .checked_add(size)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "module range overflows"))?;
        let regions = clip(regions, base, end);
        let code_regions = clip(code_regions, base, end);
        let mut data = vec![0u8; size];
        let mut unread = 0;
        for r in &regions {
            let mut at = r.base;
            while at < r.end() {
                if cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
                    return Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "snapshot cancelled",
                    ));
                }
                let n = READ_CHUNK.min(r.end() - at);
                let off = at - base;
                let got = src.read_into(at, &mut data[off..off + n]).unwrap_or(0);
                unread += n - got.min(n);
                at += n;
            }
        }
        let bytes = BufferSource::new(base, data);
        let arch = pe_machine(&bytes, base)
            .and_then(arch_from_machine)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "the module has no readable PE header for a supported architecture",
                )
            })?;
        let import = import_range(bytes.data(), base);
        let code_hash = BuildStamp::capture(&bytes, base, &code_regions).hash;
        Ok(Self {
            bytes,
            base,
            size,
            regions,
            code_regions,
            import,
            arch,
            code_hash,
            unread,
        })
    }

    #[must_use]
    pub fn base(&self) -> usize {
        self.base
    }

    #[must_use]
    pub fn size(&self) -> usize {
        self.size
    }

    #[must_use]
    pub fn arch(&self) -> Arch {
        self.arch
    }

    /// Bytes inside the readable regions that the source refused to hand over.
    #[must_use]
    pub fn unread_bytes(&self) -> usize {
        self.unread
    }

    /// The snapshot as a signature-generator input. A mapped image is already rebased and has no
    /// relocation table to consult; operand bytes are wildcarded by decoding either way.
    #[must_use]
    pub fn image_input(&self, label: String) -> ImageInput<'_> {
        ImageInput {
            label,
            source: &self.bytes,
            base: self.base,
            size: self.size,
            code_regions: self.code_regions.clone(),
            regions: self.regions.clone(),
            import: self.import,
            arch: self.arch,
            code_hash: self.code_hash,
            packed: false,
            pack_reasons: Vec::new(),
            reloc: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: usize = 0x0040_0000;

    fn pe32(size: usize) -> Vec<u8> {
        let mut d = vec![0u8; size];
        d[..2].copy_from_slice(b"MZ");
        d[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        d[0x80..0x84].copy_from_slice(b"PE\0\0");
        d[0x84..0x86].copy_from_slice(&0x14Cu16.to_le_bytes());
        let opt = 0x98;
        d[opt..opt + 2].copy_from_slice(&0x10Bu16.to_le_bytes());
        d[opt + 0x5C..opt + 0x60].copy_from_slice(&16u32.to_le_bytes());
        d[opt + 0x68..opt + 0x6C].copy_from_slice(&0x2000u32.to_le_bytes());
        d[opt + 0x6C..opt + 0x70].copy_from_slice(&0x28u32.to_le_bytes());
        d
    }

    struct Holey {
        inner: BufferSource,
        hole: Region,
    }

    impl MemorySource for Holey {
        fn read_into(&self, address: usize, buf: &mut [u8]) -> io::Result<usize> {
            if address < self.hole.end() && address + buf.len() > self.hole.base {
                return Err(io::Error::other("guard page"));
            }
            self.inner.read_into(address, buf)
        }
    }

    #[test]
    fn captures_regions_and_reads_the_mapped_headers() {
        let mut data = pe32(0x4000);
        data[0x1000..0x1004].copy_from_slice(&[0x55, 0x8B, 0xEC, 0xC3]);
        let src = BufferSource::new(BASE, data);
        let all = [Region {
            base: BASE,
            size: 0x4000,
        }];
        let code = [Region {
            base: BASE + 0x1000,
            size: 0x1000,
        }];
        let snap = ModuleSnapshot::capture(&src, BASE, 0x4000, &all, &code, None).unwrap();
        assert_eq!(snap.arch(), Arch::X86);
        assert_eq!(snap.unread_bytes(), 0);
        let input = snap.image_input("live".to_string());
        assert_eq!(input.import, Some((BASE + 0x2000, BASE + 0x2028)));
        let mut buf = [0u8; 4];
        input.source.read_into(BASE + 0x1000, &mut buf).unwrap();
        assert_eq!(buf, [0x55, 0x8B, 0xEC, 0xC3]);
    }

    #[test]
    fn unreadable_pages_are_zeroed_counted_and_clipped_to_the_module() {
        let mut data = pe32(0x4000);
        data[0x3000..0x4000].fill(0xCC);
        let src = Holey {
            inner: BufferSource::new(BASE, data),
            hole: Region {
                base: BASE + 0x3000,
                size: 0x1000,
            },
        };
        let regions = [
            Region {
                base: BASE,
                size: 0x2000,
            },
            Region {
                base: BASE + 0x3000,
                size: 0x8000,
            },
        ];
        let snap = ModuleSnapshot::capture(&src, BASE, 0x4000, &regions, &[], None).unwrap();
        assert_eq!(snap.unread_bytes(), 0x1000);
        let input = snap.image_input("live".to_string());
        assert_eq!(input.regions.last().unwrap().end(), BASE + 0x4000);
        let mut buf = [0xFFu8; 2];
        input.source.read_into(BASE + 0x3000, &mut buf).unwrap();
        assert_eq!(buf, [0, 0]);
    }

    #[cfg(windows)]
    #[inline(never)]
    fn live_probe(x: u64) -> u64 {
        let mut acc = x ^ 0x5EED_CAFE_F00D_BEEF;
        for i in 0..(x % 7 + 3) {
            acc = acc.rotate_left(13).wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ i;
        }
        std::hint::black_box(acc)
    }

    #[cfg(windows)]
    #[test]
    fn a_live_snapshot_of_this_process_signs_one_of_its_functions() {
        use crate::sigmaker::{SigOptions, TargetSpec, generate};

        std::hint::black_box(live_probe(5));
        let exe = std::env::current_exe().unwrap();
        let name = exe.file_name().unwrap().to_string_lossy().into_owned();
        let target = crate::process::Target::attach_pid(std::process::id(), &name).unwrap();
        let snap = ModuleSnapshot::capture(
            &target,
            target.module.base,
            target.module.size,
            &target.regions(),
            &target.code_regions(),
            None,
        )
        .unwrap();
        assert_eq!(snap.unread_bytes(), 0);
        let rva = (live_probe as fn(u64) -> u64 as usize - snap.base()) as u64;
        let inputs = [snap.image_input("self".to_string())];
        let report = generate(
            &inputs,
            &TargetSpec::Ref { image: 0, rva },
            &SigOptions::default(),
        );
        let chosen = report
            .chosen
            .expect("a live function must yield a signature");
        let pv = &chosen.per_version[0];
        assert!(
            pv.match_rva == Some(rva) || pv.resolved_target_rva == Some(rva),
            "signature must land on the probe at 0x{rva:X}: {pv:?}"
        );
    }

    #[test]
    fn refuses_implausible_sizes_missing_headers_and_cancellation() {
        let src = BufferSource::new(BASE, vec![0u8; 0x1000]);
        let all = [Region {
            base: BASE,
            size: 0x1000,
        }];
        assert!(ModuleSnapshot::capture(&src, BASE, 0, &all, &[], None).is_err());
        assert!(
            ModuleSnapshot::capture(&src, BASE, SNAPSHOT_MAX_BYTES + 1, &all, &[], None).is_err()
        );
        assert!(ModuleSnapshot::capture(&src, BASE, 0x1000, &all, &[], None).is_err());
        let ok = BufferSource::new(BASE, pe32(0x1000));
        let stop = AtomicBool::new(true);
        let err = ModuleSnapshot::capture(&ok, BASE, 0x1000, &all, &[], Some(&stop))
            .err()
            .unwrap();
        assert_eq!(err.kind(), io::ErrorKind::Interrupted);
    }
}
