use crate::memory::{MemorySource, Region};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildStamp {
    pub hash: u64,
    pub bytes: u64,
    pub timestamp: u32,
    pub version: Option<String>,
}

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

fn fingerprint<S: MemorySource>(source: &S, regions: &[Region]) -> (u64, u64) {
    let mut sorted = regions.to_vec();
    sorted.sort_by_key(|r| r.base);

    let mut hash = FNV_OFFSET;
    let mut total = 0u64;
    let mut buf = vec![0u8; 1 << 20];
    for region in &sorted {
        let mut off = 0;
        while off < region.size {
            let want = buf.len().min(region.size - off);
            let read = source
                .read_into(region.base + off, &mut buf[..want])
                .unwrap_or(0);
            if read == 0 {
                break;
            }
            for &byte in &buf[..read] {
                hash ^= u64::from(byte);
                hash = hash.wrapping_mul(FNV_PRIME);
            }
            total += read as u64;
            off += read;
        }
    }
    (hash, total)
}

/// Read the COFF `Machine` field of the module mapped at `module_base`, for architecture checks.
/// Returns the raw machine value (e.g. `0x8664` amd64, `0x014C` i386); `None` if the header cannot
/// be read or is not a PE.
#[must_use]
pub fn pe_machine<S: MemorySource>(source: &S, module_base: usize) -> Option<u16> {
    let mut dos = [0u8; 0x40];
    if source.read_into(module_base, &mut dos).ok()? < 0x40 || &dos[0..2] != b"MZ" {
        return None;
    }
    let e_lfanew = u32::from_le_bytes(dos[0x3C..0x40].try_into().ok()?) as usize;
    let mut pe = [0u8; 0x18];
    if source.read_into(module_base + e_lfanew, &mut pe).ok()? < 0x18 || &pe[0..4] != b"PE\0\0" {
        return None;
    }
    Some(u16::from_le_bytes(pe[4..6].try_into().ok()?))
}

fn pe_timestamp<S: MemorySource>(source: &S, module_base: usize) -> Option<u32> {
    let mut dos = [0u8; 0x40];
    if source.read_into(module_base, &mut dos).ok()? < 0x40 || &dos[0..2] != b"MZ" {
        return None;
    }
    let e_lfanew = u32::from_le_bytes(dos[0x3C..0x40].try_into().ok()?) as usize;
    let mut pe = [0u8; 0x18];
    if source.read_into(module_base + e_lfanew, &mut pe).ok()? < 0x18 || &pe[0..4] != b"PE\0\0" {
        return None;
    }
    Some(u32::from_le_bytes(pe[8..12].try_into().ok()?))
}

impl BuildStamp {
    #[must_use]
    pub fn capture<S: MemorySource>(source: &S, module_base: usize, regions: &[Region]) -> Self {
        let (hash, bytes) = fingerprint(source, regions);
        Self {
            hash,
            bytes,
            timestamp: pe_timestamp(source, module_base).unwrap_or(0),
            version: None,
        }
    }

    #[must_use]
    pub fn short(&self) -> String {
        format!("{:016X}", self.hash)
    }

    #[must_use]
    pub fn header_line(&self) -> String {
        let mut line = format!(
            "# build: hash={:016X} bytes={} timestamp={:08X}",
            self.hash, self.bytes, self.timestamp
        );
        if let Some(version) = &self.version {
            line.push_str(" version=");
            line.push_str(version);
        }
        line
    }
}

#[must_use]
pub fn parse_stamp(text: &str) -> Option<BuildStamp> {
    let line = text
        .lines()
        .find(|l| l.trim_start().starts_with("# build:"))?;
    let mut stamp = BuildStamp {
        hash: 0,
        bytes: 0,
        timestamp: 0,
        version: None,
    };
    for token in line.split_whitespace() {
        if let Some(v) = token.strip_prefix("hash=") {
            stamp.hash = u64::from_str_radix(v, 16).unwrap_or(0);
        } else if let Some(v) = token.strip_prefix("bytes=") {
            stamp.bytes = v.parse().unwrap_or(0);
        } else if let Some(v) = token.strip_prefix("timestamp=") {
            stamp.timestamp = u32::from_str_radix(v, 16).unwrap_or(0);
        } else if let Some(v) = token.strip_prefix("version=") {
            stamp.version = Some(v.to_string());
        }
    }
    Some(stamp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::BufferSource;

    #[test]
    fn fingerprint_is_stable_and_byte_sensitive() {
        let regions = [Region {
            base: 0x1000,
            size: 8,
        }];
        let a = BufferSource::new(0x1000, vec![1, 2, 3, 4, 5, 6, 7, 8]);
        let (ha, n) = fingerprint(&a, &regions);
        assert_eq!(n, 8);
        assert_eq!(fingerprint(&a, &regions), (ha, n));

        let b = BufferSource::new(0x1000, vec![1, 2, 3, 4, 5, 6, 7, 9]);
        assert_ne!(fingerprint(&b, &regions).0, ha);
    }

    #[test]
    fn reads_pe_timestamp() {
        let mut data = vec![0u8; 0x200];
        data[0..2].copy_from_slice(b"MZ");
        data[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        data[0x80..0x84].copy_from_slice(b"PE\0\0");
        data[0x88..0x8C].copy_from_slice(&0x6655_4433u32.to_le_bytes());
        let source = BufferSource::new(0x1_0000, data);
        assert_eq!(pe_timestamp(&source, 0x1_0000), Some(0x6655_4433));
    }

    #[test]
    fn reads_pe_machine() {
        let mut data = vec![0u8; 0x200];
        data[0..2].copy_from_slice(b"MZ");
        data[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        data[0x80..0x84].copy_from_slice(b"PE\0\0");
        data[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes()); // IMAGE_FILE_MACHINE_AMD64
        let source = BufferSource::new(0x1_0000, data);
        assert_eq!(pe_machine(&source, 0x1_0000), Some(0x8664));
        // a buffer that is not a PE yields nothing rather than a bogus machine value
        let junk = BufferSource::new(0x2_0000, vec![0u8; 0x200]);
        assert_eq!(pe_machine(&junk, 0x2_0000), None);
    }

    #[test]
    fn header_line_round_trips() {
        let stamp = BuildStamp {
            hash: 0xDEAD_BEEF_CAFE_F00D,
            bytes: 12345,
            timestamp: 0x6655_4433,
            version: Some("1.2.3.4".to_string()),
        };
        assert_eq!(parse_stamp(&stamp.header_line()), Some(stamp));
    }

    #[test]
    fn missing_stamp_line_is_none() {
        assert_eq!(parse_stamp("module X base 0x1000\n[g] A = 0x1"), None);
    }
}
