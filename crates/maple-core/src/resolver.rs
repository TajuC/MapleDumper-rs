use crate::memory::MemorySource;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Direct,
    Pointer,
    Call,
    Offset,
}

impl Kind {
    #[must_use]
    pub fn classify(name: &str) -> (Kind, &str) {
        if let Some(base) = name.strip_suffix("_CALL") {
            (Kind::Call, base)
        } else if let Some(base) = name.strip_suffix("_PTR") {
            (Kind::Pointer, base)
        } else if let Some(base) = name.strip_suffix("_OFF") {
            (Kind::Offset, base)
        } else {
            (Kind::Direct, name)
        }
    }
}

fn rel32(bytes: &[u8], at: usize) -> i32 {
    i32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}

#[must_use]
pub fn decode_rel_target(bytes: &[u8], ip: usize) -> Option<usize> {
    if bytes.len() >= 5 && (bytes[0] == 0xE8 || bytes[0] == 0xE9) {
        return Some(
            ip.wrapping_add(5)
                .wrapping_add_signed(rel32(bytes, 1) as isize),
        );
    }
    if bytes.len() >= 2 && bytes[0] == 0xEB {
        return Some(
            ip.wrapping_add(2)
                .wrapping_add_signed(bytes[1] as i8 as isize),
        );
    }
    if bytes.len() >= 6 && bytes[0] == 0x0F && (0x80..=0x8F).contains(&bytes[1]) {
        return Some(
            ip.wrapping_add(6)
                .wrapping_add_signed(rel32(bytes, 2) as isize),
        );
    }
    if bytes.len() >= 2 && (0x70..=0x7F).contains(&bytes[0]) {
        return Some(
            ip.wrapping_add(2)
                .wrapping_add_signed(bytes[1] as i8 as isize),
        );
    }
    None
}

#[must_use]
pub fn extract_pointer(data: &[u8], instr_addr: usize) -> Option<usize> {
    if data.len() < 2 {
        return None;
    }
    for i in 0..data.len() {
        let p = &data[i..];
        let ip = instr_addr.wrapping_add(i);
        if let Some(target) = decode_rel_target(p, ip) {
            return Some(target);
        }
        if p.len() >= 7 && p[0] == 0x48 && p[1] == 0x8B && (p[2] & 0xC7) == 0x05 {
            return Some(ip.wrapping_add(7).wrapping_add_signed(rel32(p, 3) as isize));
        }
        if p.len() >= 7 && p[0] == 0x48 && p[1] == 0x8D && (p[2] & 0xC7) == 0x05 {
            return Some(ip.wrapping_add(7).wrapping_add_signed(rel32(p, 3) as isize));
        }
        if p.len() >= 8 && (p[0] & 0xF8) == 0x40 && p[1] == 0x83 && p[2] == 0x3D {
            return Some(ip.wrapping_add(8).wrapping_add_signed(rel32(p, 3) as isize));
        }
        if p.len() >= 8
            && p[0] == 0xF2
            && p[1] == 0x0F
            && matches!(p[2], 0x10 | 0x58 | 0x59 | 0x5E)
            && p[3] == 0x05
        {
            return Some(ip.wrapping_add(8).wrapping_add_signed(rel32(p, 4) as isize));
        }
    }
    None
}

#[must_use]
pub fn extract_offset(data: &[u8], max_scan: usize) -> Option<u32> {
    for off in 0..=max_scan {
        let Some(p) = data.get(off..) else { break };
        if p.len() < 4 {
            break;
        }
        let rex = p[0];
        if (rex & 0xF0) == 0x40 && (rex & 0x08) != 0 && p[1] == 0x8B {
            match p[2] >> 6 {
                1 => return Some(u32::from(p[3])),
                2 if p.len() >= 7 => return Some(rel32(p, 3) as u32),
                _ => {}
            }
        }
    }
    None
}

pub fn resolve_call<S: MemorySource>(
    source: &S,
    match_addr: usize,
    matched: &[u8],
) -> Option<usize> {
    let rel = if matched.len() >= 5 {
        rel32(matched, 1)
    } else {
        let mut buf = [0u8; 4];
        if source.read_into(match_addr + 1, &mut buf).ok()? < 4 {
            return None;
        }
        i32::from_le_bytes(buf)
    };
    let target = match_addr.wrapping_add(5).wrapping_add_signed(rel as isize);
    let mut buf = [0u8; 0x100];
    let read = source.read_into(target, &mut buf).ok()?;
    let mut i = 0;
    while i + 5 <= read {
        if buf[i] == 0xE8 {
            let nested = rel32(&buf, i + 1);
            return Some(
                target
                    .wrapping_add(i)
                    .wrapping_add(5)
                    .wrapping_add_signed(nested as isize),
            );
        }
        i += 1;
    }
    Some(target)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::BufferSource;

    #[test]
    fn classify_suffixes() {
        assert_eq!(Kind::classify("Foo_PTR"), (Kind::Pointer, "Foo"));
        assert_eq!(Kind::classify("Foo_CALL"), (Kind::Call, "Foo"));
        assert_eq!(Kind::classify("Foo_OFF"), (Kind::Offset, "Foo"));
        assert_eq!(Kind::classify("Foo"), (Kind::Direct, "Foo"));
    }

    #[test]
    fn call_and_jmp_rel32() {
        assert_eq!(
            decode_rel_target(&[0xE8, 0x10, 0, 0, 0], 0x1000),
            Some(0x1015)
        );
        assert_eq!(
            decode_rel_target(&[0xE9, 0x10, 0, 0, 0], 0x1000),
            Some(0x1015)
        );
    }

    #[test]
    fn short_jmp_backwards() {
        assert_eq!(decode_rel_target(&[0xEB, 0xFE], 0x2000), Some(0x2000));
    }

    #[test]
    fn jcc_rel32_and_rel8() {
        assert_eq!(
            decode_rel_target(&[0x0F, 0x84, 0x00, 0x01, 0, 0], 0x1000),
            Some(0x1106)
        );
        assert_eq!(decode_rel_target(&[0x74, 0x05], 0x1000), Some(0x1007));
    }

    #[test]
    fn rip_relative_mov_and_lea() {
        let mov = [0x48, 0x8B, 0x0D, 0x78, 0x56, 0x34, 0x12];
        assert_eq!(
            extract_pointer(&mov, 0x1000),
            Some(0x1000 + 7 + 0x1234_5678)
        );
        let lea = [0x48, 0x8D, 0x0D, 0x04, 0x00, 0x00, 0x00];
        assert_eq!(extract_pointer(&lea, 0x2000), Some(0x2000 + 7 + 4));
    }

    #[test]
    fn rip_relative_cmp_and_sse() {
        let cmp = [0x40, 0x83, 0x3D, 0x10, 0x00, 0x00, 0x00, 0x05];
        assert_eq!(extract_pointer(&cmp, 0x3000), Some(0x3000 + 8 + 0x10));
        let sse = [0xF2, 0x0F, 0x10, 0x05, 0x20, 0x00, 0x00, 0x00];
        assert_eq!(extract_pointer(&sse, 0x4000), Some(0x4000 + 8 + 0x20));
    }

    #[test]
    fn offset_from_disp8_and_disp32() {
        assert_eq!(extract_offset(&[0x48, 0x8B, 0x48, 0x10], 4), Some(0x10));
        assert_eq!(
            extract_offset(&[0x48, 0x8B, 0x88, 0x00, 0x01, 0x00, 0x00], 4),
            Some(0x100)
        );
    }

    #[test]
    fn two_hop_call_resolution() {
        let base = 0x1_0000usize;
        let mut data = vec![0u8; 0x300];
        data[0x00..0x05].copy_from_slice(&[0xE8, 0xFB, 0x00, 0x00, 0x00]);
        data[0x100..0x105].copy_from_slice(&[0xE8, 0xFB, 0x00, 0x00, 0x00]);
        let source = BufferSource::new(base, data);
        let matched = [0xE8, 0xFB, 0x00, 0x00, 0x00];
        assert_eq!(resolve_call(&source, base, &matched), Some(0x1_0200));
    }
}
