use crate::memory::MemorySource;
use crate::pattern::Arch;
use iced_x86::{Decoder, DecoderOptions, Instruction, OpKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Direct,
    Pointer,
    Call,
    Offset,
    Header,
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
        } else if let Some(base) = name.strip_suffix("_HDR") {
            (Kind::Header, base)
        } else {
            (Kind::Direct, name)
        }
    }

    /// The typed resolution strategy for this kind. Dispatch reads this value rather than
    /// re-parsing the name suffix at each use.
    #[must_use]
    pub fn spec(self) -> ResolverSpec {
        match self {
            Kind::Direct => ResolverSpec::MatchAddress,
            Kind::Pointer => ResolverSpec::MemoryPointer,
            Kind::Offset => ResolverSpec::StructOffset,
            Kind::Header => ResolverSpec::Immediate,
            Kind::Call => ResolverSpec::NestedCall,
        }
    }
}

/// How a matched site turns into a reported value. Today this is derived from the pattern name
/// suffix via [`Kind::spec`], but it is an explicit type so behavior is driven by a value, not by a
/// string, and a future pattern format can set it directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolverSpec {
    MatchAddress,
    MemoryPointer,
    StructOffset,
    Immediate,
    NestedCall,
}

fn bitness(arch: Arch) -> u32 {
    if matches!(arch, Arch::X64) { 64 } else { 32 }
}

fn rel32(bytes: &[u8], at: usize) -> i32 {
    i32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}

fn abs32(bytes: &[u8], at: usize) -> usize {
    rel32(bytes, at) as u32 as usize
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

fn decode_rip_relative(p: &[u8], ip: usize) -> Option<usize> {
    if p.len() >= 7 && p[0] == 0x48 && (p[1] == 0x8B || p[1] == 0x8D) && (p[2] & 0xC7) == 0x05 {
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
    None
}

fn decode_absolute_x86(p: &[u8]) -> Option<usize> {
    if p.len() >= 5 && p[0] == 0xA1 {
        return Some(abs32(p, 1));
    }
    if p.len() >= 6 && (p[0] == 0x8B || p[0] == 0x8D) && (p[1] & 0xC7) == 0x05 {
        return Some(abs32(p, 2));
    }
    if p.len() >= 7 && p[0] == 0x83 && p[1] == 0x3D {
        return Some(abs32(p, 2));
    }
    if p.len() >= 8
        && p[0] == 0xF2
        && p[1] == 0x0F
        && matches!(p[2], 0x10 | 0x58 | 0x59 | 0x5E)
        && p[3] == 0x05
    {
        return Some(abs32(p, 4));
    }
    None
}

#[must_use]
pub fn extract_pointer(data: &[u8], instr_addr: usize, arch: Arch) -> Option<usize> {
    if data.len() < 2 {
        return None;
    }
    for i in 0..data.len() {
        let p = &data[i..];
        let ip = instr_addr.wrapping_add(i);
        if let Some(target) = decode_rel_target(p, ip) {
            return Some(target);
        }
        let target = match arch {
            Arch::X64 => decode_rip_relative(p, ip),
            Arch::X86 => decode_absolute_x86(p),
        };
        if target.is_some() {
            return target;
        }
    }
    None
}

fn offset_x64(p: &[u8]) -> Option<u32> {
    if p.len() < 4 {
        return None;
    }
    let rex = p[0];
    if (rex & 0xF0) == 0x40 && (rex & 0x08) != 0 && p[1] == 0x8B {
        let modrm = p[2];
        // an r/m of 100 means a SIB byte follows and shifts the displacement; do not misread it
        if modrm & 0x07 == 0x04 {
            return None;
        }
        match modrm >> 6 {
            1 => return Some(u32::from(p[3])),
            2 if p.len() >= 7 => return Some(rel32(p, 3) as u32),
            _ => {}
        }
    }
    None
}

fn offset_x86(p: &[u8]) -> Option<u32> {
    if p.len() < 3 || p[0] != 0x8B {
        return None;
    }
    let modrm = p[1];
    if modrm & 0x07 == 4 {
        return None;
    }
    match modrm >> 6 {
        1 => Some(u32::from(p[2])),
        2 if p.len() >= 6 => Some(rel32(p, 2) as u32),
        _ => None,
    }
}

#[must_use]
pub fn extract_offset(data: &[u8], max_scan: usize, arch: Arch) -> Option<u32> {
    for off in 0..=max_scan {
        let Some(p) = data.get(off..) else { break };
        let value = match arch {
            Arch::X64 => offset_x64(p),
            Arch::X86 => offset_x86(p),
        };
        if value.is_some() {
            return value;
        }
    }
    None
}

fn immediate_at(p: &[u8]) -> Option<u32> {
    // only skip a 0x40-0x4F byte as a REX prefix when a mov-immediate opcode follows, so a
    // standalone x86 INC/DEC is not mistaken for a prefix
    let has_rex =
        p.len() >= 2 && (p[0] & 0xF0) == 0x40 && ((0xB8..=0xBF).contains(&p[1]) || p[1] == 0xC7);
    let start = usize::from(has_rex);
    let rest = &p[start..];
    if rest.is_empty() {
        return None;
    }
    if (0xB8..=0xBF).contains(&rest[0]) && rest.len() >= 5 {
        return Some(rel32(rest, 1) as u32);
    }
    if rest[0] == 0xC7 && rest.len() >= 2 && (rest[1] >> 3) & 0x07 == 0 {
        let imm_off = match rest[1] >> 6 {
            3 => 2,
            0 if rest[1] & 0x07 != 4 && rest[1] & 0x07 != 5 => 2,
            _ => return None,
        };
        if rest.len() >= imm_off + 4 {
            return Some(rel32(rest, imm_off) as u32);
        }
    }
    None
}

#[must_use]
pub fn extract_immediate(data: &[u8], max_scan: usize) -> Option<u32> {
    for off in 0..=max_scan {
        let Some(p) = data.get(off..) else { break };
        if let Some(value) = immediate_at(p) {
            return Some(value);
        }
    }
    None
}

pub fn resolve_call<S: MemorySource>(
    source: &S,
    match_addr: usize,
    matched: &[u8],
    arch: Arch,
) -> Option<usize> {
    // first hop: the match must begin with a near call or jmp. Decoding the opcode rejects a
    // prefixed, indirect, or mis-anchored match instead of blindly reading a rel32 from offset 1.
    let mut head = [0u8; 8];
    let head: &[u8] = if matched.len() >= 8 {
        matched
    } else {
        let n = source.read_into(match_addr, &mut head).ok()?;
        &head[..n]
    };
    let target = decode_rel_target(head, match_addr)?;

    // second hop: follow one nested direct call at the callee entry. Decoding instructions means a
    // 0xE8 byte inside a displacement is never mistaken for a call, unlike a raw byte scan.
    let mut buf = [0u8; 0x100];
    let n = source.read_into(target, &mut buf).ok()?;
    Some(first_direct_call(&buf[..n], target, arch).unwrap_or(target))
}

fn first_direct_call(buf: &[u8], base: usize, arch: Arch) -> Option<usize> {
    let mut decoder = Decoder::with_ip(bitness(arch), buf, base as u64, DecoderOptions::NONE);
    let mut instr = Instruction::default();
    while decoder.can_decode() {
        decoder.decode_out(&mut instr);
        if instr.is_invalid() {
            break;
        }
        if instr.is_call_near()
            && matches!(
                instr.op0_kind(),
                OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
            )
        {
            return Some(instr.near_branch_target() as usize);
        }
    }
    None
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
    fn x64_rip_relative_mov_and_lea() {
        let mov = [0x48, 0x8B, 0x0D, 0x78, 0x56, 0x34, 0x12];
        assert_eq!(
            extract_pointer(&mov, 0x1000, Arch::X64),
            Some(0x1000 + 7 + 0x1234_5678)
        );
        let lea = [0x48, 0x8D, 0x0D, 0x04, 0x00, 0x00, 0x00];
        assert_eq!(
            extract_pointer(&lea, 0x2000, Arch::X64),
            Some(0x2000 + 7 + 4)
        );
    }

    #[test]
    fn x64_rip_relative_cmp_and_sse() {
        let cmp = [0x40, 0x83, 0x3D, 0x10, 0x00, 0x00, 0x00, 0x05];
        assert_eq!(
            extract_pointer(&cmp, 0x3000, Arch::X64),
            Some(0x3000 + 8 + 0x10)
        );
        let sse = [0xF2, 0x0F, 0x10, 0x05, 0x20, 0x00, 0x00, 0x00];
        assert_eq!(
            extract_pointer(&sse, 0x4000, Arch::X64),
            Some(0x4000 + 8 + 0x20)
        );
    }

    #[test]
    fn x86_absolute_mov_lea_and_moffs() {
        let movabs = [0x8B, 0x0D, 0x78, 0x56, 0x34, 0x12];
        assert_eq!(
            extract_pointer(&movabs, 0x1000, Arch::X86),
            Some(0x1234_5678)
        );
        let lea = [0x8D, 0x05, 0x78, 0x56, 0x34, 0x12];
        assert_eq!(extract_pointer(&lea, 0x1000, Arch::X86), Some(0x1234_5678));
        let moffs = [0xA1, 0x78, 0x56, 0x34, 0x12];
        assert_eq!(extract_pointer(&moffs, 0, Arch::X86), Some(0x1234_5678));
    }

    #[test]
    fn x64_offset_from_disp8_and_disp32() {
        assert_eq!(
            extract_offset(&[0x48, 0x8B, 0x48, 0x10], 4, Arch::X64),
            Some(0x10)
        );
        assert_eq!(
            extract_offset(&[0x48, 0x8B, 0x88, 0x00, 0x01, 0x00, 0x00], 4, Arch::X64),
            Some(0x100)
        );
    }

    #[test]
    fn x86_offset_from_disp8_and_disp32() {
        assert_eq!(
            extract_offset(&[0x8B, 0x4E, 0x10], 4, Arch::X86),
            Some(0x10)
        );
        assert_eq!(
            extract_offset(&[0x8B, 0x8E, 0x00, 0x01, 0x00, 0x00], 4, Arch::X86),
            Some(0x100)
        );
    }

    #[test]
    fn immediate_from_mov_reg_imm() {
        assert_eq!(
            extract_immediate(&[0xBA, 0x23, 0x01, 0x00, 0x00], 4),
            Some(0x123)
        );
        assert_eq!(
            extract_immediate(&[0x48, 0xC7, 0xC2, 0x23, 0x01, 0x00, 0x00], 4),
            Some(0x123)
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
        assert_eq!(
            resolve_call(&source, base, &matched, Arch::X64),
            Some(0x1_0200)
        );
    }

    #[test]
    fn resolve_call_rejects_indirect_and_prefixed() {
        let base = 0x1_0000usize;
        let data = vec![0u8; 0x40];
        let source = BufferSource::new(base, data);
        // FF 15 is an indirect call [rip+disp], not a direct rel call: must not resolve a target.
        assert_eq!(
            resolve_call(&source, base, &[0xFF, 0x15, 0, 0, 0, 0, 0, 0], Arch::X64),
            None
        );
        // a match that starts on an operand-size prefix is not a bare near call at offset 0.
        assert_eq!(
            resolve_call(&source, base, &[0x66, 0xE8, 0, 0, 0, 0, 0, 0], Arch::X64),
            None
        );
    }

    #[test]
    fn offset_x64_does_not_misread_sib_form() {
        // mov rax,[rsp+0x10] needs a SIB byte, so the displacement is not at p[3]; report nothing
        // rather than a wrong offset.
        assert_eq!(
            extract_offset(
                &[0x48, 0x8B, 0x84, 0x24, 0x10, 0x00, 0x00, 0x00],
                0,
                Arch::X64
            ),
            None
        );
    }
}
