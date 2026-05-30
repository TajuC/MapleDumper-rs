use crate::memory::MemorySource;
use crate::pattern::Arch;
use iced_x86::{Decoder, DecoderOptions, Instruction, OpKind, Register};

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

pub use crate::domain::ResolverSpec;

fn bitness(arch: Arch) -> u32 {
    if matches!(arch, Arch::X64) { 64 } else { 32 }
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

const MAX_PTR_INSTRS: usize = 8;

// The target named by one instruction: a near branch, a RIP-relative memory operand, or (x86) an
// absolute memory operand. None for anything else.
fn instr_target(instr: &Instruction, arch: Arch) -> Option<usize> {
    if matches!(
        instr.op0_kind(),
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
    ) {
        return Some(instr.near_branch_target() as usize);
    }
    if !(0..instr.op_count()).any(|i| instr.op_kind(i) == OpKind::Memory) {
        return None;
    }
    if instr.is_ip_rel_memory_operand() {
        return Some(instr.ip_rel_memory_address() as usize);
    }
    if matches!(arch, Arch::X86)
        && instr.memory_base() == Register::None
        && instr.memory_index() == Register::None
    {
        return Some(instr.memory_displacement64() as usize);
    }
    None
}

/// Resolve the target a `_PTR` pattern points at: a RIP-relative load or a rel jmp/call, or an
/// absolute load on x86. Decodes whole instructions from the match site and reads real operands, so
/// a displacement or immediate whose bytes merely look like a RIP-relative load is never mistaken
/// for one (which a raw byte scan could do).
#[must_use]
pub fn extract_pointer(data: &[u8], instr_addr: usize, arch: Arch) -> Option<usize> {
    if data.len() < 2 {
        return None;
    }
    let mut decoder =
        Decoder::with_ip(bitness(arch), data, instr_addr as u64, DecoderOptions::NONE);
    let mut instr = Instruction::default();
    for _ in 0..MAX_PTR_INSTRS {
        if !decoder.can_decode() {
            break;
        }
        let start = decoder.position();
        decoder.decode_out(&mut instr);
        if instr.is_invalid() {
            if decoder.set_position(start + 1).is_err() {
                break;
            }
            decoder.set_ip(instr_addr.wrapping_add(start + 1) as u64);
            continue;
        }
        if let Some(target) = instr_target(&instr, arch) {
            return Some(target);
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

// ---------------------------------------------------------------------------
// Typed, decode-driven resolution (ResolverSpec v2)
//
// `ResolveOp` says exactly which instruction and operand to read and how, instead of the coarse
// `Kind` "scan for the first thing that looks right". The executor `resolve_op` honors an explicit
// `instruction_offset` (which decoded instruction in the match window) and `operand_index`, validates
// the mnemonic / operand kind where it can, and returns a `ResolveDetail` rich enough to build a
// diagnostic trace. The coarse `Kind` path lowers onto these ops, so legacy patterns keep working.
// ---------------------------------------------------------------------------

/// A granular resolution operation. `instruction_offset` is the index of the decoded instruction in
/// the match window (0 = the match itself); `operand_index`, when set, selects and validates a
/// specific operand instead of taking the first suitable one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveOp {
    /// The match address itself.
    MatchAddress,
    /// A near, RIP-relative `call rel32`; the target is the callee entry.
    DirectRelativeCall { instruction_offset: usize },
    /// A near, RIP-relative `jmp rel`; the target is the branch destination.
    DirectRelativeJump { instruction_offset: usize },
    /// A RIP-relative memory operand (x64) or absolute memory operand (x86); the target is the
    /// referenced address.
    RipRelativeMemory {
        instruction_offset: usize,
        operand_index: Option<usize>,
    },
    /// An immediate operand of an instruction; the value is the immediate (a header opcode, say).
    ImmediateOperand {
        instruction_offset: usize,
        operand_index: Option<usize>,
    },
    /// A memory displacement (a struct-member offset); the value is the displacement.
    MemoryDisplacement {
        instruction_offset: usize,
        operand_index: Option<usize>,
    },
    /// A `call`/`jmp` followed one hop into the first direct call at the callee (legacy `_CALL`).
    NestedCall { instruction_offset: usize },
}

impl ResolveOp {
    /// Lower a coarse [`ResolverSpec`] plus the explicit refinements from a pattern's schema onto a
    /// granular op. Suffix-derived patterns (no refinements) map to the same behavior they always
    /// had; `@instr` / `@operand` flow straight through.
    #[must_use]
    pub fn from_spec(
        spec: ResolverSpec,
        instruction_offset: usize,
        operand_index: Option<usize>,
    ) -> ResolveOp {
        match spec {
            ResolverSpec::MatchAddress => ResolveOp::MatchAddress,
            ResolverSpec::MemoryPointer => ResolveOp::RipRelativeMemory {
                instruction_offset,
                operand_index,
            },
            ResolverSpec::StructOffset => ResolveOp::MemoryDisplacement {
                instruction_offset,
                operand_index,
            },
            ResolverSpec::Immediate => ResolveOp::ImmediateOperand {
                instruction_offset,
                operand_index,
            },
            ResolverSpec::NestedCall => ResolveOp::NestedCall { instruction_offset },
        }
    }

    /// A short, stable label for diagnostics.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            ResolveOp::MatchAddress => "match address",
            ResolveOp::DirectRelativeCall { .. } => "direct relative call",
            ResolveOp::DirectRelativeJump { .. } => "direct relative jump",
            ResolveOp::RipRelativeMemory { .. } => "rip-relative memory",
            ResolveOp::ImmediateOperand { .. } => "immediate operand",
            ResolveOp::MemoryDisplacement { .. } => "memory displacement",
            ResolveOp::NestedCall { .. } => "nested call",
        }
    }
}

/// Why a typed resolution could not produce a value. Distinct from a clean miss so a caller can tell
/// "decoded the wrong thing" from "the target was unreadable".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolveFail {
    /// The needed instruction could not be decoded.
    Decode,
    /// The instruction was not the expected branch (e.g. expected a `call`, found something else).
    WrongMnemonic,
    /// The selected operand was not of the expected kind (e.g. operand_index did not point at a
    /// memory or immediate operand).
    WrongOperand,
    /// Following the target required reading more memory and the read failed or was truncated.
    PartialRead,
}

/// Everything a resolution observed: the value it produced and the instruction-level facts behind it,
/// for diagnostics and validation. `target` is set for address-producing ops; `value` for
/// offset/immediate ops.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResolveDetail {
    pub instruction_offset: usize,
    pub mnemonic: Option<String>,
    pub operand_index: Option<usize>,
    pub operand_kind: Option<String>,
    pub raw: Option<i64>,
    pub target: Option<usize>,
    pub value: Option<u64>,
    pub is_address: bool,
}

fn mnemonic_str(instr: &Instruction) -> String {
    format!("{:?}", instr.mnemonic()).to_lowercase()
}

fn op_kind_str(kind: OpKind) -> String {
    format!("{kind:?}").to_lowercase()
}

// Decode the `n`-th valid instruction from the match (0-based), skipping bytes that fail to decode
// just like `extract_pointer`, so a mis-anchored leading byte does not abort the walk.
fn nth_instruction(data: &[u8], ip: usize, arch: Arch, n: usize) -> Option<Instruction> {
    let mut decoder = Decoder::with_ip(bitness(arch), data, ip as u64, DecoderOptions::NONE);
    let mut instr = Instruction::default();
    let mut seen = 0usize;
    for _ in 0..64 {
        if !decoder.can_decode() {
            break;
        }
        let start = decoder.position();
        decoder.decode_out(&mut instr);
        if instr.is_invalid() {
            if decoder.set_position(start + 1).is_err() {
                break;
            }
            decoder.set_ip(ip.wrapping_add(start + 1) as u64);
            continue;
        }
        if seen == n {
            return Some(instr);
        }
        seen += 1;
    }
    None
}

fn is_immediate_kind(kind: OpKind) -> bool {
    matches!(
        kind,
        OpKind::Immediate8
            | OpKind::Immediate8_2nd
            | OpKind::Immediate16
            | OpKind::Immediate32
            | OpKind::Immediate64
            | OpKind::Immediate8to16
            | OpKind::Immediate8to32
            | OpKind::Immediate8to64
            | OpKind::Immediate32to64
    )
}

// The memory/branch target named by one instruction, with the operand index and raw displacement.
fn mem_or_branch_target(instr: &Instruction, arch: Arch) -> Option<(usize, usize, OpKind, i64)> {
    if matches!(
        instr.op0_kind(),
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
    ) {
        let t = instr.near_branch_target() as usize;
        return Some((t, 0, instr.op0_kind(), t as i64));
    }
    let mem_op = (0..instr.op_count()).find(|&i| instr.op_kind(i) == OpKind::Memory)?;
    if instr.is_ip_rel_memory_operand() {
        return Some((
            instr.ip_rel_memory_address() as usize,
            mem_op as usize,
            OpKind::Memory,
            instr.memory_displacement64() as i64,
        ));
    }
    if matches!(arch, Arch::X86)
        && instr.memory_base() == Register::None
        && instr.memory_index() == Register::None
    {
        let t = instr.memory_displacement64() as usize;
        return Some((t, mem_op as usize, OpKind::Memory, t as i64));
    }
    None
}

// Scan up to `MAX_PTR_INSTRS` for the first instruction that names a memory/branch target, capturing
// its detail. This is the default (no instruction_offset) pointer behavior, matching extract_pointer.
fn first_target_detail(data: &[u8], ip: usize, arch: Arch) -> Result<ResolveDetail, ResolveFail> {
    let mut decoder = Decoder::with_ip(bitness(arch), data, ip as u64, DecoderOptions::NONE);
    let mut instr = Instruction::default();
    let mut idx = 0usize;
    for _ in 0..MAX_PTR_INSTRS {
        if !decoder.can_decode() {
            break;
        }
        let start = decoder.position();
        decoder.decode_out(&mut instr);
        if instr.is_invalid() {
            if decoder.set_position(start + 1).is_err() {
                break;
            }
            decoder.set_ip(ip.wrapping_add(start + 1) as u64);
            continue;
        }
        if let Some((target, op, kind, raw)) = mem_or_branch_target(&instr, arch) {
            return Ok(ResolveDetail {
                instruction_offset: idx,
                mnemonic: Some(mnemonic_str(&instr)),
                operand_index: Some(op),
                operand_kind: Some(op_kind_str(kind)),
                raw: Some(raw),
                target: Some(target),
                value: None,
                is_address: true,
            });
        }
        idx += 1;
    }
    Err(ResolveFail::Decode)
}

/// Execute a typed resolution op against the bytes at a match, returning a rich detail or a typed
/// failure. `source` is used only by [`ResolveOp::NestedCall`] to follow the callee.
///
/// # Errors
/// Returns a [`ResolveFail`] describing why no value could be produced.
pub fn resolve_op<S: MemorySource>(
    op: &ResolveOp,
    data: &[u8],
    ip: usize,
    arch: Arch,
    source: &S,
) -> Result<ResolveDetail, ResolveFail> {
    match op {
        ResolveOp::MatchAddress => Ok(ResolveDetail {
            target: Some(ip),
            is_address: true,
            ..Default::default()
        }),
        ResolveOp::DirectRelativeCall { instruction_offset } => {
            branch_detail(data, ip, arch, *instruction_offset, true)
        }
        ResolveOp::DirectRelativeJump { instruction_offset } => {
            branch_detail(data, ip, arch, *instruction_offset, false)
        }
        ResolveOp::RipRelativeMemory {
            instruction_offset,
            operand_index,
        } => {
            if *instruction_offset == 0 && operand_index.is_none() {
                return first_target_detail(data, ip, arch);
            }
            let instr =
                nth_instruction(data, ip, arch, *instruction_offset).ok_or(ResolveFail::Decode)?;
            if let Some(oi) = operand_index
                && !(*oi < instr.op_count() as usize
                    && matches!(
                        instr.op_kind(*oi as u32),
                        OpKind::Memory
                            | OpKind::NearBranch16
                            | OpKind::NearBranch32
                            | OpKind::NearBranch64
                    ))
            {
                return Err(ResolveFail::WrongOperand);
            }
            let (target, op, kind, raw) =
                mem_or_branch_target(&instr, arch).ok_or(ResolveFail::WrongOperand)?;
            Ok(ResolveDetail {
                instruction_offset: *instruction_offset,
                mnemonic: Some(mnemonic_str(&instr)),
                operand_index: Some(operand_index.unwrap_or(op)),
                operand_kind: Some(op_kind_str(kind)),
                raw: Some(raw),
                target: Some(target),
                value: None,
                is_address: true,
            })
        }
        ResolveOp::ImmediateOperand {
            instruction_offset,
            operand_index,
        } => {
            if let Some(instr) = nth_instruction(data, ip, arch, *instruction_offset) {
                let chosen = match operand_index {
                    Some(oi) => (*oi < instr.op_count() as usize
                        && is_immediate_kind(instr.op_kind(*oi as u32)))
                    .then_some(*oi),
                    None => (0..instr.op_count())
                        .find(|&i| is_immediate_kind(instr.op_kind(i)))
                        .map(|i| i as usize),
                };
                if let Some(oi) = chosen {
                    let imm = instr.immediate(oi as u32);
                    return Ok(ResolveDetail {
                        instruction_offset: *instruction_offset,
                        mnemonic: Some(mnemonic_str(&instr)),
                        operand_index: Some(oi),
                        operand_kind: Some(op_kind_str(instr.op_kind(oi as u32))),
                        raw: Some(imm as i64),
                        target: None,
                        value: Some(imm),
                        is_address: false,
                    });
                }
                if operand_index.is_some() {
                    return Err(ResolveFail::WrongOperand);
                }
            }
            // Fall back to the byte-scan extractor for the default case, so anything the legacy path
            // found is still found.
            if *instruction_offset == 0
                && operand_index.is_none()
                && let Some(v) = extract_immediate(data, 4)
            {
                return Ok(ResolveDetail {
                    raw: Some(i64::from(v)),
                    value: Some(u64::from(v)),
                    ..Default::default()
                });
            }
            Err(ResolveFail::WrongOperand)
        }
        ResolveOp::MemoryDisplacement {
            instruction_offset,
            operand_index,
        } => {
            if let Some(instr) = nth_instruction(data, ip, arch, *instruction_offset) {
                let mem = match operand_index {
                    Some(oi) => (*oi < instr.op_count() as usize
                        && instr.op_kind(*oi as u32) == OpKind::Memory)
                        .then_some(*oi),
                    None => (0..instr.op_count())
                        .find(|&i| instr.op_kind(i) == OpKind::Memory)
                        .map(|i| i as usize),
                };
                if let Some(oi) = mem {
                    let disp = instr.memory_displacement64();
                    return Ok(ResolveDetail {
                        instruction_offset: *instruction_offset,
                        mnemonic: Some(mnemonic_str(&instr)),
                        operand_index: Some(oi),
                        operand_kind: Some("memory".to_string()),
                        raw: Some(disp as i64),
                        target: None,
                        value: Some(disp),
                        is_address: false,
                    });
                }
                if operand_index.is_some() {
                    return Err(ResolveFail::WrongOperand);
                }
            }
            if *instruction_offset == 0
                && operand_index.is_none()
                && let Some(v) = extract_offset(data, 4, arch)
            {
                return Ok(ResolveDetail {
                    raw: Some(i64::from(v)),
                    value: Some(u64::from(v)),
                    ..Default::default()
                });
            }
            Err(ResolveFail::WrongOperand)
        }
        ResolveOp::NestedCall { instruction_offset } => {
            nested_call_detail(data, ip, arch, *instruction_offset, source)
        }
    }
}

fn branch_detail(
    data: &[u8],
    ip: usize,
    arch: Arch,
    n: usize,
    want_call: bool,
) -> Result<ResolveDetail, ResolveFail> {
    let instr = nth_instruction(data, ip, arch, n).ok_or(ResolveFail::Decode)?;
    let is_branch = matches!(
        instr.op0_kind(),
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
    );
    let right_kind = if want_call {
        instr.is_call_near()
    } else {
        instr.is_jmp_short_or_near()
    };
    if !is_branch || !right_kind {
        return Err(ResolveFail::WrongMnemonic);
    }
    let target = instr.near_branch_target() as usize;
    Ok(ResolveDetail {
        instruction_offset: n,
        mnemonic: Some(mnemonic_str(&instr)),
        operand_index: Some(0),
        operand_kind: Some(op_kind_str(instr.op0_kind())),
        raw: Some(target as i64),
        target: Some(target),
        value: None,
        is_address: true,
    })
}

fn nested_call_detail<S: MemorySource>(
    data: &[u8],
    ip: usize,
    arch: Arch,
    n: usize,
    source: &S,
) -> Result<ResolveDetail, ResolveFail> {
    let instr = nth_instruction(data, ip, arch, n).ok_or(ResolveFail::Decode)?;
    if !matches!(
        instr.op0_kind(),
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
    ) {
        return Err(ResolveFail::WrongMnemonic);
    }
    let first = instr.near_branch_target() as usize;
    // Second hop: read the callee and follow the first direct call. A hard read error at the callee
    // is a partial/inaccessible read, distinct from "decoded fine, no nested call".
    let mut buf = [0u8; 0x100];
    let read = source
        .read_into(first, &mut buf)
        .map_err(|_| ResolveFail::PartialRead)?;
    let target = first_direct_call(&buf[..read], first, arch).unwrap_or(first);
    Ok(ResolveDetail {
        instruction_offset: n,
        mnemonic: Some(mnemonic_str(&instr)),
        operand_index: Some(0),
        operand_kind: Some(op_kind_str(instr.op0_kind())),
        raw: Some(first as i64),
        target: Some(target),
        value: None,
        is_address: true,
    })
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
    fn rip_relative_bytes_inside_an_immediate_do_not_resolve() {
        // mov rax, 0x058B480D0D0D0D0D: the 8-byte immediate contains 48 8B 0D 05, which a byte scan
        // would misread as a rip-relative mov. Decoding the real instruction must resolve nothing.
        let bytes = [0x48, 0xB8, 0x0D, 0x0D, 0x0D, 0x0D, 0x48, 0x8B, 0x0D, 0x05];
        assert_eq!(extract_pointer(&bytes, 0x1000, Arch::X64), None);
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

    // ----- ResolverSpec v2 (resolve_op) golden cases -----

    fn no_source() -> BufferSource {
        BufferSource::new(0, Vec::new())
    }

    #[test]
    fn op_direct_relative_call() {
        let d = resolve_op(
            &ResolveOp::DirectRelativeCall {
                instruction_offset: 0,
            },
            &[0xE8, 0x00, 0x01, 0x00, 0x00],
            0x1000,
            Arch::X64,
            &no_source(),
        )
        .unwrap();
        assert_eq!(d.target, Some(0x1105));
        assert!(d.is_address);
        assert_eq!(d.mnemonic.as_deref(), Some("call"));
    }

    #[test]
    fn op_direct_relative_jump_near_and_short() {
        let near = resolve_op(
            &ResolveOp::DirectRelativeJump {
                instruction_offset: 0,
            },
            &[0xE9, 0x00, 0x01, 0x00, 0x00],
            0x1000,
            Arch::X64,
            &no_source(),
        )
        .unwrap();
        assert_eq!(near.target, Some(0x1105));
        let short = resolve_op(
            &ResolveOp::DirectRelativeJump {
                instruction_offset: 0,
            },
            &[0xEB, 0x05],
            0x1000,
            Arch::X64,
            &no_source(),
        )
        .unwrap();
        assert_eq!(short.target, Some(0x1007));
    }

    #[test]
    fn op_rip_relative_memory() {
        let mov = [0x48, 0x8B, 0x0D, 0x78, 0x56, 0x34, 0x12];
        let d = resolve_op(
            &ResolveOp::RipRelativeMemory {
                instruction_offset: 0,
                operand_index: None,
            },
            &mov,
            0x1000,
            Arch::X64,
            &no_source(),
        )
        .unwrap();
        assert_eq!(d.target, Some(0x1000 + 7 + 0x1234_5678));
        assert_eq!(d.operand_kind.as_deref(), Some("memory"));
    }

    #[test]
    fn op_immediate_operand() {
        let d = resolve_op(
            &ResolveOp::ImmediateOperand {
                instruction_offset: 0,
                operand_index: None,
            },
            &[0xBA, 0x23, 0x01, 0x00, 0x00],
            0x1000,
            Arch::X64,
            &no_source(),
        )
        .unwrap();
        assert_eq!(d.value, Some(0x123));
        assert!(!d.is_address);
    }

    #[test]
    fn op_memory_displacement() {
        let d = resolve_op(
            &ResolveOp::MemoryDisplacement {
                instruction_offset: 0,
                operand_index: None,
            },
            &[0x48, 0x8B, 0x48, 0x10],
            0x1000,
            Arch::X64,
            &no_source(),
        )
        .unwrap();
        assert_eq!(d.value, Some(0x10));
    }

    #[test]
    fn op_honors_instruction_offset() {
        // a leading nop, then the call; instruction_offset 1 must resolve the call, not the nop.
        let bytes = [0x90, 0xE8, 0x00, 0x01, 0x00, 0x00];
        let d = resolve_op(
            &ResolveOp::DirectRelativeCall {
                instruction_offset: 1,
            },
            &bytes,
            0x1000,
            Arch::X64,
            &no_source(),
        )
        .unwrap();
        // call ip is 0x1001, len 5, rel 0x100 -> 0x1106
        assert_eq!(d.target, Some(0x1106));
        assert_eq!(d.instruction_offset, 1);
    }

    #[test]
    fn op_wrong_mnemonic_is_reported() {
        // a mov is not a call
        let err = resolve_op(
            &ResolveOp::DirectRelativeCall {
                instruction_offset: 0,
            },
            &[0x48, 0x8B, 0x48, 0x10],
            0x1000,
            Arch::X64,
            &no_source(),
        )
        .unwrap_err();
        assert_eq!(err, ResolveFail::WrongMnemonic);
    }

    #[test]
    fn op_wrong_operand_is_reported() {
        // operand 0 of `mov rcx,[rax+0x10]` is a register, not an immediate
        let err = resolve_op(
            &ResolveOp::ImmediateOperand {
                instruction_offset: 0,
                operand_index: Some(0),
            },
            &[0x48, 0x8B, 0x48, 0x10],
            0x1000,
            Arch::X64,
            &no_source(),
        )
        .unwrap_err();
        assert_eq!(err, ResolveFail::WrongOperand);
    }

    #[test]
    fn op_undecodable_is_a_decode_failure() {
        let err = resolve_op(
            &ResolveOp::DirectRelativeCall {
                instruction_offset: 0,
            },
            &[0xFF],
            0x1000,
            Arch::X64,
            &no_source(),
        )
        .unwrap_err();
        assert_eq!(err, ResolveFail::Decode);
    }

    #[test]
    fn op_nested_call_partial_read_when_target_unreadable() {
        struct DeadSource;
        impl MemorySource for DeadSource {
            fn read_into(&self, _addr: usize, _buf: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
            }
        }
        let err = resolve_op(
            &ResolveOp::NestedCall {
                instruction_offset: 0,
            },
            &[0xE8, 0x00, 0x01, 0x00, 0x00],
            0x1000,
            Arch::X64,
            &DeadSource,
        )
        .unwrap_err();
        assert_eq!(err, ResolveFail::PartialRead);
    }

    #[test]
    fn op_match_address_is_the_ip() {
        let d = resolve_op(
            &ResolveOp::MatchAddress,
            &[0x90],
            0x4000,
            Arch::X64,
            &no_source(),
        )
        .unwrap();
        assert_eq!(d.target, Some(0x4000));
        assert!(d.is_address);
    }
}
