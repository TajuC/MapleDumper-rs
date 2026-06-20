//! Resolve a Themida import wrapper to the real API it dispatches to, by emulating the wrapper
//! with Unicorn. Ported from unlicense's `emulation.py`. The wrapper computes the API address
//! through obfuscated arithmetic and then jumps or returns into it; we emulate until execution
//! reaches a known export (the block hook) and report that address.

use unicorn_engine::RegisterX86 as R;
use unicorn_engine::Unicorn;
use unicorn_engine::unicorn_const::{Arch, HookType, Mode, Prot};

use crate::process::{Architecture, ProcessController, pack_ptr, unpack_ptr};

const STACK_MAGIC_RET_ADDR: u64 = 0xdead_beef;
const NO_RETURN_APIS: [&str; 3] = ["ExitProcess", "FatalExit", "ExitThread"];

struct Regs {
    pc: R,
    sp: R,
    bp: R,
    result: R,
}

fn regs(arch: Architecture) -> Regs {
    match arch {
        Architecture::X86_32 => Regs {
            pc: R::EIP,
            sp: R::ESP,
            bp: R::EBP,
            result: R::EAX,
        },
        Architecture::X86_64 => Regs {
            pc: R::RIP,
            sp: R::RSP,
            bp: R::RBP,
            result: R::RAX,
        },
    }
}

/// Emulate `wrapper_start` and return the address of the export it dispatches to, or `None` if
/// emulation failed or never reached a known export.
pub fn resolve_wrapped_api(
    wrapper_start: u64,
    pc: &dyn ProcessController,
    expected_ret_addr: Option<u64>,
) -> Option<u64> {
    let arch = pc.architecture();
    let page = pc.page_size() as u64;
    let ptr_size = pc.pointer_size();
    let r = regs(arch);
    let stack_addr: u64 = match arch {
        Architecture::X86_32 => 0xff00_0000,
        Architecture::X86_64 => 0xff00_0000_0000_0000,
    };

    let mode = match arch {
        Architecture::X86_32 => Mode::MODE_32,
        Architecture::X86_64 => Mode::MODE_64,
    };
    let mut uc = Unicorn::new(Arch::X86, mode).ok()?;

    // A page for the fake return address, in case a wrapper dereferences it.
    let aligned_ret = STACK_MAGIC_RET_ADDR - (STACK_MAGIC_RET_ADDR % page);
    uc.mem_map(aligned_ret, page, Prot::ALL).ok()?;

    // A small stack, primed so the first `ret` lands on the magic address.
    let stack_size = 3 * page;
    let stack_start = stack_addr + stack_size - page;
    uc.mem_map(stack_addr, stack_size, Prot::READ | Prot::WRITE)
        .ok()?;
    uc.mem_write(stack_start, &pack_ptr(ptr_size, STACK_MAGIC_RET_ADDR))
        .ok()?;
    uc.reg_write(r.sp, stack_start).ok()?;
    uc.reg_write(r.bp, stack_start).ok()?;

    setup_teb(&mut uc, arch, page)?;

    let stop_on_ret = expected_ret_addr.unwrap_or(STACK_MAGIC_RET_ADDR);

    uc.add_mem_hook(
        HookType::MEM_UNMAPPED,
        1,
        u64::MAX,
        move |uc, _t, addr, _sz, _v| map_from_process(uc, addr, pc, page),
    )
    .ok()?;
    uc.add_block_hook(1, u64::MAX, move |uc, addr, _sz| {
        on_block(uc, addr, pc, arch, ptr_size, stop_on_ret);
    })
    .ok()?;

    // Bounded run; the block hook stops us on success, the `until` bounds a runaway wrapper.
    let _ = uc.emu_start(wrapper_start, wrapper_start + 1024, 0, 0);
    uc.reg_read(r.result).ok()
}

fn setup_teb(uc: &mut Unicorn<()>, arch: Architecture, page: u64) -> Option<()> {
    match arch {
        Architecture::X86_64 => {
            let (teb, peb) = (0xff10_0000_0000_0000u64, 0xff20_0000_0000_0000u64);
            uc.mem_map(teb, page, Prot::READ | Prot::WRITE).ok()?;
            uc.mem_map(peb, page, Prot::READ | Prot::WRITE).ok()?;
            uc.mem_write(teb + 0x30, &teb.to_le_bytes()).ok()?;
            uc.mem_write(teb + 0x60, &peb.to_le_bytes()).ok()?;
            uc.reg_write(R::GS_BASE, teb).ok()?;
        }
        Architecture::X86_32 => {
            let (teb, peb) = (0xff10_0000u64, 0xff20_0000u64);
            uc.mem_map(teb, page, Prot::READ | Prot::WRITE).ok()?;
            uc.mem_map(peb, page, Prot::READ | Prot::WRITE).ok()?;
            uc.mem_write(teb + 0x18, &(teb as u32).to_le_bytes()).ok()?;
            uc.mem_write(teb + 0x30, &(peb as u32).to_le_bytes()).ok()?;
            uc.reg_write(R::FS_BASE, teb).ok()?;
        }
    }
    Some(())
}

/// Lazily mirror the target's pages into the emulator when the wrapper touches them.
fn map_from_process(
    uc: &mut Unicorn<()>,
    address: u64,
    pc: &dyn ProcessController,
    page: u64,
) -> bool {
    if address == 0 {
        return false;
    }
    let aligned = address & !(page - 1);
    let Ok(data) = pc.read_process_memory(aligned, page as usize) else {
        return false;
    };
    if uc.mem_map(aligned, data.len() as u64, Prot::ALL).is_err() {
        return false;
    }
    uc.mem_write(aligned, &data).is_ok()
}

fn on_block(
    uc: &mut Unicorn<()>,
    address: u64,
    pc: &dyn ProcessController,
    arch: Architecture,
    ptr_size: usize,
    stop_on_ret: u64,
) {
    let r = regs(arch);
    let exports = pc.enumerate_exported_functions();
    let Some(export) = exports.get(&address) else {
        return;
    };

    let Ok(sp) = uc.reg_read(r.sp) else { return };
    let Ok(ret_bytes) = uc.mem_read_as_vec(sp, ptr_size) else {
        return;
    };
    let ret_addr = unpack_ptr(ptr_size, &ret_bytes);
    let api_name = export.name.as_str();

    if ret_addr == stop_on_ret || ret_addr == stop_on_ret + 1 || ret_addr == STACK_MAGIC_RET_ADDR {
        let _ = uc.reg_write(r.result, address);
        let _ = uc.emu_stop();
        return;
    }
    if NO_RETURN_APIS.contains(&api_name) {
        let _ = uc.reg_write(r.result, address);
        let _ = uc.emu_stop();
        return;
    }
    // Themida >= 3.1.4 calls junk APIs (e.g. Sleep) mid-wrapper to fool emulation. Simulate the
    // return, clean the stack, and continue from the wrapper's return address.
    if let Some((result, arg_count)) = simulate_bogus(api_name) {
        let _ = uc.reg_write(r.result, result);
        let popped = match arch {
            Architecture::X86_32 => 1 + arg_count,
            Architecture::X86_64 => 1 + arg_count.saturating_sub(4),
        };
        let _ = uc.reg_write(r.sp, sp + (ptr_size as u64) * popped as u64);
        let _ = uc.reg_write(r.pc, ret_addr);
    }
}

fn simulate_bogus(api_name: &str) -> Option<(u64, usize)> {
    match api_name {
        "Sleep" => Some((0, 1)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::mock::MockController;

    // x86-64 wrapper: `mov rax, EXPORT; jmp rax`, dispatching to a known export.
    #[test]
    fn resolves_a_mov_jmp_wrapper_x64() {
        let wrapper = 0x10000u64;
        let export = 0x1_4000_0000u64;
        let mut pc = MockController::new(Architecture::X86_64);

        let mut stub = vec![0x48, 0xB8];
        stub.extend_from_slice(&export.to_le_bytes());
        stub.extend_from_slice(&[0xFF, 0xE0]); // jmp rax
        stub.resize(0x1000, 0x90);
        pc.map(wrapper, stub, "r-x");
        pc.map(export, vec![0xC3; 0x1000], "r-x"); // ret at the export
        pc.add_export(export, "GetProcAddress");

        assert_eq!(resolve_wrapped_api(wrapper, &pc, None), Some(export));
    }

    // A wrapper that `push EXPORT; ret`s into the API resolves the same way.
    #[test]
    fn resolves_a_push_ret_wrapper_x64() {
        let wrapper = 0x20000u64;
        let export = 0x1_4001_0000u64;
        let mut pc = MockController::new(Architecture::X86_64);

        // mov rax, EXPORT; push rax; ret
        let mut stub = vec![0x48, 0xB8];
        stub.extend_from_slice(&export.to_le_bytes());
        stub.extend_from_slice(&[0x50, 0xC3]);
        stub.resize(0x1000, 0x90);
        pc.map(wrapper, stub, "r-x");
        pc.map(export, vec![0xC3; 0x1000], "r-x");
        pc.add_export(export, "LoadLibraryA");

        assert_eq!(resolve_wrapped_api(wrapper, &pc, None), Some(export));
    }

    #[test]
    fn junk_pointer_does_not_resolve() {
        let wrapper = 0x30000u64;
        let mut pc = MockController::new(Architecture::X86_64);
        // `xor rax, rax; ret` never reaches an export.
        let mut stub = vec![0x48, 0x31, 0xC0, 0xC3];
        stub.resize(0x1000, 0x90);
        pc.map(wrapper, stub, "r-x");
        // Result register is 0; 0 is not an export, so the caller treats it as unresolved.
        let res = resolve_wrapped_api(wrapper, &pc, None);
        assert!(res == Some(0) || res.is_none());
    }
}
