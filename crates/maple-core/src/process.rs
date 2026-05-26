use crate::memory::{MemorySource, Region, coalesce};
use core::ffi::c_void;
use std::io;
use std::mem::{size_of, zeroed};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ACCESS_DENIED, GetLastError, HANDLE, INVALID_HANDLE_VALUE, LUID,
};
use windows_sys::Win32::Security::{
    AdjustTokenPrivileges, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW, SE_PRIVILEGE_ENABLED,
    TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, MODULEENTRY32W, Module32FirstW, Module32NextW, PROCESSENTRY32W,
    Process32FirstW, Process32NextW, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress, LoadLibraryW};
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
    PAGE_EXECUTE_WRITECOPY, PAGE_GUARD, PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
    VirtualQueryEx,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_INFORMATION,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{FindWindowW, GetWindowThreadProcessId};

type NtReadVirtualMemoryFn =
    unsafe extern "system" fn(HANDLE, *const c_void, *mut c_void, usize, *mut usize) -> i32;

const STATUS_PARTIAL_COPY: i32 = 0x8000_000D_u32 as i32;

#[derive(Debug, Clone, Copy)]
pub struct ModuleInfo {
    pub base: usize,
    pub size: usize,
}

#[derive(Debug, Clone)]
pub enum Locator {
    Name(String),
    Class(String),
}

#[derive(Debug, Clone, Copy)]
pub struct AttachOptions {
    pub wait: bool,
    pub timeout: Option<Duration>,
    pub poll: Duration,
}

impl Default for AttachOptions {
    fn default() -> Self {
        Self {
            wait: false,
            timeout: None,
            poll: Duration::from_millis(300),
        }
    }
}

enum AttachError {
    NotReady,
    AccessDenied,
    NoNtdll,
}

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            unsafe { CloseHandle(self.0) };
        }
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn u16_to_string(buf: &[u16]) -> String {
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..len])
}

fn strip_exe(s: &str) -> &str {
    if s.len() >= 4 && s[s.len() - 4..].eq_ignore_ascii_case(".exe") {
        &s[..s.len() - 4]
    } else {
        s
    }
}

fn name_matches(candidate: &str, query: &str) -> bool {
    strip_exe(candidate.trim()).eq_ignore_ascii_case(strip_exe(query.trim()))
}

#[must_use]
pub fn find_pid_by_name(name: &str) -> Option<u32> {
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == INVALID_HANDLE_VALUE {
            return None;
        }
        let _guard = OwnedHandle(snap);
        let mut entry: PROCESSENTRY32W = zeroed();
        entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;
        if Process32FirstW(snap, &mut entry) == 0 {
            return None;
        }
        loop {
            if name_matches(&u16_to_string(&entry.szExeFile), name) {
                return Some(entry.th32ProcessID);
            }
            if Process32NextW(snap, &mut entry) == 0 {
                return None;
            }
        }
    }
}

#[must_use]
pub fn find_pid_by_class(class: &str) -> Option<u32> {
    let wclass = wide(class.trim());
    unsafe {
        let hwnd = FindWindowW(wclass.as_ptr(), std::ptr::null());
        if hwnd.is_null() {
            return None;
        }
        let mut pid = 0u32;
        GetWindowThreadProcessId(hwnd, &mut pid);
        (pid != 0).then_some(pid)
    }
}

fn enable_debug_privilege() -> bool {
    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        ) == 0
        {
            return false;
        }
        let _guard = OwnedHandle(token);
        let mut luid: LUID = zeroed();
        let name = wide("SeDebugPrivilege");
        if LookupPrivilegeValueW(std::ptr::null(), name.as_ptr(), &mut luid) == 0 {
            return false;
        }
        let tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };
        AdjustTokenPrivileges(token, 0, &tp, 0, std::ptr::null_mut(), std::ptr::null_mut()) != 0
    }
}

fn open_process(pid: u32) -> Result<OwnedHandle, u32> {
    let rights_options = [
        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
        PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION,
    ];
    let mut last_error = 0u32;
    for rights in rights_options {
        let handle = unsafe { OpenProcess(rights, 0, pid) };
        if !handle.is_null() {
            return Ok(OwnedHandle(handle));
        }
        last_error = unsafe { GetLastError() };
    }
    Err(last_error)
}

fn find_module(pid: u32, module_name: &str) -> Option<ModuleInfo> {
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if snap == INVALID_HANDLE_VALUE {
            return None;
        }
        let _guard = OwnedHandle(snap);
        let mut me: MODULEENTRY32W = zeroed();
        me.dwSize = size_of::<MODULEENTRY32W>() as u32;
        if Module32FirstW(snap, &mut me) == 0 {
            return None;
        }
        loop {
            if name_matches(&u16_to_string(&me.szModule), module_name) {
                return Some(ModuleInfo {
                    base: me.modBaseAddr as usize,
                    size: me.modBaseSize as usize,
                });
            }
            if Module32NextW(snap, &mut me) == 0 {
                return None;
            }
        }
    }
}

fn is_readable(protect: u32) -> bool {
    if protect & PAGE_GUARD != 0 {
        return false;
    }
    const READABLE: u32 = PAGE_READONLY
        | PAGE_READWRITE
        | PAGE_WRITECOPY
        | PAGE_EXECUTE
        | PAGE_EXECUTE_READ
        | PAGE_EXECUTE_READWRITE
        | PAGE_EXECUTE_WRITECOPY;
    protect & READABLE != 0
}

fn enumerate_regions(handle: HANDLE, module: ModuleInfo) -> Vec<Region> {
    let start = module.base;
    let end = module.base + module.size;
    let mut regions = Vec::new();
    let mut addr = start;
    while addr < end {
        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { zeroed() };
        let got = unsafe {
            VirtualQueryEx(
                handle,
                addr as *const c_void,
                &mut mbi,
                size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        if got != size_of::<MEMORY_BASIC_INFORMATION>() {
            break;
        }
        let region_base = mbi.BaseAddress as usize;
        let region_size = mbi.RegionSize;
        if region_size == 0 {
            break;
        }
        let region_end = region_base + region_size;
        if mbi.State == MEM_COMMIT && is_readable(mbi.Protect) {
            let clip_start = region_base.max(start);
            let clip_end = region_end.min(end);
            if clip_end > clip_start {
                regions.push(Region {
                    base: clip_start,
                    size: clip_end - clip_start,
                });
            }
        }
        addr = region_end;
    }
    coalesce(regions)
}

fn load_nt_read() -> Option<NtReadVirtualMemoryFn> {
    unsafe {
        let name = wide("ntdll.dll");
        let mut module = GetModuleHandleW(name.as_ptr());
        if module.is_null() {
            module = LoadLibraryW(name.as_ptr());
        }
        if module.is_null() {
            return None;
        }
        let proc = GetProcAddress(module, c"NtReadVirtualMemory".as_ptr().cast::<u8>());
        proc.map(|p| {
            std::mem::transmute::<unsafe extern "system" fn() -> isize, NtReadVirtualMemoryFn>(p)
        })
    }
}

fn resolve_module_name(locator: &Locator, module: &str) -> io::Result<String> {
    let module = module.trim();
    if !module.is_empty() {
        return Ok(module.to_string());
    }
    match locator {
        Locator::Name(name) => Ok(name.trim().to_string()),
        Locator::Class(_) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "a module name is required when attaching by window class",
        )),
    }
}

fn try_attach_once(locator: &Locator, module: &str) -> Result<Target, AttachError> {
    let pid = match locator {
        Locator::Name(name) => find_pid_by_name(name),
        Locator::Class(class) => find_pid_by_class(class),
    };
    let Some(pid) = pid else {
        return Err(AttachError::NotReady);
    };
    let handle = match open_process(pid) {
        Ok(handle) => handle,
        Err(code) if code == ERROR_ACCESS_DENIED => return Err(AttachError::AccessDenied),
        Err(_) => return Err(AttachError::NotReady),
    };
    let Some(module_info) = find_module(pid, module) else {
        return Err(AttachError::NotReady);
    };
    let Some(nt_read) = load_nt_read() else {
        return Err(AttachError::NoNtdll);
    };
    Ok(Target {
        handle,
        nt_read,
        module: module_info,
    })
}

pub struct Target {
    handle: OwnedHandle,
    nt_read: NtReadVirtualMemoryFn,
    pub module: ModuleInfo,
}

// SAFETY: the process handle is an opaque kernel handle, and NtReadVirtualMemory
// is safe to call concurrently from multiple threads sharing one handle.
unsafe impl Send for Target {}
unsafe impl Sync for Target {}

impl Target {
    pub fn attach(
        locator: &Locator,
        module: &str,
        opts: &AttachOptions,
        cancel: &AtomicBool,
    ) -> io::Result<Self> {
        enable_debug_privilege();
        let module = resolve_module_name(locator, module)?;
        let deadline = opts.timeout.map(|t| Instant::now() + t);
        loop {
            if cancel.load(Ordering::Relaxed) {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "attach cancelled",
                ));
            }
            match try_attach_once(locator, &module) {
                Ok(target) => return Ok(target),
                Err(AttachError::AccessDenied) => {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "access denied opening the process - run MapleDumper as administrator",
                    ));
                }
                Err(AttachError::NoNtdll) => {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "NtReadVirtualMemory unavailable",
                    ));
                }
                Err(AttachError::NotReady) => {
                    if !opts.wait {
                        return Err(io::Error::new(
                            io::ErrorKind::NotFound,
                            "target process not found (is it running?)",
                        ));
                    }
                    if let Some(deadline) = deadline
                        && Instant::now() >= deadline
                    {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "timed out waiting for the target process",
                        ));
                    }
                    std::thread::sleep(opts.poll);
                }
            }
        }
    }

    pub fn attach_pid(pid: u32, module: &str) -> io::Result<Self> {
        enable_debug_privilege();
        let handle = open_process(pid).map_err(|code| {
            if code == ERROR_ACCESS_DENIED {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "access denied - run as administrator",
                )
            } else {
                io::Error::other(format!("OpenProcess failed (error {code})"))
            }
        })?;
        let module_info = find_module(pid, module)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "module not found"))?;
        let nt_read = load_nt_read().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                "NtReadVirtualMemory unavailable",
            )
        })?;
        Ok(Self {
            handle,
            nt_read,
            module: module_info,
        })
    }

    pub fn attach_by_name(process: &str, module: &str) -> io::Result<Self> {
        Self::attach(
            &Locator::Name(process.to_string()),
            module,
            &AttachOptions::default(),
            &AtomicBool::new(false),
        )
    }

    pub fn attach_by_class(class: &str, module: &str) -> io::Result<Self> {
        Self::attach(
            &Locator::Class(class.to_string()),
            module,
            &AttachOptions::default(),
            &AtomicBool::new(false),
        )
    }

    #[must_use]
    pub fn regions(&self) -> Vec<Region> {
        enumerate_regions(self.handle.0, self.module)
    }
}

impl MemorySource for Target {
    fn read_into(&self, address: usize, buf: &mut [u8]) -> io::Result<usize> {
        let mut read: usize = 0;
        let status = unsafe {
            (self.nt_read)(
                self.handle.0,
                address as *const c_void,
                buf.as_mut_ptr().cast::<c_void>(),
                buf.len(),
                &mut read,
            )
        };
        if status >= 0 || status == STATUS_PARTIAL_COPY {
            Ok(read)
        } else {
            Err(io::Error::other(format!(
                "NtReadVirtualMemory failed: {:#010x}",
                status as u32
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_matching_is_tolerant() {
        assert!(name_matches("MapleStory.exe", "maplestory"));
        assert!(name_matches("MapleStory.exe", "MapleStory.exe"));
        assert!(name_matches("game", "game.exe"));
        assert!(!name_matches("MapleStory.exe", "other"));
    }

    #[test]
    fn reads_own_process_memory() {
        let pid = std::process::id();
        let exe = std::env::current_exe().unwrap();
        let module_name = exe.file_name().unwrap().to_string_lossy().into_owned();
        let target = Target::attach_pid(pid, &module_name).expect("attach self");
        assert!(target.module.size > 0);
        let regions = target.regions();
        assert!(!regions.is_empty(), "expected at least one readable region");
        let first = regions[0];
        let mut buf = vec![0u8; first.size.min(4096)];
        let n = target.read_into(first.base, &mut buf).expect("read");
        assert!(n > 0);
    }
}
