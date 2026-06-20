//! Drive the live process: spawn the packed client, inject the agent, wait for the OEP, then
//! resolve imports and assemble the dump. Ports unlicense's `application.py` + `frida_exec.py`
//! orchestration and the `winlicense3.py` dumping routine.

use std::io;
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::time::{Duration, Instant};

use frida::{DeviceManager, Frida, ScriptOption, SpawnOptions};

use crate::agent::agent_source;
use crate::imports::{find_iat, unwrap_iat};
use crate::pe_build::{DumpInputs, build_dump, parse};
use crate::process::ProcessController;
use crate::rpc::SocketController;
use crate::version::{PackerVersion, detect};

fn other(m: impl Into<String>) -> io::Error {
    io::Error::other(m.into())
}

/// What the unpack produced: the OEP/imports recovered live, plus the static verification gates run
/// over the cleaned min.
#[derive(Clone, Debug)]
pub struct DumpReport {
    pub image_base: u64,
    pub oep_rva: u32,
    pub resolved_imports: usize,
    pub gates_pass: bool,
    pub import_dlls: u32,
    pub import_functions: u32,
    pub pdata_entries: u32,
    pub text_identity: Option<bool>,
    pub output_size: usize,
    /// The same end-to-end report the CLI and GUI render for the unlicense path, so the native
    /// dumper feeds the existing results card with no second report shape to drift from.
    pub unpack: maple_core::UnpackReport,
}

/// Progress callbacks so the caller can show stages and agent lines.
pub trait Progress {
    fn stage(&mut self, stage: &str);
    fn line(&mut self, line: &str);
}

/// Stdout progress, used by the binary.
pub struct StderrProgress;
impl Progress for StderrProgress {
    fn stage(&mut self, stage: &str) {
        eprintln!("[native-unpack] {stage}");
    }
    fn line(&mut self, line: &str) {
        eprintln!("    {line}");
    }
}

fn is_text_section(name: &str, chars: u32) -> bool {
    const MEM_EXECUTE: u32 = 0x2000_0000;
    chars & MEM_EXECUTE != 0
        && (name.is_empty() || name == ".text" || name == ".textbss" || name == ".textidx")
}

/// Unpack `packed` to `out`: spawn + instrument the client, recover the OEP and imports, rebuild
/// the PE, run the static clean + verification gates, and write the min only if every gate passes.
pub fn dump_packed(
    packed: &Path,
    out: &Path,
    timeout: Duration,
    on: &mut dyn Progress,
) -> io::Result<DumpReport> {
    let packed_bytes = std::fs::read(packed)?;

    on.stage("detect");
    match detect(&packed_bytes) {
        Some(PackerVersion::V3) => {}
        Some(PackerVersion::V2) => {
            return Err(other(
                "Themida/WinLicense 2.x is not supported by the native dumper (target is 3.x x64)",
            ));
        }
        None => return Err(other("could not detect a Themida/WinLicense 3.x envelope")),
    }

    let pe = parse(&packed_bytes)?;
    if !pe.is64 {
        return Err(other("only 64-bit images are supported"));
    }
    // The real code ranges to make inaccessible (RVAs), and every section range for the IAT scan.
    let text_ranges: Vec<(u64, u64)> = {
        let mut v = Vec::new();
        for s in &pe.sections {
            let stripped = s.name.trim_matches(['\0', ' ']);
            if !stripped.is_empty() && !matches!(stripped, ".text" | ".textbss" | ".textidx") {
                break;
            }
            if is_text_section(stripped, s.chars) {
                v.push((s.va as u64, s.vs as u64));
            }
        }
        v
    };
    if text_ranges.is_empty() {
        return Err(other("failed to locate a .text section to trace"));
    }

    let main_module = packed
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| other("packed path has no file name"))?
        .to_string();

    on.stage("spawn");
    let frida = unsafe { Frida::obtain() };
    let manager = DeviceManager::obtain(&frida);
    let mut device = manager
        .get_local_device()
        .map_err(|e| other(format!("no local Frida device: {e:?}")))?;
    let spawn_opts = SpawnOptions::new();
    let pid = device
        .spawn(packed.to_string_lossy().as_ref(), &spawn_opts)
        .map_err(|e| other(format!("spawn failed: {e:?}")))?;
    on.line(&format!("spawned pid {pid}"));

    // Always kill the spawned client, whether the dump succeeds or fails (e.g. an OEP timeout).
    let result = run_session(
        &device,
        pid,
        &main_module,
        &text_ranges,
        &packed_bytes,
        timeout,
        on,
    );
    device.kill(pid).ok();

    let (dump_bytes, mut report) = result?;
    std::fs::write(out, &dump_bytes)?;
    report.unpack.input = packed.display().to_string();
    report.unpack.output = Some(out.display().to_string());
    Ok(report)
}

fn accept_agent(listener: &TcpListener, timeout: Duration) -> io::Result<TcpStream> {
    listener.set_nonblocking(true)?;
    let deadline = Instant::now() + timeout;
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false)?;
                return Ok(stream);
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(other("the agent did not connect back in time"));
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => return Err(e),
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn run_session(
    device: &frida::Device,
    pid: u32,
    main_module: &str,
    text_ranges: &[(u64, u64)],
    packed_bytes: &[u8],
    timeout: Duration,
    on: &mut dyn Progress,
) -> io::Result<(Vec<u8>, DumpReport)> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();

    let session = device
        .attach(pid)
        .map_err(|e| other(format!("attach failed: {e:?}")))?;
    let mut options = ScriptOption::new();
    // The script must stay loaded for the whole dump; keep it in scope until the end.
    let script = session
        .create_script(&agent_source(port), &mut options)
        .map_err(|e| other(format!("create_script failed: {e:?}")))?;
    script
        .load()
        .map_err(|e| other(format!("load failed: {e:?}")))?;

    let stream = accept_agent(&listener, timeout)?;
    on.line("agent connected");
    let ctl = SocketController::attach(stream, main_module.to_string(), timeout)?;

    on.stage("trace");
    ctl.setup_oep_tracing(main_module, text_ranges)?;
    device
        .resume(pid)
        .map_err(|e| other(format!("resume failed: {e:?}")))?;

    on.line("waiting for the original entry point");
    let oep = ctl.wait_for_oep(timeout)?;
    if oep.dotnet {
        return Err(other(
            ".NET assemblies are not supported by the native dumper",
        ));
    }
    on.line(&format!(
        "OEP reached: base={:#x} oep={:#x}",
        oep.image_base, oep.oep
    ));

    let report = run_dump(&ctl, packed_bytes, oep, on)?;
    ctl.notify_dumping_finished().ok();
    drop(script);
    Ok(report)
}

fn run_dump(
    ctl: &dyn ProcessController,
    packed_bytes: &[u8],
    oep: crate::rpc::OepEvent,
    on: &mut dyn Progress,
) -> io::Result<(Vec<u8>, DumpReport)> {
    let pe = parse(packed_bytes)?;
    let image_base = oep.image_base;

    on.stage("imports");
    let section_rvas: Vec<(u64, u64)> = pe
        .sections
        .iter()
        .map(|s| (s.va as u64, u64::from(s.vs.max(s.rs))))
        .collect();
    let iat = find_iat(image_base, &section_rvas, ctl).ok_or_else(|| other("IAT not found"))?;
    on.line(&format!("IAT at {:#x} size {:#x}", iat.base, iat.size));
    let unwrapped = unwrap_iat(&iat, ctl).ok_or_else(|| other("IAT unwrap failed"))?;
    let dll_count = {
        let mut names: Vec<&str> = unwrapped
            .imports
            .iter()
            .map(|i| i.module.as_str())
            .collect();
        names.sort_unstable();
        names.dedup();
        names.len()
    };
    on.line(&format!(
        "resolved {} imports across {} modules",
        unwrapped.imports.len(),
        dll_count
    ));

    on.stage("dump");
    let image_mem = ctl.read_process_memory(image_base, pe.size_of_image as usize)?;
    let oep_rva = (oep.oep - image_base) as u32;
    let resolved_imports = unwrapped.imports.len();
    let dump = build_dump(&DumpInputs {
        packed: packed_bytes,
        image_mem: &image_mem,
        image_base,
        oep_rva,
        imports: &unwrapped.imports,
    })?;
    drop(image_mem);

    // Run the same static clean + verification gates the rest of the project uses, and refuse to
    // emit a binary unless every gate passes.
    on.stage("clean");
    let cleaned = maple_core::clean_bytes(&dump, &maple_core::CleanOptions::default())?;
    drop(dump);
    on.stage("verify");
    let verify = maple_core::verify_bytes(&cleaned.data, Some((packed_bytes, "packed original")))?;

    let unpack = maple_core::UnpackReport {
        input: String::new(),
        output: None,
        dump_path: None,
        gates_pass: verify.gates_pass,
        clean: cleaned.summary.clone(),
        verify: verify.clone(),
    };
    let report = DumpReport {
        image_base,
        oep_rva,
        resolved_imports,
        gates_pass: verify.gates_pass,
        import_dlls: verify.import_dlls,
        import_functions: verify.import_functions,
        pdata_entries: verify.pdata_entries,
        text_identity: verify.text_identity,
        output_size: cleaned.data.len(),
        unpack,
    };
    if !verify.gates_pass {
        return Err(other("verification gates failed; no binary was written"));
    }
    Ok((cleaned.data, report))
}
