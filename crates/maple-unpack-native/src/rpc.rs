//! The live [`ProcessController`], backed by a local socket to the agent.
//!
//! The Rust frida binding does not deliver script messages to the host, so the agent connects back
//! to a TCP server the driver runs on loopback and we speak a small framed protocol over it:
//! each frame is a little-endian u32 length followed by a kind byte (`J` JSON or `B` binary). The
//! driver sends JSON requests; the agent answers with a JSON reply (and, for memory reads, a
//! following binary frame) and pushes the `oep_reached` event.

use std::cell::{OnceCell, RefCell};
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::process::{Architecture, Export, MemoryRange, ProcessController};

const MAX_CHUNK: usize = 32 * 1024 * 1024;

/// A raw agent message: the JSON text plus any binary payload (e.g. a memory read).
type AgentMsg = (String, Option<Vec<u8>>);
/// An RPC reply: the returned JSON value plus any binary payload.
type RpcReply = (Value, Option<Vec<u8>>);

fn other(m: impl Into<String>) -> io::Error {
    io::Error::other(m.into())
}

fn parse_hex(s: &str) -> Option<u64> {
    let t = s.strip_prefix("0x").unwrap_or(s);
    u64::from_str_radix(t, 16).ok()
}

/// The OEP report carried by the agent's `oep_reached` event.
#[derive(Clone, Copy, Debug)]
pub struct OepEvent {
    pub image_base: u64,
    pub oep: u64,
    pub dotnet: bool,
}

/// Read one framed message: a little-endian u32 length, then that many bytes (the first is the kind).
fn read_frame(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_le_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf)?;
    Ok(buf)
}

fn write_json_frame(stream: &TcpStream, obj: &Value) -> io::Result<()> {
    let body = serde_json::to_vec(obj)?;
    let mut frame = Vec::with_capacity(5 + body.len());
    frame.extend_from_slice(&((1 + body.len()) as u32).to_le_bytes());
    frame.push(b'J');
    frame.extend_from_slice(&body);
    let mut s = stream;
    s.write_all(&frame)
}

/// Read frames off the socket and forward (json, optional binary) pairs to the pump. A reply with
/// `"bin":true` is immediately followed by a `B` frame carrying the bytes.
fn reader_loop(mut stream: TcpStream, tx: Sender<AgentMsg>) {
    loop {
        let frame = match read_frame(&mut stream) {
            Ok(f) if !f.is_empty() => f,
            _ => break,
        };
        if frame[0] != b'J' {
            continue;
        }
        let json = String::from_utf8_lossy(&frame[1..]).into_owned();
        let has_bin = serde_json::from_str::<Value>(&json)
            .ok()
            .and_then(|v| v.get("bin").and_then(Value::as_bool))
            .unwrap_or(false);
        let data = if has_bin {
            match read_frame(&mut stream) {
                Ok(b) if b.first() == Some(&b'B') => Some(b[1..].to_vec()),
                _ => break,
            }
        } else {
            None
        };
        if tx.send((json, data)).is_err() {
            break;
        }
    }
}

struct Pump {
    rx: Receiver<AgentMsg>,
    replies: HashMap<u64, RpcReply>,
}

impl Pump {
    fn classify(&mut self, raw: &str, data: Option<Vec<u8>>) {
        let Ok(v) = serde_json::from_str::<Value>(raw) else {
            return;
        };
        if let Some(id) = v.get("id").and_then(Value::as_u64) {
            if v.get("ok").and_then(Value::as_bool) == Some(true) {
                let value = v.get("value").cloned().unwrap_or(Value::Null);
                self.replies.insert(id, (value, data));
            } else {
                let err = v.get("error").cloned().unwrap_or(Value::Null);
                self.replies.insert(id, (json!({ "__error__": err }), None));
            }
        }
    }

    fn pump_one(&mut self, deadline: Instant) -> io::Result<()> {
        let wait = deadline
            .saturating_duration_since(Instant::now())
            .max(Duration::from_millis(1));
        match self.rx.recv_timeout(wait) {
            Ok((raw, data)) => {
                self.classify(&raw, data);
                Ok(())
            }
            Err(_) => Err(other("timed out waiting for the agent")),
        }
    }

    fn recv_reply(&mut self, id: u64, deadline: Instant) -> io::Result<RpcReply> {
        loop {
            if let Some(r) = self.replies.remove(&id) {
                return Ok(r);
            }
            self.pump_one(deadline)?;
        }
    }
}

/// A live controller over the agent socket.
pub struct SocketController {
    stream: TcpStream,
    pump: RefCell<Pump>,
    next_id: RefCell<u64>,
    timeout: Duration,
    arch: Architecture,
    pointer_size: usize,
    page_size: usize,
    main_module: String,
    exports_cache: OnceCell<HashMap<u64, Export>>,
    main_ranges_cache: OnceCell<Vec<MemoryRange>>,
}

impl SocketController {
    /// Wire a controller to an accepted agent connection and probe its basics.
    pub fn attach(stream: TcpStream, main_module: String, timeout: Duration) -> io::Result<Self> {
        stream.set_nodelay(true).ok();
        let reader = stream.try_clone()?;
        let (tx, rx) = channel();
        std::thread::spawn(move || reader_loop(reader, tx));

        let mut ctl = SocketController {
            stream,
            pump: RefCell::new(Pump {
                rx,
                replies: HashMap::new(),
            }),
            next_id: RefCell::new(0),
            timeout,
            arch: Architecture::X86_64,
            pointer_size: 8,
            page_size: 0x1000,
            main_module,
            exports_cache: OnceCell::new(),
            main_ranges_cache: OnceCell::new(),
        };

        let arch = ctl.call("getArchitecture", json!([]))?.0;
        ctl.arch = match arch.as_str() {
            Some("x64") => Architecture::X86_64,
            Some("ia32") => Architecture::X86_32,
            _ => return Err(other("unsupported target architecture")),
        };
        ctl.pointer_size = ctl
            .call("getPointerSize", json!([]))?
            .0
            .as_u64()
            .unwrap_or(8) as usize;
        ctl.page_size = ctl
            .call("getPageSize", json!([]))?
            .0
            .as_u64()
            .unwrap_or(0x1000) as usize;
        Ok(ctl)
    }

    fn call(&self, method: &str, args: Value) -> io::Result<RpcReply> {
        let id = {
            let mut n = self.next_id.borrow_mut();
            *n += 1;
            *n
        };
        let req = json!({ "id": id, "method": method, "args": args });
        write_json_frame(&self.stream, &req)?;
        let deadline = Instant::now() + self.timeout;
        let (value, data) = self.pump.borrow_mut().recv_reply(id, deadline)?;
        if let Some(err) = value.get("__error__") {
            return Err(other(format!("agent '{method}' failed: {err}")));
        }
        Ok((value, data))
    }

    /// Arm the agent's OEP tracing over the real code ranges (RVAs).
    pub fn setup_oep_tracing(
        &self,
        module_name: &str,
        text_ranges: &[(u64, u64)],
    ) -> io::Result<()> {
        let ranges: Vec<Value> = text_ranges.iter().map(|&(b, s)| json!([b, s])).collect();
        self.call("setupOepTracing", json!([module_name, ranges]))?;
        Ok(())
    }

    /// Poll the agent until it reports it reached the OEP. The agent freezes the target's thread at
    /// the OEP and we read the report over the (reliable) RPC serve loop.
    pub fn wait_for_oep(&self, timeout: Duration) -> io::Result<OepEvent> {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            let (v, _) = self.call("pollOep", json!([]))?;
            if let Some(logs) = v.get("logs").and_then(Value::as_array) {
                for l in logs {
                    if let Some(s) = l.as_str() {
                        eprintln!("    [agent] {s}");
                    }
                }
            }
            if let Some(oep) = v.get("oep").filter(|o| !o.is_null()) {
                let image_base = oep
                    .get("BASE")
                    .and_then(Value::as_str)
                    .and_then(parse_hex)
                    .ok_or_else(|| other("oep report missing BASE"))?;
                let oep_addr = oep
                    .get("OEP")
                    .and_then(Value::as_str)
                    .and_then(parse_hex)
                    .ok_or_else(|| other("oep report missing OEP"))?;
                let dotnet = oep.get("DOTNET").and_then(Value::as_bool).unwrap_or(false);
                return Ok(OepEvent {
                    image_base,
                    oep: oep_addr,
                    dotnet,
                });
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        Err(other("timed out waiting for the OEP"))
    }

    pub fn notify_dumping_finished(&self) -> io::Result<()> {
        self.call("notifyDumpingFinished", json!([]))?;
        Ok(())
    }

    fn fetch_exports(&self) -> HashMap<u64, Export> {
        let mut map = HashMap::new();
        if let Ok((Value::Array(items), _)) =
            self.call("enumerateExportedFunctions", json!([self.main_module]))
        {
            for it in items {
                let (Some(addr), Some(name)) = (
                    it.get("address")
                        .and_then(Value::as_str)
                        .and_then(parse_hex),
                    it.get("name").and_then(Value::as_str),
                ) else {
                    continue;
                };
                map.insert(
                    addr,
                    Export {
                        address: addr,
                        name: name.to_string(),
                    },
                );
            }
        }
        map
    }

    fn range_from_json(&self, v: &Value, include_data: bool) -> Option<MemoryRange> {
        let base = v.get("base").and_then(Value::as_str).and_then(parse_hex)?;
        let size = v.get("size").and_then(Value::as_u64)?;
        let protection = v
            .get("protection")
            .and_then(Value::as_str)
            .unwrap_or("---")
            .to_string();
        let mut range = MemoryRange {
            base,
            size,
            protection,
            data: None,
        };
        if include_data {
            range.data = self.read_process_memory(base, size as usize).ok();
        }
        Some(range)
    }
}

impl ProcessController for SocketController {
    fn architecture(&self) -> Architecture {
        self.arch
    }
    fn pointer_size(&self) -> usize {
        self.pointer_size
    }
    fn page_size(&self) -> usize {
        self.page_size
    }
    fn main_module_name(&self) -> &str {
        &self.main_module
    }

    fn find_module_by_address(&self, address: u64) -> Option<String> {
        let (v, _) = self
            .call("findModuleByAddress", json!([format!("{address:#x}")]))
            .ok()?;
        v.get("name").and_then(Value::as_str).map(str::to_string)
    }

    fn find_range_by_address(&self, address: u64, include_data: bool) -> Option<MemoryRange> {
        let (v, _) = self
            .call("findRangeByAddress", json!([format!("{address:#x}")]))
            .ok()?;
        if v.is_null() {
            return None;
        }
        self.range_from_json(&v, include_data)
    }

    fn find_export_by_name(&self, module: &str, export: &str) -> Option<u64> {
        let (v, _) = self
            .call("findExportByName", json!([module, export]))
            .ok()?;
        v.as_str().and_then(parse_hex)
    }

    fn enumerate_modules(&self) -> Vec<String> {
        match self.call("enumerateModules", json!([])) {
            Ok((Value::Array(a), _)) => a
                .into_iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect(),
            _ => Vec::new(),
        }
    }

    fn enumerate_module_ranges(&self, module: &str, include_data: bool) -> Vec<MemoryRange> {
        match self.call("enumerateModuleRanges", json!([module])) {
            Ok((Value::Array(a), _)) => a
                .iter()
                .filter_map(|v| self.range_from_json(v, include_data))
                .collect(),
            _ => Vec::new(),
        }
    }

    fn enumerate_exported_functions(&self) -> &HashMap<u64, Export> {
        self.exports_cache.get_or_init(|| self.fetch_exports())
    }

    fn query_memory_protection(&self, address: u64) -> Option<String> {
        let (v, _) = self
            .call("queryMemoryProtection", json!([format!("{address:#x}")]))
            .ok()?;
        v.as_str().map(str::to_string)
    }

    fn set_memory_protection(&self, address: u64, size: u64, protection: &str) -> bool {
        matches!(
            self.call(
                "setMemoryProtection",
                json!([format!("{address:#x}"), size, protection]),
            ),
            Ok((Value::Bool(true), _))
        )
    }

    fn read_process_memory(&self, address: u64, size: usize) -> io::Result<Vec<u8>> {
        let mut out = Vec::with_capacity(size);
        let mut offset = 0usize;
        while offset < size {
            let chunk = MAX_CHUNK.min(size - offset);
            let (_, data) = self.call(
                "readProcessMemory",
                json!([format!("{:#x}", address + offset as u64), chunk]),
            )?;
            let bytes = data.ok_or_else(|| other("readProcessMemory returned no data"))?;
            if bytes.len() != chunk {
                return Err(other("short read from the target"));
            }
            out.extend_from_slice(&bytes);
            offset += chunk;
        }
        Ok(out)
    }

    fn write_process_memory(&self, address: u64, data: &[u8]) -> io::Result<()> {
        let bytes: Vec<Value> = data.iter().map(|&b| json!(b)).collect();
        self.call(
            "writeProcessMemory",
            json!([format!("{address:#x}"), bytes]),
        )?;
        Ok(())
    }

    fn main_module_ranges(&self) -> Vec<MemoryRange> {
        self.main_ranges_cache
            .get_or_init(|| self.enumerate_module_ranges(&self.main_module, false))
            .clone()
    }
}
