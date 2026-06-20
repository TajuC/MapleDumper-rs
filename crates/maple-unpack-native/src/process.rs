//! The process abstraction the dumper drives, mirroring unlicense's `ProcessController` ABC.
//!
//! The live implementation ([`crate::rpc::FridaController`]) backs these calls with Frida RPCs
//! into the spawned process; [`MockController`] backs them with in-memory fixtures so the import
//! scanning and emulation logic can be unit tested without a live target.

use std::collections::HashMap;
use std::io;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Architecture {
    X86_32,
    X86_64,
}

impl Architecture {
    pub fn pointer_size(self) -> usize {
        match self {
            Architecture::X86_32 => 4,
            Architecture::X86_64 => 8,
        }
    }
}

/// A contiguous mapped region. `data`, when present, is a snapshot of the region's bytes.
#[derive(Clone, Debug)]
pub struct MemoryRange {
    pub base: u64,
    pub size: u64,
    pub protection: String,
    pub data: Option<Vec<u8>>,
}

impl MemoryRange {
    pub fn new(base: u64, size: u64, protection: impl Into<String>) -> Self {
        Self {
            base,
            size,
            protection: protection.into(),
            data: None,
        }
    }

    pub fn contains(&self, addr: u64) -> bool {
        self.base <= addr && addr < self.base + self.size
    }
}

/// An exported function: its resolved address and name.
#[derive(Clone, Debug)]
pub struct Export {
    pub address: u64,
    pub name: String,
}

/// Read/inspect/patch the target process. Every method takes `&self`; the live implementation
/// holds the mutable Frida channel behind interior mutability so the emulation hooks can borrow
/// the controller while the engine runs.
pub trait ProcessController {
    fn architecture(&self) -> Architecture;
    fn pointer_size(&self) -> usize;
    fn page_size(&self) -> usize;
    fn main_module_name(&self) -> &str;

    fn find_module_by_address(&self, address: u64) -> Option<String>;
    fn find_range_by_address(&self, address: u64, include_data: bool) -> Option<MemoryRange>;
    fn find_export_by_name(&self, module: &str, export: &str) -> Option<u64>;
    fn enumerate_modules(&self) -> Vec<String>;
    fn enumerate_module_ranges(&self, module: &str, include_data: bool) -> Vec<MemoryRange>;
    /// Address -> export, for every module other than the one being dumped. Cached by the live
    /// implementation since the emulation block hook consults it on every basic block.
    fn enumerate_exported_functions(&self) -> &HashMap<u64, Export>;

    fn query_memory_protection(&self, address: u64) -> Option<String>;
    fn set_memory_protection(&self, address: u64, size: u64, protection: &str) -> bool;
    fn read_process_memory(&self, address: u64, size: usize) -> io::Result<Vec<u8>>;
    fn write_process_memory(&self, address: u64, data: &[u8]) -> io::Result<()>;

    fn main_module_ranges(&self) -> Vec<MemoryRange>;
}

/// Pointer-pack helper shared by import scanning and emulation.
pub fn pack_ptr(pointer_size: usize, value: u64) -> Vec<u8> {
    match pointer_size {
        4 => (value as u32).to_le_bytes().to_vec(),
        _ => value.to_le_bytes().to_vec(),
    }
}

/// Pointer-unpack helper shared by import scanning and emulation.
pub fn unpack_ptr(pointer_size: usize, bytes: &[u8]) -> u64 {
    match pointer_size {
        4 => u32::from_le_bytes(bytes[..4].try_into().unwrap()) as u64,
        _ => u64::from_le_bytes(bytes[..8].try_into().unwrap()),
    }
}

#[cfg(test)]
pub mod mock {
    use super::*;

    /// A mapped region of bytes for the mock target's address space.
    #[derive(Clone)]
    pub struct Mapping {
        pub base: u64,
        pub bytes: Vec<u8>,
        pub protection: String,
    }

    /// A scriptable [`ProcessController`] over in-memory fixtures, for unit tests.
    pub struct MockController {
        pub arch: Architecture,
        pub page_size: usize,
        pub main_module: String,
        pub mappings: Vec<Mapping>,
        pub modules: HashMap<String, Vec<MemoryRange>>,
        pub exports: HashMap<u64, Export>,
        pub main_ranges: Vec<MemoryRange>,
    }

    impl MockController {
        pub fn new(arch: Architecture) -> Self {
            Self {
                arch,
                page_size: 0x1000,
                main_module: "target.exe".to_string(),
                mappings: Vec::new(),
                modules: HashMap::new(),
                exports: HashMap::new(),
                main_ranges: Vec::new(),
            }
        }

        pub fn map(&mut self, base: u64, bytes: Vec<u8>, protection: &str) {
            self.mappings.push(Mapping {
                base,
                bytes,
                protection: protection.to_string(),
            });
        }

        pub fn add_export(&mut self, address: u64, name: &str) {
            self.exports.insert(
                address,
                Export {
                    address,
                    name: name.to_string(),
                },
            );
        }

        fn mapping_at(&self, address: u64) -> Option<&Mapping> {
            self.mappings
                .iter()
                .find(|m| address >= m.base && address < m.base + m.bytes.len() as u64)
        }
    }

    impl ProcessController for MockController {
        fn architecture(&self) -> Architecture {
            self.arch
        }
        fn pointer_size(&self) -> usize {
            self.arch.pointer_size()
        }
        fn page_size(&self) -> usize {
            self.page_size
        }
        fn main_module_name(&self) -> &str {
            &self.main_module
        }

        fn find_module_by_address(&self, address: u64) -> Option<String> {
            for (name, ranges) in &self.modules {
                if ranges.iter().any(|r| r.contains(address)) {
                    return Some(name.clone());
                }
            }
            None
        }

        fn find_range_by_address(&self, address: u64, include_data: bool) -> Option<MemoryRange> {
            let m = self.mapping_at(address)?;
            let mut range = MemoryRange::new(m.base, m.bytes.len() as u64, m.protection.clone());
            if include_data {
                range.data = Some(m.bytes.clone());
            }
            Some(range)
        }

        fn find_export_by_name(&self, _module: &str, export: &str) -> Option<u64> {
            self.exports
                .values()
                .find(|e| e.name == export)
                .map(|e| e.address)
        }

        fn enumerate_modules(&self) -> Vec<String> {
            self.modules.keys().cloned().collect()
        }

        fn enumerate_module_ranges(&self, module: &str, _include_data: bool) -> Vec<MemoryRange> {
            self.modules.get(module).cloned().unwrap_or_default()
        }

        fn enumerate_exported_functions(&self) -> &HashMap<u64, Export> {
            &self.exports
        }

        fn query_memory_protection(&self, address: u64) -> Option<String> {
            self.mapping_at(address).map(|m| m.protection.clone())
        }

        fn set_memory_protection(&self, _address: u64, _size: u64, _protection: &str) -> bool {
            true
        }

        fn read_process_memory(&self, address: u64, size: usize) -> io::Result<Vec<u8>> {
            let m = self
                .mapping_at(address)
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "unmapped read"))?;
            let off = (address - m.base) as usize;
            let end = off
                .checked_add(size)
                .filter(|&e| e <= m.bytes.len())
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "read past region"))?;
            Ok(m.bytes[off..end].to_vec())
        }

        fn write_process_memory(&self, _address: u64, _data: &[u8]) -> io::Result<()> {
            Ok(())
        }

        fn main_module_ranges(&self) -> Vec<MemoryRange> {
            self.main_ranges.clone()
        }
    }
}
