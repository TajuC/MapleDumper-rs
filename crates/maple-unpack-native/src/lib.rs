//! Native Themida/WinLicense 3.x dumper for MapleDumper-rs.
//!
//! A Rust port of ergrelet/unlicense (GPL-3.0): a Frida agent finds the original entry point and
//! exposes the target's memory, Unicorn emulation resolves the obfuscated import wrappers, and a
//! native PE rebuild assembles the dump. The static clean + verification stay in
//! `maple-core::unpack`; this crate replaces only the dynamic dump step.

pub mod agent;
pub mod driver;
pub mod emulate;
pub mod imports;
pub mod pe_build;
pub mod process;
pub mod rpc;
pub mod version;

#[cfg(test)]
mod real_validation;

pub use driver::{DumpReport, Progress, StderrProgress, dump_packed};
pub use version::{PackerVersion, detect};
