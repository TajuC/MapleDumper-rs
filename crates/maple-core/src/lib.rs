pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub mod categorizer;
pub mod engine;
pub mod memory;
pub mod output;
pub mod pattern;
pub mod resolver;
pub mod scanner;

#[cfg(windows)]
pub mod process;

pub use engine::{PatternRow, ScanResult, Status, scan};
pub use memory::{MemorySource, Region};
pub use output::Finding;
pub use pattern::{Arch, Pattern, Signature};
pub use resolver::Kind;
pub use scanner::{CompiledPattern, find_all};

#[cfg(windows)]
pub use process::{AttachOptions, Locator, Target};
