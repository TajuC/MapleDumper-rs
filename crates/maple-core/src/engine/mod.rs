pub use profile::{ProfileReport, profile};
pub(crate) use scan::read_range;
pub use scan::{scan, scan_in};
pub use types::{PatternRow, ReadGap, ScanResult, read_gap_warning};

mod profile;
mod scan;
mod types;
