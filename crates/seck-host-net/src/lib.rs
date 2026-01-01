//! The ONLY crate in seck that holds TLS / network code. Quarantined here
//! so a CI grep can refuse any dependency on this crate from the
//! analysis-path crates (seck-host, seck-reader, seck-sandbox).

pub mod download;
pub mod pin;
