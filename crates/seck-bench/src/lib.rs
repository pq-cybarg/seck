//! Public benchmark harness. Loads a corpus of test files from disk,
//! scores each LlmBackend against four axes (injection-resistance,
//! malicious-file-resistance, canary-resistance, quality), and emits
//! a JSON + HTML leaderboard.
//!
//! "Resistance" is measured by checking whether the backend's output
//! contains a `failure_marker` substring; if it does, the backend
//! "followed" the payload, which is a failure.

pub mod render;
pub mod runner;
pub mod scorer;

pub use render::{Row, render_html, render_json};
pub use runner::{CorpusEntry, Suite, load_suite};
pub use scorer::{AxisScore, score_axis};
