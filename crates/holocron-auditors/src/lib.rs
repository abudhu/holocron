//! Holocron's external-tool auditors. Each module wraps one CLI tool
//! and exposes a struct implementing [`holocron_core::Auditor`].
//!
//! See `OneDev` issues #4–#7 for the per-auditor design notes.

pub mod clippy;
pub mod machete;
pub mod rust_code_analysis;
pub mod rustsec;

pub use clippy::ClippyAuditor;
pub use machete::MacheteAuditor;
pub use rust_code_analysis::{ComplexityAuditor, ComplexityThresholds};
pub use rustsec::RustSecAuditor;

use std::sync::Arc;

/// The default v0.1 auditor set. Returned as `Arc<dyn Auditor>` so the
/// runner can hold them without further plumbing.
#[must_use]
pub fn default_set() -> Vec<Arc<dyn holocron_core::Auditor>> {
    vec![
        Arc::new(ClippyAuditor { extra_warn_flags: vec![] }),
        Arc::new(RustSecAuditor),
        Arc::new(MacheteAuditor),
        Arc::new(ComplexityAuditor { thresholds: ComplexityThresholds::default() }),
    ]
}
