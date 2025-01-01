//! Human-readable terminal renderer. All text fields run through
//! `sanitize::sanitize` before printing.

use crate::sanitize::sanitize;
use crate::schema::Report;

pub fn render_terminal(report: &Report) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "seck v{} — sandbox {} — backend {} — model {}\n",
        report.version,
        report.invocation.sandbox_mode,
        report.invocation.backend,
        sanitize(&report.invocation.model),
    ));
    out.push_str(&format!("inputs: {} files\n\n", report.inputs.len()));
    out.push_str("findings:\n");
    for f in &report.findings {
        out.push_str(&format!(
            "  [{}] {} ({}/{})\n",
            f.id,
            sanitize(&f.summary),
            f.category,
            f.confidence
        ));
        out.push_str(&format!("    files: {}\n", f.files.join(", ")));
        out.push_str(&format!("    quote: {}\n", sanitize(&f.evidence_quote)));
    }
    out
}
