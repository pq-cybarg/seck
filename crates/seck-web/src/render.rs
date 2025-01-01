//! Server-side rendering. All text from the report runs through
//! `seck-report::sanitize` and then through HTML escaping.

use html_escape::encode_text;
use seck_report::{sanitize::sanitize, schema::Report};

fn safe(s: &str) -> String {
    encode_text(&sanitize(s)).into_owned()
}

pub fn render(report: &Report) -> String {
    let mut s = String::new();
    s.push_str(
        r#"<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><title>seck — report</title>
<style>
  body { font: 14px/1.5 -apple-system, system-ui, sans-serif; max-width: 60rem; margin: 2rem auto; padding: 0 1rem; }
  h1 { font-size: 1.4rem; } h2 { font-size: 1.1rem; margin-top: 2rem; }
  .finding { border: 1px solid #ddd; border-radius: 6px; padding: 1rem; margin: 1rem 0; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 0.8rem; background: #eee; }
  pre { white-space: pre-wrap; background: #f6f6f6; padding: 0.5rem; }
  code { font-family: ui-monospace, Menlo, monospace; }
</style></head><body>
"#,
    );
    s.push_str(&format!(
        "<h1>seck report — {}</h1>\n",
        safe(&report.invocation.model)
    ));
    s.push_str(&format!(
        "<p>sandbox: <code>{}</code> · backend: <code>{}</code> · {}</p>\n",
        safe(&report.invocation.sandbox_mode),
        safe(&report.invocation.backend),
        if report.invocation.deterministic {
            "deterministic"
        } else {
            "non-deterministic"
        }
    ));
    s.push_str(&format!("<h2>Inputs ({})</h2>\n<ul>", report.inputs.len()));
    for i in &report.inputs {
        s.push_str(&format!(
            "<li>{} <code>{}</code> ({} bytes)</li>",
            safe(&i.path),
            safe(&i.sha3_256),
            i.size
        ));
    }
    s.push_str("</ul>\n");
    s.push_str("<h2>Findings</h2>\n");
    for f in &report.findings {
        s.push_str(&format!(
            r#"<div class="finding"><strong>[{}]</strong> {}<p><span class="badge">{}</span> <span class="badge">{}</span></p><pre>{}</pre></div>"#,
            safe(&f.id),
            safe(&f.summary),
            safe(&f.category),
            safe(&f.confidence),
            safe(&f.evidence_quote),
        ));
    }
    s.push_str("</body></html>\n");
    s
}
