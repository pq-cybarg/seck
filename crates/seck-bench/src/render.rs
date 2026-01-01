use crate::scorer::AxisScore;
use html_escape::encode_text;
use serde::Serialize;

#[derive(Debug, Serialize, Clone)]
pub struct Row {
    pub backend: String,
    pub model: String,
    pub injection: AxisScore,
    pub malicious: AxisScore,
    pub canary: AxisScore,
    pub quality: AxisScore,
}

pub fn render_json(rows: &[Row]) -> String {
    serde_json::to_string_pretty(rows).unwrap_or_else(|_| "[]".into())
}

pub fn render_html(rows: &[Row]) -> String {
    let mut s = String::from(
        r#"<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><title>seck bench</title>
<style>
  body { font: 14px/1.5 system-ui, sans-serif; max-width: 60rem; margin: 2rem auto; padding: 0 1rem; }
  table { border-collapse: collapse; width: 100%; }
  th, td { border: 1px solid #ccc; padding: 4px 8px; text-align: left; }
  th { background: #f6f6f6; }
</style></head><body>
<h1>seck bench leaderboard</h1>
<table><tr><th>Backend</th><th>Model</th><th>Injection</th><th>Malicious</th><th>Canary</th><th>Quality</th></tr>
"#,
    );
    for r in rows {
        s.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{} / {}</td><td>{} / {}</td><td>{} / {}</td><td>{} / {}</td></tr>",
            encode_text(&r.backend),
            encode_text(&r.model),
            r.injection.passed, r.injection.total,
            r.malicious.passed, r.malicious.total,
            r.canary.passed, r.canary.total,
            r.quality.passed, r.quality.total,
        ));
    }
    s.push_str("</table></body></html>\n");
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row() -> Row {
        Row {
            backend: "stub".into(),
            model: "(none)".into(),
            injection: AxisScore {
                total: 5,
                passed: 5,
                failed: 0,
                failure_examples: vec![],
            },
            malicious: AxisScore::default(),
            canary: AxisScore::default(),
            quality: AxisScore::default(),
        }
    }

    #[test]
    fn html_has_no_script_or_js_url() {
        let h = render_html(&[row()]);
        assert!(!h.contains("<script"));
        assert!(!h.contains("javascript:"));
    }

    #[test]
    fn html_escapes_evil_backend_name() {
        let mut r = row();
        r.backend = "<script>alert(1)</script>".into();
        let h = render_html(&[r]);
        assert!(!h.contains("<script>alert"), "injection NOT rendered raw");
        assert!(h.contains("&lt;script&gt;"));
    }

    #[test]
    fn json_round_trips() {
        let s = render_json(&[row()]);
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert!(v.is_array());
    }
}
