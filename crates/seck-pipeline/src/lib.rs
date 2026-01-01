//! Three-pass pipeline: analyst → auditor (×2 in paranoid mode) → judge.
//! Per-pass deterministic seeds derived from SHA3-256(invocation_nonce || role_tag).

pub mod analyst;
pub mod auditor;
pub mod judge;
pub mod seed;

use seck_plugin::{InferenceConfig, LlmBackend};

pub use seed::{PassRole, derive_pass_seed};

#[derive(Debug, Clone, Copy)]
pub struct PipelineConfig {
    pub paranoid: bool,
    pub lenient: bool,
}

pub struct PipelineResult {
    pub analyst_raw: String,
    pub auditor_passed: bool,
    pub auditor_flags: Vec<String>,
    pub auditor_raw: String,
    pub judge_verdict: String,
    pub judge_raw: String,
    pub findings_json: serde_json::Value,
    pub analyst_surfaced_raw: bool,
}

pub fn run(
    backend: &mut dyn LlmBackend,
    cfg: &InferenceConfig,
    nonce: &[u8; 32],
    prompt_for_analyst: &str,
    pcfg: PipelineConfig,
) -> Result<PipelineResult, anyhow::Error> {
    // 1. Analyst.
    let analyst = analyst::run(backend, cfg, nonce, prompt_for_analyst)?;

    // 2. Output-schema check (retry once with tighter prompt on failure).
    let (findings_json, surfaced_raw) =
        match serde_json::from_str::<serde_json::Value>(&analyst.raw) {
            Ok(v) if has_findings_array(&v) => (v, false),
            _ => {
                let tighter = format!(
                    "{prompt_for_analyst}\n\nIMPORTANT: Your previous response was not valid JSON \
                 matching the required schema. Output ONLY valid JSON, nothing else, with a \
                 'findings' array."
                );
                let retry = analyst::run(backend, cfg, nonce, &tighter)?;
                match serde_json::from_str::<serde_json::Value>(&retry.raw) {
                    Ok(v) if has_findings_array(&v) => (v, false),
                    _ => (serde_json::json!({"raw": retry.raw}), true),
                }
            }
        };

    if pcfg.lenient {
        return Ok(PipelineResult {
            analyst_raw: analyst.raw,
            auditor_passed: true,
            auditor_flags: vec![],
            auditor_raw: "(skipped: lenient mode)".into(),
            judge_verdict: "skipped".into(),
            judge_raw: "(skipped: lenient mode)".into(),
            findings_json,
            analyst_surfaced_raw: surfaced_raw,
        });
    }

    // 3. Auditor (and a second auditor in paranoid mode).
    let aud1 = auditor::run(backend, cfg, nonce, PassRole::Auditor, &analyst.raw)?;
    let combined_auditor = if pcfg.paranoid {
        let aud2 = auditor::run(backend, cfg, nonce, PassRole::AuditorParanoid, &analyst.raw)?;
        let agreement = aud1.passed == aud2.passed;
        let mut flags = aud1.flags.clone();
        flags.extend(aud2.flags);
        let raw = format!("--- pass1 ---\n{}\n--- pass2 ---\n{}", aud1.raw, aud2.raw);
        auditor::AuditorOutput {
            passed: agreement && aud1.passed,
            flags,
            raw,
        }
    } else {
        aud1
    };

    // 4. Judge.
    let judge_out = judge::run(backend, cfg, nonce, &analyst.raw, &combined_auditor.raw)?;

    Ok(PipelineResult {
        analyst_raw: analyst.raw,
        auditor_passed: combined_auditor.passed,
        auditor_flags: combined_auditor.flags,
        auditor_raw: combined_auditor.raw,
        judge_verdict: judge_out.verdict,
        judge_raw: judge_out.raw,
        findings_json,
        analyst_surfaced_raw: surfaced_raw,
    })
}

fn has_findings_array(v: &serde_json::Value) -> bool {
    v.get("findings").is_some_and(|f| f.is_array())
}

pub fn raw_sha3(s: &str) -> String {
    hex::encode(seck_crypto::hash::sha3_256(s.as_bytes()))
}
