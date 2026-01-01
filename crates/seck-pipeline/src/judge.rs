use crate::seed::{PassRole, derive_pass_seed};
use seck_plugin::{InferenceConfig, LlmBackend};

const JUDGE_PROMPT: &str = "You will see two outputs:\n\nANALYST OUTPUT:\n---\n{ANALYST}\n\
---\n\nAUDITOR OUTPUT:\n---\n{AUDITOR}\n---\n\nDecide: do the two outputs agree on the \
behavior of the analyzed files? Answer the first line with exactly one word from \
{agreement, disagreement, escalate}. On the second line, give a one-sentence justification.";

pub struct JudgeOutput {
    pub verdict: String,
    pub justification: String,
    pub raw: String,
}

pub fn run(
    backend: &mut dyn LlmBackend,
    cfg: &InferenceConfig,
    nonce: &[u8; 32],
    analyst: &str,
    auditor: &str,
) -> Result<JudgeOutput, anyhow::Error> {
    let seed = derive_pass_seed(nonce, PassRole::Judge);
    let mut local = cfg.clone();
    local.seed = seed;
    local.temperature = 0.0;
    backend.load(&local)?;
    let prompt = JUDGE_PROMPT
        .replace("{ANALYST}", analyst)
        .replace("{AUDITOR}", auditor);
    let raw = backend.generate(&prompt)?;
    let first = raw.lines().next().unwrap_or("").trim().to_lowercase();
    let verdict = if first.contains("agree") && !first.contains("dis") {
        "agreement"
    } else if first.contains("disag") {
        "disagreement"
    } else {
        "escalate"
    }
    .to_string();
    let justification = raw.lines().nth(1).unwrap_or("").trim().to_string();
    Ok(JudgeOutput {
        verdict,
        justification,
        raw,
    })
}
