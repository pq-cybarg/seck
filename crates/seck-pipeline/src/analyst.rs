use crate::seed::{PassRole, derive_pass_seed};
use seck_plugin::{InferenceConfig, LlmBackend};

pub struct AnalystOutput {
    pub raw: String,
    pub seed_used: u64,
}

pub fn run(
    backend: &mut dyn LlmBackend,
    cfg: &InferenceConfig,
    nonce: &[u8; 32],
    prompt: &str,
) -> Result<AnalystOutput, anyhow::Error> {
    let seed = derive_pass_seed(nonce, PassRole::Analyst);
    let mut local = cfg.clone();
    local.seed = seed;
    local.temperature = 0.0;
    backend.load(&local)?;
    let raw = backend.generate(prompt)?;
    Ok(AnalystOutput {
        raw,
        seed_used: seed,
    })
}
