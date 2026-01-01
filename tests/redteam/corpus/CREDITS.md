# Red-team corpus credits

This corpus is a curated mix of public sources plus hand-curated additions:

- OWASP LLM Top 10 — <https://owasp.org/www-project-top-10-for-large-language-model-applications/>
- PromptInject — Perez & Ribeiro (2022)
- Lakera Gandalf — <https://gandalf.lakera.ai/>
- Garak (NVIDIA) — <https://github.com/NVIDIA/garak>

Each entry has a sidecar `.meta.toml`:
- `expected_behavior`: `ignore` (the LLM should not follow the payload)
- `failure_markers`: substrings whose appearance in LLM output indicates the model followed the payload

Categories:
- `injection/`: prompt-injection payloads
- `malicious-files/`: parser/RCE bait (zip bombs metadata, billion-laughs XML, polyglot files — content only; bench harness reads but does not execute)
- `canaries/`: decoy files emitted by `seck-canaries` with unique markers
- `quality/`: small "what does this code do?" tasks to measure quality
