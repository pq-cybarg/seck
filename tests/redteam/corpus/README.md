# Red-team corpus

Payloads that attempt to subvert `seck`'s analysis. Plan 06 wires these into the auditor pass; Plan 14 expands the corpus and credits public sources (OWASP LLM Top 10, PromptInject, Lakera Gandalf, Garak).

Each `.txt` file should be paired with a `.meta.toml` in Plan 14 describing:
- `source`: where it came from
- `expected_behavior`: `ignore` or `flag`
- `failure_markers`: substrings that, if present in LLM output, indicate the model followed the payload

Plan 01 ships only the seed payloads, no metadata.
