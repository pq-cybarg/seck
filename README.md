# seck

Sandboxed-LLM file/project analyzer. Plan 01 MVP: Linux + llama.cpp.

See:
- `docs/superpowers/specs/2026-05-19-seck-sandboxed-llm-analyzer-design.md` — full design
- `docs/superpowers/plans/` — implementation plans 01–17

## Quick start (Plan 01 scope)

```sh
cargo build --release --bin seck
./target/release/seck analyze ./README.md
```

Runtime requires Linux ≥ 5.13 (Landlock) for the sandbox; macOS sandbox is added in Plan 02.

## Security

See `SECURITY.md` and `docs/THREAT_MODEL.md`.
