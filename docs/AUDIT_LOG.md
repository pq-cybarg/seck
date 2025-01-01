# Audit log

`seck` writes a tamper-evident, hash-chained, ML-DSA-signed audit log to:

```
$XDG_DATA_HOME/seck/audit/YYYY-MM-DD.jsonl
```

(default: `~/.local/share/seck/audit/`).

## Format

Each line is one JSON `Record`:

```json
{
  "timestamp":            "RFC-3339 UTC",
  "event":                "<event-type>",
  "fields":               { "<key>": "<string>", ... },
  "prev_sha3_256":        "64 hex chars — SHA3-256 of the previous record's body, or 0×64 for genesis",
  "this_sha3_256":        "64 hex chars — SHA3-256 of THIS record's body",
  "ml_dsa_signature_hex": "hex — ML-DSA-65 signature over THIS record's body"
}
```

The "body" hashed/signed is the canonical JSON:

```json
{
  "timestamp": ...,
  "event":     ...,
  "fields":    ...,
  "prev_sha3_256": ...
}
```

## Properties

1. **Hash chain.** Each record's `prev_sha3_256` is the previous record's `this_sha3_256`. Any tampered record breaks the chain.
2. **Per-record signature.** ML-DSA-65 signature over the body proves the record was emitted by the holder of the device secret key — mutated records won't re-verify.
3. **Hashes only, never content.** The `fields` map stores SHA3-256 of inputs, not the inputs themselves. File contents are never written to the audit log.
4. **Mode 0600.** The log file is created with read/write for owner only.

## CLI

```sh
seck audit init               # first run: writes salt + device.pk + device.sk to $XDG_DATA_HOME/seck/keys/
seck audit verify             # walks today's log and verifies every chain link + signature
seck audit verify --day 2026-05-21
seck audit tip                # prints today's chain tip SHA3-256 without re-verifying
```

## Threat coverage

- A forensic auditor inheriting the log can detect any tampering (chain or signature).
- A compromise of the device secret key invalidates future entries but the chain history up to compromise is still cryptographically anchored.
- An auditor with only the public key can verify any past chain — no secret is needed for verification.

## Tested

`crates/seck-audit/tests/chain.rs`:
- `write_then_verify` — writes two records, verifies the whole chain.
- `tampered_record_breaks_chain` — mutates one record, asserts verify fails.
- `empty_log_returns_genesis_tip` — empty file returns the `0×64` genesis tip.
