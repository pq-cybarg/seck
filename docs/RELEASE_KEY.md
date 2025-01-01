# Release key management

Releases are signed with **SLH-DSA-SHAKE-128s** (NIST FIPS 205) keypairs.
Hash-based, conservative, no number-theoretic assumptions — safe against
both classical and quantum cryptanalysis.

## Procedure

1. **Generation** runs on an air-gapped machine. Never on CI.
   ```
   # On the air-gapped machine, with seck-crypto compiled offline:
   cargo run -p seck-release-sign -- --help   # just to confirm
   # Manual generation (one-off script using seck_crypto::sign::slh_dsa_keypair):
   echo 'use seck_crypto::sign::slh_dsa_keypair; let (pk,sk)=slh_dsa_keypair(); std::fs::write("release.pk", &pk).unwrap(); std::fs::write("release.sk", &sk).unwrap();' \
     | rustc --edition=2024 - && ./rust_out
   ```

2. **Secret-key storage:** the resulting `release.sk` is encrypted with
   XChaCha20-Poly1305 (key derived from a passphrase via Argon2id) and
   stored on a removable medium kept physically separated from the
   release machine.

3. **CI never sees the raw key.** The `SECK_RELEASE_SK_B64` GitHub
   secret references a wrapper that decrypts the key into tmpfs on the
   runner, signs, then `shred`s the tmpfs file. (`release.yml` does the
   shred in its last step.)

4. **Public key distribution:**
   - Embedded base64 in `scripts/install.sh` (`SECK_RELEASE_PUBKEY_BASE64`).
   - Published as `release.pk.txt` on the GitHub release page.
   - Mirrored at `https://seck-project.github.io/release.pk.txt`.
   - SHA3-256 fingerprint of the public key is announced in the release
     notes; install.sh embeds the same value as a defense-in-depth check.

5. **Rotation:** annual. Old public keys remain valid for verifying
   older releases. install.sh ships the union of all valid keys.

## Public key fingerprint (SHA3-256 of the public key bytes)

```
REPLACE_AT_FIRST_RELEASE
```

This file's `REPLACE_AT_FIRST_RELEASE` placeholder is replaced by a real
fingerprint at first signed release.
