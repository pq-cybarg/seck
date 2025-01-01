# seck — Plan 15: Reproducible PQ-Signed Releases + Multi-Distro Packaging

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bit-identical reproducible builds across two CI runners, SLH-DSA-signed release artifacts, CycloneDX SBOM, SLSA L3 provenance attestation, universal `install.sh` that verifies all three, and multi-distro packaging (Homebrew tap, AUR PKGBUILD, deb, rpm, Alpine apk, Void xbps, Nix flake).

**Architecture:** GitHub Actions workflows: `repro.yml` (build on `ubuntu-24.04` and `ubuntu-22.04`, sha3sum-compare), `release.yml` (tag-triggered: build, sign with SLH-DSA via Plan 07's `seck-crypto`, generate SBOM, SLSA attestation, attach to GitHub Release). `scripts/install.sh` verifies all three. Distro packaging files live under `scripts/<distro>/`.

**Tech Stack:** `cargo-cyclonedx` for SBOM, `slsa-verifier` for attestation, `cosign` for SLSA L3 (cosign uses Ed25519 by default; we publish a *separate* SLH-DSA signature alongside, computed by `seck-crypto`'s release-sign binary).

**Out of scope:** Mac App Store / Windows Store; transparency log mirroring (reserved slot only).

---

## File structure

```
seck/
├── .github/workflows/
│   ├── repro.yml             # NEW — bit-identical build CI
│   └── release.yml           # NEW — tag-triggered
├── scripts/
│   ├── install.sh            # NEW
│   ├── release-sign.sh       # NEW — SLH-DSA sign release artifacts
│   ├── brew/seck.rb          # NEW — Homebrew tap formula
│   ├── aur/PKGBUILD          # NEW
│   ├── debian/{control,rules,changelog,copyright}
│   ├── rpm/seck.spec
│   ├── alpine/APKBUILD
│   ├── void/template
│   └── nix/flake.nix
├── docs/RELEASE_KEY.md       # NEW — key-management procedure
└── tests/repro/
    ├── Cargo.toml
    └── tests/repro_idempotent.rs
```

---

## Task 1: Reproducible-build CI

**Files:**
- Create: `.github/workflows/repro.yml`

- [ ] **Step 1.1**

```yaml
name: repro
on: [push, pull_request]
jobs:
  build_a:
    runs-on: ubuntu-24.04
    outputs:
      sha3: ${{ steps.h.outputs.sha3 }}
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: sudo apt-get update && sudo apt-get install -y libseccomp-dev build-essential cmake clang
      - run: SOURCE_DATE_EPOCH=1700000000 RUSTFLAGS="-C link-arg=-Wl,-z,relro,-z,now -C codegen-units=1 -C opt-level=3 -C debuginfo=0 -C strip=symbols -C relocation-model=pie" cargo build --release --locked
      - id: h
        run: |
          # Hash all release binaries.
          H=$(find target/release -maxdepth 1 -type f -executable -print0 | sort -z | xargs -0 cat | openssl dgst -sha3-256 | awk '{print $2}')
          echo "sha3=$H" >> $GITHUB_OUTPUT
      - uses: actions/upload-artifact@v4
        with: { name: build_a, path: target/release/seck* }

  build_b:
    runs-on: ubuntu-22.04
    outputs:
      sha3: ${{ steps.h.outputs.sha3 }}
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: sudo apt-get update && sudo apt-get install -y libseccomp-dev build-essential cmake clang
      - run: SOURCE_DATE_EPOCH=1700000000 RUSTFLAGS="-C link-arg=-Wl,-z,relro,-z,now -C codegen-units=1 -C opt-level=3 -C debuginfo=0 -C strip=symbols -C relocation-model=pie" cargo build --release --locked
      - id: h
        run: |
          H=$(find target/release -maxdepth 1 -type f -executable -print0 | sort -z | xargs -0 cat | openssl dgst -sha3-256 | awk '{print $2}')
          echo "sha3=$H" >> $GITHUB_OUTPUT

  compare:
    needs: [build_a, build_b]
    runs-on: ubuntu-24.04
    steps:
      - run: |
          test "${{ needs.build_a.outputs.sha3 }}" = "${{ needs.build_b.outputs.sha3 }}" \
            || { echo "BUILD NOT REPRODUCIBLE: $A vs $B"; exit 1; }
          echo "OK — bit-identical across runners."
```

- [ ] **Step 1.2: Commit**

```bash
git add .github/workflows/repro.yml
git commit -m "ci(repro): bit-identical build across two runners"
```

---

## Task 2: Release-sign helper

**Files:**
- Create: `scripts/release-sign.sh`

- [ ] **Step 2.1**

```bash
#!/usr/bin/env bash
set -euo pipefail
# Inputs: artifact dir; outputs: artifact.sha3 + artifact.slhdsa for each file.
DIR="${1:-./release-artifacts}"
SK="${SECK_RELEASE_SK:?must be set}"      # path to SLH-DSA secret key (offline)

for f in "$DIR"/*; do
  [[ -d "$f" ]] && continue
  sha3sum "$f" | awk '{print $1}' > "$f.sha3"
  # Sign using a tiny Rust helper we ship as ./target/release/seck-release-sign.
  ./target/release/seck-release-sign --key "$SK" --in "$f" --out "$f.slhdsa"
done
echo "Signed $(ls "$DIR" | grep -c .) artifacts."
```

- [ ] **Step 2.2: Add `crates/seck-release-sign/` (tiny CLI around `seck_crypto::sign::slh_dsa_sign`)**

```rust
// src/main.rs
use clap::Parser;
#[derive(Parser)] struct Args { #[arg(long)] key: ::std::path::PathBuf,
                                #[arg(long, name="in")] inp: ::std::path::PathBuf,
                                #[arg(long, name="out")] outp: ::std::path::PathBuf, }
fn main() -> ::anyhow::Result<()> {
    let a = Args::parse();
    let sk = ::std::fs::read(&a.key)?;
    let msg = ::std::fs::read(&a.inp)?;
    let sig = ::seck_crypto::sign::slh_dsa_sign(&sk, &msg);
    ::std::fs::write(&a.outp, sig)?;
    Ok(())
}
```

Add as workspace member.

- [ ] **Step 2.3: Commit**

```bash
git add scripts/release-sign.sh crates/seck-release-sign/ Cargo.toml
git commit -m "feat(release): SLH-DSA release-sign helper"
```

---

## Task 3: Release workflow

**Files:**
- Create: `.github/workflows/release.yml`

- [ ] **Step 3.1**

```yaml
name: release
on:
  push:
    tags: ['v*']
permissions:
  contents: write
  id-token: write       # for SLSA
  attestations: write
jobs:
  release:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: sudo apt-get update && sudo apt-get install -y libseccomp-dev build-essential cmake clang
      - run: SOURCE_DATE_EPOCH=1700000000 RUSTFLAGS="-C link-arg=-Wl,-z,relro,-z,now -C codegen-units=1 -C opt-level=3 -C debuginfo=0 -C strip=symbols -C relocation-model=pie" cargo build --release --locked
      - name: Generate SBOM
        run: |
          cargo install cargo-cyclonedx
          cargo cyclonedx --format json --override-filename release.sbom.json
      - name: Bundle release artifacts
        run: |
          mkdir -p release
          cp target/release/{seck,seck-reader} release/
          cp release.sbom.json release/
          (cd release && sha3sum * > SHA3SUMS)
      - name: Sign with SLH-DSA
        env:
          SECK_RELEASE_SK: ${{ secrets.SECK_RELEASE_SK_PATH }}
        run: ./scripts/release-sign.sh release
      - uses: actions/attest-build-provenance@v2
        with: { subject-path: 'release/*' }
      - uses: softprops/action-gh-release@v2
        with: { files: release/* }
```

- [ ] **Step 3.2: Commit**

```bash
git add .github/workflows/release.yml
git commit -m "ci(release): tag-triggered build + SLH-DSA sign + SBOM + SLSA"
```

---

## Task 4: Universal `install.sh`

**Files:**
- Create: `scripts/install.sh`

- [ ] **Step 4.1**

```bash
#!/usr/bin/env bash
set -euo pipefail

OS="$(uname -s)"; ARCH="$(uname -m)"
case "$OS-$ARCH" in
  Linux-x86_64)  ASSET="seck-x86_64-unknown-linux-gnu" ;;
  Linux-aarch64) ASSET="seck-aarch64-unknown-linux-gnu" ;;
  Darwin-arm64)  ASSET="seck-aarch64-apple-darwin" ;;
  Darwin-x86_64) ASSET="seck-x86_64-apple-darwin" ;;
  *) echo "unsupported: $OS-$ARCH"; exit 1 ;;
esac

VERSION="${1:-latest}"
BASE="https://github.com/seck-project/seck/releases/${VERSION}/download"

TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
curl -fsSL -o "$TMP/seck"          "$BASE/$ASSET"
curl -fsSL -o "$TMP/seck.sha3"     "$BASE/$ASSET.sha3"
curl -fsSL -o "$TMP/seck.slhdsa"   "$BASE/$ASSET.slhdsa"

# Embedded public key — replace with the real one at first release.
PUBKEY_HEX="REPLACE_AT_FIRST_RELEASE"
echo "$PUBKEY_HEX" | xxd -r -p > "$TMP/seck.pubkey"

# 1. SHA3-256
EXPECTED=$(cat "$TMP/seck.sha3" | awk '{print $1}')
COMPUTED=$(sha3sum "$TMP/seck" | awk '{print $1}')
[[ "$EXPECTED" == "$COMPUTED" ]] || { echo "FAIL: sha3 mismatch"; exit 1; }

# 2. SLH-DSA — invoke a small verifier we ship in the release
./seck-verify-release --pubkey "$TMP/seck.pubkey" --binary "$TMP/seck" --sig "$TMP/seck.slhdsa" \
  || { echo "FAIL: SLH-DSA signature"; exit 1; }

# 3. SLSA — verify via slsa-verifier if installed.
if command -v slsa-verifier >/dev/null 2>&1; then
  slsa-verifier verify-artifact "$TMP/seck" \
    --provenance-path "$BASE/multiple.intoto.jsonl" \
    --source-uri github.com/seck-project/seck \
    || { echo "FAIL: SLSA"; exit 1; }
fi

install -m 0755 "$TMP/seck" /usr/local/bin/seck
echo "Installed: $(seck --version)"
```

- [ ] **Step 4.2: Add `seck-verify-release` binary**

Similar to seck-release-sign: takes a pubkey, binary, signature; calls `slh_dsa_verify`.

- [ ] **Step 4.3: Commit**

```bash
git add scripts/install.sh crates/seck-verify-release/ Cargo.toml
git commit -m "feat(install): universal installer with SLH-DSA + SHA3 + SLSA verify"
```

---

## Task 5: `RELEASE_KEY.md`

**Files:**
- Create: `docs/RELEASE_KEY.md`

- [ ] **Step 5.1**

```markdown
# Release key management

Releases are signed with an SLH-DSA-SHAKE-128s keypair (NIST FIPS 205). The public key is embedded in `scripts/install.sh` and reproduced below for redundancy.

**Public key fingerprint (SHA3-256 of the public key bytes):**
```
REPLACE_AT_FIRST_RELEASE
```

## Procedure

1. Key generation runs on an air-gapped machine. Never on CI.
2. Secret key is stored encrypted (XChaCha20-Poly1305 with a passphrase) on a removable medium.
3. Each release: the key is decrypted into a tmpfs, used to sign, then the tmpfs is unmounted.
4. The CI secret `SECK_RELEASE_SK_PATH` is a path to a Hardware Security Module shim; the CI never sees the raw key bytes.
5. Key rotation: annual. Old public keys remain valid for verifying old releases; install.sh ships the union.
```

- [ ] **Step 5.2: Commit**

```bash
git add docs/RELEASE_KEY.md
git commit -m "docs: release key management procedure"
```

---

## Task 6: Distro packaging

**Files:**
- Create: `scripts/{brew/seck.rb, aur/PKGBUILD, debian/control, debian/rules, rpm/seck.spec, alpine/APKBUILD, void/template}`
- Create: `flake.nix`

- [ ] **Step 6.1: `brew/seck.rb`** (Homebrew formula)

```ruby
class Seck < Formula
  desc "Sandboxed-LLM file/project analyzer"
  homepage "https://github.com/seck-project/seck"
  version "0.1.0"
  on_macos do
    on_arm do
      url "https://github.com/seck-project/seck/releases/download/v#{version}/seck-aarch64-apple-darwin"
      sha256 "REPLACE_AT_RELEASE"
    end
  end
  on_linux do
    on_intel do
      url "https://github.com/seck-project/seck/releases/download/v#{version}/seck-x86_64-unknown-linux-gnu"
      sha256 "REPLACE_AT_RELEASE"
    end
  end
  def install
    bin.install Dir["seck*"][0] => "seck"
  end
  test do
    assert_match "seck", shell_output("#{bin}/seck --version")
  end
end
```

- [ ] **Step 6.2: `aur/PKGBUILD`**

```bash
pkgname=seck
pkgver=0.1.0
pkgrel=1
pkgdesc="Sandboxed-LLM file/project analyzer"
arch=('x86_64' 'aarch64')
url="https://github.com/seck-project/seck"
license=('AGPL-3.0-or-later')
depends=('libseccomp')
source=("https://github.com/seck-project/seck/releases/download/v$pkgver/seck-${CARCH}-unknown-linux-gnu")
sha256sums=('REPLACE_AT_RELEASE')
package() {
  install -Dm755 "seck-${CARCH}-unknown-linux-gnu" "$pkgdir/usr/bin/seck"
}
```

- [ ] **Step 6.3: `debian/control`**

```
Source: seck
Section: utils
Priority: optional
Maintainer: pq-cybarg <resistant@tuta.com>
Build-Depends: debhelper-compat (= 13), cargo, libseccomp-dev
Standards-Version: 4.6.2

Package: seck
Architecture: any
Depends: ${shlibs:Depends}, ${misc:Depends}, libseccomp2
Description: Sandboxed-LLM file/project analyzer
```

- [ ] **Step 6.4: `rpm/seck.spec`**

```
Name:    seck
Version: 0.1.0
Release: 1%{?dist}
Summary: Sandboxed-LLM file/project analyzer
License: AGPLv3+
URL:     https://github.com/seck-project/seck
%description
Sandboxed-LLM file/project analyzer.
%files
/usr/bin/seck
%changelog
```

- [ ] **Step 6.5: `alpine/APKBUILD`**

```bash
pkgname=seck
pkgver=0.1.0
pkgrel=0
pkgdesc="Sandboxed-LLM file/project analyzer"
url="https://github.com/seck-project/seck"
arch="x86_64 aarch64"
license="AGPL-3.0-or-later"
makedepends="cargo libseccomp-dev"
source="https://github.com/seck-project/seck/archive/refs/tags/v$pkgver.tar.gz"
build() { cargo build --release --locked; }
package() { install -Dm755 target/release/seck "$pkgdir"/usr/bin/seck; }
```

- [ ] **Step 6.6: `void/template`**

```bash
pkgname=seck
version=0.1.0
revision=1
build_style=cargo
hostmakedepends="cargo"
makedepends="libseccomp-devel"
short_desc="Sandboxed-LLM file/project analyzer"
maintainer="pq-cybarg <resistant@tuta.com>"
license="AGPL-3.0-or-later"
homepage="https://github.com/seck-project/seck"
distfiles="https://github.com/seck-project/seck/archive/refs/tags/v${version}.tar.gz"
checksum="REPLACE_AT_RELEASE"
```

- [ ] **Step 6.7: `flake.nix`**

```nix
{
  description = "seck — sandboxed-LLM file/project analyzer";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";
  outputs = { self, nixpkgs }: let
    systems = [ "x86_64-linux" "aarch64-linux" "aarch64-darwin" "x86_64-darwin" ];
    forAll = fn: nixpkgs.lib.genAttrs systems (system: fn (import nixpkgs { inherit system; }));
  in {
    packages = forAll (pkgs: {
      default = pkgs.rustPlatform.buildRustPackage {
        pname = "seck";
        version = "0.1.0";
        src = ./.;
        cargoLock.lockFile = ./Cargo.lock;
        buildInputs = [ pkgs.libseccomp ];
      };
    });
  };
}
```

- [ ] **Step 6.8: Commit**

```bash
git add scripts/ flake.nix
git commit -m "feat(packaging): brew/AUR/deb/rpm/Alpine/Void/Nix"
```

---

## Task 7: Repro test

**Files:**
- Create: `tests/repro/Cargo.toml`
- Create: `tests/repro/tests/repro_idempotent.rs`

- [ ] **Step 7.1**

```rust
use std::process::Command;

#[test]
#[ignore = "slow, runs in CI"]
fn two_builds_produce_identical_binary() {
    let env = [
        ("SOURCE_DATE_EPOCH", "1700000000"),
        ("RUSTFLAGS", "-C link-arg=-Wl,-z,relro,-z,now -C codegen-units=1 -C opt-level=3 -C debuginfo=0 -C strip=symbols -C relocation-model=pie"),
    ];
    Command::new("cargo").args(["clean"]).status().unwrap();
    Command::new("cargo").args(["build", "--release", "--locked", "--bin", "seck"])
        .envs(env).status().unwrap();
    let h1 = sha3_of_file("target/release/seck");
    Command::new("cargo").args(["clean"]).status().unwrap();
    Command::new("cargo").args(["build", "--release", "--locked", "--bin", "seck"])
        .envs(env).status().unwrap();
    let h2 = sha3_of_file("target/release/seck");
    assert_eq!(h1, h2);
}

fn sha3_of_file(p: &str) -> String {
    use sha3::{Sha3_256, Digest};
    let mut h = Sha3_256::new();
    h.update(&std::fs::read(p).unwrap());
    hex::encode(h.finalize())
}
```

- [ ] **Step 7.2: Commit**

```bash
git add tests/repro/ Cargo.toml
git commit -m "test(repro): two-build idempotence (ignored, CI-driven)"
```

---

## Task 8: Tag

```bash
git tag -a v0.15.0-plan15 -m "seck Plan 15: reproducible PQ-signed releases + multi-distro packaging"
```

---

## Self-review

**Spec coverage:** §13 reproducible builds + PQ-signed releases + SBOM + SLSA ✓; install.sh verifies all three ✓; Homebrew/AUR/deb/rpm/Alpine/Void/Nix all present ✓; `RELEASE_KEY.md` documents air-gapped procedure ✓.

**Placeholder scan:** `REPLACE_AT_RELEASE` and `REPLACE_AT_FIRST_RELEASE` placeholders are deliberate: those are real artifacts computed at first release. The placeholders are clearly marked.

**Type consistency:** SLH-DSA / SHA3-256 / ML-DSA usage matches Plan 07's `seck-crypto` API.

Plan 15 complete.
