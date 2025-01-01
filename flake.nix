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
        buildInputs = pkgs.lib.optionals pkgs.stdenv.isLinux [ pkgs.libseccomp ];
      };
    });
  };
}
