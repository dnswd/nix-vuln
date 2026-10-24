{
  description = "A standard Rust project";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
        };
        
        # Read Cargo.toml to get package name and version
        cargoToml = builtins.fromTOML (builtins.readFile ./Cargo.toml);
        frontend = pkgs.buildNpmPackage {
          pname = "nix-vuln-frontend";
          version = cargoToml.package.version;
          src = ./frontend;
          npmDepsHash = "sha256-BLUjkjuXNDExvYc8dnW+ZPQmtd9NNqRSMHQKOfqVA0Q=";
          installPhase = ''
            mkdir -p $out
            cp -r dist/* $out/
          '';
        };
      in
      {
        packages.default = pkgs.rustPlatform.buildRustPackage {
          pname = cargoToml.package.name;
          version = cargoToml.package.version;
          src = ./.;
          cargoLock = {
            lockFile = ./Cargo.lock;
          };
          preBuild = ''
            mkdir -p frontend/dist
            cp -r ${frontend}/* frontend/dist/
          '';
          SKIP_NPM_BUILD = "1";
          doCheck = false;
          nativeBuildInputs = with pkgs; [ pkg-config ];
          buildInputs = with pkgs; [ openssl ];
        };

        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            cargo
            rustc
            rustfmt
            clippy
            pkg-config
            openssl.dev
            just
            cargo-watch
          ];
        };
      }
    );
}