{
  description = "aspen-wasm-plugin - Host-side WASM plugin runtime for Aspen RPC handlers";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/release-25.11";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };
        rustToolchain = pkgs.rust-bin.nightly."2026-02-06".default.override {
          extensions = [ "rust-src" "llvm-tools" ];
        };
      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs = [
            rustToolchain
            pkgs.clang
            pkgs.llvmPackages.bintools
          ];

          shellHook = ''
            echo "aspen-wasm-plugin development environment"
            echo ""
            echo "Note: This extracted crate depends on:"
            echo "  - ~/git/aspen (monorepo siblings)"
            echo "  - ~/git/aspen-client-api"
            echo "  - ~/git/aspen-constants"
            echo "  - ~/git/aspen-plugin-api"
            echo "  - ~/git/aspen-kv-types"
            echo "  - ~/git/aspen-traits"
            echo "  - ~/git/aspen-hlc"
            echo "  - ~/git/aspen-hooks"
            echo ""
          '';
        };
      }
    );
}
