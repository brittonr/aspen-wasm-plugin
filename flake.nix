{
  description = "aspen-wasm-plugin - Host-side WASM plugin runtime for Aspen RPC handlers";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/release-25.11";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            cargo
            rustc
            rustfmt
            clippy
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
