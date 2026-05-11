{
  description = "russh development environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = {
    nixpkgs,
    flake-utils,
    rust-overlay,
    ...
  }:
    flake-utils.lib.eachDefaultSystem (system: let
      overlays = [(import rust-overlay)];
      pkgs = import nixpkgs {
        inherit system overlays;
      };

      rustToolchain = pkgs.rust-bin.stable.latest.default.override {
        extensions = [
          "clippy"
          "llvm-tools-preview"
          "rust-analyzer"
          "rust-src"
          "rustfmt"
        ];
      };

      nativeBuildInputs = with pkgs;
        [
          rustToolchain
          pkg-config
          cmake
          perl

          cargo-audit
          cargo-bloat
          cargo-deny
          cargo-nextest
          cargo-outdated
          cargo-udeps
          cargo-watch

          git
          gh
          hyperfine
          openssh
          sccache
          tokei
        ]
        ++ lib.optionals stdenv.isLinux [
          cargo-flamegraph
          cargo-llvm-cov
          mold
          perf
          valgrind
        ];

      buildInputs = with pkgs; [
        openssl
        zlib
      ];
    in {
      devShells.default = pkgs.mkShell {
        inherit buildInputs nativeBuildInputs;

        RUST_SRC_PATH = "${rustToolchain}/lib/rustlib/src/rust/library";
        RUSTC_WRAPPER = "${pkgs.sccache}/bin/sccache";
        OPENSSL_DIR = "${pkgs.openssl.dev}";
        OPENSSL_LIB_DIR = "${pkgs.openssl.out}/lib";
        PKG_CONFIG_PATH = "${pkgs.openssl.dev}/lib/pkgconfig";
        GH_PAGER = "cat";

        shellHook = ''
          echo "russh development environment"
          echo "  Rust: $(rustc --version)"
          echo "  cargo fmt: $(cargo fmt --version)"
          echo "  cargo clippy: $(cargo clippy --version)"
        '';
      };
    });
}
