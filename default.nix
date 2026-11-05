{ pkgs ? import <nixpkgs> {} }:

pkgs.stdenv.mkDerivation rec {
  pname = "epk2extract";
  version = "devel";

  src = ./.;

  buildInputs = [
    pkgs.cmake
    pkgs.openssl.dev
    pkgs.lzo
    pkgs.zlib
  ];

  configurePhase = ''
    cmake .
  '';

  buildPhase = ''
    make
  '';

  installPhase = ''
    mkdir -p $out/bin
    cd src
    cp epk2extract tools/lzhsenc tools/lzhs_scanner tools/idb_extract tools/jffs2extract $out/bin

    chmod -x ../keys/*
    cp ../keys/*.key ../keys/*.pem $out/bin
  '';
}

