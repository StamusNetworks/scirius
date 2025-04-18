{ pkgs ? import <nixpkgs> { } }:
pkgs.mkShell {
  nativeBuildInputs = with pkgs.buildPackages; with python311Packages; [ python3 pip wheel python-ldap mypy ruff ];
}
