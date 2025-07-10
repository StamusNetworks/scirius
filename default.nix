{ pkgs ? import <nixpkgs> { } }:
pkgs.mkShell {
  nativeBuildInputs = (with pkgs.buildPackages; [ python3 nodejs_20 commitlint ]) ++ (with pkgs.buildPackages; with python311Packages ;[ pip wheel python-ldap mypy ruff ]);
}
