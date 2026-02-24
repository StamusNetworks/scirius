{ pkgs ? import <nixpkgs> { } }:
pkgs.mkShell {
  nativeBuildInputs = (with pkgs.buildPackages; [ python3 nodejs_20 commitlint ]) ++ (with pkgs.buildPackages; with python311Packages ;[ pip wheel python-ldap mypy ruff pytest ]);
  buildInputs = with pkgs; [
    openssh # openssh-client
    gcc
    gnumake # build-essential
    openldap # libldap2-dev
    cyrus_sasl # libsasl2-dev
    libyaml # libyaml-dev
    git
    suricata
  ];
}
