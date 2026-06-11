# Copyright (C) 2026 Stephan Naumann
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

{
  lib,
  rustPlatform,
  tpm2-tss,
  pkg-config,
  openssl,
  sqlite,
}:

rustPlatform.buildRustPackage {
  pname = "tssh";
  version = "0.1.0";

  src = builtins.path {
    path = ../.;
    name = "tssh-src";
    filter = (path: type: baseNameOf path != "nix");
  };
  cargoHash = "sha256-pJ/TJPC2RfajnYNs5bV23tFkwKOwBXZ6g+BRBBuRJvU=";

  nativeBuildInputs = [
    pkg-config
  ];

  buildInputs = [
    openssl
    tpm2-tss
    sqlite
  ];

  meta = with lib; {
    description = "A TPM based wrapper for ssh";
    homepage = "https://github.com/cmdscale/tssh";
    license = licenses.unlicense;
    maintainers = [ ];
  };
}
