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
  description = "flake for tssh";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
    nix-github-actions.url = "github:nix-community/nix-github-actions";
    nix-github-actions.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs =
    {
      self,
      nixpkgs,
      nix-github-actions,
    }:
    let
      supportedSystems = [
        "x86_64-linux"
        "aarch64-linux"
      ];

      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;

      nixpkgsFor = forAllSystems (
        system:
        import nixpkgs {
          inherit system;
          overlays = [
            self.overlays.default
          ];
        }
      );
    in
    {
      overlays.default = import ./nix/overlay.nix;

      packages = forAllSystems (system: {
        tssh = (nixpkgsFor.${system}).callPackage ./nix/package.nix { };
        default = (nixpkgsFor.${system}).callPackage ./nix/package.nix { };
      });

      devShells = forAllSystems (
        system:
        let
          pkgs = nixpkgsFor.${system};
        in
        {
          default = pkgs.mkShell {
            name = "tssh-default";
            buildInputs = with pkgs; [
              cargo
              rust-analyzer
              openssl
              tpm2-tss
              pkg-config
            ];
          };
        }
      );

      checks = forAllSystems (system: {
        nixos-test = nixpkgsFor.${system}.callPackage ./nix/nixos-test.nix { };
      });

      githubActions =
        let
          checks = nixpkgs.lib.recursiveUpdate (nixpkgs.lib.getAttrs [ "x86_64-linux" ] self.checks) (
            forAllSystems (system: {
              packages_tssh = self.packages.${system}.default;
            })
          );
        in
        nix-github-actions.lib.mkGithubMatrix { inherit checks; };
    };
}
