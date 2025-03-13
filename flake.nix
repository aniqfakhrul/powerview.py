{
  description = "PowerView.py is an alternative for the awesome original PowerView.ps1 script.";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      ...
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        powerview = pkgs.python3Packages.buildPythonApplication rec {
          pname = "powerview";
          version = "2025.0.4";
          format = "pyproject";

          src = pkgs.fetchFromGitHub {
            owner = "aniqfakhrul";
            repo = "powerview.py";
            rev = "main";
            hash = "sha256-855smi1qmEgeso30fXj2ivnvVYtAUrs3ps0EclDbZz0=";
          };

          nativeBuildInputs = with pkgs.python3Packages; [ poetry-core ];

          propagatedBuildInputs = with pkgs.python3Packages; [
            impacket
            ldap3-bleeding-edge
            dnspython
            future
            gnureadline
            validators
            dsinternals
            chardet
            tabulate
            requests-ntlm
            python-dateutil
            flask
          ];

          pythonRemoveDeps = [ "argparse" ];

          doCheck = false;

          meta = with pkgs.lib; {
            description = "PowerView.py is an alternative for the awesome original PowerView.ps1 script.";
            longDescription = ''
              PowerView.py is an alternative for the awesome original PowerView.ps1 script.
              Most of the modules used in PowerView are available here (some of the flags are changed).
              The main goal is to achieve an interactive session without having to repeatedly authenticate to LDAP.
            '';
            homepage = "https://github.com/aniqfakhrul/powerview.py";
            license = licenses.gpl3Only;
            mainProgram = "powerview";
          };
        };
      in
      {
        packages = {
          powerview = powerview;
          default = powerview;
        };
      }
    );
}
