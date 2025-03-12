{
  description = "PowerView.py is an alternative for the awesome original PowerView.ps1 script.";

  outputs =
    { self, nixpkgs, ... }:
    {
      defaultPackage.x86_64-linux =
        nixpkgs.legacyPackages.x86_64-linux.python3Packages.buildPythonApplication
          rec {
            pname = "powerview";
            version = "2025.0.4";
            format = "pyproject";

            src = nixpkgs.legacyPackages.x86_64-linux.fetchFromGitHub {
              owner = "aniqfakhrul";
              repo = "powerview.py";
              rev = "main";
              hash = "sha256-855smi1qmEgeso30fXj2ivnvVYtAUrs3ps0EclDbZz0=";
            };

            nativeBuildInputs = with nixpkgs.legacyPackages.x86_64-linux.python3Packages; [
              poetry-core
            ];

            propagatedBuildInputs = with nixpkgs.legacyPackages.x86_64-linux.python3Packages; [
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

            meta = with nixpkgs.lib; {
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
    };
}
