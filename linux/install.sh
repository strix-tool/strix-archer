#!/usr/bin/env bash
# Strix Archer — convenience installer for Linux/Kali.
# Installs the scripts into ~/.local/bin so you can run `strix-archer` from
# anywhere. No root required; nothing is downloaded here. The wrappable OSINT
# tools remain optional — install them separately (see `strix-archer --setup`).
set -euo pipefail

SRC_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BIN_DIR="${HOME}/.local/bin"
mkdir -p "${BIN_DIR}"

install_one() {
    local script="$1" name="$2"
    local target="${BIN_DIR}/${name}"
    cat > "${target}" <<EOF
#!/usr/bin/env bash
exec python3 "${SRC_DIR}/${script}" "\$@"
EOF
    chmod 0755 "${target}"
    echo "  installed: ${target}"
}

echo "Installing Strix Archer launchers to ${BIN_DIR} ..."
install_one "strix_archer.py"     "strix-archer"
install_one "strix_archer_tui.py" "strix-archer-tui"

case ":${PATH}:" in
    *":${BIN_DIR}:"*) : ;;
    *) echo "  note: add ${BIN_DIR} to your PATH (e.g. in ~/.bashrc)" ;;
esac

echo "Done. Run:  strix-archer --version"
echo "Authorized / lab targets only — you must pass --i-am-authorized."
