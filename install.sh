#!/bin/bash
# Installation script for Directory Objects Migrator (ALT Linux)

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "====================================="
echo "Directory Objects Migrator v1.0"
echo "Installation"
echo "====================================="
echo ""

if [ "${EUID}" -ne 0 ]; then
    echo "Please run as root:  sudo ./install.sh" >&2
    exit 1
fi

echo "Installing system dependencies..."
if ! apt-get update; then
    echo "Warning: apt-get update failed; continuing with the current package index." >&2
fi

if ! apt-get install -y \
    python3 \
    python3-module-ldap3 \
    python3-module-PyQt5 \
    python3-modules-sqlite3 \
    python3-module-yaml \
    gettext
then
    echo "" >&2
    echo "Error: package installation failed. Resolve the errors above and re-run." >&2
    exit 1
fi

echo ""
echo "Compiling translations..."
cd "$SCRIPT_DIR"
if ! python3 compile_translations.py; then
    echo "Warning: translation compilation failed. The interface will fall back" >&2
    echo "         to English, but the application will still run." >&2
fi

# Translations are compiled as root; make sure the invoking user can read them
# and can still rebuild them later without sudo.
if [ -n "${SUDO_USER:-}" ] && [ -d "$SCRIPT_DIR/locale" ]; then
    chown -R "$SUDO_USER" "$SCRIPT_DIR/locale" 2>/dev/null || true
fi

echo ""
echo "Creating desktop entry..."

DESKTOP_FILE=/usr/share/applications/directory-object-migrator.desktop

# The Exec value must be quoted: the installation path may contain spaces, and an
# unquoted path would be parsed as several arguments and fail to launch.
cat > "$DESKTOP_FILE" <<EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=Directory Objects Migrator
Comment=Migrate objects from Microsoft AD to Samba AD
Exec=bash -c '"$SCRIPT_DIR/run.sh"'
Path=$SCRIPT_DIR
Icon=$SCRIPT_DIR/resources/icon.svg
Terminal=false
Categories=System;Administration;
EOF

chmod 644 "$DESKTOP_FILE"
chmod +x "$SCRIPT_DIR/run.sh" "$SCRIPT_DIR/check_dependencies.sh" 2>/dev/null || true

echo ""
echo "Verifying installation..."
echo ""
if ! "$SCRIPT_DIR/check_dependencies.sh"; then
    echo "Installation finished, but some dependencies are still missing." >&2
    exit 1
fi

echo ""
echo "====================================="
echo "Installation complete"
echo "====================================="
echo ""
echo "Run the application:"
echo "  \"$SCRIPT_DIR/run.sh\""
echo ""
echo "Or launch 'Directory Objects Migrator' from the applications menu."
echo ""
echo "Before migrating anything, read:"
echo "  QUICKSTART.md          - install and first run"
echo "  docs/STATUS.md         - what is verified and what is not"
echo ""
