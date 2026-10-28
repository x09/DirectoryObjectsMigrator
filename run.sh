#!/bin/bash
# Run Directory Objects Migrator
#
# main.py already appends the ALT Linux site-packages directories to sys.path,
# so no PYTHONPATH juggling is needed here. This script only checks that the
# interpreter and required modules are present, then hands off.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if ! command -v python3 &> /dev/null; then
    echo "Error: python3 not found. Please install Python 3.10 or newer." >&2
    exit 1
fi

# Verify dependencies through main.py's own path setup, so this check and the
# application agree on what is importable.
missing="$(python3 - <<'PY'
import sys
from pathlib import Path

for extra in ('/usr/lib64/python3/site-packages', '/usr/lib/python3/site-packages'):
    if Path(extra).is_dir() and extra not in sys.path:
        sys.path.append(extra)

missing = []
for mod in ('PyQt5', 'ldap3', 'yaml', 'sqlite3'):
    try:
        __import__(mod)
    except ImportError:
        missing.append(mod)
print(' '.join(missing))
PY
)"

if [ -n "$missing" ]; then
    echo "Error: missing Python modules:$missing" >&2
    echo "" >&2
    echo "Install them with:" >&2
    echo "  sudo ./install.sh" >&2
    echo "" >&2
    echo "Or directly:" >&2
    echo "  sudo apt-get install python3-module-PyQt5 python3-module-ldap3 \\" >&2
    echo "                       python3-module-yaml python3-modules-sqlite3" >&2
    exit 1
fi

exec python3 main.py "$@"
