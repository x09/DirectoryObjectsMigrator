#!/bin/bash
# Check that all required Python modules are importable.
#
# Uses the same sys.path setup as main.py, so a "found" result here means the
# application will also find the module. A plain `python3 -c "import PyQt5"`
# does not, because on ALT Linux the distribution packages live outside the
# default sys.path.

set -u

if ! command -v python3 &> /dev/null; then
    echo "MISSING  python3"
    echo ""
    echo "Install Python 3.10 or newer, then re-run this script."
    exit 1
fi

echo "python3: $(python3 --version 2>&1)"
echo ""

python3 - <<'PY'
import sys
from pathlib import Path

# Same as main.py: append distribution paths without shadowing project packages
extra_paths = ('/usr/lib64/python3/site-packages', '/usr/lib/python3/site-packages')
for extra in extra_paths:
    if Path(extra).is_dir() and extra not in sys.path:
        sys.path.append(extra)

REQUIRED = {
    'PyQt5':   'python3-module-PyQt5',
    'ldap3':   'python3-module-ldap3',
    'yaml':    'python3-module-yaml',
    'sqlite3': 'python3-modules-sqlite3',
}

missing = []
for module, package in REQUIRED.items():
    try:
        mod = __import__(module)
    except ImportError:
        print(f"MISSING  {module:10} (package: {package})")
        missing.append(package)
        continue

    version = ''
    for attr in ('__version__', 'version', 'sqlite_version'):
        value = getattr(mod, attr, None)
        if isinstance(value, str):
            version = value
            break
    if module == 'PyQt5':
        try:
            from PyQt5.QtCore import PYQT_VERSION_STR
            version = PYQT_VERSION_STR
        except Exception:
            pass

    location = getattr(mod, '__file__', '') or 'built-in'
    print(f"found    {module:10} {version:12} {location}")

print()
if missing:
    print("=" * 60)
    print("Missing dependencies")
    print("=" * 60)
    print()
    print("Install with:")
    print("  sudo ./install.sh")
    print()
    print("Or directly:")
    print("  sudo apt-get install " + " ".join(sorted(missing)))
    print()
    sys.exit(1)

print("All required modules are available.")
PY
