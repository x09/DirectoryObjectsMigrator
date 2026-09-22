#!/usr/bin/env python3
"""
Run the whole test suite.

Usage:
    python3 tests/run_all.py

The GUI tests need a Qt platform plugin. When no display is available they run
under the offscreen plugin, which is set automatically below.
"""
import os
import subprocess
import sys
from pathlib import Path

TESTS_DIR = Path(__file__).parent
PROJECT_ROOT = TESTS_DIR.parent

# Ordered so that fast, low-level checks fail first
SUITES = [
    ('Unit tests (DN, database, statistics, LDAP)', 'test_units.py', False),
    ('Ignore rules (built-in containers)',          'test_ignore_rules.py', False),
    ('Custom exclusions (operator-defined DN list)', 'test_custom_exclusions.py', False),
    ('Translations and language selection',         'test_i18n.py', True),
    ('User creation (disabled-at-create, no password copy)', 'test_user_creation.py', False),
    ('Attribute coverage and exclusions',           'test_attributes.py', False),
    ('Preview plan agrees with the actual migration', 'test_plan.py', False),
    ('Migration scenario (3-run DEFERRED spec)',    'test_deferred_scenario.py', False),
    ('Dry run (must not write to destination)',     'test_dry_run.py', False),
    ('GUI construction and password caching',       'test_gui.py', True),
    ('Preview dialog rendering',                    'test_preview_dialog.py', True),
    ('Threaded migration (segfault regression)',    'test_threading.py', True),
]


def main():
    if not os.environ.get('DISPLAY') and not os.environ.get('QT_QPA_PLATFORM'):
        os.environ['QT_QPA_PLATFORM'] = 'offscreen'

    results = []
    for label, filename, needs_qt in SUITES:
        path = TESTS_DIR / filename
        if not path.exists():
            print(f"SKIP  {label} ({filename} not found)")
            results.append((label, None))
            continue

        print("\n" + "=" * 70)
        print(f"RUN   {label}")
        print("=" * 70)

        proc = subprocess.run(
            [sys.executable, str(path)],
            cwd=str(PROJECT_ROOT),
        )
        results.append((label, proc.returncode == 0))

    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)

    failed = 0
    for label, ok in results:
        if ok is None:
            status = 'SKIP'
        elif ok:
            status = 'PASS'
        else:
            status = 'FAIL'
            failed += 1
        print(f"  {status}  {label}")

    print()
    if failed:
        print(f"{failed} suite(s) FAILED")
        return 1
    print("All suites passed")
    return 0


if __name__ == '__main__':
    sys.exit(main())
