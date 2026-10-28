#!/usr/bin/env python3
"""
Extract translatable strings and report which ones are missing from the .po files.

Uses the AST rather than a regex, so multi-line implicit concatenation such as

    _("first part "
      "second part")

is recovered as the single msgid the runtime will actually look up. A regex over
the source would only ever see the first fragment.

Usage:
    python3 extract_strings.py           # report missing strings
    python3 extract_strings.py --list    # list every extracted string
"""
import ast
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent
LOCALE_DIR = PROJECT_ROOT / 'locale'
SKIP_DIRS = {'tests', '__pycache__', 'locale', 'logs', 'docs'}

# Strings passed to _() through a variable or lookup, so the AST cannot see them.
# Keep this in sync by hand when adding dynamic translation lookups.
DYNAMIC_STRINGS = {
    # Plan action labels rendered by PreviewDialog via _(action)
    'CREATE', 'EXISTS', 'CONFLICT', 'ERROR', 'DEFERRED', 'SKIPPED',
    # TYPE_LABELS values rendered via _(TYPE_LABELS[...])
    'Organizational Units', 'Users', 'Groups', 'Contacts',
}


class StringCollector(ast.NodeVisitor):
    """Collect the first string argument of every _() and ngettext() call."""

    def __init__(self):
        self.strings: set[str] = set()

    def visit_Call(self, node: ast.Call):
        func = node.func
        name = None
        if isinstance(func, ast.Name):
            name = func.id
        elif isinstance(func, ast.Attribute):
            name = func.attr

        if name in ('_', 'gettext'):
            self._collect_arg(node, 0)
        elif name == 'ngettext':
            self._collect_arg(node, 0)
            self._collect_arg(node, 1)

        self.generic_visit(node)

    def _collect_arg(self, node: ast.Call, index: int):
        if len(node.args) > index:
            arg = node.args[index]
            # Implicit concatenation is already merged into one Constant here
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                if arg.value.strip():
                    self.strings.add(arg.value)


def python_files():
    for path in sorted(PROJECT_ROOT.rglob('*.py')):
        if any(part in SKIP_DIRS for part in path.relative_to(PROJECT_ROOT).parts):
            continue
        if path.name == Path(__file__).name:
            continue
        yield path


def extract_source_strings() -> set:
    found = set(DYNAMIC_STRINGS)
    for path in python_files():
        try:
            tree = ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
        except SyntaxError as e:
            print(f"warning: could not parse {path}: {e}", file=sys.stderr)
            continue
        collector = StringCollector()
        collector.visit(tree)
        found |= collector.strings
    return found


def parse_po(po_path: Path) -> set:
    """Return the set of msgids defined in a .po file (handles multi-line)."""
    msgids = set()
    current = None
    collecting = False

    for raw in po_path.read_text(encoding='utf-8').splitlines():
        line = raw.strip()

        if line.startswith('msgid '):
            current = _unquote(line[len('msgid '):])
            collecting = True
        elif line.startswith('msgstr'):
            if collecting and current:
                msgids.add(current)
            collecting = False
            current = None
        elif collecting and line.startswith('"'):
            current = (current or '') + _unquote(line)

    return msgids


def _unquote(fragment: str) -> str:
    fragment = fragment.strip()
    if fragment.startswith('"') and fragment.endswith('"'):
        fragment = fragment[1:-1]
    return fragment.replace('\\"', '"').replace('\\n', '\n')


def po_escape(value: str) -> str:
    return value.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n')


def main():
    source_strings = extract_source_strings()

    if '--list' in sys.argv:
        for text in sorted(source_strings):
            print(repr(text))
        print(f"\n{len(source_strings)} translatable strings")
        return 0

    exit_code = 0
    for lang in ('en', 'ru'):
        po_path = LOCALE_DIR / lang / 'LC_MESSAGES' / 'DirectoryObjectMigrator.po'
        if not po_path.exists():
            print(f"missing catalogue: {po_path}")
            exit_code = 1
            continue

        defined = parse_po(po_path)
        missing = sorted(source_strings - defined)
        unused = sorted(defined - source_strings)

        print(f"\n=== {lang} ===")
        print(f"  in source:    {len(source_strings)}")
        print(f"  in catalogue: {len(defined)}")
        print(f"  missing:      {len(missing)}")
        print(f"  unused:       {len(unused)}")

        if missing:
            exit_code = 1
            print(f"\n  --- missing from {lang}, append these ---")
            for text in missing:
                print(f'\nmsgid "{po_escape(text)}"\nmsgstr ""')

    return exit_code


if __name__ == '__main__':
    sys.exit(main())
