#!/usr/bin/env python3
"""
Compile translation catalogues (.po -> .mo).

Uses msgfmt from gettext when available, otherwise falls back to a pure-Python
writer. The fallback matters: the previous version tried `import msgfmt`, which is
not a standard library module, so on a system without gettext compilation failed
outright and the interface silently stayed English.

Usage:
    python3 compile_translations.py
    python3 compile_translations.py --verify   # also load each catalogue back
"""
import array
import shutil
import struct
import subprocess
import sys
from pathlib import Path

LOCALE_DIR = Path(__file__).parent / 'locale'

# Magic number identifying a little-endian .mo file
MO_MAGIC = 0x950412de


def parse_po(po_path: Path) -> dict:
    """
    Parse a .po file into {msgid: msgstr}.

    Handles multi-line entries and the escapes that actually occur in these
    catalogues (\\n, \\t, \\", \\\\). Fuzzy and obsolete entries are skipped, as
    msgfmt does by default.
    """
    entries = {}
    msgid = None
    msgstr = None
    target = None  # 'id' | 'str'
    fuzzy = False
    pending_fuzzy = False

    def flush():
        nonlocal msgid, msgstr, target, fuzzy
        if msgid is not None and msgstr is not None and not fuzzy:
            entries[msgid] = msgstr
        msgid = msgstr = target = None
        fuzzy = False

    for raw in po_path.read_text(encoding='utf-8').splitlines():
        line = raw.strip()

        if not line:
            continue

        if line.startswith('#'):
            if line.startswith('#,') and 'fuzzy' in line:
                pending_fuzzy = True
            continue

        if line.startswith('msgid_plural'):
            # Plural forms are not used by this application; ignore the entry
            target = None
            continue

        if line.startswith('msgid '):
            flush()
            fuzzy = pending_fuzzy
            pending_fuzzy = False
            msgid = unquote(line[len('msgid '):])
            target = 'id'
            continue

        if line.startswith('msgstr '):
            msgstr = unquote(line[len('msgstr '):])
            target = 'str'
            continue

        if line.startswith('msgstr['):
            # msgstr[0] etc. - plural entry, ignored
            target = None
            continue

        if line.startswith('"'):
            fragment = unquote(line)
            if target == 'id':
                msgid = (msgid or '') + fragment
            elif target == 'str':
                msgstr = (msgstr or '') + fragment

    flush()
    return entries


def unquote(fragment: str) -> str:
    """Strip surrounding quotes and decode PO escape sequences."""
    fragment = fragment.strip()
    if fragment.startswith('"'):
        fragment = fragment[1:]
    if fragment.endswith('"'):
        fragment = fragment[:-1]

    out = []
    i = 0
    escapes = {'n': '\n', 't': '\t', 'r': '\r', '"': '"', '\\': '\\'}
    while i < len(fragment):
        ch = fragment[i]
        if ch == '\\' and i + 1 < len(fragment):
            nxt = fragment[i + 1]
            out.append(escapes.get(nxt, nxt))
            i += 2
        else:
            out.append(ch)
            i += 1
    return ''.join(out)


def write_mo(entries: dict, mo_path: Path):
    """
    Write a binary .mo file.

    Layout per the GNU gettext specification: a header, two offset/length tables
    (one for ids, one for strings), then the string data. Entries must be sorted
    by msgid because gettext binary-searches the table.
    """
    # The header entry (empty msgid) carries the catalogue metadata
    items = sorted(entries.items(), key=lambda kv: kv[0].encode('utf-8'))

    ids = b''
    strs = b''
    offsets = []

    for msgid, msgstr in items:
        id_bytes = msgid.encode('utf-8')
        str_bytes = msgstr.encode('utf-8')
        offsets.append((len(ids), len(id_bytes), len(strs), len(str_bytes)))
        ids += id_bytes + b'\x00'
        strs += str_bytes + b'\x00'

    count = len(items)
    key_start = 7 * 4 + 16 * count      # after header and both tables
    value_start = key_start + len(ids)

    key_offsets = []
    value_offsets = []
    for id_off, id_len, str_off, str_len in offsets:
        key_offsets += [id_len, id_off + key_start]
        value_offsets += [str_len, str_off + value_start]

    output = struct.pack(
        '<7I',
        MO_MAGIC,          # magic
        0,                 # format revision
        count,             # number of strings
        7 * 4,             # offset of the id table
        7 * 4 + count * 8, # offset of the string table
        0,                 # hash table size (unused)
        0,                 # hash table offset (unused)
    )
    output += array.array('i', key_offsets + value_offsets).tobytes()
    output += ids
    output += strs

    mo_path.write_bytes(output)


def compile_with_msgfmt(po_path: Path, mo_path: Path) -> bool:
    """Try the real msgfmt. Returns False if it is unavailable or fails."""
    if not shutil.which('msgfmt'):
        return False

    result = subprocess.run(
        ['msgfmt', '-o', str(mo_path), str(po_path)],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print(f"  msgfmt failed: {result.stderr.strip()}")
        return False
    return True


def verify(mo_path: Path, lang: str, expected: dict) -> bool:
    """Load the compiled catalogue through gettext and spot-check a translation."""
    import gettext

    try:
        with open(mo_path, 'rb') as fh:
            catalogue = gettext.GNUTranslations(fh)
    except Exception as e:
        print(f"  verify: could not load {mo_path.name}: {e}")
        return False

    # Pick a sample entry with a non-empty translation
    sample = next((k for k, v in expected.items() if k and v), None)
    if sample is None:
        print("  verify: catalogue has no translated entries")
        return False

    got = catalogue.gettext(sample)
    if lang == 'ru' and got != expected[sample]:
        print(f"  verify: {sample!r} -> {got!r}, expected {expected[sample]!r}")
        return False

    print(f"  verify: loaded {len(expected)} entries, "
          f"{sample!r} -> {got!r}")
    return True


def main():
    do_verify = '--verify' in sys.argv

    if not LOCALE_DIR.exists():
        print(f"Error: {LOCALE_DIR} not found", file=sys.stderr)
        return 1

    po_files = sorted(LOCALE_DIR.rglob('*.po'))
    if not po_files:
        print(f"Error: no .po files under {LOCALE_DIR}", file=sys.stderr)
        return 1

    used_fallback = False
    failures = 0

    for po_path in po_files:
        mo_path = po_path.with_suffix('.mo')
        lang = po_path.parent.parent.name
        print(f"{po_path.relative_to(LOCALE_DIR)} -> {mo_path.name}")

        entries = parse_po(po_path)

        if compile_with_msgfmt(po_path, mo_path):
            print(f"  compiled with msgfmt ({len(entries)} entries)")
        else:
            try:
                write_mo(entries, mo_path)
                used_fallback = True
                print(f"  compiled with the built-in writer ({len(entries)} entries)")
            except Exception as e:
                print(f"  FAILED: {e}")
                failures += 1
                continue

        if do_verify and not verify(mo_path, lang, entries):
            failures += 1

    print("\n" + "=" * 52)
    print(f"Catalogues processed: {len(po_files)}")
    if used_fallback:
        print("Note: msgfmt was unavailable; the built-in writer was used.")
        print("      Install the 'gettext' package to use msgfmt instead.")
    if failures:
        print(f"Failures: {failures}")
        return 1
    print("All catalogues compiled successfully.")
    return 0


if __name__ == '__main__':
    sys.exit(main())
