"""
Translation coverage and language selection.

Two problems are guarded against here:

1. Catalogue drift. The .po files were maintained by hand and had fallen badly out
   of step with the code (82 strings missing, 32 stale), so parts of the interface
   could not be translated at all. The catalogues are now generated; this test
   fails if the code and the catalogues disagree again.

2. MainWindow used to re-apply the language from config at the end of __init__.
   That was too late for its own labels and, worse, reset the active language for
   every dialog created afterwards, so dialogs stayed English while the main
   window was Russian.
"""
import os
import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

if not os.environ.get('DISPLAY') and not os.environ.get('QT_QPA_PLATFORM'):
    os.environ['QT_QPA_PLATFORM'] = 'offscreen'

from extract_strings import extract_source_strings, parse_po

FAILURES = []


def check(label, actual, expected):
    ok = actual == expected
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {actual!r}"
          f"{'' if ok else f' (expected {expected!r})'}")
    if not ok:
        FAILURES.append(label)


def test_catalogue_coverage():
    print("\n=== Catalogues cover every translatable string ===")
    source_strings = extract_source_strings()
    check("source has translatable strings", len(source_strings) > 100, True)

    for lang in ('en', 'ru'):
        po_path = (PROJECT_ROOT / 'locale' / lang / 'LC_MESSAGES'
                   / 'DirectoryObjectMigrator.po')
        check(f"{lang} catalogue exists", po_path.exists(), True)
        if not po_path.exists():
            continue

        defined = parse_po(po_path)
        missing = source_strings - defined
        stale = defined - source_strings - {''}  # '' is the metadata header

        check(f"{lang}: no strings missing from the catalogue", sorted(missing), [])
        check(f"{lang}: no stale entries", sorted(stale), [])


def test_compiled_catalogues():
    print("\n=== Compiled .mo files load and translate ===")
    import gettext

    for lang, sample, expect_translated in (
        ('en', 'Start Migration', False),
        ('ru', 'Start Migration', True),
    ):
        mo_path = (PROJECT_ROOT / 'locale' / lang / 'LC_MESSAGES'
                   / 'DirectoryObjectMigrator.mo')
        check(f"{lang} .mo exists (run compile_translations.py)", mo_path.exists(), True)
        if not mo_path.exists():
            continue

        with open(mo_path, 'rb') as fh:
            catalogue = gettext.GNUTranslations(fh)

        translated = catalogue.gettext(sample)
        if expect_translated:
            check(f"{lang}: {sample!r} is translated", translated != sample, True)
            check(f"{lang}: {sample!r} -> Russian text",
                  translated, 'Начать миграцию')
        else:
            check(f"{lang}: {sample!r} unchanged", translated, sample)


def test_runtime_language_switching():
    print("\n=== Runtime language switching ===")
    from utils import i18n

    i18n.set_language('en')
    check("English active", i18n.get_language(), 'en')
    check("English passthrough", i18n._('Users'), 'Users')

    i18n.set_language('ru')
    check("Russian active", i18n.get_language(), 'ru')
    check("Russian translation applied", i18n._('Users'), 'Пользователи')
    check("status vocabulary translated", i18n._('CONFLICT'), 'КОНФЛИКТ')
    check("multi-line string translated",
          i18n._('Dry run: the destination directory will not be modified.')
          != 'Dry run: the destination directory will not be modified.', True)


def test_dialogs_inherit_language():
    """The regression: dialogs must use the language active at startup."""
    print("\n=== MainWindow must not reset the active language ===")
    from utils import i18n
    from PyQt5.QtWidgets import QApplication

    app = QApplication.instance() or QApplication([])

    from gui.main_window import MainWindow
    from gui.connection_dialog import ConnectionDialog
    from gui.progress_window import ProgressWindow
    from utils.config_manager import ConfigManager

    i18n.set_language('ru')
    window = MainWindow()

    check("language still Russian after MainWindow", i18n.get_language(), 'ru')
    check("window title translated", window.windowTitle(), 'Миграция объектов каталога')
    check("analyze button translated", window.analyze_btn.text(), 'Анализ')

    # Dialogs built after the window are what used to come out English
    cfg = ConfigManager(Path(tempfile.mkdtemp()) / 'lang.ini')
    dialog = ConnectionDialog(cfg)
    check("dialog title translated", dialog.windowTitle(), 'Настройки подключения')
    check("dialog tab translated", dialog.tabs.tabText(0),
          'Исходный контроллер домена')

    progress = ProgressWindow()
    check("progress window translated", progress.windowTitle(), 'Выполняется миграция')

    # Leave the default language in place for any later suite
    i18n.set_language('en')


def main():
    test_catalogue_coverage()
    test_compiled_catalogues()
    test_runtime_language_switching()
    test_dialogs_inherit_language()

    print("\n" + "=" * 62)
    if FAILURES:
        print(f"{len(FAILURES)} CHECK(S) FAILED: {FAILURES}")
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == '__main__':
    sys.exit(main())
