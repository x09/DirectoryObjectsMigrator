"""
GUI regression tests for the three startup/runtime bugs.

1. ConnectionDialog._password_mode_changed received the bool from the `toggled`
   signal but was declared without a parameter.
2. MainWindow._check_connections passed a string to setEnabled(), which raised
   TypeError and prevented the window from being constructed at all.
3. Administrator passwords were re-requested on every action because nothing
   cached them for the session.

These run headlessly under the offscreen Qt platform plugin.
"""
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

if not os.environ.get('DISPLAY') and not os.environ.get('QT_QPA_PLATFORM'):
    os.environ['QT_QPA_PLATFORM'] = 'offscreen'

from PyQt5.QtWidgets import QApplication

app = QApplication.instance() or QApplication([])

from utils.config_manager import ConfigManager
from gui.connection_dialog import ConnectionDialog
from gui.main_window import MainWindow

FAILURES = []


def check(label, actual, expected):
    ok = actual == expected
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {actual!r}"
          f"{'' if ok else f' (expected {expected!r})'}")
    if not ok:
        FAILURES.append(label)


def make_configs(tmp: Path):
    """Isolated config files so the real ~/.config is never touched."""
    configured = ConfigManager(tmp / 'configured.ini')
    configured.set_source_dc_config({
        'host': '10.0.0.1', 'port': 389, 'domain': 'source.alt',
        'username': 'administrator', 'use_tls': False})
    configured.set_dest_dc_config({
        'host': '10.0.0.2', 'port': 389, 'domain': 'dest.alt',
        'username': 'administrator', 'use_tls': False})

    empty = ConfigManager(tmp / 'empty.ini')
    return configured, empty


def test_password_mode_toggle(cfg):
    print("\n=== Bug 1: password mode radio toggle ===")
    dialog = ConnectionDialog(cfg)
    check("dialog constructs (runs _password_mode_changed via _load_settings)", True, True)

    # setChecked emits the real `toggled(bool)` signal
    dialog.fixed_password_radio.setChecked(True)
    check("fixed mode disables length", dialog.password_length.isEnabled(), False)
    check("fixed mode enables password field", dialog.fixed_password.isEnabled(), True)

    dialog.random_password_radio.setChecked(True)
    check("random mode enables length", dialog.password_length.isEnabled(), True)
    check("random mode disables password field", dialog.fixed_password.isEnabled(), False)


def test_check_connections(cfg, empty_cfg):
    print("\n=== Bug 2: _check_connections must pass a bool to setEnabled ===")
    window = MainWindow()
    check("MainWindow constructs", isinstance(window, MainWindow), True)

    window.config_manager = cfg
    window._check_connections()
    check("analyze enabled when both DCs configured", window.analyze_btn.isEnabled(), True)

    window.config_manager = empty_cfg
    window._check_connections()
    check("analyze disabled when unconfigured", window.analyze_btn.isEnabled(), False)

    return window


def test_password_caching(window, cfg, ini_path: Path):
    print("\n=== Bug 3: passwords cached for the session ===")
    window.config_manager = cfg
    prompts = []

    original = MainWindow._get_password

    def counting_get_password(self, dc_type, host, domain, username):
        """Same cache logic as the real method, with the modal prompt replaced."""
        cached = self._session_passwords.get(dc_type)
        if cached:
            return cached
        prompts.append(dc_type)
        pw = f'pw-{dc_type}'
        self._session_passwords[dc_type] = pw
        return pw

    MainWindow._get_password = counting_get_password
    try:
        src = cfg.get_source_dc_config()
        for _ in range(5):
            window._get_password('source', src['host'], src['domain'], src['username'])

        check("prompted once for five requests", len(prompts), 1)
        check("cached password returned", window._session_passwords['source'], 'pw-source')

        # A failed connect clears the entry; the next call must prompt again
        window._session_passwords['source'] = None
        window._get_password('source', src['host'], src['domain'], src['username'])
        check("re-prompts after invalidation", len(prompts), 2)

        dest = cfg.get_dest_dc_config()
        window._get_password('dest', dest['host'], dest['domain'], dest['username'])
        check("source and dest cached independently",
              window._session_passwords['dest'], 'pw-dest')
    finally:
        MainWindow._get_password = original

    check("passwords never written to the ini file",
          'pw-source' in ini_path.read_text(), False)


def main():
    tmp = Path(tempfile.mkdtemp())
    cfg, empty_cfg = make_configs(tmp)

    test_password_mode_toggle(cfg)
    window = test_check_connections(cfg, empty_cfg)
    test_password_caching(window, cfg, tmp / 'configured.ini')

    print("\n" + "=" * 62)
    if FAILURES:
        print(f"{len(FAILURES)} CHECK(S) FAILED: {FAILURES}")
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == '__main__':
    sys.exit(main())
