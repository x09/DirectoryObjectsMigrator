#!/usr/bin/env python3
"""
Directory Objects Migrator
Main entry point
"""
import sys
import os
from pathlib import Path

# On ALT Linux the distribution packages (PyQt5, ldap3, ...) live in a directory
# that is not on the default sys.path. Append rather than insert, so that project
# packages such as config/ and utils/ always win over anything installed there.
for extra_path in ('/usr/lib64/python3/site-packages',
                   '/usr/lib/python3/site-packages'):
    if Path(extra_path).is_dir() and extra_path not in sys.path:
        sys.path.append(extra_path)

# Project root must take precedence over every site-packages directory
project_root = Path(__file__).resolve().parent
if str(project_root) in sys.path:
    sys.path.remove(str(project_root))
sys.path.insert(0, str(project_root))

from PyQt5.QtWidgets import QApplication, QMessageBox
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QIcon

from gui.main_window import MainWindow
from utils.i18n import set_language, detect_system_language
from utils.config_manager import ConfigManager
from config import settings


def setup_application():
    """Setup application environment"""
    # Ensure directories exist
    settings.ensure_directories()

    # Load configuration
    config_manager = ConfigManager()

    # Set language
    language = config_manager.get_language()
    if not language:
        # Auto-detect system language
        language = detect_system_language()
        config_manager.set_language(language)

    set_language(language)


def main():
    """Main entry point"""
    # Setup
    setup_application()

    # Create application
    app = QApplication(sys.argv)
    app.setApplicationName(settings.APP_NAME)
    app.setApplicationVersion(settings.APP_VERSION)
    app.setOrganizationName(settings.APP_AUTHOR)

    # Application-wide icon, so the task bar and window switcher pick it up too.
    # MainWindow sets it on itself as well; dialogs inherit it from their parent.
    icon_path = project_root / 'resources' / 'icon.svg'
    if icon_path.exists():
        app.setWindowIcon(QIcon(str(icon_path)))

    # Set application style
    app.setStyle('Fusion')

    # Global exception handler
    def exception_hook(exctype, value, traceback):
        """Handle uncaught exceptions"""
        error_msg = f"Uncaught exception:\n{exctype.__name__}: {value}"
        print(error_msg, file=sys.stderr)
        import traceback as tb
        tb.print_exception(exctype, value, traceback)

        # Show error dialog
        QMessageBox.critical(
            None,
            "Critical Error",
            f"An unexpected error occurred:\n\n{error_msg}\n\nPlease check the logs."
        )

    sys.excepthook = exception_hook

    # Create and show main window
    try:
        window = MainWindow()
        window.show()

        # Run application
        sys.exit(app.exec_())

    except Exception as e:
        import traceback
        print(f"Failed to start application: {e}", file=sys.stderr)
        print("\nFull traceback:", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        QMessageBox.critical(
            None,
            "Startup Error",
            f"Failed to start application:\n\n{str(e)}\n\nCheck console for details."
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
