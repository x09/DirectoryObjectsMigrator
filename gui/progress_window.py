"""
Progress Window
Shows migration progress with real-time logs
"""
from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QProgressBar, QTextEdit, QGroupBox
)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal
from PyQt5.QtGui import QTextCursor, QColor, QTextCharFormat

from utils.i18n import _


class ProgressWindow(QDialog):
    """Dialog showing migration progress"""

    # Emitted when the user confirms cancellation, so the owner can tell the
    # migrator to stop. The dialog itself has no reference to the migrator.
    cancel_requested = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle(_("Migration in progress"))
        self.setMinimumSize(800, 600)
        self.setModal(True)

        # Don't allow closing during migration
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowCloseButtonHint)

        self.migration_complete = False
        self.migration_cancelled = False

        self._init_ui()

    def _init_ui(self):
        """Initialize UI"""
        layout = QVBoxLayout(self)

        # Status label
        self.status_label = QLabel(_("Initializing..."))
        self.status_label.setStyleSheet("font-size: 14px; font-weight: bold; margin: 10px;")
        layout.addWidget(self.status_label)

        # Progress bar
        progress_group = QGroupBox(_("Progress"))
        progress_layout = QVBoxLayout()

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(True)
        progress_layout.addWidget(self.progress_bar)

        self.phase_label = QLabel("")
        progress_layout.addWidget(self.phase_label)

        progress_group.setLayout(progress_layout)
        layout.addWidget(progress_group)

        # Log viewer
        log_group = QGroupBox(_("Log"))
        log_layout = QVBoxLayout()

        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setStyleSheet("font-family: monospace; font-size: 10pt;")
        log_layout.addWidget(self.log_text)

        log_group.setLayout(log_layout)
        layout.addWidget(log_group)

        # Buttons
        button_layout = QHBoxLayout()
        button_layout.addStretch()

        self.cancel_btn = QPushButton(_("Cancel"))
        self.cancel_btn.clicked.connect(self._cancel_migration)
        button_layout.addWidget(self.cancel_btn)

        self.close_btn = QPushButton(_("Close"))
        self.close_btn.clicked.connect(self.accept)
        self.close_btn.setEnabled(False)
        button_layout.addWidget(self.close_btn)

        layout.addLayout(button_layout)

    def update_progress(self, percent: int, message: str):
        """
        Update progress bar and status

        Args:
            percent: Progress percentage (0-100)
            message: Status message
        """
        self.progress_bar.setValue(percent)
        self.status_label.setText(message)

        # Update phase label based on percent
        if percent < 20:
            phase = _("Phase") + " 0/5: " + _("Analysis")
        elif percent < 40:
            phase = _("Phase") + " 1/5: " + _("Creating OUs")
        elif percent < 60:
            phase = _("Phase") + " 2/5: " + _("Creating objects")
        elif percent < 80:
            phase = _("Phase") + " 3/5: " + _("Copying attributes")
        elif percent < 95:
            phase = _("Phase") + " 4/5: " + _("Resolving references")
        else:
            phase = _("Phase") + " 5/5: " + _("Verification")

        self.phase_label.setText(phase)

    def append_log(self, level: str, message: str):
        """
        Append log message

        Args:
            level: Log level (INFO, SUCCESS, WARNING, ERROR, CONFLICT)
            message: Log message
        """
        # Color based on level
        color_map = {
            'DEBUG': QColor(128, 128, 128),     # Gray
            'INFO': QColor(0, 0, 0),            # Black
            'SUCCESS': QColor(76, 175, 80),     # Green
            'WARNING': QColor(255, 152, 0),     # Orange
            'ERROR': QColor(244, 67, 54),       # Red
            'CRITICAL': QColor(183, 28, 28),    # Dark red
            'CONFLICT': QColor(156, 39, 176),   # Purple
        }

        color = color_map.get(level, QColor(0, 0, 0))

        # Format text
        cursor = self.log_text.textCursor()
        cursor.movePosition(QTextCursor.End)

        format = QTextCharFormat()
        format.setForeground(color)

        cursor.insertText(f"[{level}] {message}\n", format)

        # Auto-scroll to bottom
        scrollbar = self.log_text.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    def set_complete(self, success: bool, message: str):
        """
        Mark migration as complete

        Args:
            success: Whether migration succeeded
            message: Completion message
        """
        self.migration_complete = True
        self.progress_bar.setValue(100)

        if success:
            self.status_label.setText(_("Migration completed successfully"))
            self.status_label.setStyleSheet("font-size: 14px; font-weight: bold; color: green; margin: 10px;")
        else:
            self.status_label.setText(_("Migration failed"))
            self.status_label.setStyleSheet("font-size: 14px; font-weight: bold; color: red; margin: 10px;")

        self.append_log('INFO', message)

        # Enable close button, disable cancel
        self.cancel_btn.setEnabled(False)
        self.close_btn.setEnabled(True)
        self.close_btn.setDefault(True)

    def _cancel_migration(self):
        """Handle cancel button click"""
        from PyQt5.QtWidgets import QMessageBox

        reply = QMessageBox.question(
            self,
            _("Cancel Migration"),
            _("Are you sure you want to cancel the migration?"),
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )

        if reply == QMessageBox.Yes:
            self.migration_cancelled = True
            self.cancel_btn.setEnabled(False)
            self.status_label.setText(_("Cancelling..."))
            self.append_log('WARNING', _("Migration cancellation requested"))
            self.cancel_requested.emit()

    def is_cancelled(self) -> bool:
        """Check if migration was cancelled"""
        return self.migration_cancelled


if __name__ == "__main__":
    import sys
    from PyQt5.QtWidgets import QApplication

    app = QApplication(sys.argv)

    dialog = ProgressWindow()

    # Simulate progress
    def simulate():
        import random
        percent = dialog.progress_bar.value()

        if percent < 100:
            percent += random.randint(1, 10)
            if percent > 100:
                percent = 100

            dialog.update_progress(percent, f"Processing... {percent}%")

            # Random log messages
            levels = ['INFO', 'SUCCESS', 'WARNING']
            level = random.choice(levels)
            dialog.append_log(level, f"Test log message at {percent}%")

            if percent >= 100:
                dialog.set_complete(True, "All done!")
        else:
            timer.stop()

    timer = QTimer()
    timer.timeout.connect(simulate)
    timer.start(200)

    dialog.show()
    sys.exit(app.exec_())
