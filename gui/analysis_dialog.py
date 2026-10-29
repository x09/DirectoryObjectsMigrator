"""Modal busy indicator for read-only discovery and destination planning."""
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtWidgets import QDialog, QLabel, QProgressBar, QVBoxLayout
from utils.i18n import _


class AnalysisWorker(QThread):
    log_message = pyqtSignal(str, str)
    stage_changed = pyqtSignal(str)

    def __init__(self, operation, parent=None):
        super().__init__(parent)
        self.operation = operation
        self.result = None
        self.error = None

    def run(self):
        try:
            self.result = self.operation(self)
        except Exception as exc:
            self.error = exc


class AnalysisDialog(QDialog):
    def __init__(self, worker, parent=None):
        super().__init__(parent)
        self.worker = worker
        self.setWindowTitle(_("Analysis"))
        self.setWindowModality(Qt.ApplicationModal)
        self.setWindowFlag(Qt.WindowCloseButtonHint, False)
        self.setMinimumWidth(480)
        layout = QVBoxLayout(self)
        self.status_label = QLabel(_("Reading source objects..."))
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)
        self.progress_bar = QProgressBar()
        # LDAP supplies no reliable total before discovery has finished.
        self.progress_bar.setRange(0, 0)
        layout.addWidget(self.progress_bar)
        hint = QLabel(_("Analysis is running. Large domains may take several minutes."))
        hint.setWordWrap(True)
        layout.addWidget(hint)
        worker.stage_changed.connect(self.status_label.setText)
        worker.finished.connect(self.accept)

    def reject(self):
        # Do not destroy a running QThread or allow concurrent use of its LDAP
        # connections. LDAP timeouts still finish the operation with an error.
        if not self.worker.isRunning():
            super().reject()

    def closeEvent(self, event):
        if self.worker.isRunning():
            event.ignore()
        else:
            super().closeEvent(event)
