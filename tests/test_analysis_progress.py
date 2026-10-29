"""Analysis keeps the GUI responsive and never exposes stale plans on failure."""
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
_temp = tempfile.TemporaryDirectory()
os.environ['XDG_CONFIG_HOME'] = _temp.name
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
from PyQt5.QtWidgets import QApplication, QDialog
from PyQt5.QtCore import QTimer, QThread
from config import settings
from utils.i18n import set_language
from gui.main_window import MainWindow
from gui.analysis_dialog import AnalysisDialog
from gui.progress_window import ProgressWindow

app = QApplication.instance() or QApplication([])
settings.CONFIG_DIR = Path(_temp.name)
settings.CONFIG_FILE = settings.CONFIG_DIR / 'test.ini'
settings.LOGS_DIR = settings.CONFIG_DIR / 'logs'
settings.REPORTS_DIR = settings.CONFIG_DIR / 'reports'
settings.DB_FILE = settings.CONFIG_DIR / 'test.db'
settings.ensure_directories()


class AnalysisProgressTests(unittest.TestCase):
    def test_migration_phase_messages_are_translated(self):
        set_language('ru')
        dialog = ProgressWindow()
        for percent, message, expected in [
            (0, 'Analyzing source domain...', 'Анализ исходного домена...'),
            (20, 'Creating organizational units...', 'Создание подразделений...'),
            (40, 'Creating objects...', 'Создание объектов...'),
            (60, 'Copying attributes...', 'Копирование атрибутов...'),
            (80, 'Resolving references...', 'Обработка ссылок...'),
            (95, 'Verifying results...', 'Проверка результатов...')]:
            dialog.update_progress(percent, message)
            self.assertEqual(dialog.status_label.text(), expected)
        dialog.deleteLater()

    def exercise_analysis(self, failure=None):
        window = MainWindow()
        window.base_dn_input.setText('DC=source,DC=alt')
        window.source_conn = Mock()
        window.dest_conn = Mock()
        window.migration_db = Mock()
        window.analysis_result = 'stale'
        window.migration_plan = 'stale'
        analysis = SimpleNamespace(total_objects=10)
        plan = Mock()
        plan.summary.return_value = dict(create=10, exists=0, conflict=0, deferred=0)
        stages = []
        ticks = []
        gui_thread = QThread.currentThread()

        def read(*args, **kwargs):
            self.assertNotEqual(QThread.currentThread(), gui_thread)
            time.sleep(.08)
            if failure == 'read':
                raise RuntimeError('LDAP read failed')
            return analysis

        def build(*args):
            self.assertNotEqual(QThread.currentThread(), gui_thread)
            time.sleep(.08)
            if failure == 'plan':
                raise RuntimeError('Destination check failed')
            return plan

        def tick():
            ticks.append(1)
            dialog = app.activeModalWidget()
            if isinstance(dialog, AnalysisDialog):
                stages.append(dialog.status_label.text())
                self.assertEqual(dialog.progress_bar.maximum(), 0)
                dialog.reject()  # Escape cannot destroy the running worker.
                self.assertTrue(dialog.isVisible())

        timer = QTimer()
        timer.timeout.connect(tick)
        timer.start(10)
        with patch.object(window, '_ensure_source_connected'), patch.object(window, '_ensure_dest_connected'), \
             patch('core.analyzer.Analyzer') as analyzer, \
             patch('gui.main_window.Migrator') as migrator, \
             patch('gui.main_window.PreviewDialog') as preview, \
             patch('gui.main_window.QMessageBox.critical') as critical:
            analyzer.return_value.analyze.side_effect = read
            migrator.return_value.build_plan.side_effect = build
            preview.return_value.exec_.return_value = QDialog.Rejected
            window._analyze()
            if failure:
                self.assertIsNone(window.analysis_result)
                self.assertIsNone(window.migration_plan)
                self.assertFalse(window.migrate_btn.isEnabled())
                critical.assert_called_once()
                preview.assert_not_called()
            else:
                self.assertIs(window.analysis_result, analysis)
                self.assertIs(window.migration_plan, plan)
                self.assertTrue(window.migrate_btn.isEnabled())
                preview.assert_called_once()
                self.assertGreaterEqual(len(set(stages)), 2)
            self.assertGreater(len(ticks), 2)
        timer.stop()
        window.deleteLater()
        app.processEvents()

    def test_success(self):
        self.exercise_analysis()

    def test_read_failure(self):
        self.exercise_analysis('read')

    def test_plan_failure(self):
        self.exercise_analysis('plan')


if __name__ == '__main__':
    unittest.main()
