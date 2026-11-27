"""Shared row selection, CSV export and migration-history file selection."""
import csv
import sqlite3
from pathlib import Path
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QTableWidget, QAbstractItemView, QMenu, QFileDialog, QMessageBox
from utils.i18n import _


class MigrationTable(QTableWidget):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self._menu)

    def _menu(self, position):
        menu = QMenu(self)
        export = menu.addAction(_("Export table to CSV…"))
        if menu.exec_(self.viewport().mapToGlobal(position)) == export:
            self.export_csv()

    def save_csv(self, path):
        # UTF-8 BOM and semicolon separator work with Russian spreadsheet tools.
        with open(path, 'w', encoding='utf-8-sig', newline='') as stream:
            writer = csv.writer(stream, delimiter=';')
            writer.writerow([self.horizontalHeaderItem(col).text() if self.horizontalHeaderItem(col) else ''
                             for col in range(self.columnCount())])
            for row in range(self.rowCount()):
                writer.writerow([self.item(row, col).text() if self.item(row, col) else ''
                                 for col in range(self.columnCount())])

    def export_csv(self):
        path, unused_filter = QFileDialog.getSaveFileName(self, _("Export table to CSV…"),
                                                         'migration-analysis.csv', 'CSV (*.csv)')
        if path:
            try:
                self.save_csv(path)
            except (OSError, UnicodeError) as exc:
                QMessageBox.critical(self, _("Error"), str(exc))


def validate_history_file(path):
    """Inspect without modifying an unrelated SQLite file."""
    connection = sqlite3.connect(Path(path).resolve().as_uri() + '?mode=ro', uri=True)
    try:
        for table, columns in {'migration_runs': {'run_id'}, 'migration_map': {'source_guid', 'dest_guid'},
                               'run_configurations': {'migration_run_id', 'options_json'}}.items():
            actual = {row[1] for row in connection.execute('PRAGMA table_info(' + table + ')')}
            if not columns <= actual:
                raise ValueError(_("This file is not a migration history database."))
    finally:
        connection.close()


def choose_history_file(parent, current):
    path, unused_filter = QFileDialog.getOpenFileName(parent, _("Use existing migration history…"),
                                                     str(current), 'SQLite (*.db *.sqlite *.sqlite3);;All files (*)')
    if not path:
        return None
    try:
        validate_history_file(path)
    except (OSError, sqlite3.Error, ValueError) as exc:
        QMessageBox.critical(parent, _("Error"), str(exc))
        return None
    return Path(path).resolve()
