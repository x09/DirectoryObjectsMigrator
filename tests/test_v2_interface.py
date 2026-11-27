"""Operator workflows: provider settings, scope, conflicts, history and export."""
import os
import sys
import csv
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
os.environ['QT_QPA_PLATFORM'] = 'offscreen'
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from PyQt5.QtWidgets import QApplication, QAbstractItemView, QDialog
from PyQt5.QtCore import Qt
from config import settings
from utils.config_manager import ConfigManager
from utils.i18n import set_language
from core.sources.freeipa import SourceObject
from core.freeipa_migration import FreeIPAPlan, PlannedObject
from database.migration_db import MigrationDB
from gui.main_window import MainWindow
from gui.connection_dialog import ConnectionDialog
from gui.freeipa_discovery import FreeIPAPlanDialog, COLORS
from gui.migration_table import MigrationTable, validate_history_file

APP = QApplication.instance() or QApplication([])


class InterfaceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.paths = patch.multiple(settings, CONFIG_DIR=self.root, CONFIG_FILE=self.root/'settings.ini',
                                    DB_FILE=self.root/'history.db', LOGS_DIR=self.root, REPORTS_DIR=self.root)
        self.paths.start()
        set_language('en')
        self.config = ConfigManager()
        self.config.set_source_dc_config({'source_provider':'freeipa','host':'ipa.test','domain':'ipa.test','username':'admin'})
        self.config.set_dest_dc_config({'host':'ad.test','domain':'ad.test','username':'admin'})

    def tearDown(self):
        for window in APP.topLevelWidgets():
            window.close()
            window.deleteLater()
        APP.processEvents()
        self.paths.stop()
        self.temp.cleanup()

    def plan(self):
        return FreeIPAPlan('source', 'target', rows=[
            PlannedObject(SourceObject('user', f'uid={action},cn=users,dc=ipa,dc=test', action, action, {}),
                          target_dn=f'CN={action},CN=Users,DC=ad,DC=test', action=action,
                          reason='Destination identity already exists: sAMAccountName=user' if action=='conflict' else '')
            for action in ('conflict', 'error', 'skip', 'create', 'exists')])

    def test_ad_scope_hidden_in_freeipa_and_restored_without_losing_dn(self):
        window = MainWindow()
        window.base_dn_input.setText('OU=Keep,DC=ad,DC=test')
        self.assertTrue(window.base_dn_row.isHidden())
        self.assertFalse(window.freeipa_scope_label.isHidden())
        window.config_manager.set_source_dc_config({'source_provider':'ad','host':'ad.test','domain':'ad.test'})
        window._check_connections()
        self.assertFalse(window.base_dn_row.isHidden())
        self.assertTrue(window.freeipa_scope_label.isHidden())
        self.assertEqual(window.base_dn_input.text(), 'OU=Keep,DC=ad,DC=test')

    def test_source_provider_saved_by_dialog_and_legacy_ini_supported(self):
        legacy = self.root/'legacy.ini'
        legacy.write_text('[SourceDC]\nsource_type=freeipa\nhost=ipa.test\ndomain=ipa.test\n')
        config = ConfigManager(legacy)
        self.assertEqual(config.get_source_dc_config()['source_provider'], 'freeipa')
        dialog = ConnectionDialog(config)
        dialog.source_password.setText('not-persisted-admin-secret')
        with patch('gui.connection_dialog.QMessageBox.information'):
            dialog._save_settings()
        saved = ConfigManager(legacy)
        self.assertEqual(saved.config.get('SourceDC','source_provider'), 'freeipa')
        self.assertFalse(saved.config.has_option('SourceDC','source_type'))
        self.assertNotIn('not-persisted-admin-secret',legacy.read_text())
        dialog.source_type.setCurrentIndex(0)
        dialog.dest_host.setText('ad.test');dialog.dest_domain.setText('ad.test')
        with patch('gui.connection_dialog.QMessageBox.information'):
            dialog._save_settings()
        self.assertEqual(ConfigManager(legacy).config.get('SourceDC','source_provider'),'ad')

    def test_login_shortening_checkbox_saved_and_only_visible_for_freeipa(self):
        dialog = ConnectionDialog(self.config)
        self.assertFalse(dialog.source_shorten_logins.isChecked())
        self.assertFalse(dialog.source_shorten_logins.isHidden())
        dialog.source_shorten_logins.setChecked(True)
        with patch('gui.connection_dialog.QMessageBox.information'):
            dialog._save_settings()
        restored = ConfigManager(self.config.config_file)
        self.assertTrue(restored.get_source_dc_config()['shorten_long_logins'])
        dialog.source_type.setCurrentIndex(0)
        self.assertTrue(dialog.source_shorten_logins.isHidden())
        dialog.source_type.setCurrentIndex(1)
        self.assertTrue(dialog.source_shorten_logins.isChecked())
        plan = self.plan()
        plan.login_statistics = dict(total=152,eligible=150,generated=140,retained=10,digits=3)
        preview = FreeIPAPlanDialog(plan)
        self.assertIn('152', preview.login_summary.text())
        self.assertIn('140', preview.login_summary.text())

    def test_colors_full_row_details_and_exclusion_action(self):
        plan = self.plan()
        dialog = FreeIPAPlanDialog(plan, history_path=self.root/'history.db')
        self.assertFalse(dialog.proceed_btn.isEnabled())
        for i, row in enumerate(plan.rows):
            self.assertEqual(dialog.table.item(i,0).background().color(),COLORS[row.action])
        dialog.table.selectRow(0)
        self.assertEqual(len(dialog.table.selectedIndexes()),dialog.table.columnCount())
        self.assertIn('history database',dialog.details.toPlainText())
        dialog.exclude_btn.click()
        self.assertEqual(dialog.result(),FreeIPAPlanDialog.EXCLUDE_AND_REANALYZE)
        self.assertEqual(dialog.excluded_dns,[plan.rows[0].source.dn])

    def test_duplicate_identity_cannot_be_bypassed(self):
        plan = self.plan()
        plan.rows[0].reason='Missing, invalid or duplicate ipaUniqueID'
        dialog=FreeIPAPlanDialog(plan)
        dialog.table.selectRow(0)
        self.assertFalse(dialog.exclude_btn.isEnabled())
        self.assertFalse(dialog.proceed_btn.isEnabled())

    def test_export_context_action_writes_all_rows_with_unicode_and_quotes(self):
        table=MigrationTable(2,2)
        table.setHorizontalHeaderLabels(['DN','Причина'])
        from PyQt5.QtWidgets import QTableWidgetItem
        data=[['uid=Тест,dc=ipa,dc=test','Текст; "кавычки"\nвторая строка'],['uid=second,dc=ipa,dc=test','']]
        for i,row in enumerate(data):
            for j,value in enumerate(row):table.setItem(i,j,QTableWidgetItem(value))
        table.selectRow(0)
        path=self.root/'export.csv'
        with patch('gui.migration_table.QFileDialog.getSaveFileName', return_value=(str(path),'CSV')):
            table.export_csv()
        with path.open(encoding='utf-8-sig',newline='') as stream:
            self.assertEqual(list(csv.reader(stream,delimiter=';')),[['DN','Причина']]+data)
        self.assertEqual(table.contextMenuPolicy(),Qt.CustomContextMenu)
        self.assertEqual(table.selectionBehavior(),QAbstractItemView.SelectRows)

    def test_history_selection_persists_and_invalidates_old_plan(self):
        other=self.root/'existing.db'
        db=MigrationDB(other);db.close()
        validate_history_file(other)
        invalid=self.root/'unrelated.db'
        import sqlite3
        c=sqlite3.connect(invalid);c.execute('CREATE TABLE unrelated (id INTEGER)');c.close()
        with self.assertRaises(ValueError):validate_history_file(invalid)
        window=MainWindow();window.last_run_id=123;window.migration_plan=self.plan()
        with patch('gui.migration_table.choose_history_file',return_value=other):
            self.assertTrue(window._choose_history())
        self.assertEqual(ConfigManager().get_database_path(),other)
        self.assertIsNone(window.migration_plan)
        self.assertIsNone(window.last_run_id)
        dialog=ConnectionDialog(ConfigManager())
        self.assertEqual(dialog.database_path,other)

    def test_excluding_conflict_saves_exact_dn_and_requests_new_analysis(self):
        window=MainWindow()
        plan=self.plan()
        window._freeipa_operation=lambda: lambda worker: plan
        def exclude(dialog):
            dialog.table.selectRow(0)
            dialog._exclude()
            return dialog.result()
        with patch.object(FreeIPAPlanDialog,'exec_',exclude), patch('gui.main_window.QTimer.singleShot') as schedule:
            window._analyze_freeipa()
            schedule.assert_called_once()
        self.assertIn(plan.rows[0].source.dn,ConfigManager().get_custom_exclusions())
        self.assertIsNone(window.migration_plan)
        self.assertFalse(window.migrate_btn.isEnabled())

    def test_empty_reasons_stay_empty_with_russian_catalogue(self):
        set_language("ru")
        dialog = FreeIPAPlanDialog(self.plan())
        self.assertEqual(dialog.table.item(4, 4).text(), "")
        self.assertIn("Идентификатор", dialog.table.item(0, 4).text())

    def test_recreation_requires_explicit_confirmation_and_marks_new_plan(self):
        from PyQt5.QtWidgets import QMessageBox
        plan = self.plan()
        row = plan.rows[1]
        row.recreation = {'direction_id': 'direction', 'old_guid': 'old-guid',
                          'old_dn': row.target_dn, 'object_type': 'user'}
        dialog = FreeIPAPlanDialog(plan)
        dialog.table.selectRow(0)
        self.assertFalse(dialog.recreate_btn.isEnabled())
        dialog.table.selectRow(1)
        self.assertTrue(dialog.recreate_btn.isEnabled())
        with patch('gui.freeipa_discovery.QMessageBox.exec_', return_value=QMessageBox.No):
            dialog._recreate()
        self.assertEqual(dialog.requested_recreations, {})
        self.assertNotEqual(dialog.result(), FreeIPAPlanDialog.RECREATE_AND_REANALYZE)
        with patch('gui.freeipa_discovery.QMessageBox.exec_', return_value=QMessageBox.Yes):
            dialog._recreate()
        self.assertEqual(dialog.result(), FreeIPAPlanDialog.RECREATE_AND_REANALYZE)
        self.assertEqual(dialog.requested_recreations, {row.source.source_id: row.recreation})
        self.assertEqual(row.action, 'error', 'Confirmation must trigger fresh analysis, not edit a stale plan')

    def test_recreation_confirmation_is_forwarded_to_background_reanalysis(self):
        window = MainWindow()
        plan = self.plan()
        request = {'user-id': {'old_guid': 'old-guid'}}
        window._freeipa_operation = lambda: lambda worker: plan
        def confirm(dialog):
            dialog.requested_recreations = request
            return FreeIPAPlanDialog.RECREATE_AND_REANALYZE
        with patch.object(FreeIPAPlanDialog, 'exec_', confirm), patch('gui.main_window.QTimer.singleShot') as schedule:
            window._analyze_freeipa()
        self.assertIsNone(window.migration_plan)
        with patch.object(window, '_analyze_freeipa') as analyze:
            schedule.call_args.args[1]()
            analyze.assert_called_once_with(request)
        self.assertNotIn('old-guid', settings.CONFIG_FILE.read_text())

    def test_attribute_editor_is_freeipa_only_and_persists_rows(self):
        from core.freeipa_attributes import default_mappings
        dialog = ConnectionDialog(self.config)
        editor = dialog.attribute_mappings_tab
        self.assertTrue(dialog.tabs.isTabEnabled(dialog.attribute_mappings_index))
        self.assertEqual(editor.rows(), default_mappings())
        rows = [{'kind':'user','source':'ipaSshPubKey','target':'altSecurityIdentities','mode':'all','enabled':True},
                {'kind':'group','source':'description','target':'info','mode':'all','enabled':False}]
        editor.load_rows(rows)
        with patch('gui.connection_dialog.QMessageBox.information'):
            dialog._save_settings()
        self.assertEqual(ConfigManager().get_freeipa_mappings(), rows)
        ad = ConnectionDialog(ConfigManager())
        ad.source_type.setCurrentIndex(0)
        self.assertFalse(ad.tabs.isTabEnabled(ad.attribute_mappings_index))
        ad.attribute_mappings_tab.load_rows([])
        with patch('gui.connection_dialog.QMessageBox.information'):
            ad._save_settings()
        self.assertEqual(ConfigManager().get_freeipa_mappings(), rows, 'AD settings must not replace FreeIPA rules')

    def test_attribute_warnings_visible_and_exportable_without_blocking_creation(self):
        plan = self.plan()
        plan.rows = [plan.rows[3]]
        plan.attribute_warnings = ['sn → typo: missing attribute']
        plan.rows[0].attribute_warnings = ['mail → mail: too many values']
        dialog = FreeIPAPlanDialog(plan)
        self.assertTrue(dialog.proceed_btn.isEnabled())
        self.assertEqual(dialog.attribute_table.rowCount(), 2)
        path = self.root/'warnings.csv'
        dialog.attribute_table.save_csv(path)
        self.assertIn('sn → typo', path.read_text(encoding='utf-8-sig'))

    def test_about_describes_both_sources(self):
        window=MainWindow()
        with patch('gui.main_window.QMessageBox.about') as about:
            window._show_about()
        self.assertIn('AD/FreeIPA',about.call_args.args[2])
        self.assertIn('Samba AD',about.call_args.args[2])


if __name__=='__main__':unittest.main(verbosity=2)
