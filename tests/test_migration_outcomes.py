"""Failure injection for LDAP acknowledgement, retryability and end-to-end status."""
import os
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import tempfile
import unittest
from unittest.mock import patch
from datetime import datetime

from core.migrator import Migrator, MigrationResult
from core.analyzer import AnalysisResult
from core.verifier import VerificationResult
from core.ldap_connector import LDAPOperationError
from database.migration_db import MigrationDB
from tests.fake_ldap import FakeLDAPConnector
from utils.logger import MigrationLogger
from utils.report_generator import ReportGenerator

SRC = 'DC=source,DC=alt'
DST = 'DC=dest,DC=alt'
USER = 'CN=user,' + SRC
GROUP = 'CN=group,' + SRC
DEST_USER = 'CN=user,' + DST
DEST_GROUP = 'CN=group,' + DST


class OutcomeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = MigrationDB(Path(self.tmp.name) / 'migration.db')
        self.logger = MigrationLogger(log_file=Path(self.tmp.name) / 'test.log')
        self.logger.set_log_level('ERROR')
        self.src = FakeLDAPConnector('source.alt')
        self.dst = FakeLDAPConnector('dest.alt')
        self.src.seed(SRC, ['domain'])
        self.dst.seed(DST, ['domain'])
        self.src.seed(USER, ['user'], cn='user', sAMAccountName='user')
        self.src.seed(GROUP, ['group'], cn='group', sAMAccountName='group',
                      groupType=-2147483646, member=[USER])
        self.engine = self.make_engine()

    def make_engine(self, **kwargs):
        return Migrator(self.src, self.dst, self.db, self.logger, **kwargs)

    def tearDown(self):
        for handler in list(self.logger.logger.handlers):
            handler.close()
            self.logger.logger.removeHandler(handler)
        self.db.close()
        self.tmp.cleanup()

    def pending(self, duplicate=False):
        result = self.engine.migrate(SRC)
        self.assertEqual(result.status, 'completed')
        self.dst.entries[self.dst._key(DEST_GROUP)]['attributes']['member'] = []
        guid = self.src.entries[self.src._key(GROUP)]['attributes']['objectGUID']
        for _ in range(2 if duplicate else 1):
            self.db.add_deferred_reference(guid, DEST_GROUP, 'group', 'member', USER, result.run_id)
        return result.run_id

    def assert_status(self, result, status, success):
        self.assertEqual(result.status, status)
        self.assertEqual(result.success, success)
        self.assertEqual(self.db.get_statistics(result.run_id)['status'], status)
        self.assertEqual(self.db.get_statistics(result.run_id)['errors_count'], result.errors_count)
        self.assertIsNotNone(result.end_time)

    def test_deferred_rejection_stays_pending_and_next_run_retries(self):
        self.pending()
        with patch.object(self.dst, 'modify_add_values', side_effect=LDAPOperationError('denied')):
            result = self.make_engine().migrate(SRC)
        self.assert_status(result, 'completed_with_errors', False)
        self.assertEqual(result.phase_results['phase4_references']['resolved'], 0)
        self.assertEqual(len(self.db.get_unresolved_references()), 1)
        self.assertEqual(self.dst.members_of(DEST_GROUP), [])
        retry = self.make_engine().migrate(SRC)
        self.assert_status(retry, 'completed', True)
        self.assertEqual(self.db.get_unresolved_references(), [])
        self.assertEqual(self.dst.members_of(DEST_GROUP), [DEST_USER])

    def test_mark_resolved_happens_after_ldap_and_deduplicates_values(self):
        run_id = self.pending(duplicate=True)
        original = self.db.mark_reference_resolved
        def mark(*args):
            self.assertIn(DEST_USER, self.dst.members_of(DEST_GROUP))
            return original(*args)
        with patch.object(self.db, 'mark_reference_resolved', side_effect=mark), \
                patch.object(self.dst, 'modify_add_values', wraps=self.dst.modify_add_values) as write:
            resolved, pending = self.engine.reference_resolver.process_deferred_references(run_id)
        self.assertEqual((resolved, pending), (2, 0))
        write.assert_called_once_with(DEST_GROUP, {'member': [DEST_USER]})

    def test_false_ldap_result_does_not_acknowledge(self):
        run_id = self.pending()
        with patch.object(self.dst, 'modify_add_values', return_value=False):
            counts = self.engine.reference_resolver.process_deferred_references(run_id)
        self.assertEqual(counts, (0, 1))
        self.assertEqual(len(self.db.get_unresolved_references()), 1)

    def test_lost_reply_after_server_write_is_recovered_without_second_write(self):
        run_id = self.pending()
        write = self.dst.modify_add_values
        def lost_reply(*args):
            write(*args)
            raise LDAPOperationError('connection lost after server applied the write')
        with patch.object(self.dst, 'modify_add_values', side_effect=lost_reply):
            self.assertEqual(self.engine.reference_resolver.process_deferred_references(run_id), (0, 1))
        with patch.object(self.dst, 'modify_add_values', side_effect=AssertionError('must not rewrite')):
            self.assertEqual(self.engine.reference_resolver.process_deferred_references(run_id), (1, 0))
        self.assertEqual(self.db.get_unresolved_references(), [])

    def test_first_write_failure_is_reported_and_saved_for_retry(self):
        with patch.object(self.dst, 'modify_add_values', side_effect=LDAPOperationError('denied')):
            result = self.engine.migrate(SRC)
        self.assert_status(result, 'completed_with_errors', False)
        self.assertGreater(result.errors_count, 0)
        self.assertEqual(len(self.db.get_unresolved_references()), 1)
        self.assert_status(self.make_engine().migrate(SRC), 'completed', True)
        self.assertEqual(self.dst.members_of(DEST_GROUP), [DEST_USER])

    def test_dry_run_leaves_pending_rows_and_destination_unchanged(self):
        self.pending()
        before = [dict(row) for row in self.db.get_unresolved_references()]
        writes = list(self.dst.modify_log)
        self.make_engine(dry_run=True).migrate(SRC)
        self.assertEqual(self.db.get_unresolved_references(), before)
        self.assertEqual(self.dst.modify_log, writes)

    def test_object_failure_is_partial_result(self):
        original = self.dst.add
        def fail_user(dn, *args, **kwargs):
            if dn == DEST_USER:
                raise LDAPOperationError('schema rejection')
            return original(dn, *args, **kwargs)
        with patch.object(self.dst, 'add', side_effect=fail_user):
            result = self.engine.migrate(SRC)
        self.assert_status(result, 'completed_with_errors', False)
        self.assertGreater(result.errors_count, 0)
        self.assertTrue(self.dst.object_exists(DEST_GROUP))

    def test_verification_failure_is_not_success(self):
        verification = VerificationResult()
        verification.add_error('Missing expected object')
        with patch.object(self.engine, '_phase5_verify', return_value=verification):
            result = self.engine.migrate(SRC)
        self.assert_status(result, 'completed_with_errors', False)
        self.assertIn('Missing expected object', self.db.get_latest_run()['notes'])

    def test_verification_read_error_is_not_empty_success(self):
        self.engine.migrate(SRC)
        with patch.object(self.dst, 'search', side_effect=LDAPOperationError('timeout')):
            verification = self.engine.verifier.verify(SRC, self.engine.current_run_id)
        self.assertFalse(verification.success)
        self.assertTrue(verification.errors)

    def test_untracked_conflict_cannot_pass_content_verification(self):
        self.dst.seed(DEST_USER, ['user'], cn='user', sAMAccountName='user')
        result = self.engine.migrate(SRC)
        self.assert_status(result, 'completed_with_errors', False)
        self.assertIn(USER, result.verification_result.missing_objects)
        self.assertEqual(result.objects_conflicted, 1)

    def test_expected_out_of_scope_reference_is_warning_not_error(self):
        self.src.entries[self.src._key(GROUP)]['attributes']['member'].append('CN=outside,OU=Other,' + SRC)
        result = self.engine.migrate(SRC)
        self.assert_status(result, 'completed_with_warnings', True)
        self.assertEqual(result.errors_count, 0)

    def test_fatal_failure_preserves_run_for_report(self):
        with patch.object(self.engine, '_phase_analysis', side_effect=LDAPOperationError('offline')):
            result = self.engine.migrate(SRC)
        self.assert_status(result, 'failed', False)
        self.assertEqual(result.failure_message, 'offline')
        self.assertIn('offline', self.db.get_latest_run()['notes'])

    def test_cancellation_skips_later_phases(self):
        self.engine.progress_callback = lambda percent, _: self.engine.cancel() if percent == 20 else None
        with patch.object(self.engine, '_phase4_resolve_references') as refs:
            result = self.engine.migrate(SRC)
        self.assert_status(result, 'cancelled', False)
        refs.assert_not_called()

    def test_empty_scope_finishes_database_run(self):
        with patch.object(self.engine, '_phase_analysis', return_value=AnalysisResult(SRC)):
            result = self.engine.migrate(SRC)
        self.assert_status(result, 'completed', True)

    def test_reports_contain_partial_status(self):
        with patch.object(self.dst, 'modify_add_values', side_effect=LDAPOperationError('denied')):
            result = self.engine.migrate(SRC)
        generator = ReportGenerator(self.db)
        html = generator.generate_html_report(result.run_id, Path(self.tmp.name) / 'report.html')
        txt = generator.generate_text_report(result.run_id, Path(self.tmp.name) / 'report.txt')
        self.assertIn('COMPLETED_WITH_ERRORS', Path(html).read_text())
        self.assertIn('COMPLETED_WITH_ERRORS', Path(txt).read_text())


class GUIOutcomeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from PyQt5.QtWidgets import QApplication
        cls.app = QApplication.instance() or QApplication([])

    def test_labels_and_report_access_for_all_outcomes(self):
        from gui.main_window import MainWindow
        from gui.progress_window import ProgressWindow, completion_title
        from utils.i18n import set_language
        set_language('ru')
        with patch('gui.main_window.ConfigManager') as config:
            config.return_value.get_last_base_dn.return_value = ''
            config.return_value.get_source_dc_config.return_value = {}
            config.return_value.get_dest_dc_config.return_value = {}
            window = MainWindow()
        for status in ('completed', 'completed_with_errors', 'completed_with_warnings', 'failed', 'cancelled'):
            result = MigrationResult(status=status, run_id=1,
                                     success=status in ('completed', 'completed_with_warnings'))
            progress = ProgressWindow()
            progress.progress_bar.setValue(40)
            window._migration_complete(progress, result.success, result)
            self.assertEqual(progress.status_label.text(), completion_title(status))
            self.assertEqual(window.statusBar.currentMessage(), completion_title(status))
            self.assertTrue(window.report_btn.isEnabled())
            if status in ('failed', 'cancelled'):
                self.assertEqual(progress.progress_bar.value(), 40)
            progress.close()
        window.close()
        set_language('en')


if __name__ == '__main__':
    unittest.main()
