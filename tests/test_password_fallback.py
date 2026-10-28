"""Password policy defaults, bounded fallback and persistent migration outcomes."""
import os,sys
os.environ.setdefault('QT_QPA_PLATFORM','offscreen')
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
import unittest
from unittest.mock import patch
from tests import test_identity_tracking as fixture
from tests.test_identity_tracking import SRC,DST,USER,DU
from core.ldap_connector import LDAPOperationError
from core.migrator import Migrator
from utils.password_generator import PasswordGenerator
from utils.report_generator import ReportGenerator
from config import settings

class PasswordTests(unittest.TestCase):
    setUp=fixture.IdentityTests.setUp
    tearDown=fixture.IdentityTests.tearDown
    make_engine=fixture.IdentityTests.make_engine

    def engine_with_fixed(self, password='weak'):
        return Migrator(self.src,self.dst,self.db,self.logger,password_mode='fixed',fixed_password=password,password_length=21)

    def intercept(self, rejected=1, return_false=False):
        original=self.dst.modify
        passwords=[]
        def modify(dn,attrs):
            self.assertNotIn('userPassword',attrs)
            if 'unicodePwd' in attrs:
                pwd=attrs['unicodePwd'].decode('utf-16-le')[1:-1]
                passwords.append(pwd)
                if len(passwords)<=rejected:
                    if return_false:return False
                    raise LDAPOperationError('constraintViolation includes secret '+pwd)
            return original(dn,attrs)
        return passwords,modify

    def test_default_values_match_supplied_samba_policy(self):
        self.assertEqual(settings.DEFAULT_PASSWORD_POLICY,dict(complexity=True,store_plaintext=False,
            history_length=24,minimum_length=7,minimum_age_days=1,maximum_age_days=42,
            lockout_duration_minutes=30,lockout_threshold=0,reset_lockout_after_minutes=30))

    def test_generated_passwords_have_four_categories(self):
        for _ in range(50):
            pwd=PasswordGenerator.generate_compliant(7,forbidden=['user','admin'])
            self.assertEqual(len(pwd),7)
            self.assertTrue(any(c.islower() for c in pwd))
            self.assertTrue(any(c.isupper() for c in pwd))
            self.assertTrue(any(c.isdigit() for c in pwd))
            self.assertTrue(any(c in '_-!@#$%' for c in pwd))
            self.assertNotIn('user',pwd.lower())

    def test_fixed_rejection_uses_random_and_reports_warning_without_secrets(self):
        engine=self.engine_with_fixed()
        passwords,modify=self.intercept()
        with patch.object(self.dst,'modify',side_effect=modify):result=engine.migrate(USER)
        self.assertEqual(passwords[0],'weak')
        self.assertEqual(len(passwords),2)
        self.assertEqual(len(passwords[1]),21)
        self.assertEqual(result.status,'completed_with_warnings')
        self.assertEqual(self.dst.get_object_by_dn(DU)['attributes']['userAccountControl'],514)
        report=ReportGenerator(self.db).generate_text_report(result.run_id,Path(self.tmp.name)/'report.txt').read_text()
        log=(Path(self.tmp.name)/'test.log').read_text()
        errors=str(self.db.get_errors(result.run_id))
        for pwd in passwords:
            for content in (report,log,errors):self.assertNotIn(pwd,content)
        self.assertIn('Random fallback password accepted',report)

    def test_false_result_does_not_count_as_password_success(self):
        engine=self.engine_with_fixed()
        passwords,modify=self.intercept(return_false=True)
        with patch.object(self.dst,'modify',side_effect=modify):result=engine.migrate(USER)
        self.assertEqual(len(passwords),2)
        self.assertEqual(result.status,'completed_with_warnings')

    def test_retries_bounded_and_failure_keeps_mapping_for_retry(self):
        engine=self.engine_with_fixed()
        passwords,modify=self.intercept(rejected=99)
        with patch.object(self.dst,'modify',side_effect=modify):result=engine.migrate(USER)
        self.assertEqual(len(passwords),1+settings.PASSWORD_RANDOM_RETRIES)
        self.assertEqual(result.status,'completed_with_errors')
        mapped=engine.migration_db.get_object_by_source_guid(self.user_guid)
        self.assertEqual(mapped['error_message'],'PASSWORD_SETUP_PENDING')
        before=len(self.dst.add_log)
        retry=engine.migrate(USER)
        self.assertTrue(retry.success)
        self.assertEqual(len(self.dst.add_log),before)
        self.assertIsNone(engine.migration_db.get_object_by_source_guid(self.user_guid)['error_message'])

    def test_successful_existing_user_password_is_not_reset(self):
        engine=self.engine_with_fixed('Good-Password123')
        engine.migrate(USER)
        with patch.object(self.dst,'modify',side_effect=AssertionError('must not reset')):
            self.assertTrue(engine.migrate(USER).success)

    def test_destination_minimum_length_used_for_random_fallback(self):
        self.dst.entries[self.dst._key(DST)]['attributes']['minPwdLength']=30
        engine=self.engine_with_fixed()
        passwords,modify=self.intercept()
        with patch.object(self.dst,'modify',side_effect=modify):engine.migrate(USER)
        self.assertEqual(len(passwords[1]),30)

    def test_random_mode_also_retries(self):
        passwords,modify=self.intercept()
        with patch.object(self.dst,'modify',side_effect=modify):result=self.engine.migrate(USER)
        self.assertEqual(len(passwords),2)
        self.assertNotEqual(*passwords)
        self.assertEqual(result.status,'completed_with_warnings')

    def test_dry_run_does_not_generate_or_set_password(self):
        engine=Migrator(self.src,self.dst,self.db,self.logger,dry_run=True)
        with patch.object(PasswordGenerator,'generate_compliant',side_effect=AssertionError('not needed')):
            result=engine.migrate(USER)
        self.assertTrue(result.success)
        self.assertEqual(self.dst.modify_log,[])

    def test_ui_displays_defaults_and_fallback_notice(self):
        from PyQt5.QtWidgets import QApplication
        from gui.connection_dialog import ConnectionDialog
        from utils.config_manager import ConfigManager
        from utils.i18n import set_language
        app=QApplication.instance() or QApplication([])
        set_language('en')
        cfg=ConfigManager(Path(self.tmp.name)/'config.ini')
        dialog=ConnectionDialog(cfg)
        self.assertIn('minimum 7',dialog.password_policy_note.text())
        self.assertIn('fixed-password mode',dialog.password_fallback_note.text())
        self.assertEqual(dialog.password_length.minimum(),7)
        dialog.close()

if __name__=='__main__':unittest.main()
