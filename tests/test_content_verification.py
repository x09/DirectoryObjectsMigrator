"""Detect content loss despite matching directory object counts."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import unittest
from unittest.mock import patch
from tests import test_identity_tracking as fixtures
from tests.test_identity_tracking import SRC, DST, USER, GROUP, DU, DG, move
from utils.report_generator import ReportGenerator
from core.ldap_connector import LDAPOperationError

class ContentVerificationTests(unittest.TestCase):
    setUp = fixtures.IdentityTests.setUp
    tearDown = fixtures.IdentityTests.tearDown
    make_engine = fixtures.IdentityTests.make_engine

    def migrate(self):
        result = self.engine.migrate(SRC)
        self.assertTrue(result.success, result.verification_result.errors if result.verification_result else result.failure_message)
        return result

    def verify(self):
        return self.engine.verifier.verify(SRC, self.engine.current_run_id)

    def test_clean_migration_checks_objects_attributes_and_members(self):
        result=self.migrate().verification_result
        self.assertEqual(result.checked_objects,2)
        self.assertGreater(result.checked_attributes,0)
        self.assertGreater(result.checked_references,0)
        self.assertEqual(result.findings,[])

    def test_replacement_keeps_count_but_fails_identity(self):
        self.migrate()
        self.dst.entries.pop(self.dst._key(DU))
        self.dst.seed(DU,['user'],cn='user',sAMAccountName='user')
        result=self.verify()
        self.assertEqual(result.source_counts,result.dest_counts)
        self.assertFalse(result.success)
        self.assertTrue(any(f['source_dn']==USER for f in result.findings))

    def test_untracked_same_named_object_is_not_verified(self):
        self.dst.seed(DU,['user'],cn='user',sAMAccountName='user')
        result=self.engine.migrate(SRC)
        self.assertFalse(result.success)
        self.assertIn(USER,result.verification_result.missing_objects)

    def test_dropped_and_changed_attributes_detected(self):
        self.src.entries[self.src._key(USER)]['attributes'].update(description='original',department='IT')
        self.migrate()
        target=self.dst.entries[self.dst._key(DU)]['attributes']
        target.pop('description');target['department']='Finance'
        result=self.verify()
        self.assertFalse(result.success)
        attrs={f['attribute'] for f in result.findings}
        self.assertTrue({'description','department'} <= attrs)

    def test_transforms_and_unordered_scalar_multivalue_equivalence(self):
        self.src.entries[self.src._key(USER)]['attributes'].update(
            mail='user@source.alt',userPrincipalName='user@source.alt',
            proxyAddresses=['SMTP:user@source.alt','smtp:alias@source.alt'],description='description')
        self.migrate()
        target=self.dst.entries[self.dst._key(DU)]['attributes']
        target['proxyAddresses'].reverse()
        target['description']=['description']
        target['USERACCOUNTCONTROL']=str(target.pop('userAccountControl'))
        self.assertTrue(self.verify().success)

    def test_missing_member_and_unexpected_member_with_same_count(self):
        self.migrate()
        other='CN=unrelated,'+DST
        self.dst.seed(other,['user'],sAMAccountName='unrelated')
        self.dst.entries[self.dst._key(DG)]['attributes']['member']=[other]
        result=self.verify()
        self.assertFalse(result.success)
        kinds={f['kind'] for f in result.findings}
        self.assertIn('Missing reference values',kinds)
        self.assertIn('Unexpected reference values',kinds)

    def test_nested_group_and_manager_managedby_are_verified(self):
        nested='CN=nested,'+SRC
        self.src.seed(nested,['group'],cn='nested',sAMAccountName='nested',groupType=-2147483646)
        self.src.entries[self.src._key(GROUP)]['attributes'].update(member=[USER,nested],managedBy=USER)
        self.src.entries[self.src._key(USER)]['attributes']['manager']=USER
        self.migrate()
        self.dst.entries[self.dst._key(DU)]['attributes'].pop('manager')
        self.dst.entries[self.dst._key(DG)]['attributes'].pop('managedBy')
        self.dst.entries[self.dst._key(DG)]['attributes']['member']=[DU]
        result=self.verify()
        self.assertFalse(result.success)
        attrs={f['attribute'] for f in result.findings}
        self.assertTrue({'member','manager','managedBy'} <= attrs)

    def test_deferred_external_target_is_warning(self):
        self.src.entries[self.src._key(GROUP)]['attributes']['member'].append('CN=outside,OU=Other,'+SRC)
        result=self.migrate().verification_result
        self.assertTrue(result.success)
        self.assertTrue(any(f['kind']=='Deferred reference' for f in result.findings))

    def test_resolved_row_does_not_hide_lost_membership(self):
        self.engine.migrate(GROUP)
        self.engine.migrate(USER)
        self.assertEqual(self.engine.migration_db.get_unresolved_references(),[])
        self.dst.entries[self.dst._key(DG)]['attributes']['member']=[]
        self.assertFalse(self.verify().success)

    def test_ranged_response_is_not_reported_complete(self):
        self.migrate()
        target=self.dst.entries[self.dst._key(DG)]['attributes']
        target.pop('member');target['member;range=0-1499']=[DU]
        result=self.verify()
        self.assertFalse(result.success)
        self.assertTrue(any(f['kind']=='Incomplete reference read' for f in result.findings))

    def test_read_failure_is_verification_failure(self):
        self.migrate()
        original=self.dst.get_object_by_dn
        def fail(dn,attributes=None):
            if dn==DU and attributes and 'primaryGroupID' in attributes:
                raise LDAPOperationError('access denied')
            return original(dn,attributes)
        with patch.object(self.dst,'get_object_by_dn',side_effect=fail):
            result=self.verify()
        self.assertFalse(result.success)
        self.assertTrue(any('access denied' in message for message in result.errors))

    def test_disabled_flag_and_primary_group_are_checked(self):
        self.migrate()
        self.dst.entries[self.dst._key(DU)]['attributes'].update(userAccountControl=512,primaryGroupID=512)
        result=self.verify()
        self.assertFalse(result.success)
        self.assertTrue({'userAccountControl','primaryGroupID'} <= {f['attribute'] for f in result.findings})

    def test_server_uac_flags_and_signed_grouptype_do_not_fail(self):
        self.migrate()
        self.dst.entries[self.dst._key(DU)]['attributes']['userAccountControl']=514|0x10000
        self.dst.entries[self.dst._key(DG)]['attributes']['groupType']='2147483650'
        self.assertTrue(self.verify().success)

    def test_verifier_has_no_directory_or_mapping_writes(self):
        self.migrate()
        before=[dict(row) for row in self.db.connection.execute('SELECT * FROM migration_map')]
        with (patch.object(self.dst,'modify',side_effect=AssertionError('write')),
              patch.object(self.dst,'modify_add_values',side_effect=AssertionError('write'))):
            self.assertTrue(self.verify().success)
        self.assertEqual(before,[dict(row) for row in self.db.connection.execute('SELECT * FROM migration_map')])

    def test_ou_attributes_and_managedby_are_migrated_and_verified(self):
        ou='OU=People,'+SRC
        dest='OU=People,'+DST
        self.src.seed(ou,['organizationalUnit'],ou='People',description='OU description',managedBy=USER)
        self.migrate()
        attrs=self.dst.entries[self.dst._key(dest)]['attributes']
        self.assertEqual(attrs['ou'],'People')
        self.assertEqual(attrs['description'],'OU description')
        self.assertIn(DU,attrs['managedBy'])
        attrs.pop('description');attrs.pop('managedBy')
        result=self.verify()
        self.assertFalse(result.success)
        self.assertTrue({'description','managedBy'} <= {f['attribute'] for f in result.findings})

    def test_updated_deferred_parent_outside_scope_is_verified(self):
        self.engine.migrate(GROUP)
        original=self.engine._phase5_verify
        def corrupt(base_dn):
            self.dst.entries[self.dst._key(DG)]['attributes']['member']=[]
            return original(base_dn)
        with patch.object(self.engine,'_phase5_verify',side_effect=corrupt):
            result=self.engine.migrate(USER)
        self.assertFalse(result.success)
        self.assertTrue(any(f['source_dn']==GROUP and f['kind']=='Missing reference values'
                            for f in result.verification_result.findings))

    def test_moved_target_outside_converted_base_is_verified_by_guid(self):
        self.migrate()
        self.dst.seed('OU=Other,'+DST,['organizationalUnit'],ou='Other')
        move(self.dst,DU,'CN=user,OU=Other,'+DST)
        result=self.engine.verifier.verify(USER,self.engine.current_run_id)
        self.assertEqual(result.dest_counts['user'],0)
        self.assertEqual(result.checked_objects,1)
        self.assertTrue(result.success,result.errors)

    def test_expiry_never_sentinels_equivalent_but_far_future_is_not(self):
        from core.verifier import Verifier
        normalize=Verifier._normalized
        self.assertEqual(normalize(0,'accountExpires'),normalize('9223372036854775807','accountExpires'))
        self.assertNotEqual(normalize(9223372036854775807,'accountExpires'),
                            normalize(2650467743990000000,'accountExpires'))
        self.assertNotEqual(normalize(133000000000000001,'accountExpires'),
                            normalize(133000000000000000,'accountExpires'))

    def test_contact_values_are_checked(self):
        source='CN=contact,'+SRC
        dest='CN=contact,'+DST
        self.src.seed(source,['contact'],cn='contact',mail='contact@source.alt',telephoneNumber='123')
        self.migrate()
        self.dst.entries[self.dst._key(dest)]['attributes']['telephoneNumber']='456'
        result=self.verify()
        self.assertTrue(any(f['source_dn']==source and f['attribute']=='telephoneNumber'
                            for f in result.findings))
        self.assertFalse(result.success)

    def test_single_object_api_checks_values_not_only_presence(self):
        self.migrate()
        self.dst.entries[self.dst._key(DU)]['attributes']['sAMAccountName']='wrong'
        self.assertFalse(self.engine.verifier.verify_object(USER,DU,['sAMAccountName']))

    def test_dry_run_skips_content_comparison_and_does_not_write(self):
        self.engine.dry_run=True
        self.engine.reference_resolver.dry_run=True
        self.engine.verifier.dry_run=True
        result=self.engine.migrate(SRC)
        self.assertTrue(result.success)
        self.assertEqual(result.verification_result.checked_objects,0)
        self.assertEqual(self.dst.add_log,[])
        self.assertEqual(self.dst.modify_log,[])

    def test_detailed_reports_survive_reopening_database_and_escape_html(self):
        self.src.entries[self.src._key(USER)]['attributes']['description']='<script>alert(1)</script>'
        original=self.engine._phase5_verify
        def corrupt(base_dn):
            self.dst.entries[self.dst._key(DU)]['attributes'].pop('description')
            return original(base_dn)
        with patch.object(self.engine,'_phase5_verify',side_effect=corrupt):
            result=self.engine.migrate(SRC)
        from database.migration_db import MigrationDB
        reopened=MigrationDB(self.path)
        try:
            generator=ReportGenerator(reopened)
            html=generator.generate_html_report(result.run_id,Path(self.tmp.name)/'report.html').read_text()
            txt=generator.generate_text_report(result.run_id,Path(self.tmp.name)/'report.txt').read_text()
            self.assertIn('Attribute mismatch',html)
            self.assertIn('&lt;script&gt;',html)
            self.assertNotIn('<script>',html)
            self.assertIn('description',txt)
            self.assertIn(USER,txt)
            self.assertNotIn('unicodePwd',txt)
        finally:
            reopened.close()

if __name__=='__main__':
    unittest.main()
