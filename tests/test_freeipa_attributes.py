"""Optional mapping errors must not prevent safe identity creation."""
import sys,json,base64,unittest
from pathlib import Path
from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from ldap3 import Server,OFFLINE_AD_2012_R2
from tests import test_freeipa_migration as fixture
from core.freeipa_attributes import default_mappings,AttributeMappings
from core.freeipa_migration import FreeIPAMigrator
from core.ldap_connector import LDAPOperationError,LDAPConnectionError
from utils.config_manager import ConfigManager
from utils.report_generator import ReportGenerator


def mapping(src,dst,kind='user',mode='all',enabled=True):
    return dict(kind=kind,source=src,target=dst,mode=mode,enabled=enabled)


class AttributeTests(unittest.TestCase):
    tearDown=fixture.MigrationTests.tearDown

    def setUp(self):
        fixture.MigrationTests.setUp(self)
        self.dest.server=Server('unused',get_info=OFFLINE_AD_2012_R2)
        names={row['source'].lower() for row in default_mappings()} | {'departmentnumber','gecos','homedirectory','employeeid'}
        self.source.server=SimpleNamespace(schema=SimpleNamespace(attribute_types={k:None for k in names}))
        for obj in self.snapshot.objects:
            obj.attributes['attributelevelrights']=[', '.join(k+':rsc' for k in names)]
        def discover(rfc,exclusions,require_read_rights=False,cancelled=None,profile_attributes=None):
            self.requested=profile_attributes
            return deepcopy(self.snapshot)
        self.source.discover=discover

    def engine(self,rows,**kwargs):
        return FreeIPAMigrator(self.source,self.dest,self.db,self.logger,
                              self.dest.container,self.dest.container,attribute_mappings=rows,**kwargs)

    def run_engine(self,rows,**kwargs):
        engine=self.engine(rows,**kwargs);plan=engine.build_plan();engine.approved_plan=plan
        return engine,plan,engine.migrate()

    def test_typo_missing_attribute_and_protected_field_skip_but_objects_created(self):
        rows=[mapping('sn','sn'),mapping('sn','doesNotExist'),mapping('typoSource','displayName'),
              mapping('uid','userAccountControl'),mapping('krbPrincipalKey','description')]
        engine,plan,result=self.run_engine(rows)
        self.assertFalse(plan.blocked)
        self.assertEqual(len(plan.attribute_warnings),4)
        self.assertTrue(result.success,result.failure_message)
        self.assertEqual(result.objects_created,4)
        self.assertEqual(result.status,'completed_with_warnings')
        target=self.dest.get_object_by_dn('CN=alice,'+self.dest.container)['attributes']
        self.assertEqual(target['sn'],'Тестовая')
        self.assertEqual(target['userAccountControl'],514)
        self.assertNotIn('doesNotExist',target)
        self.assertNotIn('typoSource',self.requested)
        self.assertNotIn('krbPrincipalKey',self.requested)
        for mode in ('html','txt'):
            report=Path(self.tmp.name)/('report.'+mode)
            generator=ReportGenerator(self.db)
            if mode=='html':generator.generate_html_report(result.run_id,report)
            else:generator.generate_text_report(result.run_id,report)
            self.assertIn('doesNotExist',report.read_text())

    def test_server_rejection_only_skips_one_optional_field(self):
        self.alice.attributes['title']=['Developer']
        original=self.dest.modify
        def reject(dn,changes,*args,**kwargs):
            if 'sn' in changes:raise LDAPOperationError('constraintViolation echoed-private-value', result_code=19)
            return original(dn,changes,*args,**kwargs)
        with patch.object(self.dest,'modify',side_effect=reject):
            _,_,result=self.run_engine([mapping('sn','sn'),mapping('title','title')])
        self.assertTrue(result.success,result.warnings)
        self.assertEqual(result.objects_created,4)
        target=self.dest.get_object_by_dn('CN=alice,'+self.dest.container)['attributes']
        self.assertEqual(target['title'],'Developer')
        self.assertNotIn('sn',target)
        self.assertFalse(any('echoed-private-value' in m for m in result.warnings))
        self.assertTrue(any('sn:' in m for m in result.warnings))

    def test_transport_failure_stops_after_first_created_object(self):
        original=self.dest.modify
        def fail(dn,changes,*args,**kwargs):
            if 'sn' in changes:raise LDAPConnectionError('Lost reply')
            return original(dn,changes,*args,**kwargs)
        with patch.object(self.dest,'modify',side_effect=fail):_,_,result=self.run_engine([mapping('sn','sn')])
        self.assertFalse(result.success)
        self.assertEqual(result.objects_created,1)

    def test_unknown_write_result_stops_further_writes(self):
        original = self.dest.modify
        def unknown(dn, changes, *args, **kwargs):
            if 'sn' in changes:
                return False
            return original(dn, changes, *args, **kwargs)
        with patch.object(self.dest, 'modify', side_effect=unknown):
            _, _, result = self.run_engine([mapping('sn','sn')])
        self.assertFalse(result.success)
        self.assertEqual(result.objects_created, 1)

    def test_connector_preserves_definitive_server_result_code(self):
        from core.ldap_connector import LDAPConnector
        connector = LDAPConnector('unused',636,'test.test','unused','unused')
        connector._ensure_connected = lambda: None
        connector.connection = SimpleNamespace(modify=lambda *args: False,
            result={'result':17,'description':'undefinedAttributeType','message':'unknown field'})
        with self.assertRaises(LDAPOperationError) as error:
            connector.modify('CN=Test,DC=test,DC=test', {'typo':'value'})
        self.assertEqual(error.exception.result_code, 17)

    def test_multi_value_cardinality_does_not_truncate(self):
        self.alice.attributes['title']=['one','two']
        _,plan,result=self.run_engine([mapping('title','title')])
        self.assertTrue(result.success)
        self.assertTrue(plan.rows[0].attribute_warnings)
        self.assertNotIn('title',self.dest.get_object_by_dn(plan.rows[0].target_dn)['attributes'])

    def test_defaults_preserve_all_mail_values_and_optional_ssh_keys(self):
        key_type=b'ssh-ed25519'
        key='ssh-ed25519 '+base64.b64encode(len(key_type).to_bytes(4,'big')+key_type+(32).to_bytes(4,'big')+b'x'*32).decode()+' alice@test'
        self.alice.attributes['ipasshpubkey']=[key]
        _,plan,result=self.run_engine(default_mappings())
        self.assertTrue(result.success,result.warnings)
        self.assertFalse(plan.attribute_warnings)
        attrs=self.dest.get_object_by_dn(plan.rows[0].target_dn)['attributes']
        self.assertEqual(attrs['mail'],'alice@ipa.test')
        self.assertEqual(attrs['otherMailbox'],['alias@ipa.test'])
        self.assertEqual(attrs['altSecurityIdentities'],[key])
        self.assertNotIn('altSecurityIdentities',self.dest.attrs_in_add(plan.rows[0].target_dn))

    def test_ssh_mapping_rejects_other_identity_formats(self):
        self.alice.attributes['ipasshpubkey']=['X509:<S>CN=Unrelated']
        _,plan,result=self.run_engine([mapping('ipaSshPubKey','altSecurityIdentities')])
        self.assertTrue(result.success)
        self.assertTrue(plan.rows[0].attribute_warnings)
        self.assertNotIn('altSecurityIdentities',self.dest.get_object_by_dn(plan.rows[0].target_dn)['attributes'])

    def test_hidden_optional_field_is_warning_not_missing_identity(self):
        self.alice.attributes['attributelevelrights']=['sn:none']
        _,plan,result=self.run_engine([mapping('sn','sn')])
        self.assertTrue(result.success)
        self.assertTrue(plan.rows[0].attribute_warnings)
        self.assertFalse(plan.rows[0].optional_attributes)

    def test_duplicate_target_rows_skip_all_competing_rules(self):
        _,plan,result=self.run_engine([mapping('sn','displayName'),mapping('cn','displayName')])
        self.assertTrue(result.success)
        self.assertEqual(len(plan.attribute_warnings),2)

    def test_changed_mapping_requires_new_preview(self):
        engine=self.engine([mapping('sn','sn')]);engine.approved_plan=engine.build_plan()
        engine.attribute_mappings=[mapping('sn','description')]
        result=engine.migrate()
        self.assertFalse(result.success)
        self.assertEqual(self.dest.add_log,[])

    def test_existing_objects_are_not_modified_when_mapping_changes(self):
        self.run_engine([mapping('sn','sn')])
        self.dest.modify_log.clear();self.alice.attributes['title']=['New job']
        _,_,result=self.run_engine([mapping('title','title')])
        self.assertTrue(result.success)
        self.assertEqual(result.objects_created,0)
        self.assertEqual(self.dest.modify_log,[])
        self.assertTrue(any('title:' in w for w in result.warnings))

    def test_dry_run_reports_invalid_rules_without_writes(self):
        _,plan,result=self.run_engine([mapping('sn','typo')],dry_run=True)
        self.assertTrue(result.success)
        self.assertTrue(result.warnings)
        self.assertEqual(self.dest.add_log,[])
        self.assertTrue(self.db.is_empty())

    def test_ini_round_trip_and_disabled_or_empty_mapping_list(self):
        path=Path(self.tmp.name)/'settings.ini'
        config=ConfigManager(path)
        self.assertEqual(config.get_freeipa_mappings(),default_mappings())
        rows=[mapping('sn','percent%typo',enabled=False)]
        config.set_freeipa_mappings(rows)
        self.assertEqual(ConfigManager(path).get_freeipa_mappings(),rows)
        config.set_freeipa_mappings([])
        self.assertEqual(ConfigManager(path).get_freeipa_mappings(),[])


if __name__=='__main__':unittest.main(verbosity=2)
