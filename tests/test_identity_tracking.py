"""Real SQLite upgrade/scoping plus directory identity and privilege regression tests."""
import os
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import sqlite3
import tempfile
import unittest
import uuid
from copy import deepcopy
from unittest.mock import patch
from tests.fake_ldap import FakeLDAPConnector
from core.migrator import Migrator
from core.analyzer import Analyzer
from core.identity import MappingValidationError
from database.migration_db import MigrationDB
from utils.logger import MigrationLogger

SRC='DC=source,DC=alt'
DST='DC=dest,DC=alt'
USER='CN=user,'+SRC
GROUP='CN=group,'+SRC
DU='CN=user,'+DST
DG='CN=group,'+DST


def move(conn, before, after):
    entry=conn.entries.pop(conn._key(before))
    entry['dn']=after
    entry['attributes']['distinguishedName']=after
    conn.entries[conn._key(after)]=entry


class IdentityTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.path=Path(self.tmp.name)/'migration.db'
        self.db=MigrationDB(self.path)
        self.logger=MigrationLogger(log_file=Path(self.tmp.name)/'test.log')
        self.logger.set_log_level('ERROR')
        self.src=FakeLDAPConnector('source.alt')
        self.dst=FakeLDAPConnector('dest.alt')
        self.src.seed(SRC,['domain'])
        self.dst.seed(DST,['domain'])
        self.user_guid=self.src.seed(USER,['user'],cn='user',sAMAccountName='user')
        self.group_guid=self.src.seed(GROUP,['group'],cn='group',sAMAccountName='group',groupType=-2147483646,member=[USER])
        self.engine=self.make_engine()

    def make_engine(self,dst=None,src=None):
        return Migrator(src or self.src,dst or self.dst,self.db,self.logger)

    def plan(self,engine=None):
        engine=engine or self.engine
        return engine.build_plan(Analyzer(engine.source_conn).analyze(SRC))

    def pending(self):
        # Group first; user is genuinely not migrated yet.
        result=self.engine.migrate(GROUP)
        self.assertEqual(len(self.engine.migration_db.get_unresolved_references()),1)
        return result

    def tearDown(self):
        self.db.close()
        for h in list(self.logger.logger.handlers):
            h.close(); self.logger.logger.removeHandler(h)
        self.tmp.cleanup()

    def test_legacy_braced_uppercase_guid_preserves_mapping_and_foreign_keys(self):
        self.pending()
        scoped=self.engine.migration_db
        raw='{'+self.group_guid.upper()+'}'
        with self.db.connection:
            self.db.connection.execute('PRAGMA defer_foreign_keys=ON')
            self.db.connection.execute('UPDATE migration_map SET source_guid=? WHERE source_guid=?', (raw,self.group_guid))
            self.db.connection.execute('UPDATE deferred_references SET parent_object_guid=? WHERE parent_object_guid=?', (raw,self.group_guid))
        self.assertEqual(scoped.get_object_by_source_guid(self.group_guid)['source_guid'],raw)
        self.assertEqual(len(scoped.get_unresolved_references(parent_guid=self.group_guid)),1)
        self.engine.migrate(SRC)
        self.assertEqual(self.dst.members_of(DG),[DU])
        self.assertEqual(scoped.get_unresolved_references(),[])
        self.assertEqual(self.db.connection.execute('PRAGMA foreign_key_check').fetchall(),[])
        self.assertEqual(self.db.connection.execute('SELECT count(*) FROM migration_map').fetchone()[0],2)

    def test_same_source_two_destinations_keep_both_mappings(self):
        self.engine.migrate(SRC)
        other=FakeLDAPConnector('other.alt'); other.seed('DC=other,DC=alt',['domain'])
        second=self.make_engine(dst=other)
        result=second.migrate(SRC)
        self.assertEqual(result.objects_created,2)
        self.assertEqual(self.engine.migration_db.get_object_by_source_guid(self.user_guid)['dest_dn'],DU)
        self.assertEqual(second.migration_db.get_object_by_source_guid(self.user_guid)['dest_dn'],'CN=user,DC=other,DC=alt')
        self.assertNotEqual(second.migration_db.direction_id,self.engine.migration_db.direction_id)
        self.assertEqual(self.engine.migrate(SRC).objects_created,0)

    def test_same_dns_name_rebuilt_domain_is_a_new_direction(self):
        self.engine.migrate(SRC)
        other=FakeLDAPConnector('dest.alt');other.seed(DST,['domain'])
        second=self.make_engine(dst=other)
        self.assertNotEqual(second.migration_db.direction_id,self.engine.migration_db.direction_id)
        self.assertEqual(second.migrate(SRC).objects_created,2)

    def test_other_dc_of_same_domains_keeps_direction(self):
        self.engine.migrate(SRC)
        other=FakeLDAPConnector('dest.alt',host='another-dc');other.entries=deepcopy(self.dst.entries)
        second=self.make_engine(dst=other)
        self.assertEqual(second.migration_db.direction_id,self.engine.migration_db.direction_id)
        self.assertEqual(second.migrate(SRC).objects_created,0)

    def test_pending_rows_are_isolated_between_live_views(self):
        self.pending()
        other=FakeLDAPConnector('other.alt');other.seed('DC=other,DC=alt',['domain'])
        second=self.make_engine(dst=other)
        self.assertEqual(second.migration_db.get_unresolved_references(),[])
        second.migrate(USER)
        self.assertEqual(self.dst.modify_log,[])
        self.assertEqual(len(self.engine.migration_db.get_unresolved_references()),1)
        self.engine.migrate(USER)
        self.assertEqual(self.dst.members_of(DG),[DU])

    def test_cross_direction_acknowledgement_is_rejected(self):
        self.pending()
        row=self.engine.migration_db.get_unresolved_references()[0]
        other=FakeLDAPConnector('other.alt');other.seed('DC=other,DC=alt',['domain'])
        second=self.make_engine(dst=other)
        result=second.migrate(USER)
        with self.assertRaises(ValueError):
            self.engine.migration_db.mark_reference_resolved(row['id'],DU,result.run_id)
        self.assertEqual(len(self.engine.migration_db.get_unresolved_references()),1)

    def test_deleted_tracked_target_is_not_recreated(self):
        self.engine.migrate(SRC)
        self.dst.entries.pop(self.dst._key(DU))
        before=len(self.dst.add_log)
        self.assertTrue(any(row[0]==USER for row in self.plan().errors))
        result=self.engine.migrate(SRC)
        self.assertEqual(result.status,'completed_with_errors')
        self.assertFalse(self.dst.object_exists(DU))
        self.assertEqual(len(self.dst.add_log),before)

    def test_replacement_at_same_dn_is_not_adopted(self):
        self.engine.migrate(SRC)
        original=self.engine.migration_db.get_object_by_source_guid(self.user_guid)['dest_guid']
        self.dst.entries.pop(self.dst._key(DU))
        new_guid=self.dst.seed(DU,['user'],cn='user',sAMAccountName='user')
        self.assertTrue(self.plan().errors)
        self.assertEqual(self.engine.migrate(SRC).status,'completed_with_errors')
        self.assertEqual(self.engine.migration_db.get_object_by_source_guid(self.user_guid)['dest_guid'],original)
        self.assertNotEqual(original,new_guid)

    def test_moved_target_found_by_guid_even_if_old_dn_reused(self):
        self.engine.migrate(SRC)
        moved='CN=renamed,'+DST
        move(self.dst,DU,moved)
        self.dst.seed(DU,['user'],cn='user',sAMAccountName='unrelated')
        plan=self.plan()
        self.assertIn((USER,moved,'user'),plan.exists)
        self.assertEqual(self.engine.migration_db.get_object_by_source_guid(self.user_guid)['dest_dn'],DU)
        self.engine.migrate(SRC)
        self.assertEqual(self.engine.migration_db.get_object_by_source_guid(self.user_guid)['dest_dn'],moved)

    def test_replaced_reference_parent_receives_no_members(self):
        self.pending()
        self.dst.entries.pop(self.dst._key(DG))
        self.dst.seed(DG,['group'],cn='group',sAMAccountName='group',member=[])
        result=self.engine.migrate(USER)
        self.assertEqual(result.status,'completed_with_errors')
        self.assertEqual(self.dst.members_of(DG),[])
        self.assertEqual(len(self.engine.migration_db.get_unresolved_references()),1)

    def test_moved_reference_parent_receives_members_at_new_dn(self):
        self.pending()
        new='CN=renamed-group,'+DST
        move(self.dst,DG,new)
        self.engine.migrate(USER)
        self.assertEqual(self.dst.members_of(new),[DU])
        self.assertEqual(self.engine.migration_db.get_unresolved_references(),[])

    def test_moved_source_reference_follows_captured_guid(self):
        self.pending()
        new='CN=renamed-user,'+SRC
        move(self.src,USER,new)
        self.engine.migrate(new)
        self.assertEqual(self.dst.members_of(DG),['CN=renamed-user,'+DST])
        self.assertEqual(self.engine.migration_db.get_unresolved_references(),[])

    def test_deleted_source_reference_does_not_follow_same_name_replacement(self):
        self.pending()
        self.src.entries.pop(self.src._key(USER))
        self.src.seed(USER,['user'],cn='user',sAMAccountName='user')
        self.engine.migrate(USER)
        self.assertEqual(self.dst.members_of(DG),[])
        self.assertEqual(len(self.engine.migration_db.get_unresolved_references()),1)

    def test_same_login_without_mapping_is_not_identity(self):
        self.dst.seed(DU,['user'],cn='user',sAMAccountName='user')
        result=self.engine.migrate(GROUP)
        self.assertEqual(self.dst.members_of(DG),[])
        plan=self.plan()
        self.assertTrue(any(ref[2]==USER and not ref[3] for ref in plan.deferred))
        self.assertTrue(plan.reference_issues)
        with patch.object(self.dst,'search',side_effect=AssertionError('must not search by login')):
            self.assertIsNone(self.engine.reference_resolver.resolve_reference(USER))

    def test_reset_does_not_reconnect_matching_names(self):
        self.engine.migrate(SRC)
        self.db.reset(make_backup=False)
        new=self.make_engine()
        self.assertIsNone(new.reference_resolver.resolve_reference(USER))
        self.assertEqual(len(self.plan(new).conflict),2)

    def test_missing_domain_identity_stops_before_destination_writes(self):
        del self.dst.entries[self.dst._key(DST)]['attributes']['objectGUID']
        with self.assertRaises(MappingValidationError):
            self.make_engine()
        self.assertEqual(self.dst.add_log,[])

    def test_lookup_failure_is_not_treated_as_missing_mapping(self):
        self.engine.migrate(SRC)
        with patch.object(self.dst,'get_object_by_dn',side_effect=RuntimeError('timeout')):
            self.assertTrue(self.plan().errors)
            result=self.engine.migrate(SRC)
        self.assertEqual(result.objects_created,0)
        self.assertFalse(result.success)


class LegacyUpgradeTests(unittest.TestCase):
    def test_upgrade_preserves_history_and_scopes_verified_legacy_rows(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'old.db'
            schema=(Path(__file__).parent/'fixtures/schema_v11.sql').read_text()
            # v1.1 schema fixture is deliberately frozen into this test below
            with sqlite3.connect(path) as conn:
                conn.executescript(schema)
                conn.execute("INSERT INTO migration_runs(run_id,source_base_dn,dest_base_dn) VALUES(1,?,?)",(SRC,DST))
                conn.execute("INSERT INTO run_configurations(migration_run_id,source_domain,dest_domain) VALUES(1,'source.alt','dest.alt')")
                conn.execute("INSERT INTO migration_map(source_guid,source_dn,dest_guid,dest_dn,object_type,status,migration_run_id,first_migration_run_id) VALUES('s',?,'d',?,'group','created',1,1)",(GROUP,DG))
                conn.execute("INSERT INTO deferred_references(parent_object_guid,parent_object_dn,parent_object_type,attribute_name,referenced_source_dn,created_run_id) VALUES('s',?,'group','member',?,1)",(DG,USER))
            db=MigrationDB(path)
            self.assertEqual(len(list(Path(tmp).glob('*before_v12*'))),1)
            view=db.for_direction('source-root-guid','dest-root-guid','source.alt','dest.alt')
            self.assertEqual(view.get_object_by_source_guid('s')['dest_dn'],DG)
            self.assertEqual(len(view.get_unresolved_references()),1)
            self.assertEqual(db.connection.execute('PRAGMA foreign_key_check').fetchall(),[])
            other=db.for_direction('source-root-guid','other-root-guid','source.alt','other.alt')
            self.assertIsNone(other.get_object_by_source_guid('s'))
            self.assertEqual(other.get_unresolved_references(),[])
            db.close()
            reopened=MigrationDB(path)
            self.assertEqual(len(list(Path(tmp).glob('*before_v12*'))),1)
            reopened.close()


if __name__=='__main__':
    unittest.main()
