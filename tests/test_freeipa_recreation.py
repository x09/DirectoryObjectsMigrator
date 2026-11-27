"""Explicit recovery must not adopt replacements or lose the historical mapping."""
import sys
import unittest
import json
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tests import test_freeipa_migration as fixture
from core.freeipa_migration import values
from core.ldap_connector import LDAPOperationError, LDAPConnectionError
from core.identity import guid_text


class RecreationTests(unittest.TestCase):
    setUp = fixture.MigrationTests.setUp
    tearDown = fixture.MigrationTests.tearDown
    engine = fixture.MigrationTests.engine
    run_engine = fixture.MigrationTests.run_engine

    def deleted(self, source=None):
        source = source or self.alice
        engine, _, result = self.run_engine(rfc2307=True)
        self.assertTrue(result.success)
        mapping = engine.db.get_object_by_source_guid(source.source_id)
        entry = self.dest.entries.pop(self.dest._key(mapping['dest_dn']))
        # AD removes links to a deleted object; simulate that, not a dangling DN.
        for obj in self.dest.entries.values():
            for attr in ('member', 'manager'):
                obj['attributes'][attr] = [v for v in values(obj['attributes'], attr)
                                          if self.dest._key(v) != self.dest._key(mapping['dest_dn'])]
        self.dest.add_log.clear(); self.dest.modify_log.clear()
        return engine, mapping, entry

    def approved(self, source=None, **kwargs):
        source = source or self.alice
        plan = self.engine(rfc2307=True).build_plan()
        row = next(r for r in plan.rows if r.source.source_id == source.source_id)
        self.assertTrue(row.recreation)
        engine = self.engine(rfc2307=True, recreation_requests={source.source_id: row.recreation}, **kwargs)
        engine.approved_plan = engine.build_plan()
        self.assertFalse(engine.approved_plan.blocked)
        return engine

    def test_missing_is_blocked_without_confirmation_and_history_unchanged(self):
        engine, old, _ = self.deleted()
        counts = self.db.counts()
        plan = engine.build_plan()
        row = plan.rows[0]
        self.assertEqual(row.action, 'error')
        self.assertTrue(row.recreation)
        self.assertFalse(plan.recreation_requests)
        engine.approved_plan = plan
        self.assertFalse(engine.migrate().success)
        self.assertEqual(engine.db.get_object_by_source_guid(self.alice.source_id), old)
        self.assertEqual(self.db.counts(), counts)
        self.assertEqual(self.dest.add_log, [])

    def test_user_recreation_new_guid_disabled_password_links_audit_and_rerun(self):
        _, old, _ = self.deleted()
        engine = self.approved()
        # A new worker reconstructs approval from the reviewed plan, not global settings.
        engine = self.engine(rfc2307=True, approved_plan=engine.approved_plan)
        result = engine.migrate()
        self.assertTrue(result.success, result.failure_message or result.warnings)
        self.assertEqual(result.objects_created, 1)
        new = engine.db.get_object_by_source_guid(self.alice.source_id)
        self.assertNotEqual(new['dest_guid'], old['dest_guid'])
        self.assertEqual(new['first_migration_run_id'], old['first_migration_run_id'])
        entry = self.dest.get_object_by_dn(new['dest_dn'])['attributes']
        self.assertEqual(entry['userAccountControl'], 514)
        self.assertEqual(entry['primaryGroupID'], 513)
        self.assertIn('unicodePwd', self.dest.attrs_in_modifies(new['dest_dn']))
        self.assertIn(new['dest_dn'], self.dest.members_of('CN=team,'+self.dest.container))
        self.assertEqual(values(self.dest.get_object_by_dn('CN=bob,'+self.dest.container)['attributes'], 'manager'), [new['dest_dn']])
        audit = self.db.connection.execute("SELECT error_message FROM migration_errors WHERE phase='recreate'").fetchall()
        self.assertEqual(len(audit), 1)
        self.assertEqual(json.loads(audit[0][0])['old_guid'], old['dest_guid'])
        self.assertEqual(json.loads(audit[0][0])['new_guid'], new['dest_guid'])
        self.assertTrue(result.verification_result.success)
        _, _, again = self.run_engine(rfc2307=True)
        self.assertTrue(again.success)
        self.assertEqual(again.objects_created, 0)

    def test_group_recreation_restores_its_members_and_nested_membership(self):
        _, old, _ = self.deleted(self.group)
        engine = self.approved(self.group)
        result = engine.migrate()
        self.assertTrue(result.success, result.warnings)
        self.assertEqual(result.objects_created, 1)
        self.assertNotEqual(engine.db.get_object_by_source_guid(self.group.source_id)['dest_guid'], old['dest_guid'])
        self.assertIn('CN=alice,'+self.dest.container, self.dest.members_of(old['dest_dn']))
        self.assertIn('CN=bob,'+self.dest.container, self.dest.members_of(old['dest_dn']))
        self.assertIn(old['dest_dn'], self.dest.members_of('CN=nested,'+self.dest.container))

    def test_dry_run_does_not_modify_target_or_history(self):
        self.deleted()
        engine = self.approved(dry_run=True)
        counts = self.db.counts()
        self.assertTrue(engine.migrate().success)
        self.assertEqual(self.dest.add_log, [])
        self.assertEqual(self.dest.modify_log, [])
        self.assertEqual(self.db.counts(), counts)

    def test_occupied_dn_is_not_a_recreation_candidate(self):
        engine, old, _ = self.deleted()
        self.dest.seed(old['dest_dn'], ['user'], sAMAccountName='another')
        plan = engine.build_plan()
        self.assertTrue(plan.blocked)
        self.assertFalse(plan.rows[0].recreation)
        self.assertEqual(engine.db.get_object_by_source_guid(self.alice.source_id), old)

    def test_same_name_elsewhere_is_not_adopted(self):
        engine, _, _ = self.deleted()
        self.dest.seed('CN=unrelated,'+self.dest.container, ['user'], sAMAccountName='alice')
        row = engine.build_plan().rows[0]
        self.assertEqual(row.action, 'conflict')
        self.assertFalse(row.recreation)

    def test_moved_original_is_existing_not_recreated(self):
        engine, old, entry = self.deleted()
        moved = 'CN=Renamed,'+self.dest.container
        entry['dn'] = moved
        self.dest.entries[self.dest._key(moved)] = entry
        row = engine.build_plan().rows[0]
        self.assertEqual(row.action, 'exists')
        self.assertEqual(row.target_dn, moved)
        self.assertFalse(row.recreation)

    def test_ldap_failure_cannot_authorize_recreation(self):
        engine, _, _ = self.deleted()
        with patch.object(self.dest, 'get_object_by_guid', side_effect=LDAPConnectionError('unreachable')):
            with self.assertRaises(LDAPConnectionError):engine.build_plan()
        with patch.object(self.dest, 'get_object_by_guid', side_effect=LDAPOperationError('insufficientAccessRights')):
            self.assertFalse(engine.build_plan().rows[0].recreation)
        self.assertEqual(self.dest.add_log, [])

    def test_original_reappears_between_preview_and_add(self):
        _, old, entry = self.deleted()
        engine = self.approved()
        build = engine.build_plan
        def race():
            plan = build()
            self.dest.entries[self.dest._key(old['dest_dn'])] = entry
            return plan
        engine.build_plan = race
        self.assertFalse(engine.migrate().success)
        self.assertEqual(self.dest.add_log, [])
        self.assertEqual(engine.db.get_object_by_source_guid(self.alice.source_id)['dest_guid'], old['dest_guid'])

    def test_stale_approval_rejected_after_history_change(self):
        _, old, _ = self.deleted()
        engine = self.approved()
        self.db.connection.execute('UPDATE migration_map SET dest_guid=? WHERE source_guid=?',
                                   ('12345678-1234-1234-1234-123456789abc', self.alice.source_id))
        self.db.connection.commit()
        self.assertFalse(engine.migrate().success)
        self.assertEqual(self.dest.add_log, [])

    def test_add_failure_preserves_old_mapping(self):
        _, old, _ = self.deleted()
        engine = self.approved()
        with patch.object(self.dest, 'add', side_effect=LDAPOperationError('add denied')):
            self.assertFalse(engine.migrate().success)
        self.assertEqual(engine.db.get_object_by_source_guid(self.alice.source_id), old)
        self.assertEqual(self.db.connection.execute("SELECT COUNT(*) FROM migration_errors WHERE phase='recreate'").fetchone()[0], 0)

    def test_atomic_audit_failure_rolls_mapping_back(self):
        _, old, _ = self.deleted()
        engine = self.approved()
        self.db.connection.execute("""CREATE TRIGGER reject_recreation BEFORE INSERT ON migration_errors
            WHEN NEW.phase='recreate' BEGIN SELECT RAISE(ABORT, 'audit write failed'); END""")
        self.db.connection.commit()
        self.assertFalse(engine.migrate().success)
        self.assertEqual(engine.db.get_object_by_source_guid(self.alice.source_id), old)

    def test_password_failure_retains_new_mapping_as_pending(self):
        _, old, _ = self.deleted()
        engine = self.approved()
        engine.password.configure_password = lambda *args: False
        self.assertFalse(engine.migrate().success)
        new = engine.db.get_object_by_source_guid(self.alice.source_id)
        self.assertNotEqual(new['dest_guid'], old['dest_guid'])
        self.assertEqual(new['error_message'], 'FreeIPA password setup not confirmed')
        row = self.engine(rfc2307=True).build_plan().rows[0]
        self.assertFalse(row.recreation)
        self.assertEqual(row.action, 'error')

    def test_recreation_keeps_recorded_container_when_defaults_change(self):
        self.deleted()
        engine = self.approved()
        different = 'OU=New,'+self.dest.domain_dn
        self.dest.seed(different, ['organizationalUnit'])
        engine.users_dn = different
        plan = engine.build_plan()
        self.assertEqual(plan.rows[0].target_dn, 'CN=alice,'+self.dest.container)
        engine.approved_plan = plan
        self.assertTrue(engine.migrate().success)
        self.assertFalse(self.dest.object_exists('CN=alice,'+different))


if __name__ == '__main__':unittest.main(verbosity=2)
