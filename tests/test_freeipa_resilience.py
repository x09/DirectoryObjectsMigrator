"""Fault injection and large-group regressions without changing real directories."""
import sys
import math
from copy import deepcopy
from pathlib import Path
from unittest import TestCase, main
from unittest.mock import Mock
import uuid
from ldap3.core.exceptions import LDAPSocketReceiveError
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from core.ldap_connector import LDAPOperationError
from core.sources.freeipa import FreeIPASnapshot, DiscoveryCancelled
from tests import test_freeipa_migration as fixtures
obj = fixtures.obj


def disconnected():
    try:
        raise LDAPSocketReceiveError('simulated lost reply')
    except LDAPSocketReceiveError as exc:
        raise LDAPOperationError('Connection lost; write outcome unknown') from exc


class ResilienceTests(TestCase):
    setUp = fixtures.MigrationTests.setUp
    tearDown = fixtures.MigrationTests.tearDown
    engine = fixtures.MigrationTests.engine
    run_engine = fixtures.MigrationTests.run_engine

    def seed_large(self, count=2501):
        users = [obj(f'load{i:05}', gidnumber=[2001]) for i in range(count)]
        group = obj('load-group', 'group', gidnumber=[2001], member=[user.dn for user in users])
        self.snapshot.objects = users + [group]
        engine = self.engine()
        plan = engine.build_plan()
        self.assertFalse(plan.blocked)
        run = engine.db.create_migration_run(self.source.domain_dn, self.dest.domain_dn,
                                             self.source.host, self.dest.host, {})
        for row in plan.rows:
            attrs = dict(row.attributes)
            if row.source.kind == 'user':
                attrs['primaryGroupID'] = 513
            identity = self.dest.seed(row.target_dn, [row.source.kind], **attrs)
            engine.db.add_object(row.source.source_id, row.source.dn, identity, row.target_dn,
                                 row.source.kind, 'created', run)
        plan = engine.build_plan()
        engine.approved_plan = plan
        return engine, plan

    def test_large_group_batches_and_linear_verification_reads(self):
        engine, plan = self.seed_large()
        reads = []
        original = self.dest.get_object_by_dn
        def read(dn, attributes=None):
            if attributes and 'member' in attributes and 'load-group' in dn:
                reads.append(dn)
            return original(dn, attributes)
        self.dest.get_object_by_dn = read
        result = engine.migrate()
        self.assertTrue(result.success, result.failure_message + str(result.verification_result))
        additions = [change['member'] for dn, change in self.dest.modify_log if 'member' in change]
        self.assertEqual(sum(map(len, additions)), 2501)
        self.assertEqual(len(additions), math.ceil(2501 / engine.REFERENCE_BATCH_SIZE))
        self.assertLessEqual(len(reads), 2, 'Large group must be read once per reference/verification phase')
        self.assertEqual(result.verification_result.checked_references, 2501)
        self.assertEqual(result.verification_result.checked_objects, 2502)

    def test_cancel_after_first_batch_can_resume_without_duplicate_members(self):
        engine, plan = self.seed_large(300)
        original = self.dest.modify_add_values
        def add(dn, changes):
            result = original(dn, changes)
            engine.cancel()
            return result
        self.dest.modify_add_values = add
        first = engine.migrate()
        self.assertEqual(first.status, 'cancelled')
        self.assertEqual(len(self.dest.members_of(plan.rows[-1].target_dn)), engine.REFERENCE_BATCH_SIZE)
        self.dest.modify_add_values = original
        other, _, result = self.run_engine()
        self.assertTrue(result.success, str(result.verification_result))
        members = self.dest.members_of(plan.rows[-1].target_dn)
        self.assertEqual(len(members), 300)
        self.assertEqual(len(set(members)), 300)
        self.assertEqual(result.objects_created, 0)

    def test_server_applied_members_but_ack_lost_is_reconciled_on_retry(self):
        engine, plan = self.seed_large(10)
        original = self.dest.modify_add_values
        def add(dn, changes):
            original(dn, changes)
            disconnected()
        self.dest.modify_add_values = add
        first = engine.migrate()
        self.assertEqual(first.status, 'failed')
        self.assertEqual(len(engine.db.get_unresolved_references()), 10)
        count = len(self.dest.modify_log)
        self.dest.modify_add_values = original
        _, _, second = self.run_engine()
        self.assertTrue(second.success, str(second.verification_result))
        self.assertEqual(len(self.dest.modify_log), count)
        self.assertEqual(engine.db.get_unresolved_references(), [])

    def test_add_ack_lost_never_adopts_the_untracked_target(self):
        original = self.dest.add
        attempts = []
        def add(dn, classes, attrs):
            attempts.append(dn)
            original(dn, classes, attrs)
            disconnected()
        self.dest.add = add
        engine, _, first = self.run_engine()
        self.assertEqual(first.status, 'failed')
        self.assertEqual(len(attempts), 1)
        self.assertIsNone(engine.db.get_object_by_source_guid(self.alice.source_id))
        self.assertEqual(self.dest.modify_log, [])
        self.dest.add = original
        plan = self.engine().build_plan()
        self.assertTrue(plan.blocked)
        self.assertEqual(plan.rows[0].action, 'conflict')

    def test_disconnect_before_add_can_be_retried_after_new_preview(self):
        original = self.dest.add
        self.dest.add = Mock(side_effect=lambda *args: disconnected())
        _, _, first = self.run_engine()
        self.assertFalse(first.success)
        self.dest.add.assert_called_once()
        self.dest.add = original
        _, _, second = self.run_engine()
        self.assertTrue(second.success, str(second.verification_result))
        self.assertEqual(second.objects_created, 4)

    def test_lost_password_reply_stops_retries_and_subsequent_creations(self):
        original = self.dest.modify
        attempts = []
        def modify(dn, changes):
            attempts.append(dn)
            original(dn, changes)
            disconnected()
        self.dest.modify = modify
        engine, _, result = self.run_engine()
        self.assertEqual(result.status, 'failed')
        self.assertEqual(len(self.dest.add_log), 1)
        self.assertEqual(len(attempts), 1, 'Do not retry an uncertain password write')
        mapping = engine.db.get_object_by_source_guid(self.alice.source_id)
        self.assertEqual(mapping['error_message'], 'FreeIPA password setup not confirmed')
        self.assertNotIn('unicodePwd', result.failure_message)

    def test_password_policy_read_disconnect_does_not_fall_through_to_writes(self):
        original = self.dest.get_object_by_dn
        def read(dn, attributes=None):
            if attributes == ['minPwdLength']:
                disconnected()
            return original(dn, attributes)
        self.dest.get_object_by_dn = read
        engine, _, result = self.run_engine()
        self.assertEqual(result.status, 'failed')
        self.assertEqual(len(self.dest.add_log), 1)
        self.assertEqual(self.dest.modify_log, [])
        self.assertEqual(engine.db.get_object_by_source_guid(self.alice.source_id)['status'], 'error')

    def test_interruption_before_password_keeps_durable_pending_state(self):
        engine = self.engine()
        engine.approved_plan = engine.build_plan()
        original = engine.password.configure_password
        def password(entry, dn):
            if entry['attributes']['sAMAccountName'] == 'alice':
                mapping = engine.db.get_object_by_source_guid(self.alice.source_id)
                self.assertEqual(mapping['error_message'], 'FreeIPA password setup not confirmed')
                raise RuntimeError('simulated interruption before password setup')
            return original(entry, dn)
        engine.password.configure_password = password
        first = engine.migrate()
        self.assertFalse(first.success)
        plan = self.engine().build_plan()
        self.assertEqual(plan.rows[0].action, 'error')
        dn = 'CN=alice,' + self.dest.container
        self.dest.entries[self.dest._key(dn)]['attributes']['pwdLastSet'] = 123456789
        before = len(self.dest.modify_log)
        _, _, second = self.run_engine()
        self.assertTrue(second.success)
        self.assertEqual(len(self.dest.modify_log), before, 'Do not reset an existing user password on retry')

    def test_plan_ignores_ldap_order_but_not_directory_identity(self):
        engine = self.engine()
        original = engine.build_plan()
        self.snapshot.objects.reverse()
        for row in self.snapshot.objects:
            for value in row.attributes.values():
                if isinstance(value, list):
                    value.reverse()
        reordered = engine.build_plan()
        self.assertEqual(original.fingerprint(), reordered.fingerprint())
        altered = deepcopy(original)
        altered.instance_id, altered.destination_id = altered.destination_id, altered.instance_id
        self.assertNotEqual(original.fingerprint(), altered.fingerprint())
        engine.approved_plan = original
        result = engine.migrate()
        self.assertTrue(result.success, result.failure_message)

    def test_previous_primary_email_is_preserved_when_ldap_order_changes(self):
        self.run_engine()
        dn = 'CN=alice,' + self.dest.container
        attrs = self.dest.entries[self.dest._key(dn)]['attributes']
        attrs['mail'], attrs['otherMailbox'] = 'alias@ipa.test', ['alice@ipa.test']
        self.alice.attributes['mail'].reverse()
        _, plan, result = self.run_engine()
        self.assertTrue(result.success, str(result.verification_result))
        self.assertEqual(plan.rows[0].attributes['mail'], 'alias@ipa.test')

    def test_guid_replacement_between_validation_and_attribute_read_is_detected(self):
        engine, plan, _ = self.run_engine()
        original = self.dest.get_object_by_dn
        dn = 'CN=alice,' + self.dest.container
        def read(target, attributes=None):
            if target == dn and attributes and 'sn' in attributes:
                self.dest.entries[self.dest._key(dn)]['attributes']['objectGUID'] = str(uuid.uuid4())
            return original(target, attributes)
        self.dest.get_object_by_dn = read
        result = engine._verify(plan)
        self.assertFalse(result.success)
        self.assertTrue(any('changed while reading' in error for error in result.errors))

    def test_cancelled_discovery_does_not_write_or_record_success(self):
        engine = self.engine()
        engine.approved_plan = engine.build_plan()
        before = self.db.counts()
        self.source.discover = Mock(side_effect=DiscoveryCancelled())
        result = engine.migrate()
        self.assertEqual(result.status, 'cancelled')
        self.assertFalse(result.success)
        self.assertEqual(result.errors_count, 0)
        self.assertEqual(before, self.db.counts())
        self.assertEqual(self.dest.add_log, [])

    def test_legacy_guid_lookup_uses_index(self):
        engine, _, _ = self.run_engine()
        raw = '{' + self.alice.source_id.upper() + '}'
        self.db.connection.execute('UPDATE migration_map SET source_guid=? WHERE source_guid=?',
                                   (raw, self.alice.source_id))
        self.db.connection.commit()
        self.assertIsNotNone(engine.db.get_object_by_source_guid(self.alice.source_id))
        query = self.db.connection.execute("""EXPLAIN QUERY PLAN SELECT * FROM migration_map
            WHERE direction_id=? AND lower(replace(replace(source_guid,'{',''),'}',''))=?""",
            (engine.db.direction_id, self.alice.source_id)).fetchall()
        self.assertTrue(any('idx_migration_map_direction_native_id' in row['detail'] for row in query))


if __name__ == '__main__':
    main(verbosity=2)
