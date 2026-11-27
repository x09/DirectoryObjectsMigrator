"""Native FreeIPA plans, real SQLite isolation and additive migration regression."""
import sys
import tempfile
import unittest
import uuid
import re
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from core.freeipa_migration import FreeIPAMigrator, values
from core.sources.freeipa import SourceObject, FreeIPASnapshot
from database.migration_db import MigrationDB
from tests.fake_ldap import FakeLDAPConnector
from utils.logger import MigrationLogger


class Destination(FakeLDAPConnector):
    def __init__(self):
        super().__init__('target.test')
        self.seed(self.domain_dn, ['domainDNS'])
        self.container = 'CN=Users,' + self.domain_dn
        self.seed(self.container, ['container'])
        self.server = SimpleNamespace(schema=SimpleNamespace(attribute_types={k: None for k in ('uidNumber', 'gidNumber', 'loginShell')}))

    def add(self, dn, object_classes, attributes):
        result = super().add(dn, object_classes, attributes)
        if 'user' in object_classes:
            self.entries[self._key(dn)]['attributes']['primaryGroupID'] = 513
        return result

    def search(self, base_dn, search_filter='(objectClass=*)', attributes=None, **kwargs):
        match = re.fullmatch(r'\(&\(objectClass=(user|group)\)\((uidNumber|gidNumber)=(\d+)\)\)', search_filter)
        if match:
            kind, key, value = match.groups()
            return [deepcopy(e) for e in self.entries.values() if kind in e['attributes']['objectClass']
                    and str(e['attributes'].get(key)) == value]
        return super().search(base_dn, search_filter, attributes, **kwargs)


def obj(name, kind='user', **attrs):
    tree = 'users' if kind == 'user' else 'groups'
    key = 'uid' if kind == 'user' else 'cn'
    return SourceObject(kind, f'{key}={name},cn={tree},cn=accounts,dc=ipa,dc=test', str(uuid.uuid4()), name,
                        {key: [name], **attrs})


class MigrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = MigrationDB(Path(self.tmp.name)/'test.db')
        self.logger = MigrationLogger(log_file=Path(self.tmp.name)/'test.log')
        self.logger.set_log_level('CRITICAL')
        self.dest = Destination()
        self.alice = obj('alice', uidnumber=[1001], gidnumber=[2001], loginshell=['/bin/bash'],
                         cn=['Алиса, Тестовая'], sn=['Тестовая'], mail=['alice@ipa.test', 'alias@ipa.test'])
        self.bob = obj('bob', uidnumber=[1002], gidnumber=[2001], manager=[self.alice.dn])
        self.group = obj('team', 'group', gidnumber=[2001], member=[self.alice.dn])
        self.nested = obj('nested', 'group', member=[self.group.dn])
        self.snapshot = FreeIPASnapshot([self.alice, self.bob, self.group, self.nested])
        self.source = SimpleNamespace(domain='ipa.test', domain_dn='dc=ipa,dc=test', host='ipa.test',
                                     instance_identity=Mock(return_value=str(uuid.uuid4())))
        def discover(rfc, exclusions, require_read_rights=False, cancelled=None):
            assert require_read_rights
            return deepcopy(self.snapshot)
        self.source.discover = discover

    def engine(self, **kwargs):
        return FreeIPAMigrator(self.source, self.dest, self.db, self.logger,
                               self.dest.container, self.dest.container, **kwargs)

    def run_engine(self, **kwargs):
        engine = self.engine(**kwargs)
        plan = engine.build_plan()
        engine.approved_plan = plan
        return engine, plan, engine.migrate()

    def tearDown(self):
        self.db.close()
        for handler in list(self.logger.logger.handlers):
            handler.close()
            self.logger.logger.removeHandler(handler)
        self.tmp.cleanup()

    def test_create_disabled_users_attributes_members_managers_and_repeat(self):
        engine, plan, result = self.run_engine()
        self.assertTrue(result.success, result.failure_message + str(result.verification_result))
        self.assertEqual(result.objects_created, 4)
        target = 'CN=alice,' + self.dest.container
        entry = self.dest.get_object_by_dn(target)['attributes']
        self.assertEqual(entry['mail'], 'alice@ipa.test')
        self.assertEqual(entry['otherMailbox'], ['alias@ipa.test'])
        self.assertEqual(entry['userPrincipalName'], 'alice@target.test')
        self.assertEqual(entry['userAccountControl'], 514)
        self.assertEqual(set(self.dest.members_of('CN=team,'+self.dest.container)),
                         {target, 'CN=bob,'+self.dest.container})
        self.assertEqual(self.dest.members_of('CN=nested,'+self.dest.container), ['CN=team,'+self.dest.container])
        self.assertEqual(self.dest.get_object_by_dn('CN=bob,'+self.dest.container)['attributes']['manager'], [target])
        mapping = engine.db.get_object_by_source_guid(self.alice.source_id)
        self.assertEqual(mapping['source_guid'], self.alice.source_id)
        self.assertNotIn('objectGUID', plan.rows[0].source.attributes)
        before = (len(self.dest.add_log), len(self.dest.modify_log))
        _, _, second = self.run_engine()
        self.assertTrue(second.success, str(second.verification_result))
        self.assertEqual((len(self.dest.add_log), len(self.dest.modify_log)), before)

    def test_rfc_primary_membership_and_personal_prefix(self):
        self.alice.attributes['gidnumber'] = [2002]
        personal = obj('alice', 'group', gidnumber=[2002], mepmanagedby=[self.alice.dn])
        self.snapshot.objects.append(personal)
        _, plan, result = self.run_engine(rfc2307=True)
        self.assertTrue(result.success, str(result.verification_result))
        self.assertEqual(self.dest.members_of('CN=ipa-pg-alice,'+self.dest.container), ['CN=alice,'+self.dest.container])
        self.assertEqual(self.dest.get_object_by_dn('CN=alice,'+self.dest.container)['attributes']['uidNumber'], 1001)
        self.assertEqual(self.dest.get_object_by_dn('CN=alice,'+self.dest.container)['attributes']['primaryGroupID'], 513)

    def test_dry_run_does_not_change_destination_or_history(self):
        before = self.db.counts()
        _, _, result = self.run_engine(dry_run=True)
        self.assertTrue(result.success)
        self.assertIsNone(result.run_id)
        self.assertEqual(self.db.counts(), before)
        self.assertEqual(self.dest.add_log, [])
        self.assertEqual(self.dest.modify_log, [])

    def test_untracked_collision_never_adopted_or_modified(self):
        self.dest.seed('CN=unrelated,'+self.dest.container, ['user'], sAMAccountName='alice')
        _, plan, result = self.run_engine()
        self.assertTrue(plan.blocked)
        self.assertFalse(result.success)
        self.assertEqual(plan.rows[0].action, 'conflict')
        self.assertEqual(self.dest.add_log, [])
        self.assertEqual(self.dest.modify_log, [])

    def test_upn_collision_and_duplicate_planned_names(self):
        self.dest.seed('CN=unrelated,'+self.dest.container, ['user'], userPrincipalName='alice@target.test')
        self.assertEqual(self.engine().build_plan().rows[0].action, 'conflict')
        self.dest.entries.pop(self.dest._key('CN=unrelated,'+self.dest.container))
        self.snapshot.objects.append(obj('alice', 'group'))
        plan = self.engine().build_plan()
        self.assertEqual(plan.rows[0].action, 'conflict')
        self.assertEqual(plan.rows[-1].action, 'conflict')

    def test_changed_plan_requires_another_preview(self):
        engine = self.engine()
        engine.approved_plan = engine.build_plan()
        self.alice.attributes['sn'] = ['Changed']
        result = engine.migrate()
        self.assertFalse(result.success)
        self.assertIn('plan changed', result.failure_message)
        self.assertEqual(self.dest.add_log, [])

    def test_rebuilt_source_and_other_provider_do_not_share_history(self):
        engine, _, result = self.run_engine()
        self.assertTrue(result.success)
        old_direction = engine.db.direction_id
        other = self.db.for_source('ad', engine.instance_id, engine.destination_id, 'ipa.test', 'target.test')
        self.assertNotEqual(other.direction_id, old_direction)
        self.assertIsNone(other.get_object_by_source_guid(self.alice.source_id))
        self.source.instance_identity.return_value = str(uuid.uuid4())
        rebuilt = self.engine()
        self.assertNotEqual(rebuilt.db.direction_id, old_direction)
        self.assertTrue(rebuilt.build_plan().blocked)

    def test_freeipa_does_not_adopt_legacy_history_by_domain_name(self):
        run = self.db.create_migration_run(self.source.domain_dn, self.dest.domain_dn,
                                          self.source.host, self.dest.host,
                                          {'source_domain': 'ipa.test', 'dest_domain': 'target.test'})
        self.db.add_object(self.alice.source_id, self.alice.dn, str(uuid.uuid4()),
                           'CN=old,'+self.dest.container, 'user', 'created', run)
        before = self.db.counts()
        engine = self.engine()
        self.assertEqual(self.db.counts(), before)
        self.assertIsNone(engine.db.get_object_by_source_guid(self.alice.source_id))
        self.assertEqual(self.db.get_run_by_id(run)['direction_id'], '')

    def test_tracked_replacement_is_blocked(self):
        engine, _, _ = self.run_engine()
        target = 'CN=alice,' + self.dest.container
        self.dest.entries.pop(self.dest._key(target))
        self.dest.seed(target, ['user'], sAMAccountName='alice')
        plan = engine.build_plan()
        self.assertEqual(plan.rows[0].action, 'error')

    def test_missing_or_outside_container_and_missing_schema(self):
        for container in ('OU=missing,'+self.dest.domain_dn, 'CN=Users,DC=other,DC=test'):
            engine = self.engine()
            engine.users_dn = container
            with self.assertRaises(ValueError):
                engine.build_plan()
        self.dest.server.schema.attribute_types = {}
        with self.assertRaises(ValueError):
            self.engine(rfc2307=True).build_plan()

    def test_uid_gid_collisions_and_ambiguous_primary_group(self):
        self.bob.attributes['uidnumber'] = [1001]
        plan = self.engine(rfc2307=True).build_plan()
        self.assertTrue(plan.blocked)
        self.assertEqual(plan.rows[0].action, 'conflict')
        self.bob.attributes['uidnumber'] = [1002]
        self.snapshot.objects.append(obj('team2', 'group', gidnumber=[2001]))
        self.assertTrue(self.engine(rfc2307=True).build_plan().blocked)

    def test_destination_numeric_collision(self):
        self.dest.seed('CN=unrelated,'+self.dest.container, ['user'], uidNumber=1001)
        plan = self.engine(rfc2307=True).build_plan()
        self.assertEqual(plan.rows[0].action, 'conflict')

    def test_late_numeric_collision_is_detected_by_verification(self):
        engine, plan, result = self.run_engine(rfc2307=True)
        self.assertTrue(result.success)
        self.dest.seed('CN=late,'+self.dest.container, ['user'], uidNumber=1001)
        self.assertFalse(engine._verify(plan).success)

    def test_filtered_reference_is_skipped_unknown_reference_deferred(self):
        blocked = obj('blocked')
        blocked.reason = 'Blocked FreeIPA user'
        self.snapshot.objects.append(blocked)
        self.group.attributes['member'].extend([blocked.dn, 'uid=unknown,cn=users,cn=accounts,dc=ipa,dc=test'])
        engine, plan, result = self.run_engine()
        self.assertFalse(result.success)
        self.assertEqual(len([link for link in plan.links if link.state == 'skip']), 1)
        self.assertEqual(len(engine.db.get_unresolved_references()), 1)
        _, _, result = self.run_engine()
        self.assertEqual(len(engine.db.get_unresolved_references()), 1)
        self.group.attributes['member'].pop()
        _, _, result = self.run_engine()
        self.assertTrue(result.success)
        self.assertEqual(engine.db.get_unresolved_references(), [])

    def test_deferred_resolves_after_missing_object_becomes_available(self):
        later = obj('later', gidnumber=[2001])
        self.group.attributes['member'].append(later.dn)
        engine, _, first = self.run_engine()
        self.assertFalse(first.success)
        self.snapshot.objects.append(later)
        _, _, result = self.run_engine()
        self.assertTrue(result.success, str(result.verification_result))
        self.assertEqual(engine.db.get_unresolved_references(), [])

    def test_password_failure_is_reported_account_stays_disabled(self):
        engine = self.engine()
        engine.approved_plan = engine.build_plan()
        engine.password.configure_password = Mock(return_value=False)
        result = engine.migrate()
        self.assertFalse(result.success)
        self.assertEqual(result.objects_created, 4)
        self.assertEqual(result.errors_count, 2)
        self.assertEqual(self.dest.get_object_by_dn('CN=alice,'+self.dest.container)['attributes']['userAccountControl'], 514)
        self.assertTrue(self.engine().build_plan().blocked)

    def test_enabling_rfc_does_not_modify_previously_created_users(self):
        self.run_engine()
        before = len(self.dest.modify_log)
        _, plan, result = self.run_engine(rfc2307=True)
        self.assertTrue(plan.blocked)
        self.assertFalse(result.success)
        self.assertEqual(len(self.dest.modify_log), before)

    def test_additional_members_reported_and_preserved(self):
        engine, plan, _ = self.run_engine()
        dn = 'CN=team,' + self.dest.container
        extra = 'CN=other,' + self.dest.container
        self.dest.entries[self.dest._key(dn)]['attributes']['member'].append(extra)
        result = engine._verify(plan)
        self.assertTrue(result.success)
        self.assertTrue(result.warnings)
        self.assertIn(extra, self.dest.members_of(dn))

    def test_verification_detects_lost_attribute_and_membership(self):
        engine, plan, _ = self.run_engine()
        self.dest.entries[self.dest._key('CN=alice,'+self.dest.container)]['attributes'].pop('sn')
        self.dest.entries[self.dest._key('CN=team,'+self.dest.container)]['attributes']['member'] = []
        result = engine._verify(plan)
        self.assertFalse(result.success)
        self.assertGreaterEqual(len(result.errors), 3)

    def test_existing_manager_not_overwritten(self):
        engine, plan, _ = self.run_engine()
        target = 'CN=bob,'+self.dest.container
        self.dest.entries[self.dest._key(target)]['attributes']['manager'] = ['CN=other,'+self.dest.container]
        count = len(self.dest.modify_log)
        _, _, result = self.run_engine()
        self.assertFalse(result.success)
        self.assertEqual(len(self.dest.modify_log), count)

    def test_invalid_name_never_silently_truncated(self):
        self.alice.name = 'x'*21
        plan = self.engine().build_plan()
        self.assertEqual(plan.rows[0].action, 'error')
        self.assertEqual(self.dest.add_log, [])

    def test_insufficient_source_rights_blocks_all_writes(self):
        self.alice.error, self.alice.reason = True, 'Insufficient confirmed FreeIPA read rights'
        _, _, result = self.run_engine()
        self.assertFalse(result.success)
        self.assertEqual(self.dest.add_log, [])

    def test_cancel_before_execution(self):
        engine = self.engine()
        engine.approved_plan = engine.build_plan()
        engine.cancel()
        result = engine.migrate()
        self.assertEqual(result.status, 'cancelled')
        self.assertEqual(self.dest.add_log, [])


if __name__ == '__main__':
    unittest.main(verbosity=2)
