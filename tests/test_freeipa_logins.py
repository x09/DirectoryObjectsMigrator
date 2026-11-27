"""Long login allocation, stable native identity and target collision safety."""
import sys
import json
import unittest
from pathlib import Path
from copy import deepcopy
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tests import test_freeipa_migration as fixture
from core.freeipa_migration import values
from core.ldap_connector import LDAPConnectionError


class LoginTests(unittest.TestCase):
    tearDown = fixture.MigrationTests.tearDown
    engine = fixture.MigrationTests.engine
    run_engine = fixture.MigrationTests.run_engine

    def setUp(self):
        fixture.MigrationTests.setUp(self)
        self.long = fixture.obj('ivanov_ivanovich_petrovsky', gidnumber=[2001])
        self.group.attributes['member'] = [self.long.dn]
        self.snapshot.objects = [self.long, self.group]

    def login(self, plan, source=None):
        return next(r.attributes.get('sAMAccountName') for r in plan.rows
                    if r.source.source_id == (source or self.long).source_id)

    def test_opt_in_and_twenty_character_boundary(self):
        off = self.engine().build_plan()
        self.assertTrue(off.blocked)
        self.assertIn('Invalid destination', off.rows[0].reason)
        short = fixture.obj('a' * 20, gidnumber=[2001])
        self.assertEqual(len(short.name), 20)
        self.snapshot.objects.append(short)
        plan = self.engine(shorten_long_logins=True).build_plan()
        self.assertFalse(plan.blocked)
        self.assertEqual(self.login(plan), 'ivanov_ivanovich_001')
        self.assertEqual(self.login(plan, short), short.name)
        self.assertEqual(plan.login_statistics['total'], 1)

    def test_deterministic_order_and_same_prefix(self):
        other = fixture.obj('ivanov_ivanovich_sidorovsky', gidnumber=[2001])
        self.snapshot.objects.append(other)
        engine = self.engine(shorten_long_logins=True)
        first = engine.build_plan()
        self.snapshot.objects.reverse()
        second = engine.build_plan()
        self.assertEqual(first.fingerprint(), second.fingerprint())
        self.assertEqual(self.login(first), 'ivanov_ivanovich_001')
        self.assertEqual(self.login(first, other), 'ivanov_ivanovich_002')

    def test_source_names_groups_target_dn_sam_upn_reserved(self):
        for n, kind in [(1, 'user'), (2, 'group')]:
            self.snapshot.objects.append(fixture.obj('ivanov_ivanovich_00'+str(n), kind, gidnumber=[2001] if kind=='user' else []))
        self.dest.seed('CN=other1,'+self.dest.container, ['group'], sAMAccountName='IVANOV_IVANOVICH_003')
        self.dest.seed('CN=other2,'+self.dest.container, ['user'], userPrincipalName='ivanov_ivanovich_004@target.test')
        self.dest.seed('CN=ivanov_ivanovich_005,'+self.dest.container, ['contact'])
        plan = self.engine(shorten_long_logins=True).build_plan()
        self.assertFalse(plan.blocked, [(r.action,r.reason) for r in plan.rows])
        self.assertEqual(self.login(plan), 'ivanov_ivanovich_006')

    def test_width_from_count_and_excluded_statistics(self):
        self.snapshot.objects = [self.group] + [fixture.obj('very_long_login_for_test_%04d'%i, gidnumber=[2001]) for i in range(1000)]
        self.group.attributes['member'] = []
        excluded = fixture.obj('another_long_excluded_login', gidnumber=[2001])
        excluded.reason = 'Blocked user'
        self.snapshot.objects.append(excluded)
        plan = self.engine(shorten_long_logins=True).build_plan()
        names = [r.attributes['sAMAccountName'] for r in plan.rows if r.action=='create' and r.source.kind=='user']
        self.assertEqual(len(names),1000)
        self.assertEqual(len(set(names)),1000)
        self.assertTrue(all(len(n)==20 for n in names))
        self.assertTrue(names[0].endswith('_0001'))
        self.assertEqual(plan.login_statistics, dict(total=1001,eligible=1000,generated=1000,retained=0,digits=4))

    def test_migration_history_repeat_option_off_and_new_users(self):
        engine, plan, result = self.run_engine(shorten_long_logins=True)
        self.assertTrue(result.success, result.failure_message or result.warnings)
        name = self.login(plan)
        mapping = engine.db.get_object_by_source_guid(self.long.source_id)
        self.assertEqual(json.loads(mapping['notes'])['freeipa_login'],name)
        self.assertEqual(mapping['source_sam_account_name'],self.long.name)
        self.assertEqual(self.dest.members_of('CN=team,'+self.dest.container), [mapping['dest_dn']])
        _, again, result = self.run_engine()  # Disabling only affects new names.
        self.assertTrue(result.success, result.warnings)
        self.assertEqual(self.login(again),name)
        added = fixture.obj('aaa_another_very_long_user',gidnumber=[2001])
        self.snapshot.objects.append(added)
        newer = self.engine(shorten_long_logins=True).build_plan()
        self.assertEqual(self.login(newer),name)
        self.assertEqual(newer.login_statistics['retained'],1)
        self.assertEqual(engine.db.get_object_by_source_guid(self.long.source_id)['notes'], mapping['notes'])

    def test_recreation_keeps_name_and_checks_conflict(self):
        engine, plan, result = self.run_engine(shorten_long_logins=True)
        self.assertTrue(result.success)
        old = engine.db.get_object_by_source_guid(self.long.source_id)
        self.dest.entries.pop(self.dest._key(old['dest_dn']))
        for entry in self.dest.entries.values():
            entry['attributes']['member'] = [v for v in values(entry['attributes'],'member') if v != old['dest_dn']]
        candidate = self.engine().build_plan().rows[0]
        self.assertTrue(candidate.recreation)
        self.assertEqual(candidate.target_dn,old['dest_dn'])
        _, new, result = self.run_engine(recreation_requests={self.long.source_id:candidate.recreation})
        self.assertTrue(result.success,result.warnings)
        mapping = engine.db.get_object_by_source_guid(self.long.source_id)
        self.assertEqual(mapping['notes'],old['notes'])
        self.assertNotEqual(mapping['dest_guid'],old['dest_guid'])
        self.assertEqual(self.login(new), self.login(plan))

    def test_history_assignment_reserved_even_if_source_is_excluded(self):
        engine, plan, result = self.run_engine(shorten_long_logins=True)
        self.assertTrue(result.success)
        old = engine.db.get_object_by_source_guid(self.long.source_id)
        self.dest.entries.pop(self.dest._key(old['dest_dn']))
        self.long.reason='Custom exclusion'
        other=fixture.obj('ivanov_ivanovich_sidorovsky',gidnumber=[2001])
        self.snapshot.objects.append(other)
        new = self.engine(shorten_long_logins=True).build_plan()
        self.assertEqual(self.login(new,other),'ivanov_ivanovich_002')

    def test_dry_run_and_analysis_do_not_persist_names(self):
        before = deepcopy(self.snapshot)
        engine, _, result = self.run_engine(shorten_long_logins=True,dry_run=True)
        self.assertTrue(result.success)
        self.assertEqual(engine.db.get_freeipa_login_assignments(),{})
        self.assertEqual(self.dest.add_log,[])
        self.assertEqual(self.dest.modify_log,[])
        self.assertEqual(self.snapshot,before)

    def test_target_collision_after_preview_requires_new_review(self):
        engine = self.engine(shorten_long_logins=True)
        engine.approved_plan = engine.build_plan()
        name = self.login(engine.approved_plan)
        self.dest.seed('CN=other,'+self.dest.container,['user'],sAMAccountName=name)
        result = engine.migrate()
        self.assertFalse(result.success)
        self.assertIn('plan changed',result.failure_message)
        self.assertEqual(self.dest.add_log,[])

    def test_invalid_source_character_is_not_hidden_by_shortening(self):
        self.long.name += '/invalid'
        plan = self.engine(shorten_long_logins=True).build_plan()
        self.assertTrue(plan.blocked)
        self.assertEqual(plan.login_statistics['generated'],0)

    def test_failed_collision_lookup_stops_without_writes(self):
        with patch.object(self.dest,'search',side_effect=LDAPConnectionError('lost')):
            with self.assertRaises(LDAPConnectionError):
                self.engine(shorten_long_logins=True).build_plan()
        self.assertEqual(self.dest.add_log,[])

    def test_numeric_suffix_expands_without_exceeding_twenty(self):
        engine=self.engine(shorten_long_logins=True)
        original=engine._collision
        def occupied(row):
            if row.attributes['sAMAccountName'].endswith('_1000'):
                return original(row)
            return 'occupied'
        with patch.object(engine,'_collision',side_effect=occupied):
            plan=engine.build_plan()
        self.assertEqual(self.login(plan),'ivanov_ivanovic_1000')
        self.assertEqual(len(self.login(plan)),20)
        self.assertEqual(plan.login_statistics['digits'],4)

if __name__ == '__main__':
    unittest.main()
