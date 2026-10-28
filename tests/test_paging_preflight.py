"""Paged LDAP completeness and creation preflight regression tests."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import unittest
from unittest.mock import Mock, patch
from types import SimpleNamespace
import ldap3
from core.ldap_connector import LDAPConnector, LDAPOperationError
from core.analyzer import Analyzer
from tests import test_identity_tracking as fixtures
from tests.test_identity_tracking import SRC, DST, USER, DU
from utils.dn_utils import DNUtils

OID = '1.2.840.113556.1.4.319'

class LDAPEntry:
    def __init__(self, dn, **attrs):
        self.entry_dn = dn
        self.attrs = attrs
        self.entry_attributes = list(attrs)
    def __getitem__(self, key):
        return SimpleNamespace(value=self.attrs[key])

class PagingTests(unittest.TestCase):
    def connector(self, pages):
        conn = object.__new__(LDAPConnector)
        conn._ensure_connected = Mock()
        conn.connection = SimpleNamespace(auto_referrals=True)
        def search(**kwargs):
            rows, result = pages.pop(0)
            conn.connection.entries = rows
            conn.connection.result = result
            return bool(rows)
        conn.connection.search = Mock(side_effect=search)
        return conn

    def result(self, cookie=b''):
        return {'result': 0, 'controls': {OID: {'value': {'cookie': cookie}}}}

    def test_analysis_reads_more_than_server_page_and_ignores_continuations(self):
        root=LDAPEntry(SRC,objectClass=['domain'])
        users=[LDAPEntry(f'CN=user{i},{SRC}',objectClass=['user'],objectGUID=f'guid-{i}') for i in range(1201)]
        conn=self.connector([([root],{'result':0}), (users[:500],self.result(b'one')),
                             (users[500:1000],self.result(b'two')), (users[1000:],self.result())])
        analysis=Analyzer(conn).analyze(SRC)
        self.assertEqual(len(analysis.users),1201)
        calls=conn.connection.search.call_args_list
        self.assertNotIn('paged_size',calls[0].kwargs)
        self.assertEqual([c.kwargs['paged_cookie'] for c in calls[1:]],[None,b'one',b'two'])
        self.assertTrue(all(c.kwargs['paged_criticality'] for c in calls[1:]))
        self.assertTrue(conn.connection.auto_referrals)

    def test_later_page_failure_never_returns_partial_analysis(self):
        conn=self.connector([([LDAPEntry(SRC,objectClass=['domain'])],{'result':0}),
            ([LDAPEntry(USER,objectClass=['user'])],self.result(b'next')),
            ([],{'result':4,'description':'sizeLimitExceeded'})])
        with self.assertRaises(LDAPOperationError):
            Analyzer(conn).analyze(SRC)
        self.assertTrue(conn.connection.auto_referrals)

    def test_account_expiry_preserves_exact_wire_integer(self):
        from datetime import datetime, timezone
        from ldap3.protocol.formatters.formatters import format_ad_timestamp
        values=[0,9223372036854775807,133000000000000001]
        for value in values:
            class Entry:
                entry_dn=USER
                entry_attributes=['accountExpires']
                def __getitem__(self, key):
                    raw=str(value).encode('ascii')
                    return SimpleNamespace(value=format_ad_timestamp(raw),raw_values=[raw])
            conn=self.connector([([Entry()],self.result())])
            self.assertEqual(conn.search(SRC,'(objectClass=*)')[0]['attributes']['accountExpires'],value)

    def test_empty_success_is_not_an_error(self):
        conn=self.connector([([],self.result())])
        self.assertEqual(conn.search(SRC,'(objectClass=*)'),[])

    def test_missing_page_control_is_error(self):
        conn=self.connector([([LDAPEntry(USER)],{'result':0})])
        with self.assertRaises(LDAPOperationError):
            conn.search(SRC,'(objectClass=*)')

    def test_server_may_reuse_opaque_cookie(self):
        conn=self.connector([([],self.result(b'same')),([],self.result(b'same')),([],self.result())])
        self.assertEqual(conn.search(SRC,'(objectClass=*)'),[])

# Reuse fixtures without inheriting the other suite's tests.
class PreflightTests(unittest.TestCase):
    setUp=fixtures.IdentityTests.setUp
    tearDown=fixtures.IdentityTests.tearDown
    make_engine=fixtures.IdentityTests.make_engine
    plan=fixtures.IdentityTests.plan

    def test_missing_container_blocks_children_in_plan_and_execution(self):
        container='CN=Custom,'+SRC
        self.src.seed(container,['container'])
        user='CN=child,'+container
        self.src.seed(user,['user'],cn='child',sAMAccountName='child')
        plan=self.plan()
        self.assertTrue(any(row[0]==user for row in plan.errors))
        self.assertIn('parent',plan.issues[user].lower())
        self.engine.migrate(container)
        self.assertEqual(self.dst.add_log,[])

    def test_existing_container_accepts_children(self):
        self.src.seed('CN=Custom,'+SRC,['container'])
        self.dst.seed('CN=Custom,'+DST,['container'])
        self.src.seed('CN=child,CN=Custom,'+SRC,['user'],cn='child',sAMAccountName='child')
        self.assertEqual(self.engine.migrate('CN=Custom,'+SRC).objects_created,1)

    def test_new_nested_ous_are_valid_parents_in_preview_and_dry_run(self):
        outer='OU=outer,'+SRC
        inner='OU=inner,'+outer
        self.src.seed(inner,['organizationalUnit'],ou='inner')
        self.src.seed(outer,['organizationalUnit'],ou='outer')
        self.src.seed('CN=child,'+inner,['user'],cn='child',sAMAccountName='child')
        plan=self.engine.build_plan(Analyzer(self.src).analyze(outer))
        self.assertEqual(len(plan.create),3)
        self.engine.dry_run=True
        self.engine.reference_resolver.dry_run=True
        self.engine.verifier.dry_run=True
        self.assertEqual(self.engine.migrate(outer).objects_created,3)
        self.assertEqual(self.dst.add_log,[])

    def test_parent_with_wrong_class_is_rejected(self):
        self.src.seed('OU=outer,'+SRC,['organizationalUnit'],ou='outer')
        self.src.seed('CN=child,OU=outer,'+SRC,['user'],cn='child',sAMAccountName='child')
        self.dst.seed('OU=outer,'+DST,['user'],cn='outer',sAMAccountName='outer')
        plan=self.plan()
        self.assertTrue(any(row[0].startswith('CN=child,') for row in plan.errors))
        self.engine.migrate('OU=outer,'+SRC)
        self.assertEqual(self.dst.add_log,[])

    def test_login_conflict_anywhere_in_domain_is_not_adopted(self):
        other='CN=elsewhere,'+DST
        self.dst.seed(other,['user'],cn='elsewhere',sAMAccountName='USER')
        plan=self.plan()
        self.assertTrue(any(row[0]==USER for row in plan.conflict))
        self.assertIn('sAMAccountName',plan.issues[USER])
        self.assertEqual(self.engine.migrate(USER).objects_conflicted,1)
        self.assertEqual(self.dst.add_log,[])

    def test_transformed_upn_conflict(self):
        self.src.entries[self.src._key(USER)]['attributes']['userPrincipalName']='user@source.alt'
        self.dst.seed('CN=elsewhere,'+DST,['user'],cn='elsewhere',sAMAccountName='different',userPrincipalName='user@dest.alt')
        plan=self.plan()
        self.assertIn('userPrincipalName',plan.issues[USER])
        self.assertEqual(self.engine.migrate(USER).objects_conflicted,1)

    def test_conflict_appearing_after_preview_is_checked_again(self):
        self.assertTrue(any(row[0]==USER for row in self.plan().create))
        self.dst.seed('CN=other,'+DST,['user'],sAMAccountName='user')
        self.assertEqual(self.engine.migrate(USER).objects_created,0)
        self.assertEqual(self.dst.add_log,[])

    def test_lookup_failure_does_not_authorize_creation(self):
        with patch.object(self.dst,'search',side_effect=LDAPOperationError('denied')):
            self.assertTrue(any(row[0]==USER for row in self.plan().errors))
            self.engine.migrate(USER)
        self.assertEqual(self.dst.add_log,[])

    def test_failed_ou_creation_blocks_child_add(self):
        outer='OU=outer,'+SRC
        self.src.seed(outer,['organizationalUnit'],ou='outer')
        self.src.seed('CN=child,'+outer,['user'],cn='child',sAMAccountName='child')
        with patch.object(self.engine.handlers['ou'],'create',return_value=False):
            result=self.engine.migrate(outer)
        self.assertEqual(self.dst.add_log,[])
        self.assertEqual(result.objects_created,0)

    def test_duplicate_planned_upns_and_dry_run_agree(self):
        self.src.entries[self.src._key(USER)]['attributes']['userPrincipalName']='same@source.alt'
        self.src.seed('CN=second,'+SRC,['user'],cn='second',sAMAccountName='second',userPrincipalName='same@source.alt')
        plan=self.plan()
        self.assertEqual(len(plan.conflict),1)
        self.engine.dry_run=True
        self.engine.reference_resolver.dry_run=True
        self.engine.verifier.dry_run=True
        result=self.engine.migrate(SRC)
        self.assertEqual(result.objects_conflicted,1)
        self.assertEqual(result.objects_created,len(plan.create))
        self.assertEqual(self.dst.add_log,[])

    def test_filter_metacharacters_are_literal_values(self):
        self.src.entries[self.src._key(USER)]['attributes']['sAMAccountName']='name*(x)'
        original=self.dst.search
        with patch.object(self.dst,'search',side_effect=original) as search:
            self.plan()
        filters=[call.kwargs['search_filter'] for call in search.call_args_list]
        self.assertIn(r'(sAMAccountName=name\2a\28x\29)',filters)

    def test_parent_split_preserves_escaped_comma(self):
        self.assertEqual(DNUtils.get_parent_dn(r'CN=Last\, First,OU=People,'+DST),'OU=People,'+DST)

if __name__=='__main__':
    unittest.main()
