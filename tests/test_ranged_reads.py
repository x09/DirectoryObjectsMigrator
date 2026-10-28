"""Fail-closed ranged LDAP reads, including continuation errors and page cookies."""
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
import unittest
from unittest.mock import Mock
from types import SimpleNamespace
import ldap3
from core.ldap_connector import LDAPConnector, LDAPOperationError
from core.analyzer import Analyzer
from tests.test_paging_preflight import LDAPEntry, OID

DN='CN=large,DC=source,DC=alt'
GUID='9caa916b-a8b9-4ce0-924c-cda23ffcf184'
def row(attrs, dn=DN, guid=GUID, usn=10):
    return LDAPEntry(dn,objectGUID=guid,uSNChanged=usn,objectClass=['group'],**attrs)
def result(cookie=None, code=0):
    return {'result':code,**({'controls':{OID:{'value':{'cookie':cookie}}}} if cookie is not None else {})}
class RangeTests(unittest.TestCase):
    def connector(self,pages):
        conn=object.__new__(LDAPConnector)
        conn._ensure_connected=Mock()
        conn.connection=SimpleNamespace(auto_referrals=True,auto_range=True,empty_attributes=True)
        def search(**kwargs):
            self.assertFalse(conn.connection.auto_range)
            self.assertFalse(conn.connection.empty_attributes)
            entries,res=pages.pop(0)
            if isinstance(res,Exception):raise res
            conn.connection.entries=entries;conn.connection.result=res
            return bool(entries)
        conn.connection.search=Mock(side_effect=search)
        return conn

    def test_contiguous_three_ranges_and_cookie_preserved(self):
        conn=self.connector([
            ([row({'member;range=0-1':['a','b']})],result(b'next-page')),
            ([row({'member;range=2-3':['c','d'],'member;range=2-*':[]})],result()),
            ([row({'member;range=4-*':['e']})],result()),
            ([row({'member':['z']},dn='CN=other,DC=source,DC=alt')],result(b''))])
        entries=conn.search('DC=source,DC=alt','(objectClass=*)')
        self.assertEqual(entries[0]['attributes']['member'],['a','b','c','d','e'])
        self.assertEqual(entries[1]['attributes']['member'],['z'])
        self.assertFalse(any(';range=' in key for key in entries[0]['attributes']))
        calls=conn.connection.search.call_args_list
        self.assertEqual(calls[1].kwargs['search_scope'],ldap3.BASE)
        self.assertEqual(calls[3].kwargs['paged_cookie'],b'next-page')
        self.assertTrue(conn.connection.auto_range)
        self.assertTrue(conn.connection.empty_attributes)
        self.assertTrue(conn.connection.auto_referrals)

    def test_first_terminal_range_and_empty_placeholder(self):
        conn=self.connector([([row({'member':[],'member;range=0-*':['a']})],result())])
        self.assertEqual(conn.search(DN,'(objectClass=*)',scope=ldap3.BASE)[0]['attributes']['member'],['a'])

    def test_later_page_keeps_all_entries_when_first_group_needs_ranges(self):
        conn=self.connector([
            ([row({'member;range=0-0':['a']}),row({'member':['x']},dn='CN=second,DC=source,DC=alt')],result(b'')),
            ([row({'member;range=1-*':['b']})],result())])
        self.assertEqual(len(conn.search(DN,'(objectClass=*)')),2)

    def test_bad_continuations_fail_instead_of_returning_partial_members(self):
        variants=[
            ([],result()),
            ([row({})],result()),
            ([row({'member;range=2-*':['b']})],result()),
            ([row({'member;range=0-*':['b']})],result()),
            ([row({'member;range=1-*':[]})],result()),
            ([row({'member;range=1-*':['a']})],result()),
            ([row({'member;range=1-3':['b']})],result()),
            ([row({'member;range=1-*':['b']},usn=11)],result()),
            ([row({'member;range=1-*':['b']},guid='replacement')],result()),
            ([row({'member;range=1-*':['b']},dn='CN=wrong,DC=source,DC=alt')],result()),
            ([row({'member;range=1-*':['b']})],result(code=50)),
            ([],ldap3.core.exceptions.LDAPSocketReceiveError('timeout')),
        ]
        for continuation in variants:
            with self.subTest(continuation=continuation):
                conn=self.connector([([row({'member;range=0-0':['a']})],result(b'')),continuation])
                with self.assertRaises(LDAPOperationError):conn.search(DN,'(objectClass=*)')
                self.assertTrue(conn.connection.auto_range)
                self.assertTrue(conn.connection.empty_attributes)
                self.assertTrue(conn.connection.auto_referrals)

    def test_malformed_initial_or_missing_version_is_rejected(self):
        for entry in [row({'member;range=invalid':['a']}),row({'member;range=1-*':['a']}),
                      row({'member;range=0-2':['a']}),
                      LDAPEntry(DN,**{'member;range=0-*':['a']}),
                      row({'member':['x'],'member;range=0-*':['a']})]:
            conn=self.connector([([entry],result(b''))])
            with self.assertRaises(LDAPOperationError):conn.search(DN,'(objectClass=*)')

    def test_analyzer_never_returns_partial_result(self):
        conn=self.connector([([row({})],result()),([row({'member;range=0-0':['a']})],result(b'')),
                             ([],result(code=3))])
        with self.assertRaises(LDAPOperationError):Analyzer(conn).analyze(DN)

    def test_case_insensitive_range_attribute(self):
        conn=self.connector([([row({'MEMBER;RANGE=0-0':['a']})],result()),
                             ([row({'member;range=1-*':['b']})],result())])
        self.assertEqual(conn.search(DN,'(objectClass=*)',scope=ldap3.BASE)[0]['attributes']['MEMBER'],['a','b'])

    def test_multiple_ranged_attributes(self):
        conn=self.connector([([row({'member;range=0-0':['a'],'other;range=0-0':['c']})],result()),
            ([row({'member;range=1-*':['b']})],result()),
            ([row({'other;range=1-*':['d']})],result())])
        attrs=conn.search(DN,'(objectClass=*)',scope=ldap3.BASE)[0]['attributes']
        self.assertEqual(attrs['member'],['a','b']);self.assertEqual(attrs['other'],['c','d'])

if __name__=='__main__':unittest.main()
