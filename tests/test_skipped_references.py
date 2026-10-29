"""Unsupported references are auditable skips, never successful migrations."""
import sys, tempfile, unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from core.migrator import Migrator
from core.analyzer import Analyzer
from core.ignore_rules import IgnoreRules
from core.reference_resolver import ReferenceResolver
from database.migration_db import MigrationDB
from tests.fake_ldap import FakeLDAPConnector
from utils.logger import MigrationLogger
from utils.report_generator import ReportGenerator

SRC, DST = 'DC=source,DC=alt', 'DC=dest,DC=alt'
GROUP = 'CN=group,' + SRC
PC = 'CN=HOST,CN=Computers,' + SRC
FSP = 'CN=S-1-5-21-1-2-3-1401,CN=ForeignSecurityPrincipals,' + SRC
EXCLUDED = 'CN=excluded,CN=Users,' + SRC

class SkipTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = MigrationDB(Path(self.tmp.name)/'state.db')
        self.logger = MigrationLogger(log_file=Path(self.tmp.name)/'test.log')
        self.logger.set_log_level('ERROR')
        self.src, self.dst = FakeLDAPConnector('source.alt'), FakeLDAPConnector('dest.alt')
        for conn, root in [(self.src, SRC), (self.dst, DST)]:
            conn.seed(root, ['domain'])
            conn.seed('CN=Users,' + root, ['container'])
            for name in ('DnsAdmins', 'DnsUpdateProxy'):
                conn.seed('CN='+name+',CN=Users,'+root, ['group'], cn=name,
                          sAMAccountName=name, objectSid='S-1-5-21-1-2-3-1101', groupType=-2147483646)
        self.src.seed(PC, ['user','computer'])
        self.src.seed(FSP, ['foreignSecurityPrincipal'])
        self.src.seed(EXCLUDED, ['user'], sAMAccountName='excluded')
        self.src.seed(GROUP, ['group'], cn='group', sAMAccountName='group',
                      groupType=-2147483646, member=[PC,FSP,EXCLUDED])

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def migrator(self, **kw):
        return Migrator(self.src,self.dst,self.db,self.logger,custom_exclusions=[EXCLUDED],**kw)

    def old_run(self):
        with patch.object(ReferenceResolver, 'is_builtin_target', return_value=None):
            self.migrator().migrate(SRC)
        self.assertEqual(len(self.db.get_unresolved_references()),3)

    def test_new_run_skips_and_reports_without_conflicts(self):
        dns_before=self.dst.get_object_by_dn('CN=DnsAdmins,CN=Users,'+DST)
        migrator=self.migrator()
        plan=migrator.build_plan(Analyzer(self.src, custom_exclusions=[EXCLUDED]).analyze(SRC))
        self.assertEqual(len(plan.skipped_references),3)
        self.assertFalse(plan.deferred)
        self.assertFalse(plan.conflict)
        result=migrator.migrate(SRC)
        self.assertEqual(result.status,'completed_with_warnings')
        self.assertEqual(result.errors_count,0)
        self.assertFalse(self.db.get_unresolved_references())
        self.assertEqual(self.dst.get_object_by_dn('CN=DnsAdmins,CN=Users,'+DST),dns_before)
        self.assertFalse(self.dst.members_of('CN=group,'+DST))
        report=Path(self.tmp.name)/'report.html'
        ReportGenerator(self.db).generate_html_report(result.run_id, report)
        self.assertIn('unsupported reference target type',report.read_text())
        self.assertIn('excluded by operator',report.read_text())

    def test_old_pending_retired_but_not_resolved(self):
        self.old_run()
        result=self.migrator().migrate(SRC)
        self.assertEqual(result.status,'completed_with_warnings')
        self.assertFalse(self.db.get_unresolved_references())
        rows=self.db.connection.execute('SELECT * FROM deferred_references').fetchall()
        self.assertEqual(len(rows),3)
        for row in rows:
            self.assertEqual(row['resolved'],0)
            self.assertTrue(row['notes'].startswith('SKIPPED: '))
            self.assertFalse(row['resolved_dest_dn'])
        self.assertEqual(self.db.get_statistics(result.run_id)['deferred_references']['total'],0)
        self.assertEqual(self.migrator().migrate(SRC).status,'completed_with_warnings')

    def test_dry_run_keeps_history_unchanged(self):
        self.old_run()
        before=[dict(row) for row in self.db.connection.execute('SELECT * FROM deferred_references')]
        self.migrator(dry_run=True).migrate(SRC)
        after=[dict(row) for row in self.db.connection.execute('SELECT * FROM deferred_references')]
        self.assertEqual(before,after)

    def test_unreadable_reference_stays_pending(self):
        self.old_run()
        original=self.src.get_object_by_dn
        def read(dn,attributes=None):
            if dn==PC:raise RuntimeError('LDAP read denied')
            return original(dn,attributes)
        with patch.object(self.src,'get_object_by_dn',side_effect=read):
            result=self.migrator().migrate(SRC)
        self.assertTrue(any(row['referenced_source_dn']==PC for row in self.db.get_unresolved_references()))
        self.assertEqual(result.status,'completed_with_errors')

    def test_dns_rule_does_not_use_rid_or_arbitrary_same_name(self):
        attrs=dict(objectClass=['group'],sAMAccountName='DnsAdmins',objectSid='S-1-5-21-1-2-3-1101')
        rules=IgnoreRules(SRC)
        self.assertTrue(rules.should_ignore('CN=DnsAdmins,CN=Users,'+SRC,['group'],attrs))
        self.assertFalse(rules.should_ignore('CN=DnsAdmins,OU=custom,'+SRC,['group'],attrs))
        self.assertFalse(rules.should_ignore('CN=ordinary,CN=Users,'+SRC,['group'],{**attrs,'sAMAccountName':'ordinary'}))

    def test_real_conflict_remains_error(self):
        self.src.seed('CN=collision,'+SRC,['user'],sAMAccountName='collision')
        self.dst.seed('CN=collision,'+DST,['user'],sAMAccountName='collision')
        result=self.migrator().migrate(SRC)
        self.assertEqual(result.objects_conflicted,1)
        self.assertEqual(result.status,'completed_with_errors')

if __name__=='__main__':unittest.main()
