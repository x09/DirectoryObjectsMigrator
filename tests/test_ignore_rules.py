"""
Ignore rules: an explicitly requested built-in container must be migrated.

Reported bug: analysing CN=Users,DC=win,DC=test produced "nothing to do - everything
in this scope is already migrated" even though nothing had been migrated. The
pattern "CN=Users,DC=" in settings.IGNORED_DN_PATTERNS is a substring match against
the full DN, so it matched the requested container *and every object inside it*.
Everything landed in `ignored`, the plan came out empty, and the message was
misleading on top of that.

The rule now is: a pattern matching the requested base DN is disabled for that run,
because asking for the container is an explicit statement of intent. Every other
pattern stays active, so scanning the domain root still skips CN=Users.
"""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from tests.fake_ldap import FakeLDAPConnector
from core.ignore_rules import IgnoreRules
from core.analyzer import Analyzer
from core.migrator import Migrator
from database.migration_db import MigrationDB
from utils.logger import MigrationLogger

FAILURES = []


def check(label, actual, expected):
    ok = actual == expected
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {actual!r}"
          f"{'' if ok else f' (expected {expected!r})'}")
    if not ok:
        FAILURES.append(label)


def test_rules_directly():
    print("\n=== Scanning the whole domain still skips built-in containers ===")
    broad = IgnoreRules(base_dn='DC=win,DC=test')

    check("CN=Users container ignored",
          broad.should_ignore('CN=Users,DC=win,DC=test', ['container']), True)
    check("object inside CN=Users ignored",
          broad.should_ignore('CN=Ivan,CN=Users,DC=win,DC=test', ['user']), True)
    check("CN=Builtin ignored",
          broad.should_ignore('CN=Builtin,DC=win,DC=test', ['container']), True)
    check("a normal OU is not ignored",
          broad.should_ignore('OU=Staff,DC=win,DC=test', ['organizationalUnit']), False)
    check("no override reported", broad.describe_overrides(), '')

    print("\n=== Requesting CN=Users explicitly migrates its contents ===")
    explicit = IgnoreRules(base_dn='CN=Users,DC=win,DC=test')

    check("the requested container itself is not ignored",
          explicit.should_ignore('CN=Users,DC=win,DC=test', ['container']), False)
    check("user inside it is not ignored",
          explicit.should_ignore('CN=Ivan,CN=Users,DC=win,DC=test', ['user']), False)
    check("group inside it is not ignored",
          explicit.should_ignore('CN=Sales,CN=Users,DC=win,DC=test', ['group']), False)

    print("\n=== Other rules stay in force ===")
    check("computers still ignored by objectClass",
          explicit.should_ignore('CN=PC1,CN=Users,DC=win,DC=test', ['computer']), True)
    check("an unrelated built-in container is still ignored",
          explicit.should_ignore('CN=Builtin,DC=win,DC=test', ['container']), True)
    check("CN=System still ignored",
          explicit.should_ignore('CN=System,DC=win,DC=test', ['container']), True)
    check("the override is reported for the log",
          'CN=Users,DC=' in explicit.describe_overrides(), True)

    print("\n=== Case insensitivity ===")
    lower = IgnoreRules(base_dn='cn=users,dc=win,dc=test')
    check("lowercase base DN also opts in",
          lower.should_ignore('CN=Ivan,CN=Users,DC=win,DC=test', ['user']), False)

    print("\n=== A nested OU under CN=Users also opts in ===")
    nested = IgnoreRules(base_dn='OU=Sales,CN=Users,DC=win,DC=test')
    check("object under the nested OU is not ignored",
          nested.should_ignore('CN=Ivan,OU=Sales,CN=Users,DC=win,DC=test', ['user']),
          False)


def test_end_to_end():
    """The exact scenario from the report, through analysis and planning."""
    print("\n=== Reported scenario: CN=Users,DC=win,DC=test ===")

    SRC, DST = 'DC=win,DC=test', 'DC=altdomain,DC=loc'
    BASE = f'CN=Users,{SRC}'

    src = FakeLDAPConnector('win.test')
    src.seed(SRC, ['domain'])
    src.seed(BASE, ['container'], cn='Users')
    src.seed(f'CN=Ivan Petrov,{BASE}', ['user'], cn='Ivan Petrov',
             sAMAccountName='ipetrov')
    src.seed(f'CN=Maria Ivanova,{BASE}', ['user'], cn='Maria Ivanova',
             sAMAccountName='mivanova')
    src.seed(f'CN=Sales,{BASE}', ['group'], cn='Sales', sAMAccountName='Sales',
             groupType=-2147483646)
    # Must still be skipped even inside the requested container
    src.seed(f'CN=WORKSTATION1,{BASE}', ['computer'], cn='WORKSTATION1')

    dst = FakeLDAPConnector('altdomain.loc')
    dst.seed(DST, ['domain'])
    dst.seed(f'CN=Users,{DST}', ['container'], cn='Users')

    tmp = Path(tempfile.mkdtemp())
    db = MigrationDB(tmp / 'm.db')
    logger = MigrationLogger(log_file=tmp / 't.log')
    logger.set_log_level('ERROR')

    analysis = Analyzer(src, logger=logger).analyze(BASE, include_references=True)

    check("two users found", analysis.counts_by_type['user'], 2)
    check("one group found", analysis.counts_by_type['group'], 1)
    # Exactly one object is ignored: the computer, filtered by objectClass. The
    # users and the group must not be, which was the bug.
    check("only the computer is ignored", analysis.counts_by_type['ignored'], 1)
    check("no user or group was ignored",
          [e['dn'] for e in analysis.ignored], [f'CN=WORKSTATION1,{BASE}'])

    planner = Migrator(source_conn=src, dest_conn=dst, migration_db=db,
                       logger=logger, dry_run=True)
    plan = planner.build_plan(analysis)

    check("plan is not empty", plan.summary()['create'], 3)
    check("no false EXISTS", plan.summary()['exists'], 0)

    print("\n=== And the migration actually creates them ===")
    result = Migrator(source_conn=src, dest_conn=dst, migration_db=db,
                      logger=logger).migrate(BASE)

    check("three objects created", result.objects_created, 3)
    check("Ivan present in destination",
          dst.object_exists(f'CN=Ivan Petrov,CN=Users,{DST}'), True)
    check("Sales group present",
          dst.object_exists(f'CN=Sales,CN=Users,{DST}'), True)
    check("computer was not migrated",
          dst.object_exists(f'CN=WORKSTATION1,CN=Users,{DST}'), False)

    print("\n=== Scanning the domain root still skips CN=Users ===")
    root_analysis = Analyzer(src, logger=logger).analyze(SRC, include_references=True)
    check("no users picked up from CN=Users",
          root_analysis.counts_by_type['user'], 0)
    check("CN=Users contents reported as ignored",
          root_analysis.counts_by_type['ignored'] > 0, True)

    db.close()


def make_sid(rid: int) -> bytes:
    """Build a binary objectSid ending in the given RID, as AD would return."""
    import struct
    return (bytes([1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0])
            + struct.pack('<III', 12345, 12345, 12345)
            + struct.pack('<I', rid))


def test_builtin_principals():
    """
    Built-in accounts and groups must never be migrated.

    Matching is by objectSid RID, not by name, because a localised domain calls
    RID 500 "Администратор" while an English one calls it "Administrator". Names
    are only a fallback for when objectSid cannot be read.
    """
    print("\n=== Built-in principals recognised by RID ===")

    cases = [
        (500, 'Администратор', 'Administrator'),
        (501, 'Гость', 'Guest'),
        (502, 'krbtgt', 'krbtgt'),
        (512, 'Администраторы домена', 'Domain Admins'),
        (513, 'Пользователи домена', 'Domain Users'),
        (514, 'Гости домена', 'Domain Guests'),
        (515, 'Компьютеры домена', 'Domain Computers'),
        (516, 'Контроллеры домена', 'Domain Controllers'),
        (517, 'Издатели сертификатов', 'Cert Publishers'),
        (518, 'Администраторы схемы', 'Schema Admins'),
        (519, 'Администраторы предприятия', 'Enterprise Admins'),
        (520, 'Владельцы-создатели групповой политики', 'Group Policy Creator Owners'),
        (521, 'Контроллеры домена - только чтение', 'Read-only Domain Controllers'),
        (522, 'Клонируемые контроллеры домена', 'Cloneable Domain Controllers'),
        (571, 'Группа с разрешением репликации паролей RODC',
         'Allowed RODC Password Replication Group'),
        (572, 'Группа с запрещением репликации паролей RODC',
         'Denied RODC Password Replication Group'),
        (498, 'Контроллеры домена предприятия - только чтение',
         'Enterprise Read-only Domain Controllers'),
    ]

    for rid, russian_name, english_name in cases:
        reason = IgnoreRules.builtin_reason(
            {'objectSid': make_sid(rid), 'cn': russian_name})
        check(f"RID {rid} ({english_name}) skipped", bool(reason), True)

    print("\n=== Ordinary objects are not affected ===")
    for rid in (1103, 1104, 2000, 5000):
        reason = IgnoreRules.builtin_reason(
            {'objectSid': make_sid(rid), 'cn': f'User{rid}'})
        check(f"RID {rid} migrated", reason, None)

    print("\n=== RID wins over a coincidental name ===")
    # A real user the admin happened to name "Администраторы домена" must migrate:
    # its RID is in the normal range, so it is not the built-in group.
    for rid, name in ((1150, 'Администраторы домена'),
                      (1151, 'Domain Admins'),
                      (1152, 'krbtgt')):
        reason = IgnoreRules.builtin_reason(
            {'objectSid': make_sid(rid), 'cn': name})
        check(f"RID {rid} named {name!r} still migrated", reason, None)

    print("\n=== Name fallback when objectSid is unavailable ===")
    for name in ('krbtgt', 'Администраторы домена', 'Domain Admins',
                 'Гость', 'Пользователи домена', 'Администраторы схемы'):
        reason = IgnoreRules.builtin_reason({'cn': name})
        check(f"{name!r} skipped without objectSid", bool(reason), True)

    check("ordinary name still migrated without objectSid",
          IgnoreRules.builtin_reason({'cn': 'Иванов Иван'}), None)
    check("matching is case-insensitive",
          bool(IgnoreRules.builtin_reason({'cn': '  DOMAIN ADMINS  '})), True)
    check("sAMAccountName also checked",
          bool(IgnoreRules.builtin_reason({'sAMAccountName': 'krbtgt'})), True)
    check("multi-valued cn handled",
          bool(IgnoreRules.builtin_reason({'cn': ['Domain Users']})), True)


def test_builtin_end_to_end():
    """A localised CN=Users container: built-ins filtered, real objects migrated."""
    print("\n=== CN=Users with built-in and real objects ===")

    SRC, DST = 'DC=win,DC=test', 'DC=altdomain,DC=loc'
    BASE = f'CN=Users,{SRC}'

    src = FakeLDAPConnector('win.test')
    src.seed(SRC, ['domain'])
    src.seed(BASE, ['container'], cn='Users')

    # Built-in, as a Russian-language domain presents them
    src.seed(f'CN=Администратор,{BASE}', ['user'], cn='Администратор',
             sAMAccountName='Administrator', objectSid=make_sid(500))
    src.seed(f'CN=krbtgt,{BASE}', ['user'], cn='krbtgt',
             sAMAccountName='krbtgt', objectSid=make_sid(502))
    src.seed(f'CN=Администраторы домена,{BASE}', ['group'],
             cn='Администраторы домена', sAMAccountName='Domain Admins',
             groupType=-2147483646, objectSid=make_sid(512))
    src.seed(f'CN=Пользователи домена,{BASE}', ['group'],
             cn='Пользователи домена', sAMAccountName='Domain Users',
             groupType=-2147483646, objectSid=make_sid(513))

    # Real objects that must migrate
    src.seed(f'CN=Иванов Иван,{BASE}', ['user'], cn='Иванов Иван',
             sAMAccountName='iivanov', objectSid=make_sid(1103))
    src.seed(f'CN=Отдел IT,{BASE}', ['group'], cn='Отдел IT',
             sAMAccountName='it', groupType=-2147483646, objectSid=make_sid(1105),
             # References both a real user and a built-in account
             member=[f'CN=Иванов Иван,{BASE}', f'CN=Администратор,{BASE}'])

    dst = FakeLDAPConnector('altdomain.loc')
    dst.seed(DST, ['domain'])
    dst.seed(f'CN=Users,{DST}', ['container'], cn='Users')

    tmp = Path(tempfile.mkdtemp())
    db = MigrationDB(tmp / 'm.db')
    logger = MigrationLogger(log_file=tmp / 't.log')
    logger.set_log_level('ERROR')

    analysis = Analyzer(src, logger=logger).analyze(BASE, include_references=True)

    check("only the real user selected", analysis.counts_by_type['user'], 1)
    check("only the real group selected", analysis.counts_by_type['group'], 1)
    check("four built-in objects filtered", analysis.counts_by_type['ignored'], 4)

    result = Migrator(source_conn=src, dest_conn=dst, migration_db=db,
                     logger=logger).migrate(BASE)

    check("two objects created", result.objects_created, 2)
    check("real user migrated",
          dst.object_exists(f'CN=Иванов Иван,CN=Users,{DST}'), True)
    check("Administrator not migrated",
          dst.object_exists(f'CN=Администратор,CN=Users,{DST}'), False)
    check("krbtgt not migrated",
          dst.object_exists(f'CN=krbtgt,CN=Users,{DST}'), False)
    check("Domain Admins not migrated",
          dst.object_exists(f'CN=Администраторы домена,CN=Users,{DST}'), False)

    print("\n=== A reference to a built-in is dropped, not deferred ===")
    # Deferring it would leave a row that can never resolve, cluttering every
    # subsequent report with permanently pending work.
    members = dst.members_of(f'CN=Отдел IT,CN=Users,{DST}')
    check("group has only the real member", len(members), 1)
    check("real member present", any('Иванов' in m for m in members), True)
    check("no pending deferred references",
          len(db.get_unresolved_references()), 0)

    db.close()


def main():
    test_rules_directly()
    test_end_to_end()
    test_builtin_principals()
    test_builtin_end_to_end()

    print("\n" + "=" * 62)
    if FAILURES:
        print(f"{len(FAILURES)} CHECK(S) FAILED: {FAILURES}")
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == '__main__':
    sys.exit(main())
