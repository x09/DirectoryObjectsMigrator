"""
End-to-end test of the three-run DEFERRED scenario from the specification.

Run 1: migrate OU=Level2,OU=Level1 -> user1, user2 and group1 are created.
       group1 has member user5, which lives outside the scope, so it is DEFERRED.
Run 2: migrate OU=Level5 -> user5 is created.
Run 3: re-run OU=Level2,OU=Level1 -> nothing is recreated, but the previously
       deferred user5 membership is now resolved and added to group1.

This exercises idempotency, conflict detection and deferred resolution together.
"""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from tests.fake_ldap import FakeLDAPConnector
from core.migrator import Migrator
from database.migration_db import MigrationDB
from utils.logger import MigrationLogger
from config import settings

SRC = 'DC=source,DC=alt'
DST = 'DC=dest,DC=alt'

LEVEL2 = f'OU=Level2,OU=Level1,{SRC}'
LEVEL5 = f'OU=Level5,{SRC}'


def build_source() -> FakeLDAPConnector:
    """Build the source directory described in the specification."""
    src = FakeLDAPConnector('source.alt')
    src.seed(SRC, ['domain'])
    src.seed(f'OU=Level1,{SRC}', ['organizationalUnit'], ou='Level1')
    src.seed(LEVEL2, ['organizationalUnit'], ou='Level2')
    src.seed(LEVEL5, ['organizationalUnit'], ou='Level5')

    src.seed(f'CN=user1,{LEVEL2}', ['user'], cn='user1',
             sAMAccountName='user1', userPrincipalName='user1@source.alt',
             mail='user1@source.alt', title='Engineer')
    src.seed(f'CN=user2,{LEVEL2}', ['user'], cn='user2',
             sAMAccountName='user2', userPrincipalName='user2@source.alt')
    src.seed(f'CN=user5,{LEVEL5}', ['user'], cn='user5',
             sAMAccountName='user5', userPrincipalName='user5@source.alt')

    src.seed(f'CN=group1,{LEVEL2}', ['group'], cn='group1',
             sAMAccountName='group1', groupType=-2147483646,
             member=[f'CN=user1,{LEVEL2}', f'CN=user2,{LEVEL2}',
                     f'CN=user5,{LEVEL5}'])
    return src


def run_migration(db, base_dn, src, dst, logger):
    migrator = Migrator(
        source_conn=src, dest_conn=dst, migration_db=db, logger=logger,
        batch_size=100, dry_run=False,
    )
    return migrator.migrate(base_dn)


def main():
    tmp = Path(tempfile.mkdtemp())
    db = MigrationDB(tmp / 'migration.db')
    logger = MigrationLogger(log_file=tmp / 'test.log')
    logger.set_log_level('ERROR')  # keep test output readable

    src = build_source()
    dst = FakeLDAPConnector('dest.alt')
    dst.seed(DST, ['domain'])
    dst.seed(f'OU=Level1,{DST}', ['organizationalUnit'], ou='Level1')

    failures = []

    def check(label, actual, expected):
        ok = actual == expected
        print(f"  {'PASS' if ok else 'FAIL'}  {label}: {actual!r}"
              f"{'' if ok else f' (expected {expected!r})'}")
        if not ok:
            failures.append(label)

    # ---------------- Run 1 ----------------
    print("\n=== Run 1: migrate OU=Level2,OU=Level1 ===")
    r1 = run_migration(db, LEVEL2, src, dst, logger)
    dest_group = f'CN=group1,OU=Level2,OU=Level1,{DST}'

    check("run 1 succeeded", r1.success, True)
    check("user1 created", dst.object_exists(f'CN=user1,OU=Level2,OU=Level1,{DST}'), True)
    check("user2 created", dst.object_exists(f'CN=user2,OU=Level2,OU=Level1,{DST}'), True)
    check("group1 created", dst.object_exists(dest_group), True)
    check("user5 NOT created (out of scope)",
          dst.object_exists(f'CN=user5,OU=Level5,{DST}'), False)

    members = sorted(dst.members_of(dest_group))
    check("group1 has 2 in-scope members", len(members), 2)
    check("member user5 not yet present",
          any('user5' in m for m in members), False)
    check("one deferred reference recorded",
          len(db.get_unresolved_references()), 1)

    # UPN/mail suffix must be rewritten to the destination domain
    u1 = dst.get_object_by_dn(f'CN=user1,OU=Level2,OU=Level1,{DST}')['attributes']
    check("UPN rewritten to dest domain",
          u1.get('userPrincipalName'), 'user1@dest.alt')
    check("mail rewritten to dest domain", u1.get('mail'), 'user1@dest.alt')
    check("ordinary attribute copied", u1.get('title'), 'Engineer')
    check("account created disabled", u1.get('userAccountControl'), 514)
    check("password attribute never copied from source",
          'unicodePwd' in src.entries[src._key(f'CN=user1,{LEVEL2}')]['attributes'], False)

    # ---------------- Run 2 ----------------
    print("\n=== Run 2: migrate OU=Level5 ===")
    r2 = run_migration(db, LEVEL5, src, dst, logger)
    check("run 2 succeeded", r2.success, True)
    check("user5 created", dst.object_exists(f'CN=user5,OU=Level5,{DST}'), True)

    # ---------------- Run 3 ----------------
    print("\n=== Run 3: re-run OU=Level2,OU=Level1 (idempotent) ===")
    before = len(dst.entries)
    r3 = run_migration(db, LEVEL2, src, dst, logger)
    after = len(dst.entries)

    check("run 3 succeeded", r3.success, True)
    check("no new objects created", after, before)
    check("nothing reported as created", r3.objects_created, 0)
    check("existing objects were skipped", r3.objects_skipped > 0, True)
    check("no conflicts raised on re-run", r3.objects_conflicted, 0)

    members = sorted(dst.members_of(dest_group))
    check("group1 now has 3 members", len(members), 3)
    check("deferred user5 membership resolved",
          any('user5' in m for m in members), True)
    check("member DNs point at destination domain",
          all(m.upper().endswith(DST.upper()) for m in members), True)
    check("no unresolved references remain",
          len(db.get_unresolved_references()), 0)

    # ---------------- Conflict detection ----------------
    print("\n=== Conflict: untracked object already in destination ===")
    src.seed(f'CN=user9,{LEVEL2}', ['user'], cn='user9', sAMAccountName='user9')
    dst.seed(f'CN=user9,OU=Level2,OU=Level1,{DST}', ['user'],
             cn='user9', sAMAccountName='user9')  # created "by hand", not tracked
    r4 = run_migration(db, LEVEL2, src, dst, logger)
    check("conflict detected", r4.objects_conflicted, 1)
    check("conflict recorded in database",
          len(db.get_conflicts(r4.run_id)), 1)

    print("\n" + "=" * 60)
    if failures:
        print(f"{len(failures)} CHECK(S) FAILED: {failures}")
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == '__main__':
    sys.exit(main())
