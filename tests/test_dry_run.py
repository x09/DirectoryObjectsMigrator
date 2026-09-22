"""
Dry-run must not touch the destination directory.

Two things are checked:
  1. A dry run over a fresh scope creates nothing.
  2. A dry run performed while deferred references are pending neither writes the
     membership nor marks the pending rows resolved -- otherwise the simulation
     would consume the pending work and a later real run would skip it.
"""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from tests.fake_ldap import FakeLDAPConnector
from core.migrator import Migrator
from database.migration_db import MigrationDB
from utils.logger import MigrationLogger

SRC = 'DC=source,DC=alt'
DST = 'DC=dest,DC=alt'
LEVEL2 = f'OU=Level2,OU=Level1,{SRC}'
LEVEL5 = f'OU=Level5,{SRC}'


def build_source():
    src = FakeLDAPConnector('source.alt')
    src.seed(SRC, ['domain'])
    src.seed(f'OU=Level1,{SRC}', ['organizationalUnit'], ou='Level1')
    src.seed(LEVEL2, ['organizationalUnit'], ou='Level2')
    src.seed(LEVEL5, ['organizationalUnit'], ou='Level5')
    src.seed(f'CN=user1,{LEVEL2}', ['user'], cn='user1', sAMAccountName='user1')
    src.seed(f'CN=user5,{LEVEL5}', ['user'], cn='user5', sAMAccountName='user5')
    src.seed(f'CN=group1,{LEVEL2}', ['group'], cn='group1', sAMAccountName='group1',
             groupType=-2147483646,
             member=[f'CN=user1,{LEVEL2}', f'CN=user5,{LEVEL5}'])
    return src


def migrate(db, base_dn, src, dst, logger, dry_run):
    return Migrator(source_conn=src, dest_conn=dst, migration_db=db,
                    logger=logger, dry_run=dry_run).migrate(base_dn)


def main():
    tmp = Path(tempfile.mkdtemp())
    db = MigrationDB(tmp / 'm.db')
    logger = MigrationLogger(log_file=tmp / 't.log')
    logger.set_log_level('ERROR')

    failures = []

    def check(label, actual, expected):
        ok = actual == expected
        print(f"  {'PASS' if ok else 'FAIL'}  {label}: {actual!r}"
              f"{'' if ok else f' (expected {expected!r})'}")
        if not ok:
            failures.append(label)

    src = build_source()
    dst = FakeLDAPConnector('dest.alt')
    dst.seed(DST, ['domain'])
    dst.seed(f'OU=Level1,{DST}', ['organizationalUnit'], ou='Level1')

    # ---- 1. dry run on a fresh scope -------------------------------------
    print("\n=== Dry run over untouched scope ===")
    baseline = set(dst.entries)
    baseline_writes = len(dst.modify_log)

    r = migrate(db, LEVEL2, src, dst, logger, dry_run=True)

    check("dry run succeeded", r.success, True)
    check("destination objects unchanged", set(dst.entries), baseline)
    check("no modify operations issued", len(dst.modify_log), baseline_writes)
    check("migration_map stayed empty",
          db.get_object_by_source_dn(f'CN=user1,{LEVEL2}'), None)
    check("reported what it would create", r.objects_created > 0, True)

    # ---- 2. real run leaves user5 deferred -------------------------------
    print("\n=== Real run over Level2 only (user5 out of scope) ===")
    migrate(db, LEVEL2, src, dst, logger, dry_run=False)

    dest_group = f'CN=group1,OU=Level2,OU=Level1,{DST}'
    check("one deferred reference pending", len(db.get_unresolved_references()), 1)
    check("group1 has only the in-scope member", len(dst.members_of(dest_group)), 1)

    # ---- 3. make the target resolvable WITHOUT running phase 4 -----------
    # Phase 4 resolves deferred references globally, so a normal migration of
    # Level5 would resolve this immediately and there would be nothing pending
    # left to dry-run against. The destination object and its migration_map row
    # are therefore created directly, reproducing the "pending but now
    # resolvable" state that the dry-run guard has to protect.
    print("\n=== Dry run while a resolvable reference is pending ===")
    dst.seed(f'OU=Level5,{DST}', ['organizationalUnit'], ou='Level5')
    dest_user5 = f'CN=user5,OU=Level5,{DST}'
    dst.seed(dest_user5, ['user'], cn='user5', sAMAccountName='user5')
    db.add_object(
        source_guid=src.entries[src._key(f'CN=user5,{LEVEL5}')]['attributes']['objectGUID'],
        source_dn=f'CN=user5,{LEVEL5}',
        dest_guid='seeded', dest_dn=dest_user5,
        object_type='user', status='created', run_id=1,
    )
    check("target is now resolvable",
          db.get_object_by_source_dn(f'CN=user5,{LEVEL5}') is not None, True)

    members_before = sorted(dst.members_of(dest_group))
    writes_before = len(dst.modify_log)

    migrate(db, LEVEL2, src, dst, logger, dry_run=True)

    check("membership not modified", sorted(dst.members_of(dest_group)), members_before)
    check("no destination writes", len(dst.modify_log), writes_before)
    check("deferred row left pending for the real run",
          len(db.get_unresolved_references()), 1)

    # ---- 4. the real run must still apply it -----------------------------
    print("\n=== Real re-run still applies the deferred membership ===")
    migrate(db, LEVEL2, src, dst, logger, dry_run=False)

    members = sorted(dst.members_of(dest_group))
    check("group1 now has both members", len(members), 2)
    check("user5 membership applied", any('user5' in m for m in members), True)
    check("no pending references left", len(db.get_unresolved_references()), 0)

    print("\n" + "=" * 60)
    if failures:
        print(f"{len(failures)} CHECK(S) FAILED: {failures}")
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == '__main__':
    sys.exit(main())
