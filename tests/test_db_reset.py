"""
Resetting the migration database.

The reset button in the settings dialog exists so that test runs can be discarded
and migration started from a clean slate. What it must and must not do:

  - clear every row of this tool's own bookkeeping
  - make a recoverable backup first
  - leave the open connection usable, and restart run_id at 1
  - never touch either domain controller

The last point is the consequential one: objects already created in the destination
survive a reset, so the following run classifies them as CONFLICT rather than
EXISTS. They are still never overwritten. That behaviour is asserted here because it
is the part an operator is most likely to be surprised by.
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
L2 = f'OU=Level2,OU=Level1,{SRC}'

FAILURES = []


def check(label, actual, expected):
    ok = actual == expected
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {actual!r}"
          f"{'' if ok else f' (expected {expected!r})'}")
    if not ok:
        FAILURES.append(label)


def build_pair():
    """A source with one OU, one user and one group referencing an outsider."""
    src = FakeLDAPConnector('source.alt')
    src.seed(SRC, ['domain'])
    src.seed(f'OU=Level1,{SRC}', ['organizationalUnit'], ou='Level1')
    src.seed(L2, ['organizationalUnit'], ou='Level2')
    src.seed(f'CN=u1,{L2}', ['user'], cn='u1', sAMAccountName='u1')
    src.seed(f'CN=g1,{L2}', ['group'], cn='g1', sAMAccountName='g1',
             groupType=-2147483646,
             member=[f'CN=u1,{L2}', f'CN=outsider,OU=Elsewhere,{SRC}'])

    dst = FakeLDAPConnector('dest.alt')
    dst.seed(DST, ['domain'])
    dst.seed(f'OU=Level1,{DST}', ['organizationalUnit'], ou='Level1')
    return src, dst


def main():
    tmp = Path(tempfile.mkdtemp())
    db_path = tmp / 'migration.db'
    db = MigrationDB(db_path)
    logger = MigrationLogger(log_file=tmp / 't.log')
    logger.set_log_level('ERROR')

    src, dst = build_pair()

    print("\n=== A fresh database reports itself empty ===")
    check("is_empty on a new database", db.is_empty(), True)
    check("reset is a no-op with nothing to clear", db.reset()['total'], 0)

    print("\n=== After a migration it holds history ===")
    result = Migrator(source_conn=src, dest_conn=dst, migration_db=db,
                      logger=logger).migrate(L2)
    counts = db.counts()

    check("run recorded", counts['migration_runs'], 1)
    check("three objects tracked", counts['migration_map'], 3)
    check("one deferred reference recorded", counts['deferred_references'], 1)
    check("configuration snapshot recorded", counts['run_configurations'], 1)
    check("no longer empty", db.is_empty(), False)
    check("first run_id is 1", result.run_id, 1)

    print("\n=== Reset clears everything and backs up first ===")
    info = db.reset(make_backup=True)

    check("reported total matches what was there", info['total'], 6)
    check("backup path returned", info['backup_path'] is not None, True)
    check("backup exists on disk", info['backup_path'].exists(), True)
    check("all tables empty afterwards", sum(db.counts().values()), 0)
    check("is_empty afterwards", db.is_empty(), True)
    check("no deferred references left", len(db.get_unresolved_references()), 0)

    print("\n=== The connection stays usable and run_id restarts ===")
    # A reset recreates the schema rather than deleting the file, so callers do not
    # have to reconnect. Verified by writing through the same handle.
    new_run = db.create_migration_run('OU=X,' + SRC, 'OU=X,' + DST, '1', '2', {})
    check("run_id restarts at 1", new_run, 1)
    check("write through the same connection worked",
          db.counts()['migration_runs'], 1)

    print("\n=== The backup still holds the old history ===")
    with MigrationDB(info['backup_path']) as backup_db:
        check("backup has the original rows", sum(backup_db.counts().values()), 6)
        check("backup retains the tracked objects",
              backup_db.counts()['migration_map'], 3)

    print("\n=== The destination directory is untouched ===")
    check("destination objects still present", dst.object_exists(f'CN=u1,OU=Level2,OU=Level1,{DST}'), True)
    check("destination group still present", dst.object_exists(f'CN=g1,OU=Level2,OU=Level1,{DST}'), True)

    print("\n=== Consequence: a later run sees them as CONFLICT ===")
    # This is the behaviour to be aware of. The objects exist but are no longer
    # tracked, which is exactly the definition of a conflict; they are not
    # overwritten.
    db.close()
    fresh = MigrationDB(db_path)
    rerun = Migrator(source_conn=src, dest_conn=dst, migration_db=fresh,
                     logger=logger).migrate(L2)

    check("nothing recreated", rerun.objects_created, 0)
    check("existing objects reported as conflicts", rerun.objects_conflicted, 3)
    check("conflicts recorded in the database",
          len(fresh.get_conflicts(rerun.run_id)), 3)
    check("destination objects were not overwritten",
          dst.object_exists(f'CN=u1,OU=Level2,OU=Level1,{DST}'), True)

    print("\n=== Reset without a backup ===")
    info2 = fresh.reset(make_backup=False)
    check("no backup created", info2['backup_path'], None)
    check("data cleared regardless", fresh.is_empty(), True)

    fresh.close()

    print("\n" + "=" * 62)
    if FAILURES:
        print(f"{len(FAILURES)} CHECK(S) FAILED: {FAILURES}")
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == '__main__':
    sys.exit(main())
