"""
The preview plan must agree with what the migration actually does.

Previously the preview showed source counts only: on a repeat run it claimed it
would create objects that already existed. Migrator.build_plan() now consults the
migration database and the destination directory.

The critical property tested here is agreement: for the same scope, the plan's
create/exists/conflict counts must match the totals the real migration reports.
"""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from tests.fake_ldap import FakeLDAPConnector
from core.analyzer import Analyzer
from core.migrator import Migrator
from database.migration_db import MigrationDB
from utils.logger import MigrationLogger
from config import settings

SRC = 'DC=source,DC=alt'
DST = 'DC=dest,DC=alt'
L2 = f'OU=Level2,OU=Level1,{SRC}'
L5 = f'OU=Level5,{SRC}'

FAILURES = []


def check(label, actual, expected):
    ok = actual == expected
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {actual!r}"
          f"{'' if ok else f' (expected {expected!r})'}")
    if not ok:
        FAILURES.append(label)


def build_source():
    src = FakeLDAPConnector('source.alt')
    src.seed(SRC, ['domain'])
    src.seed(f'OU=Level1,{SRC}', ['organizationalUnit'], ou='Level1')
    src.seed(L2, ['organizationalUnit'], ou='Level2')
    src.seed(L5, ['organizationalUnit'], ou='Level5')
    src.seed(f'CN=user1,{L2}', ['user'], cn='user1', sAMAccountName='user1')
    src.seed(f'CN=user2,{L2}', ['user'], cn='user2', sAMAccountName='user2')
    src.seed(f'CN=user5,{L5}', ['user'], cn='user5', sAMAccountName='user5')
    src.seed(f'CN=group1,{L2}', ['group'], cn='group1', sAMAccountName='group1',
             groupType=-2147483646,
             member=[f'CN=user1,{L2}', f'CN=user2,{L2}', f'CN=user5,{L5}'])
    return src


def make_migrator(src, dst, db, logger, dry_run=False):
    return Migrator(source_conn=src, dest_conn=dst, migration_db=db,
                    logger=logger, dry_run=dry_run)


def plan_for(src, dst, db, logger, base_dn):
    analysis = Analyzer(src).analyze(base_dn, include_references=True)
    return make_migrator(src, dst, db, logger, dry_run=True).build_plan(analysis), analysis


def main():
    tmp = Path(tempfile.mkdtemp())
    db = MigrationDB(tmp / 'm.db')
    logger = MigrationLogger(log_file=tmp / 't.log')
    logger.set_log_level('ERROR')

    src = build_source()
    dst = FakeLDAPConnector('dest.alt')
    dst.seed(DST, ['domain'])
    dst.seed(f'OU=Level1,{DST}', ['organizationalUnit'], ou='Level1')

    # ---- first pass: everything is new --------------------------------
    print("\n=== Plan before anything is migrated ===")
    plan, analysis = plan_for(src, dst, db, logger, L2)
    s = plan.summary()

    check("4 objects to create (OU + 2 users + group)", s['create'], 4)
    check("nothing already exists", s['exists'], 0)
    check("no conflicts", s['conflict'], 0)
    check("no classification errors", s['errors'], 0)
    check("one out-of-scope reference deferred", s['deferred'], 1)
    check("that reference is not resolvable yet", s['deferred_resolvable_now'], 0)
    check("destination base DN computed", plan.dest_base_dn,
          f'OU=Level2,OU=Level1,{DST}')

    print("\n=== Plan matches what the migration then does ===")
    result = make_migrator(src, dst, db, logger).migrate(L2)
    check("created count matches the plan", result.objects_created, s['create'])
    check("conflicts match the plan", result.objects_conflicted, s['conflict'])

    # ---- second pass: everything already migrated ---------------------
    print("\n=== Plan on a repeat run (the case that used to be wrong) ===")
    plan2, _a = plan_for(src, dst, db, logger, L2)
    s2 = plan2.summary()

    check("nothing to create", s2['create'], 0)
    check("all 4 objects reported as existing", s2['exists'], 4)
    check("still no conflicts", s2['conflict'], 0)

    result2 = make_migrator(src, dst, db, logger).migrate(L2)
    check("migration also creates nothing", result2.objects_created, 0)
    check("skipped count matches the plan", result2.objects_skipped, s2['exists'])

    # ---- deferred target becomes available ----------------------------
    print("\n=== Deferred reference after its target is migrated ===")
    make_migrator(src, dst, db, logger).migrate(L5)
    plan3, _a = plan_for(src, dst, db, logger, L2)
    check("deferred reference now marked resolvable",
          plan3.summary()['deferred_resolvable_now'], 1)

    # ---- conflict detection -------------------------------------------
    print("\n=== Conflict: untracked object present in destination ===")
    src.seed(f'CN=user9,{L2}', ['user'], cn='user9', sAMAccountName='user9')
    dst.seed(f'CN=user9,OU=Level2,OU=Level1,{DST}', ['user'],
             cn='user9', sAMAccountName='user9')

    plan4, _a = plan_for(src, dst, db, logger, L2)
    s4 = plan4.summary()
    check("conflict predicted before writing", s4['conflict'], 1)
    check("conflicting object not offered for creation", s4['create'], 0)

    result4 = make_migrator(src, dst, db, logger).migrate(L2)
    check("migration reports the same conflict count",
          result4.objects_conflicted, s4['conflict'])

    # ---- missing objectGUID -------------------------------------------
    print("\n=== Object without objectGUID is an error, not a create ===")
    key = src._key(f'CN=noguid,{L2}')
    src.entries[key] = {'dn': f'CN=noguid,{L2}',
                        'attributes': {'objectClass': ['user'], 'cn': 'noguid',
                                       'sAMAccountName': 'noguid'}}
    plan5, _a = plan_for(src, dst, db, logger, L2)
    check("counted as an error", plan5.summary()['errors'], 1)
    check("not counted as a create", plan5.summary()['create'], 0)

    db.close()

    print("\n" + "=" * 62)
    if FAILURES:
        print(f"{len(FAILURES)} CHECK(S) FAILED: {FAILURES}")
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == '__main__':
    sys.exit(main())
