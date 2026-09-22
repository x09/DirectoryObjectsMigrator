"""
Unit tests for the pieces that were changed while fixing the startup crash,
the cross-thread SQLite error and the segfault.

Covers:
  - DNUtils domain conversion (used by every migrated object)
  - MigrationDB access from multiple threads
  - Migrator._calculate_statistics aggregation of nested per-type counters
  - LDAPConnector "no such object" handling
"""
import sys
import tempfile
import threading
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

FAILURES = []


def check(label, actual, expected):
    ok = actual == expected
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {actual!r}"
          f"{'' if ok else f' (expected {expected!r})'}")
    if not ok:
        FAILURES.append(label)


def test_dn_utils():
    print("\n=== DNUtils ===")
    from utils.dn_utils import DNUtils

    src, dst = 'DC=source,DC=alt', 'DC=dest,DC=alt'

    check("converts a leaf DN",
          DNUtils.convert_dn(f'CN=u1,OU=L2,OU=L1,{src}', src, dst),
          f'CN=u1,OU=L2,OU=L1,{dst}')
    check("converts the base itself", DNUtils.convert_dn(src, src, dst), dst)
    check("conversion is case-insensitive on the domain part",
          DNUtils.convert_dn('CN=u1,OU=L2,dc=SOURCE,dc=ALT', src, dst),
          f'CN=u1,OU=L2,{dst}')
    check("parent DN", DNUtils.get_parent_dn(f'CN=u1,OU=L2,{src}'), f'OU=L2,{src}')
    check("RDN", DNUtils.get_rdn(f'CN=u1,OU=L2,{src}'), 'CN=u1')
    check("depth orders parents before children",
          DNUtils.get_depth(f'OU=L1,{src}') < DNUtils.get_depth(f'OU=L2,OU=L1,{src}'),
          True)
    check("child detection", DNUtils.is_child_of(f'CN=u,OU=L1,{src}', f'OU=L1,{src}'), True)
    check("non-child detection", DNUtils.is_child_of(f'CN=u,OU=X,{src}', f'OU=L1,{src}'), False)
    check("a DN is not its own child", DNUtils.is_child_of(f'OU=L1,{src}', f'OU=L1,{src}'), False)


def test_db_threading():
    print("\n=== MigrationDB across threads ===")
    from database.migration_db import MigrationDB

    db_path = Path(tempfile.mkdtemp()) / 'threads.db'
    db = MigrationDB(db_path)

    run_id = db.create_migration_run('OU=A,DC=s,DC=alt', 'OU=A,DC=d,DC=alt',
                                     '1.1.1.1', '2.2.2.2', {})
    errors = []

    def writer(offset):
        try:
            for i in range(150):
                n = offset * 1000 + i
                db.add_object(f'guid-{n}', f'CN=u{n},OU=A,DC=s,DC=alt',
                              f'dg-{n}', f'CN=u{n},OU=A,DC=d,DC=alt',
                              'user', 'created', run_id)
        except Exception as e:
            errors.append(e)
            traceback.print_exc()

    threads = [threading.Thread(target=writer, args=(k,)) for k in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    check("no cross-thread SQLite error", errors, [])
    check("all rows written from worker threads",
          db.get_object_by_source_guid('guid-2100') is not None, True)
    check("readable from the main thread afterwards",
          bool(db.get_statistics(run_id)), True)

    db.close()
    db.close()  # must tolerate a second call
    check("double close is safe", True, True)


def test_statistics_aggregation():
    print("\n=== Migrator._calculate_statistics ===")
    from core.migrator import Migrator, MigrationResult

    r = MigrationResult()
    r.phase_results = {
        'phase1_ous': {'created': 12, 'exists': 0, 'conflicts': 0, 'errors': 0},
        'phase2_objects': {
            'user':    {'created': 183, 'exists': 4, 'conflicts': 1, 'errors': 2},
            'group':   {'created': 37,  'exists': 3, 'conflicts': 0, 'errors': 0},
            'contact': {'created': 15,  'exists': 0, 'conflicts': 0, 'errors': 0},
        },
        'phase3_attributes': {},
        # Phase 4 keys must not be mistaken for object counts
        'phase4_references': {'resolved': 9, 'deferred': 4},
    }

    Migrator._calculate_statistics(None, r)

    check("created totals include nested per-type counts", r.objects_created, 12 + 183 + 37 + 15)
    check("skipped totals", r.objects_skipped, 7)
    check("conflicts totals", r.objects_conflicted, 1)
    check("errors totals", r.errors_count, 2)


def test_no_such_object():
    print("\n=== LDAPConnector missing-object handling ===")
    from ldap3.core.exceptions import LDAPNoSuchObjectResult
    from core.ldap_connector import LDAPConnector, LDAPOperationError

    c = LDAPConnector.__new__(LDAPConnector)  # no live connection needed

    check("typed ldap3 exception recognised",
          c._is_no_such_object(LDAPNoSuchObjectResult('nope')), True)
    check("wrapped result code recognised",
          c._is_no_such_object(LDAPOperationError(
              'Search error: LDAPNoSuchObjectResult - 32 - noSuchObject')), True)
    check("prose form recognised",
          c._is_no_such_object(LDAPOperationError('no such object')), True)

    for other in ('insufficientAccessRights', 'invalidCredentials', 'sizeLimitExceeded'):
        check(f"{other} not treated as missing",
              c._is_no_such_object(LDAPOperationError(other)), False)

    def raise_missing(**kw):
        raise LDAPOperationError('Search error: LDAPNoSuchObjectResult - 32 - noSuchObject')

    def raise_denied(**kw):
        raise LDAPOperationError('Search error: insufficientAccessRights')

    c.search = raise_missing
    check("missing object returns None", c.get_object_by_dn('CN=ghost,DC=d,DC=alt'), None)

    c.search = lambda **kw: []
    check("empty result -> object_exists False", c.object_exists('CN=ghost,DC=d,DC=alt'), False)

    c.search = raise_denied
    try:
        c.get_object_by_dn('CN=x,DC=d,DC=alt')
        check("access denied propagates", False, True)
    except LDAPOperationError:
        check("access denied propagates", True, True)


def main():
    test_dn_utils()
    test_db_threading()
    test_statistics_aggregation()
    test_no_such_object()

    print("\n" + "=" * 62)
    if FAILURES:
        print(f"{len(FAILURES)} CHECK(S) FAILED: {FAILURES}")
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == '__main__':
    sys.exit(main())
