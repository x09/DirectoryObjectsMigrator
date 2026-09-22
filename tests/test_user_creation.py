"""
User creation details.

The specification lists userAccountControl among the attributes that must NOT be
transferred from the source. It was previously in the copy list, which meant an
account enabled in the source was created enabled and only patched to 514 by a
follow-up modify -- a window in which the account existed and was usable.

These tests assert the flag is part of the initial add, that the source value is
never propagated, and that passwords are generated rather than copied.
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
L2 = f'OU=Level2,OU=Level1,{SRC}'

FAILURES = []


def check(label, actual, expected):
    ok = actual == expected
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {actual!r}"
          f"{'' if ok else f' (expected {expected!r})'}")
    if not ok:
        FAILURES.append(label)


def main():
    tmp = Path(tempfile.mkdtemp())
    db = MigrationDB(tmp / 'm.db')
    logger = MigrationLogger(log_file=tmp / 't.log')
    logger.set_log_level('ERROR')

    src = FakeLDAPConnector('source.alt')
    src.seed(SRC, ['domain'])
    src.seed(f'OU=Level1,{SRC}', ['organizationalUnit'], ou='Level1')
    src.seed(L2, ['organizationalUnit'], ou='Level2')

    # An ENABLED account in the source (512 = NORMAL_ACCOUNT, no disable bit).
    # This is the case that used to leak through.
    src.seed(f'CN=enabled,{L2}', ['user'], cn='enabled',
             sAMAccountName='enabled', userAccountControl=512,
             userPrincipalName='enabled@source.alt', title='Engineer')

    # An account with extra flags set, e.g. DONT_EXPIRE_PASSWORD (0x10000)
    src.seed(f'CN=noexpire,{L2}', ['user'], cn='noexpire',
             sAMAccountName='noexpire', userAccountControl=66048)

    dst = FakeLDAPConnector('dest.alt')
    dst.seed(DST, ['domain'])
    dst.seed(f'OU=Level1,{DST}', ['organizationalUnit'], ou='Level1')

    Migrator(source_conn=src, dest_conn=dst, migration_db=db,
             logger=logger).migrate(L2)

    dest_enabled = f'CN=enabled,OU=Level2,OU=Level1,{DST}'
    dest_noexpire = f'CN=noexpire,OU=Level2,OU=Level1,{DST}'

    print("\n=== Disabled flag is set at creation time ===")
    add_attrs = dst.attrs_in_add(dest_enabled)
    check("userAccountControl present in the add operation",
          'userAccountControl' in add_attrs, True)
    check("add carries the disabled value 514",
          add_attrs.get('userAccountControl'), 514)
    check("no follow-up modify of userAccountControl was needed",
          'userAccountControl' in dst.attrs_in_modifies(dest_enabled), False)

    print("\n=== Source value never propagates ===")
    final = dst.get_object_by_dn(dest_enabled)['attributes']
    check("enabled source account is disabled in destination",
          final.get('userAccountControl'), 514)
    check("source value 512 did not survive",
          final.get('userAccountControl') == 512, False)

    noexpire_final = dst.get_object_by_dn(dest_noexpire)['attributes']
    check("extra source flags discarded (66048 -> 514)",
          noexpire_final.get('userAccountControl'), 514)

    print("\n=== Passwords are generated, never copied ===")
    check("unicodePwd absent from the add attributes",
          'unicodePwd' in add_attrs, False)
    check("password set by a separate modify",
          'unicodePwd' in dst.attrs_in_modifies(dest_enabled), True)
    check("primaryGroupID set to Domain Users",
          noexpire_final.get('primaryGroupID'), settings.PRIMARY_GROUP_ID)

    print("\n=== Ordinary attributes still copied and transformed ===")
    check("title copied", final.get('title'), 'Engineer')
    check("UPN suffix rewritten", final.get('userPrincipalName'), 'enabled@dest.alt')

    db.close()

    print("\n" + "=" * 62)
    if FAILURES:
        print(f"{len(FAILURES)} CHECK(S) FAILED: {FAILURES}")
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == '__main__':
    sys.exit(main())
