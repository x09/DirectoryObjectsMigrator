"""
Attribute coverage: everything the configuration says to copy must arrive.

Phase 3 of the pipeline is a no-op because phase 2 already writes the full
attribute set in the initial LDAP add. That is only safe if phase 2 really is
complete, which is what this test pins down: a user is populated with one
attribute from every optional category in attribute_mappings.yaml, and each one
must be present in the destination afterwards.

Also verifies that the attributes which must NOT be copied stay behind.
"""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from tests.fake_ldap import FakeLDAPConnector
from core.migrator import Migrator
from core.attribute_mapper import AttributeMapper
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


# One attribute from every optional category the config lists for a user
RICH_USER = dict(
    cn='rich', sAMAccountName='rich',
    sn='Doe', givenName='John', initials='J', displayName='John Doe',
    mail='rich@source.alt', userPrincipalName='rich@source.alt',
    proxyAddresses=['SMTP:rich@source.alt', 'smtp:r@source.alt'],
    telephoneNumber='+7-000', mobile='+7-111',
    facsimileTelephoneNumber='+7-222', ipPhone='1000', pager='p1',
    homePhone='+7-333',
    physicalDeliveryOfficeName='Room 5', streetAddress='Main st 1',
    postOfficeBox='PO-1', l='Yekaterinburg', st='Sverdlovsk',
    postalCode='620000', c='RU', co='Russia',
    title='Engineer', department='IT', company='Acme', division='Core',
    employeeID='E1', employeeNumber='42', employeeType='FTE',
    userWorkstations='PC1', homeDirectory=r'\\srv\rich', homeDrive='H:',
    scriptPath='logon.bat', profilePath=r'\\srv\prof',
    accountExpires='0',
    description='desc', info='note', comment='cmt',
    wWWHomePage='http://example.test', url='http://example.test/u',
)

# Attributes that must never reach the destination
FORBIDDEN = dict(
    objectSid='S-1-5-21-1',
    uSNCreated='123', uSNChanged='456',
    whenCreated='20200101000000.0Z', whenChanged='20200202000000.0Z',
    badPwdCount='3', badPasswordTime='132',
    lastLogon='133', lastLogonTimestamp='134', logonCount='7',
    pwdLastSet='135', lockoutTime='0',
    ntPwdHistory='hash', lmPwdHistory='hash',
    ntSecurityDescriptor='O:BA',
    instanceType='4',
    msExchMailboxGuid='xyz', msExchVersion='1', legacyExchangeDN='/o=x',
)


def main():
    tmp = Path(tempfile.mkdtemp())
    db = MigrationDB(tmp / 'm.db')
    logger = MigrationLogger(log_file=tmp / 't.log')
    logger.set_log_level('ERROR')

    src = FakeLDAPConnector('source.alt')
    src.seed(SRC, ['domain'])
    src.seed(f'OU=Level1,{SRC}', ['organizationalUnit'], ou='Level1')
    src.seed(L2, ['organizationalUnit'], ou='Level2')
    src.seed(f'CN=rich,{L2}', ['user'], **{**RICH_USER, **FORBIDDEN})

    dst = FakeLDAPConnector('dest.alt')
    dst.seed(DST, ['domain'])
    dst.seed(f'OU=Level1,{DST}', ['organizationalUnit'], ou='Level1')

    Migrator(source_conn=src, dest_conn=dst, migration_db=db,
             logger=logger).migrate(L2)

    dest_dn = f'CN=rich,OU=Level2,OU=Level1,{DST}'
    final = dst.get_object_by_dn(dest_dn)['attributes']
    mapper = AttributeMapper()

    print("\n=== Every attribute marked for copying arrives ===")
    should_copy = [a for a in RICH_USER if mapper.should_copy_attribute(a, 'user')]
    missing = sorted(a for a in should_copy if a not in final)

    check("config marks a substantial set for copying", len(should_copy) > 30, True)
    check("none are missing in the destination", missing, [])

    print("\n=== Suffix transformation applied ===")
    check("UPN rewritten", final.get('userPrincipalName'), 'rich@dest.alt')
    check("mail rewritten", final.get('mail'), 'rich@dest.alt')
    check("proxyAddresses rewritten, prefixes preserved",
          final.get('proxyAddresses'),
          ['SMTP:rich@dest.alt', 'smtp:r@dest.alt'])

    print("\n=== Excluded attributes stay behind ===")
    leaked = sorted(a for a in FORBIDDEN if a in final)
    check("no system, password or Exchange attributes copied", leaked, [])

    print("\n=== Phase 2 is complete, so phase 3 has nothing to do ===")
    # Only the two attributes that cannot be part of the add should be modified
    modified = sorted(set(dst.attrs_in_modifies(dest_dn)))
    check("only primaryGroupID and unicodePwd need a separate write",
          modified, ['primaryGroupID', 'unicodePwd'])

    print("\n=== External addresses are left alone ===")
    src.seed(f'CN=ext,{L2}', ['user'], cn='ext', sAMAccountName='ext',
             mail='someone@partner.example',
             userPrincipalName='ext@source.alt')
    Migrator(source_conn=src, dest_conn=dst, migration_db=db,
             logger=logger).migrate(L2)
    ext = dst.get_object_by_dn(f'CN=ext,OU=Level2,OU=Level1,{DST}')['attributes']
    check("foreign mail domain untouched", ext.get('mail'), 'someone@partner.example')
    check("own UPN still rewritten", ext.get('userPrincipalName'), 'ext@dest.alt')

    db.close()

    print("\n" + "=" * 62)
    if FAILURES:
        print(f"{len(FAILURES)} CHECK(S) FAILED: {FAILURES}")
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == '__main__':
    sys.exit(main())
