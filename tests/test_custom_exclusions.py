"""
Test operator-defined custom exclusions
"""
import sys
import struct
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from tests.fake_ldap import FakeLDAPConnector
from core.analyzer import Analyzer
from core.ignore_rules import IgnoreRules
from utils.config_manager import ConfigManager
from utils.logger import MigrationLogger


def dsid(rid):
    """Build a domain SID with the given RID"""
    return bytes([1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0]) + \
           struct.pack('<III', 1, 2, 3) + struct.pack('<I', rid)


def test_exclusions_in_config_round_trip():
    """Exclusion list survives write-read cycle through INI file"""
    tmp = Path(tempfile.mkdtemp())
    cfg = ConfigManager(tmp / 'test.ini')

    dns = [
        'CN=Access-Denied Assistance Users,CN=Users,DC=uk,DC=local',
        'CN=WinRMRemoteWMIUsers__,CN=Users,DC=uk,DC=local',
        'CN=Группа с кириллицей,OU=Отдел,DC=ru,DC=local',
    ]
    cfg.set_custom_exclusions(dns)

    # Re-read from a new ConfigManager: simulates next launch
    cfg2 = ConfigManager(tmp / 'test.ini')
    result = cfg2.get_custom_exclusions()

    assert result == dns, f"Expected {dns}, got {result}"
    print("  ✓ DN list with commas, equals, and Cyrillic survives INI round-trip")


def test_exclusions_filter_objects():
    """Analyzer skips objects on the exclusion list"""
    SRC = 'DC=uk,DC=local'
    BASE = f'CN=Users,{SRC}'

    src = FakeLDAPConnector('uk.local')
    src.seed(SRC, ['domain'])
    src.seed(BASE, ['container'], cn='Users')

    # Real departmental group
    src.seed(f'CN=IT Department,{BASE}', ['group'], cn='IT Department',
             sAMAccountName='IT_Dept', groupType=-2147483646, objectSid=dsid(1200))

    # Service group from File Server Resource Manager: ordinary RID, no flags
    src.seed(f'CN=Access-Denied Assistance Users,{BASE}', ['group'],
             cn='Access-Denied Assistance Users',
             sAMAccountName='Access-Denied Assistance Users',
             groupType=-2147483644, objectSid=dsid(1155))

    # Another service group
    src.seed(f'CN=WinRMRemoteWMIUsers__,{BASE}', ['group'],
             cn='WinRMRemoteWMIUsers__',
             sAMAccountName='WinRMRemoteWMIUsers__',
             groupType=-2147483644, objectSid=dsid(1201))

    # Without exclusions: all three pass
    a1 = Analyzer(src).analyze(BASE, include_references=False)
    assert len(a1.groups) == 3
    assert len(a1.ignored) == 0
    print("  ✓ Without exclusions: all three groups pass the filter")

    # With exclusions: only IT Department passes
    exclusions = [
        f'CN=Access-Denied Assistance Users,{BASE}',
        f'CN=WinRMRemoteWMIUsers__,{BASE}',
    ]
    a2 = Analyzer(src, custom_exclusions=exclusions).analyze(BASE, include_references=False)
    assert len(a2.groups) == 1
    assert a2.groups[0]['attributes']['cn'] == 'IT Department'
    assert len(a2.ignored) == 2
    print("  ✓ With exclusions: service groups filtered out, IT Department passes")


def test_exclusions_case_insensitive():
    """DN matching is case-insensitive"""
    SRC = 'DC=uk,DC=local'
    BASE = f'CN=Users,{SRC}'

    src = FakeLDAPConnector('uk.local')
    src.seed(SRC, ['domain'])
    src.seed(BASE, ['container'], cn='Users')
    src.seed(f'CN=TestGroup,{BASE}', ['group'], cn='TestGroup',
             sAMAccountName='test', groupType=-2147483646, objectSid=dsid(1300))

    # Operator pastes uppercase from a tool; directory reports mixed case
    exclusions = ['CN=TESTGROUP,CN=USERS,DC=UK,DC=LOCAL']
    a = Analyzer(src, custom_exclusions=exclusions).analyze(BASE, include_references=False)

    assert len(a.groups) == 0
    assert len(a.ignored) == 1
    print("  ✓ DN matching ignores case differences")


def test_exclusions_with_comments():
    """Comments and blank lines in the exclusion list are stripped"""
    tmp = Path(tempfile.mkdtemp())
    cfg = ConfigManager(tmp / 'test.ini')

    raw_text = """
# Service groups we don't want to migrate
CN=Access-Denied Assistance Users,CN=Users,DC=uk,DC=local

; This one causes conflicts in the destination
CN=WinRMRemoteWMIUsers__,CN=Users,DC=uk,DC=local

CN=Real Group,CN=Users,DC=uk,DC=local
"""
    cfg.set_custom_exclusions(raw_text)
    result = cfg.get_custom_exclusions()

    assert len(result) == 3
    assert 'Access-Denied Assistance Users' in result[0]
    assert 'WinRMRemoteWMIUsers__' in result[1]
    assert 'Real Group' in result[2]
    print("  ✓ Comments and blank lines are stripped from the list")


def test_exclusion_reason_in_log():
    """Excluded objects log a distinct reason (not built-in detection)"""
    SRC = 'DC=uk,DC=local'
    BASE = f'CN=Users,{SRC}'

    src = FakeLDAPConnector('uk.local')
    src.seed(SRC, ['domain'])
    src.seed(BASE, ['container'], cn='Users')
    src.seed(f'CN=TestGroup,{BASE}', ['group'], cn='TestGroup',
             sAMAccountName='test', groupType=-2147483646, objectSid=dsid(1300))

    tmp = Path(tempfile.mkdtemp())
    lg = MigrationLogger(log_file=tmp / 'test.log')
    lg.set_log_level('INFO')

    exclusions = [f'CN=TestGroup,{BASE}']
    a = Analyzer(src, logger=lg, custom_exclusions=exclusions)
    a.analyze(BASE, include_references=False)

    log_text = (tmp / 'test.log').read_text()
    assert 'excluded by operator' in log_text
    assert 'SKIPPED' in log_text
    print("  ✓ Log distinguishes operator exclusions from built-in detection")


if __name__ == '__main__':
    print("\n=== Custom Exclusions Tests ===\n")
    test_exclusions_in_config_round_trip()
    test_exclusions_filter_objects()
    test_exclusions_case_insensitive()
    test_exclusions_with_comments()
    test_exclusion_reason_in_log()
    print("\nAll custom exclusion tests passed")
