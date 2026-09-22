"""
Rules deciding which objects are skipped during a scan.

The patterns in settings.IGNORED_DN_PATTERNS exist to keep built-in containers
(CN=Users, CN=Builtin, CN=System, ...) out of a broad scan such as the whole
domain. They are substring matches against the full DN, which caused a bug: when
the operator explicitly asked to migrate CN=Users,DC=win,DC=test, the pattern
"CN=Users,DC=" matched both that container *and everything inside it*, so every
object was classified as ignored and the plan came out empty ("nothing to do").

Explicit intent has to win. A pattern that matches the requested base DN is
therefore disabled for that run, while all the other patterns stay active. Scanning
the domain root still skips CN=Users; scanning CN=Users migrates its contents.

Analyzer and Verifier both use this, so their counts stay comparable.
"""
from typing import List, Optional

from config import settings
from utils.dn_utils import DNUtils


# Well-known RIDs of built-in principals that must never be migrated. The
# destination domain creates its own copies with its own SIDs, so transferring
# these would at best collide and at worst interfere with the target domain's
# own accounts and groups.
#
# RIDs are matched rather than names: a localised domain calls RID 500
# "Администратор" and an English one calls it "Administrator", but the RID is the
# same everywhere. Names are only a fallback (see BUILTIN_NAMES) for the case
# where objectSid could not be read.
BUILTIN_RIDS = {
    # Accounts
    500: 'Administrator',
    501: 'Guest',
    502: 'krbtgt',
    503: 'DefaultAccount',
    504: 'WDAGUtilityAccount',
    # Domain groups
    498: 'Enterprise Read-only Domain Controllers',
    512: 'Domain Admins',
    513: 'Domain Users',
    514: 'Domain Guests',
    515: 'Domain Computers',
    516: 'Domain Controllers',
    517: 'Cert Publishers',
    518: 'Schema Admins',
    519: 'Enterprise Admins',
    520: 'Group Policy Creator Owners',
    521: 'Read-only Domain Controllers',
    522: 'Cloneable Domain Controllers',
    523: 'CDC Reserved',
    524: 'Domain Domain Controllers',
    525: 'Protected Users',
    526: 'Key Admins',
    527: 'Enterprise Key Admins',
    553: 'RAS and IAS Servers',
    571: 'Allowed RODC Password Replication Group',
    572: 'Denied RODC Password Replication Group',
}

# The Builtin domain authority. Every SID under it identifies a group Windows
# creates and manages itself (Administrators, Users, Backup Operators, Hyper-V
# Administrators, Access Control Assistance Operators, ...). The whole prefix is
# rejected rather than an enumeration of known members: the list grows with every
# Windows release, and a group we have not heard of is still a built-in group.
BUILTIN_SID_PREFIX = 'S-1-5-32-'

# Names for the Builtin SIDs we can label, purely so the log says something more
# useful than the bare number. Absence from this map does NOT mean the SID is
# allowed through - BUILTIN_SID_PREFIX above decides that.
BUILTIN_SID_NAMES = {
    'S-1-5-32-544': 'Administrators',
    'S-1-5-32-545': 'Users',
    'S-1-5-32-546': 'Guests',
    'S-1-5-32-547': 'Power Users',
    'S-1-5-32-548': 'Account Operators',
    'S-1-5-32-549': 'Server Operators',
    'S-1-5-32-550': 'Print Operators',
    'S-1-5-32-551': 'Backup Operators',
    'S-1-5-32-552': 'Replicators',
    'S-1-5-32-554': 'Pre-Windows 2000 Compatible Access',
    'S-1-5-32-555': 'Remote Desktop Users',
    'S-1-5-32-556': 'Network Configuration Operators',
    'S-1-5-32-557': 'Incoming Forest Trust Builders',
    'S-1-5-32-558': 'Performance Monitor Users',
    'S-1-5-32-559': 'Performance Log Users',
    'S-1-5-32-560': 'Windows Authorization Access Group',
    'S-1-5-32-561': 'Terminal Server License Servers',
    'S-1-5-32-562': 'Distributed COM Users',
    'S-1-5-32-568': 'IIS_IUSRS',
    'S-1-5-32-569': 'Cryptographic Operators',
    'S-1-5-32-573': 'Event Log Readers',
    'S-1-5-32-574': 'Certificate Service DCOM Access',
    'S-1-5-32-575': 'RDS Remote Access Servers',
    'S-1-5-32-576': 'RDS Endpoint Servers',
    'S-1-5-32-577': 'RDS Management Servers',
    'S-1-5-32-578': 'Hyper-V Administrators',
    'S-1-5-32-579': 'Access Control Assistance Operators',
    'S-1-5-32-580': 'Remote Management Users',
    'S-1-5-32-581': 'System Managed Accounts Group',
    'S-1-5-32-582': 'Storage Replica Administrators',
    'S-1-5-32-583': 'Device Owners',
}

# systemFlags bit that marks an object the directory refuses to delete. Set on
# objects Active Directory maintains itself, so it doubles as a reliable
# "this is infrastructure, not user data" signal.
SYSTEM_FLAG_DISALLOW_DELETE = 0x80000000

# The documented FLAG_DISALLOW_DELETE value (0x00000010 in some references) is
# checked too, because sources disagree on which bit is authoritative and a false
# positive here only costs us skipping an object we should not be moving anyway.
SYSTEM_FLAG_DISALLOW_DELETE_ALT = 0x00000010

# Fallback matching by name, used when objectSid is unavailable. Both the English
# names and the Russian names a localised Windows domain assigns are listed,
# because the display name is all we have in that situation. Compared
# case-insensitively against cn and sAMAccountName.
BUILTIN_NAMES = {
    # user accounts
    'krbtgt',
    'administrator', 'администратор',
    'guest', 'гость',
    # groups
    'domain admins', 'администраторы домена',
    'enterprise admins',
    'администраторы основного уровня',
    'администраторы основного уровня предприятия',
    'администраторы предприятия',
    'schema admins', 'администраторы схемы',
    'group policy creator owners', 'владельцы-создатели групповой политики',
    'domain guests', 'гости домена',
    'domain users', 'пользователи домена',
    'domain computers', 'компьютеры домена',
    'domain controllers', 'контроллеры домена',
    'read-only domain controllers', 'контроллеры домена - только чтение',
    'enterprise read-only domain controllers',
    'контроллеры домена предприятия - только чтение',
    'cloneable domain controllers', 'клонируемые контроллеры домена',
    'cert publishers', 'издатели сертификатов',
    'denied rodc password replication group',
    'группа с запрещением репликации паролей rodc',
    'allowed rodc password replication group',
    'группа с разрешением репликации паролей rodc',
    'protected users', 'защищённые пользователи', 'защищенные пользователи',
    'ras and ias servers', 'серверы ras и ias',
    'dnsadmins', 'dnsupdateproxy',
}


class IgnoreRules:
    """Decides whether an object is out of scope for a given base DN."""

    def __init__(self, base_dn: Optional[str] = None,
                 dn_patterns: Optional[List[str]] = None,
                 object_classes: Optional[List[str]] = None,
                 custom_exclusions: Optional[List[str]] = None):
        """
        Args:
            base_dn: The DN the operator asked to migrate. Patterns matching it are
                treated as opted into and disabled. Pass None to apply every
                pattern (used when no explicit scope is known).
            dn_patterns: Override the DN pattern list (defaults to settings)
            object_classes: Override the ignored objectClass list (defaults to settings)
            custom_exclusions: Exact DNs the operator listed in the settings dialog.
                Needed because service groups installed by Windows roles (for
                example "Access-Denied Assistance Users" from File Server Resource
                Manager) carry an ordinary RID and no isCriticalSystemObject flag,
                making them indistinguishable from a real departmental group. No
                automatic rule can separate the two, so the operator decides.
        """
        self.base_dn = base_dn
        self._all_dn_patterns = list(
            dn_patterns if dn_patterns is not None else settings.IGNORED_DN_PATTERNS)
        self.ignored_object_classes = {
            oc.lower() for oc in
            (object_classes if object_classes is not None
             else settings.IGNORED_OBJECT_CLASSES)
        }

        # Normalised for comparison: an operator pasting a DN from a tool may use
        # different spacing or letter case than the directory reports.
        self.custom_exclusions = {
            DNUtils.normalize_dn(dn) for dn in (custom_exclusions or []) if dn
        }

        self.active_dn_patterns, self.overridden_dn_patterns = self._split_patterns()

    def _split_patterns(self):
        """Separate patterns that apply from those the base DN opts into."""
        if not self.base_dn:
            return list(self._all_dn_patterns), []

        base_upper = self.base_dn.upper()
        active, overridden = [], []

        for pattern in self._all_dn_patterns:
            if pattern.upper() in base_upper:
                # The requested scope is inside, or is, this built-in container.
                # The operator asked for it explicitly, so stop filtering on it.
                overridden.append(pattern)
            else:
                active.append(pattern)

        return active, overridden

    def should_ignore(self, dn: str, object_classes, attributes=None) -> bool:
        """
        Args:
            dn: Distinguished Name of the object
            object_classes: Its objectClass values (any case)
            attributes: Full attribute dict, when available. Used to recognise
                built-in principals by objectSid RID (and by name as a fallback);
                without it only DN and objectClass rules apply.

        Returns:
            True if the object must be skipped
        """
        # Operator-defined exclusions come first: an explicit instruction outranks
        # every heuristic below, and checking a set is cheaper than the rest.
        if self.custom_exclusions and \
                DNUtils.normalize_dn(dn or '') in self.custom_exclusions:
            return True

        dn_upper = (dn or '').upper()
        for pattern in self.active_dn_patterns:
            if pattern.upper() in dn_upper:
                return True

        for oc in object_classes or ():
            if str(oc).lower() in self.ignored_object_classes:
                return True

        if attributes and self.builtin_reason(attributes):
            return True

        return False

    def exclusion_reason(self, dn: str) -> Optional[str]:
        """
        Reason string when a DN is on the operator's exclusion list.

        Kept separate from builtin_reason() so the log distinguishes "Windows
        created this and it must never move" from "the operator chose to skip it".

        Args:
            dn: Distinguished Name of the object

        Returns:
            A short reason for the log, or None if the DN is not excluded
        """
        if self.custom_exclusions and \
                DNUtils.normalize_dn(dn or '') in self.custom_exclusions:
            return "excluded by operator (custom exclusion list)"
        return None

    @staticmethod
    def builtin_reason(attributes) -> Optional[str]:
        """
        Identify a built-in principal that must never be migrated.

        Checks, in order of reliability:

        1. isCriticalSystemObject - set by Active Directory itself on objects the
           directory cannot function without. The single most dependable signal,
           because the directory maintains it rather than an administrator.
        2. systemFlags with the disallow-delete bit - the directory refuses to
           delete the object, which likewise marks it as infrastructure.
        3. The Builtin domain SID prefix S-1-5-32-* - every SID under that
           authority is a group Windows creates and manages.
        4. Domain-relative RID against BUILTIN_RIDS.
        5. Name matching, only when objectSid is absent.

        Checks 1 and 2 also catch service objects that carry no SID at all, such as
        system containers, which the SID-based checks below cannot see.

        Args:
            attributes: The object's attribute dict

        Returns:
            A short reason for the log, or None if the object is not built-in
        """
        # Local import: core.ldap_connector imports config, and importing it at
        # module level would make this module depend on ldap3 being installed.
        from core.ldap_connector import LDAPConnector

        # 1. isCriticalSystemObject - maintained by the directory, most reliable
        if IgnoreRules._is_true(attributes.get('isCriticalSystemObject')):
            return "critical system object (isCriticalSystemObject=TRUE)"

        # 2. systemFlags: the directory refuses to delete it
        flags = IgnoreRules._as_int(attributes.get('systemFlags'))
        if flags is not None:
            if flags & SYSTEM_FLAG_DISALLOW_DELETE:
                return (f"system object (systemFlags=0x{flags:08X}, "
                        f"DISALLOW_DELETE set)")
            if flags & SYSTEM_FLAG_DISALLOW_DELETE_ALT:
                return (f"system object (systemFlags=0x{flags:08X}, "
                        f"FLAG_DISALLOW_DELETE set)")

        sid_str = LDAPConnector.format_sid(attributes.get('objectSid'))

        # 3. Builtin domain authority: the entire prefix, not a fixed list
        if sid_str and sid_str.startswith(BUILTIN_SID_PREFIX):
            label = BUILTIN_SID_NAMES.get(sid_str, 'Builtin group')
            return f"built-in principal (Builtin SID {sid_str}, {label})"

        # 4. Domain-relative RID
        rid = LDAPConnector.sid_rid(sid_str)
        if rid is not None and rid in BUILTIN_RIDS:
            return f"built-in principal (RID {rid}, {BUILTIN_RIDS[rid]})"

        # 5. objectSid missing or unreadable: fall back to the name
        if rid is None:
            for attr in ('sAMAccountName', 'cn', 'name'):
                value = attributes.get(attr)
                if isinstance(value, list):
                    value = value[0] if value else None
                if value and str(value).strip().lower() in BUILTIN_NAMES:
                    return f"built-in principal (matched {attr}={value!r}, no objectSid)"

        return None

    @staticmethod
    def _is_true(value) -> bool:
        """
        Interpret an LDAP boolean.

        The value arrives as a real bool from ldap3, or as the string 'TRUE' when
        the server returns it unparsed, so both forms are accepted.
        """
        if isinstance(value, list):
            value = value[0] if value else None
        if value is None:
            return False
        if isinstance(value, bool):
            return value
        return str(value).strip().upper() in ('TRUE', '1')

    @staticmethod
    def _as_int(value) -> Optional[int]:
        """Parse an LDAP integer attribute, returning None when unusable."""
        if isinstance(value, list):
            value = value[0] if value else None
        if value is None:
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    def describe_overrides(self) -> str:
        """Human-readable note for the log, or '' when nothing was overridden."""
        if not self.overridden_dn_patterns:
            return ''
        patterns = ', '.join(repr(p) for p in self.overridden_dn_patterns)
        return (f"Base DN is inside a built-in container; ignore rule(s) {patterns} "
                f"disabled for this run because the scope was requested explicitly")


if __name__ == '__main__':
    print("=== IgnoreRules ===")

    broad = IgnoreRules(base_dn='DC=win,DC=test')
    print("\nbase DC=win,DC=test (whole domain)")
    print("  CN=Users container ignored:",
          broad.should_ignore('CN=Users,DC=win,DC=test', ['container']))
    print("  user inside CN=Users ignored:",
          broad.should_ignore('CN=Ivan,CN=Users,DC=win,DC=test', ['user']))

    explicit = IgnoreRules(base_dn='CN=Users,DC=win,DC=test')
    print("\nbase CN=Users,DC=win,DC=test (explicit)")
    print("  container ignored:",
          explicit.should_ignore('CN=Users,DC=win,DC=test', ['container']))
    print("  user inside ignored:",
          explicit.should_ignore('CN=Ivan,CN=Users,DC=win,DC=test', ['user']))
    print("  computer still ignored:",
          explicit.should_ignore('CN=PC1,CN=Users,DC=win,DC=test', ['computer']))
    print("  note:", explicit.describe_overrides())
