"""
Analyzer
Analyzes source domain and classifies objects for migration
"""
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass, field
from collections import defaultdict
from core.ldap_connector import LDAPConnector, LDAPOperationError
from core.ignore_rules import IgnoreRules
from utils.dn_utils import DNUtils
from config import settings
import ldap3


@dataclass
class AnalysisResult:
    """Result of domain analysis"""
    base_dn: str
    total_objects: int = 0

    # Objects by type
    organizational_units: List[Dict[str, Any]] = field(default_factory=list)
    users: List[Dict[str, Any]] = field(default_factory=list)
    groups: List[Dict[str, Any]] = field(default_factory=list)
    contacts: List[Dict[str, Any]] = field(default_factory=list)
    unsupported: List[Dict[str, Any]] = field(default_factory=list)
    ignored: List[Dict[str, Any]] = field(default_factory=list)

    # Statistics
    counts_by_type: Dict[str, int] = field(default_factory=dict)

    # Dependency tracking
    ou_hierarchy: List[str] = field(default_factory=list)  # OUs sorted by depth

    # Reference tracking
    reference_map: Dict[str, Set[str]] = field(default_factory=lambda: defaultdict(set))
    # Key: parent DN, Value: set of referenced DNs

    def __post_init__(self):
        """Initialize default counts"""
        if not self.counts_by_type:
            self.counts_by_type = {
                settings.OBJECT_TYPE_OU: 0,
                settings.OBJECT_TYPE_USER: 0,
                settings.OBJECT_TYPE_GROUP: 0,
                settings.OBJECT_TYPE_CONTACT: 0,
                'unsupported': 0,
                'ignored': 0
            }


class Analyzer:
    """
    Analyzes source LDAP directory and classifies objects for migration
    """

    def __init__(self, connector: LDAPConnector, logger=None,
                 custom_exclusions: Optional[List[str]] = None):
        """
        Initialize analyzer

        Args:
            connector: Connected LDAPConnector instance
            logger: Optional MigrationLogger. Used to report when an ignore rule is
                disabled because the requested base DN opted into it; analysis works
                without one.
            custom_exclusions: Exact DNs the operator listed in the settings dialog.
                Service groups installed by Windows roles look identical to real
                groups, so no heuristic can filter them; the operator names them.
        """
        self.connector = connector
        self.logger = logger
        self.custom_exclusions = list(custom_exclusions or [])
        self.result = None
        self.ignore_rules = None

    def analyze(self, base_dn: str, include_references: bool = True) -> AnalysisResult:
        """
        Analyze source domain starting from base_dn

        Args:
            base_dn: Base DN to start analysis from
            include_references: Whether to analyze reference attributes

        Returns:
            AnalysisResult with classified objects

        Raises:
            LDAPOperationError: If analysis fails
        """
        self.result = AnalysisResult(base_dn=base_dn)

        # Verify the base DN exists before attempting a subtree search, so the
        # operator receives a clear message rather than a cryptic search failure.
        try:
            base_obj = self.connector.get_object_by_dn(base_dn, attributes=['objectClass'])
            if not base_obj:
                raise LDAPOperationError(
                    f"Base DN does not exist in the source domain: {base_dn}")
        except LDAPOperationError as e:
            # The connector already wrapped the raw exception; re-raise it with context
            raise LDAPOperationError(
                f"Cannot access base DN {base_dn}: {e}")

        # Ignore rules are scoped to this base DN: a built-in container the operator
        # asked for explicitly must not be filtered out as if it were incidental.
        self.ignore_rules = IgnoreRules(base_dn=base_dn,
                                        custom_exclusions=self.custom_exclusions)
        note = self.ignore_rules.describe_overrides()
        if note and self.logger:
            self.logger.warning(note)

        if self.custom_exclusions and self.logger:
            self.logger.info(
                f"Operator exclusion list active: {len(self.custom_exclusions)} DN(s)")

        # Search all objects under base_dn
        try:
            entries = self.connector.search(
                base_dn=base_dn,
                search_filter='(objectClass=*)',
                scope=ldap3.SUBTREE,
                # '*' returns ordinary attributes only. objectGUID, objectSid,
                # isCriticalSystemObject and systemFlags have to be named
                # explicitly, and the last two are what the built-in object
                # detection relies on most.
                attributes=['*', 'objectGUID', 'objectSid',
                            'isCriticalSystemObject', 'systemFlags']
            )
        except LDAPOperationError as e:
            raise LDAPOperationError(f"Failed to search {base_dn}: {e}")

        # Classify each entry
        for entry in entries:
            self._classify_entry(entry)

        # Build OU hierarchy (sorted by depth)
        self._build_ou_hierarchy()

        # Analyze references if requested
        if include_references:
            self._analyze_references()

        # Calculate statistics
        self._calculate_statistics()

        return self.result

    def _classify_entry(self, entry: Dict[str, Any]):
        """
        Classify a single LDAP entry

        Args:
            entry: LDAP entry dict
        """
        dn = entry['dn']
        attributes = entry['attributes']

        # Get objectClass (can be multi-valued)
        object_classes = attributes.get('objectClass', [])
        if not isinstance(object_classes, list):
            object_classes = [object_classes]

        # Normalize to lowercase
        object_classes = [oc.lower() if isinstance(oc, str) else str(oc).lower() for oc in object_classes]

        # Check if should be ignored. Attributes are passed so built-in principals
        # (krbtgt, Administrator, Domain Admins, ...) can be recognised by their
        # objectSid RID regardless of the domain's display language.
        if self._should_ignore(dn, object_classes, attributes):
            self.result.ignored.append(entry)

            if self.ignore_rules and self.logger:
                # An operator exclusion is reported at INFO: it is a deliberate
                # instruction, and seeing it confirmed is the point of listing it.
                # Built-in detection stays at DEBUG because it is routine.
                excluded = self.ignore_rules.exclusion_reason(dn)
                if excluded:
                    self.logger.info(f"{dn} - SKIPPED ({excluded})")
                else:
                    reason = self.ignore_rules.builtin_reason(attributes)
                    if reason:
                        self.logger.debug(f"{dn} - SKIPPED ({reason})")
            return

        # Classify by objectClass
        if 'organizationalunit' in object_classes:
            self.result.organizational_units.append(entry)

        elif 'user' in object_classes and 'computer' not in object_classes:
            # User but not computer
            self.result.users.append(entry)

        elif 'group' in object_classes:
            self.result.groups.append(entry)

        elif 'contact' in object_classes:
            self.result.contacts.append(entry)

        else:
            # Anything with an ignored objectClass was already filtered out above,
            # so whatever reaches here is a type this tool does not handle yet
            # (for example printQueue or a custom class).
            self.result.unsupported.append(entry)

    def _should_ignore(self, dn: str, object_classes: List[str],
                       attributes: Optional[Dict[str, Any]] = None) -> bool:
        """
        Check whether an object is out of scope.

        Delegates to IgnoreRules, which is scoped to the base DN of this analysis so
        that a built-in container requested explicitly is not filtered out.

        Args:
            dn: Distinguished Name
            object_classes: List of objectClass values
            attributes: Full attribute dict, used to detect built-in principals

        Returns:
            True if should be ignored
        """
        rules = self.ignore_rules or IgnoreRules(base_dn=None)
        return rules.should_ignore(dn, object_classes, attributes)

    def _build_ou_hierarchy(self):
        """
        Build OU hierarchy sorted by depth (parents before children)
        """
        if not self.result.organizational_units:
            return

        # Sort OUs by depth (number of commas in DN)
        ou_list = [(ou['dn'], DNUtils.get_depth(ou['dn'])) for ou in self.result.organizational_units]
        ou_list.sort(key=lambda x: x[1])  # Sort by depth

        # Extract sorted DNs
        self.result.ou_hierarchy = [dn for dn, depth in ou_list]

    def _analyze_references(self):
        """
        Analyze reference attributes (member, manager, managedBy) across all objects
        Builds reference_map showing which objects reference other objects
        """
        reference_attrs = [settings.ATTR_MEMBER, settings.ATTR_MANAGER, settings.ATTR_MANAGED_BY]

        # Check all object types
        all_objects = (
            self.result.organizational_units +
            self.result.users +
            self.result.groups +
            self.result.contacts
        )

        for obj in all_objects:
            parent_dn = obj['dn']
            attributes = obj['attributes']

            for attr in reference_attrs:
                if attr in attributes:
                    refs = attributes[attr]

                    # Ensure it's a list
                    if not isinstance(refs, list):
                        refs = [refs]

                    # Add to reference map
                    for ref_dn in refs:
                        if ref_dn:  # Skip empty values
                            self.result.reference_map[parent_dn].add(str(ref_dn))

    def _calculate_statistics(self):
        """Calculate statistics from classified objects"""
        self.result.counts_by_type[settings.OBJECT_TYPE_OU] = len(self.result.organizational_units)
        self.result.counts_by_type[settings.OBJECT_TYPE_USER] = len(self.result.users)
        self.result.counts_by_type[settings.OBJECT_TYPE_GROUP] = len(self.result.groups)
        self.result.counts_by_type[settings.OBJECT_TYPE_CONTACT] = len(self.result.contacts)
        self.result.counts_by_type['unsupported'] = len(self.result.unsupported)
        self.result.counts_by_type['ignored'] = len(self.result.ignored)

        self.result.total_objects = sum(self.result.counts_by_type.values())

    def get_objects_by_type(self, object_type: str) -> List[Dict[str, Any]]:
        """
        Get objects of a specific type

        Args:
            object_type: Object type (ou, user, group, contact)

        Returns:
            List of objects
        """
        if not self.result:
            return []

        type_map = {
            settings.OBJECT_TYPE_OU: self.result.organizational_units,
            settings.OBJECT_TYPE_USER: self.result.users,
            settings.OBJECT_TYPE_GROUP: self.result.groups,
            settings.OBJECT_TYPE_CONTACT: self.result.contacts,
        }

        return type_map.get(object_type, [])

    def get_summary(self) -> Dict[str, Any]:
        """
        Get analysis summary

        Returns:
            Summary dict with counts and statistics
        """
        if not self.result:
            return {}

        summary = {
            'base_dn': self.result.base_dn,
            'total_objects': self.result.total_objects,
            'counts': self.result.counts_by_type.copy(),
            'ou_hierarchy_depth': len(self.result.ou_hierarchy),
            'references_found': len(self.result.reference_map),
        }

        return summary

    def find_objects_outside_scope(self) -> Dict[str, Set[str]]:
        """
        Find references to objects outside the base_dn scope
        These will need to be DEFERRED

        Returns:
            Dict mapping parent DN to set of out-of-scope referenced DNs
        """
        if not self.result:
            return {}

        base_dn = self.result.base_dn
        out_of_scope = defaultdict(set)

        # Get all DNs within scope
        in_scope_dns = set()
        for obj_list in [self.result.organizational_units, self.result.users,
                         self.result.groups, self.result.contacts]:
            for obj in obj_list:
                in_scope_dns.add(obj['dn'])

        # Check references
        for parent_dn, ref_dns in self.result.reference_map.items():
            for ref_dn in ref_dns:
                # Check if reference is within base_dn scope
                if not DNUtils.is_child_of(ref_dn, base_dn) and ref_dn not in in_scope_dns:
                    # Out of scope
                    out_of_scope[parent_dn].add(ref_dn)

        return dict(out_of_scope)

    def get_migration_preview(self) -> Dict[str, Any]:
        """
        Generate migration preview showing what will be created, exists, etc.

        Returns:
            Preview dict with categorized objects
        """
        if not self.result:
            return {}

        # Find out-of-scope references
        out_of_scope = self.find_objects_outside_scope()

        preview = {
            'will_create': {
                settings.OBJECT_TYPE_OU: len(self.result.organizational_units),
                settings.OBJECT_TYPE_USER: len(self.result.users),
                settings.OBJECT_TYPE_GROUP: len(self.result.groups),
                settings.OBJECT_TYPE_CONTACT: len(self.result.contacts),
            },
            'deferred_references': len(out_of_scope),
            'deferred_reference_details': out_of_scope,
            'ignored_objects': len(self.result.ignored),
            'unsupported_objects': len(self.result.unsupported),
        }

        return preview


if __name__ == "__main__":
    # Self-test
    print("=== Analyzer Test ===\n")
    print("Note: This test requires LDAPConnector with actual LDAP server\n")

    # Example test with mock data
    from core.ldap_connector import LDAPConnector

    # This would require actual LDAP connection
    test_config = {
        'host': '192.168.1.1',
        'port': 389,
        'domain': 'test.local',
        'username': 'administrator',
        'password': 'Password123',
        'use_tls': False
    }

    try:
        with LDAPConnector(**test_config) as connector:
            analyzer = Analyzer(connector)

            # Analyze a specific OU
            base_dn = "OU=Users,DC=test,DC=local"
            print(f"Analyzing {base_dn}...")

            result = analyzer.analyze(base_dn)

            # Print summary
            summary = analyzer.get_summary()
            print(f"\nAnalysis Summary:")
            print(f"  Total objects: {summary['total_objects']}")
            print(f"  OUs: {summary['counts']['ou']}")
            print(f"  Users: {summary['counts']['user']}")
            print(f"  Groups: {summary['counts']['group']}")
            print(f"  Contacts: {summary['counts']['contact']}")
            print(f"  Ignored: {summary['counts']['ignored']}")
            print(f"  Unsupported: {summary['counts']['unsupported']}")

            # Preview
            preview = analyzer.get_migration_preview()
            print(f"\nMigration Preview:")
            print(f"  Will create: {preview['will_create']}")
            print(f"  Deferred references: {preview['deferred_references']}")

    except Exception as e:
        print(f"Test requires actual LDAP server: {e}")
