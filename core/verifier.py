"""
Verifier
Verifies migration results and generates verification report
"""
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from core.ldap_connector import LDAPConnector, LDAPOperationError
from core.ignore_rules import IgnoreRules
from database.migration_db import MigrationDB
from utils.logger import MigrationLogger
from utils.dn_utils import DNUtils
from config import settings
import ldap3


@dataclass
class VerificationResult:
    """Result of migration verification"""
    success: bool = True
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    # Object counts
    source_counts: Dict[str, int] = field(default_factory=dict)
    dest_counts: Dict[str, int] = field(default_factory=dict)
    migration_counts: Dict[str, int] = field(default_factory=dict)

    # Deferred references
    total_deferred: int = 0
    resolved_deferred: int = 0

    # Issues
    missing_objects: List[str] = field(default_factory=list)
    extra_objects: List[str] = field(default_factory=list)

    def add_error(self, message: str):
        """Add an error"""
        self.errors.append(message)
        self.success = False

    def add_warning(self, message: str):
        """Add a warning"""
        self.warnings.append(message)


class Verifier:
    """
    Verifies migration results
    Checks object counts, deferred references, and migration completeness
    """

    def __init__(
        self,
        source_conn: LDAPConnector,
        dest_conn: LDAPConnector,
        migration_db: MigrationDB,
        logger: MigrationLogger,
        dry_run: bool = False,
        custom_exclusions: Optional[List[str]] = None
    ):
        """
        Initialize verifier

        Args:
            source_conn: Source LDAP connection
            dest_conn: Destination LDAP connection
            migration_db: Migration database
            logger: Logger instance
            dry_run: When True, skip source/destination count comparison because
                nothing was written and every object would appear to be missing
            custom_exclusions: The operator's exclusion list. Must match what the
                Analyzer used, otherwise excluded objects are counted in the source
                but absent from the destination and reported as missing.
        """
        self.source_conn = source_conn
        self.dest_conn = dest_conn
        self.migration_db = migration_db
        self.logger = logger
        self.dry_run = dry_run
        self.custom_exclusions = list(custom_exclusions or [])
        self.ignore_rules = None

    def verify(self, base_dn: str, run_id: int) -> VerificationResult:
        """
        Perform verification of migration results

        Args:
            base_dn: Base DN that was migrated (in source)
            run_id: Migration run ID

        Returns:
            VerificationResult
        """
        result = VerificationResult()

        # Scope the ignore rules to the same base DN the analysis used, and with the
        # same operator exclusions, so the source count reflects what was actually
        # selected for migration rather than everything the subtree contains.
        self.ignore_rules = IgnoreRules(base_dn=base_dn,
                                        custom_exclusions=self.custom_exclusions)

        if self.dry_run:
            # Nothing was written, so comparing counts would report the entire
            # subtree as missing. That is expected, not a finding.
            self.logger.info("Verification skipped (dry run - nothing was written)")
            result.source_counts = self._count_objects(self.source_conn, base_dn, is_source=True)
            self.logger.info(f"Source counts: {result.source_counts}")
            return result

        self.logger.info("Starting verification...")

        # Count objects in source
        result.source_counts = self._count_objects(self.source_conn, base_dn, is_source=True)
        self.logger.info(f"Source counts: {result.source_counts}")

        # Count objects in destination. DNUtils handles the case-insensitive
        # suffix swap; a plain str.replace misses differently-cased domain DNs.
        dest_base_dn = DNUtils.convert_dn(
            base_dn,
            self.source_conn.domain_dn,
            self.dest_conn.domain_dn
        )
        result.dest_counts = self._count_objects(self.dest_conn, dest_base_dn, is_source=False)
        self.logger.info(f"Destination counts: {result.dest_counts}")

        # Get migration statistics from database
        stats = self.migration_db.get_statistics(run_id)
        if stats and 'objects_by_type_status' in stats:
            for entry in stats['objects_by_type_status']:
                obj_type = entry['object_type']
                status = entry['status']
                count = entry['count']

                key = f"{obj_type}_{status}"
                result.migration_counts[key] = count

        # Check deferred references
        deferred_stats = stats.get('deferred_references', {}) if stats else {}
        result.total_deferred = deferred_stats.get('total', 0)
        result.resolved_deferred = deferred_stats.get('resolved', 0)

        if result.total_deferred > 0:
            unresolved = result.total_deferred - result.resolved_deferred
            if unresolved > 0:
                result.add_warning(f"{unresolved} deferred references remain unresolved")

        # Compare counts
        self._compare_counts(result)

        # Check for errors in migration_errors table
        errors = self.migration_db.get_errors(run_id, severity=settings.SEVERITY_ERROR)
        if errors:
            result.add_warning(f"{len(errors)} errors occurred during migration")

        # Summary
        if result.success:
            self.logger.success("Verification PASSED")
        else:
            self.logger.error("Verification FAILED")

        if result.warnings:
            self.logger.warning(f"Verification completed with {len(result.warnings)} warnings")

        return result

    def _count_objects(
        self,
        conn: LDAPConnector,
        base_dn: str,
        is_source: bool = True
    ) -> Dict[str, int]:
        """
        Count objects by type in LDAP directory

        Args:
            conn: LDAP connection
            base_dn: Base DN to count from
            is_source: Whether this is source (apply ignored filters) or destination

        Returns:
            Dict with counts by object type
        """
        counts = {
            settings.OBJECT_TYPE_OU: 0,
            settings.OBJECT_TYPE_USER: 0,
            settings.OBJECT_TYPE_GROUP: 0,
            settings.OBJECT_TYPE_CONTACT: 0,
        }

        try:
            # Search all objects
            entries = conn.search(
                base_dn=base_dn,
                search_filter='(objectClass=*)',
                scope=ldap3.SUBTREE,
                # objectSid and the naming attributes are needed so the built-in
                # principal filter can run here too. Counting with fewer rules than
                # the Analyzer applied would report those objects as "missing in
                # destination" even though they were deliberately never migrated.
                # isCriticalSystemObject and systemFlags must be named explicitly:
                # they are the filter's most reliable signals and are not covered
                # by a wildcard request.
                attributes=['objectClass', 'objectSid', 'sAMAccountName', 'cn',
                            'isCriticalSystemObject', 'systemFlags']
            )
        except LDAPOperationError as e:
            # An absent base is a legitimate result here (e.g. the destination
            # subtree was never created), so report zeros instead of an error.
            if LDAPConnector._is_no_such_object(e):
                self.logger.debug(f"Base DN not present, counting as empty: {base_dn}")
                return counts
            self.logger.error(f"Failed to count objects in {base_dn}: {e}")
            return counts

        for entry in entries:
            object_classes = entry['attributes'].get('objectClass', [])
            if not isinstance(object_classes, list):
                object_classes = [object_classes]

            object_classes = [str(oc).lower() for oc in object_classes]

            # Classify using the same rules as the Analyzer, so source and
            # destination counts are directly comparable
            if is_source and self._should_ignore(
                    entry['dn'], object_classes, entry['attributes']):
                continue

            if 'organizationalunit' in object_classes:
                counts[settings.OBJECT_TYPE_OU] += 1
            elif 'user' in object_classes and 'computer' not in object_classes:
                counts[settings.OBJECT_TYPE_USER] += 1
            elif 'group' in object_classes:
                counts[settings.OBJECT_TYPE_GROUP] += 1
            elif 'contact' in object_classes:
                counts[settings.OBJECT_TYPE_CONTACT] += 1

        return counts

    def _should_ignore(self, dn: str, object_classes: List[str],
                       attributes: Optional[Dict[str, Any]] = None) -> bool:
        """
        Check whether an object is out of scope.

        Shares IgnoreRules with the Analyzer, scoped to the same base DN, so the
        source count here matches what the analysis actually selected. Keeping a
        second copy of this logic previously risked the two drifting apart and
        producing spurious "objects missing in destination" warnings.

        Args:
            dn: Distinguished Name
            object_classes: objectClass values
            attributes: Full attribute dict, needed to detect built-in principals
        """
        rules = self.ignore_rules or IgnoreRules(base_dn=None)
        return rules.should_ignore(dn, object_classes, attributes)

    def _compare_counts(self, result: VerificationResult):
        """
        Compare source and destination counts

        Args:
            result: VerificationResult to update
        """
        for obj_type in [settings.OBJECT_TYPE_OU, settings.OBJECT_TYPE_USER,
                         settings.OBJECT_TYPE_GROUP, settings.OBJECT_TYPE_CONTACT]:
            source_count = result.source_counts.get(obj_type, 0)
            dest_count = result.dest_counts.get(obj_type, 0)

            if dest_count < source_count:
                diff = source_count - dest_count
                result.add_warning(
                    f"{obj_type}: {diff} objects in source not found in destination "
                    f"(source: {source_count}, dest: {dest_count})"
                )
            elif dest_count > source_count:
                diff = dest_count - source_count
                result.add_warning(
                    f"{obj_type}: {diff} extra objects in destination "
                    f"(source: {source_count}, dest: {dest_count})"
                )

    def verify_object(
        self,
        source_dn: str,
        dest_dn: str,
        check_attributes: Optional[List[str]] = None
    ) -> bool:
        """
        Verify a single object exists and has expected attributes

        Args:
            source_dn: Source DN
            dest_dn: Destination DN
            check_attributes: Optional list of attributes to verify

        Returns:
            True if verification passes
        """
        try:
            # Check if destination object exists
            dest_obj = self.dest_conn.get_object_by_dn(dest_dn)
            if not dest_obj:
                self.logger.error(f"Object not found in destination: {dest_dn}")
                return False

            # Optionally check specific attributes
            if check_attributes:
                dest_attrs = dest_obj.get('attributes', {})
                missing = [attr for attr in check_attributes if attr not in dest_attrs]

                if missing:
                    self.logger.warning(
                        f"Missing attributes on {dest_dn}: {', '.join(missing)}"
                    )
                    return False

            return True

        except Exception as e:
            self.logger.error(f"Verification failed for {dest_dn}: {e}")
            return False


if __name__ == "__main__":
    print("=== Verifier Test ===\n")
    print("Verifies migration results:")
    print("- Compares object counts between source and destination")
    print("- Checks deferred references status")
    print("- Reports errors and warnings")
