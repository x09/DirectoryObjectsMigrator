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
from datetime import datetime, timezone
from core.analyzer import Analyzer
from core.identity import guid_text, validate_destination



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

    checked_objects: int = 0
    checked_attributes: int = 0
    checked_references: int = 0
    findings: List[Dict[str, Any]] = field(default_factory=list)

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
    Checks GUID identities, prepared attribute values and reference membership
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
        self.handlers = None
        self.reference_resolver = None

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
        try:
            analysis = Analyzer(self.source_conn, custom_exclusions=self.custom_exclusions).analyze(base_dn)
            result.source_counts = {kind: analysis.counts_by_type[kind]
                                    for kind in ('ou', 'user', 'group', 'contact')}
        except Exception as exc:
            result.add_error(f'Cannot verify source: {exc}')
            return result
        self.logger.info(f"Source counts: {result.source_counts}")

        # Count objects in destination. DNUtils handles the case-insensitive
        # suffix swap; a plain str.replace misses differently-cased domain DNs.
        dest_base_dn = DNUtils.convert_dn(
            base_dn,
            self.source_conn.domain_dn,
            self.dest_conn.domain_dn
        )
        try:
            result.dest_counts = self._count_objects(self.dest_conn, dest_base_dn, is_source=False)
        except Exception as exc:
            result.add_error(f'Cannot verify destination: {exc}')
            return result
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

        # Counts are informational: unrelated entries cannot compensate for a
        # missing identity, and a tracked object may have moved outside this subtree.
        self._include_reference_parents(analysis, run_id, result)
        self._verify_objects(analysis, result)

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

    def _include_reference_parents(self, analysis, run_id, result):
        buckets = {'ou': analysis.organizational_units, 'user': analysis.users,
                   'group': analysis.groups, 'contact': analysis.contacts}
        seen = set()
        for entries in buckets.values():
            for entry in entries:
                try:
                    seen.add(guid_text(entry['attributes'].get('objectGUID')))
                except Exception:
                    # The individual-object check reports this without aborting
                    # verification of every other object.
                    pass
        for parent_guid in self.migration_db.get_reference_parents_for_run(run_id):
            try:
                guid = guid_text(parent_guid)
                if guid in seen:
                    continue
                mapped = self.migration_db.get_object_by_source_guid(guid)
                source = self.source_conn.get_object_by_guid(guid, base_dn=self.source_conn.domain_dn)
                if not mapped or not source or guid_text(source['attributes'].get('objectGUID')) != guid:
                    raise ValueError('Reference parent identity could not be verified')
                buckets[mapped['object_type']].append(source)
                seen.add(guid)
            except Exception as exc:
                self._finding(result, 'Reference parent verification failed', str(parent_guid), detail=str(exc))

    def _components(self):
        if self.handlers is not None and self.reference_resolver is not None:
            return
        from core.attribute_mapper import AttributeMapper
        from core.object_handlers.ou_handler import OUHandler
        from core.object_handlers.user_handler import UserHandler
        from core.object_handlers.group_handler import GroupHandler
        from core.object_handlers.contact_handler import ContactHandler
        from core.reference_resolver import ReferenceResolver
        mapper = AttributeMapper()
        self.handlers = {kind: cls(self.source_conn, self.dest_conn, mapper, self.logger,
                                  self.source_conn.domain, self.dest_conn.domain)
                         for kind, cls in [('ou', OUHandler), ('user', UserHandler),
                                           ('group', GroupHandler), ('contact', ContactHandler)]}
        self.reference_resolver = ReferenceResolver(self.source_conn, self.dest_conn,
            self.migration_db, self.logger, self.source_conn.domain_dn, self.dest_conn.domain_dn,
            dry_run=True, custom_exclusions=self.custom_exclusions)

    @staticmethod
    def _values(value):
        if value is None or value == '':
            return []
        return list(value) if isinstance(value, (list, tuple, set)) else [value]

    @classmethod
    def _normalized(cls, value, attribute, reference=False):
        values = set()
        for item in cls._values(value):
            if reference:
                item = DNUtils.normalize_dn(str(item))
            elif attribute.lower() == 'accountexpires':
                item = int(item)
                if item in (0, 9223372036854775807):
                    item = 'never-expires'
            elif attribute.lower() in ('grouptype', 'primarygroupid', 'useraccountcontrol'):
                item = int(item)
                if attribute.lower() == 'grouptype':
                    item &= 0xffffffff
                elif attribute.lower() == 'useraccountcontrol':
                    # Account-disable and normal-account bits are set by this app.
                    # Other server-maintained flags need not equal the create value.
                    item &= 0x202
            elif isinstance(item, datetime):
                item = item.astimezone(timezone.utc).isoformat() if item.tzinfo else item.isoformat()
            elif isinstance(item, (bytearray, memoryview)):
                item = bytes(item)
            values.add(item)
        return values

    @staticmethod
    def _finding(result, kind, source_dn, dest_dn='', attribute='',
                 expected=None, actual=None, detail='', warning=False):
        record = dict(kind=kind, source_dn=source_dn, dest_dn=dest_dn,
                      attribute=attribute, expected=expected, actual=actual, detail=detail,
                      severity='warning' if warning else 'error')
        result.findings.append(record)
        message = f"{kind}: {source_dn} -> {dest_dn}"
        if attribute:
            message += f" [{attribute}] expected={expected!r}; actual={actual!r}"
        if detail:
            message += f"; {detail}"
        (result.add_warning if warning else result.add_error)(message)

    def _verify_objects(self, analysis, result):
        self._components()
        pending = self.migration_db.get_unresolved_references()
        for kind, entries in [('ou', analysis.organizational_units), ('user', analysis.users),
                              ('group', analysis.groups), ('contact', analysis.contacts)]:
            for source in entries:
                source_dn = source['dn']
                dest_dn = ''
                try:
                    source_guid = guid_text(source['attributes'].get('objectGUID'))
                    mapped = self.migration_db.get_object_by_source_guid(source_guid)
                    if not mapped:
                        result.missing_objects.append(source_dn)
                        self._finding(result, 'Unverified object', source_dn,
                                      detail='No tracked GUID mapping for this domain pair')
                        continue
                    if mapped['object_type'] != kind:
                        raise ValueError('Source object class differs from the tracked type')
                    dest_dn = validate_destination(self.dest_conn, mapped)
                    handler = self.handlers[kind]
                    expected = handler.prepare_attributes(source)
                    if kind == 'user':
                        expected['primaryGroupID'] = settings.PRIMARY_GROUP_ID
                    # Never inspect or report credentials, even with custom mappings.
                    excluded = {'unicodepwd', 'userpassword', 'supplementalcredentials',
                                'ntpwdhistory', 'lmpwdhistory'}
                    expected = {k: v for k, v in expected.items() if k.lower() not in excluded}
                    refs = handler.get_reference_attributes()
                    target = self.dest_conn.get_object_by_dn(dest_dn,
                        attributes=list(set(expected) | set(refs) | {'objectGUID', 'objectClass'}))
                    if not target or guid_text(target['attributes'].get('objectGUID')) != guid_text(mapped['dest_guid']):
                        raise ValueError('Destination disappeared or changed during verification')
                    actual = {key.lower(): value for key, value in target['attributes'].items()}
                    result.checked_objects += 1
                    for attr, value in expected.items():
                        result.checked_attributes += 1
                        if self._normalized(value, attr) != self._normalized(actual.get(attr.lower()), attr):
                            self._finding(result, 'Attribute mismatch', source_dn, dest_dn,
                                          attr, value, actual.get(attr.lower()))
                    self._verify_references(source, source_guid, dest_dn, actual, refs, pending, result)
                except Exception as exc:
                    self._finding(result, 'Object verification failed', source_dn, dest_dn, detail=str(exc))

    def _verify_references(self, source, source_guid, dest_dn, actual, refs, pending, result):
        source_attrs = {key.lower(): value for key, value in source['attributes'].items()}
        for attr in refs:
            name = attr.lower()
            # A ranged response is not a complete membership list. Fail explicitly
            # unless ldap3 has already expanded it to the ordinary attribute.
            if any(key.startswith(name + ';range=') for key in set(source_attrs) | set(actual)):
                self._finding(result, 'Incomplete reference read', source['dn'], dest_dn,
                              detail=f'{attr}: ranged values were not fully expanded')
                continue
            expected_dns = set()
            for ref_dn in self._values(source_attrs.get(name)):
                ref_dn = str(ref_dn)
                skip_reason = self.reference_resolver.is_builtin_target(ref_dn)
                if skip_reason:
                    self._finding(result, 'Skipped reference', source['dn'], dest_dn,
                                  detail=f'{attr}: {ref_dn}; {skip_reason}', warning=True)
                    continue
                try:
                    mapped_dn = self.reference_resolver.resolve_reference(ref_dn, update_mapping=False)
                except Exception as exc:
                    self._finding(result, 'Reference identity failed', source['dn'], dest_dn,
                                  detail=f'{attr}: {ref_dn}: {exc}')
                    continue
                if mapped_dn:
                    expected_dns.add(DNUtils.normalize_dn(mapped_dn))
                else:
                    deferred = any(guid_text(row['parent_object_guid']) == source_guid
                                   and row['attribute_name'].lower() == name
                                   and DNUtils.normalize_dn(row['referenced_source_dn']) == DNUtils.normalize_dn(ref_dn)
                                   for row in pending)
                    self._finding(result, 'Deferred reference' if deferred else 'Untracked reference',
                                  source['dn'], dest_dn, detail=f'{attr}: {ref_dn}', warning=deferred)
            actual_dns = self._normalized(actual.get(name), attr, reference=True)
            result.checked_references += 1
            missing = expected_dns - actual_dns
            extra = actual_dns - expected_dns
            if missing:
                self._finding(result, 'Missing reference values', source['dn'], dest_dn,
                              attr, sorted(missing), sorted(actual_dns))
            if extra:
                self._finding(result, 'Unexpected reference values', source['dn'], dest_dn,
                              attr, sorted(expected_dns), sorted(extra))

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
            raise

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

    def verify_object(
        self,
        source_dn: str,
        dest_dn: str,
        check_attributes: Optional[List[str]] = None
    ) -> bool:
        """
        Verify one tracked object using the full migration contract

        Args:
            source_dn: Source DN
            dest_dn: Destination DN
            check_attributes: Optional attributes that must belong to the migration contract

        Returns:
            True if verification passes
        """
        from core.analyzer import AnalysisResult
        try:
            source = self.source_conn.get_object_by_dn(source_dn)
            if not source:
                return False
            guid = guid_text(source['attributes'].get('objectGUID'))
            mapped = self.migration_db.get_object_by_source_guid(guid)
            if not mapped or DNUtils.normalize_dn(validate_destination(self.dest_conn, mapped)) != DNUtils.normalize_dn(dest_dn):
                return False
            analysis = AnalysisResult(base_dn=source_dn)
            buckets = {'ou': analysis.organizational_units, 'user': analysis.users,
                       'group': analysis.groups, 'contact': analysis.contacts}
            buckets[mapped['object_type']].append(source)
            result = VerificationResult()
            self._verify_objects(analysis, result)
            if check_attributes:
                self._components()
                expected = self.handlers[mapped['object_type']].prepare_attributes(source)
                # This convenience API only accepts attributes in the migration contract.
                if not set(check_attributes) <= set(expected):
                    return False
            return result.success
        except Exception as exc:
            self.logger.error(f"Verification failed for {dest_dn}: {exc}")
            return False


if __name__ == "__main__":
    print("=== Verifier Test ===\n")
    print("Verifies migration results:")
    print("- Verifies GUID identities, transformed attributes and direct reference values")
    print("- Checks deferred references status")
    print("- Reports errors and warnings")
