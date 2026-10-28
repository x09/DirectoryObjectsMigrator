"""
Migrator
Main migration engine - orchestrates the entire migration process
"""
from utils.i18n import _
from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime
import time
import ldap3

from core.ldap_connector import LDAPConnector, LDAPConnectionError, LDAPOperationError
from core.analyzer import Analyzer, AnalysisResult
from core.identity import domain_identity, validate_destination, MappingValidationError, guid_text
from core.attribute_mapper import AttributeMapper
from core.reference_resolver import ReferenceResolver
from core.verifier import Verifier, VerificationResult
from core.object_handlers.ou_handler import OUHandler
from core.object_handlers.user_handler import UserHandler
from core.object_handlers.group_handler import GroupHandler
from core.object_handlers.contact_handler import ContactHandler
from database.migration_db import MigrationDB
from utils.logger import MigrationLogger
from utils.dn_utils import DNUtils
from config import settings


class MigrationPlan:
    """
    What a migration would do, computed before anything is written.

    Built by consulting both the migration database and the destination directory,
    so the preview reflects reality on a re-run instead of listing every source
    object as "will be created".

    Each of create/exists/conflict holds (source_dn, dest_dn, object_type) tuples.
    skipped holds objects excluded by ignore rules (built-in or operator-defined).
    """

    def __init__(self, base_dn: str, dest_base_dn: str):
        self.base_dn = base_dn
        self.dest_base_dn = dest_base_dn
        self.create: List[tuple] = []
        self.exists: List[tuple] = []
        self.conflict: List[tuple] = []
        self.errors: List[tuple] = []
        self.skipped: List[tuple] = []  # objects excluded by ignore rules
        # (parent_dn, attribute, referenced_dn, resolvable_now)
        self.deferred: List[tuple] = []
        self.ignored_count: int = 0
        self.unsupported_count: int = 0
        self.issues = {}  # source DN -> explanation shown in preview
        self.reference_issues = {}  # (parent DN, attribute, referenced DN) -> reason
        self.unassigned_history = False

    def counts_by_type(self, bucket: List[tuple]) -> Dict[str, int]:
        """Group one bucket by object type, for display."""
        counts: Dict[str, int] = {}
        for _, _, object_type in bucket:
            counts[object_type] = counts.get(object_type, 0) + 1
        return counts

    @property
    def resolvable_deferred(self) -> int:
        """Deferred references whose target already exists in the destination."""
        return sum(1 for *_, resolvable in self.deferred if resolvable)

    def summary(self) -> Dict[str, Any]:
        return {
            'create': len(self.create),
            'exists': len(self.exists),
            'conflict': len(self.conflict),
            'errors': len(self.errors),
            'skipped': len(self.skipped),
            'deferred': len(self.deferred),
            'deferred_resolvable_now': self.resolvable_deferred,
            'ignored': self.ignored_count,
            'unsupported': self.unsupported_count,
            'create_by_type': self.counts_by_type(self.create),
            'exists_by_type': self.counts_by_type(self.exists),
            'conflict_by_type': self.counts_by_type(self.conflict),
            'skipped_by_type': self.counts_by_type(self.skipped),
        }


@dataclass
class MigrationResult:
    """Result of migration operation"""
    success: bool = False
    status: str = settings.RUN_STATUS_IN_PROGRESS
    warnings: List[str] = field(default_factory=list)
    failure_message: str = ""
    run_id: Optional[int] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    duration_seconds: int = 0

    # Statistics
    objects_analyzed: int = 0
    objects_created: int = 0
    objects_updated: int = 0
    objects_skipped: int = 0
    objects_conflicted: int = 0
    errors_count: int = 0

    # By phase
    phase_results: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    # Analysis and verification
    analysis_result: Optional[AnalysisResult] = None
    verification_result: Optional[VerificationResult] = None


class Migrator:
    """
    Main migration engine
    Orchestrates the entire migration process across 5 phases
    """

    def __init__(
        self,
        source_conn: LDAPConnector,
        dest_conn: LDAPConnector,
        migration_db: MigrationDB,
        logger: MigrationLogger,
        attribute_mapper: Optional[AttributeMapper] = None,
        password_mode: str = settings.DEFAULT_PASSWORD_MODE,
        fixed_password: str = '',
        batch_size: int = settings.DEFAULT_BATCH_SIZE,
        dry_run: bool = False,
        progress_callback: Optional[Callable[[int, str], None]] = None,
        custom_exclusions: Optional[List[str]] = None,
        password_length: int = settings.DEFAULT_PASSWORD_LENGTH
    ):
        """
        Initialize migrator

        Args:
            source_conn: Source LDAP connection
            dest_conn: Destination LDAP connection
            migration_db: Migration database
            logger: Logger instance
            attribute_mapper: AttributeMapper (will create if None)
            password_mode: 'random' or 'fixed'
            fixed_password: Fixed password if mode is 'fixed'
            batch_size: Number of objects to process per batch
            dry_run: If True, simulate without creating objects
            progress_callback: Optional callback(progress_percent, status_message)
            custom_exclusions: Exact DNs the operator listed in the settings dialog.
                Passed to both the Analyzer and the Verifier so the two agree on
                what is in scope; a mismatch would make the verifier report the
                excluded objects as missing from the destination.
        """
        self.source_conn = source_conn
        self.dest_conn = dest_conn
        self.migration_db = migration_db.for_direction(
            domain_identity(source_conn), domain_identity(dest_conn),
            source_conn.domain, dest_conn.domain)
        self.logger = logger
        self.batch_size = batch_size
        self.dry_run = dry_run
        self.progress_callback = progress_callback
        self.custom_exclusions = list(custom_exclusions or [])

        # Initialize components
        self.attribute_mapper = attribute_mapper or AttributeMapper()
        self.analyzer = Analyzer(source_conn, logger=logger,
                                 custom_exclusions=self.custom_exclusions)
        self.reference_resolver = ReferenceResolver(
            source_conn, dest_conn, self.migration_db, logger,
            source_conn.domain_dn, dest_conn.domain_dn,
            dry_run=dry_run
        )
        self.verifier = Verifier(source_conn, dest_conn, self.migration_db, logger,
                                 dry_run=dry_run,
                                 custom_exclusions=self.custom_exclusions)

        # Initialize handlers
        self.handlers = {
            settings.OBJECT_TYPE_OU: OUHandler(
                source_conn, dest_conn, self.attribute_mapper, logger,
                source_conn.domain, dest_conn.domain
            ),
            settings.OBJECT_TYPE_USER: UserHandler(
                source_conn, dest_conn, self.attribute_mapper, logger,
                source_conn.domain, dest_conn.domain,
                password_mode=password_mode,
                fixed_password=fixed_password, password_length=password_length
            ),
            settings.OBJECT_TYPE_GROUP: GroupHandler(
                source_conn, dest_conn, self.attribute_mapper, logger,
                source_conn.domain, dest_conn.domain
            ),
            settings.OBJECT_TYPE_CONTACT: ContactHandler(
                source_conn, dest_conn, self.attribute_mapper, logger,
                source_conn.domain, dest_conn.domain
            ),
        }

        self.verifier.handlers = self.handlers
        self.verifier.reference_resolver = self.reference_resolver
        self.current_run_id = None
        self.cancelled = False
        self._simulated_ous = set()
        self._simulated_names = {}

    def _creation_check(self, entry, object_type, dest_dn, planned_ous=None,
                        reserved_names=None):
        """Shared preview/execution checks. Never adopt an untracked identity."""
        from ldap3.utils.conv import escape_filter_chars
        planned_ous = planned_ous or set()
        reserved_names = reserved_names if reserved_names is not None else {}
        if self.dest_conn.get_object_by_dn(dest_dn, attributes=['objectGUID']):
            return 'conflicts', _('Destination DN already exists and is not tracked')
        source_parent = DNUtils.get_parent_dn(entry['dn'])
        parent_dn = DNUtils.get_parent_dn(dest_dn)
        parent_key = DNUtils.normalize_dn(parent_dn)
        if parent_key not in planned_ous:
            mapped_parent = self.migration_db.get_object_by_source_dn(source_parent)
            if mapped_parent:
                actual = validate_destination(self.dest_conn, mapped_parent)
                if DNUtils.normalize_dn(actual) != parent_key:
                    return 'errors', _('Tracked parent has moved; expected destination path is unavailable')
            parent = self.dest_conn.get_object_by_dn(parent_dn, attributes=['objectClass'])
            if not parent:
                return 'errors', _('Destination parent does not exist: ') + parent_dn
            classes = parent['attributes'].get('objectClass', [])
            if isinstance(classes, str):
                classes = [classes]
            if not {'organizationalunit', 'container', 'domain', 'domaindns'} & {c.lower() for c in classes}:
                return 'errors', _('Destination parent is not an OU, container or domain: ') + parent_dn
        attrs = self.handlers[object_type].prepare_attributes(entry)
        names = []
        for attr in ('sAMAccountName', 'userPrincipalName'):
            value = attrs.get(attr)
            if not value:
                continue
            key = (attr, str(value).casefold())
            if key in reserved_names:
                return 'conflicts', _('Duplicate destination identity: ') + attr + '=' + str(value)
            matches = self.dest_conn.search(base_dn=self.dest_conn.domain_dn,
                search_filter='(' + attr + '=' + escape_filter_chars(str(value)) + ')',
                attributes=[attr], scope=ldap3.SUBTREE)
            if matches:
                return 'conflicts', _('Destination identity already exists: ') + attr + '=' + str(value)
            names.append(key)
        for key in names:
            reserved_names[key] = dest_dn
        return 'created', ''

    def build_plan(self, analysis: AnalysisResult) -> MigrationPlan:
        """
        Classify every analysed object the way _process_object would, without
        writing anything.

        This is what the preview screen shows. It must mirror the live decision
        logic exactly, otherwise the preview and the migration disagree:
          - already in migration_map            -> exists
          - present in destination, not tracked -> conflict (never overwritten)
          - no objectGUID                       -> error (cannot be tracked)
          - otherwise                           -> create

        Args:
            analysis: Result of Analyzer.analyze()

        Returns:
            MigrationPlan describing the intended outcome
        """
        dest_base_dn = DNUtils.convert_dn(
            analysis.base_dn,
            self.source_conn.domain_dn,
            self.dest_conn.domain_dn
        )
        plan = MigrationPlan(analysis.base_dn, dest_base_dn)
        plan.unassigned_history = self.migration_db.has_unassigned_history()
        plan.ignored_count = len(analysis.ignored)
        plan.unsupported_count = len(analysis.unsupported)

        # Populate skipped list from ignored objects so they appear in the preview
        for entry in analysis.ignored:
            source_dn = entry['dn']
            dest_dn = DNUtils.convert_dn(
                source_dn, self.source_conn.domain_dn, self.dest_conn.domain_dn
            )
            # Determine object type from objectClass
            object_classes = entry['attributes'].get('objectClass', [])
            if not isinstance(object_classes, list):
                object_classes = [object_classes]
            object_classes = [str(oc).lower() for oc in object_classes]

            if 'organizationalunit' in object_classes:
                object_type = settings.OBJECT_TYPE_OU
            elif 'user' in object_classes and 'computer' not in object_classes:
                object_type = settings.OBJECT_TYPE_USER
            elif 'group' in object_classes:
                object_type = settings.OBJECT_TYPE_GROUP
            elif 'contact' in object_classes:
                object_type = settings.OBJECT_TYPE_CONTACT
            else:
                object_type = 'other'

            plan.skipped.append((source_dn, dest_dn, object_type))

        typed_objects = (
            [(o, settings.OBJECT_TYPE_OU) for o in analysis.organizational_units] +
            [(o, settings.OBJECT_TYPE_USER) for o in analysis.users] +
            [(o, settings.OBJECT_TYPE_GROUP) for o in analysis.groups] +
            [(o, settings.OBJECT_TYPE_CONTACT) for o in analysis.contacts]
        )

        typed_objects.sort(key=lambda item: (item[1] != settings.OBJECT_TYPE_OU,
                                               DNUtils.get_depth(item[0]['dn']) if item[1] == settings.OBJECT_TYPE_OU else 0))
        planned_ous = set()
        reserved_names = {}
        for entry, object_type in typed_objects:
            source_dn = entry['dn']
            source_guid = entry['attributes'].get('objectGUID')
            dest_dn = DNUtils.convert_dn(
                source_dn, self.source_conn.domain_dn, self.dest_conn.domain_dn
            )

            if not source_guid:
                plan.errors.append((source_dn, dest_dn, object_type))
                continue

            mapped = self.migration_db.get_object_by_source_guid(str(source_guid))
            if mapped:
                try:
                    actual_dn = validate_destination(self.dest_conn, mapped)
                    plan.exists.append((source_dn, actual_dn, object_type))
                except Exception as exc:
                    plan.errors.append((source_dn, dest_dn, object_type))
                    plan.issues[source_dn] = str(exc)
                continue

            try:
                status, reason = self._creation_check(entry, object_type, dest_dn,
                                                      planned_ous, reserved_names)
            except Exception as exc:
                status, reason = 'errors', str(exc)
            bucket = {'created': plan.create, 'conflicts': plan.conflict, 'errors': plan.errors}[status]
            bucket.append((source_dn, dest_dn, object_type))
            if reason:
                plan.issues[source_dn] = reason
            if status == 'created' and object_type == settings.OBJECT_TYPE_OU:
                planned_ous.add(DNUtils.normalize_dn(dest_dn))

        self._plan_references(analysis, plan)
        return plan

    def _plan_references(self, analysis: AnalysisResult, plan: MigrationPlan):
        """
        Work out which references would be deferred, and which of those could be
        resolved right away because the target is already in the destination.
        """
        planned_targets = {DNUtils.normalize_dn(src) for src, _, _ in plan.create + plan.exists}

        reference_attrs = (settings.ATTR_MEMBER, settings.ATTR_MANAGER,
                           settings.ATTR_MANAGED_BY)

        for bucket in (analysis.groups, analysis.users,
                       analysis.organizational_units, analysis.contacts):
            for obj in bucket:
                attributes = obj['attributes']
                for attr in reference_attrs:
                    if attr not in attributes:
                        continue

                    values = attributes[attr]
                    if not isinstance(values, list):
                        values = [values] if values else []

                    for ref_dn in values:
                        if not ref_dn:
                            continue
                        if DNUtils.normalize_dn(str(ref_dn)) in planned_targets:
                            continue
                        try:
                            resolvable = bool(self.reference_resolver.resolve_reference(str(ref_dn), update_mapping=False))
                            reason = _('No verified mapping. Matching account names are not used automatically.')
                        except Exception as exc:
                            resolvable = False
                            reason = str(exc)
                        plan.deferred.append((obj['dn'], attr, str(ref_dn), resolvable))
                        if not resolvable:
                            plan.reference_issues[(obj['dn'], attr, str(ref_dn))] = reason

    def migrate(self, base_dn: str) -> MigrationResult:
        """
        Execute complete migration process

        Args:
            base_dn: Base DN to migrate from source

        Returns:
            MigrationResult with statistics and status
        """
        result = MigrationResult()
        result.start_time = datetime.now()

        try:
            # Create migration run
            self.current_run_id = self._create_migration_run(base_dn)
            result.run_id = self.current_run_id

            self.logger.info(f"=== Migration Run {self.current_run_id} Started ===")
            self.logger.info(f"Source Base DN: {base_dn}")
            self.logger.info(f"Dry Run Mode: {self.dry_run}")

            self._simulated_ous.clear()
            self._simulated_names.clear()

            # Phase 0: Analysis
            self._update_progress(0, "Analyzing source domain...")
            result.analysis_result = self._phase_analysis(base_dn)
            result.objects_analyzed = result.analysis_result.total_objects

            if result.objects_analyzed == 0:
                self.logger.warning("No objects found to migrate")
                self._finish_result(result)
                return result

            phases = [
                (20, 'Creating organizational units...', 'phase1_ous', self._phase1_create_ous),
                (40, 'Creating objects...', 'phase2_objects', self._phase2_create_objects),
                (60, 'Copying attributes...', 'phase3_attributes', self._phase3_copy_attributes),
                (80, 'Resolving references...', 'phase4_references', self._phase4_resolve_references),
            ]
            for percent, message, key, phase in phases:
                if self.cancelled:
                    break
                self._update_progress(percent, message)
                result.phase_results[key] = phase(result.analysis_result)
            if not self.cancelled:
                self._update_progress(95, 'Verifying results...')
                result.verification_result = self._phase5_verify(base_dn)
            self._finish_result(result)
        except Exception as exc:
            self.logger.critical(f'Migration failed with error: {exc}')
            result.failure_message = str(exc)
            self._finish_result(result, fatal=True)

        return result

    def _finish_result(self, result: MigrationResult, fatal: bool = False):
        """Use the same outcome for the worker, database, GUI and reports."""
        self._calculate_statistics(result)
        verification = result.verification_result
        if verification:
            result.warnings.extend(verification.warnings)
            if not verification.success or verification.errors:
                result.errors_count += max(1, len(verification.errors))
        if result.run_id:
            if verification:
                for message in verification.errors:
                    self.migration_db.log_error(
                        result.run_id, settings.SEVERITY_ERROR,
                        settings.PHASE_VERIFICATION, message)
                for message in verification.warnings:
                    self.migration_db.log_error(result.run_id, settings.SEVERITY_WARNING,
                                                settings.PHASE_VERIFICATION, message)
                self.migration_db.log_error(result.run_id, settings.SEVERITY_INFO,
                    settings.PHASE_VERIFICATION,
                    f"Verification checked {verification.checked_objects} objects, "
                    f"{verification.checked_attributes} attributes, "
                    f"{verification.checked_references} reference attributes"
                    + (' (skipped: Dry Run)' if self.dry_run else ''))
            if fatal:
                self.migration_db.log_error(
                    result.run_id, settings.SEVERITY_CRITICAL,
                    'migration', result.failure_message)
            logged_errors = self.migration_db.get_errors(result.run_id)
            # Object errors already appear in phase counters; reference errors
            # are logged independently and must not disappear from the result.
            result.errors_count += sum(
                e['severity'] in (settings.SEVERITY_ERROR, settings.SEVERITY_CRITICAL)
                and e['phase'] in (settings.PHASE_REFERENCES, settings.PHASE_PASSWORD) for e in logged_errors)
            result.warnings.extend(e['error_message'] for e in logged_errors
                                   if e['phase'] == settings.PHASE_PASSWORD and e['severity'] == settings.SEVERITY_WARNING)
            if self.migration_db.get_unresolved_references():
                result.warnings.append('Unresolved references remain')
        if self.migration_db.has_unassigned_history():
            result.warnings.append(_('Some legacy history could not be assigned to a domain pair and is not used'))
        if result.objects_conflicted:
            result.warnings.append(f'{result.objects_conflicted} object conflicts')
        if fatal:
            result.errors_count += 1
            result.status = settings.RUN_STATUS_FAILED
        elif self.cancelled:
            result.status = settings.RUN_STATUS_CANCELLED
        elif result.errors_count:
            result.status = settings.RUN_STATUS_COMPLETED_WITH_ERRORS
        elif result.warnings:
            result.status = settings.RUN_STATUS_COMPLETED_WITH_WARNINGS
        else:
            result.status = settings.RUN_STATUS_COMPLETED
        result.success = result.status in (
            settings.RUN_STATUS_COMPLETED, settings.RUN_STATUS_COMPLETED_WITH_WARNINGS)
        result.end_time = datetime.now()
        result.duration_seconds = int((result.end_time - result.start_time).total_seconds())
        if result.run_id:
            self._complete_migration_run(result)
        if result.status in (settings.RUN_STATUS_COMPLETED, settings.RUN_STATUS_COMPLETED_WITH_ERRORS,
                              settings.RUN_STATUS_COMPLETED_WITH_WARNINGS):
            self._update_progress(100, result.status)
        self.logger.info(f'Migration finished: {result.status}; errors={result.errors_count}')

    def cancel(self):
        """Cancel migration"""
        self.logger.warning("Migration cancellation requested")
        self.cancelled = True

    def _create_migration_run(self, base_dn: str) -> int:
        """Create migration run entry in database"""
        dest_base_dn = DNUtils.convert_dn(
            base_dn,
            self.source_conn.domain_dn,
            self.dest_conn.domain_dn
        )

        config = {
            'source_host': self.source_conn.host,
            'source_port': self.source_conn.port,
            'source_domain': self.source_conn.domain,
            'dest_host': self.dest_conn.host,
            'dest_port': self.dest_conn.port,
            'dest_domain': self.dest_conn.domain,
            'use_tls': self.source_conn.use_tls,
            'password_mode': 'random',  # Don't store actual mode
            'options': {
                'batch_size': self.batch_size,
                'dry_run': self.dry_run,
            }
        }

        return self.migration_db.create_migration_run(
            source_base_dn=base_dn,
            dest_base_dn=dest_base_dn,
            source_dc=f"{self.source_conn.host}:{self.source_conn.port}",
            dest_dc=f"{self.dest_conn.host}:{self.dest_conn.port}",
            config=config
        )

    def _complete_migration_run(self, result: MigrationResult):
        """Update migration run with final statistics"""
        stats = {
            'objects_analyzed': result.objects_analyzed,
            'objects_created': result.objects_created,
            'objects_updated': result.objects_updated,
            'objects_skipped': result.objects_skipped,
            'objects_conflicted': result.objects_conflicted,
            'errors_count': result.errors_count,
        }

        status = result.status

        self.migration_db.update_migration_run(
            self.current_run_id,
            status=status,
            stats=stats,
            duration_seconds=result.duration_seconds,
            notes='\n'.join(filter(None, [result.failure_message] + result.warnings +
                         (result.verification_result.errors if result.verification_result else [])))
        )

    def _phase_analysis(self, base_dn: str) -> AnalysisResult:
        """Phase 0: Analyze source domain"""
        self.logger.set_phase(settings.PHASE_ANALYSIS)
        self.logger.info(f"Analyzing {base_dn}...")

        analysis = self.analyzer.analyze(base_dn, include_references=True)

        self.logger.info(f"Analysis complete:")
        self.logger.info(f"  Total objects: {analysis.total_objects}")
        for obj_type, count in analysis.counts_by_type.items():
            if count > 0:
                self.logger.info(f"  {obj_type}: {count}")

        return analysis

    def _phase1_create_ous(self, analysis: AnalysisResult) -> Dict[str, Any]:
        """Phase 1: Create organizational units"""
        self.logger.set_phase(settings.PHASE_OU_CREATION)

        stats = {'created': 0, 'exists': 0, 'conflicts': 0, 'errors': 0}

        if not analysis.ou_hierarchy:
            self.logger.info("No OUs to create")
            return stats

        self.logger.info(f"Creating {len(analysis.ou_hierarchy)} OUs...")

        handler = self.handlers[settings.OBJECT_TYPE_OU]

        for source_dn in analysis.ou_hierarchy:
            if self.cancelled:
                break

            # Find the source entry
            source_entry = next(
                (ou for ou in analysis.organizational_units if ou['dn'] == source_dn),
                None
            )

            if not source_entry:
                continue

            # Process object
            status = self._process_object(source_entry, handler, settings.OBJECT_TYPE_OU)
            stats[status] = stats.get(status, 0) + 1

        self.logger.info(f"OU creation complete: {stats}")
        return stats

    def _phase2_create_objects(self, analysis: AnalysisResult) -> Dict[str, Any]:
        """Phase 2: Create users, groups, contacts"""
        self.logger.set_phase(settings.PHASE_OBJECT_CREATION)

        stats = {}
        object_lists = [
            (settings.OBJECT_TYPE_USER, analysis.users),
            (settings.OBJECT_TYPE_GROUP, analysis.groups),
            (settings.OBJECT_TYPE_CONTACT, analysis.contacts),
        ]

        for obj_type, objects in object_lists:
            if self.cancelled:
                break

            if not objects:
                continue

            self.logger.info(f"Creating {len(objects)} {obj_type} objects...")
            type_stats = {'created': 0, 'exists': 0, 'conflicts': 0, 'errors': 0}

            handler = self.handlers[obj_type]

            # Process in batches
            for i in range(0, len(objects), self.batch_size):
                if self.cancelled:
                    break

                batch = objects[i:i+self.batch_size]

                for source_entry in batch:
                    status = self._process_object(source_entry, handler, obj_type)
                    type_stats[status] = type_stats.get(status, 0) + 1

            self.logger.info(f"{obj_type} creation complete: {type_stats}")
            stats[obj_type] = type_stats

        return stats

    def _phase3_copy_attributes(self, analysis: AnalysisResult) -> Dict[str, Any]:
        """
        Phase 3: intentionally a no-op.

        Phase 2 writes the complete attribute set in the initial LDAP add, which is
        preferable to adding a bare object and patching it: fewer round trips, and
        no window in which the object exists half-populated. Only primaryGroupID and
        unicodePwd need separate writes, and the user handler does those itself.

        The phase is kept as an explicit step so the pipeline still reads as the
        six stages described in the design, and so a future need for a genuine
        second attribute pass (for example attributes Samba rejects at create time)
        has an obvious home. tests/test_attributes.py pins down that phase 2 really
        is complete, so this staying empty is safe.
        """
        self.logger.set_phase(settings.PHASE_ATTRIBUTES)
        self.logger.info("Attributes were written during object creation; nothing to do")
        return {}

    def _phase4_resolve_references(self, analysis: AnalysisResult) -> Dict[str, Any]:
        """Phase 4: Resolve reference attributes"""
        self.logger.set_phase(settings.PHASE_REFERENCES)

        stats = {'resolved': 0, 'deferred': 0}

        # Process deferred references from previous runs
        resolved, still_deferred = self.reference_resolver.process_deferred_references(
            self.current_run_id
        )

        stats['resolved'] += resolved
        stats['deferred'] = still_deferred

        self.logger.info(f"Reference resolution: {stats}")
        return stats

    def _phase5_verify(self, base_dn: str) -> VerificationResult:
        """Phase 5: Verify migration results"""
        self.logger.set_phase(settings.PHASE_VERIFICATION)

        verification = self.verifier.verify(base_dn, self.current_run_id)

        return verification

    def _process_object(self, source_entry: Dict[str, Any], handler, object_type: str) -> str:
        """
        Process a single object (idempotent)

        Args:
            source_entry: Source LDAP entry
            handler: Object handler
            object_type: Object type

        Returns:
            Status string (created, exists, conflicts, errors)
        """
        source_dn = source_entry['dn']
        source_guid = source_entry['attributes'].get('objectGUID')

        # objectGUID is the identity key for the whole migration map. Without it we
        # cannot make later runs idempotent, so skip rather than write a broken row.
        if not source_guid:
            self.logger.error(f"{source_dn} - SKIPPED (no objectGUID returned)")
            self.migration_db.log_error(
                self.current_run_id,
                settings.SEVERITY_ERROR,
                settings.PHASE_OBJECT_CREATION,
                "Source object has no objectGUID; cannot track migration",
                object_dn=source_dn,
                object_type=object_type
            )
            return 'errors'

        source_guid = str(source_guid)

        # Check if already migrated
        map_entry = self.migration_db.get_object_by_source_guid(source_guid)

        if map_entry:
            try:
                actual_dn = validate_destination(self.dest_conn, map_entry)
            except Exception as exc:
                self.logger.error(f'Invalid tracked object {source_dn}: {exc}')
                self.migration_db.log_error(self.current_run_id, settings.SEVERITY_ERROR,
                    settings.PHASE_OBJECT_CREATION, str(exc), object_dn=source_dn,
                    object_type=object_type)
                return 'errors'
            pending_password = map_entry.get('error_message') == 'PASSWORD_SETUP_PENDING'
            if not self.dry_run:
                if pending_password and object_type == settings.OBJECT_TYPE_USER:
                    handler.configure_password(source_entry, actual_dn)
                    self._record_password_events(handler, source_dn)
                    pending_password = handler.password_failed
                self.migration_db.refresh_mapping(source_guid, source_dn, actual_dn)
                self.migration_db.add_object(
                    source_guid=source_guid, source_dn=source_dn,
                    dest_guid=map_entry['dest_guid'], dest_dn=actual_dn,
                    object_type=object_type, status=settings.STATUS_EXISTS,
                    error_message='PASSWORD_SETUP_PENDING' if pending_password else None,
                    run_id=self.current_run_id)
            return 'exists'

        # Convert DN to destination
        dest_dn = DNUtils.convert_dn(
            source_dn,
            self.source_conn.domain_dn,
            self.dest_conn.domain_dn
        )

        try:
            status, reason = self._creation_check(source_entry, object_type, dest_dn,
                self._simulated_ous if self.dry_run else None,
                self._simulated_names if self.dry_run else None)
        except Exception as exc:
            status, reason = 'errors', str(exc)
        if status == 'conflicts':
            self.logger.conflict(f"{source_dn} - CONFLICT ({reason})")
            self.migration_db.add_conflict(source_dn, dest_dn,
                settings.CONFLICT_TYPE_EXISTS_NOT_TRACKED, self.current_run_id,
                object_type=object_type, notes=reason)
            return status
        if status == 'errors':
            self.logger.error(f"Cannot create {dest_dn}: {reason}")
            self.migration_db.log_error(self.current_run_id, settings.SEVERITY_ERROR,
                settings.PHASE_OBJECT_CREATION, reason, object_dn=source_dn,
                object_type=object_type)
            return status
        if self.dry_run:
            if object_type == settings.OBJECT_TYPE_OU:
                self._simulated_ous.add(DNUtils.normalize_dn(dest_dn))
            self.logger.info(f"[DRY RUN] Would create: {dest_dn}")
            return 'created'

        try:
            success = handler.create(source_entry, dest_dn)
            self._record_password_events(handler, source_dn)

            if success:
                # Get destination GUID
                dest_obj = self.dest_conn.get_object_by_dn(dest_dn, attributes=['objectGUID'])
                dest_guid = dest_obj['attributes'].get('objectGUID') if dest_obj else None
                dest_guid = str(dest_guid) if dest_guid else None

                # Record in migration_map
                self.migration_db.add_object(
                    source_guid=source_guid,
                    source_dn=source_dn,
                    dest_guid=dest_guid,
                    dest_dn=dest_dn,
                    object_type=object_type,
                    status=settings.STATUS_CREATED,
                    error_message='PASSWORD_SETUP_PENDING' if getattr(handler, 'password_failed', False) else None,
                    run_id=self.current_run_id
                )

                # Handle references
                if handler.get_reference_attributes():
                    self._handle_references(source_entry, source_guid, dest_dn, object_type, handler)

                return 'created'
            else:
                return 'errors'

        except Exception as e:
            self.logger.error(f"Failed to create {dest_dn}: {e}")
            self.migration_db.log_error(
                self.current_run_id,
                settings.SEVERITY_ERROR,
                settings.PHASE_OBJECT_CREATION,
                str(e),
                object_dn=source_dn,
                object_type=object_type
            )
            return 'errors'

    def _record_password_events(self, handler, source_dn):
        for severity, message in getattr(handler, 'password_events', []):
            self.migration_db.log_error(self.current_run_id, severity, settings.PHASE_PASSWORD,
                                        message, object_dn=source_dn, object_type='user')

    def _handle_references(self, source_entry, source_guid, dest_dn, object_type, handler):
        """Handle reference attributes for an object"""
        references = handler.extract_reference_values(source_entry)

        if references:
            stats = self.reference_resolver.resolve_references(
                parent_dn=dest_dn,
                parent_guid=source_guid,
                parent_type=object_type,
                references=references,
                run_id=self.current_run_id
            )

            if stats['deferred'] > 0:
                self.logger.debug(f"Deferred {stats['deferred']} references for {dest_dn}")

    def _calculate_statistics(self, result: MigrationResult):
        """
        Aggregate per-phase counters into the top-level result totals.

        Phase results come in two shapes: flat counters (phase 1 returns
        {'created': n, ...}) and per-type counters (phase 2 returns
        {'user': {'created': n, ...}, 'group': {...}}). Both are folded in by
        recursing one level, which is why an earlier flat-only version reported
        zero users and groups.
        """
        totals = {'created': 0, 'exists': 0, 'conflicts': 0, 'errors': 0}

        def accumulate(stats: Dict[str, Any]):
            for key, value in stats.items():
                if isinstance(value, dict):
                    accumulate(value)
                elif key in totals and isinstance(value, int):
                    totals[key] += value

        for phase_stats in result.phase_results.values():
            if isinstance(phase_stats, dict):
                accumulate(phase_stats)

        result.objects_created = totals['created']
        result.objects_skipped = totals['exists']
        result.objects_conflicted = totals['conflicts']
        result.errors_count = totals['errors']

    def _update_progress(self, percent: int, message: str):
        """Update progress"""
        if self.progress_callback:
            try:
                self.progress_callback(percent, message)
            except:
                pass


if __name__ == "__main__":
    print("=== Migrator - Main Migration Engine ===")
    print("Orchestrates 5-phase migration process:")
    print("  Phase 0: Analysis")
    print("  Phase 1: Create OUs")
    print("  Phase 2: Create Objects")
    print("  Phase 3: Copy Attributes")
    print("  Phase 4: Resolve References")
    print("  Phase 5: Verification")
