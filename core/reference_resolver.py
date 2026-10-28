"""
Reference Resolver
Handles resolution of reference attributes (member, manager, managedBy)
Manages deferred references when targets are outside migration scope
"""
from utils.i18n import _
from typing import Dict, Any, List, Optional, Set, Tuple
import ldap3
from core.ldap_connector import LDAPConnector
from core.ignore_rules import IgnoreRules
from core.identity import validate_destination, guid_text, MappingValidationError
from database.migration_db import MigrationDB
from utils.logger import MigrationLogger
from utils.dn_utils import DNUtils
from config import settings


class ReferenceResolver:
    """
    Resolves reference attributes and manages deferred references
    """

    def __init__(
        self,
        source_conn: LDAPConnector,
        dest_conn: LDAPConnector,
        migration_db: MigrationDB,
        logger: MigrationLogger,
        source_domain_dn: str,
        dest_domain_dn: str,
        dry_run: bool = False
    ):
        """
        Initialize reference resolver

        Args:
            source_conn: Source LDAP connection
            dest_conn: Destination LDAP connection
            migration_db: Migration database
            logger: Logger instance
            source_domain_dn: Source domain DN (e.g., 'DC=source,DC=alt')
            dest_domain_dn: Destination domain DN (e.g., 'DC=dest,DC=alt')
            dry_run: When True, report what would change but never write to the
                destination directory and never mark references as resolved
        """
        self.source_conn = source_conn
        self.dest_conn = dest_conn
        self.migration_db = migration_db
        self.logger = logger
        self.source_domain_dn = source_domain_dn
        self.dest_domain_dn = dest_domain_dn
        self.dry_run = dry_run
        # source DN -> reason string, or '' meaning "checked, not built-in".
        # Group members repeat heavily across groups, so caching avoids re-reading
        # the same source object once per membership.
        self._builtin_cache: Dict[str, str] = {}

    def is_builtin_target(self, source_dn: str) -> Optional[str]:
        """
        Check whether a referenced object is a built-in principal.

        Such objects are deliberately never migrated (krbtgt, Administrator,
        Domain Admins and so on), so a reference to one must be dropped rather than
        deferred: deferring it would leave a row that can never be resolved,
        cluttering every subsequent report with permanently pending work.

        The source object is read to obtain its objectSid, because the RID is what
        identifies a built-in principal independently of the domain's language.

        Args:
            source_dn: DN of the referenced object in the source domain

        Returns:
            A short reason for the log, or None if the target is a normal object
        """
        cached = self._builtin_cache.get(source_dn)
        if cached is not None:
            return cached or None

        reason = None
        try:
            entry = self.source_conn.get_object_by_dn(
                source_dn,
                # isCriticalSystemObject and systemFlags are the most reliable
                # built-in signals and must be requested by name; a wildcard
                # request would not return them.
                attributes=['objectSid', 'sAMAccountName', 'cn', 'objectClass',
                            'isCriticalSystemObject', 'systemFlags'])
            if entry:
                reason = IgnoreRules.builtin_reason(entry['attributes'])
        except Exception as e:
            # Unreadable target: fall through and let the normal deferral logic
            # handle it rather than guessing
            self.logger.debug(f"Could not inspect reference target {source_dn}: {e}")

        # '' marks "checked, not built-in" so the negative result is cached too
        self._builtin_cache[source_dn] = reason or ''
        return reason

    def existing_values(self, parent_dn: str, attr_name: str) -> Set[str]:
        """
        Values already set for an attribute on the destination object.

        Used to distinguish a member that this run added (ADDED) from one that was
        already in the group (PRESENT), and to avoid re-writing values that are
        already there.

        Returns an empty set if the object cannot be read; the caller then treats
        every value as new, which is harmless because adding an existing member is
        a no-op in LDAP.
        """
        try:
            entry = self.dest_conn.get_object_by_dn(parent_dn, attributes=[attr_name])
        except Exception as e:
            self.logger.debug(f"Could not read {attr_name} on {parent_dn}: {e}")
            return set()

        if not entry:
            return set()

        values = entry['attributes'].get(attr_name, [])
        if not isinstance(values, list):
            values = [values] if values else []

        return {DNUtils.normalize_dn(str(v)) for v in values if v}

    def resolve_reference(self, source_dn: str, source_guid=None, update_mapping=True) -> Optional[str]:
        """Use verified GUID mappings only. A matching login is never identity."""
        if source_guid:
            source = self.source_conn.get_object_by_guid(source_guid, base_dn=self.source_domain_dn)
            if source is None or guid_text(source['attributes'].get('objectGUID')) != guid_text(source_guid):
                raise MappingValidationError(_('Referenced source object no longer exists'))
        else:
            source = self.source_conn.get_object_by_dn(source_dn, attributes=['objectGUID'])
            if source is None:
                previous = self.migration_db.get_object_by_source_dn(source_dn)
                if previous:
                    return self.resolve_reference(source_dn, previous['source_guid'], update_mapping=update_mapping)
                return None
        if source is None:
            return None
        guid = guid_text(source['attributes'].get('objectGUID'))
        mapped = self.migration_db.get_object_by_source_guid(guid)
        if mapped is None:
            return None
        dest_dn = validate_destination(self.dest_conn, mapped)
        if not self.dry_run and update_mapping:
            self.migration_db.refresh_mapping(guid, source['dn'], dest_dn)
        return dest_dn

    def _defer(self, parent_guid, parent_dn, parent_type, attr_name, source_dn, run_id):
        # Capture identity now so later renames/replacements cannot redirect it.
        source = self.source_conn.get_object_by_dn(source_dn, attributes=['objectGUID'])
        guid = guid_text(source['attributes'].get('objectGUID')) if source else None
        self.migration_db.add_deferred_reference(
            parent_guid=parent_guid, parent_dn=parent_dn, parent_type=parent_type,
            attribute_name=attr_name, referenced_dn=source_dn, run_id=run_id,
            referenced_guid=guid)

    def resolve_references(
        self,
        parent_dn: str,
        parent_guid: str,
        parent_type: str,
        references: Dict[str, List[str]],
        run_id: int
    ) -> Dict[str, Any]:
        """
        Resolve all references for an object

        Args:
            parent_dn: Parent object DN (in destination)
            parent_guid: Parent object GUID (from source)
            parent_type: Parent object type
            references: Dict mapping attribute name to list of source DNs
            run_id: Current migration run ID

        Returns:
            Dict with resolution statistics
        """
        stats = {
            'resolved': 0,   # newly added to the destination object
            'present': 0,    # already set, nothing to do
            'deferred': 0,   # target not migrated yet, will retry on a later run
            'skipped': 0,    # target is a built-in principal, never migrated
            'failed': 0,     # the LDAP write was rejected
            'by_attribute': {}
        }

        for attr_name, ref_dns in references.items():
            resolved_dns = []
            resolved_sources = []
            deferred_dns = []
            # (member name, status) pairs for the per-member log block
            member_status = []

            # What the destination object already holds, so a member that was
            # already in the group is reported PRESENT rather than ADDED
            already_set = self.existing_values(parent_dn, attr_name)

            for ref_dn in ref_dns:
                # Try to resolve
                try:
                    dest_ref_dn = self.resolve_reference(ref_dn)
                except Exception as exc:
                    dest_ref_dn = None
                    self.logger.warning(f'Reference identity not verified for {ref_dn}: {exc}')
                name = DNUtils.extract_cn(ref_dn) or ref_dn

                if dest_ref_dn:
                    if DNUtils.normalize_dn(dest_ref_dn) in already_set:
                        stats['present'] = stats.get('present', 0) + 1
                        member_status.append((name, 'PRESENT'))
                        continue

                    # Resolved
                    resolved_dns.append(dest_ref_dn)
                    resolved_sources.append(ref_dn)
                    stats['resolved'] += 1
                    member_status.append((name, 'ADDED'))
                else:
                    # A reference to a built-in principal can never resolve, because
                    # such objects are deliberately never migrated. Deferring it
                    # would leave a permanently pending row in every later report.
                    builtin = self.is_builtin_target(ref_dn)
                    if builtin:
                        stats['skipped'] = stats.get('skipped', 0) + 1
                        member_status.append((name, 'SKIPPED'))
                        self.logger.debug(
                            f"Reference {attr_name} -> {ref_dn} dropped: {builtin}")
                        continue

                    # Not found - defer it
                    deferred_dns.append(ref_dn)
                    stats['deferred'] += 1
                    member_status.append((name, 'DEFERRED'))

                    # Add to deferred_references table
                    if not self.dry_run:
                        self._defer(parent_guid, parent_dn, parent_type, attr_name, ref_dn, run_id)


            # Set resolved references on destination object
            if resolved_dns:
                if self.dry_run:
                    self.logger.info(
                        f"[DRY RUN] Would set {len(resolved_dns)} {attr_name} "
                        f"references on {parent_dn}"
                    )
                else:
                    try:
                        if not self.dest_conn.modify_add_values(parent_dn, {attr_name: resolved_dns}):
                            raise RuntimeError('LDAP reference update returned False')
                    except Exception as e:
                        self.logger.warning(f"Failed to set {attr_name} on {parent_dn}: {e}")
                        stats['failed'] += len(resolved_dns)
                        stats['resolved'] -= len(resolved_dns)
                        self.migration_db.log_error(
                            run_id, settings.SEVERITY_ERROR, settings.PHASE_REFERENCES,
                            f'Failed to set {attr_name}: {e}', object_dn=parent_dn,
                            object_type=parent_type)
                        # Created parents are skipped on reruns. Preserve failed
                        # writes as pending work so the next run can retry them.
                        for source_dn in resolved_sources:
                            self._defer(parent_guid, parent_dn, parent_type, attr_name, source_dn, run_id)
                        deferred_dns.extend(resolved_sources)
                        stats['deferred'] += len(resolved_sources)
                        resolved_dns = []
                        # The write failed, so nothing was actually added
                        member_status = [(n, 'FAILED' if s == 'ADDED' else s)
                                         for n, s in member_status]

            # Track per-attribute stats
            stats['by_attribute'][attr_name] = {
                'resolved': len(resolved_dns),
                'deferred': len(deferred_dns)
            }

            self.log_member_block(parent_dn, attr_name, member_status)

        return stats

    def log_member_block(self, parent_dn: str, attr_name: str,
                         member_status: List[Tuple[str, str]]):
        """
        Log one indented block per object showing the fate of each reference.

        The specification asks for a report in which the outcome of every group
        member is visible, not just an aggregate count:

            group1
              object: CREATED
              members:
                user1: ADDED
                user5: DEFERRED

        Aggregate counters alone cannot answer "what happened to user5?", which is
        the question a migration operator actually has.
        """
        if not member_status:
            return

        self.logger.info(f"  {attr_name}:")
        for name, status in member_status:
            if status in ('ADDED', 'PRESENT'):
                self.logger.success(f"    {name}: {status}")
            elif status == 'DEFERRED':
                self.logger.warning(f"    {name}: {status}")
            elif status == 'SKIPPED':
                # A built-in principal, intentionally not migrated. Informational,
                # not a problem, so it must not be logged as an error.
                self.logger.info(f"    {name}: {status} (built-in)")
            else:
                self.logger.error(f"    {name}: {status}")

    def process_deferred_references(self, run_id: int) -> Tuple[int, int]:
        """Acknowledge rows only after LDAP confirms the write (or a read finds it).

        If the server applies a write but its reply is lost, leave the rows pending.
        The next run's read detects the existing values and completes bookkeeping.
        Dry runs neither write to LDAP nor change reference tracking.
        """
        unresolved = self.migration_db.get_unresolved_references()
        by_attribute = {}
        for ref in unresolved:
            by_attribute.setdefault((ref['parent_object_guid'], ref['parent_object_dn'], ref['attribute_name']), []).append(ref)
        resolved_count = 0
        still_deferred_count = 0
        for (parent_guid, parent_dn, attr_name), refs in by_attribute.items():
            try:
                parent = self.migration_db.get_object_by_source_guid(refs[0]['parent_object_guid'])
                if parent is None:
                    raise MappingValidationError(_('No verified mapping for reference parent'))
                source_parent = self.source_conn.get_object_by_guid(guid_text(parent['source_guid']), base_dn=self.source_domain_dn)
                if source_parent is None or guid_text(source_parent['attributes'].get('objectGUID')) != guid_text(parent['source_guid']):
                    raise MappingValidationError(_('Reference parent no longer exists in the source domain'))
                parent_dn = validate_destination(self.dest_conn, parent)
                if not self.dry_run:
                    self.migration_db.refresh_mapping(parent['source_guid'], source_parent['dn'], parent_dn)
            except Exception as exc:
                self.logger.error(f'Cannot update reference parent {parent_dn}: {exc}')
                self.migration_db.log_error(run_id, settings.SEVERITY_ERROR,
                    settings.PHASE_REFERENCES, str(exc), object_dn=parent_dn)
                still_deferred_count += len(refs)
                continue
            already_set = self.existing_values(parent_dn, attr_name)
            pending = []
            member_status = []
            for ref in refs:
                source_dn = ref['referenced_source_dn']
                name = DNUtils.extract_cn(source_dn) or source_dn
                if not self.dry_run:
                    self.migration_db.update_reference_check(ref['id'])
                try:
                    dest_dn = self.resolve_reference(source_dn, ref.get('referenced_source_guid'))
                except Exception as exc:
                    self.logger.warning(f'Reference identity not verified for {source_dn}: {exc}')
                    dest_dn = None
                if dest_dn:
                    if DNUtils.normalize_dn(dest_dn) in already_set:
                        if not self.dry_run:
                            self.migration_db.mark_reference_resolved(ref['id'], dest_dn, run_id)
                        resolved_count += 1
                        member_status.append((name, 'PRESENT'))
                    else:
                        pending.append((ref, dest_dn, name))
                elif self.is_builtin_target(source_dn):
                    if not self.dry_run:
                        self.migration_db.mark_reference_resolved(ref['id'], '', run_id)
                    member_status.append((name, 'SKIPPED'))
                else:
                    still_deferred_count += 1
                    member_status.append((name, 'DEFERRED'))

            if pending:
                # Old databases can contain duplicate rows. Send each value once,
                # but acknowledge every corresponding row after success.
                values = list(dict.fromkeys(dest_dn for _, dest_dn, _ in pending))
                if self.dry_run:
                    self.logger.info(f'[DRY RUN] Would add {len(values)} {attr_name} to {parent_dn}')
                    resolved_count += len(pending)
                else:
                    try:
                        if not self.dest_conn.modify_add_values(parent_dn, {attr_name: values}):
                            raise RuntimeError('LDAP reference update returned False')
                    except Exception as exc:
                        self.logger.error(f'Failed to add {attr_name} to {parent_dn}: {exc}')
                        self.migration_db.log_error(
                            run_id, settings.SEVERITY_ERROR, settings.PHASE_REFERENCES,
                            f'Failed to add {attr_name}: {exc}', object_dn=parent_dn,
                            object_type=refs[0]['parent_object_type'])
                        still_deferred_count += len(pending)
                        member_status.extend((name, 'FAILED') for _, _, name in pending)
                    else:
                        # Database failures propagate: do not misreport them as
                        # LDAP rejection. Any rows left pending are safe to retry.
                        for ref, dest_dn, name in pending:
                            self.migration_db.mark_reference_resolved(ref['id'], dest_dn, run_id)
                            resolved_count += 1
                            member_status.append((name, 'ADDED'))
            self.log_member_block(parent_dn, attr_name, member_status)
        self.logger.info(f'Deferred references: {resolved_count} resolved, {still_deferred_count} pending')
        return resolved_count, still_deferred_count

    def get_deferred_summary(self) -> Dict[str, Any]:
        """
        Get summary of deferred references

        Returns:
            Dict with deferred reference statistics
        """
        unresolved = self.migration_db.get_unresolved_references()

        # Group by attribute type
        by_attr = {}
        by_parent_type = {}

        for ref in unresolved:
            attr = ref['attribute_name']
            parent_type = ref['parent_object_type']

            by_attr[attr] = by_attr.get(attr, 0) + 1
            by_parent_type[parent_type] = by_parent_type.get(parent_type, 0) + 1

        return {
            'total_deferred': len(unresolved),
            'by_attribute': by_attr,
            'by_parent_type': by_parent_type,
        }


if __name__ == "__main__":
    print("=== ReferenceResolver Test ===\n")
    print("Handles reference attributes: member, manager, managedBy")
    print("Defers references when target objects are not yet migrated")
    print("Re-processes deferred references on subsequent runs")
