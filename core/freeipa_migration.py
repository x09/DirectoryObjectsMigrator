"""FreeIPA -> AD pipeline. Native identities, explicit target DNs, additive links.

This module deliberately does not present FreeIPA entries as AD entries. Only
prepared target attributes are passed to the existing password setup helper.
"""
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
import hashlib
import json
import re

from ldap3.utils.dn import escape_rdn, parse_dn
from ldap3.utils.conv import escape_filter_chars
from ldap3.core.exceptions import LDAPCommunicationError
from core.ldap_connector import LDAPConnectionError
from core.sources.freeipa import DiscoveryCancelled
from core.freeipa_attributes import AttributeMappings
from core.identity import domain_identity, guid_text, validate_destination, MappingValidationError
from core.migrator import MigrationResult
from core.verifier import VerificationResult
from core.object_handlers.user_handler import UserHandler
from config import settings
from utils.dn_utils import DNUtils
from utils.i18n import _


def values(attrs, key):
    value = next((v for k, v in attrs.items() if k.lower() == key.lower()), [])
    return value if isinstance(value, list) else ([] if value is None else [value])


def single(attrs, key, required=False):
    items = values(attrs, key)
    if len(items) > 1 or (required and not items):
        raise ValueError(f'Missing or ambiguous {key}')
    return items[0] if items else None


def norm(dn):
    return DNUtils.normalize_dn(dn)


def canonical(value):
    """LDAP attribute values and search results are unordered sets."""
    if isinstance(value, dict):
        return {key: canonical(item) for key, item in sorted(value.items())}
    if isinstance(value, tuple):
        return [canonical(item) for item in value]
    if isinstance(value, list):
        return sorted((canonical(item) for item in value), key=lambda item: json.dumps(item, sort_keys=True, default=str))
    return value


def transport_failure(exc):
    seen = set()
    while exc is not None and id(exc) not in seen:
        seen.add(id(exc))
        if isinstance(exc, (LDAPCommunicationError, LDAPConnectionError, ConnectionError, TimeoutError)):
            return True
        exc = exc.__cause__ or exc.__context__
    return False


class _PasswordDestination:
    """Stop password retries after a lost reply; never retry an uncertain write."""
    def __init__(self, destination):
        self.destination = destination
        self.connection_lost = False

    def __getattr__(self, name):
        return getattr(self.destination, name)

    def get_object_by_dn(self, *args, **kwargs):
        try:
            return self.destination.get_object_by_dn(*args, **kwargs)
        except Exception as exc:
            if transport_failure(exc):
                self.connection_lost = True
            raise

    def modify(self, *args, **kwargs):
        if self.connection_lost:
            raise LDAPConnectionError('Password write outcome is unknown; retry blocked')
        try:
            return self.destination.modify(*args, **kwargs)
        except Exception as exc:
            if transport_failure(exc):
                self.connection_lost = True
            raise


@dataclass
class PlannedObject:
    source: object
    target_dn: str = ''
    attributes: dict = field(default_factory=dict)
    action: str = 'create'
    reason: str = ''
    recreation: dict = field(default_factory=dict)
    optional_attributes: dict = field(default_factory=dict)
    attribute_warnings: list = field(default_factory=list)


@dataclass
class PlannedLink:
    parent_id: str
    attribute: str
    source_dn: str
    target_id: str = ''
    state: str = 'ready'
    reason: str = ''


@dataclass
class FreeIPAPlan:
    instance_id: str
    destination_id: str
    rows: list = field(default_factory=list)
    links: list = field(default_factory=list)
    parents: dict = field(default_factory=dict)
    recreation_requests: dict = field(default_factory=dict)
    attribute_mappings: object = None
    attribute_warnings: list = field(default_factory=list)
    shorten_long_logins: bool = False
    login_statistics: dict = field(default_factory=dict)

    @property
    def blocked(self):
        return any(row.action in ('error', 'conflict') for row in self.rows)

    def fingerprint(self):
        data = (self.instance_id, self.destination_id, self.parents, self.recreation_requests, self.attribute_mappings, self.attribute_warnings, self.shorten_long_logins, self.login_statistics,
                [(r.source.source_id, r.source.dn, r.target_dn, r.attributes, r.action, r.recreation, r.optional_attributes, r.attribute_warnings,
                  {k: v for k, v in r.source.attributes.items()
                   if k not in ('attributelevelrights', 'entrylevelrights')}) for r in self.rows],
                [(l.parent_id, l.attribute, l.source_dn, l.target_id, l.state) for l in self.links])
        return hashlib.sha256(json.dumps(canonical(data), sort_keys=True, default=str).encode()).hexdigest()


class FreeIPAMigrator:
    def __init__(self, source, destination, database, logger, users_dn, groups_dn,
                 rfc2307=False, custom_exclusions=(), dry_run=False,
                 password_mode='random', fixed_password='', password_length=16,
                 progress_callback=None, approved_plan=None, recreation_requests=None, attribute_mappings=None, shorten_long_logins=False):
        self.source, self.destination, self.database, self.logger = source, destination, database, logger
        self.users_dn, self.groups_dn = users_dn, groups_dn
        self.rfc2307, self.custom_exclusions = rfc2307, custom_exclusions
        self.dry_run, self.progress_callback = dry_run, progress_callback
        self.approved_plan = approved_plan
        self.recreation_requests = dict(recreation_requests if recreation_requests is not None else
                                        (approved_plan.recreation_requests if approved_plan else {}))
        self.cancelled = False
        self.attribute_mappings = attribute_mappings
        self.shorten_long_logins = shorten_long_logins
        self.login_names = {}
        self.profile_mapper = None
        self.optional_failures = set()
        self.instance_id = source.instance_identity()
        self.destination_id = domain_identity(destination)
        self.db = database.for_source('freeipa', self.instance_id, self.destination_id,
                                      source.domain, destination.domain)
        self._password_destination = _PasswordDestination(destination)
        self.password = UserHandler(source, self._password_destination, None, logger, source.domain,
                                    destination.domain, password_mode=password_mode,
                                    fixed_password=fixed_password, password_length=password_length)

    def cancel(self):
        self.cancelled = True

    def _check_cancelled(self):
        if self.cancelled:
            raise DiscoveryCancelled()

    def _progress(self, percent, message):
        if self.progress_callback:
            self.progress_callback(percent, message)

    def _check_parent(self, dn):
        parse_dn(dn)  # Reject malformed DNs before searching.
        if not (norm(dn) == norm(self.destination.domain_dn) or
                norm(dn).endswith(',' + norm(self.destination.domain_dn))):
            raise ValueError('Destination container is outside the target domain: ' + dn)
        entry = self.destination.get_object_by_dn(dn, ['objectGUID', 'objectClass'])
        if not entry or not ({'organizationalunit', 'container', 'domaindns'} &
                             {str(v).lower() for v in values(entry['attributes'], 'objectClass')}):
            raise ValueError('Destination OU/container does not exist: ' + dn)
        return guid_text(single(entry['attributes'], 'objectGUID', True))

    def _prepare(self, obj, existing_attributes=None):
        name = self.login_names.get(obj.source_id, obj.name) if obj.kind == 'user' else obj.name
        # AD users and groups share one sAMAccountName namespace. UPGs therefore
        # need an explicit, visible name distinct from their owner's uid.
        if obj.kind == 'group' and obj.attributes.get('mepmanagedby'):
            name = 'ipa-pg-' + name
        if (not name or name != name.strip() or name.endswith('.') or
                re.search(r'[\x00-\x1f"/\\\[\]:;|=,+*?<>@]', name) or
                len(name) > (20 if obj.kind == 'user' else 256)):
            raise ValueError('Invalid destination account name: ' + name)
        if len(name) > 64:
            raise ValueError('Destination CN exceeds 64 characters: ' + name)
        attrs = {'cn': name, 'sAMAccountName': name}
        if obj.kind == 'user':
            attrs.update(userAccountControl=514,
                         userPrincipalName=name + '@' + self.destination.domain.rstrip('.'))
            if self.attribute_mappings is None:
                mapping = {'givenname': 'givenName', 'sn': 'sn', 'displayname': 'displayName',
                           'title': 'title', 'ou': 'department', 'street': 'streetAddress',
                           'l': 'l', 'st': 'st', 'postalcode': 'postalCode',
                           'employeenumber': 'employeeNumber', 'employeetype': 'employeeType'}
                for key, target in mapping.items():
                    value = single(obj.attributes, key)
                    if value is not None:
                        attrs[target] = str(value)
                # AD mail and telephoneNumber are single-valued. Keep secondary
                # values in the corresponding multivalued AD attributes.
                for key, primary, secondary in [('mail', 'mail', 'otherMailbox'),
                        ('telephonenumber', 'telephoneNumber', 'otherTelephone'),
                        ('mobile', 'mobile', 'otherMobile')]:
                    items = sorted({str(v) for v in values(obj.attributes, key)})
                    if items:
                        # Keep a previously migrated primary value if still present.
                        preferred = single(existing_attributes or {}, primary)
                        if preferred not in items:
                            preferred = obj.name + '@' + self.source.domain.rstrip('.') if key == 'mail' else None
                        chosen = preferred if preferred in items else items[0]
                        attrs[primary] = chosen
                        remaining = [value for value in items if value != chosen]
                        if remaining:
                            attrs[secondary] = remaining
        else:
            attrs['groupType'] = -2147483646  # Global security group.
        description = values(obj.attributes, 'description')
        if description and self.attribute_mappings is None:
            attrs['description'] = [str(v) for v in description]
        if self.rfc2307:
            for key in (('uidNumber', 'gidNumber') if obj.kind == 'user' else ('gidNumber',)):
                classes = {str(v).lower() for v in values(obj.attributes, 'objectClass')}
                raw = single(obj.attributes, key, required=obj.kind == 'user' or 'posixgroup' in classes)
                if raw is not None:
                    if not str(raw).isdigit() or not 0 <= int(raw) <= 2147483647:
                        raise ValueError('Invalid RFC2307 value: ' + key)
                    attrs[key] = int(raw)
            shell = single(obj.attributes, 'loginShell') if obj.kind == 'user' else None
            if shell:
                attrs['loginShell'] = str(shell)
        parent = self.users_dn if obj.kind == 'user' else self.groups_dn
        return 'CN=' + escape_rdn(name) + ',' + parent, attrs

    def _collision(self, row):
        if self.destination.get_object_by_dn(row.target_dn, ['objectGUID']):
            return 'Destination DN already exists'
        checks = ['sAMAccountName', 'userPrincipalName']
        if self.rfc2307:
            checks.append('uidNumber' if row.source.kind == 'user' else 'gidNumber')
        for key in checks:
            if key not in row.attributes:
                continue
            query = '(' + key + '=' + escape_filter_chars(str(row.attributes[key])) + ')'
            if key in ('uidNumber', 'gidNumber'):
                query = '(&(objectClass=' + row.source.kind + ')' + query + ')'
            if self.destination.search(self.destination.domain_dn, query, ['objectGUID']):
                return 'Destination identity already exists: ' + key + '=' + str(row.attributes[key])
        return ''

    def _recreation_token(self, mapping):
        return {'direction_id': self.db.direction_id, 'old_guid': guid_text(mapping['dest_guid']),
                'old_dn': mapping['dest_dn'], 'object_type': mapping['object_type']}

    def _assert_missing(self, token):
        # A moved object is still the original object. An occupied old DN is a
        # replacement, never permission to overwrite/adopt it. LDAP failures propagate.
        if token['direction_id'] != self.db.direction_id:
            raise ValueError(_('Recreation belongs to another migration direction'))
        if self.destination.get_object_by_guid(token['old_guid'], base_dn=self.destination.domain_dn):
            raise ValueError(_('The original object still exists; analyze again'))
        if self.destination.get_object_by_dn(token['old_dn'], ['objectGUID']):
            raise ValueError(_('The previous destination DN is occupied; recreation is blocked'))

    def _prepare_recreation(self, row, mapping, plan):
        token = self._recreation_token(mapping)
        self._assert_missing(token)
        parent = DNUtils.get_parent_dn(token['old_dn'])
        plan.parents[parent] = self._check_parent(parent)
        # Keep the recorded container, even if current default destinations differ.
        row.target_dn = 'CN=' + escape_rdn(row.attributes['cn']) + ',' + parent
        collision = self._collision(row)
        if collision:
            row.action, row.reason = 'conflict', collision
            return
        requested = self.recreation_requests.get(row.source.source_id)
        if requested is not None and requested != token:
            raise ValueError(_('Migration history changed; confirm recreation again'))
        row.recreation = token
        if requested == token:
            row.action, row.reason = 'recreate', _('Recreation confirmed; a new SID/GUID will be assigned')
            plan.recreation_requests[row.source.source_id] = token
        else:
            row.action, row.reason = 'error', _('Tracked destination object is absent; explicit recreation confirmation is required')

    def _check_recreation(self, row):
        mapping = self.db.get_object_by_source_guid(row.source.source_id)
        if not mapping or self._recreation_token(mapping) != row.recreation:
            raise ValueError(_('Migration history changed; confirm recreation again'))
        self._assert_missing(row.recreation)

    def _plan_login_names(self, snapshot, plan):
        # Never infer ownership from a matching name. Historical assignments are
        # reused only through the normal, GUID-validated mapping path below.
        saved = self.db.get_freeipa_login_assignments()
        self.login_names = dict(saved)
        long_users = [o for o in snapshot.objects if o.kind == 'user' and len(o.name) > 20]
        eligible = [o for o in long_users if not o.reason]
        width = max(3, len(str(len(eligible))))
        plan.shorten_long_logins = self.shorten_long_logins
        plan.login_statistics = dict(total=len(long_users), eligible=len(eligible),
                                     generated=0, retained=0, digits=width)
        reserved = {name.casefold() for name in saved.values()}
        for obj in snapshot.objects:
            if obj.reason:
                continue
            name = ('ipa-pg-' + obj.name if obj.kind == 'group' and
                    obj.attributes.get('mepmanagedby') else obj.name)
            reserved.add(name.casefold())
            if obj.kind == 'user' and obj.source_id in saved:
                plan.login_statistics['retained'] += 1
        if not self.shorten_long_logins:
            return
        serial = 0
        for obj in sorted(eligible, key=lambda o: (o.name.casefold(), o.source_id)):
            self._check_cancelled()
            if obj.source_id in saved or self.db.get_object_by_source_guid(obj.source_id):
                continue
            # Shortening fixes length only, never hides malformed source names.
            if (obj.name != obj.name.strip() or obj.name.endswith('.') or
                    re.search(r'[\x00-\x1f"/\\\[\]:;|=,+*?<>@]', obj.name)):
                continue
            for attempt in range(10000):
                self._check_cancelled()
                serial += 1
                digits = max(width, len(str(serial)))
                name = obj.name[:20 - digits - 1].rstrip('_') + '_' + str(serial).zfill(digits)
                if name.casefold() in reserved:
                    continue
                candidate = PlannedObject(obj, target_dn='CN=' + escape_rdn(name) + ',' + self.users_dn,
                    attributes={'sAMAccountName': name,
                                'userPrincipalName': name + '@' + self.destination.domain.rstrip('.')})
                # Check DN, SAM and UPN throughout the target domain. RFC2307
                # collisions remain errors; they must not be hidden by renaming.
                if self._collision(candidate):
                    continue
                self.login_names[obj.source_id] = name
                reserved.add(name.casefold())
                plan.login_statistics['generated'] += 1
                plan.login_statistics['digits'] = max(plan.login_statistics['digits'], digits)
                break
            else:
                raise ValueError(_('Cannot allocate a free shortened login; check destination names'))

    def build_plan(self):
        self._check_cancelled()
        self._progress(0, _('Reading FreeIPA objects and permissions...'))
        if self.source.instance_identity() != self.instance_id or domain_identity(self.destination) != self.destination_id:
            raise ValueError('Directory identity changed; analyze again')
        plan = FreeIPAPlan(self.instance_id, self.destination_id)
        plan.parents = {dn: self._check_parent(dn) for dn in (self.users_dn, self.groups_dn)}
        if self.rfc2307:
            schema = getattr(getattr(self.destination, 'server', None), 'schema', None)
            attributes = {k.lower() for k in getattr(schema, 'attribute_types', {})}
            if not {'uidnumber', 'gidnumber', 'loginshell'} <= attributes:
                raise ValueError('Destination RFC2307 schema is unavailable or incomplete')
        discovery_options = {}
        if self.attribute_mappings is not None:
            self.profile_mapper = AttributeMappings(self.attribute_mappings, self.source, self.destination)
            plan.attribute_mappings = self.profile_mapper.rows
            plan.attribute_warnings = self.profile_mapper.warnings
            discovery_options['profile_attributes'] = self.profile_mapper.source_attributes()
        snapshot = self.source.discover(self.rfc2307, self.custom_exclusions,
                                        require_read_rights=True, cancelled=lambda: self.cancelled,
                                        **discovery_options)
        self._progress(5, _("Checking destination logins..."))
        self._plan_login_names(snapshot, plan)
        reserved = defaultdict(list)
        for obj in snapshot.objects:
            self._check_cancelled()
            row = PlannedObject(obj)
            plan.rows.append(row)
            if obj.reason:
                row.action, row.reason = ('error' if obj.error else 'skip'), obj.reason
                continue
            try:
                mapping = self.db.get_object_by_source_guid(obj.source_id)
                existing = None
                missing = False
                if mapping:
                    if mapping['object_type'] != obj.kind:
                        raise ValueError('Source object type changed')
                    try:
                        existing = self._read_tracked(row, self.profile_mapper.target_attributes() if self.profile_mapper else
                                                      ['mail', 'telephoneNumber', 'mobile'])
                    except MappingValidationError:
                        # Only a successful absence check can offer recreation.
                        self._assert_missing(self._recreation_token(mapping))
                        missing = True
                row.target_dn, row.attributes = self._prepare(obj, existing['attributes'] if existing else None)
                if self.profile_mapper:
                    row.optional_attributes, row.attribute_warnings = self.profile_mapper.prepare(
                        obj, self.source.domain, existing['attributes'] if existing else None)
                if missing:
                    self._prepare_recreation(row, mapping, plan)
                elif mapping:
                    row.target_dn = existing['dn']
                    if mapping.get('error_message') == 'FreeIPA password setup not confirmed':
                        entry = self.destination.get_object_by_dn(row.target_dn, ['pwdLastSet'])
                        last_set = single(entry['attributes'], 'pwdLastSet')
                        confirmed = (last_set.year > 1601 if isinstance(last_set, datetime) else
                                     str(last_set).isdigit() and int(last_set) > 0)
                        if not confirmed:
                            raise ValueError('Password setup previously failed; reset the target password before retrying')
                    if self.rfc2307:
                        entry = self.destination.get_object_by_dn(row.target_dn, ['uidNumber', 'gidNumber', 'loginShell'])
                        for key in ('uidNumber', 'gidNumber', 'loginShell'):
                            if key in row.attributes and str(single(entry['attributes'], key)) != str(row.attributes[key]):
                                raise ValueError('Existing RFC2307 attributes differ; automatic overwrite is blocked')
                    row.action = 'exists'
                else:
                    reason = self._collision(row)
                    if reason:
                        row.action, row.reason = 'conflict', reason
                reserved[('dn', norm(row.target_dn))].append(row)
                for key in ('sAMAccountName', 'userPrincipalName', 'uidNumber', 'gidNumber'):
                    if key in row.attributes and not (key == 'gidNumber' and obj.kind == 'user'):
                        reserved[(key, str(row.attributes[key]).casefold())].append(row)
            except Exception as exc:
                if transport_failure(exc):
                    raise
                row.action, row.reason = 'error', str(exc)
        for rows in reserved.values():
            if len(rows) > 1:
                for row in rows:
                    row.action, row.reason = 'conflict', 'Duplicate planned destination identity'
                    row.recreation = {}
                    plan.recreation_requests.pop(row.source.source_id, None)
        self._plan_links(plan)
        if self.source.instance_identity() != self.instance_id:
            raise ValueError('FreeIPA instance changed during discovery')
        return plan

    def _plan_links(self, plan):
        by_dn = {norm(r.source.dn): r for r in plan.rows}
        gids = defaultdict(list)
        for row in plan.rows:
            self._check_cancelled()
            if row.source.kind == 'group':
                for gid in values(row.source.attributes, 'gidNumber'):
                    gids[str(gid)].append(row)
        links = set()
        def add(parent, attr, child_dn):
            self._check_cancelled()
            key = (parent.source.source_id, attr, norm(child_dn))
            if key in links:
                return
            links.add(key)
            child = by_dn.get(norm(child_dn))
            link = PlannedLink(parent.source.source_id, attr, child_dn)
            if child:
                link.target_id = child.source.source_id
                if child.action == 'skip':
                    link.state, link.reason = 'skip', child.reason
                elif child.action not in ('create', 'exists', 'recreate'):
                    link.state, link.reason = 'deferred', child.reason
                elif attr == 'manager' and child.source.kind != 'user':
                    link.state, link.reason = 'deferred', 'Manager is not a user'
            else:
                link.state, link.reason = 'deferred', 'Referenced object is outside the readable accounts tree'
            plan.links.append(link)
        for row in plan.rows:
            if row.action not in ('create', 'exists', 'recreate'):
                continue
            obj = row.source
            attr = 'member' if obj.kind == 'group' else 'manager'
            targets = values(obj.attributes, attr)
            if attr == 'manager' and len(targets) > 1:
                row.action, row.reason = 'error', 'Multiple managers cannot be represented in AD'
                continue
            for dn in targets:
                add(row, attr, str(dn))
            if obj.kind != 'user':
                continue
            gid = single(obj.attributes, 'gidNumber')
            groups = gids.get(str(gid), []) if gid is not None else []
            if len(groups) != 1:
                row.action, row.reason = 'error', 'Missing or ambiguous POSIX primary group'
                continue
            group = groups[0]
            if group.action in ('create', 'exists', 'recreate'):
                add(group, 'member', obj.dn)
            elif self.rfc2307:
                row.action, row.reason = 'error', 'POSIX primary group is excluded or unavailable'

    def _mapped_dn(self, row):
        mapping = self.db.get_object_by_source_guid(row.source.source_id)
        if not mapping:
            raise ValueError('No confirmed destination GUID for ' + row.source.dn)
        return validate_destination(self.destination, mapping)

    def _read_tracked(self, row, attributes):
        """Confirm identity on the data read too, including a move/replacement race."""
        mapping = self.db.get_object_by_source_guid(row.source.source_id)
        if not mapping:
            raise ValueError('No confirmed destination GUID for ' + row.source.dn)
        dn = validate_destination(self.destination, mapping)
        entry = self.destination.get_object_by_dn(dn, list(set(attributes) | {'objectGUID', 'objectClass'}))
        if not entry or guid_text(single(entry['attributes'], 'objectGUID', True)) != guid_text(mapping['dest_guid']):
            raise ValueError('Tracked destination object changed while reading: ' + dn)
        classes = {str(v).lower() for v in values(entry['attributes'], 'objectClass')}
        if row.source.kind not in classes or (row.source.kind == 'user' and 'computer' in classes):
            raise ValueError('Tracked destination object has an unexpected object class')
        return entry

    def migrate(self, base_dn=None):
        result = MigrationResult(start_time=datetime.now())
        try:
            plan = self.build_plan()
            if self.approved_plan is None or self.approved_plan.fingerprint() != plan.fingerprint():
                raise ValueError('Migration plan changed or was not reviewed; analyze again')
            result.objects_analyzed = len(plan.rows)
            result.objects_conflicted = sum(r.action == 'conflict' for r in plan.rows)
            if plan.blocked:
                raise ValueError('Resolve plan errors and conflicts before migration')
            result.objects_skipped = sum(r.action in ('skip', 'exists') for r in plan.rows)
            if self.dry_run:
                result.success, result.status = True, settings.RUN_STATUS_COMPLETED
                result.warnings.extend(plan.attribute_warnings)
                result.warnings.extend(row.source.dn + ': ' + message for row in plan.rows for message in row.attribute_warnings)
                if result.warnings:
                    result.status = settings.RUN_STATUS_COMPLETED_WITH_WARNINGS
                result.warnings.append('Dry run: no destination or history writes were performed')
                return result
            result.run_id = self.db.create_migration_run(
                self.source.domain_dn, self.destination.domain_dn,
                self.source.host, self.destination.host,
                {'source_domain': self.source.domain, 'dest_domain': self.destination.domain,
                 'source_host': self.source.host, 'dest_host': self.destination.host,
                 'options': {'source_provider': 'freeipa', 'source_instance_id': self.instance_id,
                             'rfc2307': self.rfc2307, 'users_dn': self.users_dn, 'groups_dn': self.groups_dn,
                             'recreation_requests': plan.recreation_requests,
                             'attribute_mappings': plan.attribute_mappings,
                             'shorten_long_logins': self.shorten_long_logins,
                             'login_statistics': plan.login_statistics}})
            for message in plan.attribute_warnings:
                self._attribute_warning(result, message)
            for row in plan.rows:
                for message in row.attribute_warnings:
                    self._attribute_warning(result, message, row)
            for index, row in enumerate(plan.rows):
                if self.cancelled:
                    break
                self._progress(10 + int(50 * index / max(1, len(plan.rows))), _('Creating FreeIPA objects in AD...'))
                if row.action == 'skip':
                    continue
                if row.action == 'exists':
                    self.db.refresh_mapping(row.source.source_id, row.source.dn, self._mapped_dn(row))
                    mapping = self.db.get_object_by_source_guid(row.source.source_id)
                    if mapping.get('error_message') == 'FreeIPA password setup not confirmed':
                        self.db.add_object(row.source.source_id, row.source.dn, mapping['dest_guid'],
                                           mapping['dest_dn'], row.source.kind, 'exists', result.run_id)
                    continue
                try:
                    # Recheck after preview and immediately before each add.
                    parent = DNUtils.get_parent_dn(row.target_dn)
                    if self._check_parent(parent) != plan.parents[parent]:
                        raise ValueError('Destination parent was replaced')
                    if row.action == 'recreate':
                        self._check_recreation(row)
                    reason = self._collision(row)
                    if reason:
                        raise ValueError(reason)
                    if self.destination.add(row.target_dn, [row.source.kind], row.attributes) is not True:
                        raise ValueError('LDAP add did not confirm creation')
                    result.objects_created += 1
                    entry = self.destination.get_object_by_dn(row.target_dn, ['objectGUID', 'objectClass'])
                    target_id = guid_text(single(entry['attributes'], 'objectGUID', True))
                    password_pending = 'FreeIPA password setup not confirmed' if row.source.kind == 'user' else None
                    if row.action == 'recreate':
                        # A resurrected original during add must never lose its mapping.
                        if self.destination.get_object_by_guid(row.recreation['old_guid'], base_dn=self.destination.domain_dn):
                            raise ValueError(_('The original object still exists; analyze again'))
                        self.db.replace_missing_mapping(row.source.source_id, row.recreation,
                            row.source.dn, target_id, row.target_dn, result.run_id, password_pending)
                        notice = _('Recreated with a new SID/GUID; previous permissions are not restored automatically') + ': ' + row.target_dn
                        self.logger.warning(notice)
                        result.warnings.append(notice)
                    else:
                        self.db.add_object(row.source.source_id, row.source.dn, target_id, row.target_dn,
                                           row.source.kind, 'error' if row.source.kind == 'user' else 'created',
                                           result.run_id, source_sam=row.source.name, error_message=password_pending,
                                           notes=(json.dumps({'freeipa_login': row.attributes['sAMAccountName']})
                                                  if row.source.kind == 'user' and row.source.source_id in self.login_names else None))
                    self.logger.success('Created ' + row.target_dn)
                    if row.source.kind == 'user':
                        dn = self._mapped_dn(row)
                        if not self.password.configure_password({'attributes': row.attributes}, dn):
                            self.db.add_object(row.source.source_id, row.source.dn, target_id, dn,
                                row.source.kind, 'error', result.run_id,
                                error_message='FreeIPA password setup not confirmed')
                            if self._password_destination.connection_lost:
                                raise LDAPConnectionError('Connection lost while setting password; subsequent writes stopped')
                            raise ValueError('Password not confirmed; account remains disabled: ' + dn)
                        result.warnings.extend(message for severity, message in self.password.password_events if severity == 'warning')
                        self.db.add_object(row.source.source_id, row.source.dn, target_id, dn,
                                           row.source.kind, 'created', result.run_id)
                    self._apply_optional(row, result)
                except Exception as exc:
                    result.errors_count += 1
                    self.logger.error(str(exc))
                    result.warnings.append(row.source.dn + ': ' + str(exc))
                    self.db.log_error(result.run_id, 'ERROR', 'create', str(exc), row.source.dn, row.source.kind)
                    if transport_failure(exc):
                        raise
            if not self.cancelled:
                self._apply_links(plan, result)
                result.verification_result = self._verify(plan)
                self._verify_optional(plan, result)
                result.errors_count += len(result.verification_result.errors)
                result.warnings.extend(result.verification_result.warnings)
            result.success = not self.cancelled and result.errors_count == 0
            result.status = (settings.RUN_STATUS_CANCELLED if self.cancelled else
                settings.RUN_STATUS_COMPLETED_WITH_ERRORS if result.errors_count else
                settings.RUN_STATUS_COMPLETED_WITH_WARNINGS if result.warnings else settings.RUN_STATUS_COMPLETED)
        except DiscoveryCancelled:
            result.status = settings.RUN_STATUS_CANCELLED
        except Exception as exc:
            result.errors_count += 1
            result.failure_message = str(exc)
            result.status = settings.RUN_STATUS_FAILED
            self.logger.error(str(exc))
        finally:
            result.end_time = datetime.now()
            result.duration_seconds = int((result.end_time-result.start_time).total_seconds())
            if result.run_id:
                for message in (result.verification_result.errors if result.verification_result else []):
                    self.db.log_error(result.run_id, 'ERROR', 'verification', message)
                self.db.update_migration_run(result.run_id, result.status, stats={
                    key: getattr(result, key) for key in ('objects_analyzed', 'objects_created',
                        'objects_skipped', 'objects_conflicted', 'errors_count')},
                    duration_seconds=result.duration_seconds,
                    notes='\n'.join([result.failure_message] + result.warnings +
                        (result.verification_result.errors if result.verification_result else [])))
        return result

    def _attribute_warning(self, result, message, row=None):
        text = (row.source.dn + ': ' if row else '') + message
        result.warnings.append(text)
        self.logger.warning(text)
        if result.run_id:
            self.db.log_error(result.run_id, 'WARNING', 'attributes', message,
                              row.source.dn if row else None, row.source.kind if row else None)

    def _apply_optional(self, row, result):
        # Only newly created/recreated objects enter this path. Isolate each field
        # so an LDAP schema/permission rejection cannot prevent object creation.
        for attribute, value in row.optional_attributes.items():
            self._check_cancelled()
            dn = self._read_tracked(row, [])['dn']
            try:
                if self.destination.modify(dn, {attribute: value}) is not True:
                    raise ValueError('LDAP did not confirm attribute write')
            except Exception as exc:
                if transport_failure(exc):
                    raise
                from core.ldap_connector import LDAPOperationError
                if not isinstance(exc, LDAPOperationError) or exc.result_code not in (16,17,19,20,21,50,53,65):
                    raise LDAPConnectionError(_('Optional attribute write was not confirmed; subsequent writes stopped')) from exc
                # Only a definitive schema/value/permission rejection is skippable.
                # Do not include server text: it may echo attribute values.
                self.optional_failures.add((row.source.source_id, attribute))
                self._attribute_warning(result, attribute + ': ' +
                    _('Optional attribute rejected by the server; object retained without this field') +
                    f' (LDAP {exc.result_code})', row)

    def _verify_optional(self, plan, result):
        for row in plan.rows:
            if row.action not in ('create', 'exists', 'recreate') or not row.optional_attributes:
                continue
            self._check_cancelled()
            try:
                entry = self._read_tracked(row, list(row.optional_attributes))
            except Exception as exc:
                if transport_failure(exc):
                    raise
                # Identity verification is still a hard error in _verify().
                continue
            for attribute, expected in row.optional_attributes.items():
                if (row.source.source_id, attribute) in self.optional_failures:
                    continue
                wanted = {str(v) for v in (expected if isinstance(expected, list) else [expected])}
                actual = {str(v) for v in values(entry['attributes'], attribute)}
                result.verification_result.checked_attributes += 1
                if wanted != actual:
                    self._attribute_warning(result, attribute + ': ' +
                        _('Optional attribute differs or is missing; existing objects are not updated automatically'), row)

    REFERENCE_BATCH_SIZE = 128

    def _apply_links(self, plan, result):
        self._progress(70, _('Resolving FreeIPA memberships and managers...'))
        rows = {r.source.source_id: r for r in plan.rows if r.source.source_id}
        pending = {(r['parent_object_guid'], r['attribute_name'], norm(r['referenced_source_dn'])): r
                   for r in self.db.get_unresolved_references()}
        grouped = defaultdict(list)
        for link in plan.links:
            grouped[(link.parent_id, link.attribute)].append(link)

        def defer(link, exc):
            result.errors_count += 1
            result.warnings.append('Deferred reference: ' + link.source_dn + '; ' + str(exc))
            self.db.log_error(result.run_id, 'ERROR', 'references', str(exc), link.source_dn)
            key = (link.parent_id, link.attribute, norm(link.source_dn))
            previous = pending.pop(key, None)
            parent_mapping = self.db.get_object_by_source_guid(link.parent_id)
            if not previous and parent_mapping:
                self.db.add_deferred_reference(link.parent_id, parent_mapping['dest_dn'],
                    rows[link.parent_id].source.kind, link.attribute, link.source_dn,
                    result.run_id, referenced_guid=link.target_id or None)

        def resolved(link, child):
            previous = pending.pop((link.parent_id, link.attribute, norm(link.source_dn)), None)
            if previous:
                self.db.mark_reference_resolved(previous['id'], child, result.run_id)

        for (parent_id, attribute), links in grouped.items():
            self._check_cancelled()
            active = []
            for link in links:
                if link.state == 'skip':
                    result.warnings.append('Skipped reference: ' + link.source_dn + '; ' + link.reason)
                    previous = pending.pop((parent_id, attribute, norm(link.source_dn)), None)
                    if previous:
                        self.db.mark_reference_skipped(previous['id'], link.reason, result.run_id)
                elif link.state != 'ready':
                    defer(link, ValueError(link.reason))
                else:
                    active.append(link)
            if not active:
                continue
            try:
                entry = self._read_tracked(rows[parent_id], [attribute])
                current = {norm(str(v)) for v in values(entry['attributes'], attribute)}
            except Exception as exc:
                for link in active:
                    defer(link, exc)
                if transport_failure(exc):
                    raise
                continue
            for offset in range(0, len(active), self.REFERENCE_BATCH_SIZE):
                self._check_cancelled()
                missing = []
                for link in active[offset:offset + self.REFERENCE_BATCH_SIZE]:
                    try:
                        child = self._mapped_dn(rows[link.target_id])
                        if norm(child) in current:
                            resolved(link, child)
                        elif attribute == 'manager' and current:
                            defer(link, ValueError('Existing manager differs; overwrite blocked'))
                        else:
                            missing.append((link, child))
                    except Exception as exc:
                        defer(link, exc)
                        if transport_failure(exc):
                            raise
                if not missing:
                    continue
                try:
                    # Validate the parent immediately before every write, including
                    # replacements/moves after the initial membership read.
                    parent = self._read_tracked(rows[parent_id], [])['dn']
                    children = list(dict.fromkeys(child for _, child in missing))
                    if self.destination.modify_add_values(parent, {attribute: children}) is not True:
                        raise ValueError('LDAP did not confirm reference addition')
                    current.update(norm(child) for child in children)
                    for link, child in missing:
                        resolved(link, child)
                except Exception as exc:
                    for link, child_dn in missing:
                        defer(link, exc)
                    if transport_failure(exc):
                        raise
        for previous in pending.values():
            if previous['parent_object_guid'] in rows:
                self.db.mark_reference_skipped(previous['id'], 'Not in the current FreeIPA plan', result.run_id)

    def _verify(self, plan):
        self._progress(90, _('Verifying FreeIPA migration...'))
        result = VerificationResult()
        result.success = True
        rows = {r.source.source_id: r for r in plan.rows if r.action in ('create', 'exists', 'recreate')}
        # One complete, GUID-checked read per object. In particular, do not fetch
        # an entire large group's member attribute again for every member.
        observed, members = {}, {}
        expected_members = defaultdict(set)
        for identity, row in rows.items():
            self._check_cancelled()
            try:
                entry = self._read_tracked(row, list(row.attributes) + ['primaryGroupID', 'member', 'manager'])
                dn = entry['dn']
                observed[identity] = entry
                members[(identity, 'member')] = {norm(str(v)) for v in values(entry['attributes'], 'member')}
                members[(identity, 'manager')] = {norm(str(v)) for v in values(entry['attributes'], 'manager')}
                result.checked_objects += 1
                for key, expected in row.attributes.items():
                    actual = {str(v) for v in values(entry['attributes'], key)}
                    wanted = {str(v) for v in (expected if isinstance(expected, list) else [expected])}
                    if key == 'userAccountControl':
                        if not int(single(entry['attributes'], key, True)) & 2:
                            result.add_error('Migrated account is enabled: ' + dn)
                    elif actual != wanted:
                        result.add_error('Attribute mismatch: ' + dn + '; ' + key)
                    result.checked_attributes += 1
                if row.source.kind == 'user' and str(single(entry['attributes'], 'primaryGroupID')) != '513':
                    result.add_error('Unexpected Windows primary group: ' + dn)
                numeric_key = 'uidNumber' if row.source.kind == 'user' else 'gidNumber'
                if self.rfc2307 and numeric_key in row.attributes:
                    matches = self.destination.search(self.destination.domain_dn,
                        '(&(objectClass=' + row.source.kind + ')(' + numeric_key + '=' +
                        str(row.attributes[numeric_key]) + '))', ['objectGUID'])
                    if len(matches) != 1 or norm(matches[0]['dn']) != norm(dn):
                        result.add_error('RFC2307 identity is not unique: ' + dn + '; ' + numeric_key)
            except Exception as exc:
                result.add_error(str(exc))
                if transport_failure(exc):
                    raise
        for link in plan.links:
            self._check_cancelled()
            if link.state == 'skip':
                continue
            if link.state != 'ready' or link.parent_id not in observed or link.target_id not in observed:
                result.add_error('Unverified reference: ' + link.source_dn)
                continue
            parent, child = observed[link.parent_id]['dn'], observed[link.target_id]['dn']
            if norm(child) not in members[(link.parent_id, link.attribute)]:
                result.add_error('Missing reference: ' + parent + '; ' + link.attribute + ': ' + child)
            result.checked_references += 1
            if link.attribute == 'member':
                expected_members[link.parent_id].add(norm(child))
        for identity, row in rows.items():
            if row.source.kind == 'group' and identity in observed:
                extra = members[(identity, 'member')] - expected_members[identity]
                if extra:
                    result.add_warning('Additional destination members preserved: ' + observed[identity]['dn'] + '; ' + str(len(extra)))
        return result
