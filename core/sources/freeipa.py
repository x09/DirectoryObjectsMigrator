"""Read-only native FreeIPA discovery; no synthetic AD GUIDs or write operations."""
from dataclasses import dataclass, field
import uuid
import ldap3
from ldap3.utils.dn import escape_rdn
from core.ldap_connector import LDAPConnector, LDAPOperationError
from utils.dn_utils import DNUtils


class DiscoveryCancelled(Exception):
    """Cancellation is neither a partial successful read nor an LDAP failure."""


@dataclass
class SourceObject:
    kind: str
    dn: str
    source_id: str
    name: str
    attributes: dict
    reason: str = ''
    error: bool = False


@dataclass
class FreeIPASnapshot:
    objects: list = field(default_factory=list)

    @property
    def eligible(self):
        return [obj for obj in self.objects if not obj.reason]


class FreeIPAConnector(LDAPConnector):
    provider = 'freeipa'

    def _build_user_dn(self):
        if '=' in self.username:
            return self.username
        return f'uid={escape_rdn(self.username)},cn=users,cn=accounts,{self.domain_dn}'

    @staticmethod
    def _deny(*args, **kwargs):
        raise LDAPOperationError('FreeIPA source is read-only')

    add = modify = modify_add_values = delete = _deny

    def connect(self, *args, **kwargs):
        result = super().connect(*args, **kwargs)
        for name in ('add', 'modify', 'modify_dn', 'delete'):
            setattr(self.connection, name, self._deny)
        return result

    def get_object_by_guid(self, *args, **kwargs):
        raise LDAPOperationError('FreeIPA uses ipaUniqueID, not objectGUID')

    def search(self, base_dn, search_filter, attributes=None, scope=ldap3.SUBTREE, size_limit=0,
               effective_rights=False, cancelled=None):
        if cancelled and cancelled():
            raise DiscoveryCancelled()
        self._ensure_connected()
        old_referrals = self.connection.auto_referrals
        self.connection.auto_referrals = False
        rows, cookie, seen = [], None, set()
        paged = scope != ldap3.BASE and size_limit == 0
        try:
            while True:
                if cancelled and cancelled():
                    raise DiscoveryCancelled()
                options = dict(search_base=base_dn, search_filter=search_filter,
                    search_scope=scope, attributes=attributes or ['*'], size_limit=size_limit)
                if effective_rights:
                    options['controls'] = [('1.3.6.1.4.1.42.2.27.9.5.2', True,
                                           ('dn:' + self._build_user_dn()).encode('utf-8'))]
                if paged:
                    options.update(paged_size=500, paged_cookie=cookie, paged_criticality=True)
                self.connection.search(**options)
                if cancelled and cancelled():
                    raise DiscoveryCancelled()
                if self.connection.result.get('result') != 0:
                    raise LDAPOperationError('FreeIPA search failed: ' + str(self.connection.result))
                if any(row.get('type') == 'searchResRef' for row in self.connection.response):
                    raise LDAPOperationError('FreeIPA search returned a referral; incomplete read')
                for entry in self.connection.entries:
                    attrs = {name.lower(): entry[name].values for name in entry.entry_attributes}
                    rows.append({'dn': entry.entry_dn, 'attributes': attrs})
                if not paged:
                    break
                control = self.connection.result.get('controls', {}).get('1.2.840.113556.1.4.319', {})
                value = control.get('value', {})
                if 'cookie' not in value:
                    raise LDAPOperationError('FreeIPA paging response has no cookie')
                cookie = value['cookie']
                if not cookie:
                    break
                if cookie in seen:
                    raise LDAPOperationError('FreeIPA repeated paging cookie')
                seen.add(cookie)
            return rows
        except ldap3.core.exceptions.LDAPException as exc:
            raise LDAPOperationError(str(exc)) from exc
        finally:
            self.connection.auto_referrals = old_referrals

    def test_connection(self):
        try:
            self.connect()
            rows = self.search(f'cn=users,cn=accounts,{self.domain_dn}',
                               '(objectClass=*)', ['cn'], scope=ldap3.BASE)
            if not rows:
                raise LDAPOperationError('Cannot read FreeIPA accounts container')
            return True, f'FreeIPA: {self.host}:{self.port}'
        except Exception as exc:
            return False, str(exc)
        finally:
            self.disconnect()

    def instance_identity(self):
        """389 DS replicated entry identity; a rebuilt accounts tree is a new source."""
        rows = self.search(f'cn=accounts,{self.domain_dn}', '(objectClass=*)',
                           ['nsUniqueId'], scope=ldap3.BASE)
        values = rows[0]['attributes'].get('nsuniqueid', []) if len(rows) == 1 else []
        try:
            identity = uuid.UUID(str(values[0]).replace('-', '')) if len(values) == 1 else None
            if identity is None or identity.int in (0, (1 << 128) - 1):
                raise ValueError()
        except (ValueError, TypeError):
            raise LDAPOperationError('Cannot verify FreeIPA instance nsUniqueId')
        return str(identity)

    def discover(self, rfc2307=False, custom_exclusions=(), require_read_rights=False, cancelled=None, profile_attributes=None):
        snapshot = FreeIPASnapshot()
        identities = {}
        excluded = {DNUtils.normalize_dn(dn) for dn in custom_exclusions}
        user_base = f'cn=users,cn=accounts,{self.domain_dn}'
        group_base = f'cn=groups,cn=accounts,{self.domain_dn}'
        attrs = ['uid','cn','ipaUniqueID','objectClass','nsAccountLock','givenName','sn',
                 'displayName','mail','telephoneNumber','mobile','title','ou','street',
                 'l','st','postalCode','departmentNumber','employeeNumber','employeeType',
                 'uidNumber','gidNumber','loginShell','homeDirectory','manager',
                 'member','mepManagedEntry','mepManagedBy','description']
        core_fields = {'uid', 'cn', 'ipaUniqueID', 'objectClass', 'nsAccountLock',
                       'gidNumber', 'member', 'manager', 'mepManagedEntry', 'mepManagedBy'}
        if rfc2307:
            core_fields.update({'uidNumber', 'loginShell'})
        if profile_attributes is not None:
            attrs = sorted(core_fields | set(profile_attributes))
        for kind, base, query in [('user', user_base, '(objectClass=posixAccount)'),
                ('group', group_base, '(|(objectClass=ipaUserGroup)(objectClass=posixGroup)(objectClass=ipaExternalGroup))')]:
            options = {'effective_rights': True} if require_read_rights else {}
            if cancelled is not None:
                options['cancelled'] = cancelled
            for entry in self.search(base, query, attrs, **options):
                if cancelled and cancelled():
                    raise DiscoveryCancelled()
                a = entry['attributes']
                def one(key):
                    values = a.get(key, [])
                    return str(values[0]) if len(values) == 1 else ''
                classes = {str(c).lower() for c in a.get('objectclass', [])}
                name = one('uid' if kind == 'user' else 'cn')
                reason, error, identity = '', False, ''
                try:
                    identity = str(uuid.UUID(one('ipauniqueid')))
                    if identity in identities:
                        raise ValueError('duplicate')
                    identities[identity] = entry['dn']
                except ValueError:
                    reason, error = 'Missing, invalid or duplicate ipaUniqueID', True
                if not name:
                    reason, error = 'Missing or ambiguous account name', True
                if not reason:
                    if DNUtils.normalize_dn(entry['dn']) in excluded:
                        reason = 'Excluded by operator'
                    elif kind == 'user':
                        # FreeIPA/389 DS represents never-disabled users by an absent lock attribute.
                        lock = one('nsaccountlock').upper() if a.get('nsaccountlock') else 'FALSE'
                        if lock == 'TRUE':
                            reason = 'Blocked FreeIPA user'
                        elif lock != 'FALSE':
                            reason, error = 'Cannot determine FreeIPA account lock status', True
                        elif name in ('admin', 'trust admin'):
                            reason = 'FreeIPA administrative account'
                    elif 'ipaexternalgroup' in classes:
                        reason = 'External groups are not supported'
                    elif name.casefold() in ('admins','trust admins','ipausers','editors','default smb group'):
                        reason = 'FreeIPA system group'
                    elif a.get('mepmanagedby') and not rfc2307:
                        reason = 'Personal group requires RFC2307'
                    elif 'mepmanagedentry' in classes and len(a.get('mepmanagedby', [])) != 1:
                        reason, error = 'Missing or ambiguous personal group owner', True
                if not reason and require_read_rights:
                    rights = {}
                    for value in a.get('attributelevelrights', []):
                        for item in str(value).split(','):
                            key, _, permissions = item.strip().partition(':')
                            rights[key.lower()] = permissions
                    needed = {'ipauniqueid', 'objectclass', 'cn'}
                    if kind == 'user':
                        needed.update({'uid', 'nsaccountlock', 'givenname', 'sn', 'displayname',
                            'mail', 'telephonenumber', 'mobile', 'title', 'ou', 'street', 'l', 'st',
                            'postalcode', 'employeenumber', 'employeetype', 'manager', 'gidnumber'})
                        if rfc2307:
                            needed.update({'uidnumber', 'loginshell'})
                    elif 'groupofnames' in classes:
                        needed.add('member')
                    if kind == 'group' and 'posixgroup' in classes:
                        needed.add('gidnumber')
                    needed.update(key for key, values in a.items() if values and key in {v.lower() for v in attrs})
                    if 'mepmanagedentry' in classes:
                        needed.add('mepmanagedby')
                    if profile_attributes is not None:
                        # Optional profile-field rights are checked per field by the mapper;
                        # hidden identities, lock state and link attributes still block objects.
                        needed &= {key.lower() for key in core_fields}
                    if any('r' not in rights.get(key, '') for key in needed):
                        reason, error = 'Insufficient confirmed FreeIPA read rights', True
                snapshot.objects.append(SourceObject(kind,entry['dn'],identity,name,a,reason,error))
        counts = {}
        for obj in snapshot.objects:
            if obj.source_id:
                counts[obj.source_id] = counts.get(obj.source_id, 0) + 1
        for obj in snapshot.objects:
            if counts.get(obj.source_id, 0) > 1:
                obj.reason, obj.error = 'Missing, invalid or duplicate ipaUniqueID', True
        # Personal groups of users excluded from this snapshot must also be excluded.
        users = {DNUtils.normalize_dn(o.dn): o for o in snapshot.objects if o.kind == 'user'}
        for obj in snapshot.objects:
            if obj.kind != 'group' or obj.reason:
                continue
            owners = obj.attributes.get('mepmanagedby', [])
            if owners and any(DNUtils.normalize_dn(str(dn)) not in users or
                             users[DNUtils.normalize_dn(str(dn))].reason for dn in owners):
                obj.reason = 'Personal group owner is excluded or unavailable'
        return snapshot
