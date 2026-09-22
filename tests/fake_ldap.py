"""
In-memory LDAP directory double for tests.

Implements the subset of LDAPConnector that the migrator, handlers, resolver and
verifier actually use, so migration logic can be exercised without a live DC.
"""
import uuid
from typing import Optional, List, Dict, Any

import ldap3


class FakeLDAPConnector:
    """Minimal in-memory stand-in for LDAPConnector."""

    def __init__(self, domain: str, host: str = '127.0.0.1', port: int = 389,
                 username: str = 'administrator', use_tls: bool = False):
        self.domain = domain
        self.host = host
        self.port = port
        self.username = username
        self.password = 'secret'
        self.use_tls = use_tls
        self.domain_dn = ','.join(f'DC={p}' for p in domain.split('.'))

        # dn (normalized upper) -> {'dn': original, 'attributes': {...}}
        self.entries: Dict[str, Dict[str, Any]] = {}
        self._connected = True
        self.modify_log: List[tuple] = []
        self.add_log: List[tuple] = []

    def attrs_in_add(self, dn: str) -> Dict[str, Any]:
        """Attributes supplied in the add operation for the given DN."""
        for logged_dn, attrs in self.add_log:
            if self._key(logged_dn) == self._key(dn):
                return attrs
        return {}

    def attrs_in_modifies(self, dn: str) -> List[str]:
        """Attribute names touched by modify operations for the given DN."""
        names = []
        for logged_dn, changes in self.modify_log:
            if self._key(logged_dn) == self._key(dn):
                names.extend(changes.keys())
        return names

    # --- connection lifecycle -------------------------------------------------

    def connect(self, **kwargs):
        self._connected = True
        return True

    def disconnect(self):
        self._connected = False

    def is_connected(self) -> bool:
        return self._connected

    # --- helpers -------------------------------------------------------------

    @staticmethod
    def _key(dn: str) -> str:
        return ','.join(part.strip() for part in dn.split(',')).upper()

    def seed(self, dn: str, object_classes: List[str], **attributes):
        """Add an object as if it already existed in this directory."""
        attrs = {'objectClass': list(object_classes)}
        attrs.update(attributes)
        attrs.setdefault('objectGUID', str(uuid.uuid4()))
        attrs.setdefault('distinguishedName', dn)
        self.entries[self._key(dn)] = {'dn': dn, 'attributes': attrs}
        return attrs['objectGUID']

    # --- LDAP operations -----------------------------------------------------

    def search(self, base_dn: str, search_filter: str = '(objectClass=*)',
               attributes=None, scope=ldap3.SUBTREE, size_limit: int = 0):
        base_key = self._key(base_dn)

        if base_key not in self.entries and scope == ldap3.BASE:
            from core.ldap_connector import LDAPOperationError
            raise LDAPOperationError(
                'Search error: LDAPNoSuchObjectResult - 32 - noSuchObject')

        results = []
        for key, entry in self.entries.items():
            if scope == ldap3.BASE:
                match = key == base_key
            else:
                match = key == base_key or key.endswith(',' + base_key)
            if match:
                results.append({'dn': entry['dn'],
                                'attributes': dict(entry['attributes'])})

        if not results and scope == ldap3.BASE:
            from core.ldap_connector import LDAPOperationError
            raise LDAPOperationError(
                'Search error: LDAPNoSuchObjectResult - 32 - noSuchObject')

        return results

    def get_object_by_dn(self, dn: str, attributes=None) -> Optional[Dict[str, Any]]:
        entry = self.entries.get(self._key(dn))
        if not entry:
            return None
        return {'dn': entry['dn'], 'attributes': dict(entry['attributes'])}

    def object_exists(self, dn: str) -> bool:
        return self._key(dn) in self.entries

    def add(self, dn: str, object_classes: List[str], attributes: Dict[str, Any]):
        key = self._key(dn)
        # Record exactly what the add carried, so tests can distinguish attributes
        # supplied at creation time from ones patched in by a later modify.
        self.add_log.append((dn, dict(attributes)))

        if key in self.entries:
            from core.ldap_connector import LDAPOperationError
            raise LDAPOperationError(f'Add failed for {dn}: entryAlreadyExists')

        parent = ','.join(dn.split(',')[1:]).strip()
        if parent and self._key(parent) not in self.entries \
                and self._key(parent) != self._key(self.domain_dn):
            from core.ldap_connector import LDAPOperationError
            raise LDAPOperationError(f'Add failed for {dn}: noSuchObject (parent missing)')

        attrs = dict(attributes)
        attrs['objectClass'] = list(object_classes)
        attrs['objectGUID'] = str(uuid.uuid4())
        attrs['distinguishedName'] = dn
        self.entries[key] = {'dn': dn, 'attributes': attrs}
        return True

    def modify(self, dn: str, changes: Dict[str, Any], operation=None):
        entry = self.entries.get(self._key(dn))
        if not entry:
            from core.ldap_connector import LDAPOperationError
            raise LDAPOperationError(f'Modify failed for {dn}: noSuchObject')

        self.modify_log.append((dn, dict(changes)))
        for attr, value in changes.items():
            entry['attributes'][attr] = value
        return True

    def modify_add_values(self, dn: str, changes: Dict[str, Any]):
        entry = self.entries.get(self._key(dn))
        if not entry:
            from core.ldap_connector import LDAPOperationError
            raise LDAPOperationError(f'Modify failed for {dn}: noSuchObject')

        self.modify_log.append((dn, dict(changes)))
        for attr, value in changes.items():
            existing = entry['attributes'].get(attr, [])
            if not isinstance(existing, list):
                existing = [existing]
            new = value if isinstance(value, list) else [value]
            merged = list(existing)
            for v in new:
                if v not in merged:
                    merged.append(v)
            entry['attributes'][attr] = merged
        return True

    def members_of(self, dn: str) -> List[str]:
        """Convenience accessor for assertions."""
        entry = self.entries.get(self._key(dn))
        if not entry:
            return []
        members = entry['attributes'].get('member', [])
        return list(members) if isinstance(members, list) else [members]
