"""
LDAP Connector
Handles connection and operations with LDAP servers (MSAD and Samba AD)
"""
import ldap3
import uuid
import re
from copy import deepcopy
from typing import Optional, List, Dict, Any, Tuple
from datetime import datetime
import time
from config import settings


class LDAPConnectionError(Exception):
    """LDAP connection error"""
    pass


class LDAPOperationError(Exception):
    """LDAP operation error"""
    pass


class LDAPConnector:
    """
    LDAP connector with connection pooling, retry logic, and error handling
    """

    def __init__(
        self,
        host: str,
        port: int,
        domain: str,
        username: str,
        password: str,
        use_tls: bool = True,
        timeout: int = settings.DEFAULT_TIMEOUT
    ):
        """
        Initialize LDAP connector

        Args:
            host: LDAP server hostname or IP
            port: LDAP port (389 or 636)
            domain: Domain name (e.g., 'domain.alt')
            username: Username (can be UPN or DN)
            password: Password
            use_tls: Use TLS encryption
            timeout: Connection timeout in seconds
        """
        self.host = host
        self.port = port
        self.domain = domain
        self.username = username
        self.password = password
        self.use_tls = use_tls
        self.timeout = timeout

        self.server = None
        self.connection = None
        self.domain_dn = None
        self._last_bind_time = None

        # Build domain DN from domain name
        self._build_domain_dn()

    def _build_domain_dn(self):
        """Build domain DN from domain name (e.g., 'domain.alt' -> 'DC=domain,DC=alt')"""
        if self.domain:
            parts = self.domain.split('.')
            self.domain_dn = ','.join([f'DC={part}' for part in parts])
        else:
            self.domain_dn = None

    def _build_user_dn(self) -> str:
        """
        Build user DN for binding

        Supports:
        - UPN format: user@domain.alt
        - DN format: CN=User,OU=Users,DC=domain,DC=alt
        - Simple username: user (converted to user@domain)

        Returns:
            User DN or UPN for binding
        """
        # Already a DN (contains comma)
        if ',' in self.username:
            return self.username

        # Already a UPN (contains @)
        if '@' in self.username:
            return self.username

        # Simple username - convert to UPN
        if self.domain:
            return f"{self.username}@{self.domain}"

        return self.username

    def connect(self, retry_count: int = 3, retry_delay: int = 2) -> bool:
        """
        Establish connection to LDAP server with retry logic

        Args:
            retry_count: Number of retry attempts
            retry_delay: Delay between retries in seconds

        Returns:
            True if connected successfully

        Raises:
            LDAPConnectionError: If connection fails after all retries
        """
        last_error = None

        for attempt in range(retry_count):
            try:
                # Create server object
                self.server = ldap3.Server(
                    host=self.host,
                    port=self.port,
                    use_ssl=self.use_tls,
                    get_info=ldap3.ALL,
                    connect_timeout=self.timeout
                )

                # Build user DN/UPN
                user_dn = self._build_user_dn()

                # Create connection
                self.connection = ldap3.Connection(
                    self.server,
                    user=user_dn,
                    password=self.password,
                    auto_bind=True,
                    auto_range=False,
                    raise_exceptions=True,
                    receive_timeout=self.timeout
                )

                self._last_bind_time = datetime.now()

                # Verify connection by reading rootDSE
                if not self.connection.bound:
                    raise LDAPConnectionError("Failed to bind to LDAP server")

                return True

            except ldap3.core.exceptions.LDAPException as e:
                last_error = e
                if attempt < retry_count - 1:
                    time.sleep(retry_delay)
                    continue
                else:
                    raise LDAPConnectionError(f"Failed to connect after {retry_count} attempts: {e}")

            except Exception as e:
                last_error = e
                raise LDAPConnectionError(f"Unexpected error during connection: {e}")

        if last_error:
            raise LDAPConnectionError(f"Connection failed: {last_error}")

        return False

    def disconnect(self):
        """Close LDAP connection"""
        if self.connection:
            try:
                self.connection.unbind()
            except:
                pass
            finally:
                self.connection = None
                self.server = None

    def is_connected(self) -> bool:
        """Check if connection is active"""
        return self.connection is not None and self.connection.bound

    def _ensure_connected(self):
        """Ensure connection is active, reconnect if needed"""
        if not self.is_connected():
            self.connect()

        # Check if connection is stale (older than 5 minutes)
        if self._last_bind_time:
            age = (datetime.now() - self._last_bind_time).total_seconds()
            if age > 300:  # 5 minutes
                # Refresh connection
                try:
                    self.connection.rebind()
                    self._last_bind_time = datetime.now()
                except:
                    # Rebind failed, reconnect
                    self.disconnect()
                    self.connect()

    def search(
        self,
        base_dn: str,
        search_filter: str,
        attributes: List[str] = None,
        scope: str = ldap3.SUBTREE,
        size_limit: int = 0
    ) -> List[Dict[str, Any]]:
        """
        Perform LDAP search; unlimited non-BASE reads consume 500-entry pages.

        Continuation referrals are not followed outside the requested directory.
        Any failed page aborts the entire read rather than returning partial data.

        Args:
            base_dn: Base DN for search
            search_filter: LDAP filter (e.g., '(objectClass=user)')
            attributes: List of attributes to retrieve (None = all)
            scope: Search scope (SUBTREE, LEVEL, BASE)
            size_limit: Maximum number of entries to return (0 = unlimited)

        Returns:
            List of entries as dicts

        Raises:
            LDAPOperationError: If search fails
        """
        self._ensure_connected()

        # Unlimited subtree reads must consume every page. Never return a partial
        # successful-looking list after a size/time limit or a failed later page.
        paged = scope != ldap3.BASE and size_limit == 0
        cookie = None
        entries = []
        original_auto_referrals = self.connection.auto_referrals
        self.connection.auto_referrals = False
        original_auto_range = getattr(self.connection, 'auto_range', True)
        self.connection.auto_range = False
        # ldap3's empty-attribute synthesis deletes the base name for every
        # ranged key, even if it is absent (or already deleted). Explicit range
        # continuations can therefore raise KeyError before we see the response.
        original_empty_attributes = getattr(self.connection, 'empty_attributes', True)
        self.connection.empty_attributes = False
        requested = list(attributes) if isinstance(attributes, (list, tuple)) else [attributes or ldap3.ALL_ATTRIBUTES]
        # Snapshot identity/version with each result so concurrent edits cannot
        # splice different membership lists into one successful response.
        requested += [name for name in ('objectGUID', 'uSNChanged')
                      if name.lower() not in {str(a).lower() for a in requested}]
        try:
            while True:
                options = dict(search_base=base_dn, search_filter=search_filter,
                    search_scope=scope,
                    attributes=requested,
                    size_limit=size_limit)
                if paged:
                    options.update(paged_size=500, paged_cookie=cookie,
                                   paged_criticality=True)
                self.connection.search(**options)
                # False can also mean an empty successful search in ldap3.
                if self.connection.result.get('result') != 0:
                    raise LDAPOperationError(f"Search failed: {self.connection.result}")
                # Range fetches replace connection.result/entries. Preserve the
                # outer page and its cookie BEFORE issuing supplemental BASE reads.
                page_result = deepcopy(self.connection.result)
                page_entries = [self._entry_dict(entry) for entry in self.connection.entries]
                for entry in page_entries:
                    self._complete_ranges(entry)
                    entries.append(entry)
                if not paged:
                    break
                control = page_result.get('controls', {}).get('1.2.840.113556.1.4.319')
                if not control or 'cookie' not in control.get('value', {}):
                    raise LDAPOperationError('Paged search response is missing its cookie control')
                cookie = control['value']['cookie']
                if not cookie:
                    break
            return entries
        except ldap3.core.exceptions.LDAPException as e:
            raise LDAPOperationError(f"Search error: {e}") from e
        finally:
            self.connection.auto_referrals = original_auto_referrals
            self.connection.auto_range = original_auto_range
            self.connection.empty_attributes = original_empty_attributes

    @staticmethod
    def _entry_dict(entry):
        attrs = {}
        for attr in entry.entry_attributes:
            value = entry[attr].value
            if attr.lower() == 'objectguid' and isinstance(value, bytes):
                value = str(uuid.UUID(bytes_le=value))
            elif attr.lower() == 'accountexpires':
                raw = entry[attr].raw_values
                if len(raw) != 1:
                    raise LDAPOperationError('Invalid accountExpires value count')
                value = int(raw[0])
            elif attr.lower() == 'objectsid':
                value = LDAPConnector.format_sid(value)
            attrs[attr] = value
        return {'dn': entry.entry_dn, 'attributes': attrs}

    @staticmethod
    def _range_values(value):
        return value if isinstance(value, list) else ([] if value is None else [value])

    @staticmethod
    def _range_version(entry):
        attrs = {k.lower(): v for k, v in entry['attributes'].items()}
        guid = attrs.get('objectguid')
        version = attrs.get('usnchanged')
        if guid is None or version is None:
            raise LDAPOperationError('Cannot verify ranged read without objectGUID and uSNChanged')
        return str(guid).strip('{}').lower(), str(version)

    def _complete_ranges(self, entry):
        """Strict contiguous ranged retrieval; no partial values escape on failure."""
        attrs = entry['attributes']
        ranged = {}
        for name in list(attrs):
            if ';range=' not in name.lower():
                continue
            match = re.fullmatch(r'([^;]+);range=(\d+)-(\d+|\*)', name, re.I)
            if not match:
                raise LDAPOperationError(f'Malformed LDAP range attribute: {name}')
            base = match[1]
            if base.lower() in ranged:
                raise LDAPOperationError(f'Multiple ranges returned for {base}')
            ranged[base.lower()] = (base, name)
        if not ranged:
            return
        version = self._range_version(entry)
        for base, name in ranged.values():
            for ordinary in list(attrs):
                if ordinary.lower() == base.lower():
                    if self._range_values(attrs[ordinary]):
                        raise LDAPOperationError(f'Ambiguous ordinary and ranged values for {base}')
                    del attrs[ordinary]
            expected_start = 0
            combined = []
            seen = set()
            current = entry
            while True:
                match = re.fullmatch(r'([^;]+);range=(\d+)-(\d+|\*)', name, re.I)
                if not match or match[1].lower() != base.lower() or int(match[2]) != expected_start:
                    raise LDAPOperationError(f'Non-contiguous LDAP range for {base} on {entry["dn"]}')
                values = self._range_values(current['attributes'][name])
                upper = match[3]
                if not values:
                    raise LDAPOperationError(f'Empty LDAP range response for {base}; completeness not confirmed')
                if upper != '*':
                    end = int(upper)
                    if end < expected_start or len(values) != end - expected_start + 1:
                        raise LDAPOperationError(f'Invalid LDAP range length for {base}')
                for value in values:
                    key = (type(value).__name__, repr(value))
                    if key in seen:
                        raise LDAPOperationError(f'Duplicate value across LDAP ranges for {base}')
                    seen.add(key)
                combined.extend(values)
                if current is entry:
                    del attrs[name]
                if upper == '*':
                    break
                expected_start = end + 1
                self.connection.search(search_base=entry['dn'], search_filter='(objectClass=*)',
                    search_scope=ldap3.BASE,
                    attributes=[f'{base};range={expected_start}-*', 'objectGUID', 'uSNChanged'])
                if self.connection.result.get('result') != 0:
                    raise LDAPOperationError(f'LDAP range read failed for {entry["dn"]}: {self.connection.result}')
                responses = list(self.connection.entries)
                if len(responses) != 1:
                    raise LDAPOperationError(f'Object disappeared during ranged read: {entry["dn"]}')
                current = self._entry_dict(responses[0])
                if current['dn'].casefold() != entry['dn'].casefold() or self._range_version(current) != version:
                    raise LDAPOperationError(f'Object changed during ranged read; retry analysis: {entry["dn"]}')
                names = [key for key in current['attributes'] if key.lower().startswith(base.lower() + ';range=')]
                requested_name = f'{base};range={expected_start}-*'.lower()
                if len(names) > 1:
                    # ldap3 empty_attributes can synthesize the requested spelling
                    # beside the server's bounded response. Only ignore that empty
                    # placeholder when another actual range is present.
                    names = [key for key in names if not (
                        key.lower() == requested_name and not self._range_values(current['attributes'][key]))]
                if len(names) != 1:
                    raise LDAPOperationError(f'Missing or ambiguous continuation range for {base}')
                name = names[0]
            attrs[base] = combined

    def list_child_containers(self, parent_dn: str, cancelled=None) -> List[Dict[str, Any]]:
        """Read one level of OU/container children, consuming every LDAP page.

        Keep the server's DN verbatim (names may contain escaped commas). No
        users, memberships or migration state are read or written here. A failed
        page raises instead of presenting a partial branch as a complete one.
        Continuation references (e.g. AD DNS application partitions) are not
        children of this domain tree. Ignore them without following other servers.
        """
        self._ensure_connected()
        original_auto_referrals = self.connection.auto_referrals
        self.connection.auto_referrals = False
        try:
            rows = self.connection.extend.standard.paged_search(
                search_base=parent_dn,
                search_filter='(|(objectClass=organizationalUnit)(objectClass=container))',
                search_scope=ldap3.LEVEL,
                attributes=['name', 'objectClass'],
                paged_size=500,
                generator=True,
            )
            children = []
            for row in rows:
                if cancelled and cancelled():
                    return []
                if row.get('type') == 'searchResRef':
                    continue
                if row.get('type') != 'searchResEntry':
                    continue
                attrs = {k.lower(): v for k, v in row.get('attributes', {}).items()}
                name = attrs.get('name') or row['dn']
                if isinstance(name, list):
                    name = name[0] if name else row['dn']
                classes = attrs.get('objectclass', [])
                if isinstance(classes, str):
                    classes = [classes]
                children.append({
                    'dn': row['dn'], 'name': str(name),
                    'kind': 'ou' if any(c.lower() == 'organizationalunit' for c in classes) else 'container',
                })
            if self.connection.result.get('result', 0) != 0:
                raise LDAPOperationError(f"Cannot load branch: {self.connection.result}")
            return sorted(children, key=lambda row: (row['name'].casefold(), row['dn'].casefold()))
        except ldap3.core.exceptions.LDAPException as e:
            raise LDAPOperationError(f"Cannot load branch {parent_dn}: {e}") from e
        finally:
            self.connection.auto_referrals = original_auto_referrals

    def get_object_by_dn(self, dn: str, attributes: List[str] = None) -> Optional[Dict[str, Any]]:
        """
        Get a single object by DN

        A missing object is a normal, expected outcome here (it is how the migrator
        decides whether a destination object already exists), so "no such object"
        is reported as None rather than raised.

        Args:
            dn: Distinguished Name
            attributes: List of attributes to retrieve

        Returns:
            Entry dict or None if not found
        """
        try:
            results = self.search(
                base_dn=dn,
                search_filter='(objectClass=*)',
                attributes=attributes,
                scope=ldap3.BASE
            )
        except LDAPOperationError as e:
            if self._is_no_such_object(e):
                return None
            raise

        return results[0] if results else None

    def object_exists(self, dn: str) -> bool:
        """
        Check whether an object exists at the given DN

        Args:
            dn: Distinguished Name

        Returns:
            True if the object exists
        """
        return self.get_object_by_dn(dn, attributes=['distinguishedName']) is not None

    @staticmethod
    def format_sid(value) -> Optional[str]:
        """
        Decode a binary objectSid into its usual string form.

        ldap3 has no built-in formatter for objectSid, so it arrives as raw bytes.
        The layout is: revision (1 byte), sub-authority count (1 byte), identifier
        authority (6 bytes, big-endian), then that many sub-authorities (4 bytes
        each, little-endian). The final sub-authority is the RID, which identifies
        built-in principals such as 500 (Administrator) or 512 (Domain Admins)
        regardless of what language the domain names them in.

        Args:
            value: Raw bytes, or an already-decoded string

        Returns:
            'S-1-5-21-...-RID', or None if the value cannot be decoded
        """
        if value is None:
            return None

        # Already decoded (some servers or a previous pass)
        if isinstance(value, str):
            return value if value.startswith('S-') else None

        if not isinstance(value, (bytes, bytearray)):
            return None

        raw = bytes(value)
        if len(raw) < 8:
            return None

        revision = raw[0]
        sub_count = raw[1]
        authority = int.from_bytes(raw[2:8], byteorder='big')

        if len(raw) < 8 + 4 * sub_count:
            return None

        subs = [
            int.from_bytes(raw[8 + 4 * i:12 + 4 * i], byteorder='little')
            for i in range(sub_count)
        ]

        return 'S-%d-%d-%s' % (revision, authority, '-'.join(str(s) for s in subs))

    @staticmethod
    def sid_rid(sid: Optional[str]) -> Optional[int]:
        """
        Extract the trailing RID from a SID string.

        Args:
            sid: SID in 'S-1-5-21-...-RID' form

        Returns:
            The RID as an int, or None if it cannot be parsed
        """
        if not sid or not isinstance(sid, str):
            return None
        try:
            return int(sid.rsplit('-', 1)[1])
        except (IndexError, ValueError):
            return None

    @staticmethod
    def _is_no_such_object(error: Exception) -> bool:
        """
        Detect an LDAP "no such object" condition.

        ldap3 surfaces this either as LDAPNoSuchObjectResult or as a result code in
        the message, depending on how the failure was raised, so both are checked.
        """
        if isinstance(error, ldap3.core.exceptions.LDAPNoSuchObjectResult):
            return True

        text = str(error).lower()
        return 'nosuchobject' in text or 'no such object' in text

    def get_object_by_guid(self, guid: str, base_dn: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        Get object by objectGUID

        Args:
            guid: objectGUID as string
            base_dn: Base DN for search (default: domain DN)

        Returns:
            Entry dict or None if not found
        """
        # Convert GUID string to LDAP filter format
        guid_uuid = uuid.UUID(guid)
        guid_bytes = guid_uuid.bytes_le

        # Build LDAP filter for GUID
        guid_filter = '(objectGUID=' + ''.join(['\\%02x' % b for b in guid_bytes]) + ')'

        results = self.search(
            base_dn=base_dn or self.domain_dn,
            search_filter=guid_filter,
            scope=ldap3.SUBTREE
        )

        return results[0] if results else None

    def add(
        self,
        dn: str,
        object_classes: List[str],
        attributes: Dict[str, Any]
    ) -> bool:
        """
        Add a new LDAP entry

        Args:
            dn: Distinguished Name for new entry
            object_classes: List of objectClass values
            attributes: Dictionary of attributes

        Returns:
            True if successful

        Raises:
            LDAPOperationError: If add fails
        """
        self._ensure_connected()

        try:
            # Add objectClass to attributes
            attrs = dict(attributes)
            attrs['objectClass'] = object_classes

            success = self.connection.add(dn, attributes=attrs)

            if not success:
                result = self.connection.result
                raise LDAPOperationError(
                    f"Add failed for {dn}: {result['description']} - {result.get('message', '')}"
                )

            return True

        except ldap3.core.exceptions.LDAPException as e:
            raise LDAPOperationError(f"Add error for {dn}: {e}")

    def modify(
        self,
        dn: str,
        changes: Dict[str, Any],
        operation: int = ldap3.MODIFY_REPLACE
    ) -> bool:
        """
        Modify an LDAP entry

        Args:
            dn: Distinguished Name
            changes: Dictionary of attribute changes {attr: value}
            operation: MODIFY_REPLACE, MODIFY_ADD, or MODIFY_DELETE

        Returns:
            True if successful

        Raises:
            LDAPOperationError: If modify fails
        """
        self._ensure_connected()

        try:
            # Build changes dict for ldap3
            ldap_changes = {}
            for attr, value in changes.items():
                # Handle multi-valued attributes
                if not isinstance(value, list):
                    value = [value] if value is not None else []

                ldap_changes[attr] = [(operation, value)]

            success = self.connection.modify(dn, ldap_changes)

            if not success:
                result = self.connection.result
                raise LDAPOperationError(
                    f"Modify failed for {dn}: {result['description']} - {result.get('message', '')}"
                )

            return True

        except ldap3.core.exceptions.LDAPException as e:
            raise LDAPOperationError(f"Modify error for {dn}: {e}")

    def modify_add_values(self, dn: str, changes: Dict[str, Any]) -> bool:
        """Add values to multi-valued attributes"""
        return self.modify(dn, changes, ldap3.MODIFY_ADD)

    def modify_delete_values(self, dn: str, changes: Dict[str, Any]) -> bool:
        """Delete values from multi-valued attributes"""
        return self.modify(dn, changes, ldap3.MODIFY_DELETE)

    def delete(self, dn: str) -> bool:
        """
        Delete an LDAP entry

        Args:
            dn: Distinguished Name

        Returns:
            True if successful

        Raises:
            LDAPOperationError: If delete fails
        """
        self._ensure_connected()

        try:
            success = self.connection.delete(dn)

            if not success:
                result = self.connection.result
                raise LDAPOperationError(
                    f"Delete failed for {dn}: {result['description']}"
                )

            return True

        except ldap3.core.exceptions.LDAPException as e:
            raise LDAPOperationError(f"Delete error for {dn}: {e}")

    def test_connection(self) -> Tuple[bool, str]:
        """
        Test LDAP connection

        Returns:
            Tuple of (success: bool, message: str)
        """
        try:
            self.connect()

            # Try to read domain DN
            if self.domain_dn:
                result = self.get_object_by_dn(self.domain_dn, attributes=['distinguishedName'])
                if result:
                    return True, f"Connected to {self.host}:{self.port}"
                else:
                    return False, f"Connected but cannot read domain DN: {self.domain_dn}"
            else:
                return True, f"Connected to {self.host}:{self.port}"

        except LDAPConnectionError as e:
            return False, str(e)
        except Exception as e:
            return False, f"Test failed: {e}"

    def get_domain_info(self) -> Dict[str, Any]:
        """
        Get domain information

        Returns:
            Dict with domain details
        """
        if not self.server or not self.server.info:
            return {}

        info = {
            'naming_contexts': self.server.info.naming_contexts if hasattr(self.server.info, 'naming_contexts') else [],
            'schema_dn': str(self.server.info.schema_entry) if hasattr(self.server.info, 'schema_entry') else None,
            'config_dn': str(self.server.info.other.get('configurationNamingContext', [''])[0]) if hasattr(self.server.info, 'other') else None,
        }

        return info

    def __enter__(self):
        """Context manager entry"""
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.disconnect()


if __name__ == "__main__":
    # Self-test (requires actual LDAP server)
    print("=== LDAPConnector Test ===\n")
    print("Note: This test requires a working LDAP server")
    print("Update credentials below to test\n")

    # Example usage
    test_config = {
        'host': '192.168.1.1',
        'port': 389,
        'domain': 'test.local',
        'username': 'administrator',
        'password': 'Password123',
        'use_tls': False
    }

    print(f"Configuration: {test_config['host']}:{test_config['port']}")
    print("Testing connection...")

    try:
        connector = LDAPConnector(**test_config)
        success, message = connector.test_connection()

        if success:
            print(f"✓ {message}")
            print(f"Domain DN: {connector.domain_dn}")

            # Get domain info
            info = connector.get_domain_info()
            print(f"Domain info: {info}")

        else:
            print(f"✗ {message}")

    except Exception as e:
        print(f"✗ Error: {e}")
