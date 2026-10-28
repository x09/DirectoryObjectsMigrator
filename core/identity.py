"""Domain-scoped identities and validation of tracked destination objects."""
from utils.i18n import _
import uuid


class MappingValidationError(Exception):
    pass


def guid_text(value):
    if isinstance(value, bytes):
        return str(uuid.UUID(bytes_le=value))
    try:
        return str(uuid.UUID(str(value).strip('{}')))
    except (ValueError, TypeError, AttributeError):
        raise MappingValidationError(_('Missing or invalid objectGUID; identity cannot be verified'))


def domain_identity(conn):
    entry = conn.get_object_by_dn(conn.domain_dn, attributes=['objectGUID'])
    if not entry:
        raise MappingValidationError(f'Cannot read domain identity: {conn.domain_dn}')
    return guid_text(entry['attributes'].get('objectGUID'))


def validate_destination(conn, mapping):
    """Resolve a tracked object by GUID, including moves, without adopting names."""
    expected = guid_text(mapping.get('dest_guid'))
    entry = conn.get_object_by_dn(mapping['dest_dn'], attributes=['objectGUID', 'objectClass']) if mapping.get('dest_dn') else None
    if entry is None or guid_text(entry['attributes'].get('objectGUID')) != expected:
        entry = conn.get_object_by_guid(expected, base_dn=conn.domain_dn)
    if entry is None or guid_text(entry['attributes'].get('objectGUID')) != expected:
        raise MappingValidationError(_('Tracked destination object is missing or replaced; automatic recreation is blocked'))
    required = {'ou': 'organizationalunit', 'user': 'user', 'group': 'group', 'contact': 'contact'}[mapping['object_type']]
    classes = entry['attributes'].get('objectClass', [])
    if isinstance(classes, str):
        classes = [classes]
    classes = {str(c).lower() for c in classes}
    if required not in classes or (required == 'user' and 'computer' in classes):
        raise MappingValidationError(_('Tracked destination object has an unexpected object class'))
    return entry['dn']
