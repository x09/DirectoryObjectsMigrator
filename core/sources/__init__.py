"""Source-specific connections. Destination remains Active Directory."""
from core.ldap_connector import LDAPConnector


def source_connector_class(provider):
    if provider == 'ad':
        return LDAPConnector
    if provider == 'freeipa':
        from .freeipa import FreeIPAConnector
        return FreeIPAConnector
    raise ValueError('Unknown source type: ' + str(provider))
