"""
Attribute Mapper
Handles attribute mapping and transformation based on configuration
"""
import yaml
from typing import Dict, Any, List, Optional, Set
from pathlib import Path
from config import settings
import re


class AttributeMapper:
    """
    Maps and transforms attributes based on attribute_mappings.yaml configuration
    """

    def __init__(self, config_file: Optional[Path] = None):
        """
        Initialize attribute mapper

        Args:
            config_file: Path to attribute_mappings.yaml (default: config/attribute_mappings.yaml)
        """
        if config_file is None:
            config_file = Path(__file__).parent.parent / "config" / "attribute_mappings.yaml"

        self.config_file = config_file
        self.config = {}
        self._load_config()

    def _load_config(self):
        """Load configuration from YAML file"""
        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                self.config = yaml.safe_load(f)
        except Exception as e:
            raise RuntimeError(f"Failed to load attribute mappings: {e}")

    def should_copy_attribute(self, attr_name: str, object_type: str) -> bool:
        """
        Check if attribute should be copied for given object type

        Args:
            attr_name: Attribute name
            object_type: Object type (user, group, ou, contact)

        Returns:
            True if attribute should be copied
        """
        # Check global ignore list
        global_ignore = self.config.get('global_ignore_attributes', [])
        if attr_name in global_ignore:
            return False

        # Check if it's an Exchange attribute
        if attr_name.startswith('msExch'):
            return False

        # Get object type configuration
        type_config = self.config.get(object_type, {})
        if not type_config:
            # Unknown object type, be conservative
            return False

        # Check required attributes
        required = type_config.get('required_attributes', [])
        if attr_name in required:
            return True

        # Check optional attributes
        optional = type_config.get('optional_attributes', [])
        if attr_name in optional:
            return True

        # Check reference attributes
        reference = type_config.get('reference_attributes', [])
        if attr_name in reference:
            return True

        # Not in any list, don't copy
        return False

    def get_required_attributes(self, object_type: str) -> List[str]:
        """
        Get required attributes for object type

        Args:
            object_type: Object type

        Returns:
            List of required attribute names
        """
        type_config = self.config.get(object_type, {})
        return type_config.get('required_attributes', [])

    def get_optional_attributes(self, object_type: str) -> List[str]:
        """
        Get optional attributes for object type

        Args:
            object_type: Object type

        Returns:
            List of optional attribute names
        """
        type_config = self.config.get(object_type, {})
        return type_config.get('optional_attributes', [])

    def get_reference_attributes(self, object_type: str) -> List[str]:
        """
        Get reference attributes for object type

        Args:
            object_type: Object type

        Returns:
            List of reference attribute names
        """
        type_config = self.config.get(object_type, {})
        return type_config.get('reference_attributes', [])

    def needs_transformation(self, attr_name: str, object_type: str) -> bool:
        """
        Check if attribute needs transformation

        Args:
            attr_name: Attribute name
            object_type: Object type

        Returns:
            True if transformation is needed
        """
        type_config = self.config.get(object_type, {})
        transform_attrs = type_config.get('transform_attributes', [])
        return attr_name in transform_attrs

    def transform_attribute(
        self,
        attr_name: str,
        value: Any,
        source_domain: str,
        dest_domain: str
    ) -> Any:
        """
        Transform attribute value

        Args:
            attr_name: Attribute name
            value: Attribute value
            source_domain: Source domain (e.g., 'source.alt')
            dest_domain: Destination domain (e.g., 'dest.alt')

        Returns:
            Transformed value
        """
        if value is None:
            return None

        attr_lower = attr_name.lower()

        # Handle multi-valued attributes
        is_list = isinstance(value, list)
        values = value if is_list else [value]

        transformed = []
        for val in values:
            if not val:
                transformed.append(val)
                continue

            val_str = str(val)

            # Transform based on attribute type
            if attr_lower == 'userprincipalname':
                # user@source.alt -> user@dest.alt
                transformed.append(self._transform_upn(val_str, source_domain, dest_domain))

            elif attr_lower == 'mail':
                # Check if it matches source domain
                if source_domain.lower() in val_str.lower():
                    transformed.append(self._transform_email(val_str, source_domain, dest_domain))
                else:
                    # External email, keep as is
                    transformed.append(val)

            elif attr_lower == 'proxyaddresses':
                # SMTP:user@source.alt -> SMTP:user@dest.alt
                transformed.append(self._transform_proxy_address(val_str, source_domain, dest_domain))

            else:
                # No transformation needed
                transformed.append(val)

        # Return in same format as input
        return transformed if is_list else (transformed[0] if transformed else None)

    def _transform_upn(self, upn: str, source_domain: str, dest_domain: str) -> str:
        """
        Transform UPN (userPrincipalName)

        Args:
            upn: UPN value
            source_domain: Source domain
            dest_domain: Destination domain

        Returns:
            Transformed UPN
        """
        # user@source.alt -> user@dest.alt
        if '@' in upn:
            username, domain = upn.rsplit('@', 1)
            if domain.lower() == source_domain.lower():
                return f"{username}@{dest_domain}"

        return upn

    def _transform_email(self, email: str, source_domain: str, dest_domain: str) -> str:
        """
        Transform email address

        Args:
            email: Email address
            source_domain: Source domain
            dest_domain: Destination domain

        Returns:
            Transformed email
        """
        # Same logic as UPN
        return self._transform_upn(email, source_domain, dest_domain)

    def _transform_proxy_address(self, proxy: str, source_domain: str, dest_domain: str) -> str:
        """
        Transform proxyAddresses value

        Args:
            proxy: proxyAddresses value (e.g., 'SMTP:user@source.alt', 'smtp:user@source.alt')
            source_domain: Source domain
            dest_domain: Destination domain

        Returns:
            Transformed proxyAddresses value
        """
        # Format: SMTP:user@domain.alt or smtp:user@domain.alt
        if ':' in proxy:
            prefix, address = proxy.split(':', 1)

            # Transform the address part
            if '@' in address:
                username, domain = address.rsplit('@', 1)
                if domain.lower() == source_domain.lower():
                    return f"{prefix}:{username}@{dest_domain}"

        return proxy

    def filter_attributes(
        self,
        attributes: Dict[str, Any],
        object_type: str
    ) -> Dict[str, Any]:
        """
        Filter attributes to only include those that should be copied

        Args:
            attributes: Dict of all attributes
            object_type: Object type

        Returns:
            Filtered dict of attributes
        """
        filtered = {}

        for attr_name, value in attributes.items():
            if self.should_copy_attribute(attr_name, object_type):
                filtered[attr_name] = value

        return filtered

    def transform_all_attributes(
        self,
        attributes: Dict[str, Any],
        object_type: str,
        source_domain: str,
        dest_domain: str
    ) -> Dict[str, Any]:
        """
        Transform all attributes that need transformation

        Args:
            attributes: Dict of attributes
            object_type: Object type
            source_domain: Source domain
            dest_domain: Destination domain

        Returns:
            Dict with transformed attributes
        """
        transformed = {}

        for attr_name, value in attributes.items():
            if self.needs_transformation(attr_name, object_type):
                transformed[attr_name] = self.transform_attribute(
                    attr_name, value, source_domain, dest_domain
                )
            else:
                transformed[attr_name] = value

        return transformed

    def get_global_settings(self) -> Dict[str, Any]:
        """
        Get global settings from configuration

        Returns:
            Dict with global settings
        """
        return self.config.get('global', {})

    def get_special_rules(self) -> Dict[str, Any]:
        """
        Get special handling rules

        Returns:
            Dict with special rules
        """
        return self.config.get('special_rules', {})


if __name__ == "__main__":
    # Self-test
    print("=== AttributeMapper Test ===\n")

    mapper = AttributeMapper()

    # Test attribute filtering
    print("Testing attribute filtering for 'user' type:")

    test_attrs = {
        'cn': 'John Doe',
        'sn': 'Doe',
        'givenName': 'John',
        'mail': 'john@source.alt',
        'userPrincipalName': 'john@source.alt',
        'objectGUID': 'abc-123',  # Should be filtered out
        'unicodePwd': 'secret',  # Should be filtered out
        'manager': 'CN=Boss,DC=source,DC=alt',
        'msExchMailboxGuid': 'xyz',  # Should be filtered out
    }

    print(f"Input attributes: {list(test_attrs.keys())}")

    filtered = mapper.filter_attributes(test_attrs, 'user')
    print(f"Filtered attributes: {list(filtered.keys())}")

    # Test transformation
    print("\nTesting attribute transformation:")

    test_transform = {
        'userPrincipalName': 'john@source.alt',
        'mail': 'john@source.alt',
        'proxyAddresses': ['SMTP:john@source.alt', 'smtp:john.doe@source.alt'],
    }

    print(f"Before transformation: {test_transform}")

    transformed = mapper.transform_all_attributes(
        test_transform,
        'user',
        'source.alt',
        'dest.alt'
    )

    print(f"After transformation: {transformed}")

    # Test required attributes
    print("\nRequired attributes for 'user':")
    print(mapper.get_required_attributes('user'))

    print("\nReference attributes for 'group':")
    print(mapper.get_reference_attributes('group'))
