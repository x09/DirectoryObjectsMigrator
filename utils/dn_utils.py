"""
Distinguished Name (DN) utilities
Parsing, manipulation, and transformation of LDAP DNs
"""
import re
from typing import List, Tuple, Optional


class DNUtils:
    """Utilities for working with LDAP Distinguished Names"""

    # Regex pattern for DN parsing (simplified, handles most common cases)
    DN_COMPONENT_PATTERN = re.compile(r'(?:[^,\\]|\\.)+')

    @staticmethod
    def parse_dn(dn: str) -> List[Tuple[str, str]]:
        """
        Parse a DN string into components

        Args:
            dn: Distinguished Name string (e.g., "CN=user,OU=IT,DC=domain,DC=com")

        Returns:
            List of tuples [(attribute_type, value), ...]
            Example: [('CN', 'user'), ('OU', 'IT'), ('DC', 'domain'), ('DC', 'com')]
        """
        if not dn:
            return []

        components = []
        parts = dn.split(',')

        for part in parts:
            part = part.strip()
            if '=' in part:
                attr_type, attr_value = part.split('=', 1)
                attr_type = attr_type.strip().upper()
                attr_value = attr_value.strip()

                # Remove quotes if present
                if attr_value.startswith('"') and attr_value.endswith('"'):
                    attr_value = attr_value[1:-1]

                components.append((attr_type, attr_value))

        return components

    @staticmethod
    def build_dn(components: List[Tuple[str, str]]) -> str:
        """
        Build a DN string from components

        Args:
            components: List of tuples [(attribute_type, value), ...]

        Returns:
            DN string
        """
        return ','.join([f"{attr_type}={value}" for attr_type, value in components])

    @staticmethod
    def get_rdn(dn: str) -> str:
        """
        Get the Relative Distinguished Name (leftmost component)

        Args:
            dn: Full DN string

        Returns:
            RDN (e.g., "CN=user" from "CN=user,OU=IT,DC=domain,DC=com")
        """
        if not dn:
            return ""

        # Find first unescaped comma
        parts = dn.split(',', 1)
        return parts[0].strip() if parts else ""

    @staticmethod
    def get_parent_dn(dn: str) -> str:
        """
        Get the parent DN (everything after the first comma)

        Args:
            dn: Full DN string

        Returns:
            Parent DN (e.g., "OU=IT,DC=domain,DC=com" from "CN=user,OU=IT,DC=domain,DC=com")
        """
        if not dn:
            return ""

        parts = dn.split(',', 1)
        return parts[1].strip() if len(parts) > 1 else ""

    @staticmethod
    def get_depth(dn: str) -> int:
        """
        Calculate the depth of a DN (number of components)

        Args:
            dn: DN string

        Returns:
            Depth (number of comma-separated components)
        """
        if not dn:
            return 0

        # Count commas (rough approximation, good enough for sorting)
        return dn.count(',') + 1

    @staticmethod
    def convert_dn(source_dn: str, source_domain_dn: str, dest_domain_dn: str) -> str:
        """
        Convert DN from source domain to destination domain

        Args:
            source_dn: DN in source domain (e.g., "CN=user,OU=IT,DC=source,DC=alt")
            source_domain_dn: Source domain DN (e.g., "DC=source,DC=alt")
            dest_domain_dn: Destination domain DN (e.g., "DC=dest,DC=alt")

        Returns:
            DN in destination domain (e.g., "CN=user,OU=IT,DC=dest,DC=alt")
        """
        if not source_dn:
            return ""

        # Simple string replacement
        # Note: This assumes source_domain_dn only appears at the end
        if source_dn.endswith(source_domain_dn):
            prefix = source_dn[:-len(source_domain_dn)]
            if prefix.endswith(','):
                prefix = prefix[:-1]
            return f"{prefix},{dest_domain_dn}" if prefix else dest_domain_dn

        # If not a direct match, try case-insensitive
        source_dn_upper = source_dn.upper()
        source_domain_dn_upper = source_domain_dn.upper()

        if source_dn_upper.endswith(source_domain_dn_upper):
            # Find the actual position (case-insensitive)
            pos = source_dn_upper.rfind(source_domain_dn_upper)
            prefix = source_dn[:pos]
            if prefix.endswith(','):
                prefix = prefix[:-1]
            return f"{prefix},{dest_domain_dn}" if prefix else dest_domain_dn

        # Fallback: couldn't convert
        return source_dn

    @staticmethod
    def extract_cn(dn: str) -> Optional[str]:
        """
        Extract the CN value from a DN

        Args:
            dn: DN string

        Returns:
            CN value or None if not found
        """
        components = DNUtils.parse_dn(dn)
        for attr_type, value in components:
            if attr_type == 'CN':
                return value
        return None

    @staticmethod
    def extract_domain_dn(dn: str) -> Optional[str]:
        """
        Extract the domain DN (DC components only) from a full DN

        Args:
            dn: Full DN

        Returns:
            Domain DN (e.g., "DC=domain,DC=com") or None
        """
        components = DNUtils.parse_dn(dn)
        dc_components = [(attr_type, value) for attr_type, value in components if attr_type == 'DC']

        if dc_components:
            return DNUtils.build_dn(dc_components)
        return None

    @staticmethod
    def is_child_of(child_dn: str, parent_dn: str) -> bool:
        """
        Check if child_dn is a child (or descendant) of parent_dn

        Args:
            child_dn: Potential child DN
            parent_dn: Parent DN to check against

        Returns:
            True if child_dn is under parent_dn
        """
        if not child_dn or not parent_dn:
            return False

        # Normalize to uppercase for comparison
        child_upper = child_dn.upper()
        parent_upper = parent_dn.upper()

        # Check if parent_dn appears at the end of child_dn
        return child_upper.endswith(parent_upper) and child_dn != parent_dn

    @staticmethod
    def escape_dn_value(value: str) -> str:
        """
        Escape special characters in a DN value

        Args:
            value: Raw value

        Returns:
            Escaped value suitable for DN
        """
        # Escape special characters according to RFC 4514
        special_chars = [',', '\\', '#', '+', '<', '>', ';', '"', '=']

        escaped = value
        for char in special_chars:
            escaped = escaped.replace(char, '\\' + char)

        # Escape leading/trailing spaces
        if escaped.startswith(' '):
            escaped = '\\' + escaped
        if escaped.endswith(' '):
            escaped = escaped[:-1] + '\\ '

        return escaped

    @staticmethod
    def normalize_dn(dn: str) -> str:
        """
        Normalize a DN for comparison (uppercase, trimmed spaces)

        Args:
            dn: DN string

        Returns:
            Normalized DN
        """
        if not dn:
            return ""

        # Parse and rebuild to normalize spacing
        components = DNUtils.parse_dn(dn)
        return DNUtils.build_dn(components).upper()

    @staticmethod
    def compare_dn(dn1: str, dn2: str) -> bool:
        """
        Compare two DNs for equality (case-insensitive, normalized)

        Args:
            dn1: First DN
            dn2: Second DN

        Returns:
            True if DNs are equivalent
        """
        return DNUtils.normalize_dn(dn1) == DNUtils.normalize_dn(dn2)


if __name__ == "__main__":
    # Self-test
    test_dn = "CN=John Doe,OU=Users,OU=IT,DC=source,DC=alt"

    print(f"Test DN: {test_dn}")
    print(f"Parsed: {DNUtils.parse_dn(test_dn)}")
    print(f"RDN: {DNUtils.get_rdn(test_dn)}")
    print(f"Parent: {DNUtils.get_parent_dn(test_dn)}")
    print(f"Depth: {DNUtils.get_depth(test_dn)}")
    print(f"CN: {DNUtils.extract_cn(test_dn)}")
    print(f"Domain DN: {DNUtils.extract_domain_dn(test_dn)}")

    converted = DNUtils.convert_dn(test_dn, "DC=source,DC=alt", "DC=dest,DC=alt")
    print(f"Converted: {converted}")

    print(f"Is child of 'OU=IT,DC=source,DC=alt': {DNUtils.is_child_of(test_dn, 'OU=IT,DC=source,DC=alt')}")
