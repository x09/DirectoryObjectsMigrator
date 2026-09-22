"""
OU Handler
Handles creation and migration of Organizational Units
"""
from typing import Dict, Any, List
from core.object_handlers.base_handler import ObjectHandler
from core.ldap_connector import LDAPOperationError
from config import settings
import ldap3


class OUHandler(ObjectHandler):
    """Handler for Organizational Unit objects"""

    def get_object_type(self) -> str:
        return settings.OBJECT_TYPE_OU

    def get_object_classes(self) -> List[str]:
        return ['organizationalUnit']

    def prepare_attributes(self, source_entry: Dict[str, Any]) -> Dict[str, Any]:
        """
        Prepare OU attributes for creation

        Args:
            source_entry: Source LDAP entry

        Returns:
            Dict of attributes
        """
        source_attrs = source_entry['attributes']
        object_type = self.get_object_type()

        # Filter attributes
        filtered = self.attribute_mapper.filter_attributes(source_attrs, object_type)

        # Transform attributes
        transformed = self.attribute_mapper.transform_all_attributes(
            filtered,
            object_type,
            self.source_domain,
            self.dest_domain
        )

        # Ensure required attributes are present
        required = self.attribute_mapper.get_required_attributes(object_type)

        prepared = {}
        for attr in required:
            if attr in transformed:
                prepared[attr] = transformed[attr]
            elif attr in source_attrs:
                prepared[attr] = source_attrs[attr]

        # Add optional attributes
        for attr, value in transformed.items():
            if attr not in required and attr not in prepared:
                prepared[attr] = value

        # Exclude reference attributes (will be set later)
        ref_attrs = self.get_reference_attributes()
        prepared = {k: v for k, v in prepared.items() if k not in ref_attrs}

        return prepared

    def create(self, source_entry: Dict[str, Any], dest_dn: str) -> bool:
        """
        Create OU in destination

        Args:
            source_entry: Source LDAP entry
            dest_dn: Destination DN

        Returns:
            True if successful

        Raises:
            LDAPOperationError: If creation fails
        """
        # Prepare attributes
        attributes = self.prepare_attributes(source_entry)

        # Get objectClass
        object_classes = self.get_object_classes()

        try:
            # Create OU
            success = self.dest_conn.add(
                dn=dest_dn,
                object_classes=object_classes,
                attributes=attributes
            )

            if success:
                self.logger.success(f"Created OU: {dest_dn}")
                return True
            else:
                self.logger.error(f"Failed to create OU: {dest_dn}")
                return False

        except LDAPOperationError as e:
            self.logger.error(f"Error creating OU {dest_dn}: {e}")
            raise


if __name__ == "__main__":
    print("OUHandler - handles Organizational Unit objects")
