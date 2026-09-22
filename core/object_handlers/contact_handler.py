"""
Contact Handler
Handles creation and migration of Contact objects
"""
from typing import Dict, Any, List
from core.object_handlers.base_handler import ObjectHandler
from core.ldap_connector import LDAPOperationError
from config import settings
import ldap3


class ContactHandler(ObjectHandler):
    """Handler for Contact objects"""

    def get_object_type(self) -> str:
        return settings.OBJECT_TYPE_CONTACT

    def get_object_classes(self) -> List[str]:
        return ['contact']

    def prepare_attributes(self, source_entry: Dict[str, Any]) -> Dict[str, Any]:
        """
        Prepare contact attributes for creation

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

        # Ensure required attributes
        required = self.attribute_mapper.get_required_attributes(object_type)

        prepared = {}
        for attr in required:
            if attr in transformed:
                prepared[attr] = transformed[attr]
            elif attr in source_attrs:
                prepared[attr] = source_attrs[attr]

        # Add optional attributes (exclude references)
        ref_attrs = self.get_reference_attributes()
        for attr, value in transformed.items():
            if attr not in required and attr not in prepared and attr not in ref_attrs:
                prepared[attr] = value

        return prepared

    def create(self, source_entry: Dict[str, Any], dest_dn: str) -> bool:
        """
        Create contact in destination

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
            # Create contact
            success = self.dest_conn.add(
                dn=dest_dn,
                object_classes=object_classes,
                attributes=attributes
            )

            if success:
                self.logger.success(f"Created contact: {dest_dn}")
                return True
            else:
                self.logger.error(f"Failed to create contact: {dest_dn}")
                return False

        except LDAPOperationError as e:
            self.logger.error(f"Error creating contact {dest_dn}: {e}")
            raise


if __name__ == "__main__":
    print("ContactHandler - handles Contact objects")
