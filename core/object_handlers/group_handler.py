"""
Group Handler
Handles creation and migration of Group objects
"""
from typing import Dict, Any, List
from core.object_handlers.base_handler import ObjectHandler
from core.ldap_connector import LDAPOperationError
from config import settings
import ldap3


class GroupHandler(ObjectHandler):
    """Handler for Group objects"""

    def get_object_type(self) -> str:
        return settings.OBJECT_TYPE_GROUP

    def get_object_classes(self) -> List[str]:
        return ['group']

    def prepare_attributes(self, source_entry: Dict[str, Any]) -> Dict[str, Any]:
        """
        Prepare group attributes for creation

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

        # Ensure groupType is present
        if 'groupType' not in prepared and 'groupType' in source_attrs:
            prepared['groupType'] = source_attrs['groupType']

        return prepared

    def create(self, source_entry: Dict[str, Any], dest_dn: str) -> bool:
        """
        Create group in destination

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
            # Create group
            success = self.dest_conn.add(
                dn=dest_dn,
                object_classes=object_classes,
                attributes=attributes
            )

            if success:
                self.logger.success(f"Created group: {dest_dn}")
                return True
            else:
                self.logger.error(f"Failed to create group: {dest_dn}")
                return False

        except LDAPOperationError as e:
            self.logger.error(f"Error creating group {dest_dn}: {e}")
            raise

    def add_members(self, dest_dn: str, member_dns: List[str]) -> int:
        """
        Add members to group

        Args:
            dest_dn: Group DN in destination
            member_dns: List of member DNs to add

        Returns:
            Number of members successfully added
        """
        if not member_dns:
            return 0

        added_count = 0

        try:
            # Try to add all members at once
            self.dest_conn.modify_add_values(dest_dn, {'member': member_dns})
            added_count = len(member_dns)
            self.logger.debug(f"Added {added_count} members to {dest_dn}")

        except Exception as e:
            # If batch add fails, try one by one
            self.logger.warning(f"Batch member add failed for {dest_dn}, trying individually: {e}")

            for member_dn in member_dns:
                try:
                    self.dest_conn.modify_add_values(dest_dn, {'member': [member_dn]})
                    added_count += 1
                except Exception as e2:
                    self.logger.warning(f"Failed to add member {member_dn} to {dest_dn}: {e2}")

        return added_count


if __name__ == "__main__":
    print("GroupHandler - handles Group objects")
    print("Supports adding members after creation")
