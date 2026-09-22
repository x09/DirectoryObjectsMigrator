"""
Base Object Handler
Abstract base class for all object type handlers
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from core.ldap_connector import LDAPConnector
from core.attribute_mapper import AttributeMapper
from utils.logger import MigrationLogger


class ObjectHandler(ABC):
    """
    Abstract base class for object handlers
    Each object type (OU, User, Group, Contact) has its own handler
    """

    def __init__(
        self,
        source_conn: LDAPConnector,
        dest_conn: LDAPConnector,
        attribute_mapper: AttributeMapper,
        logger: MigrationLogger,
        source_domain: str,
        dest_domain: str
    ):
        """
        Initialize object handler

        Args:
            source_conn: Source LDAP connection
            dest_conn: Destination LDAP connection
            attribute_mapper: AttributeMapper instance
            logger: MigrationLogger instance
            source_domain: Source domain (e.g., 'source.alt')
            dest_domain: Destination domain (e.g., 'dest.alt')
        """
        self.source_conn = source_conn
        self.dest_conn = dest_conn
        self.attribute_mapper = attribute_mapper
        self.logger = logger
        self.source_domain = source_domain
        self.dest_domain = dest_domain

    @abstractmethod
    def get_object_type(self) -> str:
        """
        Get object type identifier

        Returns:
            Object type string (ou, user, group, contact)
        """
        pass

    @abstractmethod
    def get_object_classes(self) -> List[str]:
        """
        Get LDAP objectClass values for this object type

        Returns:
            List of objectClass values
        """
        pass

    @abstractmethod
    def create(self, source_entry: Dict[str, Any], dest_dn: str) -> bool:
        """
        Create object in destination

        Args:
            source_entry: Source LDAP entry
            dest_dn: Destination DN

        Returns:
            True if successful

        Raises:
            Exception on error
        """
        pass

    @abstractmethod
    def prepare_attributes(self, source_entry: Dict[str, Any]) -> Dict[str, Any]:
        """
        Prepare attributes for object creation
        Filter, transform, and add any required attributes

        Args:
            source_entry: Source LDAP entry

        Returns:
            Dict of attributes ready for creation
        """
        pass

    def copy_attributes(
        self,
        source_entry: Dict[str, Any],
        dest_dn: str,
        exclude_references: bool = True
    ) -> bool:
        """
        Copy attributes onto an object that already exists.

        Not used by the current pipeline: prepare_attributes() supplies the full
        attribute set to the initial LDAP add, so there is nothing left to patch
        afterwards (see Migrator._phase3_copy_attributes). Kept because it is the
        natural place to handle attributes a directory refuses at create time and
        will only accept on a subsequent modify; if that need arises, call this from
        phase 3 rather than reintroducing a second write path elsewhere.

        Args:
            source_entry: Source LDAP entry
            dest_dn: Destination DN
            exclude_references: Whether to exclude reference attributes

        Returns:
            True if successful, or if there was nothing to copy
        """
        source_attrs = source_entry['attributes']
        object_type = self.get_object_type()

        # Filter attributes
        filtered_attrs = self.attribute_mapper.filter_attributes(source_attrs, object_type)

        # Exclude reference attributes if requested
        if exclude_references:
            ref_attrs = self.attribute_mapper.get_reference_attributes(object_type)
            filtered_attrs = {k: v for k, v in filtered_attrs.items() if k not in ref_attrs}

        # Transform attributes
        transformed_attrs = self.attribute_mapper.transform_all_attributes(
            filtered_attrs,
            object_type,
            self.source_domain,
            self.dest_domain
        )

        # Remove attributes that were already set during creation
        required_attrs = self.attribute_mapper.get_required_attributes(object_type)
        attrs_to_copy = {k: v for k, v in transformed_attrs.items() if k not in required_attrs}

        if not attrs_to_copy:
            return True

        # Modify object in destination
        try:
            self.dest_conn.modify(dest_dn, attrs_to_copy)
            return True
        except Exception as e:
            self.logger.warning(f"Failed to copy some attributes to {dest_dn}: {e}")
            return False

    def get_reference_attributes(self) -> List[str]:
        """
        Get reference attribute names for this object type

        Returns:
            List of reference attribute names
        """
        return self.attribute_mapper.get_reference_attributes(self.get_object_type())

    def extract_reference_values(self, source_entry: Dict[str, Any]) -> Dict[str, List[str]]:
        """
        Extract reference attribute values from source entry

        Args:
            source_entry: Source LDAP entry

        Returns:
            Dict mapping attribute name to list of referenced DNs
        """
        source_attrs = source_entry['attributes']
        ref_attrs = self.get_reference_attributes()

        references = {}
        for attr in ref_attrs:
            if attr in source_attrs:
                value = source_attrs[attr]

                # Ensure it's a list
                if not isinstance(value, list):
                    value = [value] if value else []

                # Filter out empty values
                value = [v for v in value if v]

                if value:
                    references[attr] = value

        return references
