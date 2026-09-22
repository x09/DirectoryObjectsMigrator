"""
User Handler
Handles creation and migration of User objects
"""
from typing import Dict, Any, List
from core.object_handlers.base_handler import ObjectHandler
from core.ldap_connector import LDAPOperationError
from utils.password_generator import PasswordGenerator
from config import settings
import ldap3


class UserHandler(ObjectHandler):
    """Handler for User objects"""

    # userAccountControl bit combinations
    UAC_NORMAL_ACCOUNT = 0x0200          # 512
    UAC_DISABLED_ACCOUNT = 0x0202        # 514 = NORMAL_ACCOUNT | ACCOUNTDISABLE

    def __init__(self, *args, password_mode: str = None, fixed_password: str = None, **kwargs):
        """
        Initialize UserHandler

        Args:
            password_mode: 'random' or 'fixed'
            fixed_password: Fixed password if mode is 'fixed'
        """
        super().__init__(*args, **kwargs)
        self.password_mode = password_mode or settings.DEFAULT_PASSWORD_MODE
        self.fixed_password = fixed_password or ''

    def get_object_type(self) -> str:
        return settings.OBJECT_TYPE_USER

    def get_object_classes(self) -> List[str]:
        return ['user']

    def prepare_attributes(self, source_entry: Dict[str, Any]) -> Dict[str, Any]:
        """
        Prepare user attributes for creation

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

        # userAccountControl is computed here, never copied from source, so the
        # account is disabled from the moment it exists. 0x0002 ACCOUNTDISABLE |
        # 0x0200 NORMAL_ACCOUNT = 514.
        if settings.CREATE_USERS_DISABLED:
            prepared['userAccountControl'] = self.UAC_DISABLED_ACCOUNT
        else:
            prepared['userAccountControl'] = self.UAC_NORMAL_ACCOUNT

        return prepared

    def _generate_password(self) -> str:
        """
        Generate password based on policy

        Returns:
            Password string
        """
        if self.password_mode == settings.PASSWORD_MODE_FIXED and self.fixed_password:
            return self.fixed_password
        else:
            return PasswordGenerator.generate(
                length=settings.DEFAULT_PASSWORD_LENGTH,
                charset=settings.DEFAULT_PASSWORD_CHARSET
            )

    def _set_password(self, dest_dn: str, password: str) -> bool:
        """
        Set user password in destination

        Args:
            dest_dn: Destination DN
            password: Password to set

        Returns:
            True if successful
        """
        try:
            # In LDAP, password is set via unicodePwd attribute (for AD)
            # Format: UTF-16LE encoded, enclosed in quotes
            password_value = f'"{password}"'.encode('utf-16-le')

            self.dest_conn.modify(dest_dn, {'unicodePwd': password_value})
            return True

        except Exception as e:
            self.logger.warning(f"Failed to set password for {dest_dn}: {e}")
            # Try alternative method (userPassword for OpenLDAP/Samba)
            try:
                self.dest_conn.modify(dest_dn, {'userPassword': password})
                return True
            except Exception as e2:
                self.logger.error(f"Failed to set password (both methods) for {dest_dn}: {e2}")
                return False

    def create(self, source_entry: Dict[str, Any], dest_dn: str) -> bool:
        """
        Create user in destination

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
            # Create user object
            success = self.dest_conn.add(
                dn=dest_dn,
                object_classes=object_classes,
                attributes=attributes
            )

            if not success:
                self.logger.error(f"Failed to create user: {dest_dn}")
                return False

            # The account already exists disabled: userAccountControl was part of
            # the add above, so there is no window in which it is enabled.
            self.logger.success(f"Created user (disabled): {dest_dn}")

            # Set password. A failure here is not fatal -- the account is disabled
            # and the administrator has to set the real password anyway.
            password = self._generate_password()
            if self._set_password(dest_dn, password):
                self.logger.debug(f"Password set for {dest_dn}")
            else:
                self.logger.warning(
                    f"User created but password not set, administrator must set "
                    f"one before enabling: {dest_dn}"
                )

            # Set primaryGroupID to 513 (Domain Users)
            try:
                self.dest_conn.modify(dest_dn, {'primaryGroupID': settings.PRIMARY_GROUP_ID})
            except Exception as e:
                self.logger.warning(f"Failed to set primaryGroupID for {dest_dn}: {e}")

            return True

        except LDAPOperationError as e:
            self.logger.error(f"Error creating user {dest_dn}: {e}")
            raise


if __name__ == "__main__":
    print("UserHandler - handles User objects")
    print("Password mode: random or fixed")
    print("Users created in disabled state")
