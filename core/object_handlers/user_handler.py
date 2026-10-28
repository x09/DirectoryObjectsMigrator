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
import re


class UserHandler(ObjectHandler):
    """Handler for User objects"""

    # userAccountControl bit combinations
    UAC_NORMAL_ACCOUNT = 0x0200          # 512
    UAC_DISABLED_ACCOUNT = 0x0202        # 514 = NORMAL_ACCOUNT | ACCOUNTDISABLE

    def __init__(self, *args, password_mode: str = None, fixed_password: str = None, password_length: int = None, **kwargs):
        """
        Initialize UserHandler

        Args:
            password_mode: 'random' or 'fixed'
            fixed_password: Fixed password if mode is 'fixed'
        """
        super().__init__(*args, **kwargs)
        self.password_mode = password_mode or settings.DEFAULT_PASSWORD_MODE
        self.fixed_password = fixed_password or ''
        self.password_length = max(settings.DEFAULT_PASSWORD_POLICY['minimum_length'],
                                   password_length or settings.DEFAULT_PASSWORD_LENGTH)
        self.password_events = []
        self.password_failed = False
        self._minimum_length = None

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

    def _event(self, severity, message):
        self.password_events.append((severity, message))
        getattr(self.logger, severity)(message)

    def _random_password(self, source_entry):
        if self._minimum_length is None:
            self._minimum_length = settings.DEFAULT_PASSWORD_POLICY['minimum_length']
            try:
                root = self.dest_conn.get_object_by_dn(self.dest_conn.domain_dn,
                                                      attributes=['minPwdLength'])
                value = root['attributes'].get('minPwdLength') if root else None
                if isinstance(value, list):
                    value = value[0] if value else None
                if value is not None:
                    self._minimum_length = max(self._minimum_length, int(value))
            except Exception:
                self._event('warning', 'Cannot read destination minimum password length; using configured defaults')
        attrs = source_entry.get('attributes', {})
        tokens = [str(attrs.get('sAMAccountName', ''))]
        for key in ('displayName', 'cn', 'givenName', 'sn'):
            tokens.extend(re.split(r'[\s,._#-]+', str(attrs.get(key, ''))))
        return PasswordGenerator.generate_compliant(
            length=max(self.password_length, self._minimum_length), forbidden=tokens)

    def _generate_password(self) -> str:
        """Compatibility helper; account-aware creation uses configure_password."""
        if self.password_mode == settings.PASSWORD_MODE_FIXED and self.fixed_password:
            return self.fixed_password
        return self._random_password({})

    def _set_password(self, dest_dn: str, password: str) -> bool:
        """Set the AD password only; never bypass rejection using userPassword."""
        try:
            value = ('"' + password + '"').encode('utf-16-le')
            if self.dest_conn.modify(dest_dn, {'unicodePwd': value}) is not True:
                raise LDAPOperationError('LDAP modify returned False')
            return True
        except Exception as exc:
            # Exception text may embed submitted values. Log only recognized LDAP
            # categories, never the message, password or encoded password bytes.
            description = type(exc).__name__
            for category in ('constraintViolation', 'insufficientAccessRights',
                             'unwillingToPerform', 'unavailable', 'strongerAuthRequired'):
                if category.lower() in str(exc).lower():
                    description += ': ' + category
                    break
            self._event('warning', f'Password rejected or not confirmed for {dest_dn}: {description}')
            return False

    def configure_password(self, source_entry, dest_dn):
        self.password_events = []
        self.password_failed = False
        try:
            initial = (self.fixed_password if self.password_mode == settings.PASSWORD_MODE_FIXED
                       and self.fixed_password else self._random_password(source_entry))
            if self._set_password(dest_dn, initial):
                self._event('info', f'Password accepted by destination for {dest_dn}')
                return True
            self._event('warning', f'Trying a new random password for {dest_dn}, even if a fixed password was selected')
            for attempt in range(settings.PASSWORD_RANDOM_RETRIES):
                password = self._random_password(source_entry)
                if password == initial:
                    continue
                if self._set_password(dest_dn, password):
                    self._event('warning', f'Random fallback password accepted for {dest_dn}; the configured password must not be assumed to apply')
                    return True
        except Exception as exc:
            self._event('warning', f'Password generation/setup failed for {dest_dn}: {type(exc).__name__}')
        self.password_failed = True
        self._event('error', f'Password was not confirmed for {dest_dn}; administrator must reset it before enabling the account')
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
        self.password_events = []
        self.password_failed = False
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

            self.configure_password(source_entry, dest_dn)

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
