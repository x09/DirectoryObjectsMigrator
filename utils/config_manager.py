"""
Configuration manager
Handles loading/saving application configuration (connections, preferences)
"""
import configparser
from pathlib import Path
from typing import Optional, Dict, Any, List
from config import settings


class ConfigManager:
    """Manages application configuration (INI format)"""

    def __init__(self, config_file: Optional[Path] = None):
        """
        Initialize configuration manager

        Args:
            config_file: Path to config file (default: settings.CONFIG_FILE)
        """
        self.config_file = config_file or settings.CONFIG_FILE
        self.config = configparser.ConfigParser()

        # Create default config if doesn't exist
        if not self.config_file.exists():
            self._create_default_config()
        else:
            self.load()

    def _create_default_config(self):
        """Create default configuration"""
        # Application section
        self.config['Application'] = {
            'language': settings.DEFAULT_LANGUAGE,
            'log_level': settings.DEFAULT_LOG_LEVEL,
        }

        # Source DC section
        self.config['SourceDC'] = {
            'host': '',
            'port': str(settings.DEFAULT_LDAP_PORT),
            'domain': '',
            'username': '',
            'use_tls': str(settings.DEFAULT_USE_TLS),
        }

        # Destination DC section
        self.config['DestinationDC'] = {
            'host': '',
            'port': str(settings.DEFAULT_LDAP_PORT),
            'domain': '',
            'username': '',
            'use_tls': str(settings.DEFAULT_USE_TLS),
        }

        # Migration options section
        self.config['Migration'] = {
            'batch_size': str(settings.DEFAULT_BATCH_SIZE),
            'password_mode': settings.DEFAULT_PASSWORD_MODE,
            'password_length': str(settings.DEFAULT_PASSWORD_LENGTH),
            'fixed_password': '',
            'last_base_dn': '',
        }

        # Operator-defined exclusions: DNs to skip that no automatic rule catches.
        # Service groups created by Windows roles (Access-Denied Assistance Users,
        # DnsAdmins, WinRMRemoteWMIUsers__, ...) carry an ordinary RID and no
        # isCriticalSystemObject flag, so they are indistinguishable from a real
        # departmental group. Only the operator knows which ones are unwanted.
        self.config['Exclusions'] = {
            'dns': '',
        }

        self.save()

    def load(self):
        """Load configuration from file"""
        try:
            self.config.read(self.config_file, encoding='utf-8')
        except Exception as e:
            print(f"Warning: Could not load config: {e}")
            self._create_default_config()

    def save(self):
        """Save configuration to file"""
        try:
            settings.CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            with open(self.config_file, 'w', encoding='utf-8') as f:
                self.config.write(f)
        except Exception as e:
            print(f"Error: Could not save config: {e}")

    # Application settings

    def get_language(self) -> str:
        """Get configured language"""
        return self.config.get('Application', 'language', fallback=settings.DEFAULT_LANGUAGE)

    def set_language(self, language: str):
        """Set language"""
        if not self.config.has_section('Application'):
            self.config.add_section('Application')
        self.config.set('Application', 'language', language)
        self.save()

    def get_log_level(self) -> str:
        """Get configured log level"""
        return self.config.get('Application', 'log_level', fallback=settings.DEFAULT_LOG_LEVEL)

    def set_log_level(self, level: str):
        """Set log level"""
        if not self.config.has_section('Application'):
            self.config.add_section('Application')
        self.config.set('Application', 'log_level', level)
        self.save()

    # Source DC settings

    def get_source_dc_config(self) -> Dict[str, Any]:
        """Get source DC configuration"""
        return {
            'host': self.config.get('SourceDC', 'host', fallback=''),
            'port': self.config.getint('SourceDC', 'port', fallback=settings.DEFAULT_LDAP_PORT),
            'domain': self.config.get('SourceDC', 'domain', fallback=''),
            'username': self.config.get('SourceDC', 'username', fallback=''),
            'use_tls': self.config.getboolean('SourceDC', 'use_tls', fallback=settings.DEFAULT_USE_TLS),
        }

    def set_source_dc_config(self, config: Dict[str, Any]):
        """Set source DC configuration (passwords NOT saved)"""
        if not self.config.has_section('SourceDC'):
            self.config.add_section('SourceDC')

        self.config.set('SourceDC', 'host', config.get('host', ''))
        self.config.set('SourceDC', 'port', str(config.get('port', settings.DEFAULT_LDAP_PORT)))
        self.config.set('SourceDC', 'domain', config.get('domain', ''))
        self.config.set('SourceDC', 'username', config.get('username', ''))
        self.config.set('SourceDC', 'use_tls', str(config.get('use_tls', settings.DEFAULT_USE_TLS)))

        self.save()

    # Destination DC settings

    def get_dest_dc_config(self) -> Dict[str, Any]:
        """Get destination DC configuration"""
        return {
            'host': self.config.get('DestinationDC', 'host', fallback=''),
            'port': self.config.getint('DestinationDC', 'port', fallback=settings.DEFAULT_LDAP_PORT),
            'domain': self.config.get('DestinationDC', 'domain', fallback=''),
            'username': self.config.get('DestinationDC', 'username', fallback=''),
            'use_tls': self.config.getboolean('DestinationDC', 'use_tls', fallback=settings.DEFAULT_USE_TLS),
        }

    def set_dest_dc_config(self, config: Dict[str, Any]):
        """Set destination DC configuration (passwords NOT saved)"""
        if not self.config.has_section('DestinationDC'):
            self.config.add_section('DestinationDC')

        self.config.set('DestinationDC', 'host', config.get('host', ''))
        self.config.set('DestinationDC', 'port', str(config.get('port', settings.DEFAULT_LDAP_PORT)))
        self.config.set('DestinationDC', 'domain', config.get('domain', ''))
        self.config.set('DestinationDC', 'username', config.get('username', ''))
        self.config.set('DestinationDC', 'use_tls', str(config.get('use_tls', settings.DEFAULT_USE_TLS)))

        self.save()

    # Migration settings

    def get_migration_config(self) -> Dict[str, Any]:
        """Get migration configuration"""
        return {
            'batch_size': self.config.getint('Migration', 'batch_size', fallback=settings.DEFAULT_BATCH_SIZE),
            'password_mode': self.config.get('Migration', 'password_mode', fallback=settings.DEFAULT_PASSWORD_MODE),
            'password_length': self.config.getint('Migration', 'password_length', fallback=settings.DEFAULT_PASSWORD_LENGTH),
            'fixed_password': self.config.get('Migration', 'fixed_password', fallback=''),
            'last_base_dn': self.config.get('Migration', 'last_base_dn', fallback=''),
        }

    def set_migration_config(self, config: Dict[str, Any]):
        """Set migration configuration"""
        if not self.config.has_section('Migration'):
            self.config.add_section('Migration')

        if 'batch_size' in config:
            self.config.set('Migration', 'batch_size', str(config['batch_size']))
        if 'password_mode' in config:
            self.config.set('Migration', 'password_mode', config['password_mode'])
        if 'password_length' in config:
            self.config.set('Migration', 'password_length', str(config['password_length']))
        if 'fixed_password' in config:
            self.config.set('Migration', 'fixed_password', config['fixed_password'])
        if 'last_base_dn' in config:
            self.config.set('Migration', 'last_base_dn', config['last_base_dn'])

        self.save()

    def get_last_base_dn(self) -> str:
        """Get last used base DN"""
        return self.config.get('Migration', 'last_base_dn', fallback='')

    def set_last_base_dn(self, base_dn: str):
        """Set last used base DN"""
        if not self.config.has_section('Migration'):
            self.config.add_section('Migration')
        self.config.set('Migration', 'last_base_dn', base_dn)
        self.save()

    # Operator-defined exclusions

    def get_custom_exclusions(self) -> List[str]:
        """
        DNs the operator asked to skip, one per list entry.

        Stored one DN per line under a single INI key. A DN contains commas and
        equals signs, so a comma-separated value would be ambiguous; newline is the
        only separator that cannot occur inside a DN.

        Returns:
            List of DNs with blanks and comment lines removed
        """
        # The Exclusions section was added after initial release. Configs created
        # before the addition will not have it, so synthesise an empty one rather
        # than returning an error or triggering a fallback that writes over the
        # entire file. The section is persisted on the next set_custom_exclusions().
        if not self.config.has_section('Exclusions'):
            return []

        raw = self.config.get('Exclusions', 'dns', fallback='')
        return self._parse_exclusions(raw)

    def set_custom_exclusions(self, dns) -> None:
        """
        Store the operator's exclusion list.

        Args:
            dns: An iterable of DNs, or the raw text straight from the editor
        """
        if isinstance(dns, str):
            entries = self._parse_exclusions(dns)
        else:
            entries = self._parse_exclusions('\n'.join(dns))

        if not self.config.has_section('Exclusions'):
            self.config.add_section('Exclusions')

        # configparser indents continuation lines on read, which _parse_exclusions
        # strips again, so a round trip through the file preserves the list.
        self.config.set('Exclusions', 'dns', '\n'.join(entries))
        self.save()

    @staticmethod
    def _parse_exclusions(raw: str) -> List[str]:
        """
        Turn the multi-line value into a clean DN list.

        Blank lines are dropped, and lines starting with # or ; are treated as
        comments so an operator can annotate the list or disable an entry without
        deleting it.
        """
        entries = []
        for line in (raw or '').splitlines():
            line = line.strip()
            if not line or line[0] in '#;':
                continue
            entries.append(line)
        return entries


if __name__ == "__main__":
    # Self-test
    print("=== ConfigManager Test ===\n")

    cfg = ConfigManager()

    print("Language:", cfg.get_language())
    print("Log level:", cfg.get_log_level())
    print("Source DC:", cfg.get_source_dc_config())
    print("Dest DC:", cfg.get_dest_dc_config())
    print("Migration:", cfg.get_migration_config())

    # Test update
    cfg.set_source_dc_config({
        'host': '192.168.1.1',
        'port': 389,
        'domain': 'source.alt',
        'username': 'administrator',
        'use_tls': True
    })

    print("\nAfter update:")
    print("Source DC:", cfg.get_source_dc_config())

    print(f"\nConfig file: {settings.CONFIG_FILE}")
