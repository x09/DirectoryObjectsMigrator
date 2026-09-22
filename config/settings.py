"""
Application settings and configuration
"""
import os
from pathlib import Path

# Application metadata
APP_NAME = "DirectoryObjectsMigrator"
APP_VERSION = "1.0.0"
APP_AUTHOR = "Anton"
APP_DESCRIPTION = "Active Directory to Samba AD Migration Tool"

# Paths
HOME_DIR = Path.home()
CONFIG_DIR = HOME_DIR / ".config" / APP_NAME
CONFIG_FILE = CONFIG_DIR / f"{APP_NAME}.ini"
DB_FILE = CONFIG_DIR / "migration.db"
LOGS_DIR = CONFIG_DIR / "logs"
REPORTS_DIR = CONFIG_DIR / "reports"

# Locale settings
LOCALE_DIRS = [
    Path("/usr/share/locale"),
    Path(__file__).parent.parent / "locale"
]
DEFAULT_LANGUAGE = "en"
SUPPORTED_LANGUAGES = ["en", "ru"]
TEXTDOMAIN = "DirectoryObjectMigrator"

# LDAP defaults
DEFAULT_LDAP_PORT = 389
DEFAULT_LDAPS_PORT = 636
DEFAULT_USE_TLS = True
DEFAULT_TIMEOUT = 30  # seconds
DEFAULT_BATCH_SIZE = 100

# Password policy defaults
DEFAULT_PASSWORD_LENGTH = 12
DEFAULT_PASSWORD_CHARSET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
PASSWORD_MODE_RANDOM = "random"
PASSWORD_MODE_FIXED = "fixed"
DEFAULT_PASSWORD_MODE = PASSWORD_MODE_RANDOM

# User account defaults
CREATE_USERS_DISABLED = True
TRANSFER_ACCOUNT_DISABLED_FLAG = True
PRIMARY_GROUP_ID = 513  # Domain Users

# Logging defaults
LOG_LEVEL_DEBUG = "DEBUG"
LOG_LEVEL_INFO = "INFO"
LOG_LEVEL_WARNING = "WARNING"
LOG_LEVEL_ERROR = "ERROR"
DEFAULT_LOG_LEVEL = LOG_LEVEL_INFO

# Migration defaults
DEFAULT_DRY_RUN = False

# Object type constants
OBJECT_TYPE_OU = "ou"
OBJECT_TYPE_USER = "user"
OBJECT_TYPE_GROUP = "group"
OBJECT_TYPE_CONTACT = "contact"

# Migration status constants
STATUS_CREATED = "created"
STATUS_UPDATED = "updated"
STATUS_EXISTS = "exists"
STATUS_CONFLICT = "conflict"
STATUS_SKIPPED = "skipped"
STATUS_ERROR = "error"
STATUS_DEFERRED = "deferred"

# Migration run status constants
RUN_STATUS_IN_PROGRESS = "in_progress"
RUN_STATUS_COMPLETED = "completed"
RUN_STATUS_FAILED = "failed"
RUN_STATUS_CANCELLED = "cancelled"

# Conflict types
CONFLICT_TYPE_EXISTS_NOT_TRACKED = "exists_not_tracked"
CONFLICT_TYPE_DN_COLLISION = "dn_collision"
CONFLICT_TYPE_SAM_COLLISION = "sam_collision"

# Error severity levels
SEVERITY_WARNING = "warning"
SEVERITY_ERROR = "error"
SEVERITY_CRITICAL = "critical"

# Migration phases
PHASE_ANALYSIS = "analysis"
PHASE_OU_CREATION = "ou_creation"
PHASE_OBJECT_CREATION = "object_creation"
PHASE_ATTRIBUTES = "attributes"
PHASE_REFERENCES = "references"
PHASE_VERIFICATION = "verification"

# Reference attribute names
ATTR_MEMBER = "member"
ATTR_MANAGER = "manager"
ATTR_MANAGED_BY = "managedBy"
ATTR_MEMBER_OF = "memberOf"
ATTR_DIRECT_REPORTS = "directReports"

# Built-in DN patterns to ignore
IGNORED_DN_PATTERNS = [
    "CN=Builtin,DC=",
    "CN=Users,DC=",
    "CN=Computers,DC=",
    "CN=ForeignSecurityPrincipals,DC=",
    "CN=Managed Service Accounts,DC=",
    "CN=Program Data,DC=",
    "CN=Microsoft Exchange System Objects,DC=",
    "CN=System,DC=",
    "CN=LostAndFound,DC=",
    "CN=Infrastructure,DC=",
    "CN=Configuration,DC=",
    "CN=Schema,CN=Configuration,DC=",
]

# Object classes to ignore
IGNORED_OBJECT_CLASSES = [
    "computer",
    "printQueue",
    "volume",
    "msFVE-RecoveryInformation",
    "rIDManager",
    "rIDSet",
    "secret",
    "trustedDomain",
    "foreignSecurityPrincipal",
    "dnsNode",
    "dnsZone",
    "groupPolicyContainer",
    "site",
    "subnet",
    "siteLink",
    "interSiteTransport",
    "nTDSDSA",
    "nTDSConnection",
    "server",
    "configuration",
]

# Ensure directories exist
def ensure_directories():
    """Create necessary directories if they don't exist"""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

ensure_directories()
