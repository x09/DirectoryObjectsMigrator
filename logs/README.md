# Not the log directory

Runtime logs are **not** written here. They go to the user's config directory so
that the application does not need write access to its own installation path:

    ~/.config/DirectoryObjectMigrator/logs/migration_YYYYMMDD_HHMMSS.log

Related locations:

| Contents | Path |
|---|---|
| Logs | `~/.config/DirectoryObjectMigrator/logs/` |
| Migration database | `~/.config/DirectoryObjectMigrator/migration.db` |
| Reports (HTML/TXT) | `~/.config/DirectoryObjectMigrator/reports/` |
| Connection settings | `~/.config/DirectoryObjectMigrator/DirectoryObjectMigrator.ini` |

This directory is kept only so the paths above are documented somewhere obvious.
