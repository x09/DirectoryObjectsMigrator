"""
SQLite database interface for migration tracking
"""
import sqlite3
import json
import threading
import re
import hashlib
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple
from config import settings


class MigrationDB:
    """Interface to SQLite migration tracking database"""

    def __init__(self, db_path: Optional[Path] = None):
        """
        Initialize database connection

        Args:
            db_path: Path to database file (default: settings.DB_FILE)
        """
        self.db_path = db_path or settings.DB_FILE
        self.connection = None
        self.direction_id = None  # None is the administrative, all-directions view.
        self._owner = None
        self._lock = threading.RLock()
        self._connect()
        self._initialize_schema()
        self._install_locking()

    # Public methods that touch the connection and must be serialized across threads
    _SYNCHRONIZED_METHODS = (
        'create_migration_run', 'update_migration_run', 'get_latest_run', 'get_run_by_id',
        'add_object', 'get_object_by_source_guid', 'get_object_by_source_dn',
        'get_object_by_dest_dn', 'add_deferred_reference', 'get_unresolved_references',
        'mark_reference_resolved', 'mark_reference_skipped', 'update_reference_check', 'add_conflict',
        'get_conflicts', 'log_error', 'get_errors', 'get_statistics', 'close',
        'counts', 'is_empty', 'backup', 'reset', 'vacuum',
        'for_direction', 'refresh_mapping', 'has_unassigned_history',
        'get_reference_parents_for_run',
    )

    def _install_locking(self):
        """
        Wrap every public DB method so it holds self._lock for its whole body.

        Done once per instance rather than with a decorator on each method, so that
        adding a name to _SYNCHRONIZED_METHODS is the only step needed to protect a
        new method. The lock is re-entrant, so methods may call each other.
        """
        def synchronize(func):
            def wrapper(*args, **kwargs):
                with self._lock:
                    return func(*args, **kwargs)
            wrapper.__name__ = getattr(func, '__name__', 'wrapped')
            wrapper.__doc__ = func.__doc__
            return wrapper

        for name in self._SYNCHRONIZED_METHODS:
            bound = getattr(self, name, None)
            if bound is not None:
                setattr(self, name, synchronize(bound))

    def _connect(self):
        """
        Establish database connection

        check_same_thread=False is required because the migration runs in a QThread
        while the GUI thread reads statistics for reports. Thread safety is provided
        by self._lock, which every public method acquires (see _install_locking).
        """
        self.connection = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self.connection.row_factory = sqlite3.Row  # Enable column access by name

        # Enable foreign keys
        self.connection.execute("PRAGMA foreign_keys = ON")

    def _initialize_schema(self):
        """Create database schema if not exists"""
        schema_file = Path(__file__).parent.parent / "database" / "schema.sql"

        if schema_file.exists():
            with open(schema_file, 'r', encoding='utf-8') as f:
                schema_sql = f.read()

            self._upgrade_direction_schema(schema_sql)

            # Execute schema (multiple statements)
            self.connection.executescript(schema_sql)
            self.connection.commit()

    def _upgrade_direction_schema(self, schema_sql):
        """Upgrade legacy bookkeeping atomically, retaining IDs and a backup."""
        columns = self.connection.execute('PRAGMA table_info(migration_map)').fetchall()
        if not columns or 'direction_id' in {r['name'] for r in columns}:
            return
        self.backup('before_v12_directions_' + datetime.now().strftime('%Y%m%d_%H%M%S_%f'))
        self.connection.execute('PRAGMA foreign_keys = OFF')
        try:
            self.connection.execute('BEGIN IMMEDIATE')
            self.connection.execute("ALTER TABLE migration_runs ADD COLUMN direction_id TEXT NOT NULL DEFAULT ''")
            for table in ('migration_map', 'deferred_references', 'attribute_changes'):
                definition = re.search(r'CREATE TABLE IF NOT EXISTS ' + table + r' \(.*?\n\);', schema_sql, re.S).group()
                self.connection.execute(definition.replace(table + ' (', table + '_v12 (', 1))
                old_cols = [row['name'] for row in self.connection.execute('PRAGMA table_info(' + table + ')')]
                names = ','.join(old_cols)
                self.connection.execute(f'INSERT INTO {table}_v12 ({names}) SELECT {names} FROM {table}')
            for view in ('v_migration_summary', 'v_unresolved_references', 'v_latest_migration'):
                self.connection.execute('DROP VIEW IF EXISTS ' + view)
            for table in ('attribute_changes', 'deferred_references', 'migration_map'):
                self.connection.execute('DROP TABLE ' + table)
            for table in ('migration_map', 'deferred_references', 'attribute_changes'):
                self.connection.execute(f'ALTER TABLE {table}_v12 RENAME TO {table}')
            if self.connection.execute('PRAGMA foreign_key_check').fetchall():
                raise RuntimeError('Legacy migration database contains invalid references; upgrade rolled back')
            self.connection.commit()
        except Exception:
            self.connection.rollback()
            raise
        finally:
            self.connection.execute('PRAGMA foreign_keys = ON')

    def for_direction(self, source_identity, dest_identity, source_domain, dest_domain):
        """Immutable scoped view, sharing the owner's connection and lock.

        Legacy runs can only be attributed when both stored domain names agree.
        Every imported mapping still requires live GUID validation before use.
        Ambiguous/unattributed rows remain quarantined for inspection and backup.
        """
        key = hashlib.sha256(json.dumps([source_identity, dest_identity]).encode()).hexdigest()
        if self.direction_id is not None and self.direction_id != key:
            raise ValueError('Database view belongs to another migration direction')
        with self.connection:
            self.connection.execute('PRAGMA defer_foreign_keys = ON')
            # Do not move legacy maps whose recorded runs disagree on direction.
            self.connection.execute("""
                UPDATE migration_runs SET direction_id=? WHERE direction_id=''
                AND run_id IN (SELECT migration_run_id FROM run_configurations
                    WHERE lower(rtrim(source_domain,'.'))=? AND lower(rtrim(dest_domain,'.'))=?)
            """, (key, source_domain.rstrip('.').lower(), dest_domain.rstrip('.').lower()))
            self.connection.execute("""
                UPDATE migration_map SET direction_id=? WHERE direction_id=''
                AND first_migration_run_id IN (SELECT run_id FROM migration_runs WHERE direction_id=?)
                AND migration_run_id IN (SELECT run_id FROM migration_runs WHERE direction_id=?)
                AND NOT EXISTS (SELECT 1 FROM deferred_references d
                    LEFT JOIN migration_runs r ON r.run_id=d.created_run_id
                    WHERE d.direction_id='' AND d.parent_object_guid=migration_map.source_guid
                    AND coalesce(r.direction_id,'') != ?)
                AND NOT EXISTS (SELECT 1 FROM attribute_changes a
                    LEFT JOIN migration_runs r ON r.run_id=a.migration_run_id
                    WHERE a.direction_id='' AND a.object_guid=migration_map.source_guid
                    AND coalesce(r.direction_id,'') != ?)
            """, (key, key, key, key, key))
            self.connection.execute("""
                UPDATE deferred_references SET direction_id=? WHERE direction_id=''
                AND created_run_id IN (SELECT run_id FROM migration_runs WHERE direction_id=?)
                AND parent_object_guid IN (SELECT source_guid FROM migration_map WHERE direction_id=?)
            """, (key, key, key))
            self.connection.execute("""
                UPDATE attribute_changes SET direction_id=? WHERE direction_id=''
                AND migration_run_id IN (SELECT run_id FROM migration_runs WHERE direction_id=?)
                AND object_guid IN (SELECT source_guid FROM migration_map WHERE direction_id=?)
            """, (key, key, key))
        view = object.__new__(MigrationDB)
        view.db_path = self.db_path
        view.connection = self.connection
        view._lock = self._lock
        view.direction_id = key
        view._owner = self._owner or self
        view._install_locking()
        return view

    def has_unassigned_history(self):
        return bool(self.connection.execute("SELECT 1 FROM migration_map WHERE direction_id='' LIMIT 1").fetchone())

    @staticmethod
    def _guid(value):
        try:
            return str(uuid.UUID(str(value)))
        except (ValueError, TypeError, AttributeError):
            return value

    def _guid_mapping(self, direction, source_guid):
        return self.connection.execute("""SELECT * FROM migration_map WHERE direction_id=?
            AND lower(replace(replace(source_guid,'{',''),'}',''))=?""",
            (direction, self._guid(source_guid))).fetchone()

    def _run_direction(self, run_id):
        row = self.connection.execute('SELECT direction_id FROM migration_runs WHERE run_id=?', (run_id,)).fetchone()
        if row is None:
            raise ValueError('Unknown migration run')
        if self.direction_id is not None and row['direction_id'] != self.direction_id:
            raise ValueError('Run belongs to another migration direction')
        return row['direction_id']

    def refresh_mapping(self, source_guid, source_dn, dest_dn):
        if self.direction_id is None:
            raise ValueError('A direction is required to refresh a mapping')
        existing = self._guid_mapping(self.direction_id, source_guid)
        if existing is None:
            raise ValueError('No mapping in this migration direction')
        source_guid = existing['source_guid']
        self.connection.execute("""UPDATE migration_map SET source_dn=?, dest_dn=?,
            last_seen=CURRENT_TIMESTAMP WHERE direction_id=? AND source_guid=?""",
            (source_dn, dest_dn, self.direction_id, source_guid))
        self.connection.execute("""UPDATE deferred_references SET parent_object_dn=?
            WHERE direction_id=? AND parent_object_guid=? AND resolved=0""",
            (dest_dn, self.direction_id, source_guid))
        self.connection.commit()

    # Tables cleared by reset(), children before parents so foreign keys hold
    _DATA_TABLES = (
        'attribute_changes',
        'deferred_references',
        'conflicts',
        'migration_errors',
        'migration_map',
        'run_configurations',
        'migration_runs',
    )

    def counts(self) -> Dict[str, int]:
        """
        Row count per data table.

        Used to show what a reset would discard, and to confirm afterwards that it
        actually happened.
        """
        result = {}
        cursor = self.connection.cursor()
        for table in self._DATA_TABLES:
            try:
                cursor.execute(f"SELECT COUNT(*) FROM {table}")
                result[table] = cursor.fetchone()[0]
            except sqlite3.Error:
                # Table absent in an older database file
                result[table] = 0
        return result

    def is_empty(self) -> bool:
        """True when the database holds no migration history at all."""
        return all(count == 0 for count in self.counts().values())

    def backup(self, suffix: Optional[str] = None) -> Optional[Path]:
        """
        Copy the database file next to the original before a destructive change.

        Args:
            suffix: Filename suffix; a timestamp is used when omitted

        Returns:
            Path to the backup, or None if the database has no file on disk
        """
        if not self.db_path or not Path(self.db_path).exists():
            return None

        if suffix is None:
            suffix = datetime.now().strftime('%Y%m%d_%H%M%S')

        source = Path(self.db_path)
        target = source.with_name(f"{source.stem}_before_reset_{suffix}{source.suffix}")

        # sqlite3.Connection.backup writes a consistent copy even with an open
        # connection, which shutil.copy cannot guarantee.
        with sqlite3.connect(str(target)) as destination:
            self.connection.backup(destination)

        return target

    def reset(self, make_backup: bool = True) -> Dict[str, Any]:
        """
        Delete all migration history, returning the database to a fresh state.

        Only this tool's own bookkeeping is affected: nothing is read from or written
        to either domain controller. The practical consequence is that objects
        already created in the destination are no longer recognised as migrated, so
        the next run reports them as CONFLICT rather than EXISTS (they are still
        never overwritten). That is the intended way to start over after test runs.

        The schema is recreated rather than the file deleted, so an open connection
        stays valid and callers do not have to reconnect.

        Args:
            make_backup: Copy the file first (default), so a reset is recoverable

        Returns:
            Dict with 'backup_path', 'deleted' (per-table counts) and 'total'
        """
        before = self.counts()
        backup_path = self.backup() if make_backup else None

        cursor = self.connection.cursor()
        # Deferred so the delete order cannot trip a constraint mid-way
        cursor.execute("PRAGMA foreign_keys = OFF")
        try:
            for table in self._DATA_TABLES:
                try:
                    cursor.execute(f"DELETE FROM {table}")
                except sqlite3.Error as e:
                    raise RuntimeError(f"Failed to clear {table}: {e}")

            # Restart AUTOINCREMENT so run_id begins at 1 again
            try:
                cursor.execute("DELETE FROM sqlite_sequence")
            except sqlite3.Error:
                # Absent when no AUTOINCREMENT column has ever been used
                pass

            self.connection.commit()
        finally:
            cursor.execute("PRAGMA foreign_keys = ON")

        # Reclaim the freed pages; must run outside a transaction
        try:
            self.connection.execute("VACUUM")
        except sqlite3.Error:
            pass

        # Recreate anything a partial schema might be missing
        self._initialize_schema()

        return {
            'backup_path': backup_path,
            'deleted': before,
            'total': sum(before.values()),
        }

    def vacuum(self) -> Dict[str, Any]:
        """
        Compact the database file.

        Reclaims unused space left by deleted rows, defragments the file, and
        rebuilds indexes. Safe to run on a database in active use; the only
        consequence is a brief lock while the operation completes.

        Returns:
            Dict with 'size_before', 'size_after', and 'freed' in bytes
        """
        if not self.db_path or not Path(self.db_path).exists():
            return {'size_before': 0, 'size_after': 0, 'freed': 0}

        path = Path(self.db_path)
        size_before = path.stat().st_size

        # VACUUM must run outside a transaction
        self.connection.isolation_level = None
        try:
            self.connection.execute("VACUUM")
        finally:
            self.connection.isolation_level = 'DEFERRED'

        size_after = path.stat().st_size
        freed = size_before - size_after

        return {
            'size_before': size_before,
            'size_after': size_after,
            'freed': freed,
        }

    def close(self):
        """Close database connection (safe to call more than once)"""
        if self._owner is not None:
            return  # Only the owner closes the shared connection.
        if self.connection:
            try:
                self.connection.close()
            finally:
                self.connection = None

    # Migration runs management

    def create_migration_run(
        self,
        source_base_dn: str,
        dest_base_dn: str,
        source_dc: str,
        dest_dc: str,
        config: Dict[str, Any]
    ) -> int:
        """
        Create a new migration run entry

        Args:
            source_base_dn: Source base DN
            dest_base_dn: Destination base DN
            source_dc: Source DC host
            dest_dc: Destination DC host
            config: Configuration dict

        Returns:
            run_id of created run
        """
        cursor = self.connection.cursor()
        cursor.execute("""
            INSERT INTO migration_runs (
                source_base_dn, dest_base_dn, source_dc, dest_dc, status, direction_id
            ) VALUES (?, ?, ?, ?, ?, ?)
        """, (source_base_dn, dest_base_dn, source_dc, dest_dc, settings.RUN_STATUS_IN_PROGRESS, self.direction_id or ''))

        run_id = cursor.lastrowid

        # Store configuration
        cursor.execute("""
            INSERT INTO run_configurations (
                migration_run_id, source_dc_host, source_dc_port, source_domain,
                dest_dc_host, dest_dc_port, dest_domain, use_tls, password_policy, options_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            run_id,
            config.get('source_host'),
            config.get('source_port'),
            config.get('source_domain'),
            config.get('dest_host'),
            config.get('dest_port'),
            config.get('dest_domain'),
            config.get('use_tls', True),
            config.get('password_mode'),
            json.dumps(config.get('options', {}))
        ))

        self.connection.commit()
        return run_id

    def update_migration_run(
        self,
        run_id: int,
        status: Optional[str] = None,
        stats: Optional[Dict[str, int]] = None,
        duration_seconds: Optional[int] = None,
        notes: Optional[str] = None
    ):
        """
        Update migration run statistics

        Args:
            run_id: Run ID to update
            status: Run status (completed/failed/cancelled)
            stats: Statistics dict with keys: objects_analyzed, objects_created, etc.
            duration_seconds: Duration in seconds
            notes: Additional notes
        """
        updates = []
        params = []

        if status:
            updates.append("status = ?")
            params.append(status)

        if stats:
            for key, value in stats.items():
                updates.append(f"{key} = ?")
                params.append(value)

        if duration_seconds is not None:
            updates.append("duration_seconds = ?")
            params.append(duration_seconds)

        if notes:
            updates.append("notes = ?")
            params.append(notes)

        if updates:
            params.append(run_id)
            sql = f"UPDATE migration_runs SET {', '.join(updates)} WHERE run_id = ?"
            self.connection.execute(sql, params)
            self.connection.commit()

    def get_latest_run(self) -> Optional[Dict[str, Any]]:
        """
        Get the latest migration run

        Returns:
            Dict with run details or None
        """
        cursor = self.connection.cursor()
        cursor.execute("""
            SELECT * FROM migration_runs ORDER BY run_id DESC LIMIT 1
        """)
        row = cursor.fetchone()
        return dict(row) if row else None

    def get_run_by_id(self, run_id: int) -> Optional[Dict[str, Any]]:
        """Get migration run by ID"""
        cursor = self.connection.cursor()
        cursor.execute("SELECT * FROM migration_runs WHERE run_id = ?", (run_id,))
        row = cursor.fetchone()
        return dict(row) if row else None

    # Object mapping management

    def add_object(
        self,
        source_guid: str,
        source_dn: str,
        dest_guid: Optional[str],
        dest_dn: Optional[str],
        object_type: str,
        status: str,
        run_id: int,
        source_sid: Optional[str] = None,
        source_sam: Optional[str] = None,
        object_class: Optional[str] = None,
        error_message: Optional[str] = None
    ):
        """
        Add or update object mapping

        Args:
            source_guid: Source objectGUID
            source_dn: Source DN
            dest_guid: Destination objectGUID
            dest_dn: Destination DN
            object_type: Object type (user/group/ou/contact)
            status: Migration status
            run_id: Migration run ID
            source_sid: Source objectSid
            source_sam: Source sAMAccountName
            object_class: Object class
            error_message: Error message if status is error
        """
        cursor = self.connection.cursor()

        # Check if object already exists
        direction = self._run_direction(run_id)
        existing = self._guid_mapping(direction, source_guid)
        source_guid = existing['source_guid'] if existing else self._guid(source_guid)
        dest_guid = self._guid(dest_guid)

        if existing:
            # Update existing
            cursor.execute("""
                UPDATE migration_map SET
                    source_dn = ?,
                    dest_guid = ?,
                    dest_dn = ?,
                    status = ?,
                    last_seen = CURRENT_TIMESTAMP,
                    last_updated = CURRENT_TIMESTAMP,
                    migration_run_id = ?,
                    error_message = ?
                WHERE direction_id=? AND source_guid = ?
            """, (source_dn, dest_guid, dest_dn, status, run_id, error_message, direction, source_guid))
        else:
            # Insert new
            cursor.execute("""
                INSERT INTO migration_map (
                    direction_id, source_guid, source_dn, source_sid, source_sam_account_name,
                    dest_guid, dest_dn, object_type, object_class, status,
                    migration_run_id, first_migration_run_id, error_message
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                direction, source_guid, source_dn, source_sid, source_sam,
                dest_guid, dest_dn, object_type, object_class, status,
                run_id, run_id, error_message
            ))

        self.connection.commit()

    def _find_mapping(self, column, value):
        where = column + '=?'
        if column == 'source_guid':
            where = "lower(replace(replace(source_guid,'{',''),'}',''))=?"
            value = self._guid(value)
        params = [value]
        if self.direction_id is not None:
            where += ' AND direction_id=?'
            params.append(self.direction_id)
        rows = self.connection.execute('SELECT * FROM migration_map WHERE ' + where, params).fetchall()
        if len(rows) > 1:
            raise ValueError('Ambiguous mapping; select a migration direction')
        return dict(rows[0]) if rows else None

    def get_object_by_source_guid(self, source_guid):
        return self._find_mapping('source_guid', source_guid)

    def get_object_by_source_dn(self, source_dn):
        return self._find_mapping('source_dn', source_dn)

    def get_object_by_dest_dn(self, dest_dn):
        return self._find_mapping('dest_dn', dest_dn)

    # Deferred references management

    def add_deferred_reference(
        self,
        parent_guid: str,
        parent_dn: str,
        parent_type: str,
        attribute_name: str,
        referenced_dn: str,
        run_id: int,
        referenced_guid: Optional[str] = None,
        referenced_type: Optional[str] = None
    ):
        """Add a deferred reference"""
        direction = self._run_direction(run_id)
        mapped_parent = self._guid_mapping(direction, parent_guid)
        if mapped_parent is None:
            raise ValueError('No parent mapping in this migration direction')
        parent_guid = mapped_parent['source_guid']
        cursor = self.connection.cursor()
        cursor.execute("""
            INSERT INTO deferred_references (
                direction_id, parent_object_guid, parent_object_dn, parent_object_type,
                attribute_name, referenced_source_guid, referenced_source_dn,
                referenced_object_type, created_run_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            direction, parent_guid, parent_dn, parent_type,
            attribute_name, referenced_guid, referenced_dn,
            referenced_type, run_id
        ))
        self.connection.commit()

    def get_unresolved_references(self, parent_guid: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get unresolved deferred references

        Args:
            parent_guid: Filter by parent object GUID (optional)

        Returns:
            List of unresolved references
        """
        clauses = ["resolved=0", "COALESCE(notes, '') NOT LIKE 'SKIPPED:%'"]
        params = []
        if self.direction_id is not None:
            clauses.append('direction_id=?')
            params.append(self.direction_id)
        if parent_guid:
            clauses.append("lower(replace(replace(parent_object_guid,'{',''),'}',''))=?")
            params.append(self._guid(parent_guid))
        rows = self.connection.execute('SELECT * FROM deferred_references WHERE ' +
            ' AND '.join(clauses) + ' ORDER BY parent_object_dn, attribute_name', params)
        return [dict(row) for row in rows]

    def get_reference_parents_for_run(self, run_id):
        """Parents changed by deferred-reference work, including outside the scope."""
        direction = self._run_direction(run_id)
        rows = self.connection.execute("""
            SELECT DISTINCT parent_object_guid FROM deferred_references
            WHERE direction_id=? AND (created_run_id=? OR resolution_run_id=?)
        """, (direction, run_id, run_id))
        return [row['parent_object_guid'] for row in rows]

    def mark_reference_resolved(self, ref_id: int, dest_dn: str, run_id: int):
        """Mark a deferred reference as resolved"""
        cursor = self.connection.cursor()
        cursor.execute("""
            UPDATE deferred_references SET
                resolved = 1,
                resolved_dest_dn = ?,
                resolution_run_id = ?,
                resolution_timestamp = CURRENT_TIMESTAMP
            WHERE id = ? AND direction_id=?
        """, (dest_dn, run_id, ref_id, self._run_direction(run_id)))
        self.connection.commit()

    def mark_reference_skipped(self, ref_id: int, reason: str, run_id: int):
        """Retain a non-resolved audit row, but remove it from the retry queue.

        The existing notes field records the distinct SKIPPED disposition, so
        older databases need no schema conversion. It is never marked resolved.
        """
        self.connection.execute("""
            UPDATE deferred_references SET notes=?, resolution_run_id=?,
                resolution_timestamp=CURRENT_TIMESTAMP
            WHERE id=? AND direction_id=? AND resolved=0
        """, ('SKIPPED: ' + reason, run_id, ref_id, self._run_direction(run_id)))
        self.connection.commit()

    def update_reference_check(self, ref_id: int):
        """Update last check timestamp for a deferred reference"""
        cursor = self.connection.cursor()
        cursor.execute("""
            UPDATE deferred_references SET
                check_count = check_count + 1,
                last_check_timestamp = CURRENT_TIMESTAMP
            WHERE id = ? AND (? IS NULL OR direction_id=?)
        """, (ref_id, self.direction_id, self.direction_id))
        self.connection.commit()

    # Conflicts management

    def add_conflict(
        self,
        source_dn: str,
        dest_dn: str,
        conflict_type: str,
        run_id: int,
        dest_guid: Optional[str] = None,
        object_type: Optional[str] = None,
        notes: Optional[str] = None
    ):
        """Add a conflict entry"""
        cursor = self.connection.cursor()
        cursor.execute("""
            INSERT INTO conflicts (
                source_dn, dest_dn, dest_guid, object_type,
                conflict_type, detected_run_id, notes
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (source_dn, dest_dn, dest_guid, object_type, conflict_type, run_id, notes))
        self.connection.commit()

    def get_conflicts(self, run_id: Optional[int] = None) -> List[Dict[str, Any]]:
        """Get conflicts, optionally filtered by run_id"""
        cursor = self.connection.cursor()

        if run_id:
            cursor.execute("SELECT * FROM conflicts WHERE detected_run_id = ?", (run_id,))
        else:
            cursor.execute("SELECT * FROM conflicts ORDER BY detected_at DESC")

        return [dict(row) for row in cursor.fetchall()]

    # Errors management

    def log_error(
        self,
        run_id: int,
        severity: str,
        phase: str,
        error_message: str,
        object_dn: Optional[str] = None,
        object_type: Optional[str] = None,
        error_code: Optional[str] = None,
        stack_trace: Optional[str] = None
    ):
        """Log a migration error"""
        cursor = self.connection.cursor()
        cursor.execute("""
            INSERT INTO migration_errors (
                migration_run_id, severity, phase, object_dn, object_type,
                error_code, error_message, stack_trace
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (run_id, severity, phase, object_dn, object_type, error_code, error_message, stack_trace))
        self.connection.commit()

    def get_errors(self, run_id: int, severity: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get errors for a run, optionally filtered by severity"""
        cursor = self.connection.cursor()

        if severity:
            cursor.execute("""
                SELECT * FROM migration_errors
                WHERE migration_run_id = ? AND severity = ?
                ORDER BY error_timestamp
            """, (run_id, severity))
        else:
            cursor.execute("""
                SELECT * FROM migration_errors
                WHERE migration_run_id = ?
                ORDER BY error_timestamp
            """, (run_id,))

        return [dict(row) for row in cursor.fetchall()]

    # Statistics and reporting

    def get_statistics(self, run_id: int) -> Dict[str, Any]:
        """Get comprehensive statistics for a migration run"""
        cursor = self.connection.cursor()

        # Run summary
        cursor.execute("SELECT * FROM migration_runs WHERE run_id = ?", (run_id,))
        run = cursor.fetchone()
        if not run:
            return {}

        stats = dict(run)

        # Object counts by type and status
        cursor.execute("""
            SELECT object_type, status, COUNT(*) as count
            FROM migration_map
            WHERE migration_run_id = ?
            GROUP BY object_type, status
        """, (run_id,))
        stats['objects_by_type_status'] = [dict(row) for row in cursor.fetchall()]

        # Deferred references count
        cursor.execute("""
            SELECT COUNT(*) as total, SUM(CASE WHEN resolved = 1 THEN 1 ELSE 0 END) as resolved
            FROM deferred_references
            WHERE (created_run_id = ? OR resolution_run_id = ?)
              AND COALESCE(notes, '') NOT LIKE 'SKIPPED:%'
        """, (run_id, run_id))
        stats['deferred_references'] = dict(cursor.fetchone())

        # Conflicts count
        cursor.execute("SELECT COUNT(*) as count FROM conflicts WHERE detected_run_id = ?", (run_id,))
        stats['conflicts_count'] = cursor.fetchone()['count']

        # Errors count by severity
        cursor.execute("""
            SELECT severity, COUNT(*) as count
            FROM migration_errors
            WHERE migration_run_id = ?
            GROUP BY severity
        """, (run_id,))
        stats['errors_by_severity'] = [dict(row) for row in cursor.fetchall()]

        return stats

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()


if __name__ == "__main__":
    # Self-test
    print("=== MigrationDB Test ===\n")

    with MigrationDB() as db:
        # Create test run
        run_id = db.create_migration_run(
            source_base_dn="OU=Test,DC=source,DC=alt",
            dest_base_dn="DC=dest,DC=alt",
            source_dc="192.168.1.1",
            dest_dc="192.168.1.2",
            config={'source_host': '192.168.1.1', 'dest_host': '192.168.1.2'}
        )
        print(f"Created migration run: {run_id}")

        # Add test object
        db.add_object(
            source_guid="test-guid-123",
            source_dn="CN=TestUser,OU=Test,DC=source,DC=alt",
            dest_guid="test-guid-456",
            dest_dn="CN=TestUser,OU=Test,DC=dest,DC=alt",
            object_type="user",
            status="created",
            run_id=run_id
        )
        print("Added test object")

        # Get statistics
        stats = db.get_statistics(run_id)
        print(f"\nStatistics: {json.dumps(stats, indent=2, default=str)}")

    print(f"\nDatabase: {settings.DB_FILE}")
