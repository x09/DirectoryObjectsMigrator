"""
SQLite database interface for migration tracking
"""
import sqlite3
import json
import threading
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
        self._lock = threading.RLock()
        self._connect()
        self._initialize_schema()
        self._install_locking()

    # Public methods that touch the connection and must be serialized across threads
    _SYNCHRONIZED_METHODS = (
        'create_migration_run', 'update_migration_run', 'get_latest_run', 'get_run_by_id',
        'add_object', 'get_object_by_source_guid', 'get_object_by_source_dn',
        'get_object_by_dest_dn', 'add_deferred_reference', 'get_unresolved_references',
        'mark_reference_resolved', 'update_reference_check', 'add_conflict',
        'get_conflicts', 'log_error', 'get_errors', 'get_statistics', 'close',
        'counts', 'is_empty', 'backup', 'reset', 'vacuum',
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

            # Execute schema (multiple statements)
            self.connection.executescript(schema_sql)
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
                source_base_dn, dest_base_dn, source_dc, dest_dc, status
            ) VALUES (?, ?, ?, ?, ?)
        """, (source_base_dn, dest_base_dn, source_dc, dest_dc, settings.RUN_STATUS_IN_PROGRESS))

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
        cursor.execute("SELECT id, first_migration_run_id FROM migration_map WHERE source_guid = ?", (source_guid,))
        existing = cursor.fetchone()

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
                WHERE source_guid = ?
            """, (source_dn, dest_guid, dest_dn, status, run_id, error_message, source_guid))
        else:
            # Insert new
            cursor.execute("""
                INSERT INTO migration_map (
                    source_guid, source_dn, source_sid, source_sam_account_name,
                    dest_guid, dest_dn, object_type, object_class, status,
                    migration_run_id, first_migration_run_id, error_message
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                source_guid, source_dn, source_sid, source_sam,
                dest_guid, dest_dn, object_type, object_class, status,
                run_id, run_id, error_message
            ))

        self.connection.commit()

    def get_object_by_source_guid(self, source_guid: str) -> Optional[Dict[str, Any]]:
        """Get object mapping by source GUID"""
        cursor = self.connection.cursor()
        cursor.execute("SELECT * FROM migration_map WHERE source_guid = ?", (source_guid,))
        row = cursor.fetchone()
        return dict(row) if row else None

    def get_object_by_source_dn(self, source_dn: str) -> Optional[Dict[str, Any]]:
        """Get object mapping by source DN"""
        cursor = self.connection.cursor()
        cursor.execute("SELECT * FROM migration_map WHERE source_dn = ?", (source_dn,))
        row = cursor.fetchone()
        return dict(row) if row else None

    def get_object_by_dest_dn(self, dest_dn: str) -> Optional[Dict[str, Any]]:
        """Get object mapping by destination DN"""
        cursor = self.connection.cursor()
        cursor.execute("SELECT * FROM migration_map WHERE dest_dn = ?", (dest_dn,))
        row = cursor.fetchone()
        return dict(row) if row else None

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
        cursor = self.connection.cursor()
        cursor.execute("""
            INSERT INTO deferred_references (
                parent_object_guid, parent_object_dn, parent_object_type,
                attribute_name, referenced_source_guid, referenced_source_dn,
                referenced_object_type, created_run_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            parent_guid, parent_dn, parent_type,
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
        cursor = self.connection.cursor()

        if parent_guid:
            cursor.execute("""
                SELECT * FROM deferred_references
                WHERE resolved = 0 AND parent_object_guid = ?
                ORDER BY parent_object_dn, attribute_name
            """, (parent_guid,))
        else:
            cursor.execute("""
                SELECT * FROM deferred_references
                WHERE resolved = 0
                ORDER BY parent_object_dn, attribute_name
            """)

        return [dict(row) for row in cursor.fetchall()]

    def mark_reference_resolved(self, ref_id: int, dest_dn: str, run_id: int):
        """Mark a deferred reference as resolved"""
        cursor = self.connection.cursor()
        cursor.execute("""
            UPDATE deferred_references SET
                resolved = 1,
                resolved_dest_dn = ?,
                resolution_run_id = ?,
                resolution_timestamp = CURRENT_TIMESTAMP
            WHERE id = ?
        """, (dest_dn, run_id, ref_id))
        self.connection.commit()

    def update_reference_check(self, ref_id: int):
        """Update last check timestamp for a deferred reference"""
        cursor = self.connection.cursor()
        cursor.execute("""
            UPDATE deferred_references SET
                check_count = check_count + 1,
                last_check_timestamp = CURRENT_TIMESTAMP
            WHERE id = ?
        """, (ref_id,))
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
            WHERE created_run_id = ? OR resolution_run_id = ?
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
