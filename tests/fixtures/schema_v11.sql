-- Directory Objects Migrator - SQLite Schema
-- Migration tracking database

-- Migration runs tracking
CREATE TABLE IF NOT EXISTS migration_runs (
    run_id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    source_base_dn TEXT NOT NULL,
    dest_base_dn TEXT NOT NULL,
    source_dc TEXT,
    dest_dc TEXT,
    status TEXT DEFAULT 'in_progress', -- 'in_progress', 'completed', 'failed', 'cancelled'
    objects_analyzed INTEGER DEFAULT 0,
    objects_created INTEGER DEFAULT 0,
    objects_updated INTEGER DEFAULT 0,
    objects_skipped INTEGER DEFAULT 0,
    objects_conflicted INTEGER DEFAULT 0,
    errors_count INTEGER DEFAULT 0,
    duration_seconds INTEGER,
    notes TEXT
);

-- Main migration mapping table
CREATE TABLE IF NOT EXISTS migration_map (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    -- Source object identification
    source_guid TEXT UNIQUE NOT NULL,
    source_dn TEXT NOT NULL,
    source_sid TEXT,
    source_sam_account_name TEXT,

    -- Destination object identification
    dest_guid TEXT,
    dest_dn TEXT,
    dest_sid TEXT,

    -- Object metadata
    object_type TEXT NOT NULL, -- 'user', 'group', 'ou', 'contact'
    object_class TEXT,

    -- Migration status
    status TEXT NOT NULL, -- 'created', 'updated', 'exists', 'conflict', 'skipped', 'error'

    -- Timestamps
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_updated TIMESTAMP,

    -- Migration tracking
    migration_run_id INTEGER,
    first_migration_run_id INTEGER,

    -- Additional info
    error_message TEXT,
    notes TEXT,

    FOREIGN KEY (migration_run_id) REFERENCES migration_runs(run_id),
    FOREIGN KEY (first_migration_run_id) REFERENCES migration_runs(run_id)
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_migration_map_source_guid ON migration_map(source_guid);
CREATE INDEX IF NOT EXISTS idx_migration_map_dest_guid ON migration_map(dest_guid);
CREATE INDEX IF NOT EXISTS idx_migration_map_source_dn ON migration_map(source_dn);
CREATE INDEX IF NOT EXISTS idx_migration_map_dest_dn ON migration_map(dest_dn);
CREATE INDEX IF NOT EXISTS idx_migration_map_object_type ON migration_map(object_type);
CREATE INDEX IF NOT EXISTS idx_migration_map_status ON migration_map(status);
CREATE INDEX IF NOT EXISTS idx_migration_map_run_id ON migration_map(migration_run_id);

-- Deferred references (for objects outside migration scope)
CREATE TABLE IF NOT EXISTS deferred_references (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    -- Parent object (the one that has the reference)
    parent_object_guid TEXT NOT NULL,
    parent_object_dn TEXT NOT NULL,
    parent_object_type TEXT NOT NULL,

    -- Reference attribute details
    attribute_name TEXT NOT NULL, -- 'member', 'manager', 'managedBy'
    attribute_syntax TEXT, -- 'DN', 'DN-Binary', etc.

    -- Referenced object (the target that's not yet migrated)
    referenced_source_guid TEXT,
    referenced_source_dn TEXT NOT NULL,
    referenced_object_type TEXT,

    -- Resolution tracking
    resolved BOOLEAN DEFAULT 0,
    resolved_dest_dn TEXT,
    resolution_run_id INTEGER,
    resolution_timestamp TIMESTAMP,

    -- Creation tracking
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_run_id INTEGER,

    -- Attempts tracking
    check_count INTEGER DEFAULT 0,
    last_check_timestamp TIMESTAMP,

    notes TEXT,

    FOREIGN KEY (parent_object_guid) REFERENCES migration_map(source_guid),
    FOREIGN KEY (created_run_id) REFERENCES migration_runs(run_id),
    FOREIGN KEY (resolution_run_id) REFERENCES migration_runs(run_id)
);

-- Indexes for deferred references
CREATE INDEX IF NOT EXISTS idx_deferred_parent_guid ON deferred_references(parent_object_guid);
CREATE INDEX IF NOT EXISTS idx_deferred_referenced_guid ON deferred_references(referenced_source_guid);
CREATE INDEX IF NOT EXISTS idx_deferred_resolved ON deferred_references(resolved);
CREATE INDEX IF NOT EXISTS idx_deferred_attribute ON deferred_references(attribute_name);

-- Attribute changes log (for detailed tracking)
CREATE TABLE IF NOT EXISTS attribute_changes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    object_guid TEXT NOT NULL,
    migration_run_id INTEGER,
    attribute_name TEXT NOT NULL,
    source_value TEXT,
    dest_value TEXT,
    transformation_applied TEXT, -- Description of any transformation (e.g., 'UPN suffix changed')
    status TEXT, -- 'copied', 'transformed', 'skipped', 'error'
    error_message TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (object_guid) REFERENCES migration_map(source_guid),
    FOREIGN KEY (migration_run_id) REFERENCES migration_runs(run_id)
);

CREATE INDEX IF NOT EXISTS idx_attr_changes_object ON attribute_changes(object_guid);
CREATE INDEX IF NOT EXISTS idx_attr_changes_run ON attribute_changes(migration_run_id);

-- Conflicts log (objects that exist in dest but not in our migration DB)
CREATE TABLE IF NOT EXISTS conflicts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_dn TEXT NOT NULL,
    dest_dn TEXT NOT NULL,
    dest_guid TEXT,
    object_type TEXT,
    conflict_type TEXT, -- 'exists_not_tracked', 'dn_collision', 'sam_collision'
    resolution TEXT, -- 'skipped', 'manual', 'overwritten' (if user forces)
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    detected_run_id INTEGER,
    notes TEXT,

    FOREIGN KEY (detected_run_id) REFERENCES migration_runs(run_id)
);

-- Migration errors log
CREATE TABLE IF NOT EXISTS migration_errors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    migration_run_id INTEGER,
    error_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    severity TEXT, -- 'warning', 'error', 'critical'
    phase TEXT, -- 'analysis', 'ou_creation', 'object_creation', 'attributes', 'references', 'verification'
    object_dn TEXT,
    object_type TEXT,
    error_code TEXT,
    error_message TEXT,
    stack_trace TEXT,

    FOREIGN KEY (migration_run_id) REFERENCES migration_runs(run_id)
);

CREATE INDEX IF NOT EXISTS idx_errors_run ON migration_errors(migration_run_id);
CREATE INDEX IF NOT EXISTS idx_errors_severity ON migration_errors(severity);

-- Configuration snapshots (store connection configs per run for audit)
CREATE TABLE IF NOT EXISTS run_configurations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    migration_run_id INTEGER UNIQUE,
    source_dc_host TEXT,
    source_dc_port INTEGER,
    source_domain TEXT,
    dest_dc_host TEXT,
    dest_dc_port INTEGER,
    dest_domain TEXT,
    use_tls BOOLEAN,
    password_policy TEXT, -- e.g., 'random_12', 'fixed'
    options_json TEXT, -- JSON with other options

    FOREIGN KEY (migration_run_id) REFERENCES migration_runs(run_id)
);

-- Views for easy querying

-- View: Current migration status summary
CREATE VIEW IF NOT EXISTS v_migration_summary AS
SELECT
    object_type,
    status,
    COUNT(*) as count
FROM migration_map
GROUP BY object_type, status;

-- View: Unresolved deferred references
CREATE VIEW IF NOT EXISTS v_unresolved_references AS
SELECT
    dr.parent_object_dn,
    dr.attribute_name,
    dr.referenced_source_dn,
    dr.check_count,
    dr.last_check_timestamp
FROM deferred_references dr
WHERE dr.resolved = 0
ORDER BY dr.parent_object_dn, dr.attribute_name;

-- View: Latest migration run summary
CREATE VIEW IF NOT EXISTS v_latest_migration AS
SELECT
    run_id,
    run_date,
    source_base_dn,
    dest_base_dn,
    status,
    objects_analyzed,
    objects_created,
    objects_updated,
    objects_skipped,
    objects_conflicted,
    errors_count,
    duration_seconds
FROM migration_runs
ORDER BY run_id DESC
LIMIT 1;
