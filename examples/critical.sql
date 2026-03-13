-- examples/critical.sql
-- CRITICAL risk operations — the guard will block these until you confirm.
-- Run: schema-risk analyze examples/critical.sql
-- Run: schema-risk guard --dry-run examples/critical.sql  (preview only)
-- Run: schema-risk guard examples/critical.sql            (requires confirmation)

-- CRITICAL: permanently destroys the entire sessions table and all its data.
-- Safe alternative: ALTER TABLE sessions RENAME TO sessions_deprecated;
DROP TABLE sessions;

-- CRITICAL: destroys all rows in the audit_log table.
-- This cannot be undone without a backup.
TRUNCATE TABLE audit_log;
