//! Migration directory auto-discovery.
//!
//! Automatically detects migration directories for popular frameworks and ORMs.
//! Supports custom paths via configuration.

use crate::config::MigrationsConfig;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

// ─────────────────────────────────────────────
// Known migration patterns
// ─────────────────────────────────────────────

/// Known migration directory patterns for various frameworks.
/// Each entry is (relative_path, framework_name, description).
pub const KNOWN_PATTERNS: &[(&str, &str, &str)] = &[
    ("prisma/migrations", "Prisma", "Prisma ORM migrations"),
    ("db/migrate", "Rails", "Rails Active Record migrations"),
    ("migrations", "Generic", "Standard migrations directory"),
    (
        "alembic/versions",
        "Alembic",
        "SQLAlchemy Alembic migrations",
    ),
    ("drizzle", "Drizzle", "Drizzle ORM migrations"),
    ("supabase/migrations", "Supabase", "Supabase migrations"),
    ("flyway/sql", "Flyway", "Flyway SQL migrations"),
    ("liquibase/changelogs", "Liquibase", "Liquibase changelogs"),
    ("src/migrations", "TypeORM", "TypeORM/Sequelize migrations"),
    (
        "database/migrations",
        "Laravel",
        "Laravel Eloquent migrations",
    ),
    ("db/migrations", "Knex", "Knex.js migrations"),
    ("diesel/migrations", "Diesel", "Diesel Rust ORM migrations"),
    (
        "schema/migrations",
        "Generic",
        "Schema migrations directory",
    ),
];

// ─────────────────────────────────────────────
// Discovery result types
// ─────────────────────────────────────────────

/// A discovered migration directory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredMigrations {
    /// The framework or ORM that uses this directory structure.
    pub framework: String,
    /// Absolute path to the migration directory.
    pub path: PathBuf,
    /// Number of SQL files found.
    pub sql_file_count: usize,
    /// Total number of files in the directory.
    pub total_file_count: usize,
    /// The glob pattern that matched (if any).
    pub matched_pattern: Option<String>,
    /// Whether this was from a custom path in config.
    pub from_config: bool,
    /// Human-readable description.
    pub description: String,
    /// List of SQL file paths found.
    pub sql_files: Vec<PathBuf>,
}

/// Summary of all discovered migrations.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DiscoveryReport {
    /// Root directory that was scanned.
    pub root: PathBuf,
    /// All discovered migration directories.
    pub discovered: Vec<DiscoveredMigrations>,
    /// Total number of SQL files found across all directories.
    pub total_sql_files: usize,
    /// Patterns that were searched (from config).
    pub patterns_searched: Vec<String>,
}

// ─────────────────────────────────────────────
// Discovery engine
// ─────────────────────────────────────────────

/// Migration discovery engine.
pub struct MigrationDiscovery {
    config: MigrationsConfig,
}

impl MigrationDiscovery {
    /// Create a new discovery engine with the given configuration.
    pub fn new(config: MigrationsConfig) -> Self {
        Self { config }
    }

    /// Create a discovery engine with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(MigrationsConfig::default())
    }

    /// Discover all migration directories from the given root.
    ///
    /// # Arguments
    /// * `root` - The root directory to search from.
    ///
    /// # Returns
    /// A `DiscoveryReport` containing all discovered migration directories.
    pub fn discover(&self, root: &Path) -> DiscoveryReport {
        let mut report = DiscoveryReport {
            root: root.to_path_buf(),
            discovered: Vec::new(),
            total_sql_files: 0,
            patterns_searched: self.config.patterns.clone(),
        };

        // Track already-discovered paths to avoid duplicates
        let mut seen_paths: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();

        // 1. First check custom paths from config (highest priority)
        for custom_path in &self.config.paths {
            let full_path = root.join(custom_path);
            if full_path.is_dir() && !seen_paths.contains(&full_path) {
                if let Some(discovery) = self.scan_directory(&full_path, "Custom", "", true) {
                    if discovery.sql_file_count > 0 {
                        seen_paths.insert(full_path.clone());
                        report.total_sql_files += discovery.sql_file_count;
                        report.discovered.push(discovery);
                    }
                }
            }
        }

        // 2. Auto-discover known patterns (if enabled)
        if self.config.auto_discover {
            for (pattern, framework, description) in KNOWN_PATTERNS {
                let full_path = root.join(pattern);
                if full_path.is_dir() && !seen_paths.contains(&full_path) {
                    if let Some(discovery) =
                        self.scan_directory(&full_path, framework, description, false)
                    {
                        if discovery.sql_file_count > 0 {
                            seen_paths.insert(full_path.clone());
                            report.total_sql_files += discovery.sql_file_count;
                            report.discovered.push(discovery);
                        }
                    }
                }
            }
        }

        // 3. Search using glob patterns from config
        for pattern in &self.config.patterns {
            let full_pattern = root.join(pattern).to_string_lossy().to_string();
            // Normalize path separators for Windows
            let full_pattern = full_pattern.replace('\\', "/");

            if let Ok(paths) = glob::glob(&full_pattern) {
                for entry in paths.flatten() {
                    if let Some(parent) = entry.parent() {
                        let parent_path = parent.to_path_buf();
                        if !seen_paths.contains(&parent_path) {
                            if let Some(mut discovery) =
                                self.scan_directory(&parent_path, "Pattern", "", false)
                            {
                                if discovery.sql_file_count > 0 {
                                    discovery.matched_pattern = Some(pattern.clone());
                                    seen_paths.insert(parent_path);
                                    report.total_sql_files += discovery.sql_file_count;
                                    report.discovered.push(discovery);
                                }
                            }
                        }
                    }
                }
            }
        }

        // Sort by path for consistent output
        report.discovered.sort_by(|a, b| a.path.cmp(&b.path));

        report
    }

    /// Scan a single directory and return discovery info.
    fn scan_directory(
        &self,
        dir: &Path,
        framework: &str,
        description: &str,
        from_config: bool,
    ) -> Option<DiscoveredMigrations> {
        if !dir.is_dir() {
            return None;
        }

        let sql_files = self.find_sql_files(dir);
        let total_file_count = self.count_all_files(dir);

        Some(DiscoveredMigrations {
            framework: framework.to_string(),
            path: dir.to_path_buf(),
            sql_file_count: sql_files.len(),
            total_file_count,
            matched_pattern: None,
            from_config,
            description: if description.is_empty() {
                format!("{} migrations", framework)
            } else {
                description.to_string()
            },
            sql_files,
        })
    }

    /// Find all SQL files in a directory (recursive).
    fn find_sql_files(&self, dir: &Path) -> Vec<PathBuf> {
        let pattern = dir.join("**/*.sql").to_string_lossy().to_string();
        let pattern = pattern.replace('\\', "/");

        glob::glob(&pattern)
            .map(|paths| paths.flatten().collect())
            .unwrap_or_default()
    }

    /// Count all files in a directory (non-recursive, just for info).
    fn count_all_files(&self, dir: &Path) -> usize {
        std::fs::read_dir(dir)
            .map(|entries| {
                entries
                    .filter_map(|e| e.ok())
                    .filter(|e| e.path().is_file())
                    .count()
            })
            .unwrap_or(0)
    }
}

// ─────────────────────────────────────────────
// Convenience functions
// ─────────────────────────────────────────────

/// Quick discovery using default configuration.
pub fn discover_migrations(root: &Path) -> DiscoveryReport {
    MigrationDiscovery::with_defaults().discover(root)
}

/// Check if a directory looks like it contains migrations.
pub fn is_migration_directory(path: &Path) -> bool {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let lower = name.to_lowercase();

    // Check if the name suggests migrations
    if lower.contains("migration") || lower == "migrate" || lower == "versions" {
        return true;
    }

    // Check if it's a known pattern
    for (pattern, _, _) in KNOWN_PATTERNS {
        if path.ends_with(pattern) {
            return true;
        }
    }

    false
}

// ─────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_discovery() {
        let discovery = MigrationDiscovery::with_defaults();
        assert!(discovery.config.auto_discover);
        assert!(!discovery.config.patterns.is_empty());
    }

    #[test]
    fn test_is_migration_directory() {
        assert!(is_migration_directory(Path::new("migrations")));
        assert!(is_migration_directory(Path::new("db/migrate")));
        assert!(is_migration_directory(Path::new("alembic/versions")));
        assert!(!is_migration_directory(Path::new("src")));
        assert!(!is_migration_directory(Path::new("lib")));
    }

    #[test]
    fn test_known_patterns_have_required_fields() {
        for (pattern, framework, description) in KNOWN_PATTERNS {
            assert!(!pattern.is_empty(), "Pattern should not be empty");
            assert!(!framework.is_empty(), "Framework should not be empty");
            assert!(!description.is_empty(), "Description should not be empty");
        }
    }

    #[test]
    fn test_discovery_empty_dir() {
        let temp_dir = std::env::temp_dir().join("schema-risk-test-empty");
        let _ = std::fs::create_dir_all(&temp_dir);

        let discovery = MigrationDiscovery::with_defaults();
        let report = discovery.discover(&temp_dir);

        assert!(report.discovered.is_empty());
        assert_eq!(report.total_sql_files, 0);

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
