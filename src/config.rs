//! Configuration loader for `schema-risk.yml` / `schema-risk.yaml`.
//!
//! Loads per-project configuration from `schema-risk.yml` in the current
//! directory (or a path supplied via `--config`). Falls back gracefully to
//! built-in defaults when the file is absent.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

// ─────────────────────────────────────────────
// Top-level config struct
// ─────────────────────────────────────────────

/// Root configuration loaded from `schema-risk.yml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub version: u32,
    pub database: DatabaseConfig,
    pub migrations: MigrationsConfig,
    pub thresholds: Thresholds,
    pub rules: RulesConfig,
    pub scan: ScanConfig,
    pub guard: GuardConfig,
    pub output: OutputConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            version: 2,
            database: DatabaseConfig::default(),
            migrations: MigrationsConfig::default(),
            thresholds: Thresholds::default(),
            rules: RulesConfig::default(),
            scan: ScanConfig::default(),
            guard: GuardConfig::default(),
            output: OutputConfig::default(),
        }
    }
}

// ─────────────────────────────────────────────
// Database config
// ─────────────────────────────────────────────

/// Database connection configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DatabaseConfig {
    /// Primary environment variable to read database URL from.
    pub url_env: String,
    /// Fallback environment variables to check (in order).
    pub fallback_envs: Vec<String>,
    /// Whether to automatically load `.env` file.
    pub load_dotenv: bool,
    /// Direct database URL (not recommended — use env vars instead).
    pub url: Option<String>,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            url_env: "DATABASE_URL".to_string(),
            fallback_envs: vec!["DB_URL".to_string(), "POSTGRES_URL".to_string()],
            load_dotenv: true,
            url: None,
        }
    }
}

// ─────────────────────────────────────────────
// Migrations config
// ─────────────────────────────────────────────

/// Migration file discovery configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct MigrationsConfig {
    /// Custom paths to scan for migrations (empty = auto-detect only).
    pub paths: Vec<String>,
    /// Enable automatic migration directory discovery.
    pub auto_discover: bool,
    /// Glob patterns for migration files.
    pub patterns: Vec<String>,
}

impl Default for MigrationsConfig {
    fn default() -> Self {
        Self {
            paths: vec![],
            auto_discover: true,
            patterns: vec![
                "prisma/migrations/**/migration.sql".to_string(),
                "db/migrate/**/*.sql".to_string(),
                "migrations/**/*.sql".to_string(),
                "alembic/versions/**/*.sql".to_string(),
                "drizzle/**/*.sql".to_string(),
                "supabase/migrations/**/*.sql".to_string(),
                "flyway/sql/**/*.sql".to_string(),
                "src/migrations/**/*.sql".to_string(),
                "database/migrations/**/*.sql".to_string(),
            ],
        }
    }
}

// ─────────────────────────────────────────────
// Thresholds
// ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Thresholds {
    /// Exit non-zero if any migration reaches this risk level.
    pub fail_on: String,
    /// Show guard prompt starting at this risk level.
    pub guard_on: String,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            fail_on: "high".to_string(),
            guard_on: "medium".to_string(),
        }
    }
}

// ─────────────────────────────────────────────
// Rules config
// ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct RulesConfig {
    /// Rule IDs to disable (e.g. ["R03", "R07"])
    pub disabled: Vec<String>,
    /// Per-table risk overrides.
    pub table_overrides: HashMap<String, TableOverride>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct TableOverride {
    /// Allow higher risk level on this table.
    pub max_risk: Option<String>,
    /// Skip risk analysis entirely for this table.
    pub ignored: bool,
}

// ─────────────────────────────────────────────
// Scan config
// ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ScanConfig {
    pub root_dir: String,
    pub extensions: Vec<String>,
    pub exclude: Vec<String>,
    /// Skip columns/tables with fewer than 4 characters (avoids false positives).
    pub skip_short_identifiers: bool,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            root_dir: ".".to_string(),
            extensions: vec![
                "rs".to_string(),
                "py".to_string(),
                "go".to_string(),
                "ts".to_string(),
                "js".to_string(),
                "rb".to_string(),
                "java".to_string(),
                "kt".to_string(),
                "cs".to_string(),
                "php".to_string(),
            ],
            exclude: vec![
                "target/".to_string(),
                "node_modules/".to_string(),
                "vendor/".to_string(),
                ".git/".to_string(),
                "dist/".to_string(),
                "build/".to_string(),
            ],
            skip_short_identifiers: true,
        }
    }
}

// ─────────────────────────────────────────────
// Guard config
// ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GuardConfig {
    /// Require full phrase "yes I am sure" for Critical operations.
    pub require_typed_confirmation: bool,
    /// Path to write the audit log JSON.
    pub audit_log: String,
    /// Always exit 4 when actor is detected as an AI agent.
    pub block_agents: bool,
    /// Exit 4 for CI pipelines (default: false - just print warning).
    pub block_ci: bool,
}

impl Default for GuardConfig {
    fn default() -> Self {
        Self {
            require_typed_confirmation: true,
            audit_log: ".schemarisk-audit.json".to_string(),
            block_agents: true,
            block_ci: false,
        }
    }
}

// ─────────────────────────────────────────────
// Output config
// ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct OutputConfig {
    pub format: String,
    pub color: bool,
    pub show_recommendations: bool,
    pub show_impact: bool,
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            format: "terminal".to_string(),
            color: true,
            show_recommendations: true,
            show_impact: true,
        }
    }
}

// ─────────────────────────────────────────────
// Loader
// ─────────────────────────────────────────────

/// Load configuration from a file path, falling back to defaults if absent.
///
/// Searches in order:
/// 1. The path supplied via `--config <PATH>`
/// 2. `./schema-risk.yml`
/// 3. `./schema-risk.yaml`
/// 4. Built-in defaults
pub fn load(path: Option<&str>) -> Config {
    let candidates: Vec<&str> = if let Some(p) = path {
        vec![p]
    } else {
        vec!["schema-risk.yml", "schema-risk.yaml"]
    };

    for candidate in &candidates {
        if let Some(config) = try_load(Path::new(candidate)) {
            return config;
        }
    }

    Config::default()
}

fn try_load(path: &Path) -> Option<Config> {
    if !path.exists() {
        return None;
    }
    let contents = std::fs::read_to_string(path).ok()?;
    match serde_yaml::from_str::<Config>(&contents) {
        Ok(c) => Some(c),
        Err(e) => {
            eprintln!("warning: Failed to parse {}: {e}", path.display());
            None
        }
    }
}

/// Return the canonical YAML template written by `schemarisk init`.
pub fn default_yaml_template() -> &'static str {
    r#"# schema-risk.yml — per-project SchemaRisk configuration
version: 2

# Database connection settings
database:
  url_env: DATABASE_URL           # primary env var for DB URL
  fallback_envs:                  # fallback env vars to check (in order)
    - DB_URL
    - POSTGRES_URL
  load_dotenv: true               # auto-load .env file
  # url: postgres://...           # direct URL (not recommended - use env vars)

# Migration file discovery
migrations:
  paths: []                       # custom paths (empty = auto-detect)
  auto_discover: true             # scan for common migration patterns
  patterns:                       # glob patterns for SQL migration files
    - "prisma/migrations/**/migration.sql"
    - "db/migrate/**/*.sql"
    - "migrations/**/*.sql"
    - "alembic/versions/**/*.sql"
    - "drizzle/**/*.sql"
    - "supabase/migrations/**/*.sql"

thresholds:
  fail_on: high                   # low | medium | high | critical
  guard_on: medium                # operations at this level trigger guard prompts

rules:
  disabled: []                    # e.g. [R03, R07]
  table_overrides:
    audit_log:
      max_risk: critical          # allow higher risk on append-only tables
    sessions:
      ignored: true               # skip risk analysis entirely

scan:
  root_dir: "."                   # directory to scan for code impact
  extensions: [rs, py, go, ts, js, rb, java, kt, cs, php]
  exclude: [target/, node_modules/, vendor/, .git/, dist/, build/]
  skip_short_identifiers: true    # skip columns < 4 chars (avoids false positives)

guard:
  require_typed_confirmation: true  # "yes I am sure" for Critical ops
  audit_log: ".schemarisk-audit.json"
  block_agents: true              # always block AI agents
  block_ci: false                 # set true to block CI pipelines

output:
  format: terminal                # terminal | json | markdown | sarif
  color: true
  show_recommendations: true
  show_impact: true
"#
}

// ─────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_has_sensible_values() {
        let cfg = Config::default();
        assert_eq!(cfg.thresholds.fail_on, "high");
        assert_eq!(cfg.thresholds.guard_on, "medium");
        assert!(cfg.guard.block_agents);
        assert!(!cfg.guard.block_ci);
        assert!(cfg.scan.skip_short_identifiers);
        assert_eq!(cfg.database.url_env, "DATABASE_URL");
        assert!(cfg.database.load_dotenv);
        assert!(cfg.migrations.auto_discover);
    }

    #[test]
    fn yaml_template_parses_correctly() {
        let cfg: Config =
            serde_yaml::from_str(default_yaml_template()).expect("template should be valid YAML");
        assert_eq!(cfg.version, 2);
        assert_eq!(cfg.thresholds.fail_on, "high");
        assert_eq!(cfg.database.url_env, "DATABASE_URL");
        assert!(cfg.migrations.auto_discover);
    }

    #[test]
    fn database_config_defaults() {
        let db = DatabaseConfig::default();
        assert_eq!(db.url_env, "DATABASE_URL");
        assert_eq!(db.fallback_envs, vec!["DB_URL", "POSTGRES_URL"]);
        assert!(db.load_dotenv);
        assert!(db.url.is_none());
    }

    #[test]
    fn migrations_config_defaults() {
        let mig = MigrationsConfig::default();
        assert!(mig.paths.is_empty());
        assert!(mig.auto_discover);
        assert!(!mig.patterns.is_empty());
        assert!(mig.patterns.iter().any(|p| p.contains("prisma")));
    }
}
