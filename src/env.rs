//! Environment configuration loader.
//!
//! Provides automatic loading of `.env` files and resolution of database URLs
//! from multiple environment variable sources.
//!
//! # Priority Order for Database URL
//! 1. CLI argument `--db-url` (highest priority)
//! 2. `DATABASE_URL` environment variable
//! 3. `DB_URL` environment variable
//! 4. `POSTGRES_URL` environment variable
//! 5. `database.url` in `schema-risk.yml` config file (lowest priority)

use std::path::Path;

/// Environment variable names checked for database URL, in priority order.
pub const DB_URL_ENV_VARS: &[&str] = &["DATABASE_URL", "DB_URL", "POSTGRES_URL"];

/// Result of loading environment configuration.
#[derive(Debug, Clone)]
pub struct EnvConfig {
    /// Database URL resolved from environment (if found).
    pub database_url: Option<String>,
    /// Whether a `.env` file was successfully loaded.
    pub dotenv_loaded: bool,
    /// Path to the `.env` file that was loaded (if any).
    pub dotenv_path: Option<String>,
    /// Which environment variable the database URL came from (if any).
    pub database_url_source: Option<String>,
}

impl Default for EnvConfig {
    fn default() -> Self {
        Self {
            database_url: None,
            dotenv_loaded: false,
            dotenv_path: None,
            database_url_source: None,
        }
    }
}

impl EnvConfig {
    /// Load environment configuration.
    ///
    /// 1. Attempts to load `.env` file from current directory
    /// 2. Checks environment variables for database URL
    ///
    /// # Example
    /// ```no_run
    /// use schema_risk::env::EnvConfig;
    /// let env = EnvConfig::load();
    /// if let Some(url) = &env.database_url {
    ///     println!("Found database URL from {}", env.database_url_source.as_deref().unwrap_or("unknown"));
    /// }
    /// ```
    pub fn load() -> Self {
        Self::load_from_dir(Path::new("."))
    }

    /// Load environment configuration from a specific directory.
    pub fn load_from_dir(dir: &Path) -> Self {
        let mut config = EnvConfig::default();

        // Try to load .env file
        let env_path = dir.join(".env");
        if env_path.exists() {
            match dotenvy::from_path(&env_path) {
                Ok(()) => {
                    config.dotenv_loaded = true;
                    config.dotenv_path = Some(env_path.to_string_lossy().to_string());
                }
                Err(e) => {
                    // Log but don't fail - .env is optional
                    tracing::debug!("Failed to load .env file: {}", e);
                }
            }
        } else {
            // Try the dotenv default behavior (searches parent directories)
            if dotenvy::dotenv().is_ok() {
                config.dotenv_loaded = true;
                config.dotenv_path = dotenvy::var("DOTENV_FILE").ok();
            }
        }

        // Resolve database URL from environment variables
        for var_name in DB_URL_ENV_VARS {
            if let Ok(url) = std::env::var(var_name) {
                if !url.is_empty() {
                    config.database_url = Some(url);
                    config.database_url_source = Some(var_name.to_string());
                    break;
                }
            }
        }

        config
    }

    /// Resolve the final database URL, with CLI argument taking precedence.
    ///
    /// # Arguments
    /// * `cli_url` - URL provided via `--db-url` CLI argument
    /// * `config_url` - URL from `schema-risk.yml` config file
    ///
    /// # Returns
    /// The database URL to use, or `None` if no URL is configured.
    pub fn resolve_db_url(
        &self,
        cli_url: Option<&str>,
        config_url: Option<&str>,
    ) -> Option<String> {
        // Priority: CLI > env var > config file
        cli_url
            .map(String::from)
            .or_else(|| self.database_url.clone())
            .or_else(|| config_url.map(String::from))
    }

    /// Check if a database URL is available from any source.
    pub fn has_db_url(&self) -> bool {
        self.database_url.is_some()
    }

    /// Get a human-readable description of where the database URL came from.
    pub fn db_url_source_description(&self) -> Option<String> {
        self.database_url_source.as_ref().map(|source| {
            if self.dotenv_loaded {
                format!("{} (from .env)", source)
            } else {
                format!("{} (from environment)", source)
            }
        })
    }
}

// ───────────────────────────────────────────────────────────────────────────────
// Tests
// ───────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Mutex to serialize environment variable tests
    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    fn clear_db_env_vars() {
        std::env::remove_var("DATABASE_URL");
        std::env::remove_var("DB_URL");
        std::env::remove_var("POSTGRES_URL");
    }

    #[test]
    fn test_priority_order() {
        let _lock = ENV_MUTEX.lock().unwrap();
        clear_db_env_vars();

        // Set only POSTGRES_URL
        std::env::set_var("POSTGRES_URL", "postgres://fallback");
        let config = EnvConfig::load();
        assert_eq!(config.database_url, Some("postgres://fallback".to_string()));
        assert_eq!(
            config.database_url_source,
            Some("POSTGRES_URL".to_string())
        );

        // Set DB_URL (higher priority)
        std::env::set_var("DB_URL", "postgres://medium");
        let config = EnvConfig::load();
        assert_eq!(config.database_url, Some("postgres://medium".to_string()));
        assert_eq!(config.database_url_source, Some("DB_URL".to_string()));

        // Set DATABASE_URL (highest priority)
        std::env::set_var("DATABASE_URL", "postgres://primary");
        let config = EnvConfig::load();
        assert_eq!(config.database_url, Some("postgres://primary".to_string()));
        assert_eq!(
            config.database_url_source,
            Some("DATABASE_URL".to_string())
        );

        // Cleanup
        clear_db_env_vars();
    }

    #[test]
    fn test_cli_takes_precedence() {
        let _lock = ENV_MUTEX.lock().unwrap();
        clear_db_env_vars();

        std::env::set_var("DATABASE_URL", "postgres://from_env");
        let config = EnvConfig::load();

        // CLI should override environment
        let resolved = config.resolve_db_url(Some("postgres://from_cli"), None);
        assert_eq!(resolved, Some("postgres://from_cli".to_string()));

        // Without CLI, should use environment
        let resolved = config.resolve_db_url(None, None);
        assert_eq!(resolved, Some("postgres://from_env".to_string()));

        // Config file is lowest priority
        let resolved = config.resolve_db_url(None, Some("postgres://from_config"));
        assert_eq!(resolved, Some("postgres://from_env".to_string()));

        clear_db_env_vars();
    }

    #[test]
    fn test_empty_vars_ignored() {
        let _lock = ENV_MUTEX.lock().unwrap();
        clear_db_env_vars();

        std::env::set_var("POSTGRES_URL", "");

        let config = EnvConfig::load();
        assert!(config.database_url.is_none());

        clear_db_env_vars();
    }
}
