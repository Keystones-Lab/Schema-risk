//! Query impact detection.
//!
//! Scans source files in a given directory for SQL string literals and ORM
//! query patterns that reference tables or columns being modified by the
//! migration.  Reports which files contain queries likely affected by the
//! pending schema change.
//!
//! Uses `rayon` for parallel directory traversal.

use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

// ─────────────────────────────────────────────
// Public types
// ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImpactedFile {
    /// Relative path from the scan root
    pub path: String,
    /// Tables mentioned in this file that overlap with the migration
    pub tables_referenced: Vec<String>,
    /// Columns mentioned in this file that overlap with the migration's
    /// dropped / renamed / type-changed columns
    pub columns_referenced: Vec<String>,
    /// Relevant lines of code (file:line → snippet)
    pub hits: Vec<QueryHit>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryHit {
    pub line: usize,
    pub snippet: String,
    pub match_type: MatchType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MatchType {
    /// Plain SQL string literal containing the table/column name
    SqlLiteral,
    /// ORM query builder reference (Sequelize, Prisma, SQLAlchemy, Diesel…)
    OrmReference,
    /// An `include:` / `select:` key that contains the column name
    FieldReference,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ImpactReport {
    /// Number of source files scanned
    pub files_scanned: usize,
    /// Files that reference affected schema objects
    pub impacted_files: Vec<ImpactedFile>,
    /// Table → list of files that reference it
    pub table_file_map: HashMap<String, Vec<String>>,
    /// Column → list of files that reference it
    pub column_file_map: HashMap<String, Vec<String>>,
}

// ─────────────────────────────────────────────
// Scanner
// ─────────────────────────────────────────────

/// Source file extensions we want to look inside.
const SOURCE_EXTENSIONS: &[&str] = &[
    "rs", "go", "py", "js", "ts", "jsx", "tsx", "rb", "java", "cs", "php", "sql", "graphql",
];

pub struct ImpactScanner {
    /// Tables to look for (lowercased)
    tables: Vec<String>,
    /// Columns to look for (lowercased)
    columns: Vec<String>,
}

impl ImpactScanner {
    /// Create a scanner that **skips identifiers shorter than 4 characters**
    /// to avoid false positives (B-03 fix).
    ///
    /// Use [`new_scan_short`] if you need to include short identifiers.
    pub fn new(tables: Vec<String>, columns: Vec<String>) -> Self {
        Self::new_with_options(tables, columns, true)
    }

    /// Create a scanner that includes all short identifiers (opt-in via `--scan-short-names`).
    pub fn new_scan_short(tables: Vec<String>, columns: Vec<String>) -> Self {
        Self::new_with_options(tables, columns, false)
    }

    fn new_with_options(tables: Vec<String>, columns: Vec<String>, skip_short: bool) -> Self {
        let filter = |idents: Vec<String>| -> Vec<String> {
            idents
                .into_iter()
                .filter(|s| !skip_short || s.chars().count() >= 4)
                .map(|s| s.to_lowercase())
                .collect()
        };
        Self {
            tables: filter(tables),
            columns: filter(columns),
        }
    }

    /// Walk `root_dir` recursively, scan all source files in parallel, return
    /// an `ImpactReport`.
    pub fn scan(&self, root_dir: &Path) -> ImpactReport {
        // Collect all source file paths first
        let paths = collect_source_files(root_dir);
        let total = paths.len();

        let impacted_files: Vec<ImpactedFile> = paths
            .par_iter()
            .filter_map(|path| self.scan_file(path))
            .collect();

        // Build lookup maps
        let mut table_file_map: HashMap<String, Vec<String>> = HashMap::new();
        let mut column_file_map: HashMap<String, Vec<String>> = HashMap::new();
        for f in &impacted_files {
            for t in &f.tables_referenced {
                table_file_map
                    .entry(t.clone())
                    .or_default()
                    .push(f.path.clone());
            }
            for c in &f.columns_referenced {
                column_file_map
                    .entry(c.clone())
                    .or_default()
                    .push(f.path.clone());
            }
        }

        ImpactReport {
            files_scanned: total,
            impacted_files,
            table_file_map,
            column_file_map,
        }
    }

    // ── Per-file scan ─────────────────────────────────────────────────────

    fn scan_file(&self, path: &Path) -> Option<ImpactedFile> {
        let content = std::fs::read_to_string(path).ok()?;
        let content_lower = content.to_lowercase();

        let mut tables_found: Vec<String> = Vec::new();
        let mut columns_found: Vec<String> = Vec::new();
        let mut hits: Vec<QueryHit> = Vec::new();

        for (line_idx, line) in content.lines().enumerate() {
            let line_lower = line.to_lowercase();

            for table in &self.tables {
                if line_lower.contains(table.as_str()) {
                    if !tables_found.contains(table) {
                        tables_found.push(table.clone());
                    }
                    let match_type = classify_match(&line_lower, table);
                    hits.push(QueryHit {
                        line: line_idx + 1,
                        snippet: line.trim().chars().take(200).collect(),
                        match_type,
                    });
                }
            }

            for col in &self.columns {
                if line_lower.contains(col.as_str())
                    && !content_lower.contains(&format!("-- {}", col))
                {
                    if !columns_found.contains(col) {
                        columns_found.push(col.clone());
                    }
                    // Avoid duplicate hits on the same line
                    if !hits.iter().any(|h| h.line == line_idx + 1) {
                        let match_type = classify_match(&line_lower, col);
                        hits.push(QueryHit {
                            line: line_idx + 1,
                            snippet: line.trim().chars().take(200).collect(),
                            match_type,
                        });
                    }
                }
            }
        }

        if tables_found.is_empty() && columns_found.is_empty() {
            return None;
        }

        let rel_path = path.to_string_lossy().to_string();

        Some(ImpactedFile {
            path: rel_path,
            tables_referenced: tables_found,
            columns_referenced: columns_found,
            hits,
        })
    }
}

// ── Classify what kind of reference this line contains ───────────────────

fn classify_match(line: &str, token: &str) -> MatchType {
    // ORM patterns
    let orm_patterns = [
        "select(",
        "where(",
        "findone",
        "findall",
        "findmany",
        "create(",
        "update(",
        "delete(",
        "include:",
        "prisma.",
        "model.",
        ".query(",
        "execute(",
        "from(",
        "join(",
        "diesel::",
        "querybuilder",
        "activerecord",
        "sqlalchemy",
    ];

    let field_patterns = ["include:", "select:", "fields:", "columns:", "attributes:"];

    if field_patterns.iter().any(|p| line.contains(p)) {
        return MatchType::FieldReference;
    }

    if orm_patterns.iter().any(|p| line.contains(p)) {
        return MatchType::OrmReference;
    }

    // Raw SQL string heuristic: the token appears between quotes or after FROM/JOIN/INTO
    let sql_keywords = ["from ", "join ", "into ", "update ", "\"", "'", "`"];
    if sql_keywords.iter().any(|k| {
        if let Some(pos) = line.find(k) {
            line[pos..].contains(token)
        } else {
            false
        }
    }) {
        return MatchType::SqlLiteral;
    }

    MatchType::OrmReference
}

// ── Collect all source files under a directory ───────────────────────────

fn collect_source_files(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    collect_recursive(root, &mut files);
    files
}

fn collect_recursive(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };

    for entry in entries.flatten() {
        let path = entry.path();

        // Skip hidden dirs and common build/vendor dirs
        let name = path.file_name().and_then(OsStr::to_str).unwrap_or("");
        if name.starts_with('.')
            || matches!(
                name,
                "node_modules" | "target" | "dist" | "build" | "vendor" | "__pycache__" | ".git"
            )
        {
            continue;
        }

        if path.is_dir() {
            collect_recursive(&path, out);
        } else if let Some(ext) = path.extension().and_then(OsStr::to_str) {
            if SOURCE_EXTENSIONS.contains(&ext) {
                out.push(path);
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SQL Extraction from Source Code
// ─────────────────────────────────────────────────────────────────────────────

/// SQL extracted from source code (not from a .sql file).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedSql {
    /// The source file path.
    pub source_file: String,
    /// Line number where the SQL was found.
    pub line: usize,
    /// Column number (if known).
    pub column: Option<usize>,
    /// The extracted SQL string.
    pub sql: String,
    /// The ORM/framework context.
    pub context: SqlContext,
    /// Confidence score (0.0 - 1.0).
    pub confidence: f32,
}

/// The context in which SQL was found.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SqlContext {
    /// Raw SQL string literal (generic).
    RawSql,
    /// Prisma $queryRaw / $executeRaw.
    PrismaRaw,
    /// TypeORM query / createQueryBuilder.
    TypeOrm,
    /// Sequelize raw query.
    Sequelize,
    /// SQLAlchemy text() / execute().
    SqlAlchemy,
    /// GORM Raw / Exec.
    Gorm,
    /// Diesel sql_query.
    Diesel,
    /// Entity Framework FromSqlRaw.
    EntityFramework,
    /// Laravel DB::raw / DB::statement.
    Eloquent,
    /// Rails ActiveRecord execute.
    ActiveRecord,
    /// Unknown / generic context.
    Unknown,
}

impl std::fmt::Display for SqlContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SqlContext::RawSql => write!(f, "Raw SQL"),
            SqlContext::PrismaRaw => write!(f, "Prisma"),
            SqlContext::TypeOrm => write!(f, "TypeORM"),
            SqlContext::Sequelize => write!(f, "Sequelize"),
            SqlContext::SqlAlchemy => write!(f, "SQLAlchemy"),
            SqlContext::Gorm => write!(f, "GORM"),
            SqlContext::Diesel => write!(f, "Diesel"),
            SqlContext::EntityFramework => write!(f, "Entity Framework"),
            SqlContext::Eloquent => write!(f, "Eloquent"),
            SqlContext::ActiveRecord => write!(f, "ActiveRecord"),
            SqlContext::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Result of scanning a codebase for SQL.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SqlExtractionReport {
    /// Number of source files scanned.
    pub files_scanned: usize,
    /// All extracted SQL statements.
    pub extracted: Vec<ExtractedSql>,
    /// SQL statements that look dangerous (DELETE, DROP, TRUNCATE, ALTER).
    pub dangerous: Vec<ExtractedSql>,
    /// Breakdown by context/ORM.
    pub by_context: HashMap<String, usize>,
}

/// SQL extraction engine.
pub struct SqlExtractor {
    /// Compiled regex patterns for SQL extraction.
    patterns: Vec<SqlExtractionPattern>,
}

struct SqlExtractionPattern {
    regex: regex::Regex,
    context: SqlContext,
    /// File extensions this pattern applies to ("*" = all).
    extensions: Vec<&'static str>,
    /// Group index that captures the SQL (0 = whole match).
    capture_group: usize,
    /// Base confidence score.
    confidence: f32,
}

impl Default for SqlExtractor {
    fn default() -> Self {
        Self::new()
    }
}

impl SqlExtractor {
    /// Create a new SQL extractor with default patterns.
    pub fn new() -> Self {
        let patterns = Self::build_patterns();
        Self { patterns }
    }

    fn build_patterns() -> Vec<SqlExtractionPattern> {
        let mut patterns = Vec::new();

        // Helper to add patterns
        let mut add = |pattern: &str, ctx: SqlContext, exts: &[&'static str], group: usize, conf: f32| {
            if let Ok(re) = regex::Regex::new(pattern) {
                patterns.push(SqlExtractionPattern {
                    regex: re,
                    context: ctx,
                    extensions: exts.to_vec(),
                    capture_group: group,
                    confidence: conf,
                });
            }
        };

        // ── Prisma (JavaScript/TypeScript) ───────────────────────────────────
        add(r#"\$queryRaw\s*`([^`]+)`"#, SqlContext::PrismaRaw, &["ts", "js", "tsx", "jsx"], 1, 0.95);
        add(r#"\$executeRaw\s*`([^`]+)`"#, SqlContext::PrismaRaw, &["ts", "js", "tsx", "jsx"], 1, 0.95);
        add(r#"Prisma\.sql\s*`([^`]+)`"#, SqlContext::PrismaRaw, &["ts", "js", "tsx", "jsx"], 1, 0.9);

        // ── TypeORM (JavaScript/TypeScript) ──────────────────────────────────
        add(r#"\.query\s*\(\s*["'`]([^"'`]+)["'`]"#, SqlContext::TypeOrm, &["ts", "js", "tsx", "jsx"], 1, 0.85);
        add(r#"createQueryBuilder\s*\(\s*["']([^"']+)["']"#, SqlContext::TypeOrm, &["ts", "js", "tsx", "jsx"], 1, 0.8);
        add(r#"\.createQueryRunner\(\)\.query\s*\(\s*["'`]([^"'`]+)["'`]"#, SqlContext::TypeOrm, &["ts", "js"], 1, 0.9);

        // ── Sequelize (JavaScript/TypeScript) ────────────────────────────────
        add(r#"sequelize\.query\s*\(\s*["'`]([^"'`]+)["'`]"#, SqlContext::Sequelize, &["ts", "js", "tsx", "jsx"], 1, 0.9);
        add(r#"QueryTypes\.\w+.*["'`]([^"'`]+)["'`]"#, SqlContext::Sequelize, &["ts", "js"], 1, 0.85);

        // ── SQLAlchemy (Python) ──────────────────────────────────────────────
        add(r#"text\s*\(\s*["']([^"']+)["']"#, SqlContext::SqlAlchemy, &["py"], 1, 0.9);
        add(r#"execute\s*\(\s*["']([^"']+)["']"#, SqlContext::SqlAlchemy, &["py"], 1, 0.85);
        add(r#"session\.execute\s*\(\s*["']([^"']+)["']"#, SqlContext::SqlAlchemy, &["py"], 1, 0.9);
        add(r#"connection\.execute\s*\(\s*["']([^"']+)["']"#, SqlContext::SqlAlchemy, &["py"], 1, 0.9);

        // ── Django (Python) ──────────────────────────────────────────────────
        add(r#"cursor\.execute\s*\(\s*["']([^"']+)["']"#, SqlContext::SqlAlchemy, &["py"], 1, 0.9);
        add(r#"\.raw\s*\(\s*["']([^"']+)["']"#, SqlContext::SqlAlchemy, &["py"], 1, 0.85);

        // ── GORM (Go) ────────────────────────────────────────────────────────
        add(r#"\.Raw\s*\(\s*["'`]([^"'`]+)["'`]"#, SqlContext::Gorm, &["go"], 1, 0.9);
        add(r#"\.Exec\s*\(\s*["'`]([^"'`]+)["'`]"#, SqlContext::Gorm, &["go"], 1, 0.9);
        add(r#"db\.Query\s*\(\s*["'`]([^"'`]+)["'`]"#, SqlContext::Gorm, &["go"], 1, 0.85);

        // ── Diesel (Rust) ────────────────────────────────────────────────────
        add(r#"sql_query\s*\(\s*["']([^"']+)["']"#, SqlContext::Diesel, &["rs"], 1, 0.9);
        add(r#"diesel::sql_query\s*\(\s*["']([^"']+)["']"#, SqlContext::Diesel, &["rs"], 1, 0.95);

        // ── Entity Framework (C#) ────────────────────────────────────────────
        add(r#"\.FromSqlRaw\s*\(\s*["']([^"']+)["']"#, SqlContext::EntityFramework, &["cs"], 1, 0.9);
        add(r#"\.ExecuteSqlRaw\s*\(\s*["']([^"']+)["']"#, SqlContext::EntityFramework, &["cs"], 1, 0.9);
        add(r#"SqlQuery<[^>]+>\s*\(\s*["']([^"']+)["']"#, SqlContext::EntityFramework, &["cs"], 1, 0.85);

        // ── Laravel Eloquent (PHP) ───────────────────────────────────────────
        add(r#"DB::raw\s*\(\s*["']([^"']+)["']"#, SqlContext::Eloquent, &["php"], 1, 0.9);
        add(r#"DB::statement\s*\(\s*["']([^"']+)["']"#, SqlContext::Eloquent, &["php"], 1, 0.9);
        add(r#"DB::select\s*\(\s*["']([^"']+)["']"#, SqlContext::Eloquent, &["php"], 1, 0.85);
        add(r#"DB::insert\s*\(\s*["']([^"']+)["']"#, SqlContext::Eloquent, &["php"], 1, 0.85);
        add(r#"DB::update\s*\(\s*["']([^"']+)["']"#, SqlContext::Eloquent, &["php"], 1, 0.85);
        add(r#"DB::delete\s*\(\s*["']([^"']+)["']"#, SqlContext::Eloquent, &["php"], 1, 0.85);

        // ── Rails ActiveRecord (Ruby) ────────────────────────────────────────
        add(r#"execute\s*\(\s*["']([^"']+)["']"#, SqlContext::ActiveRecord, &["rb"], 1, 0.85);
        add(r#"exec_query\s*\(\s*["']([^"']+)["']"#, SqlContext::ActiveRecord, &["rb"], 1, 0.9);
        add(r#"connection\.execute\s*\(\s*["']([^"']+)["']"#, SqlContext::ActiveRecord, &["rb"], 1, 0.9);
        add(r#"find_by_sql\s*\(\s*["']([^"']+)["']"#, SqlContext::ActiveRecord, &["rb"], 1, 0.9);

        // ── Generic SQL string patterns (lower confidence) ───────────────────
        // These match SQL keywords in string literals
        add(
            r#"["'`]((?:SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP|TRUNCATE)\s+[^"'`]{10,})["'`]"#,
            SqlContext::RawSql,
            &["*"],
            1,
            0.7,
        );

        patterns
    }

    /// Extract SQL from a single file.
    pub fn extract_from_file(&self, path: &Path) -> Vec<ExtractedSql> {
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");

        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => return vec![],
        };

        let path_str = path.to_string_lossy().to_string();
        let mut results = Vec::new();

        for (line_idx, line) in content.lines().enumerate() {
            for pattern in &self.patterns {
                // Check if this pattern applies to this file type
                if !pattern.extensions.contains(&"*") && !pattern.extensions.contains(&ext) {
                    continue;
                }

                for cap in pattern.regex.captures_iter(line) {
                    let sql = if pattern.capture_group > 0 {
                        cap.get(pattern.capture_group)
                            .map(|m| m.as_str())
                            .unwrap_or("")
                    } else {
                        cap.get(0).map(|m| m.as_str()).unwrap_or("")
                    };

                    let sql = sql.trim().to_string();

                    // Skip empty or very short matches
                    if sql.len() < 5 {
                        continue;
                    }

                    // Verify it looks like SQL
                    if !Self::looks_like_sql(&sql) {
                        continue;
                    }

                    results.push(ExtractedSql {
                        source_file: path_str.clone(),
                        line: line_idx + 1,
                        column: cap.get(1).map(|m| m.start()),
                        sql,
                        context: pattern.context.clone(),
                        confidence: pattern.confidence,
                    });
                }
            }
        }

        results
    }

    /// Check if a string looks like SQL.
    fn looks_like_sql(s: &str) -> bool {
        let upper = s.to_uppercase();
        let sql_keywords = [
            "SELECT", "INSERT", "UPDATE", "DELETE", "CREATE", "ALTER", "DROP",
            "TRUNCATE", "FROM", "WHERE", "JOIN", "TABLE", "INDEX", "COLUMN",
        ];
        sql_keywords.iter().any(|kw| upper.contains(kw))
    }

    /// Check if SQL is dangerous (DDL or deletes).
    fn is_dangerous_sql(sql: &str) -> bool {
        let upper = sql.to_uppercase();
        upper.contains("DROP ")
            || upper.contains("TRUNCATE ")
            || upper.contains("DELETE ")
            || upper.contains("ALTER ")
            || upper.contains("CREATE INDEX")
    }

    /// Scan a directory for SQL in source code.
    pub fn scan_directory(&self, root: &Path) -> SqlExtractionReport {
        let files = collect_source_files(root);
        let total = files.len();

        let extracted: Vec<ExtractedSql> = files
            .par_iter()
            .flat_map(|path| self.extract_from_file(path))
            .collect();

        // Separate dangerous SQL
        let dangerous: Vec<ExtractedSql> = extracted
            .iter()
            .filter(|e| Self::is_dangerous_sql(&e.sql))
            .cloned()
            .collect();

        // Count by context
        let mut by_context: HashMap<String, usize> = HashMap::new();
        for e in &extracted {
            *by_context.entry(e.context.to_string()).or_insert(0) += 1;
        }

        SqlExtractionReport {
            files_scanned: total,
            extracted,
            dangerous,
            by_context,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sql_extractor_prisma() {
        let extractor = SqlExtractor::new();
        let code = r#"const result = await prisma.$queryRaw`SELECT * FROM users WHERE id = ${id}`;"#;

        // Create a temp file
        let temp_dir = std::env::temp_dir().join("schema-risk-test-prisma");
        let _ = std::fs::create_dir_all(&temp_dir);
        let file_path = temp_dir.join("test.ts");
        std::fs::write(&file_path, code).unwrap();

        let results = extractor.extract_from_file(&file_path);
        assert!(!results.is_empty());
        assert_eq!(results[0].context, SqlContext::PrismaRaw);
        assert!(results[0].sql.contains("SELECT"));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_sql_extractor_raw_sql() {
        let extractor = SqlExtractor::new();
        let code = r#"const query = "SELECT * FROM users WHERE active = true";"#;

        let temp_dir = std::env::temp_dir().join("schema-risk-test-raw");
        let _ = std::fs::create_dir_all(&temp_dir);
        let file_path = temp_dir.join("test.js");
        std::fs::write(&file_path, code).unwrap();

        let results = extractor.extract_from_file(&file_path);
        assert!(!results.is_empty());
        assert!(results[0].sql.contains("SELECT"));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_dangerous_sql_detection() {
        assert!(SqlExtractor::is_dangerous_sql("DROP TABLE users"));
        assert!(SqlExtractor::is_dangerous_sql("DELETE FROM users WHERE id = 1"));
        assert!(SqlExtractor::is_dangerous_sql("TRUNCATE TABLE sessions"));
        assert!(SqlExtractor::is_dangerous_sql("ALTER TABLE users ADD COLUMN age INT"));
        assert!(!SqlExtractor::is_dangerous_sql("SELECT * FROM users"));
        assert!(!SqlExtractor::is_dangerous_sql("INSERT INTO users (name) VALUES ('test')"));
    }

    #[test]
    fn test_looks_like_sql() {
        assert!(SqlExtractor::looks_like_sql("SELECT * FROM users"));
        assert!(SqlExtractor::looks_like_sql("INSERT INTO users (name) VALUES ('test')"));
        assert!(SqlExtractor::looks_like_sql("DROP TABLE users"));
        assert!(!SqlExtractor::looks_like_sql("Hello world"));
        assert!(!SqlExtractor::looks_like_sql("const x = 5"));
    }
}
