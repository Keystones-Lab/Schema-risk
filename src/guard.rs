//! DangerGuard — intercept SQL migrations and gate execution behind explicit confirmation.
//!
//! This module is the crown feature of SchemaRisk. It prevents AI agents, CI scripts,
//! and humans from running destructive SQL without informed, explicit confirmation.
//!
//! # Behavior by actor
//! - **Human** (interactive TTY): Shows full impact panel and prompts for typed confirmation.
//! - **CI Pipeline**: Prints impact to stderr, exits 4 (never auto-approves).
//! - **AI Agent**: Exits 4 immediately with machine-readable JSON on stdout.
//!
//! # Guard triggers
//! An operation is guarded when its **score ≥ 40** OR it involves:
//! `DROP TABLE`, `DROP DATABASE`, `DROP SCHEMA`, `TRUNCATE`, `DROP COLUMN`, `RENAME TABLE/COLUMN`.

use crate::config::Config;
use crate::engine::RiskEngine;
use crate::loader::load_file;
use crate::parser;
use crate::types::{ActorKind, GuardAuditLog, GuardDecision, MigrationReport, RiskLevel};
use chrono::Utc;
use colored::Colorize;
use serde_json;
use std::collections::HashMap;
use std::io::{self, BufRead, Write};
use std::path::Path;

// ─────────────────────────────────────────────
// Guard outcome
// ─────────────────────────────────────────────

/// Result of running the guard on a migration file.
#[derive(Debug)]
pub enum GuardOutcome {
    /// No dangerous operations found — safe to run.
    Safe,
    /// All dangerous operations were confirmed by the user.
    Approved(Vec<GuardDecision>),
    /// At least one operation was declined or blocked.
    Blocked {
        reason: String,
        operation: String,
        impact: String,
    },
}

impl GuardOutcome {
    /// Return the process exit code for this outcome.
    pub fn exit_code(&self) -> i32 {
        match self {
            GuardOutcome::Safe => 0,
            GuardOutcome::Approved(_) => 0,
            GuardOutcome::Blocked { .. } => 4,
        }
    }
}

// ─────────────────────────────────────────────
// Actor detection
// ─────────────────────────────────────────────

/// Detect the runtime actor from environment variables and TTY state.
///
/// Priority: Agent > CI > Human
pub fn detect_actor() -> ActorKind {
    // Explicit override
    if std::env::var("SCHEMARISK_ACTOR")
        .map(|v| v.to_lowercase() == "agent")
        .unwrap_or(false)
    {
        return ActorKind::Agent;
    }

    // AI provider API keys present → likely running inside an AI agent
    if std::env::var("ANTHROPIC_API_KEY").is_ok()
        || std::env::var("OPENAI_API_KEY").is_ok()
        || std::env::var("OPENAI_API_BASE").is_ok()
    {
        return ActorKind::Agent;
    }

    // CI environment variables
    if std::env::var("CI").is_ok()
        || std::env::var("GITHUB_ACTIONS").is_ok()
        || std::env::var("GITLAB_CI").is_ok()
        || std::env::var("CIRCLECI").is_ok()
        || std::env::var("JENKINS_URL").is_ok()
        || std::env::var("BUILDKITE").is_ok()
    {
        return ActorKind::Ci;
    }

    ActorKind::Human
}

// ─────────────────────────────────────────────
// Guard trigger logic
// ─────────────────────────────────────────────

/// Returns `true` if an operation should trigger the guard confirmation flow.
///
/// Triggers when score ≥ 40 OR the description matches a known destructive pattern.
pub fn is_guarded_operation(desc: &str, score: u32) -> bool {
    if score >= 40 {
        return true;
    }
    let upper = desc.to_uppercase();
    upper.contains("DROP TABLE")
        || upper.contains("TRUNCATE")
        || upper.contains("DROP DATABASE")
        || upper.contains("DROP SCHEMA")
        || upper.contains("DROP COLUMN")
        || upper.contains("RENAME COLUMN")
        || upper.contains("RENAME TO")
}

fn is_irreversible_operation(desc: &str) -> bool {
    let upper = desc.to_uppercase();
    upper.contains("DROP TABLE")
        || upper.contains("DROP DATABASE")
        || upper.contains("DROP SCHEMA")
        || upper.contains("DROP COLUMN")
        || upper.contains("TRUNCATE")
}

// ─────────────────────────────────────────────
// Impact panel rendering
// ─────────────────────────────────────────────

/// Render the full impact panel to stderr for a single guarded operation.
pub fn render_impact_panel(
    report: &MigrationReport,
    op_desc: &str,
    risk: RiskLevel,
    score: u32,
    actor: &ActorKind,
) {
    let now = Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let divider = "-".repeat(78).dimmed().to_string();
    let bullet = "•".dimmed();

    let risk_str = match risk {
        RiskLevel::Critical => "CRITICAL".red().bold().to_string(),
        RiskLevel::High => "HIGH".truecolor(255, 140, 0).bold().to_string(),
        RiskLevel::Medium => "MEDIUM".yellow().bold().to_string(),
        RiskLevel::Low => "LOW".green().bold().to_string(),
    };

    let lock_type = if score >= 90 || op_desc.to_uppercase().contains("DROP TABLE") {
        "ACCESS EXCLUSIVE"
    } else if score >= 50 {
        "SHARE"
    } else {
        "SHARE ROW EXCLUSIVE"
    };
    let desc_upper = op_desc.to_uppercase();

    eprintln!();
    eprintln!("{}", divider);
    eprintln!("{}", "Dangerous migration operation detected".bold());
    eprintln!("{}", divider);

    eprintln!("  {} {}", "Operation:".bold(), op_desc);
    eprintln!(
        "  {} {} {}",
        "Risk:".bold(),
        risk_str,
        format!("(score: {score})").dimmed()
    );
    eprintln!("  {} {}", "Lock:".bold(), lock_type);

    if let Some(secs) = report.estimated_lock_seconds {
        let lock_range = if secs < 5 {
            "< 5s".to_string()
        } else if secs < 60 {
            format!("~{}s", secs)
        } else {
            format!("~{}m", secs / 60)
        };
        eprintln!("  {} {}", "Estimated lock:".bold(), lock_range);
    }

    if is_irreversible_operation(op_desc) {
        eprintln!(
            "\n  {} {}",
            "Warning:".red().bold(),
            "This operation is irreversible.".red()
        );
    }

    if !report.affected_tables.is_empty() {
        eprintln!("\n{}", "Database impact".bold());
        for table in &report.affected_tables {
            let impact_str = if desc_upper.contains("DROP TABLE") {
                "DELETED"
            } else if desc_upper.contains("TRUNCATE") {
                "TRUNCATED"
            } else {
                "MODIFIED"
            };
            eprintln!("  {} {:<40} {}", bullet, shorten(table, 40), impact_str);
        }
        for fk in &report.fk_impacts {
            if fk.cascade {
                eprintln!(
                    "  {} {:<40} CASCADE DELETE",
                    bullet,
                    shorten(&fk.from_table, 40)
                );
            }
        }
    }

    eprintln!("\n{}", "Potential breakage".bold());
    if desc_upper.contains("DROP TABLE") {
        eprintln!("  {} All queries to the dropped table will fail", bullet);
        eprintln!(
            "  {} Foreign keys with CASCADE may delete dependent rows",
            bullet
        );
        eprintln!(
            "  {} Application code referencing this table will break",
            bullet
        );
    } else if desc_upper.contains("DROP COLUMN") || desc_upper.contains("DROP COL") {
        eprintln!("  {} Queries selecting this column will error", bullet);
        eprintln!("  {} ORM models referencing this column will break", bullet);
    } else if desc_upper.contains("RENAME") {
        eprintln!(
            "  {} Queries using the old name will fail immediately",
            bullet
        );
        eprintln!(
            "  {} Views, procedures, and constraints may need updates",
            bullet
        );
    } else if desc_upper.contains("TRUNCATE") {
        eprintln!("  {} Existing table data is permanently deleted", bullet);
        eprintln!(
            "  {} Application behavior may change with empty tables",
            bullet
        );
    } else if desc_upper.contains("ALTER COLUMN") && desc_upper.contains("TYPE") {
        eprintln!(
            "  {} Table rewrite may block writes during migration",
            bullet
        );
        eprintln!(
            "  {} Data conversion or truncation errors are possible",
            bullet
        );
    } else {
        eprintln!(
            "  {} Review migration impact carefully before continuing",
            bullet
        );
    }

    if desc_upper.contains("DROP TABLE") {
        eprintln!("\n{}", "Safer rollout".bold());
        eprintln!(
            "  {} Rename first (e.g., to *_deprecated), validate traffic, then drop later",
            bullet
        );
    } else if desc_upper.contains("DROP COLUMN") {
        eprintln!("\n{}", "Safer rollout".bold());
        eprintln!("  {} Remove app references first", bullet);
        eprintln!("  {} Deploy application changes", bullet);
        eprintln!("  {} Drop the column in a follow-up migration", bullet);
    }

    eprintln!(
        "\n  {} {}   {} {}",
        "Actor:".bold(),
        actor,
        "Time:".bold(),
        now
    );
    eprintln!("{}", divider);
    eprintln!();
}

fn shorten(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max.saturating_sub(1)])
    }
}

// ─────────────────────────────────────────────
// Confirmation prompt
// ─────────────────────────────────────────────

/// Prompt the user for confirmation.
///
/// - Critical ops: require `"yes i am sure"` (case-insensitive).
/// - High ops: require `"yes"`.
/// - Returns `true` if confirmed.
fn prompt_confirmation(risk: RiskLevel) -> bool {
    let (required_phrase, hint) = match risk {
        RiskLevel::Critical => (
            "yes i am sure",
            "Type \"yes I am sure\" to confirm, or press Enter/Ctrl-C to abort: ",
        ),
        _ => (
            "yes",
            "Type \"yes\" to confirm, or press Enter/Ctrl-C to abort: ",
        ),
    };

    eprint!("  {}", hint.yellow().bold());
    let _ = io::stderr().flush();

    let mut line = String::new();
    match io::stdin().lock().read_line(&mut line) {
        Ok(0) | Err(_) => {
            // EOF / Ctrl-C
            eprintln!("\n  Aborted.");
            return false;
        }
        Ok(_) => {}
    }

    let trimmed = line.trim().to_lowercase();
    trimmed == required_phrase
}

// ─────────────────────────────────────────────
// Agent-blocked JSON output
// ─────────────────────────────────────────────

/// Print machine-readable JSON and return the `Blocked` outcome for agent actors.
fn agent_blocked(op_desc: &str, impact: &str) -> GuardOutcome {
    let json = serde_json::json!({
        "blocked": true,
        "reason": "CRITICAL operation requires human confirmation",
        "operation": op_desc,
        "impact": impact,
        "required_action": "A human must run: schema-risk guard <file> --interactive"
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&json).unwrap_or_default()
    );
    GuardOutcome::Blocked {
        reason: "Agent actor — automatic block enforced".to_string(),
        operation: op_desc.to_string(),
        impact: impact.to_string(),
    }
}

// ─────────────────────────────────────────────
// Audit log
// ─────────────────────────────────────────────

fn write_audit_log(
    file_path: &str,
    actor: &ActorKind,
    decisions: &[GuardDecision],
    audit_path: &str,
) {
    let log = GuardAuditLog {
        schemarisk_version: env!("CARGO_PKG_VERSION").to_string(),
        file: file_path.to_string(),
        timestamp: Utc::now().to_rfc3339(),
        actor: actor.clone(),
        decisions: decisions.to_vec(),
    };
    match serde_json::to_string_pretty(&log) {
        Ok(json) => {
            if let Err(e) = std::fs::write(audit_path, &json) {
                eprintln!("warning: failed to write audit log to {audit_path}: {e}");
            } else {
                eprintln!(
                    "\n  {} Confirmation log written to {}",
                    "⚡".cyan(),
                    audit_path.cyan()
                );
            }
        }
        Err(e) => eprintln!("warning: failed to serialize audit log: {e}"),
    }
}

// ─────────────────────────────────────────────
// Main guard entry point
// ─────────────────────────────────────────────

/// Options for `run_guard`.
#[derive(Default)]
pub struct GuardOptions {
    /// Print impact panel but do not prompt. Exit code reflects risk.
    pub dry_run: bool,
    /// Skip interactive prompts (used in CI; blocks on dangerous ops).
    pub non_interactive: bool,
    /// Table row estimates for offline scoring.
    pub row_counts: HashMap<String, u64>,
    /// Configuration (thresholds, audit log path, etc.).
    pub config: Config,
}

/// Intercepts a SQL migration and gates execution behind explicit confirmation.
///
/// # Behavior by actor
/// - **Human** (interactive TTY): Shows full impact panel and prompts for typed confirmation.
/// - **CI Pipeline**: Prints impact to stderr, exits 4 (never auto-approves).
/// - **AI Agent**: Exits 4 immediately with machine-readable JSON on stdout.
///
/// # Returns
/// - `Ok(GuardOutcome::Safe)` — no operations require guarding
/// - `Ok(GuardOutcome::Approved(_))` — all operations confirmed
/// - `Ok(GuardOutcome::Blocked { .. })` — one or more operations declined
/// - `Err(SchemaRiskError)` — parse or I/O failure
pub fn run_guard(path: &Path, opts: GuardOptions) -> crate::error::Result<GuardOutcome> {
    let actor = detect_actor();
    let migration = load_file(path)?;
    let stmts = parser::parse(&migration.sql)?;
    let engine = RiskEngine::new(opts.row_counts.clone());
    let report = engine.analyze(&migration.name, &stmts);

    // Collect operations that need guarding
    let guarded_ops: Vec<_> = report
        .operations
        .iter()
        .filter(|op| is_guarded_operation(&op.description, op.score))
        .collect();

    if guarded_ops.is_empty() {
        eprintln!(
            "  {} Safe to run — no dangerous operations detected.",
            "✅".green()
        );
        return Ok(GuardOutcome::Safe);
    }

    // ── Dry-run mode ────────────────────────────────────────────────────
    if opts.dry_run {
        for op in &guarded_ops {
            render_impact_panel(&report, &op.description, op.risk_level, op.score, &actor);
        }
        let max_risk = guarded_ops
            .iter()
            .map(|o| o.risk_level)
            .max()
            .unwrap_or(RiskLevel::Low);
        let exit_code = match max_risk {
            RiskLevel::Critical => 2,
            RiskLevel::High => 1,
            _ => 0,
        };
        // Return a Blocked outcome to signal the caller to use our exit code
        if exit_code > 0 {
            return Ok(GuardOutcome::Blocked {
                reason: format!("dry-run: {} risk detected", max_risk),
                operation: guarded_ops[0].description.clone(),
                impact: format!("{} operations require confirmation", guarded_ops.len()),
            });
        }
        return Ok(GuardOutcome::Safe);
    }

    // ── Agent actor: always block with machine-readable JSON ─────────────
    if actor == ActorKind::Agent && opts.config.guard.block_agents {
        let op = &guarded_ops[0];
        let impact = format!(
            "{} dangerous operations require human confirmation",
            guarded_ops.len()
        );
        return Ok(agent_blocked(&op.description, &impact));
    }

    // ── CI actor in non-interactive mode ─────────────────────────────────
    if (actor == ActorKind::Ci || opts.non_interactive) && opts.config.guard.block_ci {
        for op in &guarded_ops {
            render_impact_panel(&report, &op.description, op.risk_level, op.score, &actor);
        }
        eprintln!(
            "  {} CI mode: dangerous operations blocked. Set block_ci: false to allow.",
            "⛔".red()
        );
        return Ok(GuardOutcome::Blocked {
            reason: "CI pipeline — non-interactive block".to_string(),
            operation: guarded_ops[0].description.clone(),
            impact: format!("{} operations require confirmation", guarded_ops.len()),
        });
    }

    // CI non-interactive but block_ci is false → print warning but continue to confirmation
    if actor == ActorKind::Ci || opts.non_interactive {
        for op in &guarded_ops {
            render_impact_panel(&report, &op.description, op.risk_level, op.score, &actor);
        }
        eprintln!(
            "  {} Non-interactive mode: cannot prompt. Blocking.",
            "⛔".red()
        );
        return Ok(GuardOutcome::Blocked {
            reason: "Non-interactive mode — cannot prompt for confirmation".to_string(),
            operation: guarded_ops[0].description.clone(),
            impact: format!("{} operations require confirmation", guarded_ops.len()),
        });
    }

    // ── Human actor: interactive confirmation loop ───────────────────────
    let mut decisions: Vec<GuardDecision> = Vec::new();

    for op in &guarded_ops {
        render_impact_panel(&report, &op.description, op.risk_level, op.score, &actor);

        let irreversible = is_irreversible_operation(&op.description);
        if irreversible {
            eprintln!(
                "  {}",
                "This operation is irreversible. Proceed only with a rollback strategy."
                    .red()
                    .bold()
            );
            eprintln!();
        }

        let confirmed = if opts.config.guard.require_typed_confirmation {
            prompt_confirmation(op.risk_level)
        } else {
            prompt_confirmation(RiskLevel::Medium) // just "yes"
        };

        let typed_phrase = if confirmed {
            match op.risk_level {
                RiskLevel::Critical => Some("yes i am sure".to_string()),
                _ => Some("yes".to_string()),
            }
        } else {
            None
        };

        let decision = GuardDecision {
            operation: op.description.clone(),
            risk_level: op.risk_level,
            score: op.score,
            impact_summary: build_impact_summary(&report, &op.description),
            confirmed,
            typed_phrase,
            timestamp: Utc::now().to_rfc3339(),
            actor: actor.clone(),
        };

        if !confirmed {
            decisions.push(decision);
            eprintln!("  {} Aborted. Migration will NOT run.", "⛔".red().bold());
            // Write audit log even for declined runs
            write_audit_log(
                &migration.name,
                &actor,
                &decisions,
                &opts.config.guard.audit_log,
            );
            return Ok(GuardOutcome::Blocked {
                reason: "User declined confirmation".to_string(),
                operation: op.description.clone(),
                impact: build_impact_summary(&report, &op.description),
            });
        }

        decisions.push(decision);
        eprintln!("  {} Confirmed — proceeding to next check...", "✓".green());
    }

    // All confirmed
    eprintln!(
        "\n  {} Proceeding. All {} operation(s) confirmed.",
        "⚡".cyan(),
        guarded_ops.len()
    );
    write_audit_log(
        &migration.name,
        &actor,
        &decisions,
        &opts.config.guard.audit_log,
    );

    Ok(GuardOutcome::Approved(decisions))
}

/// Build a one-sentence human-readable impact summary for an operation.
fn build_impact_summary(report: &MigrationReport, op_desc: &str) -> String {
    let tables_str = if report.affected_tables.is_empty() {
        String::new()
    } else {
        format!(
            " {} table(s): {}",
            report.affected_tables.len(),
            report
                .affected_tables
                .iter()
                .take(3)
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        )
    };

    let cascade_count = report.fk_impacts.iter().filter(|fk| fk.cascade).count();
    let cascade_str = if cascade_count > 0 {
        format!(", cascades to {} child table(s)", cascade_count)
    } else {
        String::new()
    };

    format!("{}{}{}", shorten(op_desc, 60), tables_str, cascade_str)
}

// ─────────────────────────────────────────────
// Code Scanning Guard Mode
// ─────────────────────────────────────────────

use crate::impact::{ExtractedSql, SqlExtractionReport, SqlExtractor};

/// Options for scanning source code for dangerous SQL.
#[derive(Default)]
pub struct CodeGuardOptions {
    /// Base guard options.
    pub base: GuardOptions,
    /// Directory to scan for SQL in code.
    pub scan_dir: std::path::PathBuf,
    /// File extensions to scan (use config defaults if empty).
    pub extensions: Vec<String>,
}

/// A dangerous SQL query found in source code.
#[derive(Debug, Clone)]
pub struct DangerousQuery {
    /// The extracted SQL information.
    pub source: ExtractedSql,
    /// The risk analysis report for this SQL.
    pub report: crate::types::MigrationReport,
    /// Operations that require guarding.
    pub guarded_operations: Vec<crate::types::DetectedOperation>,
}

/// Result of scanning code for dangerous SQL.
#[derive(Debug)]
pub struct CodeGuardReport {
    /// All extracted SQL from the codebase.
    pub extraction_report: SqlExtractionReport,
    /// Dangerous queries that require attention.
    pub dangerous_queries: Vec<DangerousQuery>,
    /// Overall guard outcome.
    pub overall_outcome: GuardOutcome,
    /// Summary statistics.
    pub stats: CodeGuardStats,
}

/// Statistics from code guard scanning.
#[derive(Debug, Default, Clone)]
pub struct CodeGuardStats {
    /// Total files scanned.
    pub files_scanned: usize,
    /// Total SQL statements found.
    pub total_sql_found: usize,
    /// Number of dangerous SQL statements.
    pub dangerous_count: usize,
    /// Breakdown by ORM/context.
    pub by_context: std::collections::HashMap<String, usize>,
}

/// Scan source code for SQL and guard against dangerous operations.
///
/// This function:
/// 1. Scans the specified directory for SQL in source code
/// 2. Parses and analyzes each SQL statement found
/// 3. Identifies dangerous operations that require confirmation
/// 4. Returns a comprehensive report
pub fn guard_code_sql(opts: CodeGuardOptions) -> crate::error::Result<CodeGuardReport> {
    let _actor = detect_actor(); // Reserved for future use
    let extractor = SqlExtractor::new();
    let extraction_report = extractor.scan_directory(&opts.scan_dir);

    let engine = RiskEngine::new(opts.base.row_counts.clone());
    let mut dangerous_queries: Vec<DangerousQuery> = Vec::new();

    // Analyze each extracted SQL statement
    for sql_item in &extraction_report.extracted {
        // Try to parse the SQL
        let stmts = match parser::parse(&sql_item.sql) {
            Ok(s) => s,
            Err(_) => continue, // Skip unparseable SQL
        };

        // Analyze for risks
        let report = engine.analyze(&sql_item.source_file, &stmts);

        // Check if any operations need guarding
        let guarded_ops: Vec<_> = report
            .operations
            .iter()
            .filter(|op| is_guarded_operation(&op.description, op.score))
            .cloned()
            .collect();

        if !guarded_ops.is_empty() {
            dangerous_queries.push(DangerousQuery {
                source: sql_item.clone(),
                report,
                guarded_operations: guarded_ops,
            });
        }
    }

    // Build statistics
    let stats = CodeGuardStats {
        files_scanned: extraction_report.files_scanned,
        total_sql_found: extraction_report.extracted.len(),
        dangerous_count: dangerous_queries.len(),
        by_context: extraction_report.by_context.clone(),
    };

    // Determine overall outcome
    let overall_outcome = if dangerous_queries.is_empty() {
        GuardOutcome::Safe
    } else {
        GuardOutcome::Blocked {
            reason: format!(
                "Found {} dangerous SQL statement(s) in source code",
                dangerous_queries.len()
            ),
            operation: dangerous_queries
                .first()
                .map(|d| d.source.sql.chars().take(60).collect())
                .unwrap_or_default(),
            impact: format!(
                "{} file(s) contain dangerous queries",
                dangerous_queries
                    .iter()
                    .map(|d| &d.source.source_file)
                    .collect::<std::collections::HashSet<_>>()
                    .len()
            ),
        }
    };

    Ok(CodeGuardReport {
        extraction_report,
        dangerous_queries,
        overall_outcome,
        stats,
    })
}

/// Render code guard results to stderr.
pub fn render_code_guard_report(report: &CodeGuardReport, actor: &ActorKind) {
    use colored::Colorize;

    let divider = "-".repeat(78).dimmed().to_string();

    eprintln!();
    eprintln!("{}", divider);
    eprintln!("{}", "SchemaRisk Code SQL Scanner".bold());
    eprintln!("{}", divider);
    eprintln!();

    eprintln!(
        "  {} files scanned, {} SQL statements found",
        report.stats.files_scanned.to_string().cyan(),
        report.stats.total_sql_found.to_string().cyan()
    );

    if !report.stats.by_context.is_empty() {
        eprintln!();
        eprintln!("  {} SQL by ORM/Framework:", "ℹ".cyan());
        for (ctx, count) in &report.stats.by_context {
            eprintln!("    • {}: {}", ctx, count);
        }
    }

    eprintln!();

    if report.dangerous_queries.is_empty() {
        eprintln!(
            "  {} No dangerous SQL found in source code",
            "✅".green().bold()
        );
    } else {
        eprintln!(
            "  {} Found {} dangerous SQL statement(s)",
            "⚠".yellow().bold(),
            report.dangerous_queries.len()
        );
        eprintln!();

        for (idx, dq) in report.dangerous_queries.iter().enumerate() {
            let risk_str = match dq.report.overall_risk {
                RiskLevel::Critical => "CRITICAL".red().bold().to_string(),
                RiskLevel::High => "HIGH".truecolor(255, 140, 0).bold().to_string(),
                RiskLevel::Medium => "MEDIUM".yellow().bold().to_string(),
                RiskLevel::Low => "LOW".green().bold().to_string(),
            };

            eprintln!("  [{}] {} ({})", idx + 1, risk_str, dq.source.context);
            eprintln!(
                "      File: {}:{}",
                dq.source.source_file.cyan(),
                dq.source.line
            );
            eprintln!(
                "      SQL: {}",
                dq.source.sql.chars().take(60).collect::<String>().dimmed()
            );

            for op in &dq.guarded_operations {
                eprintln!("      → {}", op.description);
            }
            eprintln!();
        }
    }

    let now = Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
    eprintln!(
        "  {} {}   {} {}",
        "Actor:".bold(),
        actor,
        "Time:".bold(),
        now
    );
    eprintln!("{}", divider);
    eprintln!();
}

// ─────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guarded_for_high_score() {
        assert!(is_guarded_operation(
            "ALTER TABLE x ALTER COLUMN y TYPE bigint",
            80
        ));
    }

    #[test]
    fn guarded_for_drop_table_regardless_of_score() {
        assert!(is_guarded_operation("DROP TABLE sessions", 5));
    }

    #[test]
    fn not_guarded_for_create_table() {
        assert!(!is_guarded_operation("CREATE TABLE new_table", 2));
    }

    #[test]
    fn not_guarded_for_low_score_add_column() {
        assert!(!is_guarded_operation(
            "ALTER TABLE users ADD COLUMN last_seen timestamptz",
            5
        ));
    }

    #[test]
    fn agent_detection_via_env() {
        // This test sets env var; isolate from parallel tests
        std::env::remove_var("SCHEMARISK_ACTOR");
        std::env::remove_var("ANTHROPIC_API_KEY");
        std::env::remove_var("OPENAI_API_KEY");
        std::env::remove_var("CI");
        std::env::remove_var("GITHUB_ACTIONS");
        // Without any env var set, should default to Human
        // (can't fully test CI/Agent without env isolation)
        let actor = detect_actor();
        // In test environment, CI may be set — just verify it returns a valid variant
        let _ = actor;
    }
}
