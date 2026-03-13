//! SARIF 2.1.0 output formatter for GitHub Code Scanning integration.
//!
//! Converts `MigrationReport` slices into a Static Analysis Results
//! Interchange Format (SARIF) document that GitHub can ingest as code
//! scanning alerts.
//!
//! Enable with `--format sarif` or `--features sarif`.

use crate::types::{MigrationReport, RiskLevel};
use serde_json::Value;

// ─────────────────────────────────────────────
// SARIF rule table
// ─────────────────────────────────────────────

/// Maps a description keyword or operation type to a SARIF rule ID.
struct SarifRule {
    id: &'static str,
    name: &'static str,
    short: &'static str,
    full: &'static str,
}

const RULES: &[SarifRule] = &[
    SarifRule {
        id: "SR001",
        name: "DropTable",
        short: "DROP TABLE destroys data permanently",
        full: "DROP TABLE removes the table and all its data permanently. \
               Consider renaming the table first and dropping after a full release cycle.",
    },
    SarifRule {
        id: "SR002",
        name: "AlterColumnType",
        short: "ALTER COLUMN TYPE causes full table rewrite",
        full: "Changing a column type requires PostgreSQL to rewrite the entire table \
               under an ACCESS EXCLUSIVE lock, blocking all reads and writes.",
    },
    SarifRule {
        id: "SR003",
        name: "DropColumn",
        short: "DROP COLUMN is irreversible",
        full: "Dropping a column is irreversible and holds an ACCESS EXCLUSIVE lock. \
               Deploy app changes first, then drop the column in a follow-up migration.",
    },
    SarifRule {
        id: "SR004",
        name: "SetNotNull",
        short: "SET NOT NULL requires full table scan",
        full: "Adding a NOT NULL constraint triggers a full table scan to validate \
               existing rows. Use a check constraint with NOT VALID first.",
    },
    SarifRule {
        id: "SR005",
        name: "AddColumnNoDefault",
        short: "NOT NULL column without DEFAULT fails on non-empty tables",
        full: "Adding a NOT NULL column without a default value fails immediately \
               if the table has existing rows.",
    },
    SarifRule {
        id: "SR006",
        name: "CreateIndexBlocking",
        short: "CREATE INDEX without CONCURRENTLY blocks writes",
        full: "Building an index without CONCURRENTLY holds a SHARE lock that blocks \
               all INSERT, UPDATE, and DELETE for the duration of the build.",
    },
    SarifRule {
        id: "SR007",
        name: "AddForeignKey",
        short: "ADD FOREIGN KEY acquires ShareRowExclusive lock",
        full: "Adding a foreign key constraint validates the entire table and acquires \
               a ShareRowExclusive lock. Validate the constraint with NOT VALID first.",
    },
    SarifRule {
        id: "SR008",
        name: "DropIndex",
        short: "DROP INDEX without CONCURRENTLY acquires ACCESS EXCLUSIVE lock",
        full: "Dropping an index without CONCURRENTLY blocks all access to the table. \
               Use DROP INDEX CONCURRENTLY instead.",
    },
    SarifRule {
        id: "SR009",
        name: "RenameOperation",
        short: "RENAME breaks all downstream code instantly",
        full: "Renaming a table or column invalidates all queries, ORM models, \
               views, and stored procedures referencing the old name.",
    },
    SarifRule {
        id: "SR010",
        name: "TruncateTable",
        short: "TRUNCATE permanently destroys all table data",
        full: "TRUNCATE removes all rows from the table instantly. This operation is \
               not easily reversible without a backup.",
    },
    SarifRule {
        id: "SR999",
        name: "UnmodelledDDL",
        short: "Unmodelled DDL — manual review required",
        full: "This DDL statement was not fully analysed. It may acquire locks or \
               modify data in unexpected ways. Review before deploying.",
    },
];

fn rule_for_description(desc: &str) -> &'static SarifRule {
    let upper = desc.to_uppercase();
    if upper.contains("DROP TABLE") {
        return &RULES[0];
    }
    if upper.contains("TYPE ") || (upper.contains("ALTER COLUMN") && upper.contains("TYPE")) {
        return &RULES[1];
    }
    if upper.contains("DROP COLUMN") {
        return &RULES[2];
    }
    if upper.contains("SET NOT NULL") {
        return &RULES[3];
    }
    if upper.contains("NOT NULL") && upper.contains("NO DEFAULT") {
        return &RULES[4];
    }
    if upper.contains("CREATE") && upper.contains("INDEX") && !upper.contains("CONCURRENTLY") {
        return &RULES[5];
    }
    if upper.contains("FOREIGN KEY") {
        return &RULES[6];
    }
    if upper.contains("DROP INDEX") {
        return &RULES[7];
    }
    if upper.contains("RENAME") {
        return &RULES[8];
    }
    if upper.contains("TRUNCATE") {
        return &RULES[9];
    }
    // Default fallback
    &RULES[10]
}

fn sarif_level(risk: RiskLevel) -> &'static str {
    match risk {
        RiskLevel::Critical | RiskLevel::High => "error",
        RiskLevel::Medium => "warning",
        RiskLevel::Low => "note",
    }
}

// ─────────────────────────────────────────────
// Public entry point
// ─────────────────────────────────────────────

/// Render a slice of `MigrationReport`s as a SARIF 2.1.0 JSON document.
///
/// The returned string is valid JSON ready to be written to a file and uploaded
/// to GitHub Code Scanning via the `upload-sarif` action.
pub fn render_sarif(reports: &[MigrationReport]) -> String {
    // Collect unique rules referenced
    let mut rule_ids_used: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for report in reports {
        for op in &report.operations {
            let rule = rule_for_description(&op.description);
            rule_ids_used.insert(rule.id);
        }
    }

    // Build rules array
    let rules: Vec<Value> = RULES
        .iter()
        .filter(|r| rule_ids_used.contains(r.id))
        .map(|r| {
            serde_json::json!({
                "id": r.id,
                "name": r.name,
                "shortDescription": { "text": r.short },
                "fullDescription": { "text": r.full },
                "defaultConfiguration": {
                    "level": "error"
                },
                "helpUri": "https://github.com/Ayuussshhh/newBase-backend",
                "help": { "text": r.full }
            })
        })
        .collect();

    // Build results array
    let mut results: Vec<Value> = Vec::new();
    for report in reports {
        for op in &report.operations {
            if op.score == 0 && op.risk_level == RiskLevel::Low {
                continue; // skip truly-safe ops
            }
            let rule = rule_for_description(&op.description);
            let warning_text = op.warning.as_deref().unwrap_or(&op.description);

            results.push(serde_json::json!({
                "ruleId": rule.id,
                "level": sarif_level(op.risk_level),
                "message": {
                    "text": warning_text
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": report.file,
                            "uriBaseId": "%SRCROOT%"
                        }
                    }
                }],
                "properties": {
                    "riskScore": op.score,
                    "riskLevel": op.risk_level.to_string(),
                    "tables": op.tables
                }
            }));
        }
    }

    let sarif = serde_json::json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "SchemaRisk",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/Ayuussshhh/newBase-backend",
                    "rules": rules
                }
            },
            "results": results,
            "columnKind": "utf16CodeUnits"
        }]
    });

    serde_json::to_string_pretty(&sarif)
        .unwrap_or_else(|e| format!("{{\"error\": \"SARIF serialisation failed: {e}\"}}"))
}

// ─────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sarif_output_is_valid_json() {
        let report = MigrationReport {
            file: "test.sql".to_string(),
            overall_risk: crate::types::RiskLevel::High,
            score: 80,
            affected_tables: vec!["users".to_string()],
            operations: vec![crate::types::DetectedOperation {
                description: "ALTER TABLE users ALTER COLUMN email TYPE text".to_string(),
                tables: vec!["users".to_string()],
                risk_level: crate::types::RiskLevel::High,
                score: 80,
                warning: Some("Type change causes full table rewrite".to_string()),
                acquires_lock: true,
                index_rebuild: true,
            }],
            warnings: vec![],
            recommendations: vec![],
            fk_impacts: vec![],
            estimated_lock_seconds: Some(5),
            index_rebuild_required: true,
            requires_maintenance_window: true,
            analyzed_at: "2025-01-01T00:00:00Z".to_string(),
            guard_required: false,
            guard_decisions: vec![],
        };

        let sarif = render_sarif(&[report]);
        let parsed: serde_json::Value = serde_json::from_str(&sarif).expect("valid JSON");
        assert_eq!(parsed["version"], "2.1.0");
        assert!(parsed["runs"].is_array());
        assert!(!parsed["runs"][0]["results"].as_array().unwrap().is_empty());
    }

    #[test]
    fn rule_lookup_drop_table() {
        let rule = rule_for_description("DROP TABLE orders");
        assert_eq!(rule.id, "SR001");
    }
}
