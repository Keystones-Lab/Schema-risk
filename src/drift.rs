//! Schema drift detection.
//!
//! `schema-risk diff --db-url postgres://...` connects to a live database and
//! compares what the database actually contains against what you would expect
//! based on the migration files you have.
//!
//! This answers the question: "Has someone edited the production schema by
//! hand, or are there migrations that haven't run yet?"
//!
//! Compiled unconditionally; the actual DB connection is feature-gated.

use crate::db::LiveSchema;
use crate::graph::SchemaGraph;
use crate::types::RiskLevel;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

// ─────────────────────────────────────────────
// Drift finding types
// ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum DriftFinding {
    /// Table exists in the DB but not in any migration file
    ExtraTable { table: String },
    /// Table is in migration files but not in the DB (migration not run yet)
    MissingTable { table: String },
    /// Column type in DB doesn't match the migration definition
    ColumnTypeMismatch {
        table: String,
        column: String,
        in_migration: String,
        in_database: String,
    },
    /// Column exists in DB but not in migration
    ExtraColumn { table: String, column: String },
    /// Column is in migration but not in DB
    MissingColumn { table: String, column: String },
    /// Index exists in DB but the migration never created it
    ExtraIndex { table: String, index: String },
    /// Migration creates an index that isn't in the DB (not applied)
    MissingIndex { table: String, index: String },
    /// Nullable mismatch
    NullableMismatch {
        table: String,
        column: String,
        in_migration: bool,
        in_database: bool,
    },
}

impl DriftFinding {
    pub fn severity(&self) -> RiskLevel {
        match self {
            DriftFinding::ExtraTable { .. } => RiskLevel::High,
            DriftFinding::MissingTable { .. } => RiskLevel::Critical,
            DriftFinding::ColumnTypeMismatch { .. } => RiskLevel::Critical,
            DriftFinding::ExtraColumn { .. } => RiskLevel::Low,
            DriftFinding::MissingColumn { .. } => RiskLevel::High,
            DriftFinding::ExtraIndex { .. } => RiskLevel::Low,
            DriftFinding::MissingIndex { .. } => RiskLevel::Medium,
            DriftFinding::NullableMismatch { .. } => RiskLevel::Medium,
        }
    }

    pub fn description(&self) -> String {
        match self {
            DriftFinding::ExtraTable { table } => {
                format!(
                    "Table '{}' exists in the database but not in any migration file",
                    table
                )
            }
            DriftFinding::MissingTable { table } => {
                format!(
                    "Table '{}' is defined in migrations but not found in the live database",
                    table
                )
            }
            DriftFinding::ColumnTypeMismatch {
                table,
                column,
                in_migration,
                in_database,
            } => {
                format!(
                    "Column '{}.{}': migration says '{}' but database has '{}'",
                    table, column, in_migration, in_database
                )
            }
            DriftFinding::ExtraColumn { table, column } => {
                format!(
                    "Column '{}.{}' exists in database but not in migration files",
                    table, column
                )
            }
            DriftFinding::MissingColumn { table, column } => {
                format!(
                    "Column '{}.{}' is in migration files but not in the database",
                    table, column
                )
            }
            DriftFinding::ExtraIndex { table, index } => {
                format!(
                    "Index '{}' on '{}' exists in database but not in migration files",
                    index, table
                )
            }
            DriftFinding::MissingIndex { table, index } => {
                format!(
                    "Index '{}' on '{}' is in migration files but not in the database",
                    index, table
                )
            }
            DriftFinding::NullableMismatch {
                table,
                column,
                in_migration,
                in_database,
            } => {
                format!(
                    "Nullable mismatch on '{}.{}': migration says nullable={}, database says nullable={}",
                    table, column, in_migration, in_database
                )
            }
        }
    }
}

// ─────────────────────────────────────────────
// Drift report
// ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftReport {
    pub overall_drift: RiskLevel,
    pub total_findings: usize,
    pub findings: Vec<DriftFinding>,
    pub migration_tables: Vec<String>,
    pub database_tables: Vec<String>,
    pub in_sync: bool,
}

impl DriftReport {
    pub fn is_clean(&self) -> bool {
        self.findings.is_empty()
    }
}

// ─────────────────────────────────────────────
// Diff engine
// ─────────────────────────────────────────────

/// Compare the schema graph inferred from migration files against the live
/// database snapshot.
pub fn diff(migration_graph: &SchemaGraph, live: &LiveSchema) -> DriftReport {
    let mut findings: Vec<DriftFinding> = Vec::new();

    let migration_tables: Vec<String> = migration_graph.all_tables();
    let database_tables: Vec<String> = live.tables.keys().cloned().collect();

    // Case-insensitive table lookup maps (lowercase name -> canonical name)
    let migration_table_lookup: HashMap<String, String> = migration_tables
        .iter()
        .map(|t| (t.to_ascii_lowercase(), t.clone()))
        .collect();
    let database_table_lookup: HashMap<String, String> = database_tables
        .iter()
        .map(|t| (t.to_ascii_lowercase(), t.clone()))
        .collect();

    let migration_table_set: HashSet<String> = migration_table_lookup.keys().cloned().collect();
    let database_table_set: HashSet<String> = database_table_lookup.keys().cloned().collect();

    // Precompute migration indexes by table (all lowercase for case-insensitive matching)
    let mut migration_indexes_by_table: HashMap<String, HashSet<String>> = HashMap::new();
    for (idx_name, &node) in &migration_graph.index_index {
        if let crate::graph::SchemaNode::Index { table, .. } = &migration_graph.graph[node] {
            migration_indexes_by_table
                .entry(table.to_ascii_lowercase())
                .or_default()
                .insert(idx_name.to_ascii_lowercase());
        }
    }

    // Precompute live indexes by table (excluding PK indexes)
    let mut live_indexes_by_table: HashMap<String, HashSet<String>> = HashMap::new();
    for (idx_name, idx_meta) in &live.indexes {
        if !idx_meta.is_primary {
            live_indexes_by_table
                .entry(idx_meta.table.to_ascii_lowercase())
                .or_default()
                .insert(idx_name.to_ascii_lowercase());
        }
    }

    // Tables in DB but not in migrations
    for table_key in database_table_set.difference(&migration_table_set) {
        if let Some(db_table) = database_table_lookup.get(table_key) {
            findings.push(DriftFinding::ExtraTable {
                table: db_table.clone(),
            });
        }
    }

    // Tables in migrations but not in DB
    for table_key in migration_table_set.difference(&database_table_set) {
        if let Some(mig_table) = migration_table_lookup.get(table_key) {
            findings.push(DriftFinding::MissingTable {
                table: mig_table.clone(),
            });
        }
    }

    // For tables that exist in both, check columns and indexes
    for mig_table in &migration_tables {
        let Some(db_table_name) = database_table_lookup.get(&mig_table.to_ascii_lowercase()) else {
            continue;
        };
        let live_meta = live.tables.get(db_table_name);

        let Some(live_meta) = live_meta else { continue };

        // Get migration columns from the graph
        let mig_column_lookup: HashMap<String, String> = migration_graph
            .column_index
            .keys()
            .filter(|k| k.starts_with(&format!("{}.", mig_table)))
            .map(|k| {
                let col = k.split('.').nth(1).unwrap_or("").to_string();
                (col.to_ascii_lowercase(), col)
            })
            .collect();

        let live_column_lookup: HashMap<String, &crate::db::ColumnMeta> = live_meta
            .columns
            .iter()
            .map(|c| (c.name.to_ascii_lowercase(), c))
            .collect();

        let mig_column_set: HashSet<String> = mig_column_lookup.keys().cloned().collect();
        let live_column_set: HashSet<String> = live_column_lookup.keys().cloned().collect();

        // Columns in DB but not in migration
        for col_key in live_column_set.difference(&mig_column_set) {
            if let Some(live_col) = live_column_lookup.get(col_key) {
                findings.push(DriftFinding::ExtraColumn {
                    table: mig_table.clone(),
                    column: live_col.name.clone(),
                });
            }
        }

        // Columns in migration but not in DB
        for col_key in mig_column_set.difference(&live_column_set) {
            if let Some(mig_col) = mig_column_lookup.get(col_key) {
                findings.push(DriftFinding::MissingColumn {
                    table: mig_table.clone(),
                    column: mig_col.clone(),
                });
            }
        }

        // Check nullable mismatch for columns that exist in both
        for col_key in mig_column_set.intersection(&live_column_set) {
            let Some(mig_col) = mig_column_lookup.get(col_key) else {
                continue;
            };
            let Some(live_col) = live_column_lookup.get(col_key) else {
                continue;
            };

            let key = format!("{}.{}", mig_table, mig_col);
            if let Some(&node_idx) = migration_graph.column_index.get(&key) {
                if let crate::graph::SchemaNode::Column {
                    nullable: mig_nullable,
                    ..
                } = &migration_graph.graph[node_idx]
                {
                    let db_nullable = live_col.is_nullable;
                    if *mig_nullable != db_nullable {
                        findings.push(DriftFinding::NullableMismatch {
                            table: mig_table.clone(),
                            column: mig_col.clone(),
                            in_migration: *mig_nullable,
                            in_database: db_nullable,
                        });
                    }
                }
            }
        }

        // Indexes: check DB indexes that don't appear in migration
        let table_key = mig_table.to_ascii_lowercase();
        let live_idx_set = live_indexes_by_table.get(&table_key).cloned().unwrap_or_default();
        let mig_idx_set = migration_indexes_by_table
            .get(&table_key)
            .cloned()
            .unwrap_or_default();

        for idx_name in live_idx_set.difference(&mig_idx_set) {
            if let Some(real_idx_name) = live
                .indexes
                .keys()
                .find(|name| name.eq_ignore_ascii_case(idx_name))
            {
                findings.push(DriftFinding::ExtraIndex {
                    table: mig_table.clone(),
                    index: real_idx_name.clone(),
                });
            }
        }

        // Indexes in migration but not in DB
        for idx_name in mig_idx_set.difference(&live_idx_set) {
            if let Some(real_idx_name) = migration_graph
                .index_index
                .keys()
                .find(|name| name.eq_ignore_ascii_case(idx_name))
            {
                findings.push(DriftFinding::MissingIndex {
                    table: mig_table.clone(),
                    index: real_idx_name.clone(),
                });
            }
        }
    }

    let overall_drift = findings
        .iter()
        .map(|f| f.severity())
        .max()
        .unwrap_or(RiskLevel::Low);

    let total_findings = findings.len();

    DriftReport {
        overall_drift,
        total_findings,
        findings,
        migration_tables,
        database_tables,
        in_sync: total_findings == 0,
    }
}
