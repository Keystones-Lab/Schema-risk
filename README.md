# SchemaRisk

> **Stop dangerous database migrations before they reach production.**

SchemaRisk is a production-grade PostgreSQL migration safety analyzer.  
It understands your migrations the way a senior DBA does — flags dangerous operations, generates safe alternatives, and posts risk reports directly in your pull requests.

---

## Why SchemaRisk

Schema migrations fail in production for predictable reasons:

- `ALTER TABLE ... ALTER COLUMN TYPE` rewrites the entire table under lock
- `CREATE INDEX` without `CONCURRENTLY` blocks all writes for minutes
- `DROP COLUMN` breaks application code before it's been removed
- `ADD COLUMN NOT NULL` fails instantly on tables with existing rows
- `ADD COLUMN DEFAULT` on PostgreSQL 10 rewrites the table; on PG11+ it's free

SchemaRisk detects all of these, explains exactly why they are dangerous, and gives you the step-by-step safe alternative.

---

## Key Features

| Feature | Description |
|---|---|
| **Risk scoring** | Every dangerous operation scored by severity + table size |
| **PG version-aware rules** | `ADD COLUMN DEFAULT` behaves differently on PG10 vs PG11+ — SchemaRisk knows this |
| **Safe migration generator** | Not just "danger detected" — gives you the exact zero-downtime SQL to run instead |
| **Repository impact scanner** | Finds which files in your codebase reference the changed tables/columns |
| **PR comment reports** | Posts a full migration report as a GitHub/GitLab PR comment automatically |
| **`guard` mode** | Interactive confirmation gate for dangerous operations before they run |
| **Schema drift detection** | Compares migration files against a live database to find drift |
| **SARIF output** | GitHub Security tab integration |

---

## Installation

### From crates.io

```bash
cargo install schema-risk
```

### From source

```bash
git clone https://github.com/Keystones-Lab/Schema-risk
cd Schema-risk
cargo build --release
```

Binary: `target/release/schema-risk`

---

## Quick start

```bash
# Analyze one migration — know the risk before you deploy
schema-risk analyze migrations/001_add_index.sql

# Use the correct PostgreSQL version for accurate scoring
schema-risk analyze migrations/001.sql --pg-version 14

# Get safe alternatives for everything risky
schema-risk fix migrations/001.sql --dry-run

# Post a full report to your PR
schema-risk ci-report "migrations/*.sql" --format github-comment

# Guard dangerous operations with typed confirmation
schema-risk guard migrations/005_breaking.sql
```

---

## Example output

### Terminal (`analyze`)

```
 SchemaRisk Analysis  202406_add_index.sql

  Migration Risk:  HIGH   (score: 72)

  Tables affected: users
  Estimated lock duration: ~90 sec
  Index rebuild required: YES
  Requires maintenance window: YES

  Warnings:
    ! CREATE INDEX on 'users' without CONCURRENTLY will hold a SHARE lock
      for the duration of the index build (cols: email)

  Recommendations:
    CREATE INDEX CONCURRENTLY idx_email ON users(email);
 This migration should NOT be deployed without review
```

### Safe Migration Generator (`fix`)

For a dangerous type change like:
```sql
ALTER TABLE users ALTER COLUMN email TYPE text;
```

SchemaRisk outputs a complete zero-downtime plan:

```sql
-- Step 1: Add shadow column with new type
ALTER TABLE users ADD COLUMN email_v2 text;

-- Step 2: Back-fill in batches (run until 0 rows updated)
UPDATE users
  SET email_v2 = email::text
  WHERE email_v2 IS NULL
  LIMIT 10000;

-- Step 3: Deploy app to write to both columns

-- Step 4: Atomically swap column names
ALTER TABLE users RENAME COLUMN email     TO email_old;
ALTER TABLE users RENAME COLUMN email_v2  TO email;

-- Step 5: Drop old column after verifying app health
ALTER TABLE users DROP COLUMN email_old;
```

### PR Comment Report (`ci-report`)

When a migration is included in a PR, SchemaRisk automatically posts:

> ** SchemaRisk — Migration Safety Report (PostgreSQL 14)**
>
> | File | Risk | Score | Lock | Est. Duration |
> |------|:----:|------:|------|--------------:|
> | `202406_add_index.sql` | **HIGH** | 72 | `SHARE` | ~90s |
>
> **Safe Alternative:**
> ```sql
> CREATE INDEX CONCURRENTLY idx_email ON users(email);
> ```
>
> **Impact:** 12 files reference `users.email`

---

## PostgreSQL version-aware scoring

Pass `--pg-version` to get accurate risk scores for your specific PostgreSQL version.

| Operation | PG10 | PG11+ |
|---|---|---|
| `ADD COLUMN DEFAULT` |Full table rewrite | Metadata-only |
| `SET NOT NULL` | Full scan, long lock | CHECK constraint safe alternative on PG12+ |
| `ALTER COLUMN TYPE` | Full rewrite (all versions) | Full rewrite (all versions) |

```bash
# Score correctly for an older production database
schema-risk analyze migrations/ --pg-version 10

# Or target PG14 (default)
schema-risk analyze migrations/ --pg-version 14
```

---

## Commands

### `analyze`
Analyze one or more SQL files and report risk.

```bash
schema-risk analyze migrations/001.sql
schema-risk analyze "migrations/*.sql" --verbose
schema-risk analyze migrations/001.sql --pg-version 14
schema-risk analyze migrations/001.sql --format json
schema-risk analyze migrations/001.sql --format markdown
schema-risk analyze migrations/001.sql --format sarif
schema-risk analyze migrations/001.sql --show-locks
schema-risk analyze migrations/001.sql --scan-dir ./src
schema-risk analyze migrations/001.sql --table-rows "users:5000000,orders:2000000"
schema-risk analyze migrations/001.sql --fail-on critical
```

### `fix`
Apply auto-fixes where supported and show zero-downtime migration plans for everything else.

```bash
schema-risk fix migrations/001.sql
schema-risk fix migrations/001.sql --dry-run
schema-risk fix migrations/001.sql --output migrations/001_fixed.sql
```

### `ci-report`
Generate GitHub/GitLab PR comments or JSON CI output.

```bash
schema-risk ci-report "migrations/*.sql" --format github-comment
schema-risk ci-report "migrations/*.sql" --format github-comment --pg-version 14
schema-risk ci-report "migrations/*.sql" --format json
schema-risk ci-report "migrations/*.sql" --scan-dir ./services --fail-on critical
```

### `explain`
Show a detailed, statement-by-statement breakdown.

```bash
schema-risk explain migrations/001.sql
```

### `graph`
Render the schema dependency graph from migration files.

```bash
schema-risk graph "migrations/*.sql"               # text
schema-risk graph "migrations/*.sql" --format mermaid
schema-risk graph "migrations/*.sql" --format graphviz
```

### `diff`
Compare expected schema (from migrations) against a live database to detect drift.

```bash
schema-risk diff "migrations/*.sql" --db-url postgres://user:pass@host/db
```

### `guard`
Intercept dangerous operations and require explicit confirmation before allowing them to run.

```bash
schema-risk guard migrations/005_drop.sql
schema-risk guard migrations/005_drop.sql --dry-run
schema-risk guard migrations/005_drop.sql --non-interactive

# Usage pattern (blocks the migration unless confirmed)
schema-risk guard migration.sql && psql -f migration.sql
```

### `init`
Create a starter `schema-risk.yml` config file.

```bash
schema-risk init
schema-risk init --force
```

---

## Automatic PR Migration Reports

Add SchemaRisk to your GitHub Actions workflow and get automatic risk reports on every PR that touches migration files.

### Setup (2 minutes)

Copy `.github/workflows/schema-risk.yml` from this repo into your project, then set `PG_VERSION` to match your production database:

```yaml
env:
  PG_VERSION: "14"  # Set to your production PostgreSQL version
```

That's it. Every PR with SQL changes will now receive a comment like this:

>**HIGH RISK** — significant impact on database availability.  
> Review all findings carefully before merging.
>
> | File | Risk | Score | Lock | Est. Duration | Breaking Changes |
> |------|:----:|------:|------|---:|:----|
> | `202406_add_index.sql` |**HIGH** | 72 | `SHARE` | ~90s |3 file(s) |
>
>Generated by SchemaRisk — Prevent dangerous migrations before they reach production.

### Why this matters for your team

When engineers review PRs, they see the risk report. Engineers on other teams ask "what is SchemaRisk?"  
Then they install it too.

This is how devtools grow organically — by being useful in the places developers already work.

---

## Guard behavior by actor

| Actor | Detection | Behavior |
|---|---|---|
| Human | Interactive terminal | Shows impact panel and prompts for confirmation |
| CI | `CI`, `GITHUB_ACTIONS`, etc. | Blocks dangerous ops in non-interactive mode |
| Agent | AI provider env indicators | Blocks and emits machine-readable result |

Guard output includes:
- Operation summary
- Risk + lock metadata  
- Affected objects
- Likely breakage
- Full audit trail (`.schemarisk-audit.json`)

---

## Configuration (`schema-risk.yml`)

Generate a starter file:

```bash
schema-risk init
```

Example:

```yaml
version: 2

thresholds:
  fail_on: high
  guard_on: medium

rules:
  disabled: []
  table_overrides:
    sessions:
      ignored: true

scan:
  root_dir: "."
  extensions: [rs, py, go, ts, js, rb, java, kt]
  exclude: [target/, node_modules/, vendor/, .git/]
  skip_short_identifiers: true

guard:
  require_typed_confirmation: true
  audit_log: ".schemarisk-audit.json"
  block_agents: true
  block_ci: false

output:
  format: terminal
  color: true
  show_recommendations: true
  show_impact: true
```

---

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success / below configured threshold |
| 1 | Risk meets or exceeds fail threshold |
| 2 | Parse/IO/database command error |
| 3 | Guard runtime error |
| 4 | Guard blocked execution |

---

## Development

```bash
cargo test
cargo clippy -- -D warnings
cargo fmt --all
```

---

## License

MIT
