# SchemaRisk

> Stop database outages before they happen. Analyze SQL migrations for production risk in milliseconds.

```
schema-risk analyze migrations/005_alter_orders.sql
```

```
╔══════════════════════════════════════════════════════════════════╗
  🚨 HIGH RISK MIGRATION   score: 80   file: 005_alter_orders.sql
╚══════════════════════════════════════════════════════════════════╝

  Table         : orders
  Operation     : ALTER COLUMN total TYPE bigint
  Lock          : ACCESS EXCLUSIVE — writes blocked for entire duration
  Estimated lock: ~3m – 5m  (based on ~2.1M rows)
  Index rebuild : YES

  ⚠  Full table rewrite required. All INSERT/UPDATE/DELETE are blocked.
  ⚠  Consider the shadow-column pattern for a zero-downtime migration.

  Recommendations:
  → Add shadow column orders.total_v2 bigint
  → Back-fill in batches (10k rows at a time)
  → Deploy app to write to both columns
  → Rename columns atomically
  → Drop old column after health checks pass

Exit code 1 (risk >= high threshold)
```

---

## The problem

Engineers push migrations like this without knowing the blast radius:

```sql
-- Looks harmless. Causes a 4-minute production outage on 2M rows.
ALTER TABLE orders ALTER COLUMN total TYPE bigint;

-- Looks like a cleanup. Crashes the whole app immediately.
ALTER TABLE users DROP COLUMN email;

-- Looks like an index. Blocks all writes for 90 seconds.
CREATE INDEX idx_orders_status ON orders(status);
```

`schema-risk` catches all of these **before** they run — locally, in CI, or via AI agent guard.

---

## Install

**Recommended — cargo install (one command, no dependencies):**

```bash
cargo install schema-risk
```

**Or build from source:**

```bash
git clone https://github.com/Ayuussshhh/schema-risk
cd schema-risk
cargo build --release
cp target/release/schema-risk /usr/local/bin/
```

**Linux/macOS curl installer** _(once binaries are published to GitHub Releases)_:

```bash
curl -fsSL https://raw.githubusercontent.com/Ayuussshhh/schema-risk/main/install.sh | bash
```

Verify it works:

```bash
schema-risk --version
```

---

## Quick start — 60 seconds

```bash
# 1. Generate a starter config (optional but recommended)
schema-risk init

# 2. Analyze a migration file
schema-risk analyze migrations/001_add_users.sql

# 3. Guard a dangerous migration (requires typed confirmation)
schema-risk guard migrations/005_drop_orders.sql

# 4. Preview what guard would block without running it
schema-risk guard --dry-run migrations/005_drop_orders.sql

# 5. Check all migrations at once
schema-risk ci-report "migrations/*.sql" --format github-comment
```

---

## The guard — crown feature

`schema-risk guard` intercepts destructive SQL and requires **explicit human confirmation** before it runs. It also blocks AI agents automatically.

```bash
schema-risk guard migrations/drop_legacy_tables.sql --db-url $DATABASE_URL
```

```
╔══════════════════════════════════════════════════════════════════════╗
║  ⚠  DANGEROUS OPERATION DETECTED — CONFIRMATION REQUIRED            ║
╠══════════════════════════════════════════════════════════════════════╣
║  Operation  : DROP TABLE "orders"                                    ║
║  Risk Level : CRITICAL  (score: 100)                                 ║
║  Lock Type  : ACCESS EXCLUSIVE                                       ║
║  Est. Lock  : ~3m – 5m (based on ~2.1M rows)                        ║
╠══════════════════════════════════════════════════════════════════════╣
║  DATABASE IMPACT                                                     ║
║  ┌──────────────────────────────────────────────────────────────┐   ║
║  │ Table         Impact                                         │   ║
║  │ orders        DELETED permanently                            │   ║
║  │ order_items   CASCADE → also DELETED                         │   ║
║  └──────────────────────────────────────────────────────────────┘   ║
╠══════════════════════════════════════════════════════════════════════╣
║  Actor: human (interactive terminal)   Time: 2025-03-13 14:22:01   ║
╚══════════════════════════════════════════════════════════════════════╝

  This action is IRREVERSIBLE. All data will be permanently destroyed.

  Type "yes I am sure" to confirm, or press Enter/Ctrl-C to abort:
```

### How actors are handled

| Actor | Detected by | Behavior |
|-------|-------------|----------|
| Human | Interactive TTY | Full panel + typed confirmation |
| CI pipeline | `CI=true`, `GITHUB_ACTIONS=true` | Prints panel, exits 4 (never auto-approves) |
| AI agent | `ANTHROPIC_API_KEY`, `OPENAI_API_KEY` | Exits 4 immediately with machine-readable JSON |

**AI agent response** (exits 4, no prompt):
```json
{
  "blocked": true,
  "reason": "CRITICAL operation requires human confirmation",
  "operation": "DROP TABLE orders",
  "required_action": "A human must run: schema-risk guard migration.sql --interactive"
}
```

After confirmation, an audit log is written to `.schemarisk-audit.json`.

**Safe pipeline pattern:**
```bash
schema-risk guard migrations/005_drop.sql && psql -f migrations/005_drop.sql
```

---

## CI/CD Integration

### GitHub Actions — one file, works out of the box

Copy this to `.github/workflows/schema-risk.yml`:

```yaml
name: Schema Risk Check
on:
  pull_request:
    paths: ['migrations/**/*.sql', 'db/**/*.sql', '**/*.sql']

jobs:
  schema-risk:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }

      - name: Install schema-risk
        run: cargo install schema-risk

      - name: Get changed SQL files
        id: changed
        run: |
          echo "files=$(git diff --name-only --diff-filter=ACM \
            origin/${{ github.base_ref }}...HEAD \
            | grep '\.sql$' | tr '\n' ' ')" >> $GITHUB_OUTPUT

      - name: Analyze migrations
        if: steps.changed.outputs.files != ''
        run: |
          schema-risk ci-report ${{ steps.changed.outputs.files }} \
            --format github-comment \
            --fail-on high \
            > schemarisk-report.md
        env:
          SCHEMA_RISK_DB_URL: ${{ secrets.SCHEMA_RISK_DB_URL }}

      - name: Post PR comment
        if: always() && steps.changed.outputs.files != ''
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            if (!fs.existsSync('schemarisk-report.md')) return;
            const report = fs.readFileSync('schemarisk-report.md', 'utf8');
            const marker = '<!-- schema-risk-report -->';
            const body = marker + '\n' + report;
            const comments = await github.rest.issues.listComments({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo
            });
            const existing = comments.data.find(c => c.body.startsWith(marker));
            if (existing) {
              await github.rest.issues.updateComment({
                comment_id: existing.id, body,
                owner: context.repo.owner, repo: context.repo.repo
              });
            } else {
              await github.rest.issues.createComment({
                issue_number: context.issue.number, body,
                owner: context.repo.owner, repo: context.repo.repo
              });
            }
```

Every PR that touches a `.sql` file gets an automatic risk report posted as a comment.

### Pre-commit hook

```bash
cat > .git/hooks/pre-commit << 'EOF'
#!/bin/sh
STAGED=$(git diff --cached --name-only | grep '\.sql$')
if [ -n "$STAGED" ]; then
  schema-risk analyze $STAGED --fail-on high || {
    echo "❌ High-risk migration detected. Fix before committing."
    exit 1
  }
fi
EOF
chmod +x .git/hooks/pre-commit
```

---

## All commands

### `analyze` — risk report

```bash
schema-risk analyze migrations/001.sql
schema-risk analyze "migrations/*.sql"                        # glob
schema-risk analyze migrations/001.sql --format json          # JSON output
schema-risk analyze migrations/001.sql --format sarif         # GitHub Code Scanning
schema-risk analyze migrations/001.sql --fail-on critical     # only fail on CRITICAL
schema-risk analyze migrations/001.sql --verbose              # show all operations
schema-risk analyze migrations/001.sql \
  --table-rows "users:5000000,orders:2000000"                 # row count hints
schema-risk analyze migrations/001.sql \
  --db-url postgres://user:pass@host/db                       # live row counts
schema-risk analyze migrations/001.sql --show-locks           # lock timeline
```

### `guard` — gated execution

```bash
schema-risk guard migrations/005_drop.sql                     # interactive
schema-risk guard migrations/005_drop.sql --dry-run           # preview only
schema-risk guard migrations/005_drop.sql --non-interactive   # CI mode
schema-risk guard migrations/005_drop.sql \
  --table-rows "orders:2100000"                               # offline row hints
```

### `fix` — auto-rewrite risky SQL

```bash
schema-risk fix migrations/001.sql                            # apply fixes in-place
schema-risk fix migrations/001.sql --dry-run                  # preview diff only
schema-risk fix migrations/001.sql --output migrations/001_fixed.sql
```

### `explain` — step-by-step breakdown

```bash
schema-risk explain migrations/001.sql
```

### `ci-report` — PR comment

```bash
schema-risk ci-report "migrations/*.sql" --format github-comment
schema-risk ci-report "migrations/*.sql" --format gitlab-comment
schema-risk ci-report "migrations/*.sql" --format json
```

### `graph` — schema dependency visualization

```bash
schema-risk graph "migrations/*.sql"                          # ASCII text
schema-risk graph "migrations/*.sql" --format mermaid         # Mermaid diagram
schema-risk graph "migrations/*.sql" --format graphviz        # Graphviz DOT
```

### `diff` — compare live DB vs migrations

```bash
schema-risk diff "migrations/*.sql" --db-url postgres://user:pass@host/db
```

### `init` — generate config

```bash
schema-risk init                      # writes schema-risk.yml
schema-risk init --force              # overwrite existing
```

---

## Configuration (`schema-risk.yml`)

```bash
schema-risk init    # generates this file
```

```yaml
version: 2

thresholds:
  fail_on: high          # low | medium | high | critical
  guard_on: medium       # trigger guard at this level and above

rules:
  disabled: []           # disable specific rules e.g. [R03, R07]
  table_overrides:
    sessions:
      ignored: true      # skip analysis for this table

scan:
  root_dir: "."
  extensions: [rs, py, go, ts, js, rb, java, kt]
  exclude: [target/, node_modules/, vendor/]
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
```

---

## Risk scoring

| Level | Score | Meaning |
|-------|-------|---------|
| **LOW** | 0–29 | Safe to deploy anytime |
| **MEDIUM** | 30–59 | Review before deploying |
| **HIGH** | 60–89 | Requires maintenance window |
| **CRITICAL** | 90+ | Do not deploy without a rollback plan |

### Operations and scores

| Operation | Score | Lock | Why dangerous |
|-----------|-------|------|---------------|
| `DROP TABLE` | 100 | ACCESS EXCLUSIVE | Irreversible, cascades to FKs |
| `TRUNCATE` | 90 | ACCESS EXCLUSIVE | Destroys all data instantly |
| `DROP COLUMN` (large table) | 85 | ACCESS EXCLUSIVE | Irreversible |
| `ALTER COLUMN TYPE` | 80 | ACCESS EXCLUSIVE | Full table rewrite |
| `SET NOT NULL` | 75 | ACCESS EXCLUSIVE | Full table scan |
| `ADD COLUMN NOT NULL` no default | 70 | ACCESS EXCLUSIVE | Fails with existing rows |
| `CREATE INDEX` (no CONCURRENTLY) | 60 | SHARE | Blocks writes during build |
| `ADD FOREIGN KEY` | 50 | SHARE ROW EXCLUSIVE | Full table scan |
| `DROP INDEX` | 40 | ACCESS EXCLUSIVE | May break query plans |
| `RENAME COLUMN / TABLE` | 30 | ACCESS EXCLUSIVE | Breaks all app references |
| `CREATE TABLE` | 5 | ACCESS EXCLUSIVE | Safe |

**Table-size multiplier** (with `--db-url` or `--table-rows`):

| Rows | Multiplier |
|------|-----------|
| < 10k | ×1.0 |
| 10k – 100k | ×1.25 |
| 100k – 1M | ×1.5 |
| > 1M | ×2.0 |

---

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | No risk above threshold |
| 1 | At least one HIGH risk |
| 2 | At least one CRITICAL risk |
| 3 | Parse / IO / DB error |
| 4 | Guard blocked execution (user declined or agent blocked) |

---

## Auto-fix rules

| Rule | Trigger | Auto-fixable |
|------|---------|-------------|
| R01 | `CREATE INDEX` without `CONCURRENTLY` | ✅ Yes |
| R02 | `ADD COLUMN NOT NULL` without `DEFAULT` | Step-by-step plan |
| R03 | `DROP COLUMN` on large table | Step-by-step plan |
| R04 | `ADD FOREIGN KEY` without index on FK column | Emits `CREATE INDEX CONCURRENTLY` |
| R05 | `RENAME COLUMN` | Expand-contract plan |
| R06 | `RENAME TABLE` | Expand-contract plan |
| R07 | `ALTER COLUMN TYPE` | Shadow-column plan |
| R08 | Long `ACCESS EXCLUSIVE` lock | lock_timeout wrapper |

```bash
schema-risk fix migrations/001.sql --dry-run    # preview changes
schema-risk fix migrations/001.sql              # apply in-place
```

---

## Performance

- Parses a 500-table schema in < 200 ms
- Parallelizes impact scanning over file trees with `rayon`
- Release binary < 8 MB (stripped, LTO, `panic = "abort"`)
- Zero runtime dependencies — single static binary

---

## Architecture

```
SQL File
  └─► parser.rs    sqlparser-rs → ParsedStatement
        └─► engine.rs     risk rules → MigrationReport
              ├─► locks.rs      lock timeline simulation
              ├─► graph.rs      petgraph FK dependency graph
              ├─► impact.rs     rayon file-tree scan (what breaks)
              └─► output.rs     terminal / JSON / SARIF / Markdown
```

Core modules: `engine` · `parser` · `guard` · `config` · `sarif` · `locks` · `graph` · `impact` · `recommendation` · `ci` · `drift`

---

## Contributing

```bash
git clone https://github.com/Ayuussshhh/schema-risk
cd schema-risk
cargo test           # run all tests
cargo clippy         # lint
cargo fmt            # format
```

Tests live in `tests/` (integration) and each `src/*.rs` file (unit).

---

## License

MIT
