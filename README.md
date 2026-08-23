# MS SQL Server MCP Server

[![npm version](https://img.shields.io/npm/v/@piyapat/mssql-mcp-server.svg)](https://www.npmjs.com/package/@piyapat/mssql-mcp-server)
[![npm downloads](https://img.shields.io/npm/dm/@piyapat/mssql-mcp-server.svg)](https://www.npmjs.com/package/@piyapat/mssql-mcp-server)
[![node](https://img.shields.io/node/v/@piyapat/mssql-mcp-server.svg)](https://nodejs.org)
[![license](https://img.shields.io/npm/l/@piyapat/mssql-mcp-server.svg)](LICENSE)
[![Sponsor](https://img.shields.io/badge/Sponsor-%E2%9D%A4-ff69b4)](https://github.com/sponsors/PiyapatRag)

A secure, read-only Model Context Protocol (MCP) server for Microsoft SQL Server with built-in performance monitoring and lock detection.

📦 **npm:** [@piyapat/mssql-mcp-server](https://www.npmjs.com/package/@piyapat/mssql-mcp-server)

## Quick Start with npx

You can run this MCP server directly without installation using `npx`:

```bash
npx @piyapat/mssql-mcp-server
```

## Installation

### Option 1: Use with npx (Recommended for Testing)

```bash
# Run directly with environment variables
MSSQL_SERVER=localhost \
MSSQL_DATABASE=mydb \
MSSQL_USER=readonly \
MSSQL_PASSWORD=password \
npx @piyapat/mssql-mcp-server
```

### Option 2: Global Installation

```bash
# Install globally
npm install -g @piyapat/mssql-mcp-server

# Run
mssql-mcp-server
```

### Option 3: Local Installation

```bash
# Clone and install
git clone https://github.com/PiyapatRag/mssql-mcp-server.git
cd mssql-mcp-server
npm install
npm run build

# Run
npm start
```

## Configuration

### Step 1: Create a `.env` file (Recommended)

Credentials live in a `.env` file — **not** hard-coded in the MCP client's JSON config:

```bash
cp .env.example .env
# then edit .env with your credentials
```

The server looks for a `.env` file in this order (first found wins):

1. The path in `MSSQL_ENV_FILE` (explicit override)
2. `.env` in the current working directory
3. `.env` in the project root (next to `package.json`)

Variables already set in the MCP client's `"env"` block always take precedence
over the `.env` file, and `.env` is git-ignored.

### Step 2: Point Claude Desktop at the server

Edit your Claude Desktop config:

**Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

**macOS/Linux:** `~/Library/Application Support/Claude/claude_desktop_config.json`

With a `.env` in the project root, no credentials are needed in the JSON at all:

```json
{
  "mcpServers": {
    "mssql": {
      "command": "node",
      "args": ["C:\\path\\to\\mssql-mcp-server\\build\\index.js"]
    }
  }
}
```

If the `.env` lives somewhere else, pass only its path:

```json
{
  "mcpServers": {
    "mssql": {
      "command": "node",
      "args": ["C:\\path\\to\\mssql-mcp-server\\build\\index.js"],
      "env": {
        "MSSQL_ENV_FILE": "C:\\secure\\location\\mssql.env"
      }
    }
  }
}
```

Setting variables directly in the `"env"` block still works (and overrides the
`.env` file) — useful for npx setups or running several servers against
different databases.

## Environment Variables

| Variable | Description | Default | Required |
| --- | --- | --- | --- |
| `MSSQL_SERVER` | SQL Server hostname or IP | `localhost` | Yes |
| `MSSQL_DATABASE` | Database name | - | Yes |
| `MSSQL_USER` | SQL Server username (or domain user when `MSSQL_DOMAIN` is set) | - | Yes |
| `MSSQL_PASSWORD` | Password | - | Yes |
| `MSSQL_DOMAIN` | Windows/NTLM domain. When set, Windows Authentication is used instead of SQL authentication | - | No |
| `MSSQL_PORT` | SQL Server port | `1433` | No |
| `MSSQL_ENCRYPT` | Encrypt the connection (true/false). Only a literal `false` disables it | `true` | No |
| `MSSQL_TRUST_CERT` | Skip certificate validation (true/false). Opt-in — leave off in production | `false` | No |
| `MSSQL_READ_ONLY` | `true` = read-only allow-list validation. `false` = write mode: INSERT/UPDATE/DELETE/DDL allowed, but server-level dangerous statements stay blocked | `true` | No |
| `MSSQL_ALLOWED_PROCEDURES` | Comma-separated whitelist of stored procedures `EXEC` may call in read-only mode, e.g. `dbo.GetReport,dbo.GetCustomerSummary`. Empty/unset disables `EXEC` entirely. | - | No |
| `MSSQL_ENV_FILE` | Explicit path to a `.env` file | - | No |
| `MSSQL_REQUEST_TIMEOUT` | Query timeout in ms | `30000` | No |
| `MSSQL_POOL_MAX` | Max pooled connections | `10` | No |
| `MSSQL_AUDIT_LOG` | Log every tool call to stderr as one JSON line (tool, mode, truncated query, row counts, duration, outcome). Set `false` to disable | `true` | No |
| `MSSQL_VERBOSE_ERRORS` | Return the driver's full error text to the client. Off by default: errors are capped to their first line so a failing query can't be used to map the schema. Full detail always goes to stderr | `false` | No |

## Server Modes

### Read-only mode (`MSSQL_READ_ONLY=true`, default)

`mssql_query` accepts only:

- A single `SELECT` / `WITH...SELECT`
- A multi-statement batch led by `DECLARE`, `INSERT`, or `CREATE TABLE #...`
  that writes **only to session-local `#temp` tables / `@table` variables** —
  e.g. `INSERT INTO #t SELECT ...` or
  `CREATE TABLE #t (...); INSERT INTO #t ...; SELECT * FROM #t`.
  `CREATE INDEX ... ON #t`, `TRUNCATE/ALTER/DROP TABLE #t` are also allowed
  inside such batches. **Global `##temp` tables are never allowed** (they are
  visible to every session, so they count as persistent).
- `EXEC` of a whitelisted procedure whose definition does not write to a persistent table

Everything else is rejected: writes/DDL on persistent objects, dynamic SQL,
`EXEC` inside batches (prevents bypassing the procedure whitelist), `DBCC`,
and stacked statements after a `SELECT`/`WITH`/`EXEC`.

### Write mode (`MSSQL_READ_ONLY=false`)

`INSERT` / `UPDATE` / `DELETE` / DDL are permitted, but these are **always blocked**
regardless of mode:

`xp_cmdshell`, `xp_reg*` (read and write), `xp_dirtree`, `xp_fileexist`,
`sp_OA*`, `sp_configure`, `RECONFIGURE`, `SHUTDOWN`, `KILL`, `DROP DATABASE`,
`ALTER DATABASE`, `RESTORE`, `BULK INSERT`, `CREATE ASSEMBLY`,
`CREATE/ALTER/DROP LOGIN/USER/CREDENTIAL/CERTIFICATE`, `ALTER SERVER`,
`ALTER SERVER ROLE`/`ALTER ROLE`, `sp_addrolemember`/`sp_addsrvrolemember`/
`sp_droprolemember`, `sp_addlinkedserver`, `EXECUTE AS`, `sp_executesql`,
`GRANT`/`DENY`/`REVOKE`, `OPENROWSET`/`OPENDATASOURCE`/`OPENQUERY`.

> ⚠️ Use write mode only with a SQL login whose own permissions are equally
> limited — the database login remains the primary security boundary.

## Key Features

### Security First
- ✅ **Two-layer read-only enforcement** - A database read-only login (primary) plus an application-level allow-list (defense-in-depth). The app accepts `SELECT` / `WITH...SELECT`, `DECLARE` batches that write only to `#temp` tables / `@table` variables, and `EXEC` of whitelisted procedures whose definitions never write to a persistent table
- ✅ **Quote-aware SQL scanning** - Comments and literals are removed in a single left-to-right pass that tracks quote state, so a `--` or `;` hidden inside a string literal cannot smuggle a second statement past the analyzer
- ✅ **Parameterized queries** - Built-in SQL injection protection
- ✅ **SSL/TLS by default** - Encryption and certificate validation are opt-out, not opt-in
- ✅ **Streamed result paging** - Rows are streamed and the read is cancelled one row past the requested page, so a large `SELECT` can't exhaust the server's memory
- ✅ **Audit trail** - Every tool call is logged to stderr as one JSON line (`MSSQL_AUDIT_LOG`)
- ✅ **Connection pooling** - Optimized resource management

### Performance Monitoring
- 📊 **Real-time lock detection** - Identify blocking and deadlock situations
- 📈 **Resource usage tracking** - CPU, memory, and query performance metrics
- 🔍 **Top query analysis** - Find resource-intensive queries
- ⚡ **Session monitoring** - Track active and blocked sessions

### Database Exploration
- 🗂️ **Schema introspection** - Tables, columns, keys, and constraints
- 📝 **Stored procedure analysis** - View definitions and parameters
- 🔎 **Intelligent querying** - Natural language to SQL with Claude

## Available Tools (19)

### Core

| Tool | Description |
| --- | --- |
| `mssql_query` | Execute SQL. Read-only validation by default; write mode via `MSSQL_READ_ONLY=false` (dangerous server-level statements always blocked). Pagination + JSON/Markdown output. |
| `mssql_test_connection` | Test connectivity; returns server/edition/version, database, login, and current mode. |
| `mssql_list_databases` | All databases with state, recovery model, compatibility level. |
| `mssql_list_tables` | Tables with row count and size (MB), optionally filtered by schema. |
| `mssql_sample_data` | Preview rows from a table (default 10, max 100) — no SQL needed, injection-safe. |

### Schema exploration

| Tool | Description |
| --- | --- |
| `mssql_get_schema` | Columns, data types, PK/FK per table. |
| `mssql_get_relationships` | Foreign-key graph: from/to table+column, delete/update actions. |
| `mssql_get_views` | Views with full SQL definitions. |
| `mssql_get_stored_procedures` | Stored procedures with parameters and full definitions. |
| `mssql_search_definitions` | Search the source of all procs/views/functions/triggers for a text fragment — impact analysis for legacy systems. |

### Performance & storage

| Tool | Description |
| --- | --- |
| `mssql_analyze_indexes` | Index usage stats (seeks/scans/updates) + optimizer-suggested missing indexes. |
| `mssql_index_fragmentation` | Fragmentation per index with REBUILD (≥ 30%) / REORGANIZE (5–30%) recommendations and ready-to-run `ALTER INDEX` statements (`ONLINE = ON` added automatically on editions that support it). |
| `mssql_top_queries` | Most expensive queries ranked by `cpu`, `duration`, `reads`, `writes`, `memory` (grant size), or `executions` — totals, averages, and SQL text. |
| `mssql_performance_health` | Health check: top wait stats (benign waits filtered), memory counters (PLE, grants pending, total vs target), workload counters, plus rule-based tuning recommendations. |
| `mssql_analyze_storage` | Largest tables by size + database file sizes. |
| `mssql_monitor_usage` | Sessions, CPU, buffer cache, top queries by CPU. |

### Locks, blocking & deadlocks

Supported on SQL Server 2019 (15.x), 2022 (16.x), and 2025 (17.x) — all editions
including Express. Output includes the detected server version/edition and warns
when running on an older version (best-effort). Requires `VIEW SERVER STATE`.

**Version & edition compatibility:**

| | Express | Standard | Enterprise / Developer / Eval | Azure SQL MI | Azure SQL DB |
| --- | --- | --- | --- | --- | --- |
| Query / schema / storage tools | ✅ | ✅ | ✅ | ✅ | ✅ |
| `mssql_monitor_locks` / `mssql_find_blocking` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `mssql_get_deadlocks` (`system_health` XE) | ✅ | ✅ | ✅ | ✅ | ❌ (tool explains alternatives) |
| `mssql_list_databases` / `mssql_monitor_usage` | ✅ | ✅ | ✅ | ✅ | ⚠️ limited scope |

Rows/columns above apply to SQL Server 2019, 2022, and 2025. Older versions
(2016/2017) mostly work but are reported as best-effort in the tool output.
`mssql_test_connection` reports the detected edition class and its engine
limits (e.g. Express: 10 GB/database, ~1.4 GB buffer pool, 4 cores).

| Tool | Description |
| --- | --- |
| `mssql_monitor_locks` | Raw view of current locks and waits per session. |
| `mssql_find_blocking` | Blocking chains (victim ← blocker), lead-blocker identification incl. idle sessions holding open transactions, with SQL text of both sides. |
| `mssql_get_deadlocks` | Recent deadlock events from the built-in `system_health` Extended Events session: victims, involved queries, and full deadlock-graph XML. `source: "ring_buffer"` (fast, recent) or `"file"` (further back). |

**Claude Examples:**
```
"Show me the top 10 customers by order count"
"Which tables are the largest, and which indexes are unused?"
"Which sessions are blocked right now, and who is the root blocker?"
"Were there any deadlocks last night, and which query caused them?"
"Find every stored procedure that references the CustomerOrders table"
```

## Security Setup

> **Read-only is enforced in two layers.** The database login is the *primary*
> guard — even a write statement that reached the server cannot execute. The
> application-level allow-list (`classifyQuery` in [src/index.ts](src/index.ts))
> is *defense-in-depth*: it accepts only read-only entry points and rejects
> everything else (writes, DDL, dynamic SQL, stacked queries). Because it
> allow-lists the leading keyword rather than blocking words, columns or
> aliases named `Create`, `Update`, `CreatedDate`, etc. are **not** blocked.

### Create Read-Only SQL User (Recommended)

A ready-to-run script is provided at
[scripts/create-readonly-login.sql](scripts/create-readonly-login.sql) — edit the
placeholders and run it as a `sysadmin`. It applies the least-privilege setup
below:

```sql
-- 1. Create login
CREATE LOGIN mcp_readonly WITH PASSWORD = 'SecurePassword123!';

-- 2. Switch to your database
USE YourDatabase;

-- 3. Create user
CREATE USER mcp_readonly FOR LOGIN mcp_readonly;

-- 4. Grant read permissions
ALTER ROLE db_datareader ADD MEMBER mcp_readonly;

-- 4b. Explicitly DENY writes (defense-in-depth)
ALTER ROLE db_denydatawriter ADD MEMBER mcp_readonly;

-- 5. Grant monitoring permissions
GRANT VIEW SERVER STATE TO mcp_readonly;
GRANT VIEW DATABASE STATE TO mcp_readonly;
GRANT VIEW DEFINITION TO mcp_readonly;

-- 6. Verify permissions
SELECT
    dp.name AS DatabaseUser,
    dp.type_desc,
    r.name AS RoleName
FROM sys.database_principals dp
LEFT JOIN sys.database_role_members drm ON dp.principal_id = drm.member_principal_id
LEFT JOIN sys.database_principals r ON drm.role_principal_id = r.principal_id
WHERE dp.name = 'mcp_readonly';
```

## Development

### Build
```bash
npm run build
```

### Watch Mode
```bash
npm run dev
```

### Testing Locally
```bash
# Set environment variables
export MSSQL_SERVER=localhost
export MSSQL_DATABASE=testdb
export MSSQL_USER=sa
export MSSQL_PASSWORD=password

# Run
npm start
```

## Troubleshooting

### "command not found" Error with npx

If you get an error running with npx:

1. Ensure Node.js 18+ is installed:
```bash
node --version
```

2. Clear npm cache:
```bash
npm cache clean --force
```

3. Try with full package name:
```bash
npx --package=@piyapat/mssql-mcp-server mssql-mcp-server
```

### Connection Errors

**Error: Login failed for user**
```sql
-- Check authentication mode (must be Mixed Mode)
USE master;
GO
EXEC xp_instance_regread
  N'HKEY_LOCAL_MACHINE',
  N'Software\Microsoft\MSSQLServer\MSSQLServer',
  N'LoginMode';
GO
-- Should return 2 for Mixed Mode
```

**Error: Cannot connect to server**
- Verify SQL Server Browser service is running
- Check firewall allows port 1433
- Ensure TCP/IP protocol is enabled in SQL Server Configuration Manager

### Permission Errors

```sql
-- Grant additional permissions if needed
USE YourDatabase;
GRANT EXECUTE TO mcp_readonly;  -- If you need to call stored procedures
GRANT SHOWPLAN TO mcp_readonly; -- For execution plans
```

## Reporting a Vulnerability

Please don't open a public issue for a security bug. Use
[GitHub private vulnerability reporting](https://github.com/PiyapatRag/mssql-mcp-server/security/advisories/new),
or the maintainer address on the npm package page. Scope, response targets, and
safe-harbor terms are in [SECURITY.md](SECURITY.md).

The guard battery in
[scripts/security-validation.mjs](scripts/security-validation.mjs) runs the real
compiled analyzer against ~100 attack cases and runs in CI — `npm run
test:security` reproduces it locally.

## Best Practices

1. **Always use read-only accounts** in production
2. **Keep encryption on** (`MSSQL_ENCRYPT=true`, `MSSQL_TRUST_CERT=false`) — both are the default
3. **Monitor regularly** - Set up regular monitoring checks
4. **Limit result sets** - Use maxRows; rows are streamed, so a page is all that is read
5. **Index optimization** - Monitor slow queries and add indexes
6. **Regular maintenance** - Keep statistics updated
7. **Audit access** - Keep `MSSQL_AUDIT_LOG` on and retain the server's stderr log

## Contributing

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) for development
setup, pull-request guidelines, and the release process. Version history is
tracked in [CHANGELOG.md](CHANGELOG.md).

## License

MIT License - Feel free to use and modify for your needs.

## Built With

- [@modelcontextprotocol/sdk](https://github.com/modelcontextprotocol/sdk) - MCP SDK
- [mssql](https://github.com/tediousjs/node-mssql) - SQL Server client for Node.js

## Support

For issues:
1. Check the Troubleshooting section
2. Review SQL Server error logs
3. Verify Claude Desktop logs
4. Check database permissions

---

**Built for Claude Desktop** • **Security First** • **Performance Focused**
