# Changelog

All notable changes to [@piyapat/mssql-mcp-server](https://www.npmjs.com/package/@piyapat/mssql-mcp-server)
will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Found by an end-to-end run of all 19 tools against a live SQL Server 2025
(17.0.1000.7) instance, plus an adversarial red-team pass. Security review and
red-teaming credited to **Kietgboiz17** (https://github.com/kietgboiz17).

Post-fix verification: an independent red-team pass (54 payloads) reported **0
guard bypasses**, and two follow-up source-review findings (string-literal /
dynamic-`EXEC` obfuscation, and a `#` in `quoteTableName`) were verified **not
exploitable** against the live instance. The least-privilege database login
remains the primary control; the application guard is defense-in-depth. Full
detail in [SECURITY_REVIEW.md](SECURITY_REVIEW.md) Part 6. Test suites:
security-validation 117/117, live pentest 59/59, functional e2e 105/105.

### Security

- **Widened the server-side file-read denylist from an enumeration to a class.**
  A red-team pass flagged that the file-read protection listed specific function
  names, so any unlisted file-reading built-in would classify as a plain read.
  Added the transaction-log readers `fn_dblog` / `fn_dump_dblog` and a broad
  pattern for any `sys.fn_*` built-in whose name contains `FILE`
  (`sys.fn_read_file`, `sys.fn_virtualfilestats`, future variants), anchored to
  the `sys` schema so user functions like `dbo.fn_myfile` are unaffected. No
  payload from the run was exploitable as written (the model's `sys.fn_read_file`
  hits used a non-existent function), but the class-level gap is now closed as
  defense-in-depth. See [qwen-pentest-remediation.md](qwen-pentest-remediation.md).

- **Closed a zero-width-character guard bypass (high).** SQL Server's tokenizer
  treats several zero-width / format code points (`U+200B` ZWSP, `U+200C`,
  `U+200D`, `U+2060` word joiner, and others) as a separator between keywords,
  but JavaScript's `\s` does not match them. An attacker could therefore split a
  blocked keyword — `CREATE​LOGIN`, `DROP​DATABASE`, `BULK​INSERT`,
  `WITH … UPDATE​table …` — so the analyzer saw one token and its patterns
  (dangerous-statement list, leading-keyword allow-list, and the write-target
  regexes) missed it, while SQL Server still parsed and executed it. Confirmed
  live: `CREATE​LOGIN` created a login and `DROP​DATABASE` dropped a
  database through the tool, in both read-only and write mode. A new
  `neutralizeSeparators` step collapses these code points to a space in the
  analysis copy only (plain text tokens; never string literals, quoted/bracketed
  identifiers, or the executed query), so the analyzer sees the same token
  boundaries the engine does. Found via a Qwen-model review whose specific
  rationale (a `U+00A0` bypass) was incorrect — `\s` does match `U+00A0` — but
  which pointed at the real class of bug through `U+200B`. The database login
  remains the primary boundary; this hardens the defense-in-depth guard.
- **Closed a server-side file-read gap in the read-only guard.** `OPENROWSET(BULK …)`,
  `BULK INSERT`, and the `xp_dirtree`/`xp_fileexist` family were blocked, but the
  built-in table-valued functions that read files off the server's disk were not:
  `sys.fn_xe_file_target_read_file` (Extended Events `.xel` — confirmed returning
  live `system_health` data through the tool), `sys.fn_get_audit_file`
  (`.sqlaudit`), `sys.fn_trace_gettable` (`.trc`), and `sp_readerrorlog` /
  `xp_readerrorlog` (the SQL error log). Because they are `SELECT`-shaped they
  passed the write analyzer as ordinary reads. They are now on the
  always-blocked list. Exploitation required a high-privilege login (the
  database login remains the primary boundary), but the app-level guard is meant
  to be defense-in-depth against exactly this, and the docs claimed server-side
  file access was blocked. Column/alias names that merely contain these tokens
  (e.g. `fn_get_audit_file_path`) are not affected — the patterns match whole
  identifiers only.

### Fixed

- **The server no longer dies when a database connection drops.** `sql.ConnectionPool`
  is an `EventEmitter` and emits `'error'` when a pooled connection is lost (SQL
  Server restart, failover, idle socket reset, network blip). Nothing listened
  for it, so Node re-threw it as an uncaught exception and the whole MCP server
  process exited — the client then had to be restarted to get the tools back. In
  testing this killed the process 13 times over a single run. `getPool()` now
  attaches an error listener, discards a pool that has failed so the next tool
  call reconnects, and collapses concurrent first calls onto one connect attempt
  instead of caching a failed connection.
- **`mssql_monitor_locks` failed on every invocation.** The query joined a
  table-valued function to a correlated column
  (`LEFT JOIN sys.dm_exec_sql_text(er.sql_handle) ... ON 1=1`), which SQL Server
  rejects with *"The multi-part identifier "er.sql_handle" could not be bound"*
  (error 4104). A correlated TVF must be referenced with `APPLY`; it is now an
  `OUTER APPLY`.

### Changed

- The server warns on stderr at startup when `MSSQL_DATABASE` is unset. The
  connection previously succeeded silently against the login's default database
  (usually `master`), so every schema and storage tool would quietly report on
  the wrong database.

## [2.0.2] — 2026-08-23 (security release)

> **Upgrade immediately if you are on 2.0.1 or earlier.** The guard bypass below
> is exploitable under the default read-only configuration.
>
> **Breaking:** minimum Node is now **22** (was 18) — `mssql` 12 depends on
> `tedious` 20, which requires Node 22.

### Security

- **Fixed a read-only / dangerous-statement guard bypass (critical).** A `--`
  inside a closed, same-line string literal made the analyzer discard the rest
  of the line — including a stacked `;` and the statement after it — from its
  own copy of the query, while the original text was executed unchanged. Under
  the default `MSSQL_READ_ONLY=true`, `SELECT 'x--' ; UPDATE Users SET ...` was
  classified as a read and ran; `SELECT 'x--' ; EXEC xp_cmdshell '...'` slipped
  past the always-blocked list. Root cause: `stripComments()` ran before
  `stripStringLiterals()` and had no concept of quote state. Comments and
  literals are now removed in a single left-to-right scan (`scanSql`) that
  tracks quote state, so a token that opens a string or quoted identifier
  consumes its own closing delimiter before anything inside it can be read as a
  comment or separator. Affects all releases up to and including 2.0.1.
  Reported privately by Kietgboiz17.
- Quoted identifiers (`UPDATE "Users" SET ...`) are normalized to bracket form
  before analysis instead of being blanked like string literals, which had
  hidden the write target under `QUOTED_IDENTIFIER ON`.
- Global `##temp` tables are treated as persistent write targets.
- Extended the always-blocked list: `ALTER ROLE`, `ALTER SERVER ROLE`,
  `sp_addrolemember`, `sp_addsrvrolemember`, `sp_droprolemember`, `sp_OA*`,
  `sp_executesql`, `sp_addlinkedserver`, `OPENQUERY`, `EXECUTE AS`,
  `xp_dirtree`, `xp_fileexist`, `xp_regread`, `BULK INSERT`, `CREATE ASSEMBLY`.
- **Result sets are streamed instead of buffered.** `mssql_query` used to load
  every row into memory before applying `maxRows`, so one large `SELECT` could
  exhaust the process heap regardless of the requested page size. Rows now
  stream and the read is cancelled one row past the page, bounding memory to
  `maxRows` and stopping the server from pulling the rest over the wire.
- **Driver errors are no longer echoed verbatim.** Errors are capped to their
  first line (300 chars) plus the SQL error number, so a failing query can't be
  used to map schema; the full error goes to stderr. `MSSQL_VERBOSE_ERRORS=true`
  restores the old behavior for debugging.
- **Every tool call is audited** to stderr as one JSON line — tool, mode,
  truncated query text, row counts, duration, outcome. Disable with
  `MSSQL_AUDIT_LOG=false`.
- Numeric tool arguments are validated and clamped in one place (`coerceInt`).
  A non-numeric value is rejected instead of reaching SQL as `NaN`.

### Added
- `SECURITY.md` — disclosure policy, scope, response targets, safe harbor, and
  a hardening checklist.
- `.github/workflows/ci.yml` — build, the security regression battery, and an
  `npm audit --audit-level=high` gate on every push/PR plus a weekly schedule.
- `.github/dependabot.yml` — weekly npm and monthly GitHub Actions updates.
- `npm run test:security` / `npm run audit` scripts.
- `scripts/security-validation.mjs` grew from 68 to 99 cases: numeric argument
  validation, error sanitization, streamed paging (including proof that a
  5000-row result set is cancelled after 11 rows), and the audit trail.

### Changed
- `mssql_query` JSON output adds `totalCountExact` and `scannedRows`.
  `totalCount` is `null` when the read stopped early, because the true total is
  genuinely unknown at that point rather than assumed.
- Documented `MSSQL_ENCRYPT`'s real default as `true` in the README — the code
  has always encrypted unless explicitly set to `false`, but the table said
  otherwise.
- `engines.node` raised to `>=22` to match tedious 20.

## [2.0.1] - 2026-07-24

### Changed
- Corrected package `homepage` and `repository` metadata to point at the
  actual GitHub repository.
- Translated the example Claude prompts in the README to English.

### Added
- `CHANGELOG.md`, `CONTRIBUTING.md`, and `.github/FUNDING.yml` (GitHub Sponsors).
- npm version/downloads/node/license/sponsor badges and an npm package
  reference in the README.

## [2.0.0] - 2026-07-24

### Added
- 19 MCP tools covering querying, schema exploration, performance, storage,
  and lock/blocking/deadlock analysis.
- Two-layer read-only enforcement: a database read-only login (primary) plus an
  application-level allow-list (`classifyQuery`) as defense-in-depth.
- Write mode via `MSSQL_READ_ONLY=false` — `INSERT`/`UPDATE`/`DELETE`/DDL
  permitted, while server-level dangerous statements stay blocked in every mode.
- Whitelisted read-only `EXEC` support via `MSSQL_ALLOWED_PROCEDURES`.
- `.env` file support with a documented lookup order and `MSSQL_ENV_FILE` override.
- Windows/NTLM authentication via `MSSQL_DOMAIN`.
- Lock, blocking, and deadlock monitoring for SQL Server 2019/2022/2025
  (all editions incl. Express) with version/edition detection.

[Unreleased]: https://github.com/PiyapatRag/mssql-mcp-server/compare/v2.0.2...HEAD
[2.0.2]: https://github.com/PiyapatRag/mssql-mcp-server/compare/v2.0.1...v2.0.2
[2.0.1]: https://github.com/PiyapatRag/mssql-mcp-server/compare/v2.0.0...v2.0.1
[2.0.0]: https://github.com/PiyapatRag/mssql-mcp-server/releases/tag/v2.0.0
