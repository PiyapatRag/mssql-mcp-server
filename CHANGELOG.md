# Changelog

All notable changes to [@piyapat/mssql-mcp-server](https://www.npmjs.com/package/@piyapat/mssql-mcp-server)
will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
