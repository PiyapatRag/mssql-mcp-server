# Changelog

All notable changes to [@piyapat/mssql-mcp-server](https://www.npmjs.com/package/@piyapat/mssql-mcp-server)
will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/PiyapatRag/mssql-mcp-server/compare/v2.0.0...HEAD
[2.0.0]: https://github.com/PiyapatRag/mssql-mcp-server/releases/tag/v2.0.0
