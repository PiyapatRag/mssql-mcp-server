# Security Policy

`mssql-mcp-server` sits directly on a connection to a live SQL Server database
and is used by AI agents whose input is, by design, influenced by untrusted
text. A bug in its query guards is a security bug, not a feature request — it
is treated accordingly.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 2.0.2 and later | ✅ Security fixes |
| 2.0.1 and earlier | ❌ Not supported — contains a known read-only bypass, upgrade |

Only the latest published version receives fixes. There are no long-term
support branches.

## Reporting a Vulnerability

**Please do not open a public issue for a security bug.**

1. **Preferred:** GitHub private vulnerability reporting —
   [report an advisory](https://github.com/PiyapatRag/mssql-mcp-server/security/advisories/new).
   This creates a private thread with the maintainer and can be turned into a
   published advisory (with credit) once a fix ships.
2. **Fallback:** email the maintainer address listed on the
   [npm package page](https://www.npmjs.com/package/@piyapat/mssql-mcp-server),
   with `[SECURITY]` in the subject.

Useful things to include, roughly in order of value:

- The payload or configuration that triggers it, and what a real SQL Server
  does with it versus what this server's analyzer thinks it does
- Which guard it defeats (`findDangerousStatement`, `classifyQuery`,
  `writesToPersistentTable`, `quoteTableName`, the EXEC allow-list, …)
- The affected version(s), and whether the default configuration
  (`MSSQL_READ_ONLY=true`) is enough to reproduce
- A standalone PoC if you have one. Extracting the guard functions from
  `src/index.ts` into a script is a perfectly good demonstration — a live
  database is not required to show that a guard returns the wrong verdict.

### What to expect

| Stage | Target |
|-------|--------|
| Acknowledgement | 3 business days |
| Initial assessment (severity, affected versions) | 7 days |
| Fix released for critical/high | 14 days where practical |
| Public advisory | With the fix, or coordinated with you |

Reporters are credited in the advisory and the changelog unless you ask not to
be. If a report turns out to be a non-issue, you will get the reasoning, not
silence.

## Scope

**In scope**

- Any input to the `mssql_query` tool that reaches SQL Server in a form the
  analyzer classified as something else — read-only bypasses, stacked
  statements, comment/literal parsing differentials, blocked-statement smuggling
- SQL injection through any other tool's parameters (table names, schema names,
  search text, numeric arguments)
- Bypasses of the stored-procedure allow-list or of `assertExecProcIsReadOnly`
- Credential exposure: secrets in logs, error messages, or tool output
- Weakened transport security (silent downgrade of `encrypt` /
  `trustServerCertificate`)
- Denial of service that a single ordinary tool call can trigger

**Out of scope**

- A SQL login granted more rights than it needs. The analyzer is
  defense-in-depth *on top of* a least-privilege login; see
  `scripts/create-readonly-login.sql`. "The server can write because I pointed
  it at `sa`" is a configuration problem, not a vulnerability.
- Running with `MSSQL_READ_ONLY=false` and then writing data. That is the
  documented purpose of write mode. Statements on the always-blocked list
  escaping in write mode *are* in scope.
- `MSSQL_TRUST_CERT=true` disabling certificate validation. It is opt-in,
  documented, and warned about.
- Vulnerabilities in SQL Server itself, or in `mssql`/`tedious` — report those
  upstream (still worth telling us, so we can pin around them).
- Anything requiring the attacker to already have filesystem access to the
  host running the MCP server or its `.env`.

## Safe Harbor

Testing against **your own** database instance, in good faith, following this
policy, is welcomed and will not be met with legal action. Do not test against
databases you do not own, do not access other people's data, and do not run
availability tests against production systems.

## Hardening Checklist

Guards can only ever be a second layer. Regardless of version:

- Give the server a dedicated login with `db_datareader` + `db_denydatawriter`
  (`scripts/create-readonly-login.sql`), never `sa` or `db_owner`
- Never grant it `EXECUTE` on `xp_cmdshell`, `sp_configure`, or `sp_OA*`
- Keep `MSSQL_ENCRYPT=true` and `MSSQL_TRUST_CERT=false` in production
- Leave `MSSQL_READ_ONLY` unset or `true` unless writes are genuinely required
- Leave `MSSQL_ALLOWED_PROCEDURES` empty unless a specific read-only procedure
  is needed; it disables `EXEC` entirely
- Keep `MSSQL_AUDIT_LOG` on and retain the server's stderr — it is the record of
  what was actually executed
- Keep `.env` out of version control and off shared filesystems
