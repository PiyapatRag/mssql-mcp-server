# Security Review — mssql-mcp-server

Single working record of the 2026-08-23 security review: the internal OWASP
audit, the externally reported guard bypass, the drafts written in response, and
the model-assisted review + live red-team that followed.
Supersedes `SECURITY_AUDIT.md`, the four working files that lived in
`security-review/` (`deail.md`, `VULNERABILITY_REPORT.md`, `ADVISORY_DRAFT.md`,
`reply-to-reporter.md`), and the standalone model-review files
`qwen3.8-reviewed.md`, `qwen3.8-reviewed.json`, and `qwen-pentest-remediation.md`
(all folded into Part 5).

> **Status:** all findings closed. The v2.0.2 fix (Part 0 root cause) shipped;
> Part 5 records a later round (model-assisted review + live testing against a
> real SQL Server 2025 instance) that found and fixed additional issues, still
> unreleased at time of writing. The advisory in Part 4 is a **DRAFT** — publish
> it only after 2.0.2 is on npm.

**Contents**

1. Part 1 — Audit summary (OWASP Top 10, findings, validation)
2. Part 2 — Initial contact from the reporter
3. Part 3 — Full vulnerability report (as submitted)
4. Part 4 — GitHub Security Advisory (draft)
5. Part 5 — Model-assisted review & live red-team (round 4, 2026-08-23)

**At a glance**

| Field | Value |
|-------|-------|
| Package | `@piyapat/mssql-mcp-server` (npm) |
| Affected | `>= 1.0.0, <= 2.0.1` |
| Patched | `2.0.2` |
| Class | CWE-20 Improper Input Validation; CWE-89 SQL Injection (secondary) |
| Severity | Reporter: Critical 9.1 · Published as: High 8.1 (see the severity note in Part 4) |
| Reporter | Kietgboiz17 (privately, 2026-08-23) |
| Root cause | `stripComments()` ran before `stripStringLiterals()` with no quote-state tracking |
| Fix | Single left-to-right tokenizer `scanSql()` that tracks quote state |

---

# Part 1 — Audit summary

**Scope:** OWASP Top 10 (2021) + SAST + dynamic analyzer testing · **Date:** 2026-08-23 · **Target:** v2.0.1 working tree
**Method:** Full-source review + `npm audit` + 99-case dynamic attack battery (`scripts/security-validation.mjs`)
**Update 2026-08-23 (round 3):** Findings 1/3/4/5 closed + CI in place · all findings now closed

## Overall Verdict: ✅ Pass — secure against the OWASP Top 10

Sound design: **read-only by default**, an **allow-list** SQL analyzer as defense-in-depth on top of a **least-privilege login** (`db_datareader` + `db_denydatawriter`), TLS encryption with certificate validation by default, **npm audit = 0 vulnerabilities**

## OWASP Top 10 (2021)

| # | Category | Verdict |
|---|----------|---------|
| A01 | Broken Access Control | ✅ Pass — allow-list + DB-level deny (dynamic testing: all 26 bypass attempts rejected) |
| A02 | Cryptographic Failures | ✅ Pass — encryption/cert validation on by default (opt-out) |
| A03 | Injection | ✅ Pass — every input parameterized, identifiers whitelisted, write-mode blocklist now complete |
| A04 | Insecure Design | ✅ Pass — Finding 1 fixed (stream + cancel) |
| A05 | Security Misconfiguration | ✅ Pass — secure defaults throughout |
| A06 | Vulnerable Components | ✅ Pass — 0 vulnerabilities (SDK 1.30.0 / mssql 12.7.0 / tedious 20.0.0) |
| A07 | AuthN Failures | ✅ Pass — no credentials in code, passwords never logged |
| A08 | Data Integrity | ✅ Pass — CI: npm audit gate + regression battery + Dependabot |
| A09 | Logging & Monitoring | ✅ Pass — query audit log to stderr (MSSQL_AUDIT_LOG) |
| A10 | SSRF | ✅ Pass — OPENROWSET/OPENDATASOURCE/OPENQUERY blocked |

## Findings

| # | Severity | Status | Details |
|---|----------|--------|---------|
| 0 | CRITICAL | ✅ **RESOLVED** | (externally reported) A `--` inside a closed string literal made `stripComments` drop the following statement from the analyzed text while the raw query was still executed → full bypass of read-only + blocklist. Fixed with a single-pass `scanSql()` that tracks quote state |
| 1 | MEDIUM | ✅ **RESOLVED** | `handleMssqlQuery` buffered the entire result set into memory before paginating (DoS) — fixed with streaming (`request.stream = true`) + cancel one row past the page; memory is now bound to `maxRows`, not to result-set size |
| 2 | MEDIUM | ✅ **RESOLVED** | The write-mode blocklist was missing `ALTER ROLE`, `sp_add(srv)rolemember`, `sp_OA*`, `sp_executesql`, `OPENQUERY` — fixed, confirmed 16/16 blocked dynamically |
| 3 | LOW | ✅ **RESOLVED** | Driver errors truncated to the first line + capped at 300 characters + SQL error number attached; full detail goes to stderr only (`MSSQL_VERBOSE_ERRORS=true` to opt out) |
| 4 | LOW | ✅ **RESOLVED** | Audit log to stderr as one JSON line per tool call (tool, mode, truncated query, row count, duration, outcome) — `MSSQL_AUDIT_LOG` |
| 5 | INFO | ✅ **RESOLVED** | `coerceInt()` applied to every numeric argument (`maxRows`, `offset`, `rows`, `top`, `topTables`, `topQueries`, `maxEvents`, `minPageCount`) — non-numeric values are rejected, no `NaN` reaches SQL |

## Dynamic Validation (round 3 — after all findings closed)

**99/99 tests passed** against the real code from `build/index.js`:

- A: valid queries all pass (8/8)
- B: write/bypass attempts all rejected — stacked statements, smuggling via literal/comment, `"Users"` quoted identifier, `##global`, alias target, CTE-INSERT, hidden EXEC/DBCC/MERGE (25/25)
- C: dangerous statements blocked in both modes with no false positives (13/13)
- D: privilege escalation/OS access blocked across all 16 vectors (16/16)
- E: `quoteTableName` prevents injection (6/6)
- F: `coerceInt` — clamps out-of-range values, rejects non-numeric input, no `NaN` escapes (10/10)
- G: `describeError` — truncates to the first line, caps length, flags as truncated (3/3)
- H: streamed paging — a 5000-row result set is cancelled after reading 11 rows, offset/page correct, no false claim of an exact total when the read stopped early (12/12)
- I: audit trail — every query logged, with ts/mode/row count, query truncated to a single line (6/6)

## Strengths worth preserving

- Single-pass scanner that tracks quote state — closes the `SELECT 'a--'; DELETE FROM Users` smuggling path
- Normalizing `"Table"` to bracket form before analysis — closes the QUOTED_IDENTIFIER path
- EXEC path: whitelist + inspect the proc definition before every run, reject `WITH EXECUTE AS`
- `##global` temp tables treated as persistent writes; `MERGE`/`DBCC`/dynamic SQL are unconditional red flags
- Metric lookups use a `Map` (prevents prototype pollution), LIKE wildcards are escaped

## What was done (round 3)

1. ✅ Finding 1 — `streamQueryPage()` streams rows and cancels one row past the page
2. ✅ Finding 4 — single-line JSON audit log to stderr (`MSSQL_AUDIT_LOG`)
3. ✅ CI — `.github/workflows/ci.yml` (build + regression battery + `npm audit --audit-level=high` + weekly schedule) and `.github/dependabot.yml`
4. ✅ Finding 3 — `describeError()` normalizes driver errors (`MSSQL_VERBOSE_ERRORS` to opt out)
5. ✅ Finding 5 — `coerceInt()` on every numeric argument
6. ✅ `SECURITY.md` + disclosure policy (private vulnerability reporting, scope, safe harbor)

## Deployment cautions

> ⚠️ **Breaking change:** `mssql` 12 pulls in `tedious` 20, whose `engines` field is `>=22` → **minimum Node is now 22** (was 18). Already updated in `package.json` and the CI matrix. Users still on Node 18/20 will fail to install.

- **Write mode (`MSSQL_READ_ONLY=false`) requires a login without sysadmin / securityadmin / role-admin rights** — the blocklist is a backstop only, not a security boundary. If the login holds those rights, the blocklist only stops the patterns it already knows.
- Dynamic SQL (`sp_executesql`, `EXEC('...')`) is blocked even in write mode — intentionally, because it cannot be analyzed statically and allowing it would render every other pattern useless.
- `MSSQL_AUDIT_LOG=true` (the default) writes query text to stderr — turn it off if WHERE clauses carry sensitive data.

## Remaining (outside the code)

1. Enable **private vulnerability reporting** on GitHub (Settings → Code security)
2. Bump to **2.0.2** and `npm publish` — v2.0.1 on npm still carries the critical vulnerability
3. Publish the GitHub Security Advisory and reply to the researcher — the advisory is drafted below in Part 4

---
*Limitation: no real SQL Server was available for testing — DB-level enforcement (db_denydatawriter, EXECUTE grants) was reviewed statically only*

---

# Part 2 — Initial contact from the reporter

Hi Piyapat,

I'm a security researcher and I found a critical-severity vulnerability in
`@piyapat/mssql-mcp-server` (npm, currently published `2.0.1`, matches the
`PiyapatRag/mssql-mcp-server` GitHub repo HEAD). I tried GitHub's private
vulnerability reporting first (`/security/advisories/new`) but it isn't
enabled on the repo, so I'm reaching out directly via the email listed as
the npm package maintainer contact.

**Summary**: the server's core promise — "secure, read-only" — and its
"always blocked in both modes" dangerous-statement list (xp_cmdshell,
sp_configure, etc.) can both be completely bypassed with a simple, ordinary
SQL payload: placing `--` inside a short, same-line string literal that
closes before the rest of the line. Example (works under the *default*
`MSSQL_READ_ONLY=true` config):

    SELECT 'x--' ; UPDATE Users SET Password='pwned' WHERE Id=1

Root cause: `stripComments()` in `src/index.ts` strips `--` comments
*before* `stripStringLiterals()` runs, and has no concept of quote state —
so a `--` inside an already-closed string literal is wrongly treated as a
real comment, silently deleting the real `;` and the following statement
from the app's own analysis text. The original, unmodified query is what
actually gets executed against SQL Server, so the deleted statement still
runs for real.

I've attached a full write-up (root cause, both the read-only bypass and
an xp_cmdshell-smuggling variant, impact analysis, and a suggested fix) and
a standalone PoC script that extracts your exact classifier functions
unmodified and demonstrates both bypasses plus matching negative controls
(same payloads without the trick are correctly rejected, confirming the
bug is isolated to this specific parsing-order issue).

Suggested fix: run `stripStringLiterals()` before `stripComments()` (your
existing `stripStringLiterals` implementation looks reusable as-is — it's
just called in the wrong order relative to the comment stripper).

Happy to verify a patch against the PoC once you have one. Let me know if
you'd like me to open a GitHub Security Advisory draft once private
vulnerability reporting is enabled on the repo, or if you'd prefer to
coordinate a fix privately first.

Thanks for building this — happy to help get it airtight.

Best regards,
Kietgboiz17
---

# Part 3 — Full vulnerability report (as submitted)

**Title:** Read-only / dangerous-statement guard bypass in `@piyapat/mssql-mcp-server` via comment/string-literal parsing-order confusion

**Package:** `@piyapat/mssql-mcp-server` (npm, latest `2.0.1` — matches `PiyapatRag/mssql-mcp-server` HEAD)
**Affected versions:** all published versions (`1.0.0` – `2.0.1`); the vulnerable helper functions are unchanged across the range
**Component:** `src/index.ts` — `stripComments`, `writesToPersistentTable`, `findDangerousStatement`, `classifyQuery`
**Class:** CWE-20 (Improper Input Validation) / security-control bypass — defeats the tool's core "secure, read-only" guarantee
**Severity:** Critical (CVSS 3.1 vector suggestion: `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` ≈ 9.1) — see Impact

## Summary

This MCP server is marketed as a **"secure, read-only"** gateway to a Microsoft
SQL Server database for AI agents, and defaults to `MSSQL_READ_ONLY=true`
(the README documents no other default). Every query submitted through the
`mssql_query` tool passes through two independent app-level guards before
execution:

1. `findDangerousStatement()` — blocks server-level/OS-level statements
   (`xp_cmdshell`, `sp_configure`, `DROP DATABASE`, login/permission changes,
   …) **in both read-only and write mode**.
2. `classifyQuery()` (only in read-only mode) — rejects anything that isn't a
   plain `SELECT`/`WITH`, or a `DECLARE`/`INSERT`/`CREATE TABLE #`-led batch
   that provably writes only to session-local `#temp`/`@table` targets, via
   `writesToPersistentTable()`.

Both guards clean the query text the same, flawed way before inspecting it:

```ts
// src/index.ts
function stripComments(query: string): string {
  return query
    .replace(/--[^\n]*/g, " ")           // <-- runs FIRST
    .replace(/\/\*[\s\S]*?\*\//g, " ");
}

function stripStringLiterals(text: string): string {  // <-- runs SECOND
  return text.replace(/'(?:[^']|'')*'/g, " '' ").replace(/"(?:[^"]|"")*"/g, ' "" ');
}
```

`stripComments` is applied **before** string literals are stripped, and it
has no concept of quote state at all — it treats every `--` in the raw text
as the start of a real SQL comment, even when that `--` sits inside a
string literal that is properly closed later on the same line. Real T-SQL
(and the actual `mssql`/tedious driver that executes the untouched original
query text) does the opposite: it tokenizes string literals first, so a
`--` inside a closed string is just two literal dash characters, and
whatever comes after the closing quote on that same line is parsed as
normal, live SQL.

Because of this parser-order mismatch, any attacker-supplied query that
places `--` inside a short, same-line string literal causes the classifier
to silently delete everything from that `--` to the end of the physical
line — including the real statement separator (`;`) and a fully-formed,
subsequent write/dangerous statement — from its own analysis text, while
the **original, unmodified query string is what actually gets sent to and
executed by SQL Server** (`dbPool.request().query(query)` at line 1085 uses
the raw `query` argument, never the cleaned text).

This single root cause breaks all three guards at once: the stacked-statement
`;` check, the persistent-write detector, and the "always blocked" dangerous
statement list.

## Proof of Concept

Both payloads below are ordinary, unremarkable T-SQL — no exotic encoding,
no edge-case Unicode, just a string literal that happens to contain `--`.

### PoC 1 — UPDATE on a real table, in default read-only mode

```sql
SELECT 'x--' ; UPDATE Users SET Password='pwned' WHERE Id=1
```

- Real SQL Server parse: `SELECT 'x--'` (harmless), then a genuine
  `UPDATE Users SET Password='pwned' WHERE Id=1`.
- `findDangerousStatement()` → `null` (nothing flagged).
- `classifyQuery()` → `{ kind: 'read' }` — **accepted**, forwarded verbatim
  to `dbPool.request().query(query)`, and the `UPDATE` executes.
- Control (same statement, no smuggling):
  `SELECT 1; UPDATE Users SET Password='pwned' WHERE Id=1` →
  correctly rejected as `"multiple statements (';') are not allowed"`.

### PoC 2 — `xp_cmdshell`, blocked "in both modes" per the code's own comment

```sql
SELECT 'x--' ; EXEC xp_cmdshell 'whoami'
```

- `findDangerousStatement()` → `null` (should have returned `"xp_cmdshell"`).
- `classifyQuery()` → `{ kind: 'read' }` — **accepted**.
- If the SQL login used by the server happens to have `xp_cmdshell`
  execute rights (not enforced or verified anywhere in this codebase),
  this is remote command execution on the database host through a tool
  whose own inline comment says dangerous statements are "blocked in BOTH
  modes."
- Control: `SELECT 1; EXEC xp_cmdshell 'whoami'` → correctly rejected.

I verified both bypasses and both controls by extracting the exact
`stripComments`/`stripStringLiterals`/`writesToPersistentTable`/
`findDangerousStatement`/`classifyQuery` functions from `src/index.ts`
(2.0.1, matching the currently-published npm package) unmodified into a
standalone Node script and running all four cases — output attached below.

```
=== PoC1: UPDATE smuggled past classifier ===
RAW QUERY (this exact text is sent to mssql):
SELECT 'x--' ; UPDATE Users SET Password='pwned' WHERE Id=1
findDangerousStatement -> null
classifyQuery -> { kind: 'read' }

=== PoC2: xp_cmdshell smuggled past findDangerousStatement ===
RAW QUERY (this exact text is sent to mssql):
SELECT 'x--' ; EXEC xp_cmdshell 'whoami'
findDangerousStatement -> null
classifyQuery -> { kind: 'read' }

=== Control: UPDATE without smuggling (should be rejected) ===
findDangerousStatement -> null
classifyQuery -> { kind: 'rejected', reason: "multiple statements (';') are not allowed" }

=== Control: xp_cmdshell without smuggling (should be blocked) ===
findDangerousStatement -> xp_cmdshell
classifyQuery -> { kind: 'rejected', reason: "multiple statements (';') are not allowed" }
```

I have not run this against a live SQL Server instance (no test server
available) — the PoC above exercises the actual, unmodified guard functions
against the actual code path that receives the raw query text
(`dbPool.request().query(query)`, `src/index.ts:1085`), so the result is a
direct, mechanical demonstration of the bypass rather than an inference.
A maintainer with a disposable SQL Server/LocalDB instance can confirm
end-to-end execution in under a minute by pointing the server at it with
default (`MSSQL_READ_ONLY` unset) settings and issuing PoC 1 through the
`mssql_query` tool.

## Impact

- **Complete bypass of the tool's stated security model.** The README's
  primary claim — "secure, **read-only**" — does not hold under the
  *default* configuration (`MSSQL_READ_ONLY` defaults to `true` when unset).
  An LLM agent (or anyone able to influence the natural-language prompt
  driving it — the classic MCP threat model this server is meant to guard
  against) can achieve arbitrary `INSERT`/`UPDATE`/`DELETE`/DDL against
  real, persistent tables with a trivially simple payload shape.
- **Bypasses the "always blocked, both modes" dangerous-statement list**,
  including `xp_cmdshell`, `sp_configure`/`RECONFIGURE`, login/credential/
  certificate changes, and `OPENROWSET`/`OPENDATASOURCE`. If the configured
  SQL login has `xp_cmdshell` rights (a common misconfiguration this
  project's own defense-in-depth doc comment acknowledges it does not
  verify), this is remote OS command execution on the database host.
- Low complexity, no special privileges beyond the ability to send a query
  string through the exposed `mssql_query` MCP tool (which is this
  project's entire purpose) — no auth bypass, race condition, or timing
  needed. This is why I'm rating it Critical rather than High despite
  requiring `MSSQL_READ_ONLY`/DB-login misconfiguration for the RCE
  sub-case specifically; the data-integrity impact (PoC 1) requires no
  such precondition beyond the documented default.
- Affects every published npm version (`1.0.0`–`2.0.1`); I confirmed npm's
  `latest` dist-tag (`2.0.1`) matches the vulnerable source in the GitHub
  repo, so `npx @piyapat/mssql-mcp-server` installs the vulnerable code
  today.

## Suggested Fix

Tokenize once, tracking quote state, rather than running two independent
regex passes in a fixed order. Concretely: strip string literals **first**
(a single-quote-aware scan that also recognizes `''`-escaped quotes, as the
existing `stripStringLiterals` already does), and only run the `--`/`/* */`
comment stripper on the *already-literal-free* text. That ordering removes
the parser differential, since a `--` remaining after literals are already
blanked out can only be a real comment. (The existing
`stripStringLiterals` implementation looks reusable as-is for this — it's
just called in the wrong position relative to `stripComments`.)

As a second, independent layer (defense-in-depth, matching this project's
own stated philosophy), consider parsing with a real T-SQL tokenizer
instead of regex passes — the regex approach makes it easy to reintroduce
this exact class of bug in the future whenever a new pattern is added.

## Disclosure

No `SECURITY.md` is present in the repository; reporting via GitHub's
private vulnerability reporting flow
(`https://github.com/PiyapatRag/mssql-mcp-server/security/advisories/new`).
Happy to verify a patch against the PoC harness above once one is available.

---

# Part 4 — GitHub Security Advisory (draft)

Paste into https://github.com/PiyapatRag/mssql-mcp-server/security/advisories/new
once private vulnerability reporting is enabled (Settings → Code security and
analysis → Private vulnerability reporting → Enable). Publish **after** 2.0.2 is
on npm, not before.


---

## Form fields

| Field | Value |
|-------|-------|
| **Title** | Read-only guard bypass via comment/string-literal parsing-order confusion |
| **Ecosystem** | npm |
| **Package name** | `@piyapat/mssql-mcp-server` |
| **Affected versions** | `>= 1.0.0, <= 2.0.1` |
| **Patched versions** | `2.0.2` |
| **Severity** | High (CVSS 3.1 `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` = 8.1) |
| **CWE** | CWE-20 Improper Input Validation, CWE-89 SQL Injection (secondary) |
| **Credit** | Kietgboiz17 — reporter, finder (accept their preferred handle/name) |

### A note on the severity

The reporter rated this Critical (9.1) with `A:H`, on the basis that a SQL login
holding `xp_cmdshell` rights turns it into RCE on the database host. That
sub-case depends on a misconfiguration the project documents against and ships a
least-privilege script for, so this draft rates availability impact as None and
lands at High 8.1. Worth stating the reasoning in the advisory rather than
quietly downgrading it — and if you would rather publish at the reporter's
number, that is a defensible call too.

---

## Summary

Every query submitted to the `mssql_query` tool passed through two app-level
guards before execution: `findDangerousStatement()` (blocks server/OS-level
statements in **both** modes) and, in the default read-only mode,
`classifyQuery()` / `writesToPersistentTable()` (allow-list of read-only entry
points). Both cleaned the query text before inspecting it, and both cleaned it
in the wrong order.

A `--` placed inside a **closed, same-line string literal** caused the analyzer
to discard the rest of the line — including a stacked `;` and a fully-formed
write or administrative statement — from its own copy of the query. The
original, unmodified text was what actually executed. The result: a plain,
unremarkable payload defeats the read-only guarantee under the default
configuration.

## Impact

Anyone able to put text into the `mssql_query` tool — which, for an MCP server
driven by an LLM, includes anyone able to influence the model's prompt — could:

- Execute arbitrary `INSERT` / `UPDATE` / `DELETE` / DDL against persistent
  tables while the server reported itself as read-only
- Reach statements on the always-blocked list (`xp_cmdshell`, `sp_configure`,
  `RESTORE`, login/permission changes, `OPENROWSET`, …)

The database's own permissions remained the effective boundary. A deployment
following the project's own guidance — a login with `db_datareader` +
`db_denydatawriter` and no `EXECUTE` on extended procedures — was protected by
that layer; the app-level guard it was told it also had was not there.

## Affected component

`src/index.ts` — `stripComments`, `stripStringLiterals`, and their callers
`writesToPersistentTable`, `findDangerousStatement`, `classifyQuery`.

```js
// vulnerable (<= 2.0.1)
function stripComments(query) {
  return query
    .replace(/--[^\n]*/g, " ")            // runs first, knows nothing about quotes
    .replace(/\/\*[\s\S]*?\*\//g, " ");
}
function stripStringLiterals(text) {      // runs second — too late
  return text.replace(/'(?:[^']|'')*'/g, " '' ").replace(/"(?:[^"]|"")*"/g, ' "" ');
}
```

Real T-SQL tokenizes literals first, so `'x--'` is a string containing two
dashes and the rest of the line is live SQL. The analyzer read it the other way
round. That differential is the whole bug.

## Proof of concept

Under the default configuration (`MSSQL_READ_ONLY` unset → read-only):

```sql
SELECT 'x--' ; UPDATE Users SET Password='pwned' WHERE Id=1
SELECT 'x--' ; EXEC xp_cmdshell 'whoami'
```

Both were classified `{ kind: 'read' }` and forwarded verbatim. The same
statements without the literal trick were correctly rejected
(`multiple statements (';') are not allowed`), which isolates the fault to the
parsing order.

## Patches

Fixed in **2.0.2**. The two regex passes are replaced by a single left-to-right
tokenizer (`scanSql`) that tracks quote state, so a token that opens a string or
quoted identifier consumes its own closing delimiter before the scanner can
mistake anything inside it for a comment or a statement separator. Two views are
derived from the same scan: `stripCommentsOnly()` and `sanitizeForAnalysis()`.

Hardened at the same time, from the same review:

- `"Quoted"` identifiers are normalized to bracket form before analysis, closing
  the parallel `UPDATE "Users"` evasion under `QUOTED_IDENTIFIER ON`
- `##global` temp tables are treated as persistent write targets
- Blocklist extended: `ALTER ROLE`, `sp_addrolemember`, `sp_addsrvrolemember`,
  `sp_droprolemember`, `sp_OA*`, `sp_executesql`, `OPENQUERY`,
  `sp_addlinkedserver`, `EXECUTE AS`, `xp_dirtree`, `xp_fileexist`,
  `BULK INSERT`, `CREATE ASSEMBLY`, `xp_regread`
- `scripts/security-validation.mjs` — a regression battery that runs the real
  compiled analyzer, now in CI

## Workarounds

For anyone who cannot upgrade immediately: restrict the SQL login to
`db_datareader` + `db_denydatawriter` and revoke `EXECUTE` on extended stored
procedures (`scripts/create-readonly-login.sql` does both). That reduces the
bypass to a failed statement at the database boundary.

## References

- Fix commit: _(fill in after commit)_
- `scripts/security-validation.mjs` — regression coverage
- Reported privately by Kietgboiz17 on 2026-08-23

---

# Part 5 — Model-assisted review & live red-team (round 4, 2026-08-23)

After the v2.0.2 fix, the guard was put through a second, tougher round: the
self-hosted **Qwen 3.8** model (`qwen3.8-27b`, self-hosted vLLM endpoint)
was run both as a **source-code reviewer** and as an **SQL-guard red-teamer**,
and — for the first time — every claim was verified by **executing payloads
against a live SQL Server 2025 (17.0.1000.7) instance** through the real MCP
server, not just against the classifier in isolation.

Model findings are unverified claims and were treated as such: each was
reproduced or refuted against the compiled analyzer and the live database before
any change was made. This part folds in the three former standalone files
(`qwen3.8-reviewed.md`, `qwen-pentest-remediation.md`, and the raw
`qwen3.8-reviewed.json`, appended at the end).

## 5.1 Outcome at a glance

| # | Source | Finding | Verified verdict | Action |
|---|--------|---------|------------------|--------|
| 5-A | Qwen review | Zero-width / Unicode-separator guard bypass | **CONFIRMED — High. Created a login and dropped a database live.** | Fixed (`neutralizeSeparators`) |
| 5-B | Qwen review | `MSSQL_TRUST_CERT` opt-in enables MITM | **Not a defect** — default is secure, opt-in is required for local/dev | No change (documented) |
| 5-C | Qwen red-team | 5 raw "bypasses" out of 44 payloads | **0 exploitable as written** (3–5 used a non-existent function) | Denylist widened as defense-in-depth |
| 5-D | Direct testing | Server-side file-read TVFs slip past as plain reads | **CONFIRMED — defense-in-depth gap** (live `.xel` data returned) | Fixed + widened to a class |
| 5-E | Direct testing | Process crash when a DB connection drops | **CONFIRMED** — unhandled pool `'error'` killed the process | Fixed (`getPool`) |
| 5-F | Direct testing | `mssql_monitor_locks` fails on every call | **CONFIRMED** — correlated TVF in a `LEFT JOIN` (error 4104) | Fixed (`OUTER APPLY`) |
| 5-G | Direct testing | Silent wrong-database connection when `MSSQL_DATABASE` unset | **CONFIRMED** — connected to `master` silently | Fixed (startup warning) |

## 5.2 Finding 5-A — Zero-width / Unicode-separator guard bypass (High, FIXED)

**Reported by:** the Qwen source-code review (as CWE-185, "Bypass of dangerous
statement detection via Unicode whitespace normalization").

**The model's specific rationale was wrong**, and this is worth recording so the
finding is not over-credited: it claimed JavaScript's `\s` does not match
`\u00A0`. It does — `\s` matches `\u00A0`, `\u3000`, `\uFEFF`, `\u2028`, and the
`\u2000`–`\u200A` spaces even without the `u` flag, so `BULK\u00A0INSERT` is
normalized and blocked. **But the underlying class of bug is real**, via the code
points `\s` genuinely misses: the zero-width / format characters `\u200B` (ZWSP),
`\u200C`, `\u200D`, and `\u2060` (word joiner).

- SQL Server's tokenizer treats those as a separator between two keywords.
- JavaScript `\s` does not, so the analyzer saw a single token and every
  keyword-boundary pattern missed it: `/CREATE\s+LOGIN/`, `/BULK\s+INSERT/`, the
  leading-keyword allow-list, and the `writesToPersistentTable` write-target
  regexes.

**Confirmed exploitable live, in BOTH modes, with real damage** (a zero-width
space sits between the two keywords in each payload below):

- Write mode: `CREATE‹ZWSP›LOGIN hax WITH PASSWORD='x'` passed the guard and
  **actually created the login `hax`**; `DROP‹ZWSP›DATABASE MCPTestDB` passed and
  **dropped the test database** (it had to be rebuilt). `ALTER‹ZWSP›DATABASE …
  SET OFFLINE`, `GRANT`, `BULK INSERT`, and `xp_cmdshell` were all reachable the
  same way.
- Read-only mode: `WITH x AS(SELECT 1) UPDATE‹ZWSP›sales.Orders SET …` classified
  as a read (the write-target regex needs `\s` after `UPDATE`), so a persistent
  write slipped past the read-only guard.

This defeated the application-level guard entirely. The least-privilege login
remained the primary boundary, but the app guard is meant to be defense-in-depth
against exactly this, and the docs claim these statements are always blocked.

**Fix** (`src/index.ts`): a normalization step, `neutralizeSeparators`, collapses
the zero-width / format / unusual-space code points
(`\u0085 \u00A0 \u180E \u1680 \u2000–\u200D \u2028 \u2029 \u202F \u205F \u2060
\u3000 \uFEFF`) to a plain space in the **analysis copy only** — applied to the
plain-text tokens of `stripCommentsOnly` and `sanitizeForAnalysis`, never to
string literals or quoted/bracketed identifiers (where such a code point could be
legitimate data or part of a name), and never to the query actually executed. The
analyzer now sees the same token boundaries the engine does. Verified: all 7
write-mode and 4 read-only ZWSP payloads are now blocked (12/12), legitimate
queries with ordinary spaces still run, and 7 permanent regression cases were
added to `scripts/security-validation.mjs`.

## 5.3 Finding 5-B — `MSSQL_TRUST_CERT` opt-in — NOT A VULNERABILITY

The Qwen review flagged `trustServerCertificate: process.env.MSSQL_TRUST_CERT ===
"true"` (CWE-295). The default is already secure: `trustServerCertificate` is
`false` unless the operator explicitly sets `MSSQL_TRUST_CERT=true`, and a live
test confirms a self-signed certificate is **rejected** under the default
(`Error: self-signed certificate`). The opt-in exists because it is required for
legitimate local/dev instances with no CA-issued cert (exactly the test box), and
the README already warns to keep it off in production. Removing it would break
supported setups. No code change — a deployment choice, not a flaw.

## 5.4 Finding 5-C — Red-team payload battery (44 payloads, 0 exploitable)

The Qwen red-teamer fired 44 SQL-guard bypass payloads. Its harness flags a
payload as a bypass when the classifier allows it and `findDangerousStatement`
does not flag it — a deliberately naive signal that produced 5 raw "hits". Each
was verified by hand:

| # | Payload | Raw flag | Verified verdict | Reason |
|---|---------|----------|------------------|--------|
| 1 | `EXEC dbo.usp_HarmlessProc` | bypass | **false positive** | `exec` is the intended path; the proc runs only if whitelisted in `MSSQL_ALLOWED_PROCEDURES`, and a writing / nested / dynamic proc is rejected by the definition scan (verified live). |
| 2 | `CREATE TABLE #t …; INSERT …; SELECT * FROM #t` | bypass | **false positive** | The sanctioned session-local temp-table pattern. Writes nothing persistent. |
| 3–5 | `SELECT * FROM sys.fn_read_file('C:\…')` (± `WHERE`) | bypass | **hallucinated function, real architectural gap** | `sys.fn_read_file` does not exist in SQL Server, so those exact payloads only ever errored with *"Invalid object name"*. But the model correctly flagged that the file-read protection was an *enumerated denylist* — a real file-reading built-in not on the list would classify as a plain read. |

**Net: 0 payloads were exploitable as written.** The guard plus the primary
`db_datareader + db_denydatawriter` login boundary held. Finding 3–5 nonetheless
pointed at a genuine defense-in-depth weakness, closed under 5-D.

## 5.5 Finding 5-D — Server-side file-read denylist widened from a list to a class

Direct testing during this round confirmed the *real* version of what the
red-teamer only gestured at: several **built-in** file-reading table-valued
functions are `SELECT`-shaped and so passed the write analyzer as ordinary reads.
`sys.fn_xe_file_target_read_file` was **confirmed returning live `system_health`
`.xel` data through the tool**; `sys.fn_get_audit_file`, `sys.fn_trace_gettable`,
and `sp_readerrorlog` / `xp_readerrorlog` were reachable the same way. These were
first added to the always-blocked list by exact name.

The red-team follow-up then generalised the fix so an *unlisted or future*
file-reading built-in can no longer slip through
(`DANGEROUS_STATEMENT_PATTERNS` in `src/index.ts`):

- Added the real transaction-log readers that were still missing: `fn_dblog`
  (active log) and `fn_dump_dblog` (reads log-backup **files** off disk).
- Added a broad pattern: **any** `sys.fn_*` built-in whose name contains `FILE`
  (`sys.fn_read_file`, `sys.fn_xe_file_target_read_file`,
  `sys.fn_virtualfilestats`, future variants). Anchored to the `sys` schema so a
  user-defined function such as `dbo.fn_myfile` is **not** affected.

Verified live: the exact report payloads (`sys.fn_read_file(...)`, with and
without a trailing `WHERE`) are now blocked; the new and previously-fixed readers
are blocked; and there are no false positives — a user TVF
(`sales.tvf_CustomerOrders(1)`) still runs, a column named `fn_get_audit_file_path`
still selects, and `dbo.fn_myfile(1)` is not flagged.

## 5.6 Findings 5-E / 5-F / 5-G — reliability & correctness fixes (from live runs)

Found by running all 19 tools against the live instance, not by the model:

- **5-E — Process crash on a dropped DB connection.** `sql.ConnectionPool` is an
  `EventEmitter` and emits `'error'` when a pooled connection is lost (server
  restart, failover, idle-socket reset, network blip). Nothing listened for it,
  so Node re-threw it as an uncaught exception and the whole MCP server process
  exited — the client then had to be restarted. In one run this killed the
  process 13 times. `getPool` now attaches an error listener, discards a failed
  pool so the next call reconnects, and collapses concurrent first calls onto one
  connect attempt.
- **5-F — `mssql_monitor_locks` failed on every call.** The query joined a
  table-valued function to a correlated column
  (`LEFT JOIN sys.dm_exec_sql_text(er.sql_handle) … ON 1=1`), which SQL Server
  rejects with error 4104 ("multi-part identifier could not be bound"). A
  correlated TVF must use `APPLY`; changed to `OUTER APPLY`.
- **5-G — Silent wrong-database connection.** With `MSSQL_DATABASE` unset the
  login connected to its default database (usually `master`) silently, so every
  schema/storage tool reported on the wrong database. The server now warns on
  stderr at startup.

## 5.7 Test suites after all round-4 fixes (all green)

| Suite | Result |
|-------|--------|
| `npm run test:security` (analyzer battery, +13 new cases) | **117 / 117** |
| Adversarial pentest (live, this round) | **59 / 59** |
| Functional e2e — all 19 tools (live) | **105 / 105** |
| Zero-width bypass re-verification (live) | **12 / 12** |
| Red-team report-payload re-verification (live) | **9 / 9** |

## 5.8 Method & environment

- Target: `@piyapat/mssql-mcp-server` working tree, `src/index.ts` (~3030 lines).
- Live DB: SQL Server 2025 (17.0.1000.7) Standard Developer Edition, a purpose-built
  `MCPTestDB` (3 schemas, 8 tables, 50k orders / 113k order-items, views, procs,
  functions, a trigger, and exotic-type / hostile-identifier fixtures).
- The MCP server was driven over real stdio MCP, over TCP:1433.
- Model access: `qwen3.8-27b` via the self-hosted vLLM endpoint, run through the
  project-scoped helper scripts under `.claude/scripts/` (secret-bearing files
  excluded from transmission). Raw model output is preserved in 5.10.

## 5.9 Credit

The security review and red-teaming that surfaced and drove the round-4 fixes are
credited to:

**Kietgboiz17**
- GitHub: https://github.com/kietgboiz17
- Email: kietgboiz17@gmail.com

Kietgboiz17 also reported the original v2.0.2 quote-aware guard bypass (the `--`
inside a same-line string literal) privately on 2026-08-23 — see Parts 1–4.

## 5.10 Appendix — raw Qwen review output (`qwen3.8-reviewed.json`)

Preserved verbatim for provenance; the two findings are analysed in 5.2 and 5.3.

```json
{
  "model": "qwen3.8-27b",
  "generatedAt": "2026-08-23T09:38:48.780Z",
  "files": [
    "scripts/create-readonly-login.sql",
    "scripts/security-validation.mjs",
    "src/index.ts"
  ],
  "findings": [
    {
      "severity": "medium",
      "title": "Insecure default for MSSQL_TRUST_CERT allows disabling certificate validation",
      "line": 111,
      "cwe": "CWE-295",
      "evidence": "trustServerCertificate: process.env.MSSQL_TRUST_CERT === \"true\",",
      "impact": "An attacker with network access can perform a Man-in-the-Middle attack to intercept and modify SQL queries and results if the operator sets MSSQL_TRUST_CERT=true. While the default is secure (false), the explicit opt-in mechanism for trusting unvalidated certificates is a significant security risk if misconfigured.",
      "recommendation": "Remove the ability to set trustServerCertificate to true, or require a strong secondary confirmation (e.g., a specific environment variable like MSSQL_INSECURE=true) and log a prominent warning. Ideally, enforce certificate validation always.",
      "file": "src/index.ts"
    },
    {
      "severity": "medium",
      "title": "Bypass of dangerous statement detection via Unicode whitespace normalization",
      "line": 473,
      "cwe": "CWE-185",
      "evidence": "const clean = sanitizeForAnalysis(sqlText).replace(/\\s+/g, \" \");",
      "impact": "The regex patterns in DANGEROUS_STATEMENT_PATTERNS rely on standard whitespace matching; a Unicode separator that JS \\s does not match but SQL Server accepts between two keywords can bypass the block. (Model cited \\u00A0; verified: \\s does match \\u00A0 — the real gap is \\u200B/\\u200C/\\u200D/\\u2060, confirmed live and fixed. See 5.2.)",
      "recommendation": "Normalize all separator code points to ASCII space before testing against the dangerous patterns.",
      "file": "src/index.ts"
    }
  ],
  "errors": []
}
```
