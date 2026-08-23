#!/usr/bin/env node

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  Tool,
} from "@modelcontextprotocol/sdk/types.js";
import sql from "mssql";
import * as fs from "fs";
import * as path from "path";

// ---------------------------------------------------------------------------
// .env loading (no external dependency)
//
// Credentials should live in a .env file instead of being hard-coded in the
// MCP client's JSON config. Search order (first file found wins):
//   1. The file pointed to by MSSQL_ENV_FILE (explicit override)
//   2. .env in the current working directory
//   3. .env in the project root (one level above build/)
// Variables already present in process.env are NEVER overridden, so the JSON
// config's "env" block still takes precedence when both are set.
// ---------------------------------------------------------------------------
function loadEnvFile(): void {
  const candidates = [
    process.env.MSSQL_ENV_FILE,
    path.join(process.cwd(), ".env"),
    path.join(__dirname, "..", ".env"),
  ].filter((p): p is string => !!p);

  for (const file of candidates) {
    let raw: string;
    try {
      raw = fs.readFileSync(file, "utf8");
    } catch {
      continue; // not found — try the next candidate
    }

    for (const line of raw.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) continue;
      const eq = trimmed.indexOf("=");
      if (eq <= 0) continue;
      const key = trimmed.slice(0, eq).trim();
      let value = trimmed.slice(eq + 1).trim();
      // Strip surrounding quotes and trailing inline comments (unquoted values)
      if (
        (value.startsWith('"') && value.endsWith('"')) ||
        (value.startsWith("'") && value.endsWith("'"))
      ) {
        value = value.slice(1, -1);
      } else {
        const hash = value.indexOf(" #");
        if (hash >= 0) value = value.slice(0, hash).trim();
      }
      if (!(key in process.env)) {
        process.env[key] = value;
      }
    }

    console.error(`[mssql-mcp] Loaded environment from ${file}`);
    return; // only the first file found is loaded
  }
}

loadEnvFile();

// ---------------------------------------------------------------------------
// Server mode
//
// MSSQL_READ_ONLY (default: true) controls whether mssql_query may modify data.
//   true  -> allow-list validation: only SELECT / WITH / safe DECLARE batches /
//            whitelisted read-only EXEC are accepted (current behavior).
//   false -> INSERT / UPDATE / DELETE / DDL are permitted, but clearly
//            dangerous server-level statements are still blocked (see
//            containsDangerousStatement below).
// ---------------------------------------------------------------------------
const READ_ONLY = (process.env.MSSQL_READ_ONLY ?? "true").trim().toLowerCase() !== "false";

// SQL Server configuration from environment.
// If MSSQL_DOMAIN is set, Windows (NTLM) authentication is used with the
// given domain + MSSQL_USER + MSSQL_PASSWORD; otherwise SQL authentication.
const config: sql.config = {
  server: process.env.MSSQL_SERVER || "localhost",
  database: process.env.MSSQL_DATABASE || "",
  port: parseInt(process.env.MSSQL_PORT || "1433"),
  ...(process.env.MSSQL_DOMAIN
    ? {
        authentication: {
          type: "ntlm" as const,
          options: {
            domain: process.env.MSSQL_DOMAIN,
            userName: process.env.MSSQL_USER || "",
            password: process.env.MSSQL_PASSWORD || "",
          },
        },
      }
    : {
        user: process.env.MSSQL_USER || "",
        password: process.env.MSSQL_PASSWORD || "",
      }),
  options: {
    // Encrypt by default (opt OUT, not in) so credentials and query results
    // aren't sent in cleartext when someone skips setting this. Only a literal
    // "false" disables it — for local dev against an instance with no TLS cert.
    encrypt: process.env.MSSQL_ENCRYPT !== "false",
    // Certificate validation stays ON unless explicitly disabled — trusting an
    // unvalidated cert defeats the point of enabling encryption in the first
    // place (opens a MITM path), so this is opt-in, not opt-out.
    trustServerCertificate: process.env.MSSQL_TRUST_CERT === "true",
    requestTimeout: parseInt(process.env.MSSQL_REQUEST_TIMEOUT || "30000"),
  },
  pool: {
    max: parseInt(process.env.MSSQL_POOL_MAX || "10"),
    min: 0,
    idleTimeoutMillis: 30000,
  },
};

// Connection pool
let pool: sql.ConnectionPool | null = null;

// ---------------------------------------------------------------------------
// Audit logging
//
// Every tool invocation is logged to STDERR as a single JSON line. stdout is
// the MCP transport and must never be written to; stderr is what the MCP
// client captures into its server log, so that is the audit sink.
//
// Query text is truncated and can be disabled entirely (MSSQL_AUDIT_LOG=false)
// because a query may embed sensitive literals in its WHERE clause.
// ---------------------------------------------------------------------------
const AUDIT_LOG = (process.env.MSSQL_AUDIT_LOG ?? "true").trim().toLowerCase() !== "false";
const AUDIT_QUERY_MAX_CHARS = 500;

function truncateForLog(text: string, max = AUDIT_QUERY_MAX_CHARS): string {
  const oneLine = text.replace(/\s+/g, " ").trim();
  return oneLine.length > max ? `${oneLine.slice(0, max)}…[+${oneLine.length - max} chars]` : oneLine;
}

function auditLog(entry: Record<string, unknown>): void {
  if (!AUDIT_LOG) return;
  try {
    console.error(`[mssql-mcp][audit] ${JSON.stringify({ ts: new Date().toISOString(), ...entry })}`);
  } catch {
    // Logging must never be the reason a request fails.
  }
}

// ---------------------------------------------------------------------------
// Error reporting
//
// Driver errors carry server name, procedure name, line numbers and fragments
// of the executed statement. Handing that back verbatim turns any failing
// query into a schema/structure oracle, so the client gets a first-line,
// length-capped message while the full error goes to the stderr log where the
// operator (not the caller) can read it. MSSQL_VERBOSE_ERRORS=true opts out.
// ---------------------------------------------------------------------------
const VERBOSE_ERRORS = (process.env.MSSQL_VERBOSE_ERRORS ?? "false").trim().toLowerCase() === "true";
const ERROR_MESSAGE_MAX_CHARS = 300;

function describeError(error: unknown): string {
  const raw = error instanceof Error ? error.message : String(error);
  if (VERBOSE_ERRORS) return raw;

  const firstLine = raw.split(/\r?\n/)[0].trim();
  const clipped =
    firstLine.length > ERROR_MESSAGE_MAX_CHARS
      ? `${firstLine.slice(0, ERROR_MESSAGE_MAX_CHARS)}… (truncated)`
      : firstLine;

  // The SQL Server error number is a stable, non-revealing identifier that
  // still lets the caller (and the operator reading the log) correlate.
  const number = (error as { number?: unknown } | null)?.number;
  return typeof number === "number" ? `${clipped} [SQL error ${number}]` : clipped;
}

// ---------------------------------------------------------------------------
// Numeric tool arguments arrive as untyped JSON. A non-numeric value used to
// pass straight through Math.floor() as NaN and reach the driver (or a TOP (n)
// interpolation) as "NaN". Coerce and clamp in one place instead; only a value
// that cannot be a number at all is rejected outright.
// ---------------------------------------------------------------------------
function coerceInt(
  value: unknown,
  name: string,
  opts: { min: number; max: number; fallback: number }
): number {
  if (value === undefined || value === null) return opts.fallback;

  const n =
    typeof value === "number"
      ? value
      : typeof value === "string" && value.trim() !== ""
      ? Number(value)
      : NaN;

  if (!Number.isFinite(n)) {
    throw new Error(`'${name}' must be a number (received ${JSON.stringify(value)}).`);
  }

  return Math.max(opts.min, Math.min(Math.trunc(n), opts.max));
}

// Statement-leading keywords that are permitted. This is an ALLOW-LIST:
// a query is accepted only if its first significant keyword is one of these.
// Allow-listing the read-only entry points avoids the false positives a
// blocklist suffers (e.g. columns/aliases named "Create", "Update",
// "CreatedDate") while still rejecting every write/DDL statement.
//
//   SELECT / WITH      -> plain read (or CTE that ends in a SELECT)
//   DECLARE            -> a batch that builds a @table variable / #temp result
//                         then SELECTs from it; only allowed if it never writes
//                         to a PERSISTENT table (checked by the static analyzer)
//   INSERT             -> a batch that fills a LOCAL #temp table / @table
//                         variable (e.g. INSERT INTO #t SELECT ...); only
//                         allowed if every write target is session-local
//   CREATE             -> only as CREATE TABLE #localtemp — a batch that
//                         creates a LOCAL #temp table, fills it, and reads it
//   EXEC / EXECUTE     -> runs a stored procedure; only allowed if (a) the proc
//                         is on the optional whitelist and (b) its definition
//                         does not write to a persistent table
const ALLOWED_LEADING_KEYWORDS = ["SELECT", "WITH", "DECLARE", "EXEC", "EXECUTE", "INSERT", "CREATE"];

// Entry points that may legitimately contain multiple statements (build a
// temp result, then SELECT from it). SELECT / WITH / EXEC stay single-statement.
const MULTI_STATEMENT_KEYWORDS = ["DECLARE", "INSERT", "CREATE"];

// Optional whitelist of stored procedures the EXEC path may call, supplied via
// the MSSQL_ALLOWED_PROCEDURES env var as a comma-separated list of
// (optionally schema-qualified) names, e.g. "dbo.GetReport,dbo.GetCustomer".
// If unset/empty, NO procedure may be executed (EXEC is effectively disabled).
// Names are compared case-insensitively, with surrounding [] brackets stripped.
function normalizeProcName(name: string): string {
  return name
    .split(".")
    .map((part) => part.trim().replace(/^\[|\]$/g, ""))
    .filter((part) => part.length > 0)
    .join(".")
    .toUpperCase();
}

const ALLOWED_PROCEDURES = new Set(
  (process.env.MSSQL_ALLOWED_PROCEDURES || "")
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0)
    .map(normalizeProcName)
);

// Strip SQL comments and string literals so neither can be used to hide a
// second statement, push a disallowed keyword to the front, or smuggle a
// table name past the static analyzer (e.g. a literal containing "INSERT INTO").
//
// This MUST be a single left-to-right pass, not "strip comments, then strip
// literals" as two independent regex passes. A comment-stripping pass that
// doesn't track quote state treats a `--` INSIDE a string literal as a real
// comment marker and blanks everything after it — including a stacked write
// statement the literal was hiding, e.g. `SELECT 'a--'; DELETE FROM Users`.
// Scanning once means a token that opens a string/identifier consumes its own
// closing delimiter before the scanner ever looks for a comment marker inside
// it, so an embedded `--` or `;` in a literal can never smuggle anything.
const SQL_TOKEN_RE = /--[^\n\r]*|\/\*[\s\S]*?\*\/|'(?:[^']|'')*'|"(?:[^"]|"")*"|\[[^\]]*\]/g;

type SqlToken = { type: "comment" | "squote" | "dquote" | "bracket" | "text"; value: string };

function scanSql(text: string): SqlToken[] {
  const tokens: SqlToken[] = [];
  let lastIndex = 0;
  SQL_TOKEN_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = SQL_TOKEN_RE.exec(text)) !== null) {
    if (m.index > lastIndex) tokens.push({ type: "text", value: text.slice(lastIndex, m.index) });
    const raw = m[0];
    const type: SqlToken["type"] =
      raw.startsWith("--") || raw.startsWith("/*")
        ? "comment"
        : raw.startsWith("'")
        ? "squote"
        : raw.startsWith('"')
        ? "dquote"
        : "bracket";
    tokens.push({ type, value: raw });
    lastIndex = SQL_TOKEN_RE.lastIndex;
  }
  if (lastIndex < text.length) tokens.push({ type: "text", value: text.slice(lastIndex) });
  return tokens;
}

// Comments removed, everything else left verbatim (quotes included) — needed
// where a caller must see the original quoting, e.g. detecting a leading
// string/variable right after EXEC (dynamic SQL).
function stripCommentsOnly(query: string): string {
  return scanSql(query)
    .map((t) => (t.type === "comment" ? " " : t.value))
    .join("");
}

// Fully sanitized for keyword/target analysis: comments removed, single-quoted
// literal content blanked, and double-quoted identifiers normalized to
// bracket form. The connection runs with QUOTED_IDENTIFIER ON (the
// tedious/SQL Server default), so `"Table"` is an OBJECT NAME, not a string
// literal — blanking it the way a real literal is blanked would erase the
// very table name the write-target checks below rely on, letting
// `UPDATE "Users" SET ...` or `DROP TABLE "Users"` slip past undetected.
function sanitizeForAnalysis(query: string): string {
  return scanSql(query)
    .map((t) => {
      if (t.type === "comment") return " ";
      if (t.type === "squote") return " '' ";
      if (t.type === "dquote") return `[${t.value.slice(1, -1).replace(/""/g, '"')}]`;
      return t.value; // bracketed identifier or plain text — preserved
    })
    .join("");
}

// Result of classifying a query's entry point.
type QueryClassification =
  | { kind: "read" } // SELECT / WITH / DECLARE-batch — validated by analyzer
  | { kind: "exec"; procName: string } // EXEC <proc> — needs definition check
  | { kind: "rejected"; reason: string };

// Names matching a SESSION-LOCAL temporary object: a #local temp table or an
// @table variable. Writes to these are session-scoped and never touch
// persistent data, so they are allowed. GLOBAL ##temp tables are visible to
// every session on the server and are therefore treated as persistent
// (##global is NEVER allowed as a write target).
function isTemporaryTarget(name: string): boolean {
  const n = name.trim().replace(/^\[/, "");
  if (n.startsWith("@")) return true;
  return n.startsWith("#") && !n.startsWith("##");
}

// Static analyzer: does this SQL text contain a write to a PERSISTENT table?
//
// We scan the comment-stripped, literal-stripped text for write statements and
// inspect the target immediately following them. A target that starts with
// '#' (temp table) or '@' (table variable) is permitted; anything else is a
// persistent write and causes rejection. TRUNCATE/DROP/ALTER/CREATE target
// persistent objects by definition and are always treated as writes.
//
// This is intentionally conservative: dynamic SQL (sp_executesql / EXEC on a
// string) and nested EXEC cannot be statically resolved, so their presence is
// treated as a potential persistent write and rejected. The DB-level
// db_denydatawriter grant is the backstop for anything this misses.
function writesToPersistentTable(sqlText: string): boolean {
  const normalized = sanitizeForAnalysis(sqlText).replace(/\s+/g, " ");

  // Unconditional red flags: statements that either cannot be statically
  // resolved (any EXEC / dynamic SQL — this also closes the hole where a
  // DECLARE batch could 'EXEC someProc' and bypass the whitelist), can hide
  // a persistent write (DBCC), or create persistent objects mid-batch.
  const redFlags = [
    /(?<![A-Z0-9_])MERGE(?![A-Z0-9_])/i,
    /(?<![A-Z0-9_])(?:EXEC(?:UTE)?|SP_EXECUTESQL)(?![A-Z0-9_])/i,
    /(?<![A-Z0-9_])DBCC(?![A-Z0-9_])/i,
    /(?<![A-Z0-9_])CREATE\s+(?:OR\s+ALTER\s+)?(?:VIEW|PROC(?:EDURE)?|FUNCTION|TRIGGER|SYNONYM|SEQUENCE|TYPE|SCHEMA|ROLE|ASSEMBLY|DEFAULT|RULE)(?![A-Z0-9_])/i,
  ];
  for (const rf of redFlags) {
    if (rf.test(normalized)) return true;
  }

  // Write/DDL statements whose single target must be a LOCAL #temp table or
  // @table variable (##global counts as persistent — see isTemporaryTarget).
  const targetedWrites = [
    // INSERT INTO <target> / INSERT <target>
    /(?<![A-Z0-9_])INSERT\s+(?:INTO\s+)?(\[?[@#]{0,2}[A-Za-z0-9_.\[\]]+)/gi,
    // UPDATE <target>
    /(?<![A-Z0-9_])UPDATE\s+(\[?[@#]{0,2}[A-Za-z0-9_.\[\]]+)/gi,
    // DELETE FROM <target>  /  DELETE <target>
    /(?<![A-Z0-9_])DELETE\s+(?:FROM\s+)?(\[?[@#]{0,2}[A-Za-z0-9_.\[\]]+)/gi,
    // SELECT ... INTO <target>  (the INTO target is what gets created/written)
    /(?<![A-Z0-9_])INTO\s+(\[?[@#]{0,2}[A-Za-z0-9_.\[\]]+)/gi,
    // CREATE TABLE <target>  (allowed only for #local temp tables)
    /(?<![A-Z0-9_])CREATE\s+TABLE\s+(\[?[@#]{0,2}[A-Za-z0-9_.\[\]]+)/gi,
    // CREATE [UNIQUE] [CLUSTERED|NONCLUSTERED] INDEX <name> ON <target>
    /(?<![A-Z0-9_])CREATE\s+(?:UNIQUE\s+)?(?:CLUSTERED\s+|NONCLUSTERED\s+)?INDEX\s+\[?[A-Za-z0-9_]+\]?\s+ON\s+(\[?[@#]{0,2}[A-Za-z0-9_.\[\]]+)/gi,
    // TRUNCATE TABLE <target> / ALTER TABLE <target>
    /(?<![A-Z0-9_])TRUNCATE\s+TABLE\s+(\[?[@#]{0,2}[A-Za-z0-9_.\[\]]+)/gi,
    /(?<![A-Z0-9_])ALTER\s+TABLE\s+(\[?[@#]{0,2}[A-Za-z0-9_.\[\]]+)/gi,
  ];

  for (const re of targetedWrites) {
    let m: RegExpExecArray | null;
    while ((m = re.exec(normalized)) !== null) {
      if (!isTemporaryTarget(m[1])) {
        return true; // a write whose target is NOT a local temp/var => persistent
      }
    }
  }

  // DROP TABLE accepts a comma-separated list — every name must be temporary.
  const dropRe =
    /(?<![A-Z0-9_])DROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?((?:\[?[@#]{0,2}[A-Za-z0-9_.\[\]]+\]?\s*,\s*)*\[?[@#]{0,2}[A-Za-z0-9_.\[\]]+)/gi;
  let dm: RegExpExecArray | null;
  while ((dm = dropRe.exec(normalized)) !== null) {
    for (const name of dm[1].split(",")) {
      if (!isTemporaryTarget(name)) return true;
    }
  }

  return false;
}

// Statements that are blocked even when MSSQL_READ_ONLY=false. These are
// server-level / OS-level operations no LLM-driven tool should ever run:
// command execution, instance reconfiguration, security-principal changes,
// permission grants, ad-hoc remote access, and database drop/restore.
// SCOPE NOTE: this is a BLOCKLIST, and a blocklist is never complete. It stops
// the well-known footguns in write mode; the REAL control is the permissions of
// the login this server connects as (see scripts/create-readonly-login.sql).
// Never run write mode with a login holding sysadmin / securityadmin /
// role-admin rights.
const DANGEROUS_STATEMENT_PATTERNS: Array<{ re: RegExp; label: string }> = [
  // --- dynamic SQL (must stay in this list) ---------------------------------
  // findDangerousStatement analyzes text whose string-literal CONTENT has been
  // blanked, so that a literal cannot smuggle a stacked statement past the
  // analyzer. The flip side is that it cannot see inside the string a dynamic
  // SQL call would execute — so ANY dynamic SQL voids every other pattern here:
  //     EXEC sp_executesql N'EXEC xp_cmdshell ''whoami'''
  // reaches the analyzer as `EXEC sp_executesql N ''` — nothing left to match.
  // Blocking the dynamic-SQL entry points is what makes the rest of this list
  // mean anything in write mode.
  { re: /(?<![A-Z0-9_])SP_EXECUTESQL(?![A-Z0-9_])/i, label: "sp_executesql (dynamic SQL)" },
  { re: /(?<![A-Z0-9_])EXEC(?:UTE)?\s*\(/i, label: "EXEC(<string>) dynamic SQL" },

  // --- OS / filesystem / command execution ----------------------------------
  { re: /(?<![A-Z0-9_])XP_CMDSHELL(?![A-Z0-9_])/i, label: "xp_cmdshell" },
  { re: /(?<![A-Z0-9_])SP_OA[A-Z]+(?![A-Z0-9_])/i, label: "OLE automation (sp_OA*)" },
  { re: /(?<![A-Z0-9_])XP_REG[A-Z]+(?![A-Z0-9_])/i, label: "registry access (xp_reg*)" },
  { re: /(?<![A-Z0-9_])XP_(?:DIRTREE|SUBDIRS|FILEEXIST|CREATESUBDIR|DELETESUBDIR)(?![A-Z0-9_])/i, label: "filesystem access (xp_dirtree / xp_fileexist / ...)" },
  { re: /(?<![A-Z0-9_])BULK\s+INSERT(?![A-Z0-9_])/i, label: "BULK INSERT (reads a server-side file)" },

  // --- instance configuration -----------------------------------------------
  { re: /(?<![A-Z0-9_])SP_CONFIGURE(?![A-Z0-9_])/i, label: "sp_configure" },
  { re: /(?<![A-Z0-9_])RECONFIGURE(?![A-Z0-9_])/i, label: "RECONFIGURE" },
  { re: /(?<![A-Z0-9_])SHUTDOWN(?![A-Z0-9_])/i, label: "SHUTDOWN" },
  { re: /(?<![A-Z0-9_])KILL(?![A-Z0-9_])/i, label: "KILL" },

  // --- database lifecycle ----------------------------------------------------
  { re: /(?<![A-Z0-9_])DROP\s+DATABASE(?![A-Z0-9_])/i, label: "DROP DATABASE" },
  { re: /(?<![A-Z0-9_])ALTER\s+DATABASE(?![A-Z0-9_])/i, label: "ALTER DATABASE" },
  { re: /(?<![A-Z0-9_])RESTORE\s+(?:DATABASE|LOG)(?![A-Z0-9_])/i, label: "RESTORE" },
  { re: /(?<![A-Z0-9_])BACKUP\s+(?:DATABASE|LOG)(?![A-Z0-9_])/i, label: "BACKUP" },

  // --- security principals / privilege escalation ---------------------------
  { re: /(?<![A-Z0-9_])(?:CREATE|ALTER|DROP)\s+(?:LOGIN|USER|CREDENTIAL|CERTIFICATE|ASSEMBLY)(?![A-Z0-9_])/i, label: "security principal / assembly change" },
  { re: /(?<![A-Z0-9_])ALTER\s+(?:SERVER\s+)?ROLE(?![A-Z0-9_])/i, label: "role membership change (ALTER ROLE)" },
  { re: /(?<![A-Z0-9_])SP_(?:ADD|DROP)(?:SRV)?ROLEMEMBER(?![A-Z0-9_])/i, label: "role membership change (sp_addrolemember / sp_addsrvrolemember)" },
  { re: /(?<![A-Z0-9_])EXECUTE\s+AS(?![A-Z0-9_])/i, label: "EXECUTE AS (impersonation)" },
  { re: /(?<![A-Z0-9_])ALTER\s+SERVER(?![A-Z0-9_])/i, label: "ALTER SERVER" },
  { re: /(?<![A-Z0-9_])(?:GRANT|DENY|REVOKE)(?![A-Z0-9_])/i, label: "permission change (GRANT/DENY/REVOKE)" },

  // --- remote / linked-server access ----------------------------------------
  { re: /(?<![A-Z0-9_])(?:OPENROWSET|OPENDATASOURCE|OPENQUERY)(?![A-Z0-9_])/i, label: "ad-hoc / linked-server access (OPENROWSET/OPENDATASOURCE/OPENQUERY)" },
  { re: /(?<![A-Z0-9_])SP_(?:ADD|DROP)LINKEDSERVER(?![A-Z0-9_])/i, label: "linked server change (sp_addlinkedserver)" },
];

// Returns the label of the first dangerous statement found, or null.
// Comments and string literals are stripped first so they cannot hide or
// falsely trigger a match.
function findDangerousStatement(sqlText: string): string | null {
  const clean = sanitizeForAnalysis(sqlText).replace(/\s+/g, " ");
  for (const { re, label } of DANGEROUS_STATEMENT_PATTERNS) {
    if (re.test(clean)) return label;
  }
  return null;
}

// Classify the query's entry point (sync, no DB access).
//
// NOTE: This is the application-level guard — defense-in-depth only. The
// PRIMARY enforcement is the read-only SQL Server login (db_datareader +
// db_denydatawriter, with GRANT EXECUTE only on whitelisted procs). See
// scripts/create-readonly-login.sql.
function classifyQuery(query: string): QueryClassification {
  const noComments = stripCommentsOnly(query);
  const noLiterals = sanitizeForAnalysis(query).replace(/;\s*$/, "");

  // First significant token (skip whitespace and opening parens).
  const leading = noComments.replace(/^[\s(]+/, "");
  const firstWordMatch = leading.match(/^([A-Za-z_][A-Za-z0-9_]*)/);
  if (!firstWordMatch) {
    return { kind: "rejected", reason: "no recognizable leading keyword" };
  }

  const firstKeyword = firstWordMatch[1].toUpperCase();
  if (!ALLOWED_LEADING_KEYWORDS.includes(firstKeyword)) {
    return { kind: "rejected", reason: `leading keyword '${firstKeyword}' is not allowed` };
  }

  // Reject stacked statements EXCEPT for DECLARE / INSERT / CREATE-led
  // batches, which are legitimately multi-statement (build a #temp/@table
  // result, then SELECT from it). For SELECT / WITH / EXEC, any ';' with
  // following content is stacked-query smuggling. (Literals already stripped,
  // so a ';' inside a string does not count.)
  if (!MULTI_STATEMENT_KEYWORDS.includes(firstKeyword) && noLiterals.includes(";")) {
    return { kind: "rejected", reason: "multiple statements (';') are not allowed" };
  }

  if (firstKeyword === "EXEC" || firstKeyword === "EXECUTE") {
    // EXEC [@rc =] <proc> [params]. Capture the procedure name (first token
    // after EXEC that is not an assignment to a return-code variable).
    const rest = leading.replace(/^EXEC(?:UTE)?\s+/i, "");
    // Drop a leading "@var =" return-code capture if present.
    const afterReturnCode = rest.replace(/^@[A-Za-z0-9_]+\s*=\s*/, "");
    // Reject EXEC on a string/variable (dynamic SQL).
    if (/^[(@'"]/.test(afterReturnCode)) {
      return { kind: "rejected", reason: "dynamic EXEC (string/variable) is not allowed" };
    }
    const procMatch = afterReturnCode.match(/^(\[?[A-Za-z0-9_]+\]?(?:\.\[?[A-Za-z0-9_]+\]?){0,2})/);
    if (!procMatch) {
      return { kind: "rejected", reason: "could not parse stored-procedure name after EXEC" };
    }
    // sp_executesql is dynamic SQL by another name — never allow it.
    if (normalizeProcName(procMatch[1]).endsWith("SP_EXECUTESQL")) {
      return { kind: "rejected", reason: "sp_executesql (dynamic SQL) is not allowed" };
    }
    return { kind: "exec", procName: procMatch[1] };
  }

  if (firstKeyword === "CREATE") {
    // CREATE is only allowed as CREATE TABLE #localtemp (single #, never ##).
    if (!/^CREATE\s+TABLE\s+\[?#(?!#)/i.test(leading)) {
      return {
        kind: "rejected",
        reason: "CREATE is only allowed as 'CREATE TABLE #localtemp' (session-local temp table)",
      };
    }
    if (writesToPersistentTable(query)) {
      return {
        kind: "rejected",
        reason: "CREATE TABLE # batch writes to a persistent table or global ##temp (or uses EXEC/DBCC)",
      };
    }
    return { kind: "read" };
  }

  if (firstKeyword === "DECLARE" || firstKeyword === "INSERT") {
    // A DECLARE- or INSERT-led batch is allowed only if it never writes to a
    // persistent table. The analyzer scans the whole batch (every statement)
    // for writes whose target is not a LOCAL #temp table or @table variable.
    if (writesToPersistentTable(query)) {
      return {
        kind: "rejected",
        reason: `${firstKeyword} batch writes to a persistent table or global ##temp (or uses EXEC/DBCC)`,
      };
    }
    return { kind: "read" };
  }

  // SELECT / WITH: still scan for an embedded persistent write via INTO
  // (e.g. "SELECT * INTO RealTable FROM ...").
  if (writesToPersistentTable(query)) {
    return { kind: "rejected", reason: "query writes to a persistent table (SELECT ... INTO)" };
  }
  return { kind: "read" };
}

// Initialize connection pool
async function getPool(): Promise<sql.ConnectionPool> {
  if (!pool) {
    pool = await sql.connect(config);
  }
  return pool;
}

// Typed interfaces for tool arguments
interface QueryArgs {
  query: string;
  maxRows?: number;
  offset?: number;
  response_format?: "json" | "markdown";
}

interface SchemaArgs {
  tableName?: string;
  response_format?: "json" | "markdown";
}

interface StoredProcedureArgs {
  procedureName?: string;
  response_format?: "json" | "markdown";
}

interface MonitorLocksArgs {
  response_format?: "json" | "markdown";
}

interface MonitorUsageArgs {
  topQueries?: number;
  response_format?: "json" | "markdown";
}

interface TestConnectionArgs {
  response_format?: "json" | "markdown";
}

interface ListDatabasesArgs {
  response_format?: "json" | "markdown";
}

interface ListTablesArgs {
  schemaName?: string;
  response_format?: "json" | "markdown";
}

interface SampleDataArgs {
  tableName: string;
  rows?: number;
  response_format?: "json" | "markdown";
}

interface GetRelationshipsArgs {
  tableName?: string;
  response_format?: "json" | "markdown";
}

interface GetViewsArgs {
  viewName?: string;
  response_format?: "json" | "markdown";
}

interface SearchDefinitionsArgs {
  searchText: string;
  response_format?: "json" | "markdown";
}

interface AnalyzeIndexesArgs {
  tableName?: string;
  response_format?: "json" | "markdown";
}

interface AnalyzeStorageArgs {
  topTables?: number;
  response_format?: "json" | "markdown";
}

interface FindBlockingArgs {
  response_format?: "json" | "markdown";
}

interface IndexFragmentationArgs {
  tableName?: string;
  minPageCount?: number;
  response_format?: "json" | "markdown";
}

interface TopQueriesArgs {
  metric?: "cpu" | "duration" | "reads" | "writes" | "memory" | "executions";
  top?: number;
  response_format?: "json" | "markdown";
}

interface PerformanceHealthArgs {
  response_format?: "json" | "markdown";
}

interface GetDeadlocksArgs {
  maxEvents?: number;
  source?: "ring_buffer" | "file";
  response_format?: "json" | "markdown";
}

// Define available tools
const TOOLS: Tool[] = [
  {
    name: "mssql_query",
    description: READ_ONLY
      ? "Execute a read-only SQL query against the MS SQL Server database. Accepts: a single SELECT / WITH...SELECT; a multi-statement batch led by DECLARE, INSERT, or CREATE TABLE # that writes ONLY to session-local #temp tables or @table variables (global ##temp is never allowed); or EXEC of a whitelisted stored procedure whose definition does not write to a persistent table. Writes to real tables, DDL on persistent objects, dynamic SQL, EXEC inside batches, and DBCC are blocked (server runs with MSSQL_READ_ONLY=true). Returns results as JSON or Markdown."
      : "Execute a SQL query against the MS SQL Server database. The server runs in WRITE mode (MSSQL_READ_ONLY=false): SELECT, INSERT, UPDATE, DELETE, and DDL are permitted, but server-level administrative statements (xp_cmdshell, sp_configure, DROP/ALTER DATABASE, RESTORE, login/permission changes, SHUTDOWN, KILL, OPENROWSET) are always blocked. Returns results as JSON or Markdown.",
    inputSchema: {
      type: "object",
      properties: {
        query: {
          type: "string",
          description: READ_ONLY
            ? "The SQL to execute. Must be read-only: a SELECT/WITH query, a DECLARE batch using only #temp/@table targets, or EXEC of an allowed read-only stored procedure."
            : "The SQL to execute. Data modification and DDL are allowed; server-level administrative statements are blocked.",
        },
        maxRows: {
          type: "number",
          description: "Maximum number of rows to return per page (default: 100, max: 1000)",
          default: 100,
        },
        offset: {
          type: "number",
          description: "Row offset for pagination (default: 0)",
          default: 0,
        },
        response_format: {
          type: "string",
          enum: ["json", "markdown"],
          description: "Response format: 'json' for machine-readable, 'markdown' for human-readable (default: json)",
          default: "json",
        },
      },
      required: ["query"],
    },
    annotations: {
      readOnlyHint: READ_ONLY,
      destructiveHint: !READ_ONLY,
      idempotentHint: READ_ONLY,
      openWorldHint: false,
    },
  },
  {
    name: "mssql_get_schema",
    description:
      "Get database schema information including tables, columns, data types, primary keys, and foreign keys. Optionally filter by table name.",
    inputSchema: {
      type: "object",
      properties: {
        tableName: {
          type: "string",
          description:
            "Optional: specific table name to get schema for. If not provided, returns all tables.",
        },
        response_format: {
          type: "string",
          enum: ["json", "markdown"],
          description: "Response format: 'json' for machine-readable, 'markdown' for human-readable (default: markdown)",
          default: "markdown",
        },
      },
    },
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
  },
  {
    name: "mssql_get_stored_procedures",
    description:
      "List stored procedures in the database with their definitions and parameters. Optionally filter by procedure name.",
    inputSchema: {
      type: "object",
      properties: {
        procedureName: {
          type: "string",
          description:
            "Optional: specific procedure name to get details for. If not provided, returns all procedures.",
        },
        response_format: {
          type: "string",
          enum: ["json", "markdown"],
          description: "Response format: 'json' for machine-readable, 'markdown' for human-readable (default: markdown)",
          default: "markdown",
        },
      },
    },
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
  },
  {
    name: "mssql_monitor_locks",
    description:
      "Monitor database locks, blocking sessions, and potential deadlocks. Shows lock types, resources, and wait times.",
    inputSchema: {
      type: "object",
      properties: {
        response_format: {
          type: "string",
          enum: ["json", "markdown"],
          description: "Response format: 'json' for machine-readable, 'markdown' for human-readable (default: markdown)",
          default: "markdown",
        },
      },
    },
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: false,
    },
  },
  {
    name: "mssql_monitor_usage",
    description:
      "Get database resource usage statistics including CPU, memory, active sessions, and top resource-consuming queries.",
    inputSchema: {
      type: "object",
      properties: {
        topQueries: {
          type: "number",
          description: "Number of top CPU-consuming queries to return (default: 10)",
          default: 10,
        },
        response_format: {
          type: "string",
          enum: ["json", "markdown"],
          description: "Response format: 'json' for machine-readable, 'markdown' for human-readable (default: markdown)",
          default: "markdown",
        },
      },
    },
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: false,
    },
  },
  {
    name: "mssql_test_connection",
    description:
      "Test database connectivity and return server information: version, edition, current database, login, and server mode (read-only or write).",
    inputSchema: {
      type: "object",
      properties: {
        response_format: {
          type: "string",
          enum: ["json", "markdown"],
          description: "Response format (default: markdown)",
          default: "markdown",
        },
      },
    },
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
  },
  {
    name: "mssql_list_databases",
    description:
      "List all databases on the SQL Server instance with state, recovery model, compatibility level, and creation date.",
    inputSchema: {
      type: "object",
      properties: {
        response_format: {
          type: "string",
          enum: ["json", "markdown"],
          description: "Response format (default: markdown)",
          default: "markdown",
        },
      },
    },
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
  },
  {
    name: "mssql_list_tables",
    description:
      "List tables in the current database with schema, row count, and size in MB. Optionally filter by schema name.",
    inputSchema: {
      type: "object",
      properties: {
        schemaName: {
          type: "string",
          description: "Optional: filter tables by schema (e.g. 'dbo'). Default: all schemas.",
        },
        response_format: {
          type: "string",
          enum: ["json", "markdown"],
          description: "Response format (default: markdown)",
          default: "markdown",
        },
      },
    },
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
  },
  {
    name: "mssql_sample_data",
    description:
      "Retrieve sample rows from a table (default 10, max 100). Safe way to preview data without writing SQL. Accepts 'table' or 'schema.table'.",
    inputSchema: {
      type: "object",
      properties: {
        tableName: {
          type: "string",
          description: "Table name, optionally schema-qualified (e.g. 'Orders' or 'dbo.Orders').",
        },
        rows: {
          type: "number",
          description: "Number of rows to sample (default: 10, max: 100)",
          default: 10,
        },
        response_format: {
          type: "string",
          enum: ["json", "markdown"],
          description: "Response format (default: markdown)",
          default: "markdown",
        },
      },
      required: ["tableName"],
    },
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
  },
  {
    name: "mssql_get_relationships",
    description:
      "Get foreign key relationships between tables: constraint name, from/to table and column, and delete/update actions. Optionally filter by table name (matches either side).",
    inputSchema: {
      type: "object",
      properties: {
        tableName: {
          type: "string",
          description: "Optional: only show relationships involving this table.",
        },
        response_format: {
          type: "string",
          enum: ["json", "markdown"],
          description: "Response format (default: markdown)",
          default: "markdown",
        },
      },
    },
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
  },
  {
    name: "mssql_get_views",
    description:
      "List views in the database with their full SQL definitions. Optionally filter by view name to get a single view's definition.",
    inputSchema: {
      type: "object",
      properties: {
        viewName: {
          type: "string",
          description: "Optional: specific view name to get the definition for.",
        },
        response_format: {
          type: "string",
          enum: ["json", "markdown"],
          description: "Response format (default: markdown)",
          default: "markdown",
        },
      },
    },
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
  },
  {
    name: "mssql_search_definitions",
    description:
      "Search the SQL source code of all stored procedures, views, functions, and triggers for a text fragment (e.g. a table name or business term). Useful for impact analysis and legacy code exploration.",
    inputSchema: {
      type: "object",
      properties: {
        searchText: {
          type: "string",
          description: "Text to search for inside object definitions (literal substring, case-insensitive).",
        },
        response_format: {
          type: "string",
          enum: ["json", "markdown"],
          description: "Response format (default: markdown)",
          default: "markdown",
        },
      },
      required: ["searchText"],
    },
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
  },
  {
    name: "mssql_analyze_indexes",
    description:
      "Analyze index usage (seeks/scans/lookups/updates per index) and list potentially missing indexes suggested by the query optimizer. Optionally filter usage stats by table name.",
    inputSchema: {
      type: "object",
      properties: {
        tableName: {
          type: "string",
          description: "Optional: only show index usage for this table.",
        },
        response_format: {
          type: "string",
          enum: ["json", "markdown"],
          description: "Response format (default: markdown)",
          default: "markdown",
        },
      },
    },
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: false,
    },
  },
  {
    name: "mssql_analyze_storage",
    description:
      "Analyze storage: largest tables by size (row count, total/used MB) and database file sizes. Useful for capacity planning and finding space hogs.",
    inputSchema: {
      type: "object",
      properties: {
        topTables: {
          type: "number",
          description: "Number of largest tables to return (default: 20)",
          default: 20,
        },
        response_format: {
          type: "string",
          enum: ["json", "markdown"],
          description: "Response format (default: markdown)",
          default: "markdown",
        },
      },
    },
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: false,
    },
  },
  {
    name: "mssql_index_fragmentation",
    description:
      "Analyze index fragmentation and recommend maintenance: REBUILD (fragmentation ≥ 30%), REORGANIZE (5–30%), or OK (< 5%). Generates ready-to-run ALTER INDEX statements (ONLINE=ON suggested automatically on editions that support it). Small indexes below minPageCount are excluded since fragmentation there is harmless.",
    inputSchema: {
      type: "object",
      properties: {
        tableName: {
          type: "string",
          description: "Optional: analyze only this table.",
        },
        minPageCount: {
          type: "number",
          description: "Ignore indexes smaller than this many pages (default: 100 ≈ 800 KB).",
          default: 100,
        },
        response_format: {
          type: "string",
          enum: ["json", "markdown"],
          description: "Response format (default: markdown)",
          default: "markdown",
        },
      },
    },
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: false,
    },
  },
  {
    name: "mssql_top_queries",
    description:
      "Find the most expensive queries from the plan cache, ranked by a chosen metric: cpu, duration, reads (logical I/O), writes, memory (grant size), or executions. Returns per-query totals and averages with the SQL text — the starting point for performance tuning.",
    inputSchema: {
      type: "object",
      properties: {
        metric: {
          type: "string",
          enum: ["cpu", "duration", "reads", "writes", "memory", "executions"],
          description: "Ranking metric (default: cpu)",
          default: "cpu",
        },
        top: {
          type: "number",
          description: "Number of queries to return (default: 10, max: 50)",
          default: 10,
        },
        response_format: {
          type: "string",
          enum: ["json", "markdown"],
          description: "Response format (default: markdown)",
          default: "markdown",
        },
      },
    },
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: false,
    },
  },
  {
    name: "mssql_performance_health",
    description:
      "Overall performance health check: top wait statistics (with benign waits filtered out), memory counters (Page Life Expectancy, memory grants pending, total vs target memory), workload counters (batch requests, compilations), and rule-based optimization recommendations (e.g. high CXPACKET → review MAXDOP, PAGEIOLATCH → check I/O and indexes, LCK_M → run mssql_find_blocking).",
    inputSchema: {
      type: "object",
      properties: {
        response_format: {
          type: "string",
          enum: ["json", "markdown"],
          description: "Response format (default: markdown)",
          default: "markdown",
        },
      },
    },
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: false,
    },
  },
  {
    name: "mssql_find_blocking",
    description:
      "Find current blocking chains: which sessions are blocked, by whom, on what resource, and for how long. Identifies lead blockers (including idle sessions holding open transactions) with their SQL text. Supported: SQL Server 2019 (15.x), 2022 (16.x), 2025 (17.x) — all editions including Express. Requires VIEW SERVER STATE.",
    inputSchema: {
      type: "object",
      properties: {
        response_format: {
          type: "string",
          enum: ["json", "markdown"],
          description: "Response format (default: markdown)",
          default: "markdown",
        },
      },
    },
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: false,
    },
  },
  {
    name: "mssql_get_deadlocks",
    description:
      "Retrieve recent deadlock events from the built-in system_health Extended Events session, including the full deadlock graph XML, victim sessions, and the queries involved. Source 'ring_buffer' (default, fast, recent events only) or 'file' (reads system_health .xel files, further back but slower). Supported: SQL Server 2019 (15.x), 2022 (16.x), 2025 (17.x) — all editions including Express. Requires VIEW SERVER STATE.",
    inputSchema: {
      type: "object",
      properties: {
        maxEvents: {
          type: "number",
          description: "Maximum number of deadlock events to return (default: 5, max: 25)",
          default: 5,
        },
        source: {
          type: "string",
          enum: ["ring_buffer", "file"],
          description:
            "'ring_buffer' = in-memory recent events (fast). 'file' = system_health event files (older history, slower).",
          default: "ring_buffer",
        },
        response_format: {
          type: "string",
          enum: ["json", "markdown"],
          description: "Response format (default: markdown)",
          default: "markdown",
        },
      },
    },
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: false,
    },
  },
];

// Tool handlers

// For an EXEC <proc>, verify the procedure is (a) on the whitelist and (b) does
// not write to a persistent table. Throws with a descriptive message if not.
// Returns the procedure definition's effective read-only status.
async function assertExecProcIsReadOnly(procName: string): Promise<void> {
  if (ALLOWED_PROCEDURES.size === 0) {
    throw new Error(
      "Executing stored procedures is disabled. Set MSSQL_ALLOWED_PROCEDURES to a comma-separated whitelist to enable it."
    );
  }
  if (!ALLOWED_PROCEDURES.has(normalizeProcName(procName))) {
    throw new Error(
      `Stored procedure '${procName}' is not on the allowed list (MSSQL_ALLOWED_PROCEDURES).`
    );
  }

  const dbPool = await getPool();
  const definitionResult = await dbPool
    .request()
    .input("procName", sql.NVarChar, procName)
    .query("SELECT OBJECT_DEFINITION(OBJECT_ID(@procName)) AS definition");

  const definition: string | null = definitionResult.recordset[0]?.definition ?? null;
  if (!definition) {
    throw new Error(
      `Could not read the definition of '${procName}' (it may not exist or VIEW DEFINITION is not granted). Refusing to execute.`
    );
  }

  // Strip the CREATE PROCEDURE header before analysis — otherwise the
  // header itself would trip the CREATE PROC red flag. (A WITH EXECUTE AS
  // clause is intentionally NOT stripped: privilege-escalating procs are
  // rejected by the EXEC red flag, which is the conservative choice here.)
  const body = definition.replace(/^[\s\S]*?CREATE\s+(?:OR\s+ALTER\s+)?PROC(?:EDURE)?\s+/i, "");

  if (writesToPersistentTable(body)) {
    throw new Error(
      `Stored procedure '${procName}' writes to a persistent table or global ##temp (or uses dynamic SQL / nested EXEC / DBCC) and cannot be executed by this read-only server.`
    );
  }
}

// One page of a streamed result set.
type QueryPage = {
  columns: string[];
  rows: Record<string, unknown>[];
  scanned: number; // rows observed in the first recordset before we stopped
  hasMore: boolean;
  totalKnown: boolean; // false when we cancelled before the end of the set
};

// Read a query's first recordset in STREAMING mode, keeping only the requested
// page in memory.
//
// The previous implementation awaited the whole recordset and then sliced it,
// so `SELECT * FROM HugeTable` buffered every row into the server process
// before maxRows was ever applied — a query that is perfectly legal under the
// read-only allow-list could exhaust the heap. Streaming bounds memory to
// `limit` rows regardless of how large the result set is, and cancelling one
// row past the window stops the server from shipping the rest over the wire.
//
// Only the FIRST recordset is returned, matching the previous
// `result.recordset` behaviour for DECLARE/INSERT batches.
async function streamQueryPage(query: string, offset: number, limit: number): Promise<QueryPage> {
  const dbPool = await getPool();
  const request = dbPool.request();
  request.stream = true;

  const rows: Record<string, unknown>[] = [];
  let columns: string[] = [];
  let recordsetIndex = -1;
  let scanned = 0;
  let hasMore = false;
  let stoppedEarly = false;
  let streamError: Error | null = null;

  request.on("recordset", (cols: Record<string, unknown>) => {
    recordsetIndex += 1;
    if (recordsetIndex === 0) columns = Object.keys(cols ?? {});
  });

  request.on("row", (row: Record<string, unknown>) => {
    if (recordsetIndex !== 0 || stoppedEarly) return;

    scanned += 1;
    if (scanned <= offset) return; // still skipping to the start of the page
    if (rows.length < limit) {
      rows.push(row);
      return;
    }

    // One row beyond the page window: that is all we need to report hasMore.
    // Cancel rather than drain — cancellation is asynchronous, so the
    // stoppedEarly guard above drops any rows still in flight.
    hasMore = true;
    stoppedEarly = true;
    request.cancel();
  });

  // In stream mode the driver EMITS errors instead of rejecting the promise,
  // so an unhandled 'error' event would otherwise crash the process.
  request.on("error", (err: Error) => {
    if (!streamError) streamError = err;
  });

  await request.query(query);

  // A cancel surfaces here as an error too; that one is expected and ignored.
  if (streamError && !stoppedEarly) throw streamError;

  return { columns, rows, scanned, hasMore, totalKnown: !stoppedEarly };
}

async function handleMssqlQuery(args: QueryArgs): Promise<string> {
  const { query, response_format = "json" } = args;
  const limit = coerceInt(args.maxRows, "maxRows", { min: 1, max: 1000, fallback: 100 });
  const offset = coerceInt(args.offset, "offset", { min: 0, max: 10_000_000, fallback: 0 });

  if (typeof query !== "string" || query.trim() === "") {
    throw new Error("'query' is required and must be a non-empty string.");
  }

  // Server-level dangerous statements are blocked in BOTH modes.
  const dangerous = findDangerousStatement(query);
  if (dangerous) {
    throw new Error(
      `This statement is always blocked: ${dangerous}. Server-level and destructive administrative operations are never allowed through this tool.`
    );
  }

  if (READ_ONLY) {
    const classification = classifyQuery(query);
    if (classification.kind === "rejected") {
      throw new Error(
        `Read-only mode (MSSQL_READ_ONLY=true): only read-only queries are allowed (${classification.reason}). Use a SELECT / WITH...SELECT, a DECLARE/INSERT/CREATE TABLE # batch that writes only to LOCAL #temp/@table variables (global ##temp is not allowed), or EXEC of a whitelisted read-only procedure.`
      );
    }
    if (classification.kind === "exec") {
      await assertExecProcIsReadOnly(classification.procName);
    }
  }

  const started = Date.now();
  const { columns, rows: page, scanned, hasMore, totalKnown } = await streamQueryPage(
    query,
    offset,
    limit
  );

  auditLog({
    event: "query",
    tool: "mssql_query",
    mode: READ_ONLY ? "read-only" : "write",
    query: truncateForLog(query),
    offset,
    limit,
    returnedRows: page.length,
    scannedRows: scanned,
    truncated: !totalKnown,
    durationMs: Date.now() - started,
  });

  // totalCount is only reported when the whole set was actually read; after an
  // early cancel we know the page and that more exist, not the true total.
  const totalCount = totalKnown ? scanned : null;

  if (response_format === "markdown") {
    if (page.length === 0) {
      return scanned > 0
        ? `_No rows at offset ${offset} (result set has ${scanned} row${scanned === 1 ? "" : "s"})._`
        : "_No rows returned._";
    }
    const cols = columns.length > 0 ? columns : Object.keys(page[0]);
    const header = `| ${cols.join(" | ")} |`;
    const separator = `| ${cols.map(() => "---").join(" | ")} |`;
    const rows = page.map((row) => `| ${cols.map((c) => String(row[c] ?? "")).join(" | ")} |`);
    const range = `${offset + 1}–${offset + page.length}`;
    const meta = totalKnown
      ? `\n_Showing rows ${range} of ${totalCount}${hasMore ? " (more available)" : ""}_`
      : `\n_Showing rows ${range}; more rows available (total not counted — the result set was not read to the end)._`;
    return [header, separator, ...rows, meta].join("\n");
  }

  return JSON.stringify(
    {
      totalCount,
      totalCountExact: totalKnown,
      scannedRows: scanned,
      returnedRows: page.length,
      offset,
      hasMore,
      nextOffset: hasMore ? offset + limit : null,
      columns: columns.length > 0 ? columns : Object.keys(page[0] ?? {}),
      rows: page,
    },
    null,
    2
  );
}

async function handleMssqlGetSchema(args: SchemaArgs): Promise<string> {
  const { tableName, response_format = "markdown" } = args;
  const dbPool = await getPool();

  let query = `
    SELECT
      t.TABLE_SCHEMA,
      t.TABLE_NAME,
      c.COLUMN_NAME,
      c.DATA_TYPE,
      c.CHARACTER_MAXIMUM_LENGTH,
      c.IS_NULLABLE,
      CASE WHEN pk.COLUMN_NAME IS NOT NULL THEN 'YES' ELSE 'NO' END AS IS_PRIMARY_KEY,
      CASE WHEN fk.COLUMN_NAME IS NOT NULL THEN 'YES' ELSE 'NO' END AS IS_FOREIGN_KEY,
      fk.REFERENCED_TABLE_NAME,
      fk.REFERENCED_COLUMN_NAME
    FROM INFORMATION_SCHEMA.TABLES t
    INNER JOIN INFORMATION_SCHEMA.COLUMNS c
      ON t.TABLE_SCHEMA = c.TABLE_SCHEMA
      AND t.TABLE_NAME = c.TABLE_NAME
    LEFT JOIN (
      SELECT ku.TABLE_SCHEMA, ku.TABLE_NAME, ku.COLUMN_NAME
      FROM INFORMATION_SCHEMA.TABLE_CONSTRAINTS tc
      INNER JOIN INFORMATION_SCHEMA.KEY_COLUMN_USAGE ku
        ON tc.CONSTRAINT_SCHEMA = ku.CONSTRAINT_SCHEMA
        AND tc.CONSTRAINT_NAME = ku.CONSTRAINT_NAME
      WHERE tc.CONSTRAINT_TYPE = 'PRIMARY KEY'
    ) pk ON c.TABLE_SCHEMA = pk.TABLE_SCHEMA
      AND c.TABLE_NAME = pk.TABLE_NAME
      AND c.COLUMN_NAME = pk.COLUMN_NAME
    LEFT JOIN (
      SELECT
        ku.TABLE_SCHEMA,
        ku.TABLE_NAME,
        ku.COLUMN_NAME,
        ku2.TABLE_NAME AS REFERENCED_TABLE_NAME,
        ku2.COLUMN_NAME AS REFERENCED_COLUMN_NAME
      FROM INFORMATION_SCHEMA.REFERENTIAL_CONSTRAINTS rc
      INNER JOIN INFORMATION_SCHEMA.KEY_COLUMN_USAGE ku
        ON rc.CONSTRAINT_SCHEMA = ku.CONSTRAINT_SCHEMA
        AND rc.CONSTRAINT_NAME = ku.CONSTRAINT_NAME
      INNER JOIN INFORMATION_SCHEMA.KEY_COLUMN_USAGE ku2
        ON rc.UNIQUE_CONSTRAINT_SCHEMA = ku2.CONSTRAINT_SCHEMA
        AND rc.UNIQUE_CONSTRAINT_NAME = ku2.CONSTRAINT_NAME
    ) fk ON c.TABLE_SCHEMA = fk.TABLE_SCHEMA
      AND c.TABLE_NAME = fk.TABLE_NAME
      AND c.COLUMN_NAME = fk.COLUMN_NAME
    WHERE t.TABLE_TYPE = 'BASE TABLE'
  `;

  if (tableName) {
    query += ` AND t.TABLE_NAME = @tableName`;
  }

  query += ` ORDER BY t.TABLE_SCHEMA, t.TABLE_NAME, c.ORDINAL_POSITION`;

  const request = dbPool.request();
  if (tableName) {
    request.input("tableName", sql.VarChar, tableName);
  }

  const result = await request.query(query);

  if (response_format === "json") {
    return JSON.stringify(result.recordset, null, 2);
  }

  // Markdown: group by table
  if (result.recordset.length === 0) return "_No tables found._";

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const tables = new Map<string, any[]>();
  for (const row of result.recordset) {
    const key = `${row.TABLE_SCHEMA}.${row.TABLE_NAME}`;
    if (!tables.has(key)) tables.set(key, []);
    tables.get(key)!.push(row);
  }

  const sections: string[] = [];
  for (const [tableName, cols] of tables) {
    sections.push(`### ${tableName}`);
    sections.push("| Column | Type | Nullable | PK | FK | References |");
    sections.push("| --- | --- | --- | --- | --- | --- |");
    for (const col of cols) {
      const type = col.CHARACTER_MAXIMUM_LENGTH
        ? `${col.DATA_TYPE}(${col.CHARACTER_MAXIMUM_LENGTH})`
        : col.DATA_TYPE;
      const ref = col.REFERENCED_TABLE_NAME
        ? `${col.REFERENCED_TABLE_NAME}.${col.REFERENCED_COLUMN_NAME}`
        : "";
      sections.push(`| ${col.COLUMN_NAME} | ${type} | ${col.IS_NULLABLE} | ${col.IS_PRIMARY_KEY} | ${col.IS_FOREIGN_KEY} | ${ref} |`);
    }
    sections.push("");
  }

  return sections.join("\n");
}

async function handleMssqlGetStoredProcedures(args: StoredProcedureArgs): Promise<string> {
  const { procedureName, response_format = "markdown" } = args;
  const dbPool = await getPool();

  // Single query joining procedures with their parameters (fixes N+1)
  let query = `
    SELECT
      r.ROUTINE_SCHEMA,
      r.ROUTINE_NAME,
      r.ROUTINE_TYPE,
      r.CREATED,
      r.LAST_ALTERED,
      r.ROUTINE_DEFINITION,
      p.PARAMETER_NAME,
      p.DATA_TYPE,
      p.PARAMETER_MODE,
      p.CHARACTER_MAXIMUM_LENGTH,
      p.ORDINAL_POSITION
    FROM INFORMATION_SCHEMA.ROUTINES r
    LEFT JOIN INFORMATION_SCHEMA.PARAMETERS p
      ON r.ROUTINE_SCHEMA = p.SPECIFIC_SCHEMA
      AND r.ROUTINE_NAME = p.SPECIFIC_NAME
    WHERE r.ROUTINE_TYPE = 'PROCEDURE'
  `;

  if (procedureName) {
    query += ` AND r.ROUTINE_NAME = @procedureName`;
  }

  query += ` ORDER BY r.ROUTINE_SCHEMA, r.ROUTINE_NAME, p.ORDINAL_POSITION`;

  const request = dbPool.request();
  if (procedureName) {
    request.input("procedureName", sql.VarChar, procedureName);
  }

  const result = await request.query(query);

  // Group rows by procedure
  type ProcRecord = {
    ROUTINE_SCHEMA: string;
    ROUTINE_NAME: string;
    ROUTINE_TYPE: string;
    CREATED: Date;
    LAST_ALTERED: Date;
    ROUTINE_DEFINITION: string;
    PARAMETERS: Array<{
      PARAMETER_NAME: string;
      DATA_TYPE: string;
      PARAMETER_MODE: string;
      CHARACTER_MAXIMUM_LENGTH: number | null;
    }>;
  };

  const procMap = new Map<string, ProcRecord>();
  for (const row of result.recordset) {
    const key = `${row.ROUTINE_SCHEMA}.${row.ROUTINE_NAME}`;
    if (!procMap.has(key)) {
      procMap.set(key, {
        ROUTINE_SCHEMA: row.ROUTINE_SCHEMA,
        ROUTINE_NAME: row.ROUTINE_NAME,
        ROUTINE_TYPE: row.ROUTINE_TYPE,
        CREATED: row.CREATED,
        LAST_ALTERED: row.LAST_ALTERED,
        ROUTINE_DEFINITION: row.ROUTINE_DEFINITION,
        PARAMETERS: [],
      });
    }
    if (row.PARAMETER_NAME) {
      procMap.get(key)!.PARAMETERS.push({
        PARAMETER_NAME: row.PARAMETER_NAME,
        DATA_TYPE: row.DATA_TYPE,
        PARAMETER_MODE: row.PARAMETER_MODE,
        CHARACTER_MAXIMUM_LENGTH: row.CHARACTER_MAXIMUM_LENGTH,
      });
    }
  }

  const procs = Array.from(procMap.values());

  if (response_format === "json") {
    return JSON.stringify(procs, null, 2);
  }

  // Markdown output
  if (procs.length === 0) return "_No stored procedures found._";

  const sections: string[] = [];
  for (const proc of procs) {
    sections.push(`### ${proc.ROUTINE_SCHEMA}.${proc.ROUTINE_NAME}`);
    sections.push(`- **Created**: ${proc.CREATED}`);
    sections.push(`- **Last Altered**: ${proc.LAST_ALTERED}`);
    if (proc.PARAMETERS.length > 0) {
      sections.push("\n**Parameters:**");
      sections.push("| Name | Type | Mode |");
      sections.push("| --- | --- | --- |");
      for (const p of proc.PARAMETERS) {
        const type = p.CHARACTER_MAXIMUM_LENGTH
          ? `${p.DATA_TYPE}(${p.CHARACTER_MAXIMUM_LENGTH})`
          : p.DATA_TYPE;
        sections.push(`| ${p.PARAMETER_NAME} | ${type} | ${p.PARAMETER_MODE} |`);
      }
    } else {
      sections.push("_No parameters_");
    }
    if (proc.ROUTINE_DEFINITION) {
      sections.push("\n**Definition:**");
      sections.push("```sql");
      sections.push(proc.ROUTINE_DEFINITION);
      sections.push("```");
    }
    sections.push("");
  }

  return sections.join("\n");
}

async function handleMssqlMonitorLocks(args: MonitorLocksArgs): Promise<string> {
  const { response_format = "markdown" } = args;
  const dbPool = await getPool();

  const query = `
    SELECT
      tl.request_session_id AS session_id,
      es.login_name,
      es.host_name,
      DB_NAME(tl.resource_database_id) AS database_name,
      tl.resource_type,
      tl.resource_description,
      tl.request_mode AS lock_mode,
      tl.request_status,
      wt.wait_duration_ms,
      wt.wait_type,
      er.blocking_session_id,
      er.wait_time AS request_wait_time,
      st.text AS query_text
    FROM sys.dm_tran_locks tl
    LEFT JOIN sys.dm_exec_sessions es
      ON tl.request_session_id = es.session_id
    LEFT JOIN sys.dm_exec_requests er
      ON tl.request_session_id = er.session_id
    LEFT JOIN sys.dm_os_waiting_tasks wt
      ON tl.request_session_id = wt.session_id
    LEFT JOIN sys.dm_exec_sql_text(er.sql_handle) st
      ON 1=1
    WHERE tl.request_session_id <> @@SPID
      AND es.is_user_process = 1
    ORDER BY wt.wait_duration_ms DESC, tl.request_session_id
  `;

  const result = await dbPool.request().query(query);
  const locks = result.recordset;

  if (response_format === "json") {
    return JSON.stringify({ lockCount: locks.length, locks }, null, 2);
  }

  if (locks.length === 0) return "_No active locks found._";

  const lines = [
    `**Active Locks: ${locks.length}**\n`,
    "| Session | Login | Host | DB | Resource | Lock Mode | Status | Wait (ms) | Blocking |",
    "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
  ];
  for (const l of locks) {
    lines.push(
      `| ${l.session_id} | ${l.login_name ?? ""} | ${l.host_name ?? ""} | ${l.database_name ?? ""} | ${l.resource_type} ${l.resource_description ?? ""} | ${l.lock_mode} | ${l.request_status} | ${l.wait_duration_ms ?? 0} | ${l.blocking_session_id ?? "none"} |`
    );
  }
  return lines.join("\n");
}

async function handleMssqlMonitorUsage(args: MonitorUsageArgs): Promise<string> {
  const { response_format = "markdown" } = args;
  const topQueries = coerceInt(args.topQueries, "topQueries", { min: 1, max: 100, fallback: 10 });
  const dbPool = await getPool();

  const statsQuery = `
    SELECT
      (SELECT COUNT(*) FROM sys.dm_exec_sessions WHERE is_user_process = 1) AS active_sessions,
      (SELECT COUNT(*) FROM sys.dm_exec_requests) AS active_requests,
      (SELECT SUM(cpu_time) FROM sys.dm_exec_requests) AS total_cpu_time,
      (SELECT COUNT(*) FROM sys.dm_exec_requests WHERE blocking_session_id <> 0) AS blocked_sessions
  `;

  const topQueriesQuery = `
    SELECT TOP (@topQueries)
      DB_NAME(t.dbid) AS database_name,
      qs.execution_count,
      qs.total_worker_time / 1000 AS total_cpu_ms,
      qs.total_worker_time / qs.execution_count / 1000 AS avg_cpu_ms,
      qs.total_elapsed_time / 1000 AS total_elapsed_ms,
      qs.total_elapsed_time / qs.execution_count / 1000 AS avg_elapsed_ms,
      qs.total_logical_reads,
      qs.total_logical_reads / qs.execution_count AS avg_logical_reads,
      SUBSTRING(t.text, (qs.statement_start_offset/2)+1,
        ((CASE qs.statement_end_offset
          WHEN -1 THEN DATALENGTH(t.text)
          ELSE qs.statement_end_offset
        END - qs.statement_start_offset)/2) + 1) AS query_text
    FROM sys.dm_exec_query_stats qs
    CROSS APPLY sys.dm_exec_sql_text(qs.sql_handle) t
    ORDER BY qs.total_worker_time DESC
  `;

  const memoryQuery = `
    SELECT
      DB_NAME(database_id) AS database_name,
      COUNT(*) * 8 / 1024 AS buffer_cache_mb
    FROM sys.dm_os_buffer_descriptors
    WHERE database_id > 4
    GROUP BY database_id
    ORDER BY buffer_cache_mb DESC
  `;

  const [statsResult, topQueriesResult, memoryResult] = await Promise.all([
    dbPool.request().query(statsQuery),
    dbPool.request().input("topQueries", sql.Int, topQueries).query(topQueriesQuery),
    dbPool.request().query(memoryQuery),
  ]);

  const stats = statsResult.recordset[0];
  const queries = topQueriesResult.recordset;
  const memory = memoryResult.recordset;

  if (response_format === "json") {
    return JSON.stringify({ stats, topQueries: queries, memoryUsage: memory }, null, 2);
  }

  const lines: string[] = [];

  lines.push("## Database Resource Usage\n");
  lines.push("### Session Stats");
  lines.push(`- Active user sessions: **${stats.active_sessions}**`);
  lines.push(`- Active requests: **${stats.active_requests}**`);
  lines.push(`- Blocked sessions: **${stats.blocked_sessions}**`);
  lines.push(`- Total CPU time (ms): **${stats.total_cpu_time ?? 0}**`);

  lines.push("\n### Buffer Cache Usage");
  if (memory.length === 0) {
    lines.push("_No data available._");
  } else {
    lines.push("| Database | Buffer Cache (MB) |");
    lines.push("| --- | --- |");
    for (const m of memory) {
      lines.push(`| ${m.database_name} | ${m.buffer_cache_mb} |`);
    }
  }

  lines.push(`\n### Top ${topQueries} Queries by CPU`);
  if (queries.length === 0) {
    lines.push("_No query stats available._");
  } else {
    lines.push("| DB | Executions | Avg CPU (ms) | Avg Elapsed (ms) | Avg Reads | Query |");
    lines.push("| --- | --- | --- | --- | --- | --- |");
    for (const q of queries) {
      const text = String(q.query_text ?? "").replace(/\n/g, " ").slice(0, 80);
      lines.push(`| ${q.database_name ?? ""} | ${q.execution_count} | ${q.avg_cpu_ms} | ${q.avg_elapsed_ms} | ${q.avg_logical_reads} | \`${text}\` |`);
    }
  }

  return lines.join("\n");
}

// --- New tool handlers ------------------------------------------------------

// Render a recordset as a Markdown table (generic helper for the new tools).
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function toMarkdownTable(rows: any[], emptyMessage = "_No rows._"): string {
  if (rows.length === 0) return emptyMessage;
  const columns = Object.keys(rows[0]);
  const lines = [
    `| ${columns.join(" | ")} |`,
    `| ${columns.map(() => "---").join(" | ")} |`,
    ...rows.map(
      (row) => `| ${columns.map((c) => String(row[c] ?? "").replace(/\n/g, " ").replace(/\|/g, "\\|")).join(" | ")} |`
    ),
  ];
  return lines.join("\n");
}

// Validate and safely bracket-quote a (possibly schema-qualified) table name.
// Throws if any part contains characters outside a conservative identifier set.
function quoteTableName(tableName: string): string {
  const parts = tableName
    .split(".")
    .map((p) => p.trim().replace(/^\[|\]$/g, ""))
    .filter((p) => p.length > 0);
  if (parts.length === 0 || parts.length > 2) {
    throw new Error(`Invalid table name '${tableName}'. Use 'Table' or 'schema.Table'.`);
  }
  for (const part of parts) {
    if (!/^[A-Za-z_][A-Za-z0-9_ $#-]*$/.test(part)) {
      throw new Error(`Invalid identifier '${part}' in table name.`);
    }
  }
  return parts.map((p) => `[${p}]`).join(".");
}

async function handleTestConnection(args: TestConnectionArgs): Promise<string> {
  const { response_format = "markdown" } = args;
  const dbPool = await getPool();
  const result = await dbPool.request().query(`
    SELECT
      SERVERPROPERTY('MachineName') AS machine_name,
      SERVERPROPERTY('ServerName') AS server_name,
      SERVERPROPERTY('Edition') AS edition,
      CAST(SERVERPROPERTY('EngineEdition') AS int) AS engine_edition,
      CAST(SERVERPROPERTY('ProductMajorVersion') AS int) AS major,
      SERVERPROPERTY('ProductVersion') AS product_version,
      SERVERPROPERTY('ProductLevel') AS product_level,
      DB_NAME() AS current_database,
      SUSER_SNAME() AS login_name,
      SYSDATETIME() AS server_time
  `);
  const row = result.recordset[0];
  const editionClass = classifyEdition(row.engine_edition ?? 0, String(row.edition ?? ""));
  const versionName = VERSION_NAMES[row.major] ?? `SQL Server (major version ${row.major})`;
  const info = {
    ...row,
    version_name: versionName,
    edition_class: editionClass,
    edition_note: EDITION_NOTES[editionClass],
    server_mode: READ_ONLY ? "read-only" : "write",
    tools_supported: row.major >= MIN_SUPPORTED_MAJOR || editionClass.startsWith("Azure"),
  };

  if (response_format === "json") {
    return JSON.stringify({ connected: true, ...info }, null, 2);
  }
  return [
    "✅ **Connection successful**",
    "",
    `- Server: **${info.server_name}** (${info.machine_name})`,
    `- Version: **${versionName}** ${info.product_version} (${info.product_level})`,
    `- Edition: ${info.edition} → **${editionClass}**`,
    `- Database: **${info.current_database}**`,
    `- Login: ${info.login_name}`,
    `- Server time: ${info.server_time}`,
    `- Mode: **${info.server_mode}**`,
    "",
    `> ${EDITION_NOTES[editionClass]}`,
  ].join("\n");
}

async function handleListDatabases(args: ListDatabasesArgs): Promise<string> {
  const { response_format = "markdown" } = args;
  const dbPool = await getPool();
  const result = await dbPool.request().query(`
    SELECT
      name,
      database_id,
      state_desc,
      recovery_model_desc,
      compatibility_level,
      CONVERT(varchar(19), create_date, 120) AS create_date
    FROM sys.databases
    ORDER BY name
  `);
  if (response_format === "json") return JSON.stringify(result.recordset, null, 2);
  return toMarkdownTable(result.recordset, "_No databases visible to this login._");
}

async function handleListTables(args: ListTablesArgs): Promise<string> {
  const { schemaName, response_format = "markdown" } = args;
  const dbPool = await getPool();
  const request = dbPool.request();
  if (schemaName) request.input("schemaName", sql.VarChar, schemaName);

  const result = await request.query(`
    SELECT
      s.name AS schema_name,
      t.name AS table_name,
      SUM(CASE WHEN p.index_id IN (0, 1) THEN p.rows ELSE 0 END) AS row_count,
      CAST(SUM(a.total_pages) * 8.0 / 1024 AS DECIMAL(12, 2)) AS total_mb
    FROM sys.tables t
    INNER JOIN sys.schemas s ON t.schema_id = s.schema_id
    INNER JOIN sys.partitions p ON t.object_id = p.object_id
    INNER JOIN sys.allocation_units a ON p.partition_id = a.container_id
    ${schemaName ? "WHERE s.name = @schemaName" : ""}
    GROUP BY s.name, t.name
    ORDER BY s.name, t.name
  `);
  if (response_format === "json") return JSON.stringify(result.recordset, null, 2);
  return toMarkdownTable(result.recordset, "_No tables found._");
}

async function handleSampleData(args: SampleDataArgs): Promise<string> {
  const { tableName, response_format = "markdown" } = args;
  const top = coerceInt(args.rows, "rows", { min: 1, max: 100, fallback: 10 });
  const quoted = quoteTableName(tableName);

  const dbPool = await getPool();
  const result = await dbPool.request().query(`SELECT TOP (${top}) * FROM ${quoted}`);
  const data = result.recordset ?? [];

  if (response_format === "json") {
    return JSON.stringify({ table: tableName, rows: data.length, data }, null, 2);
  }
  return [`**Sample of ${quoted}** (${data.length} rows)`, "", toMarkdownTable(data)].join("\n");
}

async function handleGetRelationships(args: GetRelationshipsArgs): Promise<string> {
  const { tableName, response_format = "markdown" } = args;
  const dbPool = await getPool();
  const request = dbPool.request();
  if (tableName) request.input("tableName", sql.VarChar, tableName);

  const result = await request.query(`
    SELECT
      fk.name AS constraint_name,
      sch1.name + '.' + t1.name AS from_table,
      c1.name AS from_column,
      sch2.name + '.' + t2.name AS to_table,
      c2.name AS to_column,
      fk.delete_referential_action_desc AS on_delete,
      fk.update_referential_action_desc AS on_update
    FROM sys.foreign_keys fk
    INNER JOIN sys.foreign_key_columns fkc ON fk.object_id = fkc.constraint_object_id
    INNER JOIN sys.tables t1 ON fkc.parent_object_id = t1.object_id
    INNER JOIN sys.schemas sch1 ON t1.schema_id = sch1.schema_id
    INNER JOIN sys.columns c1 ON fkc.parent_object_id = c1.object_id AND fkc.parent_column_id = c1.column_id
    INNER JOIN sys.tables t2 ON fkc.referenced_object_id = t2.object_id
    INNER JOIN sys.schemas sch2 ON t2.schema_id = sch2.schema_id
    INNER JOIN sys.columns c2 ON fkc.referenced_object_id = c2.object_id AND fkc.referenced_column_id = c2.column_id
    ${tableName ? "WHERE t1.name = @tableName OR t2.name = @tableName" : ""}
    ORDER BY sch1.name, t1.name, fk.name
  `);
  if (response_format === "json") return JSON.stringify(result.recordset, null, 2);
  return toMarkdownTable(result.recordset, "_No foreign key relationships found._");
}

async function handleGetViews(args: GetViewsArgs): Promise<string> {
  const { viewName, response_format = "markdown" } = args;
  const dbPool = await getPool();
  const request = dbPool.request();
  if (viewName) request.input("viewName", sql.VarChar, viewName);

  const result = await request.query(`
    SELECT
      s.name AS schema_name,
      v.name AS view_name,
      CONVERT(varchar(19), v.create_date, 120) AS create_date,
      CONVERT(varchar(19), v.modify_date, 120) AS modify_date,
      m.definition
    FROM sys.views v
    INNER JOIN sys.schemas s ON v.schema_id = s.schema_id
    INNER JOIN sys.sql_modules m ON v.object_id = m.object_id
    ${viewName ? "WHERE v.name = @viewName" : ""}
    ORDER BY s.name, v.name
  `);
  if (response_format === "json") return JSON.stringify(result.recordset, null, 2);

  if (result.recordset.length === 0) return "_No views found._";
  const sections: string[] = [];
  for (const v of result.recordset) {
    sections.push(`### ${v.schema_name}.${v.view_name}`);
    sections.push(`- **Created**: ${v.create_date}  •  **Modified**: ${v.modify_date}`);
    sections.push("```sql");
    sections.push(v.definition ?? "-- definition not available");
    sections.push("```");
    sections.push("");
  }
  return sections.join("\n");
}

async function handleSearchDefinitions(args: SearchDefinitionsArgs): Promise<string> {
  const { searchText, response_format = "markdown" } = args;
  if (!searchText || !searchText.trim()) {
    throw new Error("searchText must not be empty.");
  }
  // Escape LIKE wildcards so the search is a literal substring match.
  const escaped = searchText.replace(/[\\%_\[\]]/g, (ch) => `\\${ch}`);

  const dbPool = await getPool();
  const result = await dbPool
    .request()
    .input("pattern", sql.NVarChar, `%${escaped}%`)
    .query(`
      SELECT
        s.name AS schema_name,
        o.name AS object_name,
        o.type_desc,
        CONVERT(varchar(19), o.modify_date, 120) AS modify_date
      FROM sys.sql_modules m
      INNER JOIN sys.objects o ON m.object_id = o.object_id
      INNER JOIN sys.schemas s ON o.schema_id = s.schema_id
      WHERE m.definition LIKE @pattern ESCAPE '\\'
      ORDER BY o.type_desc, s.name, o.name
    `);
  if (response_format === "json") {
    return JSON.stringify({ searchText, matches: result.recordset }, null, 2);
  }
  if (result.recordset.length === 0) return `_No objects contain '${searchText}'._`;
  return [
    `**${result.recordset.length} object(s) contain '${searchText}':**`,
    "",
    toMarkdownTable(result.recordset),
  ].join("\n");
}

async function handleAnalyzeIndexes(args: AnalyzeIndexesArgs): Promise<string> {
  const { tableName, response_format = "markdown" } = args;
  const dbPool = await getPool();

  const usageRequest = dbPool.request();
  if (tableName) usageRequest.input("tableName", sql.VarChar, tableName);

  const usageQuery = `
    SELECT
      s.name + '.' + t.name AS table_name,
      i.name AS index_name,
      i.type_desc,
      us.user_seeks,
      us.user_scans,
      us.user_lookups,
      us.user_updates,
      CONVERT(varchar(19), us.last_user_seek, 120) AS last_user_seek
    FROM sys.indexes i
    INNER JOIN sys.tables t ON i.object_id = t.object_id
    INNER JOIN sys.schemas s ON t.schema_id = s.schema_id
    LEFT JOIN sys.dm_db_index_usage_stats us
      ON us.object_id = i.object_id AND us.index_id = i.index_id AND us.database_id = DB_ID()
    WHERE i.type > 0
    ${tableName ? "AND t.name = @tableName" : ""}
    ORDER BY s.name, t.name, i.index_id
  `;

  const missingQuery = `
    SELECT TOP 25
      mid.statement AS table_name,
      CAST(migs.avg_user_impact AS DECIMAL(5,1)) AS avg_impact_pct,
      migs.user_seeks + migs.user_scans AS potential_uses,
      mid.equality_columns,
      mid.inequality_columns,
      mid.included_columns
    FROM sys.dm_db_missing_index_details mid
    INNER JOIN sys.dm_db_missing_index_groups mig ON mid.index_handle = mig.index_handle
    INNER JOIN sys.dm_db_missing_index_group_stats migs ON mig.index_group_handle = migs.group_handle
    WHERE mid.database_id = DB_ID()
    ORDER BY migs.avg_user_impact * (migs.user_seeks + migs.user_scans) DESC
  `;

  const [usageResult, missingResult] = await Promise.all([
    usageRequest.query(usageQuery),
    dbPool.request().query(missingQuery),
  ]);

  if (response_format === "json") {
    return JSON.stringify(
      { indexUsage: usageResult.recordset, missingIndexes: missingResult.recordset },
      null,
      2
    );
  }

  return [
    "## Index Usage",
    toMarkdownTable(usageResult.recordset, "_No indexes found._"),
    "",
    "## Potentially Missing Indexes (optimizer suggestions)",
    toMarkdownTable(missingResult.recordset, "_No missing index suggestions._"),
  ].join("\n");
}

async function handleAnalyzeStorage(args: AnalyzeStorageArgs): Promise<string> {
  const { response_format = "markdown" } = args;
  const top = coerceInt(args.topTables, "topTables", { min: 1, max: 200, fallback: 20 });
  const dbPool = await getPool();

  const tablesQuery = `
    SELECT TOP (@topTables)
      s.name + '.' + t.name AS table_name,
      SUM(CASE WHEN p.index_id IN (0, 1) THEN p.rows ELSE 0 END) AS row_count,
      CAST(SUM(a.total_pages) * 8.0 / 1024 AS DECIMAL(12, 2)) AS total_mb,
      CAST(SUM(a.used_pages) * 8.0 / 1024 AS DECIMAL(12, 2)) AS used_mb
    FROM sys.tables t
    INNER JOIN sys.schemas s ON t.schema_id = s.schema_id
    INNER JOIN sys.partitions p ON t.object_id = p.object_id
    INNER JOIN sys.allocation_units a ON p.partition_id = a.container_id
    GROUP BY s.name, t.name
    ORDER BY SUM(a.total_pages) DESC
  `;

  const filesQuery = `
    SELECT
      name AS logical_name,
      type_desc,
      CAST(size * 8.0 / 1024 AS DECIMAL(12, 2)) AS size_mb,
      physical_name
    FROM sys.database_files
  `;

  const [tablesResult, filesResult] = await Promise.all([
    dbPool.request().input("topTables", sql.Int, top).query(tablesQuery),
    dbPool.request().query(filesQuery),
  ]);

  if (response_format === "json") {
    return JSON.stringify(
      { largestTables: tablesResult.recordset, databaseFiles: filesResult.recordset },
      null,
      2
    );
  }

  return [
    `## Top ${top} Tables by Size`,
    toMarkdownTable(tablesResult.recordset, "_No tables found._"),
    "",
    "## Database Files",
    toMarkdownTable(filesResult.recordset, "_No file info available._"),
  ].join("\n");
}

// --- Blocking / deadlock analysis -------------------------------------------

// Version names for the compatibility note shown in blocking/deadlock output.
const VERSION_NAMES: Record<number, string> = {
  13: "SQL Server 2016",
  14: "SQL Server 2017",
  15: "SQL Server 2019",
  16: "SQL Server 2022",
  17: "SQL Server 2025",
};

// Lowest major version these tools are tested/supported on (2019 = 15.x).
const MIN_SUPPORTED_MAJOR = 15;

// Edition classification. EngineEdition values: 2=Standard, 3=Enterprise
// (Developer and Evaluation also report 3 — disambiguated via the Edition
// string), 4=Express, 5=Azure SQL Database, 8=Azure SQL Managed Instance.
type EditionClass =
  | "Express"
  | "Standard"
  | "Enterprise"
  | "Developer"
  | "Evaluation"
  | "Azure SQL Database"
  | "Azure SQL Managed Instance"
  | "Other";

// Per-edition capability notes shown by mssql_test_connection. All the
// DMV/XE-based tools in this server work on every boxed edition (Express,
// Standard, Enterprise, Developer, Evaluation) of SQL Server 2019/2022/2025;
// only Azure SQL Database has real differences.
const EDITION_NOTES: Record<EditionClass, string> = {
  Express:
    "Express edition: all tools supported. Engine limits: max 10 GB per database, ~1.4 GB buffer pool, up to 4 cores; no SQL Server Agent.",
  Standard:
    "Standard edition: all tools supported. Engine limits: 128 GB buffer pool, up to 24 cores (2019+).",
  Enterprise: "Enterprise edition: all tools supported, no engine limits.",
  Developer:
    "Developer edition: full Enterprise feature set (non-production licensing only). All tools supported.",
  Evaluation:
    "Evaluation edition: full Enterprise feature set (time-limited license). All tools supported.",
  "Azure SQL Database":
    "Azure SQL Database: core query/schema tools work, but server-level tools differ — mssql_get_deadlocks (system_health XE) is not available, and mssql_list_databases / mssql_monitor_usage show only the logical server's visible scope.",
  "Azure SQL Managed Instance":
    "Azure SQL Managed Instance: near-full compatibility with boxed editions; all tools expected to work.",
  Other: "Unrecognized edition: tools are expected to work but are untested on this edition.",
};

function classifyEdition(engineEdition: number, editionString: string): EditionClass {
  const s = editionString.toLowerCase();
  if (engineEdition === 5) return "Azure SQL Database";
  if (engineEdition === 8) return "Azure SQL Managed Instance";
  if (engineEdition === 4 || s.includes("express")) return "Express";
  if (engineEdition === 2 || s.includes("standard")) return "Standard";
  if (s.includes("developer")) return "Developer";
  if (s.includes("evaluation")) return "Evaluation";
  if (engineEdition === 3 || s.includes("enterprise")) return "Enterprise";
  return "Other";
}

interface ServerVersionInfo {
  major: number;
  versionName: string;
  productVersion: string;
  edition: string;
  editionClass: EditionClass;
  supported: boolean;
}

async function getServerVersionInfo(): Promise<ServerVersionInfo> {
  const dbPool = await getPool();
  const result = await dbPool.request().query(`
    SELECT
      CAST(SERVERPROPERTY('ProductMajorVersion') AS int) AS major,
      CAST(SERVERPROPERTY('ProductVersion') AS nvarchar(30)) AS product_version,
      CAST(SERVERPROPERTY('Edition') AS nvarchar(100)) AS edition,
      CAST(SERVERPROPERTY('EngineEdition') AS int) AS engine_edition
  `);
  const row = result.recordset[0] ?? {};
  const major: number = row.major ?? 0;
  const edition: string = row.edition ?? "unknown";
  return {
    major,
    versionName: VERSION_NAMES[major] ?? `SQL Server (major version ${major})`,
    productVersion: row.product_version ?? "unknown",
    edition,
    editionClass: classifyEdition(row.engine_edition ?? 0, edition),
    supported: major >= MIN_SUPPORTED_MAJOR,
  };
}

function compatibilityNote(v: ServerVersionInfo): string {
  const base = `${v.versionName} ${v.productVersion} — ${v.edition} [${v.editionClass}]`;
  return v.supported
    ? base
    : `${base} ⚠️ This tool is tested on SQL Server 2019/2022/2025; results on this older version are best-effort.`;
}

// Editions that support ALTER INDEX ... REBUILD WITH (ONLINE = ON).
function supportsOnlineRebuild(editionClass: EditionClass): boolean {
  return (
    editionClass === "Enterprise" ||
    editionClass === "Developer" ||
    editionClass === "Evaluation" ||
    editionClass === "Azure SQL Database" ||
    editionClass === "Azure SQL Managed Instance"
  );
}

async function handleIndexFragmentation(args: IndexFragmentationArgs): Promise<string> {
  const { tableName, response_format = "markdown" } = args;
  const minPages = coerceInt(args.minPageCount, "minPageCount", {
    min: 1,
    max: 1_000_000_000,
    fallback: 100,
  });
  const dbPool = await getPool();
  const version = await getServerVersionInfo();

  const request = dbPool.request().input("minPageCount", sql.Int, minPages);
  if (tableName) request.input("tableName", sql.VarChar, tableName);

  const result = await request.query(`
    SELECT
      s.name AS schema_name,
      t.name AS table_name,
      i.name AS index_name,
      i.type_desc,
      ps.partition_number,
      CAST(ps.avg_fragmentation_in_percent AS DECIMAL(5, 1)) AS fragmentation_pct,
      ps.page_count,
      CASE
        WHEN ps.avg_fragmentation_in_percent >= 30 THEN 'REBUILD'
        WHEN ps.avg_fragmentation_in_percent >= 5 THEN 'REORGANIZE'
        ELSE 'OK'
      END AS recommendation
    FROM sys.dm_db_index_physical_stats(DB_ID(), NULL, NULL, NULL, 'LIMITED') ps
    INNER JOIN sys.indexes i ON ps.object_id = i.object_id AND ps.index_id = i.index_id
    INNER JOIN sys.tables t ON ps.object_id = t.object_id
    INNER JOIN sys.schemas s ON t.schema_id = s.schema_id
    WHERE ps.index_id > 0
      AND ps.alloc_unit_type_desc = 'IN_ROW_DATA'
      AND ps.page_count >= @minPageCount
      ${tableName ? "AND t.name = @tableName" : ""}
    ORDER BY ps.avg_fragmentation_in_percent DESC
  `);

  const rows = result.recordset;
  const online = supportsOnlineRebuild(version.editionClass);
  const statements = rows
    .filter((r) => r.recommendation !== "OK")
    .map((r) =>
      r.recommendation === "REBUILD"
        ? `ALTER INDEX [${r.index_name}] ON [${r.schema_name}].[${r.table_name}] REBUILD${online ? " WITH (ONLINE = ON)" : ""};`
        : `ALTER INDEX [${r.index_name}] ON [${r.schema_name}].[${r.table_name}] REORGANIZE;`
    );

  if (response_format === "json") {
    return JSON.stringify(
      { server: compatibilityNote(version), onlineRebuildSupported: online, indexes: rows, maintenanceStatements: statements },
      null,
      2
    );
  }

  const lines: string[] = [`_Server: ${compatibilityNote(version)}_`, ""];
  if (rows.length === 0) {
    lines.push(`✅ **No indexes with ≥ ${minPages} pages found${tableName ? ` on table '${tableName}'` : ""}.**`);
    return lines.join("\n");
  }

  const needsAction = rows.filter((r) => r.recommendation !== "OK").length;
  lines.push(`## Index Fragmentation (${rows.length} indexes, ${needsAction} need maintenance)`);
  lines.push("");
  lines.push(
    toMarkdownTable(
      rows.map((r) => ({
        table: `${r.schema_name}.${r.table_name}`,
        index: r.index_name,
        type: r.type_desc,
        "frag %": r.fragmentation_pct,
        pages: r.page_count,
        recommendation: r.recommendation === "OK" ? "✅ OK" : r.recommendation === "REBUILD" ? "🔴 REBUILD" : "🟡 REORGANIZE",
      }))
    )
  );

  if (statements.length > 0) {
    lines.push("");
    lines.push("### Suggested maintenance statements");
    if (!online) {
      lines.push("");
      lines.push(`_ONLINE = ON is not available on ${version.editionClass} edition — REBUILD will lock the table; run during a maintenance window._`);
    }
    lines.push("");
    lines.push("```sql");
    lines.push(statements.join("\n"));
    lines.push("```");
    lines.push("");
    lines.push("_Thresholds: ≥ 30% → REBUILD, 5–30% → REORGANIZE, < 5% → leave alone. This server does not execute these statements._");
  }
  return lines.join("\n");
}

// A Map (not a plain object) so a metric name like "constructor" or
// "__proto__" can't resolve to an inherited Object.prototype value instead of
// failing the lookup below.
const TOP_QUERY_METRICS: Map<string, { column: string; label: string }> = new Map([
  ["cpu", { column: "qs.total_worker_time", label: "total CPU" }],
  ["duration", { column: "qs.total_elapsed_time", label: "total duration" }],
  ["reads", { column: "qs.total_logical_reads", label: "total logical reads" }],
  ["writes", { column: "qs.total_logical_writes", label: "total logical writes" }],
  ["memory", { column: "qs.total_grant_kb", label: "total memory grant" }],
  ["executions", { column: "qs.execution_count", label: "execution count" }],
]);

async function handleTopQueries(args: TopQueriesArgs): Promise<string> {
  const { metric = "cpu", response_format = "markdown" } = args;
  const metricDef = TOP_QUERY_METRICS.get(metric);
  if (!metricDef) {
    throw new Error(`Unknown metric '${metric}'. Use one of: ${Array.from(TOP_QUERY_METRICS.keys()).join(", ")}.`);
  }
  const limit = coerceInt(args.top, "top", { min: 1, max: 50, fallback: 10 });
  const dbPool = await getPool();

  const result = await dbPool.request().input("top", sql.Int, limit).query(`
    SELECT TOP (@top)
      DB_NAME(t.dbid) AS database_name,
      qs.execution_count,
      qs.total_worker_time / 1000 AS total_cpu_ms,
      qs.total_worker_time / NULLIF(qs.execution_count, 0) / 1000 AS avg_cpu_ms,
      qs.total_elapsed_time / 1000 AS total_elapsed_ms,
      qs.total_elapsed_time / NULLIF(qs.execution_count, 0) / 1000 AS avg_elapsed_ms,
      qs.total_logical_reads,
      qs.total_logical_reads / NULLIF(qs.execution_count, 0) AS avg_logical_reads,
      qs.total_logical_writes,
      qs.total_grant_kb / 1024 AS total_grant_mb,
      qs.max_grant_kb / 1024 AS max_grant_mb,
      CONVERT(varchar(19), qs.last_execution_time, 120) AS last_execution,
      SUBSTRING(t.text, (qs.statement_start_offset / 2) + 1,
        ((CASE qs.statement_end_offset WHEN -1 THEN DATALENGTH(t.text)
          ELSE qs.statement_end_offset END - qs.statement_start_offset) / 2) + 1) AS query_text
    FROM sys.dm_exec_query_stats qs
    CROSS APPLY sys.dm_exec_sql_text(qs.sql_handle) t
    ORDER BY ${metricDef.column} DESC
  `);

  if (response_format === "json") {
    return JSON.stringify({ metric, rankedBy: metricDef.label, queries: result.recordset }, null, 2);
  }

  if (result.recordset.length === 0) return "_No query statistics in the plan cache._";
  const lines = [`## Top ${result.recordset.length} queries by ${metricDef.label}`, ""];
  lines.push(
    toMarkdownTable(
      result.recordset.map((q) => ({
        db: q.database_name ?? "",
        execs: q.execution_count,
        "avg cpu ms": q.avg_cpu_ms,
        "avg elapsed ms": q.avg_elapsed_ms,
        "avg reads": q.avg_logical_reads,
        "grant MB": q.max_grant_mb ?? 0,
        last_run: q.last_execution,
        query: String(q.query_text ?? "").replace(/\s+/g, " ").slice(0, 90),
      }))
    )
  );
  lines.push("");
  lines.push("_Stats come from the plan cache (sys.dm_exec_query_stats) and reset when plans are evicted or the server restarts._");
  return lines.join("\n");
}

// Wait types that are normal background noise and never actionable.
const BENIGN_WAITS = [
  "BROKER_EVENTHANDLER", "BROKER_RECEIVE_WAITFOR", "BROKER_TASK_STOP", "BROKER_TO_FLUSH",
  "CHECKPOINT_QUEUE", "CLR_AUTO_EVENT", "CLR_MANUAL_EVENT", "DIRTY_PAGE_POLL",
  "DISPATCHER_QUEUE_SEMAPHORE", "FT_IFTS_SCHEDULER_IDLE_WAIT", "HADR_CLUSAPI_CALL",
  "HADR_FILESTREAM_IOMGR_IOCOMPLETION", "HADR_LOGCAPTURE_WAIT", "HADR_NOTIFICATION_DEQUEUE",
  "HADR_TIMER_TASK", "HADR_WORK_QUEUE", "LAZYWRITER_SLEEP", "LOGMGR_QUEUE",
  "ONDEMAND_TASK_QUEUE", "PARALLEL_REDO_DRAIN_WORKER", "PARALLEL_REDO_WORKER_WAIT_WORK",
  "QDS_CLEANUP_STALE_QUERIES_TASK_MAIN_LOOP_SLEEP", "QDS_PERSIST_TASK_MAIN_LOOP_SLEEP",
  "REQUEST_FOR_DEADLOCK_SEARCH", "SLEEP_SYSTEMTASK", "SLEEP_TASK", "SOS_WORK_DISPATCHER",
  "SP_SERVER_DIAGNOSTICS_SLEEP", "SQLTRACE_BUFFER_FLUSH", "SQLTRACE_INCREMENTAL_FLUSH_SLEEP",
  "TRACEWRITE", "WAIT_XTP_HOST_WAIT", "WAITFOR", "XE_DISPATCHER_WAIT", "XE_TIMER_EVENT",
];

// Rule-based interpretation of dominant wait types.
const WAIT_ADVICE: Array<{ match: RegExp; advice: string }> = [
  { match: /^CXPACKET|^CXCONSUMER/, advice: "Parallelism waits — review MAXDOP and 'cost threshold for parallelism'; look for large scans that need indexes (mssql_analyze_indexes)." },
  { match: /^PAGEIOLATCH_/, advice: "Data-file I/O waits — storage is slow or queries read too much; check mssql_top_queries (metric: reads) and missing indexes." },
  { match: /^WRITELOG$/, advice: "Transaction-log write latency — check log-disk speed and look for many tiny transactions." },
  { match: /^LCK_M_/, advice: "Lock waits — blocking is occurring; run mssql_find_blocking to identify the lead blocker." },
  { match: /^SOS_SCHEDULER_YIELD$/, advice: "CPU pressure — check mssql_top_queries (metric: cpu) and consider plan/index tuning before adding cores." },
  { match: /^RESOURCE_SEMAPHORE/, advice: "Memory-grant pressure — large sorts/hashes are queuing; tune queries with big grants (mssql_top_queries metric: memory)." },
  { match: /^ASYNC_NETWORK_IO$/, advice: "Client is consuming results slowly — application-side issue (row-by-row processing, slow network), not the database." },
  { match: /^PAGELATCH_/, advice: "In-memory page contention — often tempdb; consider multiple equally-sized tempdb data files." },
];

async function handlePerformanceHealth(args: PerformanceHealthArgs): Promise<string> {
  const { response_format = "markdown" } = args;
  const dbPool = await getPool();
  const version = await getServerVersionInfo();

  const waitList = BENIGN_WAITS.map((w) => `'${w}'`).join(",");
  const waitsQuery = `
    SELECT TOP 15
      wait_type,
      waiting_tasks_count,
      wait_time_ms / 1000 AS wait_time_s,
      signal_wait_time_ms / 1000 AS signal_wait_s,
      CAST(100.0 * wait_time_ms / NULLIF(SUM(wait_time_ms) OVER (), 0) AS DECIMAL(5, 1)) AS pct_of_total
    FROM sys.dm_os_wait_stats
    WHERE wait_type NOT IN (${waitList})
      AND wait_type NOT LIKE 'SLEEP%'
      AND wait_time_ms > 0
    ORDER BY wait_time_ms DESC
  `;

  const countersQuery = `
    SELECT RTRIM(counter_name) AS counter_name, RTRIM(instance_name) AS instance_name, cntr_value
    FROM sys.dm_os_performance_counters
    WHERE (object_name LIKE '%Buffer Manager%' AND counter_name IN ('Page life expectancy', 'Lazy writes/sec', 'Page reads/sec'))
       OR (object_name LIKE '%Memory Manager%' AND counter_name IN ('Total Server Memory (KB)', 'Target Server Memory (KB)', 'Memory Grants Pending'))
       OR (object_name LIKE '%SQL Statistics%' AND counter_name IN ('Batch Requests/sec', 'SQL Compilations/sec', 'SQL Re-Compilations/sec'))
  `;

  const [waitsResult, countersResult] = await Promise.all([
    dbPool.request().query(waitsQuery),
    dbPool.request().query(countersQuery),
  ]);

  const waits = waitsResult.recordset;
  const counters = countersResult.recordset;
  const counter = (name: string): number | null =>
    counters.find((c) => c.counter_name === name)?.cntr_value ?? null;

  // Rule-based recommendations.
  const recommendations: string[] = [];
  for (const w of waits.slice(0, 5)) {
    if (w.pct_of_total < 5) continue;
    const rule = WAIT_ADVICE.find((r) => r.match.test(w.wait_type));
    if (rule) recommendations.push(`**${w.wait_type}** (${w.pct_of_total}% of waits): ${rule.advice}`);
  }
  const ple = counter("Page life expectancy");
  if (ple !== null && ple < 300) {
    recommendations.push(
      `**Page life expectancy is low (${ple}s)**: buffer pool is under memory pressure — add memory, reduce large scans, or check for queries reading far more than needed.`
    );
  }
  const grantsPending = counter("Memory Grants Pending");
  if (grantsPending !== null && grantsPending > 0) {
    recommendations.push(
      `**${grantsPending} memory grant(s) pending**: queries are waiting for workspace memory right now — investigate large sorts/hashes (mssql_top_queries metric: memory).`
    );
  }
  const totalMem = counter("Total Server Memory (KB)");
  const targetMem = counter("Target Server Memory (KB)");
  if (totalMem !== null && targetMem !== null && totalMem < targetMem * 0.9) {
    recommendations.push(
      `**Total server memory (${Math.round(totalMem / 1024)} MB) is below target (${Math.round(targetMem / 1024)} MB)**: the instance is still ramping up, or the OS is under external memory pressure.`
    );
  }
  if (recommendations.length === 0) {
    recommendations.push("No obvious pressure points detected from wait stats and memory counters.");
  }

  if (response_format === "json") {
    return JSON.stringify(
      { server: compatibilityNote(version), topWaits: waits, counters, recommendations: recommendations.map((r) => r.replace(/\*\*/g, "")) },
      null,
      2
    );
  }

  const lines: string[] = [
    `_Server: ${compatibilityNote(version)}_`,
    "",
    "## 🩺 Performance Health Check",
    "",
    "### Top waits (cumulative since restart, benign waits filtered)",
    toMarkdownTable(waits, "_No significant waits recorded._"),
    "",
    "### Memory & workload counters",
    toMarkdownTable(
      counters.map((c) => ({ counter: c.counter_name, instance: c.instance_name || "-", value: c.cntr_value })),
      "_No counters available._"
    ),
    "",
    "### 💡 Recommendations",
    ...recommendations.map((r) => `- ${r}`),
    "",
    "_Wait stats are cumulative since the last restart (or manual clear) — a busy server always shows waits; focus on the distribution, not absolute numbers._",
  ];
  return lines.join("\n");
}

async function handleFindBlocking(args: FindBlockingArgs): Promise<string> {
  const { response_format = "markdown" } = args;
  const dbPool = await getPool();
  const version = await getServerVersionInfo();

  // Sessions currently blocked by someone.
  const blockedQuery = `
    SELECT
      r.session_id,
      r.blocking_session_id,
      s.login_name,
      s.host_name,
      s.program_name,
      DB_NAME(r.database_id) AS database_name,
      r.command,
      r.status,
      r.wait_type,
      r.wait_time AS wait_ms,
      r.wait_resource,
      s.open_transaction_count,
      SUBSTRING(t.text, (r.statement_start_offset / 2) + 1,
        ((CASE r.statement_end_offset WHEN -1 THEN DATALENGTH(t.text)
          ELSE r.statement_end_offset END - r.statement_start_offset) / 2) + 1) AS current_statement
    FROM sys.dm_exec_requests r
    INNER JOIN sys.dm_exec_sessions s ON r.session_id = s.session_id
    OUTER APPLY sys.dm_exec_sql_text(r.sql_handle) t
    WHERE r.blocking_session_id <> 0
    ORDER BY r.wait_time DESC
  `;

  // Lead blockers: sessions that block others but are not blocked themselves.
  // These are often IDLE sessions holding an open transaction, so they must be
  // fetched from dm_exec_sessions (not dm_exec_requests) with their most
  // recent SQL text.
  const leadBlockersQuery = `
    SELECT
      s.session_id,
      s.login_name,
      s.host_name,
      s.program_name,
      s.status,
      s.open_transaction_count,
      CONVERT(varchar(19), s.last_request_end_time, 120) AS last_request_end_time,
      t.text AS last_sql
    FROM sys.dm_exec_sessions s
    LEFT JOIN sys.dm_exec_connections c ON s.session_id = c.session_id
    OUTER APPLY sys.dm_exec_sql_text(c.most_recent_sql_handle) t
    WHERE s.session_id IN (
        SELECT blocking_session_id FROM sys.dm_exec_requests WHERE blocking_session_id <> 0
      )
      AND s.session_id NOT IN (
        SELECT session_id FROM sys.dm_exec_requests WHERE blocking_session_id <> 0
      )
  `;

  const [blockedResult, leadResult] = await Promise.all([
    dbPool.request().query(blockedQuery),
    dbPool.request().query(leadBlockersQuery),
  ]);

  const blocked = blockedResult.recordset;
  const leadBlockers = leadResult.recordset;

  // Build blocking chains (victim ← ... ← lead blocker) in JS.
  const blockerOf = new Map<number, number>();
  for (const b of blocked) blockerOf.set(b.session_id, b.blocking_session_id);
  const chains = blocked.map((b) => {
    const chain: number[] = [b.session_id];
    let current = b.blocking_session_id;
    while (current && !chain.includes(current)) {
      chain.push(current);
      current = blockerOf.get(current) ?? 0;
    }
    return chain;
  });

  if (response_format === "json") {
    return JSON.stringify(
      {
        server: compatibilityNote(version),
        blockedCount: blocked.length,
        chains: chains.map((c) => c.join(" <- ")),
        blockedSessions: blocked,
        leadBlockers,
      },
      null,
      2
    );
  }

  const lines: string[] = [`_Server: ${compatibilityNote(version)}_`, ""];

  if (blocked.length === 0) {
    lines.push("✅ **No blocking detected right now.**");
    return lines.join("\n");
  }

  lines.push(`## 🚫 Blocking detected: ${blocked.length} blocked session(s)`);
  lines.push("");
  lines.push("**Blocking chains** (blocked ← blocker):");
  for (const c of chains) lines.push(`- ${c.join(" ← ")}`);

  lines.push("");
  lines.push("### Blocked sessions");
  lines.push(
    toMarkdownTable(
      blocked.map((b) => ({
        session: b.session_id,
        blocked_by: b.blocking_session_id,
        login: b.login_name,
        db: b.database_name,
        wait_type: b.wait_type,
        wait_ms: b.wait_ms,
        wait_resource: b.wait_resource,
        statement: String(b.current_statement ?? "").replace(/\s+/g, " ").slice(0, 100),
      }))
    )
  );

  lines.push("");
  lines.push("### Lead blockers (root cause)");
  if (leadBlockers.length === 0) {
    lines.push("_All blockers are themselves blocked (possible chain into a lock cycle)._ ");
  } else {
    lines.push(
      toMarkdownTable(
        leadBlockers.map((l) => ({
          session: l.session_id,
          login: l.login_name,
          host: l.host_name,
          program: String(l.program_name ?? "").slice(0, 40),
          status: l.status,
          open_trans: l.open_transaction_count,
          last_request_end: l.last_request_end_time,
          last_sql: String(l.last_sql ?? "").replace(/\s+/g, " ").slice(0, 100),
        }))
      )
    );
    lines.push("");
    lines.push(
      "_A lead blocker with status 'sleeping' and open_trans > 0 is an application holding an uncommitted transaction._"
    );
  }

  return lines.join("\n");
}

// Extract a readable summary from a deadlock graph XML using light regex
// parsing (no XML parser dependency). Best-effort: the full XML is always
// returned alongside.
function summarizeDeadlockXml(xml: string): {
  victims: string[];
  processes: Array<{ id: string; spid: string; loginName: string; inputBuffer: string }>;
} {
  const victims: string[] = [];
  const victimRe = /<victimProcess\s+id="([^"]+)"/g;
  let vm: RegExpExecArray | null;
  while ((vm = victimRe.exec(xml)) !== null) victims.push(vm[1]);

  const processes: Array<{ id: string; spid: string; loginName: string; inputBuffer: string }> = [];
  const processRe = /<process\s+id="([^"]+)"([^>]*)>([\s\S]*?)<\/process>/g;
  let pm: RegExpExecArray | null;
  while ((pm = processRe.exec(xml)) !== null) {
    const attrs = pm[2];
    const body = pm[3];
    const spid = /spid="(\d+)"/.exec(attrs)?.[1] ?? "?";
    const loginName = /loginname="([^"]*)"/i.exec(attrs)?.[1] ?? "?";
    const inputBufRaw = /<inputbuf>([\s\S]*?)<\/inputbuf>/.exec(body)?.[1] ?? "";
    const inputBuffer = inputBufRaw
      .replace(/&lt;/g, "<")
      .replace(/&gt;/g, ">")
      .replace(/&quot;/g, '"')
      .replace(/&amp;/g, "&")
      .replace(/\s+/g, " ")
      .trim();
    processes.push({ id: pm[1], spid, loginName, inputBuffer });
  }
  return { victims, processes };
}

async function handleGetDeadlocks(args: GetDeadlocksArgs): Promise<string> {
  const { source = "ring_buffer", response_format = "markdown" } = args;
  const max = coerceInt(args.maxEvents, "maxEvents", { min: 1, max: 25, fallback: 5 });
  const dbPool = await getPool();
  const version = await getServerVersionInfo();

  // The system_health XE session (and fn_xe_file_target_read_file on its
  // files) is not exposed on Azure SQL Database.
  if (version.editionClass === "Azure SQL Database") {
    const msg =
      "mssql_get_deadlocks relies on the system_health Extended Events session, which is not available on Azure SQL Database. " +
      "Use the Azure portal's Intelligent Insights / Query Store, or create a database-scoped Extended Events session capturing 'sqlserver.xml_deadlock_report'.";
    return response_format === "json"
      ? JSON.stringify({ server: compatibilityNote(version), supported: false, message: msg }, null, 2)
      : `⚠️ ${msg}\n\n_Server: ${compatibilityNote(version)}_`;
  }

  const ringBufferQuery = `
    SELECT TOP (@maxEvents)
      xed.value('@timestamp', 'datetime2') AS deadlock_time_utc,
      CONVERT(nvarchar(max), xed.query('.')) AS deadlock_xml
    FROM (
      SELECT CAST(st.target_data AS xml) AS target_data
      FROM sys.dm_xe_session_targets st
      INNER JOIN sys.dm_xe_sessions s ON s.address = st.event_session_address
      WHERE s.name = 'system_health' AND st.target_name = 'ring_buffer'
    ) t
    CROSS APPLY t.target_data.nodes('RingBufferTarget/event[@name="xml_deadlock_report"]') AS x(xed)
    ORDER BY deadlock_time_utc DESC
  `;

  const fileQuery = `
    SELECT TOP (@maxEvents)
      CAST(f.event_data AS xml).value('(event/@timestamp)[1]', 'datetime2') AS deadlock_time_utc,
      CONVERT(nvarchar(max),
        CAST(f.event_data AS xml).query('(event/data[@name="xml_report"]/value/deadlock)[1]')) AS deadlock_xml
    FROM sys.fn_xe_file_target_read_file('system_health*.xel', NULL, NULL, NULL) f
    WHERE f.object_name = 'xml_deadlock_report'
    ORDER BY deadlock_time_utc DESC
  `;

  const result = await dbPool
    .request()
    .input("maxEvents", sql.Int, max)
    .query(source === "file" ? fileQuery : ringBufferQuery);

  const events = result.recordset.map((row) => {
    const xml: string = row.deadlock_xml ?? "";
    const summary = summarizeDeadlockXml(xml);
    return { deadlock_time_utc: row.deadlock_time_utc, ...summary, deadlock_xml: xml };
  });

  if (response_format === "json") {
    return JSON.stringify(
      { server: compatibilityNote(version), source, eventCount: events.length, events },
      null,
      2
    );
  }

  const lines: string[] = [`_Server: ${compatibilityNote(version)} • Source: ${source}_`, ""];

  if (events.length === 0) {
    lines.push(
      `✅ **No deadlock events found in the ${source === "file" ? "system_health event files" : "system_health ring buffer"}.**`
    );
    if (source !== "file") {
      lines.push("");
      lines.push(
        "_The ring buffer only keeps recent events. Try `source: \"file\"` to search further back._"
      );
    }
    return lines.join("\n");
  }

  lines.push(`## 💀 ${events.length} deadlock event(s) (most recent first)`);
  events.forEach((e, i) => {
    lines.push("");
    lines.push(`### ${i + 1}. Deadlock at ${e.deadlock_time_utc} (UTC)`);
    lines.push(`- **Victim process(es)**: ${e.victims.length > 0 ? e.victims.join(", ") : "unknown"}`);
    lines.push("- **Processes involved:**");
    for (const p of e.processes) {
      const isVictim = e.victims.includes(p.id) ? " ⚠️ VICTIM" : "";
      lines.push(`  - spid ${p.spid} (${p.loginName})${isVictim}: \`${p.inputBuffer.slice(0, 150) || "(no input buffer)"}\``);
    }
    lines.push("");
    lines.push("<details><summary>Deadlock graph XML</summary>");
    lines.push("");
    lines.push("```xml");
    lines.push(e.deadlock_xml.length > 8000 ? e.deadlock_xml.slice(0, 8000) + "\n<!-- truncated -->" : e.deadlock_xml);
    lines.push("```");
    lines.push("</details>");
  });

  return lines.join("\n");
}

// Read the real version out of package.json so the version advertised over MCP
// can't drift from the published one (it sat at 2.0.0 through the 2.0.1
// release). Falls back rather than failing startup if the file isn't reachable.
function packageVersion(): string {
  for (const candidate of [
    path.join(__dirname, "..", "package.json"),
    path.join(__dirname, "package.json"),
  ]) {
    try {
      const parsed = JSON.parse(fs.readFileSync(candidate, "utf8")) as { version?: unknown };
      if (typeof parsed.version === "string" && parsed.version) return parsed.version;
    } catch {
      // try the next candidate
    }
  }
  return "0.0.0-unknown";
}

// Main server setup
async function main() {
  const server = new Server(
    {
      name: "mssql-mcp-server",
      version: packageVersion(),
    },
    {
      capabilities: {
        tools: {},
      },
    }
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: TOOLS,
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const toolName = request.params.name;
    const startedAt = Date.now();
    let failed = false;
    try {
      const { name, arguments: args } = request.params;

      switch (name) {
        case "mssql_query":
          return {
            content: [{ type: "text", text: await handleMssqlQuery(args as unknown as QueryArgs) }],
          };

        case "mssql_get_schema":
          return {
            content: [{ type: "text", text: await handleMssqlGetSchema(args as unknown as SchemaArgs) }],
          };

        case "mssql_get_stored_procedures":
          return {
            content: [{ type: "text", text: await handleMssqlGetStoredProcedures(args as unknown as StoredProcedureArgs) }],
          };

        case "mssql_monitor_locks":
          return {
            content: [{ type: "text", text: await handleMssqlMonitorLocks(args as unknown as MonitorLocksArgs) }],
          };

        case "mssql_monitor_usage":
          return {
            content: [{ type: "text", text: await handleMssqlMonitorUsage(args as unknown as MonitorUsageArgs) }],
          };

        case "mssql_test_connection":
          return {
            content: [{ type: "text", text: await handleTestConnection(args as unknown as TestConnectionArgs) }],
          };

        case "mssql_list_databases":
          return {
            content: [{ type: "text", text: await handleListDatabases(args as unknown as ListDatabasesArgs) }],
          };

        case "mssql_list_tables":
          return {
            content: [{ type: "text", text: await handleListTables(args as unknown as ListTablesArgs) }],
          };

        case "mssql_sample_data":
          return {
            content: [{ type: "text", text: await handleSampleData(args as unknown as SampleDataArgs) }],
          };

        case "mssql_get_relationships":
          return {
            content: [{ type: "text", text: await handleGetRelationships(args as unknown as GetRelationshipsArgs) }],
          };

        case "mssql_get_views":
          return {
            content: [{ type: "text", text: await handleGetViews(args as unknown as GetViewsArgs) }],
          };

        case "mssql_search_definitions":
          return {
            content: [{ type: "text", text: await handleSearchDefinitions(args as unknown as SearchDefinitionsArgs) }],
          };

        case "mssql_analyze_indexes":
          return {
            content: [{ type: "text", text: await handleAnalyzeIndexes(args as unknown as AnalyzeIndexesArgs) }],
          };

        case "mssql_analyze_storage":
          return {
            content: [{ type: "text", text: await handleAnalyzeStorage(args as unknown as AnalyzeStorageArgs) }],
          };

        case "mssql_index_fragmentation":
          return {
            content: [{ type: "text", text: await handleIndexFragmentation(args as unknown as IndexFragmentationArgs) }],
          };

        case "mssql_top_queries":
          return {
            content: [{ type: "text", text: await handleTopQueries(args as unknown as TopQueriesArgs) }],
          };

        case "mssql_performance_health":
          return {
            content: [{ type: "text", text: await handlePerformanceHealth(args as unknown as PerformanceHealthArgs) }],
          };

        case "mssql_find_blocking":
          return {
            content: [{ type: "text", text: await handleFindBlocking(args as unknown as FindBlockingArgs) }],
          };

        case "mssql_get_deadlocks":
          return {
            content: [{ type: "text", text: await handleGetDeadlocks(args as unknown as GetDeadlocksArgs) }],
          };

        default:
          throw new Error(`Unknown tool: ${name}`);
      }
    } catch (error) {
      failed = true;
      // Full detail (stack, driver metadata) goes to the operator's log only;
      // the caller gets the sanitized form. See describeError().
      auditLog({
        event: "call",
        tool: toolName,
        outcome: "error",
        durationMs: Date.now() - startedAt,
        error: error instanceof Error ? `${error.name}: ${error.message}` : String(error),
      });
      if (!AUDIT_LOG) {
        console.error(`[mssql-mcp] ${toolName} failed:`, error);
      }
      return {
        content: [{ type: "text", text: `Error: ${describeError(error)}` }],
        isError: true,
      };
    } finally {
      // Runs after the successful `return` inside the switch above, so every
      // invocation leaves exactly one outcome line in the audit trail.
      if (!failed) {
        auditLog({
          event: "call",
          tool: toolName,
          outcome: "ok",
          durationMs: Date.now() - startedAt,
        });
      }
    }
  });

  const transport = new StdioServerTransport();
  await server.connect(transport);

  console.error(
    `MS SQL Server MCP Server running on stdio (mode: ${READ_ONLY ? "READ-ONLY" : "WRITE"}, server: ${config.server}, database: ${config.database || "(default)"})`
  );
}

// Cleanup on exit
process.on("SIGINT", async () => {
  if (pool) await pool.close();
  process.exit(0);
});

process.on("SIGTERM", async () => {
  if (pool) await pool.close();
  process.exit(0);
});

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
