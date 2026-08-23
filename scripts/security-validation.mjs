// Dynamic security validation for mssql-mcp-server.
// Loads the REAL analyzer functions out of the compiled build/index.js
// (imports stripped, main() never invoked) and fires an attack battery at them.
import { readFileSync } from "fs";

let code = readFileSync(new URL("../build/index.js", import.meta.url), "utf8");

// Cut everything from "Main server setup" onward (main(), transport, process handlers).
const cut = code.indexOf("// Main server setup");
if (cut < 0) throw new Error("marker not found — build layout changed?");
code = code.slice(0, cut);

// Strip shebang; compiled output is CJS — stub `require` instead of stripping imports.
code = code.replace(/^#!.*$/gm, "");
import { createRequire } from "module";
const realRequire = createRequire(import.meta.url);
const dummy = new Proxy(function () {}, {
  get: (_t, p) => (p === "default" ? dummy : dummy),
  apply: () => dummy,
  construct: () => ({}),
});
// A fake `mssql` module so the streaming pager (section H) can be exercised
// without a live SQL Server. `fakeDb.rows` is the result set the fake driver
// replays; `fakeDb.emitted` counts how many rows it actually got to send,
// which is what proves the pager cancels instead of draining the whole set.
import { EventEmitter } from "events";

const fakeDb = { rows: [], emitted: 0 };

class FakeRequest extends EventEmitter {
  constructor() {
    super();
    this.stream = false;
    this.canceled = false;
  }
  input() { return this; }
  cancel() { this.canceled = true; }
  async query() {
    await new Promise((r) => setImmediate(r));
    const first = fakeDb.rows[0];
    this.emit("recordset", Object.fromEntries(Object.keys(first ?? {}).map((c) => [c, {}])));
    for (const row of fakeDb.rows) {
      if (this.canceled) break;
      fakeDb.emitted += 1;
      this.emit("row", row);
      // Yield between rows so a cancel() issued from the row handler is
      // observed, exactly as a real socket-driven stream would behave.
      await new Promise((r) => setImmediate(r));
    }
    return { recordsets: [], recordset: [], output: {}, rowsAffected: [] };
  }
}

// The real sql.ConnectionPool is an EventEmitter — getPool() subscribes to its
// 'error' event so a dropped connection cannot crash the process — so the fake
// has to be one too.
class FakeConnectionPool extends EventEmitter {
  constructor() {
    super();
    this.connected = false;
    this.connecting = false;
  }
  async connect() {
    this.connected = true;
    return this;
  }
  request() { return new FakeRequest(); }
  async close() { this.connected = false; }
}

// `__esModule` and `then` must read as absent: the compiled output runs the
// module through __importDefault (which checks __esModule), and a truthy
// `then` would make the module look like a thenable and hang the await.
const fakeMssql = new Proxy(
  {
    ConnectionPool: FakeConnectionPool,
    connect: async () => ({ request: () => new FakeRequest(), close: async () => {} }),
  },
  {
    get: (t, p) => (p in t ? t[p] : p === "__esModule" || p === "then" ? undefined : dummy),
  }
);

const require = (name) =>
  name === "fs" || name === "path"
    ? realRequire(name)
    : name === "mssql"
    ? fakeMssql
    : dummy;

// Eval the analyzer code and export the functions under test.
const factory = new Function(
  "require", "exports",
  `"use strict";
   const __dirname = "/tmp";
   ${code}
   return { classifyQuery, findDangerousStatement, writesToPersistentTable, quoteTableName,
            coerceInt, describeError, handleMssqlQuery, READ_ONLY };`
);
const api = factory(require, {});

let pass = 0, fail = 0;
const failures = [];
function check(label, actual, expected) {
  const ok = actual === expected;
  if (ok) pass++;
  else { fail++; failures.push({ label, expected, actual }); }
  console.log(`${ok ? "PASS" : "FAIL"}  [expected ${expected}]  ${label}${ok ? "" : `  -> got ${actual}`}`);
}

// classifyQuery returns "read" | "exec" | "rejected:<reason>"
function classify(q) {
  const c = api.classifyQuery(q);
  return c.kind === "rejected" ? `rejected` : c.kind;
}

console.log("=== A. Read-only allow-list: legitimate queries must be ACCEPTED ===");
check("plain SELECT", classify("SELECT * FROM Users"), "read");
check("SELECT with literal containing --", classify("SELECT * FROM Users WHERE note = 'a--b'"), "read");
check("CTE", classify("WITH x AS (SELECT 1 AS a) SELECT * FROM x"), "read");
check("SELECT INTO #temp", classify("SELECT * INTO #tmp FROM Users"), "read");
check("DECLARE @table batch", classify("DECLARE @t TABLE (id int); INSERT INTO @t SELECT id FROM Users; SELECT * FROM @t"), "read");
check("INSERT INTO #temp batch", classify("INSERT INTO #t SELECT * FROM Users"), "read");
check("CREATE TABLE #temp batch", classify("CREATE TABLE #t (id int); INSERT INTO #t VALUES (1); SELECT * FROM #t"), "read");
check("EXEC whitelisted name parses as exec", classify("EXEC dbo.GetReport @id = 5"), "exec");

console.log("\n=== B. Write attempts must be REJECTED (read-only mode analyzer) ===");
check("plain UPDATE", classify("UPDATE Users SET name = 'x'"), "rejected");
check("plain DELETE", classify("DELETE FROM Users"), "rejected");
check("DROP TABLE", classify("DROP TABLE Users"), "rejected");
check("stacked: SELECT ; DELETE", classify("SELECT 1; DELETE FROM Users"), "rejected");
check("smuggle via '--' inside string literal", classify("SELECT 'a--'; DELETE FROM Users"), "rejected");
check("smuggle via /* comment */", classify("SELECT 1 /* ; */ ; DELETE FROM Users"), "rejected");
check("double-quoted identifier UPDATE (QUOTED_IDENTIFIER ON)", classify('UPDATE "Users" SET x = 1'), "rejected");
check("double-quoted DROP", classify('DROP TABLE "Users"'), "rejected");
check("SELECT INTO persistent table", classify("SELECT * INTO dbo.Evil FROM Users"), "rejected");
check("SELECT INTO global ##temp", classify("SELECT * INTO ##g FROM Users"), "rejected");
check("WITH cte INSERT", classify("WITH x AS (SELECT * FROM Users) INSERT INTO dbo.T SELECT * FROM x"), "rejected");
check("DECLARE batch w/ hidden UPDATE", classify("DECLARE @a int; UPDATE Users SET name='x'; SELECT @a"), "rejected");
check("DECLARE batch w/ hidden EXEC", classify("DECLARE @a int; EXEC dbo.SomeProc; SELECT @a"), "rejected");
check("INSERT batch w/ MERGE", classify("INSERT INTO #t SELECT 1; MERGE dbo.T AS t USING #t s ON 1=0 WHEN NOT MATCHED THEN INSERT VALUES (1);"), "rejected");
check("CREATE TABLE persistent", classify("CREATE TABLE dbo.Evil (id int)"), "rejected");
check("CREATE TABLE ##global", classify("CREATE TABLE ##g (id int)"), "rejected");
check("TRUNCATE persistent", classify("DECLARE @a int; TRUNCATE TABLE Users"), "rejected");
check("ALTER TABLE persistent", classify("DECLARE @a int; ALTER TABLE Users ADD c int"), "rejected");
check("DBCC in batch", classify("DECLARE @a int; DBCC SHRINKDATABASE (x)"), "rejected");
check("sp_executesql direct", classify("EXEC sp_executesql N'SELECT 1'"), "rejected");
check("EXEC @variable", classify("EXEC @sql"), "rejected");
check("UPDATE via alias target", classify("UPDATE u SET u.x = 1 FROM Users u"), "rejected");
check("DELETE via alias target", classify("DELETE u FROM Users u"), "rejected");
check("lowercase keywords", classify("update Users set x = 1"), "rejected");
check("keyword hidden in bracket identifier is fine", classify("SELECT [update] FROM Users"), "read");

console.log("\n=== C. Dangerous statements blocked in BOTH modes (findDangerousStatement) ===");
const danger = (q) => api.findDangerousStatement(q) !== null;
const writes = (q) => api.writesToPersistentTable(q);
check("xp_cmdshell", danger("EXEC xp_cmdshell 'dir'"), true);
check("sp_configure", danger("EXEC sp_configure 'show advanced', 1"), true);
check("DROP DATABASE", danger("DROP DATABASE prod"), true);
check("BACKUP DATABASE", danger("BACKUP DATABASE prod TO DISK='x'"), true);
check("GRANT", danger("GRANT SELECT ON t TO u"), true);
check("OPENROWSET", danger("SELECT * FROM OPENROWSET('SQLOLEDB','x';'y';'z','SELECT 1')"), true);
// Built-in file-reading TVFs are SELECT-shaped, so they must be caught by the
// dangerous-statement list, not the write analyzer.
check("fn_get_audit_file", danger("SELECT * FROM sys.fn_get_audit_file('C:\\*.sqlaudit', DEFAULT, DEFAULT)"), true);
check("fn_xe_file_target_read_file", danger("SELECT * FROM sys.fn_xe_file_target_read_file('x*.xel', NULL, NULL, NULL)"), true);
check("fn_trace_gettable", danger("SELECT * FROM sys.fn_trace_gettable('C:\\x.trc', 1)"), true);
check("sp_readerrorlog", danger("EXEC sys.sp_readerrorlog 0"), true);
check("column named 'fn_get_audit_file_path' does NOT false-positive", danger("SELECT fn_get_audit_file_path FROM t"), false);
// Denylist completeness (Qwen red-team follow-up): transaction-log readers and
// any sys.fn_*file* built-in, incl. names the model probed that don't exist yet.
check("fn_dblog", danger("SELECT * FROM sys.fn_dblog(NULL, NULL)"), true);
check("fn_dump_dblog", danger("SELECT * FROM sys.fn_dump_dblog(NULL,NULL,NULL,NULL,'C:\\l.bak')"), true);
check("sys.fn_read_file", danger("SELECT * FROM sys.fn_read_file('C:\\x')"), true);
check("sys.fn_read_file + trailing WHERE", danger("SELECT * FROM sys.fn_read_file('C:\\x') WHERE 1=1"), true);
check("sys.fn_virtualfilestats (broad sys.fn_*file*)", danger("SELECT * FROM sys.fn_virtualfilestats(NULL,NULL)"), true);
check("user fn dbo.fn_myfile does NOT false-positive", danger("SELECT * FROM dbo.fn_myfile(1)"), false);
check("SHUTDOWN", danger("SHUTDOWN"), true);
check("KILL", danger("KILL 55"), true);
// Zero-width / format code points that SQL Server treats as a token separator
// but JS \s does not: without normalization, `CREATE\u200BLOGIN` slipped past
// the guard and actually ran (confirmed live). The analyzer must collapse them.
check("ZWSP splits CREATE LOGIN", danger("CREATE\u200BLOGIN hax WITH PASSWORD='x'"), true);
check("ZWSP splits DROP DATABASE", danger("DROP\u200BDATABASE prod"), true);
check("ZWSP splits BULK INSERT", danger("BULK\u200BINSERT t FROM 'C:\\x'"), true);
check("ZWJ splits GRANT", danger("GRANT\u200DSELECT ON t TO u"), true);
check("word-joiner splits xp_cmdshell", danger("EXEC\u2060xp_cmdshell 'dir'"), true);
check("ZWSP write target caught by analyzer", writes("WITH x AS(SELECT 1 n) UPDATE\u200Bdbo.Users SET a=1"), true);
check("ZWSP does NOT false-positive a plain select", danger("SELECT\u200Bcol FROM t"), false);
check("hidden in literal does NOT false-positive", danger("SELECT * FROM t WHERE x = 'xp_cmdshell'"), false);
check("column named 'shutdown_ts' does NOT false-positive", danger("SELECT shutdown_ts FROM t"), false);
check("EXEC(<string>) dynamic SQL blocked pre-classify", danger("EXEC('SELECT 1')"), true);
check("EXECUTE (<string>) dynamic SQL blocked", danger("EXECUTE ('DELETE FROM Users')"), true);
check("nested dynamic SQL voids literals", danger("EXEC sp_executesql N'EXEC xp_cmdshell ''whoami'''"), true);

console.log("\n=== D. Finding 2 re-test: write-mode blocklist gaps (now expected BLOCKED) ===");
check("ALTER ROLE ADD MEMBER blocked", danger("ALTER ROLE db_owner ADD MEMBER evildude"), true);
check("ALTER SERVER ROLE blocked", danger("ALTER SERVER ROLE sysadmin ADD MEMBER evildude"), true);
check("sp_addrolemember blocked", danger("EXEC sp_addrolemember 'db_owner', 'evildude'"), true);
check("sp_addsrvrolemember blocked", danger("EXEC sp_addsrvrolemember 'evildude', 'sysadmin'"), true);
check("sp_droprolemember blocked", danger("EXEC sp_droprolemember 'db_owner', 'evildude'"), true);
check("sp_OACreate blocked", danger("EXEC sp_OACreate 'WScript.Shell', @o OUT"), true);
check("sp_OAMethod blocked", danger("EXEC sp_OAMethod @o, 'Run'"), true);
check("sp_executesql blocked (write mode)", danger("EXEC sp_executesql N'DELETE FROM Users'"), true);
check("OPENQUERY blocked", danger("SELECT * FROM OPENQUERY(LINKEDSRV, 'SELECT 1')"), true);
check("sp_addlinkedserver blocked", danger("EXEC sp_addlinkedserver 'EVIL'"), true);
check("EXECUTE AS blocked", danger("EXECUTE AS USER = 'dbo'"), true);
check("xp_dirtree blocked", danger("EXEC xp_dirtree 'C:\\'"), true);
check("xp_fileexist blocked", danger("EXEC xp_fileexist 'C:\\boot.ini'"), true);
check("BULK INSERT blocked", danger("BULK INSERT t FROM 'C:\\data.csv'"), true);
check("CREATE ASSEMBLY blocked", danger("CREATE ASSEMBLY x FROM 0x4D5A"), true);
check("xp_regread blocked (broadened from write/delete-only)", danger("EXEC xp_regread 'HKLM', 'SAM'"), true);

console.log("\n=== E. quoteTableName identifier validation ===");
const quoteOk = (n) => { try { api.quoteTableName(n); return true; } catch { return false; } };
check("plain table ok", quoteOk("Orders"), true);
check("schema.table ok", quoteOk("dbo.Orders"), true);
check("bracketed ok", quoteOk("[dbo].[Order Details]"), true);
check("injection via semicolon rejected", quoteOk("Orders; DROP TABLE Users--"), false);
check("injection via quote rejected", quoteOk("Orders' OR '1'='1"), false);
check("three-part name rejected", quoteOk("server.dbo.Orders"), false);

console.log("\n=== F. Numeric argument validation (coerceInt) ===");
const RANGE = { min: 1, max: 100, fallback: 10 };
const coerce = (v) => { try { return api.coerceInt(v, "n", RANGE); } catch { return "rejected"; } };
check("undefined falls back to the default", coerce(undefined), 10);
check("in-range number passes through", coerce(42), 42);
check("numeric string accepted", coerce("42"), 42);
check("float truncated", coerce(42.9), 42);
check("above max clamped", coerce(5000), 100);
check("below min clamped", coerce(-5), 1);
check("non-numeric string rejected (no NaN reaches SQL)", coerce("10; DROP TABLE Users"), "rejected");
check("NaN rejected", coerce(NaN), "rejected");
check("Infinity rejected", coerce(Infinity), "rejected");
check("object rejected", coerce({}), "rejected");

console.log("\n=== G. Driver error text is not echoed verbatim ===");
const longMsg = "Invalid object name 'dbo.SecretTable'. " + "x".repeat(500);
const multiline = Object.assign(new Error("first line\nleaks the failing statement"), { number: 208 });
check("multi-line driver error collapsed to first line",
  api.describeError(multiline), "first line [SQL error 208]");
check("long message truncated", api.describeError(new Error(longMsg)).length <= 330, true);
check("truncation is marked", api.describeError(new Error(longMsg)).includes("(truncated)"), true);

console.log("\n=== H. Result paging is streamed, not buffered (DoS) ===");
// The audit trail goes to stderr via console.error; capture it here so the
// test output stays readable and section I can assert on what was logged.
const auditLines = [];
const realConsoleError = console.error;
console.error = (...parts) => auditLines.push(parts.join(" "));

async function runQuery(rowCount, args) {
  fakeDb.rows = Array.from({ length: rowCount }, (_, i) => ({ id: i + 1, name: `row${i + 1}` }));
  fakeDb.emitted = 0;
  return JSON.parse(
    await api.handleMssqlQuery({ query: "SELECT * FROM Users", response_format: "json", ...args })
  );
}

const big = await runQuery(5000, { maxRows: 10 });
check("page capped at maxRows", big.returnedRows, 10);
check("hasMore reported", big.hasMore, true);
check("total NOT claimed exact after an early stop", big.totalCountExact, false);
check("stream cancelled instead of draining 5000 rows", fakeDb.emitted <= 20, true);
check("page starts at row 1", big.rows[0].id, 1);

const paged = await runQuery(5000, { maxRows: 5, offset: 20 });
check("offset skips to the right row", paged.rows[0].id, 21);
check("page window respects the offset", paged.rows[paged.rows.length - 1].id, 25);

const small = await runQuery(3, { maxRows: 10 });
check("short result set reports an exact total", small.totalCount, 3);
check("short result set marked exact", small.totalCountExact, true);
check("no phantom next page", small.hasMore, false);

const beyond = await runQuery(3, { maxRows: 10, offset: 100 });
check("offset past the end returns no rows", beyond.returnedRows, 0);

const badMaxRows = await runQuery(3, { maxRows: "1 OR 1=1" }).then(() => "accepted", () => "rejected");
check("non-numeric maxRows rejected", badMaxRows, "rejected");

console.log("\n=== I. Query audit trail ===");
auditLines.length = 0;
const longQuery = `SELECT '${"a".repeat(700)}' AS padding FROM Users`;
await runQuery(3, { query: longQuery });
console.error = realConsoleError;

const auditEntries = auditLines
  .filter((l) => l.includes("[mssql-mcp][audit]"))
  .map((l) => JSON.parse(l.slice(l.indexOf("{"))));
const queryEntry = auditEntries.find((e) => e.event === "query");
check("every query is audited", Boolean(queryEntry), true);
check("audit records the mode", queryEntry?.mode, "read-only");
check("audit records rows returned", queryEntry?.returnedRows, 3);
check("audit timestamps the call", typeof queryEntry?.ts === "string", true);
check("audited query text is truncated", queryEntry?.query.includes("[+"), true);
check("audit line is a single line of JSON", queryEntry?.query.includes("\n"), false);

console.log(`\n========== RESULT: ${pass} passed, ${fail} failed ==========`);
if (failures.length) {
  console.log("Failures:");
  for (const f of failures) console.log(` - ${f.label}: expected ${f.expected}, got ${f.actual}`);
  process.exit(1);
}
