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
const require = (name) =>
  name === "fs" || name === "path" ? realRequire(name) : dummy;

// Eval the analyzer code and export the functions under test.
const factory = new Function(
  "require", "exports",
  `"use strict";
   const __dirname = "/tmp";
   ${code}
   return { classifyQuery, findDangerousStatement, writesToPersistentTable, quoteTableName, READ_ONLY };`
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
check("xp_cmdshell", danger("EXEC xp_cmdshell 'dir'"), true);
check("sp_configure", danger("EXEC sp_configure 'show advanced', 1"), true);
check("DROP DATABASE", danger("DROP DATABASE prod"), true);
check("BACKUP DATABASE", danger("BACKUP DATABASE prod TO DISK='x'"), true);
check("GRANT", danger("GRANT SELECT ON t TO u"), true);
check("OPENROWSET", danger("SELECT * FROM OPENROWSET('SQLOLEDB','x';'y';'z','SELECT 1')"), true);
check("SHUTDOWN", danger("SHUTDOWN"), true);
check("KILL", danger("KILL 55"), true);
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

console.log(`\n========== RESULT: ${pass} passed, ${fail} failed ==========`);
if (failures.length) {
  console.log("Failures:");
  for (const f of failures) console.log(` - ${f.label}: expected ${f.expected}, got ${f.actual}`);
  process.exit(1);
}
