# Security Audit Summary — mssql-mcp-server

**Scope:** OWASP Top 10 (2021) + SAST + dynamic analyzer testing · **Date:** 2026-08-23 · **Target:** v2.0.1 working tree
**Method:** Full-source review + `npm audit` + 99-case dynamic attack battery (`scripts/security-validation.mjs`)
**อัปเดต 2026-08-23 (รอบ 3):** ปิด Finding 1/3/4/5 + ตั้ง CI แล้ว · ทุก finding ปิดครบ

## Overall Verdict: ✅ ผ่าน — ปลอดภัยตามมาตรฐาน OWASP Top 10

ออกแบบมาดี: **read-only by default**, SQL analyzer แบบ **allow-list** เป็น defense-in-depth เหนือ **least-privilege login** (`db_datareader` + `db_denydatawriter`), TLS เข้ารหัสและตรวจ certificate เป็นค่าเริ่มต้น, **npm audit = 0 vulnerabilities**

## OWASP Top 10 (2021)

| # | Category | Verdict |
|---|----------|---------|
| A01 | Broken Access Control | ✅ Pass — allow-list + DB-level deny (ทดสอบ dynamic 26 bypass attempts ถูกปฏิเสธทั้งหมด) |
| A02 | Cryptographic Failures | ✅ Pass — encrypt/cert-validation เป็นค่าเริ่มต้น (opt-out) |
| A03 | Injection | ✅ Pass — parameterized ทุก input, whitelist identifier, blocklist write-mode ครบแล้ว |
| A04 | Insecure Design | ✅ Pass — Finding 1 แก้แล้ว (stream + cancel) |
| A05 | Security Misconfiguration | ✅ Pass — secure defaults ทุกจุด |
| A06 | Vulnerable Components | ✅ Pass — 0 vulnerabilities (SDK 1.30.0 / mssql 12.7.0 / tedious 20.0.0) |
| A07 | AuthN Failures | ✅ Pass — ไม่มี credential ในโค้ด, ไม่ log password |
| A08 | Data Integrity | ✅ Pass — CI: npm audit gate + regression battery + Dependabot |
| A09 | Logging & Monitoring | ✅ Pass — query audit log ทาง stderr (MSSQL_AUDIT_LOG) |
| A10 | SSRF | ✅ Pass — OPENROWSET/OPENDATASOURCE/OPENQUERY ถูก block |

## Findings

| # | Severity | สถานะ | รายละเอียด |
|---|----------|-------|-----------|
| 0 | CRITICAL | ✅ **RESOLVED** | (รายงานจากภายนอก) `--` ในสตริงที่ปิดแล้ว ทำให้ `stripComments` ลบ statement ถัดไปออกจากข้อความที่วิเคราะห์ แต่ query ดิบยังถูกรันจริง → ทะลุ read-only + blocklist ทั้งหมด แก้ด้วย single-pass `scanSql()` ที่ track quote state |
| 1 | MEDIUM | ✅ **RESOLVED** | `handleMssqlQuery` buffer ผลลัพธ์ทั้งก้อนเข้า memory ก่อน paginate (DoS) — แก้ด้วย streaming (`request.stream = true`) + cancel หลังเกิน page 1 แถว; memory ผูกกับ `maxRows` ไม่ใช่ขนาด result set |
| 2 | MEDIUM | ✅ **RESOLVED** | write-mode blocklist เดิมขาด `ALTER ROLE`, `sp_add(srv)rolemember`, `sp_OA*`, `sp_executesql`, `OPENQUERY` — แก้แล้ว ยืนยัน dynamic 16/16 blocked |
| 3 | LOW | ✅ **RESOLVED** | error จาก driver ตัดเหลือบรรทัดแรก + cap 300 ตัวอักษร + แนบ SQL error number; รายละเอียดเต็มลง stderr เท่านั้น (`MSSQL_VERBOSE_ERRORS=true` เพื่อ opt-out) |
| 4 | LOW | ✅ **RESOLVED** | audit log ทาง stderr เป็น JSON บรรทัดเดียวต่อ 1 tool call (tool, mode, query ที่ truncate, row count, duration, outcome) — `MSSQL_AUDIT_LOG` |
| 5 | INFO | ✅ **RESOLVED** | `coerceInt()` ใช้กับ numeric arg ทุกตัว (`maxRows`, `offset`, `rows`, `top`, `topTables`, `topQueries`, `maxEvents`, `minPageCount`) — ค่าที่ไม่ใช่ตัวเลขถูกปฏิเสธ ไม่มี `NaN` หลุดไปถึง SQL

## Dynamic Validation (รอบ 3 — หลังปิดทุก finding)

**99/99 tests ผ่าน** ยิงกับโค้ดตัวจริงจาก `build/index.js`:

- A: query ถูกต้องผ่านครบ (8/8)
- B: write/bypass ถูกปฏิเสธครบ — stacked statements, smuggle ผ่าน literal/comment, `"Users"` quoted identifier, `##global`, alias target, CTE-INSERT, hidden EXEC/DBCC/MERGE (25/25)
- C: dangerous statements ถูก block ทั้งสอง mode ไม่มี false-positive (13/13)
- D: privilege escalation/OS access ถูก block ครบ 16 เวกเตอร์ (16/16)
- E: `quoteTableName` กัน injection ครบ (6/6)
- F: `coerceInt` — clamp ค่าเกินช่วง, ปฏิเสธค่าที่ไม่ใช่ตัวเลข ไม่มี `NaN` หลุด (10/10)
- G: `describeError` — ตัดเหลือบรรทัดแรก, cap ความยาว, ติดป้าย truncated (3/3)
- H: paging แบบ stream — result set 5000 แถวถูก cancel หลังอ่าน 11 แถว, offset/หน้าถูกต้อง, ไม่โกหกว่า total แม่นยำเมื่อหยุดกลางคัน (12/12)
- I: audit trail — ทุก query ถูก log, มี ts/mode/row count, query ถูก truncate เป็นบรรทัดเดียว (6/6)

## จุดแข็งที่ควรรักษาไว้

- Scanner แบบ single-pass ที่ track quote state — ปิดช่อง smuggle แบบ `SELECT 'a--'; DELETE FROM Users`
- Normalize `"Table"` เป็น bracket ก่อน analyze — ปิดช่อง QUOTED_IDENTIFIER
- EXEC path: whitelist + ตรวจ definition ของ proc ทุกครั้งก่อน run, ปฏิเสธ `WITH EXECUTE AS`
- `##global` temp ถือเป็น persistent write; `MERGE`/`DBCC`/dynamic SQL เป็น red flag ไม่มีเงื่อนไข
- Metric lookup ใช้ `Map` (กัน prototype pollution), LIKE wildcard ถูก escape

## สิ่งที่ทำไปแล้ว (รอบ 3)

1. ✅ Finding 1 — `streamQueryPage()` stream แถวและ cancel หลังเลย page ไป 1 แถว
2. ✅ Finding 4 — audit log JSON บรรทัดเดียวทาง stderr (`MSSQL_AUDIT_LOG`)
3. ✅ CI — `.github/workflows/ci.yml` (build + regression battery + `npm audit --audit-level=high` + schedule รายสัปดาห์) และ `.github/dependabot.yml`
4. ✅ Finding 3 — `describeError()` normalize error จาก driver (`MSSQL_VERBOSE_ERRORS` เพื่อ opt-out)
5. ✅ Finding 5 — `coerceInt()` กับ numeric arg ทุกตัว
6. ✅ `SECURITY.md` + disclosure policy (private vulnerability reporting, scope, safe harbor)

## ข้อควรระวังในการ deploy

> ⚠️ **Breaking change:** `mssql` 12 ดึง `tedious` 20 ซึ่ง `engines` เป็น `>=22` → **Node ขั้นต่ำเป็น 22** (เดิม 18) ปรับใน `package.json` และ CI matrix แล้ว ผู้ใช้ที่ยังอยู่ Node 18/20 จะติดตั้งไม่ผ่าน

- **write mode (`MSSQL_READ_ONLY=false`) ต้องใช้ login ที่ไม่มีสิทธิ์ sysadmin / securityadmin / role-admin** — blocklist เป็น backstop เท่านั้น ไม่ใช่ขอบเขตความปลอดภัย ถ้า login มีสิทธิ์เหล่านี้ blocklist กันได้แค่ท่าที่รู้จัก
- dynamic SQL (`sp_executesql`, `EXEC('...')`) ถูกบล็อกแม้ใน write mode — ตั้งใจ เพราะวิเคราะห์ static ไม่ได้ และถ้าปล่อยไว้จะทำให้ pattern อื่นทั้งหมดไร้ผล
- `MSSQL_AUDIT_LOG=true` (ค่าเริ่มต้น) เขียน query text ลง stderr — ปิดถ้า WHERE clause มีข้อมูลอ่อนไหว

## ที่เหลือ (นอกโค้ด)

1. เปิด **private vulnerability reporting** บน GitHub (Settings → Code security)
2. bump เป็น **2.0.2** แล้ว `npm publish` — v2.0.1 บน npm ยังมีช่องโหว่ critical อยู่
3. เผยแพร่ GitHub Security Advisory (ร่างไว้ที่ `security-review/ADVISORY_DRAFT.md`) และตอบนักวิจัย (`security-review/reply-to-reporter.md`)

---
*ข้อจำกัด: ไม่มี SQL Server จริงให้ทดสอบ — DB-level enforcement (db_denydatawriter, EXECUTE grants) ตรวจแบบ static เท่านั้น*
