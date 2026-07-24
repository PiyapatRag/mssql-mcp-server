/* =============================================================================
   create-readonly-login.sql
   -----------------------------------------------------------------------------
   Creates a LEAST-PRIVILEGE, read-only SQL Server login + database user for the
   mssql-mcp-server to connect with.

   This is the PRIMARY enforcement layer. The application-level allow-list in
   src/index.ts (isReadOnlyQuery) is only defense-in-depth: even if a write
   statement somehow reached the server, this login cannot execute it.

   What this grants:
     - db_datareader        : SELECT on all user tables/views
     - db_denydatawriter    : explicitly DENY INSERT/UPDATE/DELETE (belt & braces)
     - VIEW DEFINITION      : read schema + stored-procedure definitions
                              (needed by mssql_get_schema / mssql_get_stored_procedures)
     - VIEW SERVER STATE    : read sys.dm_* DMVs
                              (needed by mssql_monitor_locks / mssql_monitor_usage)

     - GRANT EXECUTE        : ONLY on the specific read-only procedures you list
                              in section 3 (matches MSSQL_ALLOWED_PROCEDURES).
                              Leave section 3 empty to disable EXEC entirely.

   What this login CANNOT do:
     - INSERT / UPDATE / DELETE / MERGE         (denied by db_denydatawriter)
     - CREATE / ALTER / DROP / TRUNCATE         (no DDL permission)
     - EXEC any non-whitelisted procedure       (no EXECUTE granted on it)
     - xp_cmdshell, sp_OACreate, OPENROWSET ...  (no permission; also sysadmin-only)

   IMPORTANT: db_denydatawriter blocks writes to PERSISTENT tables only. A
   whitelisted procedure may still freely use #temp tables and @table variables
   (they live in tempdb / memory), which is exactly the read-only behavior the
   MCP server's app-level check also permits.

   -----------------------------------------------------------------------------
   USAGE
     1. Replace the placeholders below:
          <YourDatabaseName>   -> your database
          <StrongPasswordHere> -> a strong password (or use Windows/Entra auth)
     2. Run as an account with sysadmin / securityadmin rights.
     3. Point the MCP server at it via environment variables:
          MSSQL_USER=mcp_readonly
          MSSQL_PASSWORD=<StrongPasswordHere>
          MSSQL_DATABASE=<YourDatabaseName>
     4. To allow specific stored procedures, list them in section 3 of this
        script AND in the server's MSSQL_ALLOWED_PROCEDURES env var, e.g.
          MSSQL_ALLOWED_PROCEDURES=dbo.GetReport,dbo.GetCustomerSummary
        Both must agree: the DB grants EXECUTE, the app allows the name.
   ============================================================================ */

------------------------------------------------------------------------------
-- 1. Server-level login
------------------------------------------------------------------------------
USE [master];
GO

IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = N'mcp_readonly')
BEGIN
    CREATE LOGIN [mcp_readonly]
        WITH PASSWORD = N'<StrongPasswordHere>',
             CHECK_POLICY = ON,      -- enforce Windows password policy
             CHECK_EXPIRATION = ON;  -- enforce password expiration
END
GO

-- VIEW SERVER STATE is required for the monitoring tools to read sys.dm_* DMVs
-- (sessions, requests, locks, query stats). It exposes server-wide metadata
-- but grants NO ability to read table data or modify anything.
GRANT VIEW SERVER STATE TO [mcp_readonly];
GO

------------------------------------------------------------------------------
-- 2. Database-level user + roles
------------------------------------------------------------------------------
USE [<YourDatabaseName>];
GO

IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = N'mcp_readonly')
BEGIN
    CREATE USER [mcp_readonly] FOR LOGIN [mcp_readonly];
END
GO

-- Read all tables/views ...
ALTER ROLE [db_datareader] ADD MEMBER [mcp_readonly];
GO

-- ... and explicitly DENY all writes (defense-in-depth on top of the app guard).
ALTER ROLE [db_denydatawriter] ADD MEMBER [mcp_readonly];
GO

-- Allow reading object definitions (schema + stored-procedure source) so that
-- mssql_get_schema / mssql_get_stored_procedures work. This does NOT grant
-- EXECUTE on any procedure.
GRANT VIEW DEFINITION TO [mcp_readonly];
GO

------------------------------------------------------------------------------
-- 3. (Optional) Allow specific READ-ONLY stored procedures.
--
--    Only grant EXECUTE on procedures you have reviewed and that do NOT write
--    to persistent tables. These names must also be listed in the server's
--    MSSQL_ALLOWED_PROCEDURES env var. The MCP server additionally inspects
--    each procedure's definition at call time and refuses to run it if it
--    writes to a persistent table, uses sp_executesql, or nests EXEC.
--
--    Uncomment and edit per procedure (do NOT grant EXECUTE on the whole
--    schema — that would expose every procedure, defeating least privilege):
--
--    GRANT EXECUTE ON OBJECT::[dbo].[GetReport]          TO [mcp_readonly];
--    GRANT EXECUTE ON OBJECT::[dbo].[GetCustomerSummary] TO [mcp_readonly];
------------------------------------------------------------------------------

------------------------------------------------------------------------------
-- 4. (Optional, stricter) Lock down to specific schemas/tables instead of the
--    whole database. Comment out the db_datareader line above and use:
--
--    GRANT SELECT ON SCHEMA::[dbo] TO [mcp_readonly];
--    -- or per table:
--    GRANT SELECT ON OBJECT::[dbo].[Orders]   TO [mcp_readonly];
--    GRANT SELECT ON OBJECT::[dbo].[Customers] TO [mcp_readonly];
------------------------------------------------------------------------------

------------------------------------------------------------------------------
-- 5. Verify the effective permissions (run while connected AS mcp_readonly,
--    or use EXECUTE AS USER to test).
--
--    EXECUTE AS USER = 'mcp_readonly';
--    SELECT * FROM fn_my_permissions(NULL, 'DATABASE');
--    REVERT;
------------------------------------------------------------------------------

PRINT 'mcp_readonly login/user configured. Verify with fn_my_permissions before use.';
GO
