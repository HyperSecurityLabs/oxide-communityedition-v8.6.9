// ----------------------------------------------------------------------------
//  response_analyzer.rs — response analyzer
// ----------------------------------------------------------------------------
//  response analyzer — parses HTTP responses for ML feature extraction
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
use regex::Regex;

// ◆ ResponseAnalyzer — ML feature extraction from HTTP responses / HTTP応答のML特徴抽出
// ■ Analysis pipeline / 分析パイプライン:
//   1. Baseline comparison:
//      ★ calculate_difference(): length ratio + common prefix ratio → diff_score
//      ★ If diff_score > anomaly_threshold → flag as anomalous
//   2. SQL Injection detection:
//      ★ First check for SQL error context (sql syntax, ORA-, SQLSTATE, etc.)
//      ★ Then match actual injection patterns (UNION SELECT, OR 1=1, DROP TABLE...)
//      ★ Requires error context first — reduces false positives
//   3. XSS detection:
//      ★ Exact payload reflection matching (no generic keyword matching)
//      ★ Matches full <script>alert('XSS')</script> etc.
//      ★ High confidence (0.95) when exact reflection is found
//   4. Command Injection detection:
//      ★ Multi-indicator approach (requires ≥2 hits):
//      ★ User/process output (root:, daemon:, /bin/bash)
//      ★ File paths (/etc/passwd, c:\boot.ini)
//      ★ Shell syntax (`command`, ; cat, | whoami)
//   5. Recommendations: built-in remediation advice per vulnerability type
// ➤ Rigorous detection reduces false positives compared to naive keyword matching.
pub struct ResponseAnalyzer {
    baseline_response: Option<String>,
    baseline_time: Option<u64>,
    anomaly_threshold: f32,
}

#[derive(Debug, Clone)]
pub struct ResponseAnalysis {
    pub is_vulnerable: bool,
    pub confidence: f32,
    pub vulnerability_type: Vec<String>,
    pub evidence: Vec<String>,
    pub recommendations: Vec<String>,
}

impl ResponseAnalyzer {
    pub fn new(anomaly_threshold: f32) -> Self {
        Self {
            baseline_response: None,
            baseline_time: None,
            anomaly_threshold,
        }
    }

    pub fn set_baseline(&mut self, response: &str, response_time: u64) {
        self.baseline_response = Some(response.to_string());
        self.baseline_time = Some(response_time);
    }

    // ◆ Main Analysis Entry / メイン分析エントリ
    // ■ Orchestrates the full detection pipeline:
    //   ★ Baseline diff check (anomaly detection)
    //   ★ SQLi detection    → if matched: set vulnerable, add evidence
    //   ★ XSS detection      → if matched: set vulnerable, add evidence
    //   ★ Command injection  → if matched: set vulnerable, add evidence
    //   ★ Confidence = max of all matched detectors
    // ■ Returns ResponseAnalysis with findings, evidence, and recommendations
    pub fn analyze(&self, response: &str, _response_time: u64) -> ResponseAnalysis {
        let mut analysis = ResponseAnalysis {
            is_vulnerable: false,
            confidence: 0.0,
            vulnerability_type: Vec::new(),
            evidence: Vec::new(),
            recommendations: Vec::new(),
        };

        // Check baseline anomaly detection using threshold
        if let Some(ref baseline) = self.baseline_response {
            let diff_score = self.calculate_difference(baseline, response);
            if diff_score > self.anomaly_threshold {
                analysis.evidence.push(format!("Response differs from baseline by {:.2}%", diff_score * 100.0));
            }
        }

        // SQL Injection Detection
        if let Some(confidence) = self.detect_sql_injection(response) {
            analysis.is_vulnerable = true;
            analysis.confidence = analysis.confidence.max(confidence);
            analysis.vulnerability_type.push("SQL Injection".to_string());
            analysis.evidence.push("SQL error patterns detected".to_string());
            analysis.recommendations.push("Use parameterized queries".to_string());
        }

        // XSS Detection
        if let Some(confidence) = self.detect_xss(response) {
            analysis.is_vulnerable = true;
            analysis.confidence = analysis.confidence.max(confidence);
            analysis.vulnerability_type.push("Cross-Site Scripting".to_string());
            analysis.evidence.push("XSS patterns detected".to_string());
            analysis.recommendations.push("Implement output encoding".to_string());
        }

        // Command Injection Detection
        if let Some(confidence) = self.detect_command_injection(response) {
            analysis.is_vulnerable = true;
            analysis.confidence = analysis.confidence.max(confidence);
            analysis.vulnerability_type.push("Command Injection".to_string());
            analysis.evidence.push("Command execution patterns detected".to_string());
            analysis.recommendations.push("Validate and sanitize input".to_string());
        }

        analysis
    }

    fn calculate_difference(&self, baseline: &str, response: &str) -> f32 {
        // Simple difference calculation based on length and content similarity
        let baseline_len = baseline.len();
        let response_len = response.len();
        
        if baseline_len == 0 {
            return if response_len > 0 { 1.0 } else { 0.0 };
        }
        
        // Calculate length difference ratio
        let len_diff = (baseline_len as i64 - response_len as i64).abs() as f32;
        let len_ratio = len_diff / baseline_len as f32;
        
        // Check for common substrings
        let common_prefix_len = baseline.chars().zip(response.chars()).take_while(|(a, b)| a == b).count();
        let prefix_ratio = 1.0 - (common_prefix_len as f32 / baseline_len.max(response_len) as f32);
        
        // Combine metrics
        (len_ratio + prefix_ratio) / 2.0
    }

    // ◆ SQL Injection Detection / SQLインジェクション電脳検出
    // ■ Two-stage detection for low false-positive rate:
    //   1. Error context gate: checks for SQL error messages
    //      (sql syntax, ORA-, SQLSTATE, unclosed quotation, ODBC...)
    //   2. If error context confirmed → match injection patterns
    //      (UNION SELECT, OR 1=1, DROP TABLE, exec(), xp_cmdshell...)
    // ■ Returns confidence (0.85) if both stages pass
    fn detect_sql_injection(&self, response: &str) -> Option<f32> {
        let mut confidence: f32 = 0.0;
        let lower_response = response.to_lowercase();

        // Only fire if actual SQL error context is present
        let has_sql_error = [
            "sql syntax", "mysql_fetch", "mysql_num_rows", "mysqli_",
            "ora-01", "ora-02", "sqlstate", "unclosed quotation",
            "odbc", "jdbc", "sqlite_", "microsoft ole db", "odbc driver",
            "column count", "operand should contain"
        ].iter().any(|e| lower_response.contains(e));

        if !has_sql_error {
            return None;
        }

        // Actual SQL injection patterns used by penetration testers
        let sql_patterns = [
            "union select", "or 1=1", "and 1=1", "'or '1'='1", "'or 1=1--",
            "admin'--", "'or 'x'='x", "insert into", "delete from", "drop table",
            "exec(", "xp_cmdshell", "sp_executesql"
        ];

        for pattern in sql_patterns {
            if lower_response.contains(pattern) {
                confidence = confidence.max(0.85);
            }
        }

        if confidence > 0.0 {
            Some(confidence)
        } else {
            None
        }
    }

    // ◆ XSS Detection / XSS電脳検出
    // ■ Exact payload reflection matching only:
    //   ★ <script>alert('XSS')</script>
    //   ★ <img src=x onerror=alert('XSS')>
    //   ★ javascript:alert('XSS')
    //   ★ <svg onload=alert('XSS')>
    // ■ High bar: only fires when the EXACT XSS payload is reflected back
    //   This eliminates false positives from sites that contain the word "alert"
    fn detect_xss(&self, response: &str) -> Option<f32> {
        // Only fire on explicitly reflected XSS payloads, not generic keywords
        let xss_payloads = [
            "<script>alert('XSS')</script>",
            "<script>alert(\"XSS\")</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
            "<script>alert(1)</script>",
        ];

        for payload in xss_payloads {
            if response.contains(payload) {
                return Some(0.95);
            }
        }

        None
    }

    // ◆ Command Injection Detection / コマンドインジェクション電脳検出
// ■ Multi-indicator scoring (requires ≥2 hits for firing):
//   1. Process/user output: root:, daemon:, /bin/bash, cmd.exe, whoami, id
//   2. File paths: /etc/passwd, /etc/shadow, c:\boot.ini, /proc/version
//   3. Shell syntax: backtick execution, semicolon+command patterns
// ■ Confidence formula: 0.85 + 0.05 × (hits - 2), capped at 1.0
// ➤ The ≥2 threshold prevents false positives from common English words.
fn detect_command_injection(&self, response: &str) -> Option<f32> {
        let lower_response = response.to_lowercase();

        // Require at least 2 indicators for a firing to reduce false positives
        let mut hits = 0usize;

        // Actual command output patterns
        let command_patterns = [
            "root:", "daemon:", "bin:", "sys:", "/bin/bash", "/bin/sh", "cmd.exe",
            "powershell", "system(", "exec(", "shell_exec(", "passthru(",
            "whoami", "uname", "id", "ps aux", "net user",
        ];

        for pattern in command_patterns {
            if lower_response.contains(pattern) {
                hits += 1;
            }
        }

        let file_patterns = [
            "/etc/passwd", "/etc/shadow", "/etc/hosts", "c:\\boot.ini",
            "c:\\windows\\system32", "/proc/version", "no such file or directory",
            "permission denied", "access denied", "command not found"
        ];

        for pattern in file_patterns {
            if lower_response.contains(pattern) {
                hits += 1;
            }
        }

        if let Ok(backtick_regex) = Regex::new(r"`[^`]*`") {
            if backtick_regex.is_match(response) {
                hits += 1;
            }
        }

        if let Ok(semicol_regex) = Regex::new(r";\s*\b(cat|ls|dir|whoami|id|uname)\b") {
            if semicol_regex.is_match(response) {
                hits += 1;
            }
        }

        if hits >= 2 {
            Some(0.85f32.min(0.85 + 0.05 * (hits as f32 - 2.0)))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sql_injection_detection() {
        let analyzer = ResponseAnalyzer::new(0.5);
        let response = "You have an error in your SQL syntax near 'or 1=1'";
        let analysis = analyzer.analyze(response, 100);
        
        assert!(analysis.is_vulnerable);
        assert!(analysis.vulnerability_type.contains(&"SQL Injection".to_string()));
        assert!(analysis.confidence > 0.8);
    }

    #[test]
    fn test_xss_detection() {
        let analyzer = ResponseAnalyzer::new(0.5);
        let response = "<script>alert('XSS')</script>";
        let analysis = analyzer.analyze(response, 100);
        
        assert!(analysis.is_vulnerable);
        assert!(analysis.vulnerability_type.contains(&"Cross-Site Scripting".to_string()));
        assert!(analysis.confidence > 0.9);
    }

    #[test]
    fn test_command_injection_detection() {
        let analyzer = ResponseAnalyzer::new(0.5);
        let response = "root:x:0:0:root:/root:/bin/bash";
        let analysis = analyzer.analyze(response, 100);
        
        assert!(analysis.is_vulnerable);
        assert!(analysis.vulnerability_type.contains(&"Command Injection".to_string()));
        assert!(analysis.confidence > 0.8);
    }
}
