// ----------------------------------------------------------------------------
//  features.rs — feature extraction
// ----------------------------------------------------------------------------
//  feature extraction — converts HTTP response attributes into ML-ready feature vectors
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

use std::collections::HashMap;

use sha2::{
      Sha256, Digest};

use statrs::statistics::{
         Data, Distribution
         };

use crate::http::response::HttpResponse;

// ◆ ResponseFeatures — 特徴ベクトル / ML feature vector
// ◆ ■ feature extraction: converts HTTP response attributes (size, timing,
// ◆   entropy, error patterns, security headers, char distribution) into
// ◆   a normalized ML-ready numeric vector (all values 0.0–1.0).
// ◆ ■ to_vector() log-scales size features, caps timing at 30s, etc.
// ◆ ■ anomaly_score() uses z-score (|x-μ|/σ) capped at 1.0 for z > 3.
/// Extracted feature vector from HTTP response
/// Used as input to ML classifier
#[derive(Debug, Clone)]
pub struct ResponseFeatures {
    // Size-based features
    pub body_length: usize,
    pub header_size: usize,
    pub total_size: usize,
    pub body_to_header_ratio: f64,
    
    // Timing features
    pub response_time_ms: u64,
    pub normalized_time: f64,
    
    // Content structure features
    pub entropy: f64,
    pub line_count: usize,
    pub word_count: usize,
    pub tag_count: usize,
    pub json_key_count: usize,
    
    // Error indicator features
    pub has_error_keywords: bool,
    pub error_keyword_count: usize,
    pub has_stack_trace: bool,
    pub has_sql_error: bool,
    pub has_path_disclosure: bool,
    
    // Security header features
    pub security_header_count: usize,
    pub missing_security_headers: Vec<String>,
    pub has_csp: bool,
    pub has_xframe: bool,
    pub has_hsts: bool,
    
    // Content type features
    pub content_type: String,
    pub is_json: bool,
    pub is_xml: bool,
    pub is_html: bool,
    
    // Status code features
    pub status_code: u16,
    pub is_error_status: bool,
    pub is_redirect_status: bool,
    pub is_success_status: bool,
    
    // Pattern features
    pub unique_char_ratio: f64,
    pub digit_ratio: f64,
    pub uppercase_ratio: f64,
    pub special_char_ratio: f64,
    
    // Hash for deduplication
    pub content_hash: String,
    pub header_hash: String,
    
    // URL context
    pub url_path: String,
    pub has_parameters: bool,
    pub parameter_count: usize,
    pub depth: usize,
}

impl ResponseFeatures {
    /// Create new feature extractor
    pub fn new() -> Self {
        Self {
            body_length: 0,
            header_size: 0,
            total_size: 0,
            body_to_header_ratio: 0.0,
            response_time_ms: 0,
            normalized_time: 0.0,
            entropy: 0.0,
            line_count: 0,
            word_count: 0,
            tag_count: 0,
            json_key_count: 0,
            has_error_keywords: false,
            error_keyword_count: 0,
            has_stack_trace: false,
            has_sql_error: false,
            has_path_disclosure: false,
            security_header_count: 0,
            missing_security_headers: Vec::new(),
            has_csp: false,
            has_xframe: false,
            has_hsts: false,
            content_type: String::new(),
            is_json: false,
            is_xml: false,
            is_html: false,
            status_code: 0,
            is_error_status: false,
            is_redirect_status: false,
            is_success_status: false,
            unique_char_ratio: 0.0,
            digit_ratio: 0.0,
            uppercase_ratio: 0.0,
            special_char_ratio: 0.0,
            content_hash: String::new(),
            header_hash: String::new(),
            url_path: String::new(),
            has_parameters: false,
            parameter_count: 0,
            depth: 0,
        }
    }
    
    // ◆ from_response() — 特徴抽出パイプライン / feature extraction pipeline
    // ◆ ■ Basic: body_length, status_code, response_time, url_path
    // ◆ ■ Status classification: success (2xx), redirect (3xx), error (4xx+)
    // ◆ ■ Content: Shannon entropy, line/word counts
    // ◆ ■ Content type: JSON/XML/HTML detection via Content-Type header
    // ◆ ■ Structure: HTML tag count, JSON key count, XML tag count
    // ◆ ■ Character distribution: unique/digit/uppercase/special ratios
    // ◆ ■ Error patterns: SQL errors, stack traces, path disclosures, keywords
    // ◆ ■ Security headers: CSP, X-Frame-Options, HSTS, etc. (6 standard)
    // ◆ ■ Content hashing: SHA256 truncated to 16 hex chars for fingerprinting
    // ◆ ■ URL analysis: depth, query parameter count
    // ◆ ■ Body-to-header ratio (only if header_size > 0)
    /// Extract all features from HTTP response
    pub fn from_response(response: &HttpResponse, url: &str, response_time_ms: u64) -> Self {
        let mut features = Self::new();
        
        // Extract basic features
        features.body_length = response.body.len();
        features.status_code = response.status;
        features.response_time_ms = response_time_ms;
        features.url_path = url.to_string();
        
        // Status code analysis
        features.is_success_status = response.status >= 200 && response.status < 300;
        features.is_redirect_status = response.status >= 300 && response.status < 400;
          features.is_error_status = response.status >= 400;
        
        // Content analysis
        features.entropy = Self::calculate_entropy(&response.body);
        features.line_count = response.body.lines().count();
        features.word_count = response.body.split_whitespace().count();
        
        // Content type detection
        features.content_type = response.headers
            .get("content-type")
              .map(|v| v.to_lowercase())
            .unwrap_or_default();
        
        features.is_json = features.content_type.contains("json");
        features.is_xml = features.content_type.contains("xml");
        features.is_html = features.content_type.contains("html");
        
        // Content structure analysis
        features.analyze_content_structure(&response.body);
        
        // Character distribution
        features.calculate_char_stats(&response.body);
        
        // Error detection
        features.detect_error_patterns(&response.body);
        
        // Security headers
        features.analyze_security_headers(&response.headers);
        
        // Calculate hashes
        features.content_hash = Self::calculate_hash(&response.body);
        features.header_hash = Self::calculate_hash(&format!("{:?}", response.headers));
        
        // URL analysis
        features.analyze_url(url);
        
        // Calculate ratios
        if features.header_size > 0 {
            features.body_to_header_ratio = features.body_length as f64 / features.header_size as f64;
        }
        
        features
    }
    
    /// Calculate Shannon entropy of content
    fn calculate_entropy(content: &str) -> f64 {
        if content.is_empty() {
            return 0.0;
        }
        
        let mut char_counts: HashMap<char, usize> = HashMap::new();
        let total_chars = content.len() as f64;
        
        for c in content.chars() {
            *char_counts.entry(c).or_insert(0) += 1;
        }
        
        let mut entropy = 0.0;
        for count in char_counts.values() {
            let probability = *count as f64 / total_chars;
            if probability > 0.0 {
                entropy -= probability * probability.log2();
            }
        }
        
        entropy
    }
    
    /// Analyze content structure (HTML tags, JSON keys, XML tags)
    fn analyze_content_structure(&mut self, content: &str) {
        if self.is_html {
            self.tag_count = self.count_html_tags(content);
        } else if self.is_json {
            self.json_key_count = self.count_json_keys(content);
        } else if self.is_xml {
            self.tag_count = self.count_xml_tags(content);
        }
    }
    
    /// Count HTML tags in content
    fn count_html_tags(&self, content: &str) -> usize {
        // Fast HTML tag counter using regex-like parsing
        let mut count = 0;
        let mut in_tag = false;
         let mut chars = content.chars().peekable();
        
        while let Some(c) = chars.next() {
            if c == '<' && !in_tag {
                // Check it's not a comment or DOCTYPE
                let next_chars: String = chars.by_ref().take(3).collect();
                if !next_chars.starts_with('!') && !next_chars.starts_with('?') {
                    count += 1;
                }
                in_tag = true;
            } else if c == '>' && in_tag {
                in_tag = false;
            }
        }
        
        count
    }
    
    /// Count JSON keys in content
    fn count_json_keys(&self, content: &str) -> usize {
        // Count JSON key occurrences (pattern: "key":)
        let mut count = 0;
        let mut in_string = false;
        let mut prev_char = '\0';
        
        for c in content.chars() {
            if c == '"' && prev_char != '\\' {
                in_string = !in_string;
            } else if c == ':' && !in_string {
                count += 1;
            }
            prev_char = c;
        }
        
        count
    }
    
    /// Count XML tags in content
    fn count_xml_tags(&self, content: &str) -> usize {
        // Similar to HTML but more strict - count opening tags only
        let mut count = 0;
        let Ok(tag_regex) = regex::Regex::new(r"<([a-zA-Z_][a-zA-Z0-9_:.-]*)[^>]*>") else {
            return 0;
        };

        for _ in tag_regex.find_iter(content) {
            count += 1;
        }

        count
    }
    
    /// Calculate character statistics
    fn calculate_char_stats(&mut self, content: &str) {
        if content.is_empty() {
            return;
        }
        
        let total = content.len() as f64;
        let mut unique_chars = std::collections::HashSet::new();
        let mut digits = 0usize;
        let mut uppercase = 0usize;
        let mut special = 0usize;
        
        for c in content.chars() {
            unique_chars.insert(c);
            if c.is_ascii_digit() {
                digits += 1;
            } else if c.is_ascii_uppercase() {
                uppercase += 1;
            } else if !c.is_ascii_alphanumeric() && !c.is_whitespace() {
                special += 1;
            }
        }
        
        self.unique_char_ratio = unique_chars.len() as f64 / total;
        self.digit_ratio = digits as f64 / total;
        self.uppercase_ratio = uppercase as f64 / total;
        self.special_char_ratio = special as f64 / total;
    }
    
    /// Detect error patterns in response
    fn detect_error_patterns(&mut self, content: &str) {
        let error_keywords = [
            "error", "exception", "fatal", "warning", "stack trace",
            "syntax error", "parse error", "runtime error",
        ];

        // Specific DB error strings — avoid matching generic words like "sql"
        // which appear in normal URLs, JS libraries, etc.
        let sql_errors = [
            "you have an error in your sql syntax",
            "warning: mysql",
            "unclosed quotation mark",
            "quoted string not properly terminated",
            "pg::syntaxerror",
            "ora-",
            "sqlite3::exception",
            "sqlstate",
            "odbc driver",
            "microsoft ole db provider for sql server",
            "jdbc exception",
        ];

        let content_lower = content.to_lowercase();

        for keyword in &error_keywords {
            if content_lower.contains(keyword) {
                self.error_keyword_count += 1;
            }
        }

        self.has_error_keywords = self.error_keyword_count > 0;
        self.has_stack_trace = content_lower.contains("stack trace")
            || content_lower.contains("at line")
            || content_lower.contains("traceback (most recent call last)");

        // Only flag SQL error when a real DB error string is present
        self.has_sql_error = sql_errors.iter().any(|e| content_lower.contains(e));

        let has_possible_path = content.contains("/home/")
            || content.contains("/var/www/")
            || content.contains("C:\\\\")
            || content.contains("/usr/local/");
        // Only flag as disclosure if the path appears together with error indicators.
        // "/home/" appears in many normal pages (URLs, docs); alone it is not a leak.
        self.has_path_disclosure = has_possible_path
            && (self.is_error_status || self.has_error_keywords || self.has_stack_trace);
    }
    
    /// Analyze security headers
    fn analyze_security_headers(&mut self, headers: &HashMap<String, String>) {
        let security_headers = [
            "content-security-policy",
            "x-frame-options",
            "strict-transport-security",
            "x-content-type-options",
            "referrer-policy",
            "permissions-policy",
        ];
        
        for header in &security_headers {
            if headers.contains_key(&header.to_string()) {
                self.security_header_count += 1;
            } else {
                self.missing_security_headers.push(header.to_string());
            }
        }
        
        self.has_csp = headers.contains_key("content-security-policy");
        self.has_xframe = headers.contains_key("x-frame-options");
        self.has_hsts = headers.contains_key("strict-transport-security");
        
        // Calculate header size
        self.header_size = headers.iter()
            .map(|(k, v)| k.len() + v.len())
            .sum();
    }
    
    /// Analyze URL structure
    fn analyze_url(&mut self, url: &str) {
        // Extract path depth
        self.depth = url.matches('/').count();
        
        // Check for parameters
        if let Some(query_start) = url.find('?') {
            self.has_parameters = true;
            let query = &url[query_start + 1..];
            self.parameter_count = query.split('&').count();
        }
    }
    
    /// Calculate SHA256 hash of content
    fn calculate_hash(content: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        format!("{:x}", hasher.finalize())[..16].to_string()
    }
    
    /// Log-scale normalize a positive value: log10(1+x) / divisor
    fn log_norm(x: f64, divisor: f64) -> f64 {
        if divisor <= 0.0 { return 0.0; }
        (x + 1.0).log10() / divisor
    }

    // ◆ to_vector() — ML特徴ベクトル正規化 / normalized feature vector (0.0–1.0)
    // ◆ Without normalization, features at different scales (body_length: 0–1M+
    // ◆ vs status_code: 200–500) bias the Random Forest toward high-magnitude features.
    // ◆ ■ Log-scale: size features (log10(1+x) / divisor)
    // ◆ ■ Cap: timing (30s), entropy (8.0), ratios (1.0)
    // ◆ ■ Binary flags: 0/1 for booleans (has_error, has_sql, etc.)
    // ◆ ■ Count normalization: security_headers/6, keyword_count/10, etc.
    // ◆ ■ Status code: (code - 100) / 499 → 0.0–1.0 range
    /// Convert features to a normalized feature vector for ML (all values 0.0–1.0).
    /// Without normalization, features at vastly different scales (body_length: 0–1M+
    /// vs status_code: 200–500) cause the Random Forest to be biased toward high-magnitude
    /// features.
    pub fn to_vector(&self) -> Vec<f64> {
        vec![
            // Size features → log-scale
            Self::log_norm(self.body_length as f64, 7.0),            // 0 .. ~10MB (log10=7)
            Self::log_norm(self.header_size as f64, 5.0),            // 0 .. ~100KB
            Self::log_norm(self.total_size as f64, 7.0),             // 0 .. ~10MB
            (self.body_to_header_ratio.min(100.0)) / 100.0,          // cap at 100:1

            // Timing
            (self.response_time_ms as f64).min(30_000.0) / 30_000.0, // 0 .. 30s
            self.normalized_time.min(1.0),

            // Content structure
            self.entropy.min(8.0) / 8.0,                              // Shannon max ~8 for ASCII
            Self::log_norm(self.line_count as f64, 5.0),
            Self::log_norm(self.word_count as f64, 6.0),
            Self::log_norm(self.tag_count as f64, 4.0),
            Self::log_norm(self.json_key_count as f64, 4.0),

            // Error indicators (0/1)
            if self.has_error_keywords { 1.0 } else { 0.0 },
            (self.error_keyword_count as f64).min(10.0) / 10.0,
            if self.has_stack_trace { 1.0 } else { 0.0 },
            if self.has_sql_error { 1.0 } else { 0.0 },
            if self.has_path_disclosure { 1.0 } else { 0.0 },

            // Security headers (0..6)
            (self.security_header_count as f64) / 6.0,
            if self.has_csp { 1.0 } else { 0.0 },
            if self.has_xframe { 1.0 } else { 0.0 },
            if self.has_hsts { 1.0 } else { 0.0 },

            // Status code → offset to 0–1 range
            (self.status_code as f64 - 100.0).max(0.0).min(1.0) / 499.0,

            // Status type flags (0/1)
            if self.is_error_status { 1.0 } else { 0.0 },
            if self.is_redirect_status { 1.0 } else { 0.0 },
            if self.is_success_status { 1.0 } else { 0.0 },

            // Character distribution (already 0–1)
            self.unique_char_ratio,
            self.digit_ratio,
            self.uppercase_ratio,
            self.special_char_ratio,

            // URL features → bounded
            (self.parameter_count as f64).min(100.0) / 100.0,
            (self.depth as f64).min(20.0) / 20.0,
        ]
    }
}

/// Feature statistics for baseline calculation
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FeatureStats {
    pub mean: f64,
    pub std_dev: f64,
    pub min: f64,
    pub max: f64,
    pub percentile_95: f64,
}

impl FeatureStats {
    /// Calculate statistics from feature samples
    pub fn from_samples(samples: &[f64]) -> Self {
        if samples.is_empty() {
            return Self {
                mean: 0.0,
                std_dev: 0.0,
                min: 0.0,
                max: 0.0,
                percentile_95: 0.0,
            };
        }

        let data = Data::new(samples.to_vec());
        let mean = data.mean().unwrap_or(0.0);
        let std_dev = data.std_dev().unwrap_or(0.0);

        let mut sorted = samples.to_vec();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        let min = sorted.first().copied().unwrap_or(0.0);
        let max = sorted.last().copied().unwrap_or(0.0);
        let p95_idx = (sorted.len() as f64 * 0.95) as usize;
        let percentile_95 = sorted.get(p95_idx).copied().unwrap_or(max);

        Self {
            mean,
            std_dev,
            min,
            max,
            percentile_95,
        }
    }
    
    // ◆ anomaly_score() — zスコア異常度 / z-score based anomaly scoring
    // ◆ ■ z = |value - mean| / std_dev
    // ◆ ■ Score = z / 3.0, capped at 1.0 (z > 3 = fully anomalous)
    // ◆ ■ If std_dev == 0: 0.0 if value == mean, otherwise 1.0
    // ◆ ■ 3σ covers 99.7% of normal values under normal distribution
    /// Calculate anomaly score (0.0 = normal, 1.0 = highly anomalous)
    pub fn anomaly_score(&self, value: f64) -> f64 {
        if self.std_dev == 0.0 {
            return if value == self.mean { 0.0 } else { 1.0 };
        }
        
        let z_score = ((value - self.mean) / self.std_dev).abs();
        (z_score / 3.0).min(1.0)  // Cap at 1.0 for z > 3
    }
}
