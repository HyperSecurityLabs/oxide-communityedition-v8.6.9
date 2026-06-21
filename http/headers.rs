// ----------------------------------------------------------------------------
//  headers.rs — HTTP header manipulation
// ----------------------------------------------------------------------------
//  HTTP header manipulation — common security header checks and custom header
//  injection.
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
// ◆ headers.rs — HTTPヘッダー操作
// ★ HTTP header manipulation — security header audit + custom header injection
// ■ セキュリティヘッダーの有無をチェック (HSTS, CSP, XFO等)

use std::collections::HashMap;

// ★ Headers — カスタムHTTPヘッダー管理
// ★ Custom HTTP header management
#[derive(Clone, Debug)]
pub struct Headers {
    headers: HashMap<String, String>,
}

// ■ ヘッダー実装
// ■ Headers implementation
impl Headers {
    pub fn new() -> Self {
        Self {
            headers: HashMap::new(),
        }
    }

    // ◆ default_headers — 標準リクエストヘッダー
    // ◆ Default request headers (Connection: keep-alive, Upgrade-Insecure-Requests: 1)
    pub fn default_headers() -> Self {
        let mut headers = Self::new();
        headers.add("Connection", "keep-alive");
        headers.add("Upgrade-Insecure-Requests", "1");
        headers
    }

    pub fn add(&mut self, key: &str, value: &str) {
        self.headers.insert(key.to_string(), value.to_string());
    }

    pub fn to_hashmap(&self) -> HashMap<String, String> {
        self.headers.clone()
    }

    // ★ audit_security_headers — セキュリティヘッダーの完全監査
    // ★ Full security header audit
    // ■ HSTS → HTTP Strict-Transport-Security
    // ■ CSP  → Content-Security-Policy (XSS対策)
    // ■ XCTO → X-Content-Type-Options (MIMEスニッフィング対策)
    // ■ XFO  → X-Frame-Options (クリックジャッキング対策)
    // ■ XXSSP → X-XSS-Protection (レガシーブラウザ対策)
    // ■ Referrer → Referrer-Policy
    // ■ Permissions → Permissions-Policy
    // ■ CORS → Access-Control-Allow-Origin
    // ■ SecureCookie → Set-Cookie の有無
    pub fn audit_security_headers(response_headers: &HashMap<String, String>) -> Vec<(String, String, String)> {
        let checks = [
            ("Strict-Transport-Security", "HSTS", "Missing HTTP Strict-Transport-Security header"),
            ("Content-Security-Policy", "CSP", "Missing Content-Security-Policy header — XSS risk"),
            ("X-Content-Type-Options", "XCTO", "Missing X-Content-Type-Options: nosniff"),
            ("X-Frame-Options", "XFO", "Missing X-Frame-Options — clickjacking risk"),
            ("X-XSS-Protection", "XXSSP", "Missing X-XSS-Protection header"),
            ("Referrer-Policy", "Referrer", "Missing Referrer-Policy header"),
            ("Permissions-Policy", "Permissions", "Missing Permissions-Policy header"),
            ("Access-Control-Allow-Origin", "CORS", "Missing CORS headers"),
            ("Set-Cookie", "SecureCookie", "No Set-Cookie header found"),
        ];

        let mut results = Vec::new();
        for (header, short, desc) in &checks {
            if *header == "X-XSS-Protection" {
                if let Some(val) = response_headers.get("x-xss-protection") {
                    if val == "0" || val == "1" {
                        results.push((short.to_string(), "present".to_string(), "X-XSS-Protection header set".to_string()));
                        continue;
                    }
                }
            }

            let header_lower = header.to_lowercase();
            let found = response_headers.keys().any(|k| k.to_lowercase() == header_lower);

            if found {
                results.push((short.to_string(), "present".to_string(), desc.replacen("Missing ", "Found ", 1)));
            } else {
                results.push((short.to_string(), "missing".to_string(), desc.to_string()));
            }
        }
        results
    }

}

impl Default for Headers {
    fn default() -> Self {
        Self::new()
    }
}
