// ----------------------------------------------------------------------------
//  behavior.rs — Behavioral analysis of HTTP responses
// ----------------------------------------------------------------------------
//  Behavioral analysis of HTTP responses — detects anomalies in server
//  behavior patterns.
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
//  behavior.rs — 動作解析エンジン
//  Behavioral analysis engine — WAF fingerprinting, error page detection,
//   technology stack identification
//  HTTPレスポンスの挙動パターンからサーバーの特性を特定

//  BehaviorAnalyzer — HTTP応答の動作分析
//  Analyzes HTTP response behavior patterns
//  waf_vendors — 12種のWAFベンダー署名リスト (vendors  fingerprint signatures)
pub struct BehaviorAnalyzer {
    waf_vendors: Vec<(&'static str, Vec<&'static str>)>,
}

//  動作分析器の実装
//  Behavior analyzer implementation
impl BehaviorAnalyzer {
    //  new — WAFベンダーデータベースを初期化 (12ベンダー)
    //  Initializes WAF vendor database (12 vendors)
    //  Cloudflare      cf-ray, __cfduid, cf-cache-status 等
    //  AWS WAF        awselb, x-amzn-requestid 等
    //  ModSecurity    mod_security, OWASP_CRS 等
    //  F5 BIG-IP ASM  BigIP, TSessionId 等
    //  Imperva        incap_ses, X-Iinfo 等
    //  Akamai         akamai, ak_bmsc 等
    //  Sucuri         sucuri, X-Sucuri-ID 等
    //  Radware        radware, X-RW- 等
    //  Palo Alto      PAN-, x-pan- 等
    //  Fortinet       FortiWeb, FORTIWAF 等
    //  Barracuda      barracuda, x-barracuda- 等
    //  Citrix         netscaler, NS-CACHE 等
    pub fn new() -> Self {
        let mut waf_vendors: Vec<(&'static str, Vec<&'static str>)> = Vec::new();

        waf_vendors.push(("Cloudflare", vec![
            "cf-ray", "__cfduid", "cf-cache-status", "cf-request-id",
            "cf-waf-error", "cloudflare", "cf-challenge",
        ]));
        waf_vendors.push(("AWS WAF", vec![
            "awselb", "x-amzn-requestid", "x-amz-cf-id",
            "x-amz-cf-pop", "x-amzn-ErrorType", "aws-waf-token",
        ]));
        waf_vendors.push(("ModSecurity", vec![
            "mod_security", "NOYB", "OWASP_CRS", "ModSecurity",
            "x-modsec", "x-owasp-crs",
        ]));
        waf_vendors.push(("F5 BIG-IP ASM", vec![
            "BigIP", "TSessionId", "MRHSHint",
            "MRHInt", "x-wa-ident",
        ]));
        waf_vendors.push(("Imperva Incapsula", vec![
            "incap_ses", "incap_vis", "Incapsula", "X-Iinfo",
            "imperva", "visid_incap",
        ]));
        waf_vendors.push(("Akamai", vec![
            "akamai", "ak_bmsc", "bm_sz", "akavpau",
            "abck", "akacd",
        ]));
        waf_vendors.push(("Sucuri", vec![
            "sucuri", "X-Sucuri-ID", "Sucuri-Cloudproxy",
        ]));
        waf_vendors.push(("Radware", vec![
            "radware", "X-RW-", "alteon",
        ]));
        waf_vendors.push(("Palo Alto", vec![
            "PAN-", "x-pan-", "global-protect",
        ]));
        waf_vendors.push(("Fortinet FortiWeb", vec![
            "FortiWeb", "FORTIWAF", "x-forti-",
        ]));
        waf_vendors.push(("Barracuda", vec![
            "barracuda", "x-barracuda-", "BarracudaWAF",
        ]));
        waf_vendors.push(("Citrix NetScaler", vec![
            "netscaler", "NS-CACHE", "Citrix",
        ]));

        Self {
            waf_vendors,
        }
    }

    //  detect_error_page — エラーページから技術スタックを特定
    //  Detects error page patterns to identify technology stack
    //  11カテゴリのエラーパターン (MySQL, MSSQL, PostgreSQL, Oracle, Java,
    //   Python, .NET, PHP, Ruby, Express/Node, Generic SQL)
    // ※ 各カテゴリで2つ以上のシグネチャが一致すると電脳検出
    pub fn detect_error_page(&self, body: &str) -> Option<String> {
        let patterns: Vec<(&str, Vec<&str>)> = vec![
            ("MySQL Error", vec!["You have an error in your SQL syntax", "MySQL server version", "Warning: mysql_", "mysqli_fetch"]),
            ("MSSQL Error", vec!["Microsoft OLE DB", "Unclosed quotation mark", "Incorrect syntax near", "SQLSTATE[23000]"]),
            ("PostgreSQL Error", vec!["pg_query", "PSQLException", "pg_connect", "Warning: pg_"]),
            ("Oracle Error", vec!["ORA-", "Warning: oci_", "OCIParse"]),
            ("Java Error", vec!["NullPointerException", "Stack trace:", "at java.", "ServletException"]),
            ("Python Error", vec!["Traceback (most recent call last)", "File \"", "SyntaxError:", "NameError:"]),
            (".NET Error", vec!["System.Data.", "System.Web.", "System.NullReference", "ASP.NET"]),
            ("PHP Error", vec!["PHP Fatal error", "PHP Warning", "PHP Notice", "Parse error"]),
            ("Ruby Error", vec!["NoMethodError", "NameError in", "ActionController"]),
            ("Express/Node Error", vec!["SyntaxError: Unexpected token", "Cannot find module", "TypeError: Cannot read property"]),
            ("Generic SQL", vec!["SQL syntax", "SQLSTATE", "syntax error at"]),
        ];

        for (tech, signatures) in &patterns {
            let match_count = signatures.iter().filter(|sig| body.contains(*sig)).count();
            if match_count >= 2 {
                return Some(tech.to_string());
            }
        }
        None
    }

    //  detect_waf — レスポンスヘッダーからWAFベンダーを特定
    //  Identifies WAF vendor from response headers
    //  ヘッダーを小文字化し各ベンダーのシグネチャと照合
    pub fn detect_waf(&self, headers: &[String]) -> Option<String> {
        let header_lower: Vec<String> = headers.iter().map(|h| h.to_lowercase()).collect();

        for (name, sigs) in &self.waf_vendors {
            for sig in sigs {
                if header_lower.iter().any(|h| h.contains(&sig.to_lowercase())) {
                    return Some(name.to_string());
                }
            }
        }

        None
    }

    //  detect_tech_stack — サーバー技術スタックを総合的に特定
    //  Comprehensive technology stack identification
    //  Serverヘッダー  Nginx / Apache / IIS / Cloudflare
    //  X-Powered-By    PHP / ASP.NET / Express
    //  body特徴        WordPress / Joomla / Drupal / Shopify / Laravel / Django / Rails
    pub fn detect_tech_stack(&self, headers: &[String], body: &str) -> Vec<String> {
        let mut techs = Vec::new();
        let header_lower: Vec<String> = headers.iter().map(|h| h.to_lowercase()).collect();

        let server_header = header_lower.iter().find(|h| h.starts_with("server:"));
        if let Some(s) = server_header {
            let val = s.trim_start_matches("server:").trim();
            if val.contains("nginx/") || val.contains("nginx ") { techs.push("Nginx".to_string()); }
            if val.contains("apache/") { techs.push("Apache".to_string()); }
            if val.to_lowercase().contains("microsoft-iis") || val.to_lowercase().contains("iis/") { techs.push("IIS".to_string()); }
            if val.contains("cloudflare") { techs.push("Cloudflare".to_string()); }
        }

        let powered_by = header_lower.iter().find(|h| h.starts_with("x-powered-by:"));
        if let Some(s) = powered_by {
            let val = s.trim_start_matches("x-powered-by:").trim();
            if val.contains("php/") { techs.push("PHP".to_string()); }
            if val.contains("ASP.NET") { techs.push("ASP.NET".to_string()); }
            if val.contains("express/") { techs.push("Express".to_string()); }
        }

        if body.contains("wp-content") || body.contains("wp-includes") {
            techs.push("WordPress".to_string());
        }
        if body.contains("Joomla!") || body.contains("com_content") {
            techs.push("Joomla".to_string());
        }
        if body.contains("Drupal ") || body.contains("Drupal/") || body.contains("\"Drupal\"") || body.contains("drupal.js") {
            techs.push("Drupal".to_string());
        }
        if body.contains("Shopify ") || body.contains("Shopify/") || body.contains("\"Shopify\"") || body.contains("myshopify.com") {
            techs.push("Shopify".to_string());
        }
        if body.contains("Laravel ") || body.contains("Laravel/") || body.contains("\"Laravel\"") || body.contains("laravel_session") {
            techs.push("Laravel".to_string());
        }
        if body.contains("csrfmiddlewaretoken") || ((body.contains("Django ") || body.contains("Django/") || body.contains("\"Django\"")) && body.contains("__admin")) {
            techs.push("Django".to_string());
        }
        if body.contains("Ruby on Rails") && body.contains("csrf-token") {
            techs.push("Rails".to_string());
        }

        techs.sort();
        techs.dedup();
        techs
    }

}

impl Default for BehaviorAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for BehaviorAnalyzer {
    fn clone(&self) -> Self {
        Self {
            waf_vendors: self.waf_vendors.clone(),
        }
    }
}
