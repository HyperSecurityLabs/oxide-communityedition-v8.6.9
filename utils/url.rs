// ----------------------------------------------------------------------------
//  url.rs — URL utilities
// ----------------------------------------------------------------------------
//  URL utilities — parsing, normalization, validation for scan targets
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

use url::Url;

// ◆ UrlUtil — URLユーティリティ / URL parsing, normalization, validation
// ◆ ■ is_valid_url(): validates input is parseable as HTTP/HTTPS URL
// ◆ ■ extract_domain(): extracts host from URL (no scheme)
// ◆ ■ extract_query_param_names(): parses query string param names
// ◆ ■ inject_param(): adds/replaces URL parameter safely
pub struct UrlUtil;

impl UrlUtil {
    // ◆ is_valid_url() — URL検証 / validate URL format
    // ◆ ■ Prepends http:// if scheme is missing
    // ◆ ■ Uses url::Url::parse() for RFC-compliant validation
    // ◆ ■ Returns true if parse succeeds (any valid URL)
    pub fn is_valid_url(input: &str) -> bool {
        let url_str = if input.starts_with("http://") || input.starts_with("https://") {
            input.to_string()
        } else {
            format!("http://{}", input)
        };
        Url::parse(&url_str).is_ok()
    }

    // ◆ extract_domain() — ドメイン抽出 / extract hostname from URL
    // ◆ Returns host string (e.g., "example.com") or empty string on failure
    pub fn extract_domain(url: &Url) -> String {
        url.host_str().unwrap_or("").to_string()
    }

    // ◆ extract_query_param_names() — クエリパラメータ抽出 / parse query param names
    // ◆ ■ Splits query string by &, extracts keys before = sign
    // ◆ ■ Filters empty keys, returns Vec<String>
    pub fn extract_query_param_names(url_str: &str) -> Vec<String> {
        if let Ok(parsed) = Url::parse(url_str) {
            if let Some(query) = parsed.query() {
                if !query.is_empty() {
                    return query.split('&')
                        .filter_map(|param| param.split('=').next().map(|s| s.to_string()))
                        .filter(|s| !s.is_empty())
                        .collect();
                }
            }
        }
        Vec::new()
    }

    // ◆ inject_param() — パラメータ注入 / inject or replace URL parameter
    // ◆ ■ If base_url is parseable: removes existing param, appends new pair
    // ◆ ■ If unparseable: appends &param=value or ?param=value as fallback
    // ◆ ■ Returns modified URL string (safe encoding via url::Url)
    pub fn inject_param(base_url: &str, param: &str, value: &str) -> String {
        match Url::parse(base_url) {
            Ok(mut url) => {
                let mut pairs: Vec<(String, String)> = url
                    .query_pairs()
                    .filter(|(k, _)| k.as_ref() != param)
                    .map(|(k, v)| (k.into_owned(), v.into_owned()))
                    .collect();
                pairs.push((param.to_string(), value.to_string()));

                let qs = pairs.iter()
                    .map(|(k, v)| format!("{}={}", k, v))
                    .collect::<Vec<_>>()
                    .join("&");
                url.set_query(Some(&qs));
                url.to_string()
            }
            Err(_) => {
                if base_url.contains('?') {
                    format!("{}&{}={}", base_url, param, value)
                } else {
                    format!("{}?{}={}", base_url, param, value)
                }
            }
        }
    }
}
