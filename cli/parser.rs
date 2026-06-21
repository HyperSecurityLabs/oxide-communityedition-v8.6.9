// ----------------------------------------------------------------------------
//  parser.rs — input parsing utilities
// ----------------------------------------------------------------------------
//  URL validation and normalization, HTTP header and cookie string parsing,
//  module list parsing from comma-separated input, and domain name validation
//  via regex. Used by args.rs to process CLI string inputs.
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
// ◆ 入力パースユーティリティ / input parsing utilities
// ★ Parser構造体 — 静的メソッドで各種パース処理を提供 / static methods for parsing
//
// ● URLパース / URL parsing
//   ■ parse_url() — URLを検証して正規化 / validates and normalises URL
//     ➤ スキームがhttp/httpsであることを確認 / ensures scheme is http or https
//   ■ ensure_http() — スキームが無ければhttp://を付加 / prepends http:// if no scheme
//
// ● HTTPヘッダーパース / HTTP header parsing
//   ■ parse_header() — "Key: Value"形式を(K, V)タプルに分割 / splits "Key:Value" into tuple
//     ➤ フォーマットエラー時はエラーを返す / returns error on malformed input
//
// ● Cookieパース / cookie string parsing
//   ■ parse_cookie() — "key=value; key2=value2"をベクタに変換 / parses cookie string into vec
//     ➤ セミコロンで分割、各ペアを=で分割 / splits by semicolon, each pair by =
//
// ● モジュールリストパース / module list parsing
//   ■ parse_modules() — カンマ区切り文字列をVec<String>に変換 / splits comma-separated modules
//
// ● ドメイン検証 / domain validation
//   ■ is_valid_domain() — 正規表現でドメイン名の形式を検証 / regex-based domain validation
//     ➤ RFC準拠のドメイン名パターン / RFC-compliant domain pattern
//
use anyhow::{Context, Result};
// Result showing i need results with accuracy
use url::Url;

pub struct Parser;

impl Parser {
    pub fn parse_url(input: &str) -> Result<Url> {
        let url = Url::parse(input)
            .with_context(|| format!("Invalid URL: {}", input))?;
        
        if url.scheme() != "http" && url.scheme() != "https" {
            return Err(anyhow::anyhow!("URL must use http or https scheme"));
        }
        
        Ok(url)
    }

    pub fn ensure_http(url: &str) -> String {
        if url.starts_with("http://") || url.starts_with("https://") {
            url.to_string()
        } else {
            format!("http://{}", url)
        }
    }

    pub fn parse_header(header: &str) -> Result<(String, String)> {
        let parts: Vec<&str> = header.splitn(2, ':').collect();
        if parts.len() != 2 {
            return Err(anyhow::anyhow!("Header must be in format 'Key:Value'"));
        }
        
        let key = parts[0].trim().to_string();
        let value = parts[1].trim().to_string();
        
        Ok((key, value))
    }

    pub fn parse_cookie(cookie: &str) -> Vec<(String, String)> {
        let mut cookies = Vec::new();
        
        for pair in cookie.split(';') {
            let parts: Vec<&str> = pair.splitn(2, '=').collect();
            if parts.len() == 2 {
                let key = parts[0].trim().to_string();
                let value = parts[1].trim().to_string();
                cookies.push((key, value));
            }
        }
        
        cookies
    }

    pub fn parse_modules(modules: &str) -> Vec<String> {
        modules.split(',').map(|s| s.trim().to_string()).collect()
    }

    pub fn is_valid_domain(domain: &str) -> bool {
        let domain_regex = regex::Regex::new(
            r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
        );
        
        match domain_regex {
            Ok(re) => re.is_match(domain),
            Err(_) => false,
        }
    }
}
