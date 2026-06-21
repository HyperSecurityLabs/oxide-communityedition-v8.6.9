// ----------------------------------------------------------------------------
//  request.rs — Raw HTTP request builder
// ----------------------------------------------------------------------------
//  Raw HTTP request builder — constructs requests with full control over
//  method, headers, body.
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
// ◆ request.rs — HTTPリクエストビルダー
// ★ HTTP request builder — full control over method, headers, body
// ■ URL検証、メソッド電脳設定、カスタムヘッダー注入、サイズ計算

use anyhow::Result;
use reqwest::Method;
use std::collections::HashMap;
use std::str::FromStr;
// Check the target url Specified 
use url::Url;

use super::headers::Headers;

// ★ HttpRequest — 完全なHTTPリクエスト表現
// ★ Full HTTP request representation
// ◆ url     — リクエスト先URL (urlクレートで検証済み)
// ◆ method — HTTPメソッド (GET/POST等)
// ◆ headers — カスタムヘッダー
// ◆ body   — リクエストボディ (POST時)
#[derive(Clone, Debug)]
pub struct HttpRequest {
    pub url: Url,
    pub method: Method,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
}

// ■ リクエストビルダーの実装
// ■ Request builder implementation
impl HttpRequest {
    // ◆ new — URLをパースしてGETリクエストを作成
    // ◆ Creates GET request with parsed URL, default headers
    pub fn new(url: &str) -> Result<Self> {
        let parsed_url = Url::parse(url)?;

        Ok(Self {
            url: parsed_url,
            method: Method::GET,
            headers: Headers::default_headers().to_hashmap(),
            body: None,
        })
    }

    // ● get — GETリクエストの簡易ビルダー (パース失敗時はlocalhostにフォールバック)
    // ● GET request builder with fallback
    pub fn get(url: &str) -> Self {
        Self::new(url).unwrap_or_else(|_| {
            let fallback_url = Url::parse("http://localhost").unwrap_or_else(|_| {
                Url::from_str("http://localhost:80").expect("hardcoded fallback URL always valid")
            });
            Self {
                url: fallback_url,
                method: Method::GET,
                headers: Headers::default_headers().to_hashmap(),
                body: None,
            }
        })
    }

    // ● post — POSTリクエストの簡易ビルダー
    // ● POST request builder with body
    pub fn post(url: &str, body: &str) -> Self {
        let mut req = Self::get(url);
        req.method = Method::POST;
        req.body = Some(body.to_string());
        req
    }

    // ▲ add_header — カスタムヘッダーを追加
    // ▲ Adds custom header to request
    pub fn add_header(&mut self, key: &str, value: &str) {
        self.headers.insert(key.to_string(), value.to_string());
    }

    // ★ size_bytes — リクエストのおおよそのサイズを計算
    // ★ Calculates approximate request size (method line + headers + body)
    pub fn size_bytes(&self) -> u64 {
        let method_line = self.method.as_str().len() + self.url.as_str().len() + 11;
        let headers_size: usize = self.headers.iter()
            .map(|(k, v)| k.len() + 2 + v.len() + 2)
            .sum();
        let body_size = self.body.as_ref().map(|b| b.len()).unwrap_or(0);
        (method_line + headers_size + body_size + 2) as u64
    }

}
