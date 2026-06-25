// ----------------------------------------------------------------------------
//  client.rs — Async HTTP client
// ----------------------------------------------------------------------------
//  Async HTTP client built on reqwest — configurable with custom headers,
//  proxies, TLS.
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
//  client.rs — 非同期HTTPクライアント
//  Async HTTP client — reqwestベースの電脳設定可能なクライアント
//  カスタムヘッダープロキシTLS電脳設定UAローテーションをサポート

use anyhow::{Context, Result};
use reqwest::{Client, ClientBuilder, cookie::Jar, redirect::Policy};
use std::sync::Arc;
use super::request::HttpRequest;
use super::response::HttpResponse;
use super::useragents::UserAgentPool;

//  HttpClientConfig — HTTPクライアントの電脳設定
//  HTTP client configuration
//  insecure      — TLS証明書検証をスキップ
//  proxy         — プロキシURL
//  user_agent    — カスタムUA (指定時はローテーションより優先)
//  follow_redirects — リダイレクト追従フラグ
//  max_redirects — 最大リダイレクト数
//  cookie        — クッキー文字列
//  jobs          — 同時接続数
#[derive(Clone)]
pub struct HttpClientConfig {
    pub insecure: bool,
    pub proxy: Option<String>,
    pub user_agent: Option<String>,
    pub follow_redirects: bool,
    pub max_redirects: u32,
    pub cookie: Option<String>,
    pub jobs: usize,
}

impl Default for HttpClientConfig {
    fn default() -> Self {
        Self {
            insecure: false,
            proxy: None,
            user_agent: None,
            follow_redirects: true,
            max_redirects: 10,
            cookie: None,
            jobs: 2,
        }
    }
}

//  HttpClient — HTTPクライアントのメイン構造体
//  Main HTTP client — wraps reqwest Client with UA pool
//  client     — reqwest Client (ビルダーから構築)
//  ua_pool    — User-Agentローテーションプール
//  user_agent — 固定UA (オプショナル)
//  cookie_str — クッキー文字列
#[derive(Clone)]
pub struct HttpClient {
    client:     Client,
    ua_pool:    UserAgentPool,
    user_agent: Option<String>,
    cookie_str: Option<String>,
}

//  クライアント実装 — 構築・送信の全ライフサイクル
//  Client implementation — full build/send lifecycle
impl HttpClient {
    //  new — 電脳設定からクライアントを構築
    //  Builds HttpClient from config (calls build_client internally)
    pub fn new(config: HttpClientConfig) -> Result<Self> {
        let client = Self::build_client(&config)?;
        Ok(Self {
            client,
            ua_pool:  UserAgentPool::full(),
            user_agent: config.user_agent,
            cookie_str: config.cookie,
        })
    }

    //  build_client — reqwest ClientBuilder の電脳設定
    //  Builds reqwest Client with cert validation, proxy, cookies, redirects
    //  証明書検証スキップ / タイムアウト / クッキーストア / プロキシ
    fn build_client(config: &HttpClientConfig) -> Result<Client> {
        let mut builder = ClientBuilder::new()
            .danger_accept_invalid_certs(config.insecure)
            .timeout(std::time::Duration::from_secs(30))
            .cookie_store(true)
            .pool_max_idle_per_host(config.jobs.max(8))
            .tcp_keepalive(std::time::Duration::from_secs(30));

        if let Some(ref cookie_str) = config.cookie {
            let jar = Jar::default();
            for pair in cookie_str.split(';') {
                let parts: Vec<&str> = pair.splitn(2, '=').collect();
                if parts.len() == 2 {
                    jar.add_cookie_str(
                        &format!("{}={}", parts[0].trim(), parts[1].trim()),
                        &"http://localhost".parse().unwrap(),
                    );
                }
            }
            builder = builder.cookie_provider(Arc::new(jar));
        }

        if let Some(ref proxy_url) = config.proxy {
            let parsed = reqwest::Proxy::all(proxy_url)
                .with_context(|| format!("Invalid proxy URL: {}", proxy_url))?;
            builder = builder.proxy(parsed);
        }

        builder = builder.redirect(Policy::limited(config.max_redirects as usize));

        builder
            .build()
            .with_context(|| "Failed to build HTTP client")
    }

    pub fn cookie_string(&self) -> Option<&str> {
        self.cookie_str.as_deref()
    }

    //  send — リクエスト送信の完全ライフサイクル
    //  Full request lifecycle: UA selection  header override  body  send  response
    //  1. UA選択 (固定 or プールからローテーション)
    //  2. AcceptヘッダーをUAに合わせて電脳設定 (WAF対策)
    //  3. カスタムヘッダー適用 (UA/Acceptは上書き禁止)
    //  4. ボディ電脳設定
    //  5. 送信
    //  6. HttpResponse に変換
    pub async fn send(&self, request: HttpRequest) -> Result<HttpResponse> {
        let ua = self.user_agent.as_deref().unwrap_or_else(|| self.ua_pool.next());
        let (accept, accept_lang, accept_enc) = UserAgentPool::accept_headers_for(ua);

        let mut req = self.client.request(request.method.clone(), request.url.as_str());

        // Apply custom headers from request first, then override critical headers
        // with pool-selected values so UA rotation works correctly.
        for (key, value) in &request.headers {
            let key_lower = key.to_lowercase();
            match key_lower.as_str() {
                "user-agent" | "accept" | "accept-language" | "accept-encoding" => {}
                _ => { req = req.header(key, value); }
            }
        }

        req = req
            .header("User-Agent",      ua)
            .header("Accept",          accept)
            .header("Accept-Language", accept_lang)
            .header("Accept-Encoding", accept_enc);

        if let Some(body) = &request.body {
            req = req.body(body.clone());
        }
        let response = req
            .send()
            .await
            .with_context(|| format!("Failed to send request to {}", request.url))?;
        HttpResponse::from_reqwest(response).await
    }

    //  get — GETリクエストの簡易メソッド
    //  Convenience GET request
    pub async fn get(&self, url: &str) -> Result<HttpResponse> {
        self.send(HttpRequest::get(url)).await
    }

    //  post — POSTリクエストの簡易メソッド
    //  Convenience POST request
    pub async fn post(&self, url: &str, body: &str) -> Result<HttpResponse> {
        self.send(HttpRequest::post(url, body)).await
    }
}
