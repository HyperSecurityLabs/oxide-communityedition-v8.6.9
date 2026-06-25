// ----------------------------------------------------------------------------
//  response.rs — HTTP response parser
// ----------------------------------------------------------------------------
//  HTTP response parser — status codes, headers, body extraction and analysis.
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
//  response.rs — HTTPレスポンスパーサー
//  HTTP response parser — status codes, headers, body extraction
//  reqwestのResponseを内部形式に変換ヘッダーアクセスサイズ計算

use anyhow::{Context, Result};
use reqwest::Response as ReqwestResponse;
use std::collections::HashMap;

//  HttpResponse — HTTP応答の内部表現
//  Internal HTTP response representation
//  status  — HTTPステータスコード (200, 404, 500等)
//  headers — 応答ヘッダー (キー小文字で保存)
//  body    — 応答本文
#[derive(Clone, Debug)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: String,
}

//  レスポンス実装
//  Response implementation
impl HttpResponse {
    //  from_reqwest — reqwest::Response を内部形式に変換
    //  Converts reqwest response to internal HttpResponse
    //  ステータスコード抽出  ヘッダー抽出 (String変換)  ボディ読み取り
    pub async fn from_reqwest(response: ReqwestResponse) -> Result<Self> {
        let status = response.status().as_u16();
        
        let headers: HashMap<String, String> = response
            .headers()
            .iter()
            .filter_map(|(k, v)| {
                v.to_str()
                    .ok()
                    .map(|val| (k.to_string(), val.to_string()))
            })
            .collect();

        let body = response
            .text()
            .await
            .with_context(|| "Failed to read response body")?;

        Ok(Self {
            status,
            headers,
            body,
        })
    }

    //  is_success — 2xx成功コードか確認
    //  Checks if status is 2xx
    pub fn is_success(&self) -> bool {
        self.status >= 200 && self.status < 300
    }

    //  is_server_error — 5xxサーバーエラーか確認
    //  Checks if status is 5xx
    pub fn is_server_error(&self) -> bool {
        self.status >= 500 && self.status < 600
    }

    //  get_header — ヘッダー名 (大文字小文字区別なし) で値を取得
    //  Gets header value ignoring case
    pub fn get_header(&self, name: &str) -> Option<&String> {
        self.headers.get(name).or_else(|| {
            self.headers.get(&name.to_lowercase())
        })
    }

    //  server_header — Serverヘッダー取得 (バージョン開示電脳検出用)
    //  Gets Server header (used for version disclosure detection)
    pub fn server_header(&self) -> Option<&String> {
        self.get_header("Server")
    }

    // ※ powered_by — X-Powered-Byヘッダー (フレームワーク開示電脳検出用)
    // ※ Gets X-Powered-By header (framework disclosure detection)
    pub fn powered_by(&self) -> Option<&String> {
        self.get_header("X-Powered-By")
    }

    /// Calculate the approximate size of the response in bytes
    /// Includes: status line (HTTP version + status code + reason) + headers + body
    //  size_bytes — レスポンスのおおよそのバイト数を計算
    //  Calculates approximate response size (status line + headers + body + CRLF)
    pub fn size_bytes(&self) -> u64 {
        // Status line: "HTTP/1.1 200 OK\r\n" (approximation based on status code digits)
        let status_digits = if self.status == 0 { 3 } else { self.status.to_string().len() };
        let status_line = 9 + status_digits + 1 + 2 + 2; // "HTTP/1.1 " + status + " " + "OK" + "\r\n"

        // Headers size: "Key: Value\r\n" for each header
        let headers_size: usize = self.headers.iter()
            .map(|(k, v)| k.len() + 2 + v.len() + 2) // "Key: Value\r\n"
            .sum();

        // Body size
        let body_size = self.body.len();

        // Final CRLF before body
        let terminator = 2; // \r\n

        (status_line + headers_size + body_size + terminator) as u64
    }
}
