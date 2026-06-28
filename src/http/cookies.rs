// ----------------------------------------------------------------------------
//  cookies.rs — Cookie jar management
// ----------------------------------------------------------------------------
//  Cookie jar management — stores/sends cookies across requests for session
//  persistence.
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
//  cookies.rs — クッキー管理
//  Cookie jar management — stores/sends cookies for session persistence
//  Set-Cookie ヘッダーのパースセキュリティ監査

use std::collections::HashMap;

//  Cookie — クッキーのデータ構造
//  Cookie data structure with security attributes
//  name     — クッキー名
//  domain   — ドメイン
//  path     — パス
//  httponly — HttpOnlyフラグ (trueならJSからアクセス不可)
//  secure   — Secureフラグ (trueならHTTPSのみ送信)
//  samesite — SameSite属性 (Strict/Lax/None)
//  expires  — 有効期限
#[derive(Clone, Debug)]
pub struct Cookie {
    pub name: String,
    pub domain: Option<String>,
    pub path: Option<String>,
    pub httponly: bool,
    pub secure: bool,
    pub samesite: Option<String>,
    pub expires: Option<String>,
}

//  CookieJar — クッキーストア (HashMapベース)
//  Cookie jar — stores cookies in a HashMap keyed by name
#[derive(Clone, Debug)]
pub struct CookieJar {
    cookies: HashMap<String, Cookie>,
}

//  クッキージャーの実装
//  Cookie jar implementation
impl CookieJar {
    pub fn new() -> Self {
        Self {
            cookies: HashMap::new(),
        }
    }

    //  add_from_response — Set-Cookieヘッダーをパースして追加
    //  Parses Set-Cookie header and adds cookie to jar
    //  name=value / Domain / Path / HttpOnly / Secure / SameSite / Expires
    pub fn add_from_response(&mut self, set_cookie_header: &str) {
        let parts: Vec<&str> = set_cookie_header.split(';').collect();
        if parts.is_empty() { return; }

        let first = parts[0];
        let eq_pos = first.find('=');
        let (name, _value) = match eq_pos {
            Some(pos) => (first[..pos].trim().to_string(), first[pos+1..].trim().to_string()),
            None => return,
        };

        let mut cookie = Cookie {
            name: name.clone(),
            domain: None,
            path: None,
            httponly: false,
            secure: false,
            samesite: None,
            expires: None,
        };

        if parts.len() > 1 {
            for attr in &parts[1..] {
                let attr = attr.trim();
                let attr_lower = attr.to_lowercase();
                if attr_lower == "httponly" { cookie.httponly = true; }
                else if attr_lower == "secure" { cookie.secure = true; }
                else if attr_lower.starts_with("samesite=") {
                    cookie.samesite = Some(attr_lower.trim_start_matches("samesite=").to_string());
                } else if attr_lower.starts_with("domain=") {
                    cookie.domain = Some(attr.trim_start_matches("domain=").trim_matches('"').to_string());
                } else if attr_lower.starts_with("path=") {
                    cookie.path = Some(attr.trim_start_matches("path=").trim_matches('"').to_string());
                } else if attr_lower.starts_with("expires=") {
                    cookie.expires = Some(attr.trim_start_matches("expires=").to_string());
                }
            }
        }

        self.cookies.insert(name, cookie);
    }

    //  audit_security — クッキーのセキュリティ監査
    //  Audits cookie security settings
    //  HttpOnly欠落  XSSでセッション窃取可能
    //  Secure欠落    HTTP経由で送信
    //  SameSite欠落  CSRF可能
    //  SameSite=None  Secureフラグ必須
    pub fn audit_security(&self) -> Vec<String> {
        let mut issues = Vec::new();
        for cookie in self.cookies.values() {
            if !cookie.httponly {
                issues.push(format!("Cookie '{}' missing HttpOnly flag — XSS can steal session", cookie.name));
            }
            if !cookie.secure {
                issues.push(format!("Cookie '{}' missing Secure flag — sent over HTTP", cookie.name));
            }
            match &cookie.samesite {
                None => {
                    issues.push(format!("Cookie '{}' missing SameSite attribute — CSRF possible", cookie.name));
                }
                Some(s) if s == "none" => {
                    issues.push(format!("Cookie '{}' has SameSite=None — requires Secure flag", cookie.name));
                }
                _ => {}
            }
            if cookie.expires.is_some() {
                if cookie.httponly && cookie.secure && cookie.samesite.as_deref() == Some("lax") {
                    continue;
                }
            }
        }
        issues
    }
}

impl Default for CookieJar {
    fn default() -> Self {
        Self::new()
    }
}
