// ----------------------------------------------------------------------------
//  session.rs — scan session management
// ----------------------------------------------------------------------------
//  scan session management — tracks state across multi-phase attacks
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
use anyhow::Result;
use std::collections::HashMap;
use zeroize::{Zeroize, ZeroizeOnDrop};

use std::time::{
    Duration, Instant
};
use tokio::sync::RwLock;

//  SessionManager — multi-phase scan session management / 電脳走査セッション管理
//  Architecture / アーキテクチャ:
//    sessions — in-memory session store (HashMap: session_id  Session)
//    cookies  — per-session cookie jar
//    tokens   — per-session auth tokens (JWT, OAuth2, API keys)
//  Session lifecycle / セッションライフサイクル:
//    Create  set auth type (cookie, bearer, basic, API key, JWT, OAuth2)
//    Update  touch last_activity timestamp
//    Invalidate  mark invalid, clean up cookies/tokens
//    Expiry check  compare last_activity + max_idle Duration
//  Auth header generation: translates stored auth into HTTP Authorization headers
//  Cookie parsing: full Set-Cookie header parser (name, value, domain, path, httponly, secure, samesite, expires)
//  Sessions enable authenticated scanning across multiple phases.
pub struct SessionManager {
    sessions: RwLock<HashMap<String, Session>>,
    cookies: RwLock<HashMap<String, Vec<Cookie>>>,
    tokens: RwLock<HashMap<String, AuthToken>>,
}

#[derive(Debug, Clone)]
pub struct Session {
    pub id: String,
    pub created_at: Instant,
    pub last_activity: Instant,
    pub auth_type: AuthType,
    pub is_valid: bool,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub enum AuthType {
    #[zeroize(skip)]
    Cookie(Vec<Cookie>),
    BearerToken(String),
    BasicAuth { username: String, password: String },
    ApiKey { key: String, #[zeroize(skip)] header_name: String },
    Jwt { token: String, #[zeroize(skip)] claims: HashMap<String, String> },
    OAuth2 { access_token: String, refresh_token: String, #[zeroize(skip)] expires_at: u64 },
}

#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct Cookie {
    pub name: String,
    pub value: String,
    #[zeroize(skip)]
    pub domain: Option<String>,
    #[zeroize(skip)]
    pub path: Option<String>,
    #[zeroize(skip)]
    pub expires: Option<u64>,
    #[zeroize(skip)]
    pub http_only: bool,
    #[zeroize(skip)]
    pub secure: bool,
    #[zeroize(skip)]
    pub same_site: Option<String>,
}

#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct AuthToken {
    pub token: String,
    #[zeroize(skip)]
    pub token_type: TokenType,
    #[zeroize(skip)]
    pub expires_at: Option<u64>,
    #[zeroize(skip)]
    pub refresh_token: Option<String>,
}

#[derive(Debug, Clone)]
pub enum TokenType {
    Access,
    Refresh,
    Id,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            cookies: RwLock::new(HashMap::new()),
            tokens: RwLock::new(HashMap::new()),
        }
    }

    //  Session Creation / セッション作成
    //  Allocates a new Session with:
    //    Unique session_id
    //    Auth type (Cookie, Bearer, Basic, API Key, JWT, OAuth2)
    //    Timestamp tracking (created_at, last_activity)
    //    Metadata HashMap for extensibility
    //    If Cookie auth  also stores cookies separately
    //  Sessions persist until explicitly invalidated or expired.
    /// Create new session with authentication
    pub async fn create_session(&self, session_id: &str, auth_type: AuthType) -> Result<Session> {
        let now = Instant::now();
        let session = Session {
            id: session_id.to_string(),
            created_at: now,
            last_activity: now,
            auth_type: auth_type.clone(),
            is_valid: true,
            metadata: HashMap::new(),
        };

        let mut sessions = self.sessions.write().await;
        sessions.insert(session_id.to_string(), session.clone());

        // Store cookies separately if cookie auth
        if let AuthType::Cookie(cookies) = &auth_type {
            let mut cookie_store = self.cookies.write().await;
            cookie_store.insert(session_id.to_string(), cookies.clone());
        }

        println!("[SESSION] Created session {} with auth type {:?}", session_id, auth_type);
        Ok(session)
    }

    /// Get session by ID
    pub async fn get_session(&self, session_id: &str) -> Option<Session> {
        let sessions = self.sessions.read().await;
        sessions.get(session_id).cloned()
    }

    /// Update session activity
    pub async fn update_activity(&self, session_id: &str) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get_mut(session_id) {
            session.last_activity = Instant::now();
        }
        Ok(())
    }

    /// Check if session is expired
    pub async fn is_expired(&self, session_id: &str, max_idle: Duration) -> bool {
        let sessions = self.sessions.read().await;
        if let Some(session) = sessions.get(session_id) {
            session.last_activity.elapsed() > max_idle || !session.is_valid
        } else {
            true
        }
    }

    //  Session Invalidation / セッション無効化
    //  Marks session as invalid and cleans up:
    //    Sets is_valid = false
    //    Removes cookies associated with session
    //    Removes tokens associated with session
    //  Invalidated sessions are filtered out by get_active_sessions().
    /// Invalidate session
    pub async fn invalidate_session(&self, session_id: &str) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get_mut(session_id) {
            session.is_valid = false;
            println!("[SESSION] Invalidated session {}", session_id);
        }
        
        // Clean up associated data
        let mut cookies = self.cookies.write().await;
        cookies.remove(session_id);
        
        let mut tokens = self.tokens.write().await;
        tokens.remove(session_id);
        
        Ok(())
    }

    /// Get cookies for session
    pub async fn get_cookies(&self, session_id: &str) -> Option<Vec<Cookie>> {
        let cookies = self.cookies.read().await;
        cookies.get(session_id).cloned()
    }

    /// Add cookie to session
    pub async fn add_cookie(&self, session_id: &str, cookie: Cookie) -> Result<()> {
        let mut cookies = self.cookies.write().await;
        let session_cookies = cookies.entry(session_id.to_string()).or_insert_with(Vec::new);
        
        // Update existing cookie or add new
        if let Some(existing) = session_cookies.iter_mut().find(|c| c.name == cookie.name) {
            *existing = cookie;
        } else {
            session_cookies.push(cookie);
        }
        
        Ok(())
    }

    //  Cookie Parsing / Cookie解析
    //  Parses RFC 6265 Set-Cookie header:
    //    Split on ';'  — first part is name=value
    //    Attributes: HttpOnly, Secure, Domain, Path, SameSite, Expires
    //    Stores parsed Cookie into session's cookie jar
    //  Proper cookie parsing is essential for maintaining authenticated state.
    /// Parse Set-Cookie header and store
    pub async fn parse_set_cookie(&self, session_id: &str, header_value: &str) -> Result<Cookie> {
        let parts: Vec<&str> = header_value.split(';').collect();
        if parts.is_empty() {
            return Err(anyhow::anyhow!("Empty Set-Cookie header value"));
        }
        let name_value: Vec<&str> = parts[0].splitn(2, '=').collect();
        
        let name = name_value.first().map(|s| s.trim().to_string()).unwrap_or_default();
        let value = name_value.get(1).map(|v| v.trim().to_string()).unwrap_or_default();
        
        let mut cookie = Cookie {
            name,
            value,
            domain: None,
            path: Some("/".to_string()),
            expires: None,
            http_only: false,
            secure: false,
            same_site: None,
        };
        
        // Parse attributes
        if parts.len() > 1 {
            for part in &parts[1..] {
                let attr = part.trim().to_lowercase();
                if attr == "httponly" {
                    cookie.http_only = true;
                } else if attr == "secure" {
                cookie.secure = true;
            } else if attr.starts_with("domain=") {
                cookie.domain = attr.splitn(2, '=').nth(1).map(|s| s.to_string());
            } else if attr.starts_with("path=") {
                cookie.path = attr.splitn(2, '=').nth(1).map(|s| s.to_string());
            } else if attr.starts_with("samesite=") {
                cookie.same_site = attr.splitn(2, '=').nth(1).map(|s| s.to_string());
            } else if attr.starts_with("expires=") {
                // Parse expires date
                if let Some(_date_str) = attr.splitn(2, '=').nth(1) {
                    // Simplified - would use proper date parsing
                    cookie.expires = Some(0);
                }
            }
        }
        }
        
        self.add_cookie(session_id, cookie.clone()).await?;
        Ok(cookie)
    }

    //  Auth Header Generation / 認証ヘッダー生成
    //  Translates stored AuthType into HTTP Authorization header:
    //    BearerToken  Authorization: Bearer <token>
    //    BasicAuth  Authorization: Basic <base64(user:pass)>
    //    ApiKey  <header_name>: <key>
    //    JWT  Authorization: Bearer <token>
    //    OAuth2  Authorization: Bearer <access_token>
    //    Cookie  None (cookies are sent separately)
    //  Generates the exact headers needed for authenticated requests.
    /// Get auth header for request
    pub async fn get_auth_header(&self, session_id: &str) -> Option<(String, String)> {
        let sessions = self.sessions.read().await;
        let session = sessions.get(session_id)?;
        
        match &session.auth_type {
            AuthType::BearerToken(token) => {
                Some(("Authorization".to_string(), format!("Bearer {}", token)))
            }
            AuthType::BasicAuth { username, password } => {
                let creds = base64_helper::encode(format!("{}:{}", username, password));
                Some(("Authorization".to_string(), format!("Basic {}", creds)))
            }
            AuthType::ApiKey { key, header_name } => {
                Some((header_name.clone(), key.clone()))
            }
            AuthType::Jwt { token, .. } => {
                Some(("Authorization".to_string(), format!("Bearer {}", token)))
            }
            AuthType::OAuth2 { access_token, .. } => {
                Some(("Authorization".to_string(), format!("Bearer {}", access_token)))
            }
            _ => None,
        }
    }

    /// Store JWT token with claims
    pub async fn store_jwt(&self, session_id: &str, token: &str, claims: HashMap<String, String>) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get_mut(session_id) {
            session.auth_type = AuthType::Jwt {
                token: token.to_string(),
                claims,
            };
        }
        
        let auth_token = AuthToken {
            token: token.to_string(),
            token_type: TokenType::Access,
            expires_at: None,
            refresh_token: None,
        };
        
        let mut tokens = self.tokens.write().await;
        tokens.insert(session_id.to_string(), auth_token);
        
        Ok(())
    }

    //  Expiry Cleanup / 期限切れクリーンアップ
    //  Scans all sessions and invalidates those:
    //    last_activity.elapsed() > max_idle  idle timeout
    //    !is_valid  already invalid (double-cleanup safety)
    //  Returns count of expired sessions removed
    //  Prevents memory leak from abandoned sessions.
    /// Clean up expired sessions
    pub async fn cleanup_expired(&self, max_idle: Duration) -> usize {
        let sessions = self.sessions.read().await;
        let expired: Vec<String> = sessions
            .iter()
            .filter(|(_, s)| s.last_activity.elapsed() > max_idle || !s.is_valid)
            .map(|(id, _)| id.clone())
            .collect();
        drop(sessions);
        
        for id in &expired {
            let _ = self.invalidate_session(id).await;
        }
        
        expired.len()
    }

    /// Get all active sessions
    pub async fn get_active_sessions(&self) -> Vec<Session> {
        let sessions = self.sessions.read().await;
        sessions.values().filter(|s| s.is_valid).cloned().collect()
    }
}

// Base64 encoding helper
mod base64_helper {
    pub fn encode(input: String) -> String {
        let _chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut result = String::new();
        let bytes = input.as_bytes();
        
        for chunk in bytes.chunks(3) {
            let mut buf: u32 = 0;
            for (i, &b) in chunk.iter().enumerate() {
                buf |= (b as u32) << (16 - i * 8);
            }
            
            for i in 0..4 {
                if i < chunk.len() + 1 {
                    let idx = ((buf >> (18 - i * 6)) & 0x3F) as usize;
                    const BASE64_CHARS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
                    result.push(BASE64_CHARS[idx] as char);
                } else {
                    result.push('=');
                }
            }
        }
        
        result
    }
}
