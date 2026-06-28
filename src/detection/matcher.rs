// ----------------------------------------------------------------------------
//  matcher.rs — Regex-based pattern matching
// ----------------------------------------------------------------------------
//  Regex-based pattern matching against response bodies for vulnerability
//  signatures.
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
//  matcher.rs — 正規表現パターンマッチャー
//  Regex pattern matcher — maps named signatures to compiled regex patterns
//  HashMap<String, Regex> で管理高速なパターン照合を実現

use regex::Regex;
use std::collections::HashMap;

//  Matcher — 正規表現パターンレジストリ
//  Regex pattern registry — maps named patterns to compiled regexes
//  patterns: HashMap<String, Regex> — 名前コンパイル済み正規表現
pub struct Matcher {
    patterns: HashMap<String, Regex>,
}

//  マッチャーの実装 — 9つのビルトインパターンを初期化
//  Matcher implementation — initializes 9 built-in patterns
impl Matcher {
    pub fn new() -> Self {
        let mut patterns = HashMap::new();
        
        //  SQLエラー電脳検出 — MySQL/MSSQL/PostgreSQL/Oracle/Java
        patterns.insert(
            "sql_error".to_string(),
            Regex::new(r"(You have an error in your SQL syntax|Warning: mysqli_fetch_array|Warning: mysql_fetch_array|\bORA-[0-9]{5}\b|Unclosed quotation mark|Incorrect syntax near|Warning: pg_query|Microsoft OLE DB.*SQL Server|ODBC Driver.*SQL Server|java[.]sql[.]SQLException|SQLSTATE)")
                .expect("Static SQL error regex should be valid")
        );
        
        //  XSS電脳検出 — <script>alert / onerror=alert 等
        patterns.insert(
            "xss_vulnerable".to_string(),
            Regex::new(r"(<script>\balert\b|onerror=\balert\b|onload=\balert\b|onfocus=\balert\b)")
                .expect("Static XSS regex should be valid")
        );
        
        //  パストラバーサル電脳検出 — ../etc/passwd, ..\windows\win.ini, URLエンコード
        patterns.insert(
            "path_traversal".to_string(),
            Regex::new(r"(\.\./(\.\./)+\betc/passwd\b|\.\.\\windows\\win[.]ini|%2e%2e%2f%2e%2e%2f)")
                .expect("Static path traversal regex should be valid")
        );
        
        //  Log4j CVE-2021-44228 — ${jndi: / ldap: / rmi:
        patterns.insert(
            "cve_2021_44228".to_string(),
            Regex::new(r"(\$\{jndi:|ldap://|rmi://)")
                .expect("Static Log4j CVE regex should be valid")
        );
        
        //  JWTトークン — 3部構成のBase64URL形式
        patterns.insert(
            "jwt_token".to_string(),
            Regex::new(r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*")
                .expect("Static JWT token regex should be valid")
        );
        
        //  APIキー — api_key/apikey に続く32文字以上の英数字
        patterns.insert(
            "api_key".to_string(),
            Regex::new(r"(api[_-]?key|apikey)\s*[=:]\s*[a-zA-Z0-9]{32,}")
                .expect("Static API key regex should be valid")
        );
        
        //  秘密鍵 — BEGIN PRIVATE KEY ヘッダー
        patterns.insert(
            "private_key".to_string(),
            Regex::new(r"-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----")
                .expect("Static private key regex should be valid")
        );
        
        //  メールアドレス — 標準的なemail形式
        patterns.insert(
            "email_pattern".to_string(),
            Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
                .expect("Static email regex should be valid")
        );
        
        Self { patterns }
    }

    //  matches — 名前付きパターンがテキストにマッチするか
    //  Checks if a named pattern matches the given text
    pub fn matches(&self, pattern_name: &str, text: &str) -> bool {
        if let Some(regex) = self.patterns.get(pattern_name) {
            regex.is_match(text)
        } else {
            false
        }
    }

    //  find_all — パターンにマッチする全ての部分文字列を返す
    //  Finds all matches of a named pattern in text
    pub fn find_all(&self, pattern_name: &str, text: &str) -> Vec<String> {
        let mut results = Vec::new();
        
        if let Some(regex) = self.patterns.get(pattern_name) {
            for cap in regex.find_iter(text) {
                results.push(cap.as_str().to_string());
            }
        }
        
        results
    }

    //  add_pattern — 動的に新しいパターンを追加
    //  Dynamically adds a new pattern (returns error if regex is invalid)
    pub fn add_pattern(&mut self, name: &str, pattern: &str) -> Result<(), regex::Error> {
        let regex = Regex::new(pattern)?;
        self.patterns.insert(name.to_string(), regex);
        Ok(())
    }

    // ※ has_pattern — 名前付きパターンが登録済みか確認
    // ※ Checks if a named pattern exists in the registry
    pub fn has_pattern(&self, name: &str) -> bool {
        self.patterns.contains_key(name)
    }
}

impl Default for Matcher {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for Matcher {
    fn clone(&self) -> Self {
        Self {
            patterns: self.patterns.clone(),
        }
    }
}
