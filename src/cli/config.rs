// ----------------------------------------------------------------------------
//  config.rs — TOML configuration management
// ----------------------------------------------------------------------------
//  Implements loading, saving, and default generation of scan configuration
//  via TOML files. The Config struct serializes/deserializes all scanner
//  settings including threading, modules, network options, and feature flags.
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
//  TOML電脳設定管理 / TOML configuration management
//  Config構造体 — SerdeでTOMLと相互変換 / serializes/deserializes via Serde
//    基本電脳設定 / core settings — threads, user_agent, follow_redirects, max_redirects, insecure, modules
//    スキャン設定 / scan settings — timeout, payload_limit, exploitation_level, rate_limit, duration, exclude
//    クロール設定 / crawl settings — crawl_depth, max_urls, jobs, headless
//    出力設定 / output settings — format, output, silent_mode, verbose
//    認証設定 / auth settings — cookie, proxy
//    モジュールフラグ / module flags — zeroday, active, train, insta, session, multiattack, download, resume
//    ヘッダー / headers — custom HTTP headers
//
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    // ── CORE ──────────────────────────────────────────────────────────────
    pub threads: usize,
    pub user_agent: String,
    pub follow_redirects: bool,
    pub max_redirects: usize,
    pub insecure: bool,
    pub modules: Vec<String>,

    // ── SCAN ──────────────────────────────────────────────────────────────
    pub timeout: u64,
    pub payload_limit: usize,
    pub exploitation_level: u8,
    pub rate_limit: Option<u32>,
    pub duration: Option<u64>,
    pub exclude: Vec<String>,

    // ── CRAWL ─────────────────────────────────────────────────────────────
    pub crawl_depth: usize,
    pub max_urls: usize,
    pub jobs: usize,
    pub headless: bool,

    // ── OUTPUT ────────────────────────────────────────────────────────────
    pub format: String,
    pub output: String,
    pub silent_mode: bool,
    pub verbose: bool,

    // ── AUTH ──────────────────────────────────────────────────────────────
    pub cookie: Option<String>,
    pub proxy: Option<String>,

    // ── MODULES ───────────────────────────────────────────────────────────
    pub zeroday: bool,
    pub active: bool,
    pub train: bool,
    pub insta: bool,
    pub session: bool,
    pub multiattack: bool,
    pub download: bool,
    pub resume: bool,

    // ── HEADERS ───────────────────────────────────────────────────────────
    #[serde(default)]
    pub headers: HashMap<String, String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            threads: 20,
            user_agent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36".to_string(),
            follow_redirects: true,
            max_redirects: 10,
            insecure: false,
            modules: vec!["all".to_string()],

            timeout: 30,
            payload_limit: 100,
            exploitation_level: 50,
            rate_limit: None,
            duration: None,
            exclude: vec![],

            crawl_depth: 3,
            max_urls: 100,
            jobs: 2,
            headless: false,

            format: "json".to_string(),
            output: "report".to_string(),
            silent_mode: false,
            verbose: false,

            cookie: None,
            proxy: None,

            zeroday: false,
            active: false,
            train: false,
            insta: false,
            session: false,
            multiattack: false,
            download: false,
            resume: false,

            headers: HashMap::new(),
        }
    }
}

impl Config {
    /// Generate randomized config for first-time setup
    pub fn generate() -> Self {
        let uas = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.1; rv:121.0) Gecko/20100101 Firefox/121.0",
        ];

        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();

        Self {
            threads: 8 + (seed as usize % 17),
            user_agent: uas[seed as usize % uas.len()].to_string(),
            follow_redirects: true,
            max_redirects: 10,
            insecure: false,
            modules: vec!["all".to_string()],

            timeout: 15 + (seed as u64 % 31),
            payload_limit: 100,
            exploitation_level: 30 + (seed as u8 % 41),
            rate_limit: None,
            duration: None,
            exclude: vec![],

            crawl_depth: 2 + (seed as usize % 4),
            max_urls: 100,
            jobs: 1 + (seed as usize % 4),
            headless: false,

            format: "json".to_string(),
            output: "report".to_string(),
            silent_mode: false,
            verbose: false,

            cookie: None,
            proxy: None,

            zeroday: false,
            active: false,
            train: false,
            insta: false,
            session: false,
            multiattack: false,
            download: false,
            resume: false,

            headers: HashMap::new(),
        }
    }

    pub fn load(path: &PathBuf) -> Result<Self> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;

        let config: Config = toml::from_str(&content)
            .with_context(|| "Failed to parse config file")?;

        Ok(config)
    }

    pub fn save(&self, path: &PathBuf) -> Result<()> {
        let content = toml::to_string_pretty(self)
            .with_context(|| "Failed to serialize config")?;

        fs::write(path, content)
            .with_context(|| format!("Failed to write config file: {}", path.display()))?;

        Ok(())
    }

    /// Save with header comments (community-style format)
    pub fn save_with_header(&self, path: &PathBuf) -> Result<()> {
        let mut content = String::new();
        content.push_str("# OXIDE v8.6.9community — Auto-generated config\n");
        content.push_str("# Delete this file to regenerate with fresh randomized values.\n");
        content.push_str("# Edit any value below to override — your changes persist.\n");
        content.push_str("\n");

        // CORE
        content.push_str("# === CORE ===\n");
        content.push_str(&format!("# threads = {}               # randomized on first gen (8–24)\n", self.threads));
        content.push_str("# user_agent = \"...\"         # randomized from 5 real browser UAs\n");
        content.push_str(&format!("# follow_redirects = {}\n", self.follow_redirects));
        content.push_str(&format!("# max_redirects = {}\n", self.max_redirects));
        content.push_str(&format!("# insecure = {}\n", self.insecure));
        content.push_str(&format!("# modules = [\"{}\"]\n", self.modules.join("\", \"")));
        content.push_str("\n");

        // SCAN
        content.push_str("# === SCAN ===\n");
        content.push_str(&format!("# timeout = {}               # randomized on first gen (15–45s)\n", self.timeout));
        content.push_str(&format!("# payload_limit = {}\n", self.payload_limit));
        content.push_str(&format!("# exploitation_level = {}    # randomized on first gen (30–70)\n", self.exploitation_level));
        content.push_str(&format!("# rate_limit = {}\n", self.rate_limit.map_or("0".to_string(), |v| v.to_string())));
        content.push_str(&format!("# duration = {}\n", self.duration.map_or("0".to_string(), |v| v.to_string())));
        content.push_str(&format!("# exclude = [\"{}\"]\n", self.exclude.join("\", \"")));
        content.push_str("\n");

        // CRAWL
        content.push_str("# === CRAWL ===\n");
        content.push_str(&format!("# crawl_depth = {}            # randomized on first gen (2–5)\n", self.crawl_depth));
        content.push_str(&format!("# max_urls = {}\n", self.max_urls));
        content.push_str(&format!("# jobs = {}                   # randomized on first gen (1–4)\n", self.jobs));
        content.push_str(&format!("# headless = {}\n", self.headless));
        content.push_str("\n");

        // OUTPUT
        content.push_str("# === OUTPUT ===\n");
        content.push_str(&format!("# format = \"{}\"\n", self.format));
        content.push_str(&format!("# output = \"{}\"\n", self.output));
        content.push_str(&format!("# silent_mode = {}\n", self.silent_mode));
        content.push_str(&format!("# verbose = {}\n", self.verbose));
        content.push_str("\n");

        // AUTH
        content.push_str("# === AUTH ===\n");
        content.push_str(&format!("# cookie = \"{}\"\n", self.cookie.as_deref().unwrap_or("")));
        content.push_str(&format!("# proxy = \"{}\"\n", self.proxy.as_deref().unwrap_or("")));
        content.push_str("\n");

        // MODULES
        content.push_str("# === MODULES ===\n");
        content.push_str(&format!("# zeroday = {}\n", self.zeroday));
        content.push_str(&format!("# active = {}\n", self.active));
        content.push_str(&format!("# train = {}\n", self.train));
        content.push_str(&format!("# insta = {}\n", self.insta));
        content.push_str(&format!("# session = {}\n", self.session));
        content.push_str(&format!("# multiattack = {}\n", self.multiattack));
        content.push_str(&format!("# download = {}\n", self.download));
        content.push_str(&format!("# resume = {}\n", self.resume));
        content.push_str("\n");

        // HEADERS
        content.push_str("[headers]\n");
        if self.headers.is_empty() {
            content.push_str("# X-API-Key = \"your-key-here\"\n");
            content.push_str("# Authorization = \"Bearer token-here\"\n");
        } else {
            for (k, v) in &self.headers {
                content.push_str(&format!("{} = \"{}\"\n", k, v));
            }
        }

        fs::write(path, content)
            .with_context(|| format!("Failed to write config file: {}", path.display()))?;

        Ok(())
    }

    pub fn add_header(&mut self, key: &str, value: &str) {
        self.headers.insert(key.to_string(), value.to_string());
    }

    pub fn get_headers(&self) -> &HashMap<String, String> {
        &self.headers
    }
}
