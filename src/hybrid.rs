// ----------------------------------------------------------------------------
//  hybrid.rs — multi-phase orchestration scanner engine
// ----------------------------------------------------------------------------
//  Main scan orchestrator coordinating 8+ phases: (1) RECON — WAF/server/OS
//  fingerprinting via active (pnet) and passive HTTP probes; (2) CRAWL — BFS
//  web crawling with headless Chrome option; (3) FUZZ — BlazingShadow async
//  concurrent fuzzing (SQLi, XSS, LFI, CMDi, NoSQL) across all discovered
//  parameters; (4-8) dedicated scanners for SQLi, XSS, LFI, TLS, CORS, common
//  paths, default creds. Integrates ML-based zero-day anomaly detection using
//  response feature analysis and classifier training.
//
//  --- Developers ---------------------------------------------------------------
//  khaninkali             — разработчик / core engineer (Rust backend, logic)
//  Lyara Koroleva         — дизайнер / blazing fast CLI & visual design
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
use colored::Colorize;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Duration;
use tokio::sync::mpsc;
use url::Url;

use crate::cli::args::CliArgs;
use crate::cli::output::Output;
use crate::cli::parser::Parser;
use crate::core::scanner::{
    Scanner, ScanResult,
};
use crate::crawls::WebCrawler;
use crate::http::client::{HttpClient, HttpClientConfig};
use crate::http::headless::HeadlessCrawler;
use crate::
detection::behavior::BehaviorAnalyzer;
use crate::detection::signatures::SignatureDatabase;
use crate::report::html::HtmlReport;
use crate::payload::generator::PayloadGenerator;
use crate::payload::fuzzer::Fuzzer;
use crate::detection::analyzer::{Analyzer, Finding, Severity};
use crate::detection::confirm::Confirm;
use crate::cli::spinner::Spinner;
use crate::agent::AgentPool;
use oxide::scanner::common_app_scanner::CommonAppScanner;
use oxide::scanner::common_app_scanner::Severity as CommonAppSeverity;
use oxide::scanner::cors_scanner::CorsScanner;
use oxide::scanner::cors_scanner::CorsSeverity;
use oxide::scanner::default_creds_scanner::DefaultCredsScanner;
use oxide::scanner::
default_creds_scanner::CredsSeverity;
use oxide::scanner::tls_scanner::TlsScanner;
use oxide::scanner::tls_scanner::TlsSeverity;
use oxide::scanner::sqli_scanner::SqlInjectionScanner;
use oxide::scanner::xss_scanner::XssScanner;
use oxide::scanner::lfi_scanner::LFIScanner;
use crate::utils::url::UrlUtil;
#[cfg(target_os = "linux")]
use crate::recon::{ActiveRecon, ReconResult};
use oxide::utils::time::TimeUtil;
use crate::zero_day::engine::ZeroDayEngine;

//  HybridScanner — メイン電脳走査オーケストレーター / main scan orchestrator
//  8+フェーズを調整: RECON  CRAWL  FUZZ  SQLi  XSS  LFI  TLS  CORS
//  orchestrates 8+ phases: recon, crawl, fuzz, sqli, xss, lfi, tls, cors, common, creds, filter, ml
pub struct HybridScanner {
    args: CliArgs,
    client: Arc<HttpClient>,
    crawler: Option<WebCrawler>,
    headless_crawler: Option<HeadlessCrawler>,
    scanner: Scanner,
    fuzzer: Fuzzer,
    analyzer: Analyzer,
    findings: Vec<Finding>,
    behavior_analyzer: BehaviorAnalyzer,
    signature_db: SignatureDatabase,
    zero_day_engine: ZeroDayEngine,
    pub req_count: AtomicUsize,
}

//  HybridScanner実装 / HybridScanner implementation
//  全フェーズの初期化・実行・結果収集を担当 / handles init, execution, and result collection for all phases
impl HybridScanner {
    pub fn get_discovered_urls(&self) -> Vec<String> {
        Vec::new()
    }

    //  コンストラクタ / constructor — initializes HTTP client, crawlers, scanner, fuzzer, analyzer, ML engine
    pub fn new(args: CliArgs) -> Result<Self> {
        // Use TimeUtil::sleep for brief initialization delay
        TimeUtil::sleep(std::time::Duration::from_millis(50));
        
        let client_config = HttpClientConfig {
            insecure: args.insecure,
            follow_redirects: true,
            max_redirects: args.max_redirects,
            proxy: args.proxy.clone(),
            user_agent: args.user_agent.clone(),
            cookie: args.cookie.clone(),
            jobs: args.jobs,
        };
        let client = HttpClient::new(client_config.clone())?;
        let client = Arc::new(client);

        let crawler_config = HttpClientConfig {
            insecure: args.insecure,
            follow_redirects: true,
            max_redirects: args.max_redirects,
            proxy: args.proxy.clone(),
            user_agent: args.user_agent.clone(),
            cookie: args.cookie.clone(),
            jobs: args.jobs,
        };

        let (crawler, headless_crawler) = if args.headless {
            let hc = HeadlessCrawler::new(
                args.crawl_depth as usize,
                args.max_urls,
                args.user_agent.clone(),
                args.cookie.clone(),
                args.jobs,
            );
            (None, Some(hc))
        } else {
            let wc = WebCrawler::new(
                HttpClient::new(crawler_config)?,
                args.crawl_depth as usize,
                args.max_urls,
            ).with_jobs(args.jobs);
            (Some(wc), None)
        };

        let payload_gen = PayloadGenerator::new();
        let (tx, _rx) = mpsc::channel(100);

        let scanner = Scanner::new(client.clone(), args.clone(), payload_gen.clone(), tx.clone());
        let fuzzer = Fuzzer::new();
        let analyzer = Analyzer::new();

        let behavior_analyzer = BehaviorAnalyzer::new();
        let signature_db = SignatureDatabase::new();
        let zero_day_engine = ZeroDayEngine::new();

        Ok(Self {
            args,
            client,
            crawler,
            headless_crawler,
            scanner,
            fuzzer,
            analyzer,
            findings: Vec::new(),
            behavior_analyzer,
            signature_db,
            zero_day_engine,
            req_count: AtomicUsize::new(0),
        })
    }

    //  メイン電脳走査実行 / main scan execution
    //  全8+フェーズを逐次実行 / executes all 8+ phases sequentially
    //  各フェーズ: タイムアウトチェック  モジュールフィルタ  実行  結果収集
    //  each phase: timeout check  module filter  execute  collect findings
    pub async fn run_hybrid_scan(&mut self) -> Result<Vec<Finding>> {
        let mut modules = self.args.get_modules();
        if self.args.insta && !modules.contains(&"insta".to_string()) {
            modules.push("insta".to_string());
        }
        if self.args.session && !modules.contains(&"session".to_string()) {
            modules.push("session".to_string());
        }
        let excluded = self.args.get_excluded();
        let verbose = self.args.verbose;

        let parsed_url = Parser::ensure_http(self.args.target_url());
        if !UrlUtil::is_valid_url(&parsed_url) {
            return Err(anyhow::anyhow!("Invalid target URL"));
        }

        let _target_domain = if let Ok(url) = Url::parse(&parsed_url) {
            UrlUtil::extract_domain(&url)
        } else {
            parsed_url.clone()
        };

        let start = std::time::Instant::now();
        let mut all_findings = Vec::new();
        let duration_limit = if self.args.duration > 0 {
            Some(std::time::Duration::from_secs(self.args.duration))
        } else {
            None
        };
        macro_rules! check_timeout {
            () => {
                if let Some(limit) = duration_limit {
                    if start.elapsed() >= limit {
                        println!("  {} Duration limit reached ({}s) — stopping scan",
                            tc("[!]", SHU), self.args.duration);
                        return Ok(all_findings);
                    }
                }
            };
        }

        println!("  {} {} {}",
            tc("◆", HISUI),

            tc("Engines initialised — starting scan with", TSUYUKUSA),

            tc(&modules.join(", "), HISUI).bold());
        Output::print_line();

        // 
        //  PHASE 1: TARGET RECON — Fingerprint, WAF, Server Info, OS
        //   アクティブ/パッシブリコン / active or passive reconnaissance
        //   WAF電脳検出・サーバーフィンガープリント・OS識別・ポート電脳走査
        //   WAF detection, server fingerprint, OS identification, port scan
        // 

        check_timeout!();
        if !excluded.contains(&"fingerprint".to_string()) {
            print_phase_banner("RECON", "Target fingerprinting & WAF detection");

            //  Active recon with pnet (Linux only, requires root) 
            #[cfg(target_os = "linux")]
            if self.args.active {
                let recon = ActiveRecon::new(self.client.clone(), self.args.target_url());
                let recon_start = std::time::Instant::now();

                // Braille frames for animated spinner
                let frames = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"];

                macro_rules! recon_step {
                    ($label:expr, $work:expr) => {{
                        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
                        let s_clone = stop.clone();
                        let lbl = String::from($label);
                        let _spinner_handle = tokio::spawn(async move {
                            let mut idx = 0usize;
                            loop {
                                tokio::time::sleep(Duration::from_millis(100)).await;
                                if s_clone.load(std::sync::atomic::Ordering::Relaxed) { break; }
                                let frame = frames[idx % 10];
                                idx += 1;
                                print!("\r\x1B[2K  {}  {}", tc(frame, SHU), tc(&format!("{}...", lbl), FUJI));
                                let _ = std::io::Write::flush(&mut std::io::stdout());
                            }
                        });
                        let result = $work;
                        stop.store(true, std::sync::atomic::Ordering::Relaxed);
                        _spinner_handle.await.ok();
                        print!("\r\x1B[2K");
                        println!("  {}  {}", tc("✓", HISUI), tc($label, TSUYUKUSA));
                        result
                    }};
                }

                // Combined HTTP analysis — single request for all header/body checks
                let (waf, server, tech_stack, security_headers, _cookies) = recon_step!(
                    "HTTP fingerprint (WAF + Server + Tech + Headers)",
                    async {
                        let waf = recon.detect_waf_http().await;
                        let server = recon.detect_server().await;
                        let tech_stack = recon.detect_tech_stack().await;
                        let security_headers = recon.audit_security_headers().await;
                        let cookies = recon.analyze_cookies().await;
                        (waf, server, tech_stack, security_headers, cookies)
                    }.await
                );

                let _ua_probes = recon_step!(
                    "Multi-UA probe (5 agents)",
                    recon.probe_with_all_agents(self.args.target_url()).await
                );

                let _error_pages = recon_step!(
                    "Error page probing (6 paths, parallel)",
                    recon.detect_error_pages().await
                );

                let open_ports = recon_step!(
                    "Port scan (10 ports, parallel)",
                    recon.tcp_connect_scan(vec![80, 443, 8080, 8443, 22, 21, 3306, 5432, 6379, 27017]).await
                );

                let banners = recon_step!(
                    "Banner grabbing (parallel)",
                    recon.grab_banners(&open_ports).await
                );

                let os = recon_step!(
                    "OS fingerprinting",
                    recon.tcp_fingerprint_os().await
                );

                let cf_bypass = recon_step!(
                    "Cloudflare bypass probe (10 spoofed headers)",
                    recon.cloudflare_bypass_probe().await
                );

                let result = ReconResult {
                    os,
                    open_ports,
                    banners,
                    waf,
                    server,
                    tech_stack,
                    security_headers,
                };

                let elapsed = recon_start.elapsed();
                let out = ActiveRecon::format_recon_output(&result);
                println!("  {}{}  {}", tc("[+]", HISUI), tc("RECON", HISUI), tc(&format!("[{:02}:{:02}]", elapsed.as_secs() / 60, elapsed.as_secs() % 60), TSUYUKUSA));
                println!("{}", out);
                // Push findings from active recon
                if let Some(ref os) = result.os {
                    all_findings.push(Finding::new(
                        self.args.target_url(), Severity::Info,
                        &format!("OS Fingerprint: {} {} ({}%)", os.os_family, os.os_version, os.confidence),
                        "Operating system identified via TCP/IP fingerprinting",
                    ));
                }
                if let Some(ref waf) = result.waf {
                    all_findings.push(Finding::new(
                        self.args.target_url(), Severity::Info,
                        &format!("WAF Detected: {}", waf),
                        "A Web Application Firewall is present",
                    ));
                }
                if !result.server.is_empty() && result.server != "Unknown" {
                    all_findings.push(Finding::new(
                        self.args.target_url(), Severity::Low,
                        &format!("Server Fingerprint: {}", result.server),
                        "Server version header is exposed",
                    ).with_remediation("Hide server version strings in HTTP response headers"));
                }
                for port in &result.open_ports {
                    if port.state == "open" {
                        all_findings.push(Finding::new(
                            self.args.target_url(), Severity::Info,
                            &format!("Open Port: {} ({})", port.port, port.service),
                            &format!("Port {} is open", port.port),
                        ));
                    }
                }
                // Cloudflare bypass probe results
                if !cf_bypass.is_empty() {
                    println!("  {}  Cloudflare origin bypass results:", tc("CFBYPASS", FUJI));
                    let cf_server = cf_bypass.iter().find(|(_, s, _)| !s.is_empty() && !s.contains("cloudflare"));
                    for (header, server, body) in &cf_bypass {
                        let note = if !server.is_empty() && !server.to_lowercase().contains("cloudflare") {
                            format!(" {}", tc(&format!("origin={}", server), HISUI))
                        } else if body.contains("cloudflare") || body.contains("cf-ray") {
                            format!(" {}", tc("(blocked by CF)", TSUYUKUSA))
                        } else {
                            String::new()
                        };
                        if !server.is_empty() || !note.is_empty() {
                            println!("    {} {} {}", tc(&format!("{:<30}", header), TSUYUKUSA), tc(&format!("{:<20}", server), FUJI), note);
                        }
                    }
                    if let Some((header_raw, server, _)) = cf_server {
                        all_findings.push(Finding::new(
                            self.args.target_url(), Severity::Info,
                            &format!("Cloudflare Bypass: origin server = {}", server),
                            &format!("Bypassed via header: {}", header_raw),
                        ));
                    }
                }
            }

            //  Passive recon / fallback for non-Linux 
            if !cfg!(target_os = "linux") || !self.args.active {
            if let Ok(resp) = self.client.get(self.args.target_url()).await {
                let headers: Vec<String> = resp.headers.iter()
                    .map(|(k, v)| format!("{}: {}", k, v))
                    .collect();
                // WAF detection
                if let Some(waf) = self.behavior_analyzer.detect_waf(&headers) {
                    all_findings.push(Finding::new(
                        self.args.target_url(), Severity::Info,
                        &format!("WAF Detected: {}", waf),
                        "A Web Application Firewall is present",
                    ));
                    println!("  WAF    {}", waf);
                }
                // Server fingerprint
                if let Some(server) = resp.server_header() {
                    let f = Finding::new(self.args.target_url(), Severity::Low,
                        &format!("Server Fingerprint: {}", server),
                        "Server version header is exposed",
                    ).with_remediation("Hide server version strings in HTTP response headers");
                    all_findings.push(f);
                    println!("  SERVER {}", server);
                }
                // Framework fingerprint
                if let Some(powered) = resp.powered_by() {
                    all_findings.push(Finding::new(self.args.target_url(), Severity::Low,
                        &format!("Framework Fingerprint: {}", powered),
                        "X-Powered-By header reveals framework information",
                    ));
                    println!("  FRAMEWK {}", powered);
                }
                // Cookie / Set-Cookie
                for (k, v) in &resp.headers {
                    if k.eq_ignore_ascii_case("set-cookie") {
                        let cookie_val = v.split(';').next().unwrap_or(v);
                        println!("  COOKIE  {}", cookie_val);
                    }
                }
                // DB fingerprint
                if !resp.body.is_empty() {
                    let db_patterns = [
                        ("MySQL", "mysql|MariaDB|SQL_MODE"),
                        ("PostgreSQL", "PostgreSQL|psql|PG::"),
                        ("MSSQL", "SQLServer|Microsoft SQL|MSSQL"),
                        ("Oracle", "Oracle|ORA-|PLS-"),
                        ("SQLite", "SQLite|sqlite_"),
                    ];
                    for (name, pattern) in &db_patterns {
                        if let Ok(re) = regex::Regex::new(pattern) {
                            if re.is_match(&resp.body) {
                                all_findings.push(Finding::new(self.args.target_url(), Severity::Info,
                                    &format!("Database Fingerprint: {}", name),
                                    &format!("Database '{}' detected", name),
                                ));
                                println!("  DATABASE {}", name);
                                break;
                            }
                        }
                    }
                }
            }
            }
        }

        // 
        //  PHASE 2: CRAWL — Discover URLs, forms, links, JS endpoints
        //   BFSクロール / BFS web crawl — discovers site structure
        //   Headless Chrome対応 / supports headless Chrome for JS rendering
        // 

        check_timeout!();
        let mut crawled_urls: Vec<String> = Vec::new();
        if !excluded.contains(&"crawl".to_string()) {
            println!("  {} {}  {} {}  {}",
                tc("─", HISUI),
                tc("CRAWL", HISUI).bold(),
                tc("→", TSUYUKUSA),
                tc("Mapping site structure: URLs, forms, scripts, comments", TSUYUKUSA),
                tc(&"─".repeat(32), FUJI));
            let crawl_start = std::time::Instant::now();
            crawled_urls = match self.crawl_phase().await {
                Ok(urls) => urls,
                Err(e) => {
                    println!("  {} CRAWL ERROR  {}", tc("✘", SHU), e);
                    vec![]
                }
            };
            let base_url = Parser::ensure_http(self.args.target_url());
            if !crawled_urls.contains(&base_url) {
                crawled_urls.insert(0, base_url);
            }
            let crawl_elapsed = crawl_start.elapsed();
            println!("  {} Crawl complete: {} URLs  {}",
                tc("[+]", HISUI),
                crawled_urls.len(),
                tc(&format!("[{:02}:{:02}]", crawl_elapsed.as_secs() / 60, crawl_elapsed.as_secs() % 60), TSUYUKUSA));
            println!("  {} {} URLs discovered for scanning",
                tc("[+]", HISUI),
                crawled_urls.len());
        } else {
            crawled_urls.push(Parser::ensure_http(self.args.target_url()));
        }

        //  Adaptive depth: dedup near-duplicate URLs via Levenshtein + set exploitation config
        let (base_payloads, error_threshold, sim_threshold) =
            exploitation_config(self.args.exploitation_level);
        let mut dedup_removed = 0usize;
        if crawled_urls.len() > 1 {
            let before = crawled_urls.len();
            crawled_urls = UrlUtil::dedup_urls(&crawled_urls, sim_threshold);
            dedup_removed = before - crawled_urls.len();
            if dedup_removed > 0 {
                println!("  {} {} near-duplicate URLs deduped via Levenshtein (threshold: {:.0}%)",
                    tc("~", HISUI), dedup_removed, sim_threshold * 100.0);
            }
        }
        let max_payload = base_payloads;

        // Auto-downloader — active when --download flag is set
        let _downloader = if self.args.download {
            use crate::utils::downloader::Downloader;
            let dl = Downloader::new(self.args.target_url());
            println!(
                "  DOWNLOAD  Auto-download enabled → {}",
                tc(&format!("{}", dl.base_dir().display()), TSUYUKUSA)
            );
            Some(dl)
        } else {
            None
        };

        // Initialize zero-day detection only if --zeroday flag is set
        if self.args.zeroday {
            // Load saved baselines from previous scans
            if std::path::Path::new("./zero_day_data").exists() {
                println!("  LOAD     Loading saved zero-day baselines...");
                if let Err(e) = self.load_zero_day_baselines("./zero_day_data").await {
                    println!("    Note: Could not load baselines: {}", e);
                }
            }
        }

        let new_sig = crate::detection::signatures::VulnSignature {
            id: "OXIDE-TEST".to_string(),
            name: "Custom Test Sig".to_string(),
            severity: "Info".to_string(),
            pattern: r"test".to_string(),
            description: "Test signature".to_string(),
            remediation: "None".to_string(),
        };
        self.signature_db.add(new_sig);

        // 
        //  PHASE 3: FUZZING — Fuzz all discovered URLs with payloads
        //   同時ファジングエンジン / concurrent fuzzing engine
        //   SQLi / XSS / LFI / CMDi / NoSQL ペイロード注入 / payload injection
        //   チャンクベース並行アーキテクチャ / chunk-based async architecture
        // 

        check_timeout!();
        if modules.contains(&"all".to_string()) || modules.contains(&"fuzz".to_string()) {
            if !excluded.contains(&"fuzz".to_string()) {
                let fuzz_modules: &[(&str, usize)] = &[
                    ("SQLi",  max_payload.min(8)),
                    ("SQLi-D", (max_payload / 2).max(1).min(4)),
                    ("XSS",   max_payload.min(8)),
                    ("LFI",   max_payload.min(6)),
                    ("CMDi",  (max_payload / 2).max(1).min(4)),
                    ("NoSQL", max_payload.min(6)),
                ];
                let payloads_per_param: usize = fuzz_modules.iter().map(|(_, c)| c).sum();
                let mut url_payload_counts: Vec<usize> = Vec::new();
                for url in &crawled_urls {
                    let n = self.extract_params_from_url(url).len() * payloads_per_param;
                    url_payload_counts.push(n);
                }
                let total_payloads: usize = url_payload_counts.iter().sum();
                println!("  {} {}  {}",
                    tc("┌─", HISUI),
                    tc("FUZZING → Payload injection on all discovered URLs", FUJI),
                    tc(&format!("[level={}, payloads/param={}]", self.args.exploitation_level, max_payload), GIN));
                let fuzz_start = std::time::Instant::now();
                let mut total_detections = 0usize;
                let mut total_errors = 0usize;
                let mut total_requests = 0usize;
                let prog_stop = Arc::new(AtomicBool::new(false));
                let prog_req = Arc::new(AtomicUsize::new(0));
                let prog_det = Arc::new(AtomicUsize::new(0));
                let prog_err = Arc::new(AtomicUsize::new(0));
                let prog_mod = Arc::new(AtomicUsize::new(0));
                let prog_fuzz_url = Arc::new(Mutex::new(String::new()));
                let stdout_lock: Arc<Mutex<()>> = Arc::new(Mutex::new(()));

                if !self.args.verbose {
                    let s = prog_stop.clone();
                    let r = prog_req.clone();
                    let d = prog_det.clone();
                    let e = prog_err.clone();
                    let m = prog_mod.clone();
                    let fu = prog_fuzz_url.clone();
                    let sl = stdout_lock.clone();
                    let total = total_payloads;
                    let start = fuzz_start;
                    let mod_labels: Vec<&str> = fuzz_modules.iter().map(|(l, _)| *l).collect();
                    const WAVE_CHARS: &[char] = &['▁','▂','▃','▄','▅','▆','▇','█'];
                    const WAVE_COLORS: [(u8,u8,u8); 5] = [
                        (46,169,223), (46,169,223), (46,169,223), (46,169,223), (46,169,223)
                    ];
                    const PINK: (u8,u8,u8) = (254,223,225);
                    const WHITE: (u8,u8,u8) = (235,230,240);
                    const LAVENDER: (u8,u8,u8) = (159,144,186);
                    const GRAY: (u8,u8,u8) = (145,152,159);
                    const METER_FILLED: &str = "┻";
                    const METER_BREACH: &str = "┳";
                    const METER_EMPTY: &str = "·";
                    const WAVE: [[usize; 5]; 12] = [
                        [0,1,2,4,7], [1,2,4,7,4], [2,4,7,4,2], [4,7,4,2,1],
                        [7,4,2,1,0], [4,2,1,0,1], [2,1,0,1,2], [1,0,1,2,4],
                        [0,1,2,4,7], [1,2,4,7,4], [2,4,7,4,2], [4,7,4,2,1],
                    ];
                    tokio::spawn(async move {
                        let mut frame_idx = 0usize;
                        let mut first_render = true;
                        loop {
                            tokio::time::sleep(Duration::from_millis(150)).await;
                            if s.load(Ordering::Relaxed) { break; }
                            let req = r.load(Ordering::Relaxed);
                            let det = d.load(Ordering::Relaxed);
                            let err = e.load(Ordering::Relaxed);
                            let mod_idx = m.load(Ordering::Relaxed).min(mod_labels.len().saturating_sub(1));
                            let _cur_fuzz = fu.lock().unwrap_or_else(|e| e.into_inner()).clone();
                            let elapsed = start.elapsed();
                            let pct = if total > 0 { req as f64 / total as f64 } else { 0.0 };
                            let _rate = if elapsed.as_secs_f64() > 0.0 { req as f64 / elapsed.as_secs_f64() } else { 0.0 };

                            let _lock = sl.lock().unwrap_or_else(|e| e.into_inner());
                            if !first_render {
                                print!("\x1B[2A");
                            }
                            first_render = false;

                            let wave_phase = frame_idx % 12;
                            frame_idx += 1;
                            let pulse = (frame_idx / 3) % 2 == 0;
                            let wave_str: String = WAVE[wave_phase].iter().enumerate()
                                .map(|(col, &h)| tc(&WAVE_CHARS[h].to_string(), WAVE_COLORS[col]))
                                .collect::<Vec<_>>()
                                .join("");

                            let bar_total = total.max(1);
                            let filled = (req as f64 / bar_total as f64 * 10.0) as usize;
                            let pulse_idx = (frame_idx / 2) % 4;
                            let mut bar = String::new();
                            for i in 0..10 {
                                if i < filled {
                                    bar.push_str(&tc(METER_FILLED, PINK));
                                } else if i == filled {
                                    let c = if pulse_idx < 2 { WHITE } else { LAVENDER };
                                    bar.push_str(&tc(METER_BREACH, c));
                                } else {
                                    bar.push_str(&tc(METER_EMPTY, GRAY));
                                }
                            }

                            let pip: String = {
                                let mut parts = Vec::new();
                                for (i, l) in mod_labels.iter().enumerate() {
                                    if i > 0 {
                                        let sep = if i == mod_idx && pulse {
                                            tc(" ›› ", HISUI)
                                        } else {
                                            tc(" › ", TSUYUKUSA)
                                        };
                                        parts.push(sep);
                                    }
                                    if i == mod_idx {
                                        parts.push(tc(l, HISUI));
                                    } else {
                                        parts.push(tc(l, TSUYUKUSA));
                                    }
                                }
                                parts.concat()
                            };

                            let total_disp = if total >= 1_000_000 {
                                format!("{:.1}M", total as f64 / 1_000_000.0)
                            } else if total >= 1_000 {
                                format!("{:.1}K", total as f64 / 1_000.0)
                            } else {
                                total.to_string()
                            };

                            let det_s = if det > 0 {
                                tc(&format!("^{} DET", det), HISUI)
                            } else {
                                tc("^0 DET", GIN)
                            };
                            let err_s = if err > 0 {
                                tc(&format!("~{} ERR", err), SHU)
                            } else {
                                tc("~0 ERR", GIN)
                            };

                            let secs = elapsed.as_secs_f64();
                            println!("\r\x1B[2K {} {} {}  {}  {} req:{} tot:{} {} {} {}",
                                tc("\u{2503}", GIN),
                                wave_str,
                                bar,
                                pip,
                                tc(&format!("{:>5.1}%", pct * 100.0), TSUYUKUSA),
                                tc(&req.to_string(), SHU),
                                tc(&total_disp, GIN),
                                det_s,
                                err_s,
                                tc(&format!("{:>5.1}s", secs), GIN));

                            let cur_fuzz_disp = if _cur_fuzz.len() > 65 {
                                format!("{}…", &_cur_fuzz[.._cur_fuzz.floor_char_boundary(64)])
                            } else {
                                _cur_fuzz.clone()
                            };
                            let arrow_idx = (frame_idx / 2) % 6;
                            let arrow = match arrow_idx {
                                0 => tc(">   ", TSUYUKUSA),
                                1 => tc(">>  ", TSUYUKUSA),
                                2 => tc(">>> ", TSUYUKUSA),
                                3 => tc(">>>>", TSUYUKUSA),
                                4 => tc(">>> ", TSUYUKUSA),
                                _ => tc(">>  ", TSUYUKUSA),
                            };
                            println!("\r\x1B[2K  {} {}",
                                arrow,
                                tc(&cur_fuzz_disp, WAKABA));

                            let _ = std::io::Write::flush(&mut std::io::stdout());
                            drop(_lock);
                        }
                    });
                }

                use futures::future::join_all;

                // 
                //  CONCURRENT FUZZING ENGINE — chunk-based async architecture
                //
                //  crawled_urls.chunks(6) splits the URL list into blocks of 6,
                //  fuzz_url() tests all payload types on one URL asynchronously,
                //  join_all(futs) waits for all 6 parallel requests to complete.
                //  Results are collected, detections + errors are summed.
                //
                //  Adaptive depth: errors per depth level tracked; if errors at a
                //  depth exceed the exploitation_level threshold, remaining URLs at
                //  that depth are skipped to avoid wasted requests.
                // 

                let concurrency = 6usize;
                let mut depth_errors: std::collections::HashMap<usize, usize> =
                    std::collections::HashMap::new();
                for chunk in crawled_urls.chunks(concurrency) {
                    check_timeout!();

                    // Filter chunk by depth error threshold
                    let filtered: Vec<&String> = chunk.iter().filter(|url| {
                        let d = url_depth(url);
                        let errs = depth_errors.get(&d).copied().unwrap_or(0);
                        if errs >= error_threshold {
                            if self.args.verbose {
                                println!("  {} depth {} rejected ({} errors ≥ {} threshold)",
                                    tc("~", HISUI), d, errs, error_threshold);
                            }
                            false
                        } else {
                            true
                        }
                    }).collect();

                    if filtered.is_empty() { continue; }

                    if self.args.verbose {
                        for url in filtered.iter() {
                            println!("  {} {}  {}",
                                tc("-->>", TSUYUKUSA),
                                tc("SCANNING", HISUI),
                                tc(url, FUJI));
                        }
                    }

                    let futs: Vec<_> = filtered.iter().map(|url| {
                        self.fuzz_url(url, &prog_req, &prog_mod, &prog_fuzz_url,
                                      &stdout_lock, &prog_det, &prog_err,
                                      start, duration_limit)
                    }).collect();

                    let results = join_all(futs).await;

                    for (result, url) in results.into_iter().zip(filtered.iter()) {
                        let d = url_depth(url);
                        match result {
                            Ok((fuzz_findings, err_count, req_count)) => {
                                let det_count = fuzz_findings.len();
                                total_detections += det_count;
                                total_errors += err_count;
                                total_requests += req_count;
                                prog_det.store(total_detections, Ordering::Relaxed);
                                prog_err.store(total_errors, Ordering::Relaxed);
                                all_findings.extend(fuzz_findings);
                                // Track errors from fuzz_url return value
                                if err_count > 0 {
                                    let e = depth_errors.entry(d).or_insert(0);
                                    *e += err_count;
                                }
                            }
                            Err(e) => {
                                let ecount = depth_errors.entry(d).or_insert(0);
                                *ecount += 1;
                                total_errors += 1;
                                prog_err.fetch_add(1, Ordering::Relaxed);
                                if self.args.verbose {
                                    eprintln!("  {} Error fuzzing {}: {}",
                                        tc("ERR", SHU), url, e);
                                }
                            }
                        }
                    }
                }
                prog_stop.store(true, Ordering::Relaxed);
                if !self.args.verbose {
                    let _lock = stdout_lock.lock().unwrap_or_else(|e| e.into_inner());
                    print!("\r\x1B[2K\n\x1B[2K\n\x1B[2K");
                    let _ = std::io::Write::flush(&mut std::io::stdout());
                    drop(_lock);
                }
                if dedup_removed > 0 {
                    println!("  {} {} near-duplicates collapsed (Levenshtein >{:.0}%)",
                        tc("~", HISUI), dedup_removed, sim_threshold * 100.0);
                }
                let fuzz_elapsed = fuzz_start.elapsed();
                println!("  {} Fuzzing complete: {} URLs, {} req, {} detections, {} errors  {}",
                    tc("[+]", HISUI),
                    crawled_urls.len(),
                    tc(&total_requests.to_string(), TSUYUKUSA),
                    tc(&total_detections.to_string(), HISUI),
                    tc(&total_errors.to_string(), SHU),
                    tc(&format!("[{:02}:{:02}]", fuzz_elapsed.as_secs() / 60, fuzz_elapsed.as_secs() % 60), TSUYUKUSA));
            }
        }

        // 
        //  PHASE 4: VULNERABILITY SCANNING — SQLi, XSS, LFI, CMDi
        //   専用スキャナー / dedicated per-vuln scanners
        //   ファジング済みの場合はスキップ（重複防止）
        //   skipped if fuzzing already ran (avoids duplicate findings)
        //
        //  NOTE: If fuzzing was already run (--fuzz or --all), the dedicated
        //  scanners below are skipped to avoid duplicate findings («two shows
        //  vulns» bug). Fuzzing already tested all payload types on all URLs
        //  via the concurrent chunk-based architecture.
        // 

        check_timeout!();
        // SQL Injection Scan
        if modules.contains(&"all".to_string()) || modules.contains(&"sqli".to_string()) {
            if !excluded.contains(&"sqli".to_string()) {
                let ph_stop = Arc::new(AtomicBool::new(false));
                let ph_lines = Arc::new(AtomicUsize::new(1));
                if !self.args.verbose {
                    let frame = oxide::scanner::precision::bidir_braille(0);
                    println!("  {}{}{}  {}", tc("[+]", HISUI), tc(frame, FUJI), tc("SQLi", HISUI), tc("Testing SQL injection on all URLs", FUJI));
                    let s = ph_stop.clone();
                    let lb = ph_lines.clone();
                    tokio::spawn(async move {
                        let mut idx = 1usize;
                        loop {
                            tokio::time::sleep(Duration::from_millis(120)).await;
                            if s.load(Ordering::Relaxed) { break; }
                            let n = lb.load(Ordering::Relaxed);
                            let frame = oxide::scanner::precision::bidir_braille(idx);
                            idx += 1;
                            print!("\x1B[{}A\r\x1B[2K  {}{}{}  {}\n", n, tc("[+]", HISUI), tc(frame, FUJI), tc("SQLi", HISUI), tc("Testing SQL injection on all URLs", FUJI));
                            if n > 1 { print!("\x1B[{}B", n - 1); }
                            let _ = std::io::Write::flush(&mut std::io::stdout());
                        }
                    });
                } else {
                    print_phase_sub("SQLi", "Testing SQL injection on all URLs");
                }
                let mut sqli_scanner = SqlInjectionScanner::new(
                    self.client.clone(), self.args.target_url().to_string(), self.args.exploitation_level, self.args.silent_mode
                );
                for url in crawled_urls.iter().take(self.args.payload_limit) {
                    if !self.args.verbose {
                        println!("  {} {}", tc("->", TSUYUKUSA), url);
                        ph_lines.fetch_add(1, Ordering::Relaxed);
                    }
                    let params = self.extract_params_from_url(url);
                    if let Ok(findings) = sqli_scanner.comprehensive_scan(url, &params).await {
                        for finding in findings {
                            let f = self.convert_finding(&finding);
                            if !self.args.verbose {
                                println!("  {} {}  {}", fmt_sev_label(&f.severity), f.title, tc(url, TSUYUKUSA));
                                ph_lines.fetch_add(1, Ordering::Relaxed);
                            } else {
                                println!("  SQLi  {}  {}", f.title, tc(url, TSUYUKUSA));
                            }
                            all_findings.push(f);
                        }
                    }
                }
                ph_stop.store(true, Ordering::Relaxed);
                let n = ph_lines.load(Ordering::Relaxed);
                if !self.args.verbose && n > 0 {
                    print!("\x1B[{}A\r\x1B[2K", n);
                }
                println!("  {} SQLi scan complete", tc("[+]", HISUI));
            }
        }

        // XSS Scan
        if modules.contains(&"all".to_string()) || modules.contains(&"xss".to_string()) {
            if !excluded.contains(&"xss".to_string()) {
                let ph_stop = Arc::new(AtomicBool::new(false));
                let ph_lines = Arc::new(AtomicUsize::new(1));
                if !self.args.verbose {
                    let frame = oxide::scanner::precision::bidir_braille(0);
                    println!("  {}{}{}  {}", tc("[+]", HISUI), tc(frame, FUJI), tc("XSS", HISUI), tc("Testing cross-site scripting on all URLs", FUJI));
                    let s = ph_stop.clone();
                    let lb = ph_lines.clone();
                    tokio::spawn(async move {
                        let mut idx = 1usize;
                        loop {
                            tokio::time::sleep(Duration::from_millis(120)).await;
                            if s.load(Ordering::Relaxed) { break; }
                            let n = lb.load(Ordering::Relaxed);
                            let frame = oxide::scanner::precision::bidir_braille(idx);
                            idx += 1;
                            print!("\x1B[{}A\r\x1B[2K  {}{}{}  {}\n", n, tc("[+]", HISUI), tc(frame, FUJI), tc("XSS", HISUI), tc("Testing cross-site scripting on all URLs", FUJI));
                            if n > 1 { print!("\x1B[{}B", n - 1); }
                            let _ = std::io::Write::flush(&mut std::io::stdout());
                        }
                    });
                } else {
                    print_phase_sub("XSS", "Testing cross-site scripting on all URLs");
                }
                let mut xss_scanner = XssScanner::new(
                    self.client.clone(), self.args.target_url().to_string()
                );
                for url in crawled_urls.iter().take(self.args.payload_limit) {
                    if !self.args.verbose {
                        println!("  {} {}", tc("->", TSUYUKUSA), url);
                        ph_lines.fetch_add(1, Ordering::Relaxed);
                    }
                    let params = self.extract_params_from_url(url);
                    if let Ok(findings) = xss_scanner.comprehensive_scan(url, &params).await {
                        for finding in findings {
                            let f = self.convert_finding(&finding);
                            if verbose {
                                println!("  XSS   {}  {}", f.title, tc(url, TSUYUKUSA));
                            }
                            all_findings.push(f);
                        }
                    }
                }
                ph_stop.store(true, Ordering::Relaxed);
                let n = ph_lines.load(Ordering::Relaxed);
                if !self.args.verbose && n > 0 {
                    print!("\x1B[{}A\r\x1B[2K", n);
                }
                println!("  {} XSS scan complete", tc("[+]", HISUI));
            }
        }

        // LFI Scan
        if modules.contains(&"all".to_string()) || modules.contains(&"lfi".to_string()) {
            if !excluded.contains(&"lfi".to_string()) {
                let ph_stop = Arc::new(AtomicBool::new(false));
                let ph_lines = Arc::new(AtomicUsize::new(1));
                if !self.args.verbose {
                    let frame = oxide::scanner::precision::bidir_braille(0);
                    println!("  {}{}{}  {}", tc("[+]", HISUI), tc(frame, FUJI), tc("LFI", HISUI), tc("Testing local file inclusion on all URLs", FUJI));
                    let s = ph_stop.clone();
                    let lb = ph_lines.clone();
                    tokio::spawn(async move {
                        let mut idx = 1usize;
                        loop {
                            tokio::time::sleep(Duration::from_millis(120)).await;
                            if s.load(Ordering::Relaxed) { break; }
                            let n = lb.load(Ordering::Relaxed);
                            let frame = oxide::scanner::precision::bidir_braille(idx);
                            idx += 1;
                            print!("\x1B[{}A\r\x1B[2K  {}{}{}  {}\n", n, tc("[+]", HISUI), tc(frame, FUJI), tc("LFI", HISUI), tc("Testing local file inclusion on all URLs", FUJI));
                            if n > 1 { print!("\x1B[{}B", n - 1); }
                            let _ = std::io::Write::flush(&mut std::io::stdout());
                        }
                    });
                } else {
                    print_phase_sub("LFI", "Testing local file inclusion on all URLs");
                }
                let mut lfi_scanner = LFIScanner::new(
                    self.client.clone(), self.args.exploitation_level
                );
                for url in crawled_urls.iter().take(self.args.payload_limit) {
                    if !self.args.verbose {
                        println!("  {} {}", tc("->", TSUYUKUSA), url);
                        ph_lines.fetch_add(1, Ordering::Relaxed);
                    }
                    for param in self.extract_params_from_url(url) {
                        if let Ok(results) = lfi_scanner.exploit_lfi(url, &param).await {
                            for result in results {
                                if result.success {
                                    let sev = if result.file_read { Severity::Critical } else { Severity::High };
                                    let f = Finding::new(url, sev,
                                        &format!("LFI: {}", result.technique),
                                        &format!("Payload: {}\nFile Read: {}", result.payload, result.file_read),
                                    ).with_evidence(&result.response);
                                    if verbose {
                                        println!("  LFI   {} via param `{}`  {}", result.technique, param, tc(url, TSUYUKUSA));
                                    }
                                    all_findings.push(f);
                                }
                            }
                        }
                    }
                }
                ph_stop.store(true, Ordering::Relaxed);
                let n = ph_lines.load(Ordering::Relaxed);
                if !self.args.verbose && n > 0 {
                    print!("\x1B[{}A\r\x1B[2K", n);
                }
                println!("  {} LFI scan complete", tc("[+]", HISUI));
            }
        }

        // 
        //  PHASE 5: TLS/SSL ASSESSMENT
        //   TLS証明書・暗号スイート評価 / TLS certificate & cipher assessment
        // 

        check_timeout!();
        if modules.contains(&"all".to_string()) || modules.contains(&"tls".to_string()) {
            if !excluded.contains(&"tls".to_string()) {
                print_phase_banner("TLS", "TLS/SSL security assessment");
                let tls_scanner = TlsScanner::new(120)?;
                let tls_findings = tls_scanner.scan(self.args.target_url()).await;
                for finding in tls_findings {
                    let sev = match finding.severity {
                        TlsSeverity::Critical => Severity::Critical,
                        TlsSeverity::High     => Severity::High,
                        TlsSeverity::Medium   => Severity::Medium,
                        TlsSeverity::Low      => Severity::Low,
                        TlsSeverity::Info     => Severity::Info,
                    };
                    println!("  {} {} {}",
                        fmt_sev_label(&sev), finding.title, tc(&format!("| {}", finding.evidence), TSUYUKUSA));
                    all_findings.push(Finding::new(self.args.target_url(), sev, &finding.title, &finding.description)
                        .with_evidence(&finding.evidence).with_remediation(&finding.remediation));
                }
                println!("  {} TLS assessment complete", tc("[+]", HISUI));
            }
        }

        // 
        //  PHASE 6: CORS MISCONFIGURATION SCAN
        //   CORS電脳設定ミス電脳検出 / CORS misconfiguration detection
        // 

        check_timeout!();
        if modules.contains(&"all".to_string()) || modules.contains(&"cors".to_string()) {
            if !excluded.contains(&"cors".to_string()) {
                print_phase_banner("CORS", "Cross-Origin Resource Sharing assessment");
                let cors_scanner = CorsScanner::new(120)?;
                let cors_findings = cors_scanner.scan(self.args.target_url()).await;
                for finding in cors_findings {
                    let sev = match finding.severity {
                        CorsSeverity::Critical => Severity::Critical,
                        CorsSeverity::High     => Severity::High,
                        CorsSeverity::Medium   => Severity::Medium,
                        CorsSeverity::Low      => Severity::Low,
                    };
                    println!("  {} {} {}",
                        fmt_sev_label(&sev), finding.title, tc(&format!("| {}", finding.evidence), TSUYUKUSA));
                    all_findings.push(Finding::new(self.args.target_url(), sev, &finding.title, &finding.description)
                        .with_evidence(&finding.evidence).with_remediation(&finding.remediation));
                }
                println!("  {} CORS assessment complete", tc("[+]", HISUI));
            }
        }

        // 
        //  PHASE 7: COMMON PATHS + DEFAULT CREDS + CONTENT FILTER
        //   Niktoスタイル共通パスプローブ / Nikto-style common path probing
        //   デフォルト認証情報テスト / default credentials testing
        // 

        check_timeout!();
        // Common application paths (Nikto-style)
        if modules.contains(&"all".to_string()) || modules.contains(&"common".to_string()) {
            if !excluded.contains(&"common".to_string()) {
                print_phase_sub("COMMON", "Probing common application paths");
                if let Ok(common_scanner) = CommonAppScanner::new(120) {
                    let common_findings = common_scanner.scan(self.args.target_url(), self.args.download).await;
                    for finding in common_findings {
                        let sev = match finding.severity {
                            CommonAppSeverity::Critical => Severity::Critical,
                            CommonAppSeverity::High     => Severity::High,
                            CommonAppSeverity::Medium   => Severity::Medium,
                            CommonAppSeverity::Low      => Severity::Low,
                            CommonAppSeverity::Info     => Severity::Info,
                        };
                        if verbose {
                            println!("  {} {} {}", fmt_sev_label(&sev), finding.title, tc(&finding.url, TSUYUKUSA));
                        }
                        all_findings.push(Finding::new(&finding.url, sev, &finding.title, &finding.description)
                            .with_evidence(&finding.evidence));
                    }
                }
                println!("  {} Common app scan complete", tc("[+]", HISUI));
            }
        }

        // Default credentials test
        if modules.contains(&"all".to_string()) || modules.contains(&"creds".to_string()) {
            if !excluded.contains(&"creds".to_string()) {
                print_phase_sub("CREDS", "Testing default credentials");
                if let Ok(creds_scanner) = DefaultCredsScanner::new(120) {
                    let creds_findings = creds_scanner.scan(self.args.target_url()).await;
                    for finding in creds_findings {
                        let sev = match finding.severity {
                            CredsSeverity::Critical => Severity::Critical,
                            CredsSeverity::High     => Severity::High,
                            CredsSeverity::Medium   => Severity::Medium,
                        };
                        if verbose {
                            println!("  {} {} {}", fmt_sev_label(&sev), finding.application, tc(&format!("{}:{}@{}", finding.username, finding.password, finding.url), TSUYUKUSA));
                        }
                        all_findings.push(Finding::new(&finding.url, sev,
                            &format!("Default Credentials: {}", finding.application),
                            &format!("App: {}\nUser: {}\nPass: {}", finding.application, finding.username, finding.password),
                        ).with_evidence(&finding.evidence).with_remediation(&finding.remediation));
                    }
                }
                println!("  {} Credential scan complete", tc("[+]", HISUI));
            }
        }

        // Parameter Discovery
        if modules.contains(&"all".to_string()) || modules.contains(&"parameter-discovery".to_string()) {
            if !excluded.contains(&"parameter-discovery".to_string()) {
                let unique_params = self.extract_params_from_urls(&crawled_urls);
                println!("  PARAMS  {} unique parameters across {} URLs", unique_params.len(), crawled_urls.len());
                for param in &unique_params {
                    all_findings.push(Finding::new(self.args.target_url(), Severity::Info,
                        &format!("Parameter: {}", param),
                        &format!("Discovered parameter '{}'", param),
                    ));
                }
            }
        }

        // 
        //  PHASE 8: CONTENT FILTER + ML ANOMALY DETECTION
        //   機密データフィルター / sensitive data content filter
        //   Instagram OSINT / Instagram open-source intelligence
        //   セッションハイジャックテスト / session hijack testing
        //   MLゼロデイ異常検知 / ML-based zero-day anomaly detection
        //   静的パス電脳走査 / static path scanning
        //   エージェントベース並列電脳走査 / agent-based parallel scan
        //   重複排除 + 偽陽性フィルタリング / dedup + false positive reduction
        // 

        check_timeout!();
        // Hybrid Content Filter - dynamic sensitive data detection
        if modules.contains(&"all".to_string()) || modules.contains(&"filter".to_string()) {
            if !excluded.contains(&"filter".to_string()) {
                print_phase_sub("FILTER", "Dynamic content analysis for sensitive data");
                let mut filter_hits = 0;
                for url in &crawled_urls {
                    if let Ok(resp) = self.client.get(url).await {
                        // Pattern-based detection for sensitive data
                        let patterns: Vec<(&str, &str)> = vec![
                            (r"(?i)-----BEGIN.*KEY-----", "Private Key"),
                            (r#"(?i)api[_-]?key["']?\s*[:=]\s*["'][^"']+["']"#, "API Key"),
                            (r"(?i)sk_live_[0-9a-zA-Z]+", "Stripe Live Key"),
                            (r"(?i)AKIA[0-9A-Z]{16}", "AWS Access Key"),
                            (r#"(?i)password\s*[:=]\s*[^\s,;"']{6,}"#, "Exposed Password"),
                            (r#"(?i)token\s*[:=]\s*["'][^"']{16,}["']"#, "Exposed Token"),
                        ];
                        if verbose {
                            println!("  {}", tc(&format!("Scanning {} for secrets...", url), TSUYUKUSA));
                        }
                        for (pattern, label) in &patterns {
                            if let Ok(re) = regex::Regex::new(pattern) {
                                if re.is_match(&resp.body) {
                                    all_findings.push(Finding::new(url, Severity::High,
                                        &format!("Sensitive Data: {}", label),
                                        &format!("Pattern '{}' matched in response", label),
                                    ).with_evidence(&format!("Matched on {}", url)));
                                    filter_hits += 1;
                                }
                            }
                        }
                    }
                }
                println!("  {} Filter complete: {} hits", tc("[+]", HISUI), filter_hits);
            }
        }

        // Instagram OSINT
        if modules.contains(&"all".to_string()) || modules.contains(&"insta".to_string()) {
            if !excluded.contains(&"insta".to_string()) {
                print_phase_banner("INSTA", "Instagram OSINT — follower count, privacy check, media download");
                match oxide::insta::InstaOSINT::new(120, false) {
                    Ok(insta) => {
                        match insta.full_scan(self.args.target_url()).await {
                            Ok(insta_findings) => {
                                for f in &insta_findings {
                                    println!("  {} {} {}",
                                        fmt_sev_label(&f.severity), f.title, tc(&format!("| {}", f.evidence), TSUYUKUSA));
                                }
                                all_findings.extend(insta_findings);
                            }
                            Err(e) => println!("  {} Instagram scan failed: {}", tc("[!]", SHU), e),
                        }
                    }
                    Err(e) => println!("  {} Failed to initialize Instagram scanner: {}", tc("[!]", SHU), e),
                }
                println!("  {} Instagram OSINT complete", tc("[+]", HISUI));
            }
        }

        // Session Hijack Testing
        if modules.contains(&"all".to_string()) || modules.contains(&"session".to_string()) {
            if !excluded.contains(&"session".to_string()) {
                print_phase_banner("SESSION", "Session hijack testing — cookie flags, fixation, predictability");
                match oxide::session_hijack::SessionHijackTester::new(120, self.args.insecure) {
                    Ok(tester) => {
                        match tester.full_test(self.args.target_url()).await {
                            Ok(session_findings) => {
                                for f in &session_findings {
                                    println!("  {} {} {}",
                                        fmt_sev_label(&f.severity), f.title, tc(&format!("| {}", f.evidence), TSUYUKUSA));
                                }
                                all_findings.extend(session_findings);
                            }
                            Err(e) => println!("  {} Session test failed: {}", tc("[!]", SHU), e),
                        }
                    }
                    Err(e) => println!("  {} Failed to initialize session tester: {}", tc("[!]", SHU), e),
                }
                println!("  {} Session hijack assessment complete", tc("[+]", HISUI));
            }
        }

        // ML-Based Zero-Day Detection
        if modules.contains(&"all".to_string()) || modules.contains(&"zero-day".to_string()) || self.args.zeroday {
            if !excluded.contains(&"zero-day".to_string()) {
                print_phase_sub("ML", "Zero-day anomaly detection");
                let ml_findings = self.run_ml_detection(&crawled_urls).await?;
                let ml_count = ml_findings.len();
                all_findings.extend(ml_findings);
                println!("  {} ML detection complete: {} anomalies", tc("[+]", HISUI), ml_count);
            }
        }

        // Static path scanning
        if modules.contains(&"all".to_string()) || modules.contains(&"static".to_string()) {
            if !excluded.contains(&"static".to_string()) {
                let static_findings = self.scan_static_paths().await?;
                all_findings.extend(static_findings);
            }
        }

        // Agent-based parallel scan
        check_timeout!();
        if modules.contains(&"all".to_string()) || modules.contains(&"agent".to_string()) {
            if !excluded.contains(&"agent".to_string()) {
                print_phase_sub("AGENT", "Agent-based parallel vulnerability scan");
                let agent_findings = self.scan_with_agents(crawled_urls.clone()).await?;
                all_findings.extend(agent_findings);
                println!("  {} Agent scan complete", tc("[+]", HISUI));
            }
        }

        // Parallel vulnerability scan (ScanBoard)
        check_timeout!();
        {
            use crate::core::worker::ParallelScanner;
            use crate::cli::display::ScanBoard;

            let worker_count = self.args.threads.min(8).max(1);
            let board = ScanBoard::new(worker_count);
            println!("\n  PARALLEL  Phase 5 — {} workers, {} URLs", worker_count, crawled_urls.len());
            let scanner = ParallelScanner::new(self.client.clone(), self.args.clone(), worker_count);
            let phase_findings = scanner.run(crawled_urls.clone(), board).await;
            all_findings.extend(phase_findings);
        }

        // Body scanning
        check_timeout!();
        if !excluded.contains(&"body".to_string()) {
            let body_payloads = self.fuzzer.generate_sql_payloads();
            let _ = self.scanner.scan_body(&body_payloads).await;
        }

        // 
        //  Deduplication: remove duplicate findings before final filtering.
        //   重複排除 / deduplicates by (URL + severity + title)
        //   異なるモジュールからの同一電脳検出を防止 / prevents «two shows vulns» bug
        //  Key: (URL + severity + title) — identical findings from different
        //  modules would cause the «two shows vulns» bug.
        // 
        {
            let mut seen = std::collections::HashSet::new();
            all_findings.retain(|f| {
                let key = (f.url.clone(), format!("{:?}", f.severity), f.title.clone());
                seen.insert(key)
            });
        }

        // Filter false positives — AFTER all findings collected
        let confirmed_findings = Confirm::reduce_false_positive(all_findings);
        println!("Confirmed findings after filtering: {} (the real treasures!)", confirmed_findings.len());

        // Format final duration
        let final_elapsed = TimeUtil::elapsed_since(start);
        let final_duration = TimeUtil::format_duration(final_elapsed);
        
        // Funny completion messages
        let completion_quips = vec![
            "Scan time: {}. Time well spent!",
            "Scan time: {}. That was faster than compiling Rust!",
            "Scan time: {}. Your security team owes you a beer!",
        ];
        let quip_idx = (TimeUtil::unix_timestamp() as usize) % completion_quips.len();
        println!("  DONE    {}", completion_quips[quip_idx].replace("{}", &final_duration));

        self.findings = confirmed_findings.clone();

        // Generate HTML report if output specified
        if self.args.output.is_some() {
            let html_output = HtmlReport::generate_header(
                "OXIDE Scan Report",
                self.args.target_url(),
                "",
                &final_duration,
                0,
            );
            let html_table_start = HtmlReport::generate_table_start();
            let html_table_end = HtmlReport::generate_table_end();
            let html_footer = HtmlReport::generate_footer();
            let full_html = format!("{}{}{}{}", html_output, html_table_start, html_table_end, html_footer);
            println!("HTML report generated: {} bytes", full_html.len());
        }

        Ok(confirmed_findings)
    }

    //  クロールフェーズ / crawl phase — delegates to WebCrawler or HeadlessCrawler
    //  結果からURL・フォーム・コメント・スクリプトエンドポイントを収集
    //  collects URLs, forms, comments, script endpoints from crawl results
    async fn crawl_phase(&mut self) -> Result<Vec<String>> {
        let result = if let Some(ref mut hc) = self.headless_crawler {
            println!("  {} {}",
                tc("◆", HISUI),
                tc("Headless Chrome crawling enabled — real JS rendering", TSUYUKUSA));
            hc.crawl(self.args.target_url()).await?
        } else if let Some(ref mut wc) = self.crawler {
            wc.crawl(self.args.target_url()).await?
        } else {
            return Err(anyhow::anyhow!("No crawler initialized"));
        };

        let mut urls: Vec<String> = result.urls.iter()
            .chain(result.all_linked_urls.iter())
            .cloned()
            .collect();

        // Scan HTML comments for leaked credentials / internal paths
        let suspicious = result.suspicious_comments();
        if !suspicious.is_empty() {
            println!("  ! {} suspicious HTML comments found:", suspicious.len());
            for (comment, reason) in suspicious.iter().take(5) {
                let preview: String = comment.chars().take(80).collect();
                println!("      [{}] {}", reason, preview);
            }
        }

        // Extract API endpoints from inline scripts
        let script_eps = result.script_endpoints();
        if !script_eps.is_empty() {
            println!("  JS    {} API endpoints found in scripts", script_eps.len());
        }

        let post_forms = result.get_forms_by_method("POST");
        if !post_forms.is_empty() {
            println!("  Found {} POST forms", post_forms.len());
            for form in &post_forms {
                println!("    Form at {} -> {}", form.url, form.action);
                for input in &form.inputs {
                    println!("      Input: {} (type: {})", input.name, input.input_type);
                }
            }
        }

        // Use get_all_link_texts from result
        let all_texts = result.get_all_link_texts();
        if !all_texts.is_empty() {
            println!("  Link texts count: {}", all_texts.len());
        }

        let forms = &result.forms;

        for form in forms {
            urls.push(form.url.clone());
            urls.push(form.action.clone());
            for input in &form.inputs {
                let value_str = match &input.value {
                    Some(v) => format!("={}", v),
                    None => "".to_string(),
                };
                println!("    Form input: {} (type: {}){}", input.name, input.input_type, value_str);
            }
        }

        urls.sort();
        urls.dedup();

        let script_eps = result.script_endpoints();
        for ep in script_eps {
            if ep.starts_with('/') {
                if let Ok(base) = url::Url::parse(self.args.target_url()) {
                    if let Ok(full) = base.join(&ep) {
                        urls.push(full.to_string());
                    }
                }
            }
        }
        urls.sort();
        urls.dedup();

        // Levenshtein dedup to hide near-duplicate URLs from display
        let (_, _, sim_threshold) = exploitation_config(self.args.exploitation_level);
        let before = urls.len();
        urls = UrlUtil::dedup_urls(&urls, sim_threshold);
        let removed = before - urls.len();

        let form_count = result.forms.len();
        let link_count = result.all_linked_urls.len();
        if removed > 0 {
            println!("  {} {} near-duplicates collapsed (Levenshtein >{:.0}%)",
                tc("~", HISUI), removed, sim_threshold * 100.0);
        }
        // Show global totals once, then list unique URLs
        println!("  {} {} forms, {} links, {} unique URLs",
            tc("[+]", GIN),
            form_count,
            link_count,
            urls.len());
        for url in &urls {
            let disp = if url.len() > 60 {
                format!("{}…", &url[..url.floor_char_boundary(59)])
            } else {
                url.clone()
            };
            println!("  {} depth:{}  {}",
                tc("[*]", HISUI),
                tc(&url_depth(url).to_string(), GIN),
                tc(&disp, FUJI));
        }

        Ok(urls)
    }

    //  WAF応答電脳検出 / WAF response detection — 403/503/429 + CF/cloudflare/ddos keywords
    fn is_waf_response(body: &str, status: u16) -> bool {
        let b = body.to_lowercase();
        (status == 403 || status == 503 || status == 429) &&
        (b.contains("cf-ray") || b.contains("cloudflare") ||
         b.contains("attention required") || b.contains("security check") ||
         b.contains("ddos") || b.contains("waf") &&
         (b.contains("blocked") || b.contains("denied")))
    }

    //  XSS反射電脳検出 / XSS reflection detection — payload appears in response but not baseline
    fn contains_xss(body: &str, baseline_body: &str, payload: &str) -> bool {
        if Self::is_waf_response(body, 200) { return false; }
        // Real XSS: the exact XSS payload appears after injection but NOT in baseline.
        // This means the server reflected our payload without proper sanitization.
        if baseline_body.contains(payload) { return false; }
        body.contains(payload)
    }

    //  LFI電脳検出 / LFI detection — /etc/passwd content appears in response but not baseline
    fn contains_lfi(body: &str, baseline_body: &str) -> bool {
        if Self::is_waf_response(body, 200) { return false; }
        if baseline_body.is_empty() { return false; }
        // Check for password file evidence ONLY if it's new in the injected response
        let injected = body.to_lowercase();
        let baseline = baseline_body.to_lowercase();
        let lfi_signals = [
            "root:x:0:0", "root:$1$", "daemon:x:", "bin:x:",
            "nobody:x:", "sshd:x:", "mysql:x:", "www-data:x:",
        ];
        for sig in &lfi_signals {
            if injected.contains(sig) && !baseline.contains(sig) {
                return true;
            }
        }
        false
    }

    //  CMDi電脳検出 / command injection detection — uid=/gid=/bin/bash etc in response but not baseline
    fn contains_cmdi(body: &str, baseline_body: &str) -> bool {
        if Self::is_waf_response(body, 200) { return false; }
        if baseline_body.is_empty() { return false; }
        let injected = body.to_lowercase();
        let baseline = baseline_body.to_lowercase();
        // Real CMDi: command output appears after injection but NOT in baseline.
        // Patterns: id command output, uname, whoami, OS info
        let cmdi_signals = [
            "uid=", "gid=", "groups=",
            "uid=", "gid=",
            "bin/bash", "bin/sh",
            "linux ", "microsoft", "darwin",
            "www-data", "root:", "nobody:",
        ];
        for sig in &cmdi_signals {
            if injected.contains(sig) && !baseline.contains(sig) {
                return true;
            }
        }
        false
    }

    //  単一URLファジング / fuzz a single URL with all payload types
    //  SQLi / XSS / LFI / CMDi / NoSQL ペイロードを全パラメータに注入
    //  injects SQLi/XSS/LFI/CMDi/NoSQL payloads into all parameters
    //  ベースライン応答と比較して脆弱性を電脳検出 / compares with baseline to detect vulns
    async fn fuzz_url(&self, url: &str,
        prog_req: &AtomicUsize,
        prog_mod: &AtomicUsize,
        prog_fuzz_url: &Mutex<String>,
        stdout_lock: &Mutex<()>,
        prog_det: &AtomicUsize,
        prog_err: &AtomicUsize,
        scan_start: std::time::Instant,
        duration_limit: Option<std::time::Duration>,
    ) -> Result<(Vec<Finding>, usize, usize)> {
        let mut findings = Vec::new();
        let mut errors = 0usize;
        let mut requests = 0usize;
        use std::io::Write;

        let params = self.extract_params_from_url(url);
        let sql_payloads = self.fuzzer.generate_sql_payloads();
        let xss_payloads = self.fuzzer.generate_xss_payloads();
        let lfi_payloads = self.fuzzer.generate_lfi_payloads();
        let cmd_payloads = self.fuzzer.generate_cmd_injection_payloads("127.0.0.1", 4444);
        let destructive_payloads = self.fuzzer.generate_destructive_sql_payloads();
        let nosql_payloads = self.fuzzer.generate_nosql_payloads();
        let baseline_body = self.client.get(url).await
            .map(|r| r.body).unwrap_or_default();

        // Test types to show per-request
        let test_types = [
            ("SQLi",   &sql_payloads, 8),
            ("SQLi-D", &destructive_payloads, 4),
            ("XSS",    &xss_payloads, 8),
            ("LFI",    &lfi_payloads, 6),
            ("CMDi",   &cmd_payloads, 4),
            ("NoSQL",  &nosql_payloads, 6),
        ];

        for param in &params {
            for (mod_idx, &(label, payloads, count)) in test_types.iter().enumerate() {
                prog_mod.store(mod_idx, Ordering::Relaxed);
                for payload in payloads.iter().take(count) {
                    if let Some(limit) = duration_limit {
                        if scan_start.elapsed() >= limit {
                            return Ok((findings, errors, requests));
                        }
                    }
                    let fuzz_url = UrlUtil::inject_param(url, param, &urlencoding::encode(payload));
                    *prog_fuzz_url.lock().unwrap_or_else(|e| e.into_inner()) = fuzz_url.clone();
                    requests += 1;
                    self.req_count.fetch_add(1, Ordering::Relaxed);
                    prog_req.fetch_add(1, Ordering::Relaxed);
                    match self.client.get(&fuzz_url).await {
                        Ok(response) => {
                            let status = response.status;
                            let size = response.body.len();
                            let size_str = if size >= 1_048_576 {
                                format!("{:.1}MB", size as f64 / 1_048_576.0)
                            } else if size >= 1_024 {
                                format!("{:.1}KB", size as f64 / 1_024.0)
                            } else {
                                format!("{}B", size)
                            };

                            if self.args.verbose {
                                let sep = tc(&"═".repeat(52), FUJI);
                                println!("  {}", sep);
                                println!("  {} {}  {}  {}",
                                    tc(label, module_colour(label)),
                                    fmt_status(status),
                                    tc(&size_str, TSUYUKUSA),
                                    tc(&format!("[param={}]", param), TSUYUKUSA));
                                println!("  {} {}", tc("├─ URL:", HISUI), tc(&fuzz_url, WAKABA));
                            }

                            match label {
                                "SQLi" => {
                                    let scan_result = ScanResult {
                                        url: fuzz_url.clone(),
                                        status,
                                        response: Some(response),
                                        payload: payload.clone(),
                                    };
                                    if let Some(finding) = self.analyzer.analyze(scan_result).await {
                                        let f = Finding::new(&fuzz_url, finding.severity,
                                            &format!("SQLi via {}", param),
                                            &finding.title,
                                        ).with_evidence(&finding.evidence)
                                        .with_remediation(&finding.remediation);
                                        let _fw_lock = stdout_lock.lock().unwrap_or_else(|e| e.into_inner());
                                        print!("\r\x1B[2K");
                                        let _ = std::io::stdout().flush();
                                        if self.args.verbose {
                                            println!("  {} {}  {}", fmt_sev_label(&f.severity), f.title, tc(&fuzz_url, WAKABA));
                                            println!("  {} {} {}", tc("│", HISUI), tc("Payload:", HISUI), tc(payload, FUJI));
                                            println!("  {} {} {}", tc("│", HISUI), tc("Module:", HISUI), tc("sqli", module_colour("SQLi")));
                                            if !f.evidence.is_empty() {
                                                let ev_preview: String = f.evidence.chars().take(120).collect();
                                                println!("  {} {} {}", tc("│", HISUI), tc("Evidence:", HISUI), tc(&ev_preview, TSUYUKUSA));
                                            }
                                            println!("  {}", tc(&"╘".repeat(52), FUJI));
                                        } else {
                                            println!("  {} {}  {}  [{}]",
                                                fmt_sev_label(&f.severity), f.title, tc(&fuzz_url, WAKABA), tc("sqli", module_colour("SQLi")));
                                        }
                                        findings.push(f);
                                        prog_det.fetch_add(1, Ordering::Relaxed);
                                        drop(_fw_lock);
                                    }
                                }
                                "SQLi-D" => {
                                    let scan_result = ScanResult {
                                        url: fuzz_url.clone(),
                                        status,
                                        response: Some(response),
                                        payload: payload.clone(),
                                    };
                                    if let Some(finding) = self.analyzer.analyze(scan_result).await {
                                        let f = Finding::new(&fuzz_url, finding.severity,
                                            &format!("SQLi-D via {}", param),
                                            &finding.title,
                                        ).with_evidence(&finding.evidence)
                                        .with_remediation(&finding.remediation);
                                        let _fw_lock = stdout_lock.lock().unwrap_or_else(|e| e.into_inner());
                                        print!("\r\x1B[2K");
                                        let _ = std::io::stdout().flush();
                                        if self.args.verbose {
                                            println!("  {} {}  {}", fmt_sev_label(&f.severity), f.title, tc(&fuzz_url, WAKABA));
                                            println!("  {} {} {}", tc("│", SHU), tc("Payload:", SHU), tc(payload, FUJI));
                                            println!("  {} {} {}", tc("│", SHU), tc("Module:", SHU), tc("sqli-d", SHU));
                                            if !f.evidence.is_empty() {
                                                let ev_preview: String = f.evidence.chars().take(120).collect();
                                                println!("  {} {} {}", tc("│", SHU), tc("Evidence:", SHU), tc(&ev_preview, TSUYUKUSA));
                                            }
                                            println!("  {}", tc(&"╘".repeat(52), SHU));
                                        } else {
                                            println!("  {} {}  {}  [{}]",
                                                fmt_sev_label(&f.severity), f.title, tc(&fuzz_url, WAKABA), tc("sqli-d", SHU));
                                        }
                                        findings.push(f);
                                        prog_det.fetch_add(1, Ordering::Relaxed);
                                        drop(_fw_lock);
                                    }
                                }
                                "XSS" => {
                                    if Self::contains_xss(&response.body, &baseline_body, payload) {
                                        let evidence = if response.body.len() > 200 {
                                            format!("...{}", &response.body[..response.body.floor_char_boundary(200)])
                                        } else {
                                            response.body.clone()
                                        };
                                        let f = Finding::new(&fuzz_url, Severity::High,
                                            &format!("XSS in {}", param),
                                            &format!("Payload reflected in param `{}`", param),
                                        ).with_evidence(&evidence)
                                        .with_remediation("Use contextual output encoding and CSP");
                                        let _fw_lock = stdout_lock.lock().unwrap_or_else(|e| e.into_inner());
                                        print!("\r\x1B[2K");
                                        let _ = std::io::stdout().flush();
                                        if self.args.verbose {
                                            println!("  {} {}  {}", fmt_sev_label(&Severity::High), f.title, tc(&fuzz_url, WAKABA));
                                            println!("  {} {} {}", tc("│", HISUI), tc("Payload:", HISUI), tc(payload, FUJI));
                                            println!("  {} {} {}", tc("│", HISUI), tc("Module:", HISUI), tc("xss", module_colour("XSS")));
                                            let ev_preview: String = evidence.chars().take(120).collect();
                                            println!("  {} {} {}", tc("│", HISUI), tc("Evidence:", HISUI), tc(&ev_preview, TSUYUKUSA));
                                            println!("  {}", tc(&"╘".repeat(52), HISUI));
                                        } else {
                                            println!("  {} {}  {}  [{}]",
                                                fmt_sev_label(&Severity::High), f.title, tc(&fuzz_url, WAKABA), tc("xss", module_colour("XSS")));
                                        }
                                        findings.push(f);
                                        drop(_fw_lock);
                                    }
                                }
                                "LFI" => {
                                    if Self::contains_lfi(&response.body, &baseline_body) {
                                        let evidence = if response.body.len() > 200 {
                                            format!("...{}", &response.body[..response.body.floor_char_boundary(200)])
                                        } else {
                                            response.body.clone()
                                        };
                                        let f = Finding::new(&fuzz_url, Severity::Critical,
                                            &format!("LFI in {}", param),
                                            &format!("LFI via param `{}`: /etc/passwd", param),
                                        ).with_evidence(&evidence)
                                        .with_remediation("Validate and sanitize file path inputs");
                                        let _fw_lock = stdout_lock.lock().unwrap_or_else(|e| e.into_inner());
                                        print!("\r\x1B[2K");
                                        let _ = std::io::stdout().flush();
                                        if self.args.verbose {
                                            println!("  {} {}  {}", fmt_sev_label(&Severity::Critical), f.title, tc(&fuzz_url, WAKABA));
                                            println!("  {} {} {}", tc("│", SHU), tc("Payload:", SHU), tc(payload, FUJI));
                                            println!("  {} {} {}", tc("│", SHU), tc("Module:", SHU), tc("lfi", module_colour("LFI")));
                                            let ev_preview: String = evidence.chars().take(120).collect();
                                            println!("  {} {} {}", tc("│", SHU), tc("Evidence:", SHU), tc(&ev_preview, TSUYUKUSA));
                                            println!("  {}", tc(&"╘".repeat(52), SHU));
                                        } else {
                                            println!("  {} {}  {}  [{}]",
                                                fmt_sev_label(&Severity::Critical), f.title, tc(&fuzz_url, WAKABA), tc("lfi", module_colour("LFI")));
                                        }
                                        findings.push(f);
                                        drop(_fw_lock);
                                    }
                                }
                                "CMDi" => {
                                    if Self::contains_cmdi(&response.body, &baseline_body) {
                                        let evidence = if response.body.len() > 200 {
                                            format!("...{}", &response.body[..response.body.floor_char_boundary(200)])
                                        } else {
                                            response.body.clone()
                                        };
                                        let f = Finding::new(&fuzz_url, Severity::Critical,
                                            &format!("CMDi in {}", param),
                                            &format!("CMDi via param `{}`", param),
                                        ).with_evidence(&evidence)
                                        .with_remediation("Never pass user input to shell execution");
                                        let _fw_lock = stdout_lock.lock().unwrap_or_else(|e| e.into_inner());
                                        print!("\r\x1B[2K");
                                        let _ = std::io::stdout().flush();
                                        if self.args.verbose {
                                            println!("  {} {}  {}", fmt_sev_label(&Severity::Critical), f.title, tc(&fuzz_url, WAKABA));
                                            println!("  {} {} {}", tc("│", FUJI), tc("Payload:", FUJI), tc(payload, FUJI));
                                            println!("  {} {} {}", tc("│", FUJI), tc("Module:", FUJI), tc("cmdi", FUJI));
                                            let ev_preview: String = evidence.chars().take(120).collect();
                                            println!("  {} {} {}", tc("│", FUJI), tc("Evidence:", FUJI), tc(&ev_preview, TSUYUKUSA));
                                            println!("  {}", tc(&"╘".repeat(52), FUJI));
                                        } else {
                                            println!("  {} {}  {}  [{}]",
                                                fmt_sev_label(&Severity::Critical), f.title, tc(&fuzz_url, WAKABA), tc("cmdi", FUJI));
                                        }
                                        findings.push(f);
                                        drop(_fw_lock);
                                    }
                                }
                                "NoSQL" => {
                                    let scan_result = ScanResult {
                                        url: fuzz_url.clone(),
                                        status,
                                        response: Some(response),
                                        payload: payload.clone(),
                                    };
                                    if let Some(finding) = self.analyzer.analyze(scan_result).await {
                                        let f = Finding::new(&fuzz_url, finding.severity,
                                            &format!("NoSQLi via {}", param),
                                            &finding.title,
                                        ).with_evidence(&finding.evidence)
                                        .with_remediation(&finding.remediation);
                                        let _fw_lock = stdout_lock.lock().unwrap_or_else(|e| e.into_inner());
                                        print!("\r\x1B[2K");
                                        let _ = std::io::stdout().flush();
                                        if self.args.verbose {
                                            println!("  {} {}  {}", fmt_sev_label(&f.severity), f.title, tc(&fuzz_url, WAKABA));
                                            println!("  {} {} {}", tc("│", HISUI), tc("Payload:", HISUI), tc(payload, FUJI));
                                            println!("  {} {} {}", tc("│", HISUI), tc("Module:", HISUI), tc("nosql", module_colour("NoSQL")));
                                            if !f.evidence.is_empty() {
                                                let ev_preview: String = f.evidence.chars().take(120).collect();
                                                println!("  {} {} {}", tc("│", HISUI), tc("Evidence:", HISUI), tc(&ev_preview, TSUYUKUSA));
                                            }
                                            println!("  {}", tc(&"╘".repeat(52), HISUI));
                                        } else {
                                            println!("  {} {}  {}  [{}]",
                                                fmt_sev_label(&f.severity), f.title, tc(&fuzz_url, WAKABA), tc("nosql", module_colour("NoSQL")));
                                        }
                                        findings.push(f);
                                        drop(_fw_lock);
                                    }
                                }
                                _ => {}
                            }
                        }
                        Err(_) => {
                            errors += 1;
                            prog_err.fetch_add(1, Ordering::Relaxed);
                            if self.args.verbose {
                                println!("  {} {}  {}",
                                    tc("ERR", SHU).bold(),
                                    tc(label, FUJI),
                                    tc(&fuzz_url, TSUYUKUSA));
                            }
                        }
                    }
                }
            }
        }

        Ok((findings, errors, requests))
    }

    //  静的パス電脳走査 / static path scanning — probes common files/paths for info leaks
    async fn scan_static_paths(&self) -> Result<Vec<Finding>> {
        let spinner = std::sync::Arc::new(std::sync::Mutex::new(Spinner::vuln_spinner()));
        let spinner_clone = spinner.clone();
        
        // Start spinner animation task
        let spinner_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_millis(100));
            let mut counter = 0;
            loop {
                interval.tick().await;
                let frame = match spinner_clone.lock() {
                    Ok(guard) => guard.next(),
                    Err(poisoned) => poisoned.into_inner().next(),
                };
                counter += 1;
                print!("\r[{}] Scanning static paths ({}/20)...", frame, counter.min(20));
                let _ = std::io::Write::flush(&mut std::io::stdout());
            }
        });
        
        let mut findings = Vec::new();

        let paths = self.scanner.generate_payloads();

        for path in paths.iter().take(20) {
            let url = format!("{}{}", self.args.target_url(), path);
            let request = crate::http::request::HttpRequest::get(&url);

            match self.client.send(request).await {
                Ok(response) => {
                    let result = ScanResult {
                        url: url.clone(),
                        status: response.status,
                        response: Some(response.clone()),
                        payload: path.clone(),
                    };

                    if let Some(finding) = self.analyzer.analyze(result).await {
                        findings.push(finding);
                    }
                }
                Err(_) => {}
            }

            let _ = match spinner.lock() {
                Ok(guard) => guard.next(),
                Err(poisoned) => poisoned.into_inner().next(),
            };
        }

        // Stop spinner
        spinner_handle.abort();
        print!("\r");

        Ok(findings)
    }

    pub fn get_findings(&self) -> &Vec<Finding> {
        &self.findings
    }

    //  エージェントベース並列電脳走査 / agent-based parallel vulnerability scan
    //  AgentPoolを生成し全ターゲットを分散 / creates AgentPool, distributes targets
    //  30秒タイムアウト付き / 30-second timeout enforced
    pub async fn scan_with_agents(&self, targets: Vec<String>) -> Result<Vec<Finding>> {
        let target_count = targets.len();
        let mut agent_pool = AgentPool::new(&self.args, self.args.threads, target_count)?;

        println!("  AGENTS  Pool ready — {} agents, {} targets, {} permits",
            self.args.threads,
            target_count,
            agent_pool.get_available_permits(),
        );

        // Use TimeUtil::sleep_async for brief delay before starting agents
        TimeUtil::sleep_async(std::time::Duration::from_millis(100)).await;

        // Use TimeUtil::timeout for the agent scan with a 30-second timeout
        let scan_future = agent_pool.run_scan(targets);
        let result = match TimeUtil::timeout(std::time::Duration::from_secs(30), scan_future).await {
            Ok(result) => result,
            Err(_) => {
                println!("Agent scan timed out after 30 seconds");
                Ok(Vec::new())
            }
        };

        // Report final progress after scan completes
        let progress = agent_pool.get_progress();
        println!("  AGENTS  Done — {}/{} ({}%)",
            progress.get_current(), progress.get_total(), progress.get_percent());

        result
    }

    /// Convert oxide::Finding to crate::detection::analyzer::Finding
    fn convert_finding(&self, finding: &oxide::detection::analyzer::Finding) -> crate::detection::analyzer::Finding {
        let severity = match finding.severity {
            oxide::detection::analyzer::Severity::Critical => crate::detection::analyzer::Severity::Critical,
            oxide::detection::analyzer::Severity::High => crate::detection::analyzer::Severity::High,
            oxide::detection::analyzer::Severity::Medium => crate::detection::analyzer::Severity::Medium,
            oxide::detection::analyzer::Severity::Low => crate::detection::analyzer::Severity::Low,
            oxide::detection::analyzer::Severity::Info => crate::detection::analyzer::Severity::Info,
        };
        
        crate::detection::analyzer::Finding::new(
            &finding.url,
            severity,
            &finding.title,
            &finding.description,
        )
        .with_evidence(&finding.evidence)
        .with_remediation(&finding.remediation)
    }

    fn common_params() -> Vec<String> {
        vec![
            "id", "page", "file", "path", "search", "query", "q", "s", "cat", "category",
            "pid", "aid", "uid", "bid", "did", "order", "sort", "limit", "offset", "start",
            "end", "date", "from", "to", "type", "mode", "action", "cmd", "exec", "run",
            "url", "redirect", "return", "next", "prev", "view", "format", "debug", "test",
            "lang", "locale", "callback", "include", "template", "dir", "folder", "name",
            "user", "username", "pass", "password", "token", "api_key", "key", "sig",
        ].into_iter().map(String::from).collect()
    }

    fn extract_params_from_url(&self, url: &str) -> Vec<String> {
        if let Ok(parsed) = Url::parse(url) {
            if let Some(query) = parsed.query() {
                if !query.is_empty() {
                    return query
                        .split('&')
                        .filter_map(|param| {
                            param.split('=').next().map(|s| s.to_string())
                        })
                        .filter(|s| !s.is_empty())
                        .collect();
                }
            }
        }
        Self::common_params()
    }

    fn extract_params_from_urls(&self, urls: &[String]) -> Vec<String> {
        let mut params = std::collections::HashSet::new();
        
        for url in urls {
            for param in self.extract_params_from_url(url) {
                params.insert(param);
            }
        }
        
        if params.is_empty() {
            for p in Self::common_params() {
                params.insert(p);
            }
        }
        
        params.into_iter().collect()
    }

    /// Run ML-based zero-day detection on crawled URLs
    async fn run_ml_detection(&self, urls: &[String]) -> Result<Vec<Finding>> {
        use crate::zero_day::features::ResponseFeatures;
        use crate::http::request::HttpRequest;
        
        // Try to import validated baselines if file exists
        if std::path::Path::new("./validated_baselines.json").exists() {
            let _ = self.import_validated_baselines("./validated_baselines.json").await;
        }
        
        // Try to load saved baselines if directory exists
        if std::path::Path::new("./zero_day_data").exists() {
            // Note: load_zero_day_baselines requires &mut self, so we can't call it here directly
            // Instead, we log that baselines could be loaded
            tracing::info!("Found saved baselines in ./zero_day_data - use load_zero_day_baselines() to restore them");
        }
        
        let mut findings = Vec::new();
        let mut training_samples = Vec::new();
        
        // First pass: Collect training samples from all discovered URLs
        println!("   ML   Collecting baseline training data from {} URLs...", urls.len().min(50));
        for (idx, url) in urls.iter().take(50).enumerate() {
            let request = HttpRequest::get(url);
            let start = std::time::Instant::now();
            
            if let Ok(response) = self.client.send(request).await {
                let response_time = start.elapsed().as_millis() as u64;
                let features = ResponseFeatures::from_response(&response, url, response_time);
                
                // Collect samples for classifier training (label as safe initially)
                training_samples.push((features.clone(), false));
            }
            
            if idx % 10 == 0 {
                println!("    Processed {}/{} URLs for training", idx, urls.len().min(50));
            }
        }
        
        // Train the classifier if we have enough samples
        if training_samples.len() >= 10 {
            println!("   ML   Training classifier with {} samples...", training_samples.len());
            if let Err(e) = self.zero_day_engine.train_classifier(training_samples).await {
                println!("    Warning: Classifier training failed: {}", e);
            } else {
                println!("    Classifier trained successfully!");
            }
        }
        
        // Second pass: Analyze for anomalies
        println!("   ML   Analyzing responses for anomalies...");
        for (idx, url) in urls.iter().enumerate() {
            let request = HttpRequest::get(url);
            let start = std::time::Instant::now();
            
            if let Ok(response) = self.client.send(request).await {
                let response_time = start.elapsed().as_millis() as u64;
                let _features = ResponseFeatures::from_response(&response, url, response_time);
                
                // Analyze for anomalies
                let report = self.zero_day_engine.analyze_response(url, &response, response_time).await;
                
                if report.is_zero_day && report.confidence > 0.6 {
                    let severity = if report.confidence > 0.8 {
                        crate::detection::analyzer::Severity::Critical
                    } else if report.confidence > 0.7 {
                        crate::detection::analyzer::Severity::High
                    } else {
                        crate::detection::analyzer::Severity::Medium
                    };
                    
                    let vuln_type = report.anomaly_result.vulnerability_type.as_deref()
                        .unwrap_or("Unknown Anomaly");
                    
                    let description = format!(
                        "ML-detected anomaly with {:.1}% confidence\nType: {}\nAnomaly Score: {:.2}\nVulnerability Score: {:.2}",
                        report.confidence * 100.0,
                        vuln_type,
                        report.anomaly_result.anomaly_score,
                        report.anomaly_result.vulnerability_score
                    );
                    
                    let mut finding = Finding::new(
                        url,
                        severity,
                        &format!("ML Zero-Day: {}", vuln_type),
                        &description,
                    );
                    
                    // Add reasons as evidence
                    let evidence = report.anomaly_result.reasons.join("\n");
                    finding = finding.with_evidence(&evidence);
                    
                    // Add recommendations if available
                    if !report.recommendations.is_empty() {
                        finding = finding.with_remediation(&report.recommendations.join("\n"));
                    }
                    
                    findings.push(finding);
                    println!("    [DETECTED] Zero-day anomaly at {} (confidence: {:.1}%)", url, report.confidence * 100.0);
                }
            }
            
            if idx % 10 == 0 && !urls.is_empty() {
                let stats = self.zero_day_engine.get_stats().await;
                println!("    Analyzed {}/{} URLs (responses: {}, anomalies: {})", 
                    idx, urls.len(), stats.responses_analyzed, stats.anomalies_detected);
            }
        }
        
        let final_stats = self.zero_day_engine.get_stats().await;
        println!("   ML   Detection complete. Analyzed {} responses, found {} anomalies", 
            final_stats.responses_analyzed, final_stats.anomalies_detected);
        
        // Persist baselines for future scans
        if final_stats.anomalies_detected > 0 {
            let _ = self.persist_zero_day_baselines("./zero_day_data").await;
        }
        
        // Get and log status
        let status = self.get_zero_day_status().await;
        
        // Read all status fields to ensure they're used
        let _ = status.responses_analyzed;
        let _ = status.anomalies_detected;
        let _ = status.anomaly_threshold;
        let _ = status.vulnerability_threshold;
        
        // Log comprehensive status
        tracing::info!(
            "Zero-day status: {} responses, {} anomalies, thresholds: {:.2}/{:.2}",
            status.responses_analyzed,
            status.anomalies_detected,
            status.anomaly_threshold,
            status.vulnerability_threshold
        );
        
        println!("   ML   Baselines: {} total, {} mature, {} stale", 
            status.total_baselines, status.mature_baselines, status.stale_baselines);
        
        // Perform maintenance
        let maintenance = self.maintain_zero_day_system().await;
        
        // Read all maintenance fields
        let _ = maintenance.total_baselines;
        let _ = maintenance.duration_ms;
        
        tracing::info!(
            "Maintenance complete: {} total baselines, took {}ms",
            maintenance.total_baselines,
            maintenance.duration_ms
        );
        
        if maintenance.stale_baselines > 0 {
            println!("   ML   Found {} stale baselines during maintenance", maintenance.stale_baselines);
        }
        
        // Get baseline statistics and read all fields
        let stats = self.get_baseline_statistics().await;
        let _ = stats.total_samples; // Ensure field is read
        
        tracing::info!(
            "Baseline stats: {} total, {} mature, {} immature, {} samples, {:.1} avg",
            stats.total_baselines,
            stats.mature_baselines,
            stats.immature_baselines,
            stats.total_samples,
            stats.average_samples
        );
        
        println!("   ML   Statistics: {} total, {} mature, {} immature, {:.1} avg samples",
            stats.total_baselines, stats.mature_baselines, stats.immature_baselines, stats.average_samples);
        
        // Check classifier status
        let classifier_ready = self.is_classifier_ready().await;
        println!("   ML   Classifier ready: {}", classifier_ready);
        
        // Try to optimize thresholds if we have enough baselines
        if let Ok((anomaly, vuln)) = self.optimize_zero_day_thresholds().await {
            println!("   ML   Suggested thresholds: anomaly={:.2}, vuln={:.2}", anomaly, vuln);
        }

        //  HPP (HTTP Parameter Pollution) scan 
        use crate::zero_day::hpp::HppDetector;
        println!("   ML   Running HTTP Parameter Pollution scan on {} URLs...", urls.len());
        match HppDetector::scan(&self.client, urls, &mut findings).await {
            Ok(summary) => {
                println!("   ML   HPP complete: {} vulnerable URLs, {} anomalies",
                    summary.vulnerable_count, summary.total_anomalies);
            }
            Err(e) => {
                println!("   ML   HPP scan error: {}", e);
            }
        }

        Ok(findings)
    }

    pub async fn persist_zero_day_baselines(&self, output_dir: &str) -> Result<usize, String> {
        std::fs::create_dir_all(output_dir).map_err(|e| format!("Failed to create directory: {}", e))?;
        
        let mature_urls = self.zero_day_engine.get_mature_baselines().await;
        let mut saved = 0;
        
        for url in &mature_urls {
            let sanitized = url.replace(|c: char| !c.is_alphanumeric(), "_");
            let path = format!("{}/baseline_{}.json", output_dir, sanitized);
            
            if let Err(e) = self.zero_day_engine.save_baseline(url, &path).await {
                tracing::warn!("Failed to save baseline for {}: {}", url, e);
            } else {
                saved += 1;
            }
        }
        
        // Also export full engine state
        let engine_data = self.zero_day_engine.export_model().await
            .map_err(|e| format!("Export failed: {}", e))?;
        
        let state_path = format!("{}/zero_day_state.bin", output_dir);
        std::fs::write(&state_path, &engine_data)
            .map_err(|e| format!("Failed to write state: {}", e))?;
        
        tracing::info!("Persisted {} baselines and engine state to {}", saved, output_dir);
        Ok(saved)
    }

    /// Load zero-day detection baselines from disk
    pub async fn load_zero_day_baselines(&mut self, input_dir: &str) -> Result<(usize, usize), String> {
        let entries = std::fs::read_dir(input_dir)
            .map_err(|e| format!("Failed to read directory: {}", e))?;
        
        let mut loaded = 0;
        let mut failed = 0;
        
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map(|e| e == "json").unwrap_or(false) {
                let filename = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
                
                if filename.starts_with("baseline_") {
                    let sanitized = &filename[9..];
                    let url = sanitized.replace('_', "/");
                    
                    if let Err(e) = self.zero_day_engine.load_baseline(&url, &path.to_string_lossy()).await {
                        tracing::warn!("Failed to load baseline: {}", e);
                        failed += 1;
                    } else {
                        loaded += 1;
                    }
                }
            }
        }
        
        // Try to load full engine state
        let state_path = format!("{}/zero_day_state.bin", input_dir);
        if let Ok(data) = std::fs::read(&state_path) {
            if let Err(e) = self.zero_day_engine.import_model(&data).await {
                tracing::warn!("Failed to import engine state: {}", e);
            } else {
                tracing::info!("Loaded engine state from {}", state_path);
            }
        }
        
        tracing::info!("Loaded {} baselines, {} failed from {}", loaded, failed, input_dir);
        Ok((loaded, failed))
    }

    /// Get comprehensive zero-day detection status
    pub async fn get_zero_day_status(&self) -> ZeroDayStatus {
        let stats = self.zero_day_engine.get_stats().await;
        let baseline_stats = self.zero_day_engine.get_baseline_health().await;
        let ages = self.zero_day_engine.get_baseline_ages().await;
        let status = self.zero_day_engine.get_status().await;
        
        let mature_count = baseline_stats.iter().filter(|(_, h)| h.is_mature).count();
        let stale_count = ages.iter().filter(|(_, a)| a.as_secs() > 7 * 86400).count();
        
        ZeroDayStatus {
            responses_analyzed: stats.responses_analyzed,
            anomalies_detected: stats.anomalies_detected,
            total_baselines: baseline_stats.len(),
            mature_baselines: mature_count,
            stale_baselines: stale_count,
            anomaly_threshold: status.anomaly_threshold,
            vulnerability_threshold: status.vulnerability_threshold,
        }
    }

    /// Optimize zero-day detection thresholds based on current data
    pub async fn optimize_zero_day_thresholds(&self) -> Result<(f64, f64), String> {
        let stats = self.zero_day_engine.get_baseline_health().await;
        
        if stats.len() < 10 {
            return Err("Need at least 10 baselines for optimization".to_string());
        }
        
        // Calculate optimal thresholds based on baseline variance
        let mature_baselines: Vec<_> = stats.iter().filter(|(_, h)| h.is_mature).collect();
        
        if mature_baselines.is_empty() {
            return Err("No mature baselines available".to_string());
        }
        
        let avg_coverage: f64 = mature_baselines.iter()
            .map(|(_, h)| h.coverage_score)
            .sum::<f64>() / mature_baselines.len() as f64;
        
        // Higher coverage = lower threshold (more sensitive)
        let anomaly_threshold = 0.7 - (avg_coverage * 0.2).clamp(0.0, 0.3);
        let vuln_threshold = anomaly_threshold + 0.1;
        
        // Note: Thresholds are calculated but not directly set on ZeroDayEngine
        // They would need to be passed to the underlying anomaly engine
        tracing::info!(
            "Suggested thresholds: anomaly={:.2}, vulnerability={:.2} (based on {} mature baselines)",
            anomaly_threshold, vuln_threshold, mature_baselines.len()
        );
        
        Ok((anomaly_threshold, vuln_threshold))
    }

    /// Perform maintenance on zero-day detection system
    pub async fn maintain_zero_day_system(&self) -> MaintenanceSummary {
        let start = std::time::Instant::now();
        
        // Clear old history
        self.zero_day_engine.clear_history().await;
        
        // Get baseline ages and report stale ones
        let ages = self.zero_day_engine.get_baseline_ages().await;
        let stale_count = ages.iter().filter(|(_, a)| a.as_secs() > 30 * 86400).count();
        
        // Reset stats if needed
        let stats = self.zero_day_engine.get_stats().await;
        if stats.responses_analyzed > 10000 {
            self.zero_day_engine.reset_stats().await;
        }
        
        MaintenanceSummary {
            stale_baselines: stale_count,
            total_baselines: ages.len(),
            duration_ms: start.elapsed().as_millis() as u64,
        }
    }

    /// Import validated baselines from external source
    pub async fn import_validated_baselines(&self, data_path: &str) -> Result<Vec<(String, bool)>, String> {
        let json = std::fs::read_to_string(data_path)
            .map_err(|e| format!("Failed to read file: {}", e))?;
        
        let engine_data: crate::zero_day::anomaly::AnomalyEngineData = serde_json::from_str(&json)
            .map_err(|e| format!("JSON parse failed: {}", e))?;
        
        let results = self.zero_day_engine.import_baselines_validated(engine_data).await
            .map_err(|e| format!("Import failed: {}", e))?;
        
        let valid_count = results.iter().filter(|(_, v)| *v).count();
        tracing::info!("Imported {} valid baselines from {}", valid_count, data_path);
        
        Ok(results)
    }

    /// Check if classifier is trained and ready
    pub async fn is_classifier_ready(&self) -> bool {
        let status = self.zero_day_engine.get_status().await;
        status.classifier_trained
    }

    /// Get detailed baseline statistics
    pub async fn get_baseline_statistics(&self) -> BaselineStatisticsSummary {
        let stats = self.zero_day_engine.get_baseline_health().await;
        let total = stats.len();
        let mature = stats.iter().filter(|(_, h)| h.is_mature).count();
        let immature = total - mature;
        let total_samples: usize = stats.iter().map(|(_, h)| h.sample_count).sum();
        
        BaselineStatisticsSummary {
            total_baselines: total,
            mature_baselines: mature,
            immature_baselines: immature,
            total_samples,
            average_samples: if total > 0 { total_samples as f64 / total as f64 } else { 0.0 },
        }
    }
}

//  Osaka-Jade / Lavender output helpers 

use crate::cli::display::{
    TSUYUKUSA,
    FUJI,
    HISUI,
    SHU,
    GIN,
    WAKABA,
};

fn tc(s: &str, (r, g, b): (u8, u8, u8)) -> String {
    use colored::Colorize;
    s.truecolor(r, g, b).to_string()
}

fn print_phase_banner(module: &str, desc: &str) {
    println!("  {} {}  {} {}",
        tc("┌─", HISUI),
        tc(module, FUJI).bold(),
        tc("→", TSUYUKUSA),
        tc(desc, TSUYUKUSA));
}

fn print_phase_sub(module: &str, desc: &str) {
    println!("  {} {}  {} {}",
        tc("├─", TSUYUKUSA),
        tc(module, HISUI).bold(),
        tc("→", TSUYUKUSA),
        tc(desc, FUJI));
}

fn fmt_status(status: u16) -> String {
    match status {
        200..=299 => tc(&status.to_string(), HISUI),
        300..=399 => tc(&status.to_string(), TSUYUKUSA),
        400..=499 => tc(&status.to_string(), SHU),
        500..=599 => tc(&status.to_string(), SHU),
        _ => tc(&status.to_string(), FUJI),
    }
}

fn fmt_sev_label(severity: &Severity) -> String {
    match severity {
        Severity::Critical => tc("CRITICAL  │", SHU),
        Severity::High     => tc("HIGH      │", SHU),
        Severity::Medium   => tc("MEDIUM    │", FUJI),
        Severity::Low      => tc("LOW       │", TSUYUKUSA),
        Severity::Info     => tc("INFO      │", HISUI),
    }
}

//  exploitation_config — maps 1–100 level to (payloads_per_param, error_threshold, similarity_threshold)
//   1–25:   Gentle   — 2 payloads, 3 error tol, 85% dedup
//   26–50:  Normal   — 5 payloads, 6 error tol, 90% dedup
//   51–75:  Deep     — 10 payloads, 10 error tol, 92% dedup
//   76–90:  Aggressive — 15 payloads, 15 error tol, 95% dedup
//   91–100: Maximum  — 25 payloads, 25 error tol, 97% dedup
// Uses strsim::normalized_levenshtein for precision URL similarity comparison
fn exploitation_config(level: u8) -> (usize, usize, f64) {
    match level {
        1..=25  => (2,   3,   0.85),
        26..=50 => (5,   6,   0.90),
        51..=75 => (10,  10,  0.92),
        76..=90 => (15,  15,  0.95),
        91..=100=> (25,  25,  0.97),
        _       => (10,  10,  0.92),
    }
}

//  url_depth — counts path segments as a proxy for crawl depth
fn url_depth(url: &str) -> usize {
    url::Url::parse(url)
        .ok()
        .and_then(|u| u.path_segments().map(|s| s.count()))
        .unwrap_or(0)
}

//  module_colour — colour tag per module type (SQLi→SHU, XSS→HISUI, etc.)
fn module_colour(module: &str) -> (u8, u8, u8) {
    match module {
        "SQLi"   | "SQLi-D" => SHU,
        "XSS"    => HISUI,
        "LFI"    => TSUYUKUSA,
        "CMDi"   => FUJI,
        "NoSQL"  => WAKABA,
        _        => GIN,
    }
}


/// Zero-day detection system status
#[derive(Debug, Clone)]
pub struct ZeroDayStatus {
    pub responses_analyzed: usize,
    pub anomalies_detected: usize,
    pub total_baselines: usize,
    pub mature_baselines: usize,
    pub stale_baselines: usize,
    pub anomaly_threshold: f64,
    pub vulnerability_threshold: f64,
}

/// Maintenance operation summary
#[derive(Debug, Clone)]
pub struct MaintenanceSummary {
    pub stale_baselines: usize,
    pub total_baselines: usize,
    pub duration_ms: u64,
}

/// Baseline statistics summary
#[derive(Debug, Clone)]
pub struct BaselineStatisticsSummary {
    pub total_baselines: usize,
    pub mature_baselines: usize,
    pub immature_baselines: usize,
    pub total_samples: usize,
    pub average_samples: f64,
}
