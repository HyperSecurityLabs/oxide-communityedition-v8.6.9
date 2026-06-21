// ----------------------------------------------------------------------------
//  standalone.rs — standalone zero-day scanner
// ----------------------------------------------------------------------------
//  standalone zero-day scanner — can run independently of the main scan engine
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
// ◆ ZeroDayStandalone — スタンドアロンゼロデイスキャナ
// ◆ Independent zero-day mode: crawl → ML anomaly scan → fuzz → HPP → report
// ◆ ■ Phase 1: Web crawl for URL discovery (30s timeout)
// ◆ ■ Phase 2: ML-based anomaly scanning with progress tracking
// ◆ ■ Phase 2.5: Fuzz testing with 15 payload types (long str, XSS, SQLi, etc.)
// ◆ ■ Phase 2.75: HTTP Parameter Pollution detection
// ◆ ■ Phase 3: Summary report with success rate
// ◆ ■ try_exploit(): auto-confirms ML-detected anomalies with targeted payloads

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use colored::Colorize;


use crate::cli::display::{
    COL_CRIT, COL_DIM, COL_MED,
    ELITE_CYAN,
    ELITE_LAVENDER, ELITE_LAVENDER_B, ELITE_JADE_B,
};
use crate::crawls::WebCrawler;
use crate::detection::analyzer::{Finding, Severity};
use crate::http::client::HttpClient;
use crate::http::request::HttpRequest;
use crate::http::response::HttpResponse;
use crate::zero_day::engine::ZeroDayEngine;

fn tc(s: &str, c: (u8, u8, u8)) -> String {
    s.truecolor(c.0, c.1, c.2).to_string()
}

pub struct ZeroDayStandalone {
    client: Arc<HttpClient>,
    engine: ZeroDayEngine,
    target_url: String,
    duration_limit: Option<Duration>,
    start_time: Instant,
    shutdown: Arc<AtomicBool>,

    total_anomalies: AtomicUsize,
    confirmed_exploits: AtomicUsize,
    total_requests: AtomicUsize,
}

impl ZeroDayStandalone {
    pub fn new(client: Arc<HttpClient>, target_url: String, duration_secs: u64) -> Self {
        let duration_limit = if duration_secs > 0 {
            Some(Duration::from_secs(duration_secs))
        } else {
            None
        };
        Self {
            client,
            engine: ZeroDayEngine::new(),
            target_url,
            duration_limit,
            start_time: Instant::now(),
            shutdown: Arc::new(AtomicBool::new(false)),
            total_anomalies: AtomicUsize::new(0),
            confirmed_exploits: AtomicUsize::new(0),
            total_requests: AtomicUsize::new(0),
        }
    }

    fn should_continue(&self) -> bool {
        if self.shutdown.load(Ordering::Acquire) || crate::is_shutdown_requested() {
            return false;
        }
        if let Some(limit) = self.duration_limit {
            if self.start_time.elapsed() >= limit {
                return false;
            }
        }
        true
    }

    fn time_remaining(&self) -> Option<Duration> {
        self.duration_limit
            .map(|limit| limit.checked_sub(self.start_time.elapsed()).unwrap_or(Duration::ZERO))
    }

    // ◆ run() — 3フェーズスタンドアロン電脳走査 / 3-phase standalone scan
    // ◆ Phase 1: Crawl — WebCrawler discovers URLs (30s timeout, depth 2, max 50)
    // ◆ Phase 2: ML anomaly analysis — iterates URLs, sends requests,
    // ◆   runs ZeroDayEngine::analyze_response, auto-exploits if confidence > 55%
    // ◆ Phase 2.5: Fuzz testing — 15 payload × 10 targets, monitors 5xx/timeouts/crashes
    // ◆ Phase 2.75: HPP detection — delegated to HppDetector::scan
    // ◆ Phase 3: Report — prints summary stats and success rate
    pub async fn run(&mut self) -> Result<Vec<Finding>> {
        let mut all_findings = Vec::new();

        println!("  {} {}",
            tc("◈", ELITE_JADE_B),
            tc("[Zero-Day Standalone] Initialising ML anomaly engine...", ELITE_LAVENDER_B));

        println!("  {} Scanning {} with ML-based zero-day detection",
            tc("▸", ELITE_CYAN),
            tc(&self.target_url, ELITE_LAVENDER));

        if let Some(limit) = self.duration_limit {
            println!("  {} Duration limit: {}s",
                tc("▸", ELITE_CYAN),
                tc(&limit.as_secs().to_string(), ELITE_LAVENDER_B));
        }
        println!();

        // ── Phase 1: Crawl ─────────────────────────────────────────────────
        if !self.should_continue() {
            return Ok(all_findings);
        }

        println!("  ── {} ──",
            tc("Phase 1/3: Reconnaissance — crawling target", ELITE_CYAN));

        let crawler = WebCrawler::new(
            (*self.client).clone(),
            2,
            50,
        );
        let crawler = tokio::time::timeout(
            Duration::from_secs(30),
            async {
                let mut c = crawler;
                c.crawl(&self.target_url).await
            },
        ).await
            .context("Crawl phase timed out (30s limit)")?
            .context("Crawl phase failed")?;

        let urls: Vec<String> = crawler.urls.iter()
            .chain(crawler.all_linked_urls.iter())
            .cloned()
            .collect();

        println!("  {} {} URLs discovered",
            tc("✓", ELITE_JADE_B),
            tc(&urls.len().to_string(), ELITE_LAVENDER_B));

        if urls.is_empty() {
            println!("  {} No URLs to analyze — target may be inaccessible or empty",
                tc("!", COL_CRIT));
            return Ok(all_findings);
        }

        // ── Phase 2: ML-based analysis ──────────────────────────────────────
        if !self.should_continue() {
            return Ok(all_findings);
        }

        println!();
        println!("  ── {} ──",
            tc("Phase 2/3: ML anomaly scanning — dynamic fuzzing", ELITE_CYAN));

        let total = urls.len();
        let mut analyzed = 0usize;

        for url in &urls {
            if !self.should_continue() {
                println!("\n  {} Scan interrupted — stopping zeroday analysis",
                    tc("⏹", COL_MED));
                break;
            }

            analyzed += 1;
            let remaining = self.time_remaining()
                .map(|d| format!("{}s", d.as_secs()))
                .unwrap_or_else(|| "∞".to_string());

            let pct = (analyzed as f64 / total as f64) * 100.0;
            print!("\r  {} [{}/{}] {:.0}%  |  {}  |  anomalies: {}  |  exploits: {}  |  remaining: {}   ",
                tc("▸", ELITE_CYAN),
                tc(&analyzed.to_string(), ELITE_JADE_B),
                tc(&total.to_string(), COL_DIM),
                pct,
                tc(&truncate_url(url, 55), ELITE_LAVENDER),
                tc(&self.total_anomalies.load(Ordering::Relaxed).to_string(), COL_MED),
                tc(&self.confirmed_exploits.load(Ordering::Relaxed).to_string(), ELITE_JADE_B),
                tc(&remaining, COL_DIM));

            // Send request with timeout (prevent hanging on slow responses)
            let url_clone = url.clone();
            let client = self.client.clone();
            let fetch = async move {
                let req = HttpRequest::get(&url_clone);
                let start = Instant::now();
                let resp = client.send(req).await?;
                let dur = start.elapsed();
                Ok::<(HttpResponse, Duration), anyhow::Error>((resp, dur))
            };

            let (response, response_dur) = match tokio::time::timeout(Duration::from_secs(10), fetch).await {
                Ok(Ok(r)) => r,
                Ok(Err(_)) => continue,
                Err(_) => continue,
            };

            self.total_requests.fetch_add(1, Ordering::Relaxed);

            let response_time = response_dur.as_millis() as u64;

            // ML analysis
            let report = self.engine.analyze_response(url, &response, response_time).await;

            if report.is_zero_day && report.confidence > 0.55 {
                self.total_anomalies.fetch_add(1, Ordering::Relaxed);

                // Auto-exploit: try to confirm the anomaly
                let confirmed = self.try_exploit(url, &report).await;

                if confirmed {
                    self.confirmed_exploits.fetch_add(1, Ordering::Relaxed);

                    let severity = match &report.anomaly_result.severity {
                        crate::zero_day::classifier::Severity::Critical => Severity::Critical,
                        crate::zero_day::classifier::Severity::High => Severity::High,
                        crate::zero_day::classifier::Severity::Medium => Severity::Medium,
                        _ => Severity::Low,
                    };

                    all_findings.push(Finding {
                        url: url.clone(),
                        severity,
                        title: format!("[Zero-Day] {} (confirmed)", report.anomaly_result.vulnerability_type.as_deref().unwrap_or("ML Anomaly")),
                        description: format!(
                            "AI detected anomaly (confidence: {:.1}%). Exploit confirmed.",
                            report.confidence * 100.0
                        ),
                        evidence: String::new(),
                        remediation: report.recommendations.join("; "),
                    });
                }
            }

            // Flush stdout so progress line updates
            use std::io::{Write, stdout};
            stdout().flush().ok();
        }

        println!();

        // ── Phase 2.5: Fuzz testing ─────────────────────────────────────────
        if !self.should_continue() {
            return Ok(all_findings);
        }

        println!();
        println!("  ── {} ──",
            tc("Fuzz Phase: Random payload flood", ELITE_CYAN));

        let fuzz_payloads: Vec<(&str, String)> = vec![
            ("long-str",    "A".repeat(10000)),
            ("xss-flood",   "<script>".repeat(500)),
            ("path-trav",   "../../../../etc/passwd".repeat(200)),
            ("null-byte",   "%00%00%00%00".repeat(1000)),
            ("ssti-ctx",    "{{".repeat(5000)),
            ("sql-single",  "'".repeat(5000)),
            ("null-raw",    "\0".repeat(5000)),
            ("path-up",     "../../../".repeat(1000)),
            ("cmd-inj",     "`id`".repeat(1000)),
            ("pipe-flood",  "|".repeat(5000)),
            ("win-path",    "../../../windows/win.ini".repeat(200)),
            ("semicolon",   ";".repeat(5000)),
            ("dotdot",      "../".repeat(5000)),
            ("dollar-brace","${".repeat(5000)),
            ("erb-tag",     "<%= ".repeat(5000)),
        ];

        let fuzz_targets: Vec<String> = urls.iter()
            .take(10)
            .map(|u| u.clone())
            .collect();

        let mut crashed = 0usize;
        let mut timeouts = 0usize;
        let mut errors_5xx = 0usize;

        for (fi, target) in fuzz_targets.iter().enumerate() {
            if !self.should_continue() {
                break;
            }

            print!("  {} target {}/{}: {}  ",
                tc("▸", ELITE_CYAN),
                tc(&(fi + 1).to_string(), ELITE_LAVENDER_B),
                tc(&fuzz_targets.len().to_string(), COL_DIM),
                tc(&truncate_url(target, 50), ELITE_LAVENDER));
            use std::io::{Write, stdout};
            stdout().flush().ok();

            for (pi, (label, payload)) in fuzz_payloads.iter().enumerate() {
                if !self.should_continue() {
                    break;
                }

                let fuzz_url = format!("{}?__fuzz={}_{}", target, fi, pi);
                let client = self.client.clone();
                let body = payload.clone();
                let label_str = label;

                let fetch = async move {
                    let mut req = crate::http::request::HttpRequest::post(&fuzz_url, &body);
                    req.headers.insert("Content-Type".to_string(), "application/x-www-form-urlencoded".to_string());
                    client.send(req).await
                };

                let result = match tokio::time::timeout(Duration::from_secs(5), fetch).await {
                    Ok(Ok(resp)) => {
                        if resp.status >= 500 {
                            errors_5xx += 1;
                            format!("{} {}[500]", tc(label_str, COL_MED), tc("●", COL_MED))
                        } else {
                            String::new()
                        }
                    }
                    Ok(Err(_)) => {
                        crashed += 1;
                        format!("{} {}[CRASH]", tc(label_str, COL_CRIT), tc("●", COL_CRIT))
                    }
                    Err(_) => {
                        timeouts += 1;
                        format!("{} {}[TIMEOUT]", tc(label_str, COL_MED), tc("◌", ELITE_CYAN))
                    }
                };

                if !result.is_empty() {
                    print!(" {}", result);
                    stdout().flush().ok();
                }
            }
            println!();
        }

        let total_fuzz_tests = fuzz_targets.len() * fuzz_payloads.len();
        let fuzz_severity = if crashed > 0 || errors_5xx > 5 {
            COL_CRIT
        } else if timeouts > 5 || errors_5xx > 0 {
            COL_MED
        } else {
            ELITE_JADE_B
        };

        println!();
        println!("  {} Fuzz results for {} tests across {} targets",
            tc("╔═══", ELITE_CYAN),
            tc(&total_fuzz_tests.to_string(), ELITE_LAVENDER_B),
            tc(&fuzz_targets.len().to_string(), COL_DIM));
        println!("  {}  5xx errors:  {}  (server crashed or error page)",
            tc("║", fuzz_severity),
            tc(&errors_5xx.to_string(), if errors_5xx > 0 { COL_MED } else { ELITE_JADE_B }));
        println!("  {}  Timeouts:     {}  (request hung / no response)",
            tc("║", fuzz_severity),
            tc(&timeouts.to_string(), if timeouts > 0 { COL_MED } else { ELITE_JADE_B }));
        println!("  {}  Connection failures: {}  (connection refused / reset)",
            tc("║", fuzz_severity),
            tc(&crashed.to_string(), if crashed > 0 { COL_CRIT } else { ELITE_JADE_B }));
        let fuzz_risk = if crashed > 0 { "CRITICAL — crashes detected, possible memory corruption"
            } else if errors_5xx > 0 { "HIGH — server error responses indicate instability"
            } else if timeouts > 0 { "MEDIUM — some requests timed out"
            } else { "LOW — no anomalies detected" };
        println!("  {}  Risk: {}",
            tc("║", fuzz_severity),
            tc(fuzz_risk, fuzz_severity));
        println!("  {} ",
            tc("╚═══", fuzz_severity));

        // ── Phase 2.75: HPP (HTTP Parameter Pollution) ──────────────────────
        if !self.should_continue() {
            return Ok(all_findings);
        }

        println!();
        println!("  ── {} ──",
            tc("Phase 2.75: HTTP Parameter Pollution detection", ELITE_CYAN));

        match crate::zero_day::hpp::HppDetector::scan(
            &self.client, &urls, &mut all_findings
        ).await {
            Ok(hpp_summary) => {
                println!("  {} HPP results: {} vulnerable URLs, {} anomalies",
                    tc("✓", ELITE_JADE_B),
                    tc(&hpp_summary.vulnerable_count.to_string(), COL_MED),
                    tc(&hpp_summary.total_anomalies.to_string(), COL_MED));
            }
            Err(e) => {
                println!("  {} HPP scan failed: {}",
                    tc("!", COL_CRIT),
                    tc(&e.to_string(), COL_CRIT));
            }
        }

        // ── Phase 3: Summary ────────────────────────────────────────────────
        println!();
        println!("  ── {} ──",
            tc("Phase 3/3: Report", ELITE_CYAN));

        let total_anom = self.total_anomalies.load(Ordering::Relaxed);
        let confirmed = self.confirmed_exploits.load(Ordering::Relaxed);
        let total_reqs = self.total_requests.load(Ordering::Relaxed);
        let success_rate = if total_anom > 0 {
            (confirmed as f64 / total_anom as f64) * 100.0
        } else {
            0.0
        };

        println!("  {} Requests sent: {}",
            tc("▸", COL_DIM),
            tc(&total_reqs.to_string(), ELITE_CYAN));
        println!("  {} Anomalies detected: {}",
            tc("▸", COL_DIM),
            tc(&total_anom.to_string(), COL_MED));
        println!("  {} Exploits confirmed: {}",
            tc("▸", COL_DIM),
            tc(&confirmed.to_string(), ELITE_JADE_B));

        let rate_color = if success_rate >= 50.0 { ELITE_JADE_B }
            else if success_rate >= 20.0 { COL_MED }
            else { COL_CRIT };
        println!("  {} Zero-Day success rate: {}/{} ({:.1}%)",
            tc("◈", rate_color),
            tc(&confirmed.to_string(), rate_color),
            tc(&total_anom.to_string(), COL_DIM),
            success_rate);

        if let Some(limit) = self.duration_limit {
            let elapsed = self.start_time.elapsed();
            let used_pct = (elapsed.as_secs_f64() / limit.as_secs_f64()) * 100.0;
            println!("  {} Duration used: {:.1}s / {}s ({:.0}%)",
                tc("▸", COL_DIM),
                tc(&elapsed.as_secs_f64().to_string(), ELITE_CYAN),
                tc(&limit.as_secs().to_string(), COL_DIM),
                used_pct);
        }

        Ok(all_findings)
    }

    // ◆ try_exploit() — ML異常確定 / auto-confirm ML-detected anomalies
    // ◆ ■ Matches vulnerability type to exploit payloads:
    // ◆   SQLi → ' OR '1'='1, UNION SELECT, 1=1/1=2
    // ◆   XSS → <img onerror>, <script>alert(1)</script>
    // ◆   LFI → ../../etc/passwd, ....//, windows/win.ini
    // ◆   CMDi → ;id, |id, `id`, $(id)
    // ◆   SSTI → {{7*7}}, ${7*7}, <%= 7*7 %>
    // ◆   Unknown → generic payload mix
    // ◆ ■ Confirmation: checks response body for specific indicators
    // ◆   (e.g., SQL errors, root:x: for LFI, uid= for CMDi)
    /// Try to confirm an ML-detected anomaly with targeted exploit payloads.
    /// Returns true if the exploit is confirmed.
    async fn try_exploit(&self, url: &str, report: &crate::zero_day::engine::DetectionReport) -> bool {
        let vuln_type = report.anomaly_result.vulnerability_type.as_deref().unwrap_or("Unknown");

        let payloads: &[&str] = match vuln_type {
            "SQL Injection" => &[
                "' OR '1'='1",
                "' UNION SELECT NULL--",
                "1' AND 1=1--",
                "1' AND 1=2--",
            ],
            "XSS" | "Cross-Site Scripting" => &[
                "<img src=x onerror=alert(1)>",
                "<script>alert(1)</script>",
                "\"><script>alert(1)</script>",
            ],
            "LFI" | "Path Traversal" | "Local File Inclusion" => &[
                "../../../../etc/passwd",
                "....//....//....//....//etc/passwd",
                "../../../../windows/win.ini",
            ],
            "CMDi" | "Command Injection" | "RCE" => &[
                "; id",
                "| id",
                "`id`",
                "$(id)",
            ],
            "SSTI" | "Template Injection" => &[
                "{{7*7}}",
                "${7*7}",
                "<%= 7*7 %>",
            ],
            _ => &[
                "' OR '1'='1",
                "../../../../etc/passwd",
                "<script>alert(1)</script>",
            ],
        };

        for payload in payloads {
            if !self.should_continue() {
                return false;
            }

            let exploit_url = format!("{}?__oxide_test={}", url, urlencoding::encode(payload));
            let client = self.client.clone();
            let fetch = async move {
                let req = HttpRequest::get(&exploit_url);
                client.send(req).await
            };

            let response = match tokio::time::timeout(Duration::from_secs(8), fetch).await {
                Ok(Ok(r)) => r,
                _ => continue,
            };

            let body = &response.body;
            let body_lower = body.to_lowercase();

            let confirmed = match vuln_type {
                "SQL Injection" => {
                    (body_lower.contains("sql ") || body_lower.contains("sql;") || body_lower.contains("sql\"") || body_lower.contains("sql'") || body_lower.contains("sql\t") || body_lower.contains("sql\n")) || body_lower.contains("mysql")
                        || body.contains("1=1") || body.contains("1=2")
                }
                "XSS" | "Cross-Site Scripting" => {
                    body.contains("<script>alert(1)</script>")
                        || body.contains("alert(1)")
                }
                "LFI" | "Path Traversal" | "Local File Inclusion" => {
                    body.contains("root:x:") || body.contains("root:$") || body.contains("bin/bash")
                        || body.contains("[extensions]") || body.contains("for 16-bit")
                }
                "CMDi" | "Command Injection" | "RCE" => {
                    body.contains("uid=") || body.contains("gid=")
                        || body.contains("groups=")
                }
                "SSTI" | "Template Injection" => {
                    body.contains("49") && (body.contains("7*7") || body.contains("7 * 7")) && !body.contains("{49}")
                }
                _ => {
                    (body_lower.contains("sql ") || body_lower.contains("sql;") || body_lower.contains("sql\"") || body_lower.contains("sql'") || body_lower.contains("sql\t") || body_lower.contains("sql\n")) || body.contains("root:x:") || body.contains("root:$")
                        || body.contains("alert(1)")
                }
            };

            if confirmed {
                return true;
            }
        }

        false
    }
}

fn truncate_url(url: &str, max: usize) -> String {
    if url.len() > max {
        format!("...{}", &url[url.len().saturating_sub(max - 3)..])
    } else {
        url.to_string()
    }
}
