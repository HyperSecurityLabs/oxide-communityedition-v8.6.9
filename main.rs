// ----------------------------------------------------------------------------
//  main.rs — OXIDE v7.9.1-elite エントリポイント
//  Oxidation Reaction main control — 酸化反応メイン制御
// ----------------------------------------------------------------------------
//  メインエントリ: 引数解析 → バナー表示 → トレーニング/ゼロデイ/
//  マルチアタック/ハイブリッドの4経路を電脳制御
//  Main entry: arg parsing → banner → dispatch through training/zero-day/
//  multi-attack/hybrid dispatch paths with graceful shutdown.
//
//  控制流（フロー）:
//  main() → print_banner() → CliArgs::parse_args() → if args.train →
//  ZeroDayTrainer / if args.zeroday → ZeroDayStandalone / if is_multi →
//  HybridScanner per target / else HybridScanner single-target →
//  ReportGenerator → JSON+HTML auto-save → exit.
//
//  --- Developers ---------------------------------------------------------------
//  khaninkali             — разработчик / core engineer (Rust backend, scan logic)
//  Lyara Koroleva         — дизайнер / blazing fast CLI & visual design
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

use colored::Colorize;
use std::process;
use std::sync::Arc;
use std::time::{Duration, Instant};

// ◆ 内部モジュール宣言 / internal module declarations
// crawls — 電脳クローリング / cybernetic crawling engine
// hybrid — ハイブリッドスキャン / hybrid scan orchestrator
// agent — エージェント並列スキャン / agent-based parallel scanning
// recon — OS偵察モジュール / OS reconnaissance (Linux only)
// zero_day — MLゼロデイ検出 / ML zero-day anomaly detection
mod crawls;
mod hybrid;
mod agent;
#[cfg(target_os = "linux")]
mod recon;
mod zero_day;

pub use oxide::cli;
pub use oxide::core;
pub use oxide::http;
pub use oxide::payload;
pub use oxide::detection;
pub use oxide::report;
pub use oxide::utils;

use crate::cli::args::CliArgs;
use crate::cli::colors;
use crate::cli::colors::Colors;
use crate::cli::config::Config;
use crate::http::client::{HttpClient, HttpClientConfig};
use crate::cli::display::{
    COL_DIM, COL_INFO, COL_MED,
    ELITE_CYAN, ELITE_CYAN_B,
    ELITE_LAVENDER, ELITE_LAVENDER_B, ELITE_JADE, ELITE_JADE_B,
};
use crate::cli::output::Output;
use crate::cli::parser::Parser;
use crate::cli::spinner::Spinner;
use crate::utils::time::TimeUtil;
use hybrid::HybridScanner;
use core::engine::ScanEngine;

// ★ truecolor helper — 256色は初心者用 / トゥルーカラー補助関数
// ★ 16M色のRGBを直接端末に出力する / outputs 16M RGB directly to terminal
// 引数: 文字列 + (R,G,B)タプル / arg: string + (R,G,B) tuple
fn tc(s: &str, (r, g, b): (u8, u8, u8)) -> String {
    s.truecolor(r, g, b).to_string()
}

// ★ グラデーション文字列生成 / per-character gradient across a string
// 開始色→終了色へ文字単位で遷移 / interpolates per-character from start→end color
// 制御: 各文字の位置t = i/(n-1)で線形補間 / linear interpolation by position t
// 使用: バナー/区切り線のカラーグラデーション / used for banner & separator gradients
// ★ 電脳パレット / cybernetic color palette — RGB→ANSI 24bit escape sequence
fn gradient_str(s: &str, start: (u8,u8,u8), end: (u8,u8,u8)) -> String {
    let chars: Vec<char> = s.chars().collect();
    let len = chars.len().max(1);
    chars.iter().enumerate().map(|(i, &c)| {
        let t = if len > 1 { i as f64 / (len - 1) as f64 } else { 0.5 };
        let r = (start.0 as f64 * (1.0 - t) + end.0 as f64 * t) as u8;
        let g = (start.1 as f64 * (1.0 - t) + end.1 as f64 * t) as u8;
        let b = (start.2 as f64 * (1.0 - t) + end.2 as f64 * t) as u8;
        format!("\x1B[38;2;{};{};{}m{}\x1B[0m", r, g, b, c)
    }).collect()
}

// ── print_banner() ──────────────────────────────────────────────────────
//  電脳スタートアップバナー / cybernetic startup banner
//  制御フロー / control flow:
//  1. ASCIIアート「OXIDE」→ Kali→Cyan→Lavender グラデーション
//  2. プロジェクト名 + バージョンをボックス内にイタリック表示
//  3. 区切り線 (──) をKali→Cyan→Lavender→White グラデーション
//  4. Author: khaninkali (Kali-Linux) — 斜体ラベンダー太字
//  5. Designer: Lyara-Koroleva — 4色グラデーション (pink→gold→mint→lavender)
//  6. 使用例コマンドをグラデーション付き一覧表示
//  不使用colored crateのtruecolor — 手動でANSI 24bit(SGR38;2)エスケープ
fn print_banner() {
    use crate::cli::display::{
        ELITE_CYAN, ELITE_LAVENDER, ELITE_LAVENDER_B, ELITE_KALI,
    };
    let line1 = format!("=> HyperSecurity Offensive Labs  |  OXIDE v7.9.1-elite");
    let line2 = format!("=> Open eXtensible Intelligence & Detection Engine — Community Edition * ELITEv7");
    let max_w = line1.len().max(line2.len()) + 3;
    let p = "─".repeat(max_w);
    let pad = "  ";
    println!();
    // Gradient banner: kali blue-grey → cyan → lavender
    println!("{}", gradient_str("   ____       _     __   ", ELITE_KALI, ELITE_CYAN));
    println!("{}", gradient_str("  / __ \\_  __(_)___/ /__ ", ELITE_CYAN, ELITE_LAVENDER));
    println!("{}", gradient_str(" / / / / |/_/ / __  / _ \\", ELITE_KALI, ELITE_CYAN));
    println!("{}", gradient_str("/ /_/ />  </ / /_/ /  __/", ELITE_CYAN, ELITE_LAVENDER));
    println!("{}", gradient_str("\\____/_/|_/_/\\__,_/\\___/ ", ELITE_KALI, ELITE_CYAN));
    println!();
    println!("{}", tc(&format!("╭{}╮", p), ELITE_KALI));
    println!("{}{}{}{}",
        tc("│", ELITE_KALI),
        tc(pad, ELITE_KALI),
        format!("\x1B[3m{}\x1B[0m", tc(&line1, ELITE_LAVENDER)),
        tc("", ELITE_KALI));
    println!("{}{}{}{}",
        tc("│", ELITE_KALI),
        tc(pad, ELITE_KALI),
        format!("\x1B[3m{}\x1B[0m", tc(&line2, ELITE_CYAN)),
        tc(" ", ELITE_KALI));
    println!("{}", tc(&format!("╰{}╯", p), ELITE_KALI));
    let sep_s = "──────────────────────────────────────────────";
    let sep_c: Vec<char> = sep_s.chars().collect();
    let sn = sep_c.len().max(1);
    let sep_g: String = sep_c.iter().enumerate().map(|(i, &c)| {
        let t = i as f64 / (sn - 1) as f64;
        let (r, g, b) = if t < 0.5 {
            let lt = t / 0.5;
            ((85.0 + (100.0 - 85.0) * lt) as u8,
             (124.0 + (210.0 - 124.0) * lt) as u8,
             (148.0 + (255.0 - 148.0) * lt) as u8)
        } else {
            let lt = (t - 0.5) / 0.5;
            ((100.0 + (180.0 - 100.0) * lt) as u8,
             (210.0 + (160.0 - 210.0) * lt) as u8,
             (255.0 + (255.0 - 255.0) * lt) as u8)
        };
        format!("\x1B[38;2;{};{};{}m{}\x1B[0m", r, g, b, c)
    }).collect();
    println!("{}", sep_g);
    println!("{} {} [Kali-Linux]", tc("Author", ELITE_KALI), format!("\x1B[3m{}\x1B[0m", tc("khaninkali", ELITE_LAVENDER_B)));
    // Designer credit: 4-color gradient across Lyara-Koroleva
    let designer_name = "Lyara-Koroleva";
    let designer_chars: Vec<char> = designer_name.chars().collect();
    let dlen = designer_chars.len().max(1);
    let d_gradient: String = designer_chars.iter().enumerate().map(|(i, &c)| {
        let t = i as f64 / (dlen - 1) as f64;
        let col = if t < 0.33 {
            let lt = t / 0.33;
            let r = (190.0 * (1.0 - lt) + 255.0 * lt) as u8;
            let g = (175.0 * (1.0 - lt) + 150.0 * lt) as u8;
            let b = (235.0 * (1.0 - lt) + 200.0 * lt) as u8;
            (r, g, b)
        } else if t < 0.66 {
            let lt = (t - 0.33) / 0.33;
            let r = (255.0 * (1.0 - lt) + 80.0 * lt) as u8;
            let g = (150.0 * (1.0 - lt) + 220.0 * lt) as u8;
            let b = (200.0 * (1.0 - lt) + 160.0 * lt) as u8;
            (r, g, b)
        } else {
            let lt = (t - 0.66) / 0.34;
            let r = (80.0 * (1.0 - lt) + 100.0 * lt) as u8;
            let g = (220.0 * (1.0 - lt) + 210.0 * lt) as u8;
            let b = (160.0 * (1.0 - lt) + 255.0 * lt) as u8;
            (r, g, b)
        };
        format!("\x1B[38;2;{};{};{}m{}\x1B[0m", col.0, col.1, col.2, c)
    }).collect();
    println!("{} {}",
        tc("Designer", ELITE_KALI),
        format!("\x1B[3m{}\x1B[0m", d_gradient));
    let example_cmds: &[&str] = &[
        "oxide-ce --help",
        "oxide-ce -u https://example.com --all",
        "oxide-ce -u https://example.com --modules xss,sqli,lfi",
        "oxide-ce -u targets.txt --multiattack --output json",
        "oxide-ce -u https://example.com --fuzz --threads 100",
        "oxide-ce --list-modules",
    ];
    let elen = example_cmds.len().max(1);
    for (i, cmd) in example_cmds.iter().enumerate() {
        let t = i as f64 / (elen - 1) as f64;
        let (r, g, b) = if t < 0.5 {
            let lt = t / 0.5;
            ((85.0 + (100.0 - 85.0) * lt) as u8,
             (124.0 + (210.0 - 124.0) * lt) as u8,
             (148.0 + (255.0 - 148.0) * lt) as u8)
        } else {
            let lt = (t - 0.5) / 0.5;
            ((100.0 + (180.0 - 100.0) * lt) as u8,
             (210.0 + (160.0 - 210.0) * lt) as u8,
             (255.0 + (255.0 - 255.0) * lt) as u8)
        };
        println!("{} \x1B[3m\x1B[38;2;{};{};{}m{}\x1B[0m",
            tc("↳", ELITE_KALI), r, g, b, cmd);
    }
    println!("{}", sep_g);
    println!();
}

// ★ DNS名前解決 / DNS resolution — tokio非同期ルックアップ
// ホスト名→IPアドレス変換 / hostname to IP address translation
// 失敗しても空リスト返すだけ / returns empty vec on failure, never panics
// 制御: lookup_hostは "host:port" 形式が必要 / requires "host:port" format
// ★ 電脳解決 / cybernetic resolution — BTreeSetで重複排除
async fn resolve_ip(host: &str) -> Vec<String> {
    use std::collections::BTreeSet;
    let addr = format!("{}:80", host);
    match tokio::net::lookup_host(addr).await {
        Ok(addrs) => {
            let ips: BTreeSet<String> = addrs.map(|a| a.ip().to_string()).collect();
            ips.into_iter().collect()
        }
        Err(_) => Vec::new(),
    }
}

async fn print_scan_info(args: &CliArgs) {
    let tc = |s: &str, (r, g, b): (u8, u8, u8)| s.truecolor(r, g, b).to_string();
    use crate::cli::display::{
        ELITE_JADE_B, ELITE_LAVENDER, ELITE_LAVENDER_B, ELITE_CYAN,
        COL_HIGH,
    };

    Output::print_header("Target Information");
    if args.multiattack_enabled() {
        println!("  {} {}  {} {}",
            tc("▸", ELITE_JADE_B), tc("Multi-Attack", ELITE_LAVENDER_B).bold(),
            tc("→", ELITE_LAVENDER), tc(&format!("{} targets", args.target_count()), ELITE_CYAN));
        let per_target = (args.threads / args.target_count()).max(1);
        for (i, url) in args.url.iter().enumerate() {
            let clean = Parser::ensure_http(url);
            let _host = url::Url::parse(&clean)
                .ok()
                .and_then(|u| u.host_str().map(|h| h.to_string()))
                .unwrap_or_default();
            println!("  {} {}  {} {}  {} {}",
                tc("▸", ELITE_JADE_B), tc(&format!("Target {}", i + 1), ELITE_LAVENDER_B).bold(),
                tc("→", ELITE_LAVENDER), tc(&clean, ELITE_LAVENDER),
                tc("≈", ELITE_JADE_B), tc(&format!("{} thr", per_target), ELITE_JADE_B));
        }
        println!("  {} {}  {} {}  {} {}",
            tc("▸", ELITE_JADE_B), tc("Threads", ELITE_LAVENDER_B).bold(),
            tc("→", ELITE_LAVENDER), tc(&format!("{} total", args.threads), ELITE_JADE_B),
            tc("·", ELITE_JADE_B), tc(&format!("{}s duration", args.duration), ELITE_LAVENDER));
    } else {
        let clean = Parser::ensure_http(args.target_url());
        let host = url::Url::parse(&clean)
            .ok()
            .and_then(|u| u.host_str().map(|h| h.to_string()))
            .unwrap_or_default();
        let ips = resolve_ip(&host).await;
        let ip_display = if ips.is_empty() {
            tc("unresolved", COL_HIGH)
        } else {
            tc(&ips.join(", "), ELITE_JADE_B)
        };
        println!("  {} {}  {} {}",
            tc("▸", ELITE_JADE_B), tc("Target", ELITE_LAVENDER_B).bold(),
            tc("→", ELITE_LAVENDER), args.target_url().truecolor(ELITE_LAVENDER.0, ELITE_LAVENDER.1, ELITE_LAVENDER.2).bold());
        println!("  {} {}  {} {}",
            tc("▸", ELITE_JADE_B), tc("IP", ELITE_LAVENDER_B).bold(),
            tc("→", ELITE_LAVENDER), ip_display);
        println!("  {} {}  {} {}  {} {}",
            tc("▸", ELITE_JADE_B), tc("Threads", ELITE_LAVENDER_B).bold(),
            tc("→", ELITE_LAVENDER), tc(&args.threads.to_string(), ELITE_JADE_B),
            tc("·", ELITE_JADE_B), tc(&format!("{}s duration", args.duration), ELITE_LAVENDER));
    }

    let modules = args.get_modules();
    let module_line: Vec<String> = modules.iter().map(|m| tc(m, ELITE_CYAN)).collect();
    println!("  {} {}  {} {}",
        tc("▸", ELITE_JADE_B), tc("Modules", ELITE_LAVENDER_B).bold(),
        tc("→", ELITE_LAVENDER), module_line.join(tc(" │ ", ELITE_LAVENDER).as_str()));

    if let Some(output) = &args.output {
        println!("  {} {}  {} {}",
            tc("▸", ELITE_JADE_B), tc("Output", ELITE_LAVENDER_B).bold(),
            tc("→", ELITE_LAVENDER), tc(output, ELITE_JADE_B));
    }

    if args.verbose  { println!("  {} {}", tc("▸", ELITE_JADE_B), tc("Verbose mode", ELITE_JADE_B)); }
    if args.insecure { println!("  {} {}", tc("▸", ELITE_JADE_B), tc("SSL verification disabled", COL_HIGH)); }
    if args.zeroday  { println!("  {} {}", tc("▸", ELITE_JADE_B), tc("Zero-day detection", ELITE_JADE_B)); }
    if args.train    { println!("  {} {}", tc("▸", ELITE_JADE_B), tc("Training mode", COL_HIGH)); }
    if args.insta    { println!("  {} {}", tc("▸", ELITE_JADE_B), tc("Instagram OSINT", ELITE_CYAN_B)); }
    if args.session  { println!("  {} {}", tc("▸", ELITE_JADE_B), tc("Session hijack testing", ELITE_CYAN)); }

    if !args.header.is_empty() {
        Output::print_section("Custom Headers");
        for header in &args.header {
            match Parser::parse_header(header) {
                Ok((key, value)) => println!("    {}: {}",
                    tc(&key, ELITE_JADE_B), tc(&value, ELITE_LAVENDER_B)),
                Err(e) => println!("    Invalid header '{}': {}", header, e),
            }
        }
    }

    if let Some(cookie) = &args.cookie {
        Output::print_section("Cookies");
        for (key, value) in &Parser::parse_cookie(cookie) {
            println!("    {}: {}",
                tc(&key, ELITE_JADE_B), tc(&value, ELITE_LAVENDER_B));
        }
    }

    Output::print_line();
    println!();
}

use std::sync::atomic::Ordering;
pub use oxide::{SHUTDOWN, is_shutdown_requested};

/// Run a scan future with periodic Ctrl+C polling so we don't hang on long I/O.
async fn run_scan_cancellable<F, T>(scan: F) -> Result<T, anyhow::Error>
where
    F: std::future::Future<Output = Result<T, anyhow::Error>>,
{
    tokio::pin!(scan);
    loop {
        tokio::select! {
            result = &mut scan => return result,
            _ = tokio::time::sleep(Duration::from_millis(200)) => {
                if is_shutdown_requested() {
                    return Err(anyhow::anyhow!("aborted by user (SIGINT)"));
                }
            }
        }
    }
}

#[tokio::main]
async fn main() {
    // ── Signal Handlers ─────────────────────────────────────────────────
    //  SIGINT (Ctrl+C) と SIGTERM (kill) のグレースフルシャットダウン
    //  Graceful shutdown — sets SHUTDOWN atomic flag, 200ms polling loop
    //  in run_scan_cancellable detects the flag and aborts cleanly.
    //  ユーザーが途中で止めても部分結果を失わない / no data loss on interrupt
    // ◆ SIGINT handler — Ctrl+C gracefully, no data loss
    {
        let _ = tokio::spawn(async move {
            match tokio::signal::ctrl_c().await {
                Ok(()) => {
                    SHUTDOWN.store(true, Ordering::SeqCst);
                    eprint!("\r\x1B[2K");
                    println!("  {} SIGINT — finishing current operation, saving checkpoint...",
                        "◈".truecolor(220, 200, 255));
                }
                Err(e) => {
                    eprintln!("[!] SIGINT handler registration failed: {}", e);
                }
            }
        });
    }
    // ☢ SIGTERM handler — Unix only, OS kill signal, same graceful behavior
    #[cfg(unix)]
    {
        let _ = tokio::spawn(async move {
            use tokio::signal::unix::{signal, SignalKind};
            let mut sigterm = match signal(SignalKind::terminate()) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("[!] SIGTERM handler registration failed: {}", e);
                    return;
                }
            };
            sigterm.recv().await;
            SHUTDOWN.store(true, Ordering::SeqCst);
            eprint!("\r\x1B[2K");
            println!("  {} SIGTERM — finishing current operation, saving checkpoint...",
                "◈".truecolor(220, 200, 255));
        });
    }

    // ── Banner & Checkpoint Init ────────────────────────────────────────
    //  OXIDE バナーを常に最初に表示 / banner always renders first
    //  ユーザーがエラー時でもバナーを見られる / visible even on arg errors
    print_banner();

    // ◆ Ensure /checkpoints directory exists for ML training snapshots
    let _ = std::fs::create_dir_all("checkpoints");

    let args = match CliArgs::parse_args() {
        Ok(args) => args,
        Err(e) => {
            eprintln!("{} {}", "[ERROR]".red().bold(), e);
            process::exit(1);
        }
    };

    if args.list_modules {
        let modules = [
            ("all", "Run all modules (default)"),
            ("fingerprint", "Target fingerprinting — WAF, server, OS detection"),
            ("crawl", "Crawl target for URLs, forms, scripts, comments"),
            ("fuzz", "Fuzz all parameters with injection payloads (SQLi, XSS, LFI, CMDi, NoSQL, SSTI)"),
            ("sqli", "SQL injection detection"),
            ("xss", "Cross-site scripting detection"),
            ("lfi", "Local file inclusion detection"),
            ("tls", "TLS/SSL configuration assessment"),
            ("cors", "CORS misconfiguration scanning"),
            ("common", "Common paths and files (Nikto-style)"),
            ("creds", "Default credentials testing"),
            ("filter", "Content filter — sensitive data exposure (API keys, tokens, passwords)"),
            ("insta", "Instagram OSINT — follower count, profile detection, media download"),
            ("session", "Session hijack testing — cookie flags, fixation, predictability"),
            ("zeroday", "ML-based zero-day anomaly detection"),
            ("static", "Static path scanning"),
            ("agent", "Agent-based parallel vulnerability scanning"),
            ("body", "Response body scanning for signatures"),
            ("parameter-discovery", "Parameter fuzzing and discovery"),
            ("engine", "Legacy ScanEngine (replaced by hybrid)"),
        ];
        println!("\n  {} Available modules:",
            "◆".truecolor(ELITE_JADE_B.0, ELITE_JADE_B.1, ELITE_JADE_B.2));
        for (name, desc) in modules {
            println!("  {}  {}  — {}",
                "▸".truecolor(ELITE_JADE.0, ELITE_JADE.1, ELITE_JADE.2),
                name.truecolor(ELITE_CYAN.0, ELITE_CYAN.1, ELITE_CYAN.2),
                desc.truecolor(ELITE_LAVENDER.0, ELITE_LAVENDER.1, ELITE_LAVENDER.2));
        }
        println!();
        process::exit(0);
    }
    
    // Print start timestamp (not used for scan duration timing)
    let scan_start = TimeUtil::now();
    println!("Scan started at: {}", TimeUtil::format_timestamp(&scan_start));
    println!("Unix timestamp: {}", TimeUtil::unix_timestamp());
    
    // Validate proxy library — binary won't run without it
    if let Err(e) = crate::http::proxy_loader::ensure_proxy_library() {
        eprintln!("[FATAL] Missing proxy library — {}", e);
        process::exit(1);
    }
    
    // Load or create default config
    let config_path = std::path::PathBuf::from("oxide-config.toml");
    let mut config = if config_path.exists() {
        match Config::load(&config_path) {
            Ok(c) => {
                println!("Loaded config from {}", config_path.display());
                c
            }
            Err(e) => {
                println!("Failed to load config: {}, using defaults", e);
                Config::default()
            }
        }
    } else {
        let default_config = Config::generate();
        if let Err(e) = default_config.save(&config_path) {
            println!("Failed to save default config: {}", e);
        } else {
            println!("Created default config at {}", config_path.display());
        }
        default_config
    };
    
    // Add custom headers to config
    for header in &args.header {
        if let Ok((key, value)) = Parser::parse_header(header) {
            config.add_header(&key, &value);
        }
    }
    
    // Get and display config headers
    let headers = config.get_headers();
    if !headers.is_empty() {
        println!("Loaded {} custom headers from config", headers.len());
    }
    
    // Validate URL using Parser
    let validated_url = Parser::ensure_http(args.target_url());
    
    // Use Parser::parse_url for strict validation
    match Parser::parse_url(&validated_url) {
        Ok(url) => println!("Valid URL parsed: {}", url),
        Err(e) => {
            eprintln!("{} Invalid URL: {}", "[ERROR]".red().bold(), e);
            process::exit(1);
        }
    }
    
    // Use Parser::is_valid_domain for domain validation
    let clean_url = validated_url.replace("http://", "").replace("https://", "");
    let domain = clean_url.split('/').next().unwrap_or("");
    if !Parser::is_valid_domain(domain) {
        eprintln!("{} Invalid domain: {}", "[ERROR]".red().bold(), domain);
        process::exit(1);
    }
    println!("Domain validation passed: {}", domain);
    
    let funny_messages = vec![
        "Initialising scan engine...",
        "Setting up target parameters...",
        "Preparing payload configurations...",
        "Loading module profiles...",
        "Configuring scan vectors...",
        "Building request pipeline...",
        "Warming up connection pool...",
    ];
    let msg_idx = (scan_start.timestamp() as usize) % funny_messages.len();
    println!("[+] {}", funny_messages[msg_idx].bright_cyan());
    
    println!("Using config: {} threads, {} custom headers", 
        config.threads, headers.len());
    println!("[+] Scan engines initialising — this may take a moment");
    
    print_scan_info(&args).await;
    
    // Initialize fingerprint spinner
    let _finger_spin = Spinner::finger_spinner();
    
    // ── Train mode: run all scanners and train zero-day ML classifier ─────
    if args.train {
        println!("{}", "Training mode engaged — indexing all scanners...".bright_green().bold());
        let train_config = HttpClientConfig {
            insecure: args.insecure,
            proxy: args.proxy.clone(),
            user_agent: args.user_agent.clone(),
            follow_redirects: true,
            max_redirects: args.max_redirects,
            cookie: args.cookie.clone(),
            jobs: args.jobs,
        };
        let client = std::sync::Arc::new(HttpClient::new(train_config)
            .unwrap_or_else(|e| {
                eprintln!("{} Failed to create HTTP client for training: {}",
                    "[ERROR]".red().bold(), e);
                process::exit(1);
            }));
        let engine = zero_day::engine::ZeroDayEngine::new();
        let trainer = zero_day::trainer::ZeroDayTrainer::new(
            client, engine, args.target_url(), 120,
        );
        match trainer.run_training().await {
            Ok(()) => {
                println!("{} Training complete!", "[OK]".green().bold());
                process::exit(0);
            }
            Err(e) => {
                eprintln!("{} Training failed: {}", "[ERROR]".red().bold(), e);
                process::exit(1);
            }
        }
    }

    let total_targets = args.target_count();
    let is_multi = args.multiattack_enabled();
    if is_multi {
        println!("  {} {}  {} {}",
            tc("⚔", COL_MED),
            tc("Multi-Attack engaged", ELITE_JADE_B).bold(),
            tc("→", COL_DIM),
            tc(&format!("{} concurrent targets", total_targets), ELITE_LAVENDER_B));
    }
    println!("  {} {}",
        tc("◈", COL_MED),
        tc("Launching scan — sit tight", ELITE_LAVENDER_B).bold());
    println!();
    
    // Start timing the scan (not the setup)
    let start_time = Instant::now();


    // ── Zero-Day Standalone Mode ────────────────────────────────────────
    if args.zeroday && !is_multi && !args.get_modules().contains(&"engine".to_string()) {
        println!("  {} {}",
            tc("◈", ELITE_JADE_B),
            tc("Zero-Day Standalone — isolated ML anomaly scanning", ELITE_LAVENDER_B).bold());
        println!();

        let zd_client_config = HttpClientConfig {
            insecure: args.insecure,
            proxy: args.proxy.clone(),
            user_agent: args.user_agent.clone(),
            follow_redirects: true,
            max_redirects: args.max_redirects,
            cookie: args.cookie.clone(),
            jobs: args.jobs,
        };
        let zd_client = Arc::new(HttpClient::new(zd_client_config)
            .unwrap_or_else(|e| {
                eprintln!("{} Failed to create HTTP client: {}", "[ERROR]".red().bold(), e);
                process::exit(1);
            }));

        let mut zd_scanner = zero_day::standalone::ZeroDayStandalone::new(
            zd_client,
            args.target_url().to_string(),
            args.duration,
        );

        let zd_findings = match run_scan_cancellable(zd_scanner.run()).await {
            Ok(f) => f,
            Err(e) => {
                eprintln!("\n{} Zero-Day scan failed: {}", "[FAILED]".red().bold(), e);
                process::exit(1);
            }
        };

        let elapsed = start_time.elapsed();
        let final_duration = TimeUtil::format_duration(elapsed);
        println!("\n  {} {}    {} {}",
            tc("·", ELITE_JADE_B), tc(&format!("Duration: {}", final_duration), ELITE_CYAN),
            tc("·", ELITE_JADE_B), tc(&format!("Ended: {}", TimeUtil::format_timestamp(&TimeUtil::now())), COL_DIM));

        // Auto-save reports
        let target_host_str = Parser::ensure_http(args.target_url());
        let host = url::Url::parse(&target_host_str)
            .ok()
            .and_then(|u| u.host_str().map(|h| h.to_string()))
            .unwrap_or_default();
        let target_ip = resolve_ip(&host).await.join(", ");

        let _ = std::fs::create_dir_all("reports");
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let json_path = std::path::PathBuf::from(format!("reports/oxide_report_{}.json", ts));
        {
            let mut reporter = report::generator::ReportGenerator::new(
                "json", args.target_url(), &target_ip, &[], elapsed.as_secs(),
            );
            for finding in &zd_findings {
                reporter.add_finding(finding.clone());
            }
            let _ = reporter.save_json_report(&json_path);
        }

        let html_path = std::path::PathBuf::from(format!("reports/oxide_report_{}.html", ts));
        {
            let mut reporter = report::generator::ReportGenerator::new(
                "html", args.target_url(), &target_ip, &[], elapsed.as_secs(),
            );
            for finding in &zd_findings {
                reporter.add_finding(finding.clone());
            }
            let _ = reporter.save_html_report(&html_path);
        }

        if !zd_findings.is_empty() {
            println!("  {} {}",
                tc("◈", COL_MED),
                tc(&format!("Found {} confirmed zero-day issue(s)", zd_findings.len()), ELITE_CYAN));
            for f in &zd_findings {
                Output::print_finding_stylish(
                    &format!("{:?}", f.severity),
                    &f.title,
                    &f.url,
                    &f.evidence,
                );
            }
        } else {
            println!("  {} {}",
                tc("◈", ELITE_JADE_B),
                tc("No zero-day vulnerabilities confirmed — target anomaly profile is clean", ELITE_CYAN));
        }

        println!("\n{} Zero-Day scan completed successfully", "[DONE]".green().bold());
        process::exit(0);
    }

    let (findings, hybrid_scanner, total_reqs) = if is_multi {
        let per_target = (args.threads / total_targets).max(1);
        let mut scanners = Vec::new();
        for (i, target_url) in args.url.iter().enumerate() {
            let mut target_args = args.clone();
            target_args.url = vec![target_url.clone()];
            target_args.threads = per_target;
            match HybridScanner::new(target_args) {
                Ok(scanner) => {
                    scanners.push((i + 1, scanner, target_url.clone()));
                }
                Err(e) => {
                    eprintln!("  [Target {}] Failed to initialize: {}", i + 1, e);
                }
            }
        }
        let mut all_findings = Vec::new();
        let mut total_reqs = 0usize;
        let global_start = std::time::Instant::now();
        let duration_limit = if args.duration > 0 {
            Some(std::time::Duration::from_secs(args.duration))
        } else {
            None
        };
        for (idx, mut scanner, url) in scanners {
            if let Some(limit) = duration_limit {
                if global_start.elapsed() >= limit {
                    println!("  {} {} {} — global duration reached",
                        tc("⏹", COL_MED),
                        tc(&format!("[Target {}]", idx), COL_DIM),
                        tc("skipped", COL_DIM));
                    continue;
                }
            }
            match run_scan_cancellable(scanner.run_hybrid_scan()).await {
                Ok(f) => {
                    total_reqs += scanner.req_count.load(std::sync::atomic::Ordering::Relaxed);
                    println!("  {} {}  {}",
                        tc("✓", ELITE_JADE_B),
                        tc(&format!("[Target {}] done", idx), COL_INFO),
                        tc(&format!("{} findings", f.len()), ELITE_JADE_B));
                    all_findings.extend(f);
                }
                Err(e) => {
                    eprintln!("  [Target {}] Scan failed: {} ({})", idx, e, url);
                }
            }
        }
        let summary = format!("Multi-Attack complete — {} total findings across {} targets",
            all_findings.len(), total_targets);
        println!("  {} {}", tc("⚔", COL_MED), tc(&summary, ELITE_LAVENDER_B));
        (all_findings, None, total_reqs)
    } else if args.get_modules().contains(&"engine".to_string()) {
        println!("Using legacy ScanEngine...");
        let engine = match ScanEngine::new(args.clone()) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("{} Failed to create HTTP client: {}", "[ERROR]".red().bold(), e);
                process::exit(1);
            }
        };
        match run_scan_cancellable(engine.run()).await {
            Ok(_) => (Vec::new(), None, 0),
            Err(e) => {
                eprintln!("{} ScanEngine failed: {}", "[ERROR]".red().bold(), e);
                process::exit(1);
            }
        }
    } else {
        let mut hybrid_scanner = match HybridScanner::new(args.clone()) {
            Ok(scanner) => scanner,
            Err(e) => {
                eprintln!("{} Failed to initialize scanner: {}", "[ERROR]".red().bold(), e);
                process::exit(1);
            }
        };
        
        match run_scan_cancellable(hybrid_scanner.run_hybrid_scan()).await {
            Ok(f) => {
                println!("[+] Scan complete — all phases finished");
                (f, Some(hybrid_scanner), 0)
            }
            Err(e) => {
                eprintln!("\n{} Scan failed: {}", "[FAILED]".red().bold(), e);
                process::exit(1);
            }
        }
    };
    
    let elapsed = start_time.elapsed();
    let req_count = if total_reqs > 0 {
        total_reqs
    } else {
        hybrid_scanner.as_ref()
            .map(|s| s.req_count.load(std::sync::atomic::Ordering::Relaxed))
            .unwrap_or(0)
    };

    Output::print_scan_complete(
        &format!("{:.1}s", elapsed.as_secs_f64()),
        req_count,
        &findings,
    );
    
    if findings.is_empty() {
        println!("  {} {}", tc("◈", ELITE_JADE_B), tc("No vulnerabilities found — target appears secure", ELITE_CYAN));
    } else {
        println!("  {} {}", tc("◈", COL_MED), tc(&format!("Found {} issue(s):", findings.len()), ELITE_CYAN));
        for f in &findings {
            Output::print_finding_stylish(
                &format!("{:?}", f.severity),
                &f.title,
                &f.url,
                &f.evidence,
            );
        }
    }

    if let Some(scanner) = &hybrid_scanner {
        let detailed_findings = scanner.get_findings();
        if !detailed_findings.is_empty() && args.verbose {
            println!("  {}", tc("Detailed findings:", COL_DIM).underline());
            for (idx, finding) in detailed_findings.iter().take(10).enumerate() {
                println!("    {}. {} — {}",
                    tc(&format!("{:>2}", idx + 1), COL_DIM),
                    tc(&finding.title, ELITE_LAVENDER_B),
                    tc(&finding.url[..finding.url.len().min(60)], ELITE_CYAN));
            }
            if detailed_findings.len() > 10 {
                println!("    {} {} more findings not shown", tc("⋯", COL_DIM), detailed_findings.len() - 10);
            }
        }
    }

    let final_duration = TimeUtil::format_duration(elapsed);
    println!("  {} {}    {} {}",
        tc("·", ELITE_JADE_B), tc(&format!("Duration: {}", final_duration), ELITE_CYAN),
        tc("·", ELITE_JADE_B), tc(&format!("Ended: {}", TimeUtil::format_timestamp(&TimeUtil::now())), COL_DIM));

    // ── Auto-save reports (JSON + HTML) after every scan ─────────────────
    let target_host_str = Parser::ensure_http(args.target_url());
    let host = url::Url::parse(&target_host_str)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_string()))
        .unwrap_or_default();
    let target_ip = resolve_ip(&host).await.join(", ");

    let discovered_urls: Vec<String> = hybrid_scanner.as_ref()
        .map(|s| s.get_discovered_urls())
        .unwrap_or_default();

    let _ = std::fs::create_dir_all("reports");
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Save JSON report
    let json_path = std::path::PathBuf::from(format!("reports/oxide_report_{}.json", ts));
    {
        let mut reporter = report::generator::ReportGenerator::new(
            "json", args.target_url(), &target_ip, &discovered_urls, elapsed.as_secs(),
        );
        for finding in &findings {
            reporter.add_finding(finding.clone());
        }
        match reporter.save_json_report(&json_path) {
            Ok(_) => println!("  {} Report saved: {}", Colors::ok("[OK]"), json_path.display()),
            Err(e) => eprintln!("  {} Failed to save JSON report: {}", "[ERROR]".red(), e),
        }
    }

    // Save HTML report
    let html_path = std::path::PathBuf::from(format!("reports/oxide_report_{}.html", ts));
    {
        let mut reporter = report::generator::ReportGenerator::new(
            "html", args.target_url(), &target_ip, &discovered_urls, elapsed.as_secs(),
        );
        for finding in &findings {
            reporter.add_finding(finding.clone());
        }
        match reporter.save_html_report(&html_path) {
            Ok(_) => println!("  {} Report saved: {}", Colors::ok("[OK]"), html_path.display()),
            Err(e) => eprintln!("  {} Failed to save HTML report: {}", "[ERROR]".red(), e),
        }
    }

    // Also save user-requested format if --output was specified
    if let Some(output_path) = &args.output {
        let mut reporter = report::generator::ReportGenerator::new(
            &args.format, args.target_url(), &target_ip, &discovered_urls, elapsed.as_secs(),
        );
        for finding in &findings {
            reporter.add_finding(finding.clone());
        }
        let output_path = std::path::PathBuf::from(output_path);
        match reporter.save(&output_path) {
            Ok(_) => println!("\n{} Report saved to: {}", Colors::ok("[OK]"), output_path.display()),
            Err(e) => eprintln!("\n{} Failed to save report: {}", "[ERROR]".red(), e),
        }
    }
    
    // Use Colors::ok for final status display
    println!("{}", Colors::ok(&format!("Scan complete: {} vulnerabilities found", findings.len())));
    colors::print_status("OK", &format!("Found {} vulnerabilities", findings.len()));
    
    println!("[+] Scan complete — {} vulnerabilities identified", findings.len());
    
    // Use additional TimeUtil functions
    let utc_now = TimeUtil::now_utc();
    println!("Scan completed at (UTC): {}", TimeUtil::format_timestamp_iso(&utc_now));
    
    // Use TimeUtil::elapsed_since with a new instant
    let test_start = std::time::Instant::now();
    TimeUtil::sleep(std::time::Duration::from_millis(10));
    let _test_elapsed = TimeUtil::elapsed_since(test_start);
    
    // Use sleep_async and timeout
    let sleep_future = TimeUtil::sleep_async(std::time::Duration::from_millis(10));
    let _ = TimeUtil::timeout(std::time::Duration::from_millis(100), sleep_future).await;
    
    println!("\n{} Scan completed successfully", "[DONE]".green().bold());
}
