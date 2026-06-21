// ----------------------------------------------------------------------------
//  lib.rs — library root with public API re-exports
// ----------------------------------------------------------------------------
//  Library crate root that declares all public modules (advanced, ai, cli, core,
//  detection, http, payload, report, scanner, utils) and re-exports key types
//  (CliArgs, ScanEngine, Analyzer, Finding, HttpClient, PayloadGenerator,
//  ReportGenerator) for external consumers. Also defines the global SHUTDOWN
//  atomic flag used for graceful Ctrl+C/SIGTERM handling across the async
//  runtime.
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
// ◆ ライブラリルートモジュール / library root module
// ◆ 全公開モジュールと型を再エクスポート / re-exports all public modules & types
//
pub mod advanced;
pub mod ai;
pub mod cli;
pub mod core;
pub mod db;
pub mod detection;
pub mod http;
pub mod insta;
pub mod payload;
pub mod session_hijack;
pub mod report;
pub mod scanner;
pub mod utils;

// ◆ シャットダウンフラグ / global shutdown flag — set by SIGINT/SIGTERM handlers
// ◆ 全非同期ループがこのフラグをポーリングして安全に終了 / all async loops poll this for safe exit
use std::sync::atomic::{AtomicBool, Ordering};

pub static SHUTDOWN: AtomicBool = AtomicBool::new(false);

// ◆ シャットダウン要求確認 / check if shutdown was requested
pub fn is_shutdown_requested() -> bool {
    SHUTDOWN.load(Ordering::Acquire)
}



pub use cli::args::CliArgs;
pub use core::engine::ScanEngine;
pub use detection::analyzer::{Analyzer, Finding, Severity};
pub use http::client::HttpClient;
pub use payload::generator::PayloadGenerator;
pub use report::generator::ReportGenerator;

// ◆ ライブラリ定数 / library constants — version, name, description
pub const VERSION: &str = "7.9.1-elite";
pub const NAME: &str = "OXIDE Community Edition";
pub const DESCRIPTION: &str = "Open eXtensible Intelligence & Detection Engine — Community Edition";
