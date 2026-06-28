// ----------------------------------------------------------------------------
//  mod.rs — Advanced OXIDE features
// ----------------------------------------------------------------------------
//  Advanced OXIDE features — API fuzzing, clustering, JS crawling, ML detection
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
//  Advanced Module Overview / 高度なモジュール概要
//  This module aggregates OXIDE's advanced scanning subsystems:
//    api_fuzzer    — REST/GraphQL API fuzzing with injection templates
//    cache         — response caching layer (memory + disk with LRU eviction)
//    cluster       — distributed scan coordination (master/agent architecture)
//    crawler_js    — JS-aware crawling (SPA support, URL extraction)
//    evasion       — WAF/IDS bypass techniques (encoding, header manipulation)
//    ml_detector   — ML-based anomaly detection (statistical + neural)
//    plugin        — dynamic plugin loading via FFI (.so/.dll/.dylib)
//    rate_limiter  — token-bucket algorithm + adaptive rate adjustment
//    session       — multi-phase scan session state management
//    websocket     — WebSocket fuzzing (handshake, frame injection, auth bypass)
//
//  Each module is self-contained and communicates via OXIDE's shared types.
/// Advanced OXIDE features for v8
/// Includes distributed scanning, advanced evasion, ML detection, and more

pub mod api_fuzzer;
pub mod cache;
pub mod cluster;
pub mod crawler_js;
pub mod evasion;
pub mod ml_detector;
pub mod plugin;
pub mod rate_limiter;
pub mod session;
pub mod websocket;
