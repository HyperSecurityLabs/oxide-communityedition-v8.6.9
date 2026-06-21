// ----------------------------------------------------------------------------
//  mod.rs — zero-day detection module
// ----------------------------------------------------------------------------
//  zero-day detection module — ML-based anomaly detection for unknown vulnerabilities
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
// ◆ ゼロデイ電脳検出モジュール — Zero-Day Detection Module Overview
// ◆ This module provides ML-based anomaly detection for discovering unknown
// ◆ vulnerabilities (zero-days) by baseline profiling, feature extraction, and
// ◆ ensemble classification (Random Forest + SVM).
// ◆
// ◆ ■ features.rs  — 特徴抽出 / HTTP response → ML feature vectors
// ◆ ■ classifier.rs — ML分類器 / Random Forest + SVM classifier
// ◆ ■ baseline.rs   — ベースライン学習 / Statistical profiling of normal responses
// ◆ ■ anomaly.rs    — 異常検知 / Anomaly scoring against baseline
// ◆ ■ engine.rs     — エンジン電脳制御 / Orchestration: baseline → feature → classify
// ◆ ■ trainer.rs    — トレーニング / ML training pipeline
// ◆ ■ standalone.rs — スタンドアロン / Independent zero-day scanner mode
// ◆ ■ hpp.rs        — HPP電脳検出 / HTTP Parameter Pollution testing
// ---------------------------------------------------------------------------

pub mod features;
pub mod classifier;
pub mod baseline;
pub mod anomaly;
pub mod engine;
pub mod trainer;
pub mod standalone;
pub mod hpp;
