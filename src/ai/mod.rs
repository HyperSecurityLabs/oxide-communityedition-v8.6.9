// ----------------------------------------------------------------------------
//  mod.rs — AI module root
// ----------------------------------------------------------------------------
//  AI module root — ML-powered exploit analysis, pattern learning, payload mutation
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
//  AI Module Overview / AIモジュール概要
//  This module provides ML-powered intelligence for adaptive exploitation:
//    exploit_analyzer  — learns from response patterns to identify exploitable paths
//    response_analyzer — parses HTTP responses for ML feature extraction
//    payload_mutator   — AI-driven payload mutation (8 strategies + WAF bypass)
//    pattern_learner   — Bayesian pattern learning with exponential moving average
//
//  The AI pipeline: response  feature extraction  pattern learning  payload mutation
// AI-powered exploit analysis and adaptive testing
pub mod exploit_analyzer;
pub mod response_analyzer;
pub mod payload_mutator;
pub mod pattern_learner;
