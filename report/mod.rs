// ----------------------------------------------------------------------------
//  mod.rs — report module root
// ----------------------------------------------------------------------------
//  Report module root — re-exports all report format generators.
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

// ◆ Report Module: レポート出力モジュール
// ◆ Scan report generation in multiple formats for interoperability.
// ■ Sub-modules:
//   generator — レポート生成フロー (収集→整形→出力) / finding collection & format dispatch
//   csv      — カンマ区切り出力 / spreadsheet-compatible CSV export
//   html     — サイバーパンク形式HTML / styled HTML with severity color coding
//   json     — 構造化JSON出力 / programmatic JSON serialization
//   xml      — XML出力 / schema-compliant XML representation
pub mod csv;
pub mod generator;
pub mod html;
pub mod json;
pub mod xml;
