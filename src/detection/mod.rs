// ----------------------------------------------------------------------------
//  mod.rs — Detection module root
// ----------------------------------------------------------------------------
//  Detection module root — re-exports all detection submodules.
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
//  detection/ モジュールルート — サブモジュールの再エクスポート
//  Module root — re-exports all detection submodules
//  各サブモジュールは特定の電脳検出機能を担当：
//   analyzer   —  脆弱性発見構造体 (Finding) と分析パイプライン
//   behavior   —  WAF識別 / エラーページ電脳検出 / 技術スタック分析
//   confirm    —  セカンダリプローブによる偽陽性除去
//   matcher    —  正規表現ベースのシグネチャマッチング
//   scorer     — ※ 編集距離 (Levenshtein) + ベイズ信頼度スコアリング
//   signatures —  シグネチャデータベース (ID・重大度・パターン)
//   timing     —  タイムベース盲検インジェクション用応答時間測定

pub mod analyzer;
pub mod behavior;
pub mod confirm;
pub mod matcher;
pub mod scorer;
pub mod signatures;
pub mod timing;
