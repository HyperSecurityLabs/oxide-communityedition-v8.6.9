// ----------------------------------------------------------------------------
//  mod.rs — CLI module structure
// ----------------------------------------------------------------------------
//  Root module for the CLI subsystem. Re-exports submodules (args, colors,
//  config, display, output, parser, progress, spinner) that handle command-line
//  argument parsing, terminal output, configuration, and progress rendering.
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
// ◆ CLIモジュール構造 / CLI module structure overview
// ■  args.rs — clapによるコマンドライン電脳引数解析 / argument parsing via clap derive
// ■  colors.rs — ANSI TrueColor定数とステータス表示 / colour constants and status helpers
// ■  config.rs — TOML電脳設定の読み書き生成 / config load/save/generate
// ■  display.rs — ターミナルUIエンジン / terminal display engine (ScanBoard, AgentBar, braille)
// ■  output.rs — 下位互換性のための再エクスポート / backward-compat re-export shim
// ■  parser.rs — URL・ヘッダ・クッキー・モジュールパース / input parsing utilities
// ■  progress.rs — アトミックカウンタによる進行追跡 / atomic scan progress tracker
// ■  spinner.rs — 点字スピナーアニメーション / braille spinner animation system
//
pub mod args;
pub mod colors;
pub mod config;
pub mod display;
pub mod output;
pub mod parser;
pub mod progress;
pub mod spinner;
