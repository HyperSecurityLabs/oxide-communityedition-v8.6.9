// ----------------------------------------------------------------------------
//  mod.rs — payload module root
// ----------------------------------------------------------------------------
//  Payload module root — re-exports all payload libraries.
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

//  Payload Module: ペイロード生成ライブラリ
//  Payload generation and manipulation library for vulnerability scanning.
//  Sub-modules:
//   command_injection — Unix/Windows/ブラインドコマンド / OS command payloads
//   encoder           — URL/Base64/Hex/二重エンコード / encoding techniques
//   fuzzer            — ペイロード順列生成 / payload permutation & fuzzing
//   generator         — テクノロジー認識ペイロード / tech-aware payload selection
//   lfi               — パストラバーサル / LFI path traversal & PHP wrappers
//   mutator           — ケース/エンコード/パディング変換 / mutation strategies
//   sql_injection     — エラー/UNION/ブール/時間/NoSQL / SQLi payload types
//   xss               — Reflected/Stored/DOM/CSPバイパス / XSS attack variants
pub mod command_injection;
pub mod encoder;
pub mod fuzzer;
pub mod generator;
pub mod lfi;
pub mod mutator;
pub mod sql_injection;
pub mod xss;
