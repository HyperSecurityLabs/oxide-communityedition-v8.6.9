// ----------------------------------------------------------------------------
//  mod.rs — scanner module collection
// ----------------------------------------------------------------------------
//  Aggregates all security scanner submodules into a single module. Each
//  submodule implements a distinct vulnerability detection technique — SQLi,
//  XSS, LFI, command injection, CORS, TLS, and more — for comprehensive
//  web application security assessment.
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

//  モジュール構成 / module composition:
//   Each submodule implements a distinct vulnerability detection technique.
//    SQLi     (sqli_scanner, blind_sqli_scanner) — error/time/boolean/union
//    XSS      (xss_scanner) — reflected/DOM/stored
//    LFI      (lfi_scanner, path_traversal_scanner) — inclusion/traversal
//    CMD      (cmd_injection_scanner) — OS command injection
//    CORS     (cors_scanner) — misconfiguration analysis
//    TLS      (tls_scanner) — protocol/certificate assessment
//    DB       (db_fingerprinter) — database type fingerprinting
//    CREDS    (default_creds_scanner) — default credential testing
//    CF       (hypersecurity_cf) — Cloudflare/WAF bypass analysis
//    PREC     (precision) — CGI false positive elimination
//    COMMON   (common_app_scanner) — Nikto-style path enumeration (6000+ tests)
// Scanner module for performing security tests
pub mod blind_sqli_scanner;
pub mod hypersecurity_cf;
pub mod cmd_injection_scanner;
pub mod common_app_scanner;
pub mod cors_scanner;
pub mod db_fingerprinter;
pub mod default_creds_scanner;
pub mod lfi_scanner;
pub mod path_traversal_scanner;
pub mod precision;
pub mod sqli_scanner;
pub mod tls_scanner;
pub mod xss_scanner;
