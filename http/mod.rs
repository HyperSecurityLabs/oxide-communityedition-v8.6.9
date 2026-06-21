// ----------------------------------------------------------------------------
//  mod.rs — HTTP module root
// ----------------------------------------------------------------------------
//  HTTP module root — re-exports HTTP client and related types.
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
// ◆ http/ モジュールルート — HTTP通信モジュール
// ★ HTTP module root — re-exports all HTTP submodules
// ■ 各サブモジュールの役割：
//   client       — ★ HTTPクライアント構築 (reqwestラッパー)
//   cookies      — ◆ クッキー管理とセッション永続化
//   crawl_types  — ● 電脳収集用データ構造
//   headless     — ▲ ヘッドレスブラウザレンダリング
//   headers      — ※ セキュリティヘッダー監査
//   proxy_loader — ➤ プロキシライブラリ (FFI) 読み込み
//   redirect     — ♢ リダイレクト処理
//   request      — ★ HTTPリクエストビルダー
//   response     — ◆ HTTPレスポンスパーサー
//   tls          — ● TLSバージョンチェック
//   useragents   — ▲ User-Agentローテーション

pub mod client;
pub mod cookies;
pub mod crawl_types;
pub mod headless;
pub mod headers;
pub mod proxy_loader;
pub mod redirect;
pub mod request;
pub mod response;
pub mod tls;
pub mod useragents;
