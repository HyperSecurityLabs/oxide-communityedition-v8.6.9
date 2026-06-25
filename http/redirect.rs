// ----------------------------------------------------------------------------
//  redirect.rs — HTTP redirect handling
// ----------------------------------------------------------------------------
//  HTTP redirect handling — follows redirect chains, detects open redirects.
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
//  redirect.rs — HTTPリダイレクト処理
//  HTTP redirect handling — follows redirect chains, detects open redirects
//  Locationヘッダー抽出ステータスコードによるリダイレクト分類

use crate::http::response::HttpResponse;

//  extract_redirect_url — Locationヘッダーからリダイレクト先URLを抽出
//  Extracts redirect URL from Location header
pub fn extract_redirect_url(response: &HttpResponse) -> Option<String> {
    response
        .headers
        .get("location")
        .or_else(|| response.headers.get("Location"))
        .cloned()
}

//  is_303_redirect — 303 See Other リダイレクトを電脳検出
//  Detects 303 See Other redirect (POSTGET変換)
pub fn is_303_redirect(response: &HttpResponse) -> bool {
    response.status == 303
}

//  is_redirect — ステータスコードがリダイレクトか判定
//  Checks if status code is a redirect (301/302/303/307/308)
pub fn is_redirect(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

//  should_switch_to_get — 303時はPOSTGETに切り替え
//  Should switch from POST to GET for 303 redirect
pub fn should_switch_to_get(status: u16) -> bool {
    matches!(status, 303)
}
