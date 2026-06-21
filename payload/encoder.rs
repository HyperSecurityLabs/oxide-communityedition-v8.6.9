// ----------------------------------------------------------------------------
//  encoder.rs — payload encoder
// ----------------------------------------------------------------------------
//  Payload encoder — URL, base64, hex encoding for WAF/IDS evasion.
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

// ◆ Encoder: ペイロードエンコーダ
// ◆ Encoding techniques for WAF/IDS evasion.
// ■ エンコード手法:
//   ➊ url_encode — URLパーセントエンコーディング (%XX)
//   ➋ base64_encode — Base64標準エンコーディング
//   ➌ hex_encode — 16進数エンコーディング
//   ➍ double_encode — 二重URLエンコード (%25XX → %XX)
// ♢ WAFバイパスに有効: 二重エンコードで復号処理を混乱させる
pub struct Encoder;

impl Encoder {
    // ◆ url_encode: URLパーセントエンコード
    // ◆ Percent-encodes special characters for safe URL transmission.
    // ■ 例: "<script>" → "%3Cscript%3E"
    pub fn url_encode(input: &str) -> String {
        urlencoding::encode(input).to_string()
    }

    // ◆ base64_encode: Base64エンコード
    // ◆ Encodes input to standard Base64 (RFC 4648) for data encoding.
    // ■ 例: "alert(1)" → "YWxlcnQoMSk="
    pub fn base64_encode(input: &str) -> String {
        use base64::{Engine as _, engine::general_purpose};
        general_purpose::STANDARD.encode(input.as_bytes())
    }

    // ◆ hex_encode: 16進数エンコード
    // ◆ Converts input bytes to hexadecimal string representation.
    // ■ 例: "id" → "6964"
    pub fn hex_encode(input: &str) -> String {
        hex::encode(input.as_bytes())
    }

    // ◆ double_encode: 二重URLエンコード
    // ◆ Applies URL encoding twice — bypasses decoders that decode only once.
    // ■ 例: "<" → "%253C" (first: %3C, second: %253C)
    pub fn double_encode(input: &str) -> String {
        Self::url_encode(&Self::url_encode(input))
    }
}
