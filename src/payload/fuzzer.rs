// ----------------------------------------------------------------------------
//  fuzzer.rs — payload fuzzer
// ----------------------------------------------------------------------------
//  Payload fuzzer — generates permutations of base payloads for extensive coverage.
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

use crate::payload::xss::XssPayloads;
use crate::payload::sql_injection::SqlInjection;
use crate::payload::lfi::Lfi;
use crate::payload::command_injection::CommandInjection;


//  Fuzzer: ペイロードファザー
//  Generates expanded payload sets by combining base payloads from all categories.
//  戦略:
//   - 各ベースペイロードライブラリから全ペイロードを収集
//   - SQLi, XSS, LFI, CommandInjectionの全カテゴリを網羅
//   - ファジングで広範囲カバレッジを確保
//  ペイロードの順列生成: 基本ペイロード + バリエーションの総和
pub struct Fuzzer;

impl Fuzzer {
    pub fn new() -> Self {
        Self
    }

    //  generate_sql_payloads: SQLiペイロード一括生成
    //  Aggregates error-based, WAF bypass, time-based, union, boolean, stacked SQLi payloads.
    //  全サブカテゴリを単一ベクターにマージ
    pub fn generate_sql_payloads(&self) -> Vec<String> {
        let mut payloads = SqlInjection::get_error_payloads();
        payloads.extend(SqlInjection::get_waf_bypass_payloads());
        payloads.extend(SqlInjection::get_time_payloads());
        payloads.extend(SqlInjection::get_union_payloads());
        payloads.extend(SqlInjection::get_boolean_payloads().iter().map(|(t, _)| t.clone()));
        payloads.extend(SqlInjection::get_stacked_payloads());
        payloads
    }

    //  generate_destructive_sql_payloads: 電脳攻撃的SQLiペイロード
    //  Real-world attack payloads — webshell deploy, privilege esc, data exfil.
    pub fn generate_destructive_sql_payloads(&self) -> Vec<String> {
        SqlInjection::get_destructive_payloads()
    }

    //  generate_nosql_payloads: NoSQLインジェクションペイロード
    //  MongoDB operator injection — $gt, $ne, $regex, $where, array injection.
    pub fn generate_nosql_payloads(&self) -> Vec<String> {
        SqlInjection::get_nosql_payloads()
    }

    //  generate_xss_payloads: XSSペイロード一括生成
    //  Aggregates basic, event handler, WAF bypass, and encoded XSS payloads.
    pub fn generate_xss_payloads(&self) -> Vec<String> {
        let mut payloads = XssPayloads::get_basic_payloads();
        payloads.extend(XssPayloads::get_event_handlers());
        payloads.extend(XssPayloads::get_waf_bypass_payloads());
        payloads.extend(XssPayloads::get_encoded_payloads());
        payloads
    }

    //  generate_ssti_payloads: SSTIペイロード
    //  Server-Side Template Injection — Jinja2, Freemarker, Velocity, Smarty, etc.
    pub fn generate_ssti_payloads(&self) -> Vec<String> {
        XssPayloads::get_ssti_payloads()
    }

    //  generate_lfi_payloads: LFIペイロード
    //  Path traversal sequences — Unix, Windows, encoding variants, PHP wrappers.
    pub fn generate_lfi_payloads(&self) -> Vec<String> {
        Lfi::get_payloads()
    }

    //  generate_cmd_injection_payloads: OSコマンドインジェクション一括生成
    //  Aggregates basic, OOB, time-based, reverse shell, and Windows payloads.
    //  listener_ip/portはリバースシェル用
    pub fn generate_cmd_injection_payloads(&self, listener_ip: &str, listener_port: u16) -> Vec<String> {
        let mut payloads = CommandInjection::get_basic_payloads();
        payloads.extend(CommandInjection::get_oob_payloads("collab.oxide.local"));
        payloads.extend(CommandInjection::get_time_based_payloads());
        payloads.extend(CommandInjection::get_reverse_shell_payloads(listener_ip, listener_port));
        payloads.extend(CommandInjection::get_windows_payloads());
        payloads
    }

}
