// ----------------------------------------------------------------------------
//  xml.rs — XML report generator
// ----------------------------------------------------------------------------
//  XML report generator — exports findings in XML format for interoperability.
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

// ◆ XmlReport: XMLレポート生成器
// ◆ Exports findings as XML for interoperability with external security tools.
// ■ スキーマ準拠:
//   <scan xmlns="http://oxide.org/schema">
//     <metadata> — tool name + version
//     <findings> — <finding>要素のリスト (url/severity/title/description/evidence/remediation)
// ■ エスケープ: &lt; &gt; &amp; &quot; &apos; をXMLエンティティに変換
// ♢ escape_xml: 5つのXML特殊文字を安全にエスケープ
pub struct XmlReport;

impl XmlReport {
    // ◆ generate_header: XMLドキュメントヘッダー
    // ◆ Generates XML declaration + root <scan> element with metadata.
    pub fn generate_header() -> String {
        r#"<?xml version="1.0" encoding="UTF-8"?>
<scan xmlns="http://oxide.org/schema">
    <metadata>
        <tool>OXIDE</tool>
        <version>1.0.0</version>
    </metadata>
    <findings>
"#.to_string()
    }

    // ◆ generate_finding: XML発見要素生成
    // ◆ Generates a single <finding> element with all fields XML-escaped.
    pub fn generate_finding(
        url: &str,
        severity: &str,
        title: &str,
        description: &str,
        evidence: &str,
        remediation: &str,
    ) -> String {
        format!(
        r#"        <finding>
            <url>{}</url>
            <severity>{}</severity>
            <title>{}</title>
            <description>{}</description>
            <evidence>{}</evidence>
            <remediation>{}</remediation>
        </finding>
"#,
            Self::escape_xml(url),
            Self::escape_xml(severity),
            Self::escape_xml(title),
            Self::escape_xml(description),
            Self::escape_xml(evidence),
            Self::escape_xml(remediation)
        )
    }

    // ◆ generate_footer: XMLフッター
    // ◆ Closes <findings> and <scan> elements.
    pub fn generate_footer() -> String {
        r#"    </findings>
</scan>"#.to_string()
    }

    fn escape_xml(text: &str) -> String {
        text.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&apos;")
    }
}
