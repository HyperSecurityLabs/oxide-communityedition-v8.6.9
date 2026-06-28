// ----------------------------------------------------------------------------
//  csv.rs — CSV report generator
// ----------------------------------------------------------------------------
//  CSV report generator — exports findings in comma-separated format for spreadsheet analysis.
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

//  CsvReport: CSVレポート生成器
//  Exports findings as comma-separated values for spreadsheet/BI tool analysis.
//  カラム構成: URL, Severity, Title, Description, Evidence, Remediation
//  エスケープ処理: カンマ/引用符/改行を含むフィールドは二重引用符でラップ
//  escape_field: 特殊文字を含むフィールドを安全にCSVフォーマット
pub struct CsvReport;

impl CsvReport {
    //  generate_header: CSVヘッダー行生成
    //  Returns the CSV column header line.
    pub fn generate_header() -> String {
        "URL,Severity,Title,Description,Evidence,Remediation\n".to_string()
    }

    pub fn escape_field(field: &str) -> String {
        let needs_quotes = field.contains(',') || field.contains('"') || field.contains('\n');
        
        if needs_quotes {
            let escaped = field.replace('"', "\"\"");
            format!("\"{}\"", escaped)
        } else {
            field.to_string()
        }
    }

    //  generate_row: CSVデータ行生成
    //  Formats a single finding as a CSV row with proper escaping.
    //  ヘルパー: escape_field — カンマ/引用符/改行を処理
    pub fn generate_row(
        url: &str,
        severity: &str,
        title: &str,
        description: &str,
        evidence: &str,
        remediation: &str,
    ) -> String {
        format!(
            "{},{},{},{},{},{}\n",
            Self::escape_field(url),
            Self::escape_field(severity),
            Self::escape_field(title),
            Self::escape_field(description),
            Self::escape_field(evidence),
            Self::escape_field(remediation)
        )
    }
}
