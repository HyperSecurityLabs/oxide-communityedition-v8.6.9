// ----------------------------------------------------------------------------
//  json.rs — JSON report generator
// ----------------------------------------------------------------------------
//  JSON report generator — exports structured findings as JSON for programmatic consumption.
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

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::detection::analyzer::Finding;

//  JsonReport: JSONレポート生成器
//  Structured JSON export for programmatic consumption and integration.
//  構成:
//   scan_info — ターゲット/IP/時間/バージョン (ScanInfo)
//   findings — 発見結果の配列 (FindingJson: url/severity/title/description/evidence/remediation)
//   statistics — 統計情報 (total_findings + by_severity集計)
//   discovered_urls — 発見URL一覧
//  serde Serialize/Deserialize対応により他ツールとの連携が容易
#[derive(Debug, Serialize, Deserialize)]
pub struct JsonReport {
    pub scan_info: ScanInfo,
    pub findings: Vec<FindingJson>,
    pub statistics: Statistics,
    pub discovered_urls: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScanInfo {
    pub target: String,
    pub target_ip: String,
    pub start_time: String,
    pub end_time: String,
    pub duration_seconds: u64,
    pub oxyde_version: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FindingJson {
    pub url: String,
    pub severity: String,
    pub title: String,
    pub description: String,
    pub evidence: String,
    pub remediation: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Statistics {
    pub total_findings: usize,
    pub by_severity: HashMap<String, usize>,
}

impl JsonReport {
    //  from_findings: 発見結果からJSONレポート構築
    //  Constructs a complete JsonReport from scan findings and metadata.
    //  処理: Finding  FindingJson変換  HashMap by_severity集計  Self
    pub fn from_findings(target: &str, target_ip: &str, findings: &[Finding], discovered_urls: &[String], duration_secs: u64) -> Self {
        let finding_jsons: Vec<FindingJson> = findings
            .iter()
            .map(|f| FindingJson {
                url: f.url.clone(),
                severity: format!("{:?}", f.severity),
                title: f.title.clone(),
                description: f.description.clone(),
                evidence: f.evidence.clone(),
                remediation: f.remediation.clone(),
            })
            .collect();

        let mut by_severity: HashMap<String, usize> = HashMap::new();
        for finding in findings {
            let sev = format!("{:?}", finding.severity);
            *by_severity.entry(sev).or_insert(0) += 1;
        }

        Self {
            scan_info: ScanInfo {
                target: target.to_string(),
                target_ip: target_ip.to_string(),
                start_time: String::new(),
                end_time: String::new(),
                duration_seconds: duration_secs,
                oxyde_version: "8.5.0community-edition".to_string(),
            },
            findings: finding_jsons,
            statistics: Statistics {
                total_findings: findings.len(),
                by_severity,
            },
            discovered_urls: discovered_urls.to_vec(),
        }
    }
}
