// ----------------------------------------------------------------------------
//  generator.rs — report generator
// ----------------------------------------------------------------------------
//  Report generator — creates structured reports from scan findings.
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

use anyhow::Result;
use std::collections::VecDeque;
use std::path::PathBuf;

use crate::detection::analyzer::Finding;
use crate::report::xml::XmlReport;
use crate::report::json::JsonReport;
use crate::report::html::HtmlReport;
use crate::report::csv::CsvReport;

//  ReportGenerator: レポート生成フロー電脳制御
//  Collects findings and dispatches to format-specific generators.
//  Flow:
//   1. add_finding() — 電脳走査結果をVecDequeに収集
//   2. save() — 指定フォーマットに応じてdispatch (json/html/csv/xml)
//   3. print_summary() — コンソールに重要度別集計を表示
//  VecDequeでFIFO順序を維持 / テスト容易性のためクローン可能
pub struct ReportGenerator {
    findings: VecDeque<Finding>,
    format: String,
    target: String,
    target_ip: String,
    discovered_urls: Vec<String>,
    duration_secs: u64,
}

impl ReportGenerator {
    pub fn new(format: &str, target: &str, target_ip: &str, discovered_urls: &[String], duration_secs: u64) -> Self {
        Self {
            findings: VecDeque::new(),
            format: format.to_string(),
            target: target.to_string(),
            target_ip: target_ip.to_string(),
            discovered_urls: discovered_urls.to_vec(),
            duration_secs,
        }
    }

    pub fn add_finding(&mut self, finding: Finding) {
        self.findings.push_back(finding);
    }

    pub fn get_findings(&self) -> &VecDeque<Finding> {
        &self.findings
    }

    pub fn count(&self) -> usize {
        self.findings.len()
    }

    //  save: フォーマットディスパッチ
    //  Dispatches to the correct format handler based on self.format string.
    //  デフォルト: JSON (未知のフォーマットはJSONにフォールバック)
    pub fn save(&self, path: &PathBuf) -> Result<()> {
        match self.format.as_str() {
            "json" => self.save_json(path),
            "html" => self.save_html(path),
            "csv" => self.save_csv(path),
            "xml" => self.save_xml(path),
            _ => self.save_json(path),
        }
    }

    pub fn save_json_report(&self, path: &PathBuf) -> Result<()> {
        use std::fs;
        let findings: Vec<_> = self.findings.iter().cloned().collect();
        let json_report = JsonReport::from_findings(&self.target, &self.target_ip, &findings, &self.discovered_urls, self.duration_secs);
        let json = serde_json::to_string_pretty(&json_report)?;
        fs::write(path, json)?;
        Ok(())
    }

    pub fn save_html_report(&self, path: &PathBuf) -> Result<()> {
        use std::fs;
        let findings: Vec<_> = self.findings.iter().cloned().collect();
        let dur = format!("{}s", self.duration_secs);
        let mut html = HtmlReport::generate_header(
            "OXIDE Security Scan Report",
            &self.target,
            &self.target_ip,
            &dur,
            self.discovered_urls.len(),
        );
        html.push_str(&HtmlReport::generate_links_section(&self.discovered_urls));
        html.push_str(&HtmlReport::generate_table_start());

        for finding in &findings {
            html.push_str(&format!(
                "<tr class=\"finding\"><td class=\"severity-cell {}\">{:?}</td><td><a class=\"finding-url\" href=\"{}\" target=\"_blank\">{}</a></td><td class=\"finding-title\">{}</td><td class=\"finding-desc\">{}</td></tr>\n",
                format!("{:?}", finding.severity).to_lowercase(),
                finding.severity,
                finding.url,
                finding.url,
                finding.title,
                finding.description,
            ));
        }

        html.push_str(&HtmlReport::generate_table_end());
        html.push_str(&HtmlReport::generate_footer());
        fs::write(path, html)?;
        Ok(())
    }

    fn save_json(&self, path: &PathBuf) -> Result<()> {
        self.save_json_report(path)
    }

    fn save_html(&self, path: &PathBuf) -> Result<()> {
        self.save_html_report(path)
    }

    fn save_csv(&self, path: &PathBuf) -> Result<()> {
        use std::fs;
        let mut csv = CsvReport::generate_header();

        for finding in &self.findings {
            csv.push_str(&CsvReport::generate_row(
                &finding.url,
                &format!("{:?}", finding.severity),
                &finding.title,
                &finding.description,
                &finding.evidence,
                &finding.remediation,
            ));
        }

        fs::write(path, csv)?;
        Ok(())
    }

    fn save_xml(&self, path: &PathBuf) -> Result<()> {
        use std::fs;
        let mut xml = XmlReport::generate_header();

        for finding in &self.findings {
            xml.push_str(&XmlReport::generate_finding(
                &finding.url,
                &format!("{:?}", finding.severity),
                &finding.title,
                &finding.description,
                &finding.evidence,
                &finding.remediation,
            ));
        }

        xml.push_str(&XmlReport::generate_footer());
        fs::write(path, xml)?;
        Ok(())
    }

    //  print_summary: コンソール集計表示
    //  Prints a severity breakdown summary to stdout.
    //  カウント: Critical / High / Medium / Low / Info
    pub fn print_summary(&self) {
        let mut critical = 0;
        let mut high = 0;
        let mut medium = 0;
        let mut low = 0;
        let mut info = 0;

        // Use get_findings method
        let findings = self.get_findings();

        for finding in findings {
            match finding.severity {
                crate::detection::analyzer::Severity::Critical => critical += 1,
                crate::detection::analyzer::Severity::High => high += 1,
                crate::detection::analyzer::Severity::Medium => medium += 1,
                crate::detection::analyzer::Severity::Low => low += 1,
                crate::detection::analyzer::Severity::Info => info += 1,
            }
        }

        println!();
        println!("Scan Summary:");
        println!("  Critical: {}", critical);
        println!("  High: {}", high);
        println!("  Medium: {}", medium);
        println!("  Low: {}", low);
        println!("  Info: {}", info);
        // Use count method
        println!("  Total: {}", self.count());
    }
}

impl Clone for ReportGenerator {
    fn clone(&self) -> Self {
        Self {
            findings: self.findings.clone(),
            format: self.format.clone(),
            target: self.target.clone(),
            target_ip: self.target_ip.clone(),
            discovered_urls: self.discovered_urls.clone(),
            duration_secs: self.duration_secs,
        }
    }
}
