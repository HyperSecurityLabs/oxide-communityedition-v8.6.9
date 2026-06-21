// ----------------------------------------------------------------------------
//  html.rs — HTML report generator
// ----------------------------------------------------------------------------
//  HTML report generator — renders findings as styled web pages with severity highlighting.
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

// ◆ HtmlReport: HTMLレポート生成器
// ◆ Renders findings as a styled cyberpunk-themed HTML report.
// ■ テンプレート構造:
//   - ヘッダー: Orbitronフォント + グラデーション (Oxide Elite Edition)
//   - メタグリッド: ターゲット/IP/時間/URL数
//   - 重要度バー: Critical/High/Medium/Low/Infoの視覚的集計
//   - 発見テーブル: 重要度別カラーコード化 (赤/橙/黄/青緑/青)
//   - フッター: ジェネレーションブランディング
// ♢ 重要度カラー: Critical=#ff4444, High=#ff8800, Medium=#ffcc00, Low=#00c8b4, Info=#64aaff
pub struct HtmlReport;

impl HtmlReport {
    // ◆ generate_header: HTMLヘッダー生成
    // ◆ Generates complete <head> + <style> + header <div> with meta-grid.
    pub fn generate_header(title: &str, target: &str, target_ip: &str, duration: &str, links_count: usize) -> String {
        format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&family=Rajdhani:wght@400;500;600;700&family=Fira+Code:wght@400;600&display=swap" rel="stylesheet">
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}

        body {{
            background: #0a0e14;
            color: #c0d0e0;
            font-family: 'Rajdhani', 'Segoe UI', sans-serif;
            min-height: 100vh;
            overflow-x: hidden;
            position: relative;
        }}

        /* ── Scanline overlay ── */
        body::before {{
            content: '';
            position: fixed;
            top: 0; left: 0; right: 0; bottom: 0;
            background: repeating-linear-gradient(
                0deg,
                transparent 0px,
                transparent 2px,
                rgba(85, 124, 148, 0.03) 2px,
                rgba(85, 124, 148, 0.03) 4px
            );
            pointer-events: none;
            z-index: 9999;
        }}

        /* ── Diagonal slash lines ── */
        body::after {{
            content: '';
            position: fixed;
            top: -50%; left: -50%;
            width: 200%; height: 200%;
            background: repeating-linear-gradient(
                -45deg,
                transparent 0px,
                transparent 80px,
                rgba(100, 210, 255, 0.015) 80px,
                rgba(100, 210, 255, 0.015) 82px
            );
            pointer-events: none;
            z-index: 9998;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 30px 24px;
            position: relative;
            z-index: 1;
        }}

        /* ── Header with cyberpunk gradient ── */
        .header {{
            position: relative;
            background: linear-gradient(135deg, #0d1b2a 0%, #1b2838 50%, #0d1b2a 100%);
            border: 1px solid rgba(85, 124, 148, 0.4);
            padding: 40px 36px;
            border-radius: 4px;
            margin-bottom: 28px;
            overflow: hidden;
        }}

        .header::before {{
            content: '';
            position: absolute;
            top: 0; left: 0; right: 0;
            height: 3px;
            background: linear-gradient(90deg, #557C94, #64d2ff, #c4a7e7, #557C94);
            background-size: 300% 100%;
            animation: gradientSlide 4s ease infinite;
        }}

        @keyframes gradientSlide {{
            0% {{ background-position: 0% 0%; }}
            50% {{ background-position: 100% 0%; }}
            100% {{ background-position: 0% 0%; }}
        }}

        .header::after {{
            content: '';
            position: absolute;
            top: 0; right: 0;
            width: 200px; height: 200px;
            background: radial-gradient(circle at center, rgba(100,210,255,0.06) 0%, transparent 70%);
            pointer-events: none;
        }}

        /* ── Diagonal accent in header ── */
        .header .diagonal-accent {{
            position: absolute;
            bottom: 0; right: 0;
            width: 150px; height: 150px;
            background: linear-gradient(135deg, transparent 49.9%, rgba(85,124,148,0.12) 50%);
            pointer-events: none;
        }}

        .header h1 {{
            font-family: 'Orbitron', 'Rajdhani', sans-serif;
            font-weight: 900;
            font-size: 26px;
            text-transform: uppercase;
            letter-spacing: 4px;
            background: linear-gradient(90deg, #64d2ff, #c4a7e7, #80e8c0);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 8px;
            position: relative;
        }}

        .header .subtitle {{
            font-family: 'Rajdhani', sans-serif;
            font-weight: 500;
            font-size: 14px;
            color: rgba(100, 210, 255, 0.7);
            letter-spacing: 2px;
            text-transform: uppercase;
        }}

        .header .version {{
            font-family: 'Fira Code', monospace;
            font-size: 12px;
            color: rgba(85, 124, 148, 0.6);
            margin-top: 4px;
        }}

        /* ── Meta grid cards ── */
        .meta-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 12px;
            margin-bottom: 24px;
        }}

        .meta-card {{
            background: linear-gradient(135deg, rgba(13,27,42,0.9), rgba(27,40,56,0.8));
            border: 1px solid rgba(85, 124, 148, 0.25);
            border-radius: 4px;
            padding: 16px 18px;
            position: relative;
            overflow: hidden;
            transition: border-color 0.3s ease;
        }}

        .meta-card:hover {{
            border-color: rgba(100, 210, 255, 0.4);
        }}

        .meta-card::before {{
            content: '';
            position: absolute;
            top: 0; left: 0;
            width: 3px; height: 100%;
            background: linear-gradient(180deg, #557C94, #64d2ff);
            opacity: 0.6;
        }}

        .meta-card .label {{
            font-family: 'Rajdhani', sans-serif;
            font-weight: 600;
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 2px;
            color: rgba(85, 124, 148, 0.8);
        }}

        .meta-card .value {{
            font-family: 'Orbitron', 'Rajdhani', sans-serif;
            font-weight: 700;
            font-size: 18px;
            color: #e0edf5;
            margin-top: 6px;
            word-break: break-all;
        }}

        .meta-card .value.ip-value {{
            font-family: 'Rajdhani', 'Fira Code', monospace;
            font-weight: 600;
            font-size: 14px;
            color: #b0d0e0;
            letter-spacing: 0.5px;
        }}

        .meta-card .value.ip-value .ip-list {{
            list-style: none;
            padding: 0;
            margin: 0;
        }}

        .meta-card .value.ip-value .ip-list li {{
            padding: 2px 0;
        }}

        .meta-card .value.ip-value .ip-list li::before {{
            content: '▸ ';
            color: #64d2ff;
        }}

        .meta-card .value .highlight {{
            background: linear-gradient(90deg, #64d2ff, #c4a7e7);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }}

        /* ── Section headers ── */
        h2 {{
            font-family: 'Orbitron', 'Rajdhani', sans-serif;
            font-weight: 700;
            font-size: 16px;
            text-transform: uppercase;
            letter-spacing: 3px;
            color: #64d2ff;
            padding: 12px 0;
            margin: 28px 0 4px 0;
            border-bottom: 1px solid rgba(85, 124, 148, 0.2);
            position: relative;
        }}

        h2::after {{
            content: '';
            position: absolute;
            bottom: -1px; left: 0;
            width: 80px; height: 2px;
            background: linear-gradient(90deg, #64d2ff, transparent);
        }}

        /* ── Severity bar ── */
        .severity-bar {{
            display: flex;
            gap: 8px;
            margin: 16px 0;
        }}

        .severity-bar .bar-segment {{
            flex: 1;
            text-align: center;
            padding: 10px 6px;
            font-family: 'Orbitron', sans-serif;
            font-weight: 700;
            font-size: 13px;
            letter-spacing: 1px;
            border-radius: 2px;
            text-transform: uppercase;
            position: relative;
            overflow: hidden;
        }}

        .severity-bar .bar-segment::before {{
            content: '';
            position: absolute;
            top: 0; left: 0; right: 0; bottom: 0;
            background: repeating-linear-gradient(
                -45deg,
                transparent 0px,
                transparent 4px,
                rgba(255,255,255,0.03) 4px,
                rgba(255,255,255,0.03) 6px
            );
        }}

        .sev-critical {{ background: rgba(255, 68, 68, 0.2); border: 1px solid rgba(255, 68, 68, 0.4); color: #ff4444; box-shadow: 0 0 12px rgba(255,68,68,0.1); }}
        .sev-high     {{ background: rgba(255, 136, 0, 0.15); border: 1px solid rgba(255, 136, 0, 0.35); color: #ff8800; }}
        .sev-medium   {{ background: rgba(255, 204, 0, 0.12); border: 1px solid rgba(255, 204, 0, 0.3); color: #ffcc00; }}
        .sev-low      {{ background: rgba(0, 200, 180, 0.1); border: 1px solid rgba(0, 200, 180, 0.3); color: #00c8b4; }}
        .sev-info     {{ background: rgba(100, 170, 255, 0.08); border: 1px solid rgba(100, 170, 255, 0.25); color: #64aaff; }}

        /* ── Table ── */
        .table-wrapper {{
            overflow-x: auto;
            margin-top: 8px;
            border: 1px solid rgba(85, 124, 148, 0.15);
            border-radius: 4px;
        }}

        table {{
            border-collapse: collapse;
            width: 100%;
            font-family: 'Rajdhani', sans-serif;
        }}

        th {{
            background: rgba(13, 27, 42, 0.95);
            color: #64d2ff;
            padding: 14px 16px;
            text-align: left;
            font-family: 'Orbitron', 'Rajdhani', sans-serif;
            font-weight: 600;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 2px;
            border-bottom: 1px solid rgba(85, 124, 148, 0.2);
        }}

        td {{
            padding: 12px 16px;
            border-bottom: 1px solid rgba(85, 124, 148, 0.08);
            font-size: 14px;
            font-weight: 500;
            color: #b0c8d8;
        }}

        .finding {{
            transition: background 0.2s ease;
        }}

        .finding:hover {{
            background: rgba(85, 124, 148, 0.08);
        }}

        .severity-cell {{
            font-family: 'Orbitron', 'Rajdhani', sans-serif;
            font-weight: 700;
            font-size: 12px;
            letter-spacing: 1px;
        }}

        .severity-cell.critical {{ color: #ff4444; text-shadow: 0 0 8px rgba(255,68,68,0.3); }}
        .severity-cell.high     {{ color: #ff8800; text-shadow: 0 0 6px rgba(255,136,0,0.2); }}
        .severity-cell.medium   {{ color: #ffcc00; }}
        .severity-cell.low      {{ color: #00c8b4; }}
        .severity-cell.info     {{ color: #64aaff; }}

        .finding-url {{
            color: #58a6ff;
            font-family: 'Fira Code', 'Rajdhani', monospace;
            font-size: 13px;
            word-break: break-all;
            text-decoration: none;
        }}

        .finding-url:hover {{
            color: #79c0ff;
            text-decoration: underline;
        }}

        .finding-title {{
            font-weight: 600;
            color: #d0e0f0;
        }}

        .finding-desc {{
            color: #8098a8;
            font-size: 13px;
        }}

        .conf-badge {{
            font-family: 'Rajdhani', sans-serif;
            font-weight: 600;
            font-size: 11px;
            padding: 2px 8px;
            border-radius: 2px;
            display: inline-block;
            letter-spacing: 0.5px;
        }}

        .conf-badge.confirmed {{
            background: rgba(0, 200, 180, 0.15);
            border: 1px solid rgba(0, 200, 180, 0.3);
            color: #00c8b4;
        }}

        .conf-badge.false-positive {{
            background: rgba(255, 68, 68, 0.12);
            border: 1px solid rgba(255, 68, 68, 0.25);
            color: #ff6666;
        }}

        /* ── Links section ── */
        .links-section {{
            background: rgba(13, 27, 42, 0.6);
            border: 1px solid rgba(85, 124, 148, 0.15);
            border-radius: 4px;
            padding: 16px;
            margin-top: 8px;
            max-height: 300px;
            overflow-y: auto;
        }}

        .links-section::-webkit-scrollbar {{
            width: 6px;
            background: rgba(13, 27, 42, 0.5);
        }}

        .links-section::-webkit-scrollbar-thumb {{
            background: rgba(85, 124, 148, 0.4);
            border-radius: 3px;
        }}

        .links-section a {{
            color: #58a6ff;
            text-decoration: none;
            display: block;
            padding: 5px 8px;
            font-family: 'Fira Code', 'Rajdhani', monospace;
            font-size: 13px;
            border-left: 2px solid transparent;
            transition: all 0.2s ease;
        }}

        .links-section a:hover {{
            color: #79c0ff;
            background: rgba(85, 124, 148, 0.06);
            border-left-color: #64d2ff;
        }}

        /* ── Footer ── */
        footer {{
            margin-top: 48px;
            text-align: center;
            padding: 24px 0;
            border-top: 1px solid rgba(85, 124, 148, 0.1);
            position: relative;
        }}

        footer::before {{
            content: '';
            position: absolute;
            top: -1px; left: 10%; right: 10%;
            height: 1px;
            background: linear-gradient(90deg, transparent, rgba(85,124,148,0.3), transparent);
        }}

        footer p {{
            font-family: 'Rajdhani', sans-serif;
            font-weight: 400;
            font-size: 13px;
            color: rgba(85, 124, 148, 0.5);
            letter-spacing: 1px;
        }}

        footer .glitch {{
            font-family: 'Orbitron', sans-serif;
            font-size: 11px;
            color: rgba(100, 210, 255, 0.3);
            letter-spacing: 3px;
            text-transform: uppercase;
        }}

        /* ── Responsive ── */
        @media (max-width: 640px) {{
            .meta-grid {{ grid-template-columns: 1fr; }}
            .header h1 {{ font-size: 20px; }}
            .severity-bar {{ flex-direction: column; }}
        }}
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <div class="diagonal-accent"></div>
        <h1>◈ OXIDE — Security Scan Report</h1>
        <div class="subtitle">Elite Edition &nbsp;|&nbsp; Zero-Day Intelligence & Detection Engine</div>
        <div class="version">v7.9.1-elite  //  hypersecurity_offsec</div>
    </div>
    <div class="meta-grid">
        <div class="meta-card">
            <div class="label">Target</div>
            <div class="value"><span class="highlight">{target}</span></div>
        </div>
        <div class="meta-card">
            <div class="label">IP Address</div>
                <div class="value ip-value">
                    <ul class="ip-list">
                        {target_ip}
                    </ul>
                </div>
        </div>
        <div class="meta-card">
            <div class="label">Duration</div>
            <div class="value">{duration}</div>
        </div>
        <div class="meta-card">
            <div class="label">URLs Discovered</div>
            <div class="value">{links_count}</div>
        </div>
    </div>
"#,
            title = title,
            target = target,
            target_ip = target_ip.split(", ")
                .filter(|s| !s.is_empty())
                .map(|ip| format!("<li>{}</li>", ip.trim()))
                .collect::<Vec<_>>()
                .join("\n                        "),
            duration = duration,
            links_count = links_count,
        )
    }

    // ◆ generate_links_section: 発見URL一覧セクション
    // ◆ Renders discovered URLs as a scrollable link list.
    pub fn generate_links_section(links: &[String]) -> String {
        if links.is_empty() {
            return String::new();
        }
        let mut html = String::from(r#"<h2>⧩ Discovered URLs</h2><div class="links-section">"#);
        for link in links {
            html.push_str(&format!(
                r#"<a href="{}" target="_blank">▸ {}</a>"#,
                link, link
            ));
        }
        html.push_str("</div>");
        html
    }

    // ◆ generate_table_start: 発見テーブル開始
    // ◆ Opens findings HTML table with <thead> severity/URL/Title/Description columns.
    pub fn generate_table_start() -> String {
        r#"<h2>⧩ Findings & Exploits</h2>
<div class="table-wrapper">
<table>
    <thead>
        <tr>
            <th>Severity</th>
            <th>URL</th>
            <th>Title</th>
            <th>Description</th>
        </tr>
    </thead>
    <tbody>"#
        .to_string()
    }

    // ◆ generate_table_end: 発見テーブル終了
    // ◆ Closes findings table + div wrapper.
    pub fn generate_table_end() -> String {
        "</tbody></table></div>".to_string()
    }

    // ◆ generate_footer: HTMLフッター生成
    // ◆ Generates branded footer with version info.
    pub fn generate_footer() -> String {
        r#"
    <footer>
        <p>Generated by OXIDE Elite Edition v7.9.1-elite</p>
        <div class="glitch">// hypersecurity_offsec // kali linux elite //</div>
    </footer>
</div>
</body>
</html>"#
        .to_string()
    }
}
