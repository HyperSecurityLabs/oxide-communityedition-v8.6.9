// ----------------------------------------------------------------------------
//  crawl_types.rs — Data types for crawling
// ----------------------------------------------------------------------------
//  Data types for crawling — defines CrawlResult, CrawlTarget, and related
//  structures.
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
// ◆ crawl_types.rs — 電脳収集用データ構造
// ★ Crawling data types — FormData, InputField, LinkData, CrawlResult
// ■ フォーム解析、リンク抽出、スクリプト分析の出力形式を定義

// ★ FormData — HTMLフォームのデータ構造
// ★ HTML form structure for crawling
// ◆ url    — フォームが存在するページのURL
// ◆ method — HTTPメソッド (GET/POST)
// ◆ action — 送信先URL
// ◆ inputs — 入力フィールドのリスト
#[derive(Clone, Debug)]
pub struct FormData {
    pub url: String,
    pub method: String,
    pub action: String,
    pub inputs: Vec<InputField>,
}

// ◆ InputField — フォーム入力フィールド
// ◆ Form input field
// ◆ name       — フィールド名
// ◆ input_type — タイプ (text/password/hidden等)
// ◆ value      — デフォルト値
#[derive(Clone, Debug)]
pub struct InputField {
    pub name: String,
    pub input_type: String,
    pub value: Option<String>,
}

// ◆ LinkData — リンクデータ
// ◆ Link tracking data
// ◆ from — リンク元URL
// ◆ to   — リンク先URL
// ◆ text — リンクテキスト
#[derive(Clone, Debug)]
pub struct LinkData {
    pub from: String,
    pub to: String,
    pub text: String,
}

// ★ CrawlResult — 電脳収集結果の完全な出力
// ★ Complete crawl output
// ◆ urls           — 発見したURL一覧
// ◆ all_linked_urls — 全リンク先
// ◆ forms          — フォーム一覧
// ◆ links          — リンク一覧
// ◆ comments       — HTMLコメント
// ◆ scripts        — スクリプト内容
#[derive(Debug)]
pub struct CrawlResult {
    pub urls: Vec<String>,
    pub all_linked_urls: Vec<String>,
    pub forms: Vec<FormData>,
    pub links: Vec<LinkData>,
    pub comments: Vec<String>,
    pub scripts: Vec<String>,
}

// ■ クロール結果のフィルタリングメソッド
// ■ Crawl result filtering methods
impl CrawlResult {
    // ◆ 指定メソッドのフォームのみ抽出
    pub fn get_forms_by_method(&self, method: &str) -> Vec<&FormData> {
        self.forms.iter().filter(|f| f.method.eq_ignore_ascii_case(method)).collect()
    }

    // ● 空でないリンクテキストを全て収集
    pub fn get_all_link_texts(&self) -> Vec<&String> {
        self.links.iter().map(|l| &l.text).filter(|t| !t.is_empty()).collect()
    }

    // ★ suspicious_comments — コメントから機密情報を電脳検出
    // ★ Detects sensitive info in HTML comments
    // ■ password / secret / token / api_key / todo / fixme / internal IP
    pub fn suspicious_comments(&self) -> Vec<(&String, &'static str)> {
        let patterns: &[(&str, &str)] = &[
            ("password", "possible credential"),
            ("passwd",   "possible credential"),
            ("secret",   "possible secret"),
            ("token",    "possible token"),
            ("api_key",  "possible API key"),
            ("todo",     "developer note"),
            ("fixme",    "developer note"),
            ("hack",     "developer note"),
            ("/etc/",    "internal path"),
            ("192.168.", "internal IP"),
            ("10.0.",    "internal IP"),
        ];
        self.comments.iter().filter_map(|c| {
            let cl = c.to_lowercase();
            patterns.iter().find(|(p, _)| cl.contains(p)).map(|(_, reason)| (c, *reason))
        }).collect()
    }

    // ➤ script_endpoints — スクリプトからAPIエンドポイントを抽出
    // ➤ Extracts API endpoints from scripts using regex
    // ■ /api /v[0-9] /rest /graphql パターンを電脳検出
    pub fn script_endpoints(&self) -> Vec<String> {
        let Ok(re) = regex::Regex::new(r#"["'](/(?:api|v\d|rest|graphql)[^"'\s]*)"#) else {
            return Vec::new();
        };
        self.scripts.iter().flat_map(|s| {
            re.captures_iter(s)
                .filter_map(|c| c.get(1).map(|m| m.as_str().to_string()))
        }).collect()
    }
}
