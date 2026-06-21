// ----------------------------------------------------------------------------
//  headless.rs — Headless browser HTTP client
// ----------------------------------------------------------------------------
//  Headless browser HTTP client — renders JS for client-side vulnerability
//  detection.
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
// ◆ headless.rs — ヘッドレスブラウザクライアント
// ★ Headless browser HTTP client — renders JS for client-side detection
// ■ Chromiumをサブプロセスとして実行し、JSレンダリング後のDOMを解析

use anyhow::{Context, Result};
use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tokio::sync::Mutex;

use crate::cli::display::{LAVENDER_BLUE, OSAKA_JADE, OSAKA_JADE_B};
use colored::Colorize;
use crate::http::crawl_types::{CrawlResult, FormData, InputField, LinkData};

fn tc(s: &str, c: (u8, u8, u8)) -> String {
    s.truecolor(c.0, c.1, c.2).to_string()
}

// ★ HeadlessCrawler — Chromiumベースのヘッドレスクローラー
// ★ Chromium-based headless crawler for JS rendering
// ◆ max_depth — BFS最大深さ
// ◆ max_pages — 最大ページ数
// ◆ visited   — 訪問済みURL (スレッドセーフ)
// ◆ queue     — BFSキュー (スレッドセーフ)
// ◆ jobs      — 同時ワーカー数
// ※ Arc<Mutex<>> でスレッド間共有
pub struct HeadlessCrawler {
    max_depth: usize,
    max_pages: usize,
    visited: Arc<Mutex<HashSet<String>>>,
    queue: Arc<Mutex<VecDeque<(String, usize)>>>,
    discovered_urls: Arc<Mutex<Vec<String>>>,
    all_linked_urls: Arc<Mutex<Vec<String>>>,
    forms: Arc<Mutex<Vec<FormData>>>,
    links: Arc<Mutex<Vec<LinkData>>>,
    comments: Arc<Mutex<Vec<String>>>,
    scripts: Arc<Mutex<Vec<String>>>,
    user_agent: Option<String>,
    cookie: Option<String>,
    jobs: usize,
}

// ■ ヘッドレスクローラーの実装
// ■ Headless crawler implementation
impl HeadlessCrawler {
    // ◆ new — クローラーの初期化 (BFS深さ・最大ページ・UA・クッキー・ジョブ数)
    pub fn new(max_depth: usize, max_pages: usize, user_agent: Option<String>, cookie: Option<String>, jobs: usize) -> Self {
        Self {
            max_depth,
            max_pages,
            visited: Arc::new(Mutex::new(HashSet::new())),
            queue: Arc::new(Mutex::new(VecDeque::new())),
            discovered_urls: Arc::new(Mutex::new(Vec::new())),
            all_linked_urls: Arc::new(Mutex::new(Vec::new())),
            forms: Arc::new(Mutex::new(Vec::new())),
            links: Arc::new(Mutex::new(Vec::new())),
            comments: Arc::new(Mutex::new(Vec::new())),
            scripts: Arc::new(Mutex::new(Vec::new())),
            user_agent,
            cookie,
            jobs,
        }
    }

    // ★ crawl — BFS電脳収集のメイン電脳入口点
    // ★ Main crawl entry point — BFS with concurrent workers
    // ➤ 1. 開始URLをキューに追加
    // ➤ 2. スピナー起動 (表示用)
    // ➤ 3. ジョブ数だけワーカーを起動
    // ➤ 4. 各ワーカー: キューから取得 → visited確認 → Chromeで取得 → HTML解析
    // ➤ 5. 新しいURLをキューに追加 (深さ+1)
    // ➤ 6. キューが空かつ全ワーカーアイドル → 終了
    // ➤ 7. CrawlResult を返却
    pub async fn crawl(&mut self, start_url: &str) -> Result<CrawlResult> {
        let start = std::time::Instant::now();
        {
            let mut q = self.queue.lock().await;
            q.push_back((start_url.to_string(), 0));
        }

        let page_count = Arc::new(AtomicUsize::new(0));
        let max_pages = self.max_pages;
        let max_depth = self.max_depth;
        let visited = self.visited.clone();
        let queue = self.queue.clone();
        let discovered_urls = self.discovered_urls.clone();
        let all_linked_urls = self.all_linked_urls.clone();
        let forms = self.forms.clone();
        let links = self.links.clone();
        let comments = self.comments.clone();
        let scripts = self.scripts.clone();
        let ua = self.user_agent.clone();
        let cookie = self.cookie.clone();
        let jobs = self.jobs.max(1);

        let running = Arc::new(AtomicBool::new(true));

        let r = running.clone();
        let url_s = start_url.to_string();
        let spinner = tokio::spawn(async move {
            let mut idx = 0usize;
            while r.load(Ordering::Relaxed) {
                let elapsed = start.elapsed().as_secs();
                let frame = match idx % 10 {
                    0 => "⠋", 1 => "⠙", 2 => "⠹", 3 => "⠸", 4 => "⠼",
                    5 => "⠴", 6 => "⠦", 7 => "⠧", 8 => "⠇", 9 => "⠏",
                    _ => "⠋",
                };
                idx += 1;
                print!("\r  {} {} headless-crawl  {}  {}  [{:02}:{:02}]   ",
                    tc("[*]", OSAKA_JADE),
                    tc(frame, OSAKA_JADE_B),
                    tc("depth:0", LAVENDER_BLUE),
                    tc(&url_s, LAVENDER_BLUE),
                    elapsed / 60, elapsed % 60);
                let _ = std::io::Write::flush(&mut std::io::stdout());
                tokio::time::sleep(std::time::Duration::from_millis(120)).await;
            }
        });

        let active_workers = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        for _ in 0..jobs {
            let visited = visited.clone();
            let queue = queue.clone();
            let discovered_urls = discovered_urls.clone();
            let all_linked_urls = all_linked_urls.clone();
            let forms = forms.clone();
            let links = links.clone();
            let comments = comments.clone();
            let scripts = scripts.clone();
            let page_count = page_count.clone();
            let ua = ua.clone();
            let cookie = cookie.clone();
            let running = running.clone();
            let active = active_workers.clone();
            handles.push(tokio::spawn(async move {
                loop {
                    if !running.load(Ordering::Relaxed) {
                        return;
                    }
                    let item = {
                        let mut q = queue.lock().await;
                        q.pop_front()
                    };
                    let (url, depth) = match item {
                        Some(item) => item,
                        None => {
                            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                            continue;
                        }
                    };

                    {
                        let mut v = visited.lock().await;
                        if v.contains(&url) || depth > max_depth {
                            continue;
                        }
                        if page_count.load(Ordering::Relaxed) >= max_pages {
                            continue;
                        }
                        v.insert(url.clone());
                    }

                    page_count.fetch_add(1, Ordering::Relaxed);
                    active.fetch_add(1, Ordering::Relaxed);

                    match fetch_via_chrome(&url, &ua, &cookie).await {
                        Ok(html) => {
                            let extracted = extract_from_html(&url, &html, depth);
                            {
                                let mut du = discovered_urls.lock().await;
                                du.push(url.clone());
                            }
                            {
                                let mut alu = all_linked_urls.lock().await;
                                alu.extend(extracted.all_linked_urls);
                            }
                            {
                                let mut f = forms.lock().await;
                                f.extend(extracted.forms);
                            }
                            {
                                let mut l = links.lock().await;
                                l.extend(extracted.links);
                            }
                            {
                                let mut c = comments.lock().await;
                                c.extend(extracted.comments);
                            }
                            {
                                let mut s = scripts.lock().await;
                                s.extend(extracted.scripts);
                            }
                            {
                                let mut q = queue.lock().await;
                                for link in extracted.new_urls {
                                    let mut v = visited.lock().await;
                                    if !v.contains(&link) {
                                        v.insert(link.clone());
                                        q.push_back((link, depth + 1));
                                    }
                                }
                            }
                        }
                        Err(_) => {}
                    }

                    active.fetch_sub(1, Ordering::Relaxed);
                }
            }));
        }

        // Wait until queue is empty, all workers idle, page limit reached, or cancelled
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            let qlen = self.queue.lock().await.len();
            let idle = active_workers.load(Ordering::Relaxed) == 0;
            let pages_reached = page_count.load(Ordering::Relaxed) >= max_pages;
            if (qlen == 0 && idle) || pages_reached {
                break;
            }
        }

        running.store(false, Ordering::Release);

        // Abort all worker handles
        for h in &handles {
            h.abort();
        }

        let _ = spinner.await;

        // Yield to let tasks finalise
        tokio::task::yield_now().await;

        let urls = self.discovered_urls.lock().await.clone();
        let all_linked = self.all_linked_urls.lock().await.clone();
        let forms_vec = self.forms.lock().await.clone();
        let links_vec = self.links.lock().await.clone();
        let comments_vec = self.comments.lock().await.clone();
        let scripts_vec = self.scripts.lock().await.clone();

        let pc = page_count.load(Ordering::Relaxed);
        println!("  {} Headless crawl complete: {} pages, {} URLs, {} forms, {} links",
            tc("[+]", OSAKA_JADE),
            pc,
            urls.len(),
            forms_vec.len(),
            links_vec.len());

        Ok(CrawlResult {
            urls,
            all_linked_urls: all_linked,
            forms: forms_vec,
            links: links_vec,
            comments: comments_vec,
            scripts: scripts_vec,
        })
    }

}

// ◆ fetch_via_chrome — Chrome/Chromiumをサブプロセスで実行
// ◆ Executes Chrome/Chromium as subprocess with --headless --dump-dom
// ■ 3種類のバイナリをフォールバック: chromium-browser → google-chrome → chromium
// ■ --headless --disable-gpu --no-sandbox --disable-dev-shm-usage フラグ
async fn fetch_via_chrome(url: &str, user_agent: &Option<String>, cookie: &Option<String>) -> Result<String> {
    use std::process::Command;

    let mut cmd = Command::new("chromium-browser");
    cmd.arg("--headless");
    cmd.arg("--disable-gpu");
    cmd.arg("--no-sandbox");
    cmd.arg("--disable-dev-shm-usage");
    cmd.arg(format!("--dump-dom"));
    cmd.arg(&url);

    if let Some(ua) = user_agent {
        cmd.arg(format!("--user-agent={}", ua));
    }

    if let Some(ref c) = cookie {
        cmd.env("HTTP_COOKIE", c.clone());
    }

    let output = cmd.output()
        .or_else(|_| {
            let mut cmd2 = Command::new("google-chrome");
            cmd2.arg("--headless");
            cmd2.arg("--disable-gpu");
            cmd2.arg("--no-sandbox");
            cmd2.arg("--disable-dev-shm-usage");
            cmd2.arg(format!("--dump-dom"));
            cmd2.arg(&url);
            if let Some(ua) = user_agent {
                cmd2.arg(format!("--user-agent={}", ua));
            }
            cmd2.output()
        })
        .or_else(|_| {
            let mut cmd3 = Command::new("chromium");
            cmd3.arg("--headless");
            cmd3.arg("--disable-gpu");
            cmd3.arg("--no-sandbox");
            cmd3.arg("--disable-dev-shm-usage");
            cmd3.arg(format!("--dump-dom"));
            cmd3.arg(&url);
            if let Some(ua) = user_agent {
                cmd3.arg(format!("--user-agent={}", ua));
            }
            cmd3.output()
        })
        .context("No Chrome/Chromium binary found. Install chromium-browser, google-chrome, or chromium.")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow::anyhow!("Chrome dump-dom failed: {}", stderr));
    }

    let html = String::from_utf8_lossy(&output.stdout).to_string();
    Ok(html)
}

struct HeadlessExtractResult {
    new_urls: Vec<String>,
    all_linked_urls: Vec<String>,
    forms: Vec<FormData>,
    links: Vec<LinkData>,
    comments: Vec<String>,
    scripts: Vec<String>,
}

// ★ extract_from_html — HTMLからリンク・フォーム・コメント・スクリプトを抽出
// ★ Extracts links, forms, comments, scripts from HTML via regex
// ■ リンク抽出: <a href="...">...</a>
// ■ フォーム抽出: <form>...</form> → action / method / input fields
// ■ コメント抽出: <!-- ... -->
// ■ スクリプト抽出: <script>...</script>
fn extract_from_html(base_url: &str, html: &str, _depth: usize) -> HeadlessExtractResult {
    let mut new_urls = Vec::new();
    let mut all_linked_urls = Vec::new();
    let mut forms = Vec::new();
    let mut links = Vec::new();
    let mut comments = Vec::new();
    let mut scripts = Vec::new();

    // Extract links
    let link_re = regex::Regex::new(r#"<a[^>]*href=["']([^"']+)["'][^>]*>(.*?)</a>"#).ok();
    let tag_re = regex::Regex::new(r"<[^>]*>").ok();

    if let (Some(ref lr), Some(ref tr)) = (link_re, tag_re) {
        for cap in lr.captures_iter(html) {
            if let Some(href) = cap.get(1) {
                let href_str = href.as_str();
                let raw_text = cap.get(2).map(|m| m.as_str()).unwrap_or("");
                let link_text = tr.replace_all(raw_text, "").to_string();

                if let Ok(absolute) = resolve_url(base_url, href_str) {
                    all_linked_urls.push(absolute.clone());
                    if is_same_domain(base_url, &absolute) {
                        links.push(LinkData {
                            from: base_url.to_string(),
                            to: absolute.clone(),
                            text: link_text,
                        });
                        new_urls.push(absolute);
                    }
                }
            }
        }
    }

    // Extract forms
    let form_re = regex::Regex::new(r#"(?s)<form[^>]*>.*?</form>"#).ok();
    let action_re = regex::Regex::new(r#"action=["']([^"']*)["']"#).ok();
    let method_re = regex::Regex::new(r#"method=["']([^"']*)["']"#).ok();
    let input_re = regex::Regex::new(r#"<input[^>]*>"#).ok();
    let name_re = regex::Regex::new(r#"name=["']([^"']*)["']"#).ok();
    let type_re = regex::Regex::new(r#"type=["']([^"']*)["']"#).ok();
    let value_re = regex::Regex::new(r#"value=["']([^"']*)["']"#).ok();

    if let (Some(ref fr), Some(ref ar), Some(ref mr), Some(ref ir), Some(ref nr), Some(ref tyr), Some(ref vr)) =
        (form_re, action_re, method_re, input_re, name_re, type_re, value_re)
    {
        for form_m in fr.find_iter(html) {
            let form_html = form_m.as_str();
            let action = ar.captures(form_html)
                .and_then(|c| c.get(1))
                .map(|m| m.as_str().to_string())
                .unwrap_or_else(|| base_url.to_string());
            let action = resolve_url(base_url, &action).unwrap_or_else(|_| base_url.to_string());

            let method = mr.captures(form_html)
                .and_then(|c| c.get(1))
                .map(|m| m.as_str().to_uppercase())
                .unwrap_or_else(|| "GET".to_string());

            let inputs: Vec<InputField> = ir.find_iter(form_html).filter_map(|im| {
                let ih = im.as_str();
                let name = nr.captures(ih)?.get(1)?.as_str().to_string();
                if name.is_empty() { return None; }
                Some(InputField {
                    name,
                    input_type: tyr.captures(ih)
                        .and_then(|c| c.get(1))
                        .map(|m| m.as_str().to_string())
                        .unwrap_or_else(|| "text".to_string()),
                    value: vr.captures(ih)
                        .and_then(|c| c.get(1))
                        .map(|m| m.as_str().to_string()),
                })
            }).collect();

            forms.push(FormData {
                url: base_url.to_string(),
                method,
                action,
                inputs,
            });
        }
    }

    // Extract comments
    let comment_re = regex::Regex::new(r"<!--([\s\S]*?)-->").ok();
    if let Some(ref cr) = comment_re {
        for cap in cr.captures_iter(html) {
            if let Some(m) = cap.get(1) {
                let text = m.as_str().trim().to_string();
                if !text.is_empty() {
                    comments.push(text);
                }
            }
        }
    }

    // Extract scripts
    let script_re = regex::Regex::new(r"(?s)<script[^>]*>(.*?)</script>").ok();
    if let Some(ref sr) = script_re {
        for cap in sr.captures_iter(html) {
            if let Some(m) = cap.get(1) {
                let text = m.as_str().trim().to_string();
                if !text.is_empty() {
                    scripts.push(text);
                }
            }
        }
    }

    HeadlessExtractResult {
        new_urls,
        all_linked_urls,
        forms,
        links,
        comments,
        scripts,
    }
}

// ▲ resolve_url — 相対URLを絶対URLに解決
// ▲ Resolves relative URL to absolute URL using url::Url::join
fn resolve_url(base: &str, relative: &str) -> Result<String> {
    let base_url = url::Url::parse(base)
        .with_context(|| format!("Invalid base URL: {}", base))?;
    let resolved = base_url.join(relative)
        .with_context(|| format!("Failed to join: {} + {}", base, relative))?;
    Ok(resolved.to_string())
}

// ※ is_same_domain — 2つのURLが同一ドメインかを判定
// ※ Checks if two URLs share the same host
fn is_same_domain(url1: &str, url2: &str) -> bool {
    let fallback = url::Url::parse("http://localhost").unwrap();
    let d1 = url::Url::parse(url1).unwrap_or(fallback.clone());
    let d2 = url::Url::parse(url2).unwrap_or(fallback);
    d1.host_str() == d2.host_str()
}
