// ----------------------------------------------------------------------------
//  worker.rs — worker thread pool
// ----------------------------------------------------------------------------
//  Worker thread pool — executes scan tasks concurrently with controlled parallelism.
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

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::RwLock;

use crate::cli::args::CliArgs;
use crate::cli::display::ScanBoard;
use crate::core::scanner::ScanResult;
use crate::detection::analyzer::{Analyzer, Finding, Severity};
use crate::http::client::HttpClient;
use crate::http::request::HttpRequest;
use crate::utils::url::UrlUtil;

// ◆ ParallelScanner: ワーカースレッドプール
// ◆ Manages N concurrent worker threads that consume URLs from a shared atomic cursor.
// ■ Concurrent execution model:
//   - AtomicUsize cursor — 全ワーカーが共有するインデックス (▲ Ordering::SeqCst)
//   - 各ワーカーはcursor.fetch_add()で次のURLを取得 → 排他電脳制御不要
//   - ワーカー数はmin(threads, urls.len())でクランプ
// ♢ 負荷分散: ラウンドロビン方式でワーカーにフェーズ名を割り当て
// ★ worker_phases配列でrecon/sqli/xss/lfi/cmdi/crawl/cors/fuzzを巡回
pub struct ParallelScanner {
    client:  Arc<HttpClient>,
    args:    CliArgs,
    workers: usize,
}

impl ParallelScanner {
    pub fn new(client: Arc<HttpClient>, args: CliArgs, workers: usize) -> Self {
        Self { client, args, workers: workers.max(1) }
    }

    // ◆ run: ワーカープール実行
    // ◆ Launches effective worker tasks, each consuming URLs via atomic cursor.
    // ■ Steps:
    //   1. urlsをArcで共有 / cursorはAtomicUsize
    //   2. effective個のtokio::spawnタスク生成
    //   3. 各タスク: idx = fetch_add → urls[idx] → HTTP GET → analyze → probe_vulns
    //   4. ライブレンダリングループ: 120msごとにScanBoard更新
    //   5. all_findingsをArc<RwLock<Vec<Finding>>>に集約
    // ♢ 戻り値はVec<Finding> — 全ワーカーの電脳検出結果を統合
    pub async fn run(&self, urls: Vec<String>, board: Arc<ScanBoard>) -> Vec<Finding> {
        if urls.is_empty() { return Vec::new(); }
        let total     = urls.len();
        let effective = self.workers.min(total).max(1);
        board.set_total(total);
        let urls         = Arc::new(urls);
        let cursor       = Arc::new(AtomicUsize::new(0));
        let all_findings = Arc::new(RwLock::new(Vec::<Finding>::new()));
        let mut handles  = Vec::new();

        let worker_phases = ["recon", "sqli", "xss", "lfi", "cmdi", "crawl", "cors", "fuzz"];

        for wid in 0..effective {
            let client       = self.client.clone();
            let args         = self.args.clone();
            let urls         = urls.clone();
            let cursor       = cursor.clone();
            let board        = board.clone();
            let findings_out = all_findings.clone();

            handles.push(tokio::spawn(async move {
                let analyzer = Analyzer::new();
                loop {
                    let idx = cursor.fetch_add(1, Ordering::SeqCst);
                    if idx >= urls.len() { break; }
                    let url = &urls[idx];
                    let phase = worker_phases[wid % worker_phases.len()];
                    board.worker_start(wid, phase, url).await;
                    match client.send(HttpRequest::get(url)).await {
                        Ok(response) => {
                            let scan_result = ScanResult {
                                url:            url.clone(),
                                status:         response.status,
                                response:       Some(response),
                                payload:        String::new(),
                            };
                            if let Some(finding) = analyzer.analyze(scan_result).await {
                                board.print_finding_live(
                                    &format!("{:?}", finding.severity),
                                    &finding.title, url,
                                ).await;
                                findings_out.write().await.push(finding);
                            }
                            Self::probe_vulns(&client, &args, url, wid, &board, &findings_out).await;
                            board.done.fetch_add(1, Ordering::SeqCst);
                        }
                        Err(e) => { board.worker_error(wid, e.to_string()).await; }
                    }
                }
                board.worker_done(wid, 0).await;
            }));
        }

        let _ = board.render().await;
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(120)).await;
            let h = board.render_height().await;
            if h > 0 { print!("\x1B[{}A\x1B[0G", h); }
            println!("{}", board.render().await);
            std::io::Write::flush(&mut std::io::stdout()).ok();
            if board.done.load(Ordering::SeqCst) >= total { break; }
        }
        let h = board.render_height().await;
        if h > 0 { print!("\x1B[{}A\x1B[0G", h); }
        println!("{}", board.render().await);

        for handle in handles { let _ = handle.await; }
        Arc::try_unwrap(all_findings).map(|rw| rw.into_inner()).unwrap_or_default()
    }

    // ◆ probe_vulns: 追加脆弱性プローブ
    // ◆ Secondary targeted probes — SQLi, XSS, LFI on all discovered parameters.
    // ■ Probe matrix:
    //   - SQLi: "'" と "' OR '1'='1" → "sql syntax" インジケータ
    //   - XSS:  "OXIDEXSS" → "<script>alert(1)" リフレクションチェック
    //   - LFI:  "../../../../etc/passwd" → "root:x:" パターンマッチ
    // ■ Parameter extraction:
    //   1. URLから既存パラメータを抽出 (UrlUtil::extract_query_param_names)
    //   2. 空なら共通パラメータ名リストでフォールバック
    //   3. 各パラメータ×各プローブの直積でテスト
    // ♢ レート制限: args.rate_limit > 0 の場合、1秒あたりのリクエスト数を制限
    // ★ ペイロードがレスポンスに反映され + インジケータが一致 → Finding生成
    async fn probe_vulns(
        client:   &Arc<HttpClient>,
        args:     &CliArgs,
        base_url: &str,
        wid:      usize,
        board:    &Arc<ScanBoard>,
        findings: &Arc<RwLock<Vec<Finding>>>,
    ) {
        let probes: &[(&str, &str, &str)] = &[
            ("SQLi", "'",                        "sql syntax"),
            ("SQLi", "' OR '1'='1",              "sql syntax"),
            ("XSS",  "OXIDEXSS",                 "<script>alert(1)"),
            ("LFI",  "../../../../etc/passwd",    "root:x:"),
            ("LFI",  "..%2F..%2Fetc%2Fpasswd",   "root:x:"),
        ];

        let mut params = UrlUtil::extract_query_param_names(base_url);
        if params.is_empty() {
            params = vec![
                "id".into(), "q".into(), "page".into(),
                "file".into(), "url".into(), "name".into(),
                "cat".into(), "dir".into(), "path".into(),
            ];
        }

        for param in &params {
            for &(label, payload, indicator) in probes {
                let probe_url = UrlUtil::inject_param(base_url, param, &urlencoding::encode(payload));
                board.worker_start(wid, label, base_url).await;
                if let Ok(resp) = client.send(HttpRequest::get(&probe_url)).await {
                    let body_lower = resp.body.to_lowercase();
                    let payload_reflected = payload.len() > 4 && body_lower.contains(&payload.to_lowercase());
                    let indicator_hit = body_lower.contains(&indicator.to_lowercase());

                    if payload_reflected && indicator_hit {
                        let severity = match label {
                            "SQLi" | "LFI" => Severity::Critical,
                            "XSS" => Severity::High,
                            _ => Severity::Medium,
                        };
                        let finding = Finding::new(
                            base_url, severity,
                            &format!("{} detected", label),
                            &format!("Payload `{}` on param `{}` reflected and triggered `{}`", payload, param, indicator),
                        )
                        .with_evidence(&format!("probe: {}", probe_url))
                        .with_remediation("Sanitize all user-supplied input.");
                        board.print_finding_live(
                            &format!("{:?}", finding.severity), &finding.title, base_url,
                        ).await;
                        findings.write().await.push(finding);
                    }
                }
                if args.rate_limit > 0 {
                    let cap = args.rate_limit.min(1000);
                    let delay_ms = (1000 / cap).max(1);
                    tokio::time::sleep(
                        std::time::Duration::from_millis(delay_ms)
                    ).await;
                }
            }
        }
    }
}
