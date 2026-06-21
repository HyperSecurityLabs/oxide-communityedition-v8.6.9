// ----------------------------------------------------------------------------
//  agent.rs — concurrent scanning agent pool
// ----------------------------------------------------------------------------
//  Implements an agent pool distributing URLs across up to 8 concurrent
//  ScanAgents via tokio::spawn. Uses semaphore-based concurrency control and
//  a shared AgentBar with braille spinner animation (セキュリティ電脳走査) for
//  real-time per-agent progress. Findings print above a fixed N+1 line block
//  and scroll into scan history.
//
//  --- Developers ---------------------------------------------------------------
//  khaninkali             — разработчик / core engineer (Rust backend, logic)
//  Lyara Koroleva         — дизайнер / blazing fast CLI & visual design
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
use anyhow::Result;
use std::sync::Arc;
use std::time::Duration;
// Arc mutex Coordination For data and threads Acess 
/// System Engineering
 
use tokio::sync::{
       mpsc, Semaphore,
        RwLock};

use crate::cli::args::CliArgs;
use crate::cli::display::AgentBar;
use crate::http::client::{HttpClient, HttpClientConfig};
use crate::http::request::HttpRequest;
use crate::http::response::HttpResponse;
                           
use crate::core::scanner::ScanResult;
use crate::detection::analyzer::{
                       Analyzer, Finding};
use crate::cli::progress::Progress;
use tokio::time::Instant;

const MAX_AGENTS: usize = 8;
// ◆ 最大エージェント数 / maximum concurrent scanning agents (tokio::spawn pool limit)

// ■ ScanAgent — 単一電脳走査エージェント / single scanning agent
// ■ セマフォベースの並行性電脳制御 + ブレイルスピナー表示 / semaphore concurrency + braille spinner
// ── ScanAgent ─────────────────────────────────────────────────────────────────

pub struct ScanAgent {
    id:             usize,
    client:         Arc<HttpClient>,
    analyzer:       Analyzer,
    semaphore:      Arc<Semaphore>,
    progress:       Arc<Progress>,
    tx:             mpsc::Sender<AgentResult>,
    current_target: Arc<RwLock<Option<String>>>,
    is_working:     Arc<RwLock<bool>>,
}

// ♢ エージェント結果型 / agent result — finding or error from one target scan
#[derive(Clone, Debug)]
pub struct AgentResult {
    pub finding:       Option<Finding>,
    pub error:         Option<String>,
}

// ★ ScanAgent実装 / ScanAgent implementation
// ★ 各エージェントはID・HTTPクライアント・アナライザーを保持
// ★ each agent holds id, HTTP client, analyzer, semaphore, progress, channel
impl ScanAgent {
    pub fn new(
        id: usize,
        client: Arc<HttpClient>,
        semaphore: Arc<Semaphore>,
        progress: Arc<Progress>,
        tx: mpsc::Sender<AgentResult>,
    ) -> Self {
        Self {
            id,
            client,
            analyzer:       Analyzer::new(),
            semaphore,
            progress,
            tx,
            current_target: Arc::new(RwLock::new(None)),
            is_working:     Arc::new(RwLock::new(false)),
        }
    }

    // ◆ 単一ターゲット電脳走査 / scan a single target URL
    // ◆ フェーズ割り当て（recon/sqli/xss/lfi/cmdi/crawl/cors/fuzz）
    // ◆ phase assignment rotates by agent id modulo 8
    pub async fn scan_target(&self, target: &str, bar: &Arc<AgentBar>) -> Result<AgentResult> {
        *self.is_working.write().await = true;
        *self.current_target.write().await = Some(target.to_string());

        let _permit = self.semaphore.acquire().await?;
        let start   = Instant::now();

        let phase = match self.id % 8 {
            0 => "recon",
            1 => "sqli",
            2 => "xss",
            3 => "lfi",
            4 => "cmdi",
            5 => "crawl",
            6 => "cors",
            _ => "fuzz",
        };
        bar.agent_start_with_phase(self.id, phase, target).await;

        let result = match self.client.send(HttpRequest::get(target)).await {
            Ok(response) => {
                let _response_time = start.elapsed();
                let finding = self.analyze_response(target, &response).await;

                if let Some(ref f) = finding {
                    bar.print_finding(&format!("{:?}", f.severity), &f.title, target).await;
                    bar.add_finding().await;
                }

                AgentResult {
                    finding,
                    error:    None,
                }
            }
            Err(e) => {
                bar.agent_error(self.id).await;
                AgentResult {
                    finding:       None,
                    error:         Some(e.to_string()),
                }
            }
        };

        *self.is_working.write().await = false;
        *self.current_target.write().await = None;

        self.progress.increment();
        let _ = self.tx.send(result.clone()).await;
        Ok(result)
    }

    // ▲ レスポンス分析 / analyze HTTP response for vulnerabilities
    // ▲ ScanResult構築 → Analyzer.analyze() へ委譲 / delegates to Analyzer
    async fn analyze_response(&self, url: &str, response: &HttpResponse) -> Option<Finding> {
        let scan_result = ScanResult {
            url:            url.to_string(),
            status:         response.status,
            response:       Some(response.clone()),
            payload:        String::new(),
        };
        self.analyzer.analyze(scan_result).await
    }

    // ● バッチ電脳走査 / scan multiple targets sequentially
    // ● 各ターゲットにscan_targetを呼び出し / calls scan_target per URL
    pub async fn scan_batch(&self, targets: &[String], bar: &Arc<AgentBar>) -> Vec<Result<AgentResult>> {
        let mut results = Vec::new();
        for target in targets {
            results.push(self.scan_target(target, bar).await);
        }
        results
    }
}

// ※ AgentPool — エージェントプール管理 / agent pool manager
// ※ 複数ScanAgentを生成し、チャンネル経由で結果収集
// ※ spawns ScanAgents, collects results via mpsc channel
// ── AgentPool ─────────────────────────────────────────────────────────────────

pub struct AgentPool {
    agents:    Vec<ScanAgent>,
    semaphore: Arc<Semaphore>,
    progress:  Arc<Progress>,
    rx:        mpsc::Receiver<AgentResult>,
    active:    bool,
}

// ★ AgentPool実装 / AgentPool implementation
// ★ エージェント生成 → HttpClient構成 → セマフォ電脳設定
// ★ agent creation → HttpClient config → semaphore → channel setup
impl AgentPool {
    pub fn new(args: &CliArgs, agent_count: usize, total_targets: usize) -> Result<Self> {
        let n      = agent_count.min(MAX_AGENTS).max(1);
        let http_config = HttpClientConfig {
            insecure: args.insecure,
            proxy: args.proxy.clone(),
            user_agent: args.user_agent.clone(),
            follow_redirects: true,
            max_redirects: args.max_redirects,
            cookie: args.cookie.clone(),
            jobs: args.jobs,
        };
        let client = Arc::new(HttpClient::new(http_config)?);
        let sem    = Arc::new(Semaphore::new(args.threads.min(MAX_AGENTS)));
        let prog   = Arc::new(Progress::new(total_targets));
        let (tx, rx) = mpsc::channel(256);

        let agents = (0..n)
            .map(|id| ScanAgent::new(id, client.clone(), sem.clone(), prog.clone(), tx.clone()))
            .collect();

        Ok(Self { agents, semaphore: sem, progress: prog, rx, active: args.active })
    }

    // ◆ メイン電脳走査実行フロー / main scan execution flow
    // ◆ ①ターゲット分割 ②AgentBar初期化 ③エージェントspawn ④アニメーション ⑤結果収集
    // ◆ ① chunk targets  ② init AgentBar  ③ spawn agents  ④ animation loop  ⑤ collect results
    pub async fn run_scan(&mut self, targets: Vec<String>) -> Result<Vec<Finding>> {
        if targets.is_empty() {
            return Ok(Vec::new());
        }

        let num_targets    = targets.len();
        let effective      = self.agents.len().min(num_targets).max(1);
        let chunk_size     = (num_targets + effective - 1) / effective;

        // Shared AgentBar — all agents write to it, animation loop reads it
        let bar = AgentBar::new(effective);
        if self.active { bar.set_active(); }
        bar.set_total(num_targets);
        bar.draw_initial().await;

        // ➤ エージェントタスク生成 / spawn one tokio task per agent
        // ➤ 各エージェントはチャンクを受け取りscan_batchを実行
        // ➤ each agent receives a chunk and calls scan_batch
        let mut handles = Vec::new();
        for idx in 0..effective {
            let start = idx * chunk_size;
            let end   = ((idx + 1) * chunk_size).min(num_targets);
            let chunk: Vec<String> = targets[start..end].to_vec();

            let agent = ScanAgent::new(
                idx,
                self.agents[idx].client.clone(),
                self.agents[idx].semaphore.clone(),
                self.agents[idx].progress.clone(),
                self.agents[idx].tx.clone(),
            );
            let bar_clone = bar.clone();

            handles.push(tokio::spawn(async move {
                let results = agent.scan_batch(&chunk, &bar_clone).await;
                bar_clone.agent_done(idx, results.iter().filter(|r| r.is_ok()).count()).await;
                results
            }));
        }

        // ➤ アニメーションループ / animation loop — redraws AgentBar every 120ms
        // ➤ エージェント稼働中は常に描画 / continuously redraws while agents are active
        let bar_anim = bar.clone();
        let anim_handle = tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(120)).await;
                bar_anim.redraw().await;
            }
        });

        // ➤ 結果収集ループ / result collection loop
        // ➤ mpscチャンネルから結果を受信、タイムアウト処理
        // ➤ receives results from mpsc channel, handles timeout
        let mut all_findings = Vec::new();
        let mut completed    = 0;
        let mut error_count  = 0;

        while completed < num_targets {
            match tokio::time::timeout(Duration::from_millis(50), self.rx.recv()).await {
                Ok(Some(result)) => {
                    if let Some(f) = result.finding {
                        all_findings.push(f);
                    }
                    if result.error.is_some() { error_count += 1; }
                    completed += 1;
                    bar.progress_tick();
                }
                Ok(None) => break,
                Err(_)   => {
                    if self.progress.is_complete() { break; }
                }
            }
        }

        anim_handle.abort();
        for h in handles { let _ = h.await; }

        // ▼ 最終描画 + サマリー表示 / final redraw + error summary
        bar.redraw().await;
        bar.finish();

        if error_count > 0 {
            eprintln!("\x1B[90m[AGENTS] {} errors during scan\x1B[0m", error_count);
        }

        Ok(all_findings)
    }

    // ♢ 進捗取得 / get progress reference
    pub fn get_progress(&self) -> &Arc<Progress> { &self.progress }

    // ♢ 利用可能なセマフォ許可数 / get available semaphore permits
    pub fn get_available_permits(&self) -> usize { self.semaphore.available_permits() }
}
