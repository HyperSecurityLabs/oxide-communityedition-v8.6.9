// ----------------------------------------------------------------------------
//  trainer.rs — ML model trainer
// ----------------------------------------------------------------------------
//  ML model trainer — trains classifiers on labeled HTTP response datasets
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

use crate::http::client::HttpClient;
use crate::zero_day::engine::ZeroDayEngine;
use crate::zero_day::features::ResponseFeatures;

use oxide::scanner::tls_scanner::TlsScanner;
use oxide::scanner::cors_scanner::CorsScanner;
use oxide::scanner::common_app_scanner::CommonAppScanner;
use oxide::scanner::default_creds_scanner::DefaultCredsScanner;

// ◆ ZeroDayTrainer — MLトレーニングパイプライン / ML training pipeline
// ◆ ■ Data collection: runs TLS, CORS, CommonApp, DefaultCreds scanners
// ◆   to collect positive (vulnerable) samples from target.
// ◆ ■ Negative samples: fetches known-safe URLs (/, robots.txt, favicon.ico, /index.html).
// ◆ ■ Model fitting: calls engine.train_classifier() with collected samples.
// ◆ ■ Evaluation: prints sample counts, logs training success/failure.
// ◆ ■ Export: saves trained model to zero_day_model.bin + zero_day_model.json.
pub struct ZeroDayTrainer {
    client: Arc<HttpClient>,
    engine: ZeroDayEngine,
    target: String,
    timeout_secs: u64,
}

impl ZeroDayTrainer {
    pub fn new(
        client: Arc<HttpClient>,
        engine: ZeroDayEngine,
        target: &str,
        timeout_secs: u64,
    ) -> Self {
        Self {
            client,
            engine,
            target: target.to_string(),
            timeout_secs,
        }
    }

    // ◆ run_training() — MLトレーニングパイプライン / full training pipeline
    // ◆ ■ Phase 1-4: Collect positive (vulnerable) samples from 4 scanners:
    // ◆   1. TLS Scanner — SSL/TLS misconfiguration findings
    // ◆   2. CORS Scanner — CORS misconfiguration findings
    // ◆   3. CommonApp Scanner — known application vulnerabilities
    // ◆   4. DefaultCreds Scanner — default credential usage
    // ◆ ■ Phase 5: Collect negative (safe) samples from known-clean URLs
    // ◆   (/, /robots.txt, /favicon.ico, /index.html), padding to ≥ 5 samples
    // ◆ ■ Phase 6: Train classifier via engine.train_classifier()
    // ◆ ■ Phase 7: Export model to zero_day_model.bin + zero_day_model.json
    pub async fn run_training(&self) -> anyhow::Result<()> {
        println!("[TRAIN] Zero-day classifier training mode");
        println!("[TRAIN] Running all scanners against {}", self.target);

        let mut positive_samples: Vec<(ResponseFeatures, bool)> = Vec::new();
        let mut negative_samples: Vec<(ResponseFeatures, bool)> = Vec::new();

        // ── 1. TLS Scanner ────────────────────────────────────────────────
        println!("[TRAIN] Scanning TLS...");
        match TlsScanner::new(self.timeout_secs) {
            Ok(tls) => {
                let findings = tls.scan(&self.target).await;
                if !findings.is_empty() {
                    println!("[TRAIN]   TLS found {} issues", findings.len());
                    if let Ok(resp) = self.client.get(&self.target).await {
                        let features = ResponseFeatures::from_response(&resp, &self.target, 100);
                        positive_samples.push((features, true));
                    }
                }
            }
            Err(e) => println!("[TRAIN]   TLS scanner failed: {}", e),
        }

        // ── 2. CORS Scanner ──────────────────────────────────────────────
        println!("[TRAIN] Scanning CORS...");
        match CorsScanner::new(self.timeout_secs) {
            Ok(cors) => {
                let findings = cors.scan(&self.target).await;
                if !findings.is_empty() {
                    println!("[TRAIN]   CORS found {} issues", findings.len());
                    if let Ok(resp) = self.client.get(&self.target).await {
                        let features = ResponseFeatures::from_response(&resp, &self.target, 100);
                        positive_samples.push((features, true));
                    }
                }
            }
            Err(e) => println!("[TRAIN]   CORS scanner failed: {}", e),
        }

        // ── 3. Common App Scanner ────────────────────────────────────────
        println!("[TRAIN] Scanning common applications...");
        match CommonAppScanner::new(self.timeout_secs) {
            Ok(common) => {
                let findings = common.scan(&self.target, false).await;
                for finding in &findings {
                    println!("[TRAIN]   App finding: {} at {}", finding.title, finding.url);
                    if let Ok(resp) = self.client.get(&finding.url).await {
                        let features = ResponseFeatures::from_response(&resp, &finding.url, 100);
                        positive_samples.push((features, true));
                    }
                }
            }
            Err(e) => println!("[TRAIN]   CommonApp scanner failed: {}", e),
        }

        // ── 4. Default Creds Scanner ─────────────────────────────────────
        println!("[TRAIN] Scanning default credentials...");
        match DefaultCredsScanner::new(self.timeout_secs) {
            Ok(creds) => {
                let findings = creds.scan(&self.target).await;
                for finding in &findings {
                    println!("[TRAIN]   Creds finding: {} at {}", finding.application, finding.url);
                    if let Ok(resp) = self.client.get(&finding.url).await {
                        let features = ResponseFeatures::from_response(&resp, &finding.url, 100);
                        positive_samples.push((features, true));
                    }
                }
            }
            Err(e) => println!("[TRAIN]   DefaultCreds scanner failed: {}", e),
        }

        // ── 5. Collect negative samples ──────────────────────────────────
        println!("[TRAIN] Collecting negative (safe) samples...");
        let negative_urls = vec![
            format!("{}/", self.target),
            format!("{}/robots.txt", self.target),
            format!("{}/favicon.ico", self.target),
            format!("{}/index.html", self.target),
        ];
        for url in &negative_urls {
            match self.client.get(url).await {
                Ok(resp) => {
                    let features = ResponseFeatures::from_response(&resp, url, 100);
                    negative_samples.push((features, false));
                }
                Err(_) => {
                    // Some paths may 404 — still useful as negative samples
                    if let Ok(resp) = self.client.get(&self.target).await {
                        let features = ResponseFeatures::from_response(&resp, &self.target, 100);
                        negative_samples.push((features, false));
                    }
                }
            }
        }

        // Ensure at least 5 negative samples by padding with repeated requests
        while negative_samples.len() < 5 {
            if let Ok(resp) = self.client.get(&self.target).await {
                let features = ResponseFeatures::from_response(&resp, &self.target, 100);
                negative_samples.push((features, false));
            }
        }

        let total_positive = positive_samples.len();
        let total_negative = negative_samples.len();

        println!("[TRAIN] Collected {} positive samples (vulnerable)", total_positive);
        println!("[TRAIN] Collected {} negative samples (safe)", total_negative);

        if total_positive == 0 {
            println!("[TRAIN] No vulnerable findings — classifier will learn only from safe baselines");
        }

        // ── 6. Train the classifier ──────────────────────────────────────
        let mut all_samples = positive_samples;
        all_samples.extend(negative_samples);

        if all_samples.len() < 5 {
            println!("[TRAIN] Too few samples ({}) — skipping training", all_samples.len());
            return Ok(());
        }

        println!("[TRAIN] Training classifier with {} samples...", all_samples.len());
        match self.engine.train_classifier(all_samples).await {
            Ok(()) => println!("[TRAIN] Classifier trained successfully!"),
            Err(e) => println!("[TRAIN] Classifier training failed: {}", e),
        }

        // ── 7. Export the trained model ──────────────────────────────────
        println!("[TRAIN] Exporting trained model...");
        match self.engine.save_model_to_file("zero_day_model.bin").await {
            Ok(()) => println!("[TRAIN] Model saved to zero_day_model.bin"),
            Err(e) => println!("[TRAIN] Model export failed: {}", e),
        }

        match self.engine.export_model_json().await {
            Ok(json) => {
                match std::fs::write("zero_day_model.json", &json) {
                    Ok(()) => println!("[TRAIN] Model JSON saved to zero_day_model.json"),
                    Err(e) => println!("[TRAIN] Model JSON export failed: {}", e),
                }
            }
            Err(e) => println!("[TRAIN] JSON serialization failed: {}", e),
        }

        println!("[TRAIN] Training complete!");
        Ok(())
    }
}
