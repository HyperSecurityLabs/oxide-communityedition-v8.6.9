// ----------------------------------------------------------------------------
//  scorer.rs — Scoring engine
// ----------------------------------------------------------------------------
//  Scoring engine — uses normalized Levenshtein similarity to match response
//  patterns.
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
// ◆ scorer.rs — スコアリングエンジン
// ★ Scoring engine — Levenshtein similarity, n-gram cosine, Bayesian confidence
// ■ 複数の指標を組み合わせて脆弱性判定の信頼度を算出

use strsim::normalized_levenshtein;

/// Bayesian confidence calculator for vulnerability verdicts.
/// Combines multiple signal sources into a single confidence score.
// ★ Scorer — ベイズ信頼度 + 編集距離スコアリングエンジン
// ★ Bayesian confidence + Levenshtein similarity scoring engine
// ■ 複数のシグナルを統合して脆弱性判定の信頼度を計算
pub struct Scorer;

// ■ スコアリング実装
// ■ Scoring implementation
impl Scorer {
    // ◆ response_similarity — 正規化Levenshtein距離による応答類似度
    // ◆ Normalized Levenshtein similarity between baseline and response
    // ★ 1.0 = 完全一致, 0.0 = 完全不一致
    pub fn response_similarity(baseline: &str, response: &str) -> f64 {
        if baseline.is_empty() && response.is_empty() {
            return 1.0;
        }
        if baseline.is_empty() || response.is_empty() {
            return 0.0;
        }
        normalized_levenshtein(baseline, response)
    }

    // ◆ response_diff_score — ベースラインとの差分スコア
    // ◆ Difference score — 1.0 = 完全に異なる
    // ■ 1.0 - similarity で算出
    pub fn response_diff_score(baseline: &str, response: &str) -> f64 {
        1.0 - Self::response_similarity(baseline, response)
    }

    // ● ngram_cosine — N-gramベースのコサイン類似度
    // ● N-gram cosine similarity — catches structural changes Levenshtein misses
    // ■ 大きな本文での構造的変化を電脳検出するのに有効
    pub fn ngram_cosine(a: &str, b: &str, n: usize) -> f64 {
        let grams_a = Self::ngrams(a, n);
        let grams_b = Self::ngrams(b, n);
        if grams_a.is_empty() || grams_b.is_empty() {
            return 0.0;
        }
        let dot: usize = grams_a.iter().map(|g| grams_b.iter().filter(|h| *h == g).count()).sum();
        let mag_a = (grams_a.len() as f64).sqrt();
        let mag_b = (grams_b.len() as f64).sqrt();
        if mag_a == 0.0 || mag_b == 0.0 {
            return 0.0;
        }
        dot as f64 / (mag_a * mag_b)
    }

    // ▲ ngrams — 文字列からN-gramを生成
    // ▲ Generates N-grams from a string (char-level windows)
    fn ngrams(s: &str, n: usize) -> Vec<String> {
        s.chars()
            .collect::<Vec<char>>()
            .windows(n)
            .map(|w| w.iter().collect())
            .collect()
    }

    // ★ bayesian_confidence — ベイズ更新による事後信頼度
    // ★ Bayesian confidence — posterior probability from evidence signals
    // ◆ likelihoods: 各証拠が真の脆弱性を示す確率 [0.0, 1.0]
    // ◆ prior: 事前確率 (デフォルト 0.1)
    // ◆ 偽陽性率 P(E|~V) を 0.1 と仮定
    // ◆ ベイズの定理: P(V|E) = P(E|V)*P(V) / (P(E|V)*P(V) + P(E|~V)*P(~V))
    pub fn bayesian_confidence(likelihoods: &[f64], prior: f64) -> f64 {
        if likelihoods.is_empty() {
            return prior;
        }
        let prior = prior.clamp(0.001, 0.999);
        let mut posterior = prior;
        for &likelihood in likelihoods {
            let likelihood = likelihood.clamp(0.001, 0.999);
            // P(V|E) = P(E|V) * P(V) / (P(E|V)*P(V) + P(E|~V)*P(~V))
            // Assume P(E|~V) = 0.1 (false positive rate)
            let false_positive_rate = 0.1;
            let numerator = likelihood * posterior;
            let denominator = numerator + false_positive_rate * (1.0 - posterior);
            if denominator > 0.0 {
                posterior = numerator / denominator;
            }
        }
        posterior
    }

    // ※ passes_threshold — 信頼度が閾値を超えているか確認
    // ※ Quick confidence gate
    pub fn passes_threshold(confidence: f64, threshold: f64) -> bool {
        confidence >= threshold
    }

    // ➤ ensemble_confirm — アンサンブル確認: 複数シグナルの多数決
    // ➤ Ensemble confirmation — requires ≥ N signals to be true
    pub fn ensemble_confirm(signals: &[bool], required: usize) -> bool {
        signals.iter().filter(|&&s| s).count() >= required
    }
}
