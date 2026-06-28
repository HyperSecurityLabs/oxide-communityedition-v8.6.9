// ----------------------------------------------------------------------------
//  pattern_learner.rs — pattern learner
// ----------------------------------------------------------------------------
//  pattern learner — records successful payload patterns and generalizes for future scans
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
use std::collections::HashMap;

//  PatternLearner — Bayesian-style pattern learning / ベイズ的パターン学習
//  Uses exponential moving average (EMA) confidence update:
//    new_conf = old_conf + lr  (outcome - old_conf)
//    outcome = 1.0 for success, 0.0 for failure
//    lr=1.0   immediate full adjustment (pure win/loss ratio)
//    lr=0.1   conservative, smooth updates (resistant to noise)
//    lr=0.01  very slow adaptation (for high-noise environments)
//  Each pattern tracks:
//    signature     — the payload/technique identifier
//    success_count — how many times it worked
//    failure_count — how many times it failed
//    confidence    — smoothed score in [0, 1], starts at 0.5 (no prior)
//    context       — strings describing the environment where it worked
//  Query methods:
//    predict_success(signature)   returns confidence (0.5 for unseen)
//    get_best_patterns(count)     top K patterns by confidence
//    get_statistics()             aggregate metrics
//  Unlike the old implementation, learning_rate is ACTUALLY used here
//   (the previous version stored it but never applied it).
pub struct PatternLearner {
    patterns: HashMap<String, Pattern>,
    learning_rate: f32,
}

#[derive(Clone, Debug)]
pub struct Pattern {
    pub signature: String,
    pub success_count: usize,
    pub failure_count: usize,
    /// Smoothed confidence in [0, 1].  Starts at 0.5 (no prior knowledge).
    pub confidence: f32,
    pub context: Vec<String>,
}

impl PatternLearner {
    pub fn new(learning_rate: f32) -> Self {
        Self {
            patterns: HashMap::new(),
            learning_rate: learning_rate.clamp(0.01, 1.0),
        }
    }

    //  Learn Success / 成功学習
    //  Increments success_count, updates confidence upward via EMA
    //  Extends context with environmental data for future matching
    //  If signature unseen  initializes with confidence=0.5
    /// Record a successful exploitation of `signature`.
    pub fn learn_success(&mut self, signature: &str, context: Vec<String>) {
        let lr = self.learning_rate;
        let entry = self.patterns.entry(signature.to_string()).or_insert_with(|| Pattern {
            signature: signature.to_string(),
            success_count: 0,
            failure_count: 0,
            confidence: 0.5,
            context: Vec::new(),
        });
        entry.success_count += 1;
        entry.confidence = Self::update_confidence(entry.confidence, true, lr);
        entry.context.extend(context);
    }

    //  Learn Failure / 失敗学習
    //  Increments failure_count, updates confidence downward via EMA
    //  Failure context is not stored (only successful contexts are kept)
    /// Record a failed exploitation of `signature`.
    pub fn learn_failure(&mut self, signature: &str) {
        let lr = self.learning_rate;
        let entry = self.patterns.entry(signature.to_string()).or_insert_with(|| Pattern {
            signature: signature.to_string(),
            success_count: 0,
            failure_count: 0,
            confidence: 0.5,
            context: Vec::new(),
        });
        entry.failure_count += 1;
        entry.confidence = Self::update_confidence(entry.confidence, false, lr);
    }

    //  Confidence Update (EMA) / 信頼度更新（指数移動平均）
    //  new_conf = old_conf + lr  (outcome - old_conf)
    //   When lr=1.0: new_conf = outcome (instant jump)
    //   When lr=0.1: new_conf moves 10% toward outcome each time
    //  Properties:
    //    Bounded to [0.0, 1.0]
    //    No prior knowledge starts at 0.5 (maximum entropy)
    //    Smooth convergence — resistant to outlier observations
    /// Online confidence update using exponential moving average.
    ///
    /// `learning_rate` controls how much each new observation shifts the score:
    ///   new_conf = old_conf + lr * (outcome - old_conf)
    ///
    /// outcome = 1.0 for success, 0.0 for failure.
    /// This is equivalent to an EMA and actually uses learning_rate unlike the
    /// previous implementation that stored it but ignored it.
    fn update_confidence(current: f32, success: bool, learning_rate: f32) -> f32 {
        let outcome = if success { 1.0_f32 } else { 0.0_f32 };
        (current + learning_rate * (outcome - current)).clamp(0.0, 1.0)
    }

    /// Return the top `count` patterns sorted by confidence descending.
    pub fn get_best_patterns(&self, count: usize) -> Vec<&Pattern> {
        let mut patterns: Vec<&Pattern> = self.patterns.values().collect();
        patterns.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence)
            .unwrap_or(std::cmp::Ordering::Equal));
        patterns.into_iter().take(count).collect()
    }

    /// Predicted success probability for `signature` (0.5 if unseen).
    pub fn predict_success(&self, signature: &str) -> f32 {
        self.patterns.get(signature).map(|p| p.confidence).unwrap_or(0.5)
    }

    /// Aggregate statistics across all learned patterns.
    pub fn get_statistics(&self) -> HashMap<String, f32> {
        let mut stats = HashMap::new();
        let n = self.patterns.len() as f32;
        stats.insert("total_patterns".to_string(), n);

        if n > 0.0 {
            let avg_conf = self.patterns.values().map(|p| p.confidence).sum::<f32>() / n;
            stats.insert("avg_confidence".to_string(), avg_conf);

            let total_attempts: usize = self.patterns.values()
                .map(|p| p.success_count + p.failure_count).sum();
            stats.insert("total_attempts".to_string(), total_attempts as f32);

            let total_success: usize = self.patterns.values()
                .map(|p| p.success_count).sum();
            stats.insert("overall_success_rate".to_string(),
                total_success as f32 / total_attempts.max(1) as f32);
        }
        stats
    }

    /// Return the learning rate in use.
    pub fn learning_rate(&self) -> f32 { self.learning_rate }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_confidence_rises_on_success() {
        let mut learner = PatternLearner::new(0.8);
        learner.learn_success("sqli_1", vec!["ctx".to_string()]);
        learner.learn_success("sqli_1", vec![]);
        assert!(learner.predict_success("sqli_1") > 0.5);
    }

    #[test]
    fn test_confidence_falls_on_failure() {
        let mut learner = PatternLearner::new(0.8);
        learner.learn_failure("sqli_1");
        learner.learn_failure("sqli_1");
        assert!(learner.predict_success("sqli_1") < 0.5);
    }

    #[test]
    fn test_unseen_pattern_returns_half() {
        let learner = PatternLearner::new(0.5);
        assert_eq!(learner.predict_success("never_seen"), 0.5);
    }

    #[test]
    fn test_learning_rate_actually_used() {
        // With lr=1.0 a single success should push confidence to 1.0
        let mut learner = PatternLearner::new(1.0);
        learner.learn_success("p", vec![]);
        assert_eq!(learner.predict_success("p"), 1.0);

        // With lr=0.1 a single success should only nudge from 0.5 to 0.55
        let mut learner2 = PatternLearner::new(0.1);
        learner2.learn_success("p", vec![]);
        let conf = learner2.predict_success("p");
        assert!((conf - 0.55).abs() < 1e-5, "expected ~0.55, got {}", conf);
    }
}
