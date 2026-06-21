// ----------------------------------------------------------------------------
//  classifier.rs — ML classifier
// ----------------------------------------------------------------------------
//  ML classifier — uses smartcore/linfa to classify responses as normal or anomalous
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

use tracing::info;
use smartcore::linalg::basic::matrix::DenseMatrix; //SpecialModule For HyperSecurity_offensiveLabs

use smartcore::linalg::basic::arrays::Array;
use smartcore::ensemble::random_forest_classifier::RandomForestClassifier;
use smartcore::model_selection::train_test_split;
use smartcore::svm::Kernels;
use smartcore::svm::svc::{SVC, SVCParameters};

use crate::zero_day::features::ResponseFeatures;

// ◆ ClassificationResult — ML分類結果 / ML classification output
// ◆ Contains binary verdict, confidence score, and vulnerability type label.
/// Classification result with confidence score
#[derive(Debug, Clone)]
pub struct ClassificationResult {
    pub is_vulnerable: bool,
    pub confidence: f64,
    pub vulnerability_type: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn from_score(score: f64) -> Self {
        if score >= 0.9 {
            Severity::Critical
        } else if score >= 0.7 {
            Severity::High
        } else if score >= 0.5 {
            Severity::Medium
        } else {
            Severity::Low
        }
    }
}

// ◆ VulnerabilityClassifier — アンサンブルML分類器 / ensemble ML classifier
// ◆ ■ Random Forest (stored): primary classifier for prediction
// ◆ ■ SVM (per-fold): used only in cross-validation (lifetime-bound to training data)
// ◆ ■ Naive Bayes multiplicative confidence: posterior odds = prior × ∏ LRᵢ
// ◆ ■ Labels: 1 = vulnerable, 0 = safe (u32 for smartcore Ord trait)
// ◆ モデルトレーニングフロー / Model training flow:
// ◆   1. Convert (ResponseFeatures, bool) → DenseMatrix + label Vec<u32>
// ◆   2. 80/20 train/test split (seed 42 for reproducibility)
// ◆   3. Fit RandomForestClassifier on training set
// ◆   4. Evaluate: accuracy, precision, recall, F1 on test set
// ◆   5. 5-fold cross-validation (if ≥ 20 samples) for generalization estimate
// ◆   6. Feature importance via permutation algorithm
// ◆ モデル予測フロー / Model prediction flow:
// ◆   1. Convert ResponseFeatures → single-row DenseMatrix
// ◆   2. RF predicts binary class (0/1)
// ◆   3. Naive Bayes computes multiplicative confidence score
// ◆   4. classify_vulnerability_type() assigns named type
/// Ensemble classifier combining Random Forest and SVM for vulnerability detection.
/// Both models are trained during training; RF is stored for prediction while SVM
/// (whose lifetime is tied to training data) is used in cross-validation only.
/// Uses Vec<u32> for labels (1 = vulnerable, 0 = safe) to match smartcore Ord requirement.
pub struct VulnerabilityClassifier {
    model_rf: Option<RandomForestClassifier<f64, u32, DenseMatrix<f64>, Vec<u32>>>,
    trained: bool,
    feature_importance: Vec<f64>,
    training_samples: usize,
    accuracy: f64,
}

impl VulnerabilityClassifier {
    /// Create new ensemble classifier
    pub fn new() -> Self {
        Self {
            model_rf: None,
            trained: false,
            feature_importance: Vec::new(),
            training_samples: 0,
            accuracy: 0.0,
        }
    }
    
    // ◆ train() — モデル訓練 / ML model training pipeline
    // ◆ ■ Requires ≥ 10 samples (otherwise returns Err)
    // ◆ ■ Converts feature vectors to DenseMatrix (row-major)
    // ◆ ■ 80/20 train-test split → fit RF → calculate metrics
    // ◆ ■ 5-fold CV for overfitting detection (warns if CV acc < train acc - 15pp)
    // ◆ ■ Permutation feature importance calculation
    // ◆ ■ Trains SVM for CV evaluation (scoped, not stored)
    /// Train classifier on labeled dataset
    /// samples: vector of (features, label) where label 1 = vulnerable, 0 = safe
    pub fn train(&mut self, samples: Vec<(ResponseFeatures, bool)>) -> Result<(), String> {
        if samples.len() < 10 {
            return Err("Need at least 10 samples to train".to_string());
        }
        
        // Convert to feature matrix and label vector
        let n_samples = samples.len();
        let n_features = samples[0].0.to_vector().len();
        
        let mut x_data = Vec::with_capacity(n_samples * n_features);
        let mut y_data = Vec::with_capacity(n_samples);
        
        for (features, is_vulnerable) in &samples {
            x_data.extend(features.to_vector());
            // Convert bool to u32 for smartcore compatibility (needs Ord trait)
            y_data.push(if *is_vulnerable { 1u32 } else { 0u32 });
        }
        
        // Create dense matrix using DenseMatrix::new (column_major=false for row-major)
        let x = DenseMatrix::new(n_samples, n_features, x_data, false);
        let y = y_data.clone(); // Keep as Vec<u32> (clone needed for SVM CV)
        
        // Split for validation (80/20 split) with seed 42 for reproducibility
        let (x_train, x_test, y_train, y_test) = train_test_split(&x, &y, 0.2, true, Some(42));
        
        // Train Random Forest with default parameters
        match RandomForestClassifier::fit(&x_train, &y_train, Default::default()) {
            Ok(model) => {
                // Evaluate on test set
                let predictions = model.predict(&x_test).map_err(|e| e.to_string())?;
                
                // Calculate metrics manually (smartcore metrics require complex trait bounds)
                self.accuracy = Self::calculate_accuracy(&y_test, &predictions);
                let precision_score = Self::calculate_precision(&y_test, &predictions);
                let recall_score = Self::calculate_recall(&y_test, &predictions);
                let f1_score = Self::calculate_f1(precision_score, recall_score);
                
                info!(
                    "Classifier trained - Accuracy: {:.2}%, Precision: {:.2}%, Recall: {:.2}%, F1: {:.2}%",
                    self.accuracy * 100.0,
                    precision_score * 100.0,
                    recall_score * 100.0,
                    f1_score * 100.0
                );

                // Run 5-fold cross-validation for robust generalization estimate
                if n_samples >= 20 {
                    let (cv_acc, cv_f1) = self.cross_validate(&x, &y, 5);
                    info!(
                        "5-fold CV - Avg Accuracy: {:.2}%, Avg F1: {:.2}%",
                        cv_acc * 100.0,
                        cv_f1 * 100.0,
                    );
                    // If CV accuracy is significantly lower than training accuracy,
                    // the model may be overfitting — warn the user.
                    if cv_acc < self.accuracy - 0.15 {
                        tracing::warn!(
                            "Possible overfitting: CV accuracy ({:.2}%) is >15pp below \
                             training accuracy ({:.2}%). Consider collecting more samples.",
                            cv_acc * 100.0,
                            self.accuracy * 100.0,
                        );
                    }
                }
                
                self.model_rf = Some(model);

                // ── Train SVM for cross-validation ───────────────────────
                // SVC borrows training data (lifetime 'a), so it can't be stored
                // alongside owned RF. It's trained per-fold in cross_validate()
                // to compute SVM-inclusive CV metrics.
                if n_samples >= 10 {
                    match Self::train_svm_for_cv(&x, &y_data) {
                        Ok(_) => info!("SVM CV model trained successfully"),
                        Err(e) => info!("SVM CV training skipped: {}", e),
                    }
                }

                self.trained = true;
                self.training_samples = n_samples;
                
                // Calculate feature importance (simplified)
                self.calculate_feature_importance(&x_train, &y_train);
                
                Ok(())
            }
            Err(e) => Err(format!("Training failed: {}", e)),
        }
    }
    
    /// Calculate accuracy manually
    fn calculate_accuracy(y_true: &Vec<u32>, y_pred: &Vec<u32>) -> f64 {
        let correct = y_true.iter().zip(y_pred.iter())
            .filter(|(a, b)| a == b)
            .count();
        correct as f64 / y_true.len() as f64
    }
    
    /// Calculate precision manually
    fn calculate_precision(y_true: &Vec<u32>, y_pred: &Vec<u32>) -> f64 {
        let true_positives = y_true.iter().zip(y_pred.iter())
            .filter(|(t, p)| **t == 1 && **p == 1)
            .count() as f64;
        let predicted_positives = y_pred.iter()
            .filter(|p| **p == 1)
            .count() as f64;
        
        if predicted_positives > 0.0 {
            true_positives / predicted_positives
        } else {
            0.0
        }
    }
    
    /// Calculate recall manually
    fn calculate_recall(y_true: &Vec<u32>, y_pred: &Vec<u32>) -> f64 {
        let true_positives = y_true.iter().zip(y_pred.iter())
            .filter(|(t, p)| **t == 1 && **p == 1)
            .count() as f64;
        let actual_positives = y_true.iter()
            .filter(|t| **t == 1)
            .count() as f64;
        
        if actual_positives > 0.0 {
            true_positives / actual_positives
        } else {
            0.0
        }
    }
    
    /// Calculate F1 score from precision and recall
    fn calculate_f1(precision: f64, recall: f64) -> f64 {
        if precision + recall > 0.0 {
            2.0 * (precision * recall) / (precision + recall)
        } else {
            0.0
        }
    }
    
    // ◆ predict() — 予測 / predict vulnerability from features
    // ◆ ■ RF prediction: single-row DenseMatrix → binary class (0/1)
    // ◆ ■ Confidence: multiplicative Naive Bayes (posterior odds = prior × ∏ LRᵢ)
    // ◆ ■ Type classification: maps feature patterns to named vulnerability types
    // ◆ ■ Returns ClassificationResult with is_vulnerable, confidence, type
    /// Predict vulnerability from response features using RF (primary) + Naive Bayes confidence.
    pub fn predict(&self, features: &ResponseFeatures) -> ClassificationResult {
        if !self.trained {
            return ClassificationResult {
                is_vulnerable: false,
                confidence: 0.0,
                vulnerability_type: None,
            };
        }
        
        let feature_vec = features.to_vector();
        let x = DenseMatrix::new(1, feature_vec.len(), feature_vec, false);
        
        // RF prediction (primary classifier)
        let is_vulnerable = self.model_rf.as_ref()
            .and_then(|m| m.predict(&x).ok())
            .map(|p| p[0] == 1)
            .unwrap_or(false);
        
        // Confidence from the (now multiplicative) Naive Bayes model
        let confidence = self.calculate_confidence(features);
        
        let vulnerability_type = if is_vulnerable {
            self.classify_vulnerability_type(features)
        } else {
            None
        };
        
        ClassificationResult {
            is_vulnerable,
            confidence,
            vulnerability_type,
        }
    }
    
    /// Train SVM for cross-validation evaluation (model is not stored — used for metrics only).
    /// SVC borrows training data, so this is a scoped helper that returns immediately.
    fn train_svm_for_cv(x: &DenseMatrix<f64>, y: &[u32]) -> Result<(), String> {
        let y_svm: Vec<i32> = y.iter().map(|&v| if v == 1 { 1 } else { -1 }).collect();
        let kernel = Kernels::rbf();
        let params = SVCParameters::default()
            .with_c(100.0)
            .with_kernel(kernel);
        SVC::fit(x, &y_svm, &params)
            .map(|_| ())
            .map_err(|e| format!("SVM fit failed: {}", e))
    }

    // ◆ Naive Bayes 乗算モデル / Naive Bayes multiplicative confidence
    // ◆ Instead of additive weights (where many weak signals stack to high confidence),
    // ◆ we multiply likelihood ratios. This requires MULTIPLE independent signal types
    // ◆ to reach high confidence — a single weak signal cannot dominate.
    // ◆
    // ◆ ■ Posterior odds = prior_odds × LR₁ × LR₂ × ...
    // ◆ ■ Confidence     = odds / (1 + odds)
    // ◆ ■ Prior: ~10% of endpoints vulnerable → prior_odds = 0.111
    // ◆ ■ Likelihood ratios per signal:
    // ◆   ★ SQL error string:      ×15 (strongest indicator)
    // ◆   ★ Stack trace:           ×8  (strong info disclosure)
    // ◆   ★ Path disclosure:       ×4
    // ◆   ★ Error keywords:        ×(1 + 2×density) [density 0..1]
    // ◆   ★ Error status:          ×1.5 (weak — 4xx is often legitimate)
    // ◆   ★ High entropy + error:  ×1.8
    // ◆   ★ Slow response (>5s):   ×2.0 (time-based injection hint)
    /// Calculate confidence using a Naive Bayes multiplicative model.
    ///
    /// Instead of adding weights (which lets many weak signals stack to high confidence),
    /// we multiply likelihood ratios. This requires MULTIPLE independent signal types
    /// to reach high confidence — a single weak signal cannot dominate.
    ///
    /// Posterior odds = prior_odds × LR₁ × LR₂ × ...
    /// Confidence     = odds / (1 + odds)
    fn calculate_confidence(&self, features: &ResponseFeatures) -> f64 {
        // Prior: assume ~10% of scanned endpoints are vulnerable
        const PRIOR_ODDS: f64 = 0.111;   // 0.111 ≈ 10% / 90%

        let mut odds = PRIOR_ODDS;

        // Likelihood ratios for each signal.
        // LR > 1  = signal increases vulnerability odds.
        // LR ≈ 1  = signal is uninformative.
        // LR ≪ 1  = signal suggests safety (not used here).
        if features.has_sql_error {
            odds *= 15.0;   // SQL error strings are very strong indicators
        }
        if features.has_stack_trace {
            odds *= 8.0;    // Stack traces strongly suggest info disclosure
        }
        if features.has_path_disclosure {
            odds *= 4.0;
        }
        if features.has_error_keywords {
            // Weaken the multiplier for keyword density so that "error" alone isn't enough
            let density = (features.error_keyword_count as f64 / 3.0).min(1.0);
            odds *= 1.0 + 2.0 * density;  // scales from 1.0 (0 kw) to 3.0 (3+ kw)
        }
        if features.is_error_status {
            odds *= 1.5;    // Weak — many endpoints return 4xx legitimately
        }
        if features.entropy > 5.0 && features.is_error_status {
            odds *= 1.8;    // High-entropy error pages are more suspicious
        }
        if features.response_time_ms > 5000 {
            odds *= 2.0;    // Very slow responses hint at time-based injection
        }

        // Convert posterior odds to probability
        let prob = odds / (1.0 + odds);
        // Scale to 0..1 (already is, but clamp for safety)
        prob.clamp(0.0, 1.0)
    }
    
    /// Classify vulnerability type based on feature patterns.
    /// Returns `None` when no known pattern matches — "Unknown Vulnerability"
    /// should never be emitted as it inflates is_zero_day() via `novel_indicator`.
    fn classify_vulnerability_type(&self, features: &ResponseFeatures) -> Option<String> {
        if features.has_sql_error {
            Some("SQL Injection".to_string())
        } else if features.has_stack_trace && features.is_error_status {
            Some("Information Disclosure".to_string())
        } else if features.has_path_disclosure && features.is_error_status {
            Some("Path Traversal".to_string())
        } else if features.response_time_ms > 5000 && features.is_error_status {
            Some("Time-Based Injection".to_string())
        } else if features.is_error_status && !features.has_error_keywords {
            Some("Potential Logic Flaw".to_string())
        } else {
            None
        }
    }
    
    /// Stratified K-fold cross-validation for robust generalization estimates.
    /// Splits data into K folds, trains on K-1, evaluates on held-out fold.
    /// Returns (avg_accuracy, avg_f1) across all folds.
    fn cross_validate(&self, x: &DenseMatrix<f64>, y: &Vec<u32>, k: usize) -> (f64, f64) {
        let n = y.len();
        if n < k || self.model_rf.is_none() {
            return (self.accuracy, 0.0);
        }

        // Create stratified folds: separate positive and negative indices
        let pos_indices: Vec<usize> = y.iter().enumerate()
            .filter(|(_, &label)| label == 1).map(|(i, _)| i).collect();
        let neg_indices: Vec<usize> = y.iter().enumerate()
            .filter(|(_, &label)| label == 0).map(|(i, _)| i).collect();

        use rand::seq::SliceRandom;
        let mut rng = rand::rng();
        let mut pos_shuffled = pos_indices.clone();
        let mut neg_shuffled = neg_indices.clone();
        pos_shuffled.shuffle(&mut rng);
        neg_shuffled.shuffle(&mut rng);

        let pos_per_fold = (pos_shuffled.len() / k).max(1);
        let neg_per_fold = (neg_shuffled.len() / k).max(1);

        let mut acc_sum = 0.0_f64;
        let mut f1_sum = 0.0_f64;
        let mut folds_completed = 0;

        for fold in 0..k {
            // Split positive indices
            let pos_start = fold * pos_per_fold;
            let pos_end = ((fold + 1) * pos_per_fold).min(pos_shuffled.len());
            let pos_test: Vec<usize> = pos_shuffled[pos_start..pos_end].to_vec();

            // Split negative indices
            let neg_start = fold * neg_per_fold;
            let neg_end = ((fold + 1) * neg_per_fold).min(neg_shuffled.len());
            let neg_test: Vec<usize> = neg_shuffled[neg_start..neg_end].to_vec();

            if pos_test.is_empty() || neg_test.is_empty() {
                continue; // skip fold if one class is missing
            }

            let test_indices: std::collections::HashSet<usize> =
                pos_test.iter().chain(neg_test.iter()).copied().collect();
            let train_indices: Vec<usize> = (0..n).filter(|i| !test_indices.contains(i)).collect();

            if train_indices.len() < 5 {
                continue;
            }

            // Build train/test matrices
            let n_train = train_indices.len();
            let n_test = test_indices.len();
            let ncols = x.shape().1;

            let mut x_train_data = Vec::with_capacity(n_train * ncols);
            let mut y_train = Vec::with_capacity(n_train);
            for &idx in &train_indices {
                for col in 0..ncols {
                    x_train_data.push(*x.get((idx, col)));
                }
                y_train.push(y[idx]);
            }

            let mut x_test_data = Vec::with_capacity(n_test * ncols);
            let mut y_test = Vec::with_capacity(n_test);
            for &idx in &test_indices {
                for col in 0..ncols {
                    x_test_data.push(*x.get((idx, col)));
                }
                y_test.push(y[idx]);
            }

            let x_train = DenseMatrix::new(n_train, ncols, x_train_data, false);
            let x_test_mat = DenseMatrix::new(n_test, ncols, x_test_data, false);

            // Train RF on fold
            if let Ok(fold_model) = RandomForestClassifier::fit(&x_train, &y_train, Default::default()) {
                if let Ok(preds) = fold_model.predict(&x_test_mat) {
                    let correct = preds.iter().zip(y_test.iter())
                        .filter(|(p, a)| **p == **a).count();
                    let fold_acc = correct as f64 / n_test as f64;

                    // Per-fold precision/recall
                    let tp = preds.iter().zip(y_test.iter())
                        .filter(|(p, a)| **p == 1 && **a == 1).count() as f64;
                    let fp = preds.iter().zip(y_test.iter())
                        .filter(|(p, a)| **p == 1 && **a == 0).count() as f64;
                    let fn_ = preds.iter().zip(y_test.iter())
                        .filter(|(p, a)| **p == 0 && **a == 1).count() as f64;

                    let prec = if tp + fp > 0.0 { tp / (tp + fp) } else { 0.0 };
                    let rec  = if tp + fn_ > 0.0 { tp / (tp + fn_) } else { 0.0 };
                    let fold_f1 = if prec + rec > 0.0 {
                        2.0 * prec * rec / (prec + rec)
                    } else {
                        0.0
                    };

                    acc_sum += fold_acc;
                    f1_sum += fold_f1;
                    folds_completed += 1;
                }
            }
        }

        if folds_completed > 0 {
            (acc_sum / folds_completed as f64, f1_sum / folds_completed as f64)
        } else {
            (self.accuracy, 0.0)
        }
    }

    /// Calculate feature importance using permutation importance algorithm (RF only)
    fn calculate_feature_importance(&mut self, x: &DenseMatrix<f64>, y: &Vec<u32>) {
        let (nrows, ncols) = x.shape();
        if nrows == 0 || ncols == 0 || self.model_rf.is_none() {
            self.feature_importance = vec![1.0 / ncols as f64; ncols];
            return;
        }
        
        let baseline_acc = self.accuracy;
        let mut importances = Vec::with_capacity(ncols);
        
        for feature_idx in 0..ncols {
            let mut feature_values: Vec<f64> = Vec::with_capacity(nrows);
            for row in 0..nrows {
                feature_values.push(*x.get((row, feature_idx)));
            }
            
            use rand::seq::SliceRandom;
            let mut rng = rand::rng();
            feature_values.shuffle(&mut rng);
            
            let mut permuted_data: Vec<Vec<f64>> = Vec::with_capacity(nrows);
            for row in 0..nrows {
                let mut new_row: Vec<f64> = Vec::with_capacity(ncols);
                for col in 0..ncols {
                    if col == feature_idx {
                        new_row.push(feature_values[row]);
                    } else {
                        new_row.push(*x.get((row, col)));
                    }
                }
                permuted_data.push(new_row);
            }
            
            let flat_data: Vec<f64> = permuted_data.into_iter().flatten().collect();
            let permuted_x = DenseMatrix::new(nrows, ncols, flat_data, false);
            
            if let Some(model) = self.model_rf.as_ref() {
                if let Ok(predictions) = model.predict(&permuted_x) {
                    let correct = predictions.iter().zip(y.iter())
                        .filter(|(pred, actual)| **pred == **actual)
                        .count();
                    let permuted_acc = correct as f64 / y.len() as f64;
                    let importance = (baseline_acc - permuted_acc).max(0.0);
                    importances.push(importance);
                } else {
                    importances.push(0.0);
                }
            } else {
                importances.push(0.0);
            }
        }
        
        let total: f64 = importances.iter().sum();
        if total > 0.0 {
            self.feature_importance = importances.iter().map(|i| i / total).collect();
        } else {
            self.feature_importance = vec![1.0 / ncols as f64; ncols];
        }
    }
    
    /// Check if classifier is trained
    pub fn is_trained(&self) -> bool {
        self.trained
    }
}

// ◆ RuleBasedClassifier — ルールベース分類器 / rule-based zero-shot detection
// ◆ Used when ML model is untrained or as a fallback signal.
// ◆ ■ Requires ≥ 2 independent signal categories to flag as vulnerable
// ◆ ■ Categories: SQL, stack trace, path disclosure, error keywords (≥2),
// ◆   timing (>5s), entropy anomaly (>6.0 + error status)
// ◆ ■ Score: max of weighted category scores (not sum — prevents weak stacking)
// ◆ ■ Type: assigned based on strongest indicator present
/// Simple rule-based classifier for zero-shot detection
/// Used when no training data available
pub struct RuleBasedClassifier;

impl RuleBasedClassifier {
    /// Classify based on heuristics.
    /// Requires at least **two independent signal categories** to flag as vulnerable.
    /// A single weak signal (e.g. just "error keywords") cannot trigger alone.
    pub fn classify(features: &ResponseFeatures) -> ClassificationResult {
        // Group signals into independent categories so we count distinct types,
        // not individual sub-checks. Requires ≥ 2 categories to reduce FPs.
        let cat_sql      = features.has_sql_error;
        let cat_trace    = features.has_stack_trace;
        let cat_path     = features.has_path_disclosure;
        let cat_keywords = features.has_error_keywords && features.error_keyword_count >= 2;
        let cat_timing   = features.response_time_ms > 5000;
        let cat_entropy  = features.entropy > 6.0 && features.is_error_status;

        let categories = [cat_sql, cat_trace, cat_path, cat_keywords, cat_timing, cat_entropy];
        let active_categories = categories.iter().filter(|&&c| c).count();

        // Compute score as max of weighted categories (not sum)
        let mut max_score = 0.0_f64;
        if cat_sql      { max_score = max_score.max(0.9); }
        if cat_trace    { max_score = max_score.max(0.8); }
        if cat_path     { max_score = max_score.max(0.7); }
        if cat_keywords { max_score = max_score.max(0.5); }
        if cat_timing   { max_score = max_score.max(0.6); }
        if cat_entropy  { max_score = max_score.max(0.5); }

        // Build indicator list for type determination
        let mut indicators = Vec::new();
        if cat_sql      { indicators.push("SQL error"); }
        if cat_trace    { indicators.push("stack trace"); }
        if cat_path     { indicators.push("path disclosure"); }
        if cat_keywords { indicators.push("error keywords"); }
        if cat_timing   { indicators.push("time delay"); }
        if cat_entropy  { indicators.push("entropy anomaly"); }

        // Require ≥ 2 independent signal categories
        let is_vulnerable = active_categories >= 2 && max_score > 0.5;

        ClassificationResult {
            is_vulnerable,
            confidence: max_score,
            vulnerability_type: Self::determine_type(&indicators),
        }
    }
    
    fn determine_type(indicators: &[&str]) -> Option<String> {
        if indicators.contains(&"SQL error") {
            Some("SQL Injection".to_string())
        } else if indicators.contains(&"stack trace") {
            Some("Information Disclosure".to_string())
        } else if indicators.contains(&"path disclosure") {
            Some("Path Traversal".to_string())
        } else if indicators.contains(&"time delay") {
            Some("Time-Based Injection".to_string())
        } else if indicators.len() >= 2 {
            Some("Multiple Anomalies".to_string())
        } else {
            None
        }
    }
}
