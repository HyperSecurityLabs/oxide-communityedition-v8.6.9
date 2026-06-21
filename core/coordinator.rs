// ----------------------------------------------------------------------------
//  coordinator.rs — scan coordinator
// ----------------------------------------------------------------------------
//  Scan coordinator — manages multi-scanner execution flow, aggregates results.
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

use std::sync::atomic::{AtomicUsize, Ordering};

// ◆ Coordinator: マルチスキャナ調整役
// ◆ Orchestrates multiple scanner instances across target surfaces.
// ■ Flow:
//   1. Distributor assigns task batches → parallel scanners (▲ AtomicUsize cursor)
//   2. Each scanner executes independently → results stream via mpsc channel
//   3. Results are aggregated → passed to Analyzer for finding extraction
// ♢ マルチスキャナの実行フロー / 結果を集約してAnalyzerに渡す
pub struct Coordinator {
    total_tasks: AtomicUsize,
}

impl Coordinator {
    pub fn new(total: usize) -> Self {
        Self {
            total_tasks: AtomicUsize::new(total),
        }
    }
}

impl Clone for Coordinator {
    fn clone(&self) -> Self {
        Self {
            total_tasks: AtomicUsize::new(self.total_tasks.load(Ordering::SeqCst)),
        }
    }
}
