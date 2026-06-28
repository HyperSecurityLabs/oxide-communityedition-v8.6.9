// ----------------------------------------------------------------------------
//  progress.rs — scan progress tracker
// ----------------------------------------------------------------------------
//  Thread-safe scan progress tracking with atomic counters for severity
//  buckets (critical, high, medium, low, info), network I/O accounting,
//  ETA calculation, and percentage completion. Used by the display engine.
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
//  進行状況追跡 / scan progress tracking
//  Progress構造体 — アトミックカウンタによるスレッドセーフな進行管理
//                     / thread-safe progress management via atomic counters
//    カウンタグループ / counter groups:
//      基本進行 / base progress — total, current
//      重大度バケット / severity buckets — critical, high, medium, low, info
//      電脳網 / network I/O — bytes_tx, bytes_rx, requests, errors
//      時間計測 / timing — start_time
//
//  インクリメントメソッド / increment methods (書き込み / writes):
//    increment() — 現在の処理数を進める / advances current count
//    add_critical/high/medium/low/info() — 各重大度カウンタを進める / advances severity buckets
//    add_request() — リクエスト数を進める / advances request count
//
//  読み取りメソッド / read methods:
//    get_current/total/vulns/critical/high/medium/low/info_count/errors/requests()
//     — 各カウンタの現在値を取得 / reads current counter values
//    get_bytes_tx/rx() — 転送バイト数を取得 / reads byte transfer counts
//    get_elapsed() — 開始からの経過時間を取得 / reads elapsed time
//    get_percent() — 完了率(0–100%)を計算 / calculates completion percentage
//    is_complete() — 全処理が完了したか判定 / checks if all work is done
//    get_elapsed_string() — 経過時間を"MM:SS"形式で取得 / elapsed as "MM:SS"
//
//  Clone実装 / Clone implementation
//    各アトミックカウンタを現在値で新しいAtomicにコピー / copies each atomic with current value
//    start_timeはそのまま参照 / start_time is copied directly
//
use std::sync::atomic::
        {AtomicU64, AtomicUsize,
                         Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Thread-safe scan progress tracker with per-severity vuln counters,
/// bytes-transferred accounting, and ETA calculation.
pub struct Progress {
    pub total: usize,
    current:   AtomicUsize,
    // Severity buckets
    critical:  AtomicUsize,
    high:      AtomicUsize,
    medium:    AtomicUsize,
    low:       AtomicUsize,
    info:      AtomicUsize,
    // Network accounting
    bytes_tx:  AtomicU64,
    bytes_rx:  AtomicU64,
    requests:  AtomicUsize,
    errors:    AtomicUsize,
    start_time: Instant,
}

impl Progress {
    pub fn new(total: usize) -> Self {
        Self {
            total,
            current:    AtomicUsize::new(0),
            critical:   AtomicUsize::new(0),
            high:       AtomicUsize::new(0),
            medium:     AtomicUsize::new(0),
            low:        AtomicUsize::new(0),
            info:       AtomicUsize::new(0),
            bytes_tx:   AtomicU64::new(0),
            bytes_rx:   AtomicU64::new(0),
            requests:   AtomicUsize::new(0),
            errors:     AtomicUsize::new(0),
            start_time: Instant::now(),
        }
    }

    //  Counters 

    pub fn increment(&self) { self.current.fetch_add(1, Ordering::Relaxed); }

    pub fn add_critical(&self) { self.critical.fetch_add(1, Ordering::Relaxed); }
    pub fn add_high(&self)     { self.high.fetch_add(1, Ordering::Relaxed); }
    pub fn add_medium(&self)   { self.medium.fetch_add(1, Ordering::Relaxed); }
    pub fn add_low(&self)      { self.low.fetch_add(1, Ordering::Relaxed); }
    pub fn add_info(&self)     { self.info.fetch_add(1, Ordering::Relaxed); }
    pub fn add_request(&self)  { self.requests.fetch_add(1, Ordering::Relaxed); }

    //  Reads 

    pub fn get_current(&self)  -> usize { self.current.load(Ordering::Relaxed) }
    pub fn get_total(&self)    -> usize { self.total }
    pub fn get_vulns(&self)    -> usize { self.get_critical() + self.get_high() + self.get_medium() + self.get_low() }
    pub fn get_critical(&self) -> usize { self.critical.load(Ordering::Relaxed) }
    pub fn get_high(&self)     -> usize { self.high.load(Ordering::Relaxed) }
    pub fn get_medium(&self)   -> usize { self.medium.load(Ordering::Relaxed) }
    pub fn get_low(&self)      -> usize { self.low.load(Ordering::Relaxed) }
    pub fn get_info_count(&self) -> usize { self.info.load(Ordering::Relaxed) }
    pub fn get_errors(&self)   -> usize { self.errors.load(Ordering::Relaxed) }
    pub fn get_requests(&self) -> usize { self.requests.load(Ordering::Relaxed) }
    pub fn get_bytes_tx(&self) -> u64   { self.bytes_tx.load(Ordering::Relaxed) }
    pub fn get_bytes_rx(&self) -> u64   { self.bytes_rx.load(Ordering::Relaxed) }
    pub fn get_elapsed(&self)  -> Duration { self.start_time.elapsed() }

    pub fn get_percent(&self) -> usize {
        if self.total == 0 { return 0; }
        ((self.get_current() * 100) / self.total).min(100)
    }

    pub fn is_complete(&self) -> bool { self.get_current() >= self.total }

    pub fn get_elapsed_string(&self) -> String {
        let s = self.get_elapsed().as_secs();
        format!("{:02}:{:02}", s / 60, s % 60)
    }

    pub fn clone_arc(self) -> Arc<Self> { Arc::new(self) }
}

impl Clone for Progress {
    fn clone(&self) -> Self {
        Self {
            total:      self.total,
            current:    AtomicUsize::new(self.get_current()),
            critical:   AtomicUsize::new(self.get_critical()),
            high:       AtomicUsize::new(self.get_high()),
            medium:     AtomicUsize::new(self.get_medium()),
            low:        AtomicUsize::new(self.get_low()),
            info:       AtomicUsize::new(self.get_info_count()),
            bytes_tx:   AtomicU64::new(self.get_bytes_tx()),
            bytes_rx:   AtomicU64::new(self.get_bytes_rx()),
            requests:   AtomicUsize::new(self.get_requests()),
            errors:     AtomicUsize::new(self.get_errors()),
            start_time: self.start_time,
        }
    }
}
