// ----------------------------------------------------------------------------
//  downloader.rs — remote resource downloader
// ----------------------------------------------------------------------------
//  remote resource downloader — fetches payload lists, wordlists, update files
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

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

//  Downloader — リモートリソースダウンローダー / remote resource downloader
//  Downloads payload lists, wordlists, and update files from remote sources.
//   new(): creates target-specific download dir (downloads/{domain}_{timestamp})
//   base_dir(): returns the download directory path for file I/O
pub struct Downloader {
    base_dir: PathBuf,
}

impl Downloader {
    //  new() — ダウンローダー初期化 / downloader setup
    //   Extracts domain from target_url (strips scheme, path, port colon)
    //   Generates Unix timestamp for unique directory naming
    //   Creates download path: downloads/{domain}_{timestamp}
    //   base_dir() returns the path for subsequent file I/O operations
    pub fn new(target_url: &str) -> Self {
        let domain = target_url
            .replace("https://", "")
            .replace("http://", "")
            .split('/')
            .next()
            .unwrap_or("unknown")
            .replace(':', "_");

        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let base_dir = PathBuf::from(format!("downloads/{}_{}", domain, ts));
        Self { base_dir }
    }

    pub fn base_dir(&self) -> &Path { &self.base_dir }
}
