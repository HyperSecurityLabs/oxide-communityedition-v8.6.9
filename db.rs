// ----------------------------------------------------------------------------
//  db.rs — encrypted SQLite test database loader
// ----------------------------------------------------------------------------
//  Loads the encrypted SQLite database (oxide_tests.db.enc), XOR-decrypts it
//  to a temporary file in memory, then opens it with rusqlite to retrieve all
//  test records. Each record contains path, method, expected status, content
//  indicators, severity, category, and remediation data used to drive the
//  vulnerability scanning engine (уязвимость-detection pipeline).
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
use anyhow::{Result, anyhow};
use std::io::Write;
use std::path::Path;

// ■ データベース定数 / database constants — directory & filenames
/// Database directory name — change here to relocate the test database folder
pub const DB_DIR: &str = "cgi_database";

/// Database filename (plain SQLite before encryption)
pub const DB_FILE: &str = "oxide_tests.db";

/// Encrypted database filename
pub const DB_ENC_FILE: &str = "oxide_tests.db.enc";

/// XOR key — must match tools/build_db.py DEFAULT_KEY
// ◆ XOR鍵 / XOR decryption key — matches build_db.py
const XOR_KEY: &[u8] = b"OXIDE::v7.9.1-elite::HyperSecurityOffensiveLabs";

// ◆ XOR復号 + テンポラリ書き出し / XOR decrypt → temp file
// ◆ 暗号化DBをXOR復号し、SQLite形式を検証 / decrypts & validates SQLite magic header
/// Decrypt an XOR-encrypted file to a temporary path and return the path.
/// The caller should clean up the temp file after use.
pub fn decrypt_to_temp(enc_path: &Path) -> Result<std::path::PathBuf> {
    let encrypted = std::fs::read(enc_path)
        .map_err(|e| anyhow!("Failed to read encrypted DB '{}': {}", enc_path.display(), e))?;

    let decrypted: Vec<u8> = encrypted.iter()
        .enumerate()
        .map(|(i, &b)| b ^ XOR_KEY[i % XOR_KEY.len()])
        .collect();

    // Verify it looks like a valid SQLite header
    if decrypted.len() < 16 || &decrypted[..16] != b"SQLite format 3\x00" {
        return Err(anyhow!("Decrypted data is not a valid SQLite database — wrong XOR key or corrupt file"));
    }

    let tmp = std::env::temp_dir().join(format!("oxide_tests_{}.db", std::process::id()));
    let mut f = std::fs::File::create(&tmp)?;
    f.write_all(&decrypted)?;
    f.sync_all()?;
    Ok(tmp)
}

// ※ SQLiteテストレコード読み込み / load all test records from SQLite DB
// ※ path, method, status, indicators, severity, category, title, desc, remediation, download_flag
/// Load all test records from the encrypted SQLite database.
/// Returns a Vec of (path, method, expected_status_str, content_indicators_str,
/// severity_str, category_str, title, description, remediation, download_flag).
pub fn load_all_rows(db_path: &Path) -> Result<Vec<(String, String, String, String, String, String, String, String, String, bool)>> {
    let conn = rusqlite::Connection::open(db_path)?;

    let mut stmt = conn.prepare(
        "SELECT path, method, expected_status, content_indicators,
                severity, category, title, description, remediation, download_flag
         FROM tests ORDER BY id"
    )?;

    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, String>(5)?,
            row.get::<_, String>(6)?,
            row.get::<_, String>(7)?,
            row.get::<_, String>(8)?,
            row.get::<_, i32>(9)? != 0,
        ))
    })?;

    let mut results = Vec::new();
    for row in rows {
        results.push(row?);
    }
    Ok(results)
}

// ● 便利関数: 復号 + 全行読み込み + 後片付け / convenience: decrypt + load + cleanup
/// Convenience: decrypt + load all rows in one call.
/// The temp file is cleaned up after loading.
pub fn decrypt_and_load(enc_path: &Path) -> Result<Vec<(String, String, String, String, String, String, String, String, String, bool)>> {
    let tmp = decrypt_to_temp(enc_path)?;
    let result = load_all_rows(&tmp);
    let _ = std::fs::remove_file(&tmp);
    result
}
