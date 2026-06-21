// ----------------------------------------------------------------------------
//  signatures.rs — Signature database
// ----------------------------------------------------------------------------
//  Signature database — maps vulnerability patterns to detection signatures.
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
// ◆ signatures.rs — シグネチャデータベース
// ★ Signature database — maps vulnerability IDs to detection patterns
// ■ HashMap<String, VulnSignature> で管理、IDによる高速検索を実現

use std::collections::HashMap;

// ★ SignatureDatabase — シグネチャデータベース
// ★ Centralized signature store — maps IDs to vulnerability signatures
pub struct SignatureDatabase {
    signatures: HashMap<String, VulnSignature>,
}

// ◆ VulnSignature — 脆弱性シグネチャの完全な定義
// ◆ Complete vulnerability signature definition
// ■ id          — 一意識別子 (例: OXIDE-001)
// ■ name        — 発見名
// ■ severity    — 重大度 (文字列)
// ■ pattern     — 電脳検出パターン (部分一致)
// ■ description — 説明
// ■ remediation — 修正方法
#[derive(Clone, Debug)]
pub struct VulnSignature {
    pub id: String,
    pub name: String,
    pub severity: String,
    pub pattern: String,
    pub description: String,
    pub remediation: String,
}

// ■ シグネチャデータベースの実装
// ■ Signature database implementation
impl SignatureDatabase {
    // ◆ new — 空のデータベースを作成し、デフォルトシグネチャをロード
    pub fn new() -> Self {
        let mut db = Self {
            signatures: HashMap::new(),
        };
        
        db.load_default_signatures();
        db
    }

    // ■ load_default_signatures — ビルトインシグネチャ (WordPress, Drupal) をロード
    fn load_default_signatures(&mut self) {
        let sigs = vec![
            VulnSignature {
                id: "OXIDE-001".to_string(),
                name: "WordPress Detected".to_string(),
                severity: "Info".to_string(),
                pattern: r"\bwp-content\b|\bwordpress\b".to_string(),
                description: "WordPress installation detected".to_string(),
                remediation: "Ensure WordPress is kept updated".to_string(),
            },
            VulnSignature {
                id: "OXIDE-002".to_string(),
                name: "Drupal CMS Detected".to_string(),
                severity: "Info".to_string(),
                pattern: r"\bdrupal\b|\bDrupal\b".to_string(),
                description: "Drupal CMS detected".to_string(),
                remediation: "Ensure Drupal is kept updated".to_string(),
            },
        ];

        for sig in sigs {
            self.signatures.insert(sig.id.clone(), sig);
        }
    }

    // ● all — 全シグネチャへの参照を取得
    // ● Returns reference to all signatures
    pub fn all(&self) -> &HashMap<String, VulnSignature> {
        &self.signatures
    }

    // ▲ add — 新しいシグネチャを追加
    // ▲ Adds a new signature to the database
    pub fn add(&mut self, sig: VulnSignature) {
        self.signatures.insert(sig.id.clone(), sig);
    }
}

impl Default for SignatureDatabase {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for SignatureDatabase {
    fn clone(&self) -> Self {
        Self {
            signatures: self.signatures.clone(),
        }
    }
}
