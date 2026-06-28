// ----------------------------------------------------------------------------
//  mutator.rs — payload mutator
// ----------------------------------------------------------------------------
//  Payload mutator — applies transformations to existing payloads (case, encoding, padding).
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

//  Mutator: ペイロードミューテータ
//  Applies transformations to base payloads for evasion and coverage.
//  ミューテーション戦略:
//   ➊ mutate_path — 大文字小文字変換URLエンコード../追加
//   ➋ mutate_param — パラメータ値のエンコードNullバイトCRLF注入
//   ➌ mutate_header — ヘッダー値のバリエーション生成
//  各ミューテーションは元のペイロードを含めて返す
pub struct Mutator;

impl Mutator {
    pub fn new() -> Self {
        Self
    }

    //  mutate_path: パスのミューテーション
    //  Generates path traversal variations — case changes, URL encoding, dot-dot sequences.
    //  変換: UPPER/lower, %2f/%252f URLエンコード, ../, %2e%2e
    pub fn mutate_path(&self, path: &str) -> Vec<String> {
        let mut mutations = vec![];
        
        mutations.push(path.to_string());
        mutations.push(path.to_uppercase());
        mutations.push(path.to_lowercase());
        mutations.push(path.replace("/", "%2f"));
        mutations.push(path.replace("/", "%252f"));
        mutations.push(format!("{}/", path));
        mutations.push(format!("{}/.", path));
        mutations.push(format!("{}/..", path));
        mutations.push(format!("{}/../", path));
        mutations.push(format!("{}/%2e%2e/", path));
        
        mutations
    }

    //  mutate_param: パラメータのミューテーション
    //  Generates parameter injection variations — encoding, null byte, CRLF, XSS/SQLi probes.
    //  変換: URLエンコード, 二重エンコード, Nullバイト(%00), CRLF(%0d%0a)
    //   $B$^$?$OG$0$U$j$K(BXSS <script>alert(1)</script> や SQLi ' OR '1'='1 を挿入
    pub fn mutate_param(&self, param: &str) -> Vec<String> {
        let mut mutations = vec![];
        
        mutations.push(param.to_string());
        
        if param.contains('=') {
            let parts: Vec<&str> = param.splitn(2, '=').collect();
            if parts.len() == 2 {
                let key = parts[0];
                let value = parts[1];
                
                mutations.push(format!("{}={}", key, urlencoding::encode(value)));
                mutations.push(format!("{}={}", key, Self::double_encode(value)));
                mutations.push(format!("{}={}%00", key, value));
                mutations.push(format!("{}={}%0d%0a", key, value));
                mutations.push(format!("{}[]={}", key, value));
                mutations.push(format!("{}[0]={}", key, value));
                mutations.push(format!("{}=<script>alert(1)</script>", key));
                mutations.push(format!("{}=' OR '1'='1", key));
                mutations.push(format!("{}=1 AND 1=1", key));
                mutations.push(format!("{}=../../../../etc/passwd", key));
            }
        }
        
        mutations
    }

    //  mutate_header: ヘッダーのミューテーション
    //  Generates HTTP header variations — IP obfuscation, port append, CRLF injection.
    //  変換: [.]ドット置換, .local追加, :80/:443ポート追加, %0d%0aインジェクション
    pub fn mutate_header(&self, header: &str) -> Vec<String> {
        let mut mutations = vec![];
        
        mutations.push(header.to_string());
        
        if header.contains(':') {
            let parts: Vec<&str> = header.splitn(2, ':').collect();
            if parts.len() == 2 {
                let key = parts[0];
                let value = parts[1].trim();
                
                mutations.push(format!("{}: {}", key, value));
                mutations.push(format!("{}: {}", key, value.replace(".", "[.]")));
                mutations.push(format!("{}: {}.local", key, value));
                mutations.push(format!("{}: {}:80", key, value));
                mutations.push(format!("{}: {}:443", key, value));
                mutations.push(format!("{}: null.{}", key, value));
                mutations.push(format!("{}: {}%0d%0a", key, value));
            }
        }
        
        mutations
    }

    fn double_encode(input: &str) -> String {
        urlencoding::encode(&urlencoding::encode(input)).to_string()
    }
}

impl Clone for Mutator {
    fn clone(&self) -> Self {
        Self
    }
}
