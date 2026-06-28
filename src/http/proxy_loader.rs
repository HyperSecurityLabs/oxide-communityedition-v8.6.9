// ----------------------------------------------------------------------------
//  proxy_loader.rs — SOCKS/HTTP proxy loader
// ----------------------------------------------------------------------------
//  SOCKS/HTTP proxy loader — loads proxies from file or shared library.
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
//  proxy_loader.rs — SOCKS/HTTPプロキシローダー
//  Proxy library loader — loads external proxy library via FFI (libloading)
//  動的ライブラリを読み込みプロキシチェーンを構成

use libloading::{Library, Symbol};
use std::path::Path;
use std::sync::{Arc, OnceLock};

//  ProxyLoaderError — プロキシローダーのエラー型
//  Error types for proxy library loading
#[derive(Debug)]
pub enum ProxyLoaderError {
    NotFound(String),
    Invalid(String),
    SymbolMissing(String),
}

impl std::fmt::Display for ProxyLoaderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound(p) => write!(f, "proxy library not found: {}", p),
            Self::Invalid(p) => write!(f, "invalid proxy library: {}", p),
            Self::SymbolMissing(s) => write!(f, "missing symbol: {}", s),
        }
    }
}

//  ProxyLibrary — プロキシ動的ライブラリのラッパー
//  Wrapper around dynamically loaded proxy library (FFI)
//  libloading::Library を Arc でラップして共有
pub struct ProxyLibrary {
    _lib: Arc<Library>,
}

//  プラットフォーム依存のライブラリ名
//  Platform-specific library name
//  Windows: liboxide_proxy.dll
//  Linux/macOS: liboxide_proxy.so
const LIB_NAME: &str = if cfg!(target_os = "windows") {
    "liboxide_proxy.dll"
} else {
    "liboxide_proxy.so"
};

//  search_paths — ライブラリの検索パス一覧
//  Library search paths (binary directory, system paths)
fn search_paths() -> Vec<String> {
    let mut paths = Vec::new();
    // Next to binary
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            paths.push(dir.join(LIB_NAME).to_string_lossy().to_string());
        }
    }
    // Linux-specific system paths
    #[cfg(target_os = "linux")]
    {
        paths.push("/usr/lib/liboxide_proxy.so".into());
        paths.push("/usr/local/lib/liboxide_proxy.so".into());
        paths.push("/opt/oxide/lib/liboxide_proxy.so".into());
    }
    paths
}

//  find_library — 全検索パスからライブラリを探す
//  Searches all paths for the proxy library
//  バイナリ隣接  システムパス  LD_LIBRARY_PATH / PATH
fn find_library() -> Option<String> {
    // Search next to the binary first (common on all platforms)
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let path = dir.join(LIB_NAME);
            if path.exists() {
                return Some(path.to_string_lossy().to_string());
            }
        }
    }
    for path in search_paths() {
        if Path::new(&path).exists() {
            return Some(path);
        }
    }
    None
}

//  プロキシライブラリのロード実装
//  Proxy library loading implementation
impl ProxyLibrary {
    //  load — 動的ライブラリをロードし必須シンボルを検証
    //  Loads library and validates required symbols (proxy_ping)
    pub fn load() -> Result<Self, ProxyLoaderError> {
        let path = find_library()
            .ok_or_else(|| ProxyLoaderError::NotFound(
                format!("{} not found in search paths", LIB_NAME).into()
            ))?;

        let lib = unsafe {
            Library::new(&path)
                .map_err(|e| ProxyLoaderError::Invalid(format!("{}: {}", path, e)))?
        };

        let symbols = [
            "proxy_ping",
        ];

        for sym in &symbols {
            unsafe {
                lib.get::<unsafe extern "C" fn()>(sym.as_bytes())
                    .map_err(|_| ProxyLoaderError::SymbolMissing(sym.to_string()))?;
            }
        }

        Ok(Self { _lib: Arc::new(lib) })
    }
}

//  Global proxy library (loaded once at startup) 

//  PROXY_LIB — グローバルプロキシライブラリ (起動時に1度だけロード)
//  Global proxy library singleton — loaded once at startup
static PROXY_LIB: OnceLock<Arc<Library>> = OnceLock::new();

//  ensure_proxy_library — プロキシライブラリを起動時に初期化
//  Ensures proxy library is loaded at startup
//  proxy_ping シンボルを呼び出してバージョンを表示
pub fn ensure_proxy_library() -> Result<(), ProxyLoaderError> {
    let proxy = ProxyLibrary::load()?;
    let lib = proxy._lib.clone();
    let _ = PROXY_LIB.set(lib);
    if let Some(l) = PROXY_LIB.get() {
        let func: Result<Symbol<unsafe extern "C" fn() -> u32>, _> =
            unsafe { l.get(b"proxy_ping") };
        match func {
            Ok(f) => {
                let v = unsafe { f() };
                eprintln!("[+] Proxy library loaded: oxide-proxy/{}", v);
            }
            Err(_) => {
                eprintln!("[!] Proxy library loaded but missing 'proxy_ping' symbol — version unknown");
            }
        }
    }
    Ok(())
}


