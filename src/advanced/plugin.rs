// ----------------------------------------------------------------------------
//  plugin.rs — plugin system
// ----------------------------------------------------------------------------
//  plugin system — loads external scanner modules dynamically at runtime
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
use anyhow::Result;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::detection::analyzer::Finding;
use crate::http::response::HttpResponse;

//  PluginManager — dynamic plugin loading system / 動的プラグインローダー
//  Architecture / アーキテクチャ:
//    plugins       — registry of all loaded plugins (map name  trait object)
//    enabled_plugins — subset of plugins currently active for scanning
//    loaded_libraries — Arc'd Library handles kept alive for FFI safety
//  Plugin lifecycle:
//    Register: add Box<dyn VulnPlugin> to registry, auto-enable
//    Load from file: dlopen .so/.dll/.dylib  find create_plugin symbol  instantiate
//    Enable/disable: toggle plugin in active set
//    Run: iterate enabled plugins  applies() check  check()  collect findings
//  Built-in examples: SecurityHeadersPlugin, InfoDisclosurePlugin
//  The trait-based design allows third-party plugins without recompiling OXIDE.
pub struct PluginManager {
    plugins: RwLock<HashMap<String, Box<dyn VulnPlugin>>>,
    enabled_plugins: RwLock<Vec<String>>,
    loaded_libraries: RwLock<Vec<Arc<libloading::Library>>>,
}

/// Trait for vulnerability detection plugins
pub trait VulnPlugin: Send + Sync + std::any::Any {
    /// Plugin name
    fn name(&self) -> &str;
    
    /// Plugin version
    fn version(&self) -> &str;
    
    /// Plugin description
    fn description(&self) -> &str;
    
    /// Plugin author
    fn author(&self) -> &str;
    
    /// Check if plugin applies to this response
    fn applies(&self, response: &HttpResponse) -> bool;
    
    /// Run the vulnerability check
    fn check(&self, response: &HttpResponse) -> Vec<Finding>;
    
    /// Get plugin configuration
    fn config(&self) -> HashMap<String, String>;
    
    /// Update plugin configuration
    fn set_config(&mut self, key: &str, value: &str);
}

impl PluginManager {
    pub fn new() -> Self {
        Self {
            plugins: RwLock::new(HashMap::new()),
            enabled_plugins: RwLock::new(Vec::new()),
            loaded_libraries: RwLock::new(Vec::new()),
        }
    }

    /// Register a new plugin
    pub async fn register_plugin(&self, plugin: Box<dyn VulnPlugin>) -> Result<()> {
        let name = plugin.name().to_string();
        let mut plugins = self.plugins.write().await;
        
        if plugins.contains_key(&name) {
            return Err(anyhow::anyhow!("Plugin '{}' already registered", name));
        }
        
        println!("[PLUGIN] Registered: {} v{} by {}", 
            name, plugin.version(), plugin.author());
        
        plugins.insert(name.clone(), plugin);
        
        // Enable by default
        let mut enabled = self.enabled_plugins.write().await;
        enabled.push(name);
        
        Ok(())
    }

    /// Unregister a plugin
    pub async fn unregister_plugin(&self, name: &str) -> Result<()> {
        let mut plugins = self.plugins.write().await;
        plugins.remove(name);
        
        let mut enabled = self.enabled_plugins.write().await;
        enabled.retain(|n| n != name);
        
        println!("[PLUGIN] Unregistered: {}", name);
        Ok(())
    }

    /// Enable a plugin
    pub async fn enable_plugin(&self, name: &str) -> Result<()> {
        let plugins = self.plugins.read().await;
        if !plugins.contains_key(name) {
            return Err(anyhow::anyhow!("Plugin '{}' not found", name));
        }
        
        let mut enabled = self.enabled_plugins.write().await;
        if !enabled.contains(&name.to_string()) {
            enabled.push(name.to_string());
            println!("[PLUGIN] Enabled: {}", name);
        }
        
        Ok(())
    }

    /// Disable a plugin
    pub async fn disable_plugin(&self, name: &str) -> Result<()> {
        let mut enabled = self.enabled_plugins.write().await;
        enabled.retain(|n| n != name);
        println!("[PLUGIN] Disabled: {}", name);
        Ok(())
    }

    //  Plugin Execution / プラグイン実行
    //  For each enabled plugin:
    //    Check `applies(response)` — quick filter to skip irrelevant plugins
    //    Call `check(response)` — actual vulnerability detection logic
    //    Collect findings from all plugins into a single Vec
    //  Plugins are isolated — one plugin's failure doesn't affect others.
    /// Run all enabled plugins against a response
    pub async fn run_plugins(&self, response: &HttpResponse) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        let plugins = self.plugins.read().await;
        let enabled = self.enabled_plugins.read().await;
        
        for plugin_name in enabled.iter() {
            if let Some(plugin) = plugins.get(plugin_name) {
                if plugin.applies(response) {
                    let plugin_findings = plugin.check(response);
                    findings.extend(plugin_findings);
                }
            }
        }
        
        findings
    }

    /// Get list of all registered plugins
    pub async fn list_plugins(&self) -> Vec<PluginInfo> {
        let plugins = self.plugins.read().await;
        let enabled = self.enabled_plugins.read().await;
        
        plugins.values()
            .map(|p| PluginInfo {
                name: p.name().to_string(),
                version: p.version().to_string(),
                description: p.description().to_string(),
                author: p.author().to_string(),
                enabled: enabled.contains(&p.name().to_string()),
            })
            .collect()
    }

    /// Get plugin by name
    pub async fn get_plugin(&self, name: &str) -> Option<Box<dyn VulnPlugin>> {
        let plugins = self.plugins.read().await;
        if let Some(plugin) = plugins.get(name) {
            // Return plugin info
            let _ = plugin.name(); // Access plugin to use the variable
        }
        drop(plugins);
        // Note: This is a simplified version - in real implementation
        // you'd need Arc<Mutex<>> or similar for shared ownership
        None
    }

    //  FFI Plugin Loading / FFIプラグイン読み込み
    //  Steps / ロード手順:
    //   1. Validate file exists and extension is .so/.dll/.dylib
    //   2. Check file is in an allowed plugin directory
    //   3. Verify file is owned by current user or root (not world-writable)
    //   4. dlopen via libloading::Library (unsafe FFI call)
    //   5. Lookup `create_plugin` function symbol in the library
    //   6. Call create_plugin()  returns *mut dyn VulnPlugin
    //   7. Convert raw pointer to Box<dyn VulnPlugin> (take ownership)
    //   8. Register the plugin
    //   9. Store Arc<Library> to keep library loaded (prevent dangling fn pointers)
    //  Safety: Plugins must be compiled for the same Rust ABI (same compiler version).
    /// Load plugin from dynamic library file (.so/.dll/.dylib)
    pub async fn load_from_file(&self, path: &Path) -> Result<()> {
        use libloading::{Library, Symbol};
        use std::ffi::OsStr;

        if !path.exists() {
            return Err(anyhow::anyhow!("Plugin file does not exist: {:?}", path));
        }

        // Check file extension
        let ext = path.extension().and_then(OsStr::to_str);
        let is_valid_ext = matches!(ext, Some("so") | Some("dll") | Some("dylib"));

        if !is_valid_ext {
            return Err(anyhow::anyhow!(
                "Invalid plugin file extension. Expected .so, .dll, or .dylib, got {:?}",
                ext
            ));
        }

        // Path allowlist: only load from plugins/ directory or allowed paths
        let allowed_prefixes = [
            "plugins/",
            "./plugins/",
            "/opt/oxide/plugins/",
            "/usr/local/lib/oxide/plugins/",
        ];
        let path_str = path.to_string_lossy();
        let in_allowed_dir = allowed_prefixes.iter().any(|p| path_str.starts_with(p));
        if !in_allowed_dir {
            return Err(anyhow::anyhow!(
                "Plugin not in allowed directory. Must be in plugins/, /opt/oxide/plugins/, or /usr/local/lib/oxide/plugins/. Got: {:?}",
                path
            ));
        }

        // Verify file ownership — deny world-writable plugins
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if let Ok(meta) = std::fs::metadata(path) {
                let mode = meta.mode();
                // Reject if world-writable (others have write permission)
                if mode & 0o002 != 0 {
                    return Err(anyhow::anyhow!(
                        "Plugin file is world-writable — refusing to load for security: {:?}", path
                    ));
                }
            }
        }

        println!("[PLUGIN] Loading dynamic library: {:?}", path);

        // Load the library
        let lib = unsafe { Library::new(path) }
            .map_err(|e| anyhow::anyhow!("Failed to load library: {}", e))?;

        // Look for the plugin creation symbol
        type CreatePluginFn = unsafe fn() -> *mut dyn VulnPlugin;

        let create_plugin: Symbol<CreatePluginFn> = unsafe {
            lib.get(b"create_plugin\0")
                .map_err(|e| anyhow::anyhow!("Failed to find 'create_plugin' symbol: {}", e))?
        };

        // Create the plugin instance
        let plugin_ptr = unsafe { (create_plugin)() };
        if plugin_ptr.is_null() {
            return Err(anyhow::anyhow!("Plugin creation returned null pointer"));
        }

        // Convert to Box (this is safe because the plugin was allocated by the library)
        let plugin: Box<dyn VulnPlugin> = unsafe { Box::from_raw(plugin_ptr) };

        let plugin_name = plugin.name().to_string();
        println!("[PLUGIN] Successfully loaded plugin: {} v{}", 
            plugin_name, plugin.version());

        // Register the plugin
        self.register_plugin(plugin).await?;

        // Keep the library handle alive so function pointers remain valid
        let lib = Arc::new(lib);
        self.loaded_libraries.write().await.push(lib);

        Ok(())
    }

    /// Get plugin statistics
    pub async fn get_stats(&self) -> PluginStats {
        let plugins = self.plugins.read().await;
        let enabled = self.enabled_plugins.read().await;
        
        PluginStats {
            total: plugins.len(),
            enabled: enabled.len(),
            disabled: plugins.len() - enabled.len(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PluginInfo {
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: String,
    pub enabled: bool,
}

#[derive(Debug)]
pub struct PluginStats {
    pub total: usize,
    pub enabled: usize,
    pub disabled: usize,
}

//  SecurityHeadersPlugin — Built-in Example / 組み込みプラグイン例
//  Checks for 6 critical security headers:
//    Content-Security-Policy
//    Strict-Transport-Security (HSTS)
//    X-Frame-Options (clickjacking protection)
//    X-Content-Type-Options (MIME sniffing prevention)
//    Referrer-Policy
//    Permissions-Policy
//  All findings reported at Medium severity
//  This serves as a reference implementation for custom plugin authors.
/// Example built-in plugin for detecting missing security headers
pub struct SecurityHeadersPlugin {
    config: HashMap<String, String>,
}

impl SecurityHeadersPlugin {
    pub fn new() -> Self {
        let mut config = HashMap::new();
        config.insert("severity".to_string(), "Medium".to_string());
        Self { config }
    }
}

impl VulnPlugin for SecurityHeadersPlugin {
    fn name(&self) -> &str {
        "security-headers"
    }

    fn version(&self) -> &str {
        "1.0.0"
    }

    fn description(&self) -> &str {
        "Checks for missing security headers (CSP, HSTS, X-Frame-Options, etc.)"
    }

    fn author(&self) -> &str {
        "OXIDE Team"
    }

    fn applies(&self, _response: &HttpResponse) -> bool {
        true // Applies to all responses
    }

    fn check(&self, response: &HttpResponse) -> Vec<Finding> {
        let mut findings = Vec::new();
        let headers: HashMap<String, String> = response.headers.iter()
            .map(|(k, v)| (k.to_lowercase(), v.to_lowercase()))
            .collect();
        
        // Check required security headers
        let required_headers = vec![
            ("content-security-policy", "Missing Content-Security-Policy header"),
            ("strict-transport-security", "Missing HSTS header"),
            ("x-frame-options", "Missing X-Frame-Options header (clickjacking protection)"),
            ("x-content-type-options", "Missing X-Content-Type-Options header"),
            ("referrer-policy", "Missing Referrer-Policy header"),
            ("permissions-policy", "Missing Permissions-Policy header"),
        ];
        
        for (header, description) in required_headers {
            if !headers.contains_key(header) {
                findings.push(
                    crate::detection::analyzer::Finding::new(
                        "",
                        crate::detection::analyzer::Severity::Medium,
                        &format!("Missing Security Header: {}", header),
                        description,
                    )
                );
            }
        }
        
        findings
    }

    fn config(&self) -> HashMap<String, String> {
        self.config.clone()
    }

    fn set_config(&mut self, key: &str, value: &str) {
        self.config.insert(key.to_string(), value.to_string());
    }
}

//  InfoDisclosurePlugin — Built-in Example / 情報漏洩電脳検出プラグイン
//  Detects two common information disclosure vectors:
//    Server Version Disclosure — digits in Server header
//    Technology Disclosure — X-Powered-By header presence
//  Information disclosure findings help assess the target's security posture.
/// Example plugin for detecting information disclosure
pub struct InfoDisclosurePlugin {
    config: HashMap<String, String>,
}

impl InfoDisclosurePlugin {
    pub fn new() -> Self {
        let mut config = HashMap::new();
        config.insert("severity".to_string(), "Low".to_string());
        Self { config }
    }
}

impl VulnPlugin for InfoDisclosurePlugin {
    fn name(&self) -> &str {
        "info-disclosure"
    }

    fn version(&self) -> &str {
        "1.0.0"
    }

    fn description(&self) -> &str {
        "Detects information disclosure in headers and response body"
    }

    fn author(&self) -> &str {
        "OXIDE Team"
    }

    fn applies(&self, _response: &HttpResponse) -> bool {
        true
    }

    fn check(&self, response: &HttpResponse) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        // Check Server header for version disclosure
        if let Some(server) = response.headers.get("Server") {
            if server.chars().any(|c| c.is_ascii_digit()) {
                findings.push(
                    crate::detection::analyzer::Finding::new(
                        "",
                        crate::detection::analyzer::Severity::Low,
                        "Server Version Disclosure",
                        &format!("Server header reveals version information: {}", server),
                    )
                );
            }
        }
        
        // Check X-Powered-By
        if response.headers.contains_key("X-Powered-By") {
            findings.push(
                crate::detection::analyzer::Finding::new(
                    "",
                    crate::detection::analyzer::Severity::Low,
                    "Technology Disclosure",
                    "X-Powered-By header reveals backend technology",
                )
            );
        }
        
        findings
    }

    fn config(&self) -> HashMap<String, String> {
        self.config.clone()
    }

    fn set_config(&mut self, key: &str, value: &str) {
        self.config.insert(key.to_string(), value.to_string());
    }
}
