// ----------------------------------------------------------------------------
//  crawler_js.rs — JavaScript-aware crawler
// ----------------------------------------------------------------------------
//  JavaScript-aware crawler — extracts URLs from JS, evaluates dynamic content
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
use regex::Regex;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::Mutex;
use url::Url;

// ◆ JsCrawler — JavaScript-aware web crawler / JS対応クローラ
// ■ Purpose: extract URLs and API endpoints from dynamic JS content
// ■ Three tracking sets / 3つの追跡セット:
//   ★ discovered_urls  — all URLs found in JS/HTML
//   ★ js_resources     — JS file URLs for further processing
//   ★ api_endpoints    — REST/GraphQL endpoints discovered
// ■ Extraction patterns / 抽出パターン:
//   ★ fetch/XHR calls, Axios, jQuery AJAX
//   ★ Router configs (React, Vue, Angular)
//   ★ Dynamic imports (import())
//   ★ GraphQL endpoints and WebSocket URLs
//   ★ Initial state data (window.__INITIAL_STATE__)
// ■ SPA framework detection → route generation based on framework conventions
// ➤ The crawler handles relative URL resolution, protocol-relative URLs,
//   and proper ../ normalization via url::Url::join.
pub struct JsCrawler {
    discovered_urls: Arc<Mutex<HashSet<String>>>,
    js_resources: Arc<Mutex<HashSet<String>>>,
    api_endpoints: Arc<Mutex<HashSet<String>>>,
    max_depth: usize,
}

impl JsCrawler {
    pub fn new(max_depth: usize) -> Self {
        Self {
            discovered_urls: Arc::new(Mutex::new(HashSet::new())),
            js_resources: Arc::new(Mutex::new(HashSet::new())),
            api_endpoints: Arc::new(Mutex::new(HashSet::new())),
            max_depth,
        }
    }

    // ◆ JS URL Extraction / JSからのURL抽出フロー
    // ■ Depth-gated extraction — stops if discovered URLs exceed max_depth × 100
    // ■ Pattern categories / パターンカテゴリ:
    //   1. Network requests: fetch(), axios.{$method}(), $.ajax(), XMLHttpRequest
    //   2. Router paths: path:, route:, when(), @Route decorators
    //   3. Dynamic imports: import('...')
    //   4. GraphQL: /graphql, /api/gql, /query markers in JS
    //   5. WebSocket: new WebSocket(...), ws:// or wss://
    // ➤ All relative URLs resolved to absolute via resolve_url()
    /// Extract URLs from JavaScript content with depth tracking
    pub async fn extract_js_urls(&self, js_content: &str, base_url: &str) -> Vec<String> {
        let mut urls = Vec::new();
        
        // Check depth limit
        let current_count = self.discovered_urls.lock().await.len();
        if current_count >= self.max_depth * 100 {
            return urls; // Stop if we've reached approximate limit
        }
        
        // Pattern 1: Fetch/XHR calls
        let fetch_patterns = vec![
            r#"fetch\(["']([^"']+)["']"#,
            r#"axios\.(?:get|post|put|delete)\(["']([^"']+)["']"#,
            r#"\$\.(?:get|post|ajax)\s*\(\s*["']([^"']+)["']"#,
            r#"XMLHttpRequest.*open.*["']([^"']+)["']"#,
        ];
        
        for pattern in &fetch_patterns {
            let Ok(regex) = Regex::new(pattern) else { continue; };
            for cap in regex.captures_iter(js_content) {
                if let Some(matched) = cap.get(1) {
                    let url = matched.as_str();
                    if let Some(absolute) = self.resolve_url(url, base_url) {
                        urls.push(absolute);
                    }
                }
            }
        }
        
        // Pattern 2: Router configurations (React, Vue, Angular)
        let router_patterns = vec![
            r#"path\s*:\s*["']([^"']+)["']"#,           // React Router, Vue Router
            r#"route\s*:\s*["']([^"']+)["']"#,          // Generic routes
            r#"when\s*\(\s*["']([^"']+)["']"#,          // Angular
            r#"@Route\s*\(\s*["']([^"']+)["']"#,        // Decorators
        ];
        
        for pattern in &router_patterns {
            let Ok(regex) = Regex::new(pattern) else { continue; };
            for cap in regex.captures_iter(js_content) {
                if let Some(matched) = cap.get(1) {
                    let route = matched.as_str();
                    let full_url = format!("{}{}", base_url.trim_end_matches('/'), route);
                    urls.push(full_url);
                }
            }
        }
        
        // Pattern 3: Dynamic imports
        let import_pattern = r#"import\s*\(\s*["']([^"']+)["']"#;
        let Ok(regex) = Regex::new(import_pattern) else { return urls; };
        for cap in regex.captures_iter(js_content) {
            if let Some(matched) = cap.get(1) {
                let url = matched.as_str();
                if let Some(absolute) = self.resolve_url(url, base_url) {
                    urls.push(absolute);
                }
            }
        }
        
        // Pattern 4: GraphQL endpoints
        if js_content.contains("graphql") || js_content.contains("gql`") || js_content.contains("'gql") {
            let gql_patterns = vec![
                r#"/graphql"#,
                r#"/api/gql"#,
                r#"/query"#,
            ];
            for pattern in &gql_patterns {
                if js_content.contains(pattern) {
                    let gql_url = format!("{}{}", base_url.trim_end_matches('/'), pattern);
                    let mut api_endpoints = self.api_endpoints.lock().await;
                    api_endpoints.insert(gql_url.clone());
                    urls.push(gql_url);
                    drop(api_endpoints);
                }
            }
        }
        
        // Pattern 5: WebSocket endpoints
        let ws_patterns = vec![
            r#"new\s+WebSocket\s*\(\s*["']([^"']+)["']"#,
            r#"ws[s]?://([^"'\s]+)"#,
        ];
        for pattern in &ws_patterns {
            let Ok(regex) = Regex::new(pattern) else { continue; };
            for cap in regex.captures_iter(js_content) {
                if let Some(matched) = cap.get(1) {
                    urls.push(matched.as_str().to_string());
                }
            }
        }
        
        // Add to discovered set
        let mut discovered = self.discovered_urls.lock().await;
        for url in &urls {
            discovered.insert(url.clone());
        }
        
        urls
    }

    // ◆ API Endpoint Extraction / APIエンドポイント抽出
    // ■ Regex patterns targeting API URL conventions:
    //   ★ /api/v{digit}/..., /rest/..., /v{digit}/..., /services/...
    //   ★ Extracts raw path strings from JS content
    //   ★ Deduplicates via api_endpoints HashSet
    // ➤ These endpoints become targets for the api_fuzzer module.
    /// Extract API endpoints from JavaScript
    pub async fn extract_api_endpoints(&self, js_content: &str) -> Vec<String> {
        let mut endpoints = Vec::new();
        
        // REST API patterns
        let api_patterns = vec![
            r#"/api/v\d+/[^"'\s]+"#,
            r#"/rest/[^"'\s]+"#,
            r#"/v\d+/[^"'\s]+"#,
            r#"/services/[^"'\s]+"#,
            r#"/endpoint[s]?/[^"'\s]+"#,
        ];
        
        for pattern in &api_patterns {
            let Ok(regex) = Regex::new(pattern) else { continue; };
            for mat in regex.find_iter(js_content) {
                endpoints.push(mat.as_str().to_string());
            }
        }
        
        // Store in set
        let mut api_set = self.api_endpoints.lock().await;
        for endpoint in &endpoints {
            api_set.insert(endpoint.clone());
        }
        
        endpoints
    }

    // ◆ JS Resource Extraction / JSリソース抽出
    // ■ Two extraction passes on HTML:
    //   ★ <script src="..."> — standard script tag references
    //   ★ <script type="module">...import from "..." — ES module imports
    //   ★ All URLs resolved to absolute
    // ➤ Extracted JS URLs are fetched and scanned recursively.
    /// Extract JavaScript resource URLs from HTML
    pub async fn extract_js_resources(&self, html: &str, base_url: &str) -> Vec<String> {
        let mut resources = Vec::new();
        
        // Script src attributes
        let script_pattern = r#"<script[^>]+src=["']([^"']+)["']"#;
        let Ok(regex) = Regex::new(script_pattern) else { return resources; };
        for cap in regex.captures_iter(html) {
            if let Some(matched) = cap.get(1) {
                let url = matched.as_str();
                if let Some(absolute) = self.resolve_url(url, base_url) {
                    resources.push(absolute);
                }
            }
        }
        
        // Module imports
        let module_pattern = r#"<script[^>]+type=["']module["'][^>]*>.*?import.*?from\s*["']([^"']+)["']"#;
        let Ok(regex) = Regex::new(module_pattern) else { return resources; };
        for cap in regex.captures_iter(html) {
            if let Some(matched) = cap.get(1) {
                let url = matched.as_str();
                if let Some(absolute) = self.resolve_url(url, base_url) {
                    resources.push(absolute);
                }
            }
        }
        
        // Store in set
        let mut js_set = self.js_resources.lock().await;
        for resource in &resources {
            js_set.insert(resource.clone());
        }
        
        resources
    }

    // ◆ SPA Routing Analysis / SPAルーティング分析
    // ■ Framework detection via DOM markers:
    //   ★ React   → __REACT_DEVTOOLS_GLOBAL_HOOK__, data-reactroot
    //   ★ Vue     → __VUE_DEVTOOLS_GLOBAL_HOOK__, __vue_app__, data-v-
    //   ★ Angular → ng-version, ng-app, ng-reflect
    //   ★ Svelte  → __svelte, svelte-
    // ■ Extracts initial state from window.__INITIAL_STATE__ etc.
    // ■ Generates common route paths based on detected framework
    // ➤ SPA apps hide routes from traditional crawlers; this recovers them.
    /// Analyze single-page application routing
    pub async fn analyze_spa_routing(&self, html: &str, base_url: &str) -> Vec<String> {
        let mut routes = Vec::new();
        
        // Detect framework using reliable markers (not just substring matches on names)
        let framework = if html.contains("__REACT_DEVTOOLS_GLOBAL_HOOK__")
            || html.contains("data-reactroot")
            || html.contains("_reactListening")
            || html.contains("React.") && html.contains("react-dom")
        {
            "react"
        } else if html.contains("__VUE_DEVTOOLS_GLOBAL_HOOK__")
            || html.contains("__vue_app__")
            || html.contains("data-v-")
            || html.contains("vue.createApp")
        {
            "vue"
        } else if html.contains("ng-version")
            || html.contains("ng-app")
            || html.contains("ng-reflect")
        {
            "angular"
        } else if html.contains("svelte") && (html.contains("__svelte") || html.contains("svelte-")) {
            "svelte"
        } else {
            "unknown"
        };
        
        if framework != "unknown" {
            println!("[JS_CRAWL] Detected SPA framework: {}", framework);
        }
        
        // Extract initial state/data
        let state_patterns = vec![
            r#"window\.__INITIAL_STATE__\s*=\s*(\{[^}]+\})"#,
            r#"window\.__DATA__\s*=\s*(\{[^}]+\})"#,
            r#"window\.__PRELOADED_STATE__\s*=\s*(\{[^}]+\})"#,
        ];
        
        for pattern in &state_patterns {
            let Ok(regex) = Regex::new(pattern) else { continue; };
            for cap in regex.captures_iter(html) {
                if let Some(state) = cap.get(1) {
                    // Parse JSON state for URLs
                    let state_str = state.as_str();
                    let Ok(url_pattern) = Regex::new(r#"["'](https?://[^"']+)["']"#) else { continue; };
                    for url_cap in url_pattern.captures_iter(state_str) {
                        if let Some(url) = url_cap.get(1) {
                            routes.push(url.as_str().to_string());
                        }
                    }
                }
            }
        }
        
        // Common SPA routes based on framework
        let common_routes = match framework {
            "react" => vec!["/", "/home", "/about", "/contact", "/dashboard", "/profile", "/settings"],
            "vue" => vec!["/", "/home", "/about", "/contact", "/dashboard", "/profile"],
            "angular" => vec!["/", "/home", "/about", "/contact", "/dashboard"],
            "svelte" => vec!["/", "/about", "/contact", "/dashboard"],
            _ => vec!["/", "/home", "/about", "/api"],
        };
        
        let base = base_url.trim_end_matches('/');
        for route in common_routes {
            routes.push(format!("{}{}", base, route));
        }
        
        routes
    }

    // ◆ GraphQL Operation Extraction / GraphQL操作抽出
    // ■ Detects named operations: query Name(...) { ... } and mutation Name(...) { ... }
    // ■ Balanced brace matching to extract full operation bodies
    //   (naive regex cannot handle nested braces — this uses a depth counter)
    // ■ Also detects Apollo Client gql`...` tagged template literals
    // ■ Categorizes as Query or Mutation based on keyword before the operation
    // ➤ Extracted operations feed into GraphQL fuzzing for introspection and injection.
    /// Find GraphQL operations in JavaScript
    pub async fn find_graphql_operations(&self, js_content: &str) -> Vec<GraphQLOperation> {
        let mut operations = Vec::new();
        
        // GraphQL query/mutation patterns — handles arguments and nested braces with balanced matching
        let gql_re = Regex::new(r#"(?:query|mutation)\s+(\w+)\s*(?:\([^)]*\))?\s*\{"#);
        let gql_re = match gql_re {
            Ok(r) => r,
            Err(_) => return operations,
        };
        
        for cap in gql_re.captures_iter(js_content) {
            let Some(name) = cap.get(1) else { continue };
            let start = match cap.get(0) {
                Some(m) => m.end(),
                None => continue,
            };
            let after = &js_content[start..];
            
            // Manually balance braces to handle nested selections
            let mut depth = 0u32;
            let mut body_end = 0;
            for (i, ch) in after.char_indices() {
                if ch == '{' { depth += 1; }
                else if ch == '}' {
                    if depth == 0 { body_end = i; break; }
                    depth -= 1;
                }
            }
            let body = if body_end > 0 { &after[..body_end] } else { continue };
            
            let match_start = cap.get(0).map_or(0, |m| m.start());
            let op_type = if js_content[..match_start].contains("mutation") {
                OperationType::Mutation
            } else {
                OperationType::Query
            };
            
            operations.push(GraphQLOperation {
                name: name.as_str().to_string(),
                operation_type: op_type,
                body: body.to_string(),
            });
        }
        
        // Apollo Client gql tag — with brace balancing
        let gql_tag_re = Regex::new(r#"gql`([^`]+)`"#);
        let gql_tag_re = match gql_tag_re {
            Ok(r) => r,
            Err(_) => return operations,
        };
        for gql_cap in gql_tag_re.captures_iter(js_content) {
            if let Some(gql_body) = gql_cap.get(1) {
                operations.push(GraphQLOperation {
                    name: "anonymous".to_string(),
                    operation_type: OperationType::Query,
                    body: gql_body.as_str().to_string(),
                });
            }
        }
        
        operations
    }

    /// Get all discovered URLs
    pub async fn get_discovered_urls(&self) -> Vec<String> {
        let urls = self.discovered_urls.lock().await;
        urls.iter().cloned().collect()
    }

    /// Get all JavaScript resources
    pub async fn get_js_resources(&self) -> Vec<String> {
        let resources = self.js_resources.lock().await;
        resources.iter().cloned().collect()
    }

    /// Get all API endpoints
    pub async fn get_api_endpoints(&self) -> Vec<String> {
        let endpoints = self.api_endpoints.lock().await;
        endpoints.iter().cloned().collect()
    }

    /// Clear all discovered data
    pub async fn clear(&self) {
        self.discovered_urls.lock().await.clear();
        self.js_resources.lock().await.clear();
        self.api_endpoints.lock().await.clear();
    }

    // ◆ URL Resolution / URL解決
    // ■ Handles three URL forms:
    //   ★ Protocol-relative: //example.com/path → inherit scheme from base
    //   ★ Already absolute: http(s)://... → return as-is
    //   ★ Relative: /path, ../path, ./path → join with base URL
    // ■ Uses url::Url::join for proper RFC 3986 resolution (handles ../, ./)
    // ➤ Correct resolution is critical — many JS URLs are relative.
    /// Resolve relative URL to absolute — uses proper URL join for correct
    /// `../` normalization and protocol-relative URL handling.
    fn resolve_url(&self, url: &str, base_url: &str) -> Option<String> {
        // Protocol-relative: //example.com/path
        if url.starts_with("//") {
            // Inherit scheme from base
            let scheme = base_url.split(':').next().unwrap_or("https");
            return Some(format!("{}:{}", scheme, url));
        }
        // Already absolute
        if url.starts_with("http://") || url.starts_with("https://") {
            return Some(url.to_string());
        }
        // Use url::Url::join for proper path resolution (handles ../, ./ etc.)
        let base = Url::parse(base_url).ok()?;
        base.join(url).ok().map(|u| u.to_string())
    }
}

#[derive(Debug, Clone)]
pub struct GraphQLOperation {
    pub name: String,
    pub operation_type: OperationType,
    pub body: String,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum OperationType {
    Query,
    Mutation,
    Subscription,
}
