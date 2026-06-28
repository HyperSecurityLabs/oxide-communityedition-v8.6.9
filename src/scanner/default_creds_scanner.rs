// ----------------------------------------------------------------------------
//  default_creds_scanner.rs — default credentials scanner
// ----------------------------------------------------------------------------
//  Tests for factory-default credentials on common web applications, middleware,
//  databases, and devices (Tomcat, Jenkins, WordPress, phpMyAdmin, Grafana,
//  Elasticsearch, Docker, Kubernetes, and more). Uses Basic, Form, Bearer,
//  and Digest authentication methods with success/failure indicators.
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
use reqwest::Client;
use std::collections::HashMap;
use tokio::time::Duration;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use zeroize::{Zeroize, ZeroizeOnDrop};

//  認証方式と電脳検出手法 / auth methods & detection:
//   Tests 40+ applications with default credential combinations using 5 auth methods:
//    Basic   — Base64-encoded "username:password" in Authorization header
//    Form    — POST with configurable username/password field names
//    Bearer  — Token-based authorization header
//    Digest  — MD5 challenge-response (placeholder)
//    API Key — Custom header (e.g., X-API-Key)
//    Detection: success_indicator must match AND failure_indicator must be absent
//    Rate limiting protection: 500ms delay between attempts
//   Applications covered: Tomcat, Jenkins, WordPress, phpMyAdmin, Grafana,
//   Elasticsearch, Kibana, MongoDB, Redis, RabbitMQ, Docker, Kubernetes,
//   cPanel, Plesk, Webmin, SonarQube, JBoss, WebLogic, Splunk, Nextcloud,
//   Drupal, Nagios, Zabbix, Cacti, Prometheus, Cisco
/// Default Credentials Scanner
/// Tests for factory default passwords on common applications, devices, and services
/// Similar to Nikto's dbcheck but with modern applications
pub struct DefaultCredsScanner {
    client: Client,
    timeout: Duration,
    creds_db: Vec<CredentialEntry>,
}

#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
struct CredentialEntry {
    #[zeroize(skip)]
    application: String,
    #[zeroize(skip)]
    path: String,
    username: String,
    password: String,
    #[zeroize(skip)]
    auth_method: AuthMethod,
    #[zeroize(skip)]
    success_indicator: Vec<String>,
    #[zeroize(skip)]
    failure_indicator: Vec<String>,
}

#[derive(Clone, Debug)]
pub enum AuthMethod {
    Basic,
    Form { username_field: String, password_field: String },
    Bearer,
    ApiKey { header_name: String },
    Digest,
}

#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct CredsFinding {
    #[zeroize(skip)]
    pub severity: CredsSeverity,
    #[zeroize(skip)]
    pub application: String,
    #[zeroize(skip)]
    pub url: String,
    pub username: String,
    pub password: String,
    #[zeroize(skip)]
    pub evidence: String,
    #[zeroize(skip)]
    pub remediation: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CredsSeverity {
    Critical,
    High,
    Medium,
}

impl DefaultCredsScanner {
    pub fn new(timeout_secs: u64) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .cookie_store(true)
            .build()?;
        
        let mut scanner = Self {
            client,
            timeout: Duration::from_secs(timeout_secs),
            creds_db: Vec::new(),
        };
        
        scanner.load_creds_database();
        
        Ok(scanner)
    }
    
    /// Get the configured timeout duration
    pub fn get_timeout(&self) -> Duration {
        self.timeout
    }
    
    /// Load comprehensive default credentials database
    fn load_creds_database(&mut self) {
        // Web Servers & Middleware
        self.add_entry(CredentialEntry {
            application: "Apache Tomcat".to_string(),
            path: "/manager/html".to_string(),
            username: "tomcat".to_string(),
            password: "tomcat".to_string(),
            auth_method: AuthMethod::Basic,
            success_indicator: vec!["Tomcat Web Application Manager".to_string(), "Manager".to_string()],
            failure_indicator: vec!["401".to_string(), "Unauthorized".to_string()],
        });
        
        self.add_entry(CredentialEntry {
            application: "Apache Tomcat".to_string(),
            path: "/manager/html".to_string(),
            username: "admin".to_string(),
            password: "admin".to_string(),
            auth_method: AuthMethod::Basic,
            success_indicator: vec!["Tomcat Web Application Manager".to_string()],
            failure_indicator: vec!["401".to_string()],
        });
        
        self.add_entry(CredentialEntry {
            application: "Apache Tomcat".to_string(),
            path: "/host-manager/html".to_string(),
            username: "tomcat".to_string(),
            password: "tomcat".to_string(),
            auth_method: AuthMethod::Basic,
            success_indicator: vec!["Host Manager".to_string()],
            failure_indicator: vec!["401".to_string()],
        });
        
        // Jenkins
        self.add_entry(CredentialEntry {
            application: "Jenkins".to_string(),
            path: "/login".to_string(),
            username: "admin".to_string(),
            password: "admin".to_string(),
            auth_method: AuthMethod::Form { 
                username_field: "j_username".to_string(),
                password_field: "j_password".to_string(),
            },
            success_indicator: vec!["Dashboard".to_string(), "Jenkins".to_string(), "Manage Jenkins".to_string()],
            failure_indicator: vec!["Invalid".to_string(), "loginError".to_string()],
        });
        
        self.add_entry(CredentialEntry {
            application: "Jenkins".to_string(),
            path: "/login".to_string(),
            username: "jenkins".to_string(),
            password: "jenkins".to_string(),
            auth_method: AuthMethod::Form { 
                username_field: "j_username".to_string(),
                password_field: "j_password".to_string(),
            },
            success_indicator: vec!["Dashboard".to_string()],
            failure_indicator: vec!["Invalid".to_string()],
        });
        
        // WordPress
        self.add_entry(CredentialEntry {
            application: "WordPress".to_string(),
            path: "/wp-login.php".to_string(),
            username: "admin".to_string(),
            password: "admin".to_string(),
            auth_method: AuthMethod::Form {
                username_field: "log".to_string(),
                password_field: "pwd".to_string(),
            },
            success_indicator: vec!["wp-admin".to_string(), "Dashboard".to_string(), "WordPress".to_string()],
            failure_indicator: vec!["incorrect".to_string(), "ERROR".to_string()],
        });
        
        // phpMyAdmin (usually configured differently, but common combos)
        self.add_entry(CredentialEntry {
            application: "phpMyAdmin".to_string(),
            path: "/phpmyadmin/index.php".to_string(),
            username: "root".to_string(),
            password: "".to_string(), // Empty password
            auth_method: AuthMethod::Form {
                username_field: "pma_username".to_string(),
                password_field: "pma_password".to_string(),
            },
            success_indicator: vec!["phpMyAdmin".to_string(), "general_settings".to_string()],
            failure_indicator: vec!["Access denied".to_string(), "Cannot log in".to_string()],
        });
        
        self.add_entry(CredentialEntry {
            application: "phpMyAdmin".to_string(),
            path: "/phpmyadmin/index.php".to_string(),
            username: "root".to_string(),
            password: "root".to_string(),
            auth_method: AuthMethod::Form {
                username_field: "pma_username".to_string(),
                password_field: "pma_password".to_string(),
            },
            success_indicator: vec!["phpMyAdmin".to_string()],
            failure_indicator: vec!["Access denied".to_string()],
        });
        
        // MySQL (via API or direct if exposed)
        self.add_entry(CredentialEntry {
            application: "MySQL Web".to_string(),
            path: "/mysql/".to_string(),
            username: "root".to_string(),
            password: "root".to_string(),
            auth_method: AuthMethod::Basic,
            success_indicator: vec!["MySQL".to_string(), "database".to_string()],
            failure_indicator: vec!["401".to_string()],
        });
        
        // Grafana
        self.add_entry(CredentialEntry {
            application: "Grafana".to_string(),
            path: "/login".to_string(),
            username: "admin".to_string(),
            password: "admin".to_string(),
            auth_method: AuthMethod::Form {
                username_field: "user".to_string(),
                password_field: "password".to_string(),
            },
            success_indicator: vec!["Grafana".to_string(), "Home".to_string(), "Dashboards".to_string()],
            failure_indicator: vec!["Invalid".to_string(), "login".to_string()],
        });
        
        // Elasticsearch
        self.add_entry(CredentialEntry {
            application: "Elasticsearch".to_string(),
            path: "/".to_string(),
            username: "elastic".to_string(),
            password: "changeme".to_string(),
            auth_method: AuthMethod::Basic,
            success_indicator: vec!["cluster_name".to_string(), "tagline".to_string()],
            failure_indicator: vec!["401".to_string(), "authentication".to_string()],
        });
        
        // Kibana
        self.add_entry(CredentialEntry {
            application: "Kibana".to_string(),
            path: "/login".to_string(),
            username: "elastic".to_string(),
            password: "changeme".to_string(),
            auth_method: AuthMethod::Form {
                username_field: "username".to_string(),
                password_field: "password".to_string(),
            },
            success_indicator: vec!["Kibana".to_string(), "Discover".to_string()],
            failure_indicator: vec!["Invalid".to_string()],
        });
        
        // MongoDB Web Interface
        self.add_entry(CredentialEntry {
            application: "MongoDB".to_string(),
            path: "/mongo/".to_string(),
            username: "admin".to_string(),
            password: "pass".to_string(),
            auth_method: AuthMethod::Basic,
            success_indicator: vec!["Mongo".to_string(), "DB".to_string()],
            failure_indicator: vec!["401".to_string()],
        });
        
        // Redis Web
        self.add_entry(CredentialEntry {
            application: "Redis".to_string(),
            path: "/redis/".to_string(),
            username: "admin".to_string(),
            password: "redis".to_string(),
            auth_method: AuthMethod::Basic,
            success_indicator: vec!["Redis".to_string()],
            failure_indicator: vec!["401".to_string()],
        });
        
        // Memcached
        self.add_entry(CredentialEntry {
            application: "Memcached".to_string(),
            path: "/memcached/".to_string(),
            username: "admin".to_string(),
            password: "memcached".to_string(),
            auth_method: AuthMethod::Basic,
            success_indicator: vec!["stats".to_string()],
            failure_indicator: vec!["401".to_string()],
        });
        
        // RabbitMQ
        self.add_entry(CredentialEntry {
            application: "RabbitMQ".to_string(),
            path: "/api/".to_string(),
            username: "guest".to_string(),
            password: "guest".to_string(),
            auth_method: AuthMethod::Basic,
            success_indicator: vec!["rabbitmq_version".to_string(), "management_version".to_string()],
            failure_indicator: vec!["401".to_string(), "Unauthorized".to_string()],
        });
        
        self.add_entry(CredentialEntry {
            application: "RabbitMQ Management".to_string(),
            path: "/".to_string(),
            username: "guest".to_string(),
            password: "guest".to_string(),
            auth_method: AuthMethod::Basic,
            success_indicator: vec!["RabbitMQ Management".to_string()],
            failure_indicator: vec!["login".to_string()],
        });
        
        // Docker Registry
        self.add_entry(CredentialEntry {
            application: "Docker Registry".to_string(),
            path: "/v2/_catalog".to_string(),
            username: "admin".to_string(),
            password: "password".to_string(),
            auth_method: AuthMethod::Basic,
            success_indicator: vec!["repositories".to_string()],
            failure_indicator: vec!["401".to_string(), "Unauthorized".to_string()],
        });
        
        // Kubernetes Dashboard
        self.add_entry(CredentialEntry {
            application: "Kubernetes Dashboard".to_string(),
            path: "/api/v1/namespaces/kube-system/services/https:kubernetes-dashboard:/proxy/".to_string(),
            username: "admin".to_string(),
            password: "admin".to_string(),
            auth_method: AuthMethod::Bearer,
            success_indicator: vec!["kubernetes".to_string(), "kube-system".to_string()],
            failure_indicator: vec!["Unauthorized".to_string()],
        });
        
        // cPanel
        self.add_entry(CredentialEntry {
            application: "cPanel".to_string(),
            path: "/login".to_string(),
            username: "root".to_string(),
            password: "root".to_string(),
            auth_method: AuthMethod::Form {
                username_field: "user".to_string(),
                password_field: "pass".to_string(),
            },
            success_indicator: vec!["cPanel".to_string(), "dashboard".to_string()],
            failure_indicator: vec!["Invalid".to_string()],
        });
        
        // Plesk
        self.add_entry(CredentialEntry {
            application: "Plesk".to_string(),
            path: "/login_up.php".to_string(),
            username: "admin".to_string(),
            password: "setup".to_string(),
            auth_method: AuthMethod::Form {
                username_field: "login_name".to_string(),
                password_field: "passwd".to_string(),
            },
            success_indicator: vec!["Plesk".to_string(), "admin".to_string()],
            failure_indicator: vec!["Authentication".to_string()],
        });
        
        // Webmin
        self.add_entry(CredentialEntry {
            application: "Webmin".to_string(),
            path: "/session_login.cgi".to_string(),
            username: "root".to_string(),
            password: "root".to_string(),
            auth_method: AuthMethod::Form {
                username_field: "user".to_string(),
                password_field: "pass".to_string(),
            },
            success_indicator: vec!["Webmin".to_string(), "Dashboard".to_string()],
            failure_indicator: vec!["Failed".to_string()],
        });
        
        // SonarQube
        self.add_entry(CredentialEntry {
            application: "SonarQube".to_string(),
            path: "/api/authentication/validate".to_string(),
            username: "admin".to_string(),
            password: "admin".to_string(),
            auth_method: AuthMethod::Basic,
            success_indicator: vec!["\"valid\":true".to_string()],
            failure_indicator: vec!["\"valid\":false".to_string()],
        });
        
        // JBoss
        self.add_entry(CredentialEntry {
            application: "JBoss".to_string(),
            path: "/management".to_string(),
            username: "admin".to_string(),
            password: "admin".to_string(),
            auth_method: AuthMethod::Digest,
            success_indicator: vec!["JBoss".to_string(), "management".to_string()],
            failure_indicator: vec!["401".to_string()],
        });
        
        // WebLogic
        self.add_entry(CredentialEntry {
            application: "WebLogic".to_string(),
            path: "/console".to_string(),
            username: "weblogic".to_string(),
            password: "weblogic".to_string(),
            auth_method: AuthMethod::Form {
                username_field: "j_username".to_string(),
                password_field: "j_password".to_string(),
            },
            success_indicator: vec!["WebLogic".to_string(), "console".to_string()],
            failure_indicator: vec!["Login".to_string()],
        });
        
        // Splunk
        self.add_entry(CredentialEntry {
            application: "Splunk".to_string(),
            path: "/en-US/account/login".to_string(),
            username: "admin".to_string(),
            password: "changeme".to_string(),
            auth_method: AuthMethod::Form {
                username_field: "username".to_string(),
                password_field: "password".to_string(),
            },
            success_indicator: vec!["Splunk".to_string(), "Home".to_string()],
            failure_indicator: vec!["incorrect".to_string()],
        });
        
        // Nextcloud
        self.add_entry(CredentialEntry {
            application: "Nextcloud".to_string(),
            path: "/login".to_string(),
            username: "admin".to_string(),
            password: "admin".to_string(),
            auth_method: AuthMethod::Form {
                username_field: "user".to_string(),
                password_field: "password".to_string(),
            },
            success_indicator: vec!["Nextcloud".to_string(), "Files".to_string()],
            failure_indicator: vec!["Wrong".to_string()],
        });
        
        // Drupal
        self.add_entry(CredentialEntry {
            application: "Drupal".to_string(),
            path: "/user/login".to_string(),
            username: "admin".to_string(),
            password: "admin".to_string(),
            auth_method: AuthMethod::Form {
                username_field: "name".to_string(),
                password_field: "pass".to_string(),
            },
            success_indicator: vec!["admin".to_string(), "Dashboard".to_string()],
            failure_indicator: vec!["Unrecognized".to_string()],
        });
        
        // Nagios
        self.add_entry(CredentialEntry {
            application: "Nagios".to_string(),
            path: "/nagios".to_string(),
            username: "nagiosadmin".to_string(),
            password: "nagiosadmin".to_string(),
            auth_method: AuthMethod::Basic,
            success_indicator: vec!["Nagios".to_string(), "Core".to_string()],
            failure_indicator: vec!["401".to_string()],
        });
        
        // Zabbix
        self.add_entry(CredentialEntry {
            application: "Zabbix".to_string(),
            path: "/index.php".to_string(),
            username: "Admin".to_string(),
            password: "zabbix".to_string(),
            auth_method: AuthMethod::Form {
                username_field: "name".to_string(),
                password_field: "password".to_string(),
            },
            success_indicator: vec!["Zabbix".to_string(), "Dashboard".to_string()],
            failure_indicator: vec!["Login".to_string()],
        });
        
        // Cacti
        self.add_entry(CredentialEntry {
            application: "Cacti".to_string(),
            path: "/cacti/index.php".to_string(),
            username: "admin".to_string(),
            password: "admin".to_string(),
            auth_method: AuthMethod::Form {
                username_field: "login_username".to_string(),
                password_field: "login_password".to_string(),
            },
            success_indicator: vec!["Cacti".to_string(), "console".to_string()],
            failure_indicator: vec!["Invalid".to_string()],
        });
        
        // Prometheus
        self.add_entry(CredentialEntry {
            application: "Prometheus".to_string(),
            path: "/".to_string(),
            username: "admin".to_string(),
            password: "admin".to_string(),
            auth_method: AuthMethod::Basic,
            success_indicator: vec!["Prometheus".to_string(), "Alerts".to_string()],
            failure_indicator: vec!["Unauthorized".to_string()],
        });
        
        // Cisco Router
        self.add_entry(CredentialEntry {
            application: "Cisco Router".to_string(),
            path: "/level/15/exec/".to_string(),
            username: "cisco".to_string(),
            password: "cisco".to_string(),
            auth_method: AuthMethod::Basic,
            success_indicator: vec!["Cisco IOS Software".to_string()],
            failure_indicator: vec!["401".to_string(), "Unauthorized".to_string()],
        });
    }
    
    fn add_entry(&mut self, entry: CredentialEntry) {
        self.creds_db.push(entry);
    }
    
    /// Scan for default credentials
    pub async fn scan(&self, base_url: &str) -> Vec<CredsFinding> {
        let mut findings = Vec::new();
        let base = base_url.trim_end_matches('/');
        
        println!("[DEFAULT-CREDS] Testing {} credential combinations...", self.creds_db.len());
        
        for (idx, entry) in self.creds_db.iter().enumerate() {
            if idx % 10 == 0 {
                println!("[DEFAULT-CREDS] Testing {}/{}: {}", idx, self.creds_db.len(), entry.application);
            }
            
            let url = format!("{}{}", base, entry.path);
            
            match self.test_credential(&url, entry).await {
                Ok(true) => {
                    findings.push(CredsFinding {
                        severity: CredsSeverity::Critical,
                        application: entry.application.clone(),
                        url: url.clone(),
                        username: entry.username.clone(),
                        password: entry.password.clone(),
                        evidence: format!("Successfully authenticated with {}/{}", entry.username, entry.password),
                        remediation: format!("Change default credentials immediately. Disable {} access if not needed.", entry.application),
                    });
                    
                    println!("[DEFAULT-CREDS] FOUND: {} at {} with {}/{}",
                        entry.application, url, entry.username, entry.password);
                }
                _ => {}
            }
            
            // Delay to avoid lockouts
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        
        findings
    }
    
    /// Test a single credential entry
    async fn test_credential(&self, url: &str, entry: &CredentialEntry) -> Result<bool> {
        let result = match &entry.auth_method {
            AuthMethod::Basic => {
                let auth = format!("{}:{}", entry.username, entry.password);
                let encoded = BASE64.encode(auth.as_bytes());
                
                let response = self.client
                    .get(url)
                    .header("Authorization", format!("Basic {}", encoded))
                    .send()
                    .await?;
                
                let status = response.status();
                let body = response.text().await.unwrap_or_default();
                
                if status.is_success() {
                    if entry.success_indicator.iter().any(|s| body.contains(s)) {
                        return Ok(true);
                    }
                }
                
                if entry.failure_indicator.iter().any(|f| body.contains(f)) {
                    return Ok(false);
                }
                
                false
            }
            
            AuthMethod::Form { username_field, password_field } => {
                let mut form_data = HashMap::new();
                form_data.insert(username_field.clone(), entry.username.clone());
                form_data.insert(password_field.clone(), entry.password.clone());
                
                let response = self.client
                    .post(url)
                    .form(&form_data)
                    .send()
                    .await?;
                
                let status = response.status();
                let body = response.text().await.unwrap_or_default();
                
                if status.is_success() {
                    if entry.success_indicator.iter().any(|s| body.contains(s)) {
                        return Ok(true);
                    }
                }
                
                if entry.failure_indicator.iter().any(|f| body.contains(f)) {
                    return Ok(false);
                }
                
                // Check for redirects (common on successful login)
                status.is_success() && !body.to_lowercase().contains("login")
            }
            
            AuthMethod::Bearer => {
                let response = self.client
                    .get(url)
                    .header("Authorization", format!("Bearer {}", entry.password))
                    .send()
                    .await?;
                
                let status = response.status();
                let body = response.text().await.unwrap_or_default();
                
                if status.is_success() && entry.success_indicator.iter().any(|s| body.contains(s)) {
                    return Ok(true);
                }
                
                false
            }
            
            AuthMethod::Digest => {
                false
            }
            
            AuthMethod::ApiKey { header_name } => {
                let response = self.client
                    .get(url)
                    .header(header_name.clone(), &entry.password)
                    .send()
                    .await?;
                
                let status = response.status();
                let body = response.text().await.unwrap_or_default();
                
                if status.is_success() && entry.success_indicator.iter().any(|s| body.contains(s)) {
                    return Ok(true);
                }
                
                false
            }
        };
        
        Ok(result)
    }
    
    /// Get database statistics
    pub fn get_stats(&self) -> HashMap<String, usize> {
        let mut stats: HashMap<String, usize> = HashMap::new();
        
        for entry in &self.creds_db {
            *stats.entry(entry.application.clone()).or_insert(0) += 1;
        }
        
        stats
    }
}
