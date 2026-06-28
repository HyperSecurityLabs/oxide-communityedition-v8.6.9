// ----------------------------------------------------------------------------
//  cache.rs — response caching layer
// ----------------------------------------------------------------------------
//  response caching layer — stores HTTP responses to reduce duplicate requests during scanning
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
use std::io::Write as IoWrite;
use std::path::PathBuf;
use std::time::{
         SystemTime, 
         UNIX_EPOCH};
use tokio::fs;
use tokio::sync::RwLock;

use serde::{Serialize
              , Deserialize};

use crate::detection::analyzer::Finding;

//  ScanCache — two-tier caching layer / 2層キャッシュシステム
//  Architecture / アーキテクチャ:
//    Memory (RAM)  — fast reads via HashMap, max_memory_entries capped
//    Disk (FS)     — persistent storage using serde_json serialization
//  Operations flow / 操作フロー:
//    put  : memory  if full, LRU evict  then persist to disk atomically
//    get  : memory first (fast path)  disk fallback (slow path)
//    remove/clear : both tiers purged consistently
//  Checkpoint system: serializes scan state for crash recovery
//    create_checkpoint  save ScanCheckpoint with u64::MAX TTL
//    load_checkpoint    validate integrity, restore scan state
//  Atomic writes prevent corruption: write .tmp  fsync  rename .cache
pub struct ScanCache {
    cache_dir: PathBuf,
    memory_cache: RwLock<HashMap<String, CacheEntry>>,
    max_memory_entries: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntry {
    pub key: String,
    pub data: Vec<u8>,
    pub created_at: u64,
    pub expires_at: u64,
    pub access_count: u32,
    pub last_accessed: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanCheckpoint {
    pub scan_id: String,
    pub target: String,
    pub start_time: u64,
    pub last_update: u64,
    pub completed_urls: Vec<String>,
    pub pending_urls: Vec<String>,
    pub completed_phases: Vec<String>,
    pub findings: Vec<Finding>,
    pub scan_config: HashMap<String, String>,
}

impl ScanCache {
    // Synchronous constructor for non-async contexts
    pub fn new_sync(cache_dir: &str) -> Self {
        let path = PathBuf::from(cache_dir);
        let _ = std::fs::create_dir_all(&path);
        Self {
            cache_dir: path,
            memory_cache: RwLock::new(HashMap::new()),
            max_memory_entries: 1000,
        }
    }

    pub async fn new(cache_dir: &str) -> Result<Self> {
        let path = PathBuf::from(cache_dir);
        if !path.exists() {
            fs::create_dir_all(&path).await?;
        }
        Ok(Self {
            cache_dir: path,
            memory_cache: RwLock::new(HashMap::new()),
            max_memory_entries: 1000,
        })
    }

    //  Cache Put Flow / キャッシュ格納フロー
    //  Steps / ステップ:
    //    Compute TTL: saturating_add for overflow safety
    //    Write to RAM first (fast access for repeated reads)
    //    If memory full  evict LRU entry
    //    Then persist to disk via atomic write (tmp + rename)
    //  Two-tier design: RAM for speed, disk for durability.
    //    On restart, disk cache is loaded on demand (lazy loading).
    /// Store entry in cache with TTL in seconds
    pub async fn put(&self, key: &str, data: Vec<u8>, ttl_seconds: u64) -> Result<()> {
        let now = self.now();
        let expires_at = if ttl_seconds >= u64::MAX >> 1 {
            u64::MAX
        } else {
            now.saturating_add(ttl_seconds)
        };
        let entry = CacheEntry {
            key: key.to_string(),
            data: data.clone(),
            created_at: now,
            expires_at,
            access_count: 0,
            last_accessed: now,
        };
        // ram first
        {
            let mut cache = self.memory_cache.write().await;
            if cache.len() >= self.max_memory_entries {
                self.evict_oldest(&mut cache).await;
            }
            cache.insert(key.to_string(), entry.clone());
        }
        // then disk
        self.persist_entry(&entry).await?;
        Ok(())
    }

    //  Cache Get Flow / キャッシュ取得フロー
    //  Steps / ステップ:
    //    RAM lookup first  if found, check expiry  update access stats
    //    Expired entries are removed and None returned
    //    Miss in RAM  try disk load  promote back to RAM
    //    Promoted entries go to memory for subsequent fast access
    //  This LRU-with-promotion pattern optimizes for repeated URL scans.
    /// Get entry from cache. Returns None if expired or not found
    pub async fn get(&self, key: &str) -> Option<Vec<u8>> {
        // try memory first — faster
        {
            let mut cache = self.memory_cache.write().await;
            if let Some(entry) = cache.get_mut(key) {
                let now = self.now();
                if entry.expires_at < now {
                    cache.remove(key);
                    return None;
                }
                entry.access_count += 1;
                entry.last_accessed = now;
                return Some(entry.data.clone());
            }
        }
        // not in ram? try disk
        if let Ok(entry) = self.load_entry(key).await {
            let now = self.now();
            if entry.expires_at >= now {
                let mut cache = self.memory_cache.write().await;
                cache.insert(key.to_string(), entry.clone());
                return Some(entry.data);
            }
        }
        None
    }

    // Delete from both memory and disk
    pub async fn remove(&self, key: &str) -> Result<()> {
        self.memory_cache.write().await.remove(key);
        let path = self.cache_dir.join(format!("{}.cache", self.sanitize_key(key)));
        if path.exists() {
            fs::remove_file(&path).await?;
        }
        Ok(())
    }

    // Clear all cached entries
    pub async fn clear(&self) -> Result<()> {
        self.memory_cache.write().await.clear();
        let mut entries = fs::read_dir(&self.cache_dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            if entry.path().extension().map(|e| e == "cache").unwrap_or(false) {
                fs::remove_file(entry.path()).await?;
            }
        }
        println!("[CACHE] all entries purged");
        Ok(())
    }

    //  Checkpoint Save / チェックポイント保存
    //  Purpose: enable scan resumption after crash/interruption
    //    Serializes ScanCheckpoint (target, URLs, phases, findings, config)
    //    Stores with effectively-infinite TTL (u64::MAX >> 1)
    //    Key is host + scan_id for uniqueness
    //    Prints a styled summary line for user visibility
    //  Checkpoints are how OXIDE implements "resume scan" functionality.
    /// Save a checkpoint for scan resumption
    pub async fn create_checkpoint(&self, checkpoint: &ScanCheckpoint) -> Result<()> {
        let host = checkpoint.target
            .trim_start_matches("http://")
            .trim_start_matches("https://")
            .split('/')
            .next()
            .unwrap_or("unknown");
        let key = format!("checkpoint_{}_{}", host, checkpoint.scan_id);
        let data = serde_json::to_vec(checkpoint)?;
        // these never expire. obviously
        self.put(&key, data, u64::MAX >> 1).await?;
        let lavender = "\x1B[38;2;190;175;235m";
        let jade     = "\x1B[38;2;0;180;120m";
        let cyan     = "\x1B[38;2;100;210;255m";
        let dim      = "\x1B[38;2;120;130;150m";
        let rst      = "\x1B[0m";
        let phase_count = checkpoint.completed_phases.len();
        let url_count = checkpoint.completed_urls.len();
        let find_count = checkpoint.findings.len();
        println!("{lavender}◇{rst} {jade}checkpoint{rst} {cyan}{}{rst} {dim}scan{rst} {} {dim}phases{rst} {} {dim}urls{rst} {} {dim}finds{rst} {}",
            checkpoint.target, checkpoint.scan_id, phase_count, url_count, find_count);
        Ok(())
    }

    //  Checkpoint Load / チェックポイント読み込み
    //  Steps:
    //    Look up key "checkpoint_{scan_id}" from cache
    //    Validate data integrity (size, JSON structure, scan_id presence)
    //    If corrupted  print warning, return None (skip gracefully)
    //    Deserialize JSON  ScanCheckpoint struct
    //  Validation prevents crashes from partially-written checkpoint files.
    /// Try to load a checkpoint. Skip if corrupted
    pub async fn load_checkpoint(&self, scan_id: &str) -> Option<ScanCheckpoint> {
        let key = format!("checkpoint_{}", scan_id);
        let data = self.get(&key).await?;
        if !Self::validate_checkpoint(&data) {
            eprintln!("[CACHE] corrupted checkpoint {}, skipping", scan_id);
            return None;
        }
        serde_json::from_slice(&data).ok()
    }

    // show me what you got
    pub async fn list_checkpoints(&self) -> Vec<ScanCheckpoint> {
        let mut checkpoints = Vec::new();
        let cache = self.memory_cache.read().await;
        for (key, entry) in cache.iter() {
            if key.starts_with("checkpoint_") {
                if let Ok(cp) = serde_json::from_slice::<ScanCheckpoint>(&entry.data) {
                    checkpoints.push(cp);
                }
            }
        }
        checkpoints
    }

    // get rid of one
    pub async fn delete_checkpoint(&self, scan_id: &str) -> Result<()> {
        let key = format!("checkpoint_{}", scan_id);
        self.remove(&key).await
    }

    // cache an HTTP response so we don't hit the same endpoint twice
    // because that's just wasteful
    pub async fn cache_response(&self, url: &str, body: &str, status: u16) -> Result<()> {
        let key = format!("response_{}_{}", self.hash_url(url), status);
        let data = body.as_bytes().to_vec();
        self.put(&key, data, 3600).await?; // 1 hour
        Ok(())
    }

    pub async fn get_cached_response(&self, url: &str, status: u16) -> Option<String> {
        let key = format!("response_{}_{}", self.hash_url(url), status);
        self.get(&key).await
            .and_then(|data| String::from_utf8(data).ok())
    }

    //  Atomic Persist / アトミック永続化
    //  Crash-safe write sequence:
    //    Write serde_json to .tmp file
    //    fsync (flush to disk) for durability
    //    atomic rename .tmp  .cache (filesystem-level atomic on Linux)
    //    If crash during write: .tmp is lost, .cache remains intact
    //  This prevents partial/corrupted cache entries after power loss.
    /// Atomic write: write to .tmp then rename for crash safety
    async fn persist_entry(&self, entry: &CacheEntry) -> Result<()> {
        let filename = format!("{}.cache", self.sanitize_key(&entry.key));
        let path = self.cache_dir.join(filename);
        let tmp_path = self.cache_dir.join(format!("{}.tmp", self.sanitize_key(&entry.key)));
        let data = serde_json::to_vec(entry)?;
        {
            let mut tmp = std::fs::File::create(&tmp_path)?;
            tmp.write_all(&data)?;
            tmp.sync_all()?;
        }
        std::fs::rename(&tmp_path, &path)?;
        Ok(())
    }

    // Validate checkpoint data integrity
    pub fn validate_checkpoint(data: &[u8]) -> bool {
        if data.is_empty() || data.len() > 10_000_000 {
            return false;
        }
        if !data.starts_with(b"{") {
            return false;
        }
        let v: serde_json::Value = match serde_json::from_slice(data) {
            Ok(v) => v,
            Err(_) => return false,
        };
        match v.get("scan_id") {
            Some(id) => id.as_str().map_or(false, |s| !s.is_empty()),
            None => false,
        }
    }

    // Read entry from disk
    async fn load_entry(&self, key: &str) -> Result<CacheEntry> {
        let filename = format!("{}.cache", self.sanitize_key(key));
        let path = self.cache_dir.join(filename);
        let data = fs::read(&path).await?;
        let entry = serde_json::from_slice(&data)?;
        Ok(entry)
    }

    //  LRU Eviction / LRU退避
    //  Evicts the entry with the oldest `last_accessed` timestamp
    //   Only evicts from memory cache (disk entries remain for later load)
    //   Uses min_by_key over last_accessed for O(n) scan (acceptable for <10k entries)
    //  Pure LRU (not LRU-K) — sufficient for scan workloads where temporal
    //   locality is the dominant access pattern.
    /// Evict the least recently used entry from memory cache
    async fn evict_oldest(&self, cache: &mut HashMap<String, CacheEntry>) {
        if let Some(oldest_key) = cache.iter()
            .min_by_key(|(_, v)| v.last_accessed)
            .map(|(k, _)| k.clone())
        {
            cache.remove(&oldest_key);
            println!("[CACHE] evicted (LRU): {}", oldest_key);
        }
    }

    // how we doin?
    pub async fn get_stats(&self) -> CacheStats {
        let memory = self.memory_cache.read().await;
        let disk_count = match fs::read_dir(&self.cache_dir).await {
            Ok(mut entries) => {
                let mut count = 0;
                while let Ok(Some(_)) = entries.next_entry().await {
                    count += 1;
                }
                count
            }
            Err(_) => 0,
        };
        let total_memory_bytes: usize = memory.values()
            .map(|e| e.data.len())
            .sum();
        CacheStats {
            memory_entries: memory.len(),
            disk_entries: disk_count,
            total_memory_bytes,
            avg_entry_size: if !memory.is_empty() { 
                total_memory_bytes / memory.len() 
            } else { 
                0 
            },
        }
    }

    fn now(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    fn hash_url(&self, url: &str) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        url.hash(&mut hasher);
        format!("{:016x}", hasher.finish())
    }

    // make a key safe for the filesystem.
    // filesystems hate special chars, who knew
    fn sanitize_key(&self, key: &str) -> String {
        key.replace(|c: char| !c.is_alphanumeric() && c != '-' && c != '_', "_")
    }

    // Clean up expired entries from memory cache
    pub async fn cleanup_expired(&self) -> Result<usize> {
        let now = self.now();
        let mut removed = 0;
        {
            let mut cache = self.memory_cache.write().await;
            let expired: Vec<String> = cache
                .iter()
                .filter(|(_, v)| v.expires_at < now)
                .map(|(k, _)| k.clone())
                .collect();
            for key in expired {
                cache.remove(&key);
                removed += 1;
            }
        }
        println!("[CACHE] {} expired entries evicted", removed);
        Ok(removed)
    }
}

#[derive(Debug)]
pub struct CacheStats {
    pub memory_entries: usize,
    pub disk_entries: usize,
    pub total_memory_bytes: usize,
    pub avg_entry_size: usize,
}

// thread-local cache for when you don't wanna share
pub struct LocalCache<T: Clone> {
    data: RwLock<HashMap<String, T>>,
    max_size: usize,
}

impl<T: Clone> LocalCache<T> {
    pub fn new(max_size: usize) -> Self {
        Self {
            data: RwLock::new(HashMap::new()),
            max_size,
        }
    }

    pub async fn get(&self, key: &str) -> Option<T> {
        self.data.read().await.get(key).cloned()
    }

    pub async fn put(&self, key: String, value: T) {
        let mut data = self.data.write().await;
        if data.len() >= self.max_size {
            if let Some(first_key) = data.keys().next().cloned() {
                data.remove(&first_key);
            }
        }
        data.insert(key, value);
    }

    pub async fn clear(&self) {
        self.data.write().await.clear();
    }
}
