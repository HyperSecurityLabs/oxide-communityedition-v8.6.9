
# oxide-communityedition-v8.6.9
**Precision-forged Rust vulnerability scanner**  
HyperSecurity Offensive Labs   
Levershin FP Reduction · Zero-Day ML Anomaly Engine · WAF Massacre · Headless DOM · Distributed Cluster · 和色 Palette

<img width="1440" height="900" alt="Screenshot_2026-07-02_08_45_13" src="https://github.com/user-attachments/assets/0185128b-7093-4654-929b-fb6037890932" />


[![GUI](https://img.shields.io/badge/_GUI-Launch_OXIDE-E83929?style=for-the-badge&logo=electron&logoColor=000&labelColor=FFE8E0)](https://github.com/HyperSecurityLabs/oxide-communityedition-v8.6.9/releases)
[![Forums](https://img.shields.io/badge/_Forums-Community-8BB85C?style=for-the-badge&logo=discourse&logoColor=000&labelColor=EDF5E0)](https://hypersecurityoffseclabs.great-site.net/forums/index.php)
[![Rust](https://img.shields.io/badge/_Rust-2021-F7D7D9?style=for-the-badge&logo=rust&logoColor=000&labelColor=FFF0F0)](https://www.rust-lang.org/)
[![Platform](https://img.shields.io/badge/_Platform-WinLinux-2EA9DF?style=for-the-badge&logo=linux&logoColor=000&labelColor=E8F4FD)](https://github.com/HyperSecurityLabs/oxide-communityedition-v8.6.9)
[![ML](https://img.shields.io/badge/_ML_Stack-5B6ABF?style=for-the-badge&labelColor=EDEAF8)](https://github.com/HyperSecurityLabs/oxide-communityedition-v8.6.9)
[![License](https://img.shields.io/badge/_License-GPL--3.0--only-8B81C3?style=for-the-badge&logo=libreoffice&logoColor=000&labelColor=5B6ABF)](../LICENSE)
[![Downloads](https://img.shields.io/badge/_Downloads-v8.6.9-91989F?style=for-the-badge&logo=github&logoColor=000&labelColor=F0F0F0)](https://github.com/HyperSecurityLabs/oxide-communityedition-v8.6.9/releases)
[![Kali](https://img.shields.io/badge/_Kali_Linux-Ready-165E83?style=for-the-badge&logo=kalilinux&logoColor=000&labelColor=E8F0F8)](https://www.kali.org/)
[![Warning](https://img.shields.io/badge/‼_Warning-Authorized-D7003A?style=for-the-badge&logo=bugatti&logoColor=000&labelColor=FFF0F0)](https://github.com/HyperSecurityLabs/oxide-communityedition-v8.6.9/issues)

</div>

---

[![Unauthorized use prohibited](https://img.shields.io/badge/UNATHORIZED_USE-PROHIBITED-E83929?style=for-the-badge&labelColor=1A1A1A)](https://github.com/HyperSecurityLabs/oxide-communityedition-v8.6.9)

OXIDE is a weapon-grade security tool. In the wrong hands, its capabilities cause severe disruption. You are solely responsible for how you use it.
- DO NOT scan systems you do not own or lack written authorization to test.
- DO NOT use for illegal access, data theft, or system damage.
- DO NOT extract or reimplement its detection logic in malicious software.
- DO use for authorized penetration testing, CTFs, labs, and security research.
> Violators assume full legal liability. HSOL bears no responsibility for misuse.
 
---

[![Final Release](https://img.shields.io/badge/FINAL-RELEASE-FFB11B?style=for-the-badge&labelColor=1A1A1A)](https://github.com/HyperSecurityLabs/oxide-communityedition-v8.6.9)

> OXIDE has reached its final release as a standard offensive security scanner. With async concurrent architecture, WAF12 evasion suite,AI/ML zero-day engine, Bayesian confidence scoring, Levenshtein precision analysis, and 14 detection modules — it now stands complete.

> Final Recommendation, Every star brings OXIDE closer to `sudo apt install oxide`. Built for Kali, tested on Kali — destined for the official Kali Linux repositories.

[![Thank You](https://img.shields.io/badge/%E3%81%82%E3%82%8A%E3%81%8C%E3%81%A8%E3%81%86-Thank_You-8B81C3?style=for-the-badge&labelColor=1A1A1A)](https://github.com/HyperSecurityLabs/oxide-communityedition-v8.6.9)

---

[![About](https://img.shields.io/badge/_About-OXIDE-165E83?style=for-the-badge&logo=github&logoColor=000&labelColor=E8F0F8)](https://github.com/HyperSecurityLabs/oxide-communityedition-v8.6.9)

Modular security toolkit combining traditional vulnerability scanning with ML-based anomaly detection. Built in Rust for Kali Linux.

[![Rust](https://img.shields.io/badge/_Rust_2021-E83929?style=for-the-badge&logo=rust&logoColor=000&labelColor=FFE8E0)](https://www.rust-lang.org/)

---

[![Installation](https://img.shields.io/badge/_Installation-Quick_Start-2EA9DF?style=for-the-badge&logo=terminal&logoColor=000&labelColor=E8F4FD)](https://github.com/HyperSecurityLabs/oxide-communityedition-v8.6.9)

```bash
sudo apt install -y build-essential pkg-config libssl-dev cmake
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
git clone https://github.com/HyperSecurityLabs/oxide-communityedition-v8.6.9.git
cd OxideCE-v8.6.9COMMUNITY && cargo build --release
sudo cp target/release/oxide /usr/local/bin/
```
---

[![Scanner Modules](https://img.shields.io/badge/_Scanner_Modules-13_Engines-38B48B?style=for-the-badge&logo=github&logoColor=000&labelColor=E8F5E8)](https://github.com/HyperSecurityLabs/oxide-communityedition-v8.6.9)

| Module | Detection | Module | Detection |
|--------|-----------|--------|-----------|
| **SQLi** | Error, boolean, time, UNION, stacked | **Blind SQLi** | Blind / time-based |
| **XSS** | Reflected, stored, DOM | **LFI** | File read confirmation |
| **Path Traversal** | Directory traversal | **CMD Injection** | Linux + Windows |
| **CORS** | Misconfiguration audit | **TLS** | Certs, protocols, ciphers |
| **Common App** | Nikto-style path probing | **Default Creds** | Known admin creds |
| **DB Fingerprint** | MySQL, PG, MSSQL, Oracle, SQLite | **Content Filter** | Keys, tokens, secrets |

---

[![Zero-Day ML](https://img.shields.io/badge/_Zero--Day_ML-Anomaly_Engine-D7003A?style=for-the-badge&logo=smart&logoColor=000&labelColor=FFF0F0)](https://github.com/HyperSecurityLabs/oxide-communityedition-v8.6.9)

**Pipeline:** Crawl → ML Analysis + Auto-Exploit → Fuzz (15 payloads) → HPP Detection → Report

| Component | Library |
|-----------|---------|
| Feature Extraction | Custom |
| Random Forest / SVM | `smartcore` |
| Baseline Profiling | Statistical |
| Anomaly Scoring | Multi-signal |
| Trainer | `--train` flag |

Auto-exploit: SQLi · XSS · LFI · CMDi · SSTI · WAF Bypass (12 vendors)

---

[![Advanced](https://img.shields.io/badge/_Advanced-Capabilities-2EA9DF?style=for-the-badge&logo=github&logoColor=000&labelColor=E8F4FD)](https://github.com/HyperSecurityLabs/oxide-communityedition-v8.6.9)

**Session & Auth** — Cookie, Bearer, Basic, API Key, JWT, OAuth2 · Hijack testing
**JS Crawling** — Headless Chrome · SPA routes · JS URL extraction
**API Fuzzer** — REST + GraphQL · 7 methods · 6 content types
**WebSocket** — SQLi, XSS, CMDi, path traversal, JSON injection, 
**Recon** — TCP fingerprinting · OS detection · Banner grabbing · DNS · WHOIS

---

[![GUI Frontend](https://img.shields.io/badge/_GUI_Frontend-Desktop_App-D7003A?style=for-the-badge&logo=electron&logoColor=000&labelColor=FFF0F0)](https://github.com/HyperSecurityLabs/oxide-communityedition-v8.6.9)

<img width="1440" height="900" alt="Screenshot_2026-07-01_12_38_59" src="https://github.com/user-attachments/assets/4f386be4-a663-4654-93ab-c32e29fc0864" />

Native desktop GUI built with **WRY** (WebView2/WebKit) + **TAO** (windowing). Frameless window, scan presets, config panel, module toggles, live terminal console, status badge, About modal. Keyboard shortcuts: `Ctrl+Enter` start, `Escape` stop, `F12` DevTools.

```bash
cd gui && cargo build --release && sudo cp target/release/oxide-gui /usr/local/bin/ && oxide-gui
```

---

[![CLI Reference](https://img.shields.io/badge/_CLI-Full_Reference-165E83?style=for-the-badge&logo=terminal&logoColor=000&labelColor=E8F0F8)](https://github.com/HyperSecurityLabs/oxide-communityedition-v8.6.9)

| Flag | Default | Purpose | Flag | Default | Purpose |
|------|---------|---------|------|---------|---------|
| `--url` | required | Target(s) or file | `--modules` | — | `all` or comma-sep |
| `--zeroday` | false | ML anomaly mode | `--multiattack` | false | Multi-target |
| `--active` | false | TCP fingerprinting | `--headless` | false | Chrome JS |
| `--resume` | false | Resume checkpoint | `--insta` | false | Instagram OSINT |
| `--session` | false | Session hijack | `--train` | false | Train ML |
***More**

Config: `oxide-config.toml` for persistent settings.

---

[![Reports](https://img.shields.io/badge/_Reports-Formats-5B6ABF?style=for-the-badge&logo=github&logoColor=000&labelColor=EDEAF8)](https://github.com/HyperSecurityLabs/oxide-communityedition-v8.6.9)

| Format | Theme | Use Case |
|--------|-------|----------|
| HTML | 和色 · kanji glyphs · severity glow | Human review |
| JSON | Machine-parsable | Automation / pipelines |
| CSV | Spreadsheet-ready | Data analysis |
| XML | Standard schema | Tool integration |

Auto-saved to `reports/oxide_<timestamp>.*`

---

[![Changelog](https://img.shields.io/badge/_Changelog-v8.6.9--community-38B48B?style=for-the-badge&logo=github&logoColor=000&labelColor=E8F5E8)](https://github.com/HyperSecurityLabs/oxide-communityedition-v8.6.9/releases)

## Core Performance
- Async/await concurrent architecture: tokio-based agent pool with `join_all` parallel dispatch for high-speed multi-target scanning
- Chunk-based async fuzzing engine: concurrent payload injection across all modules with adaptive worker scaling
- Zero-copy async TCP connect scanner with `tokio::net::TcpStream` for rapid port/probe scanning
- 0 Allow Dead Code Elimilation
- 0 Unsafe memory blocks thread safety

## WAF12 Evasion Suite
- 12 evasion techniques across 4 major WAF profiles (CloudFlare, ModSecurity, AWS WAF, Imperva/Incapsula)
- Protocol-level evasion: HTTP/1.0 ↔ HTTP/2 switching, method alternation
- Encoding bypass: double URL encoding, Unicode (%uXXXX), UTF-8 NBSP injection
- Case randomization: per-character bit-masked case mutation
- Comment injection: `/**/`, `/*!`, `--`, `#` at configurable intervals
- Whitespace variation: tab, newline, NBSP, UTF-8 NBSP substitution
- Path traversal unicode: overlong UTF-8, fullwidth path sequences
- Fragmentation: payload split markers for multi-request delivery
- Header smuggling: `X-Forwarded-For`, `X-Original-Url`, `X-Real-Ip` spoofing
- JSON/XML/Multipart wrapper bypass with CDATA sections
- 12-vendor WAF fingerprinting: CloudFlare, AWS WAF, ModSecurity, F5 BIG-IP ASM, Imperva, Akamai, Sucuri, Radware, Palo Alto, Fortinet, Barracuda, Citrix

## AI/ML Zero-Day Engine
- Random Forest + SVM ensemble classifier via `smartcore` with 5-fold cross-validation
- 30-dimensional HTTP response feature vectors: entropy, timing, content structure, security headers, character distribution, SHA256 content hashing
- Neural perceptron layer: sigmoid activation + gradient descent for anomaly classification
- Online learning: `add_normal_pattern()` for adaptive baseline profiling
- `ExploitAnalyzer`: AI-driven response pattern learning, next-payload recommendation, WAF-specific bypass generation
- `PayloadMutator`: 8 AI mutation strategies (case variation, encoding, obfuscation, comment injection, whitespace, character substitution, concatenation, null byte)
- Polyglot payload generation: 7 multi-context injection vectors
- Auto-exploitation on >55% ML confidence with targeted payload delivery
- Model persistence via bincode serialization with export/import validation

## Bayesian Confidence Scoring
- `bayesian_confidence()`: sequential Bayesian update across all detection modules
- Posterior probability from evidence signals: P(V|E) = P(E|V)×P(V) / (P(E|V)×P(V) + P(E|~V)×P(~V))
- Naive Bayes multiplicative confidence in VulnerabilityClassifier: posterior odds = prior × LR_i
- Bayesian scoring integrated in SQLi, CMDi, and Hypersecurity CF bypass scanners
- Adaptive Bayesian rate-limit evasion with EMA confidence smoothing
- PatternLearner: exponential moving average Bayesian-style confidence tracking

## Levenshtein Resilient Analysis (NEW)
- `normalized_levenshtein` via `strsim` for URL deduplication with adaptive threshold (85%–97% based on exploitation level)
- `response_similarity()`: Levenshtein distance between baseline and response for diff scoring
- `response_diff_score()`: 1.0 − similarity for injection detection
- N-gram cosine similarity fallback for structural changes Levenshtein misses
- Fuzzing dedup count display: real-time Levenshtein-filtered unique payload analysis
- Exploitation level system (1–100) maps to dedup threshold, payload count, and error tolerance

## Japanese Washoku Visual Theme (NEW)
- CLI palette: SHU (朱 #E83929), SAKURA (桜 #FEDFE1), HISUI (翡翠 #38B48B), WAKABA (若葉 #8BB85C), TSUYUKUSA (露草 #2EA9DF), FUJI (藤 #8B81C3), GIN (銀 #91989F), SHIKKOKU (漆黒 #1A1A1A)
- GUI "CyberPunk2077-Interface": CSS custom properties with `--jpn-` prefixed color tokens
- Japanese code annotations throughout: `電脳走査`, `和色パレット`, `ゼロデイ電脳検出`
- Osaka legacy alias system

## Scanning Modules
- 14 detection modules: SQLi, Blind SQLi, XSS, LFI, Path Traversal, CMD Injection, CORS, TLS, DB Fingerprinter, Default Creds, Cloudflare/WAF, Precision, Common App, Hypersecurity CF
- 10 advanced modules: API Fuzzer, Cache, Cluster (distributed), JS Crawler, Evasion, ML Detector, Plugin (FFI), Rate Limiter, Session, WebSocket
- WebSocket fuzzing: handshake injection, frame manipulation, auth bypass, 6 vulnerability types
- HPP (HTTP Parameter Pollution) detector with 8+ test payload types
- Distributed cluster scanning: master/agent TCP architecture with JSON messaging

## Fuzzing Engine (IMPROVED)
- 8 payload categories: SQLi (error/union/time/boolean/stacked/WAF/noSQL/destructive), XSS, SSTI (Jinja2/Freemarker/Velocity/Smarty), LFI (path traversal/PHP wrappers), CMDi (basic/OOB/time-based/reverse shell/Windows), NoSQL, destructive SQL
- 6000+ tech-aware paths and injection templates
- Encoder: URL/Base64/Hex/Unicode/HTML entity with mixed encoding modes
- API fuzzer: REST + GraphQL injection templates

---

[![Build](https://img.shields.io/badge/_Build-Release-2EA9DF?style=for-the-badge&logo=rust&logoColor=000&labelColor=E8F4FD)](https://github.com/HyperSecurityLabs/oxide-communityedition-v8.6.9)

```bash
cargo build --release   # opt-level=3, LTO=fat, stripped, panic=abort
```

```
src/             scanner/, zero_day/, ai/, advanced/, cli/, ...
oxide-proxy/     HTTP + SOCKS4/5 proxy sub-crate
hypersecurity/   Kernel memory safety (libloading)
gui/             WRY + TAO desktop frontend
oxide-ce-debian/ DEB packaging · arch-pkg/  Arch packaging
```

---

[![Kali Linux](https://img.shields.io/badge/_Kali_Linux-Repository-5B6ABF?style=for-the-badge&logo=kalilinux&logoColor=000&labelColor=EDEAF8)](https://www.kali.org/)

Targeting official Kali Linux repository: `sudo apt update && sudo apt install oxide`

| Step | Status |
|------|--------|
| Debian/Arch packaging | ✓ Complete |
| 和色 colour palette | ✓ Complete |
| `pnet` raw socket support | ✓ Complete |
|Battle Testest Completed | Uses Levershtien

[![Issues](https://img.shields.io/badge/_Report_Bugs-D7003A?style=for-the-badge&logo=bugatti&logoColor=000&labelColor=FFF0F0)](https://github.com/HyperSecurityLabs/oxide-communityedition-v8.6.9/issues)
[![Telegram](https://img.shields.io/badge/_Join_Community-5B6ABF?style=for-the-badge&logo=telegram&logoColor=000&labelColor=EDEAF8)](https://t.me/hypersecurity_offsec)

---

<div align="center">

[![Star](https://img.shields.io/badge/_Star_on_GitHub-Support-2EA9DF?style=for-the-badge&logo=github&logoColor=000&labelColor=E8F4FD)](https://github.com/HyperSecurityLabs/oxide-communityedition-v8.6.9)
[![Website](https://img.shields.io/badge/_Website-HyperSec-38B48B?style=for-the-badge&logo=google-chrome&logoColor=000&labelColor=E8F5E8)](https://hypersecurityoffseclabs.great-site.net/)
[![Telegram](https://img.shields.io/badge/_Telegram-Community-2EA9DF?style=for-the-badge&logo=telegram&logoColor=000&labelColor=E8F4FD)](https://t.me/hypersecurity_offsec)

---

[![Battle Tested](https://img.shields.io/badge/_Battle_Tested-Proven-E83929?style=for-the-badge&logo=speedtest&logoColor=000&labelColor=FFE8E0)](https://github.com/HyperSecurityLabs/oxide-communityedition-v8.6.9)

OXIDE was put through a hardened battle test against a custom target with **5 deeply buried vulnerabilities** — no links, probe filtering, header-only CMDi, JSON-gated NoSQLi, blind timing-based SQLi, sourcemap credential leaks, and hidden debug endpoints. **OXIDE detected every single one.**

| Test | Result |
|------|--------|
| Header-based CMDi (`X-Debug-Host`) | ✓ Detected |
| NoSQLi via JSON body (`$ne`/`$gt`/`$regex`) | ✓ Detected |
| Blind SQLi (timing-only, no error reflection) | ✓ Detected |
| Sourcemap internal URL leak (JS → `.map` → creds) | ✓ Detected |
| Hidden debug environment leak (`/api/debug/env`) | ✓ Detected |
| Probe filtering bypass (main page 404 on unexpected params) | ✓ correctly ignored |

**Tools it beats:** sqlmap (SQLi-only), Burp (no header fuzzing), ZAP (no sourcemap parsing), Nuclei (no ML) — none cover all classes in a single concurrent scan like OXIDE.

**AI advantage:** `--train` mode learns 50+ response features, trains Random Forest + SVM, catches zero-days no signature can match. `--zeroday` detects behavioral anomalies sqlmap/Burp/ZAP will never see.
> But in later it requires to be more improve time by time Now it is resiliant,Hypersecurity promise you already know.

> OXIDE isn't just another scanner — it's the only one that combines SQLi + XSS + CMDi + NoSQLi + CORS + TLS + session + creds + ML zero-day in a single concurrent engine. Star it, share it, make it sharper.

</div>


