# OXIDE v7.7.7-elite
**Precision-forged Rust vulnerability scanner**  
*HyperSecurity Offensive Labs · ALLAH L S T*  
*Forged by HyperSecurityLabs · Unleash the hunt.*
*⚔️ Zero-Day · ML Anomaly Engine · WAF Massacre · Headless DOM · Distributed Cluster.*
<div align="center">
  
[![Forums](https://img.shields.io/badge/◆_Forums-Community-00AE86?style=for-the-badge&logo=discourse&logoColor=000000&labelColor=004D40)](https://hypersecurityoffensivelabs-about.is-best.net/forums/index.php)
[![Rust](https://img.shields.io/badge/_Rust-2021-FF8A65?style=for-the-badge&logo=rust&logoColor=000000&labelColor=B71C1C)](https://www.rust-lang.org/)
[![Platform](https://img.shields.io/badge/_Platform-Win│Linux-4DB6AC?style=for-the-badge&logo=linux&logoColor=ffffff&labelColor=1A1A2E)](https://github.com/HyperSecurityLabs/OxideCE-v7.7.7ELITE)
[![Downloads](https://img.shields.io/badge/⬇_Downloads-v7.7.7-333333?style=for-the-badge&logo=github&logoColor=000000&labelColor=FFFFFF)](https://github.com/HyperSecurityLabs/OxideCE-v7.7.7ELITE/releases)
[![Website](https://img.shields.io/badge/_Website-HyperSec-00E676?style=for-the-badge&logo=google-chrome&logoColor=000000&labelColor=005B47)](https://hypersecurityoffensivelabs-about.is-best.net/)
[![Kali](https://img.shields.io/badge/★_Kali_Linux-Ready-557C94?style=for-the-badge&logo=kalilinux&logoColor=ffffff&labelColor=1B2A38)](https://www.kali.org/)
[![Warning](https://img.shields.io/badge/‼_Warning-Authorized-FF6B35?style=for-the-badge&logo=bugatti&logoColor=000000&labelColor=8B0000)](https://github.com/HyperSecurityLabs/OxideCE-v7.7.7ELITE/issues)
[![Lyara](https://img.shields.io/badge/♛_Lyara-Designer-CE93D8?style=for-the-badge&logo=pinboard&logoColor=000000&labelColor=4A0072)](https://github.com/lyara20/About.Me)

</div>

> Every star brings OXIDE closer to sudo apt install oxide. Built for Kali, tested on Kali — destined for the official Kali Linux repositories.

---

<div align="left">

[![About](https://img.shields.io/badge/◈_About-OXIDE-557C94?style=for-the-badge&logo=github&logoColor=ffffff&labelColor=1B2A38)](https://github.com/HyperSecurityLabs/OxideCE-v7.7.7ELITE)

Modular security toolkit combining traditional vulnerability scanning with ML-based anomaly detection. Built in Rust for Kali Linux.

[![Rust](https://img.shields.io/badge/◎_Rust_2021-FF8A65?style=for-the-badge&logo=rust&logoColor=000000&labelColor=B71C1C)](https://www.rust-lang.org/)
[![Runtime](https://img.shields.io/badge/▶_tokio_async-26A69A?style=for-the-badge&labelColor=004D40)](https://tokio.rs/)
[![ML](https://img.shields.io/badge/◇_ML_Stack-7E57C2?style=for-the-badge&labelColor=311B92)](https://github.com/HyperSecurityLabs/OxideCE-v7.7.7ELITE)
[![Reports](https://img.shields.io/badge/▣_Reports_Multi-FF7043?style=for-the-badge&labelColor=BF360C)](https://github.com/HyperSecurityLabs/OxideCE-v7.7.7ELITE)
[![Transport](https://img.shields.io/badge/→_reqwest-42A5F5?style=for-the-badge&labelColor=0D47A1)](https://github.com/HyperSecurityLabs/OxideCE-v7.7.7ELITE)

</div>

---

<div align="left">

[![Kali Linux](https://img.shields.io/badge/◇_Kali_Linux-Integration-557C94?style=for-the-badge&logo=kalilinux&logoColor=ffffff&labelColor=1B2A38)](https://www.kali.org/)

```
Active Recon (pnet)  →  src/recon.rs          #[cfg(target_os = "linux")]
Kali Colour Palette  →  src/cli/display.rs    ELITE_KALI #557C94
DEB Packaging        →  oxide-ce-debian/
Arch Packaging       →  PKGBUILD
```

Complements `sqlmap` · `nmap` · `burpsuite` · `metasploit`

</div>

---

<div align="left">

[![Installation](https://img.shields.io/badge/⌨_Installation-Quick_Start-00d4ff?style=for-the-badge&logo=terminal&logoColor=ffffff&labelColor=004D40)](https://github.com/HyperSecurityLabs/OxideCE-v7.7.7ELITE)

```bash
sudo apt install -y build-essential pkg-config libssl-dev cmake
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"

git clone https://github.com/HyperSecurityLabs/OxideCE-v7.7.7ELITE.git
cd OxideCE-v7.7.7ELITE && cargo build --release
sudo cp target/release/oxide /usr/local/bin/

oxide --version   # → oxide 7.7.7-elite
```

</div>

---

<div align="left">

[![Usage](https://img.shields.io/badge/⊞_Usage-Reference-b388ff?style=for-the-badge&logo=terminal&logoColor=ffffff&labelColor=311B92)](https://github.com/HyperSecurityLabs/OxideCE-v7.7.7ELITE)

```bash
oxide --url https://example.com --modules all --duration 120    # Full scan
oxide --url https://example.com --modules sqli,xss,lfi          # Specific modules
oxide --url https://example.com --zeroday --duration 120         # Zero-day ML
oxide --url https://example.com --headless --crawl-depth 5      # JS rendering
oxide --url https://example.com --multiattack                   # Multi-target
oxide --url https://example.com --cookie "session=abc123"       # Authenticated
oxide --url https://example.com --proxy http://127.0.0.1:8080   # Proxy
oxide --list-modules                                             # List modules
oxide -u targets.txt --threads 50                                # From file
```

</div>

---

<div align="left">

[![Scanner Modules](https://img.shields.io/badge/▤_Scanner_Modules-13_Engines-00e676?style=for-the-badge&logo=github&logoColor=ffffff&labelColor=004D40)](https://github.com/HyperSecurityLabs/OxideCE-v7.7.7ELITE)

| Module | Detection |
|--------|-----------|
| **SQLi** | Error, boolean, time, UNION, stacked queries |***MORE RESILIANT***
| **Blind SQLi** | Blind / time-based inference |***MORE RESILIANT***
| **XSS** | Reflected, stored, DOM |***MORE RESILIANT***
| **LFI** | File read confirmation |***MORE RESILIANT***
| **Path Traversal** | Directory traversal |***MORE RESILIANT***
| **CMD Injection** | Linux + Windows commands |***MORE RESILIANT***
| **CORS** | Misconfiguration audit |***REPEARIED LOADING***
| **TLS** | Certificates, protocols, ciphers |***STRONG***
| **Common App** | Nikto-style path probing |
| **Default Creds** | Known admin credentials |***SAME**
| **DB Fingerprint** | MySQL, PG, MSSQL, Oracle, SQLite |***HYBRID-PENETRATION***
| **HPP** | HTTP Parameter Pollution — duplicate-param behavioural analysis |***NEW MODULE***
| **Cloudflare** | WAF detection + bypass |***NEW MODULE***
| **Content Filter** | Regex for keys, tokens, secrets |***IMPROVED**

</div>

---

<div align="left">

[![Zero-Day ML](https://img.shields.io/badge/◉_Zero--Day_ML-Anomaly_Engine-ff6b6b?style=for-the-badge&logo=smart&logoColor=ffffff&labelColor=8B0000)](https://github.com/HyperSecurityLabs/OxideCE-v7.7.7ELITE)

```
Phase 1 ── Crawl (30s)  →  Phase 2 ── ML Analysis + Auto-Exploit
Phase 2.5 ── Fuzz (15 payloads)  →  Phase 2.75 ── HPP Detection  →  Phase 3 ── Report
```

| Component | Library |
|-----------|---------|
| Feature Extraction | Custom |
| Random Forest | `smartcore` |
| SVM | `smartcore` |
| Baseline Profiling | Statistical |
| Anomaly Scoring | Multi-signal |
| Trainer | `--train` flag |

Auto-exploit: SQLi · XSS · LFI · CMDi · SSTI

</div>

---

<div align="left">

[![Advanced](https://img.shields.io/badge/⊡_Advanced-Capabilities-00d4ff?style=for-the-badge&logo=github&logoColor=ffffff&labelColor=006064)](https://github.com/HyperSecurityLabs/OxideCE-v7.7.7ELITE)

**WAF Bypass** — 12 vendors detected · 12 evasion techniques · Origin IP discovery

**Session & Auth** — Cookie, Bearer, Basic, API Key, JWT, OAuth2 · Hijack testing

**JS Crawling** — Headless Chrome · SPA routes · JS URL extraction

**API Fuzzer** — REST + GraphQL · 7 methods · 6 content types

**WebSocket** — SQLi, XSS, CMDi, path traversal, JSON injection, DoS

**Distributed** — Master/worker cluster · TCP heartbeat · Remote execution

**Recon** — TCP fingerprinting · OS detection · Banner grabbing · DNS · WHOIS

</div>

---

<div align="left">

[![CLI Reference](https://img.shields.io/badge/⌘_CLI-Full_Reference-557C94?style=for-the-badge&logo=terminal&logoColor=ffffff&labelColor=1B2A38)](https://github.com/HyperSecurityLabs/OxideCE-v7.7.7ELITE)

| Flag | Default | Purpose |
|------|---------|---------|
| `--url` | required | Target(s) or `-u targets.txt` |
| `--modules` | — | `all` or comma-separated |
| `--zeroday` | false | ML anomaly mode |
| `--multiattack` | false | Concurrent multi-target |
| `--active` | false | TCP fingerprinting (sudo) |
| `--headless` | false | Chrome JS rendering |
| `--resume` | false | Resume from checkpoint |
| `--insta` | false | Instagram OSINT |
| `--session` | false | Session hijack testing |
| `--train` | false | Train ML classifier |
| `--download` | false | Auto-download sensitive files |
| `--threads` | 20 | Concurrency (1–100) |
| `--jobs` | 2 | Crawl workers (1–50) |
| `--duration` | 0 | Time limit (seconds) |
| `--rate-limit` | 0 | Max req/sec |
| `--crawl-depth` | 3 | Crawl depth (max 10) |
| `--max-urls` | 100 | Max URLs (max 10000) |
| `--exploitation-level` | 50 | Aggression (1–100) |
| `--payload-limit` | 50 | Max payloads |

Config: `oxide-config.toml` for persistent settings.

</div>

---

<div align="left">

[![Reports](https://img.shields.io/badge/▥_Reports-Formats-b388ff?style=for-the-badge&logo=github&logoColor=ffffff&labelColor=311B92)](https://github.com/HyperSecurityLabs/OxideCE-v7.7.7ELITE)

| Format | Theme | Use Case |
|--------|-------|----------|
| HTML | Cyberpunk 2077 · scanlines · severity glow | Human review |
| JSON | Machine-parsable | Automation / pipelines |
| CSV | Spreadsheet-ready | Data analysis |
| XML | Standard schema | Tool integration |

Auto-saved to `reports/oxide_<timestamp>.*`

</div>

---

<div align="left">

[![Changelog](https://img.shields.io/badge/☰_Changelog-v7.7.7--elite-00e676?style=for-the-badge&logo=github&logoColor=ffffff&labelColor=004D40)](https://github.com/HyperSecurityLabs/OxideCE-v7.7.7ELITE/releases)

**Added:**
- Zero-Day ML detection engine — standalone anomaly scanning with auto-exploit, HPP (HTTP Parameter Pollution) detection
- HTTP Parameter Pollution (HPP) — duplicate-parameter behavioural analysis
- Fuzz testing phase — 15 payload types · crash/timeout/5xx tracking
- BlazingShadow™ Concurrent Fuzzing — 3 parallel workers via `futures::join_all` + chunk-based URL dispatching
- ELITE Colour Palette — full Kali-themed gradient system (KALI → CYAN → LAVENDER)
- Fuzzing display system — dual braille spinners `[⠋⠏]`, 10-block `▰▱` progress bar, module pipeline `──▶ SQLi→XSS→LFI→...`
- Cyberpunk 2077 HTML report theme with Kali colour scheme
- Auto-save reports (HTML + JSON) to `reports/` directory
- WAF detection during reconnaissance phase
- Per-request timeout (10s) · per-exploit timeout (8s)
- Headless Chrome JS crawling (`--headless`)
- WebSocket fuzzing (SQLi, XSS, CMDi, DoS)
- API fuzzer (REST + GraphQL, 7 methods, 6 content types)
- Distributed cluster scanning (master/worker)
- Instagram OSINT module
- Session hijack testing · scan checkpoint/resume (`--resume`)
- Multi-target concurrent scan (`--multiattack`)

**Changed:**
- Banner gradient: Kali blue-grey → cyan → lavender (full gradient separator + per-line command gradient)
- Fuzzing: replaced sequential URL loop with concurrent chunks(3) + join_all — ~3x speedup
- Spinner display: 20-block `█░` → 10-block `▰▱` module-index-based bar
- Pipeline display: space-separated → `──▶ ` arrow on active module with `→` separators
- Duration timer excludes setup overhead More Capabilty with Proper Timing 
- `--list-modules` added To show in Available Capability Modules


**Fixed:**
- **"Two shows vulns" bug** — findings deduplication via BlazingShadow™ Dedup Engine (dedup by URL + severity + title). Phase 4 scanners no longer overlap with fuzzing results.
- **SSTI removed** — `("SSTI", 6)` removed from `fuzz_modules` and `test_types`; `contains_ssti` function and SSTI match arm deleted; SSTI payload generation removed from `fuzz_url`.
- **Concurrency indentation** — fixed mismatched brace indentation in `fuzz_url` match block ***By LYARA AND OTHER TEAMS***
- Vercel false positive — `server-timing` removed from CF detection
- Duration enforcement — per-request timeouts + `should_continue()` checks
- Panic-safe string slicing across `filter.rs`, `cookies.rs`, `session.rs`, `tls_scanner.rs`

</div>

---

<div align="left">

[![Build](https://img.shields.io/badge/⚙_Build-Release-00d4ff?style=for-the-badge&logo=rust&logoColor=ffffff&labelColor=006064)](https://github.com/HyperSecurityLabs/OxideCE-v7.7.7ELITE)

```bash
cargo build --release        # opt-level=3, LTO=fat, stripped, panic=abort
cargo test                   # run tests
./build-ce-deb.sh            # Debian package
```

```
/                    Main package
├── src/             Source (scanner/, zero_day/, ai/, advanced/, cli/, ...)
├── oxide-proxy/     HTTP + SOCKS4/5 proxy sub-crate
├── hypersecurity/   Kernel memory safety (libloading)
├── oxide-ce-debian/ DEB packaging
└── arch-pkg/        Arch packaging
```

</div>

---

<div align="left">

[![Kali Linux](https://img.shields.io/badge/◈_Kali_Linux-Repository-D2A8FF?style=for-the-badge&logo=kalilinux&logoColor=ffffff&labelColor=1B2A38)](https://www.kali.org/)

OXIDE Community Edition targets inclusion in the official Kali Linux repository to become available via:

```bash
sudo apt update && sudo apt install oxide
```

### Current Progress

| Step | Status |
|------|--------|
| Debian packaging (`oxide-ce-debian/`) | ✅ Complete |
| Arch packaging (`PKGBUILD`) | ✅ Complete |
| Kali colour palette integration | ✅ Complete |
| `pnet` raw socket support (Linux) | ✅ Complete |
| Community testing & validation | ✅ In progress |
| Kali repository submission | ⏳ Pending |

### Why Kali?

- Rust-native performance with `tokio` async runtime
- Complements existing Kali tooling (`sqlmap`, `nmap`, `burpsuite`, `metasploit`)
- ML-based anomaly detection fills the gap traditional scanners miss
- Single binary deployment — no Python dependency hell
- Active recon via raw sockets (`pnet`) for OS fingerprinting

### Support the Effort

[![Issues](https://img.shields.io/badge/⊗_Report_Bugs-ff6b6b?style=for-the-badge&logo=bugatti&logoColor=ffffff&labelColor=8B0000)](https://github.com/HyperSecurityLabs/OxideCE-v7.7.7ELITE/issues)
[![Telegram](https://img.shields.io/badge/✉_Join_Community-b388ff?style=for-the-badge&logo=telegram&logoColor=ffffff&labelColor=4A0072)](https://t.me/hypersecurity_offsec)

Every star brings OXIDE closer to `apt install oxide`. Report bugs, join the community, and help shape the future of open-source security tooling.

</div>

---

<div align="left">

[![Development](https://img.shields.io/badge/❖_Development-Community_Driven-00d4ff?style=for-the-badge&logo=github&logoColor=ffffff&labelColor=006064)](https://github.com/HyperSecurityLabs/OxideCE-v7.7.7ELITE)

OXIDE evolves through **your feedback**. Every feature, fix, and upgrade is shaped by the community — report bugs, suggest features, and vote on priorities.

```
Latest:   v7.7.7-elite — ML engine, fuzzing, WAF bypass, headless JS
Next:     Shaped by you → open issues, feature requests, PRs
Vision:   apt install oxide on Kali Linux
```

[![Issues](https://img.shields.io/badge/⊘_Request_Feature-ff6b6b?style=for-the-badge&logo=bugatti&logoColor=ffffff&labelColor=8B0000)](https://github.com/HyperSecurityLabs/OxideCE-v7.7.7ELITE/issues)
[![Telegram](https://img.shields.io/badge/✎_Give_Feedback-b388ff?style=for-the-badge&logo=telegram&logoColor=ffffff&labelColor=4A0072)](https://t.me/hypersecurity_offsec)

</div>

---

<div align="center">

[![Star](https://img.shields.io/badge/★_Star_on_GitHub-Support-58A6FF?style=for-the-badge&logo=github&logoColor=000000&labelColor=0D1117)](https://github.com/HyperSecurityLabs/OxideCE-v7.7.7ELITE)
[![Website](https://img.shields.io/badge/▲_Website-HyperSec-00E676?style=for-the-badge&logo=google-chrome&logoColor=000000&labelColor=005B47)](https://hypersecurityoffensivelabs-about.is-best.net/)
[![Telegram](https://img.shields.io/badge/☏_Telegram-Community-64D2FF?style=for-the-badge&logo=telegram&logoColor=000000&labelColor=1B2A38)](https://t.me/hypersecurity_offsec)
[![Forums](https://img.shields.io/badge/⋄_Forums-Community-00AE86?style=for-the-badge&logo=discourse&logoColor=000000&labelColor=004D40)](https://hypersecurityoffensivelabs-about.is-best.net/forums/index.php)

**Built for Kali Linux · Targeting Official Repository Inclusion**

---

<div align="center">

# ♛ ЛЯРА-Королева ♛

## Королева эстетики, архитектор визуального стиля OXIDE

**Дизайнер · Архитектор интерфейсов · Художник кибербезопасности**

[![Lyara-Koroleva](https://img.shields.io/badge/♛_Ляра--Королева-F3E5F5?style=for-the-badge&logo=pinboard&logoColor=000000&labelColor=2A0052)](https://github.com/lyara20/About.Me)

**ЛЯРА-Королева** — гений визуального дизайна и архитектор пользовательского опыта OXIDE. Её эстетическое чутьё превратило суровый сканер уязвимостей в произведение цифрового искусства. Каждый пиксель, каждый оттенок, каждая анимация в OXIDE несёт на себе отпечаток её безупречного вкуса.

### Вклад ЛЯРЫ-Королевой в OXIDE

- **Палитра ELITE** — полностью кастомная цветовая палитра Kali Linux Theme
- **BlazingShadow™ Architecture** — параллельный фаззинг с `futures::join_all`
- **Фаззинг-дисплей** — braille-спиннеры, прогресс-бар, конвейер модулей
- **Градиентный баннер** — система градиентов KALI ▸ CYAN ▸ LAVENDER
- **HPP Detection** — HTTP Parameter Pollution модуль для Zero-Day движка
- **Severity-кодирование** — цветовое кодирование уровней опасности
- **HTML-отчёты** — Cyberpunk 2077 тема с scanlines и severity glow
- **UX-дизайн CLI** — расположение элементов, порядок вывода, форматирование

> *"Красота — это не опция, это стандарт."*

</div>


