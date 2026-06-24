# OXIDE-v8.5.0-community-edition
**Precision-forged Rust vulnerability scanner**  
*HyperSecurity Offensive Labs · ALLAH L S T*  
*Forged by HyperSecurityLabs · Unleash the hunt.*
*⚔️ Zero-Day · ML Anomaly Engine · WAF Massacre · Headless DOM · Distributed Cluster.*

[![GUI](https://img.shields.io/badge/⟡_GUI-Launch_OXIDE-FF2D95?style=for-the-badge&logo=electron&logoColor=000000&labelColor=6A0032)](https://github.com/HyperSecurityLabs/oxide-communityedition-v8.5.0/releases)
[![Forums](https://img.shields.io/badge/◆_Forums-Community-00AE86?style=for-the-badge&logo=discourse&logoColor=000000&labelColor=004D40)](https://hypersecurityoffensivelabs-about.is-best.net/forums/index.php)
[![Rust](https://img.shields.io/badge/●_Rust-2021-FF8A65?style=for-the-badge&logo=rust&logoColor=000000&labelColor=B71C1C)](https://www.rust-lang.org/)
[![Platform](https://img.shields.io/badge/■_Platform-Win│Linux-4DB6AC?style=for-the-badge&logo=linux&logoColor=ffffff&labelColor=1A1A2E)](https://github.com/HyperSecurityLabs/oxide-communityedition-v8.5.0)
[![Downloads](https://img.shields.io/badge/⬇_Downloads-v8.5.0-333333?style=for-the-badge&logo=github&logoColor=000000&labelColor=FFFFFF)](https://github.com/HyperSecurityLabs/oxide-communityedition-v8.5.0/releases)
[![Website](https://img.shields.io/badge/▲_Website-HyperSec-00E676?style=for-the-badge&logo=google-chrome&logoColor=000000&labelColor=005B47)](https://hypersecurityoffensivelabs-about.is-best.net/)
[![Kali](https://img.shields.io/badge/★_Kali_Linux-Ready-557C94?style=for-the-badge&logo=kalilinux&logoColor=ffffff&labelColor=1B2A38)](https://www.kali.org/)
[![Warning](https://img.shields.io/badge/‼_Warning-Authorized-FF6B35?style=for-the-badge&logo=bugatti&logoColor=000000&labelColor=8B0000)](https://github.com/HyperSecurityLabs/oxide-communityedition-v8.5.0/issues)
[![Lyara](https://img.shields.io/badge/♛_Lyara-Designer-CE93D8?style=for-the-badge&logo=pinboard&logoColor=000000&labelColor=4A0072)](https://github.com/lyara20/About.Me)

</div>

> Every star brings OXIDE closer to sudo apt install oxide. Built for Kali, tested on Kali — destined for the official Kali Linux repositories.

---

[![About](https://img.shields.io/badge/◈_About-OXIDE-557C94?style=for-the-badge&logo=github&logoColor=ffffff&labelColor=1B2A38)](https://github.com/HyperSecurityLabs/oxide-communityedition-v8.5.0)

Modular security toolkit combining traditional vulnerability scanning with ML-based anomaly detection. Built in Rust for Kali Linux.

[![Rust](https://img.shields.io/badge/◎_Rust_2021-FF8A65?style=for-the-badge&logo=rust&logoColor=000000&labelColor=B71C1C)](https://www.rust-lang.org/)
[![Runtime](https://img.shields.io/badge/▶_tokio_async-26A69A?style=for-the-badge&labelColor=004D40)](https://tokio.rs/)
[![ML](https://img.shields.io/badge/◇_ML_Stack-7E57C2?style=for-the-badge&labelColor=311B92)](https://github.com/HyperSecurityLabs/oxide-communityedition-v8.5.0)
[![Reports](https://img.shields.io/badge/▣_Reports_Multi-FF7043?style=for-the-badge&labelColor=BF360C)](https://github.com/HyperSecurityLabs/oxide-communityedition-v8.5.0)

---

[![Installation](https://img.shields.io/badge/⌨_Installation-Quick_Start-00d4ff?style=for-the-badge&logo=terminal&logoColor=ffffff&labelColor=004D40)](https://github.com/HyperSecurityLabs/oxide-communityedition-v8.5.0)

```bash
sudo apt install -y build-essential pkg-config libssl-dev cmake
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
git clone https://github.com/HyperSecurityLabs/oxide-communityedition-v8.5.0.git
cd OxideCE-v8.5.0COMMUNITY && cargo build --release
sudo cp target/release/oxide /usr/local/bin/
```

---

[![Usage](https://img.shields.io/badge/⊞_Usage-Reference-b388ff?style=for-the-badge&logo=terminal&logoColor=ffffff&labelColor=311B92)](https://github.com/HyperSecurityLabs/oxide-communityedition-v8.5.0)

```bash
oxide --url https://example.com --modules all --duration 120    # Full scan
oxide --url https://example.com --modules sqli,xss,lfi          # Specific modules
oxide --url https://example.com --zeroday --duration 120         # Zero-day ML
oxide --url https://example.com --headless --crawl-depth 5      # JS rendering
oxide --url https://example.com --multiattack                   # Multi-target
oxide -u targets.txt --threads 50                                # From file
```

---

[![Scanner Modules](https://img.shields.io/badge/▤_Scanner_Modules-13_Engines-00e676?style=for-the-badge&logo=github&logoColor=ffffff&labelColor=004D40)](https://github.com/HyperSecurityLabs/oxide-communityedition-v8.5.0)

| Module | Detection | Module | Detection |
|--------|-----------|--------|-----------|
| **SQLi** | Error, boolean, time, UNION, stacked | **Blind SQLi** | Blind / time-based |
| **XSS** | Reflected, stored, DOM | **LFI** | File read confirmation |
| **Path Traversal** | Directory traversal | **CMD Injection** | Linux + Windows |
| **CORS** | Misconfiguration audit | **TLS** | Certs, protocols, ciphers |
| **Common App** | Nikto-style path probing | **Default Creds** | Known admin creds |
| **DB Fingerprint** | MySQL, PG, MSSQL, Oracle, SQLite | **Content Filter** | Keys, tokens, secrets |

---

[![Zero-Day ML](https://img.shields.io/badge/◉_Zero--Day_ML-Anomaly_Engine-ff6b6b?style=for-the-badge&logo=smart&logoColor=ffffff&labelColor=8B0000)](https://github.com/HyperSecurityLabs/oxide-communityedition-v8.5.0)

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

[![Advanced](https://img.shields.io/badge/⊡_Advanced-Capabilities-00d4ff?style=for-the-badge&logo=github&logoColor=ffffff&labelColor=006064)](https://github.com/HyperSecurityLabs/oxide-communityedition-v8.5.0)

**Session & Auth** — Cookie, Bearer, Basic, API Key, JWT, OAuth2 · Hijack testing
**JS Crawling** — Headless Chrome · SPA routes · JS URL extraction
**API Fuzzer** — REST + GraphQL · 7 methods · 6 content types
**WebSocket** — SQLi, XSS, CMDi, path traversal, JSON injection, DoS
**Distributed** — Master/worker cluster · TCP heartbeat · Remote execution
**Recon** — TCP fingerprinting · OS detection · Banner grabbing · DNS · WHOIS

---

[![GUI Frontend](https://img.shields.io/badge/🖥_GUI_Frontend-Desktop_App-ff1744?style=for-the-badge&logo=electron&logoColor=ffffff&labelColor=4A0000)](https://github.com/HyperSecurityLabs/oxide-communityedition-v8.5.0)

Native desktop GUI built with **WRY** (WebView2/WebKit) + **TAO** (windowing). Frameless window, scan presets, config panel, module toggles, live terminal console, status badge, About modal. Keyboard shortcuts: `Ctrl+Enter` start, `Escape` stop, `F12` DevTools.

```bash
cd gui && cargo build --release && sudo cp target/release/oxide-gui /usr/local/bin/ && oxide-gui
```

---

[![CLI Reference](https://img.shields.io/badge/⌘_CLI-Full_Reference-557C94?style=for-the-badge&logo=terminal&logoColor=ffffff&labelColor=1B2A38)](https://github.com/HyperSecurityLabs/oxide-communityedition-v8.5.0)

| Flag | Default | Purpose | Flag | Default | Purpose |
|------|---------|---------|------|---------|---------|
| `--url` | required | Target(s) or file | `--modules` | — | `all` or comma-sep |
| `--zeroday` | false | ML anomaly mode | `--multiattack` | false | Multi-target |
| `--active` | false | TCP fingerprinting | `--headless` | false | Chrome JS |
| `--resume` | false | Resume checkpoint | `--insta` | false | Instagram OSINT |
| `--session` | false | Session hijack | `--train` | false | Train ML |
| `--download` | false | Auto-download | `--threads` | 50 | Concurrency |
| `--jobs` | 2 | Crawl workers | `--duration` | 0 | Time limit (s) |
| `--rate-limit` | 0 | Max req/sec | `--crawl-depth` | 3 | Crawl depth |
| `--max-urls` | 100 | Max URLs | `--exploitation-level` | 75 | Aggression |
| `--payload-limit` | 100 | Max payloads | `--proxy` | — | HTTP proxy |
| `--output` | — | Report path | `--format` | json | json/html/csv/xml |
| `--insecure` | false | Skip SSL verify | `--verbose` | false | Detailed output |

Config: `oxide-config.toml` for persistent settings.

---

[![Reports](https://img.shields.io/badge/▥_Reports-Formats-b388ff?style=for-the-badge&logo=github&logoColor=ffffff&labelColor=311B92)](https://github.com/HyperSecurityLabs/oxide-communityedition-v8.5.0)

| Format | Theme | Use Case |
|--------|-------|----------|
| HTML | Cyberpunk · scanlines · severity glow | Human review |
| JSON | Machine-parsable | Automation / pipelines |
| CSV | Spreadsheet-ready | Data analysis |
| XML | Standard schema | Tool integration |

Auto-saved to `reports/oxide_<timestamp>.*`

---

[![Changelog](https://img.shields.io/badge/☰_Changelog-v8.5.0--community-00e676?style=for-the-badge&logo=github&logoColor=ffffff&labelColor=004D40)](https://github.com/HyperSecurityLabs/oxide-communityedition-v8.5.0/releases)

**Added:**
- Zero-Day ML engine — standalone anomaly scanning, auto-exploit, HPP detection
- Fuzz testing (15 payload types) · BlazingShadow™ concurrent fuzzing (3 workers, `futures::join_all`)
- GUI desktop app — WRY + TAO, frameless window, scan presets, live console
- Bayesian fusion scorer — Levenshtein + n-gram cosine → Bayes confidence (0.65 threshold) for UNION/boolean SQLi & CMDi detection
- False-positive reduction — evidence-chain confidence gate (0.7), per-type confirm heuristics, asymmetric response check for boolean SQLi
- AES-256-GCM database encryption (replaced XOR), path-allowlisted plugin loading, headless URL sanitization
- ELITE colour palette (KALI → CYAN → LAVENDER), Cyberpunk HTML reports, dual braille spinners, 10-block progress bar
- Headless Chrome JS crawling, WebSocket fuzzing, API fuzzer (REST + GraphQL), distributed cluster scanning
- Instagram OSINT module, session hijack testing, scan checkpoint/resume
- Multi-target concurrent scan, WAF detection (12 vendors, 12 evasion techniques)

**Changed:**
- Banner gradient: Kali blue-grey → cyan → lavender with full gradient separator
- Fuzzing: sequential URL loop → concurrent chunks(3) + `join_all` (~3x speedup)
- `--threads` default 20→50, `--exploitation-level` 50→75, `--payload-limit` 50→100
- Duration timer excludes setup overhead, `--list-modules` no longer requires `--url`
- Rebranded to `8.5.0-community-edition`

**Fixed:**
- Findings deduplication via BlazingShadow™ Dedup Engine (URL + severity + title)
- SSTI removed from fuzz modules, Ctrl+C responsiveness (200ms poll), Vercel false positive
- Duration enforcement, panic-safe string slicing across filter, cookies, session, TLS scanner

---

[![Build](https://img.shields.io/badge/⚙_Build-Release-00d4ff?style=for-the-badge&logo=rust&logoColor=ffffff&labelColor=006064)](https://github.com/HyperSecurityLabs/oxide-communityedition-v8.5.0)

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

[![Kali Linux](https://img.shields.io/badge/◈_Kali_Linux-Repository-D2A8FF?style=for-the-badge&logo=kalilinux&logoColor=ffffff&labelColor=1B2A38)](https://www.kali.org/)

Targeting official Kali Linux repository: `sudo apt update && sudo apt install oxide`

| Step | Status |
|------|--------|
| Debian/Arch packaging | ✅ Complete |
| Kali colour palette | ✅ Complete |
| `pnet` raw socket support | ✅ Complete |
| Community testing | ✅ In progress |
| Kali submission | ⏳ Pending |

**Why Kali?** Rust-native (`tokio`), complements `sqlmap`/`nmap`/`burpsuite`/`metasploit`, ML anomaly detection, single binary, active recon via `pnet`.

[![Issues](https://img.shields.io/badge/⊗_Report_Bugs-ff6b6b?style=for-the-badge&logo=bugatti&logoColor=ffffff&labelColor=8B0000)](https://github.com/HyperSecurityLabs/oxide-communityedition-v8.5.0/issues)
[![Telegram](https://img.shields.io/badge/✉_Join_Community-b388ff?style=for-the-badge&logo=telegram&logoColor=ffffff&labelColor=4A0072)](https://t.me/hypersecurity_offsec)

---

[![Development](https://img.shields.io/badge/❖_Development-Community_Driven-00d4ff?style=for-the-badge&logo=github&logoColor=ffffff&labelColor=006064)](https://github.com/HyperSecurityLabs/oxide-communityedition-v8.5.0)

```
Latest:   v8.5.0community-edition — ML engine, fuzzing, WAF bypass, headless JS, GUI
Next:     Shaped by you → open issues, feature requests, PRs
Vision:   apt install oxide on Kali Linux
```

[![Issues](https://img.shields.io/badge/⊘_Request_Feature-ff6b6b?style-for-the-badge&logo=bugatti&logoColor=ffffff&labelColor=8B0000)](https://github.com/HyperSecurityLabs/oxide-communityedition-v8.5.0/issues)
[![Telegram](https://img.shields.io/badge/✎_Give_Feedback-b388ff?style=for-the-badge&logo=telegram&logoColor=ffffff&labelColor=4A0072)](https://t.me/hypersecurity_offsec)

---

<div align="center">

[![Star](https://img.shields.io/badge/★_Star_on_GitHub-Support-58A6FF?style=for-the-badge&logo=github&logoColor=000000&labelColor=0D1117)](https://github.com/HyperSecurityLabs/oxide-communityedition-v8.5.0)
[![Website](https://img.shields.io/badge/▲_Website-HyperSec-00E676?style=for-the-badge&logo=google-chrome&logoColor=000000&labelColor=005B47)](https://hypersecurityoffensivelabs-about.is-best.net/)
[![Telegram](https://img.shields.io/badge/☏_Telegram-Community-64D2FF?style=for-the-badge&logo=telegram&logoColor=000000&labelColor=1B2A38)](https://t.me/hypersecurity_offsec)
[![Forums](https://img.shields.io/badge/⋄_Forums-Community-00AE86?style=for-the-badge&logo=discourse&logoColor=000000&labelColor=004D40)](https://hypersecurityoffensivelabs-about.is-best.net/forums/index.php)

**Built for Kali Linux · Targeting Official Repository Inclusion**

---

# ♛ ЛЯРА-Королева ♛

**Дизайнер · Архитектор интерфейсов** — Королева эстетики OXIDE, architect of the ELITE colour palette, gradient system, braille spinners, HTML report theme.

[![Lyara-Koroleva](https://img.shields.io/badge/♛_Ляра--Королева-F3E5F5?style=for-the-badge&logo=pinboard&logoColor=000000&labelColor=2A0052)](https://github.com/lyara20/About.Me)

> *"Красота — это не опция, это стандарт."*

</div>
