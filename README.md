# OxideCE-v7.7.7ELITE

Open eXtensible Intelligence & Detection Engine — AI-Powered · Red Team · Kali Linux Ready
```bash

   ____       _     __   
  / __ \_  __(_)___/ /__ 
 / / / / |/_/ / __  / _ \
/ /_/ />  </ / /_/ /  __/
\____/_/|_/_/\__,_/\___/ 

 OXIDE Community Edition v7.7.7-elite
 Open eXtensible Intelligence & Detection Engine
 Built for Kali Linux · Targeting Official Repository Inclusion

 Active development by khaninkali @ HyperSecurity Offensive Labs
 Contributions, bug reports, and community feedback welcome.
```
<div align="center">
Contributions, bug reports, and community feedback welcome.*

[![Forums](https://img.shields.io/badge/Forums-Community-00C8B4?style=for-the-badge&logo=discourse&logoColor=000000)](https://hypersecurityoffensivelabs-about.is-best.net/forums/index.php)
[![Rust](https://img.shields.io/badge/Rust-2021%20Edition-00e676?style=for-the-badge&logo=rust&logoColor=ffffff)](https://www.rust-lang.org/)
[![Issues](https://img.shields.io/badge/Issues-Report-f6c177?style=for-the-badge&logo=bugatti&logoColor=000000)](https://github.com/HyperSecurityLabs/OxideCE-v7.7.7ELITE/issues)
[![Releases](https://img.shields.io/badge/Releases-Download-557C94?style=for-the-badge&logo=github&logoColor=ffffff)](https://github.com/HyperSecurityLabs/OxideCE-v7.7.7ELITE/releases)
[![GitHub](https://img.shields.io/badge/GitHub-OxideCE--v7.7.7ELITE-557C94?style=for-the-badge&logo=github&logoColor=ffffff)](https://github.com/HyperSecurityLabs/OxideCE-v7.7.7ELITE)
[![Website](https://img.shields.io/badge/Website-HyperSecurity%20Labs-00d4ff?style=for-the-badge&logo=google-chrome&logoColor=ffffff)](https://hypersecurityoffensivelabs-about.is-best.net/)
[![Telegram](https://img.shields.io/badge/Telegram-@hypersecurity__offsec-b388ff?style=for-the-badge&logo=telegram&logoColor=ffffff)](https://t.me/hypersecurity_offsec)
<br>
[![Kali Linux](https://img.shields.io/badge/Kali_Linux-Ready-367bf0?style=for-the-badge&logo=kalilinux&logoColor=ffffff)](https://www.kali.org/)

</div>

**OXIDE Community Edition — v7.7.7-elite** · Open eXtensible Intelligence & Detection Engine · AI-Powered · Kali Linux Ready

> **⭐ Support OXIDE for Kali Linux Official Repository** — Star on GitHub to help bring to Kali.

---

[![About](https://img.shields.io/badge/About-OXIDE-557C94?style=for-the-badge&logo=github&logoColor=ffffff)](https://github.com/HyperSecurityLabs/OxideCE-v7.7.7ELITE)

Modular security toolkit combining traditional vulnerability scanning with ML-based anomaly detection. Built in Rust for Kali Linux.

| Component | Technology |
|-----------|-----------|
| Language | Rust 2021 Edition |
| Runtime | `tokio` async |
| ML | `smartcore`, `linfa`, `ndarray`, `statrs` |
| Reports | HTML (Cyberpunk) · JSON · CSV · XML |
| Transport | reqwest (gzip + brotli) |

---

[![Kali Linux](https://img.shields.io/badge/Kali_Linux-Integration-367bf0?style=for-the-badge&logo=kalilinux&logoColor=ffffff)](https://www.kali.org/)

```
Active Recon (pnet)  →  src/recon.rs          #[cfg(target_os = "linux")]
Kali Colour Palette  →  src/cli/display.rs    ELITE_KALI #557C94
DEB Packaging        →  oxide-ce-debian/
Arch Packaging       →  PKGBUILD
```

Complements `sqlmap` · `nmap` · `burpsuite` · `metasploit`

---

[![Installation](https://img.shields.io/badge/Installation-Quick_Start-00d4ff?style=for-the-badge&logo=terminal&logoColor=ffffff)](https://github.com/HyperSecurityLabs/OxideCE-v7.7.7ELITE)

```bash
sudo apt install -y build-essential pkg-config libssl-dev cmake
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"

git clone https://github.com/HyperSecurityLabs/OxideCE-v7.7.7ELITE.git
cd OxideCE-v7.7.7ELITE && cargo build --release
sudo cp target/release/oxide /usr/local/bin/

oxide --version   # → oxide 7.7.7-elite
```

---

[![Usage](https://img.shields.io/badge/Usage-Reference-b388ff?style=for-the-badge&logo=terminal&logoColor=ffffff)](https://github.com/HyperSecurityLabs/OxideCE-v7.7.7ELITE)

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

---

[![Scanner Modules](https://img.shields.io/badge/Scanner_Modules-13_Engines-00e676?style=for-the-badge&logo=github&logoColor=ffffff)](https://github.com/HyperSecurityLabs/OxideCE-v7.7.7ELITE)

| Module | Detection |
|--------|-----------|
| **SQLi** | Error, boolean, time, UNION, stacked queries |
| **Blind SQLi** | Blind / time-based inference |
| **XSS** | Reflected, stored, DOM |
| **LFI** | File read confirmation |
| **Path Traversal** | Directory traversal |
| **CMD Injection** | Linux + Windows commands |
| **CORS** | Misconfiguration audit |
| **TLS** | Certificates, protocols, ciphers |
| **Common App** | Nikto-style path probing |
| **Default Creds** | Known admin credentials |
| **DB Fingerprint** | MySQL, PG, MSSQL, Oracle, SQLite |
| **Cloudflare** | WAF detection + bypass |
| **Content Filter** | Regex for keys, tokens, secrets |

---

[![Zero-Day ML](https://img.shields.io/badge/Zero--Day_ML-Anomaly_Engine-ff6b6b?style=for-the-badge&logo=smart&logoColor=ffffff)](https://github.com/HyperSecurityLabs/OxideCE-v7.7.7ELITE)

```
Phase 1 ── Crawl (30s)  →  Phase 2 ── ML Analysis + Auto-Exploit
Phase 2.5 ── Fuzz (15 payloads)  →  Phase 3 ── Report
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

---

[![Advanced](https://img.shields.io/badge/Advanced-Capabilities-00d4ff?style=for-the-badge&logo=github&logoColor=ffffff)](https://github.com/HyperSecurityLabs/OxideCE-v7.7.7ELITE)

**WAF Bypass** — 12 vendors detected · 12 evasion techniques · Origin IP discovery

**Session & Auth** — Cookie, Bearer, Basic, API Key, JWT, OAuth2 · Hijack testing

**JS Crawling** — Headless Chrome · SPA routes · JS URL extraction

**API Fuzzer** — REST + GraphQL · 7 methods · 6 content types

**WebSocket** — SQLi, XSS, CMDi, path traversal, JSON injection, DoS

**Distributed** — Master/worker cluster · TCP heartbeat · Remote execution

**Active-Recon(Root)** — TCP fingerprinting · OS detection · Banner grabbing · DNS · WHOIS

---

[![CLI Reference](https://img.shields.io/badge/CLI-Full_Reference-557C94?style=for-the-badge&logo=terminal&logoColor=ffffff)](https://github.com/HyperSecurityLabs/OxideCE-v7.7.7ELITE)

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
| `--proxy` | — | HTTP proxy |
| `--cookie` | — | Session cookie |
| `--header` | — | Custom headers |
| `--user-agent` | — | Custom UA |
| `--output` | — | Report path |
| `--format` | json | json/html/csv/xml |
| `--insecure` | false | Skip SSL verify |
| `--follow-redirects` | false | Follow redirects |
| `--max-redirects` | 10 | Redirect limit |
| `--silent-mode` | false | Quiet output |
| `--verbose` | false | Detailed output |
| `--list-modules` | — | List modules & exit |
| `--exclude` | — | Skip modules |

Config: `oxide-config.toml` for persistent settings.

---

[![Reports](https://img.shields.io/badge/Reports-Formats-b388ff?style=for-the-badge&logo=github&logoColor=ffffff)](https://github.com/HyperSecurityLabs/OxideCE-v7.7.7ELITE)

| Format | Theme | Use Case |
|--------|-------|----------|
| HTML | Cyberpunk 2077 · scanlines · severity glow | Human review |
| JSON | Machine-parsable | Automation / pipelines |
| CSV | Spreadsheet-ready | Data analysis |
| XML | Standard schema | Tool integration |

Auto-saved to `reports/oxide_<timestamp>.*`

---

[![Changelog](https://img.shields.io/badge/Changelog-v7.7.7--elite-00e676?style=for-the-badge&logo=github&logoColor=ffffff)](https://github.com/HyperSecurityLabs/OxideCE-v7.7.7ELITE/releases)

**Added:**
- Zero-Day ML detection engine — standalone anomaly scanning with auto-exploit
- Fuzz testing phase — 15 payload types · crash/timeout/5xx tracking
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
- Banner gradient: Kali blue-grey → cyan → lavender
- Duration timer excludes setup overhead
- `--list-modules` no longer requires `--url`

**Fixed:**
- Ctrl+C responsiveness — polls shutdown every 200ms
- Duration enforcement — per-request timeouts + `should_continue()` checks
- Panic-safe string slicing across `filter.rs`, `cookies.rs`, `session.rs`, `tls_scanner.rs`

---

[![Build](https://img.shields.io/badge/Build-Release-00d4ff?style=for-the-badge&logo=rust&logoColor=ffffff)](https://github.com/HyperSecurityLabs/OxideCE-v7.7.7ELITE)

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

---

---

[![Kali Linux](https://img.shields.io/badge/Kali_Linux-Official_Repository_Integration-367bf0?style=for-the-badge&logo=kalilinux&logoColor=ffffff)](https://www.kali.org/)

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

[![Star](https://img.shields.io/badge/Star_on_GitHub-Support-557C94?style=for-the-badge&logo=github&logoColor=ffffff)](https://github.com/HyperSecurityLabs/OxideCE-v7.7.7ELITE)
[![Issues](https://img.shields.io/badge/Report_Bugs-ff6b6b?style=for-the-badge&logo=bugatti&logoColor=ffffff)](https://github.com/HyperSecurityLabs/OxideCE-v7.7.7ELITE/issues)
[![Telegram](https://img.shields.io/badge/Join_Community-b388ff?style=for-the-badge&logo=telegram&logoColor=ffffff)](https://t.me/hypersecurity_offsec)

Every star brings OXIDE closer to `apt install oxide`. Report bugs, join the community, and help shape the future of open-source security tooling.

---

---

[![Development](https://img.shields.io/badge/Development-Community_Driven-00d4ff?style=for-the-badge&logo=github&logoColor=ffffff)](https://github.com/HyperSecurityLabs/OxideCE-v7.7.7ELITE)

OXIDE evolves through **your feedback**. Every feature, fix, and upgrade is shaped by the community — report bugs, suggest features, and vote on priorities.

```
Latest:   v7.7.7-elite — ML engine, fuzzing, WAF bypass, headless JS
Next:     Shaped by you → open issues, feature requests, PRs
Vision:   apt install oxide on Kali Linux
```
---

<div align="center">

[![Star](https://img.shields.io/badge/⭐_Star_on_GitHub-BEAFEB?style=for-the-badge&logo=github&logoColor=000000)](https://github.com/HyperSecurityLabs/OxideCE-v7.7.7ELITE)
[![Website](https://img.shields.io/badge/⎈_Website-64D2FF?style=for-the-badge&logo=google-chrome&logoColor=000000)](https://hypersecurityoffensivelabs-about.is-best.net/)
[![Telegram](https://img.shields.io/badge/✉_Telegram-64AAFF?style=for-the-badge&logo=telegram&logoColor=000000)](https://t.me/hypersecurity_offsec)
[![Forums](https://img.shields.io/badge/⎈_Community_Forums-00C8B4?style=for-the-badge&logo=discourse&logoColor=000000)](https://hypersecurityoffensivelabs-about.is-best.net/forums/index.php)
[![Rust](https://img.shields.io/badge/⚙_Download_Rust-00B478?style=for-the-badge&logo=rust&logoColor=000000)](https://www.rust-lang.org/)

**Built for Kali Linux · Targeting Official Repository Inclusion**

</div>
<p align="center">
  <img src="https://img.shields.io/badge/⚠%20Legal%20Disclaimer-557C94?style=for-the-badge&labelColor=1a1a2e" alt="Legal Disclaimer"/>
</p>

1. **Authorized use only** — You must have explicit permission before scanning any system.
2. **Legal compliance** — You are responsible for following all applicable laws.
3. **No warranty** — This software is provided "as is" with no liability.
4. **Attribution** — Author name (khaninkali) and HyperSecurityLabs brand must remain intact.

---
<p align="center">
  <a href="https://github.com/HyperSecurityLabs/OxideCE-v7.7.7ELITE/issues"><img src="https://img.shields.io/badge/Report%20Issue-64D2FF?style=for-the-badge&logo=github&logoColor=white" alt="Report Issue"/></a>
  <br>
  <sub>Found a bug or security concern? Let us know.</sub>
</p>
<p align="center">
  <a href="https://github.com/HyperSecurityLabs/OxideCE-v7.7.7ELITE/security/policy"><img src="https://img.shields.io/badge/Security%20Policy-BEAFEB?style=for-the-badge&logo=shield&logoColor=white" alt="Security Policy"/></a>
  <br>
  <sub>Our responsible disclosure and security procedures.</sub>
</p>
