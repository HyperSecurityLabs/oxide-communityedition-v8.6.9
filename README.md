
# OXIDE-v8.6.9-Community-Edition
**Precision-forged Rust vulnerability scanner**  
*HyperSecurity Offensive Labs ·*   
Levershin FP Reduction · Zero-Day ML Anomaly Engine · WAF Massacre · Headless DOM · Distributed Cluster · 和色 Palette

<img width="1440" height="900" alt="Screenshot_2026-07-01_12_38_54" src="https://github.com/user-attachments/assets/fb7e854a-b362-443b-b447-8fce97dd0311" />

[![GUI](https://img.shields.io/badge/_GUI-Launch_OXIDE-E83929?style=for-the-badge&logo=electron&logoColor=000&labelColor=FFE8E0)](https://github.com/HyperSecurityLabs/oxide-communityedition-v8.6.9/releases)
[![Forums](https://img.shields.io/badge/_Forums-Community-8BB85C?style=for-the-badge&logo=discourse&logoColor=000&labelColor=EDF5E0)](https://hypersecurityoffseclabs.great-site.net/forums/index.php)
[![Rust](https://img.shields.io/badge/_Rust-2021-F7D7D9?style=for-the-badge&logo=rust&logoColor=000&labelColor=FFF0F0)](https://www.rust-lang.org/)
[![Platform](https://img.shields.io/badge/_Platform-WinLinux-2EA9DF?style=for-the-badge&logo=linux&logoColor=000&labelColor=E8F4FD)](https://github.com/HyperSecurityLabs/oxide-communityedition-v8.6.9)
[![ML](https://img.shields.io/badge/_ML_Stack-5B6ABF?style=for-the-badge&labelColor=EDEAF8)](https://github.com/HyperSecurityLabs/oxide-communityedition-v8.6.9)
[![Downloads](https://img.shields.io/badge/_Downloads-v8.6.9-91989F?style=for-the-badge&logo=github&logoColor=000&labelColor=F0F0F0)](https://github.com/HyperSecurityLabs/oxide-communityedition-v8.6.9/releases)
[![Kali](https://img.shields.io/badge/_Kali_Linux-Ready-165E83?style=for-the-badge&logo=kalilinux&logoColor=000&labelColor=E8F0F8)](https://www.kali.org/)
[![Warning](https://img.shields.io/badge/‼_Warning-Authorized-D7003A?style=for-the-badge&logo=bugatti&logoColor=000&labelColor=FFF0F0)](https://github.com/HyperSecurityLabs/oxide-communityedition-v8.6.9/issues)


</div>


> Every star brings OXIDE closer to `sudo apt install oxide`. Built for Kali, tested on Kali — destined for the official Kali Linux repositories.

---
[![Levershin](https://img.shields.io/badge/_Levershin-FP_Reduction-884898?style=for-the-badge&logo=trustpilot&logoColor=000&labelColor=F0E8F2)](https://github.com/HyperSecurityLabs/oxide-communityedition-v8.6.9/issues)

OXIDE's **Levershin engine** is a multi-stage false positive reduction system that validates every detection before it reaches the report. Instead of flooding you with raw alerts, Levershin cross-references each finding against response behavior, timing patterns, and confirmation probes — silently discarding phantom positives while elevating verified vulnerabilities.

---

[![About](https://img.shields.io/badge/_About-OXIDE-165E83?style=for-the-badge&logo=github&logoColor=000&labelColor=E8F0F8)](https://github.com/HyperSecurityLabs/oxide-communityedition-v8.6.9)

Modular security toolkit combining traditional vulnerability scanning with ML-based anomaly detection. Built in Rust for Kali Linux.

[![Rust](https://img.shields.io/badge/_Rust_2021-E83929?style=for-the-badge&logo=rust&logoColor=000&labelColor=FFE8E0)](https://www.rust-lang.org/)
[![Reports](https://img.shields.io/badge/_Reports_Multi-FFB11B?style=for-the-badge&labelColor=FFF8E0)](https://github.com/HyperSecurityLabs/oxide-communityedition-v8.6.9)

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
**WebSocket** — SQLi, XSS, CMDi, path traversal, JSON injection, DoS
**Distributed** — Master/worker cluster · TCP heartbeat · Remote execution
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

**v8.6.9 — 和色 (Washoku) Edition:**

**Added:**
- Pure Japanese washoku colour palette — 朱/Shu, 紅/Kurenai, 金/Kin, 山吹/Yamabuki, 翡翠/Hisui, 若葉/Wakaba, 露草/Tsuyukusa, 藍/Ai, 桔梗/Kikyo, 藤/Fuji, 菫/Sumire, 桜/Sakura, 銀/Gin, 銅/Akagane, 漆黒/Shikkoku
- 全モジュール and 色統一 — all scanner modules now render in Japanese washoku
- Banner gradient: 翡翠→若葉→露草 with 和色 designer credit
- Levershin false positive reduction — behavioural, timing, and re-probe filtering pipeline
- GUI CyberPunk2077 interface — 和色 theme: 露草/藤/朱/若葉/山吹 palette replacing Gruvbox
- New 朱 red Rust logo badge in documentation

**Changed:**
- Replaced entire ELITE / Rosé Pine / Osaka-Jade / Lavender colour system with pure Japanese washoku palette across 13 scanner modules, CLI display, advanced modules, and zero-day engine
- Banner palette switched to 翡翠→若葉→露草 gradient (was 藍→露草→藤)
- `--version` updated to `v8.6.9-community-edition`
- Added Socket2
- More stable optimization with HyperSecurity Promize
- More High Performance with Modern Async/Await

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

[![Development](https://img.shields.io/badge/_Development-Community_Driven-2EA9DF?style=for-the-badge&logo=github&logoColor=000&labelColor=E8F4FD)](https://github.com/HyperSecurityLabs/oxide-communityedition-v8.6.9)

```
Latest:   v8.6.9community-edition — 和色 palette, socket2 TLS, washoku UI
Next:     Shaped by you — open issues, feature requests, PRs
Vision:   apt install oxide on Kali Linux
```

[![Issues](https://img.shields.io/badge/_Request_Feature-D7003A?style=for-the-badge&logo=bugatti&logoColor=000&labelColor=FFF0F0)](https://github.com/HyperSecurityLabs/oxide-communityedition-v8.6.9/issues)
[![Telegram](https://img.shields.io/badge/_Give_Feedback-5B6ABF?style=for-the-badge&logo=telegram&logoColor=000&labelColor=EDEAF8)](https://t.me/hypersecurity_offsec)

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

```bash
# Full battle test scan
./oxide -u <target> --all --threads 20 --duration 300

# Train + zero-day ML detection
./oxide -u <target> --train --duration 120
./oxide -u <target> --zeroday --duration 300
```

**Bottom line:** OXIDE isn't just another scanner — it's the only one that combines SQLi + XSS + CMDi + NoSQLi + CORS + TLS + session + creds + ML zero-day in a single concurrent engine. Star it, share it, make it sharper.

</div>
