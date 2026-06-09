# OxideCE-v7.7.7elite
OxideCE-v7.7.7elite — Precision-forged Rust vulnerability scanner. AI/ML-powered detection, Cloudflare WAF bypass, kernel-level hypersecurity. Built for the offensive security elite. 

<p align="center">
  <img src="https://img.shields.io/badge/version-7.7.7-elite-50dca0?style=for-the-badge&labelColor=1a1a2e" />
  <img src="https://img.shields.io/badge/status-ELITE%20EDITION-80dca0?style=for-the-badge&labelColor=1a1a2e" />
  <img src="https://img.shields.io/badge/license-Proprietary-beb0eb?style=for-the-badge&labelColor=1a1a2e" />
  <img src="https://img.shields.io/badge/plat-Linux%20%7C%20Win-aac3eb?style=for-the-badge&labelColor=1a1a2e" />
  <img src="https://img.shields.io/badge/Rust-2021-50dca0?style=for-the-badge&labelColor=1a1a2e" />
  <img src="https://img.shields.io/badge/Kali_Linux-557C94?style=for-the-badge&logo=kali-linux&logoColor=white&labelColor=1a1a2e" />
</p>

```text

  ▷ This is the Elite Edition.
  Future development moves exclusively to OXIDE Pro Edition.

```

<p align="center">
  <a href="https://github.com/hypersecuritylabs/OxideCE-v7.7.7elite">
    <img src="https://img.shields.io/badge/%E2%AD%90%20Star%20on%20GitHub-50dca0?style=for-the-badge&labelColor=1a1a2e" />
  </a>
  <a href="https://www.kali.org/tools/">
    <img src="https://img.shields.io/badge/Proudly%20crafted%20for-Kali%20Linux-557C94?style=for-the-badge&labelColor=1a1a2e&logo=kali-linux" />
  </a>
</p>

> **OXIDE** is a next-generation, AI-augmented web vulnerability scanner in **Rust**.  
> From SQLi/XSS to zero-day anomaly detection via Random Forest & SVM — built for offensive security pros.  
> **Release:** 2026-05-29 · **Author:** [khaninkali](https://github.com/hypersecuritylabs) · HyperSecurityLabs

---

> **⚠️ WARNING — READ BEFORE USE**
>
> OXIDE is purpose-built for **offensive security operations**. It is designed to launch **multiple concurrent scan attacks from a single binary** — SQLi, XSS, LFI, CMDi, blind injection, and destructive payloads all fire simultaneously across discovered vectors. This WILL cause **service degradation, data corruption, and potential server crashes** on unprotected targets.
>
> **False positives are inherent** by design. The scanner uses aggressive detection patterns, broad regex signatures, and behavioral heuristics that prioritize catching every possible vulnerability over precision. Many findings require manual validation. Always confirm findings against a safe baseline before reporting.
>
> **You are responsible for:**
> - Obtaining written authorization before scanning any target
> - Using rate limiting (`--rate-limit`) and duration caps (`--duration`)
> - Validating all findings manually
> - The legal consequences of unauthorized scanning
>
> **This is not a toy.** OXIDE launches real payloads against real endpoints. Misuse can destroy websites, corrupt databases, and trigger WAF/IPS blocks that take targets offline. Use responsibly.

---

![](https://img.shields.io/badge/KALI%20LINUX-557C94?style=flat-square&logo=kali-linux&logoColor=white)

<p align="center">
  <a href="https://www.kali.org/tools/">
    <img src="https://img.shields.io/badge/Proudly%20crafted%20for-Kali%20Linux-557C94?style=for-the-badge&labelColor=1a1a2e&logo=kali-linux" />
  </a>
</p>

**OXIDE belongs in Kali Linux.** It is purpose-built for offensive operations — the same philosophy that drives the Kali distribution. Every module, payload, and scanner is designed for professional red teams and pentesters.

If you believe OXIDE deserves a place in the official Kali repos alongside Burp Suite, sqlmap, and Metasploit — **star the repository**. Each star signals demand to the Kali maintainers.

[![Star on GitHub](https://img.shields.io/badge/%E2%AD%90%20Star%20to%20bring%20OXIDE%20to%20Kali-557C94?style=for-the-badge&labelColor=1a1a2e&logo=kali-linux)](https://github.com/hypersecuritylabs/OxideCE-v7.7.7elite)

---

### 💥 Why OXIDE Can Destroy Websites — Code Evidence

This is not marketing. Every claim below is backed by the source:

| Threat | Code Location | What It Does |
|--------|--------------|--------------|
| **Concurrent multi-vector fuzzing** | `src/hybrid.rs:1312-1321` | Fires SQLi, XSS, LFI, CMDi, NoSQL, SSTI + **destructive SQL** across all discovered parameters simultaneously — no sequential ordering, no safe defaults |
| **DROP TABLE / TRUNCATE** | `src/payload/sql_injection.rs:349-352` | `DROP TABLE IF EXISTS users`, `DROP DATABASE`, `TRUNCATE users` — permanent data loss |
| **Webshell deployment** | `src/payload/sql_injection.rs:324-332` | `INTO OUTFILE` writes `<?php system($_GET[0]);?>` to web root — RCE via MySQL |
| **xp_cmdshell RCE** | `src/payload/sql_injection.rs:357-362` | `EXEC xp_cmdshell` runs `powershell`, `certutil` download cradle, `bitsadmin` — full Windows takeover |
| **COPY TO PROGRAM RCE** | `src/payload/sql_injection.rs:378-381` | PostgreSQL `COPY TO PROGRAM` executes `curl`, `wget`, `bash -i`, `ncat` — reverse shell |
| **Privilege escalation** | `src/payload/sql_injection.rs:346-347, 374-376, 387-388` | `CREATE USER ... SUPERUSER`, `sp_addsrvrolemember 'sysadmin'`, `GRANT ALL PRIVILEGES` — database root |
| **Data exfiltration** | `src/payload/sql_injection.rs:334-344, 364-366, 371-372, 399, 401-404` | `LOAD_FILE(/etc/shadow)`, `UTL_HTTP.request()`, `OPENROWSET`, `SELECT * FROM credit_cards` — steals sensitive data |
| **No rate limit by default** | `src/core/worker.rs:147-151` | `--rate-limit` defaults to `0` (unlimited). At 20+ threads, this can saturate target connections instantly |
| **3-target multiattack** | `src/cli/args.rs:88`, `src/main.rs:107` | `--multiattack` fans out all scanners across 3 targets concurrently — triples the load |
| **20+ threads default** | `src/cli/args.rs` | 20 concurrent workers per target, each firing payloads without backoff |

**Rate limiting is now enforced** — `--rate-limit` is capped at 1000 req/s minimum and the computed delay floor is 1ms, preventing accidental unlimited bursts even with high values.

---

![](https://img.shields.io/badge/SCANNERS-ffb432?style=flat-square)

| Module | Flag | Description |
|--------|------|-------------|
| SQL Injection | `sqli` | Error-based, blind, time-based with 20+ regex |
| Blind SQLi | `blind-sqli` | Timing analysis |
| XSS | `xss` | Reflected, stored, DOM-based |
| LFI | `lfi` | Path traversal chains |
| Path Traversal | `path-traversal` | OS variants |
| Command Injection | `cmd-injection` | Blind + reflected |
| CORS | `cors` | Misconfiguration assessment |
| TLS Audit | `tls` | Protocols, ciphers, certs |
| Default Creds | `creds` | 6000+ combos |
| Common Apps | `common` | 2790+ Nikto-style checks |
| DB Fingerprint | `db-fingerprint` | Error + banner fingerprinting |
| Instagram OSINT | `insta` | Followers, private, profile pic |
| Session Hijack | `session` | Cookie flags, fixation, predictability |
| ML Trainer | `train` | RF/SVM from live results |
| Zero-Day ML | `zeroday` | `smartcore` + `linfa` anomaly detection |
| Hypersecurity | `hypersecurity` | Memory safety .so module |

---

![](https://img.shields.io/badge/AI%20ML-50dca0?style=flat-square)

| Component | Library | Purpose |
|-----------|---------|---------|
| Zero-Day Detection | `smartcore` RF/SVM | Statistical anomaly detection |
| Pattern Learner | Custom ngram | Adaptive payload mutation |
| Exploit Analyzer | Custom heuristic | Exploit chain analysis |
| Response Analyzer | Custom model | HTTP behavioural fingerprinting |
| Payload Mutator | Custom genetic alg | ML-guided evolution |
| Clustering | `linfa-clustering` | Unsupervised anomaly grouping |
| Stats Engine | `statrs` | Distribution outlier detection |

---

![](https://img.shields.io/badge/DISTRIBUTION-788298?style=flat-square)

| Platform | Package | Size | SHA256 |
|----------|---------|------|--------|
| 🐧 **Debian** | `oxide-ce_7.7.7-elite_amd64.deb` | 3.1M | `5a6bc1dea5aa240af3db70010418576e9411b37f0a177eeb54dee24f7ce10fe5` |
| 🐧 **Linux** | `oxide-ce-v7.7.7-elite-linux.zip` | 4.2M | `6813a5e39675bf62ee6adf0dd3a319b1699243fc08a70ef217d92ce54447672d` |
| 🪟 **Windows** | `oxide-ce-v7.7.7-elite-windows.zip` | 4.1M | `ca59291c86e366cbd0f6ae3bdf5906c9025cd89cb48e08db86e9f1c45c692c23` |

**Linux contents:** `oxide` · `libhypersecurity.so` · `liboxide_proxy.so` · `oxide_tests.db` · `oxide_tests.db.enc` · `RELEASE.md` · `GITHUB.md` · `DISTRIBUTION.md`

**Windows contents:** `oxide.exe` · `hypersecurity.dll` · `oxide_proxy.dll` · `oxide_tests.db` · `oxide_tests.db.enc` · `RELEASE.md` · `WINDOWS.md` · `DISTRIBUTION.md`

**Verification:**
```sh
sha256sum oxide-ce_7.7.7-elite_amd64.deb
sha256sum oxide-ce-v7.7.7-elite-linux.zip
sha256sum oxide-ce-v7.7.7-elite-windows.zip
```

---

![](https://img.shields.io/badge/ARCHITECTURE-50dca0?style=flat-square)

```
src/main.rs · hybrid.rs · crawls.rs · cli/ · detection/ · scanner/ · http/ · ai/
zero_day/ · advanced/ · payload/ · report/ · insta/ · session_hijack/
hypersecurity/ (C ABI .so) · oxide-proxy/ (routing .so)
```

---

![](https://img.shields.io/badge/QUICK%20START-aac3eb?style=flat-square)

**Debian/Kali (.deb):**
```bash
sudo dpkg -i oxide-ce_7.7.7-elite_amd64.deb
sudo apt install -f
oxide-ce --url https://target.com --modules all
```

**Linux (portable):**
```bash
unzip oxide-ce-v7.7.7-elite-linux.zip && cd oxide-v7.7.7-elite-linux
./oxide --url https://target.com --modules all
./oxide --url https://target.com --modules all --verbose --output report.html --format html --duration 600
./oxide --url https://target.com/page.php?id=1 --modules sqli,xss,lfi --payload-limit 20 --exploitation-level 75
```

**Windows:**
```powershell
.\oxide.exe --url https://target.com --modules all --verbose
.\oxide.exe --url https://target.com --output report.json --format json
```

---

![](https://img.shields.io/badge/CLI%20REF-788298?style=flat-square)

| Flag | Default | Description |
|------|---------|-------------|
| `-u, --url` | *required* | Target URL (up to 3 with `--multiattack`) |
| `--modules` | `all` | Comma-separated module list |
| `-t, --threads` | `20` | Concurrent workers (1-100) |
| `--payload-limit` / `--payloads` | `50` | Max payloads per test |
| `--exploitation-level` / `--exploitation` | `50` | Aggression (1-100) |
| `--duration` | `0` (unlim) | Max scan seconds |
| `-o, --output` | stdout | Output file path |
| `-f, --format` | `json` | json/html/csv/xml |
| `--rate-limit` | unlimited | Req/sec cap |
| `--proxy` | none | Proxy URL |
| `--user-agent` | default | Custom UA |
| `--cookie` | none | Auth cookie |
| `--header` | none | Extra headers |
| `--follow-redirects` | false | Follow redirects |
| `--max-redirects` | `10` | Max chain depth |
| `--insecure` | false | Skip SSL verify |
| `--crawl-depth` | `3` | Crawler depth |
| `--max-pages` | `100` | Max crawl pages |
| `--zeroday` | false | ML zero-day mode |
| `--train` | false | Train classifier |
| `--insta` | false | Instagram OSINT |
| `--session` | false | Session hijack |
| `-v, --verbose` | false | Full output |
| `--multiattack` | false | Up to 3 targets |

---

![](https://img.shields.io/badge/PALETTE-50dca0?style=flat-square)

```
OSAKA_JADE_B #50dca0 · LAVENDER #beb0eb · LAVENDER_BLUE #aac3eb
COL_CRIT #ff3232 · COL_HIGH #ff6450 · COL_MED #ffb432 · COL_LOW #f0a030 · COL_DIM #788298
```

```
[CRITICAL] Finding Title  // https://target.com/path
[  HIGH  ] Finding Title  // https://target.com/path
[ MEDIUM ] Finding Title  // https://target.com/path
[  LOW   ] Finding Title  // https://target.com/path
[  INFO  ] Finding Title  // https://target.com/path
```

UI: `[⠋]` ScanBoard · `[⠋ ⠏]` AgentBar · `████░░` Progress · `det:5 err:2` Counters · `─` Borders

---

![](https://img.shields.io/badge/HYPERSECURITY-557C94?style=flat-square)

Standalone `cdylib` workspace member (~1.9 MB) — memory safety at kernel level. Loaded at runtime via `libloading` — zero-link dependency. Silently no-ops cache ops for non-root users.

**C ABI exports:**

```c
bool hs_check_leaks(void);      // W+X region scan via /proc/self/maps
bool hs_sanitise_cache(void);   // drop_caches (root)
bool hs_memory_barrier(void);   // SeqCst fence
const char* hs_version(void);   // "7.7.7-elite"
```

Loaded at runtime via `libloading` · Build: `cargo build -p hypersecurity --release`

---

![](https://img.shields.io/badge/HARDENING-ff6450?style=flat-square)

XOR-encrypted SQLite · Proxy FFI sandbox (`panic=abort`) · W+X memory scanning · Cache sanitisation · Runtime enforcement · Proprietary license

---

![](https://img.shields.io/badge/LICENSE-ff6450?style=flat-square)

**Proprietary** — Copyright © 2024-2026 khaninkali · HyperSecurityLabs · All Rights Reserved

| Action | Public | Members |
|--------|--------|---------|
| View/fork/reference | ✅ | ✅ |
| Personal/edu use | ✅ | ✅ |
| Modify/distribute | ❌ | ✅ |
| Remove attribution | ❌ **Never** | ❌ **Never** |
| Sell/rebrand | ❌ Legal action | ❌ Legal action |

> Removing author name ("khaninkali"), HyperSecurityLabs brand, or copyright = violation + legal action.

---

![](https://img.shields.io/badge/STAR%20THIS%20PROJECT-50dca0?style=flat-square)

<p align="center">
  This is the <strong>Elite Edition</strong> — countless hours of work.  
  If OXIDE helped you in a pentest, CTF, or research,  
  <a href="https://github.com/hypersecuritylabs/OxideCE-v7.7.7elite"><strong>please star the repository ★</strong></a>
  <br/><br/>
  <a href="https://github.com/hypersecuritylabs/OxideCE-v7.7.7elite">
    <img src="https://img.shields.io/badge/%E2%AD%90%20Star%20on%20GitHub-50dca0?style=for-the-badge&labelColor=1a1a2e" />
  </a>
</p>

---

![](https://img.shields.io/badge/CONNECT-beb0eb?style=flat-square)

| Platform | Link |
|----------|------|
| 🐙 GitHub | [github.com/hypersecuritylabs](https://github.com/hypersecuritylabs) |
| 🌐 Website | [hypersecurityoffensivelabs](https://hypersecurityoffensivelabs-about.is-best.net/)) |
| 💬 Telegram | [t.me/hypersecurity_offsec](https://t.me/hypersecurity_offsec) |
| 🐉 Kali Linux | [kali.org/tools](https://www.kali.org/tools/) |

---

> **Special thanks to [lyara](https://github.com/lyara) for development contributions.**

<p align="center">
  <code>Built with 🦀 Rust · Forged in the offensive security trenches</code><br/>
  <strong>HyperSecurityLabs · OXIDE Framework v7.7.7-elite</strong><br/>
  <em>"Scan everything. Trust nothing. Patch accordingly."</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/END_OF_LINE-50dca0?style=for-the-badge&labelColor=1a1a2e" />
  <img src="https://img.shields.io/badge/ELITE_EDITION-ff6450?style=for-the-badge&labelColor=1a1a2e" />
</p>