// ----------------------------------------------------------------------------
//  useragents.rs — User-Agent rotation
// ----------------------------------------------------------------------------
//  User-Agent rotation — realistic browser UA strings for red team operations.
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
//  useragents.rs — User-Agentローテーション
//  User-Agent rotation — realistic browser UA strings for red team ops
//  30+の現実的なUA文字列をラウンドロビンでローテーション
//  WAFバイパス用の電脳攻撃的エージェントプールも提供

use std::sync::atomic::{AtomicUsize, Ordering};

/// A pool of realistic user-agent strings.
/// Call `next()` to rotate through them in round-robin order.
//  UserAgentPool — User-Agentローテーションプール
//  User-Agent rotation pool — round-robin through realistic browser UAs
//  agents — UA文字列の静的スライス
//  cursor — アトミックカーソル (スレッドセーフなローテーション)
pub struct UserAgentPool {
    agents: &'static [&'static str],
    cursor: AtomicUsize,
}

//  UAプールはClone可能 (カーソル状態を保持)
impl Clone for UserAgentPool {
    fn clone(&self) -> Self {
        Self {
            agents: self.agents,
            cursor: AtomicUsize::new(self.cursor.load(Ordering::Relaxed)),
        }
    }
}

//  UAプールの実装
//  UA pool implementation
impl UserAgentPool {
    //  full — 全30種類の現実的なブラウザUA + 電脳攻撃的UA
    pub fn full() -> Self {
        Self { agents: ALL_AGENTS, cursor: AtomicUsize::new(0) }
    }

    //  aggressive — WAFバイパス用電脳攻撃的UAプール (ボット・旧ブラウザ・CLI)
    //  Aggressive pool: bots + scanners that bypass WAF and trigger real server responses
    //  検索エンジンボット (Googlebot/Bing/Yandex) — WAFは通常ブロックしない
    //  旧ブラウザ (MSIE6/Firefox11) — レガシーコードパスを起動
    //  CLIツール (curl/wget/python-requests) — JSチャレンジをバイパス
    pub fn aggressive() -> Self {
        Self { agents: AGGRESSIVE_AGENTS, cursor: AtomicUsize::new(0) }
    }

    /// Rotate to the next agent.
    //  next — ラウンドロビンで次のUAを取得
    //  Round-robin: get next UA (atomic cursor increment)
    pub fn next(&self) -> &'static str {
        let idx = self.cursor.fetch_add(1, Ordering::Relaxed);
        self.agents[idx % self.agents.len()]
    }

    /// Pick a random agent (uses the rotation index as a pseudo-random seed).
    //  random — 疑似ランダムUA選択 (カーソルを7ずつ進める)
    //  Pseudo-random UA selection (steps cursor by 7)
    pub fn random(&self) -> &'static str {
        let idx = self.cursor.fetch_add(7, Ordering::Relaxed);
        self.agents[idx % self.agents.len()]
    }

    /// Return the full set of Accept headers that match the given UA.
    /// Pairing UA + Accept headers is critical for Cloudflare bypass.
    //  accept_headers_for — UAに合わせたAcceptヘッダーを返す
    //  Returns Accept headers matching the UA (critical for Cloudflare bypass)
    //  Firefox   text/html,application/xhtml+xml  + en-US,en;q=0.5  + gzip, deflate, br
    //  Safari    text/html,application/xhtml+xml  + en-US,en;q=0.9  + gzip, deflate, br
    //  ボット    シンプルなAccept + gzip, deflate
    //  Chrome/Edge  フルセット + application/signed-exchange + br, zstd
    pub fn accept_headers_for(ua: &str) -> (&'static str, &'static str, &'static str) {
        // (Accept, Accept-Language, Accept-Encoding)
        if ua.contains("Firefox") {
            (
                "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                "en-US,en;q=0.5",
                "gzip, deflate, br",
            )
        } else if ua.contains("Safari") && !ua.contains("Chrome") {
            (
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "en-US,en;q=0.9",
                "gzip, deflate, br",
            )
        } else if ua.contains("Googlebot") || ua.contains("bingbot") || ua.contains("Slurp") {
            (
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "en-US,en;q=0.5",
                "gzip, deflate",
            )
        } else {
            // Chrome / Edge / default
            (
                "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                "en-US,en;q=0.9",
                "gzip, deflate, br, zstd",
            )
        }
    }
}

//  Aggressive WAF bypass / server probing agents 
// These trigger different server behavior, bypass WAF allowlists, and expose
// backend fingerprints that modern browsers hide behind CDN.

const AGGRESSIVE_AGENTS: &[&str] = &[
    //  Search engine bots (WAFs rarely block these) 
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "Mozilla/5.0 (compatible; DuckDuckBot-Https/1.1; +https://duckduckgo.com/duckduckbot)",
    "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
    "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)",
    "Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)",
    //  Legacy / old browsers (trigger fallback paths, no modern security) 
    "Mozilla/5.0 (Windows NT 5.1; rv:11.0) Gecko/20100101 Firefox/11.0",
    "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)",
    "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)",
    "Mozilla/5.0 (Windows NT 4.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2049.0 Safari/537.36",
    //  CLI tools (bypass JS challenges, no JS execution) 
    "curl/8.7.1",
    "Wget/1.24.5 (linux-gnu)",
    "Python-urllib/3.12",
    "python-requests/2.31.0",
    "Go-http-client/2.0",
    "HTTPie/3.2.2",
    "Aria2/1.37.0",
    "Lynx/2.9.2dev.9 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/3.0.12",
    //  RSS readers / feed fetchers 
    "FeedReader/3.14 Generic/2.0",
    "NetNewsWire/6.1 (Macintosh; Intel Mac OS X 14.4)",
    //  Headless / automation (no "HeadlessChrome" — stealth) 
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.4; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
];

//  Combined pool 

const ALL_AGENTS: &[&str] = &[
    // Chrome Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    // Chrome macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    // Chrome Linux
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    // Edge
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0",
    // Firefox
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.4; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    // Safari
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    // Mobile Chrome
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6312.118 Mobile Safari/537.36",
    // Mobile Safari
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3.1 Mobile/15E148 Safari/604.1",
    // Opera
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 OPR/109.0.0.0",
];
