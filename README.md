# Falco nginx Plugin / Falco nginxプラグイン

[English](#english) | [日本語](#japanese)

<a name="english"></a>
## English

A [Falco](https://falco.org) plugin that reads nginx access logs and detects security threats in real-time.

### Features

- **Real-time nginx log monitoring**: Continuously monitors nginx access logs
- **Security threat detection**: Detects SQL injection, XSS, directory traversal, command injection, and more
- **Scanner detection**: Identifies common security scanning tools
- **Brute force detection**: Monitors authentication failures and password attacks
  - Failed login attempts on multiple endpoints (/login, /admin, /api/auth, etc.)
  - HTTP Basic Authentication failures
  - Password reset abuse detection
  - WordPress and CMS login monitoring
- **High performance**: Efficient log parsing with minimal overhead
- **Easy deployment**: Simple binary installation with automated setup

### Quick Start

#### One-liner Installation (Recommended)

The easiest way to get started:

```bash
curl -sSL https://raw.githubusercontent.com/takaosgb3/falco-nginx-plugin/main/install.sh | sudo bash
```

This will automatically:
- ✅ Check system requirements
- ✅ Install and configure nginx (if needed)
- ✅ Install Falco
- ✅ Download and install the nginx plugin
- ✅ Configure everything for immediate use

#### Manual Installation

1. **Download the latest release**:
```bash
wget https://github.com/takaosgb3/falco-nginx-plugin/releases/latest/download/libfalco-nginx-plugin-linux-amd64.so
wget https://github.com/takaosgb3/falco-nginx-plugin/releases/latest/download/nginx_rules.yaml
```

2. **Install the plugin**:
```bash
sudo mkdir -p /usr/share/falco/plugins
sudo cp libfalco-nginx-plugin-linux-amd64.so /usr/share/falco/plugins/libfalco-nginx-plugin.so
sudo chmod 644 /usr/share/falco/plugins/libfalco-nginx-plugin.so
```

3. **Install the rules**:
```bash
sudo mkdir -p /etc/falco/rules.d
sudo cp nginx_rules.yaml /etc/falco/rules.d/
```

4. **Configure Falco** - Add to `/etc/falco/falco.yaml`:
```yaml
load_plugins: [nginx]

plugins:
  - name: nginx
    library_path: /usr/share/falco/plugins/libfalco-nginx-plugin.so
    init_config:
      log_paths:
        - /var/log/nginx/access.log
```

### Testing

After installation, test the plugin:

```bash
# Step 1: Find which Falco service is running (quick check)
for svc in falco falco-modern-bpf falco-bpf; do 
  echo -n "$svc: "
  systemctl is-active $svc 2>/dev/null || echo "not found"
done
# Look for "active" - that's your service!

# Step 2: Monitor alerts using YOUR active service
# If falco: active         → sudo journalctl -u falco -f
# If falco-modern-bpf: active → sudo journalctl -u falco-modern-bpf -f  
# If falco-bpf: active     → sudo journalctl -u falco-bpf -f

# Step 3: In another terminal, simulate attacks
curl "http://localhost/search.php?q=%27%20OR%20%271%27%3D%271"  # SQL injection
curl "http://localhost/search.php?q=%3Cscript%3Ealert(1)%3C/script%3E"  # XSS

# Verify plugin is loaded
sudo falco --list-plugins | grep nginx
```

**💡 Tip**: Not sure which service? Run `sudo systemctl status falco` - if it shows "not found" or "inactive", try `sudo systemctl status falco-modern-bpf` (common on EC2/cloud).

### Documentation

- [Quick Start Binary Installation](docs/QUICK_START_BINARY_INSTALLATION.md)
- [Configuration Guide](docs/configuration.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Performance Tuning](docs/performance.md)
- [Rule Reference](docs/rules.md)

### Requirements

- **Falco**: 0.36.0 or higher
- **OS**: Linux x86_64
- **nginx**: 1.14.0+ with combined log format

### License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

---

<a name="japanese"></a>
## 日本語

nginxのアクセスログを読み取り、セキュリティ脅威をリアルタイムで検出する[Falco](https://falco.org)プラグイン。

### 機能

- **リアルタイムnginxログ監視**: nginxアクセスログを継続的に監視
- **セキュリティ脅威検出**: SQLインジェクション、XSS、ディレクトリトラバーサル、コマンドインジェクション等を検出
- **スキャナー検出**: 一般的なセキュリティスキャンツールを識別
- **ブルートフォース検出**: 認証攻撃を監視
- **高性能**: 最小限のオーバーヘッドで効率的なログ解析
- **簡単な展開**: 自動セットアップによる簡単なバイナリインストール

### クイックスタート

#### ワンライナーインストール（推奨）

最も簡単な開始方法：

```bash
curl -sSL https://raw.githubusercontent.com/takaosgb3/falco-nginx-plugin/main/install.sh | sudo bash
```

これにより自動的に以下が実行されます：
- ✅ システム要件の確認
- ✅ nginx のインストールと設定（必要な場合）
- ✅ Falco のインストール
- ✅ nginx プラグインのダウンロードとインストール
- ✅ すぐに使用できるようにすべてを設定

#### 手動インストール

1. **最新リリースをダウンロード**：
```bash
wget https://github.com/takaosgb3/falco-nginx-plugin/releases/latest/download/libfalco-nginx-plugin-linux-amd64.so
wget https://github.com/takaosgb3/falco-nginx-plugin/releases/latest/download/nginx_rules.yaml
```

2. **プラグインをインストール**：
```bash
sudo mkdir -p /usr/share/falco/plugins
sudo cp libfalco-nginx-plugin-linux-amd64.so /usr/share/falco/plugins/libfalco-nginx-plugin.so
sudo chmod 644 /usr/share/falco/plugins/libfalco-nginx-plugin.so
```

3. **ルールをインストール**：
```bash
sudo mkdir -p /etc/falco/rules.d
sudo cp nginx_rules.yaml /etc/falco/rules.d/
```

4. **Falcoを設定** - `/etc/falco/falco.yaml`に追加：
```yaml
load_plugins: [nginx]

plugins:
  - name: nginx
    library_path: /usr/share/falco/plugins/libfalco-nginx-plugin.so
    init_config:
      log_paths:
        - /var/log/nginx/access.log
```

### テスト

インストール後、プラグインをテスト：

```bash
# アラートを監視（サービスは既に起動しています）
sudo journalctl -u falco -f
# またはEC2/eBPFシステムの場合:
sudo journalctl -u falco-modern-bpf -f

# 別のターミナルで攻撃をシミュレート
curl "http://localhost/search.php?q=%27%20OR%20%271%27%3D%271"
```

### ドキュメント

- [クイックスタート バイナリインストール](docs/QUICK_START_BINARY_INSTALLATION.md)
- [設定ガイド](docs/configuration.md)
- [トラブルシューティング](docs/troubleshooting.md)
- [パフォーマンスチューニング](docs/performance.md)
- [ルールリファレンス](docs/rules.md)

### 要件

- **Falco**: 0.36.0以上
- **OS**: Linux x86_64
- **nginx**: 1.14.0以上（combined形式のログ）

### ライセンス

このプロジェクトはApache License 2.0でライセンスされています - 詳細は[LICENSE](LICENSE)ファイルを参照してください。