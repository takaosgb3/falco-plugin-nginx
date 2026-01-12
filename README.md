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

### E2E Security Tests

This repository includes comprehensive E2E tests for security detection validation.

**Running E2E Tests**:
```bash
# Trigger via GitHub Actions
gh workflow run e2e-test.yml
```

**Test Coverage** (300 attack patterns across 12 categories):

| Category | Patterns | Description |
|----------|----------|-------------|
| SQL Injection | 79 | Time-based, Boolean-based, Error-based SQLi |
| XSS | 56 | Reflected, DOM-based, Stored XSS attacks |
| Path Traversal | 50 | Directory traversal, LFI, RFI patterns |
| Command Injection | 55 | Shell, OS command injection patterns |
| LDAP Injection | 10 | LDAP query manipulation |
| SSTI | 10 | Server-Side Template Injection |
| NoSQL Injection | 7 | MongoDB, Redis injection patterns |
| XXE | 8 | XML External Entity attacks |
| XPath Injection | 5 | XPath query manipulation |
| GraphQL Injection | 5 | GraphQL query attacks |
| API Security | 5 | BOLA, authentication bypass |
| Other | 10 | Additional security patterns |

**Latest Results**: See [Actions](../../actions/workflows/e2e-test.yml) for test runs and [Allure Report](https://takaosgb3.github.io/falco-plugin-nginx/) for detailed results.

### Documentation

- [Quick Start Binary Installation](docs/QUICK_START_BINARY_INSTALLATION.md)
- [Configuration Guide](docs/configuration.md)
- [Troubleshooting](docs/TROUBLESHOOTING.md)
- [Performance Tuning](docs/performance.md)
- [Rule Reference](docs/rules.md)
- [E2E Test Guide](e2e/README.md)

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

### E2Eセキュリティテスト

このリポジトリには、セキュリティ検出を検証するための包括的なE2Eテストが含まれています。

**E2Eテストの実行**:
```bash
# GitHub Actions経由でトリガー
gh workflow run e2e-test.yml
```

**テストカバレッジ**（300攻撃パターン、12カテゴリ）:

| カテゴリ | パターン数 | 説明 |
|----------|------------|------|
| SQLインジェクション | 79 | 時間ベース、ブールベース、エラーベースSQLi |
| XSS | 56 | 反射型、DOMベース、格納型XSS攻撃 |
| パストラバーサル | 50 | ディレクトリトラバーサル、LFI、RFI |
| コマンドインジェクション | 55 | シェル、OSコマンドインジェクション |
| LDAPインジェクション | 10 | LDAPクエリ操作 |
| SSTI | 10 | サーバーサイドテンプレートインジェクション |
| NoSQLインジェクション | 7 | MongoDB、Redisインジェクション |
| XXE | 8 | XML外部エンティティ攻撃 |
| XPathインジェクション | 5 | XPathクエリ操作 |
| GraphQLインジェクション | 5 | GraphQLクエリ攻撃 |
| APIセキュリティ | 5 | BOLA、認証バイパス |
| その他 | 10 | 追加セキュリティパターン |

**最新結果**: テスト実行は[Actions](../../actions/workflows/e2e-test.yml)、詳細結果は[Allure Report](https://takaosgb3.github.io/falco-plugin-nginx/)を参照。

### ドキュメント

- [クイックスタート バイナリインストール](docs/QUICK_START_BINARY_INSTALLATION.md)
- [設定ガイド](docs/configuration.md)
- [トラブルシューティング](docs/TROUBLESHOOTING.md)
- [パフォーマンスチューニング](docs/performance.md)
- [ルールリファレンス](docs/rules.md)
- [E2Eテストガイド](e2e/README.md)

### 要件

- **Falco**: 0.36.0以上
- **OS**: Linux x86_64
- **nginx**: 1.14.0以上（combined形式のログ）

### ライセンス

このプロジェクトはApache License 2.0でライセンスされています - 詳細は[LICENSE](LICENSE)ファイルを参照してください。