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
curl -sSL https://raw.githubusercontent.com/takaosgb3/falco-plugin-nginx/main/install.sh | sudo bash
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
wget https://github.com/takaosgb3/falco-plugin-nginx/releases/latest/download/libfalco-nginx-plugin-linux-amd64.so
wget https://github.com/takaosgb3/falco-plugin-nginx/releases/latest/download/nginx_rules.yaml
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

**Test Coverage** (850 attack patterns across 24 categories):

| Category | Patterns | Description |
|----------|----------|-------------|
| SQL Injection | 138 | Time-based, Boolean-based, Error-based, Advanced SQLi |
| Command Injection | 98 | Shell, OS command injection, obfuscation bypass |
| XSS | 96 | Reflected, DOM-based, Advanced, Filter bypass, Mutation |
| Path Traversal | 81 | Directory traversal, LFI, RFI, Unicode bypass |
| SSRF | 41 | Cloud metadata, internal network, hex/IPv6/octal IP |
| SSTI | 34 | Jinja2, Pug, EJS, Handlebars, Mako, Nunjucks |
| Other | 34 | Additional security patterns |
| CRLF Injection | 31 | Header injection, response splitting, Unicode CRLF |
| API Security | 30 | BOLA, authentication bypass, mass assignment |
| GraphQL | 25 | Introspection, data extraction, query abuse |
| XPath Injection | 25 | Boolean-based, blind, function abuse |
| Host Header Injection | 21 | Multi-host, CRLF, port manipulation |
| HPP | 20 | HTTP Parameter Pollution, array, type juggling |
| Open Redirect | 20 | Data URI, fragment, meta refresh, Unicode |
| NoSQL Injection | 20 | MongoDB, Redis, CouchDB injection patterns |
| LDAP Injection | 20 | LDAP query manipulation, filter injection |
| WAF Bypass | 18 | Chunked, multipart, double encoding |
| XXE | 18 | XML External Entity, DOCTYPE/ENTITY injection |
| JWT | 15 | KID injection, X5U, JWE, replay, JWKS |
| Prototype Pollution | 15 | `__proto__`, constructor.prototype pollution |
| HTTP Smuggling | 15 | CL.TE, TE.CL, request splitting |
| Pickle/Deserialization | 15 | Python deserialization, pickle exploitation |
| Information Disclosure | 10 | Server info, debug endpoints, error pages |
| Auth Bypass via Path | 10 | Path normalization, case manipulation |

**Latest Results**: See [Actions](../../actions/workflows/e2e-test.yml) for test runs and [Allure Report](https://takaosgb3.github.io/falco-plugin-nginx/) for detailed results.

### Extractable Fields

This plugin provides 17 fields for use in Falco rules:

| Field | Type | Description |
|-------|------|-------------|
| `nginx.remote_addr` | string | Client IP address |
| `nginx.remote_user` | string | Authenticated username |
| `nginx.time_local` | string | Local time of the request |
| `nginx.method` | string | HTTP request method (GET, POST, etc.) |
| `nginx.path` | string | Request URI path |
| `nginx.query_string` | string | Query string parameters |
| `nginx.request_uri` | string | Complete request URI (path + query) |
| `nginx.protocol` | string | HTTP protocol version |
| `nginx.status` | uint64 | HTTP response status code |
| `nginx.bytes_sent` | uint64 | Response size in bytes |
| `nginx.referer` | string | HTTP referer header |
| `nginx.user_agent` | string | HTTP user agent |
| `nginx.log_path` | string | Path to the log file |
| `nginx.raw` | string | Raw log line |
| `nginx.headers[key]` | string | HTTP request headers (key-based access) |
| `nginx.test_id` | string | E2E test identifier (X-Test-ID header) |
| `nginx.category` | string | Attack category (X-Category header) |
| `nginx.pattern_id` | string | Pattern ID (X-Pattern-ID header) |

**Example rule using these fields**:
```yaml
- rule: SQL Injection Attempt
  desc: Detects SQL injection patterns in nginx access logs
  condition: nginx.request_uri contains "' OR " or nginx.request_uri contains "1=1"
  output: "SQL Injection detected (client=%nginx.remote_addr path=%nginx.path)"
  priority: WARNING
  source: nginx
```

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
curl -sSL https://raw.githubusercontent.com/takaosgb3/falco-plugin-nginx/main/install.sh | sudo bash
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
wget https://github.com/takaosgb3/falco-plugin-nginx/releases/latest/download/libfalco-nginx-plugin-linux-amd64.so
wget https://github.com/takaosgb3/falco-plugin-nginx/releases/latest/download/nginx_rules.yaml
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

**テストカバレッジ**（850攻撃パターン、24カテゴリ）:

| カテゴリ | パターン数 | 説明 |
|----------|------------|------|
| SQLインジェクション | 138 | 時間ベース、ブールベース、エラーベース、高度なSQLi |
| コマンドインジェクション | 98 | シェル、OSコマンドインジェクション、難読化バイパス |
| XSS | 96 | 反射型、DOMベース、高度なXSS、フィルターバイパス、ミューテーション |
| パストラバーサル | 81 | ディレクトリトラバーサル、LFI、RFI、Unicodeバイパス |
| SSRF | 41 | クラウドメタデータ、内部ネットワーク、hex/IPv6/octal IP |
| SSTI | 34 | Jinja2、Pug、EJS、Handlebars、Mako、Nunjucks |
| その他 | 34 | 追加セキュリティパターン |
| CRLFインジェクション | 31 | ヘッダーインジェクション、レスポンス分割、Unicode CRLF |
| APIセキュリティ | 30 | BOLA、認証バイパス、マスアサインメント |
| GraphQLインジェクション | 25 | イントロスペクション、データ抽出、クエリ悪用 |
| XPathインジェクション | 25 | ブールベース、ブラインド、関数悪用 |
| Host Headerインジェクション | 21 | マルチホスト、CRLF、ポート操作 |
| HPP | 20 | HTTPパラメータ汚染、配列、型ジャグリング |
| オープンリダイレクト | 20 | Data URI、フラグメント、metaリフレッシュ、Unicode |
| NoSQLインジェクション | 20 | MongoDB、Redis、CouchDBインジェクション |
| LDAPインジェクション | 20 | LDAPクエリ操作、フィルターインジェクション |
| WAFバイパス | 18 | チャンク、マルチパート、二重エンコーディング |
| XXE | 18 | XML外部エンティティ、DOCTYPE/ENTITYインジェクション |
| JWT | 15 | KIDインジェクション、X5U、JWE、リプレイ、JWKS |
| プロトタイプ汚染 | 15 | `__proto__`、constructor.prototype汚染 |
| HTTPスマグリング | 15 | CL.TE、TE.CL、リクエスト分割 |
| Pickle/デシリアライゼーション | 15 | Pythonデシリアライゼーション、Pickle悪用 |
| 情報漏洩 | 10 | サーバー情報、デバッグエンドポイント、エラーページ |
| パスベース認証バイパス | 10 | パス正規化、大文字小文字操作 |

**最新結果**: テスト実行は[Actions](../../actions/workflows/e2e-test.yml)、詳細結果は[Allure Report](https://takaosgb3.github.io/falco-plugin-nginx/)を参照。

### 抽出可能フィールド

このプラグインはFalcoルールで使用できる17フィールドを提供します：

| フィールド | 型 | 説明 |
|------------|------|------|
| `nginx.remote_addr` | string | クライアントIPアドレス |
| `nginx.remote_user` | string | 認証済みユーザー名 |
| `nginx.time_local` | string | リクエストのローカル時刻 |
| `nginx.method` | string | HTTPリクエストメソッド（GET、POSTなど） |
| `nginx.path` | string | リクエストURIパス |
| `nginx.query_string` | string | クエリ文字列パラメータ |
| `nginx.request_uri` | string | 完全なリクエストURI（パス＋クエリ） |
| `nginx.protocol` | string | HTTPプロトコルバージョン |
| `nginx.status` | uint64 | HTTPレスポンスステータスコード |
| `nginx.bytes_sent` | uint64 | レスポンスサイズ（バイト） |
| `nginx.referer` | string | HTTPリファラーヘッダー |
| `nginx.user_agent` | string | HTTPユーザーエージェント |
| `nginx.log_path` | string | ログファイルのパス |
| `nginx.raw` | string | 生のログ行 |
| `nginx.headers[key]` | string | HTTPリクエストヘッダー（キーベースアクセス） |
| `nginx.test_id` | string | E2Eテスト識別子（X-Test-IDヘッダー） |
| `nginx.category` | string | 攻撃カテゴリ（X-Categoryヘッダー） |
| `nginx.pattern_id` | string | パターンID（X-Pattern-IDヘッダー） |

**これらのフィールドを使用したルール例**：
```yaml
- rule: SQL Injection Attempt
  desc: nginxアクセスログでSQLインジェクションパターンを検出
  condition: nginx.request_uri contains "' OR " or nginx.request_uri contains "1=1"
  output: "SQLインジェクション検出 (client=%nginx.remote_addr path=%nginx.path)"
  priority: WARNING
  source: nginx
```

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
