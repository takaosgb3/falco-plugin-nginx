# Falco Nginx Plugin

[日本語版](#falco-nginx-プラグイン) | [English](#falco-nginx-plugin)

A Falco plugin for real-time security monitoring of nginx access logs. Detects SQL injection, XSS, path traversal, and other web-based attacks.

## ✨ Features

- **Real-time threat detection** using Falco's powerful rules engine
- **Multiple attack detection**: SQL injection, XSS, path traversal, command injection
- **Scanner detection**: Identifies common security scanners and bots
- **Performance monitoring**: Detects unusual request patterns
- **No kernel module required**: Runs in plugin-only mode

## 📋 Requirements

- **Falco**: 0.36.0 or higher
- **OS**: Linux x86_64
- **nginx**: Access logs in combined format

## 🚀 Quick Start

📖 **[Quick Start Guide](docs/QUICK_START_BINARY_INSTALLATION.md)** - Get started in 5 minutes with pre-built binaries

### 1. Download the Plugin

```bash
# Download the latest release
wget https://github.com/takaosgb3/falco-plugin-nginx/releases/download/v0.3.0/libfalco-nginx-plugin.so

# Verify checksum
echo "997e60627f103946c1bac9b31aa6ec1803fbd25fbccbf045fe37afaa5ec644d6  libfalco-nginx-plugin.so" | sha256sum -c

# Install to Falco plugins directory
sudo mkdir -p /usr/share/falco/plugins
sudo cp libfalco-nginx-plugin.so /usr/share/falco/plugins/
sudo chmod 644 /usr/share/falco/plugins/libfalco-nginx-plugin.so
```

### 2. Configure Falco

Edit `/etc/falco/falco.yaml`:

```yaml
# Add nginx plugin configuration
plugins:
  - name: nginx
    library_path: /usr/share/falco/plugins/libfalco-nginx-plugin.so
    init_config:
      log_paths:
        - /var/log/nginx/access.log
      buffer_size: 8192
      watch_interval: 1000

# Enable the plugin
load_plugins: [nginx]
```

### 3. Download Rules

```bash
# Download nginx security rules
wget https://github.com/takaosgb3/falco-plugin-nginx/releases/download/v0.3.0/nginx_rules.yaml
sudo cp nginx_rules.yaml /etc/falco/rules.d/
```

### 4. Run Falco

```bash
# Run in plugin-only mode (no kernel module required)
sudo falco --disable-source syscall -r /etc/falco/rules.d/nginx_rules.yaml
```

## 🧪 Test the Detection

```bash
# Test SQL injection detection
curl "http://localhost/search?q=' OR '1'='1"

# Test XSS detection
curl "http://localhost/page?content=<script>alert('XSS')</script>"

# Test directory traversal
curl "http://localhost/file?path=../../../../etc/passwd"
```

## 📖 Documentation

### Plugin Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `log_paths` | Array of nginx log file paths | `["/var/log/nginx/access.log"]` |
| `buffer_size` | Event buffer size | `8192` |
| `watch_interval` | File check interval (ms) | `1000` |

### Available Fields

The plugin extracts the following fields from nginx logs:

- `nginx.client_ip` - Client IP address
- `nginx.method` - HTTP method
- `nginx.request_uri` - Full request URI
- `nginx.path` - Request path
- `nginx.query_string` - Query parameters
- `nginx.status` - HTTP status code
- `nginx.body_bytes_sent` - Response size
- `nginx.user_agent` - User agent string
- `nginx.referer` - Referer header

### Running as a Service

Create `/etc/systemd/system/falco-nginx.service`:

```ini
[Unit]
Description=Falco Nginx Security Monitoring
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/falco --disable-source syscall -r /etc/falco/rules.d/nginx_rules.yaml
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl enable falco-nginx
sudo systemctl start falco-nginx
```

## 🔍 Troubleshooting

### Plugin not loading?

```bash
# Check if plugin is recognized
sudo falco --list-plugins | grep nginx

# Run with debug output
sudo falco -A --disable-source syscall
```

### Rules not triggering?

1. Verify `source: nginx` is set in rules
2. Check log file path and permissions
3. Ensure nginx uses combined log format

### Common Issues

- **"kernel module not found"**: Use `--disable-source syscall`
- **"plugin not found"**: Check file path and permissions
- **No alerts**: Verify nginx is writing to configured log path

## 🏗️ Building from Source

```bash
git clone https://github.com/takaosgb3/falco-nginx-plugin-claude
cd falco-nginx-plugin-claude
make build
```

## 📜 License

Apache License 2.0

## 🤝 Contributing

Contributions welcome! Please open issues or submit pull requests.

## 🔗 Links

- [Falco Documentation](https://falco.org/docs/)
- [Development Repository](https://github.com/takaosgb3/falco-nginx-plugin-claude)
- [Report Issues](https://github.com/takaosgb3/falco-plugin-nginx/issues)

---

# Falco Nginx プラグイン

[English](#falco-nginx-plugin) | [日本語版](#falco-nginx-プラグイン)

nginxアクセスログのリアルタイムセキュリティ監視を行うFalcoプラグインです。SQLインジェクション、XSS、パストラバーサル、その他のWeb攻撃を検出します。

## ✨ 特徴

- **リアルタイム脅威検出**: Falcoの強力なルールエンジンを使用
- **多様な攻撃検出**: SQLインジェクション、XSS、パストラバーサル、コマンドインジェクション
- **スキャナー検出**: 一般的なセキュリティスキャナーとボットを識別
- **パフォーマンス監視**: 異常なリクエストパターンを検出
- **カーネルモジュール不要**: プラグイン専用モードで動作

## 📋 要件

- **Falco**: 0.36.0以上
- **OS**: Linux x86_64
- **nginx**: combinedフォーマットのアクセスログ

## 🚀 クイックスタート

📖 **[クイックスタートガイド](docs/QUICK_START_BINARY_INSTALLATION.md)** - ビルド済みバイナリで5分で始める

### 1. プラグインのダウンロード

```bash
# 最新リリースをダウンロード
wget https://github.com/takaosgb3/falco-plugin-nginx/releases/download/v0.3.0/libfalco-nginx-plugin.so

# チェックサムの確認
echo "997e60627f103946c1bac9b31aa6ec1803fbd25fbccbf045fe37afaa5ec644d6  libfalco-nginx-plugin.so" | sha256sum -c

# Falcoプラグインディレクトリにインストール
sudo mkdir -p /usr/share/falco/plugins
sudo cp libfalco-nginx-plugin.so /usr/share/falco/plugins/
sudo chmod 644 /usr/share/falco/plugins/libfalco-nginx-plugin.so
```

### 2. Falcoの設定

`/etc/falco/falco.yaml`を編集:

```yaml
# nginxプラグイン設定を追加
plugins:
  - name: nginx
    library_path: /usr/share/falco/plugins/libfalco-nginx-plugin.so
    init_config:
      log_paths:
        - /var/log/nginx/access.log
      buffer_size: 8192
      watch_interval: 1000

# プラグインを有効化
load_plugins: [nginx]
```

### 3. ルールのダウンロード

```bash
# nginxセキュリティルールをダウンロード
wget https://github.com/takaosgb3/falco-plugin-nginx/releases/download/v0.3.0/nginx_rules.yaml
sudo cp nginx_rules.yaml /etc/falco/rules.d/
```

### 4. Falcoの実行

```bash
# プラグイン専用モードで実行（カーネルモジュール不要）
sudo falco --disable-source syscall -r /etc/falco/rules.d/nginx_rules.yaml
```

## 🧪 検出テスト

```bash
# SQLインジェクション検出のテスト
curl "http://localhost/search?q=' OR '1'='1"

# XSS検出のテスト
curl "http://localhost/page?content=<script>alert('XSS')</script>"

# ディレクトリトラバーサルのテスト
curl "http://localhost/file?path=../../../../etc/passwd"
```

## 📖 ドキュメント

### プラグイン設定

| パラメータ | 説明 | デフォルト |
|-----------|------|------------|
| `log_paths` | nginxログファイルパスの配列 | `["/var/log/nginx/access.log"]` |
| `buffer_size` | イベントバッファサイズ | `8192` |
| `watch_interval` | ファイルチェック間隔（ミリ秒） | `1000` |

### 利用可能なフィールド

プラグインはnginxログから以下のフィールドを抽出します:

- `nginx.client_ip` - クライアントIPアドレス
- `nginx.method` - HTTPメソッド
- `nginx.request_uri` - 完全なリクエストURI
- `nginx.path` - リクエストパス
- `nginx.query_string` - クエリパラメータ
- `nginx.status` - HTTPステータスコード
- `nginx.body_bytes_sent` - レスポンスサイズ
- `nginx.user_agent` - ユーザーエージェント文字列
- `nginx.referer` - リファラーヘッダー

### サービスとして実行

`/etc/systemd/system/falco-nginx.service`を作成:

```ini
[Unit]
Description=Falco Nginx セキュリティ監視
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/falco --disable-source syscall -r /etc/falco/rules.d/nginx_rules.yaml
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

有効化と起動:

```bash
sudo systemctl enable falco-nginx
sudo systemctl start falco-nginx
```

## 🔍 トラブルシューティング

### プラグインがロードされない？

```bash
# プラグインが認識されているか確認
sudo falco --list-plugins | grep nginx

# デバッグ出力で実行
sudo falco -A --disable-source syscall
```

### ルールがトリガーされない？

1. ルールに`source: nginx`が設定されているか確認
2. ログファイルのパスと権限を確認
3. nginxがcombinedログフォーマットを使用しているか確認

### 一般的な問題

- **「カーネルモジュールが見つかりません」**: `--disable-source syscall`を使用
- **「プラグインが見つかりません」**: ファイルパスと権限を確認
- **アラートが表示されない**: nginxが設定されたログパスに書き込んでいるか確認

## 🏗️ ソースからのビルド

```bash
git clone https://github.com/takaosgb3/falco-nginx-plugin-claude
cd falco-nginx-plugin-claude
make build
```

## 📜 ライセンス

Apache License 2.0

## 🤝 コントリビューション

貢献を歓迎します！イシューを開くか、プルリクエストを送ってください。

## 🔗 リンク

- [Falcoドキュメント](https://falco.org/docs/)
- [開発リポジトリ](https://github.com/takaosgb3/falco-nginx-plugin-claude)
- [問題報告](https://github.com/takaosgb3/falco-plugin-nginx/issues)