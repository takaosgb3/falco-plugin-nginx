# 🚀 Quick Start: Binary Installation / クイックスタート: バイナリインストール

[English](#english) | [日本語](#japanese)

<a name="english"></a>
## English

This guide provides the fastest way to set up the Falco nginx plugin using pre-built binaries without cloning the source code.

### 📋 What This Guide Covers

- ✅ nginx web server setup
- ✅ Deploy web content for attack testing  
- ✅ Install Falco and nginx plugin
- ✅ Test security attack detection (SQL injection, XSS, directory traversal, etc.)
- ✅ Verify real-time alerts

**Time Required**: About 7 minutes  
**Prerequisites**: Ubuntu 20.04+ or Debian 10+

### 🚀 One-liner Installation (Recommended)

The easiest way is to use the automated installation script:

```bash
# Install latest version automatically
curl -sSL https://raw.githubusercontent.com/takaosgb3/falco-plugin-nginx/main/install.sh | sudo bash

# Or install a specific version
PLUGIN_VERSION=v1.2.10 curl -sSL https://raw.githubusercontent.com/takaosgb3/falco-plugin-nginx/main/install.sh | sudo bash
```

This script automatically:
- ✅ Checks system requirements
- ✅ Installs and configures nginx
- ✅ Installs Falco
- ✅ Downloads and installs the plugin and rules
- ✅ Verifies operation and shows test commands
- ✅ Optionally sets up test web content for attack simulation

After installation, you can test attack detection:
```bash
# Monitor Falco logs (service name may vary on EC2)
sudo journalctl -u falco -f
# or for EC2/eBPF systems:
sudo journalctl -u falco-modern-bpf -f

# IMPORTANT: Set up test web content first (required for attack simulation):
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/takaosgb3/falco-plugin-nginx/main/scripts/setup-test-content.sh)"

# Then simulate attacks (must use URL-encoded format for detection):
curl "http://localhost/search.php?q=%27%20OR%20%271%27%3D%271"  # SQL Injection
```

### 🌐 Setting Up Test Web Content (Required)

**Important**: You must set up test web content before testing attacks. Without this setup, all attack URLs will return 404 errors:

```bash
# Option 1: During installation (when prompted)
# The installer will ask: "Would you like to set up test web content for security testing? (y/N)"

# Option 2: Manual setup after installation
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/takaosgb3/falco-plugin-nginx/main/scripts/setup-test-content.sh)"
```

This creates vulnerable test endpoints:
- `/search.php` - SQL injection testing
- `/api/users.php` - API attack testing  
- `/upload.php` - Directory traversal testing
- `/admin/` - Brute force detection testing

### 📊 Full Installation Guide

For detailed manual installation steps, see [Installation Guide](installation.md).

### ✅ Testing Attack Detection

#### SQL Injection
```bash
# MUST use URL-encoded format for proper detection
curl "http://localhost/search.php?q=%27%20OR%20%271%27%3D%271"  # Detected
# curl "http://localhost/search.php?q=' OR '1'='1"  # NOT detected (unencoded)
```

#### XSS Attack
```bash
# MUST use URL-encoded format for proper detection
curl "http://localhost/search.php?q=%3Cscript%3Ealert(1)%3C/script%3E"  # Detected
# curl "http://localhost/search.php?q=<script>alert(1)</script>"  # NOT detected (unencoded)
```

#### Directory Traversal
```bash
curl "http://localhost/upload.php?file=../../../../../../etc/passwd"  # Detected
```

#### Command Injection
```bash
# MUST use URL-encoded format for proper detection
curl "http://localhost/api/users.php?cmd=;cat%20/etc/passwd"  # Detected
# curl "http://localhost/api/users.php?cmd=;cat /etc/passwd"  # May not be detected (spaces not encoded)
```

### 📝 Monitoring Alerts

Falco may use different service names depending on your system:
```bash
# Check which Falco service is running
systemctl status falco falco-modern-bpf falco-bpf 2>/dev/null | grep "Active: active"

# Then monitor the active service:
sudo journalctl -u <service-name> -f
```

### 🆘 Troubleshooting

#### Common Issues

1. **"Unknown source nginx" error**:
   - The plugin is not loaded in Falco
   - Check if `load_plugins: [nginx]` is set in `/etc/falco/falco.yaml`
   - Fix: `sudo sed -i 's/load_plugins: \[\]/load_plugins: [nginx]/' /etc/falco/falco.yaml`

2. **No alerts when testing attacks**:
   - Ensure Falco is running in plugin mode: `sudo falco -c /etc/falco/falco.yaml --disable-source syscall`
   - Check nginx access logs exist: `ls -la /var/log/nginx/access.log`
   - Check if rules are installed: `ls -la /etc/falco/rules.d/nginx_rules.yaml`

3. **Rules not installed**:
   ```bash
   # Download and install rules manually
   sudo curl -sSL https://raw.githubusercontent.com/takaosgb3/falco-plugin-nginx/main/rules/nginx_rules.yaml \
     -o /etc/falco/rules.d/nginx_rules.yaml
   ```

4. **404 errors on test URLs**:
   - Run the test content setup script as shown above

See [Troubleshooting Guide](troubleshooting.md) for more detailed solutions.

---

<a name="japanese"></a>
## 日本語

このガイドは、ソースコードをクローンせずに、ビルド済みのバイナリを使用してFalco nginxプラグインをセットアップする最短手順です。

### 📋 このガイドでできること

- ✅ nginx Webサーバーのセットアップ
- ✅ 攻撃テスト用のWebコンテンツ配備
- ✅ Falcoとnginxプラグインのインストール
- ✅ セキュリティ攻撃の検出テスト（SQL注入、XSS、ディレクトリトラバーサル等）
- ✅ リアルタイムアラートの確認

**所要時間**: 約7分  
**前提条件**: Ubuntu 20.04+ または Debian 10+

### 🚀 ワンライナーインストール（推奨）

最も簡単な方法は、自動インストールスクリプトを使用することです：

```bash
# 最新版を自動インストール
curl -sSL https://raw.githubusercontent.com/takaosgb3/falco-plugin-nginx/main/install.sh | sudo bash

# または特定のバージョンをインストール
PLUGIN_VERSION=v1.2.10 curl -sSL https://raw.githubusercontent.com/takaosgb3/falco-plugin-nginx/main/install.sh | sudo bash
```

このスクリプトは以下を自動的に実行します：
- ✅ システム要件の確認
- ✅ nginxのインストールと基本設定
- ✅ Falcoのインストール
- ✅ プラグインとルールファイルのダウンロード・配置
- ✅ 動作確認とテストコマンドの表示
- ✅ 攻撃シミュレーション用のテストWebコンテンツの設定（オプション）

インストール後、攻撃検出テストを実行できます：
```bash
# Falcoログを監視
sudo journalctl -u falco -f

# 重要: 最初にテストWebコンテンツをセットアップ（攻撃シミュレーションに必須）：
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/takaosgb3/falco-plugin-nginx/main/scripts/setup-test-content.sh)"

# その後、攻撃をシミュレート（検出のためURLエンコード形式を使用）：
curl "http://localhost/search.php?q=%27%20OR%20%271%27%3D%271"  # SQLインジェクション
```

### 🌐 テストWebコンテンツのセットアップ（必須）

**重要**: 攻撃テストを行う前に、必ずテストWebコンテンツをセットアップする必要があります。セットアップなしでは、すべての攻撃URLが404エラーになります：

```bash
# オプション1: インストール中（プロンプトが表示されたとき）
# インストーラーが尋ねます: "Would you like to set up test web content for security testing? (y/N)"

# オプション2: インストール後の手動セットアップ
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/takaosgb3/falco-plugin-nginx/main/scripts/setup-test-content.sh)"
```

これにより以下の脆弱なテストエンドポイントが作成されます：
- `/search.php` - SQLインジェクションテスト用
- `/api/users.php` - API攻撃テスト用
- `/upload.php` - ディレクトリトラバーサルテスト用
- `/admin/` - ブルートフォース検出テスト用

### 📊 詳細なインストールガイド

手動インストールの詳細な手順については、[インストールガイド](installation.md)を参照してください。

### ✅ 攻撃検出テスト

#### SQLインジェクション
```bash
# 正しく検出させるため、必ずURLエンコード形式を使用
curl "http://localhost/search.php?q=%27%20OR%20%271%27%3D%271"  # 検出される
# curl "http://localhost/search.php?q=' OR '1'='1"  # 検出されない（エンコードなし）
# curl "http://localhost/api/users.php?id=1' UNION SELECT * FROM users--"  # 検出されない（エンコードなし）
```

#### XSS攻撃
```bash
# 正しく検出させるため、必ずURLエンコード形式を使用
curl "http://localhost/search.php?q=%3Cscript%3Ealert(1)%3C/script%3E"  # 検出される
# curl "http://localhost/search.php?q=<script>alert(1)</script>"  # 検出されない（エンコードなし）
```

#### ディレクトリトラバーサル
```bash
curl "http://localhost/upload.php?file=../../../../../../etc/passwd"  # 検出される
```

#### コマンドインジェクション
```bash
# 正しく検出させるため、必ずURLエンコード形式を使用
curl "http://localhost/api/users.php?cmd=;cat%20/etc/passwd"  # 検出される
# curl "http://localhost/api/users.php?cmd=;cat /etc/passwd"  # 検出されない場合あり（スペース未エンコード）
```

### 🆘 トラブルシューティング

#### よくある問題

1. **「Unknown source nginx」エラー**:
   - プラグインがFalcoに読み込まれていません
   - `/etc/falco/falco.yaml`に`load_plugins: [nginx]`が設定されているか確認
   - 修正: `sudo sed -i 's/load_plugins: \[\]/load_plugins: [nginx]/' /etc/falco/falco.yaml`

2. **攻撃テスト時にアラートが出ない**:
   - Falcoがプラグインモードで実行されているか確認: `sudo falco -c /etc/falco/falco.yaml --disable-source syscall`
   - nginxアクセスログが存在するか確認: `ls -la /var/log/nginx/access.log`
   - ルールがインストールされているか確認: `ls -la /etc/falco/rules.d/nginx_rules.yaml`

3. **ルールがインストールされていない**:
   ```bash
   # 手動でルールをダウンロード・インストール
   sudo curl -sSL https://raw.githubusercontent.com/takaosgb3/falco-plugin-nginx/main/rules/nginx_rules.yaml \
     -o /etc/falco/rules.d/nginx_rules.yaml
   ```

4. **テストURLで404エラー**:
   - 上記のテストコンテンツセットアップスクリプトを実行

詳細な解決方法については、[トラブルシューティングガイド](troubleshooting.md)を参照してください。