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
# Monitor Falco logs
sudo journalctl -u falco -f

# If you see 404 errors, set up test content:
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/takaosgb3/falco-plugin-nginx/main/scripts/setup-test-content.sh)"

# Then simulate attacks (URL-encoded):
curl "http://localhost/search.php?q=%27%20OR%20%271%27%3D%271"
```

### 🌐 Setting Up Test Web Content

If you encounter 404 errors when testing attacks, you need to set up test web content:

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
# Use URL-encoded format to avoid shell interpretation issues
curl "http://localhost/search.php?q=%27%20OR%20%271%27%3D%271"
curl "http://localhost/api/users.php?id=1%27%20UNION%20SELECT%20%2A%20FROM%20users--"
```

#### XSS Attack
```bash
# URL-encoded to prevent shell issues
curl "http://localhost/search.php?q=%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E"
curl "http://localhost/search.php?q=%3Cimg%20src%3Dx%20onerror%3Dalert%281%29%3E"
```

#### Directory Traversal
```bash
curl "http://localhost/upload.php?file=../../../../../../etc/passwd"
curl "http://localhost/api/users.php?path=../../../config/database.yml"
```

### 🆘 Troubleshooting

See [Troubleshooting Guide](troubleshooting.md) for common issues and solutions.

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

# 404エラーが出る場合は、テストコンテンツをセットアップ：
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/takaosgb3/falco-plugin-nginx/main/scripts/setup-test-content.sh)"

# その後、攻撃をシミュレート（URLエンコード済み）：
curl "http://localhost/search.php?q=%27%20OR%20%271%27%3D%271"
```

### 🌐 テストWebコンテンツのセットアップ

攻撃テスト時に404エラーが発生する場合は、テストWebコンテンツをセットアップする必要があります：

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
# シェルの解釈問題を避けるためURLエンコード形式を使用
curl "http://localhost/search.php?q=%27%20OR%20%271%27%3D%271"
curl "http://localhost/api/users.php?id=1%27%20UNION%20SELECT%20%2A%20FROM%20users--"
```

#### XSS攻撃
```bash
# シェルの問題を防ぐためURLエンコード済み
curl "http://localhost/search.php?q=%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E"
curl "http://localhost/search.php?q=%3Cimg%20src%3Dx%20onerror%3Dalert%281%29%3E"
```

#### ディレクトリトラバーサル
```bash
curl "http://localhost/upload.php?file=../../../../../../etc/passwd"
curl "http://localhost/api/users.php?path=../../../config/database.yml"
```

### 🆘 トラブルシューティング

よくある問題と解決方法については、[トラブルシューティングガイド](troubleshooting.md)を参照してください。