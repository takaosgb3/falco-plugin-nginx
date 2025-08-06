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

After installation, you can test attack detection:
```bash
# Monitor Falco logs
sudo journalctl -u falco -f

# In another terminal, simulate attacks
curl "http://localhost/search.php?q=' OR '1'='1"
```

### 📊 Full Installation Guide

For detailed manual installation steps, see [Installation Guide](installation.md).

### ✅ Testing Attack Detection

#### SQL Injection
```bash
curl "http://localhost/search.php?q=' OR '1'='1"
curl "http://localhost/api/users.php?id=1' UNION SELECT * FROM users--"
```

#### XSS Attack
```bash
curl "http://localhost/search.php?q=<script>alert('XSS')</script>"
curl "http://localhost/search.php?q=<img src=x onerror=alert(1)>"
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

インストール後、攻撃検出テストを実行できます：
```bash
# Falcoログを監視
sudo journalctl -u falco -f

# 別ターミナルで攻撃をシミュレート
curl "http://localhost/search.php?q=' OR '1'='1"
```

### 📊 詳細なインストールガイド

手動インストールの詳細な手順については、[インストールガイド](installation.md)を参照してください。

### ✅ 攻撃検出テスト

#### SQLインジェクション
```bash
curl "http://localhost/search.php?q=' OR '1'='1"
curl "http://localhost/api/users.php?id=1' UNION SELECT * FROM users--"
```

#### XSS攻撃
```bash
curl "http://localhost/search.php?q=<script>alert('XSS')</script>"
curl "http://localhost/search.php?q=<img src=x onerror=alert(1)>"
```

#### ディレクトリトラバーサル
```bash
curl "http://localhost/upload.php?file=../../../../../../etc/passwd"
curl "http://localhost/api/users.php?path=../../../config/database.yml"
```

### 🆘 トラブルシューティング

よくある問題と解決方法については、[トラブルシューティングガイド](troubleshooting.md)を参照してください。