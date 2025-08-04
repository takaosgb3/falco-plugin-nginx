# Falco Plugin for Nginx

[日本語版](#falco-nginx-プラグイン)

> **📢 Latest Update (2025-08-04)**: SDK-based plugin with real-time threat detection!
> - Complete rewrite using official Falco Plugin SDK for Go v0.8.1
> - Processes both existing and new log entries
> - Fixed nginx_rules.yaml syntax for SDK compatibility
> - Tested and verified on Ubuntu 22.04 with Falco 0.41.3
> - Binary SHA256: `2b97aaa085ce514a6075c49ba166ea7cf47d30533475eb51dd614acbb3a5c244`

Real-time security monitoring plugin for nginx web servers powered by Falco.

## 🚀 Quick Start

This repository provides pre-built binaries and installation guides for the Falco nginx plugin.

### Download

Download the latest release files from the [releases](releases/) directory:

- `libfalco-nginx-plugin-linux-amd64.so` - Plugin binary for Linux x86_64
- `nginx_rules.yaml` - Falco detection rules
- `libfalco-nginx-plugin-linux-amd64.so.sha256` - Checksum file

**Latest SHA256**: `2b97aaa085ce514a6075c49ba166ea7cf47d30533475eb51dd614acbb3a5c244`

### Installation

Follow the [Quick Start Binary Installation Guide](docs/QUICK_START_BINARY_INSTALLATION.md) for detailed setup instructions.

## ✨ Features

- **Real-time Threat Detection**
  - SQL injection attacks
  - Cross-site scripting (XSS)
  - Directory traversal attempts
  - Command injection
  - Brute force attacks
  - Security scanner detection

- **High Performance**
  - < 1ms per event processing
  - Minimal memory footprint
  - Zero-downtime log rotation support

- **Easy Integration**
  - Works with existing nginx installations
  - Compatible with Falco 0.36.0+
  - Simple configuration

## 📋 Requirements

- Ubuntu 20.04+ or Debian 10+
- Falco 0.36.0+
- nginx 1.18.0+

## 📖 Documentation

- [Quick Start Binary Installation](docs/QUICK_START_BINARY_INSTALLATION.md) - Get started in 7 minutes
- [Troubleshooting Guide](docs/TROUBLESHOOTING.md) - Common issues and solutions

## 📄 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

### Binary Distribution

The pre-compiled binaries include code from several open-source projects:
- Falco Plugin SDK for Go (Apache 2.0)
- Go standard library (BSD-style)
- fsnotify (BSD-3-Clause)

See [NOTICE](NOTICE) for full attribution.

## 🔗 Links

- [Falco Project](https://falco.org/)
- [nginx](https://nginx.org/)

---

# Falco nginx プラグイン

[English](#falco-plugin-for-nginx)

> **📢 最新更新 (2025-08-04)**: SDKベースのプラグインでリアルタイム脅威検出！
> - 公式Falco Plugin SDK for Go v0.8.1を使用した完全な書き直し
> - 既存ログと新規ログの両方を処理
> - nginx_rules.yamlをSDK互換構文に修正
> - Ubuntu 22.04とFalco 0.41.3でテスト・検証済み
> - バイナリSHA256: `2b97aaa085ce514a6075c49ba166ea7cf47d30533475eb51dd614acbb3a5c244`

Falcoを使用したnginx Webサーバー向けのリアルタイムセキュリティ監視プラグインです。

## 🚀 クイックスタート

このリポジトリでは、Falco nginxプラグインのビルド済みバイナリとインストールガイドを提供しています。

### ダウンロード

[releases](releases/)ディレクトリから最新のリリースファイルをダウンロードしてください：

- `libfalco-nginx-plugin-linux-amd64.so` - Linux x86_64用プラグインバイナリ
- `nginx_rules.yaml` - Falco検出ルール
- `libfalco-nginx-plugin-linux-amd64.so.sha256` - チェックサムファイル

**最新SHA256**: `2b97aaa085ce514a6075c49ba166ea7cf47d30533475eb51dd614acbb3a5c244`

### インストール

詳細なセットアップ手順については、[クイックスタートバイナリインストールガイド](docs/QUICK_START_BINARY_INSTALLATION.md)をご覧ください。

## ✨ 機能

- **リアルタイム脅威検出**
  - SQLインジェクション攻撃
  - クロスサイトスクリプティング（XSS）
  - ディレクトリトラバーサル攻撃
  - コマンドインジェクション
  - ブルートフォース攻撃
  - セキュリティスキャナー検出

- **高性能**
  - イベントあたり1ms未満の処理時間
  - 最小限のメモリフットプリント
  - ダウンタイムゼロのログローテーション対応

- **簡単な統合**
  - 既存のnginxインストールで動作
  - Falco 0.36.0以降に対応
  - シンプルな設定

## 📋 要件

- Ubuntu 20.04+ または Debian 10+
- Falco 0.36.0+
- nginx 1.18.0+

## 📖 ドキュメント

- [クイックスタートバイナリインストール](docs/QUICK_START_BINARY_INSTALLATION.md) - 7分で開始
- [トラブルシューティングガイド](docs/TROUBLESHOOTING.md) - よくある問題と解決方法

## 📄 ライセンス

このプロジェクトはApache License 2.0でライセンスされています - 詳細は[LICENSE](LICENSE)ファイルをご覧ください。

### バイナリ配布について

プリコンパイルされたバイナリには、以下のオープンソースプロジェクトのコードが含まれています：
- Falco Plugin SDK for Go (Apache 2.0)
- Go標準ライブラリ (BSDスタイル)
- fsnotify (BSD-3-Clause)

完全な帰属情報については[NOTICE](NOTICE)をご覧ください。

## 🔗 リンク

- [Falcoプロジェクト](https://falco.org/)
- [nginx](https://nginx.org/)

---

## 🔧 Technical Details

### Plugin Architecture
- Built with Falco Plugin SDK for Go v0.8.1
- Implements both source and extractor capabilities
- Real-time file monitoring using fsnotify
- Zero-copy event processing with GOB encoding

### Supported Fields
- `nginx.remote_addr` - Client IP address
- `nginx.method` - HTTP method (GET, POST, etc.)
- `nginx.path` - Request URI path
- `nginx.query_string` - Query parameters
- `nginx.status` - HTTP response status code
- `nginx.bytes_sent` - Response size in bytes
- `nginx.user_agent` - Client user agent
- And 6 more fields for comprehensive monitoring

### Binary Distribution Notice

This repository provides pre-compiled binaries for ease of deployment. The binaries are:
- Built on Ubuntu 22.04 LTS
- Compiled with Go 1.22+
- Statically linked for maximum compatibility
- Tested across multiple Linux distributions

For source code access or custom builds, please contact the maintainers.

---

**Note**: This is a binary distribution repository. Source code is maintained in a separate private repository for security reasons.