# Falco Plugin for Nginx

[日本語版](#falco-nginx-プラグイン)

Real-time security monitoring plugin for nginx web servers powered by Falco.

## 🚀 Quick Start

This repository provides pre-built binaries and installation guides for the Falco nginx plugin.

### Download

Download the latest release files from the [releases](releases/) directory:

- `libfalco-nginx-plugin-linux-amd64.so` - Plugin binary for Linux x86_64
- `nginx_rules.yaml` - Falco detection rules
- `libfalco-nginx-plugin-linux-amd64.so.sha256` - Checksum file

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

Apache License 2.0

## 🔗 Links

- [Falco Project](https://falco.org/)
- [nginx](https://nginx.org/)

---

# Falco nginx プラグイン

[English](#falco-plugin-for-nginx)

Falcoを使用したnginx Webサーバー向けのリアルタイムセキュリティ監視プラグインです。

## 🚀 クイックスタート

このリポジトリでは、Falco nginxプラグインのビルド済みバイナリとインストールガイドを提供しています。

### ダウンロード

[releases](releases/)ディレクトリから最新のリリースファイルをダウンロードしてください：

- `libfalco-nginx-plugin-linux-amd64.so` - Linux x86_64用プラグインバイナリ
- `nginx_rules.yaml` - Falco検出ルール
- `libfalco-nginx-plugin-linux-amd64.so.sha256` - チェックサムファイル

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

Apache License 2.0

## 🔗 リンク

- [Falcoプロジェクト](https://falco.org/)
- [nginx](https://nginx.org/)

---

**Note / 注意**: This repository contains only the compiled binaries and documentation. Source code is maintained separately. / このリポジトリにはコンパイル済みのバイナリとドキュメントのみが含まれています。ソースコードは別途管理されています。