# Release v0.4.2 - Falco 0.41.x Compatibility Fix / Falco 0.41.x 互換性修正

[English](#english) | [日本語](#japanese)

<a name="english"></a>
## English

### 🐛 Critical Bug Fix

This release fixes compatibility issues with Falco 0.41.x by updating rule priority values.

### 🔄 What's Changed

#### Rule Priority Updates
- Changed `HIGH` → `WARNING`
- Changed `MEDIUM` → `NOTICE`
- Changed `LOW` → `INFO`
- `CRITICAL` remains unchanged

#### Installation Script Improvements
- Fixed `load_plugins` array update to ensure nginx plugin is loaded
- Added automatic load_plugins configuration

### 🚨 Important for Users

If you're using Falco 0.41.x and experiencing "Unknown source nginx" or priority validation errors, this release fixes those issues.

#### Quick Fix for Existing Installations
```bash
# Update rules file
sudo curl -sSL https://raw.githubusercontent.com/takaosgb3/falco-plugin-nginx/main/rules/nginx_rules.yaml \
  -o /etc/falco/rules.d/nginx_rules.yaml

# Update load_plugins if needed
sudo sed -i 's/load_plugins: \[\]/load_plugins: [nginx]/' /etc/falco/falco.yaml

# Restart Falco
sudo systemctl restart falco
```

### 💾 Installation

Use the same installation methods as before:

#### One-liner Installation
```bash
curl -sSL https://raw.githubusercontent.com/takaosgb3/falco-plugin-nginx/main/install.sh | sudo bash
```

### 🔧 Compatibility

- **Falco**: 0.36.0+ (Tested with 0.41.3)
- **Architecture**: Linux x86_64
- **nginx**: 1.14.0+ with combined log format

### 📝 Note

No changes to the plugin binary - only rules and installation script were updated.

---

<a name="japanese"></a>
## 日本語

### 🐛 重要なバグ修正

このリリースは、ルールの優先度値を更新することでFalco 0.41.xとの互換性の問題を修正します。

### 🔄 変更内容

#### ルール優先度の更新
- `HIGH` → `WARNING` に変更
- `MEDIUM` → `NOTICE` に変更
- `LOW` → `INFO` に変更
- `CRITICAL` は変更なし

#### インストールスクリプトの改善
- nginxプラグインが確実にロードされるよう`load_plugins`配列の更新を修正
- load_pluginsの自動設定を追加

### 🚨 ユーザーへの重要なお知らせ

Falco 0.41.xを使用していて「Unknown source nginx」や優先度検証エラーが発生している場合、このリリースでこれらの問題が修正されます。

#### 既存インストールのクイック修正
```bash
# ルールファイルを更新
sudo curl -sSL https://raw.githubusercontent.com/takaosgb3/falco-plugin-nginx/main/rules/nginx_rules.yaml \
  -o /etc/falco/rules.d/nginx_rules.yaml

# 必要に応じてload_pluginsを更新
sudo sed -i 's/load_plugins: \[\]/load_plugins: [nginx]/' /etc/falco/falco.yaml

# Falcoを再起動
sudo systemctl restart falco
```

### 💾 インストール

以前と同じインストール方法を使用してください：

#### ワンライナーインストール
```bash
curl -sSL https://raw.githubusercontent.com/takaosgb3/falco-plugin-nginx/main/install.sh | sudo bash
```

### 🔧 互換性

- **Falco**: 0.36.0以上（0.41.3でテスト済み）
- **アーキテクチャ**: Linux x86_64
- **nginx**: 1.14.0以上（combined形式のログ）

### 📝 注記

プラグインバイナリに変更はありません - ルールとインストールスクリプトのみが更新されました。

---
**Full Changelog / 変更履歴**: https://github.com/takaosgb3/falco-plugin-nginx/compare/v0.4.1...v0.4.2