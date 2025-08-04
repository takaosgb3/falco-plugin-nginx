# Falco nginx Plugin Troubleshooting Guide

[日本語版](#falco-nginx-プラグイントラブルシューティングガイド)

This guide helps resolve common issues when installing and running the Falco nginx plugin.

**Important Update (2025-08-04)**: The plugin has been completely rewritten using the Falco Plugin SDK for Go. This resolves many previous initialization issues.

## Common Issues and Solutions

### 1. Plugin Rule Syntax Errors (SDK-based Plugin)

**Error Message:**
```
Error: filter_check called with nonexistent field evt.type
```

**Cause:**
SDK-based plugins require all rules to include `source: nginx` attribute. The traditional `evt.type=pluginevent` syntax does not work with SDK plugins.

**Solution:**
Ensure all rules include the `source` attribute:
```yaml
- rule: SQL Injection Attempt
  desc: Detects SQL injection patterns
  source: nginx  # REQUIRED for SDK plugins
  condition: nginx.request_uri contains "' OR"
  output: "SQL injection detected"
  priority: CRITICAL
```

### 2. Previous CGO-related Errors (Now Resolved)

**Historical Error:**
```
Error: could not initialize plugin: plugin handle or 'get_last_error' function not defined
```

**Status:** ✅ RESOLVED
This error was common with the previous CGO-based implementation. The SDK rewrite has eliminated these initialization issues.

**Solution 1: Create log file if missing:**
```bash
# Create nginx log directory and file
sudo mkdir -p /var/log/nginx
sudo touch /var/log/nginx/access.log
sudo chown www-data:adm /var/log/nginx/access.log
sudo chmod 644 /var/log/nginx/access.log
```

**Solution 2: Test with minimal config (no init_config):**
```bash
# Test without init_config to use defaults
cat > /tmp/minimal-falco.yaml << 'EOF'
rules_files:
  - /etc/falco/falco_rules.yaml
  - /etc/falco/rules.d

load_plugins: [nginx]

plugins:
  - name: nginx
    library_path: /usr/share/falco/plugins/libfalco-nginx-plugin.so
EOF

sudo falco -c /tmp/minimal-falco.yaml --validate
```

#### B. Falco Configuration Issue
Ensure the falco.yaml is properly formatted.

**Fix configuration:**
```bash
# Backup current config
sudo cp /etc/falco/falco.yaml /etc/falco/falco.yaml.bak

# Create clean configuration section
sudo tee /tmp/plugin_config.yaml << 'EOF'

load_plugins: [nginx]

plugins:
  - name: nginx
    library_path: /usr/share/falco/plugins/libfalco-nginx-plugin.so
    init_config:
      log_paths:
        - /var/log/nginx/access.log
      max_batch_size: 1000
      watch_interval: 1000
EOF

# Append to falco.yaml (be careful not to duplicate)
sudo sh -c 'cat /tmp/plugin_config.yaml >> /etc/falco/falco.yaml'
```

### 2. Falco Service Crash on Startup

**Error Message:**
```
schema validation: failed for <root>: Object contains a property that could not be validated using 'properties' or 'additionalProperties' constraints: 'rules_file'.
```

**Solution:**
This error occurs when using the deprecated `rules_file` (singular) instead of `rules_files` (plural) in Falco 0.36.0+.

```bash
# Restore from backup or recreate
sudo cp /etc/falco/falco.yaml.bak /etc/falco/falco.yaml

# Or download fresh config
wget https://raw.githubusercontent.com/falcosecurity/falco/master/falco.yaml
sudo mv falco.yaml /etc/falco/falco.yaml

# Then add plugin configuration carefully
```

### 3. Plugin Not Loading

**Symptoms:**
- `falco --list-plugins` shows the plugin
- But validation fails with initialization error

**Debug Steps:**

1. **Test with minimal configuration:**
```bash
# Create test configuration
cat > /tmp/test-falco.yaml << 'EOF'
# Use the new plural form for Falco 0.36.0+
rules_files:
  - /etc/falco/falco_rules.yaml
  - /etc/falco/rules.d

json_output: true
json_include_output_property: true

load_plugins: [nginx]

plugins:
  - name: nginx
    library_path: /usr/share/falco/plugins/libfalco-nginx-plugin.so
    init_config:
      log_paths:
        - /var/log/nginx/access.log
EOF

# Test with this config
sudo falco -c /tmp/test-falco.yaml --validate
```

2. **Check file permissions:**
```bash
# Plugin file
ls -la /usr/share/falco/plugins/libfalco-nginx-plugin.so
# Should be: -rw-r--r-- 1 root root

# Log file
ls -la /var/log/nginx/access.log
# Should be readable by falco user
```

3. **Test plugin loading directly:**
```bash
# Run falco in debug mode
sudo falco -o log_level=debug -c /tmp/test-falco.yaml 2>&1 | grep -i plugin
```

4. **Debug exact initialization failure:**
```bash
# Test with strace to see exact system calls
sudo strace -e openat,access,stat falco -c /tmp/test-falco.yaml --validate 2>&1 | grep -E "(nginx|access.log)"

# Check if plugin can find the log file
ls -la /var/log/nginx/access.log

# Test with explicit empty config
cat > /tmp/debug-falco.yaml << 'EOF'
rules_files:
  - /etc/falco/falco_rules.yaml
  - /etc/falco/rules.d

load_plugins: [nginx]

plugins:
  - name: nginx
    library_path: /usr/share/falco/plugins/libfalco-nginx-plugin.so
    init_config: '{}'
EOF

sudo falco -c /tmp/debug-falco.yaml --validate
```

### 4. Service Continuously Restarting

**Symptoms:**
- Service shows "activating (auto-restart)" repeatedly
- Exit code 1 with no clear error message

**Debug Steps:**

1. **Check detailed logs:**
```bash
# View recent service logs
sudo journalctl -u falco-bpf.service -n 50 --no-pager

# Check for configuration errors
sudo falco -c /etc/falco/falco.yaml --validate

# Run Falco manually to see errors
sudo /usr/bin/falco -o engine.kind=ebpf
```

2. **Common causes:**
- Corrupted falco.yaml
- Missing kernel headers for eBPF
- Insufficient permissions
- Plugin binary incompatibility

3. **Fix kernel headers (for eBPF):**
```bash
# Install kernel headers
sudo apt install -y linux-headers-$(uname -r)

# For AWS EC2 instances
sudo apt install -y linux-headers-aws
```

### 5. API Version Compatibility

**Current Plugin Version:**
- Implementation: Falco Plugin SDK for Go (complete rewrite as of 2025-08-04)
- API version: 3.11.0
- Compatible with Falco 0.36.0 - 0.41.3
- SHA256: `5eab89337302337022ab05e3d3c5c69b1f25fa2517ce34e4e3268fce03301e13`

**Check Falco version:**
```bash
falco --version
```

**Compatibility Table:**
| Falco Version | Recommended Plugin API Version |
|---------------|-------------------------------|
| 0.35.x        | 3.0.0                        |
| 0.36.x-0.40.x | 3.3.0                        |
| 0.41.x        | 3.11.0 (current)             |

**If you have compatibility issues:**
- Ensure you have the latest binary from this repository
- Consider updating Falco to version 0.41.x for best compatibility

### 6. Alternative Installation Method

If the pre-built binary doesn't work, try using the Falco plugin registry:

```bash
# Install falcoctl if not present
curl -fsSL https://github.com/falcosecurity/falcoctl/releases/latest/download/falcoctl-linux-amd64 -o falcoctl
sudo install -o root -g root -m 0755 falcoctl /usr/local/bin/falcoctl

# Try to install from registry (if available)
sudo falcoctl artifact install nginx
```

## Complete Working Example

Here's a minimal working setup:

1. **Prepare environment:**
```bash
# Ensure nginx is installed and running
sudo systemctl status nginx

# Create log file if missing
sudo touch /var/log/nginx/access.log
sudo chown www-data:adm /var/log/nginx/access.log
```

2. **Download and install plugin:**
```bash
# Download plugin
wget https://raw.githubusercontent.com/takaosgb3/falco-plugin-nginx/main/releases/libfalco-nginx-plugin-linux-amd64.so

# Install
sudo mkdir -p /usr/share/falco/plugins
sudo cp libfalco-nginx-plugin-linux-amd64.so /usr/share/falco/plugins/libfalco-nginx-plugin.so
sudo chmod 644 /usr/share/falco/plugins/libfalco-nginx-plugin.so
```

3. **Configure Falco:**
```bash
# Create minimal config
sudo tee /etc/falco/falco.yaml << 'EOF'
# Use the new plural form for Falco 0.36.0+
rules_files:
  - /etc/falco/falco_rules.yaml
  - /etc/falco/rules.d

json_output: true
json_include_output_property: true
log_level: info

engine:
  kind: modern_ebpf

load_plugins: [nginx]

plugins:
  - name: nginx
    library_path: /usr/share/falco/plugins/libfalco-nginx-plugin.so
    init_config:
      log_paths:
        - /var/log/nginx/access.log
EOF

# Download rules
wget https://raw.githubusercontent.com/takaosgb3/falco-plugin-nginx/main/releases/nginx_rules.yaml
sudo cp nginx_rules.yaml /etc/falco/rules.d/
```

4. **Start Falco:**
```bash
# For modern eBPF
sudo systemctl restart falco-modern-bpf.service

# Or for standard eBPF
sudo systemctl restart falco-bpf.service

# Check status
sudo systemctl status falco-bpf.service
```

## Getting Help

If you continue to experience issues:

1. Collect debug information:
```bash
# System info
uname -a
falco --version
ls -la /usr/share/falco/plugins/
ls -la /var/log/nginx/

# Falco logs
sudo journalctl -u falco-bpf.service --since "10 minutes ago"

# Manual test
sudo /usr/bin/falco -o engine.kind=ebpf 2>&1 | head -50
```

2. Report issue at: https://github.com/takaosgb3/falco-nginx-plugin-claude/issues

---

# Falco nginx プラグイントラブルシューティングガイド

[English](#falco-nginx-plugin-troubleshooting-guide)

このガイドは、Falco nginxプラグインのインストールと実行時の一般的な問題を解決するのに役立ちます。

**重要な更新（2025-08-04）**: プラグインはFalco Plugin SDK for Goを使用して完全に書き直されました。これにより、以前の多くの初期化問題が解決されています。

## よくある問題と解決方法

### 1. プラグインルール構文エラー（SDKベースプラグイン）

**エラーメッセージ:**
```
Error: filter_check called with nonexistent field evt.type
```

**原因:**
SDKベースのプラグインでは、すべてのルールに`source: nginx`属性を含める必要があります。従来の`evt.type=pluginevent`構文はSDKプラグインでは機能しません。

**解決方法:**
すべてのルールに`source`属性を含めてください：
```yaml
- rule: SQL Injection Attempt
  desc: SQLインジェクションパターンを検出
  source: nginx  # SDKプラグインでは必須
  condition: nginx.request_uri contains "' OR"
  output: "SQLインジェクション検出"
  priority: CRITICAL
```

### 2. 以前のCGO関連エラー（現在は解決済み）

**過去のエラー:**
```
Error: could not initialize plugin: plugin handle or 'get_last_error' function not defined
```

**ステータス:** ✅ 解決済み
このエラーは以前のCGOベースの実装で一般的でした。SDKへの書き直しにより、これらの初期化問題は解消されています。

**解決方法1: ログファイルが存在しない場合は作成:**
```bash
# nginxログディレクトリとファイルを作成
sudo mkdir -p /var/log/nginx
sudo touch /var/log/nginx/access.log
sudo chown www-data:adm /var/log/nginx/access.log
sudo chmod 644 /var/log/nginx/access.log
```

**解決方法2: 最小設定でテスト（init_configなし）:**
```bash
# デフォルトを使用するためinit_configなしでテスト
cat > /tmp/minimal-falco.yaml << 'EOF'
rules_files:
  - /etc/falco/falco_rules.yaml
  - /etc/falco/rules.d

load_plugins: [nginx]

plugins:
  - name: nginx
    library_path: /usr/share/falco/plugins/libfalco-nginx-plugin.so
EOF

sudo falco -c /tmp/minimal-falco.yaml --validate
```

#### B. Falco設定の問題
falco.yamlが正しくフォーマットされていることを確認してください。

**設定を修正:**
```bash
# 現在の設定をバックアップ
sudo cp /etc/falco/falco.yaml /etc/falco/falco.yaml.bak

# クリーンな設定セクションを作成
sudo tee /tmp/plugin_config.yaml << 'EOF'

load_plugins: [nginx]

plugins:
  - name: nginx
    library_path: /usr/share/falco/plugins/libfalco-nginx-plugin.so
    init_config:
      log_paths:
        - /var/log/nginx/access.log
      max_batch_size: 1000
      watch_interval: 1000
EOF

# falco.yamlに追加（重複しないよう注意）
sudo sh -c 'cat /tmp/plugin_config.yaml >> /etc/falco/falco.yaml'
```

### 2. Falcoサービスの起動時クラッシュ

**エラーメッセージ:**
```
schema validation: failed for <root>: Object contains a property that could not be validated using 'properties' or 'additionalProperties' constraints: 'rules_file'.
```

**解決方法:**
このエラーは、Falco 0.36.0以降で廃止された`rules_file`（単数形）を使用している場合に発生します。`rules_files`（複数形）を使用する必要があります。

```bash
# バックアップから復元または再作成
sudo cp /etc/falco/falco.yaml.bak /etc/falco/falco.yaml

# または新しい設定をダウンロード
wget https://raw.githubusercontent.com/falcosecurity/falco/master/falco.yaml
sudo mv falco.yaml /etc/falco/falco.yaml

# その後、プラグイン設定を慎重に追加
```

### 3. プラグインがロードされない

**症状:**
- `falco --list-plugins`でプラグインが表示される
- しかし検証が初期化エラーで失敗する

**デバッグ手順:**

1. **最小限の設定でテスト:**
```bash
# テスト設定を作成
cat > /tmp/test-falco.yaml << 'EOF'
# Falco 0.36.0以降用の新しい複数形を使用
rules_files:
  - /etc/falco/falco_rules.yaml
  - /etc/falco/rules.d

json_output: true
json_include_output_property: true

load_plugins: [nginx]

plugins:
  - name: nginx
    library_path: /usr/share/falco/plugins/libfalco-nginx-plugin.so
    init_config:
      log_paths:
        - /var/log/nginx/access.log
EOF

# この設定でテスト
sudo falco -c /tmp/test-falco.yaml --validate
```

2. **ファイル権限を確認:**
```bash
# プラグインファイル
ls -la /usr/share/falco/plugins/libfalco-nginx-plugin.so
# 以下のようになっているはずです: -rw-r--r-- 1 root root

# ログファイル
ls -la /var/log/nginx/access.log
# falcoユーザーが読み取り可能である必要があります
```

3. **プラグインのロードを直接テスト:**
```bash
# デバッグモードでfalcoを実行
sudo falco -o log_level=debug -c /tmp/test-falco.yaml 2>&1 | grep -i plugin
```

4. **初期化失敗の正確な原因をデバッグ:**
```bash
# straceで正確なシステムコールを確認
sudo strace -e openat,access,stat falco -c /tmp/test-falco.yaml --validate 2>&1 | grep -E "(nginx|access.log)"

# プラグインがログファイルを見つけられるか確認
ls -la /var/log/nginx/access.log

# 明示的な空の設定でテスト
cat > /tmp/debug-falco.yaml << 'EOF'
rules_files:
  - /etc/falco/falco_rules.yaml
  - /etc/falco/rules.d

load_plugins: [nginx]

plugins:
  - name: nginx
    library_path: /usr/share/falco/plugins/libfalco-nginx-plugin.so
    init_config: '{}'
EOF

sudo falco -c /tmp/debug-falco.yaml --validate
```

### 4. サービスが継続的に再起動する

**症状:**
- サービスが「activating (auto-restart)」を繰り返す
- 明確なエラーメッセージなしで終了コード1

**デバッグ手順:**

1. **詳細なログを確認:**
```bash
# 最近のサービスログを表示
sudo journalctl -u falco-bpf.service -n 50 --no-pager

# 設定エラーを確認
sudo falco -c /etc/falco/falco.yaml --validate

# 手動でFalcoを実行してエラーを確認
sudo /usr/bin/falco -o engine.kind=ebpf
```

2. **一般的な原因:**
- falco.yamlの破損
- eBPF用のカーネルヘッダーの欠如
- 権限不足
- プラグインバイナリの非互換性

3. **カーネルヘッダーを修正（eBPF用）:**
```bash
# カーネルヘッダーをインストール
sudo apt install -y linux-headers-$(uname -r)

# AWS EC2インスタンスの場合
sudo apt install -y linux-headers-aws
```

### 5. APIバージョンの互換性

**現在のプラグインバージョン:**
- 実装: Falco Plugin SDK for Go（2025-08-04に完全書き直し）
- APIバージョン: 3.11.0
- Falco 0.36.0 - 0.41.3に対応
- SHA256: `5eab89337302337022ab05e3d3c5c69b1f25fa2517ce34e4e3268fce03301e13`

**Falcoバージョンを確認:**
```bash
falco --version
```

**互換性表:**
| Falcoバージョン | 推奨プラグインAPIバージョン |
|----------------|---------------------------|
| 0.35.x         | 3.0.0                     |
| 0.36.x-0.40.x  | 3.3.0                     |
| 0.41.x         | 3.11.0（現在）             |

**互換性の問題がある場合:**
- このリポジトリから最新のバイナリを取得していることを確認
- 最高の互換性のため、Falcoをバージョン0.41.xに更新することを検討

## 完全な動作例

最小限の動作セットアップ:

1. **環境を準備:**
```bash
# nginxがインストールされ実行中であることを確認
sudo systemctl status nginx

# ログファイルが存在しない場合は作成
sudo touch /var/log/nginx/access.log
sudo chown www-data:adm /var/log/nginx/access.log
```

2. **プラグインをダウンロードしてインストール:**
```bash
# プラグインをダウンロード
wget https://raw.githubusercontent.com/takaosgb3/falco-plugin-nginx/main/releases/libfalco-nginx-plugin-linux-amd64.so

# インストール
sudo mkdir -p /usr/share/falco/plugins
sudo cp libfalco-nginx-plugin-linux-amd64.so /usr/share/falco/plugins/libfalco-nginx-plugin.so
sudo chmod 644 /usr/share/falco/plugins/libfalco-nginx-plugin.so
```

3. **Falcoを設定:**
```bash
# 最小限の設定を作成
sudo tee /etc/falco/falco.yaml << 'EOF'
# Falco 0.36.0以降用の新しい複数形を使用
rules_files:
  - /etc/falco/falco_rules.yaml
  - /etc/falco/rules.d

json_output: true
json_include_output_property: true
log_level: info

engine:
  kind: modern_ebpf

load_plugins: [nginx]

plugins:
  - name: nginx
    library_path: /usr/share/falco/plugins/libfalco-nginx-plugin.so
    init_config:
      log_paths:
        - /var/log/nginx/access.log
EOF

# ルールをダウンロード
wget https://raw.githubusercontent.com/takaosgb3/falco-plugin-nginx/main/releases/nginx_rules.yaml
sudo cp nginx_rules.yaml /etc/falco/rules.d/
```

4. **Falcoを開始:**
```bash
# Modern eBPFの場合
sudo systemctl restart falco-modern-bpf.service

# または標準eBPFの場合
sudo systemctl restart falco-bpf.service

# ステータスを確認
sudo systemctl status falco-modern-bpf.service
```

## ヘルプを得る

問題が続く場合:

1. デバッグ情報を収集:
```bash
# システム情報
uname -a
falco --version
ls -la /usr/share/falco/plugins/
ls -la /var/log/nginx/

# Falcoログ
sudo journalctl -u falco-bpf.service --since "10 minutes ago"

# 手動テスト
sudo /usr/bin/falco -o engine.kind=ebpf 2>&1 | head -50
```

2. 問題を報告: https://github.com/takaosgb3/falco-nginx-plugin-claude/issues